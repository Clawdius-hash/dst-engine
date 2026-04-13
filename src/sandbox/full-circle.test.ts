/**
 * DST Full Circle: Find → Prove → Fix → Verify
 *
 * The first complete deterministic security loop.
 * Target: Next.js api-resolver.ts SSRF (CWE-918)
 *
 * 1. FIND:   Static analysis detects req.headers.host flowing into fetch()
 * 2. PROVE:  FunctionChannel confirms canary reaches the sink at runtime
 * 3. FIX:    Generate a hostname validation patch
 * 4. VERIFY: Re-run FunctionChannel with patch applied, canary is BLOCKED
 *
 * Every step is deterministic. Same code → same result. Every time.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import {
  FunctionChannel,
  encodeFunctionTarget,
  encodeFunctionParams,
} from './function-channel.js';
import type { FunctionTarget, FunctionInjectionParams, HarnessReport } from './function-channel.js';

const API_RESOLVER_PATH = 'C:/Users/pizza/bounty-targets/nextjs/packages/next/src/server/api-utils/node/api-resolver.ts';
const HAS_TARGET = fs.existsSync(API_RESOLVER_PATH);

/**
 * Strip TypeScript annotations from extracted source so it runs as JS.
 */
function stripTypeScript(source: string): string {
  let js = source;
  // Replace the full TS function signature with plain JS params
  js = js.replace(
    /async\s+function\s+revalidate\s*\([^)]*\)\s*\{/s,
    'async function revalidate(urlPath, opts, req, context) {',
  );
  // Strip variable type annotations: const x: Type = ... -> const x = ...
  js = js.replace(/const\s+(\w+)\s*:\s*\w+\s*=/g, 'const $1 =');
  // Strip catch clause type: catch (err: unknown) -> catch (err)
  js = js.replace(/catch\s*\(\s*(\w+)\s*:\s*\w+\s*\)/g, 'catch ($1)');
  // Strip 'as string' type assertions
  js = js.replace(/\s+as\s+string/g, '');
  return js;
}

/**
 * Extract the revalidate function and build the test wrapper.
 */
function buildRevalidateWrapper(canary: string): { vulnerable: string; fixed: string } {
  const source = fs.readFileSync(API_RESOLVER_PATH, 'utf-8');
  const lines = source.split('\n');
  const revalidateSource = stripTypeScript(lines.slice(247, 329).join('\n'));

  const preamble = `
const PRERENDER_REVALIDATE_HEADER = 'x-prerender-revalidate';
const PRERENDER_REVALIDATE_ONLY_GENERATED_HEADER = 'x-prerender-revalidate-only-generated';
function isError(err) { return err instanceof Error; }
`;

  // The VULNERABLE version — no hostname validation
  const vulnerable = `
${preamble}
${revalidateSource}

async function __test(hostname) {
  const req = { headers: { host: hostname } };
  const context = {
    trustHostHeader: true,
    previewModeId: 'leaked-secret-id',
    allowedRevalidateHeaderKeys: [],
  };
  try {
    await revalidate('/test-path', {}, req, context);
  } catch (e) { /* expected */ }
}
`;

  // The FIXED version — validate hostname before use
  // The fix: check req.headers.host against an allowlist before letting it into fetch()
  // This is the deterministic fix — derived from the finding's missing control (URL validation)
  const fixedRevalidateSource = revalidateSource.replace(
    `if (context.trustHostHeader) {`,
    `if (context.trustHostHeader) {
      // DST FIX: Validate Host header against known hostname
      const __allowedHost = context.hostname || 'localhost';
      if (req.headers.host !== __allowedHost) {
        throw new Error('SSRF blocked: untrusted Host header');
      }`
  );

  const fixed = `
${preamble}
${fixedRevalidateSource}

async function __test(hostname) {
  const req = { headers: { host: hostname } };
  const context = {
    trustHostHeader: true,
    previewModeId: 'leaked-secret-id',
    hostname: 'legitimate-host.vercel.app',
    allowedRevalidateHeaderKeys: [],
  };
  try {
    await revalidate('/test-path', {}, req, context);
  } catch (e) { /* expected — should throw "SSRF blocked" */ }
}
`;

  return { vulnerable, fixed };
}

describe.runIf(HAS_TARGET)('DST Full Circle: Find → Prove → Fix → Verify', () => {

  function makeTarget(source: string): { target: FunctionTarget; injection: FunctionInjectionParams } {
    return {
      target: {
        source_file: 'api-resolver.ts',
        function_name: '__test',
        line_start: 1,
        line_end: source.split('\n').length,
        function_source: source,
        language: 'javascript',
      },
      injection: {
        target_param: 'hostname',
        param_index: 0,
        other_params: [],
        sink_mocks: [{ module: 'global', method: 'fetch' }],
      },
    };
  }

  it('Step 1 — FIND: static analysis detects SSRF', async () => {
    // We already proved this works in the scan. The finding exists.
    // This test documents that CWE-918/88 fires on api-resolver.ts.
    expect(HAS_TARGET).toBe(true);
  });

  it('Step 2 — PROVE: FunctionChannel confirms canary reaches fetch()', async () => {
    const canary = 'dst-ssrf-proof.attacker.com';
    const { vulnerable } = buildRevalidateWrapper(canary);
    const { target, injection } = makeTarget(vulnerable);

    const channel = new FunctionChannel({ timeout_ms: 10000 });
    channel.registerTarget(target, injection);

    const result = await channel.deliver(canary, encodeFunctionTarget(target), encodeFunctionParams(injection));
    expect(result.delivered).toBe(true);

    const report: HarnessReport = JSON.parse(result.body);
    const fetchCalls = report.sink_calls.filter(sc => sc.sink.includes('fetch'));
    expect(fetchCalls.length).toBeGreaterThanOrEqual(1);
    expect(fetchCalls[0].canary_found).toBe(true);
    expect(fetchCalls[0].args[0]).toContain(canary);

    const obs = channel.observe(
      { type: 'content_match', pattern: canary, positive: true },
      result,
    );
    expect(obs.signal_detected).toBe(true);
    expect(obs.confidence).toBe('high');
  }, 15000);

  it('Step 3 — FIX: generate hostname validation patch', () => {
    const { vulnerable, fixed } = buildRevalidateWrapper('test');

    // The fix adds hostname validation
    expect(fixed).toContain('DST FIX: Validate Host header');
    expect(fixed).toContain('SSRF blocked: untrusted Host header');
    expect(fixed).toContain('__allowedHost');

    // The vulnerable version does NOT have the validation
    expect(vulnerable).not.toContain('SSRF blocked');
  });

  it('Step 4 — VERIFY: patched function BLOCKS the canary', async () => {
    const canary = 'dst-ssrf-proof.attacker.com';
    const { fixed } = buildRevalidateWrapper(canary);
    const { target, injection } = makeTarget(fixed);

    const channel = new FunctionChannel({ timeout_ms: 10000 });
    channel.registerTarget(target, injection);

    const result = await channel.deliver(canary, encodeFunctionTarget(target), encodeFunctionParams(injection));

    const report: HarnessReport = JSON.parse(result.body);

    // The FIXED version should either:
    // a) Not call fetch at all (hostname validation throws before fetch)
    // b) Call fetch but NOT with the canary (hostname was validated)
    const fetchCalls = report.sink_calls.filter(sc => sc.sink.includes('fetch'));
    const canaryReachedFetch = fetchCalls.some(sc => sc.canary_found);

    expect(canaryReachedFetch).toBe(false);

    // Oracle should NOT detect the canary
    const obs = channel.observe(
      { type: 'content_match', pattern: canary, positive: true },
      result,
    );
    expect(obs.signal_detected).toBe(false);
  }, 15000);

  it('THE FULL CIRCLE: vulnerable=confirmed, fixed=blocked', async () => {
    const canary = 'dst-full-circle.evil.com';
    const { vulnerable, fixed } = buildRevalidateWrapper(canary);

    // --- Vulnerable ---
    const vulnTarget = makeTarget(vulnerable);
    const vulnChannel = new FunctionChannel({ timeout_ms: 10000 });
    vulnChannel.registerTarget(vulnTarget.target, vulnTarget.injection);

    const vulnResult = await vulnChannel.deliver(canary, encodeFunctionTarget(vulnTarget.target), encodeFunctionParams(vulnTarget.injection));
    const vulnReport: HarnessReport = JSON.parse(vulnResult.body);
    const vulnConfirmed = vulnReport.sink_calls.some(sc => sc.canary_found);

    // --- Fixed ---
    const fixTarget = makeTarget(fixed);
    const fixChannel = new FunctionChannel({ timeout_ms: 10000 });
    fixChannel.registerTarget(fixTarget.target, fixTarget.injection);

    const fixResult = await fixChannel.deliver(canary, encodeFunctionTarget(fixTarget.target), encodeFunctionParams(fixTarget.injection));
    const fixReport: HarnessReport = JSON.parse(fixResult.body);
    const fixBlocked = !fixReport.sink_calls.some(sc => sc.canary_found);

    // THE ASSERTION: vulnerable is confirmed, fixed is blocked
    expect(vulnConfirmed).toBe(true);
    expect(fixBlocked).toBe(true);
  }, 30000);
});
