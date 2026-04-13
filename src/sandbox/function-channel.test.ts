/**
 * FunctionChannel harness generator tests.
 *
 * These tests are NOT string-comparison tests. Each test generates a real .mjs
 * harness file, writes it to a temp directory, and executes it under `node`.
 * The harness must produce valid JSON (HarnessReport) on stdout.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync, unlinkSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { execFile } from 'child_process';
import { promisify } from 'util';
import {
  generateHarness,
  FunctionChannel,
  encodeFunctionTarget,
  decodeFunctionTarget,
  encodeFunctionParams,
  buildFunctionTarget,
  buildInjectionParams,
} from './function-channel.js';
import type {
  FunctionTarget,
  FunctionInjectionParams,
  HarnessReport,
} from './function-channel.js';
import type { DeliveryResult } from './channels.js';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import { verifyAll } from '../verifier/index.js';
import type { NeuralMap } from '../types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const execFileAsync = promisify(execFile);

describe('generateHarness', () => {
  it('generates executable harness that captures fetch calls', async () => {
    const target: FunctionTarget = {
      source_file: 'test.js',
      function_name: 'leakyFetch',
      line_start: 1,
      line_end: 4,
      function_source: `async function leakyFetch(host) {\n  const res = await fetch('https://' + host + '/api');\n  return res;\n}`,
      language: 'javascript',
    };
    const injection: FunctionInjectionParams = {
      target_param: 'host',
      param_index: 0,
      other_params: [],
      sink_mocks: [{ module: 'global', method: 'fetch' }],
    };
    const canary = 'dst-ssrf-probe.example.com';
    const harness = generateHarness(target, injection, canary);

    // Execute the harness
    const dir = mkdtempSync(join(tmpdir(), 'dst-test-'));
    const harnessPath = join(dir, 'harness.mjs');
    writeFileSync(harnessPath, harness);
    try {
      const { stdout } = await execFileAsync('node', [harnessPath], {
        timeout: 5000,
      });
      const report: HarnessReport = JSON.parse(stdout.trim());
      expect(report.completed).toBe(true);
      expect(report.sink_calls.length).toBeGreaterThanOrEqual(1);
      expect(report.sink_calls[0].canary_found).toBe(true);
    } finally {
      try {
        unlinkSync(harnessPath);
      } catch {}
    }
  });

  it('generates harness that captures exec calls', async () => {
    const target: FunctionTarget = {
      source_file: 'test.js',
      function_name: 'runCmd',
      line_start: 1,
      line_end: 4,
      function_source: `function runCmd(cmd) {\n  const cp = require('child_process');\n  cp.exec(cmd);\n}`,
      language: 'javascript',
    };
    const injection: FunctionInjectionParams = {
      target_param: 'cmd',
      param_index: 0,
      other_params: [],
      sink_mocks: [{ module: 'child_process', method: 'exec' }],
    };
    const canary = 'dst-cmdi-proof';
    const harness = generateHarness(target, injection, canary);

    const dir = mkdtempSync(join(tmpdir(), 'dst-test-'));
    const harnessPath = join(dir, 'harness.mjs');
    writeFileSync(harnessPath, harness);
    try {
      const { stdout } = await execFileAsync('node', [harnessPath], {
        timeout: 5000,
      });
      const report: HarnessReport = JSON.parse(stdout.trim());
      expect(report.completed).toBe(true);
      expect(report.sink_calls.length).toBeGreaterThanOrEqual(1);
      expect(report.sink_calls[0].sink).toContain('exec');
      expect(report.sink_calls[0].canary_found).toBe(true);
    } finally {
      try {
        unlinkSync(harnessPath);
      } catch {}
    }
  });

  it('harness handles function that throws without crashing', async () => {
    const target: FunctionTarget = {
      source_file: 'test.js',
      function_name: 'throwError',
      line_start: 1,
      line_end: 3,
      function_source: `function throwError(x) {\n  throw new Error('boom: ' + x);\n}`,
      language: 'javascript',
    };
    const injection: FunctionInjectionParams = {
      target_param: 'x',
      param_index: 0,
      other_params: [],
      sink_mocks: [],
    };
    const harness = generateHarness(target, injection, 'test');

    const dir = mkdtempSync(join(tmpdir(), 'dst-test-'));
    const harnessPath = join(dir, 'harness.mjs');
    writeFileSync(harnessPath, harness);
    try {
      const { stdout } = await execFileAsync('node', [harnessPath], {
        timeout: 5000,
      }).catch((e: any) => ({ stdout: e.stdout || '' }));
      const report: HarnessReport = JSON.parse(stdout.trim());
      expect(report.completed).toBe(false);
      expect(report.error).toContain('boom');
    } finally {
      try {
        unlinkSync(harnessPath);
      } catch {}
    }
  });

  it('harness with no sink calls reports empty array', async () => {
    const target: FunctionTarget = {
      source_file: 'test.js',
      function_name: 'safeFn',
      line_start: 1,
      line_end: 3,
      function_source: `function safeFn(x) {\n  return x.toUpperCase();\n}`,
      language: 'javascript',
    };
    const injection: FunctionInjectionParams = {
      target_param: 'x',
      param_index: 0,
      other_params: [],
      sink_mocks: [],
    };
    const harness = generateHarness(target, injection, 'hello');

    const dir = mkdtempSync(join(tmpdir(), 'dst-test-'));
    const harnessPath = join(dir, 'harness.mjs');
    writeFileSync(harnessPath, harness);
    try {
      const { stdout } = await execFileAsync('node', [harnessPath], {
        timeout: 5000,
      });
      const report: HarnessReport = JSON.parse(stdout.trim());
      expect(report.completed).toBe(true);
      expect(report.sink_calls).toEqual([]);
      expect(report.return_value).toBe('"HELLO"');
    } finally {
      try {
        unlinkSync(harnessPath);
      } catch {}
    }
  });
});


// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

describe('encodeFunctionTarget / decodeFunctionTarget', () => {
  it('round-trips a FunctionTarget through encode/decode', () => {
    const ft: FunctionTarget = {
      source_file: 'src/app.js',
      function_name: 'leakyFetch',
      line_start: 10,
      line_end: 15,
      function_source: 'function leakyFetch() {}',
      language: 'javascript',
    };
    const encoded = encodeFunctionTarget(ft);
    expect(encoded.base_url).toBe('file://src/app.js');
    expect(encoded.path).toBe('/leakyFetch');

    const decoded = decodeFunctionTarget(encoded);
    expect(decoded).not.toBeNull();
    expect(decoded!.source_file).toBe('src/app.js');
    expect(decoded!.function_name).toBe('leakyFetch');
  });

  it('decodeFunctionTarget returns null for non-file URLs', () => {
    expect(decodeFunctionTarget({ base_url: 'https://example.com', path: '/fn' })).toBeNull();
  });
});

describe('encodeFunctionParams', () => {
  it('encodes injection params as DeliveryParams', () => {
    const fp: FunctionInjectionParams = {
      target_param: 'host',
      param_index: 0,
      other_params: [],
      sink_mocks: [{ module: 'global', method: 'fetch' }],
    };
    const encoded = encodeFunctionParams(fp);
    expect(encoded.method).toBe('CALL');
    expect(encoded.param).toBe('host');
  });
});


// ---------------------------------------------------------------------------
// FunctionChannel class
// ---------------------------------------------------------------------------

describe('FunctionChannel class', () => {
  it('deliver() executes harness and returns DeliveryResult with report', async () => {
    const channel = new FunctionChannel({ timeout_ms: 5000 });
    const target: FunctionTarget = {
      source_file: 'test.js',
      function_name: 'leakyFetch',
      line_start: 1,
      line_end: 4,
      function_source: `async function leakyFetch(host) {\n  const res = await fetch('https://' + host + '/api');\n  return res;\n}`,
      language: 'javascript',
    };
    const injection: FunctionInjectionParams = {
      target_param: 'host',
      param_index: 0,
      other_params: [],
      sink_mocks: [{ module: 'global', method: 'fetch' }],
    };
    channel.registerTarget(target, injection);

    const result = await channel.deliver(
      'dst-ssrf-probe.example.com',
      encodeFunctionTarget(target),
      encodeFunctionParams(injection),
    );

    expect(result.delivered).toBe(true);
    expect(result.status_code).toBe(200);
    const report: HarnessReport = JSON.parse(result.body);
    expect(report.completed).toBe(true);
    expect(report.sink_calls.length).toBeGreaterThanOrEqual(1);
    expect(report.sink_calls[0].canary_found).toBe(true);
  });

  it('deliver() returns 404 for unregistered target', async () => {
    const channel = new FunctionChannel();
    const result = await channel.deliver(
      'payload',
      { base_url: 'file://unknown.js', path: '/unknownFn' },
      { method: 'CALL', param: 'x' },
    );
    expect(result.delivered).toBe(false);
    expect(result.status_code).toBe(404);
    expect(result.error).toContain('not registered');
  });

  it('deliver() returns 400 for non-file target', async () => {
    const channel = new FunctionChannel();
    const result = await channel.deliver(
      'payload',
      { base_url: 'https://example.com', path: '/fn' },
      { method: 'CALL', param: 'x' },
    );
    expect(result.delivered).toBe(false);
    expect(result.status_code).toBe(400);
  });

  it('observe() detects canary in sink calls', () => {
    const channel = new FunctionChannel();
    const attackResult: DeliveryResult = {
      delivered: true,
      status_code: 200,
      body: JSON.stringify({
        completed: true,
        sink_calls: [{
          sink: 'global.fetch',
          args: ['https://dst-ssrf-probe.example.com/api', 'GET', '{}'],
          canary_found: true,
        }],
        elapsed_ms: 50,
      }),
      response_time_ms: 50,
      headers: {},
    };

    const obs = channel.observe(
      { type: 'content_match', pattern: 'dst-ssrf-probe', positive: true },
      attackResult,
    );
    expect(obs.signal_detected).toBe(true);
    expect(obs.confidence).toBe('high');
    expect(obs.evidence).toContain('dst-ssrf-probe');
    expect(obs.evidence).toContain('global.fetch');
  });

  it('observe() returns no signal when canary not found', () => {
    const channel = new FunctionChannel();
    const attackResult: DeliveryResult = {
      delivered: true,
      status_code: 200,
      body: JSON.stringify({
        completed: true,
        sink_calls: [{
          sink: 'global.fetch',
          args: ['https://safe-host.com/api', 'GET', '{}'],
          canary_found: false,
        }],
        elapsed_ms: 50,
      }),
      response_time_ms: 50,
      headers: {},
    };

    const obs = channel.observe(
      { type: 'content_match', pattern: 'dst-ssrf-probe', positive: true },
      attackResult,
    );
    expect(obs.signal_detected).toBe(false);
  });

  it('observe() rejects when canary in both baseline and attack (false proof prevention)', () => {
    const channel = new FunctionChannel();
    const report = {
      completed: true,
      sink_calls: [{
        sink: 'fetch',
        args: ['https://dst-ssrf-probe.example.com'],
        canary_found: true,
      }],
      elapsed_ms: 10,
    };
    const attack: DeliveryResult = {
      delivered: true,
      status_code: 200,
      body: JSON.stringify(report),
      response_time_ms: 10,
      headers: {},
    };
    const baseline: DeliveryResult = {
      delivered: true,
      status_code: 200,
      body: JSON.stringify(report),
      response_time_ms: 10,
      headers: {},
    };

    const obs = channel.observe(
      { type: 'content_match', pattern: 'dst-ssrf-probe', positive: true },
      attack,
      baseline,
    );
    expect(obs.signal_detected).toBe(false); // same in both = not payload-caused
    expect(obs.confidence).toBe('none');
  });

  it('observe() handles unparseable body gracefully', () => {
    const channel = new FunctionChannel();
    const attackResult: DeliveryResult = {
      delivered: true,
      status_code: 200,
      body: 'not json at all',
      response_time_ms: 50,
      headers: {},
    };

    const obs = channel.observe(
      { type: 'content_match', pattern: 'canary', positive: true },
      attackResult,
    );
    expect(obs.signal_detected).toBe(false);
    expect(obs.signal_type).toBe('none');
  });

  it('deliver() kills child on timeout and returns 408', async () => {
    const channel = new FunctionChannel({ timeout_ms: 500 });
    const target: FunctionTarget = {
      source_file: 'test.js',
      function_name: 'hang',
      line_start: 1,
      line_end: 3,
      function_source: `async function hang(x) { await new Promise(r => setTimeout(r, 999999)); }`,
      language: 'javascript',
    };
    const injection: FunctionInjectionParams = {
      target_param: 'x',
      param_index: 0,
      other_params: [],
      sink_mocks: [],
    };
    channel.registerTarget(target, injection);

    const result = await channel.deliver(
      'test',
      encodeFunctionTarget(target),
      encodeFunctionParams(injection),
    );
    expect(result.delivered).toBe(false);
    expect(result.status_code).toBe(408);
    expect(result.error).toContain('timed out');
  }, 10000);

  it('snapshot() returns correct channel state', () => {
    const channel = new FunctionChannel();
    const snap = channel.snapshot();
    expect(snap.channel_type).toBe('function');
    expect(snap.connected).toBe(true);
    expect(snap.last_request_time).toBeUndefined();
  });

  it('end-to-end: deliver() + observe() detects SSRF vulnerability', async () => {
    const channel = new FunctionChannel({ timeout_ms: 5000 });
    const target: FunctionTarget = {
      source_file: 'test.js',
      function_name: 'leakyFetch',
      line_start: 1,
      line_end: 4,
      function_source: `async function leakyFetch(host) {\n  const res = await fetch('https://' + host + '/api');\n  return res;\n}`,
      language: 'javascript',
    };
    const injection: FunctionInjectionParams = {
      target_param: 'host',
      param_index: 0,
      other_params: [],
      sink_mocks: [{ module: 'global', method: 'fetch' }],
    };
    channel.registerTarget(target, injection);

    const canary = 'dst-ssrf-proof-42';
    const deliveryResult = await channel.deliver(
      canary,
      encodeFunctionTarget(target),
      encodeFunctionParams(injection),
    );

    expect(deliveryResult.delivered).toBe(true);

    const observation = channel.observe(
      { type: 'content_match', pattern: canary, positive: true },
      deliveryResult,
    );

    expect(observation.signal_detected).toBe(true);
    expect(observation.confidence).toBe('high');
    expect(observation.signal_type).toBe('content_match');
  });
});


// ---------------------------------------------------------------------------
// buildFunctionTarget + buildInjectionParams (NeuralMap integration)
// ---------------------------------------------------------------------------

describe('buildFunctionTarget + buildInjectionParams', () => {
  let parser: InstanceType<typeof Parser>;

  beforeAll(async () => {
    await Parser.init();
    parser = new Parser();
    const wasmPath = path.resolve(
      __dirname,
      '../../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm',
    );
    const wasmBuffer = fs.readFileSync(wasmPath);
    const JavaScript = await Language.load(wasmBuffer);
    parser.setLanguage(JavaScript);
  });

  function parseAndMap(code: string, file = 'test.js'): NeuralMap {
    resetSequence();
    const tree = parser.parse(code);
    const { map } = buildNeuralMap(tree, code, file);
    tree.delete();
    return map;
  }

  it('extracts function target from NeuralMap for command injection', () => {
    const code = [
      "const { exec } = require('child_process');",
      'function runCommand(cmd) {',
      '  exec(cmd);',
      '}',
    ].join('\n');

    const map = parseAndMap(code);
    const results = verifyAll(map);

    // Find a CWE-78 (OS Command Injection) finding
    const cwe78 = results.find(r => r.cwe === 'CWE-78');
    // The code may detect it as CWE-78 or we can use any finding that involves exec
    const anyFinding = cwe78?.findings[0]
      ?? results.flatMap(r => r.findings).find(f =>
        f.sink.code.includes('exec') || f.sink.label.includes('exec'),
      );

    // If verifier didn't produce a finding, test the factory with a synthetic finding
    const finding = anyFinding ?? {
      source: { id: map.nodes.find(n => n.node_type === 'INGRESS')?.id ?? map.nodes[0]?.id ?? 'missing', label: 'cmd', line: 2, code: 'cmd' },
      sink: { id: 'sink_1', label: 'exec', line: 3, code: 'exec(cmd)' },
      missing: 'input validation',
      severity: 'critical' as const,
      description: 'Command injection via exec',
      fix: 'Sanitize input',
    };

    const target = buildFunctionTarget(map, finding);
    expect(target).not.toBeNull();
    expect(target!.function_name).toBe('runCommand');
    expect(target!.function_source).toContain('exec(cmd)');
    expect(target!.line_start).toBeGreaterThan(0);
    expect(target!.line_end).toBeGreaterThanOrEqual(target!.line_start);
  });

  it('builds injection params from finding', () => {
    const code = [
      "const { exec } = require('child_process');",
      'function runCommand(cmd) {',
      '  exec(cmd);',
      '}',
    ].join('\n');

    const map = parseAndMap(code);
    const results = verifyAll(map);

    const cwe78 = results.find(r => r.cwe === 'CWE-78');
    const anyFinding = cwe78?.findings[0]
      ?? results.flatMap(r => r.findings).find(f =>
        f.sink.code.includes('exec') || f.sink.label.includes('exec'),
      );

    const finding = anyFinding ?? {
      source: { id: map.nodes.find(n => n.node_type === 'INGRESS')?.id ?? map.nodes[0]?.id ?? 'missing', label: 'cmd', line: 2, code: 'cmd' },
      sink: { id: 'sink_1', label: 'exec', line: 3, code: 'exec(cmd)' },
      missing: 'input validation',
      severity: 'critical' as const,
      description: 'Command injection via exec',
      fix: 'Sanitize input',
    };

    const params = buildInjectionParams(map, finding, [
      { module: 'child_process', method: 'exec' },
    ]);
    expect(params).not.toBeNull();
    expect(params!.target_param).toBe('cmd');
    expect(params!.param_index).toBe(0);
    expect(params!.sink_mocks).toHaveLength(1);
    expect(params!.sink_mocks[0].module).toBe('child_process');
  });

  it('returns null when source node not found', () => {
    const code = 'function noop() {}';
    const map = parseAndMap(code);

    const finding = {
      source: { id: 'nonexistent_id', label: 'x', line: 1, code: 'x' },
      sink: { id: 'sink_1', label: 'y', line: 1, code: 'y' },
      missing: 'n/a',
      severity: 'low' as const,
      description: 'test',
      fix: 'test',
    };

    expect(buildFunctionTarget(map, finding)).toBeNull();
    expect(buildInjectionParams(map, finding, [])).toBeNull();
  });

  it('picks the tightest enclosing function for nested functions', () => {
    const code = [
      'function outer(a) {',
      '  function inner(b) {',
      '    eval(b);',
      '  }',
      '  inner(a);',
      '}',
    ].join('\n');

    const map = parseAndMap(code);

    // Find the inner STRUCTURAL/function node
    const innerNode = map.nodes.find(n =>
      n.node_type === 'STRUCTURAL' && n.label === 'inner',
    );
    expect(innerNode).toBeDefined();

    // Find the outer STRUCTURAL/function node
    const outerNode = map.nodes.find(n =>
      n.node_type === 'STRUCTURAL' && n.label === 'outer',
    );
    expect(outerNode).toBeDefined();

    // Use the innerNode itself as the source — it IS inside inner's range
    // and also inside outer's range, so tightest-fit should pick inner
    const finding = {
      source: { id: innerNode!.id, label: 'b', line: innerNode!.line_start, code: 'eval(b)' },
      sink: { id: 'sink_1', label: 'eval', line: 3, code: 'eval(b)' },
      missing: 'input validation',
      severity: 'critical' as const,
      description: 'eval injection',
      fix: 'Avoid eval',
    };

    const target = buildFunctionTarget(map, finding);
    expect(target).not.toBeNull();
    // Should NOT pick outer — must be inner or a tighter sub-function
    expect(target!.function_name).not.toBe('outer');
    // The line range should be within inner's range (not the full outer)
    expect(target!.line_start).toBeGreaterThanOrEqual(innerNode!.line_start);
    expect(target!.line_end).toBeLessThanOrEqual(innerNode!.line_end);
    // Function source should contain eval
    expect(target!.function_source).toContain('eval');
  });

  it('extracts params via regex when param_names not on node', () => {
    const code = [
      "const { exec } = require('child_process');",
      'function runCommand(cmd) {',
      '  exec(cmd);',
      '}',
    ].join('\n');

    const map = parseAndMap(code);

    // Find the STRUCTURAL function node and strip param_names for this test
    const funcNode = map.nodes.find(
      n => n.node_type === 'STRUCTURAL' && n.label === 'runCommand',
    );
    expect(funcNode).toBeDefined();

    // Save and clear param_names to force regex extraction
    const saved = funcNode!.param_names;
    funcNode!.param_names = undefined;

    const finding = {
      source: { id: funcNode!.id, label: 'cmd', line: 2, code: 'cmd' },
      sink: { id: 'sink_1', label: 'exec', line: 3, code: 'exec(cmd)' },
      missing: 'input validation',
      severity: 'critical' as const,
      description: 'Command injection',
      fix: 'Sanitize',
    };

    const params = buildInjectionParams(map, finding, [
      { module: 'child_process', method: 'exec' },
    ]);
    expect(params).not.toBeNull();
    expect(params!.target_param).toBe('cmd');

    // Restore
    funcNode!.param_names = saved;
  });
});
