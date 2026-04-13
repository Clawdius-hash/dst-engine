/**
 * FunctionChannel harness generator tests.
 *
 * These tests are NOT string-comparison tests. Each test generates a real .mjs
 * harness file, writes it to a temp directory, and executes it under `node`.
 * The harness must produce valid JSON (HarnessReport) on stdout.
 */

import { describe, it, expect } from 'vitest';
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
} from './function-channel.js';
import type {
  FunctionTarget,
  FunctionInjectionParams,
  HarnessReport,
} from './function-channel.js';
import type { DeliveryResult } from './channels.js';

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
