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
import { generateHarness } from './function-channel.js';
import type {
  FunctionTarget,
  FunctionInjectionParams,
  HarnessReport,
} from './function-channel.js';

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
