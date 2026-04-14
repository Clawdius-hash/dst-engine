/**
 * FunctionChannel — white-box runtime verification via function extraction.
 *
 * Extracts vulnerable functions from source code, wraps them in a sandbox
 * with mocked sinks, executes in a child_process, and checks if the
 * canary payload reached the dangerous sink.
 */

import { execFile } from 'child_process';
import { mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { promisify } from 'util';
import type {
  Channel,
  DeliveryTarget,
  DeliveryParams,
  DeliveryResult,
  ObservationResult,
  ChannelSnapshot,
} from './channels.js';
import type { Finding } from '../verifier/types.js';
import type { NeuralMap, NeuralMapNode } from '../types.js';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FunctionTarget {
  source_file: string;
  function_name: string;
  line_start: number;
  line_end: number;
  function_source: string;
  language: 'javascript' | 'typescript' | 'python';
}

export interface FunctionInjectionParams {
  target_param: string;
  param_index: number;
  other_params: Array<{ name: string; default_value: string }>;
  sink_mocks: SinkMockSpec[];
  /** Pre-computed nested object shape for the target parameter */
  param_shape?: Record<string, any> | string;
}

export interface SinkMockSpec {
  module: string;        // 'global', 'child_process', 'fs', 'http', 'https'
  method: string;        // 'fetch', 'exec', 'writeFile', 'request'
}

export interface HarnessReport {
  completed: boolean;
  sink_calls: Array<{
    sink: string;
    args: string[];
    canary_found: boolean;
  }>;
  return_value?: string;
  error?: string;
  elapsed_ms: number;
}

/**
 * Convert a callee chain like ['req', 'headers', 'host'] into a nested object
 * { headers: { host: payload } } for harness parameter construction.
 * chain[0] is the parameter name itself. chain[1..n] is the nesting path.
 */
export function chainToObject(
  chain: string[],
  funcParams: string[],
  payload: string,
): Record<string, any> | string {
  if (chain.length <= 1) return payload;
  if (!funcParams.includes(chain[0])) return payload;
  return chain.slice(1).reduceRight<any>(
    (acc, key) => ({ [key]: acc }),
    payload,
  );
}

// ---------------------------------------------------------------------------
// Harness generator
// ---------------------------------------------------------------------------

/**
 * Generates a self-contained .mjs harness file that:
 * 1. Defines recording mocks for all dangerous sinks
 * 2. Embeds the extracted function source
 * 3. Calls the function with the canary payload injected at the target param
 * 4. Catches errors (never crashes)
 * 5. Writes a HarnessReport JSON to stdout
 */
export function generateHarness(
  target: FunctionTarget,
  injection: FunctionInjectionParams,
  canary: string,
): string {
  const canaryEscaped = escapeForJS(canary);

  // Build the argument list for calling the function
  const args = buildArgList(injection, canaryEscaped);

  // Determine which modules need mocking
  const mockedModules = new Set(injection.sink_mocks.map(s => s.module));

  // Build the harness source
  const lines: string[] = [];

  // -- Preamble: sink call recorder and canary
  lines.push(`// Auto-generated DST harness — do not edit`);
  lines.push(`const __canary = ${JSON.stringify(canary)};`);
  lines.push(`const __sink_calls = [];`);
  lines.push(``);

  // -- Helper: record a sink call and check for canary
  lines.push(`function __recordSink(sinkName, args) {`);
  lines.push(`  const strArgs = args.map(a => {`);
  lines.push(`    try { return typeof a === 'string' ? a : JSON.stringify(a); }`);
  lines.push(`    catch { return String(a); }`);
  lines.push(`  });`);
  lines.push(`  const canary_found = strArgs.some(a => a && a.includes(__canary));`);
  lines.push(`  __sink_calls.push({ sink: sinkName, args: strArgs, canary_found });`);
  lines.push(`}`);
  lines.push(``);

  // -- Mock global.fetch
  if (mockedModules.has('global') || injection.sink_mocks.some(s => s.method === 'fetch')) {
    lines.push(`// Mock global fetch`);
    lines.push(`globalThis.fetch = async function __mockFetch(input, init) {`);
    lines.push(`  const url = (typeof input === 'string') ? input : (input instanceof URL ? input.href : String(input));`);
    lines.push(`  const method = (init && init.method) ? init.method : 'GET';`);
    lines.push(`  const headers = (init && init.headers) ? init.headers : {};`);
    lines.push(`  __recordSink('global.fetch', [url, method, JSON.stringify(headers)]);`);
    lines.push(`  return {`);
    lines.push(`    ok: true,`);
    lines.push(`    status: 200,`);
    lines.push(`    statusText: 'OK',`);
    lines.push(`    headers: { get: () => null },`);
    lines.push(`    json: async () => ({}),`);
    lines.push(`    text: async () => '',`);
    lines.push(`    arrayBuffer: async () => new ArrayBuffer(0),`);
    lines.push(`  };`);
    lines.push(`};`);
    lines.push(``);
  }

  // -- Mock modules (child_process, fs, http, https)
  lines.push(`// Mock module registry`);
  lines.push(`const __mock_modules = {};`);
  lines.push(``);

  if (mockedModules.has('child_process')) {
    lines.push(`__mock_modules['child_process'] = {`);
    lines.push(`  exec: function(cmd, ...rest) { __recordSink('child_process.exec', [cmd, ...rest.map(String)]); const cb = rest.find(r => typeof r === 'function'); if (cb) cb(null, '', ''); },`);
    lines.push(`  execSync: function(cmd, opts) { __recordSink('child_process.execSync', [cmd]); return Buffer.from(''); },`);
    lines.push(`  execFile: function(file, args, ...rest) { __recordSink('child_process.execFile', [file, ...(args||[])]); const cb = rest.find(r => typeof r === 'function'); if (cb) cb(null, '', ''); },`);
    lines.push(`  spawn: function(cmd, args) { __recordSink('child_process.spawn', [cmd, ...(args||[])]); return { stdout: { on(){} }, stderr: { on(){} }, on(e,cb){ if(e==='close') setTimeout(()=>cb(0),0); } }; },`);
    lines.push(`};`);
    lines.push(``);
  }

  if (mockedModules.has('fs')) {
    lines.push(`__mock_modules['fs'] = {`);
    lines.push(`  writeFile: function(path, data, ...rest) { __recordSink('fs.writeFile', [path, data]); const cb = rest.find(r => typeof r === 'function'); if (cb) cb(null); },`);
    lines.push(`  writeFileSync: function(path, data) { __recordSink('fs.writeFileSync', [path, data]); },`);
    lines.push(`  readFile: function(path, ...rest) { __recordSink('fs.readFile', [path]); const cb = rest.find(r => typeof r === 'function'); if (cb) cb(null, ''); },`);
    lines.push(`  readFileSync: function(path) { __recordSink('fs.readFileSync', [path]); return ''; },`);
    lines.push(`  appendFile: function(path, data, ...rest) { __recordSink('fs.appendFile', [path, data]); const cb = rest.find(r => typeof r === 'function'); if (cb) cb(null); },`);
    lines.push(`  unlink: function(path, cb) { __recordSink('fs.unlink', [path]); if (cb) cb(null); },`);
    lines.push(`};`);
    lines.push(``);
  }

  if (mockedModules.has('http')) {
    lines.push(`__mock_modules['http'] = {`);
    lines.push(`  request: function(opts, cb) { __recordSink('http.request', [typeof opts === 'string' ? opts : JSON.stringify(opts)]); return { on(){}, write(){}, end(){} }; },`);
    lines.push(`  get: function(opts, cb) { __recordSink('http.get', [typeof opts === 'string' ? opts : JSON.stringify(opts)]); return { on(){}, end(){} }; },`);
    lines.push(`};`);
    lines.push(``);
  }

  if (mockedModules.has('https')) {
    lines.push(`__mock_modules['https'] = {`);
    lines.push(`  request: function(opts, cb) { __recordSink('https.request', [typeof opts === 'string' ? opts : JSON.stringify(opts)]); return { on(){}, write(){}, end(){} }; },`);
    lines.push(`  get: function(opts, cb) { __recordSink('https.get', [typeof opts === 'string' ? opts : JSON.stringify(opts)]); return { on(){}, end(){} }; },`);
    lines.push(`};`);
    lines.push(``);
  }

  // -- Mock require() for ESM context
  lines.push(`// Mock require for ESM context — intercepts require('child_process') etc.`);
  lines.push(`const __origRequire = typeof require !== 'undefined' ? require : null;`);
  lines.push(`globalThis.require = (id) => {`);
  lines.push(`  if (__mock_modules[id]) return __mock_modules[id];`);
  lines.push(`  if (__origRequire) return __origRequire(id);`);
  lines.push(`  throw new Error(\`Cannot require('\${id}') in harness\`);`);
  lines.push(`};`);
  lines.push(``);

  // -- Embed function source
  lines.push(`// ---- Embedded function source ----`);
  lines.push(target.function_source);
  lines.push(`// ---- End embedded source ----`);
  lines.push(``);

  // -- Execution wrapper: async IIFE with try/catch, outputs HarnessReport
  const isAsync = target.function_source.includes('async ');
  const callExpr = `${target.function_name}(${args.join(', ')})`;

  lines.push(`// Execute and report`);
  lines.push(`const __start = Date.now();`);
  lines.push(`(async () => {`);
  lines.push(`  let __completed = false;`);
  lines.push(`  let __return_value = undefined;`);
  lines.push(`  let __error = undefined;`);
  lines.push(`  try {`);
  lines.push(`    const __result = ${isAsync ? 'await ' : ''}${callExpr};`);
  lines.push(`    __completed = true;`);
  lines.push(`    try { __return_value = JSON.stringify(__result); } catch { __return_value = String(__result); }`);
  lines.push(`  } catch (e) {`);
  lines.push(`    __completed = false;`);
  lines.push(`    __error = e && e.message ? e.message : String(e);`);
  lines.push(`  }`);
  lines.push(`  const __report = {`);
  lines.push(`    completed: __completed,`);
  lines.push(`    sink_calls: __sink_calls,`);
  lines.push(`    elapsed_ms: Date.now() - __start,`);
  lines.push(`  };`);
  lines.push(`  if (__return_value !== undefined) __report.return_value = __return_value;`);
  lines.push(`  if (__error !== undefined) __report.error = __error;`);
  lines.push(`  process.stdout.write(JSON.stringify(__report));`);
  lines.push(`})();`);

  return lines.join('\n');
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeForJS(s: string): string {
  return JSON.stringify(s);
}

/**
 * Serialize a param_shape object into a JS expression string,
 * replacing the placeholder '__CANARY__' with the actual canary expression.
 */
function shapeToExpr(shape: Record<string, any> | string, canaryExpr: string): string {
  if (typeof shape === 'string') {
    return shape === '__CANARY__' ? canaryExpr : JSON.stringify(shape);
  }
  const entries = Object.entries(shape).map(([k, v]) => {
    const valExpr = shapeToExpr(v, canaryExpr);
    return `${JSON.stringify(k)}: ${valExpr}`;
  });
  return `{ ${entries.join(', ')} }`;
}

function buildArgList(injection: FunctionInjectionParams, canaryExpr: string): string[] {
  // Total params = other_params (non-target) + 1 (target), but at least param_index + 1
  const totalParams = Math.max(
    injection.param_index + 1,
    injection.other_params.length + 1,   // other_params excludes target, so +1
  );

  // Build ordered args: the canary goes at param_index, other_params fill the rest
  const args: string[] = [];
  let otherIdx = 0;

  for (let i = 0; i < totalParams; i++) {
    if (i === injection.param_index) {
      // If param_shape is an object, build a nested object expression with canary inside
      if (injection.param_shape && typeof injection.param_shape === 'object') {
        args.push(shapeToExpr(injection.param_shape, canaryExpr));
      } else {
        args.push(canaryExpr);
      }
    } else if (otherIdx < injection.other_params.length) {
      args.push(injection.other_params[otherIdx].default_value);
      otherIdx++;
    } else {
      args.push('undefined');
    }
  }

  return args;
}


// ---------------------------------------------------------------------------
// Encoding helpers — map FunctionTarget/FunctionInjectionParams to Channel types
// ---------------------------------------------------------------------------

export function encodeFunctionTarget(ft: FunctionTarget): DeliveryTarget {
  return { base_url: `file://${ft.source_file}`, path: `/${ft.function_name}` };
}

export function decodeFunctionTarget(dt: DeliveryTarget): { source_file: string; function_name: string } | null {
  if (!dt.base_url.startsWith('file://')) return null;
  return { source_file: dt.base_url.slice(7), function_name: dt.path.slice(1) };
}

export function encodeFunctionParams(fp: FunctionInjectionParams): DeliveryParams {
  return { method: 'CALL', param: fp.target_param };
}


// ---------------------------------------------------------------------------
// Factory functions — extract FunctionTarget + FunctionInjectionParams from NeuralMap
// ---------------------------------------------------------------------------

/**
 * Given a NeuralMap and a Finding, extract the function containing the vulnerability.
 *
 * Strategy:
 *   1. Find the source node from the finding
 *   2. Find the enclosing STRUCTURAL/function node (tightest fit)
 *   3. Extract the function source from the NeuralMap's source_code
 */
export function buildFunctionTarget(map: NeuralMap, finding: Finding): FunctionTarget | null {
  // 1. Find the source node
  const sourceNode = map.nodes.find(n => n.id === finding.source.id);
  if (!sourceNode) return null;

  // 2. Find enclosing STRUCTURAL/function nodes
  let candidates = map.nodes.filter(n =>
    n.node_type === 'STRUCTURAL' &&
    n.node_subtype.includes('function') &&
    n.line_start <= sourceNode.line_start &&
    (n.line_end >= sourceNode.line_start || n.line_end === 0),
  );

  if (candidates.length === 0) return null;

  // Prefer multi-line functions over single-line stubs when both exist
  // (single-line STRUCTURAL/function nodes are typically anonymous wrappers
  //  that don't contain a complete function body)
  const multiLine = candidates.filter(n => n.line_end > n.line_start);
  if (multiLine.length > 0) candidates = multiLine;

  // 3. Pick tightest enclosing function (smallest line range)
  const enclosing = candidates.reduce((best, curr) => {
    const bestRange = best.line_end - best.line_start;
    const currRange = curr.line_end - curr.line_start;
    // line_end === 0 means single-line — prefer nodes with actual ranges
    if (best.line_end === 0 && curr.line_end !== 0) return curr;
    if (curr.line_end === 0 && best.line_end !== 0) return best;
    return currRange < bestRange ? curr : best;
  });

  // 4. Extract function source from the source code
  const lines = map.source_code.split('\n');
  const functionSource = lines.slice(enclosing.line_start - 1, enclosing.line_end).join('\n');

  return {
    source_file: map.source_file,
    function_name: enclosing.label,
    line_start: enclosing.line_start,
    line_end: enclosing.line_end,
    function_source: functionSource,
    language: (enclosing.language as FunctionTarget['language']) || 'javascript',
  };
}

/**
 * Given a NeuralMap, Finding, and SinkMockSpec array, build injection params.
 *
 * Strategy:
 *   1. Find the source node from the finding
 *   2. Get param_names from the enclosing STRUCTURAL/function node
 *   3. If no param_names on the node, try regex extraction from function source
 *   4. Determine which parameter carries the taint
 *   5. Build default values for other params
 */
export function buildInjectionParams(
  map: NeuralMap,
  finding: Finding,
  sinkMocks: SinkMockSpec[],
): FunctionInjectionParams | null {
  // 1. Find the source node
  const sourceNode = map.nodes.find(n => n.id === finding.source.id);
  if (!sourceNode) return null;

  // 2. Find enclosing function node (same logic as buildFunctionTarget)
  let candidates2 = map.nodes.filter(n =>
    n.node_type === 'STRUCTURAL' &&
    n.node_subtype.includes('function') &&
    n.line_start <= sourceNode.line_start &&
    (n.line_end >= sourceNode.line_start || n.line_end === 0),
  );

  if (candidates2.length === 0) return null;

  // Prefer multi-line functions over single-line stubs
  const multiLine2 = candidates2.filter(n => n.line_end > n.line_start);
  if (multiLine2.length > 0) candidates2 = multiLine2;

  const enclosing = candidates2.reduce((best, curr) => {
    const bestRange = best.line_end - best.line_start;
    const currRange = curr.line_end - curr.line_start;
    if (best.line_end === 0 && curr.line_end !== 0) return curr;
    if (curr.line_end === 0 && best.line_end !== 0) return best;
    return currRange < bestRange ? curr : best;
  });

  // 3. Get parameter names — prefer AST-extracted param_names on the node
  let paramNames: string[] = enclosing.param_names ?? [];

  // If no param_names on the node, try regex extraction from function source
  if (paramNames.length === 0) {
    const lines = map.source_code.split('\n');
    const funcSource = lines.slice(enclosing.line_start - 1, enclosing.line_end).join('\n');
    paramNames = extractParamNamesFromSource(funcSource);
  }

  if (paramNames.length === 0) return null;

  // 4. Determine which parameter carries the taint
  //    Match against source node's label or code_snapshot
  const sourceLabel = sourceNode.label.toLowerCase();
  const sourceCode = sourceNode.code_snapshot.toLowerCase();

  let targetIndex = -1;
  for (let i = 0; i < paramNames.length; i++) {
    const pLower = paramNames[i].toLowerCase();
    if (sourceLabel.includes(pLower) || sourceCode.includes(pLower)) {
      targetIndex = i;
      break;
    }
  }

  // Fallback: if no match found, use first parameter (most common for simple functions)
  if (targetIndex === -1) {
    targetIndex = 0;
  }

  // 5. Build other_params with default values
  const otherParams: Array<{ name: string; default_value: string }> = [];
  for (let i = 0; i < paramNames.length; i++) {
    if (i !== targetIndex) {
      otherParams.push({ name: paramNames[i], default_value: 'undefined' });
    }
  }

  // 6. Compute parameter object shape from source node's callee chain
  let paramShape: Record<string, any> | string | undefined;
  if (sourceNode.callee_chain && sourceNode.callee_chain.length > 1) {
    paramShape = chainToObject(sourceNode.callee_chain, paramNames, '__CANARY__');
  }

  return {
    target_param: paramNames[targetIndex],
    param_index: targetIndex,
    other_params: otherParams,
    sink_mocks: sinkMocks,
    param_shape: paramShape,
  };
}

/**
 * Extract parameter names from function source using regex.
 * Handles: function declarations, arrow functions, method shorthand.
 */
function extractParamNamesFromSource(source: string): string[] {
  const patterns = [
    /function\s+\w+\s*\(([^)]*)\)/,     // function foo(a, b)
    /\(([^)]*)\)\s*=>/,                   // (a, b) =>
    /\(([^)]*)\)\s*\{/,                   // (a, b) {  (method shorthand / anonymous)
  ];

  for (const re of patterns) {
    const m = source.match(re);
    if (m && m[1] !== undefined) {
      const raw = m[1].trim();
      if (raw === '') return [];
      return raw.split(',').map(p => {
        // Handle default values: "a = 5" => "a"
        // Handle rest params: "...args" => "args"
        // Handle destructuring: ignore for now (return raw)
        let name = p.trim().split('=')[0].trim();
        if (name.startsWith('...')) name = name.slice(3);
        return name;
      }).filter(n => n.length > 0);
    }
  }

  return [];
}

// ---------------------------------------------------------------------------
// FunctionChannel — implements Channel for function-level verification
// ---------------------------------------------------------------------------

export class FunctionChannel implements Channel {
  readonly name = 'function';
  private timeoutMs: number;
  private keepHarness: boolean;
  private lastRequestTime?: number;
  private targetRegistry = new Map<string, FunctionTarget>();
  private injectionRegistry = new Map<string, FunctionInjectionParams>();

  constructor(options?: { timeout_ms?: number; keep_harness?: boolean }) {
    this.timeoutMs = options?.timeout_ms ?? 5000;
    this.keepHarness = options?.keep_harness ?? false;
  }

  /**
   * Register a function target and its injection params.
   * Must be called before deliver() for the corresponding target.
   */
  registerTarget(target: FunctionTarget, params: FunctionInjectionParams): void {
    const key = `${target.source_file}::${target.function_name}`;
    this.targetRegistry.set(key, target);
    this.injectionRegistry.set(key, params);
  }

  // ── Delivery ────────────────────────────────────────────────────────

  async deliver(
    payload: string,
    target: DeliveryTarget,
    params: DeliveryParams,
  ): Promise<DeliveryResult> {
    const decoded = decodeFunctionTarget(target);
    if (!decoded) {
      return {
        delivered: false,
        status_code: 400,
        body: '',
        response_time_ms: 0,
        headers: {},
        error: `Invalid function target: ${target.base_url}`,
      };
    }

    const key = `${decoded.source_file}::${decoded.function_name}`;
    const funcTarget = this.targetRegistry.get(key);
    const injection = this.injectionRegistry.get(key);

    if (!funcTarget || !injection) {
      return {
        delivered: false,
        status_code: 404,
        body: '',
        response_time_ms: 0,
        headers: {},
        error: `Target not registered: ${key}`,
      };
    }

    // Generate the harness source
    const harnessSource = generateHarness(funcTarget, injection, payload);

    // Write to temp file
    const dir = mkdtempSync(join(tmpdir(), 'dst-harness-'));
    const ext = funcTarget.language === 'typescript' ? '.ts' : '.mjs';
    const harnessPath = join(dir, `harness${ext}`);
    writeFileSync(harnessPath, harnessSource);

    const start = performance.now();
    try {
      const cmd = harnessPath.endsWith('.ts') ? 'npx' : 'node';
      const args = harnessPath.endsWith('.ts') ? ['tsx', harnessPath] : [harnessPath];
      const { stdout } = await execFileAsync(cmd, args, {
        timeout: this.timeoutMs,
      });

      const elapsed = performance.now() - start;
      this.lastRequestTime = Date.now();

      return {
        delivered: true,
        status_code: 200,
        body: stdout.trim(),
        response_time_ms: Math.round(elapsed),
        headers: {},
      };
    } catch (err: unknown) {
      const elapsed = performance.now() - start;
      this.lastRequestTime = Date.now();

      // Check if the process was killed (timeout)
      if (err && typeof err === 'object' && 'killed' in err && (err as any).killed) {
        return {
          delivered: false,
          status_code: 408,
          body: '',
          response_time_ms: Math.round(elapsed),
          headers: {},
          error: `Harness execution timed out after ${this.timeoutMs}ms`,
        };
      }

      // Process exited with non-zero but may have produced stdout (e.g. uncaught error after report)
      const stdout = (err as any)?.stdout;
      if (stdout && typeof stdout === 'string' && stdout.trim()) {
        // Try to parse — the harness may have written the report before crashing
        try {
          JSON.parse(stdout.trim());
          return {
            delivered: true,
            status_code: 200,
            body: stdout.trim(),
            response_time_ms: Math.round(elapsed),
            headers: {},
          };
        } catch {
          // stdout wasn't valid JSON, fall through to error
        }
      }

      const message = err instanceof Error ? err.message : String(err);
      return {
        delivered: false,
        status_code: 500,
        body: '',
        response_time_ms: Math.round(elapsed),
        headers: {},
        error: message,
      };
    } finally {
      if (!this.keepHarness) {
        try { unlinkSync(harnessPath); } catch { /* ignore */ }
        try { rmdirSync(dir); } catch { /* ignore */ }
      }
    }
  }

  // ── Observation / Oracle evaluation ─────────────────────────────────

  observe(
    oracle: { type: string; pattern: string; positive: boolean },
    attackResult: DeliveryResult,
    baselineResult?: DeliveryResult,
  ): ObservationResult {
    // Parse HarnessReport from the attack result body
    let attackReport: HarnessReport | null = null;
    try {
      if (attackResult.body) {
        attackReport = JSON.parse(attackResult.body) as HarnessReport;
      }
    } catch {
      return {
        signal_detected: false,
        signal_type: 'none',
        evidence: 'Failed to parse HarnessReport from attack result body',
        confidence: 'none',
      };
    }

    if (!attackReport) {
      return {
        signal_detected: false,
        signal_type: 'none',
        evidence: 'No HarnessReport in attack result body',
        confidence: 'none',
      };
    }

    // Parse baseline report if present
    let baselineReport: HarnessReport | null = null;
    if (baselineResult?.body) {
      try {
        baselineReport = JSON.parse(baselineResult.body) as HarnessReport;
      } catch {
        // Baseline parse failure is not fatal — just means no baseline comparison
      }
    }

    // Check if the canary (oracle.pattern) appears in any sink call args
    const canaryInAttack = attackReport.sink_calls.some(
      sc => sc.canary_found || sc.args.some(a => a && a.includes(oracle.pattern)),
    );

    // Baseline comparison: if canary appears in both, it's not payload-caused
    const canaryInBaseline = baselineReport
      ? baselineReport.sink_calls.some(
          sc => sc.canary_found || sc.args.some(a => a && a.includes(oracle.pattern)),
        )
      : false;

    if (canaryInAttack && canaryInBaseline) {
      return {
        signal_detected: false,
        signal_type: 'content_match',
        evidence: `Canary "${oracle.pattern}" found in BOTH attack and baseline sink calls — not payload-caused`,
        confidence: 'none',
      };
    }

    if (canaryInAttack) {
      // Find the specific sink call for evidence
      const matchingSink = attackReport.sink_calls.find(
        sc => sc.canary_found || sc.args.some(a => a && a.includes(oracle.pattern)),
      );
      return {
        signal_detected: true,
        signal_type: 'content_match',
        evidence: matchingSink
          ? `Canary "${oracle.pattern}" reached sink ${matchingSink.sink} with args: ${matchingSink.args.join(', ')}`
          : `Canary "${oracle.pattern}" found in sink calls`,
        confidence: 'high',
      };
    }

    return {
      signal_detected: false,
      signal_type: 'content_match',
      evidence: `Canary "${oracle.pattern}" not found in any sink calls`,
      confidence: 'none',
    };
  }

  // ── Snapshot ────────────────────────────────────────────────────────

  snapshot(): ChannelSnapshot {
    return {
      channel_type: 'function',
      connected: true,
      last_request_time: this.lastRequestTime,
    };
  }
}
