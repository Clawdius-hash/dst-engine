/**
 * FunctionChannel — white-box runtime verification via function extraction.
 *
 * Extracts vulnerable functions from source code, wraps them in a sandbox
 * with mocked sinks, executes in a child_process, and checks if the
 * canary payload reached the dangerous sink.
 *
 * Task 1: Types + generateHarness() only. FunctionChannel class in Task 2.
 */

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

function buildArgList(injection: FunctionInjectionParams, canaryExpr: string): string[] {
  // Figure out total param count
  const totalParams = Math.max(
    injection.param_index + 1,
    injection.other_params.length > 0
      ? Math.max(...injection.other_params.map(p => {
          // other_params don't have indices, they're in order excluding target
          return 0; // handled below
        })) + 1
      : injection.param_index + 1,
  );

  // Build ordered args: the canary goes at param_index, other_params fill the rest
  const args: string[] = [];
  let otherIdx = 0;

  for (let i = 0; i < totalParams; i++) {
    if (i === injection.param_index) {
      args.push(canaryExpr);
    } else if (otherIdx < injection.other_params.length) {
      args.push(injection.other_params[otherIdx].default_value);
      otherIdx++;
    } else {
      args.push('undefined');
    }
  }

  return args;
}
