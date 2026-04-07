/**
 * CWE Verification Stress Tests
 *
 * Tests all 13 hand-written CWE verifiers in verifier.ts against
 * synthetic NeuralMap structures. Each CWE gets:
 *   1. VULNERABLE: code that SHOULD trigger the CWE (holds=false, findings>0)
 *   2. SAFE: code that should NOT trigger the CWE (holds=true, findings=0)
 *
 * Additional edge-case tests probe boundary conditions in verifier logic.
 *
 * NOTE: CWE-94 (Code Injection), CWE-352 (CSRF), and CWE-1321 (Prototype
 * Pollution) are now registered in the CWE_REGISTRY (added for language-agnostic
 * coverage). CWE-94/eval is also partially covered by CWE-502.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { verify, verifyAll, registeredCWEs, formatReport } from './verifier';
import { createNode, createNeuralMap, resetSequence } from './types';
import type { NeuralMap, NeuralMapNode } from './types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildMap(code: string, nodes: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap('test.js', code);
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

/** Log a one-line CWE test result */
function logResult(
  cwe: string,
  name: string,
  vulnResult: { holds: boolean; findings: { length: number } },
  safeResult: { holds: boolean; findings: { length: number } },
) {
  const vulnOk = !vulnResult.holds && vulnResult.findings.length > 0;
  const safeOk = safeResult.holds && safeResult.findings.length === 0;
  const vulnMark = vulnOk ? 'holds=false OK' : `BUG holds=${vulnResult.holds} findings=${vulnResult.findings.length}`;
  const safeMark = safeOk ? 'holds=true OK' : `BUG holds=${safeResult.holds} findings=${safeResult.findings.length}`;
  console.log(`${cwe} (${name}): VULNERABLE -> ${vulnMark} | SAFE -> ${safeMark}`);
}

// ---------------------------------------------------------------------------
// CWE-89: SQL Injection
// ---------------------------------------------------------------------------

describe('CWE-89: SQL Injection (stress)', () => {
  it('VULNERABLE: template literal SQL with user input', () => {
    const map = buildMap(
      'app.post("/api/login", (req, res) => { db.query(`SELECT * FROM users WHERE email = \'${req.body.email}\'`); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.email',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.email',
          attack_surface: ['user_input'],
          data_out: [{ name: 'email', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'PII' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query(`SELECT * FROM users WHERE email = \'${req.body.email}\'`)',
          attack_surface: ['sql_sink'],
          data_in: [{ name: 'email', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'PII' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
  });

  it('SAFE: parameterized query with $1 placeholders', () => {
    const map = buildMap(
      'app.post("/api/login", (req, res) => { db.query("SELECT * FROM users WHERE email = $1", [req.body.email]); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.email',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.email',
          attack_surface: ['user_input'],
          data_out: [{ name: 'email', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'PII' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query("SELECT * FROM users WHERE email = $1", [req.body.email])',
          attack_surface: ['sql_sink'],
          data_in: [{ name: 'email', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'PII' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: raw exec() call with concatenation', () => {
    const map = buildMap(
      'pool.execute("INSERT INTO logs VALUES (" + userInput + ")")',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'userInput',
          node_subtype: 'http_param',
          code_snapshot: 'userInput',
          attack_surface: ['user_input'],
          data_out: [{ name: 'userInput', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'pool.execute()',
          node_subtype: 'database',
          code_snapshot: 'pool.execute("INSERT INTO logs VALUES (" + userInput + ")")',
          attack_surface: [],
          data_in: [{ name: 'userInput', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('FIXED: prepared statement with single ? placeholder is correctly recognized', () => {
    // Previously a BUG: The verifier regex /\?\s*,/ required ? followed by comma.
    // A single-placeholder query like VALUES (?) has ? followed by ), not comma.
    // FIX: regex changed to /\?\s*[,)]/ which matches both single and multi-placeholder queries.
    const map = buildMap(
      'pool.execute("INSERT INTO logs VALUES (?)", [userInput])',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'userInput',
          node_subtype: 'http_param',
          code_snapshot: 'userInput',
          attack_surface: ['user_input'],
          data_out: [{ name: 'userInput', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'pool.execute()',
          node_subtype: 'database',
          code_snapshot: 'pool.execute("INSERT INTO logs VALUES (?)", [userInput])',
          attack_surface: [],
          data_in: [{ name: 'userInput', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    // FIXED: Single ? placeholder now correctly recognized as parameterized query
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: prepared statement with multiple ? placeholders (has ?, pattern)', () => {
    // This one works because the regex /\?\s*,/ matches "?, ?" in the query
    const map = buildMap(
      'pool.execute("INSERT INTO logs (a, b) VALUES (?, ?)", [x, y])',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'userInput',
          node_subtype: 'http_param',
          code_snapshot: 'userInput',
          attack_surface: ['user_input'],
          data_out: [{ name: 'userInput', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'pool.execute()',
          node_subtype: 'database',
          code_snapshot: 'pool.execute("INSERT INTO logs (a, b) VALUES (?, ?)", [x, y])',
          attack_surface: [],
          data_in: [{ name: 'userInput', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: CONTROL node (ORM validation) between INGRESS and STORAGE', () => {
    const map = buildMap(
      'const user = await User.findOne({ where: { email: validate(req.body.email) } })',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.email',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.email',
          attack_surface: ['user_input'],
          edges: [{ target: 'CTRL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CTRL', node_type: 'CONTROL',
          label: 'validate()',
          node_subtype: 'validation',
          code_snapshot: 'validate(req.body.email)',
          data_in: [{ name: 'email', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'PII' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'User.findOne()',
          node_subtype: 'sql_query',
          code_snapshot: 'User.findOne({ where: { email: validated } })',
          attack_surface: ['sql_sink'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// CWE-78: OS Command Injection
// ---------------------------------------------------------------------------

describe('CWE-78: OS Command Injection (stress)', () => {
  it('VULNERABLE: exec() with string interpolation', () => {
    const map = buildMap(
      'const { exec } = require("child_process"); exec("convert " + req.body.filename);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.filename',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.filename',
          attack_surface: ['user_input'],
          data_out: [{ name: 'filename', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'exec()',
          node_subtype: 'shell_command',
          code_snapshot: 'exec("convert " + req.body.filename)',
          attack_surface: ['shell_exec'],
          data_in: [{ name: 'filename', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-78');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
  });

  it('SAFE: execFile with array arguments', () => {
    const map = buildMap(
      'execFile("convert", [req.body.filename, "output.png"]);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.filename',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.filename',
          attack_surface: ['user_input'],
          data_out: [{ name: 'filename', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'execFile()',
          node_subtype: 'shell_command',
          code_snapshot: 'execFile("convert", [req.body.filename, "output.png"])',
          attack_surface: ['shell_exec'],
          data_in: [{ name: 'filename', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-78');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: execSync with template literal', () => {
    const map = buildMap(
      'execSync(`ping ${req.query.host}`)',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.host',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.host',
          attack_surface: ['user_input'],
          data_out: [{ name: 'host', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'execSync()',
          node_subtype: 'shell_command',
          code_snapshot: 'execSync(`ping ${req.query.host}`)',
          attack_surface: ['shell_exec'],
          data_in: [{ name: 'host', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-78');
    expect(result.holds).toBe(false);
    expect(result.findings[0].severity).toBe('critical');
  });

  it('SAFE: spawn with argument array', () => {
    const map = buildMap(
      'spawn("ping", ["-c", "1", req.query.host])',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.host',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.host',
          attack_surface: ['user_input'],
          data_out: [{ name: 'host', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'spawn()',
          node_subtype: 'shell_command',
          code_snapshot: 'spawn("ping", ["-c", "1", req.query.host])',
          attack_surface: ['shell_exec'],
          data_in: [{ name: 'host', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-78');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-79: Cross-Site Scripting (XSS)
// ---------------------------------------------------------------------------

describe('CWE-79: Cross-Site Scripting (stress)', () => {
  it('VULNERABLE: innerHTML assignment from user input', () => {
    const map = buildMap(
      'document.getElementById("output").innerHTML = userInput;',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'userInput',
          node_subtype: 'http_param',
          code_snapshot: 'userInput',
          attack_surface: ['user_input'],
          data_out: [{ name: 'userInput', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'innerHTML',
          node_subtype: 'html_output',
          code_snapshot: 'document.getElementById("output").innerHTML = userInput',
          attack_surface: ['html_output'],
          data_in: [{ name: 'userInput', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-79');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
  });

  it('SAFE: textContent assignment (not innerHTML)', () => {
    const map = buildMap(
      'document.getElementById("output").textContent = userInput;',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'userInput',
          node_subtype: 'http_param',
          code_snapshot: 'userInput',
          attack_surface: ['user_input'],
          data_out: [{ name: 'userInput', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'textContent',
          node_subtype: 'html_output',
          code_snapshot: 'document.getElementById("output").textContent = userInput',
          attack_surface: ['html_output'],
          data_in: [{ name: 'userInput', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-79');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: res.write with user data, no encoding', () => {
    const map = buildMap(
      'res.write("<div>" + req.query.comment + "</div>")',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.comment',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.comment',
          attack_surface: ['user_input'],
          data_out: [{ name: 'comment', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.write()',
          node_subtype: 'http_response',
          code_snapshot: 'res.write("<div>" + req.query.comment + "</div>")',
          attack_surface: ['html_output'],
          data_in: [{ name: 'comment', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-79');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: DOMPurify sanitized output', () => {
    const map = buildMap(
      'res.send(DOMPurify.sanitize(userInput))',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'userInput',
          node_subtype: 'http_param',
          code_snapshot: 'userInput',
          attack_surface: ['user_input'],
          data_out: [{ name: 'userInput', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.send()',
          node_subtype: 'html_response',
          code_snapshot: 'res.send(DOMPurify.sanitize(userInput))',
          attack_surface: ['html_output'],
          data_in: [{ name: 'userInput', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-79');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-94 / CWE-502: Code Injection / Deserialization
// (CWE-94 is not registered; eval is caught by CWE-502)
// ---------------------------------------------------------------------------

describe('CWE-502: Deserialization of Untrusted Data (stress)', () => {
  it('VULNERABLE: eval() on user input (code injection via deserialization verifier)', () => {
    const map = buildMap(
      'const result = eval(req.body.expression);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.expression',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.expression',
          attack_surface: ['user_input'],
          data_out: [{ name: 'expression', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'TRANSFORM',
          label: 'eval()',
          node_subtype: 'deserialize',
          code_snapshot: 'eval(req.body.expression)',
          attack_surface: ['code_exec'],
          data_in: [{ name: 'expression', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-502');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
  });

  it('SAFE: JSON.parse on user input (safe parser)', () => {
    const map = buildMap(
      'const data = JSON.parse(req.body.payload);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.payload',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.payload',
          attack_surface: ['user_input'],
          data_out: [{ name: 'payload', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'TRANSFORM',
          label: 'JSON.parse()',
          node_subtype: 'parse',
          code_snapshot: 'JSON.parse(req.body.payload)',
          attack_surface: ['deserialize'],
          data_in: [{ name: 'payload', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-502');
    // JSON.parse matches the sink filter, but isDangerous check should NOT match
    // because JSON.parse is not in the dangerous list
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: new Function() constructor with user input', () => {
    const map = buildMap(
      'const fn = new Function(req.body.code); fn();',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.code',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.code',
          attack_surface: ['user_input'],
          data_out: [{ name: 'code', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'TRANSFORM',
          label: 'new Function()',
          node_subtype: 'deserialize',
          code_snapshot: 'const fn = new Function (req.body.code)',
          attack_surface: ['code_exec'],
          data_in: [{ name: 'code', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-502');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: yaml.load on user input', () => {
    const map = buildMap(
      'const config = yaml.load(req.body.yamlData);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.yamlData',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.yamlData',
          attack_surface: ['user_input'],
          data_out: [{ name: 'yamlData', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'TRANSFORM',
          label: 'yaml.load()',
          node_subtype: 'parse',
          code_snapshot: 'yaml.load(req.body.yamlData)',
          attack_surface: ['deserialize'],
          data_in: [{ name: 'yamlData', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-502');
    expect(result.holds).toBe(false);
    expect(result.findings[0].severity).toBe('critical');
  });
});

// ---------------------------------------------------------------------------
// CWE-918: SSRF
// ---------------------------------------------------------------------------

describe('CWE-918: SSRF (stress)', () => {
  it('VULNERABLE: fetch() with user-controlled URL', () => {
    const map = buildMap(
      'app.get("/proxy", (req, res) => { fetch(req.query.target).then(r => res.json(r)); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.target',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.target',
          attack_surface: ['user_input'],
          data_out: [{ name: 'target', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'fetch()',
          node_subtype: 'http_request',
          code_snapshot: 'fetch(req.query.target)',
          attack_surface: ['outbound_request'],
          data_in: [{ name: 'target', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-918');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
  });

  it('SAFE: fetch() with hardcoded URL (no user input flows to it)', () => {
    const map = buildMap(
      'const data = await fetch("https://api.example.com/data");',
      [
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'fetch()',
          node_subtype: 'http_request',
          code_snapshot: 'fetch("https://api.example.com/data")',
          attack_surface: ['outbound_request'],
          data_in: [],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-918');
    // No INGRESS nodes at all -> no source->sink path
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: axios.get with user-controlled URL', () => {
    const map = buildMap(
      'axios.get(req.body.webhookUrl)',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.webhookUrl',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.webhookUrl',
          attack_surface: ['user_input'],
          data_out: [{ name: 'webhookUrl', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'axios.get()',
          node_subtype: 'http_request',
          code_snapshot: 'axios.get(req.body.webhookUrl)',
          attack_surface: ['outbound_request'],
          data_in: [{ name: 'webhookUrl', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-918');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: URL validated with allowlist before fetch', () => {
    const map = buildMap(
      'if (allowlist.includes(url)) { fetch(url); }',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.url',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.url',
          attack_surface: ['user_input'],
          edges: [{ target: 'CTRL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CTRL', node_type: 'CONTROL',
          label: 'allowlist.includes()',
          node_subtype: 'validation',
          code_snapshot: 'allowlist.includes(url)',
          data_in: [{ name: 'url', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: true, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'fetch()',
          node_subtype: 'http_request',
          code_snapshot: 'fetch(url)',
          attack_surface: ['outbound_request'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-918');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-22: Path Traversal
// ---------------------------------------------------------------------------

describe('CWE-22: Path Traversal (stress)', () => {
  it('VULNERABLE: fs.readFile with user-controlled path', () => {
    const map = buildMap(
      'fs.readFile(req.query.filepath, "utf8", (err, data) => res.send(data));',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.filepath',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.filepath',
          attack_surface: ['user_input'],
          data_out: [{ name: 'filepath', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'fs.readFile()',
          node_subtype: 'file_read',
          code_snapshot: 'fs.readFile(req.query.filepath, "utf8", callback)',
          attack_surface: ['file_access'],
          data_in: [{ name: 'filepath', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-22');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].description).toContain('../../');
  });

  it('SAFE: path.resolve + startsWith check', () => {
    const map = buildMap(
      'const resolved = path.resolve(base, req.query.file); if (!resolved.startsWith(base)) throw new Error("no"); fs.readFile(resolved, cb);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.file',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.file',
          attack_surface: ['user_input'],
          data_out: [{ name: 'file', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'fs.readFile()',
          node_subtype: 'file_read',
          code_snapshot: 'const resolved = path.resolve(base, userPath); if (!resolved.startsWith(base)) throw; fs.readFile(resolved, cb)',
          attack_surface: ['file_access'],
          data_in: [{ name: 'file', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-22');
    // code_snapshot contains path.resolve and startsWith -> isValidated = true
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: createReadStream with user input, no validation', () => {
    const map = buildMap(
      'fs.createReadStream(req.params.file).pipe(res)',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.params.file',
          node_subtype: 'http_param',
          code_snapshot: 'req.params.file',
          attack_surface: ['user_input'],
          data_out: [{ name: 'file', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'createReadStream()',
          node_subtype: 'file_stream',
          code_snapshot: 'fs.createReadStream(req.params.file).pipe(res)',
          attack_surface: ['file_access'],
          data_in: [{ name: 'file', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-22');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: CONTROL node between user input and file access', () => {
    const map = buildMap(
      'const safePath = sanitizePath(req.query.file); fs.readFile(safePath, cb);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.file',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.file',
          attack_surface: ['user_input'],
          edges: [{ target: 'CTRL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CTRL', node_type: 'CONTROL',
          label: 'sanitizePath()',
          node_subtype: 'path_validation',
          code_snapshot: 'sanitizePath(req.query.file)',
          data_in: [{ name: 'file', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'fs.readFile()',
          node_subtype: 'file_read',
          code_snapshot: 'fs.readFile(safePath, cb)',
          attack_surface: ['file_access'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-22');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-306: Missing Authentication
// ---------------------------------------------------------------------------

describe('CWE-306: Missing Authentication (stress)', () => {
  it('VULNERABLE: DELETE route with no auth middleware', () => {
    const map = buildMap(
      'app.delete("/api/users/:id", (req, res) => { db.query("DELETE FROM users WHERE id = " + req.params.id); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'DELETE /api/users/:id',
          node_subtype: 'http_handler',
          code_snapshot: 'app.delete("/api/users/:id", (req, res) =>',
          attack_surface: ['user_input'],
          data_out: [{ name: 'id', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query(DELETE)',
          node_subtype: 'sql_delete',
          code_snapshot: 'db.query("DELETE FROM users WHERE id = " + req.params.id)',
          attack_surface: ['sensitive', 'delete'],
          data_in: [{ name: 'id', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-306');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].missing).toContain('AUTH');
  });

  it('SAFE: AUTH middleware present between INGRESS and sensitive operation', () => {
    const map = buildMap(
      'app.delete("/api/users/:id", requireAuth, isAdmin, (req, res) => { db.query("DELETE FROM users WHERE id = $1", [req.params.id]); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'DELETE /api/users/:id',
          node_subtype: 'http_handler',
          code_snapshot: 'app.delete("/api/users/:id", requireAuth, isAdmin, handler)',
          attack_surface: ['user_input'],
          edges: [{ target: 'AUTH_MID', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'AUTH_MID', node_type: 'AUTH',
          label: 'requireAuth',
          node_subtype: 'middleware',
          code_snapshot: 'requireAuth',
          data_in: [{ name: 'request', source: 'SRC', data_type: 'object', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query(DELETE)',
          node_subtype: 'sql_delete',
          code_snapshot: 'db.query("DELETE FROM users WHERE id = $1", [req.params.id])',
          attack_surface: ['sensitive', 'delete'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-306');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: admin update endpoint without auth', () => {
    const map = buildMap(
      'app.put("/admin/settings", (req, res) => { db.update("settings", req.body); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'PUT /admin/settings',
          node_subtype: 'http_handler',
          code_snapshot: 'app.put("/admin/settings", (req, res) =>',
          attack_surface: ['user_input'],
          data_out: [{ name: 'body', source: 'EXTERNAL', data_type: 'object', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.update(settings)',
          node_subtype: 'database_write',
          code_snapshot: 'db.update("settings", req.body)',
          attack_surface: ['admin', 'write'],
          data_in: [{ name: 'body', source: 'SRC', data_type: 'object', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-306');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: read-only GET endpoint (no sensitive operation detected)', () => {
    const map = buildMap(
      'app.get("/api/status", (req, res) => { res.json({ status: "ok" }); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'GET /api/status',
          node_subtype: 'http_handler',
          code_snapshot: 'app.get("/api/status", (req, res) =>',
          attack_surface: ['user_input'],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.json()',
          node_subtype: 'http_response',
          code_snapshot: 'res.json({ status: "ok" })',
          attack_surface: ['api_response'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-306');
    // EGRESS is not STORAGE or EXTERNAL, and doesn't match sensitive filters
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-798: Hardcoded Credentials
// ---------------------------------------------------------------------------

describe('CWE-798: Hardcoded Credentials (stress)', () => {
  it('VULNERABLE: password = "secret123" in config', () => {
    const map = buildMap(
      'const config = { password: "secret123", host: "db.example.com" };',
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'config',
          node_subtype: 'config',
          code_snapshot: 'const config = { password: "secret123", host: "db.example.com" }',
          attack_surface: ['config'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-798');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
  });

  it('SAFE: password = process.env.DB_PASSWORD', () => {
    const map = buildMap(
      'const config = { password: process.env.DB_PASSWORD, host: "db.example.com" };',
      [
        {
          id: 'ENV', node_type: 'META',
          label: 'env.DB_PASSWORD',
          node_subtype: 'env_ref',
          code_snapshot: 'process.env.DB_PASSWORD',
          attack_surface: [],
          edges: [{ target: 'CFG', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CFG', node_type: 'STORAGE',
          label: 'config',
          node_subtype: 'config',
          code_snapshot: 'const config = { password: process.env.DB_PASSWORD, host: "db.example.com" }',
          attack_surface: ['config'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-798');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: hardcoded API key', () => {
    const map = buildMap(
      'const apiKey = "sk_live_abcdef1234567890abcdef";',
      [
        {
          id: 'SRC', node_type: 'TRANSFORM',
          label: 'apiKey assignment',
          node_subtype: 'variable',
          code_snapshot: 'api_key = "sk_live_abcdef1234567890abcdef"',
          attack_surface: [],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-798');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: hardcoded connection string', () => {
    const map = buildMap(
      'const connStr = "postgresql://user:p4ssw0rd@localhost:5432/mydb";',
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'connStr',
          node_subtype: 'config',
          code_snapshot: 'connection_string = "postgresql://user:p4ssw0rd@localhost:5432/mydb"',
          attack_surface: ['config'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-798');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: no credential patterns in code', () => {
    const map = buildMap(
      'const name = "John Doe"; const count = 42;',
      [
        {
          id: 'SRC', node_type: 'TRANSFORM',
          label: 'name assignment',
          node_subtype: 'variable',
          code_snapshot: 'const name = "John Doe"; const count = 42;',
          attack_surface: [],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-798');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: hardcoded token', () => {
    const map = buildMap(
      'const auth = { token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123" };',
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'auth config',
          node_subtype: 'config',
          code_snapshot: 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123"',
          attack_surface: ['config'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-798');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-200: Information Exposure
// ---------------------------------------------------------------------------

describe('CWE-200: Information Exposure (stress)', () => {
  it('VULNERABLE: raw database record with password hash sent to client', () => {
    const map = buildMap(
      'app.get("/users/:id", async (req, res) => { const user = await db.findById(id); res.json(user); });',
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'db.findById()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.findById(id) // returns { id, name, email, password_hash, ssn }',
          attack_surface: ['sensitive_data'],
          data_out: [{ name: 'user', source: 'SRC', data_type: 'object', tainted: false, sensitivity: 'PII' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.json()',
          node_subtype: 'http_response',
          code_snapshot: 'res.json(user)',
          attack_surface: ['api_response'],
          data_in: [{ name: 'user', source: 'SRC', data_type: 'object', tainted: false, sensitivity: 'PII' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-200');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].missing).toContain('CONTROL');
  });

  it('SAFE: DTO/pick filtering before sending response', () => {
    const map = buildMap(
      'res.json(pick(user, ["id", "name", "email"]))',
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'db.findById()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.findById(id) // returns password_hash, ssn columns',
          attack_surface: ['sensitive_data'],
          data_out: [{ name: 'user', source: 'SRC', data_type: 'object', tainted: false, sensitivity: 'PII' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.json()',
          node_subtype: 'http_response',
          code_snapshot: 'res.json(pick(user, ["id", "name", "email"]))',
          attack_surface: ['api_response'],
          data_in: [{ name: 'user', source: 'SRC', data_type: 'object', tainted: false, sensitivity: 'PII' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-200');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: secret token stored then sent without filtering', () => {
    const map = buildMap(
      'const creds = db.getCredentials(userId); res.send(creds);',
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'db.getCredentials()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.getCredentials(userId) // contains secret keys',
          attack_surface: ['sensitive_data'],
          data_out: [{ name: 'creds', source: 'SRC', data_type: 'object', tainted: false, sensitivity: 'SECRET' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.send()',
          node_subtype: 'http_response',
          code_snapshot: 'res.send(creds)',
          attack_surface: ['api_response'],
          data_in: [{ name: 'creds', source: 'SRC', data_type: 'object', tainted: false, sensitivity: 'SECRET' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-200');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: CONTROL node redacts sensitive fields before EGRESS', () => {
    const map = buildMap(
      'const user = await db.getUser(id); const safe = redact(user); res.json(safe);',
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'db.getUser()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.getUser(id) // has password hash',
          attack_surface: ['sensitive_data'],
          data_out: [{ name: 'user', source: 'SRC', data_type: 'object', tainted: false, sensitivity: 'PII' }],
          edges: [{ target: 'CTRL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CTRL', node_type: 'CONTROL',
          label: 'redact()',
          node_subtype: 'data_filter',
          code_snapshot: 'redact(user)',
          data_in: [{ name: 'user', source: 'SRC', data_type: 'object', tainted: false, sensitivity: 'PII' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.json()',
          node_subtype: 'http_response',
          code_snapshot: 'res.json(safe)',
          attack_surface: ['api_response'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-200');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-611: XML External Entity (XXE)
// ---------------------------------------------------------------------------

describe('CWE-611: XXE (stress)', () => {
  it('VULNERABLE: DOMParser on user-supplied XML', () => {
    const map = buildMap(
      'const doc = new DOMParser().parseFromString(req.body.xml, "text/xml");',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.xml',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.xml',
          attack_surface: ['user_input'],
          data_out: [{ name: 'xml', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'TRANSFORM',
          label: 'DOMParser()',
          node_subtype: 'xml_parse',
          code_snapshot: 'new DOMParser().parseFromString(req.body.xml, "text/xml")',
          attack_surface: ['xml_parse'],
          data_in: [{ name: 'xml', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-611');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
  });

  it('SAFE: defusedxml parser used for user XML', () => {
    const map = buildMap(
      'const doc = defusedxml.parse(req.body.xml);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.xml',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.xml',
          attack_surface: ['user_input'],
          data_out: [{ name: 'xml', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'TRANSFORM',
          label: 'defusedxml.parse()',
          node_subtype: 'xml_parse',
          code_snapshot: 'defusedxml.parse(req.body.xml)',
          attack_surface: ['xml_parse'],
          data_in: [{ name: 'xml', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-611');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: xml2js without secure config', () => {
    const map = buildMap(
      'xml2js.parseString(req.body, callback)',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body',
          node_subtype: 'http_body',
          code_snapshot: 'req.body',
          attack_surface: ['user_input'],
          data_out: [{ name: 'body', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'TRANSFORM',
          label: 'xml2js.parseString()',
          node_subtype: 'xml_parse',
          code_snapshot: 'xml2js.parseString(req.body, callback)',
          attack_surface: ['xml_parse'],
          data_in: [{ name: 'body', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-611');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: CONTROL node (parser config) between INGRESS and XML parse', () => {
    const map = buildMap(
      'const parser = new XMLParser({ resolveEntities: false }); parser.parse(req.body.xml);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.xml',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.xml',
          attack_surface: ['user_input'],
          edges: [{ target: 'CTRL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CTRL', node_type: 'CONTROL',
          label: 'XMLParser config',
          node_subtype: 'parser_config',
          code_snapshot: 'new XMLParser({ resolveEntities: false })',
          data_in: [{ name: 'xml', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'TRANSFORM',
          label: 'parser.parse()',
          node_subtype: 'xml_parse',
          code_snapshot: 'parser.parse(req.body.xml)',
          attack_surface: ['xml_parse'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-611');
    // CONTROL node between INGRESS and TRANSFORM means hasTaintedPathWithoutControl = false
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Edge cases and structural tests
// ---------------------------------------------------------------------------

describe('Edge cases: multiple paths, no sinks, empty maps', () => {
  it('CWE-89: no STORAGE nodes -> holds=true (nothing to exploit)', () => {
    const map = buildMap('console.log("hello")', [
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.query.q',
        node_subtype: 'http_param',
        code_snapshot: 'req.query.q',
        attack_surface: ['user_input'],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(true);
  });

  it('CWE-79: no INGRESS nodes -> holds=true (no taint source)', () => {
    const map = buildMap('res.send("<h1>Static</h1>")', [
      {
        id: 'SINK', node_type: 'EGRESS',
        label: 'res.send()',
        node_subtype: 'html_response',
        code_snapshot: 'res.send("<h1>Static Content</h1>")',
        attack_surface: ['html_output'],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-79');
    expect(result.holds).toBe(true);
  });

  it('Empty NeuralMap -> all CWEs hold (no nodes to check)', () => {
    const map = buildMap('// empty file', []);
    const results = verifyAll(map);
    for (const r of results) {
      expect(r.holds).toBe(true);
    }
  });

  it('Unknown CWE -> returns unknown result', () => {
    const map = buildMap('x', []);
    const result = verify(map, 'CWE-99999');
    expect(result.cwe).toBe('CWE-99999');
    expect(result.name).toBe('Unknown');
  });

  it('CWE-306: STORAGE with insert keyword but no INGRESS -> holds=true', () => {
    const map = buildMap('db.query("INSERT INTO logs VALUES (1)")', [
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'db.query()',
        node_subtype: 'sql_insert',
        code_snapshot: 'db.query("INSERT INTO logs VALUES (1)")',
        attack_surface: ['write'],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-306');
    expect(result.holds).toBe(true);
  });

  it('CWE-89: multiple INGRESS to single STORAGE -> catches all paths', () => {
    const map = buildMap(
      'db.query("SELECT * FROM x WHERE a=" + p1 + " AND b=" + p2)',
      [
        {
          id: 'SRC1', node_type: 'INGRESS',
          label: 'param1',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.p1',
          attack_surface: ['user_input'],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SRC2', node_type: 'INGRESS',
          label: 'param2',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.p2',
          attack_surface: ['user_input'],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query("SELECT * FROM x WHERE a=" + p1 + " AND b=" + p2)',
          attack_surface: ['sql_sink'],
          data_in: [
            { name: 'p1', source: 'SRC1', data_type: 'string', tainted: true, sensitivity: 'NONE' },
            { name: 'p2', source: 'SRC2', data_type: 'string', tainted: true, sensitivity: 'NONE' },
          ],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(false);
    // Both paths should produce findings
    expect(result.findings.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Summary: log all results in one consolidated test
// ---------------------------------------------------------------------------

describe('CWE Verification Summary Report', () => {
  it('runs all 13 CWEs and logs summary', () => {
    const registered = registeredCWEs();
    console.log(`\nRegistered CWE verifiers: ${registered.length}`);
    console.log(`CWEs: ${registered.join(', ')}`);

    // Original 10 verifiers
    expect(registered).toContain('CWE-89');
    expect(registered).toContain('CWE-79');
    expect(registered).toContain('CWE-78');
    expect(registered).toContain('CWE-22');
    expect(registered).toContain('CWE-502');
    expect(registered).toContain('CWE-918');
    expect(registered).toContain('CWE-798');
    expect(registered).toContain('CWE-306');
    expect(registered).toContain('CWE-200');
    expect(registered).toContain('CWE-611');

    // 3 new verifiers
    expect(registered).toContain('CWE-94');    // Code Injection
    expect(registered).toContain('CWE-352');   // CSRF
    expect(registered).toContain('CWE-1321');  // Prototype Pollution
    // 13 hand-written + generated verifiers from GENERATED_REGISTRY
    expect(registered.length).toBeGreaterThanOrEqual(13);
  });

  it('consolidated vulnerable/safe pairs for all 10 CWEs', () => {
    resetSequence();

    // Build quick vuln/safe pairs for each CWE and log results
    const pairs: Array<{
      cwe: string;
      name: string;
      vulnMap: NeuralMap;
      safeMap: NeuralMap;
    }> = [
      {
        cwe: 'CWE-89', name: 'SQL Injection',
        vulnMap: buildMap('db.query("SELECT * FROM users WHERE id=" + id)', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_param', code_snapshot: 'req.params.id', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'STORAGE', label: 'db.query()', node_subtype: 'sql_query',
            code_snapshot: 'db.query("SELECT * FROM users WHERE id=" + id)', attack_surface: ['sql_sink'], edges: [] },
        ]),
        safeMap: buildMap('db.query("SELECT * FROM users WHERE id=$1", [id])', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_param', code_snapshot: 'req.params.id', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'STORAGE', label: 'db.query()', node_subtype: 'sql_query',
            code_snapshot: 'db.query("SELECT * FROM users WHERE id=$1", [id])', attack_surface: ['sql_sink'], edges: [] },
        ]),
      },
      {
        cwe: 'CWE-79', name: 'XSS',
        vulnMap: buildMap('res.send("<p>" + input + "</p>")', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_param', code_snapshot: 'req.query.q', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'EGRESS', label: 'res.send()', node_subtype: 'html_response',
            code_snapshot: 'res.send("<p>" + input + "</p>")', attack_surface: ['html_output'], edges: [] },
        ]),
        safeMap: buildMap('res.send(escape(input))', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_param', code_snapshot: 'req.query.q', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'EGRESS', label: 'res.send()', node_subtype: 'html_response',
            code_snapshot: 'res.send(escape(input))', attack_surface: ['html_output'], edges: [] },
        ]),
      },
      {
        cwe: 'CWE-78', name: 'OS Command Injection',
        vulnMap: buildMap('exec("ls " + dir)', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_param', code_snapshot: 'req.query.dir', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'EXTERNAL', label: 'exec()', node_subtype: 'shell_command',
            code_snapshot: 'exec("ls " + dir)', attack_surface: ['shell_exec'], edges: [] },
        ]),
        safeMap: buildMap('execFile("ls", [dir])', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_param', code_snapshot: 'req.query.dir', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'EXTERNAL', label: 'execFile()', node_subtype: 'shell_command',
            code_snapshot: 'execFile("ls", [dir])', attack_surface: ['shell_exec'], edges: [] },
        ]),
      },
      {
        cwe: 'CWE-22', name: 'Path Traversal',
        vulnMap: buildMap('fs.readFile(userPath)', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_param', code_snapshot: 'req.query.path', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'STORAGE', label: 'fs.readFile()', node_subtype: 'file_read',
            code_snapshot: 'fs.readFile(userPath, cb)', attack_surface: ['file_access'], edges: [] },
        ]),
        safeMap: buildMap('path.resolve then startsWith', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_param', code_snapshot: 'req.query.path', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'STORAGE', label: 'fs.readFile()', node_subtype: 'file_read',
            code_snapshot: 'const p = path.resolve(base, input); if (p.startsWith(base)) fs.readFile(p)', attack_surface: ['file_access'], edges: [] },
        ]),
      },
      {
        cwe: 'CWE-502', name: 'Deserialization',
        vulnMap: buildMap('eval(req.body.data)', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_body', code_snapshot: 'req.body.data', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'TRANSFORM', label: 'eval()', node_subtype: 'deserialize',
            code_snapshot: 'eval(req.body.data)', attack_surface: ['code_exec'], edges: [] },
        ]),
        safeMap: buildMap('JSON.parse(req.body.data)', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_body', code_snapshot: 'req.body.data', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'TRANSFORM', label: 'JSON.parse()', node_subtype: 'parse',
            code_snapshot: 'JSON.parse(req.body.data)', attack_surface: ['deserialize'], edges: [] },
        ]),
      },
      {
        cwe: 'CWE-918', name: 'SSRF',
        vulnMap: buildMap('fetch(req.query.url)', [
          { id: 'S', node_type: 'INGRESS', label: 'input', node_subtype: 'http_param', code_snapshot: 'req.query.url', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'EXTERNAL', label: 'fetch()', node_subtype: 'http_request',
            code_snapshot: 'fetch(req.query.url)', attack_surface: ['outbound_request'], edges: [] },
        ]),
        safeMap: buildMap('fetch("https://api.safe.com/data")', [
          { id: 'K', node_type: 'EXTERNAL', label: 'fetch()', node_subtype: 'http_request',
            code_snapshot: 'fetch("https://api.safe.com/data")', attack_surface: ['outbound_request'], edges: [] },
        ]),
      },
      {
        cwe: 'CWE-798', name: 'Hardcoded Credentials',
        vulnMap: buildMap('password: "SuperSecret123"', [
          { id: 'S', node_type: 'STORAGE', label: 'config', node_subtype: 'config',
            code_snapshot: 'password: "SuperSecret123"', attack_surface: ['config'], edges: [] },
        ]),
        safeMap: buildMap('password: process.env.DB_PASS', [
          { id: 'M', node_type: 'META', label: 'env.DB_PASS', node_subtype: 'env_ref',
            code_snapshot: 'process.env.DB_PASS', attack_surface: [],
            edges: [{ target: 'S', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'S', node_type: 'STORAGE', label: 'config', node_subtype: 'config',
            code_snapshot: 'password: process.env.DB_PASS', attack_surface: ['config'], edges: [] },
        ]),
      },
      {
        cwe: 'CWE-306', name: 'Missing Authentication',
        vulnMap: buildMap('app.delete("/users/:id", handler)', [
          { id: 'S', node_type: 'INGRESS', label: 'DELETE /users/:id', node_subtype: 'http_handler',
            code_snapshot: 'app.delete("/users/:id", handler)', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'STORAGE', label: 'db.delete()', node_subtype: 'sql_delete',
            code_snapshot: 'db.query("DELETE FROM users WHERE id=" + id)', attack_surface: ['sensitive', 'delete'], edges: [] },
        ]),
        safeMap: buildMap('app.delete("/users/:id", requireAuth, handler)', [
          { id: 'S', node_type: 'INGRESS', label: 'DELETE /users/:id', node_subtype: 'http_handler',
            code_snapshot: 'app.delete("/users/:id", requireAuth, handler)', attack_surface: ['user_input'],
            edges: [{ target: 'A', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'A', node_type: 'AUTH', label: 'requireAuth', node_subtype: 'middleware', code_snapshot: 'requireAuth',
            data_in: [{ name: 'request', source: 'S', data_type: 'object', tainted: true, sensitivity: 'NONE' }],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'STORAGE', label: 'db.delete()', node_subtype: 'sql_delete',
            code_snapshot: 'db.query("DELETE FROM users WHERE id=$1", [id])', attack_surface: ['sensitive', 'delete'], edges: [] },
        ]),
      },
      {
        cwe: 'CWE-200', name: 'Information Exposure',
        vulnMap: buildMap('res.json(rawUser)', [
          { id: 'S', node_type: 'STORAGE', label: 'db.getUser()', node_subtype: 'sql_query',
            code_snapshot: 'db.getUser(id) // has password, ssn',
            attack_surface: ['sensitive_data'],
            data_out: [{ name: 'user', source: 'S', data_type: 'object', tainted: false, sensitivity: 'PII' }],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'EGRESS', label: 'res.json()', node_subtype: 'http_response',
            code_snapshot: 'res.json(rawUser)', attack_surface: ['api_response'], edges: [] },
        ]),
        safeMap: buildMap('res.json(omit(user, ["password"]))', [
          { id: 'S', node_type: 'STORAGE', label: 'db.getUser()', node_subtype: 'sql_query',
            code_snapshot: 'db.getUser(id) // has password',
            attack_surface: ['sensitive_data'],
            data_out: [{ name: 'user', source: 'S', data_type: 'object', tainted: false, sensitivity: 'PII' }],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'EGRESS', label: 'res.json()', node_subtype: 'http_response',
            code_snapshot: 'res.json(omit(user, ["password"]))', attack_surface: ['api_response'], edges: [] },
        ]),
      },
      {
        cwe: 'CWE-611', name: 'XXE',
        vulnMap: buildMap('parseXML(req.body)', [
          { id: 'S', node_type: 'INGRESS', label: 'req.body', node_subtype: 'http_body', code_snapshot: 'req.body', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'TRANSFORM', label: 'parseXML()', node_subtype: 'xml_parse',
            code_snapshot: 'parseXML(req.body)', attack_surface: ['xml_parse'], edges: [] },
        ]),
        safeMap: buildMap('defusedxml.parse(req.body)', [
          { id: 'S', node_type: 'INGRESS', label: 'req.body', node_subtype: 'http_body', code_snapshot: 'req.body', attack_surface: ['user_input'],
            edges: [{ target: 'K', edge_type: 'DATA_FLOW', conditional: false, async: false }] },
          { id: 'K', node_type: 'TRANSFORM', label: 'defusedxml.parse()', node_subtype: 'xml_parse',
            code_snapshot: 'defusedxml.parse(req.body)', attack_surface: ['xml_parse'], edges: [] },
        ]),
      },
    ];

    console.log('\n--- CWE VERIFICATION STRESS TEST RESULTS ---\n');

    let allPass = true;
    for (const { cwe, name, vulnMap, safeMap } of pairs) {
      const vulnResult = verify(vulnMap, cwe);
      const safeResult = verify(safeMap, cwe);

      logResult(cwe, name, vulnResult, safeResult);

      const vulnOk = !vulnResult.holds && vulnResult.findings.length > 0;
      const safeOk = safeResult.holds && safeResult.findings.length === 0;

      if (!vulnOk) {
        console.log(`  BUG: ${cwe} VULNERABLE case not detected! holds=${vulnResult.holds}, findings=${vulnResult.findings.length}`);
        allPass = false;
      }
      if (!safeOk) {
        console.log(`  BUG: ${cwe} SAFE case incorrectly flagged! holds=${safeResult.holds}, findings=${safeResult.findings.length}`);
        allPass = false;
      }

      expect(vulnResult.holds).toBe(false);
      expect(vulnResult.findings.length).toBeGreaterThan(0);
      expect(safeResult.holds).toBe(true);
      expect(safeResult.findings.length).toBe(0);
    }

    console.log(`\n${allPass ? 'ALL 10 CWEs PASS' : 'SOME CWEs HAVE BUGS'}`);
    console.log('---\n');
  });
});

// ---------------------------------------------------------------------------
// CWE-111: Direct Use of Unsafe JNI
// ---------------------------------------------------------------------------

describe('CWE-111: Direct Use of Unsafe JNI', () => {
  it('VULNERABLE: native method called with user input (no validation)', () => {
    const map = buildMap(
      `native String test(String s1, int len);
       static { System.loadLibrary("JNITest"); }
       String stringLine = readerBuffered.readLine();
       int intNumber = Integer.parseInt(readerBuffered.readLine());
       test(stringLine, intNumber);`,
      [
        {
          id: 'CLASS', node_type: 'STRUCTURAL',
          label: 'CWE111_Unsafe_JNI',
          code_snapshot: 'native String test(String s1, int len);',
          edges: [
            { target: 'INPUT', edge_type: 'CONTAINS', conditional: false, async: false },
            { target: 'CALL', edge_type: 'CONTAINS', conditional: false, async: false },
          ],
        },
        {
          id: 'INPUT', node_type: 'INGRESS',
          label: 'readerBuffered.readLine()',
          node_subtype: 'user_input',
          code_snapshot: 'readerBuffered.readLine()',
          attack_surface: ['user_input'],
          data_out: [{ name: 'stringLine', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'CALL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CALL', node_type: 'TRANSFORM',
          label: 'test(stringLine, intNumber)',
          code_snapshot: 'test(stringLine, intNumber)',
          data_in: [{ name: 'stringLine', source: 'INPUT', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-111');
    console.log(`  VULNERABLE: holds=${result.holds}, findings=${result.findings.length} ${!result.holds ? '✓' : '✗'}`);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
  });

  it('SAFE: native method called with validated input (bounds check)', () => {
    const map = buildMap(
      `native String test(String s1, int len);
       String stringLine = readerBuffered.readLine();
       if (stringLine.length() <= 100) { test(stringLine, Math.min(intNumber, 100)); }`,
      [
        {
          id: 'CLASS', node_type: 'STRUCTURAL',
          label: 'CWE111_Safe',
          code_snapshot: 'native String test(String s1, int len);',
          edges: [
            { target: 'INPUT', edge_type: 'CONTAINS', conditional: false, async: false },
            { target: 'VALIDATE', edge_type: 'CONTAINS', conditional: false, async: false },
            { target: 'CALL', edge_type: 'CONTAINS', conditional: false, async: false },
          ],
        },
        {
          id: 'INPUT', node_type: 'INGRESS',
          label: 'readerBuffered.readLine()',
          node_subtype: 'user_input',
          code_snapshot: 'readerBuffered.readLine()',
          attack_surface: ['user_input'],
          data_out: [{ name: 'stringLine', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'VALIDATE', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'VALIDATE', node_type: 'CONTROL',
          label: 'bounds check',
          code_snapshot: 'if (stringLine.length() <= 100)',
          data_in: [{ name: 'stringLine', source: 'INPUT', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'CALL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CALL', node_type: 'TRANSFORM',
          label: 'test(stringLine, intNumber)',
          code_snapshot: 'test(stringLine, Math.min(intNumber, 100))',
          data_in: [{ name: 'stringLine', source: 'VALIDATE', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-111');
    console.log(`  SAFE: holds=${result.holds}, findings=${result.findings.length} ${result.holds ? '✓' : '✗'}`);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: tainted loadLibrary (user controls library name)', () => {
    const map = buildMap(
      'String libName = request.getParameter("lib"); System.loadLibrary(libName);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'request.getParameter("lib")',
          node_subtype: 'http_param',
          code_snapshot: 'request.getParameter("lib")',
          attack_surface: ['user_input'],
          data_out: [{ name: 'libName', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'System.loadLibrary(libName)',
          node_subtype: 'system_exec',
          code_snapshot: 'System.loadLibrary(libName)',
          data_in: [{ name: 'libName', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-111');
    console.log(`  VULNERABLE (tainted loadLibrary): holds=${result.holds}, findings=${result.findings.length} ${!result.holds ? '✓' : '✗'}`);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-114: Process Control
// ---------------------------------------------------------------------------

describe('CWE-114: Process Control', () => {
  it('VULNERABLE: System.loadLibrary() with relative name', () => {
    const map = buildMap(
      'String libraryName = "test.dll"; System.loadLibrary(libraryName);',
      [
        {
          id: 'BAD', node_type: 'STRUCTURAL',
          label: 'bad',
          code_snapshot: 'System.loadLibrary(libraryName)',
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-114');
    console.log(`  VULNERABLE (loadLibrary): holds=${result.holds}, findings=${result.findings.length} ${!result.holds ? '✓' : '✗'}`);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('medium');
  });

  it('SAFE: System.load() with hardcoded absolute path', () => {
    const map = buildMap(
      'System.load("/opt/myapp/libs/test.so");',
      [
        {
          id: 'GOOD', node_type: 'STRUCTURAL',
          label: 'good1',
          code_snapshot: 'System.load("/opt/myapp/libs/test.so")',
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-114');
    console.log(`  SAFE (absolute path): holds=${result.holds}, findings=${result.findings.length} ${result.holds ? '✓' : '✗'}`);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: System.load() with root + libraryName (Juliet good pattern)', () => {
    const map = buildMap(
      'String root = "C:\\\\libs\\\\"; System.load(root + libraryName);',
      [
        {
          id: 'GOOD', node_type: 'STRUCTURAL',
          label: 'good',
          code_snapshot: 'System.load(root + libraryName)',
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-114');
    console.log(`  SAFE (root+name): holds=${result.holds}, findings=${result.findings.length} ${result.holds ? '✓' : '✗'}`);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: Runtime.exec with tainted input', () => {
    const map = buildMap(
      'String cmd = request.getParameter("cmd"); Runtime.getRuntime().exec(cmd);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'request.getParameter("cmd")',
          node_subtype: 'http_param',
          code_snapshot: 'request.getParameter("cmd")',
          attack_surface: ['user_input'],
          data_out: [{ name: 'cmd', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'Runtime.getRuntime().exec(cmd)',
          node_subtype: 'system_exec',
          code_snapshot: 'Runtime.getRuntime().exec(cmd)',
          data_in: [{ name: 'cmd', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-114');
    console.log(`  VULNERABLE (Runtime.exec): holds=${result.holds}, findings=${result.findings.length} ${!result.holds ? '✓' : '✗'}`);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
  });

  it('SAFE: System.loadLibrary with SecurityManager', () => {
    const map = buildMap(
      'SecurityManager sm = System.getSecurityManager(); sm.checkLink("test"); System.loadLibrary("test");',
      [
        {
          id: 'GOOD', node_type: 'STRUCTURAL',
          label: 'secureLoad',
          code_snapshot: 'SecurityManager sm = System.getSecurityManager(); sm.checkLink("test"); System.loadLibrary("test");',
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-114');
    console.log(`  SAFE (SecurityManager): holds=${result.holds}, findings=${result.findings.length} ${result.holds ? '✓' : '✗'}`);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});
