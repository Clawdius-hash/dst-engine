/**
 * Verification Engine Tests — real vulnerable code patterns
 *
 * Each test builds a neural map from a known-vulnerable pattern,
 * runs the verifier, and confirms it catches the vulnerability.
 * Then tests the FIXED version and confirms it passes.
 */

import { describe, it, expect } from 'vitest';
import { verify, verifyAll, formatReport } from './verifier';
import { createNode, createNeuralMap, resetSequence } from './types';
import type { NeuralMap } from './types';

// Helper: build a neural map from nodes with edges wired up
function buildMap(code: string, nodes: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap('test.js', code);
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

describe('CWE-89: SQL Injection', () => {
  it('catches string concatenation in SQL query', () => {
    const map = buildMap(
      `app.get('/users', (req, res) => { db.query("SELECT * FROM users WHERE id = " + req.params.id); });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.params.id',
          node_subtype: 'http_param',
          code_snapshot: 'req.params.id',
          attack_surface: ['user_input'],
          data_out: [{ name: 'id', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
          attack_surface: ['sql_sink'],
          data_in: [{ name: 'id', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].missing).toContain('parameterized');
  });

  it('passes when using parameterized queries', () => {
    const map = buildMap(
      `app.get('/users', (req, res) => { db.query("SELECT * FROM users WHERE id = $1", [req.params.id]); });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.params.id',
          node_subtype: 'http_param',
          code_snapshot: 'req.params.id',
          attack_surface: ['user_input'],
          data_out: [{ name: 'id', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query("SELECT * FROM users WHERE id = $1", [req.params.id])',
          attack_surface: ['sql_sink'],
          data_in: [{ name: 'id', source: 'node_1_1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('passes when CONTROL node exists between INGRESS and STORAGE', () => {
    const map = buildMap(
      `app.get('/users', (req, res) => { const id = validate(req.params.id); db.query("SELECT * FROM users WHERE id = " + id); });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.params.id',
          node_subtype: 'http_param',
          code_snapshot: 'req.params.id',
          attack_surface: ['user_input'],
          edges: [{ target: 'MID', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'MID', node_type: 'CONTROL',
          label: 'validate()',
          node_subtype: 'validation',
          code_snapshot: 'const id = validate(req.params.id)',
          data_in: [{ name: 'id', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query("SELECT * FROM users WHERE id = " + id)',
          attack_surface: ['sql_sink'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(true);
  });
});

describe('CWE-79: Cross-Site Scripting', () => {
  it('catches reflected user input in innerHTML', () => {
    const map = buildMap(
      `app.get('/search', (req, res) => { res.send("<h1>" + req.query.q + "</h1>"); });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.q',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.q',
          attack_surface: ['user_input'],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.send()',
          node_subtype: 'html_response',
          code_snapshot: 'res.send("<h1>" + req.query.q + "</h1>")',
          attack_surface: ['html_output'],
          data_in: [{ name: 'q', source: 'node_1_1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-79');
    expect(result.holds).toBe(false);
    expect(result.findings[0].severity).toBe('high');
  });

  it('passes when output is sanitized', () => {
    const map = buildMap(
      `app.get('/search', (req, res) => { res.send("<h1>" + escape(req.query.q) + "</h1>"); });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.q',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.q',
          attack_surface: ['user_input'],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.send()',
          node_subtype: 'html_response',
          code_snapshot: 'res.send("<h1>" + escape(req.query.q) + "</h1>")',
          attack_surface: ['html_output'],
          data_in: [{ name: 'q', source: 'node_1_1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-79');
    expect(result.holds).toBe(true);
  });
});

describe('CWE-22: Path Traversal', () => {
  it('catches user-controlled file path', () => {
    const map = buildMap(
      `app.get('/file', (req, res) => { fs.readFile(req.query.path, cb); });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.path',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.path',
          attack_surface: ['user_input'],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'fs.readFile()',
          node_subtype: 'file_read',
          code_snapshot: 'fs.readFile(req.query.path, cb)',
          attack_surface: ['file_access'],
          data_in: [{ name: 'path', source: 'node_1_1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-22');
    expect(result.holds).toBe(false);
    expect(result.findings[0].description).toContain('../../');
  });
});

describe('CWE-918: SSRF', () => {
  it('catches user-controlled URL in fetch', () => {
    const map = buildMap(
      `app.get('/proxy', (req, res) => { fetch(req.query.url).then(r => r.text()); });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.url',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.url',
          attack_surface: ['user_input'],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'fetch()',
          node_subtype: 'http_request',
          code_snapshot: 'fetch(req.query.url)',
          attack_surface: ['outbound_request'],
          data_in: [{ name: 'url', source: 'node_1_1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-918');
    expect(result.holds).toBe(false);
    expect(result.findings[0].severity).toBe('high');
  });
});

describe('CWE-798: Hardcoded Credentials', () => {
  it('catches hardcoded password in source code', () => {
    const map = buildMap(
      `const dbConfig = { host: "localhost", password: "SuperSecret123" };`,
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'dbConfig',
          node_subtype: 'config',
          code_snapshot: 'const dbConfig = { host: "localhost", password: "SuperSecret123" }',
          attack_surface: ['config'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-798');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].missing).toContain('META');
  });

  it('passes when credentials come from environment variables', () => {
    const map = buildMap(
      `const dbConfig = { host: "localhost", password: process.env.DB_PASSWORD };`,
      [
        {
          id: 'SRC', node_type: 'META',
          label: 'env.DB_PASSWORD',
          node_subtype: 'env_ref',
          code_snapshot: 'process.env.DB_PASSWORD',
          attack_surface: [],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'dbConfig',
          node_subtype: 'config',
          code_snapshot: 'const dbConfig = { host: "localhost", password: process.env.DB_PASSWORD }',
          attack_surface: ['config'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-798');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('catches hardcoded API key', () => {
    const map = buildMap(
      `const client = new Stripe("sk_live_abc123def456ghi789");`,
      [
        {
          id: 'SRC', node_type: 'EXTERNAL',
          label: 'Stripe()',
          node_subtype: 'api_client',
          code_snapshot: 'const client = new Stripe("sk_live_abc123def456ghi789"); api_key = "sk_live_abc123def456ghi789"',
          attack_surface: ['api_client'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-798');
    expect(result.holds).toBe(false);
    expect(result.findings[0].description).toContain('Hardcoded credential');
  });
});

describe('CWE-306: Missing Authentication', () => {
  it('catches unauthenticated delete operation', () => {
    const map = buildMap(
      `app.delete('/users/:id', (req, res) => { db.query("DELETE FROM users WHERE id = " + req.params.id); });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'DELETE /users/:id',
          node_subtype: 'http_handler',
          code_snapshot: 'app.delete("/users/:id", (req, res) =>',
          attack_surface: ['user_input'],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query(DELETE)',
          node_subtype: 'sql_delete',
          code_snapshot: 'db.query("DELETE FROM users WHERE id = " + req.params.id)',
          attack_surface: ['sensitive', 'write'],
          data_in: [{ name: 'id', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-306');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].missing).toContain('AUTH');
  });

  it('passes when AUTH middleware is present', () => {
    const map = buildMap(
      `app.delete('/users/:id', requireAuth, (req, res) => { db.query("DELETE FROM users WHERE id = $1", [req.params.id]); });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'DELETE /users/:id',
          node_subtype: 'http_handler',
          code_snapshot: 'app.delete("/users/:id", requireAuth, (req, res) =>',
          attack_surface: ['user_input'],
          edges: [{ target: 'MID', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'MID', node_type: 'AUTH',
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
          attack_surface: ['sensitive', 'write'],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-306');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

describe('CWE-200: Information Exposure', () => {
  it('catches raw database record sent to client', () => {
    const map = buildMap(
      `app.get('/user/:id', async (req, res) => { const user = await db.query("SELECT * FROM users WHERE id = $1"); res.json(user); });`,
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'db.query(users)',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query("SELECT * FROM users WHERE id = $1") // has password_hash, ssn columns',
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
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].missing).toContain('CONTROL');
  });

  it('passes when sensitive fields are filtered', () => {
    const map = buildMap(
      `app.get('/user/:id', async (req, res) => { const user = await db.query("SELECT * FROM users WHERE id = $1"); res.json(pick(user, ['id', 'name', 'email'])); });`,
      [
        {
          id: 'SRC', node_type: 'STORAGE',
          label: 'db.query(users)',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query("SELECT * FROM users WHERE id = $1") // has password_hash, ssn columns',
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
});

describe('CWE-78: OS Command Injection', () => {
  it('catches user input in exec()', () => {
    const map = buildMap(
      `app.get('/convert', (req, res) => { exec("ffmpeg -i " + req.query.file + " output.mp4"); });`,
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
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'exec()',
          node_subtype: 'shell_command',
          code_snapshot: 'exec("ffmpeg -i " + req.query.file + " output.mp4")',
          attack_surface: ['shell_exec'],
          data_in: [{ name: 'file', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-78');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].description).toContain('shell command');
  });

  it('passes when using spawn with argument array', () => {
    const map = buildMap(
      `app.get('/convert', (req, res) => { spawn("ffmpeg", ["-i", req.query.file, "output.mp4"]); });`,
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
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'spawn()',
          node_subtype: 'shell_command',
          code_snapshot: 'spawn("ffmpeg", ["-i", req.query.file, "output.mp4"])',
          attack_surface: ['shell_exec'],
          data_in: [{ name: 'file', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-78');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

describe('CWE-611: XML External Entity (XXE)', () => {
  it('catches unsafe XML parsing of user input', () => {
    const map = buildMap(
      `app.post('/import', (req, res) => { const doc = parseXML(req.body); });`,
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
          label: 'parseXML()',
          node_subtype: 'xml_parse',
          code_snapshot: 'parseXML(req.body)',
          attack_surface: ['xml_parse'],
          data_in: [{ name: 'body', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-611');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].description).toContain('external entities');
  });

  it('passes when external entities are disabled', () => {
    const map = buildMap(
      `app.post('/import', (req, res) => { const doc = defusedxml.parse(req.body); });`,
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
          label: 'defusedxml.parse()',
          node_subtype: 'xml_parse',
          code_snapshot: 'defusedxml.parse(req.body)',
          attack_surface: ['xml_parse'],
          data_in: [{ name: 'body', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-611');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

describe('Full verification report', () => {
  it('runs all CWEs and formats report', () => {
    const map = buildMap(
      `// Vulnerable Express app
       app.get('/users', (req, res) => {
         db.query("SELECT * FROM users WHERE id = " + req.params.id);
         res.send("<h1>" + req.query.q + "</h1>");
         fetch(req.query.url);
       });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.params.id',
          node_subtype: 'http_param',
          code_snapshot: 'req.params.id',
          attack_surface: ['user_input'],
          edges: [
            { target: 'SQL_SINK', edge_type: 'DATA_FLOW', conditional: false, async: false },
            { target: 'HTML_SINK', edge_type: 'DATA_FLOW', conditional: false, async: false },
            { target: 'FETCH_SINK', edge_type: 'DATA_FLOW', conditional: false, async: false },
          ],
        },
        {
          id: 'SQL_SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
          attack_surface: ['sql_sink'],
          edges: [],
        },
        {
          id: 'HTML_SINK', node_type: 'EGRESS',
          label: 'res.send()',
          node_subtype: 'html_response',
          code_snapshot: 'res.send("<h1>" + req.query.q + "</h1>")',
          attack_surface: ['html_output'],
          edges: [],
        },
        {
          id: 'FETCH_SINK', node_type: 'EXTERNAL',
          label: 'fetch()',
          node_subtype: 'http_request',
          code_snapshot: 'fetch(req.query.url)',
          attack_surface: ['outbound_request'],
          edges: [],
        },
      ]
    );

    const results = verifyAll(map);
    const report = formatReport(results);

    // Should catch SQL injection, XSS, and SSRF
    const failures = results.filter(r => !r.holds);
    expect(failures.length).toBeGreaterThanOrEqual(3);

    // Report should be human readable
    expect(report).toContain('CWE-89');
    expect(report).toContain('CWE-79');
    expect(report).toContain('CWE-918');
    expect(report).toContain('FAIL');

    console.log('\n' + report);
  });
});
