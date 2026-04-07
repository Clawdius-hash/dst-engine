/**
 * Comment-stripping tests — ensures comments in code_snapshot cannot
 * suppress vulnerability findings via safe-pattern regex bypass.
 */

import { describe, it, expect } from 'vitest';
import { verify, stripComments } from './verifier';
import { createNode, createNeuralMap, resetSequence } from './types';
import type { NeuralMap } from './types';

// Helper: build a neural map from nodes with edges wired up
function buildMap(code: string, nodes: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap('test.js', code);
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

// ---------------------------------------------------------------------------
// stripComments unit tests
// ---------------------------------------------------------------------------

describe('stripComments', () => {
  it('removes single-line // comments', () => {
    const code = 'db.query(sql); // parameterized query';
    expect(stripComments(code)).toBe('db.query(sql); ');
  });

  it('removes multi-line /* */ comments', () => {
    const code = 'db.query(sql); /* parameterized */ next();';
    const stripped = stripComments(code);
    // The safe-pattern word must be gone
    expect(stripped).not.toMatch(/parameterized/);
    // Surrounding code preserved
    expect(stripped).toMatch(/db\.query\(sql\);/);
    expect(stripped).toMatch(/next\(\);/);
  });

  it('removes hash comments (Python/Ruby)', () => {
    const code = 'cursor.execute(sql) # parameterized query';
    expect(stripComments(code)).toBe('cursor.execute(sql) ');
  });

  it('preserves string contents with // inside', () => {
    const code = 'const url = "http://example.com"; query(url);';
    expect(stripComments(code)).toBe(code);
  });

  it('preserves single-quoted string contents with // inside', () => {
    const code = "const url = 'http://example.com'; query(url);";
    expect(stripComments(code)).toBe(code);
  });

  it('preserves template literal contents with // inside', () => {
    const code = 'const url = `http://example.com`; query(url);';
    expect(stripComments(code)).toBe(code);
  });

  it('preserves escaped quotes in strings', () => {
    const code = 'const s = "he said \\"parameterized\\""; db.query(sql);';
    expect(stripComments(code)).toBe(code);
  });

  it('handles code with no comments', () => {
    const code = 'db.query("SELECT * FROM users WHERE id = $1", [id])';
    expect(stripComments(code)).toBe(code);
  });

  it('handles empty string', () => {
    expect(stripComments('')).toBe('');
  });

  it('strips multiline comment spanning lines', () => {
    const code = 'before();\n/* sanitize\nall inputs */\nafter();';
    expect(stripComments(code)).toBe('before();\n \nafter();');
  });
});

// ---------------------------------------------------------------------------
// CWE-89: Comment in code_snapshot must NOT suppress SQL injection finding
// ---------------------------------------------------------------------------

describe('CWE-89: comment bypass prevention', () => {
  it('a comment containing "parameterized" does NOT suppress CWE-89', () => {
    const map = buildMap(
      `app.get('/users', (req, res) => {
        // parameterized query
        db.query("SELECT * FROM users WHERE id = " + req.body.id);
      });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.id',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.id',
          attack_surface: ['user_input'],
          data_out: [{ name: 'id', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          // The comment says "parameterized" but the actual code is string concatenation
          code_snapshot: '// parameterized query\ndb.query("SELECT * FROM users WHERE id = " + req.body.id)',
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
  });

  it('a multi-line comment with "parameterized" does NOT suppress CWE-89', () => {
    const map = buildMap(
      `app.get('/users', (req, res) => {
        /* TODO: use parameterized queries here */
        db.query("SELECT * FROM users WHERE id = " + req.body.id);
      });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.id',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.id',
          attack_surface: ['user_input'],
          data_out: [{ name: 'id', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          code_snapshot: '/* TODO: use parameterized queries here */\ndb.query("SELECT * FROM users WHERE id = " + req.body.id)',
          attack_surface: ['sql_sink'],
          data_in: [{ name: 'id', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('actual parameterized code DOES suppress CWE-89', () => {
    const map = buildMap(
      `app.get('/users', (req, res) => {
        db.query("SELECT * FROM users WHERE id = $1", [req.body.id]);
      });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.id',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.id',
          attack_surface: ['user_input'],
          data_out: [{ name: 'id', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'db.query()',
          node_subtype: 'sql_query',
          code_snapshot: 'db.query("SELECT * FROM users WHERE id = $1", [req.body.id])',
          attack_surface: ['sql_sink'],
          data_in: [{ name: 'id', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('a Python hash comment with "prepare" does NOT suppress CWE-89', () => {
    const map = buildMap(
      `cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # TODO: prepare statement`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'user_id',
          node_subtype: 'http_param',
          code_snapshot: 'user_id = request.args.get("id")',
          attack_surface: ['user_input'],
          data_out: [{ name: 'user_id', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'STORAGE',
          label: 'cursor.execute()',
          node_subtype: 'sql_query',
          code_snapshot: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # TODO: prepare statement',
          attack_surface: ['sql_sink'],
          data_in: [{ name: 'user_id', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-89');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-79: Comment bypass for XSS safe-pattern
// ---------------------------------------------------------------------------

describe('CWE-79: comment bypass prevention', () => {
  it('a comment containing "sanitize" does NOT suppress CWE-79', () => {
    const map = buildMap(
      `app.get('/page', (req, res) => {
        // sanitize input before render
        res.send("<div>" + req.query.name + "</div>");
      });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.name',
          node_subtype: 'http_param',
          code_snapshot: 'req.query.name',
          attack_surface: ['user_input'],
          data_out: [{ name: 'name', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.send()',
          node_subtype: 'html_response',
          code_snapshot: '// sanitize input before render\nres.send("<div>" + req.query.name + "</div>")',
          attack_surface: ['html_output'],
          data_in: [{ name: 'name', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-79');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-78: Comment bypass for command injection safe-pattern
// ---------------------------------------------------------------------------

describe('CWE-78: comment bypass prevention', () => {
  it('a comment containing "sanitize" does NOT suppress CWE-78', () => {
    const map = buildMap(
      `app.get('/run', (req, res) => {
        // sanitize the command
        exec(req.body.cmd);
      });`,
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.cmd',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.cmd',
          attack_surface: ['user_input'],
          data_out: [{ name: 'cmd', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'EXTERNAL',
          label: 'exec()',
          node_subtype: 'shell_exec',
          code_snapshot: '// sanitize the command\nexec(req.body.cmd)',
          attack_surface: ['shell_exec'],
          data_in: [{ name: 'cmd', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-78');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Generic factory (via _helpers.ts) — comment bypass
// ---------------------------------------------------------------------------

describe('Generated verifiers: comment bypass prevention', () => {
  // CWE-113 (HTTP Response Splitting) uses the generic factory
  // Safe pattern typically matches "sanitize" or "encode" — a comment should not suppress it
  it('a comment containing safe-pattern words does not suppress generated verifier findings', () => {
    // Use stripComments directly to verify it works on the pattern the factory would use
    const codeWithComment = '// encode the output\nres.setHeader("X-Custom", userInput)';
    const codeOnly = stripComments(codeWithComment);
    expect(codeOnly).not.toMatch(/encode/);

    const codeWithActualEncode = 'res.setHeader("X-Custom", encodeURIComponent(userInput))';
    const codeOnly2 = stripComments(codeWithActualEncode);
    expect(codeOnly2).toMatch(/encode/);
  });
});
