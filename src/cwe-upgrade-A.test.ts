/**
 * CWE Upgrade Tests — Agent A
 *
 * Tests for 5 CWEs upgraded from factory-generated to hand-written quality:
 *   1. CWE-95  (Eval Injection)            — batch_002
 *   2. CWE-787 (Out-of-bounds Write)       — batch_001
 *   3. CWE-113 (HTTP Response Splitting)   — batch_005
 *   4. CWE-759 (Hash without Salt)         — batch_004
 *   5. CWE-377 (Insecure Temporary File)   — batch_003
 *
 * Each CWE gets:
 *   - VULNERABLE: realistic code that SHOULD trigger (holds=false, findings>0)
 *   - SAFE: realistic mitigated code that should NOT trigger (holds=true, findings=0)
 *   - Edge case tests for false positive / false negative boundary
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { NeuralMap, NeuralMapNode } from './types.js';

import { verifyCWE95 } from './generated/batch_002.js';
import { verifyCWE787 } from './generated/batch_001.js';
import { verifyCWE113 } from './generated/batch_005.js';
import { verifyCWE759 } from './generated/batch_004.js';
import { verifyCWE377 } from './generated/batch_003.js';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function buildMap(nodes: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap('test.js', '// test');
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

// ===========================================================================
// CWE-95: Eval Injection
// ===========================================================================

describe('CWE-95: Eval Injection (upgraded)', () => {
  it('VULNERABLE: eval() with direct user input', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.expression',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.expression',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'TRANSFORM',
        label: 'eval(userExpr)',
        node_subtype: 'eval',
        code_snapshot: 'const result = eval(req.body.expression)',
        attack_surface: ['code_execution'],
        edges: [],
      },
    ]);

    const result = verifyCWE95(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].missing).toContain('eval');
  });

  it('VULNERABLE: new Function() with user input', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.query.code',
        node_subtype: 'http_param',
        code_snapshot: 'req.query.code',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'TRANSFORM',
        label: 'new Function(userCode)',
        node_subtype: 'dynamic',
        code_snapshot: 'const fn = new Function("return " + req.query.code)',
        attack_surface: ['code_execution'],
        edges: [],
      },
    ]);

    const result = verifyCWE95(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: setTimeout with string argument from user', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.callback',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.callback',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'TRANSFORM',
        label: 'setTimeout(userString)',
        node_subtype: 'eval',
        code_snapshot: 'setTimeout("doAction(\'" + req.body.callback + "\')", 1000)',
        attack_surface: ['code_execution'],
        edges: [],
      },
    ]);

    const result = verifyCWE95(map);
    expect(result.holds).toBe(false);
  });

  it('SAFE: JSON.parse() is not code execution', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body',
        node_subtype: 'http_body',
        code_snapshot: 'req.body',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'TRANSFORM',
        label: 'JSON.parse(body)',
        node_subtype: 'parse',
        code_snapshot: 'const data = JSON.parse(req.body)',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verifyCWE95(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: vm2 sandboxed execution', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.script',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.script',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'TRANSFORM',
        label: 'vm2.run(script)',
        node_subtype: 'eval',
        code_snapshot: 'const vm = new VM2({ sandbox: {} }); vm.run(req.body.script)',
        attack_surface: ['code_execution'],
        edges: [],
      },
    ]);

    const result = verifyCWE95(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: CONTROL node (input validation) blocks the path', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.expr',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.expr',
        attack_surface: ['user_input'],
        edges: [{ target: 'CTRL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'CTRL', node_type: 'CONTROL',
        label: 'allowlist check',
        node_subtype: 'validation',
        code_snapshot: 'if (!allowedExpressions.includes(expr)) throw new Error("invalid")',
        data_in: [{ name: 'expr', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: true, async: false }],
      },
      {
        id: 'SINK', node_type: 'TRANSFORM',
        label: 'eval(validated)',
        node_subtype: 'eval',
        code_snapshot: 'eval(validatedExpr)',
        attack_surface: ['code_execution'],
        edges: [],
      },
    ]);

    const result = verifyCWE95(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ===========================================================================
// CWE-787: Out-of-bounds Write
// ===========================================================================

describe('CWE-787: Out-of-bounds Write (upgraded)', () => {
  it('VULNERABLE: Buffer.write with user-controlled offset, no bounds check', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.offset',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.offset',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'buf.write(data, offset)',
        node_subtype: 'buffer',
        code_snapshot: 'buf.write(data, parseInt(req.body.offset))',
        attack_surface: ['buffer_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE787(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
  });

  it('VULNERABLE: memcpy with user-controlled size', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'user_size',
        node_subtype: 'http_param',
        code_snapshot: 'size_t len = atoi(user_size)',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'memcpy(dst, src, len)',
        node_subtype: 'memory',
        code_snapshot: 'memcpy(dst, src, len)',
        attack_surface: ['buffer_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE787(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: array index write from user without check', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.params.index',
        node_subtype: 'http_param',
        code_snapshot: 'req.params.index',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'items[idx] = value',
        node_subtype: 'array',
        code_snapshot: 'items[parseInt(req.params.index)] = newValue',
        attack_surface: ['array_access'],
        edges: [],
      },
    ]);

    const result = verifyCWE787(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: bounds check with Math.min before write', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.offset',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.offset',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'buf.write(data, safeOffset)',
        node_subtype: 'buffer',
        code_snapshot: 'const safeOffset = Math.min(offset, buf.length - data.length); buf.write(data, safeOffset)',
        attack_surface: ['buffer_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE787(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: explicit length check guards the write', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.data',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.data',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'buf.write with length check',
        node_subtype: 'buffer',
        code_snapshot: 'if (offset + data.length <= buf.length) { buf.write(data, offset) }',
        attack_surface: ['buffer_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE787(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ===========================================================================
// CWE-113: HTTP Response Splitting
// ===========================================================================

describe('CWE-113: HTTP Response Splitting (upgraded)', () => {
  it('VULNERABLE: setHeader with unsanitized user input', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.query.lang',
        node_subtype: 'http_param',
        code_snapshot: 'req.query.lang',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'EGRESS',
        label: 'res.setHeader("Content-Language", lang)',
        node_subtype: 'header',
        code_snapshot: 'res.setHeader("Content-Language", req.query.lang)',
        attack_surface: ['http_header'],
        edges: [],
      },
    ]);

    const result = verifyCWE113(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].description).toMatch(/header|CRLF|split/i);
  });

  it('VULNERABLE: writeHead with user-controlled Location header', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.query.redirect',
        node_subtype: 'http_param',
        code_snapshot: 'req.query.redirect',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'EGRESS',
        label: 'res.writeHead(302, {"Location": url})',
        node_subtype: 'header',
        code_snapshot: 'res.writeHead(302, {"Location": req.query.redirect})',
        attack_surface: ['http_header'],
        edges: [],
      },
    ]);

    const result = verifyCWE113(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: CRLF stripping before header insertion', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.query.lang',
        node_subtype: 'http_param',
        code_snapshot: 'req.query.lang',
        attack_surface: ['user_input'],
        edges: [{ target: 'XFORM', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'XFORM', node_type: 'TRANSFORM',
        label: 'strip CRLF',
        node_subtype: 'sanitize',
        code_snapshot: 'const safeLang = lang.replace(/[\\r\\n]/g, "")',
        data_in: [{ name: 'lang', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'EGRESS',
        label: 'res.setHeader("Content-Language", safeLang)',
        node_subtype: 'header',
        code_snapshot: 'res.setHeader("Content-Language", safeLang)',
        attack_surface: ['http_header'],
        edges: [],
      },
    ]);

    const result = verifyCWE113(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: encodeURIComponent before header', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.query.url',
        node_subtype: 'http_param',
        code_snapshot: 'req.query.url',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'EGRESS',
        label: 'res.setHeader with encodeURIComponent',
        node_subtype: 'header',
        code_snapshot: 'res.setHeader("Location", encodeURIComponent(req.query.url))',
        attack_surface: ['http_header'],
        edges: [],
      },
    ]);

    const result = verifyCWE113(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('FALSE NEGATIVE GUARD: res.json is not an HTTP header sink', () => {
    // res.json is safe — it's body output, not header manipulation
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.query.data',
        node_subtype: 'http_param',
        code_snapshot: 'req.query.data',
        attack_surface: ['user_input'],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'EGRESS',
        label: 'res.json(data)',
        node_subtype: 'response',
        code_snapshot: 'res.json({ data: req.query.data })',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verifyCWE113(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ===========================================================================
// CWE-759: Use of a One-Way Hash without a Salt
// ===========================================================================

describe('CWE-759: Hash without Salt (upgraded)', () => {
  it('VULNERABLE: MD5 hash of password without salt', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.password',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.password',
        attack_surface: ['user_input'],
        data_out: [{ name: 'password', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
        edges: [{ target: 'HASH', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'HASH', node_type: 'TRANSFORM',
        label: 'createHash("md5")',
        node_subtype: 'hash',
        code_snapshot: 'const hashed = crypto.createHash("md5").update(password).digest("hex")',
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'db.save(hashedPassword)',
        node_subtype: 'credential',
        code_snapshot: 'db.query("UPDATE users SET password = $1", [hashed])',
        attack_surface: ['credential_store'],
        edges: [],
      },
    ]);

    const result = verifyCWE759(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
  });

  it('VULNERABLE: SHA256 without salt stored to credential store', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.password',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.password',
        attack_surface: ['user_input'],
        data_out: [{ name: 'password', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
        edges: [{ target: 'HASH', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'HASH', node_type: 'TRANSFORM',
        label: 'createHash("sha256")',
        node_subtype: 'hash',
        code_snapshot: 'const hashed = crypto.createHash("sha256").update(password).digest("hex")',
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'user.save()',
        node_subtype: 'password',
        code_snapshot: 'user.password = hashed; user.save()',
        attack_surface: ['credential_store'],
        edges: [],
      },
    ]);

    const result = verifyCWE759(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: direct password storage with no hash at all', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.password',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.password',
        attack_surface: ['user_input'],
        data_out: [{ name: 'password', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'db.save(password)',
        node_subtype: 'credential',
        code_snapshot: 'db.query("INSERT INTO users (password) VALUES ($1)", [req.body.password])',
        attack_surface: ['credential_store'],
        edges: [],
      },
    ]);

    const result = verifyCWE759(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: bcrypt.hash includes automatic salting', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.password',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.password',
        attack_surface: ['user_input'],
        data_out: [{ name: 'password', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
        edges: [{ target: 'HASH', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'HASH', node_type: 'TRANSFORM',
        label: 'bcrypt.hash(password, 12)',
        node_subtype: 'hash',
        code_snapshot: 'const hashed = await bcrypt.hash(password, 12)',
        data_in: [{ name: 'password', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'db.save(hashedPassword)',
        node_subtype: 'credential',
        code_snapshot: 'db.query("UPDATE users SET password = $1", [hashed])',
        attack_surface: ['credential_store'],
        edges: [],
      },
    ]);

    const result = verifyCWE759(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: Argon2 hash includes salt parameter', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'INGRESS',
        label: 'req.body.password',
        node_subtype: 'http_body',
        code_snapshot: 'req.body.password',
        attack_surface: ['user_input'],
        data_out: [{ name: 'password', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
        edges: [{ target: 'HASH', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'HASH', node_type: 'TRANSFORM',
        label: 'argon2.hash(password)',
        node_subtype: 'hash',
        code_snapshot: 'const hashed = await argon2.hash(password, { type: argon2.argon2id })',
        data_in: [{ name: 'password', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'db.save(hashedPassword)',
        node_subtype: 'credential',
        code_snapshot: 'db.query("UPDATE users SET password = $1", [hashed])',
        attack_surface: ['credential_store'],
        edges: [],
      },
    ]);

    const result = verifyCWE759(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ===========================================================================
// CWE-377: Insecure Temporary File
// ===========================================================================

describe('CWE-377: Insecure Temporary File (upgraded)', () => {
  it('VULNERABLE: mktemp creates predictable temp file name', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'TRANSFORM',
        label: 'mktemp(/tmp/fileXXXXXX)',
        node_subtype: 'string',
        code_snapshot: 'char *name = mktemp("/tmp/fileXXXXXX")',
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'fopen(name, "w")',
        node_subtype: 'file',
        code_snapshot: 'FILE *f = fopen(name, "w")',
        attack_surface: ['file_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE377(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: tmpnam() used for temp file path', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'TRANSFORM',
        label: 'tmpnam(NULL)',
        node_subtype: 'string',
        code_snapshot: 'const tmpPath = tmpnam(NULL)',
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'open(tmpPath)',
        node_subtype: 'temp',
        code_snapshot: 'int fd = open(tmpPath, O_WRONLY | O_CREAT, 0644)',
        attack_surface: ['file_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE377(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: fs.writeFileSync to predictable /tmp path', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'TRANSFORM',
        label: 'build temp path',
        node_subtype: 'string',
        code_snapshot: 'const tmpFile = "/tmp/upload_" + Date.now()',
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'fs.writeFileSync(tmpFile)',
        node_subtype: 'file',
        code_snapshot: 'fs.writeFileSync(tmpFile, data)',
        attack_surface: ['file_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE377(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: mkstemp creates secure temp file atomically', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'TRANSFORM',
        label: 'mkstemp(template)',
        node_subtype: 'string',
        code_snapshot: 'int fd = mkstemp(template)',
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'write(fd, data)',
        node_subtype: 'file',
        code_snapshot: 'write(fd, data, len)',
        attack_surface: ['file_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE377(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: fs.mkdtemp for Node.js secure temp directory', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'TRANSFORM',
        label: 'fs.mkdtemp(prefix)',
        node_subtype: 'string',
        code_snapshot: 'const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "upload-"))',
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'fs.writeFile in temp dir',
        node_subtype: 'file',
        code_snapshot: 'await fs.writeFile(path.join(tmpDir, "data.bin"), buffer)',
        attack_surface: ['file_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE377(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: O_EXCL flag prevents TOCTOU race', () => {
    const map = buildMap([
      {
        id: 'SRC', node_type: 'TRANSFORM',
        label: 'generate temp name',
        node_subtype: 'string',
        code_snapshot: 'snprintf(path, sizeof(path), "/tmp/data_%d", getpid())',
        edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      },
      {
        id: 'SINK', node_type: 'STORAGE',
        label: 'open with O_EXCL',
        node_subtype: 'file',
        code_snapshot: 'int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600)',
        attack_surface: ['file_write'],
        edges: [],
      },
    ]);

    const result = verifyCWE377(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});
