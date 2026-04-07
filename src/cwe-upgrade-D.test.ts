/**
 * CWE Upgrade D — Hand-written verifier tests
 *
 * Tests 5 upgraded CWEs (from factory-generic to hand-written):
 *   CWE-287  Improper Authentication              (batch_018)
 *   CWE-312  Cleartext Storage of Sensitive Info   (batch_018)
 *   CWE-362  Race Condition / TOCTOU               (batch_018)
 *   CWE-208  Observable Timing Discrepancy         (batch_016)
 *   CWE-601  Open Redirect                         (batch_020)
 *
 * Each CWE has:
 *   1. VULNERABLE — map that MUST trigger (holds=false, findings.length > 0)
 *   2. SAFE — map that MUST NOT trigger (holds=true, findings.length === 0)
 *   3. EDGE CASE — boundary condition testing specific logic
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { verify } from './verifier';
import { createNode, createNeuralMap, resetSequence } from './types';
import type { NeuralMap } from './types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildMap(code: string, nodes: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap('test.js', code);
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

// ===========================================================================
// CWE-287: Improper Authentication
// ===========================================================================

describe('CWE-287: Improper Authentication (upgraded)', () => {
  it('VULNERABLE: unauthenticated route directly queries database', () => {
    const map = buildMap(
      'app.get("/api/users/:id", (req, res) => { db.findOne({ id: req.params.id }); });',
      [
        {
          id: 'INGRESS_1', node_type: 'INGRESS',
          label: 'GET /api/users/:id',
          node_subtype: 'http_handler',
          code_snapshot: 'app.get("/api/users/:id", (req, res) => {',
          attack_surface: ['user_input'],
          data_out: [{ name: 'id', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'db.findOne()',
          node_subtype: 'database',
          code_snapshot: 'db.findOne({ id: req.params.id })',
          attack_surface: ['protected_resource'],
          data_in: [{ name: 'id', source: 'INGRESS_1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-287');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].missing).toContain('AUTH');
  });

  it('SAFE: route protected by JWT verification middleware', () => {
    const map = buildMap(
      'app.get("/api/users/:id", requireAuth, (req, res) => { db.findOne({ id: req.params.id }); });',
      [
        {
          id: 'INGRESS_1', node_type: 'INGRESS',
          label: 'GET /api/users/:id',
          node_subtype: 'http_handler',
          code_snapshot: 'app.get("/api/users/:id", requireAuth, (req, res) => {',
          attack_surface: ['user_input'],
          edges: [{ target: 'AUTH_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'AUTH_1', node_type: 'AUTH',
          label: 'requireAuth middleware',
          node_subtype: 'jwt_verify',
          code_snapshot: 'jwt.verify(token, secret); req.user = decoded;',
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'db.findOne()',
          node_subtype: 'database',
          code_snapshot: 'db.findOne({ id: req.params.id })',
          attack_surface: ['protected_resource'],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-287');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('EDGE CASE: passport.authenticate in source code_snapshot suppresses finding', () => {
    const map = buildMap(
      'app.get("/api/data", passport.authenticate("bearer"), handler);',
      [
        {
          id: 'INGRESS_1', node_type: 'INGRESS',
          label: 'GET /api/data',
          node_subtype: 'http_handler',
          code_snapshot: 'app.get("/api/data", passport.authenticate("bearer"), handler)',
          attack_surface: ['user_input'],
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'db.find()',
          node_subtype: 'database',
          code_snapshot: 'db.find({ userId: req.user.id })',
          attack_surface: ['protected_resource'],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-287');
    // passport.authenticate in the source code_snapshot is recognized as safe
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-312: Cleartext Storage of Sensitive Information
// ===========================================================================

describe('CWE-312: Cleartext Storage of Sensitive Info (upgraded)', () => {
  it('VULNERABLE: password stored in database without hashing', () => {
    const map = buildMap(
      'app.post("/register", (req, res) => { db.save({ email: req.body.email, password: req.body.password }); });',
      [
        {
          id: 'INGRESS_1', node_type: 'INGRESS',
          label: 'req.body.password',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.password',
          attack_surface: ['credentials'],
          data_out: [{ name: 'password', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'db.save()',
          node_subtype: 'database',
          code_snapshot: 'db.save({ email: req.body.email, password: req.body.password })',
          attack_surface: [],
          data_in: [{ name: 'password', source: 'INGRESS_1', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-312');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    // Should be critical for password (not just high)
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].missing).toContain('hash');
  });

  it('SAFE: password hashed with bcrypt before storage', () => {
    const map = buildMap(
      'const hash = await bcrypt.hash(req.body.password, 12); db.save({ passwordHash: hash });',
      [
        {
          id: 'INGRESS_1', node_type: 'INGRESS',
          label: 'req.body.password',
          node_subtype: 'http_body',
          code_snapshot: 'req.body.password',
          attack_surface: ['credentials'],
          edges: [{ target: 'TRANSFORM_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'TRANSFORM_1', node_type: 'TRANSFORM',
          label: 'bcrypt.hash()',
          node_subtype: 'crypto_hash',
          code_snapshot: 'const hash = await bcrypt.hash(req.body.password, 12)',
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'db.save()',
          node_subtype: 'database',
          code_snapshot: 'db.save({ passwordHash: hash })',
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-312');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: API key stored in cleartext (non-password path)', () => {
    const map = buildMap(
      'db.save({ userId: user.id, apiKey: generateApiKey() });',
      [
        {
          id: 'TRANSFORM_1', node_type: 'TRANSFORM',
          label: 'generateApiKey()',
          node_subtype: 'key_generation',
          code_snapshot: 'const apiKey = generateApiKey(); // api_key for external access',
          attack_surface: [],
          data_out: [{ name: 'apiKey', source: 'TRANSFORM_1', data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'db.save()',
          node_subtype: 'database',
          code_snapshot: 'db.save({ userId: user.id, apiKey: plaintext })',
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-312');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    // Non-password secret should be high, not critical
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].missing).toContain('encryption');
  });
});

// ===========================================================================
// CWE-362: Race Condition / TOCTOU
// ===========================================================================

describe('CWE-362: Race Condition / TOCTOU (upgraded)', () => {
  it('VULNERABLE: TOCTOU — existsSync then writeFileSync', () => {
    const map = buildMap(
      'if (fs.existsSync(path)) { fs.writeFileSync(path, data); }',
      [
        {
          id: 'CONTROL_1', node_type: 'CONTROL',
          label: 'fs.existsSync()',
          node_subtype: 'filesystem_check',
          code_snapshot: 'if (fs.existsSync(path)) {',
          attack_surface: [],
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: true, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'fs.writeFileSync()',
          node_subtype: 'file',
          code_snapshot: 'fs.writeFileSync(path, data)',
          attack_surface: [],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-362');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('TOCTOU');
  });

  it('SAFE: atomic file creation with O_CREAT|O_EXCL', () => {
    const map = buildMap(
      'const fd = fs.openSync(path, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY);',
      [
        {
          id: 'CONTROL_1', node_type: 'CONTROL',
          label: 'O_CREAT|O_EXCL check',
          node_subtype: 'filesystem_check',
          code_snapshot: 'if (needsFile) { // check with O_CREAT and O_EXCL flags',
          attack_surface: [],
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: true, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'fs.openSync()',
          node_subtype: 'file',
          code_snapshot: 'fs.openSync(path, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY)',
          attack_surface: [],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-362');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: shared counter increment without lock', () => {
    const map = buildMap(
      'const count = counter.get(); counter.set(count + 1);',
      [
        {
          id: 'TRANSFORM_1', node_type: 'TRANSFORM',
          label: 'counter read-modify-write',
          node_subtype: 'shared',
          code_snapshot: 'const count = counter.get(); // read then increment counter',
          attack_surface: ['shared_resource'],
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'counter.set()',
          node_subtype: 'shared',
          code_snapshot: 'counter.set(count + 1)',
          attack_surface: ['shared_state'],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-362');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].missing).toContain('lock');
  });

  it('SAFE: database update wrapped in transaction', () => {
    const map = buildMap(
      'await db.transaction(async (trx) => { const bal = await trx.select("balance"); await trx.update({ balance: bal - amount }); });',
      [
        {
          id: 'TRANSFORM_1', node_type: 'TRANSFORM',
          label: 'balance update',
          node_subtype: 'concurrent',
          code_snapshot: 'const balance = await trx.select("balance"); // read balance in transaction',
          attack_surface: ['shared_resource'],
          edges: [{ target: 'STORAGE_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'STORAGE_1', node_type: 'STORAGE',
          label: 'trx.update()',
          node_subtype: 'shared',
          code_snapshot: 'await trx.update({ balance: bal - amount }); // transaction + BEGIN/COMMIT',
          attack_surface: ['shared_state'],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-362');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ===========================================================================
// CWE-208: Observable Timing Discrepancy
// ===========================================================================

describe('CWE-208: Observable Timing Discrepancy (upgraded)', () => {
  it('VULNERABLE: token compared with === operator', () => {
    const map = buildMap(
      'if (req.headers.authorization === storedToken) { grantAccess(); }',
      [
        {
          id: 'AUTH_1', node_type: 'AUTH',
          label: 'token comparison',
          node_subtype: 'token_verify',
          code_snapshot: 'if (req.headers.authorization === storedToken) {',
          attack_surface: ['secret_comparison'],
          edges: [{ target: 'EGRESS_1', edge_type: 'DATA_FLOW', conditional: true, async: false }],
        },
        {
          id: 'EGRESS_1', node_type: 'EGRESS',
          label: 'grantAccess()',
          node_subtype: 'http_response',
          code_snapshot: 'res.json({ success: true })',
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-208');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('constant-time');
  });

  it('SAFE: token compared with crypto.timingSafeEqual', () => {
    const map = buildMap(
      'if (crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))) { grantAccess(); }',
      [
        {
          id: 'AUTH_1', node_type: 'AUTH',
          label: 'token comparison',
          node_subtype: 'token_verify',
          code_snapshot: 'crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(stored))',
          attack_surface: ['secret_comparison'],
          edges: [{ target: 'EGRESS_1', edge_type: 'DATA_FLOW', conditional: true, async: false }],
        },
        {
          id: 'EGRESS_1', node_type: 'EGRESS',
          label: 'response',
          node_subtype: 'http_response',
          code_snapshot: 'res.json({ success: true })',
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-208');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: password compared with bcrypt.compare (inherently constant-time)', () => {
    const map = buildMap(
      'const match = await bcrypt.compare(password, hash);',
      [
        {
          id: 'AUTH_1', node_type: 'AUTH',
          label: 'password comparison',
          node_subtype: 'password_verify',
          code_snapshot: 'const match = await bcrypt.compare(password, storedHash)',
          attack_surface: ['secret_comparison'],
          edges: [{ target: 'EGRESS_1', edge_type: 'DATA_FLOW', conditional: true, async: false }],
        },
        {
          id: 'EGRESS_1', node_type: 'EGRESS',
          label: 'login response',
          node_subtype: 'http_response',
          code_snapshot: 'res.json({ token: jwt.sign(user) })',
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-208');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: HMAC digest compared with == (non-constant-time)', () => {
    const map = buildMap(
      'const sig = crypto.createHmac("sha256", key).update(body).digest("hex"); if (sig == header) { }',
      [
        {
          id: 'AUTH_1', node_type: 'AUTH',
          label: 'HMAC verification',
          node_subtype: 'hmac_verify',
          code_snapshot: 'const hmac = crypto.createHmac("sha256", key).update(body).digest("hex"); if (hmac == providedSignature) {',
          attack_surface: ['secret_comparison'],
          edges: [{ target: 'EGRESS_1', edge_type: 'DATA_FLOW', conditional: true, async: false }],
        },
        {
          id: 'EGRESS_1', node_type: 'EGRESS',
          label: 'webhook response',
          node_subtype: 'http_response',
          code_snapshot: 'res.sendStatus(200)',
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-208');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// CWE-601: Open Redirect
// ===========================================================================

describe('CWE-601: Open Redirect (upgraded)', () => {
  it('VULNERABLE: user-controlled redirect URL without validation', () => {
    const map = buildMap(
      'app.get("/login", (req, res) => { res.redirect(req.query.next); });',
      [
        {
          id: 'INGRESS_1', node_type: 'INGRESS',
          label: 'req.query.next',
          node_subtype: 'query_param',
          code_snapshot: 'const next = req.query.next; // redirect target from URL',
          attack_surface: ['user_input', 'url_input'],
          data_out: [{ name: 'next', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'EGRESS_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'EGRESS_1', node_type: 'EGRESS',
          label: 'res.redirect()',
          node_subtype: 'redirect',
          code_snapshot: 'res.redirect(req.query.next)',
          attack_surface: ['redirect'],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-601');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('evil.com');
  });

  it('SAFE: redirect with allowlist validation', () => {
    const map = buildMap(
      'const allowedUrls = ["/dashboard", "/profile"]; if (allowedUrls.includes(next)) res.redirect(next);',
      [
        {
          id: 'INGRESS_1', node_type: 'INGRESS',
          label: 'req.query.next',
          node_subtype: 'query_param',
          code_snapshot: 'const next = req.query.next;',
          attack_surface: ['user_input'],
          edges: [{ target: 'CONTROL_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CONTROL_1', node_type: 'CONTROL',
          label: 'URL allowlist check',
          node_subtype: 'validation',
          code_snapshot: 'if (allowedUrls.includes(next)) {',
          data_in: [{ name: 'next', source: 'INGRESS_1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'EGRESS_1', edge_type: 'DATA_FLOW', conditional: true, async: false }],
        },
        {
          id: 'EGRESS_1', node_type: 'EGRESS',
          label: 'res.redirect()',
          node_subtype: 'redirect',
          code_snapshot: 'res.redirect(next)',
          attack_surface: ['redirect'],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-601');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: redirect with relative path enforcement (startsWith "/")', () => {
    const map = buildMap(
      'if (url.startsWith("/") && !url.startsWith("//")) res.redirect(url);',
      [
        {
          id: 'INGRESS_1', node_type: 'INGRESS',
          label: 'req.query.redirect',
          node_subtype: 'query_param',
          code_snapshot: 'const url = req.query.redirect;',
          attack_surface: ['user_input'],
          edges: [{ target: 'EGRESS_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'EGRESS_1', node_type: 'EGRESS',
          label: 'res.redirect()',
          node_subtype: 'redirect',
          code_snapshot: 'if (url.startsWith("/") && !url.startsWith("//")) res.redirect(url)',
          attack_surface: ['redirect'],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-601');
    // startsWith("/") pattern is recognized as safe in sink code_snapshot
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: window.location set from URL parameter (client-side)', () => {
    const map = buildMap(
      'const url = new URLSearchParams(location.search).get("goto"); window.location = url;',
      [
        {
          id: 'INGRESS_1', node_type: 'INGRESS',
          label: 'searchParams.get("goto")',
          node_subtype: 'url_param',
          code_snapshot: 'const goto = new URLSearchParams(location.search).get("goto");',
          attack_surface: ['user_input'],
          edges: [{ target: 'EGRESS_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'EGRESS_1', node_type: 'EGRESS',
          label: 'window.location assignment',
          node_subtype: 'redirect',
          code_snapshot: 'window.location = goto;',
          attack_surface: ['redirect'],
          edges: [],
        },
      ],
    );

    const result = verify(map, 'CWE-601');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
