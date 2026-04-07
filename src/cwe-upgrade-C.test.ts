/**
 * CWE Upgrade Tests — Agent C
 *
 * Tests 5 hand-upgraded CWE verifiers from batches 011-015.
 * Each CWE gets:
 *   1. VULNERABLE: realistic code that SHOULD trigger (holds=false, findings>0)
 *   2. SAFE: code with proper mitigation (holds=true, findings=0)
 *   3. Additional edge cases where appropriate
 *
 * Upgraded CWEs:
 *   CWE-367: TOCTOU Race Condition (batch_011)
 *   CWE-620: Unverified Password Change (batch_012)
 *   CWE-532: Sensitive Information in Log File (batch_013)
 *   CWE-829: Inclusion from Untrusted Control Sphere (batch_014)
 *   CWE-330: Use of Insufficiently Random Values (batch_015)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createNode, createNeuralMap, resetSequence } from './types';
import type { NeuralMap, NeuralMapNode } from './types';

// Import the upgraded verifiers directly
import { verifyCWE367 } from './generated/batch_011';
import { verifyCWE620 } from './generated/batch_012';
import { verifyCWE532 } from './generated/batch_013';
import { verifyCWE829 } from './generated/batch_014';
import { verifyCWE330 } from './generated/batch_015';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildMap(nodes: NeuralMapNode[]): NeuralMap {
  const map = createNeuralMap('test.js', '// test code');
  map.nodes = nodes;
  return map;
}

// ===========================================================================
// CWE-367: TOCTOU Race Condition
// ===========================================================================

describe('CWE-367: TOCTOU Race Condition (UPGRADED)', () => {
  beforeEach(() => resetSequence());

  it('VULNERABLE: stat() then open() — classic TOCTOU', () => {
    const check = createNode({
      node_type: 'CONTROL',
      id: 'check1',
      label: 'fs.stat(filePath)',
      code_snapshot: 'const stats = fs.statSync(filePath); if (stats.size > MAX_SIZE) throw new Error("too large")',
      edges: [{ target: 'use1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const use = createNode({
      node_type: 'TRANSFORM',
      id: 'use1',
      label: 'fs.readFile(filePath)',
      code_snapshot: 'const data = fs.readFileSync(filePath)',
      edges: [],
    });
    const map = buildMap([check, use]);
    const result = verifyCWE367(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('medium');
    expect(result.findings[0].description).toContain('symlink');
  });

  it('VULNERABLE: access() then open() — permission TOCTOU', () => {
    const check = createNode({
      node_type: 'CONTROL',
      id: 'check1',
      label: 'fs.access check',
      code_snapshot: 'fs.access(uploadPath, fs.constants.W_OK, (err) => {',
      edges: [{ target: 'use1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const use = createNode({
      node_type: 'STORAGE',
      id: 'use1',
      label: 'fs.writeFile',
      code_snapshot: 'fs.writeFile(uploadPath, data, callback)',
      edges: [],
    });
    const map = buildMap([check, use]);
    const result = verifyCWE367(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: open with O_EXCL flag — atomic create', () => {
    const check = createNode({
      node_type: 'CONTROL',
      id: 'check1',
      label: 'existsSync check',
      code_snapshot: 'if (fs.existsSync(lockFile)) return',
      edges: [{ target: 'use1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const use = createNode({
      node_type: 'TRANSFORM',
      id: 'use1',
      label: 'atomic create',
      code_snapshot: 'fs.open(lockFile, O_EXCL | O_CREAT | O_WRONLY, (err, fd) => {',
      edges: [],
    });
    const map = buildMap([check, use]);
    const result = verifyCWE367(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: fstat on file descriptor instead of path', () => {
    const check = createNode({
      node_type: 'CONTROL',
      id: 'check1',
      label: 'stat check',
      code_snapshot: 'const stats = fs.statSync(filePath)',
      edges: [{ target: 'use1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const use = createNode({
      node_type: 'TRANSFORM',
      id: 'use1',
      label: 'fstat + read',
      code_snapshot: 'const fd = fs.openSync(filePath); const real = fs.fstatSync(fd); fs.readSync(fd, buf)',
      edges: [],
    });
    const map = buildMap([check, use]);
    const result = verifyCWE367(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('NO FINDING: non-file CONTROL -> TRANSFORM (no file check in code)', () => {
    // This tests specificity: generic validation should NOT trigger TOCTOU
    const check = createNode({
      node_type: 'CONTROL',
      id: 'check1',
      label: 'input validation',
      code_snapshot: 'if (!isValid(userInput)) throw new Error("invalid")',
      edges: [{ target: 'use1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const use = createNode({
      node_type: 'TRANSFORM',
      id: 'use1',
      label: 'transform data',
      code_snapshot: 'const result = processData(userInput)',
      edges: [],
    });
    const map = buildMap([check, use]);
    const result = verifyCWE367(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ===========================================================================
// CWE-620: Unverified Password Change
// ===========================================================================

describe('CWE-620: Unverified Password Change (UPGRADED)', () => {
  beforeEach(() => resetSequence());

  it('VULNERABLE: password change without current password verification', () => {
    const ingress = createNode({
      node_type: 'INGRESS',
      id: 'ing1',
      label: 'req.body.newPassword',
      code_snapshot: 'const { newPassword } = req.body',
      data_out: [{ name: 'newPassword', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
      edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const auth = createNode({
      node_type: 'AUTH',
      id: 'auth1',
      label: 'user.setPassword()',
      code_snapshot: 'await user.setPassword(newPassword); await user.save()',
      edges: [],
    });
    const map = buildMap([ingress, auth]);
    const result = verifyCWE620(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].description).toContain('stolen session');
  });

  it('VULNERABLE: bcrypt.hash without comparing old password first', () => {
    const ingress = createNode({
      node_type: 'INGRESS',
      id: 'ing1',
      label: 'req.body',
      code_snapshot: 'const newPwd = req.body.password',
      data_out: [{ name: 'password', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
      edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const auth = createNode({
      node_type: 'AUTH',
      id: 'auth1',
      label: 'updatePassword',
      code_snapshot: 'const hashed = await bcrypt.hash(newPwd, 10); await db.query("UPDATE users SET password = $1", [hashed])',
      edges: [],
    });
    const map = buildMap([ingress, auth]);
    const result = verifyCWE620(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: verifies current password with bcrypt.compare before change', () => {
    const ingress = createNode({
      node_type: 'INGRESS',
      id: 'ing1',
      label: 'req.body',
      code_snapshot: 'const { currentPassword, newPassword } = req.body',
      data_out: [{ name: 'newPassword', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
      edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const control = createNode({
      node_type: 'CONTROL',
      id: 'ctrl1',
      label: 'verify current password',
      code_snapshot: 'const match = await bcrypt.compare(currentPassword, user.passwordHash); if (!match) throw new Error("wrong password")',
      edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const auth = createNode({
      node_type: 'AUTH',
      id: 'auth1',
      label: 'user.setPassword()',
      code_snapshot: 'await user.setPassword(newPassword); await user.save()',
      edges: [],
    });
    const map = buildMap([ingress, control, auth]);
    const result = verifyCWE620(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('NO FINDING: AUTH node without password change operations', () => {
    // Specificity test: login should not trigger unverified password change
    const ingress = createNode({
      node_type: 'INGRESS',
      id: 'ing1',
      label: 'req.body.password',
      code_snapshot: 'const password = req.body.password',
      data_out: [{ name: 'password', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'SECRET' }],
      edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const auth = createNode({
      node_type: 'AUTH',
      id: 'auth1',
      label: 'login check',
      code_snapshot: 'const isValid = await bcrypt.compare(password, user.hash); if (isValid) createSession(user)',
      edges: [],
    });
    const map = buildMap([ingress, auth]);
    const result = verifyCWE620(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ===========================================================================
// CWE-532: Sensitive Information in Log File
// ===========================================================================

describe('CWE-532: Sensitive Info in Log File (UPGRADED)', () => {
  beforeEach(() => resetSequence());

  it('VULNERABLE: logging password to console.log', () => {
    const storage = createNode({
      node_type: 'STORAGE',
      id: 'store1',
      label: 'user.password',
      code_snapshot: 'const password = user.password',
      data_out: [{ name: 'password', source: 'db', data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
      edges: [{ target: 'log1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const logSink = createNode({
      node_type: 'EGRESS',
      id: 'log1',
      label: 'console.log()',
      code_snapshot: 'console.log("User login:", { email: user.email, password: user.password })',
      edges: [],
    });
    const map = buildMap([storage, logSink]);
    const result = verifyCWE532(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('password');
    expect(result.findings[0].description).toContain('log');
  });

  it('VULNERABLE: logging API key to winston logger', () => {
    const storage = createNode({
      node_type: 'STORAGE',
      id: 'store1',
      label: 'config.apiKey',
      code_snapshot: 'const apiKey = config.apiKey',
      data_out: [{ name: 'apiKey', source: 'config', data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
      edges: [{ target: 'log1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const logSink = createNode({
      node_type: 'EGRESS',
      id: 'log1',
      label: 'logger.info()',
      code_snapshot: 'logger.info("Request to external API", { url, apiKey, response })',
      edges: [],
    });
    const map = buildMap([storage, logSink]);
    const result = verifyCWE532(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('apiKey');
  });

  it('SAFE: redacted password before logging', () => {
    const storage = createNode({
      node_type: 'STORAGE',
      id: 'store1',
      label: 'user credentials',
      code_snapshot: 'const password = user.password',
      data_out: [{ name: 'password', source: 'db', data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
      edges: [{ target: 'log1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const logSink = createNode({
      node_type: 'EGRESS',
      id: 'log1',
      label: 'logger.info()',
      code_snapshot: 'logger.info("User login:", { email: user.email, password: "[REDACTED]" })',
      edges: [],
    });
    const map = buildMap([storage, logSink]);
    const result = verifyCWE532(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: logging with field masking', () => {
    const storage = createNode({
      node_type: 'STORAGE',
      id: 'store1',
      label: 'request.token',
      code_snapshot: 'const token = req.headers.authorization',
      data_out: [{ name: 'token', source: 'request', data_type: 'string', tainted: false, sensitivity: 'AUTH' }],
      edges: [{ target: 'log1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const logSink = createNode({
      node_type: 'EGRESS',
      id: 'log1',
      label: 'pino logger',
      code_snapshot: 'logger.info({ token: mask(token, "***") }, "API request received")',
      edges: [],
    });
    const map = buildMap([storage, logSink]);
    const result = verifyCWE532(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('NO FINDING: logging non-sensitive data', () => {
    // Specificity: logging a username (not a password) should not trigger
    const storage = createNode({
      node_type: 'STORAGE',
      id: 'store1',
      label: 'user.displayName',
      code_snapshot: 'const displayName = user.displayName',
      data_out: [{ name: 'displayName', source: 'db', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [{ target: 'log1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const logSink = createNode({
      node_type: 'EGRESS',
      id: 'log1',
      label: 'console.log()',
      code_snapshot: 'console.log("User logged in:", displayName)',
      edges: [],
    });
    const map = buildMap([storage, logSink]);
    const result = verifyCWE532(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ===========================================================================
// CWE-829: Inclusion from Untrusted Control Sphere
// ===========================================================================

describe('CWE-829: Inclusion from Untrusted Source (UPGRADED)', () => {
  beforeEach(() => resetSequence());

  it('VULNERABLE: script tag from CDN without SRI', () => {
    const structural = createNode({
      node_type: 'STRUCTURAL',
      id: 'struct1',
      label: 'index.html script include',
      code_snapshot: '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>',
      edges: [{ target: 'ext1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const external = createNode({
      node_type: 'EXTERNAL',
      id: 'ext1',
      label: 'CDN lodash',
      code_snapshot: 'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js',
      edges: [],
    });
    const map = buildMap([structural, external]);
    const result = verifyCWE829(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].description).toContain('integrity');
  });

  it('VULNERABLE: eval of fetched code', () => {
    const structural = createNode({
      node_type: 'STRUCTURAL',
      id: 'struct1',
      label: 'dynamic code loader',
      code_snapshot: 'const code = await fetch(pluginUrl).then(r => r.text()); eval(code)',
      edges: [{ target: 'ext1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const external = createNode({
      node_type: 'EXTERNAL',
      id: 'ext1',
      label: 'remote plugin',
      code_snapshot: 'eval(fetchedCode)',
      edges: [],
    });
    const map = buildMap([structural, external]);
    const result = verifyCWE829(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: script with SRI integrity attribute', () => {
    const structural = createNode({
      node_type: 'STRUCTURAL',
      id: 'struct1',
      label: 'index.html script include',
      code_snapshot: '<script src="https://cdn.example.com/lib.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K" crossorigin="anonymous"></script>',
      edges: [{ target: 'ext1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const external = createNode({
      node_type: 'EXTERNAL',
      id: 'ext1',
      label: 'CDN lib',
      code_snapshot: 'https://cdn.example.com/lib.js loaded with SRI',
      edges: [],
    });
    const map = buildMap([structural, external]);
    const result = verifyCWE829(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: dependency with lockfile hash verification', () => {
    const structural = createNode({
      node_type: 'STRUCTURAL',
      id: 'struct1',
      label: 'package.json require',
      code_snapshot: 'const express = require("express")',
      edges: [{ target: 'ext1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const external = createNode({
      node_type: 'EXTERNAL',
      id: 'ext1',
      label: 'npm express',
      code_snapshot: 'express loaded from CDN, verified via package-lock.json hash',
      edges: [],
    });
    const map = buildMap([structural, external]);
    const result = verifyCWE829(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('NO FINDING: internal module inclusion (not external)', () => {
    // Specificity: local imports should not trigger
    const structural = createNode({
      node_type: 'STRUCTURAL',
      id: 'struct1',
      label: 'local import',
      code_snapshot: 'const utils = require("./utils")',
      edges: [{ target: 'ext1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const external = createNode({
      node_type: 'EXTERNAL',
      id: 'ext1',
      label: 'local utils module',
      code_snapshot: 'module.exports = { helper: () => {} }',
      edges: [],
    });
    const map = buildMap([structural, external]);
    const result = verifyCWE829(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ===========================================================================
// CWE-330: Use of Insufficiently Random Values
// ===========================================================================

describe('CWE-330: Insufficient Random Values (UPGRADED)', () => {
  beforeEach(() => resetSequence());

  it('VULNERABLE: Math.random() for session token', () => {
    const transform = createNode({
      node_type: 'TRANSFORM',
      id: 'xform1',
      label: 'token generation',
      code_snapshot: 'const token = Math.random().toString(36).substring(2)',
      edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const auth = createNode({
      node_type: 'AUTH',
      id: 'auth1',
      label: 'session creation',
      code_snapshot: 'req.session.token = token; sessions.set(token, userId)',
      edges: [],
    });
    const map = buildMap([transform, auth]);
    const result = verifyCWE330(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].description).toContain('Math.random');
    expect(result.findings[0].description).toContain('predictable');
  });

  it('VULNERABLE: random.randint for CSRF token (Python)', () => {
    const transform = createNode({
      node_type: 'TRANSFORM',
      id: 'xform1',
      label: 'csrf token gen',
      code_snapshot: 'csrf_token = str(random.randint(100000, 999999))',
      language: 'python',
      edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const auth = createNode({
      node_type: 'AUTH',
      id: 'auth1',
      label: 'csrf validation',
      code_snapshot: 'session["csrf_token"] = csrf_token',
      edges: [],
    });
    const map = buildMap([transform, auth]);
    const result = verifyCWE330(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('random.randint');
  });

  it('SAFE: crypto.randomBytes for token generation', () => {
    const transform = createNode({
      node_type: 'TRANSFORM',
      id: 'xform1',
      label: 'secure token gen',
      code_snapshot: 'const token = crypto.randomBytes(32).toString("hex")',
      edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const auth = createNode({
      node_type: 'AUTH',
      id: 'auth1',
      label: 'session creation',
      code_snapshot: 'req.session.token = token; sessions.set(token, userId)',
      edges: [],
    });
    const map = buildMap([transform, auth]);
    const result = verifyCWE330(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: Python secrets module', () => {
    const transform = createNode({
      node_type: 'TRANSFORM',
      id: 'xform1',
      label: 'secure token gen',
      code_snapshot: 'token = secrets.token_hex(32)',
      language: 'python',
      edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const auth = createNode({
      node_type: 'AUTH',
      id: 'auth1',
      label: 'session token',
      code_snapshot: 'session["token"] = token',
      edges: [],
    });
    const map = buildMap([transform, auth]);
    const result = verifyCWE330(map);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('NO FINDING: Math.random for non-security purpose', () => {
    // Specificity: Math.random for UI shuffling should not trigger
    const transform = createNode({
      node_type: 'TRANSFORM',
      id: 'xform1',
      label: 'shuffle items',
      code_snapshot: 'const shuffled = items.sort(() => Math.random() - 0.5)',
      edges: [{ target: 'egress1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const egress = createNode({
      node_type: 'EGRESS',
      id: 'egress1',
      label: 'render list',
      code_snapshot: 'res.json({ items: shuffled })',
      edges: [],
    });
    const map = buildMap([transform, egress]);
    const result = verifyCWE330(map);
    // Should not trigger because the sink is EGRESS, not AUTH
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});
