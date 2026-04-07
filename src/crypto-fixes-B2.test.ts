/**
 * Crypto Fixes B2 — Juliet Gap Tests
 *
 * Tests that the 4 upgraded crypto verifiers (batch_crypto_B2) correctly
 * detect vulnerabilities that Juliet exposes but OWASP Benchmark did not.
 *
 * The root cause: OWASP Benchmark uses different code patterns than Juliet.
 *   - CWE-336: OWASP uses java.util.Random. Juliet uses SecureRandom.setSeed(hardcoded).
 *   - CWE-614: OWASP uses setSecure(false). Juliet omits setSecure() entirely.
 *   - CWE-759: OWASP has passwordFile context. Juliet has bare MessageDigest.
 *   - CWE-760: OWASP has password context. Juliet has bare Random + MessageDigest.
 *
 * Each CWE gets:
 *   - VULNERABLE: Juliet-style pattern (the gap that was missed)
 *   - VULNERABLE: OWASP-style pattern (regression check — must still pass)
 *   - SAFE: good() variant from Juliet (must NOT fire)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { NeuralMap } from './types.js';
import { verify } from './verifier';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function buildJavaMap(funcName: string, code: string, extraNodes?: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap(`${funcName}.java`, code);
  const funcNode = createNode({
    label: funcName,
    node_type: 'STRUCTURAL',
    node_subtype: 'function',
    language: 'java',
    code_snapshot: code.slice(0, 500),
    analysis_snapshot: code,
  });
  map.nodes = [funcNode, ...(extraNodes || []).map(n => createNode({ language: 'java', ...n }))];
  return map;
}

// ===========================================================================
// CWE-336: Same Seed in PRNG
// ===========================================================================

describe('CWE-336 B2: Same Seed in PRNG (Juliet-aware)', () => {
  it('VULNERABLE [Juliet gap]: SecureRandom.setSeed(hardcoded byte array)', () => {
    // This is the EXACT Juliet pattern: SecureRandom with hardcoded seed
    const code = `public void bad() throws Throwable {
      final byte[] SEED = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};
      SecureRandom secureRandom = new SecureRandom();
      secureRandom.setSeed(SEED);
      IO.writeLine("" + secureRandom.nextInt());
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-336');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f =>
      f.description.includes('setSeed') || f.description.includes('hardcoded')
    )).toBe(true);
  });

  it('VULNERABLE [OWASP regression]: java.util.Random()', () => {
    // OWASP Benchmark pattern — must still detect
    const code = `public void doPost() {
      float rand = new java.util.Random().nextFloat();
      String key = Float.toString(rand);
    }`;
    const map = buildJavaMap('doPost', code, [{
      label: 'new java.util.Random().nextFloat()',
      node_type: 'TRANSFORM',
      node_subtype: 'compute',
      code_snapshot: 'new java.util.Random().nextFloat()',
    }]);
    const result = verify(map, 'CWE-336');
    expect(result.holds).toBe(false);
  });

  it('VULNERABLE [OWASP regression]: Math.random()', () => {
    const code = `public void doPost() {
      double value = java.lang.Math.random();
    }`;
    const map = buildJavaMap('doPost', code, [{
      label: 'java.lang.Math.random()',
      node_type: 'TRANSFORM',
      node_subtype: 'compute',
      code_snapshot: 'java.lang.Math.random()',
    }]);
    const result = verify(map, 'CWE-336');
    expect(result.holds).toBe(false);
  });

  it('SAFE [Juliet good()]: SecureRandom without setSeed', () => {
    // Juliet good() variant: SecureRandom self-seeded
    const code = `public void good1() throws Throwable {
      SecureRandom secureRandom = new SecureRandom();
      IO.writeLine("" + secureRandom.nextInt());
      IO.writeLine("" + secureRandom.nextInt());
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-336');
    expect(result.holds).toBe(true);
  });

  it('SAFE: SecureRandom.getInstance("SHA1PRNG") without explicit seed', () => {
    const code = `public void doPost() {
      int randNumber = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);
    }`;
    const map = buildJavaMap('doPost', code, [{
      label: 'SecureRandom.getInstance("SHA1PRNG").nextInt(99)',
      node_type: 'TRANSFORM',
      node_subtype: 'compute',
      code_snapshot: 'java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99)',
    }]);
    const result = verify(map, 'CWE-336');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-614: Sensitive Cookie Without Secure Flag
// ===========================================================================

describe('CWE-614 B2: Cookie Without Secure Flag (Juliet-aware)', () => {
  it('VULNERABLE [Juliet gap]: new Cookie() + addCookie() without setSecure()', () => {
    // Juliet pattern: Cookie created and added, but setSecure() never called
    const code = `public void bad(HttpServletRequest request, HttpServletResponse response) {
      Cookie cookie = new Cookie("SecretMessage", "test");
      if (request.isSecure()) {
        response.addCookie(cookie);
      }
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-614');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f =>
      f.description.includes('setSecure') || f.description.includes('Secure flag')
    )).toBe(true);
  });

  it('VULNERABLE [OWASP regression]: cookie.setSecure(false)', () => {
    const code = `public void doPost() {
      javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);
      cookie.setSecure(false);
      cookie.setHttpOnly(true);
      response.addCookie(cookie);
    }`;
    const map = buildJavaMap('doPost', code);
    const result = verify(map, 'CWE-614');
    expect(result.holds).toBe(false);
  });

  it('SAFE [Juliet good()]: Cookie with setSecure(true)', () => {
    // Juliet good() variant
    const code = `public void good1(HttpServletRequest request, HttpServletResponse response) {
      Cookie cookie = new Cookie("SecretMessage", "Drink your Ovaltine");
      if (request.isSecure()) {
        cookie.setSecure(true);
        response.addCookie(cookie);
      }
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-614');
    expect(result.holds).toBe(true);
  });

  it('SAFE: OWASP-style cookie with setSecure(true)', () => {
    const code = `public void doPost() {
      javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);
      cookie.setSecure(true);
      cookie.setHttpOnly(true);
      response.addCookie(cookie);
    }`;
    const map = buildJavaMap('doPost', code);
    const result = verify(map, 'CWE-614');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-759: Hash Without Salt
// ===========================================================================

describe('CWE-759 B2: Hash Without Salt (Juliet-aware)', () => {
  it('VULNERABLE [Juliet gap]: MessageDigest.digest() with no salt, no password keyword', () => {
    // Juliet pattern: bare MessageDigest with no password context at all
    const code = `public void bad() throws Throwable {
      MessageDigest hash = MessageDigest.getInstance("SHA-512");
      byte[] hashValue = hash.digest("hash me".getBytes("UTF-8"));
      IO.writeLine(IO.toHex(hashValue));
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-759');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f =>
      f.description.includes('salt') || f.description.includes('MessageDigest')
    )).toBe(true);
  });

  it('VULNERABLE [OWASP regression]: MessageDigest with passwordFile storage', () => {
    const code = `public void doPost() {
      java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
      md.update(input);
      byte[] result = md.digest();
      java.io.FileWriter fw = new java.io.FileWriter(new java.io.File("passwordFile.txt"), true);
      fw.write("hash_value=" + result);
    }`;
    const map = buildJavaMap('doPost', code, [{
      label: 'java.security.MessageDigest.getInstance("SHA-256")',
      node_type: 'TRANSFORM',
      node_subtype: 'encrypt',
      code_snapshot: 'java.security.MessageDigest.getInstance("SHA-256")',
    }, {
      label: 'fw.write',
      node_type: 'STORAGE',
      node_subtype: 'db_write',
      code_snapshot: 'fw.write("hash_value=" + result)',
    }]);
    const result = verify(map, 'CWE-759');
    expect(result.holds).toBe(false);
  });

  it('SAFE [Juliet good()]: MessageDigest with SecureRandom salt via update()', () => {
    // Juliet good() variant: salt added via hash.update(prng.generateSeed(32))
    const code = `public void good1() throws Throwable {
      MessageDigest hash = MessageDigest.getInstance("SHA-512");
      SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
      hash.update(prng.generateSeed(32));
      byte[] hashValue = hash.digest("hash me".getBytes("UTF-8"));
      IO.writeLine(IO.toHex(hashValue));
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-759');
    expect(result.holds).toBe(true);
  });

  it('SAFE: bcrypt for password hashing', () => {
    const code = `public void doPost() {
      String hash = BCrypt.hashpw(password, BCrypt.gensalt());
    }`;
    const map = buildJavaMap('doPost', code);
    const result = verify(map, 'CWE-759');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-760: Hash with Predictable Salt
// ===========================================================================

describe('CWE-760 B2: Hash with Predictable Salt (Juliet-aware)', () => {
  it('VULNERABLE [Juliet gap]: java.util.Random as salt for MessageDigest, no password keyword', () => {
    // Juliet pattern: Random used as salt, no password keyword
    const code = `public void bad() throws Throwable {
      Random random = new Random();
      MessageDigest hash = MessageDigest.getInstance("SHA-512");
      hash.update((Integer.toString(random.nextInt())).getBytes("UTF-8"));
      byte[] hashValue = hash.digest("hash me".getBytes("UTF-8"));
      IO.writeLine(IO.toHex(hashValue));
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-760');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f =>
      f.description.includes('Random') || f.description.includes('predictable')
    )).toBe(true);
  });

  it('VULNERABLE [password context]: hardcoded salt with password', () => {
    // Uses pattern: .update(password + "hardcoded") — detected by HARD_SALT_RE
    const code = `public void hashPassword() {
      String password = getPassword();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(password + "static_salt_123");
      byte[] result = md.digest();
    }`;
    const map = buildJavaMap('hashPassword', code);
    const result = verify(map, 'CWE-760');
    expect(result.holds).toBe(false);
  });

  it('SAFE [Juliet good()]: SecureRandom for salt', () => {
    // Juliet good() variant
    const code = `public void good1() throws Throwable {
      SecureRandom secureRandom = new SecureRandom();
      MessageDigest hash = MessageDigest.getInstance("SHA-512");
      SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
      hash.update(prng.generateSeed(32));
      byte[] hashValue = hash.digest("hash me".getBytes("UTF-8"));
      IO.writeLine(IO.toHex(hashValue));
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-760');
    expect(result.holds).toBe(true);
  });

  it('SAFE: bcrypt (handles salt internally)', () => {
    const code = `public void doPost() {
      String hash = BCrypt.hashpw(password, BCrypt.gensalt());
    }`;
    const map = buildJavaMap('doPost', code);
    const result = verify(map, 'CWE-760');
    expect(result.holds).toBe(true);
  });
});
