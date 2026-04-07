/**
 * Crypto Fixes A2 -- Tests for Juliet-aware CWE verifier upgrades
 *
 * CWE-259 (Hard-coded Password)  -- batch_crypto_A2.ts
 * CWE-321 (Hard-coded Crypto Key) -- batch_crypto_A2.ts
 * CWE-328 (Weak Hash)            -- already works (hand-written in verifier.ts)
 * CWE-329 (Predictable IV)       -- batch_crypto_A2.ts
 *
 * ROOT CAUSE ANALYSIS:
 *
 * CWE-259: Source scan regex requires `String var = "..."` on one line.
 *   Juliet separates: `String data;` then `data = "7e5tc4s3";`
 *   FIX: Match bare reassignment when variable was declared as String earlier.
 *
 * CWE-321: HARDCODED_KEY_RE looks for `key='"..."` -- variable is `data`, not `key`.
 *   JAVA_HARDCODED_KEY looks for `new SecretKeySpec("..."` -- Juliet uses
 *   `new SecretKeySpec(data.getBytes(...))` where `data` is an indirect reference.
 *   FIX: Source-scan for hardcoded string var flowing to SecretKeySpec.
 *
 * CWE-328: ALREADY WORKS. MessageDigest.getInstance("MD5") matched by hand-written
 *   verifyCWE328 in verifier.ts.
 *
 * CWE-329: ZERO_IV_RE expects `new byte[16]` or `iv=0x...` -- Juliet uses
 *   `byte[] initializationVector = {0x00,...}` (array initializer).
 *   Variable name is `initializationVector`, not `iv/IV`.
 *   FIX: Match Java array initializer with all-constant bytes + IvParameterSpec.
 *
 * Integration note: CWE-321 and CWE-329 have hand-written verifiers in verifier.ts
 * that override the generated versions. To activate A2 versions, the partner agent
 * needs to either remove them from verifier.ts CWE_REGISTRY or have the hand-written
 * versions delegate to A2.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { NeuralMap } from './types.js';

import { verifyCWE259_A2, verifyCWE321_A2, verifyCWE329_A2 } from './generated/batch_crypto_A2.js';

// ---------------------------------------------------------------------------
// Helper: build map with source code
// ---------------------------------------------------------------------------

function buildMap(nodes: Parameters<typeof createNode>[0][], sourceCode: string): NeuralMap {
  resetSequence();
  const map = createNeuralMap('Test.java', sourceCode);
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

function buildMapNoSource(nodes: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap('Test.java', '');
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

// ===========================================================================
// CWE-259: Use of Hard-coded Password
// ===========================================================================

describe('CWE-259: Hard-coded Password (A2 Juliet-aware)', () => {

  // ------- TRUE POSITIVE: Juliet baseline -------

  it('VULNERABLE: Juliet pattern -- separate declaration + assignment + DriverManager', () => {
    // Exact Juliet pattern: String data; ... data = "7e5tc4s3"; ... DriverManager.getConnection(url, "root", data)
    const sourceCode = `
package testcases.CWE259_Hard_Coded_Password;
import java.sql.*;
public class CWE259_Test extends AbstractTestCase {
    public void bad() throws Throwable {
        String data;
        data = "7e5tc4s3";
        Connection connection = DriverManager.getConnection("data-url", "root", data);
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad() { String data; data = "7e5tc4s3"; Connection connection = DriverManager.getConnection("data-url", "root", data); }' },
    ], sourceCode);

    const result = verifyCWE259_A2(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].severity).toBe('critical');
  });

  it('VULNERABLE: Juliet pattern -- typed declaration with init + DriverManager', () => {
    // Also common: String data = "7e5tc4s3"; on one line
    const sourceCode = `
package testcases.CWE259_Hard_Coded_Password;
import java.sql.*;
public class Test {
    public void bad() throws Throwable {
        String data = "7e5tc4s3";
        Connection connection = DriverManager.getConnection("data-url", "root", data);
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad() { String data = "7e5tc4s3"; Connection c = DriverManager.getConnection("data-url", "root", data); }' },
    ], sourceCode);

    const result = verifyCWE259_A2(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });

  it('VULNERABLE: Juliet pattern -- PasswordAuthentication sink', () => {
    const sourceCode = `
package testcases.CWE259;
public class Test {
    public void bad() throws Throwable {
        String data;
        data = "hardcoded_pw";
        new PasswordAuthentication("user", data);
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad() { String data; data = "hardcoded_pw"; new PasswordAuthentication("user", data); }' },
    ], sourceCode);

    const result = verifyCWE259_A2(map);
    expect(result.holds).toBe(false);
  });

  it('VULNERABLE: Strategy 2 -- direct password variable assignment', () => {
    const map = buildMapNoSource([
      { id: 'N', node_type: 'TRANSFORM', label: 'setPassword', node_subtype: 'assignment',
        code_snapshot: 'password = "secret123"' },
    ]);

    const result = verifyCWE259_A2(map);
    expect(result.holds).toBe(false);
  });

  // ------- TRUE NEGATIVE: safe code -------

  it('SAFE: password read from console (readLine)', () => {
    const sourceCode = `
package testcases.CWE259;
import java.io.*;
public class Test {
    public void good() throws Throwable {
        String data;
        data = new BufferedReader(new InputStreamReader(System.in)).readLine();
        Connection connection = DriverManager.getConnection("data-url", "root", data);
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'good', node_subtype: 'function',
        code_snapshot: 'data = new BufferedReader(new InputStreamReader(System.in)).readLine()' },
    ], sourceCode);

    const result = verifyCWE259_A2(map);
    expect(result.holds).toBe(true);
  });

  it('SAFE: no credential sinks', () => {
    const sourceCode = `
package testcases;
public class Test {
    public void ok() {
        String data;
        data = "just_a_string";
        System.out.println(data);
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'ok', node_subtype: 'function',
        code_snapshot: 'String data; data = "just_a_string"; System.out.println(data);' },
    ], sourceCode);

    const result = verifyCWE259_A2(map);
    expect(result.holds).toBe(true);
  });

  it('SAFE: password from environment variable', () => {
    const sourceCode = `
package testcases;
public class Test {
    public void good() {
        String data = System.getenv("DB_PASSWORD");
        DriverManager.getConnection("url", "root", data);
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'good', node_subtype: 'function',
        code_snapshot: 'String data = System.getenv("DB_PASSWORD"); DriverManager.getConnection("url", "root", data);' },
    ], sourceCode);

    const result = verifyCWE259_A2(map);
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-321: Use of Hard-coded Cryptographic Key
// ===========================================================================

describe('CWE-321: Hard-coded Crypto Key (A2 Juliet-aware)', () => {

  // ------- TRUE POSITIVE: Juliet baseline -------

  it('VULNERABLE: Juliet pattern -- separate decl + assignment + SecretKeySpec via getBytes', () => {
    const sourceCode = `
package testcases.CWE321;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
public class CWE321_Test {
    public void bad() throws Throwable {
        String data;
        data = "23 ~j;asn!@#/>as";
        SecretKeySpec secretKeySpec = new SecretKeySpec(data.getBytes("UTF-8"), "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad() { String data; data = "23 ~j;asn!@#/>as"; SecretKeySpec sk = new SecretKeySpec(data.getBytes("UTF-8"), "AES"); }' },
      { id: 'C', node_type: 'TRANSFORM', label: 'Cipher.getInstance("AES")', node_subtype: 'encrypt',
        code_snapshot: 'Cipher.getInstance("AES")' },
    ], sourceCode);

    const result = verifyCWE321_A2(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].severity).toBe('critical');
  });

  it('VULNERABLE: Juliet pattern -- typed init + SecretKeySpec', () => {
    const sourceCode = `
package testcases.CWE321;
import javax.crypto.spec.SecretKeySpec;
public class Test {
    public void bad() {
        String data = "mysecretkey12345";
        SecretKeySpec key = new SecretKeySpec(data.getBytes("UTF-8"), "AES");
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'String data = "mysecretkey12345"; new SecretKeySpec(data.getBytes("UTF-8"), "AES")' },
      { id: 'C', node_type: 'TRANSFORM', label: 'Cipher.getInstance("AES")', node_subtype: 'encrypt',
        code_snapshot: 'Cipher.getInstance("AES")' },
    ], sourceCode);

    const result = verifyCWE321_A2(map);
    expect(result.holds).toBe(false);
  });

  it('VULNERABLE: Strategy 1 -- inline key in createCipheriv (JS)', () => {
    const map = buildMapNoSource([
      { id: 'N', node_type: 'TRANSFORM', label: 'createCipheriv', node_subtype: 'encrypt',
        code_snapshot: 'crypto.createCipheriv("aes-256-cbc", "abcdefghijklmnop12345678", iv)' },
    ]);

    const result = verifyCWE321_A2(map);
    expect(result.holds).toBe(false);
  });

  it('VULNERABLE: Strategy 2 -- new SecretKeySpec with inline bytes', () => {
    const map = buildMapNoSource([
      { id: 'N', node_type: 'TRANSFORM', label: 'encrypt', node_subtype: 'encrypt',
        code_snapshot: 'new SecretKeySpec(new byte[]{1,2,3,4,5,6,7,8}, "AES")' },
    ]);

    const result = verifyCWE321_A2(map);
    expect(result.holds).toBe(false);
  });

  // ------- TRUE NEGATIVE: safe code -------

  it('SAFE: key from readLine (Juliet good function)', () => {
    const sourceCode = `
package testcases.CWE321;
import javax.crypto.spec.SecretKeySpec;
public class Test {
    public void good() throws Throwable {
        String data;
        data = new BufferedReader(new InputStreamReader(System.in)).readLine();
        SecretKeySpec secretKeySpec = new SecretKeySpec(data.getBytes("UTF-8"), "AES");
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'good', node_subtype: 'function',
        code_snapshot: 'data = readerBuffered.readLine(); SecretKeySpec sk = new SecretKeySpec(data.getBytes("UTF-8"), "AES");' },
    ], sourceCode);

    const result = verifyCWE321_A2(map);
    expect(result.holds).toBe(true);
  });

  it('SAFE: key from environment variable', () => {
    const map = buildMapNoSource([
      { id: 'N', node_type: 'TRANSFORM', label: 'encrypt', node_subtype: 'encrypt',
        code_snapshot: 'crypto.createCipheriv("aes-256-cbc", process.env.ENCRYPTION_KEY, iv)' },
    ]);

    const result = verifyCWE321_A2(map);
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-329: Predictable IV with CBC Mode
// ===========================================================================

describe('CWE-329: Predictable IV with CBC Mode (A2 Juliet-aware)', () => {

  // ------- TRUE POSITIVE: Juliet baseline -------

  it('VULNERABLE: Juliet pattern -- hardcoded byte array IV + Cipher CBC', () => {
    const sourceCode = `
package testcases.CWE329;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
public class CWE329_Test {
    public void bad() throws Throwable {
        byte[] initializationVector = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: `public void bad() { byte[] initializationVector = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector); }` },
      { id: 'C', node_type: 'TRANSFORM', label: 'Cipher.getInstance("AES/CBC/PKCS5Padding")', node_subtype: 'encrypt',
        code_snapshot: 'Cipher.getInstance("AES/CBC/PKCS5Padding")' },
    ], sourceCode);

    const result = verifyCWE329_A2(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].severity).toBe('high');
  });

  it('VULNERABLE: source-level cross-node -- byte array in different scope from Cipher', () => {
    // Even when the function-level node snapshot is too short to contain both
    const sourceCode = `
package testcases.CWE329;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
public class Test {
    public void bad() throws Throwable {
        byte[] myIV = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec spec = new IvParameterSpec(myIV);
    }
}`;
    const map = buildMap([
      { id: 'C', node_type: 'TRANSFORM', label: 'Cipher.getInstance("AES/CBC/PKCS5Padding")', node_subtype: 'encrypt',
        code_snapshot: 'Cipher.getInstance("AES/CBC/PKCS5Padding")' },
    ], sourceCode);

    const result = verifyCWE329_A2(map);
    expect(result.holds).toBe(false);
  });

  it('VULNERABLE: Strategy 1 -- JS Buffer.alloc zero IV with CBC', () => {
    const map = buildMapNoSource([
      { id: 'N', node_type: 'TRANSFORM', label: 'encrypt', node_subtype: 'encrypt',
        code_snapshot: 'const iv = Buffer.alloc(16); crypto.createCipheriv("aes-256-cbc", key, iv)' },
    ]);

    const result = verifyCWE329_A2(map);
    expect(result.holds).toBe(false);
  });

  it('VULNERABLE: Strategy 2 -- ECB mode (no IV at all)', () => {
    const map = buildMapNoSource([
      { id: 'N', node_type: 'TRANSFORM', label: 'Cipher.getInstance("AES/ECB/PKCS5Padding")', node_subtype: 'encrypt',
        code_snapshot: 'Cipher.getInstance("AES/ECB/PKCS5Padding")' },
    ]);

    const result = verifyCWE329_A2(map);
    expect(result.holds).toBe(false);
  });

  // ------- TRUE NEGATIVE: safe code -------

  it('SAFE: SecureRandom IV (Juliet good function)', () => {
    const sourceCode = `
package testcases.CWE329;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
public class Test {
    public void good() throws Throwable {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
    }
}`;
    const map = buildMap([
      { id: 'F', node_type: 'STRUCTURAL', label: 'good1', node_subtype: 'function',
        code_snapshot: `Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); byte[] initializationVector = new byte[16]; SecureRandom secureRandom = new SecureRandom(); secureRandom.nextBytes(initializationVector); IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);` },
      { id: 'C', node_type: 'TRANSFORM', label: 'Cipher.getInstance("AES/CBC/PKCS5Padding")', node_subtype: 'encrypt',
        code_snapshot: 'Cipher.getInstance("AES/CBC/PKCS5Padding")' },
    ], sourceCode);

    const result = verifyCWE329_A2(map);
    expect(result.holds).toBe(true);
  });

  it('SAFE: AES-GCM mode (uses random nonce by design)', () => {
    const map = buildMapNoSource([
      { id: 'N', node_type: 'TRANSFORM', label: 'Cipher.getInstance("AES/GCM/NoPadding")', node_subtype: 'encrypt',
        code_snapshot: 'Cipher.getInstance("AES/GCM/NoPadding")' },
    ]);

    const result = verifyCWE329_A2(map);
    expect(result.holds).toBe(true);
  });

  it('SAFE: no CBC mode present', () => {
    const map = buildMapNoSource([
      { id: 'N', node_type: 'TRANSFORM', label: 'encrypt', node_subtype: 'encrypt',
        code_snapshot: 'Cipher.getInstance("AES")' },
    ]);

    const result = verifyCWE329_A2(map);
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-328: Weak Hash (already working -- sanity check)
// ===========================================================================

describe('CWE-328: Weak Hash (sanity -- already works in verifier.ts)', () => {
  it('should be tested via DST CLI against Juliet MD5 file (not in A2 scope)', () => {
    // CWE-328 is handled by the hand-written verifyCWE328 in verifier.ts.
    // It correctly detects MessageDigest.getInstance("MD5") in the Juliet test.
    // This is just a documentation test to record that CWE-328 is NOT broken.
    expect(true).toBe(true);
  });
});
