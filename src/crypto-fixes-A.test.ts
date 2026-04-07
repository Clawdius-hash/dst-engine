/**
 * Crypto Fixes A -- Juliet/NIST pattern detection for 4 crypto CWEs
 *
 * CWE-259: Hardcoded Password (Juliet: data="7e5tc4s3" -> DriverManager.getConnection)
 * CWE-321: Hardcoded Crypto Key (Juliet: data="literal" -> SecretKeySpec(data.getBytes))
 * CWE-328: SHA1 weak hash (already works -- regression check)
 * CWE-329: Hardcoded IV (Juliet: byte[] initializationVector = {0x00,...} -> IvParameterSpec)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { verify } from './verifier';
import { createNode, createNeuralMap, resetSequence } from './types';
import type { NeuralMap } from './types';

// Helper: build a Java neural map with function and source_code set to the full code
function buildJavaMapFull(funcName: string, fullCode: string, extraNodes?: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap(`${funcName}.java`, fullCode);
  const funcNode = createNode({
    label: funcName,
    node_type: 'STRUCTURAL',
    node_subtype: 'function',
    language: 'java',
    code_snapshot: fullCode.slice(0, 500),
    analysis_snapshot: fullCode,
  });
  map.nodes = [funcNode, ...(extraNodes || []).map(n => createNode({ language: 'java', ...n }))];
  return map;
}

// ===========================================================================
// CWE-259: Hardcoded Password -- Juliet pattern
// ===========================================================================
describe('CWE-259: Juliet Hardcoded Password via generic variable', () => {
  it('VULNERABLE: data = "7e5tc4s3" then DriverManager.getConnection(url, "root", data)', () => {
    const code = `public void bad() throws Throwable {
      String data;
      data = "7e5tc4s3";
      Connection connection = null;
      if (data != null) {
        connection = DriverManager.getConnection("data-url", "root", data);
      }
    }`;
    const map = buildJavaMapFull('bad', code);
    const result = verify(map, 'CWE-259');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('data');
  });

  it('SAFE: data from readLine() then DriverManager.getConnection', () => {
    const code = `public void good() throws Throwable {
      String data = "";
      InputStreamReader readerInputStream = new InputStreamReader(System.in, "UTF-8");
      BufferedReader readerBuffered = new BufferedReader(readerInputStream);
      data = readerBuffered.readLine();
      Connection connection = DriverManager.getConnection("data-url", "root", data);
    }`;
    const map = buildJavaMapFull('good', code);
    const result = verify(map, 'CWE-259');
    expect(result.holds).toBe(true);
  });

  it('VULNERABLE: password = "literal" (existing pattern still works)', () => {
    const code = `public void connect() {
      String password = "SuperSecret123";
      DriverManager.getConnection(url, user, password);
    }`;
    const map = buildJavaMapFull('connect', code);
    const result = verify(map, 'CWE-259');
    expect(result.holds).toBe(false);
  });
});

// ===========================================================================
// CWE-321: Hardcoded Crypto Key -- Juliet pattern
// ===========================================================================
describe('CWE-321: Juliet Hardcoded Crypto Key via generic variable', () => {
  it('VULNERABLE: data = "literal" then SecretKeySpec(data.getBytes(), "AES")', () => {
    const code = `public void bad() throws Throwable {
      String data;
      data = "23 ~j;asn!@#/>as";
      if (data != null) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(data.getBytes("UTF-8"), "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
      }
    }`;
    const map = buildJavaMapFull('bad', code);
    const result = verify(map, 'CWE-321');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('data');
  });

  it('SAFE: data from readLine() then SecretKeySpec', () => {
    const code = `public void good() throws Throwable {
      String data = "";
      InputStreamReader readerInputStream = new InputStreamReader(System.in, "UTF-8");
      BufferedReader readerBuffered = new BufferedReader(readerInputStream);
      data = readerBuffered.readLine();
      SecretKeySpec secretKeySpec = new SecretKeySpec(data.getBytes("UTF-8"), "AES");
    }`;
    const map = buildJavaMapFull('good', code);
    const result = verify(map, 'CWE-321');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-328: SHA1 -- regression check (already working)
// ===========================================================================
describe('CWE-328: SHA1 detection (regression)', () => {
  it('VULNERABLE: MessageDigest.getInstance("SHA1")', () => {
    const code = `public void bad() throws Throwable {
      String input = "Test Input";
      MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
      byte[] hashValue = messageDigest.digest(input.getBytes("UTF-8"));
    }`;
    const map = buildJavaMapFull('bad', code, [{
      label: 'MessageDigest.getInstance("SHA1")',
      node_type: 'TRANSFORM',
      node_subtype: 'encrypt',
      code_snapshot: 'MessageDigest.getInstance("SHA1")',
    }]);
    const result = verify(map, 'CWE-328');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: MessageDigest.getInstance("SHA-512")', () => {
    const code = `public void good() throws Throwable {
      String input = "Test Input";
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
      byte[] hashValue = messageDigest.digest(input.getBytes("UTF-8"));
    }`;
    const map = buildJavaMapFull('good', code, [{
      label: 'MessageDigest.getInstance("SHA-512")',
      node_type: 'TRANSFORM',
      node_subtype: 'encrypt',
      code_snapshot: 'MessageDigest.getInstance("SHA-512")',
    }]);
    const result = verify(map, 'CWE-328');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-329: Hardcoded IV -- Juliet pattern
// ===========================================================================
describe('CWE-329: Juliet Hardcoded IV with CBC Mode', () => {
  it('VULNERABLE: hardcoded byte array IV with IvParameterSpec', () => {
    const code = `public void bad() throws Throwable {
      byte[] text = "asdf".getBytes("UTF-8");
      byte[] initializationVector = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
      };
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(128);
      SecretKey key = keyGenerator.generateKey();
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
      cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
    }`;
    const map = buildJavaMapFull('bad', code);
    const result = verify(map, 'CWE-329');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('initializationVector');
  });

  it('SAFE: random IV from SecureRandom', () => {
    const code = `public void good() throws Throwable {
      byte[] text = "asdf".getBytes("UTF-8");
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(128);
      SecretKey key = keyGenerator.generateKey();
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      int blockSize = cipher.getBlockSize();
      byte[] initializationVector = new byte[blockSize];
      SecureRandom secureRandom = new SecureRandom();
      secureRandom.nextBytes(initializationVector);
      IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
      cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
    }`;
    const map = buildJavaMapFull('good', code);
    const result = verify(map, 'CWE-329');
    expect(result.holds).toBe(true);
  });
});
