/**
 * Crypto Fixes B -- CWE verifier tests for 4 crypto CWEs against NIST Juliet patterns
 *
 * Tests for 4 CWEs:
 *   1. CWE-336 (Same Seed in PRNG)              -- SecureRandom.setSeed(constant)
 *   2. CWE-614 (Sensitive Cookie Without Secure) -- new Cookie() + addCookie() without setSecure(true)
 *   3. CWE-759 (Unsalted One Way Hash)           -- MessageDigest.digest() without salt
 *   4. CWE-760 (Predictable Salt One Way Hash)   -- java.util.Random as salt source
 *
 * Each CWE gets:
 *   - VULNERABLE: realistic code matching Juliet pattern (holds=false, findings>0)
 *   - SAFE: fixed code that should NOT trigger (holds=true, findings=0)
 *   - Real Juliet file scan (using tree-sitter Java parser)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { NeuralMap } from './types.js';
import { verify } from './verifier';
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JULIET_BASE = 'C:/Users/pizza/vigil/juliet-java/src/testcases';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildMap(nodes: Parameters<typeof createNode>[0][], sourceFile = 'test.java'): NeuralMap {
  resetSequence();
  const map = createNeuralMap(sourceFile, '// test');
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

let parser: InstanceType<typeof Parser>;
let javaLang: InstanceType<typeof Language>;
let javaProfile: any;

async function init() {
  if (parser) return;
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../node_modules/tree-sitter-java/tree-sitter-java.wasm');
  const wasmBuffer = fs.readFileSync(wasmPath);
  javaLang = await Language.load(wasmBuffer);
  parser.setLanguage(javaLang);
  const mod = await import('./profiles/java');
  javaProfile = mod.javaProfile;
}

function scanFileForCWE(filePath: string, cwe: string) {
  const code = fs.readFileSync(filePath, 'utf-8');
  resetSequence();
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, filePath, javaProfile);
  return verify(map, cwe);
}

// ===========================================================================
// CWE-336: Same Seed in PRNG
// ===========================================================================

describe('CWE-336: Same Seed in PRNG', () => {

  it('VULNERABLE: SecureRandom.setSeed(constant) (Juliet pattern)', () => {
    const map = buildMap([
      {
        id: 'BAD', node_type: 'STRUCTURAL',
        label: 'bad',
        node_subtype: 'function',
        code_snapshot: `public void bad() throws Throwable {
          final byte[] SEED = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};
          SecureRandom secureRandom = new SecureRandom();
          secureRandom.setSeed(SEED);
          IO.writeLine("" + secureRandom.nextInt());
        }`,
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-336');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f => f.description.includes('setSeed'))).toBe(true);
  });

  it('SAFE: SecureRandom without setSeed (self-seeded)', () => {
    const map = buildMap([
      {
        id: 'GOOD', node_type: 'STRUCTURAL',
        label: 'good',
        node_subtype: 'function',
        code_snapshot: `public void good() throws Throwable {
          SecureRandom secureRandom = new SecureRandom();
          IO.writeLine("" + secureRandom.nextInt());
        }`,
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-336');
    expect(result.holds).toBe(true);
  });

  it('Juliet CWE336 _01 file: detects vulnerability', async () => {
    await init();
    const result = scanFileForCWE(
      path.join(JULIET_BASE, 'CWE336_Same_Seed_in_PRNG/CWE336_Same_Seed_in_PRNG__basic_01.java'),
      'CWE-336'
    );
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// CWE-614: Sensitive Cookie Without Secure Flag
// ===========================================================================

describe('CWE-614: Sensitive Cookie Without Secure Flag', () => {

  it('VULNERABLE: new Cookie() + addCookie() without setSecure(true)', () => {
    const map = buildMap([
      {
        id: 'BAD', node_type: 'STRUCTURAL',
        label: 'bad',
        node_subtype: 'function',
        code_snapshot: `public void bad(HttpServletRequest request, HttpServletResponse response) {
          Cookie cookie = new Cookie("SecretMessage", "test");
          if (request.isSecure()) {
            response.addCookie(cookie);
          }
        }`,
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-614');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f => f.missing.includes('setSecure'))).toBe(true);
  });

  it('SAFE: new Cookie() + setSecure(true) + addCookie()', () => {
    const map = buildMap([
      {
        id: 'GOOD', node_type: 'STRUCTURAL',
        label: 'good1',
        node_subtype: 'function',
        code_snapshot: `private void good1(HttpServletRequest request, HttpServletResponse response) {
          Cookie cookie = new Cookie("SecretMessage", "Drink your Ovaltine");
          if (request.isSecure()) {
            cookie.setSecure(true);
            response.addCookie(cookie);
          }
        }`,
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-614');
    expect(result.holds).toBe(true);
  });

  it('Juliet CWE614 _01 file: detects vulnerability', async () => {
    await init();
    const result = scanFileForCWE(
      path.join(JULIET_BASE, 'CWE614_Sensitive_Cookie_Without_Secure/CWE614_Sensitive_Cookie_Without_Secure__Servlet_01.java'),
      'CWE-614'
    );
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// CWE-759: Unsalted One Way Hash
// ===========================================================================

describe('CWE-759: Unsalted One Way Hash', () => {

  it('VULNERABLE: MessageDigest.digest() without salt (Juliet pattern)', () => {
    const map = buildMap([
      {
        id: 'BAD', node_type: 'STRUCTURAL',
        label: 'bad',
        node_subtype: 'function',
        code_snapshot: `public void bad() throws Throwable {
          MessageDigest hash = MessageDigest.getInstance("SHA-512");
          byte[] hashValue = hash.digest("hash me".getBytes("UTF-8"));
          IO.writeLine(IO.toHex(hashValue));
        }`,
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-759');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f => f.description.includes('MessageDigest'))).toBe(true);
  });

  it('SAFE: MessageDigest with SecureRandom salt via update()', () => {
    const map = buildMap([
      {
        id: 'GOOD', node_type: 'STRUCTURAL',
        label: 'good1',
        node_subtype: 'function',
        code_snapshot: `private void good1() throws Throwable {
          MessageDigest hash = MessageDigest.getInstance("SHA-512");
          SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
          hash.update(prng.generateSeed(32));
          byte[] hashValue = hash.digest("hash me".getBytes("UTF-8"));
          IO.writeLine(IO.toHex(hashValue));
        }`,
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-759');
    expect(result.holds).toBe(true);
  });

  it('Juliet CWE759 _01 file: detects vulnerability', async () => {
    await init();
    const result = scanFileForCWE(
      path.join(JULIET_BASE, 'CWE759_Unsalted_One_Way_Hash/CWE759_Unsalted_One_Way_Hash__basic_01.java'),
      'CWE-759'
    );
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// CWE-760: Predictable Salt One Way Hash
// ===========================================================================

describe('CWE-760: Predictable Salt One Way Hash', () => {

  it('VULNERABLE: java.util.Random as salt source (Juliet pattern)', () => {
    const map = buildMap([
      {
        id: 'BAD', node_type: 'STRUCTURAL',
        label: 'bad',
        node_subtype: 'function',
        code_snapshot: `public void bad() throws Throwable {
          Random random = new Random();
          MessageDigest hash = MessageDigest.getInstance("SHA-512");
          hash.update((Integer.toString(random.nextInt())).getBytes("UTF-8"));
          byte[] hashValue = hash.digest("hash me".getBytes("UTF-8"));
          IO.writeLine(IO.toHex(hashValue));
        }`,
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-760');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f => f.description.includes('java.util.Random') || f.description.includes('predictable'))).toBe(true);
  });

  it('SAFE: SecureRandom as salt source', () => {
    const map = buildMap([
      {
        id: 'GOOD', node_type: 'STRUCTURAL',
        label: 'good1',
        node_subtype: 'function',
        code_snapshot: `private void good1() throws Throwable {
          SecureRandom secureRandom = new SecureRandom();
          MessageDigest hash = MessageDigest.getInstance("SHA-512");
          SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
          hash.update(prng.generateSeed(32));
          byte[] hashValue = hash.digest("hash me".getBytes("UTF-8"));
          IO.writeLine(IO.toHex(hashValue));
        }`,
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-760');
    expect(result.holds).toBe(true);
  });

  it('Juliet CWE760 _01 file: detects vulnerability', async () => {
    await init();
    const result = scanFileForCWE(
      path.join(JULIET_BASE, 'CWE760_Predictable_Salt_One_Way_Hash/CWE760_Predictable_Salt_One_Way_Hash__basic_01.java'),
      'CWE-760'
    );
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
