/**
 * Merge Fixes 2 — CWE verifier detection tests for 5 new/improved CWEs
 *
 * CWE-500: Public Static Field Not Final (new source scan)
 * CWE-582: Array Declared Public Final Static (new source scan)
 * CWE-607: Public Static Final Field Mutable (improved source scan)
 * CWE-483: Incorrect Block Delimitation (regression fix — semicolon + single-line patterns)
 * CWE-561: Dead Code (expanded — unused private methods)
 *
 * Each test parses a Juliet Java _01 baseline test file (known vulnerable),
 * builds a Neural Map, runs the target CWE verifier, and asserts detection.
 * Good-version tests confirm false positives are avoided.
 */

import { describe, it, expect } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper';
import { verify, verifyAll, registeredCWEs } from './verifier';
import { createNode, createNeuralMap, resetSequence } from './types';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JULIET_BASE = 'C:/Users/pizza/vigil/juliet-java/src/testcases';

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

function scanFile(filePath: string): { cwe: string; holds: boolean; findings: any[] }[] {
  const code = fs.readFileSync(filePath, 'utf-8');
  resetSequence();
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, filePath, javaProfile);
  return verifyAll(map, undefined, { noDedup: true }) as any[];
}

function findResult(results: { cwe: string; holds: boolean }[], cweId: string): boolean | undefined {
  const r = results.find(r => r.cwe === cweId);
  return r ? r.holds : undefined;
}

// Helper: build a neural map from inline code nodes for unit-level tests
function buildMap(code: string, nodes: Parameters<typeof createNode>[0][]) {
  resetSequence();
  const map = createNeuralMap('test.java', code);
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

// =========================================================================
// CWE-500: Public Static Field Not Marked Final
// =========================================================================
describe('CWE-500: Public Static Field Not Final', () => {

  it('detects public static field without final (Juliet bad)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE500_Public_Static_Field_Not_Final/CWE500_Public_Static_Field_Not_Final__String_01_bad.java`
    );
    expect(findResult(results, 'CWE-500')).toBe(false);
  });

  it('passes when field is public static final (Juliet good)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE500_Public_Static_Field_Not_Final/CWE500_Public_Static_Field_Not_Final__String_01_good1.java`
    );
    expect(findResult(results, 'CWE-500')).toBe(true);
  });

  it('detects public static int without final (unit test)', () => {
    const map = buildMap(
      `public class Config { public static int MAX_RETRIES = 3; }`,
      [{
        id: 'N1', node_type: 'STRUCTURAL', label: 'Config',
        node_subtype: 'class', language: 'java',
        code_snapshot: 'public class Config { public static int MAX_RETRIES = 3; }',
        edges: [],
      }]
    );
    const result = verify(map, 'CWE-500');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('MAX_RETRIES');
  });

  it('passes when field has final modifier (unit test)', () => {
    const map = buildMap(
      `public class Config { public static final int MAX_RETRIES = 3; }`,
      [{
        id: 'N1', node_type: 'STRUCTURAL', label: 'Config',
        node_subtype: 'class', language: 'java',
        code_snapshot: 'public class Config { public static final int MAX_RETRIES = 3; }',
        edges: [],
      }]
    );
    const result = verify(map, 'CWE-500');
    expect(result.holds).toBe(true);
  });
});

// =========================================================================
// CWE-582: Array Declared Public, Final, and Static
// =========================================================================
describe('CWE-582: Array Declared Public Final Static', () => {

  it('detects public final static array (Juliet bad)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE582_Array_Public_Final_Static/CWE582_Array_Public_Final_Static__basic_01_bad.java`
    );
    expect(findResult(results, 'CWE-582')).toBe(false);
  });

  it('passes when array is private (Juliet good)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE582_Array_Public_Final_Static/CWE582_Array_Public_Final_Static__basic_01_good1.java`
    );
    expect(findResult(results, 'CWE-582')).toBe(true);
  });

  it('detects public static final String[] (unit test)', () => {
    const map = buildMap(
      `public class Roles { public static final String[] ADMIN_ROLES = {"admin", "superadmin"}; }`,
      [{
        id: 'N1', node_type: 'STRUCTURAL', label: 'Roles',
        node_subtype: 'class', language: 'java',
        code_snapshot: 'public class Roles { public static final String[] ADMIN_ROLES = {"admin", "superadmin"}; }',
        edges: [],
      }]
    );
    const result = verify(map, 'CWE-582');
    expect(result.holds).toBe(false);
    expect(result.findings[0].description).toContain('ADMIN_ROLES');
  });

  it('does not flag private static final arrays (unit test)', () => {
    const map = buildMap(
      `public class Roles { private static final String[] ADMIN_ROLES = {"admin"}; }`,
      [{
        id: 'N1', node_type: 'STRUCTURAL', label: 'Roles',
        node_subtype: 'class', language: 'java',
        code_snapshot: 'public class Roles { private static final String[] ADMIN_ROLES = {"admin"}; }',
        edges: [],
      }]
    );
    const result = verify(map, 'CWE-582');
    expect(result.holds).toBe(true);
  });
});

// =========================================================================
// CWE-607: Public Static Final Field References Mutable Object
// =========================================================================
describe('CWE-607: Public Static Final Field Mutable', () => {

  it('detects public final static Date (Juliet bad)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE607_Public_Static_Final_Mutable/CWE607_Public_Static_Final_Mutable__console_01_bad.java`
    );
    expect(findResult(results, 'CWE-607')).toBe(false);
  });

  it('passes when Date is private (Juliet good)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE607_Public_Static_Final_Mutable/CWE607_Public_Static_Final_Mutable__console_01_good1.java`
    );
    expect(findResult(results, 'CWE-607')).toBe(true);
  });

  it('detects public static final ArrayList (unit test)', () => {
    const code = 'public class Config { public static final ArrayList<String> ALLOWED = new ArrayList<>(); }';
    const map = buildMap(code, [{
      id: 'N1', node_type: 'STRUCTURAL', label: 'Config',
      node_subtype: 'class', language: 'java',
      code_snapshot: code,
      edges: [],
    }]);
    const result = verify(map, 'CWE-607');
    expect(result.holds).toBe(false);
  });

  it('passes with Collections.unmodifiableList (unit test)', () => {
    const code = 'public class Config { public static final List<String> ALLOWED = Collections.unmodifiableList(Arrays.asList("a")); }';
    const map = buildMap(code, [{
      id: 'N1', node_type: 'STRUCTURAL', label: 'Config',
      node_subtype: 'class', language: 'java',
      code_snapshot: code,
      edges: [],
    }]);
    const result = verify(map, 'CWE-607');
    expect(result.holds).toBe(true);
  });
});

// =========================================================================
// CWE-483: Incorrect Block Delimitation (regression fix)
// =========================================================================
describe('CWE-483: Incorrect Block Delimitation', () => {

  it('detects if-without-braces multiline (Juliet)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE483_Incorrect_Block_Delimitation/CWE483_Incorrect_Block_Delimitation__if_without_braces_multiline_01.java`
    );
    expect(findResult(results, 'CWE-483')).toBe(false);
  });

  it('detects semicolon after if (Juliet)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE483_Incorrect_Block_Delimitation/CWE483_Incorrect_Block_Delimitation__semicolon_01.java`
    );
    expect(findResult(results, 'CWE-483')).toBe(false);
  });

  it('detects single-line multiple statements (Juliet)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE483_Incorrect_Block_Delimitation/CWE483_Incorrect_Block_Delimitation__if_without_braces_single_line_01.java`
    );
    expect(findResult(results, 'CWE-483')).toBe(false);
  });

  it('detects semicolon pattern (unit test)', () => {
    const code = `if (x == 0);\n{\n  doSomething();\n}`;
    const map = buildMap(code, [{
      id: 'N1', node_type: 'STRUCTURAL', label: 'Controller.handle',
      node_subtype: 'function', language: 'java',
      code_snapshot: code,
      edges: [],
    }]);
    const result = verify(map, 'CWE-483');
    expect(result.holds).toBe(false);
    expect(result.findings[0].description).toContain('semicolon');
  });

  it('detects single-line multi-stmt (unit test)', () => {
    const code = `if (x == 0) doA(); doB();`;
    const map = buildMap(code, [{
      id: 'N1', node_type: 'STRUCTURAL', label: 'Controller.handle',
      node_subtype: 'function', language: 'java',
      code_snapshot: code,
      edges: [],
    }]);
    const result = verify(map, 'CWE-483');
    expect(result.holds).toBe(false);
    expect(result.findings[0].description).toContain('single line');
  });

  it('passes with proper braces (unit test)', () => {
    const code = `if (x == 0) {\n  doA();\n  doB();\n}`;
    const map = buildMap(code, [{
      id: 'N1', node_type: 'STRUCTURAL', label: 'Controller.handle',
      node_subtype: 'function', language: 'java',
      code_snapshot: code,
      edges: [],
    }]);
    const result = verify(map, 'CWE-483');
    expect(result.holds).toBe(true);
  });
});

// =========================================================================
// CWE-561: Dead Code (expanded)
// =========================================================================
describe('CWE-561: Dead Code', () => {

  it('detects unused private method (Juliet bad)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE561_Dead_Code/CWE561_Dead_Code__unused_method_01_bad.java`
    );
    expect(findResult(results, 'CWE-561')).toBe(false);
  });

  it('passes when private method is called (Juliet good)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE561_Dead_Code/CWE561_Dead_Code__unused_method_01_good1.java`
    );
    expect(findResult(results, 'CWE-561')).toBe(true);
  });

  it('detects code after return (unit test)', () => {
    const code = `function process() {\n  return result;\n  cleanup();\n}`;
    const map = buildMap(code, [{
      id: 'N1', node_type: 'STRUCTURAL', label: 'process',
      node_subtype: 'function',
      code_snapshot: code,
      edges: [],
    }]);
    const result = verify(map, 'CWE-561');
    expect(result.holds).toBe(false);
    expect(result.findings.some((f: any) => f.description.includes('unreachable') || f.description.includes('return'))).toBe(true);
  });

  it('detects always-false condition (unit test)', () => {
    const code = `function check() {\n  if (false) {\n    validateToken();\n  }\n}`;
    const map = buildMap(code, [{
      id: 'N1', node_type: 'STRUCTURAL', label: 'check',
      node_subtype: 'function',
      code_snapshot: code,
      edges: [],
    }]);
    const result = verify(map, 'CWE-561');
    expect(result.holds).toBe(false);
    expect(result.findings[0].description).toContain('always false');
  });

  it('passes with live code (unit test)', () => {
    const code = `function process(x) {\n  if (x > 0) {\n    return x;\n  }\n  return 0;\n}`;
    const map = buildMap(code, [{
      id: 'N1', node_type: 'STRUCTURAL', label: 'process',
      node_subtype: 'function',
      code_snapshot: code,
      edges: [],
    }]);
    const result = verify(map, 'CWE-561');
    expect(result.holds).toBe(true);
  });
});

// =========================================================================
// Registration check — all 5 CWEs are in the registry
// =========================================================================
describe('Registry completeness', () => {
  it('CWE-500 is registered', () => {
    expect(registeredCWEs()).toContain('CWE-500');
  });
  it('CWE-582 is registered', () => {
    expect(registeredCWEs()).toContain('CWE-582');
  });
  it('CWE-607 is registered', () => {
    expect(registeredCWEs()).toContain('CWE-607');
  });
  it('CWE-483 is registered', () => {
    expect(registeredCWEs()).toContain('CWE-483');
  });
  it('CWE-561 is registered', () => {
    expect(registeredCWEs()).toContain('CWE-561');
  });
});
