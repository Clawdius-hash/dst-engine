/**
 * Merge Fixes — CWE verifier detection tests for 5 merged CWEs
 *
 * CWE-546: Suspicious Comment (merged source scan from generated)
 * CWE-563: Unused Variable (merged scope-aware scan from generated)
 * CWE-570: Expression Always False (merged getClass().equals() pattern)
 * CWE-571: Expression Always True (merged !getClass().equals() pattern)
 * CWE-597: Wrong String Comparison (merged String var tracking from generated)
 *
 * Each test parses a Juliet Java _01 baseline test file (known vulnerable),
 * builds a Neural Map, runs the target CWE verifier, and asserts detection.
 */

import { describe, it, expect } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper';
import { verify, verifyAll } from './verifier';
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

function scanFile(filePath: string) {
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

function buildMap(code: string, nodes: Parameters<typeof createNode>[0][]) {
  resetSequence();
  const map = createNeuralMap('test.java', code);
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

// =========================================================================
// CWE-546: Suspicious Comment — source scan catches BUG/HACK/FIXME
// =========================================================================
describe('CWE-546: Suspicious Comment (merged source scan)', () => {

  it('detects BUG comment in Juliet bad case', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE546_Suspicious_Comment/CWE546_Suspicious_Comment__BUG_01.java`
    );
    expect(findResult(results, 'CWE-546')).toBe(false);
  });

  it('detects HACK comment in Juliet bad case', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE546_Suspicious_Comment/CWE546_Suspicious_Comment__HACK_01.java`
    );
    expect(findResult(results, 'CWE-546')).toBe(false);
  });

  it('detects FIXME comment in Juliet bad case', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE546_Suspicious_Comment/CWE546_Suspicious_Comment__FIXME_01.java`
    );
    expect(findResult(results, 'CWE-546')).toBe(false);
  });
});

// =========================================================================
// CWE-563: Unused Variable — scope-aware "assigned but never read"
// =========================================================================
describe('CWE-563: Unused Variable (merged scope-aware scan)', () => {

  it('detects unused int variable in Juliet bad case', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE563_Unused_Variable/CWE563_Unused_Variable__unused_init_variable_int_01.java`
    );
    expect(findResult(results, 'CWE-563')).toBe(false);
  });

  it('detects unused String variable in Juliet bad case', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE563_Unused_Variable/CWE563_Unused_Variable__unused_init_variable_String_01.java`
    );
    expect(findResult(results, 'CWE-563')).toBe(false);
  });

  it('detects unused long variable in Juliet bad case', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE563_Unused_Variable/CWE563_Unused_Variable__unused_init_variable_long_01.java`
    );
    expect(findResult(results, 'CWE-563')).toBe(false);
  });
});

// =========================================================================
// CWE-570: Expression Always False — getClass().equals() with different types
// =========================================================================
describe('CWE-570: Expression Always False (merged getClass pattern)', () => {

  it('detects getClass().equals() with different types (Juliet bad)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE570_Expression_Always_False/CWE570_Expression_Always_False__class_getClass_equal_01.java`
    );
    expect(findResult(results, 'CWE-570')).toBe(false);
  });

  it('detects if(false) literal (Juliet bad)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE570_Expression_Always_False/CWE570_Expression_Always_False__false_01.java`
    );
    expect(findResult(results, 'CWE-570')).toBe(false);
  });
});

// =========================================================================
// CWE-571: Expression Always True — !getClass().equals() with different types
// =========================================================================
describe('CWE-571: Expression Always True (merged getClass pattern)', () => {

  it('detects !getClass().equals() with different types (Juliet bad)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE571_Expression_Always_True/CWE571_Expression_Always_True__class_getClass_not_equal_01.java`
    );
    expect(findResult(results, 'CWE-571')).toBe(false);
  });

  it('detects if(true) literal (Juliet bad)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE571_Expression_Always_True/CWE571_Expression_Always_True__true_01.java`
    );
    expect(findResult(results, 'CWE-571')).toBe(false);
  });
});

// =========================================================================
// CWE-597: Wrong String Comparison — var == var with String tracking
// =========================================================================
describe('CWE-597: Wrong String Comparison (merged String var tracking)', () => {

  it('detects String == String with readLine() variables (Juliet bad)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE597_Wrong_Operator_String_Comparison/CWE597_Wrong_Operator_String_Comparison__basic_01.java`
    );
    expect(findResult(results, 'CWE-597')).toBe(false);
  });

  it('detects var == var pattern in unit test', () => {
    const code = `package test;
import java.io.*;
public class Test {
  public void bad() throws Throwable {
    String s1 = br.readLine();
    String s2 = br.readLine();
    if (s1 == s2) { System.out.println("match"); }
  }
}`;
    const map = buildMap(code, [{
      id: 'N1', node_type: 'STRUCTURAL', label: 'Test',
      node_subtype: 'class', language: 'java',
      code_snapshot: code,
      edges: [],
    }]);
    const result = verify(map, 'CWE-597');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('.equals()');
  });
});
