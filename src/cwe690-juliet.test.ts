/**
 * CWE-690: Unchecked Return Value to NULL Pointer Dereference — Juliet Tests
 *
 * Tests the hand-written CWE-690 verifier against NIST Juliet Java benchmark.
 * CWE-690 is the "impossible" CWE — it normally requires interprocedural analysis
 * across method boundaries to know that a called method can return null.
 *
 * Our approach: source-scan for known nullable APIs (System.getProperty,
 * getParameter, Properties.getProperty, etc.) and same-file methods with
 * `return null`, then check for dereference without null guard.
 *
 * 8 baseline (_01) variants × 8 source/sink combos = 8 tests.
 * All 8 should detect the vulnerability (holds=false).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper';
import { verifyAll, registeredCWEs } from './verifier';
import { resetSequence } from './types';
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

function scanFile(filePath: string): { cwe: string; holds: boolean }[] {
  const code = fs.readFileSync(filePath, 'utf-8');
  resetSequence();
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, filePath, javaProfile);
  return verifyAll(map, undefined, { noDedup: true });
}

function findResult(results: { cwe: string; holds: boolean }[], cweId: string): boolean | undefined {
  const r = results.find(r => r.cwe === cweId);
  return r ? r.holds : undefined;
}

describe('CWE-690: Unchecked Return Value to NULL Pointer Dereference — Juliet', () => {

  // --- Baseline _01 variants (all should detect) ---

  it('Class_StringBuilder_01 — Helper.getStringBuilderBad() + .toString().trim()', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__Class_StringBuilder_01.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  it('Class_String_01 — Helper.getStringBad() + .trim()', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__Class_String_01.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  it('System_getProperty_trim_01 — System.getProperty() + .trim()', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__System_getProperty_trim_01.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  it('System_getProperty_equals_01 — System.getProperty() + .equals()', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__System_getProperty_equals_01.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  it('Properties_getProperty_trim_01 — properties.getProperty() + .trim() (try-catch)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__Properties_getProperty_trim_01.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  it('Properties_getProperty_equals_01 — properties.getProperty() + .equals() (try-catch)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__Properties_getProperty_equals_01.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  it('getParameter_Servlet_trim_01 — request.getParameter() + .trim()', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__getParameter_Servlet_trim_01.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  it('getParameter_Servlet_equals_01 — request.getParameter() + .equals()', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__getParameter_Servlet_equals_01.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  // --- Control flow variants (stretch goals) ---

  it('Class_StringBuilder_02 — if(true)/if(false) control flow', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__Class_StringBuilder_02.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  it('Class_StringBuilder_03 — if(5==5) control flow', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__Class_StringBuilder_03.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(false);
  });

  // --- Helper file (no deref — should NOT flag) ---

  it('Class_Helper — defines null-returning methods but no deref (clean)', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE690_NULL_Deref_From_Return/CWE690_NULL_Deref_From_Return__Class_Helper.java`
    );
    expect(findResult(results, 'CWE-690')).toBe(true);
  });
});
