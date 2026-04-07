/**
 * Wave 1 Batch 2 — Juliet Java structural CWE verifier tests
 *
 * Tests 10 structural/AST-pattern CWEs against NIST Juliet Java benchmark files.
 * These CWEs detect code quality and logic issues via source-code pattern matching,
 * not data-flow graph traversal.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper';
import { resetSequence } from './types';
import type { NeuralMap } from './types';
import { verifyCWE484, verifyCWE570, verifyCWE571, verifyCWE546, verifyCWE563, verifyCWE398 } from './generated/batch_016';
import { verifyCWE597, verifyCWE482 } from './generated/batch_015';
import { verifyCWE209 } from './generated/batch_018';
import { verifyCWE476 } from './generated/batch_019';
import * as fs from 'fs';
import * as path from 'path';

const JULIET_BASE = 'C:/Users/pizza/vigil/juliet-java/src/testcases';

let parser: InstanceType<typeof Parser>;
let javaProfile: any;

async function buildMap(filePath: string): Promise<NeuralMap> {
  const source = fs.readFileSync(filePath, 'utf-8');
  const tree = parser.parse(source);
  resetSequence();
  const { map } = buildNeuralMap(tree, source, path.basename(filePath), javaProfile);
  tree.delete();
  return map;
}

beforeAll(async () => {
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(
    __dirname, '../node_modules/tree-sitter-java/tree-sitter-java.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const lang = await Language.load(wasmBuffer);
  parser.setLanguage(lang);

  const profileMod = await import('./profiles/java');
  javaProfile = profileMod.default ?? profileMod.javaProfile ?? profileMod.profile;
});

// ---------------------------------------------------------------------------
// CWE-484: Omitted Break Statement in Switch
// ---------------------------------------------------------------------------
describe('CWE-484: Omitted Break in Switch', () => {
  it('detects missing break in Juliet basic_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE484_Omitted_Break_Statement_in_Switch/CWE484_Omitted_Break_Statement_in_Switch__basic_01.java`
    );
    const result = verifyCWE484(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('case 2');
  });
});

// ---------------------------------------------------------------------------
// CWE-482: Comparing Instead of Assigning
// ---------------------------------------------------------------------------
describe('CWE-482: Comparing Instead of Assigning', () => {
  it('detects == used where = was intended in Juliet basic_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE482_Comparing_Instead_of_Assigning/CWE482_Comparing_Instead_of_Assigning__basic_01.java`
    );
    const result = verifyCWE482(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('Comparison');
  });
});

// ---------------------------------------------------------------------------
// CWE-597: Wrong Operator for String Comparison (Java == vs .equals())
// ---------------------------------------------------------------------------
describe('CWE-597: Wrong String Comparison Operator', () => {
  it('detects == on String objects in Juliet basic_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE597_Wrong_Operator_String_Comparison/CWE597_Wrong_Operator_String_Comparison__basic_01.java`
    );
    const result = verifyCWE597(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('.equals()');
  });

  it('detects stringVar == "literal" (variable vs string literal)', () => {
    const syntheticMap: NeuralMap = {
      source_file: 'Test.java',
      source_code: [
        'package com.test;',
        'public class Test {',
        '  public void check() {',
        '    String role = getUserRole();',
        '    if (role == "admin") {',
        '      System.out.println("granted");',
        '    }',
        '  }',
        '}',
      ].join('\n'),
      nodes: [{ id: 'n1', node_type: 'CONTROL', label: 'if', code_snapshot: 'role == "admin"', line_start: 5, line_end: 5, language: 'java' }],
      edges: [],
    } as any;
    const result = verifyCWE597(syntheticMap);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('.equals()');
    expect(result.findings[0].description).toContain('"admin"');
  });

  it('detects "literal" == stringVar (Yoda comparison)', () => {
    const syntheticMap: NeuralMap = {
      source_file: 'Test.java',
      source_code: [
        'package com.test;',
        'public class Test {',
        '  public void check() {',
        '    String name = getName();',
        '    if ("root" == name) {',
        '      System.out.println("found");',
        '    }',
        '  }',
        '}',
      ].join('\n'),
      nodes: [{ id: 'n1', node_type: 'CONTROL', label: 'if', code_snapshot: '"root" == name', line_start: 5, line_end: 5, language: 'java' }],
      edges: [],
    } as any;
    const result = verifyCWE597(syntheticMap);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('.equals()');
    expect(result.findings[0].description).toContain('"root"');
  });

  it('still ignores stringVar == null (not a violation)', () => {
    const syntheticMap: NeuralMap = {
      source_file: 'Test.java',
      source_code: [
        'package com.test;',
        'public class Test {',
        '  public void check() {',
        '    String name = getName();',
        '    if (name == null) {',
        '      return;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
      nodes: [{ id: 'n1', node_type: 'CONTROL', label: 'if', code_snapshot: 'name == null', line_start: 5, line_end: 5, language: 'java' }],
      edges: [],
    } as any;
    const result = verifyCWE597(syntheticMap);
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-398: Poor Code Quality (Empty Block)
// ---------------------------------------------------------------------------
describe('CWE-398: Poor Code Quality (Empty Block)', () => {
  it('detects empty block in Juliet empty_block_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE398_Poor_Code_Quality/CWE398_Poor_Code_Quality__empty_block_01.java`
    );
    const result = verifyCWE398(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('Empty code block');
  });
});

// ---------------------------------------------------------------------------
// CWE-563: Unused Variable Assignment
// ---------------------------------------------------------------------------
describe('CWE-563: Unused Variable Assignment', () => {
  it('detects unused assigned variable in Juliet int_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE563_Unused_Variable/CWE563_Unused_Variable__unused_init_variable_int_01.java`
    );
    const result = verifyCWE563(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('data');
  });
});

// ---------------------------------------------------------------------------
// CWE-570: Expression Always False
// ---------------------------------------------------------------------------
describe('CWE-570: Expression Always False', () => {
  it('detects if(false) in Juliet false_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE570_Expression_Always_False/CWE570_Expression_Always_False__false_01.java`
    );
    const result = verifyCWE570(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('false');
  });

  it('detects n == (n-1) in Juliet n_equal_n_minus_one_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE570_Expression_Always_False/CWE570_Expression_Always_False__n_equal_n_minus_one_01.java`
    );
    const result = verifyCWE570(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// CWE-571: Expression Always True
// ---------------------------------------------------------------------------
describe('CWE-571: Expression Always True', () => {
  it('detects n < Integer.MAX_VALUE in Juliet n_less_int_max_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE571_Expression_Always_True/CWE571_Expression_Always_True__n_less_int_max_01.java`
    );
    const result = verifyCWE571(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('Integer.MAX_VALUE');
  });
});

// ---------------------------------------------------------------------------
// CWE-546: Suspicious Comment
// ---------------------------------------------------------------------------
describe('CWE-546: Suspicious Comment', () => {
  it('detects BUG comment in Juliet BUG_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE546_Suspicious_Comment/CWE546_Suspicious_Comment__BUG_01.java`
    );
    const result = verifyCWE546(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('BUG');
  });

  it('detects BUG comment in variant BUG_02', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE546_Suspicious_Comment/CWE546_Suspicious_Comment__BUG_02.java`
    );
    const result = verifyCWE546(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// CWE-209: Error Message Information Exposure
// ---------------------------------------------------------------------------
describe('CWE-209: Error Message Info Exposure', () => {
  it('detects printStackTrace() in Juliet printStackTrace_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE209_Information_Leak_Error/CWE209_Information_Leak_Error__printStackTrace_01.java`
    );
    const result = verifyCWE209(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('printStackTrace');
  });
});

// ---------------------------------------------------------------------------
// CWE-476: NULL Pointer Dereference
// ---------------------------------------------------------------------------
describe('CWE-476: NULL Pointer Dereference', () => {
  it('detects non-short-circuit & in null check in Juliet binary_if_01', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE476_NULL_Pointer_Dereference/CWE476_NULL_Pointer_Dereference__binary_if_01.java`
    );
    const result = verifyCWE476(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('short-circuit');
  });

  it('detects in variant binary_if_02', async () => {
    const map = await buildMap(
      `${JULIET_BASE}/CWE476_NULL_Pointer_Dereference/CWE476_NULL_Pointer_Dereference__binary_if_02.java`
    );
    const result = verifyCWE476(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });
});
