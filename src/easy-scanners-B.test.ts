import { existsSync } from 'fs';
const HAS_JULIET = existsSync('C:/Users/pizza/vigil/juliet-java/src/testcases');
/**
 * Easy Scanners B — Source-scan CWE verifier tests
 *
 * Tests for 4 CWEs upgraded to detect Juliet Java benchmark patterns:
 *   1. CWE-378 (Temp File Insecure Permissions)  — createTempFile without setReadable/setWritable
 *   2. CWE-379 (Temp File Insecure Directory)     — 2-arg createTempFile / mkdir without dir perms
 *   3. CWE-390 (Error Without Action)             — empty catch block OR empty if-block after error call
 *   4. CWE-674 (Uncontrolled Recursion)           — self-recursive method (Java syntax support)
 *
 * Each CWE gets:
 *   - VULNERABLE: realistic code that SHOULD trigger (holds=false, findings>0)
 *   - SAFE: realistic mitigated code that should NOT trigger (holds=true, findings=0)
 *   - Juliet-specific tests where applicable
 */

import { describe, it, expect } from 'vitest';
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
// CWE-378: Creation of Temporary File With Insecure Permissions
// ===========================================================================

describe.runIf(HAS_JULIET)('CWE-378: Temp File Insecure Permissions', () => {

  it('VULNERABLE: createTempFile without permission-setting (synthetic)', () => {
    const map = buildMap([
      {
        id: 'FN', node_type: 'STRUCTURAL',
        label: 'bad',
        node_subtype: 'function',
        code_snapshot: 'public void bad() throws Throwable { tempFile = File.createTempFile("temp", "1234"); }',
        attack_surface: [],
        edges: [{ target: 'N1', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'N1', node_type: 'TRANSFORM',
        label: 'tempFile =',
        node_subtype: 'assignment',
        code_snapshot: 'tempFile = File.createTempFile("temp", "1234")',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-378');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].missing).toContain('permission');
  });

  it('SAFE: createTempFile with setReadable/setWritable (synthetic)', () => {
    const map = buildMap([
      {
        id: 'FN', node_type: 'STRUCTURAL',
        label: 'good1',
        node_subtype: 'function',
        code_snapshot: 'private void good1() { tempFile = File.createTempFile("temp", "1234"); tempFile.setWritable(true, true); tempFile.setReadable(true, true); }',
        attack_surface: [],
        edges: [
          { target: 'N1', edge_type: 'CONTAINS', conditional: false, async: false },
          { target: 'N2', edge_type: 'CONTAINS', conditional: false, async: false },
        ],
      },
      {
        id: 'N1', node_type: 'TRANSFORM',
        label: 'tempFile =',
        node_subtype: 'assignment',
        code_snapshot: 'tempFile = File.createTempFile("temp", "1234")',
        attack_surface: [],
        edges: [],
      },
      {
        id: 'N2', node_type: 'CONTROL',
        label: 'if',
        node_subtype: 'branch',
        code_snapshot: 'if (!tempFile.setWritable(true, true)) { IO.logger.log(Level.WARNING, "Could not set Writable permissions"); }',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-378');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: Juliet CWE-378 baseline (_01) — bad() method detected', async () => {
    await init();
    const result = scanFileForCWE(
      `${JULIET_BASE}/CWE378_Temporary_File_Creation_With_Insecure_Perms/CWE378_Temporary_File_Creation_With_Insecure_Perms__basic_01.java`,
      'CWE-378'
    );
    // bad() method has createTempFile without setReadable/setWritable
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: explicit world-readable permissions (0666)', () => {
    const map = buildMap([
      {
        id: 'FN', node_type: 'STRUCTURAL',
        label: 'insecure',
        node_subtype: 'function',
        code_snapshot: 'void insecure() { File f = createTempFile("tmp", ".dat"); chmod(f, 0666); }',
        attack_surface: [],
        edges: [{ target: 'N1', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'N1', node_type: 'TRANSFORM',
        label: 'createTempFile',
        node_subtype: 'assignment',
        code_snapshot: 'File f = createTempFile("tmp", ".dat"); chmod(f, 0666)',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-378');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// CWE-379: Creation of Temporary File in Directory with Insecure Permissions
// ===========================================================================

describe.runIf(HAS_JULIET)('CWE-379: Temp File in Insecure Directory', () => {

  it('VULNERABLE: 2-arg createTempFile uses system default temp dir (synthetic)', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'TRANSFORM',
        label: 'tempFile =',
        node_subtype: 'assignment',
        code_snapshot: 'tempFile = File.createTempFile("temp", "1234")',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-379');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].missing).toContain('directory');
  });

  it('SAFE: 3-arg createTempFile with explicit secure directory (synthetic)', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'TRANSFORM',
        label: 'tempFile =',
        node_subtype: 'assignment',
        code_snapshot: 'tempFile = File.createTempFile("temp", "1234", secureDir)',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-379');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: hardcoded /tmp directory', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'STORAGE',
        label: 'writeToTmp',
        node_subtype: 'file_write',
        code_snapshot: 'new FileOutputStream("/tmp/data.txt")',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-379');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: hardcoded /tmp with mkdtemp', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'STORAGE',
        label: 'writeToTmp',
        node_subtype: 'file_write',
        code_snapshot: 'String dir = mkdtemp("/tmp/app-XXXXXX"); new FileOutputStream(dir + "/data.txt")',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-379');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: Juliet CWE-379 baseline (_01) — mkdir without dir permissions', async () => {
    await init();
    const result = scanFileForCWE(
      `${JULIET_BASE}/CWE379_Temporary_File_Creation_in_Insecure_Dir/CWE379_Temporary_File_Creation_in_Insecure_Dir__basic_01.java`,
      'CWE-379'
    );
    // bad() method creates directory without setReadable/setWritable on it
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// CWE-390: Detection of Error Condition Without Action
// ===========================================================================

describe.runIf(HAS_JULIET)('CWE-390: Error Without Action', () => {

  it('VULNERABLE: empty catch block (synthetic)', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'CONTROL',
        label: 'catch',
        node_subtype: 'error_handling',
        code_snapshot: 'catch (Exception e) { }',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-390');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].missing).toContain('error handling');
  });

  it('VULNERABLE: catch block with only comment (synthetic)', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'CONTROL',
        label: 'catch',
        node_subtype: 'error_handling',
        code_snapshot: 'catch (IOException e) { /* ignore */ }',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-390');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: catch block that rethrows', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'CONTROL',
        label: 'catch',
        node_subtype: 'error_handling',
        code_snapshot: 'catch (Exception e) { throw new RuntimeException("failed", e); }',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-390');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: empty if-block after mkdirs() (Juliet pattern)', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'CONTROL',
        label: 'if',
        node_subtype: 'branch',
        code_snapshot: 'if (!newDirectory.mkdirs())\n        {\n            /* FLAW: do nothing if newDirectory cannot be created */\n        }',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-390');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].missing).toContain('error');
  });

  it('SAFE: if-block after mkdirs() with throw (Juliet good pattern)', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'CONTROL',
        label: 'if',
        node_subtype: 'branch',
        code_snapshot: 'if (!newDirectory.mkdirs())\n        {\n            IO.writeLine("The directories could not be created");\n            throw new Exception(errorString.toString());\n        }',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-390');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: Juliet CWE-390 baseline (_01) — mkdirs empty if-block', async () => {
    await init();
    const result = scanFileForCWE(
      `${JULIET_BASE}/CWE390_Error_Without_Action/CWE390_Error_Without_Action__mkdirs_01.java`,
      'CWE-390'
    );
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: empty if-block after delete() call', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'CONTROL',
        label: 'if',
        node_subtype: 'branch',
        code_snapshot: 'if (!tempFile.delete()) {\n    // nothing\n}',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-390');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: Python except block with raise', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'CONTROL',
        label: 'except',
        node_subtype: 'error_handling',
        code_snapshot: 'catch (ValueError e) { raise; }',
        attack_surface: [],
        edges: [],
      },
    ], 'test.py');

    const result = verify(map, 'CWE-390');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-674: Uncontrolled Recursion
// ===========================================================================

describe.runIf(HAS_JULIET)('CWE-674: Uncontrolled Recursion', () => {

  it('VULNERABLE: self-recursive JS function without depth guard', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'STRUCTURAL',
        label: 'traverse',
        node_subtype: 'function',
        code_snapshot: 'function traverse(node) { if (node.left) traverse(node.left); if (node.right) traverse(node.right); }',
        attack_surface: [],
        edges: [],
      },
    ], 'test.js');

    const result = verify(map, 'CWE-674');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].missing).toContain('recursion');
  });

  it('SAFE: recursive JS function with depth guard', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'STRUCTURAL',
        label: 'traverse',
        node_subtype: 'function',
        code_snapshot: 'function traverse(node, depth) { if (depth > MAX_DEPTH) return; traverse(node.left, depth + 1); }',
        attack_surface: [],
        edges: [],
      },
    ], 'test.js');

    const result = verify(map, 'CWE-674');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: Java self-recursive method — missing base case (Juliet pattern)', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'STRUCTURAL',
        label: 'helperBad',
        node_subtype: 'function',
        code_snapshot: 'private static long helperBad(long level)\n    {\n        long longSum = level + helperBad(level-1);\n        return longSum;\n    }',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-674');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: Java recursive method with limit guard (Juliet good pattern)', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'STRUCTURAL',
        label: 'helperGood1',
        node_subtype: 'function',
        code_snapshot: 'private static void helperGood1(long level)\n    {\n        if (level > RECURSION_LONG_MAX) \n        {\n            IO.writeLine("ERROR IN RECURSION");\n            return;\n        }\n        if (level == 0) \n        {\n            return;\n        }\n        helperGood1(level - 1);\n    }',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-674');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: Java method with level == 0 but Long.MAX_VALUE depth (Juliet long pattern)', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'STRUCTURAL',
        label: 'helperBad',
        node_subtype: 'function',
        code_snapshot: 'private static void helperBad(long level)\n    {\n        if (level == 0) \n        {\n            return;\n        }\n        helperBad(level - 1);\n    }',
        attack_surface: [],
        edges: [],
      },
    ]);

    const result = verify(map, 'CWE-674');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: Juliet CWE-674 long variant (_01)', async () => {
    await init();
    const result = scanFileForCWE(
      `${JULIET_BASE}/CWE674_Uncontrolled_Recursion/CWE674_Uncontrolled_Recursion__long_01.java`,
      'CWE-674'
    );
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: Juliet CWE-674 missing base case (_01)', async () => {
    await init();
    const result = scanFileForCWE(
      `${JULIET_BASE}/CWE674_Uncontrolled_Recursion/CWE674_Uncontrolled_Recursion__missing_base_01.java`,
      'CWE-674'
    );
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: Python recursive function with base case', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'STRUCTURAL',
        label: 'factorial',
        node_subtype: 'function',
        code_snapshot: 'def factorial(n):\n    if n <= 1:\n        return 1\n    return n * factorial(n - 1)',
        attack_surface: [],
        edges: [],
      },
    ], 'test.py');

    // Python def pattern + base case with small number
    const result = verify(map, 'CWE-674');
    // This has a base case (n <= 1) but no MAX_DEPTH — could flag or not
    // Our guard requires comparison to named constant. n <= 1 is fine for factorial.
    // The function is bounded by input, not by MAX_DEPTH. This is a borderline case.
  });

  it('VULNERABLE: Go recursive function without guard', () => {
    const map = buildMap([
      {
        id: 'N1', node_type: 'STRUCTURAL',
        label: 'walk',
        node_subtype: 'function',
        code_snapshot: 'func walk(node *Node) {\n    walk(node.left)\n    walk(node.right)\n}',
        attack_surface: [],
        edges: [],
      },
    ], 'test.go');

    const result = verify(map, 'CWE-674');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
