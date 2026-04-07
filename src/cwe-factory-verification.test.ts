/**
 * CWE Factory Pattern Stress Tests
 *
 * Tests each UNIQUE factory pattern used across the 16 batches of generated
 * CWE verifiers. Picks ONE representative CWE per factory and verifies:
 *   1. Vulnerable code => holds=false, findings>0
 *   2. Safe code       => holds=true,  findings=0
 *
 * Factory patterns identified (15 unique patterns):
 *
 *  1. createPathTraversalVerifier       (batch_001) INGRESS->STORAGE[file] w/o CONTROL
 *  2. createBufferVerifier              (batch_001) INGRESS->STORAGE[buffer] w/o CONTROL
 *  3. createIntegerVerifier             (batch_001) INGRESS->STORAGE[numeric] w/o CONTROL
 *  4. createGenericVerifier             (_helpers)  configurable src->sink w/o CONTROL
 *  5. createInputValidationVerifier     (batch_002) INGRESS->TRANSFORM[data] w/o CONTROL
 *  6. createTransformStorageVerifier    (batch_003) TRANSFORM->STORAGE w/o CONTROL
 *  7. createNoTransformVerifier         (batch_004) INGRESS->STORAGE w/o TRANSFORM
 *  8. createOutputVerifier              (batch_005) INGRESS->EGRESS w/o TRANSFORM
 *  9. createIntermediateTransformVerifier (batch_006) INGRESS->TRANSFORM w/o intermediate TRANSFORM
 * 10. createTransformTransformVerifier  (batch_007) TRANSFORM->TRANSFORM w/o CONTROL
 * 11. createFilteringVerifier           (batch_008) INGRESS->EGRESS w/o CONTROL
 * 12. createExternalNoTransformVerifier (batch_009) INGRESS->EXTERNAL w/o TRANSFORM
 * 13. createAuthVerifier                (batch_010) INGRESS->STORAGE w/o AUTH
 * 14. createControlTransformVerifier    (batch_011) CONTROL->TRANSFORM w/o intermediate CONTROL
 * 15. createAuthControlVerifier         (batch_012) INGRESS->AUTH w/o CONTROL
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { NeuralMap, NeuralMapNode } from './types.js';

// Import one representative CWE from each factory pattern
import { verifyCWE23 } from './generated/batch_001.js';   // 1. Path traversal
import { verifyCWE121 } from './generated/batch_001.js';  // 2. Buffer
import { verifyCWE190 } from './generated/batch_001.js';  // 3. Integer
import { verifyCWE471 } from './generated/batch_001.js';  // 4. Generic (trust boundary)
import { verifyCWE103 } from './generated/batch_002.js';  // 5. Input validation
import { verifyCWE118 } from './generated/batch_003.js';  // 6. Transform->Storage
import { verifyCWE41 } from './generated/batch_004.js';   // 7. No transform (path canon)
import { verifyCWE80 } from './generated/batch_005.js';   // 8. Output (Basic XSS)
import { verifyCWE140 } from './generated/batch_006.js';  // 9. Intermediate transform
import { verifyCWE131 } from './generated/batch_007.js';  // 10. Transform->Transform
import { verifyCWE790 } from './generated/batch_008.js';  // 11. Filtering
import { verifyCWE77 } from './generated/batch_009.js';   // 12. External no transform (Command Injection)
import { verifyCWE285 } from './generated/batch_010.js';  // 13. Auth
import { verifyCWE273 } from './generated/batch_011.js';  // 14. Control->Transform
import { verifyCWE187 } from './generated/batch_012.js';  // 15. Auth control

// ---------------------------------------------------------------------------
// Helper: build a NeuralMap with specified nodes and edges
// ---------------------------------------------------------------------------
function buildMap(nodes: NeuralMapNode[]): NeuralMap {
  const map = createNeuralMap('test.js', '// test code');
  map.nodes = nodes;
  return map;
}

// ---------------------------------------------------------------------------
// Logging helper
// ---------------------------------------------------------------------------
function logResult(
  factoryName: string,
  cwe: string,
  label: string,
  result: { holds: boolean; findings: { length: number } },
  expectedHolds: boolean,
) {
  const ok = result.holds === expectedHolds;
  const expectedFindings = expectedHolds ? 0 : '>0';
  const actualFindings = result.findings.length;
  console.log(
    `  ${label}: holds=${result.holds}, findings=${actualFindings} ${ok ? '\u2713' : '\u2717 BUG'}`,
  );
}

// ===========================================================================
// TESTS
// ===========================================================================

describe('CWE Factory Pattern Verification', () => {
  beforeEach(() => {
    resetSequence();
  });

  // -------------------------------------------------------------------------
  // 1. createPathTraversalVerifier (batch_001)
  //    Pattern: INGRESS -> STORAGE[file] without CONTROL
  //    Tested via CWE-23 (Relative Path Traversal)
  // -------------------------------------------------------------------------
  describe('Factory: createPathTraversalVerifier (CWE-23)', () => {
    it('VULNERABLE: ingress -> file storage with no control', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.params.filename',
        code_snapshot: 'req.params.filename',
        edges: [{ target: 'store1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const storage = createNode({
        node_type: 'STORAGE',
        id: 'store1',
        label: 'fs.readFile(userPath)',
        node_subtype: 'file',
        code_snapshot: 'fs.readFile(userPath)',
        attack_surface: ['file_access'],
        edges: [],
      });
      const map = buildMap([ingress, storage]);
      const result = verifyCWE23(map);
      console.log('Factory: createPathTraversalVerifier (tested via CWE-23)');
      logResult('createPathTraversalVerifier', 'CWE-23', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> control -> file storage', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.params.filename',
        code_snapshot: 'req.params.filename',
        edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'path validation',
        code_snapshot: 'if (!path.resolve(userPath).startsWith(baseDir)) throw new Error()',
        edges: [{ target: 'store1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const storage = createNode({
        node_type: 'STORAGE',
        id: 'store1',
        label: 'fs.readFile(safePath)',
        node_subtype: 'file',
        code_snapshot: 'fs.readFile(path.resolve(safePath))',
        attack_surface: ['file_access'],
        edges: [],
      });
      const map = buildMap([ingress, control, storage]);
      const result = verifyCWE23(map);
      logResult('createPathTraversalVerifier', 'CWE-23', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 2. createBufferVerifier (batch_001)
  //    Pattern: INGRESS -> STORAGE[buffer] without CONTROL
  //    Tested via CWE-121 (Stack-based Buffer Overflow)
  // -------------------------------------------------------------------------
  describe('Factory: createBufferVerifier (CWE-121)', () => {
    it('VULNERABLE: ingress -> buffer storage with no control', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'user input',
        code_snapshot: 'req.body.data',
        edges: [{ target: 'buf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const buffer = createNode({
        node_type: 'STORAGE',
        id: 'buf1',
        label: 'buffer write',
        node_subtype: 'buffer',
        code_snapshot: 'Buffer.from(userData).copy(targetBuffer)',
        attack_surface: ['buffer_write'],
        edges: [],
      });
      const map = buildMap([ingress, buffer]);
      const result = verifyCWE121(map);
      console.log('Factory: createBufferVerifier (tested via CWE-121)');
      logResult('createBufferVerifier', 'CWE-121', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> control -> buffer storage', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'user input',
        code_snapshot: 'req.body.data',
        edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'bounds check',
        code_snapshot: 'if (data.length > Buffer.alloc(256).length) throw new Error()',
        edges: [{ target: 'buf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const buffer = createNode({
        node_type: 'STORAGE',
        id: 'buf1',
        label: 'buffer write',
        node_subtype: 'buffer',
        code_snapshot: 'Buffer.alloc(256).write(validatedData)',
        attack_surface: ['buffer_write'],
        edges: [],
      });
      const map = buildMap([ingress, control, buffer]);
      const result = verifyCWE121(map);
      logResult('createBufferVerifier', 'CWE-121', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 3. createIntegerVerifier (batch_001)
  //    Pattern: INGRESS -> STORAGE[numeric] without CONTROL
  //    Tested via CWE-190 (Integer Overflow or Wraparound)
  // -------------------------------------------------------------------------
  describe('Factory: createIntegerVerifier (CWE-190)', () => {
    it('VULNERABLE: ingress -> numeric storage with no control', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'user input',
        code_snapshot: 'req.query.count',
        edges: [{ target: 'num1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const numeric = createNode({
        node_type: 'STORAGE',
        id: 'num1',
        label: 'numeric assignment',
        node_subtype: 'numeric',
        code_snapshot: 'total = userCount * price',
        attack_surface: ['numeric_operation'],
        edges: [],
      });
      const map = buildMap([ingress, numeric]);
      const result = verifyCWE190(map);
      console.log('Factory: createIntegerVerifier (tested via CWE-190)');
      logResult('createIntegerVerifier', 'CWE-190', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> control -> numeric storage', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'user input',
        code_snapshot: 'req.query.count',
        edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'range check',
        code_snapshot: 'if (!Number.isSafeInteger(count)) throw new Error()',
        edges: [{ target: 'num1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const numeric = createNode({
        node_type: 'STORAGE',
        id: 'num1',
        label: 'numeric assignment',
        node_subtype: 'numeric',
        code_snapshot: 'total = Number.isSafeInteger(validCount) ? validCount * price : 0',
        attack_surface: ['numeric_operation'],
        edges: [],
      });
      const map = buildMap([ingress, control, numeric]);
      const result = verifyCWE190(map);
      logResult('createIntegerVerifier', 'CWE-190', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 4. createGenericVerifier (_helpers)
  //    Pattern: configurable source -> configurable sink without CONTROL
  //    Tested via CWE-471 (Modification of Assumed-Immutable Data)
  // -------------------------------------------------------------------------
  describe('Factory: createGenericVerifier (CWE-471)', () => {
    it('VULNERABLE: ingress -> trust storage with no control', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.body',
        code_snapshot: 'req.body',
        edges: [{ target: 'trust1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const trust = createNode({
        node_type: 'STORAGE',
        id: 'trust1',
        label: 'session.config',
        node_subtype: 'session',
        code_snapshot: 'req.session.config = req.body.config',
        attack_surface: ['trusted_data'],
        edges: [],
      });
      const map = buildMap([ingress, trust]);
      const result = verifyCWE471(map);
      console.log('Factory: createGenericVerifier (tested via CWE-471)');
      logResult('createGenericVerifier', 'CWE-471', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> control -> trust storage', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.body',
        code_snapshot: 'req.body',
        edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'validation',
        code_snapshot: 'const safe = validate(req.body)',
        edges: [{ target: 'trust1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const trust = createNode({
        node_type: 'STORAGE',
        id: 'trust1',
        label: 'session.config',
        node_subtype: 'session',
        code_snapshot: 'req.session.config = Object.freeze(sanitize(data))',
        attack_surface: ['trusted_data'],
        edges: [],
      });
      const map = buildMap([ingress, control, trust]);
      const result = verifyCWE471(map);
      logResult('createGenericVerifier', 'CWE-471', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 5. createInputValidationVerifier (batch_002)
  //    Pattern: INGRESS -> TRANSFORM[data] without CONTROL
  //    Tested via CWE-103 (Struts: Incomplete validate())
  // -------------------------------------------------------------------------
  describe('Factory: createInputValidationVerifier (CWE-103)', () => {
    it('VULNERABLE: ingress -> data transform with no control', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'user input',
        code_snapshot: 'import org.apache.struts.action.ActionForm; req.body.xml',
        edges: [{ target: 'xf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'XML parse',
        node_subtype: 'parse',
        code_snapshot: 'parseXML(rawInput)',
        attack_surface: ['data_processing'],
        edges: [],
      });
      const map = buildMap([ingress, transform]);
      const result = verifyCWE103(map);
      console.log('Factory: createInputValidationVerifier (tested via CWE-103)');
      logResult('createInputValidationVerifier', 'CWE-103', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> control -> data transform', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'user input',
        code_snapshot: 'req.body.xml',
        edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'validation',
        code_snapshot: 'schema.validate(req.body)',
        edges: [{ target: 'xf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'XML parse',
        node_subtype: 'parse',
        code_snapshot: 'parseXML(validate(rawInput))',
        attack_surface: ['data_processing'],
        edges: [],
      });
      const map = buildMap([ingress, control, transform]);
      const result = verifyCWE103(map);
      logResult('createInputValidationVerifier', 'CWE-103', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 6. createTransformStorageVerifier (batch_003)
  //    Pattern: TRANSFORM -> STORAGE without CONTROL
  //    Tested via CWE-118 (Improper Access of Indexable Resource)
  // -------------------------------------------------------------------------
  describe('Factory: createTransformStorageVerifier (CWE-118)', () => {
    it('VULNERABLE: transform -> buffer storage with no control', () => {
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'calculate offset',
        code_snapshot: 'const offset = computeIndex(data)',
        edges: [{ target: 'buf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const buffer = createNode({
        node_type: 'STORAGE',
        id: 'buf1',
        label: 'array write',
        node_subtype: 'buffer',
        code_snapshot: 'arr[offset] = value',
        attack_surface: ['buffer_write'],
        edges: [],
      });
      const map = buildMap([transform, buffer]);
      const result = verifyCWE118(map);
      console.log('Factory: createTransformStorageVerifier (tested via CWE-118)');
      logResult('createTransformStorageVerifier', 'CWE-118', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: transform -> control -> buffer storage', () => {
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'calculate offset',
        code_snapshot: 'const offset = computeIndex(data)',
        edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'bounds check',
        code_snapshot: 'if (offset < 0 || offset >= arr.length) throw new RangeError()',
        data_in: [{ name: 'offset', source: 'xf1', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'buf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const buffer = createNode({
        node_type: 'STORAGE',
        id: 'buf1',
        label: 'array write',
        node_subtype: 'buffer',
        code_snapshot: 'if (offset >= 0 && offset < arr.length) arr[offset] = value',
        attack_surface: ['buffer_write'],
        edges: [],
      });
      const map = buildMap([transform, control, buffer]);
      const result = verifyCWE118(map);
      logResult('createTransformStorageVerifier', 'CWE-118', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 7. createNoTransformVerifier (batch_004)
  //    Pattern: INGRESS -> STORAGE without TRANSFORM
  //    Tested via CWE-41 (Improper Resolution of Path Equivalence)
  // -------------------------------------------------------------------------
  describe('Factory: createNoTransformVerifier (CWE-41)', () => {
    it('VULNERABLE: ingress -> file storage with no transform', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.params.path',
        code_snapshot: 'req.params.path',
        edges: [{ target: 'store1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const storage = createNode({
        node_type: 'STORAGE',
        id: 'store1',
        label: 'fs.readFile(path)',
        node_subtype: 'file',
        code_snapshot: 'fs.readFile(userPath)',
        attack_surface: ['file_access'],
        edges: [],
      });
      const map = buildMap([ingress, storage]);
      const result = verifyCWE41(map);
      console.log('Factory: createNoTransformVerifier (tested via CWE-41)');
      logResult('createNoTransformVerifier', 'CWE-41', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> transform -> file storage', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.params.path',
        code_snapshot: 'req.params.path',
        edges: [{ target: 'xf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'canonicalize path',
        code_snapshot: 'const safePath = path.resolve(basedir, path.normalize(userPath))',
        edges: [{ target: 'store1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const storage = createNode({
        node_type: 'STORAGE',
        id: 'store1',
        label: 'fs.readFile(safePath)',
        node_subtype: 'file',
        code_snapshot: 'fs.readFile(path.resolve(safePath))',
        attack_surface: ['file_access'],
        edges: [],
      });
      const map = buildMap([ingress, transform, storage]);
      const result = verifyCWE41(map);
      logResult('createNoTransformVerifier', 'CWE-41', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 8. createOutputVerifier (batch_005)
  //    Pattern: INGRESS -> EGRESS without TRANSFORM
  //    Tested via CWE-80 (Basic XSS)
  // -------------------------------------------------------------------------
  describe('Factory: createOutputVerifier (CWE-80)', () => {
    it('VULNERABLE: ingress -> html egress with no transform', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.query.name',
        code_snapshot: 'req.query.name',
        edges: [{ target: 'eg1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const egress = createNode({
        node_type: 'EGRESS',
        id: 'eg1',
        label: 'res.send(html)',
        node_subtype: 'html',
        code_snapshot: 'res.send("<h1>" + userName + "</h1>")',
        attack_surface: ['html_output'],
        edges: [],
      });
      const map = buildMap([ingress, egress]);
      const result = verifyCWE80(map);
      console.log('Factory: createOutputVerifier (tested via CWE-80)');
      logResult('createOutputVerifier', 'CWE-80', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> transform -> html egress', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.query.name',
        code_snapshot: 'req.query.name',
        edges: [{ target: 'xf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'encode HTML',
        code_snapshot: 'const safe = encodeHtml(userName)',
        edges: [{ target: 'eg1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const egress = createNode({
        node_type: 'EGRESS',
        id: 'eg1',
        label: 'res.send(html)',
        node_subtype: 'html',
        code_snapshot: 'res.send(DOMPurify.sanitize(content))',
        attack_surface: ['html_output'],
        edges: [],
      });
      const map = buildMap([ingress, transform, egress]);
      const result = verifyCWE80(map);
      logResult('createOutputVerifier', 'CWE-80', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 9. createIntermediateTransformVerifier (batch_006)
  //    Pattern: INGRESS -> TRANSFORM(sink) without intermediate TRANSFORM
  //    Tested via CWE-140 (Delimiter Injection)
  // -------------------------------------------------------------------------
  describe('Factory: createIntermediateTransformVerifier (CWE-140)', () => {
    it('VULNERABLE: ingress -> delimiter processing with no prior transform', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.body.csv',
        code_snapshot: 'req.body.csv',
        edges: [{ target: 'xf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'CSV parse',
        node_subtype: 'parse',
        code_snapshot: 'data.split(",")',
        attack_surface: ['data_processing'],
        edges: [],
      });
      const map = buildMap([ingress, transform]);
      const result = verifyCWE140(map);
      console.log('Factory: createIntermediateTransformVerifier (tested via CWE-140)');
      logResult('createIntermediateTransformVerifier', 'CWE-140', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> sanitize transform -> delimiter processing', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.body.csv',
        code_snapshot: 'req.body.csv',
        edges: [{ target: 'xf_san', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sanitizer = createNode({
        node_type: 'TRANSFORM',
        id: 'xf_san',
        label: 'sanitize delimiters',
        code_snapshot: 'const safe = escape(input)',
        edges: [{ target: 'xf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'CSV parse',
        node_subtype: 'parse',
        code_snapshot: 'CSV.stringify(sanitize(data))',
        attack_surface: ['data_processing'],
        edges: [],
      });
      const map = buildMap([ingress, sanitizer, transform]);
      const result = verifyCWE140(map);
      logResult('createIntermediateTransformVerifier', 'CWE-140', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 10. createTransformTransformVerifier (batch_007)
  //     Pattern: TRANSFORM -> TRANSFORM without CONTROL
  //     Tested via CWE-131 (Incorrect Calculation of Buffer Size)
  // -------------------------------------------------------------------------
  describe('Factory: createTransformTransformVerifier (CWE-131)', () => {
    it('VULNERABLE: compute transform -> memory transform with no control', () => {
      // CWE-131 source=computeTransformNodes, sink=memoryTransformNodes
      // Source must match computeTransformNodes (arithmetic/Math/parseInt etc.)
      // Sink must match memoryTransformNodes (malloc/Buffer.alloc etc.)
      // Neither code_snapshot should match SIZE_CHECK_SAFE
      const compute = createNode({
        node_type: 'TRANSFORM',
        id: 'comp1',
        label: 'calculate size',
        node_subtype: 'calculate',
        code_snapshot: 'const totalSize = width * height',
        edges: [{ target: 'mem1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const memOp = createNode({
        node_type: 'TRANSFORM',
        id: 'mem1',
        label: 'allocate buffer',
        node_subtype: 'alloc',
        code_snapshot: 'const buf = malloc(totalSize)',
        edges: [],
      });
      const map = buildMap([compute, memOp]);
      const result = verifyCWE131(map);
      console.log('Factory: createTransformTransformVerifier (tested via CWE-131)');
      logResult('createTransformTransformVerifier', 'CWE-131', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: compute transform -> control -> memory transform', () => {
      const compute = createNode({
        node_type: 'TRANSFORM',
        id: 'comp1',
        label: 'calculate size',
        node_subtype: 'calculate',
        code_snapshot: 'const totalSize = width * height',
        edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'size validation',
        code_snapshot: 'if (totalSize > SIZE_MAX || totalSize <= 0) throw new RangeError()',
        data_in: [{ name: 'totalSize', source: 'comp1', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'mem1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const memOp = createNode({
        node_type: 'TRANSFORM',
        id: 'mem1',
        label: 'allocate buffer',
        node_subtype: 'alloc',
        code_snapshot: 'const buf = malloc(checkedSize)',
        edges: [],
      });
      const map = buildMap([compute, control, memOp]);
      const result = verifyCWE131(map);
      logResult('createTransformTransformVerifier', 'CWE-131', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 11. createFilteringVerifier (batch_008)
  //     Pattern: INGRESS -> EGRESS without CONTROL
  //     Tested via CWE-790 (Improper Filtering of Special Elements)
  // -------------------------------------------------------------------------
  describe('Factory: createFilteringVerifier (CWE-790)', () => {
    it('VULNERABLE: ingress -> egress with no control', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'user input',
        code_snapshot: 'req.query.search',
        edges: [{ target: 'eg1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const egress = createNode({
        node_type: 'EGRESS',
        id: 'eg1',
        label: 'res.send',
        code_snapshot: 'res.send(userInput)',
        edges: [],
      });
      const map = buildMap([ingress, egress]);
      const result = verifyCWE790(map);
      console.log('Factory: createFilteringVerifier (tested via CWE-790)');
      logResult('createFilteringVerifier', 'CWE-790', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> control -> egress', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'user input',
        code_snapshot: 'req.query.search',
        edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'filter',
        code_snapshot: 'const filtered = DOMPurify.sanitize(input)',
        edges: [{ target: 'eg1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const egress = createNode({
        node_type: 'EGRESS',
        id: 'eg1',
        label: 'res.send',
        code_snapshot: 'res.send(DOMPurify.sanitize(filtered))',
        edges: [],
      });
      const map = buildMap([ingress, control, egress]);
      const result = verifyCWE790(map);
      logResult('createFilteringVerifier', 'CWE-790', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 12. createExternalNoTransformVerifier (batch_009)
  //     Pattern: INGRESS -> EXTERNAL without TRANSFORM
  //     Tested via CWE-77 (Command Injection)
  // -------------------------------------------------------------------------
  describe('Factory: createExternalNoTransformVerifier (CWE-77)', () => {
    it('VULNERABLE: ingress -> command external with no transform', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.body.cmd',
        code_snapshot: 'req.body.filename',
        edges: [{ target: 'ext1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const external = createNode({
        node_type: 'EXTERNAL',
        id: 'ext1',
        label: 'exec command',
        node_subtype: 'command',
        code_snapshot: 'exec("ls " + userInput)',
        attack_surface: ['shell_exec'],
        edges: [],
      });
      const map = buildMap([ingress, external]);
      const result = verifyCWE77(map);
      console.log('Factory: createExternalNoTransformVerifier (tested via CWE-77)');
      logResult('createExternalNoTransformVerifier', 'CWE-77', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> transform -> command external', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.body.filename',
        code_snapshot: 'req.body.filename',
        edges: [{ target: 'xf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'escape shell args',
        code_snapshot: 'const safe = escapeShell(filename)',
        edges: [{ target: 'ext1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const external = createNode({
        node_type: 'EXTERNAL',
        id: 'ext1',
        label: 'execFile',
        node_subtype: 'command',
        code_snapshot: 'execFile("ls", [safeName])',
        attack_surface: ['shell_exec'],
        edges: [],
      });
      const map = buildMap([ingress, transform, external]);
      const result = verifyCWE77(map);
      logResult('createExternalNoTransformVerifier', 'CWE-77', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 13. createAuthVerifier (batch_010)
  //     Pattern: INGRESS -> STORAGE without AUTH
  //     Tested via CWE-285 (Improper Authorization)
  // -------------------------------------------------------------------------
  describe('Factory: createAuthVerifier (CWE-285)', () => {
    it('VULNERABLE: ingress -> storage with no auth', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.params.id',
        code_snapshot: 'req.params.id',
        edges: [{ target: 'store1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const storage = createNode({
        node_type: 'STORAGE',
        id: 'store1',
        label: 'db.findById',
        node_subtype: 'database',
        code_snapshot: 'db.users.findById(req.params.id)',
        edges: [],
      });
      const map = buildMap([ingress, storage]);
      const result = verifyCWE285(map);
      console.log('Factory: createAuthVerifier (tested via CWE-285)');
      logResult('createAuthVerifier', 'CWE-285', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> auth -> storage', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.params.id',
        code_snapshot: 'req.params.id',
        edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const auth = createNode({
        node_type: 'AUTH',
        id: 'auth1',
        label: 'authorization check',
        code_snapshot: 'if (!authorize(req.user, resource)) throw 403',
        edges: [{ target: 'store1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const storage = createNode({
        node_type: 'STORAGE',
        id: 'store1',
        label: 'db.findById',
        node_subtype: 'database',
        code_snapshot: 'db.users.findById(authorize(req.params.id))',
        edges: [],
      });
      const map = buildMap([ingress, auth, storage]);
      const result = verifyCWE285(map);
      logResult('createAuthVerifier', 'CWE-285', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 14. createControlTransformVerifier (batch_011)
  //     Pattern: CONTROL -> TRANSFORM without intermediate CONTROL
  //     Tested via CWE-273 (Improper Check for Dropped Privileges)
  // -------------------------------------------------------------------------
  describe('Factory: createControlTransformVerifier (CWE-273)', () => {
    it('VULNERABLE: control -> transform with no intermediate control', () => {
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'privilege check',
        code_snapshot: 'setuid(0)',
        edges: [{ target: 'xf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'process data',
        code_snapshot: 'processAsRoot(data)',
        edges: [],
      });
      const map = buildMap([control, transform]);
      const result = verifyCWE273(map);
      console.log('Factory: createControlTransformVerifier (tested via CWE-273)');
      logResult('createControlTransformVerifier', 'CWE-273', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: control -> control (verify result) -> transform', () => {
      const control1 = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'drop privileges',
        code_snapshot: 'setuid(targetUser)',
        edges: [{ target: 'ctrl2', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control2 = createNode({
        node_type: 'CONTROL',
        id: 'ctrl2',
        label: 'verify drop',
        code_snapshot: 'if (result !== 0) throw new Error("privilege drop failed")',
        edges: [{ target: 'xf1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const transform = createNode({
        node_type: 'TRANSFORM',
        id: 'xf1',
        label: 'process data',
        code_snapshot: 'assert(result === 0); processData(data)',
        edges: [],
      });
      const map = buildMap([control1, control2, transform]);
      const result = verifyCWE273(map);
      logResult('createControlTransformVerifier', 'CWE-273', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // 15. createAuthControlVerifier (batch_012)
  //     Pattern: INGRESS -> AUTH without CONTROL
  //     Tested via CWE-187 (Partial String Comparison)
  // -------------------------------------------------------------------------
  describe('Factory: createAuthControlVerifier (CWE-187)', () => {
    it('VULNERABLE: ingress -> auth with no control', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.body.password',
        code_snapshot: 'req.body.password',
        edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const auth = createNode({
        node_type: 'AUTH',
        id: 'auth1',
        label: 'login check',
        code_snapshot: 'if (password.startsWith(storedHash)) return true',
        edges: [],
      });
      const map = buildMap([ingress, auth]);
      const result = verifyCWE187(map);
      console.log('Factory: createAuthControlVerifier (tested via CWE-187)');
      logResult('createAuthControlVerifier', 'CWE-187', '  VULNERABLE', result, false);
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('SAFE: ingress -> control -> auth', () => {
      const ingress = createNode({
        node_type: 'INGRESS',
        id: 'ing1',
        label: 'req.body.password',
        code_snapshot: 'req.body.password',
        edges: [{ target: 'ctrl1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const control = createNode({
        node_type: 'CONTROL',
        id: 'ctrl1',
        label: 'rate limiter',
        code_snapshot: 'rateLimiter.check(req.ip)',
        edges: [{ target: 'auth1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const auth = createNode({
        node_type: 'AUTH',
        id: 'auth1',
        label: 'login check',
        code_snapshot: 'crypto.timingSafeEqual(hash, storedHash)',
        edges: [],
      });
      const map = buildMap([ingress, control, auth]);
      const result = verifyCWE187(map);
      logResult('createAuthControlVerifier', 'CWE-187', '  SAFE', result, true);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });
});
