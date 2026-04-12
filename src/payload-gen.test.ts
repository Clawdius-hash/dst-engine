/**
 * Tests for the DST Reverse Mapper (payload-gen.ts + payload-dictionary.ts)
 *
 * Covers:
 * - lookupNode: direct match, srcline-N fallback, line_end===0 fix, null for unknown
 * - tracePath: finds path, returns null for disconnected, ignores CONTAINS edges
 * - resolveSinkClass: exact match, fuzzy match, null for unrecognized
 * - classifyTransform: codec->encoding, encrypt->destruction, sanitize->destruction (FIX #2)
 * - extractSQLContext: string vs numeric
 * - validatePayloadSafety: accepts safe, rejects destructive
 * - generateProof: produces ProofCertificate for CWE-89, returns null for CWE-327,
 *   time-based has execution_safe:false (FIX #3)
 * - Determinism: same input -> identical output
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { NeuralMap, NeuralMapNode } from './types.js';
import type { Finding } from './verifier/types.ts';
import {
  lookupNode,
  tracePath,
  extractSQLContext,
  generateCanary,
  selectPayload,
  analyzeTransforms,
  buildDeliverySpec,
  buildOracle,
  validatePayloadSafety,
  generateProof,
  inferPayloadClassFromContent,
} from './payload-gen.js';
import { buildReverseEdgeIndex } from './mapper.js';
import {
  resolveSinkClass,
  inferPayloadClassFromCWE,
  classifyTransform,
  SQL_INJECTION_PAYLOADS,
} from './payload-dictionary.js';

// ---------------------------------------------------------------------------
// Helpers -- build minimal NeuralMaps for testing
// ---------------------------------------------------------------------------

function buildTestMap(nodes: NeuralMapNode[]): NeuralMap {
  const map = createNeuralMap('test.js', 'test source');
  map.nodes = nodes;
  map.edges = [];
  return map;
}

function makeFinding(
  sourceId: string,
  sinkId: string,
  opts?: Partial<Finding>,
): Finding {
  return {
    source: { id: sourceId, label: 'source', line: 1, code: 'req.body.input' },
    sink: { id: sinkId, label: 'sink', line: 10, code: "db.query('SELECT * FROM users WHERE id=' + input)" },
    missing: 'CONTROL (parameterized query)',
    severity: 'critical',
    description: 'SQL injection',
    fix: 'Use parameterized queries',
    ...opts,
  };
}

// ---------------------------------------------------------------------------
// lookupNode
// ---------------------------------------------------------------------------

describe('lookupNode', () => {
  beforeEach(() => resetSequence());

  it('finds node by direct ID match', () => {
    const node = createNode({ id: 'node_1', node_type: 'STORAGE', node_subtype: 'db_read', line_start: 10 });
    const map = buildTestMap([node]);
    const result = lookupNode(map, { id: 'node_1', label: 'sink', line: 10, code: '' });
    expect(result).toBe(node);
  });

  it('finds node by srcline-N fallback using line range', () => {
    const node = createNode({
      id: 'real_node',
      node_type: 'STORAGE',
      node_subtype: 'db_read',
      line_start: 8,
      line_end: 12,
    });
    const map = buildTestMap([node]);
    const result = lookupNode(map, { id: 'srcline-10', label: 'SQL query (line 10)', line: 10, code: '' });
    expect(result).toBe(node);
  });

  it('handles line_end === 0 by matching line_start exactly (FIX #4)', () => {
    const node = createNode({
      id: 'real_node',
      node_type: 'STORAGE',
      node_subtype: 'db_read',
      line_start: 10,
      line_end: 0,  // createNode default
    });
    const map = buildTestMap([node]);
    const result = lookupNode(map, { id: 'srcline-10', label: 'SQL query (line 10)', line: 10, code: '' });
    expect(result).toBe(node);
  });

  it('returns null for unknown ID', () => {
    const map = buildTestMap([]);
    const result = lookupNode(map, { id: 'does_not_exist', label: '', line: 0, code: '' });
    expect(result).toBeNull();
  });

  it('returns most specific (smallest span) node for srcline-N', () => {
    const broad = createNode({
      id: 'broad',
      node_type: 'STRUCTURAL',
      node_subtype: 'function',
      line_start: 1,
      line_end: 50,
    });
    const narrow = createNode({
      id: 'narrow',
      node_type: 'STORAGE',
      node_subtype: 'db_read',
      line_start: 9,
      line_end: 11,
    });
    const map = buildTestMap([broad, narrow]);
    const result = lookupNode(map, { id: 'srcline-10', label: '', line: 10, code: '' });
    expect(result).toBe(narrow);
  });
});

// ---------------------------------------------------------------------------
// tracePath
// ---------------------------------------------------------------------------

describe('tracePath', () => {
  beforeEach(() => resetSequence());

  it('finds a direct path from source to sink', () => {
    const src = createNode({
      id: 'src',
      node_type: 'INGRESS',
      edges: [{ target: 'mid', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const mid = createNode({
      id: 'mid',
      node_type: 'TRANSFORM',
      edges: [{ target: 'sink', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({ id: 'sink', node_type: 'STORAGE' });
    const map = buildTestMap([src, mid, sink]);

    const path = tracePath(map, 'src', 'sink');
    expect(path).toEqual(['src', 'mid', 'sink']);
  });

  it('returns null when nodes are disconnected', () => {
    const src = createNode({ id: 'src', node_type: 'INGRESS' });
    const sink = createNode({ id: 'sink', node_type: 'STORAGE' });
    const map = buildTestMap([src, sink]);

    const path = tracePath(map, 'src', 'sink');
    expect(path).toBeNull();
  });

  it('ignores CONTAINS edges (structural, not data flow)', () => {
    const src = createNode({
      id: 'src',
      node_type: 'INGRESS',
      edges: [{ target: 'sink', edge_type: 'CONTAINS', conditional: false, async: false }],
    });
    const sink = createNode({ id: 'sink', node_type: 'STORAGE' });
    const map = buildTestMap([src, sink]);

    const path = tracePath(map, 'src', 'sink');
    expect(path).toBeNull();
  });

  it('follows CALLS and WRITES edges', () => {
    const src = createNode({
      id: 'src',
      node_type: 'INGRESS',
      edges: [{ target: 'mid', edge_type: 'CALLS', conditional: false, async: false }],
    });
    const mid = createNode({
      id: 'mid',
      node_type: 'TRANSFORM',
      edges: [{ target: 'sink', edge_type: 'WRITES', conditional: false, async: false }],
    });
    const sink = createNode({ id: 'sink', node_type: 'STORAGE' });
    const map = buildTestMap([src, mid, sink]);

    const path = tracePath(map, 'src', 'sink');
    expect(path).toEqual(['src', 'mid', 'sink']);
  });

  it('returns single-element path for source === sink', () => {
    const node = createNode({ id: 'same', node_type: 'STORAGE' });
    const map = buildTestMap([node]);

    const path = tracePath(map, 'same', 'same');
    expect(path).toEqual(['same']);
  });
});

// ---------------------------------------------------------------------------
// resolveSinkClass
// ---------------------------------------------------------------------------

describe('resolveSinkClass', () => {
  it('resolves exact match: db_read -> sql_injection', () => {
    expect(resolveSinkClass('db_read')).toBe('sql_injection');
  });

  it('resolves exact match: db_write -> sql_injection', () => {
    expect(resolveSinkClass('db_write')).toBe('sql_injection');
  });

  it('resolves exact match: system_exec -> command_injection', () => {
    expect(resolveSinkClass('system_exec')).toBe('command_injection');
  });

  it('resolves fuzzy match: custom_db_read_v2 -> sql_injection', () => {
    expect(resolveSinkClass('custom_db_read_v2')).toBe('sql_injection');
  });

  it('resolves fuzzy match: xml_parse_unsafe -> xxe', () => {
    expect(resolveSinkClass('xml_parse_unsafe')).toBe('xxe');
  });

  it('returns null for unrecognized subtype', () => {
    expect(resolveSinkClass('banana_smoothie')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// classifyTransform
// ---------------------------------------------------------------------------

describe('classifyTransform', () => {
  beforeEach(() => resetSequence());

  it('classifies codec subtype as encoding', () => {
    const node = createNode({ node_type: 'TRANSFORM', node_subtype: 'codec' });
    const effect = classifyTransform(node);
    expect(effect.effect).toBe('encoding');
    expect(effect.payload_action).toBe('encode_before_delivery');
  });

  it('classifies encrypt subtype as destruction', () => {
    const node = createNode({ node_type: 'TRANSFORM', node_subtype: 'encrypt' });
    const effect = classifyTransform(node);
    expect(effect.effect).toBe('destruction');
    expect(effect.payload_action).toBe('payload_blocked');
  });

  it('FIX #2: classifies sanitize in code_snapshot as destruction, NOT encoding', () => {
    const node = createNode({
      node_type: 'TRANSFORM',
      node_subtype: '',  // generic subtype
      code_snapshot: 'HtmlUtils.htmlEscape(userInput)',
    });
    const effect = classifyTransform(node);
    expect(effect.effect).toBe('destruction');
    expect(effect.payload_action).toBe('payload_blocked');
  });

  it('classifies DOMPurify.sanitize as destruction', () => {
    const node = createNode({
      node_type: 'TRANSFORM',
      node_subtype: '',
      code_snapshot: 'DOMPurify.sanitize(html)',
    });
    const effect = classifyTransform(node);
    expect(effect.effect).toBe('destruction');
    expect(effect.payload_action).toBe('payload_blocked');
  });

  it('classifies URLEncoder as encoding (survives but needs pre-encoding)', () => {
    const node = createNode({
      node_type: 'TRANSFORM',
      node_subtype: '',
      code_snapshot: 'URLEncoder.encode(input, "UTF-8")',
    });
    const effect = classifyTransform(node);
    // URLEncoder matches the encode pattern
    expect(effect.effect).toBe('encoding');
    expect(effect.payload_action).toBe('encode_before_delivery');
  });

  it('classifies format subtype as type_coercion', () => {
    const node = createNode({ node_type: 'TRANSFORM', node_subtype: 'format' });
    const effect = classifyTransform(node);
    expect(effect.effect).toBe('type_coercion');
    expect(effect.payload_action).toBe('check_if_numeric_only');
  });

  it('classifies unknown transform as unknown', () => {
    const node = createNode({
      node_type: 'TRANSFORM',
      node_subtype: '',
      code_snapshot: 'customProcessor.doSomething(x)',
    });
    const effect = classifyTransform(node);
    expect(effect.effect).toBe('unknown');
    expect(effect.payload_action).toBe('flag_uncertain');
  });
});

// ---------------------------------------------------------------------------
// extractSQLContext
// ---------------------------------------------------------------------------

describe('extractSQLContext', () => {
  beforeEach(() => resetSequence());

  it('detects string context from quoted concatenation', () => {
    const node = createNode({
      node_type: 'STORAGE',
      code_snapshot: `"SELECT * FROM users WHERE name='" + input + "'"`,
    });
    expect(extractSQLContext(node)).toBe('sql_string');
  });

  it('detects numeric context from unquoted concatenation', () => {
    const node = createNode({
      node_type: 'STORAGE',
      code_snapshot: `"SELECT * FROM users WHERE id=" + input`,
    });
    expect(extractSQLContext(node)).toBe('sql_numeric');
  });

  it('defaults to sql_string for ambiguous patterns', () => {
    const node = createNode({
      node_type: 'STORAGE',
      code_snapshot: 'db.query(input)',
    });
    expect(extractSQLContext(node)).toBe('sql_string');
  });
});

// ---------------------------------------------------------------------------
// validatePayloadSafety
// ---------------------------------------------------------------------------

describe('validatePayloadSafety', () => {
  it('accepts safe SQL payloads (tautology)', () => {
    expect(validatePayloadSafety("' OR '1'='1", 'sql_injection')).toBe(true);
  });

  it('accepts safe SQL payloads (UNION SELECT)', () => {
    expect(validatePayloadSafety("' UNION SELECT 'DST_CANARY_SQLI' --", 'sql_injection')).toBe(true);
  });

  it('rejects destructive SQL payloads (DROP TABLE)', () => {
    expect(validatePayloadSafety("'; DROP TABLE users --", 'sql_injection')).toBe(false);
  });

  it('rejects destructive SQL payloads (DELETE)', () => {
    expect(validatePayloadSafety("'; DELETE FROM users --", 'sql_injection')).toBe(false);
  });

  it('accepts safe command injection payloads', () => {
    expect(validatePayloadSafety('; echo DST_CMDI_PROOF', 'command_injection')).toBe(true);
  });

  it('accepts whoami command', () => {
    expect(validatePayloadSafety('; whoami', 'command_injection')).toBe(true);
  });

  it('rejects dangerous commands (rm)', () => {
    expect(validatePayloadSafety('; rm -rf /', 'command_injection')).toBe(false);
  });

  it('rejects dangerous commands (shutdown)', () => {
    expect(validatePayloadSafety('; shutdown -h now', 'command_injection')).toBe(false);
  });

  it('accepts all SQL dictionary payloads', () => {
    for (const [key, tmpl] of Object.entries(SQL_INJECTION_PAYLOADS)) {
      expect(validatePayloadSafety(tmpl.value, 'sql_injection')).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// generateProof
// ---------------------------------------------------------------------------

describe('generateProof', () => {
  beforeEach(() => resetSequence());

  it('produces a ProofCertificate for CWE-89 with real nodes', () => {
    const src = createNode({
      id: 'ingress_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      line_start: 5,
      code_snapshot: 'req.body.login',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'STORAGE',
      node_subtype: 'db_read',
      line_start: 10,
      code_snapshot: `"SELECT * FROM users WHERE login='" + req.body.login + "'"`,
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('ingress_1', 'sink_1');

    const proof = generateProof(map, finding, 'CWE-89');
    expect(proof).not.toBeNull();
    expect(proof!.primary_payload.value).toContain('UNION SELECT');
    expect(proof!.primary_payload.canary).toBe('DST_CANARY_SQLI');
    expect(proof!.primary_payload.context).toBe('sql_string');
    expect(proof!.proof_strength).toBe('conclusive');
    expect(proof!.delivery.channel).toBe('http');
    expect(proof!.path_analysis).not.toBeNull();
    expect(proof!.path_analysis!.path_node_ids).toEqual(['ingress_1', 'sink_1']);
    expect(proof!.oracle.type).toBe('hybrid');
  });

  it('returns null for CWE-327 (not payload-generatable)', () => {
    const node = createNode({
      id: 'crypto_1',
      node_type: 'TRANSFORM',
      node_subtype: 'encrypt',
      line_start: 5,
      code_snapshot: 'MessageDigest.getInstance("MD5")',
    });
    const map = buildTestMap([node]);
    const finding = makeFinding('crypto_1', 'crypto_1');

    const proof = generateProof(map, finding, 'CWE-327');
    expect(proof).toBeNull();
  });

  it('FIX #3: time-based SQL payloads have execution_safe: false', () => {
    const src = createNode({
      id: 'src_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      code_snapshot: 'req.body.id',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'STORAGE',
      node_subtype: 'db_read',
      code_snapshot: `"SELECT * FROM users WHERE id='" + input + "'"`,
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('src_1', 'sink_1');

    const proof = generateProof(map, finding, 'CWE-89');
    expect(proof).not.toBeNull();

    // Check that time-based variants all have execution_safe: false
    const timeVariants = proof!.variants.filter(v =>
      v.value.includes('SLEEP') || v.value.includes('pg_sleep') || v.value.includes('WAITFOR')
    );
    expect(timeVariants.length).toBeGreaterThan(0);
    for (const tv of timeVariants) {
      expect(tv.execution_safe).toBe(false);
    }
  });

  it('handles synthetic srcline-N findings gracefully', () => {
    const node = createNode({
      id: 'real_sink',
      node_type: 'STORAGE',
      node_subtype: 'db_read',
      line_start: 10,
      line_end: 12,
      code_snapshot: `"SELECT * FROM users WHERE id='" + input + "'"`,
    });
    const map = buildTestMap([node]);
    const finding = makeFinding('srcline-5', 'srcline-10', {
      source: { id: 'srcline-5', label: 'input (line 5)', line: 5, code: 'String input = request.getParameter("id")' },
      sink: { id: 'srcline-10', label: 'SQL query (line 10)', line: 10, code: "stmt.executeQuery(sql)" },
    });

    const proof = generateProof(map, finding, 'CWE-89');
    expect(proof).not.toBeNull();
    expect(proof!.proof_strength).toBe('indicative');
    expect(proof!.path_analysis).toBeNull();
  });

  it('produces proof via CWE inference when sink subtype is unknown', () => {
    const src = createNode({
      id: 'src_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      code_snapshot: 'req.body.q',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'STORAGE',
      node_subtype: 'unknown_storage_type',
      code_snapshot: `db.query("SELECT * FROM t WHERE x='" + q + "'")`,
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('src_1', 'sink_1');

    const proof = generateProof(map, finding, 'CWE-89');
    expect(proof).not.toBeNull();
    expect(proof!.primary_payload.canary).toBe('DST_CANARY_SQLI');
  });

  it('uses sink context to resolve payload class when CWE and subtype fail', () => {
    // Create a TRANSFORM/template_string sink node with cross_file_param_taint_via_slugFilterOrder
    // Use code_snapshot that won't trigger content-aware inference (no 2+ SQL keywords, no shell, etc.)
    const src = createNode({
      id: 'src_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      code_snapshot: 'req.body.q',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'TRANSFORM',
      node_subtype: 'template_string',
      code_snapshot: '`processing ${input} through pipeline`',
      data_in: [
        { name: 'cross_file_param_taint_via_slugFilterOrder', source: 'ext', data_type: 'string', tainted: true, sensitivity: 'PII' },
      ],
    });
    const map = buildTestMap([src, sink]);
    // CWE-190 has no payload class match in the dictionary
    const finding = makeFinding('src_1', 'sink_1');

    // Without sinkContext -> returns null (template_string has no match, CWE-190 has no match, content has no match)
    const proofWithout = generateProof(map, finding, 'CWE-190');
    expect(proofWithout).toBeNull();

    // With sinkContext mapping 'slugFilterOrder' -> {'sql_query'} -> resolves to sql_injection
    const sinkContext = new Map<string, Set<string>>();
    sinkContext.set('slugFilterOrder', new Set(['sql_query']));
    const proofWith = generateProof(map, finding, 'CWE-190', sinkContext);
    expect(proofWith).not.toBeNull();
    expect(proofWith!.primary_payload.canary).toBe('DST_CANARY_SQLI');
  });

  it('downgrades proof_strength to "strong" when path has unknown transforms', () => {
    const src = createNode({
      id: 'src_1',
      node_type: 'INGRESS',
      edges: [{ target: 'xform', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const xform = createNode({
      id: 'xform',
      node_type: 'TRANSFORM',
      node_subtype: '',
      code_snapshot: 'customProcessor.transform(x)',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'STORAGE',
      node_subtype: 'db_read',
      code_snapshot: "db.query(x)",
    });
    const map = buildTestMap([src, xform, sink]);
    const finding = makeFinding('src_1', 'sink_1');

    const proof = generateProof(map, finding, 'CWE-89');
    expect(proof).not.toBeNull();
    expect(proof!.proof_strength).toBe('strong');
  });
});

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

describe('determinism', () => {
  beforeEach(() => resetSequence());

  it('same input produces identical output', () => {
    const buildMap = () => {
      resetSequence();
      const src = createNode({
        id: 'src',
        node_type: 'INGRESS',
        node_subtype: 'http_request',
        code_snapshot: 'req.body.login',
        edges: [{ target: 'sink', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'sink',
        node_type: 'STORAGE',
        node_subtype: 'db_read',
        code_snapshot: `"SELECT * FROM users WHERE login='" + req.body.login + "'"`,
      });
      return buildTestMap([src, sink]);
    };

    const finding = makeFinding('src', 'sink');

    const map1 = buildMap();
    const proof1 = generateProof(map1, finding, 'CWE-89');

    const map2 = buildMap();
    const proof2 = generateProof(map2, finding, 'CWE-89');

    expect(JSON.stringify(proof1)).toBe(JSON.stringify(proof2));
  });
});

// ---------------------------------------------------------------------------
// inferPayloadClassFromCWE
// ---------------------------------------------------------------------------

describe('inferPayloadClassFromCWE', () => {
  it('maps CWE-89 to sql_injection', () => {
    expect(inferPayloadClassFromCWE('CWE-89')).toBe('sql_injection');
  });

  it('maps CWE-78 to command_injection', () => {
    expect(inferPayloadClassFromCWE('CWE-78')).toBe('command_injection');
  });

  it('returns null for non-injectable CWEs', () => {
    expect(inferPayloadClassFromCWE('CWE-327')).toBeNull();
    expect(inferPayloadClassFromCWE('CWE-798')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// analyzeTransforms
// ---------------------------------------------------------------------------

describe('analyzeTransforms', () => {
  beforeEach(() => resetSequence());

  it('identifies TRANSFORM nodes on the path', () => {
    const src = createNode({ id: 'src', node_type: 'INGRESS' });
    const xform = createNode({
      id: 'xform',
      node_type: 'TRANSFORM',
      node_subtype: 'codec',
    });
    const sink = createNode({ id: 'sink', node_type: 'STORAGE' });
    const map = buildTestMap([src, xform, sink]);

    const transforms = analyzeTransforms(map, ['src', 'xform', 'sink']);
    expect(transforms).toHaveLength(1);
    expect(transforms[0].node_id).toBe('xform');
    expect(transforms[0].subtype).toBe('codec');
    expect(transforms[0].effect.effect).toBe('encoding');
  });

  it('skips non-TRANSFORM nodes', () => {
    const src = createNode({ id: 'src', node_type: 'INGRESS' });
    const ctrl = createNode({ id: 'ctrl', node_type: 'CONTROL' });
    const sink = createNode({ id: 'sink', node_type: 'STORAGE' });
    const map = buildTestMap([src, ctrl, sink]);

    const transforms = analyzeTransforms(map, ['src', 'ctrl', 'sink']);
    expect(transforms).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// buildDeliverySpec
// ---------------------------------------------------------------------------

describe('buildDeliverySpec', () => {
  beforeEach(() => resetSequence());

  it('detects HTTP channel from http_request subtype', () => {
    const src = createNode({
      id: 'src',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      code_snapshot: 'req.body.login',
      param_names: ['login'],
    });
    const map = buildTestMap([src]);
    const spec = buildDeliverySpec(
      map, src,
      { id: 'src', label: '', line: 1, code: '' },
      "' OR '1'='1",
      [],
    );
    expect(spec.channel).toBe('http');
    expect(spec.http).toBeDefined();
    expect(spec.http!.method).toBe('POST');
    expect(spec.http!.param).toBe('login');
  });

  it('applies URL encoding when codec transform is present', () => {
    const map = buildTestMap([]);
    const spec = buildDeliverySpec(
      map, null,
      { id: 'src', label: '', line: 1, code: '' },
      "' OR '1'='1",
      [{ effect: 'encoding', payload_action: 'encode_before_delivery' }],
    );
    expect(spec.encoded_payload).toBe(encodeURIComponent("' OR '1'='1"));
    expect(spec.raw_payload).toBe("' OR '1'='1");
  });
});

// ---------------------------------------------------------------------------
// buildOracle
// ---------------------------------------------------------------------------

describe('buildOracle', () => {
  it('builds hybrid oracle with content_match for canary payloads', () => {
    const oracle = buildOracle(
      'sql_injection',
      { value: "' UNION SELECT 'DST_CANARY_SQLI' --", canary: 'DST_CANARY_SQLI', context: 'sql_string', execution_safe: true },
      null,
    );
    expect(oracle.type).toBe('hybrid');
    expect(oracle.dynamic_signal!.type).toBe('content_match');
    expect(oracle.dynamic_signal!.pattern).toBe('DST_CANARY_SQLI');
  });

  it('builds timing oracle for time-based payloads', () => {
    const oracle = buildOracle(
      'sql_injection',
      { value: "' OR SLEEP(2) -- -", canary: '', context: 'sql_string', execution_safe: false },
      null,
    );
    expect(oracle.type).toBe('hybrid');
    expect(oracle.dynamic_signal!.type).toBe('timing');
  });

  it('includes path info in static proof when available', () => {
    const pathAnalysis: import('./verifier/types.ts').PathAnalysis = {
      path_node_ids: ['a', 'b', 'c'],
      transforms: [],
      payload_reaches_sink: true,
    };
    const oracle = buildOracle(
      'sql_injection',
      { value: "' OR '1'='1", canary: '1', context: 'sql_string', execution_safe: true },
      pathAnalysis,
    );
    expect(oracle.static_proof).toContain('3 nodes');
    expect(oracle.static_proof).toContain('no transforms');
  });
});

// ---------------------------------------------------------------------------
// inferPayloadClassFromContent
// ---------------------------------------------------------------------------

describe('inferPayloadClassFromContent', () => {
  beforeEach(() => resetSequence());

  it('detects SQL injection from template string with SELECT...WHERE', () => {
    const src = createNode({
      id: 'src_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      code_snapshot: 'req.body.q',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'TRANSFORM',
      node_subtype: 'template_string',
      code_snapshot: '`SELECT * FROM users WHERE id = ${req.body.q}`',
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('src_1', 'sink_1');

    // CWE-190 has no payload class match — will fall through to content inference
    const proof = generateProof(map, finding, 'CWE-190');
    expect(proof).not.toBeNull();
    expect(proof!.primary_payload.canary).toBe('DST_CANARY_SQLI');
  });

  it('detects command injection from shell command (/bin/sh)', () => {
    const node = createNode({
      node_type: 'TRANSFORM',
      node_subtype: 'template_string',
      code_snapshot: '`/bin/sh -c "${cmd}"`',
    });
    const result = inferPayloadClassFromContent(node);
    expect(result).toBe('command_injection');
  });

  it('returns null for harmless content ("Hello ${name}!")', () => {
    const node = createNode({
      node_type: 'TRANSFORM',
      node_subtype: 'template_string',
      code_snapshot: '`Hello ${name}!`',
    });
    const result = inferPayloadClassFromContent(node);
    expect(result).toBeNull();
  });

  it('returns null for single SQL keyword in English context', () => {
    const node = createNode({
      node_type: 'TRANSFORM',
      node_subtype: 'template_string',
      code_snapshot: 'Please SELECT the best option',
    });
    const result = inferPayloadClassFromContent(node);
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// proof-based CWE reclassification
// ---------------------------------------------------------------------------

describe('proof-based CWE reclassification', () => {
  beforeEach(() => resetSequence());

  it('sets inferred_class when payload class differs from CWE (CWE-190 + SQL content)', () => {
    const src = createNode({
      id: 'src_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      code_snapshot: 'req.body.q',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'TRANSFORM',
      node_subtype: 'template_string',
      code_snapshot: '`SELECT * FROM users WHERE id = ${req.body.q}`',
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('src_1', 'sink_1');

    // CWE-190 (Integer Overflow) has no payload class — content inference picks up SQL
    const proof = generateProof(map, finding, 'CWE-190');
    expect(proof).not.toBeNull();
    expect(proof!.inferred_class).toBe('sql_injection');
  });

  it('does not set inferred_class when CWE already matches (CWE-89 + sql_query sink)', () => {
    const src = createNode({
      id: 'src_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      code_snapshot: 'req.body.login',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'STORAGE',
      node_subtype: 'db_read',
      code_snapshot: `"SELECT * FROM users WHERE login='" + req.body.login + "'"`,
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('src_1', 'sink_1');

    // CWE-89 maps to sql_injection, sink subtype db_read also resolves to sql_injection — match
    const proof = generateProof(map, finding, 'CWE-89');
    expect(proof).not.toBeNull();
    expect(proof!.inferred_class).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// buildReverseEdgeIndex
// ---------------------------------------------------------------------------

describe('buildReverseEdgeIndex', () => {
  beforeEach(() => resetSequence());

  it('produces correct predecessors for a 3-node chain', () => {
    const src = createNode({
      id: 'src',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      edges: [{ target: 'mid', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const mid = createNode({
      id: 'mid',
      node_type: 'TRANSFORM',
      node_subtype: 'string_op',
      edges: [{ target: 'sink', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink',
      node_type: 'STORAGE',
      node_subtype: 'db_read',
    });
    const map = buildTestMap([src, mid, sink]);

    const reverse = buildReverseEdgeIndex(map);

    // sink's predecessor is mid
    expect(reverse.get('sink')).toEqual([{ source: 'mid', edge_type: 'DATA_FLOW' }]);
    // mid's predecessor is src
    expect(reverse.get('mid')).toEqual([{ source: 'src', edge_type: 'DATA_FLOW' }]);
    // src has no predecessors
    expect(reverse.get('src')).toBeUndefined();
  });
});
