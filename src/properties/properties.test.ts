import { describe, it, expect, beforeEach } from 'vitest';
import { createNode, createNeuralMap, resetSequenceHard } from '../types.js';
import type { NeuralMap } from '../types.js';
import type { NodeRef } from '../verifier/types.js';

// Task 1: PropertyViolation and PropertyResult have NO cwe field
import type {
  SecurityProperty,
  CWEMapping,
  PropertyContext,
  PropertyResult,
  PropertyViolation,
} from './types.js';

// Task 2: cwe-map functions
import { mapViolationToCWE, violationToFinding } from './cwe-map.js';

// Task 3: taint reachability property
import { taintReachability } from './taint-reachability.js';

// Task 4: engine + index
import { runProperties, propertyResultsToFindings } from './engine.js';
import { PROPERTY_REGISTRY } from './index.js';

// Task 5: verifyAll integration
import { verifyAll } from '../verifier/index.js';

// Task 6: missing-auth property
import { missingAuth } from './missing-auth.js';

// Task 7: sensitive-exposure property
import { sensitiveExposure } from './sensitive-exposure.js';

// Task 8: weak-crypto property
import { weakCrypto } from './weak-crypto.js';

// Task 9: resource-lifecycle property
import { resourceLifecycle } from './resource-lifecycle.js';

describe('Property Engine', () => {
  beforeEach(() => {
    resetSequenceHard();
  });

  // ==========================================================================
  // Task 1: Types — CWE-free violations
  // ==========================================================================
  describe('types (Task 1)', () => {
    it('PropertyViolation has NO cwe field', () => {
      const v: PropertyViolation = {
        source: { id: 'n1', label: 'input', line: 1, code: 'req.body' },
        sink: { id: 'n2', label: 'query', line: 5, code: 'db.query(q)' },
        sinkType: 'STORAGE',
        sinkSubtype: 'sql_query',
        missing: 'sanitization',
        via: 'property_bfs',
        description: 'tainted data reaches SQL query',
      };
      // The violation must not carry a CWE — CWE mapping is a separate concern
      expect(Object.keys(v)).not.toContain('cwe');
      // Verify all expected fields exist
      expect(v.source.id).toBe('n1');
      expect(v.sink.id).toBe('n2');
      expect(v.sinkType).toBe('STORAGE');
      expect(v.sinkSubtype).toBe('sql_query');
      expect(v.missing).toBe('sanitization');
      expect(v.via).toBe('property_bfs');
      expect(v.description).toBe('tainted data reaches SQL query');
    });

    it('PropertyResult has NO cwe field', () => {
      const r: PropertyResult = {
        propertyId: 'taint-reachability',
        holds: false,
        violations: [],
      };
      expect(Object.keys(r)).not.toContain('cwe');
      expect(r.propertyId).toBe('taint-reachability');
      expect(r.holds).toBe(false);
      expect(r.violations).toEqual([]);
    });

    it('PropertyViolation optional context field works', () => {
      const v: PropertyViolation = {
        source: { id: 'n1', label: 'input', line: 1, code: 'req.body' },
        sink: { id: 'n2', label: 'query', line: 5, code: 'db.query(q)' },
        sinkType: 'STORAGE',
        sinkSubtype: 'sql_query',
        missing: 'sanitization',
        via: 'property_bfs',
        description: 'test',
        context: { framework: 'express' },
      };
      expect(v.context).toEqual({ framework: 'express' });
    });
  });

  // ==========================================================================
  // Task 2: CWE Mapping
  // ==========================================================================
  describe('cwe-map (Task 2)', () => {
    const violation: PropertyViolation = {
      source: { id: 'n1', label: 'input', line: 1, code: 'req.body' },
      sink: { id: 'n2', label: 'query', line: 5, code: 'db.query(q)' },
      sinkType: 'STORAGE',
      sinkSubtype: 'sql_query',
      missing: 'sanitization',
      via: 'property_bfs',
      description: 'tainted data reaches SQL query',
    };

    it('maps STORAGE/sql_query to CWE-89', () => {
      const mappings: CWEMapping[] = [
        {
          cwe: 'CWE-89',
          name: 'SQL Injection',
          when: { sinkType: 'STORAGE', sinkSubtype: 'sql_query', missing: 'sanitization' },
          severity: 'critical',
        },
      ];
      const result = mapViolationToCWE(violation, mappings);
      expect(result).not.toBeNull();
      expect(result!.cwe).toBe('CWE-89');
    });

    it('maps EXTERNAL/system_exec to CWE-78', () => {
      const v: PropertyViolation = {
        source: { id: 'n1', label: 'input', line: 1, code: 'req.body' },
        sink: { id: 'n3', label: 'exec', line: 10, code: 'exec(cmd)' },
        sinkType: 'EXTERNAL',
        sinkSubtype: 'system_exec',
        missing: 'sanitization',
        via: 'property_bfs',
        description: 'tainted data reaches system exec',
      };
      const mappings: CWEMapping[] = [
        {
          cwe: 'CWE-78',
          name: 'OS Command Injection',
          when: { sinkType: 'EXTERNAL', sinkSubtype: 'system_exec', missing: 'sanitization' },
          severity: 'critical',
        },
      ];
      const result = mapViolationToCWE(v, mappings);
      expect(result).not.toBeNull();
      expect(result!.cwe).toBe('CWE-78');
    });

    it('maps EGRESS/http_response to CWE-79', () => {
      const v: PropertyViolation = {
        source: { id: 'n1', label: 'input', line: 1, code: 'req.query' },
        sink: { id: 'n4', label: 'render', line: 15, code: 'res.send(html)' },
        sinkType: 'EGRESS',
        sinkSubtype: 'http_response',
        missing: 'encoding',
        via: 'property_bfs',
        description: 'tainted data reaches HTTP response',
      };
      const mappings: CWEMapping[] = [
        {
          cwe: 'CWE-79',
          name: 'XSS',
          when: { sinkType: 'EGRESS', sinkSubtype: 'http_response', missing: 'encoding' },
          severity: 'high',
        },
      ];
      const result = mapViolationToCWE(v, mappings);
      expect(result).not.toBeNull();
      expect(result!.cwe).toBe('CWE-79');
    });

    it('returns null when no mapping matches', () => {
      const mappings: CWEMapping[] = [
        {
          cwe: 'CWE-89',
          name: 'SQL Injection',
          when: { sinkType: 'STORAGE', sinkSubtype: 'sql_query', missing: 'sanitization' },
          severity: 'critical',
        },
      ];
      const v: PropertyViolation = {
        source: { id: 'n1', label: 'input', line: 1, code: 'req.body' },
        sink: { id: 'n5', label: 'log', line: 20, code: 'console.log(x)' },
        sinkType: 'EGRESS',
        sinkSubtype: 'log_output',
        missing: 'encoding',
        via: 'property_bfs',
        description: 'tainted data reaches log',
      };
      const result = mapViolationToCWE(v, mappings);
      expect(result).toBeNull();
    });

    it('violationToFinding produces a Finding with correct CWE', () => {
      const cwe: CWEMapping = {
        cwe: 'CWE-89',
        name: 'SQL Injection',
        when: { sinkType: 'STORAGE', sinkSubtype: 'sql_query' },
        severity: 'critical',
      };
      const finding = violationToFinding(violation, cwe, 'Use parameterized queries');
      expect(finding.source.id).toBe('n1');
      expect(finding.sink.id).toBe('n2');
      expect(finding.severity).toBe('critical');
      expect(finding.fix).toBe('Use parameterized queries');
      expect(finding.missing).toBe('sanitization');
    });

    it('matches sinkSubtype array', () => {
      const mappings: CWEMapping[] = [
        {
          cwe: 'CWE-78',
          name: 'OS Command Injection',
          when: { sinkType: 'EXTERNAL', sinkSubtype: ['system_exec', 'shell_exec', 'process_spawn'], missing: 'sanitization' },
          severity: 'critical',
        },
      ];
      const v: PropertyViolation = {
        source: { id: 'n1', label: 'input', line: 1, code: 'req.body' },
        sink: { id: 'n3', label: 'spawn', line: 10, code: 'spawn(cmd)' },
        sinkType: 'EXTERNAL',
        sinkSubtype: 'process_spawn',
        missing: 'sanitization',
        via: 'property_bfs',
        description: 'tainted data reaches process spawn',
      };
      const result = mapViolationToCWE(v, mappings);
      expect(result).not.toBeNull();
      expect(result!.cwe).toBe('CWE-78');
    });
  });

  // ==========================================================================
  // Task 3: Taint Reachability Property
  // ==========================================================================
  describe('taint-reachability (Task 3)', () => {
    const ctx: PropertyContext = {
      language: 'javascript',
      hasStory: false,
      isLibrary: false,
      pedantic: false,
    };

    it('detects INGRESS -> STORAGE/sql_query without CONTROL/TRANSFORM', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const ingress = createNode({
        node_type: 'INGRESS',
        node_subtype: 'http_body',
        label: 'req.body',
        data_out: [{ name: 'userInput', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'sink_1',
        node_type: 'STORAGE',
        node_subtype: 'sql_query',
        label: 'db.query',
        data_in: [{ name: 'userInput', source: ingress.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [ingress, sink];

      const result = taintReachability.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].sinkType).toBe('STORAGE');
      expect(result.violations[0].sinkSubtype).toBe('sql_query');
      expect(result.violations[0].missing).toBe('sanitization');
    });

    it('holds when TRANSFORM/sanitize exists on path', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const ingress = createNode({
        node_type: 'INGRESS',
        node_subtype: 'http_body',
        label: 'req.body',
        data_out: [{ name: 'userInput', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'sanitize_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sanitize = createNode({
        id: 'sanitize_1',
        node_type: 'TRANSFORM',
        node_subtype: 'sanitize',
        label: 'sanitize(input)',
        data_in: [{ name: 'userInput', source: ingress.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        data_out: [{ name: 'cleanInput', source: '', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'sink_1',
        node_type: 'STORAGE',
        node_subtype: 'sql_query',
        label: 'db.query',
        data_in: [{ name: 'cleanInput', source: sanitize.id, data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [ingress, sanitize, sink];

      const result = taintReachability.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('holds when parameter-binding is used (story-based)', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const ingress = createNode({
        node_type: 'INGRESS',
        node_subtype: 'http_body',
        label: 'req.body',
        data_out: [{ name: 'userInput', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'sink_1',
        node_type: 'STORAGE',
        node_subtype: 'sql_query',
        label: 'db.query',
        data_in: [{ name: 'userInput', source: ingress.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [ingress, sink];

      // Story shows parameter binding neutralizes taint
      map.story = [
        {
          text: 'INGRESS receives userInput from HTTP body',
          templateKey: 'ingress_http',
          slots: { variable: 'userInput' },
          lineNumber: 1,
          nodeId: ingress.id,
          taintClass: 'TAINTED',
        },
        {
          text: 'STORAGE executes SQL query with parameter-binding on userInput',
          templateKey: 'sink_sql_parameterized',
          slots: { variable: 'userInput', object: 'stmt' },
          lineNumber: 5,
          nodeId: sink.id,
          taintClass: 'SINK',
        },
      ];

      const storyCtx: PropertyContext = { ...ctx, hasStory: true };
      const result = taintReachability.verify(map, storyCtx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('CWE mappings cover all injection types', () => {
      const requiredCWEs = [
        'CWE-89', 'CWE-79', 'CWE-78', 'CWE-77', 'CWE-22',
        'CWE-90', 'CWE-643', 'CWE-918', 'CWE-611', 'CWE-94',
        'CWE-601', 'CWE-502', 'CWE-943',
      ];
      const mappedCWEs = taintReachability.cweMapping.map(m => m.cwe);
      for (const cwe of requiredCWEs) {
        expect(mappedCWEs).toContain(cwe);
      }
    });
  });

  // ==========================================================================
  // Task 4: Engine + Index
  // ==========================================================================
  describe('engine (Task 4)', () => {
    it('runProperties returns results for registered properties', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const ctx: PropertyContext = {
        language: 'javascript',
        hasStory: false,
        isLibrary: false,
        pedantic: false,
      };
      const results = runProperties(map, ctx);
      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeGreaterThanOrEqual(1);
      // Each result should be a PropertyResult
      for (const r of results) {
        expect(r).toHaveProperty('propertyId');
        expect(r).toHaveProperty('holds');
        expect(r).toHaveProperty('violations');
      }
    });

    it('propertyResultsToFindings produces CWE-89 finding from sql_query violation', () => {
      const results: PropertyResult[] = [
        {
          propertyId: 'taint-reachability',
          holds: false,
          violations: [
            {
              source: { id: 'n1', label: 'input', line: 1, code: 'req.body' },
              sink: { id: 'n2', label: 'query', line: 5, code: 'db.query(q)' },
              sinkType: 'STORAGE',
              sinkSubtype: 'sql_query',
              missing: 'sanitization',
              via: 'property_bfs',
              description: 'tainted data reaches SQL query without sanitization',
            },
          ],
        },
      ];
      const verResults = propertyResultsToFindings(results);
      expect(verResults.length).toBeGreaterThanOrEqual(1);
      // Find the CWE-89 result
      const sql = verResults.find(r => r.cwe === 'CWE-89');
      expect(sql).toBeDefined();
      expect(sql!.holds).toBe(false);
      expect(sql!.findings.length).toBeGreaterThanOrEqual(1);
      expect(sql!.findings[0].source.id).toBe('n1');
      expect(sql!.findings[0].sink.id).toBe('n2');
    });

    it('PROPERTY_REGISTRY contains taint-reachability', () => {
      expect(PROPERTY_REGISTRY.length).toBeGreaterThanOrEqual(1);
      const ids = PROPERTY_REGISTRY.map(p => p.id);
      expect(ids).toContain('taint-reachability');
    });
  });

  // ==========================================================================
  // Task 5: Property engine integration with verifyAll
  // ==========================================================================
  describe('verifyAll integration (Task 5)', () => {
    beforeEach(() => resetSequenceHard());

    it('property-detected SQLi appears in verifyAll results', () => {
      const map = createNeuralMap('test.js', '');
      const src = createNode({
        node_type: 'INGRESS', node_subtype: 'http_request', label: 'req.body',
        data_in: [{ name: 'x', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'sink1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'sink1', node_type: 'STORAGE', node_subtype: 'sql_query', label: 'db.query',
        data_in: [{ name: 'q', source: src.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [src, sink];

      const results = verifyAll(map, 'javascript');
      const sqli = results.find(r => r.cwe === 'CWE-89' && !r.holds);
      expect(sqli).toBeDefined();
      expect(sqli!.findings.length).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // Task 6: Missing-Auth Property
  // ==========================================================================
  describe('missing-auth property (Task 6)', () => {
    const ctx: PropertyContext = {
      language: 'javascript',
      hasStory: false,
      isLibrary: false,
      pedantic: false,
    };

    beforeEach(() => resetSequenceHard());

    it('detects INGRESS -> privileged STORAGE without AUTH', () => {
      const map = createNeuralMap('test.js', '');
      const ingress = createNode({
        node_type: 'INGRESS',
        node_subtype: 'http_body',
        label: 'req.body',
        data_out: [{ name: 'userInput', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'sink_1',
        node_type: 'STORAGE',
        node_subtype: 'db_write',
        label: 'db.insert',
        data_in: [{ name: 'userInput', source: ingress.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [ingress, sink];

      const result = missingAuth.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].missing).toBe('authorization');
    });

    it('holds when AUTH node exists on path', () => {
      const map = createNeuralMap('test.js', '');
      const ingress = createNode({
        node_type: 'INGRESS',
        node_subtype: 'http_body',
        label: 'req.body',
        data_out: [{ name: 'userInput', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'auth_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const auth = createNode({
        id: 'auth_1',
        node_type: 'AUTH',
        node_subtype: 'session_check',
        label: 'requireAuth()',
        data_in: [{ name: 'userInput', source: ingress.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        data_out: [{ name: 'authedInput', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'sink_1',
        node_type: 'STORAGE',
        node_subtype: 'db_write',
        label: 'db.insert',
        data_in: [{ name: 'authedInput', source: auth.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [ingress, auth, sink];

      const result = missingAuth.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('detects path to node with FINANCIAL sensitivity', () => {
      const map = createNeuralMap('test.js', '');
      const ingress = createNode({
        node_type: 'INGRESS',
        node_subtype: 'http_body',
        label: 'req.body',
        data_out: [{ name: 'amount', source: '', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'sink_1',
        node_type: 'STORAGE',
        node_subtype: 'db_update',
        label: 'db.updateBalance',
        data_in: [{ name: 'amount', source: ingress.id, data_type: 'number', tainted: true, sensitivity: 'FINANCIAL' }],
        edges: [],
      });
      map.nodes = [ingress, sink];

      const result = missingAuth.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
    });

    it('detects path to node with admin attack surface', () => {
      const map = createNeuralMap('test.js', '');
      const ingress = createNode({
        node_type: 'INGRESS',
        node_subtype: 'http_body',
        label: 'req.body',
        data_out: [{ name: 'payload', source: '', data_type: 'object', tainted: true, sensitivity: 'NONE' }],
        edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'sink_1',
        node_type: 'STORAGE',
        node_subtype: 'db_update',
        label: 'admin.deleteUser',
        attack_surface: ['admin', 'user_management'],
        data_in: [{ name: 'payload', source: ingress.id, data_type: 'object', tainted: true, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [ingress, sink];

      const result = missingAuth.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
    });

    it('CWE mappings cover authorization CWEs', () => {
      const requiredCWEs = ['CWE-285', 'CWE-862', 'CWE-863', 'CWE-306'];
      const mappedCWEs = missingAuth.cweMapping.map(m => m.cwe);
      for (const cwe of requiredCWEs) {
        expect(mappedCWEs).toContain(cwe);
      }
    });

    it('is registered in PROPERTY_REGISTRY', () => {
      const ids = PROPERTY_REGISTRY.map(p => p.id);
      expect(ids).toContain('missing-auth');
    });
  });

  // ==========================================================================
  // Task 7: Sensitive-Exposure Property
  // ==========================================================================
  describe('sensitive-exposure (Task 7)', () => {
    const ctx: PropertyContext = {
      language: 'javascript',
      hasStory: false,
      isLibrary: false,
      pedantic: false,
    };

    it('detects SECRET data reaching EGRESS without encryption', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const source = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'assignment',
        label: 'loadSecret',
        data_in: [{ name: 'apiKey', source: '', data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
        edges: [{ target: 'egress_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'egress_1',
        node_type: 'EGRESS',
        node_subtype: 'http_response',
        label: 'res.json',
        data_in: [{ name: 'apiKey', source: source.id, data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
        edges: [],
      });
      map.nodes = [source, sink];

      const result = sensitiveExposure.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].sinkType).toBe('EGRESS');
      expect(result.violations[0].sinkSubtype).toBe('http_response');
      expect(result.violations[0].missing).toBe('encryption');
    });

    it('holds when TRANSFORM/encrypt exists on path', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const source = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'assignment',
        label: 'loadSecret',
        data_in: [{ name: 'apiKey', source: '', data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
        edges: [{ target: 'encrypt_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const encrypt = createNode({
        id: 'encrypt_1',
        node_type: 'TRANSFORM',
        node_subtype: 'encrypt',
        label: 'encrypt(apiKey)',
        data_in: [{ name: 'apiKey', source: source.id, data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
        data_out: [{ name: 'encrypted', source: '', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [{ target: 'egress_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'egress_1',
        node_type: 'EGRESS',
        node_subtype: 'http_response',
        label: 'res.json',
        data_in: [{ name: 'encrypted', source: encrypt.id, data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [source, encrypt, sink];

      const result = sensitiveExposure.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('detects PII data reaching log sink', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const source = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'assignment',
        label: 'loadUser',
        data_in: [{ name: 'email', source: '', data_type: 'string', tainted: false, sensitivity: 'PII' }],
        edges: [{ target: 'log_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'log_1',
        node_type: 'STORAGE',
        node_subtype: 'log_write',
        label: 'logger.info',
        data_in: [{ name: 'email', source: source.id, data_type: 'string', tainted: false, sensitivity: 'PII' }],
        edges: [],
      });
      map.nodes = [source, sink];

      const result = sensitiveExposure.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].sinkType).toBe('STORAGE');
      expect(result.violations[0].sinkSubtype).toBe('log_write');
      expect(result.violations[0].missing).toBe('encryption');
    });

    it('TRANSFORM/hash also neutralizes sensitive data', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const source = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'assignment',
        label: 'loadUser',
        data_in: [{ name: 'ssn', source: '', data_type: 'string', tainted: false, sensitivity: 'PII' }],
        edges: [{ target: 'hash_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const hash = createNode({
        id: 'hash_1',
        node_type: 'TRANSFORM',
        node_subtype: 'hash',
        label: 'hash(ssn)',
        data_in: [{ name: 'ssn', source: source.id, data_type: 'string', tainted: false, sensitivity: 'PII' }],
        data_out: [{ name: 'hashed', source: '', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [{ target: 'log_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'log_1',
        node_type: 'STORAGE',
        node_subtype: 'log_write',
        label: 'logger.info',
        data_in: [{ name: 'hashed', source: hash.id, data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [source, hash, sink];

      const result = sensitiveExposure.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('TRANSFORM/sanitize also neutralizes sensitive data', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const source = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'assignment',
        label: 'loadCard',
        data_in: [{ name: 'cardNum', source: '', data_type: 'string', tainted: false, sensitivity: 'FINANCIAL' }],
        edges: [{ target: 'redact_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const redact = createNode({
        id: 'redact_1',
        node_type: 'TRANSFORM',
        node_subtype: 'sanitize',
        label: 'redact(cardNum)',
        data_in: [{ name: 'cardNum', source: source.id, data_type: 'string', tainted: false, sensitivity: 'FINANCIAL' }],
        data_out: [{ name: 'redacted', source: '', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [{ target: 'egress_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'egress_1',
        node_type: 'EGRESS',
        node_subtype: 'http_response',
        label: 'res.json',
        data_in: [{ name: 'redacted', source: redact.id, data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [source, redact, sink];

      const result = sensitiveExposure.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('CWE mappings cover required sensitive-exposure CWEs', () => {
      const requiredCWEs = [
        'CWE-200', 'CWE-209', 'CWE-312', 'CWE-319', 'CWE-532', 'CWE-598',
      ];
      const mappedCWEs = sensitiveExposure.cweMapping.map(m => m.cwe);
      for (const cwe of requiredCWEs) {
        expect(mappedCWEs).toContain(cwe);
      }
    });

    it('detects AUTH data reaching EGRESS without encryption', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const source = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'assignment',
        label: 'loadToken',
        data_in: [{ name: 'token', source: '', data_type: 'string', tainted: false, sensitivity: 'AUTH' }],
        edges: [{ target: 'egress_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'egress_1',
        node_type: 'EGRESS',
        node_subtype: 'redirect',
        label: 'res.redirect',
        data_in: [{ name: 'token', source: source.id, data_type: 'string', tainted: false, sensitivity: 'AUTH' }],
        edges: [],
      });
      map.nodes = [source, sink];

      const result = sensitiveExposure.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].missing).toBe('encryption');
    });

    it('does not flag NONE sensitivity data', () => {
      resetSequenceHard();
      const map = createNeuralMap('test.js', '');
      const source = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'assignment',
        label: 'loadPublic',
        data_in: [{ name: 'publicInfo', source: '', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [{ target: 'egress_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const sink = createNode({
        id: 'egress_1',
        node_type: 'EGRESS',
        node_subtype: 'http_response',
        label: 'res.json',
        data_in: [{ name: 'publicInfo', source: source.id, data_type: 'string', tainted: false, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [source, sink];

      const result = sensitiveExposure.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('is registered in PROPERTY_REGISTRY', () => {
      const ids = PROPERTY_REGISTRY.map(p => p.id);
      expect(ids).toContain('sensitive-exposure');
    });
  });

  // ==========================================================================
  // Task 8: Weak-Crypto Property
  // ==========================================================================
  describe('weak-crypto property (Task 8)', () => {
    const ctx: PropertyContext = {
      language: 'javascript',
      hasStory: false,
      isLibrary: false,
      pedantic: false,
    };

    beforeEach(() => resetSequenceHard());

    it('detects MD5 usage in TRANSFORM/hash node', () => {
      const map = createNeuralMap('test.js', '');
      const node = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'hash',
        label: 'crypto.createHash',
        algorithm_name: 'MD5',
        code_snapshot: "crypto.createHash('md5')",
        edges: [],
      });
      map.nodes = [node];

      const result = weakCrypto.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].sinkType).toBe('TRANSFORM');
      expect(result.violations[0].sinkSubtype).toBe('hash');
      expect(result.violations[0].missing).toBe('encryption');
      expect(result.violations[0].via).toBe('property_structural');
      expect(result.violations[0].context?.weak_algorithm).toBe('MD5');
    });

    it('holds for SHA-256', () => {
      const map = createNeuralMap('test.js', '');
      const node = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'hash',
        label: 'crypto.createHash',
        algorithm_name: 'SHA-256',
        code_snapshot: "crypto.createHash('sha256')",
        edges: [],
      });
      map.nodes = [node];

      const result = weakCrypto.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('detects DES in code_snapshot when algorithm_name not set', () => {
      const map = createNeuralMap('test.js', '');
      const node = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'encrypt',
        label: 'encrypt',
        code_snapshot: "cipher = crypto.createCipher('des', key)",
        edges: [],
      });
      map.nodes = [node];

      const result = weakCrypto.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].context?.weak_algorithm).toBeDefined();
    });

    it('detects SHA1 in algorithm_name', () => {
      const map = createNeuralMap('test.js', '');
      const node = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'hash',
        label: 'crypto.createHash',
        algorithm_name: 'SHA-1',
        code_snapshot: "crypto.createHash('sha1')",
        edges: [],
      });
      map.nodes = [node];

      const result = weakCrypto.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].context?.weak_algorithm).toBe('SHA-1');
    });

    it('detects RC4 in analysis_snapshot', () => {
      const map = createNeuralMap('test.js', '');
      const node = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'encrypt',
        label: 'encrypt',
        analysis_snapshot: 'Uses RC4 stream cipher for encryption',
        code_snapshot: '',
        edges: [],
      });
      map.nodes = [node];

      const result = weakCrypto.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
    });

    it('detects ECB mode in code_snapshot', () => {
      const map = createNeuralMap('test.js', '');
      const node = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'encrypt',
        label: 'encrypt',
        code_snapshot: "cipher = crypto.createCipher('aes-128-ecb', key)",
        edges: [],
      });
      map.nodes = [node];

      const result = weakCrypto.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
    });

    it('detects hardcoded key from literal source', () => {
      const map = createNeuralMap('test.js', '');
      const literal = createNode({
        node_type: 'STRUCTURAL',
        node_subtype: 'constant',
        label: 'secretKey',
        data_out: [{ name: 'key', source: '', data_type: 'literal', tainted: false, sensitivity: 'NONE' }],
        edges: [{ target: 'enc_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const enc = createNode({
        id: 'enc_1',
        node_type: 'TRANSFORM',
        node_subtype: 'encrypt',
        label: 'encrypt',
        algorithm_name: 'AES-256-CBC',
        data_in: [{ name: 'key', source: literal.id, data_type: 'literal', tainted: false, sensitivity: 'NONE' }],
        edges: [],
      });
      map.nodes = [literal, enc];

      const result = weakCrypto.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].context?.hardcoded_key).toBe('true');
    });

    it('holds for AES-256-CBC with non-literal key', () => {
      const map = createNeuralMap('test.js', '');
      const keySource = createNode({
        node_type: 'INGRESS',
        node_subtype: 'env_var',
        label: 'process.env.KEY',
        data_out: [{ name: 'key', source: '', data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
        edges: [{ target: 'enc_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
      });
      const enc = createNode({
        id: 'enc_1',
        node_type: 'TRANSFORM',
        node_subtype: 'encrypt',
        label: 'encrypt',
        algorithm_name: 'AES-256-CBC',
        data_in: [{ name: 'key', source: keySource.id, data_type: 'string', tainted: false, sensitivity: 'SECRET' }],
        edges: [],
      });
      map.nodes = [keySource, enc];

      const result = weakCrypto.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('ignores non-crypto TRANSFORM nodes', () => {
      const map = createNeuralMap('test.js', '');
      const node = createNode({
        node_type: 'TRANSFORM',
        node_subtype: 'sanitize',
        label: 'sanitizeInput',
        code_snapshot: "input.replace(/[<>]/g, '')",
        edges: [],
      });
      map.nodes = [node];

      const result = weakCrypto.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('CWE mappings cover required weak-crypto CWEs', () => {
      const requiredCWEs = [
        'CWE-327', 'CWE-328', 'CWE-326', 'CWE-261', 'CWE-321',
      ];
      const mappedCWEs = weakCrypto.cweMapping.map(m => m.cwe);
      for (const cwe of requiredCWEs) {
        expect(mappedCWEs).toContain(cwe);
      }
    });

    it('is registered in PROPERTY_REGISTRY', () => {
      const ids = PROPERTY_REGISTRY.map(p => p.id);
      expect(ids).toContain('weak-crypto');
    });
  });

  // ==========================================================================
  // Task 9: Resource-Lifecycle Property
  // ==========================================================================
  describe('resource-lifecycle (Task 9)', () => {
    const ctx: PropertyContext = {
      language: 'javascript',
      hasStory: false,
      isLibrary: false,
      pedantic: false,
    };

    beforeEach(() => resetSequenceHard());

    it('detects file opened without close in same scope', () => {
      const map = createNeuralMap('test.js', '');
      const func = createNode({
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        label: 'processFile',
        edges: [{ target: 'open1', edge_type: 'CONTAINS', conditional: false, async: false }],
      });
      const open = createNode({
        id: 'open1',
        node_type: 'STORAGE',
        node_subtype: 'file_read',
        label: 'fs.open',
        code_snapshot: "fs.open('data.txt')",
        edges: [],
      });
      map.nodes = [func, open];

      const result = resourceLifecycle.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].missing).toBe('lifecycle');
      expect(result.violations[0].via).toBe('property_structural');
      expect(result.violations[0].sinkSubtype).toBe('file_read');
    });

    it('holds when close exists in same function', () => {
      const map = createNeuralMap('test.js', '');
      const func = createNode({
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        label: 'processFile',
        edges: [
          { target: 'open1', edge_type: 'CONTAINS', conditional: false, async: false },
          { target: 'close1', edge_type: 'CONTAINS', conditional: false, async: false },
        ],
      });
      const open = createNode({
        id: 'open1',
        node_type: 'STORAGE',
        node_subtype: 'file_read',
        label: 'fs.open',
        code_snapshot: "fs.open('data.txt')",
        edges: [],
      });
      const close = createNode({
        id: 'close1',
        node_type: 'TRANSFORM',
        node_subtype: 'format',
        label: 'fs.close',
        code_snapshot: 'file.close()',
        edges: [],
      });
      map.nodes = [func, open, close];

      const result = resourceLifecycle.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('detects db_connect without disconnect', () => {
      const map = createNeuralMap('test.js', '');
      const func = createNode({
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        label: 'fetchData',
        edges: [{ target: 'conn1', edge_type: 'CONTAINS', conditional: false, async: false }],
      });
      const conn = createNode({
        id: 'conn1',
        node_type: 'RESOURCE',
        node_subtype: 'db_connect',
        label: 'db.connect',
        code_snapshot: "db.connect('localhost')",
        edges: [],
      });
      map.nodes = [func, conn];

      const result = resourceLifecycle.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].sinkSubtype).toBe('db_connect');
    });

    it('holds when disconnect exists in same function for db_connect', () => {
      const map = createNeuralMap('test.js', '');
      const func = createNode({
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        label: 'fetchData',
        edges: [
          { target: 'conn1', edge_type: 'CONTAINS', conditional: false, async: false },
          { target: 'disc1', edge_type: 'CONTAINS', conditional: false, async: false },
        ],
      });
      const conn = createNode({
        id: 'conn1',
        node_type: 'RESOURCE',
        node_subtype: 'db_connect',
        label: 'db.connect',
        code_snapshot: "db.connect('localhost')",
        edges: [],
      });
      const disc = createNode({
        id: 'disc1',
        node_type: 'TRANSFORM',
        node_subtype: 'format',
        label: 'db.disconnect',
        code_snapshot: 'conn.disconnect()',
        edges: [],
      });
      map.nodes = [func, conn, disc];

      const result = resourceLifecycle.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('detects socket_write without close', () => {
      const map = createNeuralMap('test.js', '');
      const func = createNode({
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        label: 'sendData',
        edges: [{ target: 'sock1', edge_type: 'CONTAINS', conditional: false, async: false }],
      });
      const sock = createNode({
        id: 'sock1',
        node_type: 'RESOURCE',
        node_subtype: 'socket_write',
        label: 'socket.write',
        code_snapshot: "socket.write('data')",
        edges: [],
      });
      map.nodes = [func, sock];

      const result = resourceLifecycle.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
    });

    it('detects lock_acquire without unlock', () => {
      const map = createNeuralMap('test.js', '');
      const func = createNode({
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        label: 'criticalSection',
        edges: [{ target: 'lock1', edge_type: 'CONTAINS', conditional: false, async: false }],
      });
      const lock = createNode({
        id: 'lock1',
        node_type: 'RESOURCE',
        node_subtype: 'lock_acquire',
        label: 'mutex.lock',
        code_snapshot: 'mutex.lock()',
        edges: [],
      });
      map.nodes = [func, lock];

      const result = resourceLifecycle.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.violations[0].sinkSubtype).toBe('lock_acquire');
    });

    it('holds when unlock exists for lock_acquire', () => {
      const map = createNeuralMap('test.js', '');
      const func = createNode({
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        label: 'criticalSection',
        edges: [
          { target: 'lock1', edge_type: 'CONTAINS', conditional: false, async: false },
          { target: 'unlock1', edge_type: 'CONTAINS', conditional: false, async: false },
        ],
      });
      const lock = createNode({
        id: 'lock1',
        node_type: 'RESOURCE',
        node_subtype: 'lock_acquire',
        label: 'mutex.lock',
        code_snapshot: 'mutex.lock()',
        edges: [],
      });
      const unlock = createNode({
        id: 'unlock1',
        node_type: 'TRANSFORM',
        node_subtype: 'format',
        label: 'mutex.unlock',
        code_snapshot: 'mutex.unlock()',
        edges: [],
      });
      map.nodes = [func, lock, unlock];

      const result = resourceLifecycle.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('handles resource node without containing function (no violation)', () => {
      const map = createNeuralMap('test.js', '');
      const open = createNode({
        node_type: 'STORAGE',
        node_subtype: 'file_read',
        label: 'fs.open',
        code_snapshot: "fs.open('data.txt')",
        edges: [],
      });
      map.nodes = [open];

      const result = resourceLifecycle.verify(map, ctx);
      expect(result.holds).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('CWE mappings cover resource lifecycle CWEs', () => {
      const requiredCWEs = ['CWE-401', 'CWE-404', 'CWE-772', 'CWE-775'];
      const mappedCWEs = resourceLifecycle.cweMapping.map(m => m.cwe);
      for (const cwe of requiredCWEs) {
        expect(mappedCWEs).toContain(cwe);
      }
    });

    it('is registered in PROPERTY_REGISTRY', () => {
      const ids = PROPERTY_REGISTRY.map(p => p.id);
      expect(ids).toContain('resource-lifecycle');
    });

    it('detects nested containment — resource in nested function', () => {
      const map = createNeuralMap('test.js', '');
      const outerFunc = createNode({
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        label: 'outer',
        edges: [{ target: 'inner1', edge_type: 'CONTAINS', conditional: false, async: false }],
      });
      const innerFunc = createNode({
        id: 'inner1',
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        label: 'inner',
        edges: [{ target: 'file1', edge_type: 'CONTAINS', conditional: false, async: false }],
      });
      const file = createNode({
        id: 'file1',
        node_type: 'STORAGE',
        node_subtype: 'file_write',
        label: 'fs.writeFile',
        code_snapshot: "fs.writeFile('out.txt', data)",
        edges: [],
      });
      map.nodes = [outerFunc, innerFunc, file];

      const result = resourceLifecycle.verify(map, ctx);
      expect(result.holds).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
    });
  });
});
