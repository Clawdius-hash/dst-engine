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
});
