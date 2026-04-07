import { describe, it, expect, beforeEach } from 'vitest';
import {
  createNode,
  createNeuralMap,
  resetSequence,
  NODE_TYPES,
  EDGE_TYPES,
} from './types.js';
import type {
  NodeType,
  EdgeType,
  NeuralMapNode,
  NeuralMap,
  DataFlow,
  Edge,
  Sensitivity,
} from './types.js';

describe('Neural Map types', () => {
  beforeEach(() => {
    resetSequence();
  });

  describe('type constants', () => {
    it('has exactly 9 node types', () => {
      expect(NODE_TYPES).toHaveLength(9);
      const expected: NodeType[] = [
        'INGRESS', 'EGRESS', 'TRANSFORM', 'CONTROL', 'AUTH',
        'STORAGE', 'EXTERNAL', 'STRUCTURAL', 'META',
      ];
      expect([...NODE_TYPES]).toEqual(expected);
    });

    it('has exactly 7 edge types', () => {
      expect(EDGE_TYPES).toHaveLength(7);
      const expected: EdgeType[] = [
        'CALLS', 'RETURNS', 'READS', 'WRITES', 'DEPENDS', 'CONTAINS', 'DATA_FLOW',
      ];
      expect([...EDGE_TYPES]).toEqual(expected);
    });
  });

  describe('createNode', () => {
    it('produces valid defaults with only node_type', () => {
      const node = createNode({ node_type: 'INGRESS' });

      expect(node.id).toMatch(/^node_\d+_1$/);
      expect(node.sequence).toBe(1);
      expect(node.node_type).toBe('INGRESS');
      expect(node.node_subtype).toBe('');
      expect(node.language).toBe('javascript');
      expect(node.file).toBe('');
      expect(node.line_start).toBe(0);
      expect(node.line_end).toBe(0);
      expect(node.code_snapshot).toBe('');
      expect(node.data_in).toEqual([]);
      expect(node.data_out).toEqual([]);
      expect(node.edges).toEqual([]);
      expect(node.attack_surface).toEqual([]);
      expect(node.trust_boundary).toBe('');
      expect(node.tags).toEqual([]);
      expect(node.metadata).toEqual({});
    });

    it('auto-increments sequence across calls', () => {
      const a = createNode({ node_type: 'INGRESS' });
      const b = createNode({ node_type: 'EGRESS' });
      const c = createNode({ node_type: 'TRANSFORM' });

      expect(a.sequence).toBe(1);
      expect(b.sequence).toBe(2);
      expect(c.sequence).toBe(3);
      expect(a.id).toMatch(/^node_\d+_1$/);
      expect(b.id).toMatch(/^node_\d+_2$/);
      expect(c.id).toMatch(/^node_\d+_3$/);
    });

    it('resets sequence counter', () => {
      createNode({ node_type: 'INGRESS' });
      createNode({ node_type: 'EGRESS' });
      resetSequence();
      const fresh = createNode({ node_type: 'TRANSFORM' });
      expect(fresh.sequence).toBe(1);
      expect(fresh.id).toMatch(/^node_\d+_1$/);
    });

    it('allows overriding all fields', () => {
      const dataIn: DataFlow[] = [{
        name: 'body',
        source: 'EXTERNAL',
        data_type: 'object',
        tainted: true,
        sensitivity: 'PII',
      }];
      const edges: Edge[] = [{
        target: 'node_99',
        edge_type: 'CALLS',
        conditional: false,
        async: true,
      }];

      const node = createNode({
        id: 'custom_id',
        label: 'POST /login',
        sequence: 42,
        node_type: 'INGRESS',
        node_subtype: 'http_handler',
        language: 'typescript',
        file: 'routes/auth.ts',
        line_start: 10,
        line_end: 25,
        code_snapshot: 'app.post("/login", ...)',
        data_in: dataIn,
        data_out: [],
        edges,
        attack_surface: ['user_input', 'auth_endpoint'],
        trust_boundary: 'public',
        tags: ['auth', 'critical'],
        metadata: { method: 'POST' },
      });

      expect(node.id).toBe('custom_id');
      expect(node.label).toBe('POST /login');
      expect(node.sequence).toBe(42);
      expect(node.node_subtype).toBe('http_handler');
      expect(node.language).toBe('typescript');
      expect(node.file).toBe('routes/auth.ts');
      expect(node.line_start).toBe(10);
      expect(node.line_end).toBe(25);
      expect(node.data_in).toHaveLength(1);
      expect(node.data_in[0].tainted).toBe(true);
      expect(node.data_in[0].sensitivity).toBe('PII');
      expect(node.edges).toHaveLength(1);
      expect(node.edges[0].edge_type).toBe('CALLS');
      expect(node.edges[0].async).toBe(true);
      expect(node.attack_surface).toEqual(['user_input', 'auth_endpoint']);
      expect(node.trust_boundary).toBe('public');
      expect(node.tags).toEqual(['auth', 'critical']);
      expect(node.metadata).toEqual({ method: 'POST' });
    });

    it('each node gets independent arrays (no shared references)', () => {
      const a = createNode({ node_type: 'INGRESS' });
      const b = createNode({ node_type: 'EGRESS' });

      a.data_in.push({
        name: 'x', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE',
      });

      expect(b.data_in).toHaveLength(0);
    });
  });

  describe('createNeuralMap', () => {
    it('creates an empty map shell', () => {
      const map = createNeuralMap('test.js', 'const x = 1;');

      expect(map.nodes).toEqual([]);
      expect(map.edges).toEqual([]);
      expect(map.source_file).toBe('test.js');
      expect(map.source_code).toBe('const x = 1;');
      expect(map.parser_version).toBe('0.1.0');
      expect(map.created_at).toBeTruthy();
      // Verify ISO date format
      expect(() => new Date(map.created_at)).not.toThrow();
      expect(new Date(map.created_at).toISOString()).toBe(map.created_at);
    });
  });

  describe('type safety smoke tests', () => {
    it('Sensitivity type covers all values', () => {
      const values: Sensitivity[] = ['NONE', 'PII', 'SECRET', 'AUTH', 'FINANCIAL'];
      expect(values).toHaveLength(5);
    });

    it('NeuralMapNode satisfies the interface shape', () => {
      const node: NeuralMapNode = createNode({ node_type: 'META' });
      // If this compiles, the interface is correct
      const _keys: (keyof NeuralMapNode)[] = [
        'id', 'label', 'sequence', 'node_type', 'node_subtype', 'language',
        'file', 'line_start', 'line_end', 'code_snapshot',
        'data_in', 'data_out', 'edges', 'attack_surface',
        'trust_boundary', 'tags', 'metadata',
      ];
      // Every key should exist on the node
      for (const key of _keys) {
        expect(node).toHaveProperty(key);
      }
    });

    it('NeuralMap satisfies the interface shape', () => {
      const map: NeuralMap = createNeuralMap('x.js', '');
      const _keys: (keyof NeuralMap)[] = [
        'nodes', 'edges', 'source_file', 'source_code', 'created_at', 'parser_version',
      ];
      for (const key of _keys) {
        expect(map).toHaveProperty(key);
      }
    });
  });
});
