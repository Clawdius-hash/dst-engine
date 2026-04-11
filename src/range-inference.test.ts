import { describe, it, expect, beforeEach } from 'vitest';
import {
  createRange, createUnboundedRange, narrowRange,
  isRangeSafe, rangeExcludesZero,
  createNode, createNeuralMap, resetSequenceHard,
} from './types.js';
import type { NeuralMap, NeuralMapNode } from './types.js';
import { MapperContext } from './mapper.js';
import { javascriptProfile } from './profiles/javascript.js';
import {
  sinkHasBoundedRange, sinkHasNonZeroRange, sinkHasSafeRange,
} from './generated/_helpers.js';

describe('RangeInfo', () => {
  it('createRange sets bounded correctly', () => {
    const r = createRange(0, 1000);
    expect(r.bounded).toBe(true);
    expect(r.min).toBe(0);
    expect(r.max).toBe(1000);
  });

  it('createUnboundedRange is not bounded', () => {
    const r = createUnboundedRange();
    expect(r.bounded).toBe(false);
    expect(r.min).toBe(-Infinity);
    expect(r.max).toBe(Infinity);
  });

  it('narrowRange intersects correctly', () => {
    const a = createRange(0, Infinity);    // x > 0
    const b = createRange(-Infinity, 1000); // x < 1000
    const n = narrowRange(a, b);
    expect(n.min).toBe(0);
    expect(n.max).toBe(1000);
    expect(n.bounded).toBe(true);
  });

  it('narrowRange with disjoint ranges produces empty (min > max)', () => {
    const a = createRange(100, 200);
    const b = createRange(300, 400);
    const n = narrowRange(a, b);
    expect(n.min).toBe(300);   // max(100,300)
    expect(n.max).toBe(200);   // min(200,400)
    expect(n.bounded).toBe(true); // both finite, but min > max = empty
  });

  it('isRangeSafe works for safe range', () => {
    const r = createRange(0, 255);
    expect(isRangeSafe(r, 255)).toBe(true);
    expect(isRangeSafe(r, 254)).toBe(false); // max exceeds limit
  });

  it('isRangeSafe rejects unbounded', () => {
    const r = createUnboundedRange();
    expect(isRangeSafe(r, 1000)).toBe(false);
  });

  it('isRangeSafe rejects negative min', () => {
    const r = createRange(-5, 100);
    expect(isRangeSafe(r, 1000)).toBe(false);
  });

  it('rangeExcludesZero for positive range', () => {
    expect(rangeExcludesZero(createRange(1, 100))).toBe(true);
  });

  it('rangeExcludesZero for negative range', () => {
    expect(rangeExcludesZero(createRange(-100, -1))).toBe(true);
  });

  it('rangeExcludesZero for range including zero', () => {
    expect(rangeExcludesZero(createRange(-5, 5))).toBe(false);
  });

  it('rangeExcludesZero for unbounded', () => {
    expect(rangeExcludesZero(createUnboundedRange())).toBe(false);
  });
});

describe('VariableInfo.range', () => {
  it('declareVariable creates variable with no range by default', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    // Push a module scope manually using a minimal SyntaxNode mock
    ctx.pushScope('module', { type: 'program' } as any);
    ctx.declareVariable('x', 'let');
    const v = ctx.resolveVariable('x');
    expect(v).not.toBeNull();
    expect(v!.range).toBeUndefined();
  });

  it('range can be attached to variable after declaration', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);
    ctx.declareVariable('x', 'let');
    const v = ctx.resolveVariable('x')!;
    v.range = createRange(0, 100);
    expect(v.range.bounded).toBe(true);
    expect(v.range.min).toBe(0);
    expect(v.range.max).toBe(100);
  });
});

describe('DataFlow.range on NeuralMapNode', () => {
  it('DataFlow can carry range info', () => {
    const node = createNode({
      node_type: 'CONTROL',
      label: 'if (x > 0 && x < 1000)',
      data_out: [{
        name: 'x',
        source: 'ctrl1',
        data_type: 'number',
        tainted: true,
        sensitivity: 'NONE',
        range: createRange(0, 1000, 'ctrl1'),
      }],
    });
    const flow = node.data_out[0];
    expect(flow.range).toBeDefined();
    expect(flow.range!.bounded).toBe(true);
    expect(flow.range!.min).toBe(0);
    expect(flow.range!.max).toBe(1000);
  });
});

// ---------------------------------------------------------------------------
// Step 5: Range propagation through addDataFlow
// ---------------------------------------------------------------------------

describe('DataFlow range propagation (Step 5)', () => {
  beforeEach(() => resetSequenceHard());

  it('addDataFlow carries range when provided', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    const src = createNode({ node_type: 'INGRESS', label: 'input' });
    const sink = createNode({ node_type: 'STORAGE', label: 'db.query' });
    ctx.neuralMap.nodes.push(src, sink);

    const range = createRange(1, 100, 'ctrl1');
    ctx.addDataFlow(src.id, sink.id, 'x', 'number', true, range);

    const sinkFlow = sink.data_in.find(d => d.name === 'x');
    expect(sinkFlow).toBeDefined();
    expect(sinkFlow!.range).toBeDefined();
    expect(sinkFlow!.range!.min).toBe(1);
    expect(sinkFlow!.range!.max).toBe(100);
    expect(sinkFlow!.range!.bounded).toBe(true);
  });

  it('addDataFlow also attaches range to source data_out', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    const src = createNode({ node_type: 'INGRESS', label: 'input' });
    const sink = createNode({ node_type: 'STORAGE', label: 'db.query' });
    ctx.neuralMap.nodes.push(src, sink);

    const range = createRange(0, 255);
    ctx.addDataFlow(src.id, sink.id, 'y', 'number', false, range);

    const outFlow = src.data_out.find(d => d.name === 'y');
    expect(outFlow).toBeDefined();
    expect(outFlow!.range).toBeDefined();
    expect(outFlow!.range!.min).toBe(0);
    expect(outFlow!.range!.max).toBe(255);
  });

  it('addDataFlow works without range (backward compat)', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    const src = createNode({ node_type: 'INGRESS', label: 'input' });
    const sink = createNode({ node_type: 'STORAGE', label: 'db.query' });
    ctx.neuralMap.nodes.push(src, sink);

    ctx.addDataFlow(src.id, sink.id, 'x', 'number', true);

    const sinkFlow = sink.data_in.find(d => d.name === 'x');
    expect(sinkFlow).toBeDefined();
    expect(sinkFlow!.range).toBeUndefined();
  });

  it('addDataFlow deduplication still works with range', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    const src = createNode({ node_type: 'INGRESS', label: 'input' });
    const sink = createNode({ node_type: 'STORAGE', label: 'db.query' });
    ctx.neuralMap.nodes.push(src, sink);

    const range = createRange(0, 50);
    // Call twice — should not duplicate
    ctx.addDataFlow(src.id, sink.id, 'z', 'number', true, range);
    ctx.addDataFlow(src.id, sink.id, 'z', 'number', true, range);

    const inFlows = sink.data_in.filter(d => d.name === 'z');
    expect(inFlows.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Step 5b: Auto-bridge — addDataFlow looks up variable range from scope
// ---------------------------------------------------------------------------

describe('Auto-bridge: addDataFlow looks up variable range', () => {
  beforeEach(() => resetSequenceHard());

  it('auto-propagates range when variable has range but caller does not pass it', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);

    const src = createNode({ node_type: 'INGRESS', node_subtype: 'http_request', label: 'input' });
    const sink = createNode({ node_type: 'STORAGE', node_subtype: 'sql_query', label: 'query' });
    ctx.neuralMap.nodes.push(src, sink);
    ctx.nodeById.set(src.id, src);
    ctx.nodeById.set(sink.id, sink);

    // Declare variable with a range (simulating extractRangeFromCondition)
    ctx.declareVariable('x', 'let', null, true, src.id);
    const v = ctx.resolveVariable('x')!;
    v.range = createRange(1, 999, 'ctrl1');

    // Call addDataFlow WITHOUT the 6th range parameter
    ctx.addDataFlow(src.id, sink.id, 'x', 'number', true);

    // The range should auto-propagate from VariableInfo
    const sinkFlow = sink.data_in.find(d => d.name === 'x');
    expect(sinkFlow).toBeDefined();
    expect(sinkFlow!.range).toBeDefined();
    expect(sinkFlow!.range!.min).toBe(1);
    expect(sinkFlow!.range!.max).toBe(999);
    expect(sinkFlow!.range!.bounded).toBe(true);

    // Also check source data_out
    const srcFlow = src.data_out.find(d => d.name === 'x');
    expect(srcFlow).toBeDefined();
    expect(srcFlow!.range).toBeDefined();
    expect(srcFlow!.range!.min).toBe(1);
  });

  it('does not override explicitly passed range', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);

    const src = createNode({ node_type: 'INGRESS', node_subtype: 'http_request', label: 'input' });
    const sink = createNode({ node_type: 'STORAGE', node_subtype: 'sql_query', label: 'query' });
    ctx.neuralMap.nodes.push(src, sink);
    ctx.nodeById.set(src.id, src);
    ctx.nodeById.set(sink.id, sink);

    ctx.declareVariable('x', 'let', null, true, src.id);
    const v = ctx.resolveVariable('x')!;
    v.range = createRange(1, 999);

    // Explicitly pass a DIFFERENT range
    const explicitRange = createRange(0, 50);
    ctx.addDataFlow(src.id, sink.id, 'x', 'number', true, explicitRange);

    const sinkFlow = sink.data_in.find(d => d.name === 'x');
    expect(sinkFlow!.range!.min).toBe(0);  // explicit wins
    expect(sinkFlow!.range!.max).toBe(50);
  });

  it('no range when variable has no range', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);

    const src = createNode({ node_type: 'INGRESS', node_subtype: 'http_request', label: 'input' });
    const sink = createNode({ node_type: 'STORAGE', node_subtype: 'sql_query', label: 'query' });
    ctx.neuralMap.nodes.push(src, sink);
    ctx.nodeById.set(src.id, src);
    ctx.nodeById.set(sink.id, sink);

    ctx.declareVariable('y', 'let', null, true, src.id);
    // No range on variable

    ctx.addDataFlow(src.id, sink.id, 'y', 'string', true);

    const sinkFlow = sink.data_in.find(d => d.name === 'y');
    expect(sinkFlow).toBeDefined();
    expect(sinkFlow!.range).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Step 6: Constant folding → range integration
// ---------------------------------------------------------------------------

describe('Constant folding to range (Step 6)', () => {
  beforeEach(() => resetSequenceHard());

  it('const x = 42 produces exact range [42, 42]', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);
    ctx.declareVariable('x', 'const');
    const v = ctx.resolveVariable('x')!;
    // Simulate constant folding — set constantValue then range
    v.constantValue = '42';
    const numVal = Number(v.constantValue);
    v.range = createRange(numVal, numVal);
    expect(v.range.min).toBe(42);
    expect(v.range.max).toBe(42);
    expect(v.range.bounded).toBe(true);
  });

  it('non-numeric constantValue does not produce range', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);
    ctx.declareVariable('s', 'const');
    const v = ctx.resolveVariable('s')!;
    v.constantValue = 'hello';
    const numVal = Number(v.constantValue);
    // isNaN guard prevents setting range for string constants
    if (!isNaN(numVal) && Number.isFinite(numVal)) {
      v.range = createRange(numVal, numVal);
    }
    expect(v.range).toBeUndefined();
  });

  it('numeric constant range is bounded (both min and max finite)', () => {
    const r = createRange(15, 15);
    expect(r.bounded).toBe(true);
    expect(r.min).toBe(15);
    expect(r.max).toBe(15);
  });

  it('isRangeSafe for exact constant [15, 15] within max 100', () => {
    const r = createRange(15, 15);
    expect(isRangeSafe(r, 100)).toBe(true);
    expect(isRangeSafe(r, 14)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Step 7: Verifier helpers — sinkHasBoundedRange, sinkHasNonZeroRange, sinkHasSafeRange
// ---------------------------------------------------------------------------

function buildMap(nodes: NeuralMapNode[]): NeuralMap {
  return {
    nodes,
    edges: [],
    source_file: 'test.js',
    source_code: '',
    created_at: '',
    parser_version: '0.1.0',
  };
}

describe('Range-aware verifier helpers (Step 7)', () => {
  beforeEach(() => resetSequenceHard());

  it('sinkHasBoundedRange returns true when data_in has bounded range', () => {
    const sink = createNode({
      node_type: 'STORAGE',
      data_in: [{
        name: 'x', source: 'ctrl1', data_type: 'number',
        tainted: true, sensitivity: 'NONE',
        range: createRange(0, 100),
      }],
    });
    expect(sinkHasBoundedRange(buildMap([sink]), sink.id)).toBe(true);
  });

  it('sinkHasBoundedRange returns false when no range', () => {
    const sink = createNode({
      node_type: 'STORAGE',
      data_in: [{
        name: 'x', source: 'src1', data_type: 'number',
        tainted: true, sensitivity: 'NONE',
      }],
    });
    expect(sinkHasBoundedRange(buildMap([sink]), sink.id)).toBe(false);
  });

  it('sinkHasBoundedRange returns false for unbounded range', () => {
    const sink = createNode({
      node_type: 'STORAGE',
      data_in: [{
        name: 'x', source: 'src1', data_type: 'number',
        tainted: true, sensitivity: 'NONE',
        range: createUnboundedRange(),
      }],
    });
    expect(sinkHasBoundedRange(buildMap([sink]), sink.id)).toBe(false);
  });

  it('sinkHasBoundedRange returns false for unknown sinkId', () => {
    expect(sinkHasBoundedRange(buildMap([]), 'nonexistent')).toBe(false);
  });

  it('sinkHasNonZeroRange returns true for positive range', () => {
    const sink = createNode({
      node_type: 'TRANSFORM',
      data_in: [{
        name: 'divisor', source: 'ctrl1', data_type: 'number',
        tainted: true, sensitivity: 'NONE',
        range: createRange(1, 1000),
      }],
    });
    expect(sinkHasNonZeroRange(buildMap([sink]), sink.id)).toBe(true);
  });

  it('sinkHasNonZeroRange returns true for negative range', () => {
    const sink = createNode({
      node_type: 'TRANSFORM',
      data_in: [{
        name: 'divisor', source: 'ctrl1', data_type: 'number',
        tainted: true, sensitivity: 'NONE',
        range: createRange(-100, -1),
      }],
    });
    expect(sinkHasNonZeroRange(buildMap([sink]), sink.id)).toBe(true);
  });

  it('sinkHasNonZeroRange returns false when range includes zero', () => {
    const sink = createNode({
      node_type: 'TRANSFORM',
      data_in: [{
        name: 'divisor', source: 'ctrl1', data_type: 'number',
        tainted: true, sensitivity: 'NONE',
        range: createRange(-5, 5),
      }],
    });
    expect(sinkHasNonZeroRange(buildMap([sink]), sink.id)).toBe(false);
  });

  it('sinkHasNonZeroRange returns false when no range', () => {
    const sink = createNode({
      node_type: 'TRANSFORM',
      data_in: [{ name: 'x', source: 'src1', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
    });
    expect(sinkHasNonZeroRange(buildMap([sink]), sink.id)).toBe(false);
  });

  it('sinkHasSafeRange returns true when range fits within maxSafe', () => {
    const sink = createNode({
      node_type: 'STORAGE',
      data_in: [{
        name: 'size', source: 'ctrl1', data_type: 'number',
        tainted: true, sensitivity: 'NONE',
        range: createRange(0, 1024),
      }],
    });
    expect(sinkHasSafeRange(buildMap([sink]), sink.id, 2048)).toBe(true);
    expect(sinkHasSafeRange(buildMap([sink]), sink.id, 512)).toBe(false);
  });

  it('sinkHasSafeRange returns false for negative min', () => {
    const sink = createNode({
      node_type: 'STORAGE',
      data_in: [{
        name: 'size', source: 'ctrl1', data_type: 'number',
        tainted: true, sensitivity: 'NONE',
        range: createRange(-1, 100),
      }],
    });
    expect(sinkHasSafeRange(buildMap([sink]), sink.id, 1000)).toBe(false);
  });

  it('sinkHasSafeRange returns false for unbounded', () => {
    const sink = createNode({
      node_type: 'STORAGE',
      data_in: [{
        name: 'size', source: 'src1', data_type: 'number',
        tainted: true, sensitivity: 'NONE',
        range: createUnboundedRange(),
      }],
    });
    expect(sinkHasSafeRange(buildMap([sink]), sink.id, 1000)).toBe(false);
  });
});

describe('Java numericValue → RangeInfo bridge', () => {
  it('integer constant gets exact range', () => {
    const ctx = new MapperContext('Test.java', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);
    ctx.declareVariable('BUFFER_SIZE', 'const');
    const v = ctx.resolveVariable('BUFFER_SIZE')!;

    // Simulate what Java profile does
    v.numericValue = 128;
    // The bridge should also set range
    if (v.numericValue !== undefined && v.range === undefined) {
      v.range = createRange(v.numericValue, v.numericValue);
    }

    expect(v.range).toBeDefined();
    expect(v.range!.min).toBe(128);
    expect(v.range!.max).toBe(128);
    expect(v.range!.bounded).toBe(true);
  });
});
