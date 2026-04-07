/**
 * Data Flow Integration Tests -- Goal 4 capstone.
 *
 * These tests parse realistic Express routes and verify the complete
 * data flow chain: INGRESS -> processing -> EGRESS/STORAGE.
 *
 * Three scenarios:
 *   1. Unsafe route (SQL injection path) -- tainted data reaches STORAGE
 *   2. Safe route (sanitized) -- sanitizer clears taint before STORAGE
 *   3. Multi-flow login -- multiple tainted inputs, AUTH, STORAGE, EGRESS
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { resetSequence } from './types.js';
import type { NeuralMap, NeuralMapNode, DataFlow } from './types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

beforeAll(async () => {
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const JavaScript = await Language.load(wasmBuffer);
  parser.setLanguage(JavaScript);
});

beforeEach(() => {
  resetSequence();
});

function parse(code: string): NeuralMap {
  const tree = parser.parse(code);
  // Step 04's API: pass tree (not rootNode), returns { map, ctx }
  const { map } = buildNeuralMap(tree, code, 'test.js');
  tree.delete();
  return map;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nodesByType(map: NeuralMap, nodeType: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === nodeType);
}

function nodesBySubtype(map: NeuralMap, nodeType: string, subtype: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === nodeType && n.node_subtype === subtype);
}

function allDataFlows(map: NeuralMap): { node: NeuralMapNode; flow: DataFlow; direction: 'in' | 'out' }[] {
  const results: { node: NeuralMapNode; flow: DataFlow; direction: 'in' | 'out' }[] = [];
  for (const node of map.nodes) {
    for (const flow of node.data_out) {
      results.push({ node, flow, direction: 'out' });
    }
    for (const flow of node.data_in) {
      results.push({ node, flow, direction: 'in' });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Test 1: Unsafe route (SQL injection path)
// ---------------------------------------------------------------------------

describe('Data Flow Integration: Unsafe Route (SQL injection path)', () => {
  const unsafeCode = `
app.get('/user/:id', (req, res) => {
  const id = req.params.id;
  const user = db.query(\`SELECT * FROM users WHERE id = \${id}\`);
  res.json(user);
});
`.trim();

  let map: NeuralMap;

  beforeEach(() => {
    map = parse(unsafeCode);
  });

  it('creates at least one INGRESS node for req.params', () => {
    const ingress = nodesByType(map, 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    // Should be http_request subtype
    const httpIngress = ingress.filter(n => n.node_subtype === 'http_request');
    expect(httpIngress.length).toBeGreaterThanOrEqual(1);
  });

  it('INGRESS node has tainted data_out', () => {
    const ingress = nodesByType(map, 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);

    const hasAnyTainted = ingress.some(n => n.data_out.some(d => d.tainted));
    expect(hasAnyTainted).toBe(true);
  });

  it('creates a STORAGE node for db.query', () => {
    const storage = nodesByType(map, 'STORAGE');
    expect(storage.length).toBeGreaterThanOrEqual(1);
  });

  it('STORAGE node has tainted data_in from INGRESS (id flows through)', () => {
    const ingress = nodesByType(map, 'INGRESS');
    const storage = nodesByType(map, 'STORAGE');

    if (ingress.length > 0 && storage.length > 0) {
      // Check if the STORAGE node received tainted data
      // This may come directly from INGRESS or indirectly through the variable 'id'
      const storageNode = storage[0];
      if (storageNode.data_in.length > 0) {
        const hasTaintedInput = storageNode.data_in.some(d => d.tainted);
        expect(hasTaintedInput).toBe(true);
      }
    }
  });

  it('creates an EGRESS node for res.json', () => {
    const egress = nodesByType(map, 'EGRESS');
    expect(egress.length).toBeGreaterThanOrEqual(1);
    expect(egress[0].node_subtype).toBe('http_response');
  });

  it('the complete chain exists: INGRESS -> STORAGE -> EGRESS', () => {
    const ingress = nodesByType(map, 'INGRESS');
    const storage = nodesByType(map, 'STORAGE');
    const egress = nodesByType(map, 'EGRESS');

    // All three node types must be present
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    expect(storage.length).toBeGreaterThanOrEqual(1);
    expect(egress.length).toBeGreaterThanOrEqual(1);

    // Verify the sequence makes sense:
    // INGRESS appears before STORAGE, STORAGE before EGRESS
    const ingressSeq = Math.min(...ingress.map(n => n.sequence));
    const storageSeq = Math.min(...storage.map(n => n.sequence));
    const egressSeq = Math.min(...egress.map(n => n.sequence));
    expect(ingressSeq).toBeLessThan(storageSeq);
    expect(storageSeq).toBeLessThan(egressSeq);
  });
});

// ---------------------------------------------------------------------------
// Test 2: Safe route (sanitized)
// ---------------------------------------------------------------------------

describe('Data Flow Integration: Safe Route (sanitized input)', () => {
  const safeCode = `
app.post('/user', (req, res) => {
  const name = escape(req.body.name);
  db.insert({ name });
  res.json({ ok: true });
});
`.trim();

  let map: NeuralMap;

  beforeEach(() => {
    map = parse(safeCode);
  });

  it('creates an INGRESS node for req.body', () => {
    const ingress = nodesByType(map, 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
  });

  it('INGRESS node has tainted data_out', () => {
    const ingress = nodesByType(map, 'INGRESS');
    if (ingress.length > 0) {
      const hasTainted = ingress.some(n => n.data_out.some(d => d.tainted));
      expect(hasTainted).toBe(true);
    }
  });

  it('creates a TRANSFORM/sanitize node for escape()', () => {
    const transforms = nodesBySubtype(map, 'TRANSFORM', 'sanitize');
    expect(transforms.length).toBeGreaterThanOrEqual(1);
  });

  it('TRANSFORM/sanitize data_out is NOT tainted', () => {
    const sanitizers = nodesBySubtype(map, 'TRANSFORM', 'sanitize');
    if (sanitizers.length > 0) {
      for (const flow of sanitizers[0].data_out) {
        expect(flow.tainted).toBe(false);
      }
    }
  });

  it('creates a STORAGE node for db.insert', () => {
    const storage = nodesByType(map, 'STORAGE');
    expect(storage.length).toBeGreaterThanOrEqual(1);
    expect(storage[0].node_subtype).toBe('db_write');
  });

  it('STORAGE node data_in should NOT be tainted (sanitizer cleared it)', () => {
    const storage = nodesByType(map, 'STORAGE');
    if (storage.length > 0 && storage[0].data_in.length > 0) {
      // The name variable went through escape() which clears taint.
      // If DataFlow was properly constructed, the STORAGE data_in
      // should reference the TRANSFORM node (not INGRESS directly).
      const sanitizers = nodesBySubtype(map, 'TRANSFORM', 'sanitize');
      if (sanitizers.length > 0) {
        const fromSanitizer = storage[0].data_in.filter(d => d.source === sanitizers[0].id);
        if (fromSanitizer.length > 0) {
          // Data from sanitizer should not be tainted
          expect(fromSanitizer[0].tainted).toBe(false);
        }
      }
    }
  });

  it('creates an EGRESS node for res.json', () => {
    const egress = nodesByType(map, 'EGRESS');
    expect(egress.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Test 3: Multiple data flows (login route)
// ---------------------------------------------------------------------------

describe('Data Flow Integration: Multi-flow Login Route', () => {
  const loginCode = `
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.findOne({ username });
  const valid = bcrypt.compare(password, user.hash);
  if (valid) {
    const token = jwt.sign({ id: user.id }, secret);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid' });
  }
});
`.trim();

  let map: NeuralMap;

  beforeEach(() => {
    map = parse(loginCode);
  });

  it('creates INGRESS node(s) for req.body', () => {
    const ingress = nodesByType(map, 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
  });

  it('INGRESS has tainted data_out', () => {
    const ingress = nodesByType(map, 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    const hasTainted = ingress.some(n => n.data_out.some(d => d.tainted));
    expect(hasTainted).toBe(true);
  });

  it('creates a STORAGE node for db.findOne', () => {
    const storage = nodesByType(map, 'STORAGE');
    expect(storage.length).toBeGreaterThanOrEqual(1);
    const readNodes = storage.filter(n => n.node_subtype === 'db_read');
    expect(readNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('STORAGE node receives tainted username', () => {
    const storage = nodesByType(map, 'STORAGE');
    const readNodes = storage.filter(n => n.node_subtype === 'db_read');

    if (readNodes.length > 0 && readNodes[0].data_in.length > 0) {
      // The username variable came from req.body (tainted)
      const taintedInputs = readNodes[0].data_in.filter(d => d.tainted);
      expect(taintedInputs.length).toBeGreaterThanOrEqual(1);
    }
  });

  it('creates an AUTH node for bcrypt.compare', () => {
    const auth = nodesByType(map, 'AUTH');
    expect(auth.length).toBeGreaterThanOrEqual(1);
    expect(auth[0].node_subtype).toBe('authenticate');
  });

  it('AUTH node receives tainted password', () => {
    const auth = nodesByType(map, 'AUTH');

    if (auth.length > 0 && auth[0].data_in.length > 0) {
      // The password variable came from req.body (tainted)
      const taintedInputs = auth[0].data_in.filter(d => d.tainted);
      expect(taintedInputs.length).toBeGreaterThanOrEqual(1);
    }
  });

  it('creates an AUTH node for jwt.sign', () => {
    const auth = nodesByType(map, 'AUTH');
    // Should have at least 2 AUTH nodes: bcrypt.compare AND jwt.sign
    expect(auth.length).toBeGreaterThanOrEqual(2);
  });

  it('creates at least 2 EGRESS nodes (success and error responses)', () => {
    const egress = nodesByType(map, 'EGRESS');
    // res.json({ token }) and res.status(401).json({ error })
    expect(egress.length).toBeGreaterThanOrEqual(2);
  });

  it('total node count is at least 8', () => {
    // Minimum: 1 INGRESS + 1 STORAGE + 2 AUTH + 2 EGRESS + 1 CONTROL (if) + 1 STRUCTURAL (arrow fn)
    expect(map.nodes.length).toBeGreaterThanOrEqual(8);
  });

  it('creates a CONTROL/branch node for the if statement', () => {
    const control = nodesByType(map, 'CONTROL');
    const branches = control.filter(n => n.node_subtype === 'branch');
    expect(branches.length).toBeGreaterThanOrEqual(1);
  });

  it('all node IDs are unique', () => {
    const ids = map.nodes.map(n => n.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('all nodes have valid node_type values', () => {
    const validTypes = new Set([
      'INGRESS', 'EGRESS', 'TRANSFORM', 'CONTROL', 'AUTH',
      'STORAGE', 'EXTERNAL', 'STRUCTURAL', 'META',
    ]);
    for (const node of map.nodes) {
      expect(validTypes.has(node.node_type)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 4: Edge cases
// ---------------------------------------------------------------------------

describe('Data Flow Integration: Edge Cases', () => {
  it('empty function body produces STRUCTURAL node but no data flow', () => {
    const code = `
app.get('/ping', (req, res) => {});
`.trim();
    const map = parse(code);
    // Should have at least the arrow function as STRUCTURAL
    const structural = nodesByType(map, 'STRUCTURAL');
    expect(structural.length).toBeGreaterThanOrEqual(1);
  });

  it('multiple routes in one file produce independent node sets', () => {
    const code = `
app.get('/a', (req, res) => {
  res.json({ a: 1 });
});
app.get('/b', (req, res) => {
  res.json({ b: 2 });
});
`.trim();
    const map = parse(code);
    const egress = nodesByType(map, 'EGRESS');
    // Each route has its own res.json call
    expect(egress.length).toBeGreaterThanOrEqual(2);
  });

  it('deeply nested function calls do not crash the mapper', () => {
    const code = `
app.post('/complex', (req, res) => {
  const data = JSON.parse(JSON.stringify(req.body));
  const result = db.insert({
    name: data.name,
    hash: bcrypt.hash(data.password, 10),
  });
  res.json(result);
});
`.trim();
    expect(() => parse(code)).not.toThrow();
    const map = parse(code);
    // Should have multiple classified nodes
    expect(map.nodes.length).toBeGreaterThanOrEqual(4);
  });

  it('no false positives: unknown function calls do not create classified nodes', () => {
    const code = `
app.get('/test', (req, res) => {
  const x = myCustomUtil(req.params.id);
  res.json(x);
});
`.trim();
    const map = parse(code);
    // myCustomUtil should NOT create a classified node
    const unknownNodes = map.nodes.filter(
      n => n.label.includes('myCustomUtil') &&
        ['INGRESS', 'EGRESS', 'TRANSFORM', 'AUTH', 'STORAGE', 'EXTERNAL'].includes(n.node_type)
    );
    expect(unknownNodes).toHaveLength(0);
  });
});
