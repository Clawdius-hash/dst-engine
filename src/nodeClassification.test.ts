import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { resetSequence, resetSequenceHard } from './types.js';
import type { NeuralMapNode, NodeType } from './types.js';

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

function parse(code: string) {
  const tree = parser.parse(code);
  // Step 04's API: pass tree (not rootNode), returns { map, ctx }
  const { map } = buildNeuralMap(tree, code, 'test-app.js');
  tree.delete();
  return map;
}

/**
 * Helper: count nodes by type
 */
function countByType(nodes: NeuralMapNode[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const n of nodes) {
    counts[n.node_type] = (counts[n.node_type] || 0) + 1;
  }
  return counts;
}

/**
 * Helper: find nodes by type and optional subtype
 */
function findNodes(nodes: NeuralMapNode[], type: NodeType, subtype?: string): NeuralMapNode[] {
  return nodes.filter(n =>
    n.node_type === type && (subtype === undefined || n.node_subtype === subtype)
  );
}

// ─────────────────────────────────────────────────────────────
// The main integration test: a realistic Express route handler
// that exercises all 9 node types.
// ─────────────────────────────────────────────────────────────

const EXPRESS_APP = `
const express = require('express');
const { exec } = require('child_process');
const db = require('./db');

const app = express();

app.post('/user', async (req, res) => {
  const { username, password } = req.body;
  const sanitized = escape(username);

  if (!sanitized) {
    return res.status(400).json({ error: 'Invalid' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const user = await db.insert({ username: sanitized, password: hash });
    res.json({ id: user.id });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Server error' });
  }
});
`.trim();

describe('Node Classification Integration Test', () => {
  describe('Express route handler — all 9 node types', () => {
    let map: ReturnType<typeof parse>;
    let counts: Record<string, number>;

    beforeEach(() => {
      map = parse(EXPRESS_APP);
      counts = countByType(map.nodes);
    });

    it('produces a non-empty neural map', () => {
      expect(map.nodes.length).toBeGreaterThan(0);
      expect(map.source_file).toBe('test-app.js');
      expect(map.source_code).toBe(EXPRESS_APP);
    });

    it('total node count is reasonable (not 0, not 1000)', () => {
      expect(map.nodes.length).toBeGreaterThan(5);
      expect(map.nodes.length).toBeLessThan(100);
    });

    it('has STRUCTURAL nodes (function, dependency)', () => {
      const structural = findNodes(map.nodes, 'STRUCTURAL');
      expect(structural.length).toBeGreaterThanOrEqual(1);
      // Should have at least the arrow function for the route handler
      const functions = findNodes(map.nodes, 'STRUCTURAL', 'function');
      expect(functions.length).toBeGreaterThanOrEqual(1);
    });

    it('has TRANSFORM nodes (escape call)', () => {
      const transforms = findNodes(map.nodes, 'TRANSFORM');
      expect(transforms.length).toBeGreaterThanOrEqual(1);
      // escape() is in DIRECT_CALLS with subtype 'sanitize'
      const sanitizeNodes = findNodes(map.nodes, 'TRANSFORM', 'sanitize');
      expect(sanitizeNodes.length).toBeGreaterThanOrEqual(1);
    });

    it('has AUTH nodes (bcrypt.hash)', () => {
      const auth = findNodes(map.nodes, 'AUTH');
      expect(auth.length).toBeGreaterThanOrEqual(1);
    });

    it('has STORAGE nodes (db.insert)', () => {
      const storage = findNodes(map.nodes, 'STORAGE');
      expect(storage.length).toBeGreaterThanOrEqual(1);
      // db.insert should be STORAGE/db_write
      const writes = findNodes(map.nodes, 'STORAGE', 'db_write');
      expect(writes.length).toBeGreaterThanOrEqual(1);
    });

    it('has EGRESS nodes (res.json, console.log)', () => {
      const egress = findNodes(map.nodes, 'EGRESS');
      expect(egress.length).toBeGreaterThanOrEqual(2);
      // res.json -> EGRESS/http_response
      const httpResp = findNodes(map.nodes, 'EGRESS', 'http_response');
      expect(httpResp.length).toBeGreaterThanOrEqual(1);
      // console.log -> EGRESS/display
      const display = findNodes(map.nodes, 'EGRESS', 'display');
      expect(display.length).toBeGreaterThanOrEqual(1);
    });

    it('has CONTROL nodes (if, try/catch)', () => {
      const control = findNodes(map.nodes, 'CONTROL');
      expect(control.length).toBeGreaterThanOrEqual(2);
      // if_statement -> CONTROL/branch
      const branches = findNodes(map.nodes, 'CONTROL', 'branch');
      expect(branches.length).toBeGreaterThanOrEqual(1);
      // try_statement -> CONTROL/error_handler
      const errorHandlers = findNodes(map.nodes, 'CONTROL', 'error_handler');
      expect(errorHandlers.length).toBeGreaterThanOrEqual(1);
    });

    it('every node has a valid id (non-empty string)', () => {
      for (const node of map.nodes) {
        expect(node.id).toBeTruthy();
        expect(typeof node.id).toBe('string');
        expect(node.id.length).toBeGreaterThan(0);
      }
    });

    it('every node has correct line numbers (>= 1)', () => {
      for (const node of map.nodes) {
        expect(node.line_start).toBeGreaterThanOrEqual(1);
        expect(node.line_end).toBeGreaterThanOrEqual(node.line_start);
      }
    });

    it('every node has a non-empty code_snapshot', () => {
      for (const node of map.nodes) {
        expect(node.code_snapshot).toBeTruthy();
        expect(node.code_snapshot.length).toBeGreaterThan(0);
        expect(node.code_snapshot.length).toBeLessThanOrEqual(200);
      }
    });

    it('every node has language set to javascript', () => {
      for (const node of map.nodes) {
        expect(node.language).toBe('javascript');
      }
    });

    it('every node has file set to test-app.js', () => {
      for (const node of map.nodes) {
        expect(node.file).toBe('test-app.js');
      }
    });

    it('all node IDs are unique', () => {
      const ids = map.nodes.map(n => n.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it('sequence numbers are monotonically increasing', () => {
      const sequences = map.nodes.map(n => n.sequence);
      for (let i = 1; i < sequences.length; i++) {
        expect(sequences[i]).toBeGreaterThan(sequences[i - 1]);
      }
    });
  });

  describe('Simple cases — verify correct classification', () => {
    it('empty code produces zero nodes', () => {
      const map = parse('');
      expect(map.nodes).toHaveLength(0);
    });

    it('comment-only code produces zero nodes', () => {
      const map = parse('// this is a comment\n/* block comment */');
      expect(map.nodes).toHaveLength(0);
    });

    it('single function declaration produces STRUCTURAL node for hello', () => {
      const map = parse('function hello() { return "world"; }');
      const helloNode = map.nodes.find(n => n.node_type === 'STRUCTURAL' && n.label === 'hello');
      expect(helloNode).toBeDefined();
      expect(helloNode!.node_subtype).toBe('function');
    });

    it('single if statement produces 1 CONTROL node', () => {
      const map = parse('if (true) { }');
      expect(map.nodes).toHaveLength(1);
      expect(map.nodes[0].node_type).toBe('CONTROL');
      expect(map.nodes[0].node_subtype).toBe('branch');
    });

    it('single fetch call produces 1 EXTERNAL node', () => {
      const map = parse("fetch('https://api.example.com')");
      const ext = findNodes(map.nodes, 'EXTERNAL');
      expect(ext).toHaveLength(1);
      expect(ext[0].node_subtype).toBe('api_call');
    });
  });

  describe('Security-relevant classification', () => {
    it('SQL injection vector: req.body → db.query', () => {
      const code = `
app.post('/search', (req, res) => {
  const term = req.body.search;
  db.query("SELECT * FROM items WHERE name = '" + term + "'");
});
`.trim();
      const map = parse(code);
      // Should have STORAGE node for db.query
      const storage = findNodes(map.nodes, 'STORAGE');
      expect(storage.length).toBeGreaterThanOrEqual(1);
    });

    it('command injection vector: req.query → exec', () => {
      const code = `
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping ' + host);
});
`.trim();
      const map = parse(code);
      const ext = findNodes(map.nodes, 'EXTERNAL', 'system_exec');
      expect(ext.length).toBeGreaterThanOrEqual(1);
      expect(ext[0].attack_surface).toContain('command_injection');
    });

    it('sensitive data in logs: console.log(password)', () => {
      const code = `
function login(password) {
  console.log(password);
}
`.trim();
      const map = parse(code);
      const display = findNodes(map.nodes, 'EGRESS', 'display');
      expect(display.length).toBeGreaterThanOrEqual(1);
    });

    it('auth flow: bcrypt.compare in route', () => {
      const code = `
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.findOne({ email });
  const match = await bcrypt.compare(password, user.hash);
  if (match) {
    res.json({ token: jwt.sign({ id: user.id }, secret) });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});
`.trim();
      const map = parse(code);
      // AUTH node from bcrypt.compare
      const auth = findNodes(map.nodes, 'AUTH');
      expect(auth.length).toBeGreaterThanOrEqual(1);
      // STORAGE node from db.findOne
      const storage = findNodes(map.nodes, 'STORAGE');
      expect(storage.length).toBeGreaterThanOrEqual(1);
      // EGRESS nodes from res.json
      const egress = findNodes(map.nodes, 'EGRESS');
      expect(egress.length).toBeGreaterThanOrEqual(1);
      // CONTROL from if statement
      const control = findNodes(map.nodes, 'CONTROL');
      expect(control.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Determinism — same input, same output', () => {
    it('produces identical results on two runs', () => {
      resetSequenceHard();
      const map1 = parse(EXPRESS_APP);
      resetSequenceHard();
      const map2 = parse(EXPRESS_APP);

      expect(map1.nodes.length).toBe(map2.nodes.length);
      for (let i = 0; i < map1.nodes.length; i++) {
        expect(map1.nodes[i].id).toBe(map2.nodes[i].id);
        expect(map1.nodes[i].node_type).toBe(map2.nodes[i].node_type);
        expect(map1.nodes[i].node_subtype).toBe(map2.nodes[i].node_subtype);
        expect(map1.nodes[i].label).toBe(map2.nodes[i].label);
        expect(map1.nodes[i].line_start).toBe(map2.nodes[i].line_start);
        expect(map1.nodes[i].sequence).toBe(map2.nodes[i].sequence);
      }
    });
  });
});
