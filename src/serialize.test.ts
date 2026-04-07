import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { resetSequence, resetSequenceHard } from './types.js';
import { serializeNeuralMap, compareNeuralMaps } from './serialize.js';

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

// Same fixture as integration.test.ts
const EXPRESS_APP = `
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');
const app = express();
app.use(express.json());

// GET /users/:id -- read user (potential injection)
app.get('/users/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const user = await db.findOne({ _id: id });
    if (!user) {
      return res.status(404).json({ error: 'Not found' });
    }
    res.json(user);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /users -- create user (sanitized)
app.post('/users', async (req, res) => {
  const { username, email, password } = req.body;
  const cleanName = escape(username);
  const cleanEmail = escape(email);
  const hash = await bcrypt.hash(password, 10);

  const user = await db.insert({
    username: cleanName,
    email: cleanEmail,
    password: hash,
  });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.status(201).json({ user: { id: user._id, username: cleanName }, token });
});

// POST /login -- authenticate
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.findOne({ username });

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});
`.trim();

const GOLDEN_PATH = path.resolve(__dirname, '__fixtures__/golden-reference-neuralmap.json');

function parseFixture() {
  const tree = parser.parse(EXPRESS_APP);
  const { map } = buildNeuralMap(tree, EXPRESS_APP, 'routes/api.js');
  tree.delete();
  return map;
}

describe('Step 22: Serialization', () => {
  it('produces valid JSON output', () => {
    const map = parseFixture();
    const json = serializeNeuralMap(map);
    expect(() => JSON.parse(json)).not.toThrow();
    const parsed = JSON.parse(json);
    expect(parsed.source_file).toBe('routes/api.js');
    expect(parsed.node_count).toBeGreaterThan(0);
    expect(parsed.nodes).toBeInstanceOf(Array);
    expect(parsed.edges).toBeInstanceOf(Array);
  });

  it('serialization is deterministic: two parses produce identical JSON', () => {
    resetSequenceHard();
    const map1 = parseFixture();
    const json1 = serializeNeuralMap(map1);

    resetSequenceHard();
    const map2 = parseFixture();
    const json2 = serializeNeuralMap(map2);

    expect(json1).toBe(json2);
  });

  it('serialization is deterministic across 5 consecutive runs', () => {
    const results: string[] = [];
    for (let i = 0; i < 5; i++) {
      resetSequenceHard();
      const map = parseFixture();
      results.push(serializeNeuralMap(map));
    }
    for (let i = 1; i < results.length; i++) {
      expect(results[i]).toBe(results[0]);
    }
  });

  it('nodes are sorted by sequence in output', () => {
    const map = parseFixture();
    const json = serializeNeuralMap(map);
    const parsed = JSON.parse(json);
    for (let i = 1; i < parsed.nodes.length; i++) {
      expect(parsed.nodes[i].sequence).toBeGreaterThan(parsed.nodes[i - 1].sequence);
    }
  });

  it('edges are sorted by type then target in output', () => {
    const map = parseFixture();
    const json = serializeNeuralMap(map);
    const parsed = JSON.parse(json);
    for (let i = 1; i < parsed.edges.length; i++) {
      const prev = parsed.edges[i - 1];
      const curr = parsed.edges[i];
      const cmp = prev.edge_type.localeCompare(curr.edge_type);
      if (cmp === 0) {
        expect(prev.target.localeCompare(curr.target)).toBeLessThanOrEqual(0);
      } else {
        expect(cmp).toBeLessThan(0);
      }
    }
  });
});

describe('Step 22: compareNeuralMaps', () => {
  it('identical maps compare as matching', () => {
    resetSequence();
    const map1 = parseFixture();
    resetSequence();
    const map2 = parseFixture();
    const result = compareNeuralMaps(map1, map2);
    expect(result.match).toBe(true);
    expect(result.differences).toHaveLength(0);
  });

  it('detects node count difference', () => {
    resetSequence();
    const map1 = parseFixture();
    resetSequence();
    const map2 = parseFixture();
    // Artificially remove a node
    map2.nodes.pop();
    const result = compareNeuralMaps(map1, map2);
    expect(result.match).toBe(false);
    expect(result.differences.some(d => d.includes('Node count'))).toBe(true);
  });

  it('detects edge type distribution difference', () => {
    resetSequence();
    const map1 = parseFixture();
    resetSequence();
    const map2 = parseFixture();
    // Artificially add an edge
    map2.edges.push({
      target: 'fake_node',
      edge_type: 'CALLS',
      conditional: false,
      async: false,
    });
    const result = compareNeuralMaps(map1, map2);
    expect(result.match).toBe(false);
  });
});

describe('Step 22: Golden reference', () => {
  it('generates and saves golden reference on first run, then regresses against it', () => {
    resetSequence();
    const map = parseFixture();
    const currentJson = serializeNeuralMap(map);

    const fixturesDir = path.dirname(GOLDEN_PATH);
    if (!fs.existsSync(fixturesDir)) {
      fs.mkdirSync(fixturesDir, { recursive: true });
    }

    if (!fs.existsSync(GOLDEN_PATH)) {
      // First run: save the golden reference
      fs.writeFileSync(GOLDEN_PATH, currentJson, 'utf-8');
      console.log(`Golden reference saved to ${GOLDEN_PATH}`);
      console.log(`Nodes: ${map.nodes.length}, Edges: ${map.edges.length}`);
      // Pass the test -- we just created the reference
      expect(currentJson).toBeTruthy();
    } else {
      // Subsequent runs: compare against golden reference
      const goldenJson = fs.readFileSync(GOLDEN_PATH, 'utf-8');
      if (currentJson !== goldenJson) {
        // Parse both for a better diff message
        const golden = JSON.parse(goldenJson);
        const current = JSON.parse(currentJson);
        const nodeDiff = current.node_count - golden.node_count;
        const edgeDiff = current.edge_count - golden.edge_count;
        expect.fail(
          `Golden reference mismatch.\n` +
          `  Nodes: ${golden.node_count} -> ${current.node_count} (${nodeDiff >= 0 ? '+' : ''}${nodeDiff})\n` +
          `  Edges: ${golden.edge_count} -> ${current.edge_count} (${edgeDiff >= 0 ? '+' : ''}${edgeDiff})\n` +
          `  To update golden reference, delete ${GOLDEN_PATH} and re-run.`
        );
      }
      expect(currentJson).toBe(goldenJson);
    }
  });
});
