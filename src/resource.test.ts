/**
 * RESOURCE Node Type Tests
 *
 * Tests the 10th node type: RESOURCE — finite shared capacity that multiple
 * data flows compete for. Covers:
 *   - Node classification via calleePatterns (phoneme database)
 *   - Full mapper integration (tree-sitter → NeuralMap → RESOURCE nodes)
 *   - CWE-400: Uncontrolled Resource Consumption
 *   - CWE-770: Allocation of Resources Without Limits or Throttling
 *   - CWE-1333: ReDoS (Inefficient Regular Expression Complexity)
 *   - CWE-404: Improper Resource Shutdown or Release
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { verify, verifyAll, registeredCWEs } from './verifier';
import { lookupCallee } from './calleePatterns.js';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { NeuralMap, NeuralMapNode, NodeType } from './types.js';

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parse(code: string) {
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, 'test-resource.js');
  tree.delete();
  return map;
}

function findNodes(nodes: NeuralMapNode[], type: NodeType, subtype?: string): NeuralMapNode[] {
  return nodes.filter(n =>
    n.node_type === type && (subtype === undefined || n.node_subtype === subtype)
  );
}

function buildMap(code: string, nodes: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap('test-resource.js', code);
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 1: Callee Pattern Classification
// ═══════════════════════════════════════════════════════════════════════════

describe('RESOURCE callee pattern classification', () => {
  it('RegExp direct call → RESOURCE/cpu', () => {
    const result = lookupCallee(['RegExp']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('cpu');
  });

  it('Buffer.alloc → RESOURCE/memory', () => {
    const result = lookupCallee(['Buffer', 'alloc']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('memory');
  });

  it('Buffer.allocUnsafe → RESOURCE/memory', () => {
    const result = lookupCallee(['Buffer', 'allocUnsafe']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('memory');
  });

  it('Buffer.from → RESOURCE/memory', () => {
    const result = lookupCallee(['Buffer', 'from']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('memory');
  });

  it('fs.open → RESOURCE/file_descriptors', () => {
    const result = lookupCallee(['fs', 'open']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('file_descriptors');
  });

  it('fs.openSync → RESOURCE/file_descriptors', () => {
    const result = lookupCallee(['fs', 'openSync']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('file_descriptors');
  });

  it('net.createServer → RESOURCE/connections', () => {
    const result = lookupCallee(['net', 'createServer']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('connections');
  });

  it('net.createConnection → RESOURCE/connections', () => {
    const result = lookupCallee(['net', 'createConnection']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('connections');
  });

  it('zlib.inflate → RESOURCE/memory (zip bomb vector)', () => {
    const result = lookupCallee(['zlib', 'inflate']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('memory');
  });

  it('zlib.gunzip → RESOURCE/memory', () => {
    const result = lookupCallee(['zlib', 'gunzip']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('memory');
  });

  it('crypto.pbkdf2Sync → RESOURCE/cpu', () => {
    const result = lookupCallee(['crypto', 'pbkdf2Sync']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('cpu');
  });

  it('crypto.scryptSync → RESOURCE/cpu', () => {
    const result = lookupCallee(['crypto', 'scryptSync']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('cpu');
  });

  it('pool.getConnection → RESOURCE/connections', () => {
    const result = lookupCallee(['pool', 'getConnection']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('connections');
  });

  it('pool.acquire → RESOURCE/connections', () => {
    const result = lookupCallee(['pool', 'acquire']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('connections');
  });

  it('cluster.fork → RESOURCE/threads', () => {
    const result = lookupCallee(['cluster', 'fork']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('threads');
  });

  it('http.createServer → RESOURCE/connections', () => {
    const result = lookupCallee(['http', 'createServer']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('connections');
  });

  // Wildcard connection method resolution
  it('wildcard: any.getConnection → RESOURCE/connections', () => {
    const result = lookupCallee(['mysql', 'getConnection']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('connections');
  });

  it('wildcard: any.acquire → RESOURCE/connections', () => {
    const result = lookupCallee(['pg', 'acquire']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('connections');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 2: Mapper Integration (tree-sitter → RESOURCE nodes)
// ═══════════════════════════════════════════════════════════════════════════

describe('RESOURCE mapper integration', () => {
  it('new RegExp(userInput) creates a RESOURCE/cpu node', () => {
    const code = `
      const express = require('express');
      const app = express();
      app.get('/search', (req, res) => {
        const pattern = req.query.pattern;
        const regex = new RegExp(pattern);
        const results = data.filter(d => regex.test(d));
        res.json(results);
      });
    `;
    const map = parse(code);
    const resources = findNodes(map.nodes, 'RESOURCE', 'cpu');
    expect(resources.length).toBeGreaterThanOrEqual(1);
    // Verify it's the RegExp call
    const regexpNode = resources.find(n => /RegExp/.test(n.code_snapshot));
    expect(regexpNode).toBeDefined();
  });

  it('Buffer.alloc(userSize) creates a RESOURCE/memory node', () => {
    const code = `
      const express = require('express');
      const app = express();
      app.post('/upload', (req, res) => {
        const size = req.body.size;
        const buf = Buffer.alloc(size);
        res.send(buf);
      });
    `;
    const map = parse(code);
    const resources = findNodes(map.nodes, 'RESOURCE', 'memory');
    expect(resources.length).toBeGreaterThanOrEqual(1);
    const bufNode = resources.find(n => /Buffer\.alloc/.test(n.code_snapshot));
    expect(bufNode).toBeDefined();
  });

  it('fs.open creates a RESOURCE/file_descriptors node', () => {
    const code = `
      const fs = require('fs');
      const express = require('express');
      const app = express();
      app.get('/read', (req, res) => {
        const fd = fs.open(req.query.path, 'r', (err, fd) => {
          res.send('opened');
        });
      });
    `;
    const map = parse(code);
    const resources = findNodes(map.nodes, 'RESOURCE', 'file_descriptors');
    expect(resources.length).toBeGreaterThanOrEqual(1);
  });

  it('zlib.inflate creates a RESOURCE/memory node', () => {
    const code = `
      const zlib = require('zlib');
      const express = require('express');
      const app = express();
      app.post('/decompress', (req, res) => {
        zlib.inflate(req.body.data, (err, result) => {
          res.send(result);
        });
      });
    `;
    const map = parse(code);
    const resources = findNodes(map.nodes, 'RESOURCE', 'memory');
    expect(resources.length).toBeGreaterThanOrEqual(1);
  });

  it('pool.getConnection creates a RESOURCE/connections node', () => {
    const code = `
      const pool = require('./db');
      const express = require('express');
      const app = express();
      app.get('/data', (req, res) => {
        pool.getConnection((err, conn) => {
          conn.query('SELECT * FROM users', (err, rows) => {
            res.json(rows);
          });
        });
      });
    `;
    const map = parse(code);
    const resources = findNodes(map.nodes, 'RESOURCE', 'connections');
    expect(resources.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 3: CWE-400 — Uncontrolled Resource Consumption
// ═══════════════════════════════════════════════════════════════════════════

describe('CWE-400: Uncontrolled Resource Consumption', () => {
  it('is registered in the CWE registry', () => {
    const cwes = registeredCWEs();
    expect(cwes).toContain('CWE-400');
  });

  it('VULNERABLE: user input → Buffer.alloc without size limit', () => {
    const map = buildMap(
      'app.post("/upload", (req, res) => { const buf = Buffer.alloc(req.body.size); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.size',
          node_subtype: 'http_request',
          code_snapshot: 'req.body.size',
          attack_surface: ['user_input'],
          data_out: [{ name: 'size', source: 'EXTERNAL', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'RESOURCE',
          label: 'Buffer.alloc(req.body.size)',
          node_subtype: 'memory',
          code_snapshot: 'Buffer.alloc(req.body.size)',
          attack_surface: [],
          data_in: [{ name: 'size', source: 'SRC', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-400');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].missing).toContain('CONTROL');
  });

  it('SAFE: user input → Buffer.alloc with size limit (CONTROL node)', () => {
    const map = buildMap(
      'app.post("/upload", (req, res) => { if (req.body.size > MAX_SIZE) return; const buf = Buffer.alloc(req.body.size); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.size',
          node_subtype: 'http_request',
          code_snapshot: 'req.body.size',
          attack_surface: ['user_input'],
          data_out: [{ name: 'size', source: 'EXTERNAL', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'CTRL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CTRL', node_type: 'CONTROL',
          label: 'size check',
          node_subtype: 'validation',
          code_snapshot: 'if (req.body.size > MAX_SIZE) return;',
          attack_surface: [],
          data_in: [{ name: 'size', source: 'SRC', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: true, async: false }],
        },
        {
          id: 'SINK', node_type: 'RESOURCE',
          label: 'Buffer.alloc(req.body.size)',
          node_subtype: 'memory',
          code_snapshot: 'Buffer.alloc(req.body.size)',
          attack_surface: [],
          data_in: [{ name: 'size', source: 'CTRL', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-400');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: user input → crypto.pbkdf2Sync with user-controlled iterations', () => {
    const map = buildMap(
      'app.post("/hash", (req, res) => { crypto.pbkdf2Sync(req.body.pass, salt, req.body.iterations, 64, "sha512"); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.iterations',
          node_subtype: 'http_request',
          code_snapshot: 'req.body.iterations',
          attack_surface: ['user_input'],
          data_out: [{ name: 'iterations', source: 'EXTERNAL', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'RESOURCE',
          label: 'crypto.pbkdf2Sync',
          node_subtype: 'cpu',
          code_snapshot: 'crypto.pbkdf2Sync(req.body.pass, salt, req.body.iterations, 64, "sha512")',
          attack_surface: [],
          data_in: [{ name: 'iterations', source: 'SRC', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-400');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high'); // cpu resources are high severity
  });

  it('SAFE: bounded allocation passes (no false positive)', () => {
    const map = buildMap(
      'const buf = Buffer.alloc(1024);', // hardcoded, no user input
      [
        {
          id: 'ALLOC', node_type: 'RESOURCE',
          label: 'Buffer.alloc(1024)',
          node_subtype: 'memory',
          code_snapshot: 'Buffer.alloc(1024)',
          attack_surface: [],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-400');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: user input → zlib.inflate (zip bomb)', () => {
    const map = buildMap(
      'app.post("/decompress", (req, res) => { zlib.inflate(req.body.data, cb); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.data',
          node_subtype: 'http_request',
          code_snapshot: 'req.body.data',
          attack_surface: ['user_input'],
          data_out: [{ name: 'data', source: 'EXTERNAL', data_type: 'Buffer', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'RESOURCE',
          label: 'zlib.inflate',
          node_subtype: 'memory',
          code_snapshot: 'zlib.inflate(req.body.data, cb)',
          attack_surface: [],
          data_in: [{ name: 'data', source: 'SRC', data_type: 'Buffer', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-400');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 4: CWE-770 — Allocation Without Limits or Throttling
// ═══════════════════════════════════════════════════════════════════════════

describe('CWE-770: Allocation of Resources Without Limits', () => {
  it('is registered in the CWE registry', () => {
    const cwes = registeredCWEs();
    expect(cwes).toContain('CWE-770');
  });

  it('VULNERABLE: INGRESS → RESOURCE without rate limiting', () => {
    const map = buildMap(
      'app.post("/api", (req, res) => { pool.getConnection(cb); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body',
          node_subtype: 'http_request',
          code_snapshot: 'req.body',
          attack_surface: ['user_input'],
          data_out: [{ name: 'data', source: 'EXTERNAL', data_type: 'object', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'RESOURCE',
          label: 'pool.getConnection',
          node_subtype: 'connections',
          code_snapshot: 'pool.getConnection(cb)',
          attack_surface: [],
          data_in: [{ name: 'data', source: 'SRC', data_type: 'object', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-770');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].missing).toContain('rate limiting');
  });

  it('SAFE: rate-limited endpoint passes (no false positive)', () => {
    const map = buildMap(
      'app.post("/api", rateLimiter, (req, res) => { pool.getConnection(cb); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body',
          node_subtype: 'http_request',
          code_snapshot: 'req.body',
          attack_surface: ['user_input'],
          data_out: [{ name: 'data', source: 'EXTERNAL', data_type: 'object', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'LIMIT', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'LIMIT', node_type: 'CONTROL',
          label: 'rate-limiter',
          node_subtype: 'rate_limiter',
          code_snapshot: '// rate limiter middleware',
          attack_surface: [],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'RESOURCE',
          label: 'pool.getConnection',
          node_subtype: 'connections',
          code_snapshot: 'pool.getConnection(cb)',
          attack_surface: [],
          data_in: [],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-770');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: no RESOURCE nodes means no findings', () => {
    const map = buildMap(
      'app.get("/hello", (req, res) => { res.send("world"); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req',
          node_subtype: 'http_request',
          code_snapshot: 'req',
          attack_surface: ['user_input'],
          edges: [],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.send',
          node_subtype: 'http_response',
          code_snapshot: 'res.send("world")',
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-770');
    expect(result.holds).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 5: CWE-1333 — ReDoS
// ═══════════════════════════════════════════════════════════════════════════

describe('CWE-1333: ReDoS (Regular Expression Denial of Service)', () => {
  it('is registered in the CWE registry', () => {
    const cwes = registeredCWEs();
    expect(cwes).toContain('CWE-1333');
  });

  it('VULNERABLE: new RegExp(userInput) without escaping', () => {
    const map = buildMap(
      'app.get("/search", (req, res) => { const regex = new RegExp(req.query.pattern); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.pattern',
          node_subtype: 'http_request',
          code_snapshot: 'req.query.pattern',
          attack_surface: ['user_input'],
          data_out: [{ name: 'pattern', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'RESOURCE',
          label: 'new RegExp(req.query.pattern)',
          node_subtype: 'cpu',
          code_snapshot: 'new RegExp(req.query.pattern)',
          attack_surface: [],
          data_in: [{ name: 'pattern', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-1333');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].description).toContain('ReDoS');
  });

  it('SAFE: new RegExp with escapeRegExp', () => {
    const map = buildMap(
      'app.get("/search", (req, res) => { const regex = new RegExp(escapeRegExp(req.query.pattern)); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.pattern',
          node_subtype: 'http_request',
          code_snapshot: 'req.query.pattern',
          attack_surface: ['user_input'],
          data_out: [{ name: 'pattern', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'CTRL', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'CTRL', node_type: 'CONTROL',
          label: 'escapeRegExp',
          node_subtype: 'validation',
          code_snapshot: 'escapeRegExp(req.query.pattern)',
          attack_surface: [],
          data_in: [{ name: 'pattern', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'SINK', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'SINK', node_type: 'RESOURCE',
          label: 'new RegExp',
          node_subtype: 'cpu',
          code_snapshot: 'new RegExp(escapeRegExp(req.query.pattern))',
          attack_surface: [],
          data_in: [{ name: 'pattern', source: 'CTRL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-1333');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: code-snapshot scan catches new RegExp(tainted) via scope proximity', () => {
    // Even without a RESOURCE node, if we detect new RegExp() in a TRANSFORM
    // node that shares scope with an INGRESS, we flag it.
    const map = buildMap(
      'app.get("/search", (req, res) => { const regex = new RegExp(req.query.pattern); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query.pattern',
          node_subtype: 'http_request',
          code_snapshot: 'req.query.pattern',
          attack_surface: ['user_input'],
          line_start: 1, line_end: 1,
          data_out: [{ name: 'pattern', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'REGEX', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'FUNC', node_type: 'STRUCTURAL',
          label: 'handler',
          node_subtype: 'function',
          code_snapshot: '(req, res) => { const regex = new RegExp(req.query.pattern); }',
          line_start: 1, line_end: 1,
          edges: [
            { target: 'SRC', edge_type: 'CONTAINS', conditional: false, async: false },
            { target: 'REGEX', edge_type: 'CONTAINS', conditional: false, async: false },
          ],
        },
        {
          id: 'REGEX', node_type: 'TRANSFORM',
          label: 'new RegExp(req.query.pattern)',
          node_subtype: 'format',
          code_snapshot: 'new RegExp(req.query.pattern)',
          line_start: 1, line_end: 1,
          attack_surface: [],
          data_in: [{ name: 'pattern', source: 'SRC', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-1333');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: no regex construction → no findings', () => {
    const map = buildMap(
      'app.get("/search", (req, res) => { res.json(results); });',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.query',
          node_subtype: 'http_request',
          code_snapshot: 'req.query',
          attack_surface: ['user_input'],
          edges: [],
        },
        {
          id: 'SINK', node_type: 'EGRESS',
          label: 'res.json',
          node_subtype: 'http_response',
          code_snapshot: 'res.json(results)',
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-1333');
    expect(result.holds).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 6: CWE-404 — Resource Leak
// ═══════════════════════════════════════════════════════════════════════════

describe('CWE-404: Improper Resource Shutdown or Release', () => {
  it('is registered in the CWE registry', () => {
    const cwes = registeredCWEs();
    expect(cwes).toContain('CWE-404');
  });

  it('VULNERABLE: db connection acquired without release in function', () => {
    const map = buildMap(
      'function getData() { const conn = pool.getConnection(); const data = conn.query("SELECT 1"); return data; }',
      [
        {
          id: 'FUNC', node_type: 'STRUCTURAL',
          label: 'getData',
          node_subtype: 'function',
          code_snapshot: 'function getData() { const conn = pool.getConnection(); const data = conn.query("SELECT 1"); return data; }',
          edges: [
            { target: 'ACQUIRE', edge_type: 'CONTAINS', conditional: false, async: false },
            { target: 'QUERY', edge_type: 'CONTAINS', conditional: false, async: false },
          ],
        },
        {
          id: 'ACQUIRE', node_type: 'RESOURCE',
          label: 'pool.getConnection()',
          node_subtype: 'connections',
          code_snapshot: 'pool.getConnection()',
          attack_surface: [],
          edges: [],
        },
        {
          id: 'QUERY', node_type: 'STORAGE',
          label: 'conn.query',
          node_subtype: 'db_read',
          code_snapshot: 'conn.query("SELECT 1")',
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-404');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('connection');
  });

  it('SAFE: db connection acquired with release in same function', () => {
    const map = buildMap(
      'function getData() { const conn = pool.getConnection(); try { conn.query("SELECT 1"); } finally { conn.release(); } }',
      [
        {
          id: 'FUNC', node_type: 'STRUCTURAL',
          label: 'getData',
          node_subtype: 'function',
          code_snapshot: 'function getData() { const conn = pool.getConnection(); try { conn.query("SELECT 1"); } finally { conn.release(); } }',
          edges: [
            { target: 'ACQUIRE', edge_type: 'CONTAINS', conditional: false, async: false },
            { target: 'RELEASE', edge_type: 'CONTAINS', conditional: false, async: false },
          ],
        },
        {
          id: 'ACQUIRE', node_type: 'RESOURCE',
          label: 'pool.getConnection()',
          node_subtype: 'connections',
          code_snapshot: 'pool.getConnection()',
          attack_surface: [],
          edges: [],
        },
        {
          id: 'RELEASE', node_type: 'RESOURCE',
          label: 'conn.release()',
          node_subtype: 'connections',
          code_snapshot: 'conn.release()',
          attack_surface: [],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-404');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('VULNERABLE: fs.open without close on error path', () => {
    const map = buildMap(
      'function readData(path) { const fd = fs.open(path, "r"); const data = fs.read(fd); return data; }',
      [
        {
          id: 'FUNC', node_type: 'STRUCTURAL',
          label: 'readData',
          node_subtype: 'function',
          code_snapshot: 'function readData(path) { const fd = fs.open(path, "r"); const data = fs.read(fd); return data; }',
          edges: [
            { target: 'OPEN', edge_type: 'CONTAINS', conditional: false, async: false },
            { target: 'READ', edge_type: 'CONTAINS', conditional: false, async: false },
          ],
        },
        {
          id: 'OPEN', node_type: 'RESOURCE',
          label: 'fs.open(path, "r")',
          node_subtype: 'file_descriptors',
          code_snapshot: 'fs.open(path, "r")',
          attack_surface: [],
          edges: [],
        },
        {
          id: 'READ', node_type: 'INGRESS',
          label: 'fs.read(fd)',
          node_subtype: 'file_read',
          code_snapshot: 'fs.read(fd)',
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-404');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].description).toContain('file_descriptors');
  });

  it('SAFE: fs.open with close in finally block', () => {
    const map = buildMap(
      'function readData(path) { const fd = fs.open(path, "r"); try { fs.read(fd); } finally { fs.close(fd); } }',
      [
        {
          id: 'FUNC', node_type: 'STRUCTURAL',
          label: 'readData',
          node_subtype: 'function',
          code_snapshot: 'function readData(path) { const fd = fs.open(path, "r"); try { fs.read(fd); } finally { fs.close(fd); } }',
          edges: [
            { target: 'OPEN', edge_type: 'CONTAINS', conditional: false, async: false },
          ],
        },
        {
          id: 'OPEN', node_type: 'RESOURCE',
          label: 'fs.open(path, "r")',
          node_subtype: 'file_descriptors',
          code_snapshot: 'fs.open(path, "r")',
          attack_surface: [],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-404');
    // The func code_snapshot contains "close" and "finally" so it should pass
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });

  it('SAFE: RESOURCE/memory and RESOURCE/cpu are not checked for release', () => {
    // Memory and CPU resources don't need explicit release (GC handles memory, CPU is freed automatically)
    const map = buildMap(
      'function compute() { Buffer.alloc(1024); crypto.pbkdf2Sync("pass", "salt", 100000, 64, "sha512"); }',
      [
        {
          id: 'FUNC', node_type: 'STRUCTURAL',
          label: 'compute',
          node_subtype: 'function',
          code_snapshot: 'function compute() { Buffer.alloc(1024); crypto.pbkdf2Sync("pass", "salt", 100000, 64, "sha512"); }',
          edges: [
            { target: 'BUF', edge_type: 'CONTAINS', conditional: false, async: false },
            { target: 'HASH', edge_type: 'CONTAINS', conditional: false, async: false },
          ],
        },
        {
          id: 'BUF', node_type: 'RESOURCE',
          label: 'Buffer.alloc(1024)',
          node_subtype: 'memory',
          code_snapshot: 'Buffer.alloc(1024)',
          edges: [],
        },
        {
          id: 'HASH', node_type: 'RESOURCE',
          label: 'crypto.pbkdf2Sync',
          node_subtype: 'cpu',
          code_snapshot: 'crypto.pbkdf2Sync("pass", "salt", 100000, 64, "sha512")',
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-404');
    expect(result.holds).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 7: Full Integration — verifyAll includes RESOURCE CWEs
// ═══════════════════════════════════════════════════════════════════════════

describe('RESOURCE verifyAll integration', () => {
  it('verifyAll includes CWE-400, CWE-770, CWE-1333, CWE-404 in results', () => {
    const map = buildMap('// empty', []);
    const results = verifyAll(map);
    const cwes = results.map(r => r.cwe);
    expect(cwes).toContain('CWE-400');
    expect(cwes).toContain('CWE-770');
    expect(cwes).toContain('CWE-1333');
    expect(cwes).toContain('CWE-404');
  });

  it('RESOURCE type is accepted by createNode', () => {
    const node = createNode({
      node_type: 'RESOURCE',
      label: 'test-resource',
      node_subtype: 'memory',
      code_snapshot: 'Buffer.alloc(size)',
    });
    expect(node.node_type).toBe('RESOURCE');
    expect(node.node_subtype).toBe('memory');
    expect(node.id).toBeDefined();
  });

  it('RESOURCE nodes survive full mapper round-trip', () => {
    // Parse code that contains RESOURCE-classified calls
    const code = `
      const express = require('express');
      const fs = require('fs');
      const app = express();
      app.get('/file', (req, res) => {
        fs.open(req.query.path, 'r', (err, fd) => {
          res.send('ok');
        });
      });
    `;
    const map = parse(code);
    const resources = findNodes(map.nodes, 'RESOURCE');
    expect(resources.length).toBeGreaterThanOrEqual(1);
    // Verify the resource node has proper fields
    const resNode = resources[0];
    expect(resNode.language).toBe('javascript');
    expect(resNode.file).toBe('test-resource.js');
    expect(resNode.line_start).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 8: Edge Cases and Combined Patterns
// ═══════════════════════════════════════════════════════════════════════════

describe('RESOURCE edge cases', () => {
  it('multiple RESOURCE subtypes in same function are all detected', () => {
    const code = `
      const express = require('express');
      const fs = require('fs');
      const zlib = require('zlib');
      const app = express();
      app.post('/process', (req, res) => {
        const fd = fs.open(req.body.path, 'r');
        const buf = Buffer.alloc(req.body.size);
        zlib.inflate(req.body.compressed, (err, result) => {
          res.send(result);
        });
      });
    `;
    const map = parse(code);
    const resources = findNodes(map.nodes, 'RESOURCE');
    // Should have at least file_descriptors and memory nodes
    const subtypes = new Set(resources.map(r => r.node_subtype));
    expect(subtypes.size).toBeGreaterThanOrEqual(2);
  });

  it('child_process.fork remains EXTERNAL/system_exec (security takes priority over resource)', () => {
    // child_process.fork is primarily a security concern (code execution), not just resource
    const result = lookupCallee(['child_process', 'fork']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('system_exec');
  });

  it('cluster.fork is RESOURCE/threads (process forking for capacity)', () => {
    const result = lookupCallee(['cluster', 'fork']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('RESOURCE');
    expect(result!.subtype).toBe('threads');
  });

  it('RESOURCE node taint propagation works', () => {
    // When tainted data flows through a RESOURCE node, taint should propagate
    const map = buildMap(
      'const buf = Buffer.alloc(req.body.size);',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.size',
          node_subtype: 'http_request',
          code_snapshot: 'req.body.size',
          attack_surface: ['user_input'],
          data_out: [{ name: 'size', source: 'EXTERNAL', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'RES', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'RES', node_type: 'RESOURCE',
          label: 'Buffer.alloc',
          node_subtype: 'memory',
          code_snapshot: 'Buffer.alloc(req.body.size)',
          data_in: [{ name: 'size', source: 'SRC', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    // CWE-400 should catch this
    const result = verify(map, 'CWE-400');
    expect(result.holds).toBe(false);
  });

  it('SAFE: RESOURCE with explicit max limit in code_snapshot passes CWE-400', () => {
    const map = buildMap(
      'const buf = Buffer.alloc(Math.min(req.body.size, MAX_SIZE));',
      [
        {
          id: 'SRC', node_type: 'INGRESS',
          label: 'req.body.size',
          node_subtype: 'http_request',
          code_snapshot: 'req.body.size',
          attack_surface: ['user_input'],
          data_out: [{ name: 'size', source: 'EXTERNAL', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [{ target: 'RES', edge_type: 'DATA_FLOW', conditional: false, async: false }],
        },
        {
          id: 'RES', node_type: 'RESOURCE',
          label: 'Buffer.alloc',
          node_subtype: 'memory',
          code_snapshot: 'Buffer.alloc(Math.min(req.body.size, MAX_SIZE))',
          data_in: [{ name: 'size', source: 'SRC', data_type: 'number', tainted: true, sensitivity: 'NONE' }],
          edges: [],
        },
      ]
    );

    const result = verify(map, 'CWE-400');
    // Should pass because MAX_SIZE is detected as a bound
    expect(result.holds).toBe(true);
  });
});
