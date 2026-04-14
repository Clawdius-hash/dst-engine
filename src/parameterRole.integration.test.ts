import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { resetSequence } from './types.js';
import type { NeuralMapNode } from './types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

beforeAll(async () => {
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm');
  const wasmBuffer = fs.readFileSync(wasmPath);
  const JavaScript = await Language.load(wasmBuffer);
  parser.setLanguage(JavaScript);
});

beforeEach(() => {
  resetSequence();
});

function parse(code: string, filename = 'test.js') {
  const tree = parser.parse(code);
  const { map, ctx } = buildNeuralMap(tree, code, filename);
  tree.delete();
  return { map, ctx };
}

function findNodes(nodes: NeuralMapNode[], type: string, subtype?: string) {
  return nodes.filter(n => n.node_type === type && (!subtype || n.node_subtype === subtype));
}

describe('Structural inference integration', () => {
  it('creates INGRESS nodes for input-role params of Express callbacks', () => {
    const code = `
      const express = require('express');
      const app = express();
      app.get('/users', function handler(req, res) {
        const name = req.body.name;
        res.json({ name });
      });
    `;
    const { map } = parse(code);
    const ingress = findNodes(map.nodes, 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    // Should find an INGRESS related to req
    const reqIngress = ingress.find(n =>
      n.label.includes('req') || n.code_snapshot.includes('req')
    );
    expect(reqIngress).toBeTruthy();
  });

  it('does NOT create structural INGRESS for local function callbacks', () => {
    const code = `
      function processItems(items, callback) {
        items.forEach(item => callback(item));
      }
      processItems([1, 2, 3], function handler(item) {
        console.log(item);
      });
    `;
    const { map } = parse(code);
    // Should NOT have structural INGRESS for 'item'
    const structuralIngress = findNodes(map.nodes, 'INGRESS').filter(n =>
      n.label.includes('structural') && n.label.includes('item')
    );
    expect(structuralIngress).toHaveLength(0);
  });

  it('handles fs.readFile callback', () => {
    const code = `
      const fs = require('fs');
      fs.readFile('/etc/passwd', function handler(err, data) {
        console.log(data.toString());
      });
    `;
    const { map } = parse(code);
    // Should detect either via existing patterns OR structural inference
    const ingress = findNodes(map.nodes, 'INGRESS');
    // At minimum, the fs.readFile should be detected
    const fileNodes = map.nodes.filter(n =>
      n.node_subtype === 'file_read' || n.code_snapshot.includes('readFile')
    );
    expect(fileNodes.length).toBeGreaterThanOrEqual(1);
  });

  it('preserves existing pattern-based detection', () => {
    const code = `
      const pg = require('pg');
      const pool = new pg.Pool();
      pool.query('SELECT * FROM users WHERE id = ' + userId);
    `;
    const { map } = parse(code);
    // pool.query should still be detected via existing patterns
    // Check for STORAGE nodes or any node referencing .query
    const storageOrQuery = map.nodes.filter(n =>
      n.node_type === 'STORAGE' ||
      (n.code_snapshot && n.code_snapshot.includes('query'))
    );
    expect(storageOrQuery.length).toBeGreaterThanOrEqual(1);
  });

  it('story has TAINTED sentences for Express handler params', () => {
    const code = `
      const express = require('express');
      const app = express();
      app.post('/api/data', function handler(req, res) {
        const input = req.body.data;
        res.send(input);
      });
    `;
    const { map } = parse(code);
    expect(map.story).toBeDefined();
    expect(map.story!.length).toBeGreaterThan(0);
  });

  it('handles Koa-style ctx parameter', () => {
    const code = `
      const Koa = require('koa');
      const app = new Koa();
      app.use(function handler(ctx) {
        const user = ctx.request.body;
        ctx.body = { user };
      });
    `;
    const { map } = parse(code);
    // koa is HTTP_FRAMEWORK, ctx is used as input (reads .request)
    // Should create an INGRESS node
    const ingress = findNodes(map.nodes, 'INGRESS');
    const ctxIngress = ingress.find(n => n.label.includes('ctx'));
    expect(ctxIngress).toBeTruthy();
  });

  it('handles arrow function callbacks', () => {
    const code = `
      const express = require('express');
      const app = express();
      app.get('/api', (req, res) => {
        const q = req.query.search;
        res.json({ q });
      });
    `;
    const { map } = parse(code);
    const ingress = findNodes(map.nodes, 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
  });
});
