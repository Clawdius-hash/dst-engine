import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import * as fs from 'fs';
import * as path from 'path';
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

beforeEach(() => resetSequence());

function parse(code: string) {
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, 'smoke.js');
  tree.delete();
  return map;
}

function hasNode(nodes: NeuralMapNode[], type: string, subtype?: string) {
  return nodes.some(n => n.node_type === type && (!subtype || n.node_subtype === subtype));
}

describe('Smoke: structural inference on real-world patterns', () => {

  it('Koa ctx.request.body -- structural inference only (no MEMBER_CALLS pattern)', () => {
    const code = `
      const Koa = require('koa');
      const app = new Koa();
      app.use(function handler(ctx) {
        const user = ctx.request.body.name;
        ctx.body = { user };
      });
    `;
    const map = parse(code);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    // ctx is INPUT role from HTTP_FRAMEWORK callback
    const ctxIngress = ingress.find(n => n.label.includes('ctx'));
    expect(ctxIngress).toBeTruthy();
  });

  it('custom var names (input, output) with two-hop alias -- structural inference only', () => {
    const code = `
      const myFramework = require('express');
      const server = myFramework();
      server.post('/data', function process(input, output) {
        const cmd = input.body.command;
        output.json({ received: cmd });
      });
    `;
    const map = parse(code);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    const inputIngress = ingress.find(n => n.label.includes('input'));
    expect(inputIngress).toBeTruthy();
  });

  it('aliased cp.exec resolves via alias chain fallback', () => {
    const code = `
      const cp = require('child_process');
      cp.exec('ls -la ' + userInput);
    `;
    const map = parse(code);
    expect(hasNode(map.nodes, 'EXTERNAL', 'system_exec')).toBe(true);
  });

  it('Fastify-style handler -- structural inference detects request param', () => {
    const code = `
      const fastify = require('fastify');
      const app = fastify();
      app.post('/api', function handler(request, reply) {
        const data = request.body;
        reply.send({ data });
      });
    `;
    const map = parse(code);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
  });

  it('SQLi end-to-end: tainted input reaches db.query with string concat', () => {
    const code = `
      const express = require('express');
      const db = require('pg');
      const app = express();
      app.post('/users', (req, res) => {
        const name = req.body.name;
        db.query('SELECT * FROM users WHERE name = ' + name);
        res.json({ ok: true });
      });
    `;
    const map = parse(code);
    expect(hasNode(map.nodes, 'INGRESS')).toBe(true);
    expect(hasNode(map.nodes, 'STORAGE')).toBe(true);
    const tainted = map.story?.filter(s => s.taintClass === 'TAINTED') ?? [];
    expect(tainted.length).toBeGreaterThanOrEqual(1);
  });

  it('command injection end-to-end: req.body flows to cp.exec', () => {
    const code = `
      const express = require('express');
      const cp = require('child_process');
      const app = express();
      app.post('/run', (req, res) => {
        const cmd = req.body.command;
        cp.exec(cmd);
        res.json({ ok: true });
      });
    `;
    const map = parse(code);
    expect(hasNode(map.nodes, 'INGRESS')).toBe(true);
    expect(hasNode(map.nodes, 'EXTERNAL', 'system_exec')).toBe(true);
  });

  it('safe endpoint -- no tainted data reaches sinks', () => {
    const code = `
      const express = require('express');
      const app = express();
      app.get('/health', (req, res) => {
        res.json({ status: 'ok', time: Date.now() });
      });
    `;
    const map = parse(code);
    // Should parse without errors
    expect(map.nodes.length).toBeGreaterThan(0);
    // No STORAGE or EXTERNAL sinks with tainted data
    const dangerousSinks = map.nodes.filter(n =>
      (n.node_type === 'STORAGE' || (n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec')) &&
      n.data_in.some(d => d.tainted)
    );
    expect(dangerousSinks).toHaveLength(0);
  });

  it('ternary with literal branches does NOT propagate taint from condition', () => {
    const code = `
      const express = require('express');
      const app = express();
      app.get('/test', (req, res) => {
        const sameSite = process.env.NODE_ENV !== 'development' ? 'none' : 'lax';
        res.json({ sameSite });
      });
    `;
    const map = parse(code);
    const taintedSameSite = map.story?.filter(s =>
      s.taintClass === 'TAINTED' && s.slots?.subject === 'sameSite'
    ) ?? [];
    expect(taintedSameSite).toHaveLength(0);
  });

  it('ternary with tainted branch DOES propagate taint', () => {
    const code = `
      const express = require('express');
      const app = express();
      app.get('/test', (req, res) => {
        const output = process.env.NODE_ENV !== 'dev' ? 'safe' : req.body.evil;
        res.json({ output });
      });
    `;
    const map = parse(code);
    const taintedOutput = map.story?.filter(s =>
      s.taintClass === 'TAINTED' && s.slots?.subject === 'output'
    ) ?? [];
    expect(taintedOutput.length).toBeGreaterThanOrEqual(1);
  });
});
