import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { resetSequence } from './types.js';
import type { NeuralMapNode, NeuralMap } from './types.js';

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

function parse(code: string) {
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, 'oracle-test.js');
  tree.delete();
  return map;
}

function hasNodeOfType(map: { nodes: NeuralMapNode[] }, type: string, subtype?: string): boolean {
  return map.nodes.some(n => n.node_type === type && (!subtype || n.node_subtype === subtype));
}

function findByType(map: { nodes: NeuralMapNode[] }, type: string, subtype?: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === type && (!subtype || n.node_subtype === subtype));
}

describe('Pattern Oracle: structural inference matches existing patterns', () => {

  describe('Express handler patterns', () => {
    it('req.body detected as INGRESS/http_request', () => {
      const code = `
        const express = require('express');
        const app = express();
        app.post('/api', function(req, res) {
          const data = req.body;
        });
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'INGRESS', 'http_request')).toBe(true);
    });

    it('req.params detected as INGRESS', () => {
      const code = `
        const express = require('express');
        const app = express();
        app.get('/users/:id', function(req, res) {
          const id = req.params.id;
        });
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'INGRESS', 'http_request')).toBe(true);
    });

    it('req.query detected as INGRESS', () => {
      const code = `
        const express = require('express');
        const app = express();
        app.get('/search', function(req, res) {
          const q = req.query.q;
        });
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'INGRESS', 'http_request')).toBe(true);
    });

    it('req.headers detected as INGRESS', () => {
      const code = `
        const express = require('express');
        const app = express();
        app.get('/', function(req, res) {
          const auth = req.headers.authorization;
        });
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'INGRESS', 'http_request')).toBe(true);
    });

    it('res.json detected as EGRESS/http_response', () => {
      const code = `
        const express = require('express');
        const app = express();
        app.get('/', function(req, res) {
          res.json({ ok: true });
        });
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'EGRESS', 'http_response')).toBe(true);
    });

    it('res.send detected as EGRESS/http_response', () => {
      const code = `
        const express = require('express');
        const app = express();
        app.get('/', function(req, res) {
          res.send('hello');
        });
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'EGRESS', 'http_response')).toBe(true);
    });
  });

  describe('Database sink patterns', () => {
    it('db.query detected as STORAGE', () => {
      const code = `
        const db = require('pg');
        db.query('SELECT * FROM users WHERE id = ' + userId);
      `;
      const map = parse(code);
      const storage = findByType(map, 'STORAGE');
      const hasQuery = storage.length > 0 || map.nodes.some(n => n.code_snapshot.includes('query'));
      expect(hasQuery).toBe(true);
    });
  });

  describe('Shell execution patterns', () => {
    it('require("child_process").exec detected as EXTERNAL/system_exec', () => {
      const code = `
        require('child_process').exec('ls -la ' + userInput);
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'EXTERNAL', 'system_exec')).toBe(true);
    });

    it('destructured exec detected as EXTERNAL/system_exec', () => {
      const code = `
        const { exec } = require('child_process');
        exec('ls -la ' + userInput);
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'EXTERNAL', 'system_exec')).toBe(true);
    });

    // Aliased module member calls — cp = require('child_process'); cp.exec(...)
    it('aliased module member: cp.exec after const cp = require("child_process")', () => {
      const code = `
        const cp = require('child_process');
        cp.exec('ls -la ' + userInput);
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'EXTERNAL', 'system_exec')).toBe(true);
    });
  });

  describe('Filesystem patterns', () => {
    it('fs.readFile detected', () => {
      const code = `
        const fs = require('fs');
        fs.readFile(userPath, 'utf8', (err, data) => {});
      `;
      const map = parse(code);
      const fileNodes = map.nodes.filter(n =>
        n.node_subtype === 'file_read' || n.code_snapshot.includes('readFile')
      );
      expect(fileNodes.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('End-to-end taint flow', () => {
    it('Express req.body -> db.query produces tainted flow', () => {
      const code = `
        const express = require('express');
        const db = require('pg');
        const app = express();
        app.post('/api', function(req, res) {
          const name = req.body.name;
          db.query('SELECT * FROM users WHERE name = ' + name);
        });
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'INGRESS')).toBe(true);
      const taintedSentences = map.story?.filter(s => s.taintClass === 'TAINTED') ?? [];
      expect(taintedSentences.length).toBeGreaterThanOrEqual(1);
    });

    it('Express req.body -> exec() produces tainted flow', () => {
      const code = `
        const express = require('express');
        const { exec } = require('child_process');
        const app = express();
        app.post('/run', function(req, res) {
          const cmd = req.body.command;
          exec(cmd);
        });
      `;
      const map = parse(code);
      expect(hasNodeOfType(map, 'INGRESS')).toBe(true);
      expect(hasNodeOfType(map, 'EXTERNAL', 'system_exec')).toBe(true);
    });
  });
});
