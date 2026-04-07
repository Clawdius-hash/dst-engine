import { describe, it, expect } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// In Node.js/Vitest context, load WASM as buffer to avoid ESM require('fs/promises') issue
async function createTestParser(): Promise<InstanceType<typeof Parser>> {
  await Parser.init();
  const parser = new Parser();

  // Read grammar WASM as buffer — bypasses Language.load's internal fs/promises usage
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const JavaScript = await Language.load(wasmBuffer);
  parser.setLanguage(JavaScript);
  return parser;
}

describe('tree-sitter JavaScript parser', () => {
  it('parses a simple variable declaration', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('const x = 42;');
    const root = tree.rootNode;

    expect(root.type).toBe('program');
    expect(root.namedChildCount).toBe(1);

    const decl = root.namedChildren[0]!;
    expect(decl.type).toBe('lexical_declaration');

    const declarator = decl.namedChildren[0]!;
    expect(declarator.type).toBe('variable_declarator');

    tree.delete();
    parser.delete();
  });

  it('parses an Express route handler and finds key AST nodes', async () => {
    const parser = await createTestParser();
    const code = `
const express = require('express');
const app = express();

app.get('/users/:id', async (req, res) => {
  const userId = req.params.id;
  const user = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
  res.json(user);
});
    `.trim();

    const tree = parser.parse(code);
    const root = tree.rootNode;

    expect(root.type).toBe('program');

    // Should have 3 top-level statements
    expect(root.namedChildCount).toBe(3);

    // Find all call_expression nodes (require, express, app.get, db.query, res.json)
    const calls = root.descendantsOfType('call_expression');
    expect(calls.length).toBeGreaterThanOrEqual(4);

    // Find all string nodes (route path, SQL query)
    const strings = root.descendantsOfType('string');
    const stringTexts = strings.map(s => s.text);
    expect(stringTexts).toContain("'express'");
    expect(stringTexts).toContain("'/users/:id'");

    // Find the arrow function (the route handler)
    const arrows = root.descendantsOfType('arrow_function');
    expect(arrows.length).toBe(1);
    expect(arrows[0]!.text).toContain('req.params.id');

    // Find member_expression nodes (req.params.id, db.query, res.json, app.get)
    const members = root.descendantsOfType('member_expression');
    expect(members.length).toBeGreaterThanOrEqual(4);

    tree.delete();
    parser.delete();
  });

  it('finds function declarations by type', async () => {
    const parser = await createTestParser();
    const code = `
function loadData(url) {
  return fetch(url).then(r => r.json());
}

async function main() {
  const data = await loadData('/api/data');
  console.log(data);
}
    `.trim();

    const tree = parser.parse(code);
    const functions = tree.rootNode.descendantsOfType('function_declaration');

    expect(functions.length).toBe(2);
    expect(functions[0]!.childForFieldName('name')!.text).toBe('loadData');
    expect(functions[1]!.childForFieldName('name')!.text).toBe('main');

    tree.delete();
    parser.delete();
  });

  it('detects security-relevant patterns (taint source)', async () => {
    const parser = await createTestParser();
    const code = `
app.post('/login', (req, res) => {
  const username = req.body.username;
  const query = "SELECT * FROM users WHERE name = '" + username + "'";
  db.execute(query);
});
    `.trim();

    const tree = parser.parse(code);

    // Find the taint source: req.body.username
    const members = tree.rootNode.descendantsOfType('member_expression');
    const reqBody = members.find(m => m.text.includes('req.body'));
    expect(reqBody).toBeDefined();

    // Find string concatenation (potential SQL injection)
    const binaries = tree.rootNode.descendantsOfType('binary_expression');
    const concats = binaries.filter(b => b.text.includes('+'));
    expect(concats.length).toBeGreaterThanOrEqual(1);

    // Find the db.execute call (taint sink)
    const calls = tree.rootNode.descendantsOfType('call_expression');
    const dbExec = calls.find(c => c.text.includes('db.execute'));
    expect(dbExec).toBeDefined();

    tree.delete();
    parser.delete();
  });
});
