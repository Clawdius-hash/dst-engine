import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { resolveCallee, resolvePropertyAccess, isNewExpression } from './resolveCallee.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Reuse the same test parser helper pattern from parser.test.ts
async function createTestParser(): Promise<InstanceType<typeof Parser>> {
  await Parser.init();
  const parser = new Parser();
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const JavaScript = await Language.load(wasmBuffer);
  parser.setLanguage(JavaScript);
  return parser;
}

// Helper: parse code, find all nodes of a given type
function findNodes(root: import('web-tree-sitter').SyntaxNode, type: string): import('web-tree-sitter').SyntaxNode[] {
  return root.descendantsOfType(type);
}

// Helper: parse code and find the first call_expression whose text contains a substring
function findCallContaining(
  root: import('web-tree-sitter').SyntaxNode,
  substring: string
): import('web-tree-sitter').SyntaxNode | undefined {
  const calls = findNodes(root, 'call_expression');
  return calls.find(c => c.text.includes(substring));
}

// Helper: parse code and find the first member_expression whose text matches exactly
// or contains a substring (for property access, not calls)
function findMemberContaining(
  root: import('web-tree-sitter').SyntaxNode,
  substring: string
): import('web-tree-sitter').SyntaxNode | undefined {
  const members = findNodes(root, 'member_expression');
  return members.find(m => m.text.includes(substring));
}

describe('resolveCallee — call expression resolution', () => {
  let parser: InstanceType<typeof Parser>;

  beforeAll(async () => {
    parser = await createTestParser();
  });

  // ── Simple calls ──

  it('resolves res.json(user) → EGRESS/http_response', () => {
    const tree = parser.parse('res.json(user);');
    const call = findCallContaining(tree.rootNode, 'res.json');
    expect(call).toBeDefined();

    const result = resolveCallee(call!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
    expect(result!.chain).toEqual(['res', 'json']);

    tree.delete();
  });

  it('resolves fetch("/api/data") → EXTERNAL/api_call', () => {
    const tree = parser.parse('fetch("/api/data");');
    const call = findCallContaining(tree.rootNode, 'fetch');
    expect(call).toBeDefined();

    const result = resolveCallee(call!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('api_call');
    expect(result!.chain).toEqual(['fetch']);

    tree.delete();
  });

  it('resolves db.query("SELECT...") → STORAGE/db_read', () => {
    const tree = parser.parse('db.query("SELECT * FROM users");');
    const call = findCallContaining(tree.rootNode, 'db.query');
    expect(call).toBeDefined();

    const result = resolveCallee(call!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_read');

    tree.delete();
  });

  it('resolves exec("ls") → EXTERNAL/system_exec', () => {
    const tree = parser.parse('exec("ls");');
    const call = findCallContaining(tree.rootNode, 'exec');
    expect(call).toBeDefined();

    const result = resolveCallee(call!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('system_exec');

    tree.delete();
  });

  it('resolves JSON.parse(data) → TRANSFORM/parse', () => {
    const tree = parser.parse('JSON.parse(data);');
    const call = findCallContaining(tree.rootNode, 'JSON.parse');
    expect(call).toBeDefined();

    const result = resolveCallee(call!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('parse');
    expect(result!.chain).toEqual(['JSON', 'parse']);

    tree.delete();
  });

  it('resolves bcrypt.hash(password, 10) → AUTH/authenticate', () => {
    const tree = parser.parse('bcrypt.hash(password, 10);');
    const call = findCallContaining(tree.rootNode, 'bcrypt.hash');
    expect(call).toBeDefined();

    const result = resolveCallee(call!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('AUTH');
    expect(result!.subtype).toBe('authenticate');

    tree.delete();
  });

  it('resolves console.log(x) → EGRESS/display', () => {
    const tree = parser.parse('console.log(x);');
    const call = findCallContaining(tree.rootNode, 'console.log');
    expect(call).toBeDefined();

    const result = resolveCallee(call!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('display');

    tree.delete();
  });

  it('resolves res.status(200).json(data) — outer call is .json()', () => {
    // tree-sitter parses this as:
    //   call_expression (.json(data))
    //     function: member_expression
    //       object: call_expression (.status(200))
    //         function: member_expression (res.status)
    //       property: json
    const tree = parser.parse('res.status(200).json(data);');
    const calls = findNodes(tree.rootNode, 'call_expression');

    // The outermost call is .json(data) — it wraps .status(200)
    const outerCall = calls.find(c => c.text.includes('.json(data)'));
    expect(outerCall).toBeDefined();

    const result = resolveCallee(outerCall!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
    // Chain should end with 'json'
    expect(result!.chain[result!.chain.length - 1]).toBe('json');

    tree.delete();
  });

  // ── Chained calls ──

  it('resolves db.collection("users").find({id}) → STORAGE/db_read', () => {
    const tree = parser.parse('db.collection("users").find({id});');
    const calls = findNodes(tree.rootNode, 'call_expression');

    // Outermost call is .find({id})
    const outerCall = calls.find(c => c.text.includes('.find('));
    expect(outerCall).toBeDefined();

    const result = resolveCallee(outerCall!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_read');

    tree.delete();
  });

  it('resolves db.collection("users").insertOne(doc) → STORAGE/db_write', () => {
    const tree = parser.parse('db.collection("users").insertOne(doc);');
    const calls = findNodes(tree.rootNode, 'call_expression');

    const outerCall = calls.find(c => c.text.includes('.insertOne('));
    expect(outerCall).toBeDefined();

    const result = resolveCallee(outerCall!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_write');

    tree.delete();
  });

  // ── Unknown callee → null ──

  it('returns null for someRandomFunction()', () => {
    const tree = parser.parse('someRandomFunction();');
    const call = findCallContaining(tree.rootNode, 'someRandomFunction');
    expect(call).toBeDefined();

    const result = resolveCallee(call!);
    expect(result).toBeNull();

    tree.delete();
  });

  it('returns null for node that is not call_expression', () => {
    const tree = parser.parse('const x = 42;');
    const decl = tree.rootNode.namedChildren[0]!;
    // This is a lexical_declaration, not a call_expression
    const result = resolveCallee(decl);
    expect(result).toBeNull();

    tree.delete();
  });

  // ── Multi-statement: Express route handler ──

  it('resolves all calls in an Express route handler', () => {
    const code = `
app.get('/users/:id', async (req, res) => {
  const userId = req.params.id;
  const user = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
  res.json(user);
});
    `.trim();

    const tree = parser.parse(code);
    const calls = findNodes(tree.rootNode, 'call_expression');

    // Find the db.query call (startsWith to avoid matching outer app.get whose body contains db.query)
    const dbCall = calls.find(c => c.text.startsWith('db.query'));
    expect(dbCall).toBeDefined();
    const dbResult = resolveCallee(dbCall!);
    expect(dbResult).not.toBeNull();
    expect(dbResult!.nodeType).toBe('STORAGE');
    expect(dbResult!.subtype).toBe('db_read');

    // Find the res.json call (use startsWith to avoid matching outer app.get() whose body contains res.json)
    const resCall = calls.find(c => c.text.startsWith('res.json'));
    expect(resCall).toBeDefined();
    const resResult = resolveCallee(resCall!);
    expect(resResult).not.toBeNull();
    expect(resResult!.nodeType).toBe('EGRESS');
    expect(resResult!.subtype).toBe('http_response');

    tree.delete();
  });
});

describe('resolvePropertyAccess — non-call member expressions', () => {
  let parser: InstanceType<typeof Parser>;

  beforeAll(async () => {
    parser = await createTestParser();
  });

  it('resolves req.params.id → INGRESS/http_request (tainted)', () => {
    const tree = parser.parse('const id = req.params.id;');
    // Find member_expression for req.params (the deepest relevant one)
    const members = findNodes(tree.rootNode, 'member_expression');
    // req.params.id has nested member_expressions:
    //   member_expression (req.params.id)
    //     object: member_expression (req.params)
    //     property: id
    // We want to resolve the outermost one (req.params.id)
    const reqParams = members.find(m => m.text === 'req.params.id');
    expect(reqParams).toBeDefined();

    const result = resolvePropertyAccess(reqParams!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.subtype).toBe('http_request');
    expect(result!.tainted).toBe(true);

    tree.delete();
  });

  it('resolves req.body.username → INGRESS/http_request (tainted)', () => {
    const tree = parser.parse('const name = req.body.username;');
    const members = findNodes(tree.rootNode, 'member_expression');
    const reqBody = members.find(m => m.text === 'req.body.username');
    expect(reqBody).toBeDefined();

    const result = resolvePropertyAccess(reqBody!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);

    tree.delete();
  });

  it('resolves process.env.SECRET → INGRESS/env_read', () => {
    const tree = parser.parse('const key = process.env.SECRET;');
    const members = findNodes(tree.rootNode, 'member_expression');
    const processEnv = members.find(m => m.text === 'process.env.SECRET');
    expect(processEnv).toBeDefined();

    const result = resolvePropertyAccess(processEnv!);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.subtype).toBe('env_read');

    tree.delete();
  });

  it('returns null for unknown property access', () => {
    const tree = parser.parse('const x = obj.thing;');
    const members = findNodes(tree.rootNode, 'member_expression');
    const objThing = members.find(m => m.text === 'obj.thing');
    expect(objThing).toBeDefined();

    const result = resolvePropertyAccess(objThing!);
    expect(result).toBeNull();

    tree.delete();
  });

  it('returns null for non-member_expression node', () => {
    const tree = parser.parse('const x = 42;');
    const decl = tree.rootNode.namedChildren[0]!;
    const result = resolvePropertyAccess(decl);
    expect(result).toBeNull();

    tree.delete();
  });
});

describe('isNewExpression — constructor detection', () => {
  let parser: InstanceType<typeof Parser>;

  beforeAll(async () => {
    parser = await createTestParser();
  });

  it('detects new Buffer(data) as new_expression', () => {
    const tree = parser.parse('const buf = new Buffer(data);');
    const calls = findNodes(tree.rootNode, 'call_expression');
    // Note: tree-sitter parses `new X(args)` as new_expression, NOT call_expression.
    // So we check new_expression nodes instead.
    const newExprs = findNodes(tree.rootNode, 'new_expression');
    expect(newExprs.length).toBeGreaterThanOrEqual(1);
    expect(newExprs[0]!.text).toContain('Buffer');

    tree.delete();
  });

  it('regular call is NOT a new_expression', () => {
    const tree = parser.parse('fetch("/api");');
    const calls = findNodes(tree.rootNode, 'call_expression');
    expect(calls.length).toBe(1);

    const result = isNewExpression(calls[0]!);
    expect(result).toBe(false);

    tree.delete();
  });
});
