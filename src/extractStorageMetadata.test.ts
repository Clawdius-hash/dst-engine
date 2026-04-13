/**
 * Tests for extractStorageMetadata — verifies AST-based extraction of storage
 * targets (table names, collection names, file paths, env var names, model names).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { extractStorageMetadata } from './extractStorageMetadata.js';
import { resolveCallee, resolvePropertyAccess } from './resolveCallee.js';
import type { ResolvedCallee } from './resolveCallee.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

beforeAll(async () => {
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm',
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const JavaScript = await Language.load(wasmBuffer);
  parser.setLanguage(JavaScript);
});

/**
 * Parse code and find the first call_expression node (depth-first).
 */
function findFirstCallExpression(code: string) {
  const tree = parser.parse(code);
  const root = tree.rootNode;
  const node = findNodeOfType(root, 'call_expression');
  return { tree, node };
}

/**
 * Parse code and find the first member_expression node (for property access patterns).
 */
function findFirstMemberExpression(code: string) {
  const tree = parser.parse(code);
  const root = tree.rootNode;
  const node = findNodeOfType(root, 'member_expression');
  return { tree, node };
}

function findNodeOfType(
  node: import('web-tree-sitter').Node,
  type: string,
): import('web-tree-sitter').Node | null {
  if (node.type === type) return node;
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) {
      const found = findNodeOfType(child, type);
      if (found) return found;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// SQL table extraction
// ---------------------------------------------------------------------------

describe('SQL table extraction', () => {
  it('extracts table from SELECT ... FROM users', () => {
    const code = `db.query("SELECT * FROM users WHERE id = 1")`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'table', name: 'users' });
    tree.delete();
  });

  it('extracts table from INSERT INTO orders', () => {
    const code = `db.query("INSERT INTO orders (id, amount) VALUES (1, 100)")`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'table', name: 'orders' });
    tree.delete();
  });

  it('extracts table from UPDATE products', () => {
    const code = `db.query("UPDATE products SET price = 10 WHERE id = 1")`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'table', name: 'products' });
    tree.delete();
  });

  it('extracts table from template literal SQL', () => {
    const code = 'db.query(`SELECT * FROM accounts WHERE id = ${userId}`)';
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'table', name: 'accounts' });
    tree.delete();
  });

  it('extracts table from concatenated SQL (left side)', () => {
    const code = `db.query("SELECT * FROM sessions WHERE id = " + id)`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'table', name: 'sessions' });
    tree.delete();
  });
});

// ---------------------------------------------------------------------------
// MongoDB collection extraction
// ---------------------------------------------------------------------------

describe('MongoDB collection extraction', () => {
  it('extracts collection from db.collection("users").find()', () => {
    const code = `db.collection("users").find({ active: true })`;
    const { tree, node } = findFirstCallExpression(code);
    // The outer call_expression is .find() — resolveCallee should give us the chain
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'collection', name: 'users' });
    tree.delete();
  });

  it('extracts collection from db.collection("orders").insertOne()', () => {
    const code = `db.collection("orders").insertOne({ amount: 50 })`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'collection', name: 'orders' });
    tree.delete();
  });
});

// ---------------------------------------------------------------------------
// Prisma model extraction
// ---------------------------------------------------------------------------

describe('Prisma model extraction', () => {
  it('extracts model from prisma.user.create()', () => {
    const code = `prisma.user.create({ data: { name: "Alice" } })`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'model', name: 'user' });
    tree.delete();
  });

  it('extracts model from prisma.post.findMany()', () => {
    const code = `prisma.post.findMany({ where: { published: true } })`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'model', name: 'post' });
    tree.delete();
  });

  it('does NOT extract model from prisma.$queryRawUnsafe (raw query)', () => {
    const code = `prisma.$queryRawUnsafe("SELECT * FROM users")`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    // Should extract as table from SQL, not as model
    expect(result).not.toEqual(expect.objectContaining({ kind: 'model' }));
    tree.delete();
  });
});

// ---------------------------------------------------------------------------
// File path extraction
// ---------------------------------------------------------------------------

describe('File path extraction', () => {
  it('extracts file path from fs.writeFileSync()', () => {
    const code = `fs.writeFileSync("/tmp/data.json", JSON.stringify(data))`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'file', name: '/tmp/data.json' });
    tree.delete();
  });

  it('extracts file path from fs.readFileSync()', () => {
    const code = `fs.readFileSync("/etc/passwd", "utf8")`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'file', name: '/etc/passwd' });
    tree.delete();
  });
});

// ---------------------------------------------------------------------------
// Env var extraction
// ---------------------------------------------------------------------------

describe('Env var name extraction', () => {
  it('extracts env var name from process.env.DATABASE_URL chain', () => {
    // process.env.DATABASE_URL is a member_expression, not a call
    // We use resolvePropertyAccess for this
    const code = `const url = process.env.DATABASE_URL`;
    const { tree, node } = findFirstMemberExpression(code);
    const resolution = resolvePropertyAccess(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'env', name: 'DATABASE_URL' });
    tree.delete();
  });

  it('extracts env var from process.env.SECRET_KEY', () => {
    const code = `const key = process.env.SECRET_KEY`;
    const { tree, node } = findFirstMemberExpression(code);
    const resolution = resolvePropertyAccess(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toEqual({ kind: 'env', name: 'SECRET_KEY' });
    tree.delete();
  });
});

// ---------------------------------------------------------------------------
// Null for unrecognizable patterns
// ---------------------------------------------------------------------------

describe('Null for unrecognizable patterns', () => {
  it('returns null for console.log()', () => {
    const code = `console.log("hello world")`;
    const { tree, node } = findFirstCallExpression(code);
    const resolution = resolveCallee(node!);
    const result = extractStorageMetadata(node, resolution);
    expect(result).toBeNull();
    tree.delete();
  });

  it('returns null when resolution is null', () => {
    const code = `myCustomFunc(123)`;
    const { tree, node } = findFirstCallExpression(code);
    // myCustomFunc is unknown, resolveCallee returns null
    const result = extractStorageMetadata(node, null);
    expect(result).toBeNull();
    tree.delete();
  });
});

// ---------------------------------------------------------------------------
// Null node handling (property access patterns like process.env.X)
// ---------------------------------------------------------------------------

describe('Null node handling', () => {
  it('returns env var when node is null but resolution has chain', () => {
    const fakeResolution: ResolvedCallee = {
      nodeType: 'INGRESS',
      subtype: 'env_read',
      tainted: true,
      chain: ['process', 'env', 'API_KEY'],
    };
    const result = extractStorageMetadata(null, fakeResolution);
    expect(result).toEqual({ kind: 'env', name: 'API_KEY' });
  });

  it('returns null when both node and resolution are null', () => {
    const result = extractStorageMetadata(null, null);
    expect(result).toBeNull();
  });

  it('returns null when node is null for non-env resolution', () => {
    const fakeResolution: ResolvedCallee = {
      nodeType: 'STORAGE',
      subtype: 'db_read',
      tainted: false,
      chain: ['db', 'query'],
    };
    // Node is null so we can't extract SQL from args
    const result = extractStorageMetadata(null, fakeResolution);
    expect(result).toBeNull();
  });
});
