import { describe, it, expect } from 'vitest';
import { extractStorageTarget } from './extract-target.js';

describe('extractStorageTarget', () => {
  // ── SQL ────────────────────────────────────────────────────────────────────

  describe('SQL patterns', () => {
    it('extracts table from INSERT INTO', () => {
      const r = extractStorageTarget('db.query("INSERT INTO users VALUES ($1, $2)")');
      expect(r).toEqual({ kind: 'storage', name: 'users' });
    });

    it('extracts table from INSERT INTO with backtick-quoted name', () => {
      const r = extractStorageTarget('db.query("INSERT INTO `audit_log` (msg) VALUES (?)")');
      expect(r).toEqual({ kind: 'storage', name: 'audit_log' });
    });

    it('extracts table from SELECT ... FROM', () => {
      const r = extractStorageTarget('db.query("SELECT id, name FROM accounts WHERE id = $1")');
      expect(r).toEqual({ kind: 'storage', name: 'accounts' });
    });

    it('extracts table from UPDATE', () => {
      const r = extractStorageTarget('db.query("UPDATE sessions SET active = false WHERE id = $1")');
      expect(r).toEqual({ kind: 'storage', name: 'sessions' });
    });

    it('extracts table from DELETE FROM', () => {
      const r = extractStorageTarget('db.query("DELETE FROM tokens WHERE expired = true")');
      expect(r).toEqual({ kind: 'storage', name: 'tokens' });
    });

    it('handles case-insensitive SQL keywords', () => {
      const r = extractStorageTarget('db.query("select * from Users where 1=1")');
      expect(r).toEqual({ kind: 'storage', name: 'Users' });
    });
  });

  // ── MongoDB ────────────────────────────────────────────────────────────────

  describe('MongoDB patterns', () => {
    it('extracts collection name from .collection()', () => {
      const r = extractStorageTarget('db.collection("users").insertOne(doc)');
      expect(r).toEqual({ kind: 'storage', name: 'users' });
    });

    it('handles single-quoted collection name', () => {
      const r = extractStorageTarget("db.collection('orders').find({})");
      expect(r).toEqual({ kind: 'storage', name: 'orders' });
    });
  });

  // ── Prisma ─────────────────────────────────────────────────────────────────

  describe('Prisma patterns', () => {
    it('extracts model from prisma.model.method', () => {
      const r = extractStorageTarget('await prisma.user.create({ data })');
      expect(r).toEqual({ kind: 'storage', name: 'user' });
    });

    it('extracts model from prisma.model.findMany', () => {
      const r = extractStorageTarget('const items = await prisma.product.findMany()');
      expect(r).toEqual({ kind: 'storage', name: 'product' });
    });
  });

  // ── File I/O ───────────────────────────────────────────────────────────────

  describe('File I/O patterns', () => {
    it('extracts path from writeFile', () => {
      const r = extractStorageTarget('fs.writeFile("/tmp/data.json", content, cb)');
      expect(r).toEqual({ kind: 'file_io', name: '/tmp/data.json' });
    });

    it('extracts path from writeFileSync', () => {
      const r = extractStorageTarget('fs.writeFileSync("/etc/config.yml", yaml)');
      expect(r).toEqual({ kind: 'file_io', name: '/etc/config.yml' });
    });

    it('extracts path from readFile', () => {
      const r = extractStorageTarget('fs.readFile("/var/log/app.log", "utf8", cb)');
      expect(r).toEqual({ kind: 'file_io', name: '/var/log/app.log' });
    });

    it('extracts path from readFileSync', () => {
      const r = extractStorageTarget('const data = fs.readFileSync("/secrets/key.pem", "utf8")');
      expect(r).toEqual({ kind: 'file_io', name: '/secrets/key.pem' });
    });

    it('extracts path from createWriteStream', () => {
      const r = extractStorageTarget('const ws = fs.createWriteStream("/tmp/output.csv")');
      expect(r).toEqual({ kind: 'file_io', name: '/tmp/output.csv' });
    });

    it('extracts path from createReadStream', () => {
      const r = extractStorageTarget('const rs = fs.createReadStream("/data/input.csv")');
      expect(r).toEqual({ kind: 'file_io', name: '/data/input.csv' });
    });
  });

  // ── Env vars ───────────────────────────────────────────────────────────────

  describe('Env var patterns', () => {
    it('extracts env var from process.env.NAME', () => {
      const r = extractStorageTarget('const secret = process.env.JWT_SECRET');
      expect(r).toEqual({ kind: 'env_var', name: 'JWT_SECRET' });
    });

    it('extracts env var from process.env["NAME"]', () => {
      const r = extractStorageTarget('const key = process.env["API_KEY"]');
      expect(r).toEqual({ kind: 'env_var', name: 'API_KEY' });
    });

    it('extracts env var from assignment', () => {
      const r = extractStorageTarget('process.env.NODE_ENV = "production"');
      expect(r).toEqual({ kind: 'env_var', name: 'NODE_ENV' });
    });
  });

  // ── Edge cases / null returns ──────────────────────────────────────────────

  describe('unrecognizable patterns return null', () => {
    it('returns null for console.log', () => {
      expect(extractStorageTarget('console.log("hello")')).toBeNull();
    });

    it('returns null for plain arithmetic', () => {
      expect(extractStorageTarget('const x = a + b')).toBeNull();
    });

    it('returns null for function declarations', () => {
      expect(extractStorageTarget('function handleRequest(req, res) {')).toBeNull();
    });

    it('returns null for empty string', () => {
      expect(extractStorageTarget('')).toBeNull();
    });

    it('returns null for variable assignment', () => {
      expect(extractStorageTarget('const data = JSON.parse(body)')).toBeNull();
    });
  });
});
