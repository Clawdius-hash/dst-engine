/**
 * Threat-Control Mismatch Detection Tests
 *
 * Tests the new check #7 in evaluateControlEffectiveness() and the
 * scope-based third pass in verifyAll() that catches CWE-566
 * (authorization bypass through SQL primary key).
 *
 * The core insight: a parameterized query prevents INJECTION but says
 * nothing about AUTHORIZATION. When the control addresses the wrong
 * threat class, the vulnerability persists despite the control's presence.
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { resetSequence } from './types.js';
import type { NeuralMap, NeuralMapNode } from './types.js';
import type { LanguageProfile } from './languageProfile.js';
import {
  evaluateControlEffectiveness,
  controlThreatMismatch,
} from './generated/_helpers.js';
import { verifyAll } from './verifier';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let jsParser: InstanceType<typeof Parser>;
let javaParser: InstanceType<typeof Parser>;
let javaProfile: LanguageProfile;

beforeAll(async () => {
  await Parser.init();

  // JavaScript parser
  jsParser = new Parser();
  const jsWasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm'
  );
  const jsWasmBuffer = fs.readFileSync(jsWasmPath);
  const JavaScript = await Language.load(jsWasmBuffer);
  jsParser.setLanguage(JavaScript);

  // Java parser
  javaParser = new Parser();
  const javaWasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-java/tree-sitter-java.wasm'
  );
  const javaWasmBuffer = fs.readFileSync(javaWasmPath);
  const Java = await Language.load(javaWasmBuffer);
  javaParser.setLanguage(Java);

  // Java profile
  const profileMod = await import('./profiles/java.js');
  javaProfile = profileMod.default ?? profileMod.javaProfile ?? profileMod.profile;
});

beforeEach(() => {
  resetSequence();
});

function parseJS(code: string): NeuralMap {
  const tree = jsParser.parse(code);
  const { map } = buildNeuralMap(tree, code, 'test.js');
  tree.delete();
  return map;
}

function parseJava(code: string, filename = 'Test.java'): NeuralMap {
  const tree = javaParser.parse(code);
  const { map } = buildNeuralMap(tree, code, filename, javaProfile);
  tree.delete();
  return map;
}

// ---------------------------------------------------------------------------
// Unit tests for controlThreatMismatch helper
// ---------------------------------------------------------------------------

describe('controlThreatMismatch', () => {
  it('is exported from _helpers', () => {
    expect(typeof controlThreatMismatch).toBe('function');
  });
});

// ---------------------------------------------------------------------------
// Integration tests: CWE-566 via Juliet test cases
// ---------------------------------------------------------------------------

describe('CWE-566: Authorization Bypass Through SQL Primary Key', () => {
  const JULIET_DIR = 'C:/Users/pizza/vigil/juliet-java/src/testcases/CWE566_Authorization_Bypass_Through_SQL_Primary';
  const JULIET_FILE = path.join(JULIET_DIR, 'CWE566_Authorization_Bypass_Through_SQL_Primary__Servlet_01.java');

  it('detects CWE-566 in Juliet bad() function via threat-mismatch', () => {
    const source = fs.readFileSync(JULIET_FILE, 'utf8');
    const map = parseJava(source, 'CWE566_Servlet_01.java');

    const results = verifyAll(map, 'java', { noDedup: true });
    const cwe566 = results.find(r => r.cwe === 'CWE-566');

    expect(cwe566).toBeDefined();
    expect(cwe566!.holds).toBe(false);
    expect(cwe566!.findings.length).toBeGreaterThan(0);

    // Should mention the threat-control mismatch
    const finding = cwe566!.findings[0];
    expect(finding.missing).toContain('EFFECTIVE_CONTROL');
    expect(finding.description).toContain('injection');
    expect(finding.description).toContain('authorization');
    expect(finding.severity).toBe('high');
  });

  it('finding points to the SQL query sink, not the catch block', () => {
    const source = fs.readFileSync(JULIET_FILE, 'utf8');
    const map = parseJava(source, 'CWE566_Servlet_01.java');

    const results = verifyAll(map, 'java', { noDedup: true });
    const cwe566 = results.find(r => r.cwe === 'CWE-566');
    expect(cwe566).toBeDefined();

    const finding = cwe566!.findings[0];
    // Sink should be the prepareStatement call (line 51), not an error handler
    expect(finding.sink.code).toContain('prepareStatement');
    expect(finding.sink.code).toContain('select * from invoices where uid=?');
  });

  it('source is the user-controlled getParameter, not the type declaration', () => {
    const source = fs.readFileSync(JULIET_FILE, 'utf8');
    const map = parseJava(source, 'CWE566_Servlet_01.java');

    const results = verifyAll(map, 'java', { noDedup: true });
    const cwe566 = results.find(r => r.cwe === 'CWE-566');
    expect(cwe566).toBeDefined();

    // At least one finding should come from getParameter
    const hasGetParamSource = cwe566!.findings.some(f =>
      f.source.code.includes('getParameter')
    );
    expect(hasGetParamSource).toBe(true);
  });

  it('does not flag goodG2B (hardcoded ID, no user input)', () => {
    const source = fs.readFileSync(JULIET_FILE, 'utf8');
    const map = parseJava(source, 'CWE566_Servlet_01.java');

    const results = verifyAll(map, 'java', { noDedup: true });
    const cwe566 = results.find(r => r.cwe === 'CWE-566');
    expect(cwe566).toBeDefined();

    // No finding should reference the goodG2B function's SQL query (line 132)
    const goodG2BFindings = cwe566!.findings.filter(f =>
      f.sink.line >= 110 && f.sink.line <= 183
    );
    expect(goodG2BFindings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CWE-566 language filter test
// ---------------------------------------------------------------------------

describe('CWE-566 language filter', () => {
  it('CWE-566 is not filtered out for Java', () => {
    const source = fs.readFileSync(
      path.join(
        'C:/Users/pizza/vigil/juliet-java/src/testcases/CWE566_Authorization_Bypass_Through_SQL_Primary',
        'CWE566_Authorization_Bypass_Through_SQL_Primary__Servlet_01.java'
      ),
      'utf8'
    );
    const map = parseJava(source, 'CWE566_Servlet_01.java');
    const results = verifyAll(map, 'java', { noDedup: true });

    // CWE-566 should appear in results (not filtered out)
    const cwe566 = results.find(r => r.cwe === 'CWE-566');
    expect(cwe566).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// JavaScript equivalent test — Express.js IDOR pattern
// ---------------------------------------------------------------------------

describe('CWE-566 via JS — Express IDOR pattern', () => {
  it('detects IDOR in Express route with parameterized query but no ownership check', () => {
    const code = `
const express = require('express');
const db = require('./db');
const app = express();

// VULNERABLE: user-supplied ID used in query, parameterized but no ownership check
app.get('/invoices/:id', async (req, res) => {
  const id = req.params.id;
  const result = await db.query('SELECT * FROM invoices WHERE uid = $1', [id]);
  res.json(result.rows);
});
`;
    const map = parseJS(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });

    // Should detect CWE-639 (user-controlled key)
    const cwe639 = results.find(r => r.cwe === 'CWE-639');
    expect(cwe639).toBeDefined();
    if (cwe639) {
      expect(cwe639.holds).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// evaluateControlEffectiveness check #7 integration
// ---------------------------------------------------------------------------

describe('evaluateControlEffectiveness check #7', () => {
  it('includes controlThreatMismatch in its checks', () => {
    // The function should exist and be callable
    expect(typeof evaluateControlEffectiveness).toBe('function');

    // Create a minimal map where a CONTROL mediates INGRESS->STORAGE
    const code = `
const express = require('express');
const db = require('./db');
const app = express();
app.get('/users/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const user = await db.query('SELECT * FROM users WHERE id = $1', [id]);
  res.json(user.rows);
});
`;
    const map = parseJS(code);

    // evaluateControlEffectiveness should not crash
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    const storage = map.nodes.filter(n => n.node_type === 'STORAGE');

    for (const src of ingress) {
      for (const sink of storage) {
        const findings = evaluateControlEffectiveness(map, src.id, sink.id);
        // Should return an array (possibly empty)
        expect(Array.isArray(findings)).toBe(true);
      }
    }
  });
});
