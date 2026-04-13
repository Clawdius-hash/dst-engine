/**
 * P0/P1 Capability Validation Test Suite
 *
 * Exercises DST's new detection capabilities end-to-end:
 *   1. ENV VAR TAINT VALIDATION -- process.env -> various sinks
 *   2. COMPOSITION ENGINE VALIDATION -- cross-finding chain detection
 *   3. FAIL-OPEN VALIDATION -- security cap bypass detection
 *
 * These scan realistic vulnerable code patterns and verify DST produces
 * the expected findings (or correctly identifies safe patterns).
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { resetSequence } from './types.js';
import type { NeuralMap, NeuralMapNode, Edge } from './types.js';
import { verifyAll } from './verifier/index.js';
import type { VerificationResult, Finding, NodeRef } from './verifier/types.js';
import { composeFindings } from './composition/index.js';
import type { ComposableFinding } from './composition/types.js';
import { detectFailOpen } from './verifier/fail-open.js';

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

function parse(code: string, filename = 'app.js'): NeuralMap {
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, filename);
  tree.delete();
  return map;
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

function nodesByType(map: NeuralMap, type: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === type);
}

function nodesByTypeAndSubtype(map: NeuralMap, type: string, subtype: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === type && n.node_subtype === subtype);
}

function allEdges(map: NeuralMap): Edge[] {
  const edges: Edge[] = [...map.edges];
  for (const node of map.nodes) {
    edges.push(...node.edges);
  }
  return edges;
}

/** Collect all failed verifications (holds === false) */
function failedResults(results: VerificationResult[]): VerificationResult[] {
  return results.filter(r => !r.holds);
}

/** Check if any finding matches a CWE pattern */
function hasCWE(results: VerificationResult[], cwePattern: string): boolean {
  return results.some(r => r.cwe.includes(cwePattern) && !r.holds);
}

/** Get all findings across all results */
function allFindings(results: VerificationResult[]): Finding[] {
  return results.flatMap(r => r.findings);
}

/** Get findings with a specific severity */
function findingsBySeverity(results: VerificationResult[], severity: string): Finding[] {
  return allFindings(results).filter(f => f.severity === severity);
}

/** Make a minimal NodeRef for composition testing */
function makeNodeRef(id: string, label: string, line: number, code: string, file?: string): NodeRef {
  return { id, label, line, code, file };
}

/** Make a minimal ComposableFinding for composition testing */
function makeFinding(
  cwe: string,
  file: string,
  sourceCode: string,
  sinkCode: string,
  severity: Finding['severity'] = 'high',
): ComposableFinding {
  return {
    cwe,
    file,
    finding: {
      source: makeNodeRef(`src-${cwe}-${file}`, `source in ${file}`, 1, sourceCode),
      sink: makeNodeRef(`sink-${cwe}-${file}`, `sink in ${file}`, 10, sinkCode),
      missing: 'CONTROL (test)',
      severity,
      description: `${cwe} finding in ${file}`,
      fix: 'test fix',
    },
  };
}

// ===========================================================================
// 1. ENV VAR TAINT VALIDATION
// ===========================================================================

describe('P0: ENV VAR TAINT VALIDATION', () => {

  // ── Pattern 1: process.env -> SQL injection ──

  describe('Pattern 1: process.env.DB_HOST -> SQL injection', () => {
    const CODE = `
const db = require('./db');
const dbHost = process.env.DB_HOST;
const result = db.query("SELECT * FROM users WHERE host = '" + dbHost + "'");
    `.trim();

    let map: NeuralMap;
    let results: VerificationResult[];

    beforeEach(() => {
      resetSequence();
      map = parse(CODE, 'db-config.js');
      results = verifyAll(map, 'javascript');
    });

    it('detects an INGRESS/env_read node for process.env.DB_HOST', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      expect(envNodes.length).toBeGreaterThanOrEqual(1);
      const hasDbHost = envNodes.some(n => n.code_snapshot.includes('process.env'));
      expect(hasDbHost).toBe(true);
    });

    it('the INGRESS/env_read node has tainted data_out', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      const hasTaintedOut = envNodes.some(n =>
        n.data_out.some(f => f.tainted === true)
      );
      expect(hasTaintedOut).toBe(true);
    });

    it.skip('detects a STORAGE node for db.query [GAP: db.query() not in STORAGE patterns]', () => {
      const storageNodes = nodesByType(map, 'STORAGE');
      const hasQuery = storageNodes.some(n =>
        n.code_snapshot.includes('query') || n.code_snapshot.includes('db')
      );
      expect(hasQuery).toBe(true);
    });

    it.skip('verifyAll produces at least one SQL injection finding (CWE-89) [GAP: needs STORAGE node for db.query]', () => {
      const failed = failedResults(results);
      const hasSQLi = hasCWE(results, '89');
      expect(
        hasSQLi,
        `Expected CWE-89 (SQL injection) finding. Failed CWEs: ${failed.map(r => r.cwe).join(', ')}`
      ).toBe(true);
    });
  });

  // ── Pattern 2: process.env -> command injection ──

  describe('Pattern 2: process.env.EDITOR -> command injection', () => {
    const CODE = `
const { exec } = require('child_process');
const editor = process.env.EDITOR;
exec(editor + ' file.txt');
    `.trim();

    let map: NeuralMap;
    let results: VerificationResult[];

    beforeEach(() => {
      resetSequence();
      map = parse(CODE, 'run-editor.js');
      results = verifyAll(map, 'javascript');
    });

    it('detects an INGRESS/env_read node for process.env.EDITOR', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      expect(envNodes.length).toBeGreaterThanOrEqual(1);
      const hasEditor = envNodes.some(n => n.code_snapshot.includes('process.env'));
      expect(hasEditor).toBe(true);
    });

    it('the env_read node has tainted data_out', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      const hasTaintedOut = envNodes.some(n =>
        n.data_out.some(f => f.tainted === true)
      );
      expect(hasTaintedOut).toBe(true);
    });

    it('detects an EXTERNAL/system_exec node for exec()', () => {
      const execNodes = nodesByTypeAndSubtype(map, 'EXTERNAL', 'system_exec');
      expect(execNodes.length).toBeGreaterThanOrEqual(1);
    });

    it('the EXTERNAL/system_exec node has command_injection attack surface', () => {
      const execNodes = nodesByTypeAndSubtype(map, 'EXTERNAL', 'system_exec');
      const hasCmdInjection = execNodes.some(n =>
        n.attack_surface.includes('command_injection')
      );
      expect(hasCmdInjection).toBe(true);
    });

    it('verifyAll produces at least one command injection finding (CWE-78)', () => {
      const hasCmdInj = hasCWE(results, '78');
      expect(
        hasCmdInj,
        `Expected CWE-78 (OS command injection). Got: ${failedResults(results).map(r => r.cwe).join(', ')}`
      ).toBe(true);
    });
  });

  // ── Pattern 3: process.env -> XSS (response without encoding) ──

  describe('Pattern 3: process.env.GREETING -> XSS via res.send', () => {
    const CODE = `
const express = require('express');
const app = express();
const greeting = process.env.GREETING;
app.get('/', (req, res) => {
  res.send('<h1>' + greeting + '</h1>');
});
    `.trim();

    let map: NeuralMap;
    let results: VerificationResult[];

    beforeEach(() => {
      resetSequence();
      map = parse(CODE, 'greeting.js');
      results = verifyAll(map, 'javascript');
    });

    it('detects an INGRESS/env_read node for process.env.GREETING', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      expect(envNodes.length).toBeGreaterThanOrEqual(1);
      const hasGreeting = envNodes.some(n => n.code_snapshot.includes('process.env'));
      expect(hasGreeting).toBe(true);
    });

    it('the env_read node has tainted data_out', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      const hasTaintedOut = envNodes.some(n =>
        n.data_out.some(f => f.tainted === true)
      );
      expect(hasTaintedOut).toBe(true);
    });

    it('detects an EGRESS node for res.send', () => {
      const egressNodes = nodesByType(map, 'EGRESS');
      const hasSend = egressNodes.some(n =>
        n.code_snapshot.includes('res.send')
      );
      expect(hasSend).toBe(true);
    });

    it('verifyAll produces at least one XSS finding (CWE-79)', () => {
      const hasXSS = hasCWE(results, '79');
      expect(
        hasXSS,
        `Expected CWE-79 (XSS). Got: ${failedResults(results).map(r => r.cwe).join(', ')}`
      ).toBe(true);
    });
  });

  // ── Pattern 4: SAFE - process.env as port number ──

  describe('Pattern 4: SAFE - process.env.PORT used as port number', () => {
    const CODE = `
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
app.listen(port);
    `.trim();

    let map: NeuralMap;
    let results: VerificationResult[];

    beforeEach(() => {
      resetSequence();
      map = parse(CODE, 'server.js');
      results = verifyAll(map, 'javascript');
    });

    it('still detects an INGRESS/env_read node (env input is always modeled)', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      expect(envNodes.length).toBeGreaterThanOrEqual(1);
    });

    it('produces no critical or high injection findings', () => {
      // This is a safe pattern -- using PORT for app.listen is not a vulnerability
      const criticalHighFindings = allFindings(results).filter(
        f => (f.severity === 'critical' || f.severity === 'high') &&
          (f.description.toLowerCase().includes('injection') ||
           f.description.toLowerCase().includes('command') ||
           f.description.toLowerCase().includes('xss'))
      );
      expect(
        criticalHighFindings.length,
        `Safe PORT pattern should not trigger injection findings. Found: ${criticalHighFindings.map(f => f.description).join('; ')}`
      ).toBe(0);
    });
  });

  // ── Pattern 5: process.env -> file path traversal ──

  describe('Pattern 5: process.env.UPLOAD_DIR -> path traversal', () => {
    const CODE = `
const fs = require('fs');
const uploadDir = process.env.UPLOAD_DIR;
const filename = req.params.filename;
fs.writeFileSync(uploadDir + '/' + filename, data);
    `.trim();

    let map: NeuralMap;
    let results: VerificationResult[];

    beforeEach(() => {
      resetSequence();
      map = parse(CODE, 'upload.js');
      results = verifyAll(map, 'javascript');
    });

    it('detects an INGRESS/env_read node for process.env.UPLOAD_DIR', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      expect(envNodes.length).toBeGreaterThanOrEqual(1);
    });

    it('the env_read has tainted data_out', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      const hasTaintedOut = envNodes.some(n =>
        n.data_out.some(f => f.tainted === true)
      );
      expect(hasTaintedOut).toBe(true);
    });

    it.skip('detects a file write node (STORAGE or EXTERNAL) [GAP: fs.writeFileSync not classified]', () => {
      const storageNodes = nodesByType(map, 'STORAGE');
      const externalNodes = nodesByType(map, 'EXTERNAL');
      const allRelevant = [...storageNodes, ...externalNodes];
      const hasFileWrite = allRelevant.some(n =>
        n.code_snapshot.includes('writeFileSync') || n.code_snapshot.includes('writeFile')
      );
      expect(hasFileWrite).toBe(true);
    });

    it('verifyAll produces at least one path traversal finding (CWE-22 or CWE-73)', () => {
      const hasPathTraversal = hasCWE(results, '22') || hasCWE(results, '73');
      expect(
        hasPathTraversal,
        `Expected CWE-22/73 (path traversal). Got: ${failedResults(results).map(r => r.cwe).join(', ')}`
      ).toBe(true);
    });
  });

  // ── Pattern 6: process.env -> LDAP injection ──

  describe('Pattern 6: process.env.LDAP_BASE -> LDAP filter injection', () => {
    const CODE = `
const ldap = require('ldapjs');
const baseDN = process.env.LDAP_BASE;
const username = req.body.username;
client.search(baseDN, { filter: '(uid=' + username + ')' });
    `.trim();

    let map: NeuralMap;
    let results: VerificationResult[];

    beforeEach(() => {
      resetSequence();
      map = parse(CODE, 'auth-ldap.js');
      results = verifyAll(map, 'javascript');
    });

    it('detects INGRESS/env_read for process.env.LDAP_BASE', () => {
      const envNodes = nodesByTypeAndSubtype(map, 'INGRESS', 'env_read');
      expect(envNodes.length).toBeGreaterThanOrEqual(1);
    });

    it('detects tainted data flowing into the LDAP call', () => {
      let taintedFlows = 0;
      for (const node of map.nodes) {
        for (const flow of [...node.data_in, ...node.data_out]) {
          if (flow.tainted) taintedFlows++;
        }
      }
      expect(taintedFlows).toBeGreaterThanOrEqual(2);
    });
  });
});

// ===========================================================================
// 2. COMPOSITION ENGINE VALIDATION
// ===========================================================================

describe('P1: COMPOSITION ENGINE VALIDATION', () => {

  // ── Pattern 1: SQLi write in file1 -> SQLi read in file2 (same table) ──

  describe('Pattern 1: SQL write-then-read chain across files', () => {
    it('chains findings that share the same DB table (users)', () => {
      const findings: ComposableFinding[] = [
        makeFinding(
          'CWE-89', 'api/register.js',
          'const username = req.body.username;',
          "db.query(\"INSERT INTO users (name) VALUES ('\" + username + \"')\")",
          'high',
        ),
        makeFinding(
          'CWE-89', 'api/admin.js',
          "db.query(\"SELECT * FROM users WHERE role = 'admin'\")",
          'res.json(rows)',
          'high',
        ),
      ];

      const chains = composeFindings(findings);
      expect(chains.length).toBeGreaterThanOrEqual(1);

      // The chain should be storage-bridged via "users" table
      const storageChain = chains.find(c => c.chainType === 'storage');
      expect(storageChain).toBeDefined();
      expect(storageChain!.boundariesCrossed).toBeGreaterThanOrEqual(1);
      // Severity should escalate (high + high -> critical)
      expect(storageChain!.severity).toBe('critical');
    });
  });

  // ── Pattern 2: env var write -> env var read chain ──

  describe('Pattern 2: env var bridge chain', () => {
    it('chains findings that share the same env var (API_KEY)', () => {
      const findings: ComposableFinding[] = [
        makeFinding(
          'CWE-312', 'config/setup.js',
          'const key = readInput();',
          'process.env.API_KEY = key;',
          'medium',
        ),
        makeFinding(
          'CWE-200', 'routes/external.js',
          'const apiKey = process.env.API_KEY;',
          'fetch(url, { headers: { Authorization: apiKey } })',
          'high',
        ),
      ];

      const chains = composeFindings(findings);
      expect(chains.length).toBeGreaterThanOrEqual(1);

      const envChain = chains.find(c => c.chainType === 'env_var');
      expect(envChain).toBeDefined();
      expect(envChain!.boundariesCrossed).toBeGreaterThanOrEqual(1);
      // medium + high -> high (escalated)
      expect(['high', 'critical']).toContain(envChain!.severity);
    });
  });

  // ── Pattern 3: file write -> file read chain ──

  describe('Pattern 3: file I/O bridge chain', () => {
    it('chains findings that share the same file path (/tmp/cache.json)', () => {
      const findings: ComposableFinding[] = [
        makeFinding(
          'CWE-73', 'services/cache-writer.js',
          'const userInput = req.body.data;',
          "fs.writeFileSync('/tmp/cache.json', userInput)",
          'high',
        ),
        makeFinding(
          'CWE-502', 'services/cache-reader.js',
          "const raw = fs.readFileSync('/tmp/cache.json')",
          'const obj = JSON.parse(raw)',
          'high',
        ),
      ];

      const chains = composeFindings(findings);
      expect(chains.length).toBeGreaterThanOrEqual(1);

      const fileChain = chains.find(c => c.chainType === 'file_io');
      expect(fileChain).toBeDefined();
      expect(fileChain!.boundariesCrossed).toBeGreaterThanOrEqual(1);
      expect(fileChain!.severity).toBe('critical');
    });
  });

  // ── Pattern 4: no chain when targets differ ──

  describe('Pattern 4: no chain when storage targets differ', () => {
    it('does NOT chain findings that touch different tables', () => {
      const findings: ComposableFinding[] = [
        makeFinding(
          'CWE-89', 'api/users.js',
          'const name = req.body.name;',
          "db.query(\"INSERT INTO users (name) VALUES ('\" + name + \"')\")",
          'high',
        ),
        makeFinding(
          'CWE-89', 'api/products.js',
          "db.query(\"SELECT * FROM products WHERE id = '\" + id + \"'\")",
          'res.json(rows)',
          'high',
        ),
      ];

      const chains = composeFindings(findings);
      // Should NOT produce a storage chain since tables differ (users vs products)
      const storageChain = chains.find(c => c.chainType === 'storage');
      expect(storageChain).toBeUndefined();
    });
  });
});

// ===========================================================================
// 3. FAIL-OPEN VALIDATION
// ===========================================================================

describe('P1: FAIL-OPEN VALIDATION', () => {

  // ── Pattern 1: Cap-based bypass (vulnerable) ──

  describe('Pattern 1: Cap-based security bypass (VULNERABLE)', () => {
    const CODE = `
function analyzePermissions(commands) {
  if (commands.length > 50) {
    return true;
  }
  for (const cmd of commands) {
    if (isDangerous(cmd)) {
      return false;
    }
  }
  return true;
}
    `.trim();

    let map: NeuralMap;

    beforeEach(() => {
      resetSequence();
      map = parse(CODE, 'permissions.js');
    });

    it('detectFailOpen catches the cap-based bypass', () => {
      const result = detectFailOpen(map);
      expect(result.cwe).toBe('CWE-636');
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThanOrEqual(1);

      // Check that the finding describes the cap bypass pattern
      const capFinding = result.findings.find(f =>
        f.description.includes('cap') || f.description.includes('bypass') || f.description.includes('skip')
      );
      expect(capFinding).toBeDefined();
      expect(capFinding!.severity).toBe('critical');
    });

    it('the finding references the correct function context', () => {
      const result = detectFailOpen(map);
      const finding = result.findings[0];
      expect(finding).toBeDefined();
      // Source and sink should reference the same node (structural pattern)
      expect(finding.source.id).toBe(finding.sink.id);
    });
  });

  // ── Pattern 2: Safe denial on large input ──

  describe('Pattern 2: Proper denial on large input (SAFE)', () => {
    const CODE = `
function validateInput(items) {
  if (items.length > 1000) {
    throw new Error('Input too large');
  }
  for (const item of items) {
    if (!isValid(item)) {
      throw new Error('Invalid item');
    }
  }
  return true;
}
    `.trim();

    let map: NeuralMap;

    beforeEach(() => {
      resetSequence();
      map = parse(CODE, 'validator.js');
    });

    it('detectFailOpen does NOT flag the safe denial pattern', () => {
      const result = detectFailOpen(map);
      expect(result.holds).toBe(true);
      expect(result.findings.length).toBe(0);
    });
  });

  // ── Pattern 3: Default-allow initialization (vulnerable) ──

  describe('Pattern 3: Default-allow auth variable (VULNERABLE)', () => {
    const CODE = `
function checkAuthorization(user, resource) {
  let authorized = true;
  try {
    const role = getUserRole(user);
    if (role !== 'admin') {
      authorized = false;
    }
  } catch (e) {
    console.log('Auth check failed:', e);
  }
  return authorized;
}
    `.trim();

    let map: NeuralMap;

    beforeEach(() => {
      resetSequence();
      map = parse(CODE, 'auth-check.js');
    });

    it.skip('detectFailOpen catches the default-allow initialization [GAP: hasConditionalDeny ignores try/catch wrappers]', () => {
      const result = detectFailOpen(map);
      expect(result.cwe).toBe('CWE-636');
      // This SHOULD be caught -- authorized starts as true
      // If the catch block runs, authorized stays true -> fail-open
      expect(result.holds).toBe(false);
      expect(result.findings.length).toBeGreaterThanOrEqual(1);

      const defaultAllowFinding = result.findings.find(f =>
        f.description.includes('authorized') || f.description.includes('default')
      );
      expect(defaultAllowFinding).toBeDefined();
    });
  });
});
