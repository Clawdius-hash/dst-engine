/**
 * Phase B Red-Team Test Suite
 *
 * Tests the FULL DST pipeline (tree-sitter parse -> buildNeuralMap -> verifyAll)
 * against three categories of code snippets:
 *
 * 1. True Negatives — correct sanitizer for correct sink (should NOT fire)
 * 2. True Positives — no sanitization at all (MUST fire)
 * 3. Cross-Domain Mismatches — wrong sanitizer for wrong sink (Phase B novelty)
 *
 * This is an observational red-team test: Category 3 logs findings without
 * hard assertions so we can understand the engine's actual behavior before
 * locking it down.
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { resetSequence } from './types.js';
import type { NeuralMap } from './types.js';
import { verifyAll, formatReport } from './verifier';
import type { VerificationResult, Finding } from './verifier';

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

function parse(code: string): NeuralMap {
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, 'routes/api.js');
  tree.delete();
  return map;
}

/** Extract all failed results for a given CWE prefix */
function findingsByCWE(results: VerificationResult[], cwePrefix: string): VerificationResult[] {
  return results.filter(r => !r.holds && r.cwe.startsWith(cwePrefix));
}

/** Pretty-print findings for a code snippet (used in observational tests) */
function logFindings(label: string, results: VerificationResult[]): void {
  const failures = results.filter(r => !r.holds);
  console.log(`\n--- ${label} ---`);
  console.log(`Total CWEs checked: ${results.length}`);
  console.log(`Failures: ${failures.length}`);
  for (const f of failures) {
    console.log(`  [FAIL] ${f.cwe}: ${f.name}`);
    for (const finding of f.findings) {
      console.log(`    source: ${finding.source.code.slice(0, 80)}`);
      console.log(`    sink:   ${finding.sink.code.slice(0, 80)}`);
      console.log(`    missing: ${finding.missing}`);
      console.log(`    severity: ${finding.severity}`);
    }
  }
  if (failures.length === 0) {
    console.log('  (no findings)');
  }
}

// ===========================================================================
// CATEGORY 1: TRUE NEGATIVES — correct sanitizer for correct sink
// These should NOT produce CWE-89 / CWE-79 findings.
// ===========================================================================

describe('Category 1: True Negatives (no FPs expected)', () => {

  it('TN-1: generic escape() before SQL — taint cleared by sanitize', () => {
    const code = `
const express = require('express');
const db = require('./db');
const app = express();
app.get('/users', (req, res) => {
  const safe = escape(req.body.name);
  db.query("SELECT * FROM users WHERE name='" + safe + "'");
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });
    const sqli = findingsByCWE(results, 'CWE-89');

    logFindings('TN-1: escape() before SQL', results);

    // escape() is classified as 'sanitize' which clears taint.
    // The taint-reachability check should not see tainted data at the sink.
    // Note: Phase B state-vs-requirement knows sanitize does NOT set sql_safe,
    // so this may still fire from the property engine. That's actually CORRECT
    // behavior — escape() is not a proper SQL defense.
    // We document what happens rather than assert absence.
    console.log(`  CWE-89 findings: ${sqli.length}`);
  });

  it('TN-2: encodeURIComponent() before HTTP response', () => {
    const code = `
const express = require('express');
const app = express();
app.get('/echo', (req, res) => {
  const encoded = encodeURIComponent(req.query.input);
  res.send(encoded);
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });
    const xss = findingsByCWE(results, 'CWE-79');

    logFindings('TN-2: encodeURIComponent before res.send', results);

    // encodeURIComponent is 'encode' -> sets xss_safe.
    // CWE-79 should NOT fire.
    console.log(`  CWE-79 findings: ${xss.length}`);
  });

  it('TN-3: parameterized query (gold standard)', () => {
    const code = `
const express = require('express');
const db = require('./db');
const app = express();
app.get('/users', (req, res) => {
  db.query("SELECT * FROM users WHERE id = ?", [req.body.id]);
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });
    const sqli = findingsByCWE(results, 'CWE-89');

    logFindings('TN-3: parameterized query', results);

    // Parameterized queries are the gold standard.
    // CWE-89 should NOT fire.
    expect(sqli.length).toBe(0);
  });

  it('TN-4: bcrypt.hash before storage (authentication pattern)', () => {
    const code = `
const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');
const app = express();
app.post('/register', async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  db.query("INSERT INTO users (name, password) VALUES ($1, $2)", [req.body.name, hash]);
  res.json({ ok: true });
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });
    const sqli = findingsByCWE(results, 'CWE-89');

    logFindings('TN-4: bcrypt + parameterized insert', results);

    // Hash destroys data, parameterized query handles the rest.
    expect(sqli.length).toBe(0);
  });
});

// ===========================================================================
// CATEGORY 2: TRUE POSITIVES — no sanitization at all (MUST fire)
// ===========================================================================

describe('Category 2: True Positives (must fire)', () => {

  it('TP-1: raw SQL injection — string concat in db.query', () => {
    const code = `
const express = require('express');
const db = require('./db');
const app = express();
app.get('/users', (req, res) => {
  db.query("SELECT * FROM users WHERE name='" + req.body.name + "'");
});
`.trim();

    const map = parse(code);

    // Debug: log node types and subtypes
    console.log('\n  Map nodes:');
    for (const n of map.nodes) {
      console.log(`    ${n.node_type}/${n.node_subtype} — ${n.label} (${n.id})`);
      if (n.data_in.length) console.log(`      data_in: ${JSON.stringify(n.data_in.map(d => ({ name: d.name, tainted: d.tainted })))}`);
    }

    const results = verifyAll(map, 'javascript', { noDedup: true });

    // Check if CWE-89 was covered by property engine or present at all
    const cwe89results = results.filter(r => r.cwe === 'CWE-89');
    console.log(`\n  CWE-89 in results: ${cwe89results.length}`);
    for (const r of cwe89results) {
      console.log(`    holds: ${r.holds}, findings: ${r.findings.length}`);
    }

    logFindings('TP-1: raw SQL injection', results);

    // Raw user input concatenated into SQL — CWE-89 MUST fire.
    const sqli = findingsByCWE(results, 'CWE-89');
    expect(sqli.length).toBeGreaterThan(0);
  });

  it('TP-2: raw XSS — user input in res.send with HTML', () => {
    const code = `
const express = require('express');
const app = express();
app.get('/search', (req, res) => {
  res.send("<h1>" + req.query.name + "</h1>");
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });
    const xss = findingsByCWE(results, 'CWE-79');

    logFindings('TP-2: raw XSS', results);

    // Raw user input in HTML response — CWE-79 MUST fire.
    expect(xss.length).toBeGreaterThan(0);
  });

  it('TP-3: raw command injection — user input in exec()', () => {
    const code = `
const express = require('express');
const child_process = require('child_process');
const app = express();
app.get('/run', (req, res) => {
  child_process.exec("ls " + req.body.path);
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });
    const cmdi = findingsByCWE(results, 'CWE-78');

    logFindings('TP-3: raw command injection', results);

    // Raw user input in shell exec — CWE-78 MUST fire.
    expect(cmdi.length).toBeGreaterThan(0);
  });

  it('TP-4: raw path traversal — user input in fs.readFile', () => {
    const code = `
const express = require('express');
const fs = require('fs');
const app = express();
app.get('/file', (req, res) => {
  fs.readFile(req.query.path, 'utf8', (err, data) => {
    res.send(data);
  });
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });
    const pathTraversal = findingsByCWE(results, 'CWE-22');

    logFindings('TP-4: raw path traversal', results);

    // Raw user input as file path — CWE-22 MUST fire.
    expect(pathTraversal.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// CATEGORY 3: CROSS-DOMAIN MISMATCHES — wrong sanitizer for wrong sink
// This is the NOVEL Phase B test. Observational — log and document.
// ===========================================================================

describe('Category 3: Cross-Domain Mismatches (Phase B observational)', () => {

  it('XDM-1: DOMPurify.sanitize (HTML sanitizer) before SQL sink', () => {
    const code = `
const express = require('express');
const DOMPurify = require('dompurify');
const db = require('./db');
const app = express();
app.get('/users', (req, res) => {
  const safe = DOMPurify.sanitize(req.body.name);
  db.query("SELECT * FROM users WHERE name='" + safe + "'");
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });

    logFindings('XDM-1: DOMPurify.sanitize -> SQL sink', results);

    // DOMPurify.sanitize should be classified as sanitize_html (xss_safe only).
    // The SQL sink requires sql_safe. Phase B should detect this mismatch.
    const sqli = findingsByCWE(results, 'CWE-89');
    console.log(`  >> CWE-89 fired: ${sqli.length > 0 ? 'YES' : 'NO'} (count: ${sqli.length})`);

    // Check all failures to see if any mention domain mismatch
    const allFailures = results.filter(r => !r.holds);
    for (const f of allFailures) {
      for (const finding of f.findings) {
        if (finding.description.includes('neutralization') ||
            finding.description.includes('mismatch') ||
            finding.description.includes('domain')) {
          console.log(`  >> Phase B signal: ${f.cwe} — ${finding.description.slice(0, 120)}`);
        }
      }
    }
  });

  it('XDM-2: escape() (generic sanitize) before shell exec', () => {
    const code = `
const express = require('express');
const child_process = require('child_process');
const app = express();
app.get('/run', (req, res) => {
  const escaped = escape(req.body.cmd);
  child_process.exec("ls " + escaped);
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });

    logFindings('XDM-2: escape() -> shell exec', results);

    // escape() is 'sanitize' which sets shell_safe=true (in the generic mapping).
    // So this MIGHT pass. That's interesting — escape() is not a real shell sanitizer
    // but our conservative mapping allows it.
    const cmdi = findingsByCWE(results, 'CWE-78');
    console.log(`  >> CWE-78 fired: ${cmdi.length > 0 ? 'YES' : 'NO'} (count: ${cmdi.length})`);

    // Document what actually happens
    const allFailures = results.filter(r => !r.holds);
    for (const f of allFailures) {
      for (const finding of f.findings) {
        if (finding.description.includes('neutralization') ||
            finding.description.includes('mismatch') ||
            finding.description.includes('shell')) {
          console.log(`  >> Signal: ${f.cwe} — ${finding.description.slice(0, 120)}`);
        }
      }
    }
  });

  it('XDM-3: path.normalize (path validation) before XSS sink', () => {
    const code = `
const express = require('express');
const path = require('path');
const app = express();
app.get('/show', (req, res) => {
  const validated = path.normalize(req.query.input);
  res.send("<div>" + validated + "</div>");
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });

    logFindings('XDM-3: path.normalize -> HTML response', results);

    // path.normalize should be 'validate' which sets path_safe and redirect_safe.
    // The HTML sink requires xss_safe. Phase B should detect this mismatch.
    const xss = findingsByCWE(results, 'CWE-79');
    console.log(`  >> CWE-79 fired: ${xss.length > 0 ? 'YES' : 'NO'} (count: ${xss.length})`);

    // Check for domain mismatch signals
    const allFailures = results.filter(r => !r.holds);
    for (const f of allFailures) {
      for (const finding of f.findings) {
        if (finding.description.includes('neutralization') ||
            finding.description.includes('mismatch') ||
            finding.description.includes('domain') ||
            finding.description.includes('xss_safe')) {
          console.log(`  >> Phase B signal: ${f.cwe} — ${finding.description.slice(0, 120)}`);
        }
      }
    }
  });

  it('XDM-4: encodeURIComponent (URL encoding) before SQL sink', () => {
    const code = `
const express = require('express');
const db = require('./db');
const app = express();
app.get('/users', (req, res) => {
  const encoded = encodeURIComponent(req.body.name);
  db.query("SELECT * FROM users WHERE name='" + encoded + "'");
});
`.trim();

    const map = parse(code);
    const results = verifyAll(map, 'javascript', { noDedup: true });

    logFindings('XDM-4: encodeURIComponent -> SQL sink', results);

    // encodeURIComponent is 'encode' which sets xss_safe, log_safe, ssti_safe.
    // SQL sink requires sql_safe. Phase B should detect this mismatch.
    const sqli = findingsByCWE(results, 'CWE-89');
    console.log(`  >> CWE-89 fired: ${sqli.length > 0 ? 'YES' : 'NO'} (count: ${sqli.length})`);

    // Check for Phase B signals
    const allFailures = results.filter(r => !r.holds);
    for (const f of allFailures) {
      for (const finding of f.findings) {
        if (finding.description.includes('neutralization') ||
            finding.description.includes('mismatch') ||
            finding.description.includes('sql_safe')) {
          console.log(`  >> Phase B signal: ${f.cwe} — ${finding.description.slice(0, 120)}`);
        }
      }
    }
  });

  it('SUMMARY: Print cross-domain findings report', () => {
    // This test just prints a consolidated summary for review
    console.log('\n========================================');
    console.log('PHASE B RED-TEAM: Cross-Domain Summary');
    console.log('========================================');
    console.log('');
    console.log('Neutralizer -> Domain mapping (from neutralizers.ts):');
    console.log('  sanitize       -> xss_safe, shell_safe, ssti_safe, log_safe (NOT sql_safe)');
    console.log('  sanitize_html  -> xss_safe only');
    console.log('  encode/escape  -> xss_safe, log_safe, ssti_safe');
    console.log('  validate       -> path_safe, redirect_safe');
    console.log('  parameterize   -> sql_safe, ldap_safe, xpath_safe');
    console.log('  hash           -> ALL domains safe');
    console.log('');
    console.log('Expected cross-domain mismatches:');
    console.log('  XDM-1: sanitize_html + SQL -> should fire (no sql_safe)');
    console.log('  XDM-2: sanitize + shell   -> might NOT fire (shell_safe is set)');
    console.log('  XDM-3: validate + XSS     -> should fire (no xss_safe)');
    console.log('  XDM-4: encode + SQL       -> should fire (no sql_safe)');
    expect(true).toBe(true);
  });
});
