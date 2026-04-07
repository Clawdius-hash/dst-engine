/**
 * End-to-end test: DVNA-style vulnerable Express app
 *
 * This simulates what happens when the DST processes real
 * vulnerable code from the Damn Vulnerable Node Application.
 * We manually build the neural map (until the mapper auto-generates it)
 * and verify the engine catches all vulnerabilities.
 */

import { describe, it, expect } from 'vitest';
import { verifyAll, formatReport } from './verifier';
import { createNode, createNeuralMap, resetSequence } from './types';

describe('DVNA-style vulnerable Express app', () => {
  it('catches SQL injection, XSS, and SSRF in a realistic app', () => {
    resetSequence();

    // Simulated DVNA code — three routes, three vulnerability classes
    const sourceCode = `
const express = require('express');
const db = require('./db');
const fetch = require('node-fetch');
const app = express();

// VULNERABLE: SQL Injection (CWE-89)
// From DVNA User Search feature
app.post('/users/search', (req, res) => {
  var query = "SELECT name FROM Users WHERE login='" + req.body.login + "'";
  db.query(query, (err, results) => {
    res.render('search', { results: results });
  });
});

// VULNERABLE: Reflected XSS (CWE-79)
app.get('/welcome', (req, res) => {
  res.send('<h1>Welcome, ' + req.query.name + '!</h1>');
});

// VULNERABLE: SSRF (CWE-918)
app.get('/fetch', (req, res) => {
  fetch(req.query.url)
    .then(r => r.text())
    .then(body => res.send(body));
});

app.listen(3000);
`;

    const map = createNeuralMap('dvna/app.js', sourceCode);

    // Route 1: SQL Injection
    map.nodes.push(createNode({
      id: 'login_input',
      node_type: 'INGRESS',
      label: 'req.body.login',
      node_subtype: 'http_body',
      code_snapshot: "var query = \"SELECT name FROM Users WHERE login='\" + req.body.login + \"'\"",
      line_start: 10,
      line_end: 10,
      attack_surface: ['user_input'],
      data_out: [{ name: 'login', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'sql_query', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    }));

    map.nodes.push(createNode({
      id: 'sql_query',
      node_type: 'STORAGE',
      label: 'db.query()',
      node_subtype: 'sql_query',
      code_snapshot: "db.query(query, (err, results) => {",
      line_start: 11,
      line_end: 13,
      attack_surface: ['sql_sink'],
      data_in: [{ name: 'login', source: 'login_input', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'search_render', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    }));

    map.nodes.push(createNode({
      id: 'search_render',
      node_type: 'EGRESS',
      label: 'res.render(search)',
      node_subtype: 'html_response',
      code_snapshot: "res.render('search', { results: results })",
      line_start: 12,
      line_end: 12,
      attack_surface: ['html_output'],
      edges: [],
    }));

    // Route 2: XSS
    map.nodes.push(createNode({
      id: 'name_param',
      node_type: 'INGRESS',
      label: 'req.query.name',
      node_subtype: 'http_param',
      code_snapshot: 'req.query.name',
      line_start: 17,
      line_end: 17,
      attack_surface: ['user_input'],
      data_out: [{ name: 'name', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'welcome_send', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    }));

    map.nodes.push(createNode({
      id: 'welcome_send',
      node_type: 'EGRESS',
      label: 'res.send(welcome)',
      node_subtype: 'html_response',
      code_snapshot: "res.send('<h1>Welcome, ' + req.query.name + '!</h1>')",
      line_start: 18,
      line_end: 18,
      attack_surface: ['html_output'],
      data_in: [{ name: 'name', source: 'name_param', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    }));

    // Route 3: SSRF
    map.nodes.push(createNode({
      id: 'url_param',
      node_type: 'INGRESS',
      label: 'req.query.url',
      node_subtype: 'http_param',
      code_snapshot: 'req.query.url',
      line_start: 22,
      line_end: 22,
      attack_surface: ['user_input'],
      data_out: [{ name: 'url', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'fetch_call', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    }));

    map.nodes.push(createNode({
      id: 'fetch_call',
      node_type: 'EXTERNAL',
      label: 'fetch(req.query.url)',
      node_subtype: 'http_request',
      code_snapshot: 'fetch(req.query.url)',
      line_start: 23,
      line_end: 25,
      attack_surface: ['outbound_request'],
      data_in: [{ name: 'url', source: 'url_param', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    }));

    // Run ALL verifications (noDedup for per-CWE scoring assertions)
    const results = verifyAll(map, undefined, { noDedup: true });
    const report = formatReport(results);

    // Print the full report
    console.log('\n' + report);

    // Assertions
    const sqli = results.find(r => r.cwe === 'CWE-89')!;
    const xss = results.find(r => r.cwe === 'CWE-79')!;
    const ssrf = results.find(r => r.cwe === 'CWE-918')!;
    const pathTraversal = results.find(r => r.cwe === 'CWE-22')!;
    const deser = results.find(r => r.cwe === 'CWE-502')!;

    // Should FAIL on SQLi, XSS, SSRF
    expect(sqli.holds).toBe(false);
    expect(sqli.findings[0].severity).toBe('critical');
    expect(sqli.findings[0].source.label).toBe('req.body.login');

    expect(xss.holds).toBe(false);
    expect(xss.findings[0].severity).toBe('high');

    expect(ssrf.holds).toBe(false);
    expect(ssrf.findings[0].severity).toBe('high');

    // Should PASS on Path Traversal and Deserialization (no file ops or unsafe parsers)
    expect(pathTraversal.holds).toBe(true);
    expect(deser.holds).toBe(true);

    // At least 3 hand-written verifiers fail (SQLi, XSS, SSRF) + generated verifiers may also flag issues
    const failures = results.filter(r => !r.holds);
    expect(failures.length).toBeGreaterThanOrEqual(3);
  });
});
