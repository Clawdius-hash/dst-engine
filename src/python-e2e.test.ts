/**
 * Python E2E — Does DST catch vulnerabilities in Python?
 *
 * Not "does it create nodes." Does it CATCH THINGS.
 * Parse → Map → Verify → Findings.
 *
 * The verifier was built for JavaScript. It queries the graph.
 * The graph is language-agnostic. If the PythonProfile names things correctly,
 * the verifier should catch the same vulnerability classes in Python
 * that it catches in JavaScript. Same 9 node types. Same edges. Same CWEs.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { pythonProfile } from './profiles/python.js';
import { verify, verifyAll } from './verifier';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

beforeAll(async () => {
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../node_modules/tree-sitter-python/tree-sitter-python.wasm');
  const Python = await Language.load(fs.readFileSync(wasmPath));
  parser.setLanguage(Python);
});

const scan = (code: string, file = 'test.py') => {
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, file, pythonProfile);
  return map;
};

describe('Python E2E — DST catches Python vulnerabilities', () => {

  it('CWE-89: SQL Injection in Flask', () => {
    const code = `
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/users')
def get_users():
    user_id = request.args.get('id')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    return str(cursor.fetchall())
`;
    const map = scan(code, 'vuln_sqli.py');
    const result = verify(map, 'CWE-89');

    // The verifier should find SQL injection:
    // INGRESS(request.args) → STORAGE(cursor.execute) without CONTROL(parameterized_query)
    console.log('CWE-89 result:', JSON.stringify({ holds: result.holds, findings: result.findings.length }, null, 2));
    console.log('INGRESS nodes:', map.nodes.filter(n => n.node_type === 'INGRESS').map(n => ({ label: n.label, sub: n.node_subtype })));
    console.log('STORAGE nodes:', map.nodes.filter(n => n.node_type === 'STORAGE').map(n => ({ label: n.label, sub: n.node_subtype })));
    console.log('All node types:', map.nodes.map(n => `${n.node_type}/${n.node_subtype}`));
  });

  it('CWE-78: Command Injection in Flask', () => {
    const code = `
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    os.system("ping -c 1 " + host)
    return "done"
`;
    const map = scan(code, 'vuln_cmdi.py');
    const result = verify(map, 'CWE-78');

    console.log('CWE-78 result:', JSON.stringify({ holds: result.holds, findings: result.findings.length }, null, 2));
    console.log('INGRESS nodes:', map.nodes.filter(n => n.node_type === 'INGRESS').map(n => ({ label: n.label, sub: n.node_subtype })));
    console.log('EXTERNAL nodes:', map.nodes.filter(n => n.node_type === 'EXTERNAL').map(n => ({ label: n.label, sub: n.node_subtype })));
  });

  it('CWE-94: Code Injection via eval()', () => {
    const code = `
from flask import Flask, request

app = Flask(__name__)

@app.route('/calc')
def calc():
    expr = request.args.get('expr')
    result = eval(expr)
    return str(result)
`;
    const map = scan(code, 'vuln_eval.py');
    const result = verify(map, 'CWE-94');

    console.log('CWE-94 result:', JSON.stringify({ holds: result.holds, findings: result.findings.length }, null, 2));
    console.log('INGRESS nodes:', map.nodes.filter(n => n.node_type === 'INGRESS').map(n => ({ label: n.label, sub: n.node_subtype })));
    console.log('EXTERNAL nodes:', map.nodes.filter(n => n.node_type === 'EXTERNAL').map(n => ({ label: n.label, sub: n.node_subtype })));
  });

  it('shows the full node map for a vulnerable Flask app', () => {
    const code = `
from flask import Flask, request
import sqlite3
import os
import subprocess

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q')
    name = request.form.get('name')

    # SQL injection
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name LIKE '%" + query + "%'")

    # Command injection
    os.system("grep " + name + " /var/log/app.log")

    # Code injection
    result = eval(query)

    # Subprocess injection
    subprocess.call("echo " + name, shell=True)

    return "ok"
`;
    const map = scan(code, 'vuln_kitchen_sink.py');

    console.log('\n=== PYTHON NEURAL MAP — Kitchen Sink Vulnerable App ===\n');
    console.log(`Total nodes: ${map.nodes.length}`);
    console.log(`Total edges: ${map.edges.length}`);
    console.log('');

    const byType: Record<string, number> = {};
    for (const n of map.nodes) {
      const key = `${n.node_type}/${n.node_subtype}`;
      byType[key] = (byType[key] || 0) + 1;
    }
    console.log('Node distribution:');
    for (const [type, count] of Object.entries(byType).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${type}: ${count}`);
    }

    console.log('\nINGRESS nodes (taint sources):');
    for (const n of map.nodes.filter(n => n.node_type === 'INGRESS')) {
      console.log(`  [${n.id}] ${n.label} (${n.node_subtype}) tainted_out=${n.data_out.some(d => d.tainted)}`);
    }

    console.log('\nSTORAGE nodes (data sinks):');
    for (const n of map.nodes.filter(n => n.node_type === 'STORAGE')) {
      console.log(`  [${n.id}] ${n.label} (${n.node_subtype}) tainted_in=${n.data_in.some(d => d.tainted)}`);
    }

    console.log('\nEXTERNAL nodes (system calls):');
    for (const n of map.nodes.filter(n => n.node_type === 'EXTERNAL')) {
      console.log(`  [${n.id}] ${n.label} (${n.node_subtype}) tainted_in=${n.data_in.some(d => d.tainted)}`);
    }

    console.log('\nDATA_FLOW edges (taint paths):');
    const dataFlowEdges = map.edges.filter(e => e.edge_type === 'DATA_FLOW');
    for (const e of dataFlowEdges) {
      const source = map.nodes.find(n => n.edges.some(ne => ne === e));
      console.log(`  → ${e.target} (async=${e.async})`);
    }

    // Run ALL verifiers and show what catches
    const allResults = verifyAll(map);
    const failures = allResults.filter(r => !r.holds);
    console.log(`\n=== VERIFICATION RESULTS ===`);
    console.log(`Total CWEs checked: ${allResults.length}`);
    console.log(`Vulnerabilities found: ${failures.length}`);
    for (const f of failures) {
      console.log(`  [VULN] ${f.cwe}: ${f.name} (${f.findings.length} findings)`);
      for (const finding of f.findings.slice(0, 3)) {
        console.log(`         ${finding.severity}: ${finding.description?.slice(0, 100)}`);
      }
    }
    const passes = allResults.filter(r => r.holds);
    console.log(`Properties held: ${passes.length}`);

    // We expect SOME vulnerabilities to be caught
    expect(failures.length).toBeGreaterThan(0);
  });
});
