/**
 * Python Profile — BREAK IT.
 *
 * The happy path worked. Now the adversarial cases.
 * Multi-hop taint, cross-method taint through self,
 * **kwargs into sinks, f-string SQL injection,
 * pickle deserialization, YAML unsafe load,
 * decorator parameter injection, dynamic getattr,
 * and the patterns that actually appear in the wild.
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
  return buildNeuralMap(tree, code, file, pythonProfile);
};

const scanAndVerify = (code: string, cwe: string, file = 'test.py') => {
  const { map } = scan(code, file);
  return { map, result: verify(map, cwe) };
};

describe('Python BREAK tests — find the walls', () => {

  // ═══════════════════════════════════════════════════════════════
  // MULTI-HOP TAINT — does taint survive variable reassignment?
  // ═══════════════════════════════════════════════════════════════

  it('multi-hop taint: input → a → b → c → sink', () => {
    const code = `
from flask import request
import sqlite3

user_input = request.args.get('id')
a = user_input
b = a
c = b
conn = sqlite3.connect('db.sqlite')
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id=" + c)
`;
    const { map, result } = scanAndVerify(code, 'CWE-89');
    console.log('Multi-hop taint CWE-89:', { holds: result.holds, findings: result.findings.length });
    console.log('  INGRESS:', map.nodes.filter(n => n.node_type === 'INGRESS').length);
    console.log('  STORAGE:', map.nodes.filter(n => n.node_type === 'STORAGE').length);
    // This is HARD. Taint has to flow through 3 variable reassignments.
  });

  // ═══════════════════════════════════════════════════════════════
  // F-STRING SQL INJECTION — subtler than concat
  // ═══════════════════════════════════════════════════════════════

  it('f-string SQL injection', () => {
    const code = `
from flask import request
import sqlite3

name = request.form.get('name')
conn = sqlite3.connect('db.sqlite')
cursor = conn.cursor()
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
`;
    const { map, result } = scanAndVerify(code, 'CWE-89');
    console.log('F-string SQLi CWE-89:', { holds: result.holds, findings: result.findings.length });
  });

  // ═══════════════════════════════════════════════════════════════
  // CROSS-METHOD TAINT — taint stored on self, used elsewhere
  // ═══════════════════════════════════════════════════════════════

  it('cross-method taint through self', () => {
    const code = `
from flask import request
import os

class Handler:
    def get_input(self):
        self.user_data = request.args.get('cmd')

    def execute(self):
        os.system(self.user_data)
`;
    const { map, result } = scanAndVerify(code, 'CWE-78');
    console.log('Cross-method taint CWE-78:', { holds: result.holds, findings: result.findings.length });
    console.log('  INGRESS:', map.nodes.filter(n => n.node_type === 'INGRESS').map(n => n.label));
    console.log('  EXTERNAL:', map.nodes.filter(n => n.node_type === 'EXTERNAL').map(n => n.label));
    // This requires tracking taint across method boundaries via self.
    // Very hard for static analysis. Probably breaks.
  });

  // ═══════════════════════════════════════════════════════════════
  // **KWARGS INTO SINK — taint hidden in keyword args
  // ═══════════════════════════════════════════════════════════════

  it('kwargs into dangerous function', () => {
    const code = `
from flask import request
import subprocess

def run_command(**kwargs):
    subprocess.call(kwargs['cmd'], shell=True)

cmd = request.args.get('command')
run_command(cmd=cmd)
`;
    const { map, result } = scanAndVerify(code, 'CWE-78');
    console.log('Kwargs taint CWE-78:', { holds: result.holds, findings: result.findings.length });
  });

  // ═══════════════════════════════════════════════════════════════
  // PICKLE DESERIALIZATION — CWE-502
  // ═══════════════════════════════════════════════════════════════

  it('pickle deserialization of user input', () => {
    const code = `
from flask import request
import pickle

@app.route('/load')
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)
`;
    const { map } = scan(code);
    // pickle.loads should be classified as EXTERNAL/system_exec or similar dangerous pattern
    const dangerous = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' || (n.node_type === 'TRANSFORM' && n.node_subtype === 'deserialize')
    );
    console.log('Pickle deser:', dangerous.map(n => `${n.node_type}/${n.node_subtype}: ${n.label}`));
    // Even if it doesn't catch CWE-502 specifically, it should at least create nodes
    expect(map.nodes.length).toBeGreaterThan(0);
  });

  // ═══════════════════════════════════════════════════════════════
  // YAML UNSAFE LOAD
  // ═══════════════════════════════════════════════════════════════

  it('yaml.load without SafeLoader', () => {
    const code = `
from flask import request
import yaml

@app.route('/config')
def parse_config():
    raw = request.get_data()
    config = yaml.load(raw)
    return str(config)
`;
    const { map } = scan(code);
    console.log('YAML load nodes:', map.nodes.filter(n => n.node_type !== 'STRUCTURAL' && n.node_type !== 'CONTROL').map(n => `${n.node_type}/${n.node_subtype}: ${n.label}`));
  });

  // ═══════════════════════════════════════════════════════════════
  // FORMAT STRING INJECTION — .format() with user input
  // ═══════════════════════════════════════════════════════════════

  it('format string injection into SQL', () => {
    const code = `
from flask import request
import sqlite3

query = request.args.get('q')
sql = "SELECT * FROM items WHERE name = '{}'".format(query)
conn = sqlite3.connect('db.sqlite')
cursor = conn.cursor()
cursor.execute(sql)
`;
    const { map, result } = scanAndVerify(code, 'CWE-89');
    console.log('Format string SQLi CWE-89:', { holds: result.holds, findings: result.findings.length });
  });

  // ═══════════════════════════════════════════════════════════════
  // SSRF — user-controlled URL in requests.get
  // ═══════════════════════════════════════════════════════════════

  it('SSRF via user-controlled URL', () => {
    const code = `
from flask import request
import requests as http

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    response = http.get(url)
    return response.text
`;
    const { map, result } = scanAndVerify(code, 'CWE-918');
    console.log('SSRF CWE-918:', { holds: result.holds, findings: result.findings.length });
    console.log('  INGRESS:', map.nodes.filter(n => n.node_type === 'INGRESS').map(n => n.label));
    console.log('  EXTERNAL:', map.nodes.filter(n => n.node_type === 'EXTERNAL').map(n => n.label));
  });

  // ═══════════════════════════════════════════════════════════════
  // PATH TRAVERSAL — user input in file open
  // ═══════════════════════════════════════════════════════════════

  it('path traversal via user-controlled filename', () => {
    const code = `
from flask import request

@app.route('/read')
def read_file():
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        return f.read()
`;
    const { map, result } = scanAndVerify(code, 'CWE-22');
    console.log('Path traversal CWE-22:', { holds: result.holds, findings: result.findings.length });
  });

  // ═══════════════════════════════════════════════════════════════
  // SAFE CODE — should NOT flag
  // ═══════════════════════════════════════════════════════════════

  it('parameterized query should NOT flag CWE-89', () => {
    const code = `
from flask import request
import sqlite3

user_id = request.args.get('id')
conn = sqlite3.connect('db.sqlite')
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
`;
    const { map, result } = scanAndVerify(code, 'CWE-89');
    // Parameterized query — the taint from user_id is bound safely by the DB driver.
    // The STORAGE node should NOT have tainted data_in, and CWE-89 should not fire.
    const storage = map.nodes.filter(n => n.node_type === 'STORAGE');
    const executeNode = storage.find(n => n.code_snapshot.includes('cursor.execute'));
    console.log('Parameterized query STORAGE:', storage.map(n => ({ label: n.label.slice(0, 80), tainted_in: n.data_in.some(d => d.tainted) })));
    console.log('Parameterized query CONTROL:', map.nodes.filter(n => n.node_type === 'CONTROL').map(n => `${n.node_subtype}: ${n.label}`));
    console.log('CWE-89 result:', { holds: result.holds, findings: result.findings.length });

    // The execute node should not have tainted data_in
    if (executeNode) {
      expect(executeNode.data_in.some(d => d.tainted)).toBe(false);
    }
    // CWE-89 should hold (no findings)
    expect(result.holds).toBe(true);
  });

  // ═══════════════════════════════════════════════════════════════
  // THE REALISTIC ONE — a whole Django view with mixed safe/unsafe
  // ═══════════════════════════════════════════════════════════════

  it('realistic Django view with mixed patterns', () => {
    const code = `
from django.http import HttpRequest, JsonResponse
from django.db import connection
from django.contrib.auth.decorators import login_required
import hashlib
import subprocess

@login_required
def user_dashboard(request: HttpRequest):
    user_id = request.GET.get('user_id')
    action = request.POST.get('action')

    # SAFE: ORM query (parameterized internally)
    # user = User.objects.get(id=user_id)

    # DANGEROUS: raw SQL
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM auth_user WHERE id = " + user_id)
    user_data = cursor.fetchone()

    # DANGEROUS: command injection
    if action == 'export':
        subprocess.Popen("tar -czf /tmp/export_" + user_id + ".tar.gz /data/" + user_id, shell=True)

    # SAFE: hashing (not dangerous)
    token = hashlib.sha256(user_id.encode()).hexdigest()

    return JsonResponse({'user': user_data, 'token': token})
`;
    const { map } = scan(code, 'views.py');

    const allResults = verifyAll(map);
    const failures = allResults.filter(r => !r.holds);

    console.log('\n=== DJANGO VIEW SCAN ===');
    console.log(`Nodes: ${map.nodes.length}, Edges: ${map.edges.length}`);
    console.log(`CWEs checked: ${allResults.length}, Vulnerabilities: ${failures.length}`);

    // Should catch at minimum SQLi and command injection
    const sqli = allResults.find(r => r.cwe === 'CWE-89');
    const cmdi = allResults.find(r => r.cwe === 'CWE-78');
    console.log('CWE-89 (SQLi):', sqli ? { holds: sqli.holds, findings: sqli.findings.length } : 'not checked');
    console.log('CWE-78 (CMDi):', cmdi ? { holds: cmdi.holds, findings: cmdi.findings.length } : 'not checked');

    // At least SOME vulns should be found
    expect(failures.length).toBeGreaterThan(0);
  });
});
