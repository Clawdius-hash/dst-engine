/**
 * Python Profile Integration Test
 *
 * The PythonProfile has never spoken a sentence.
 * This test makes it name things for the first time.
 *
 * One vulnerable Flask app → parse with tree-sitter-python → map with PythonProfile → verify.
 * If cursor.execute("..." + user_input) becomes INGRESS → STORAGE without CONTROL,
 * the mapper speaks Python.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { pythonProfile } from './profiles/python.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

async function createPythonParser(): Promise<InstanceType<typeof Parser>> {
  await Parser.init();
  const p = new Parser();
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-python/tree-sitter-python.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const Python = await Language.load(wasmBuffer);
  p.setLanguage(Python);
  return p;
}

function parsePython(code: string) {
  return parser.parse(code);
}

describe('PythonProfile — first words', () => {
  beforeAll(async () => {
    parser = await createPythonParser();
  });

  it('parses a simple Python function and creates STRUCTURAL nodes', () => {
    const code = `
def hello(name):
    print("Hello, " + name)

hello("world")
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'hello.py', pythonProfile);

    const structuralNodes = map.nodes.filter(n => n.node_type === 'STRUCTURAL');
    expect(structuralNodes.length).toBeGreaterThan(0);

    const funcNode = structuralNodes.find(n => n.node_subtype === 'function');
    expect(funcNode).toBeDefined();
    expect(funcNode!.label).toBe('hello');
    expect(funcNode!.language).toBe('python');
  });

  it('classifies Flask request.args as INGRESS', () => {
    const code = `
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q')
    return query
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'app.py', pythonProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingressNodes.length).toBeGreaterThan(0);
  });

  it('classifies cursor.execute() as STORAGE', () => {
    const code = `
import sqlite3
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM users")
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'db.py', pythonProfile);

    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');
    expect(storageNodes.length).toBeGreaterThan(0);
  });

  it('classifies os.system() as EXTERNAL/system_exec', () => {
    const code = `
import os
os.system("ls -la")
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'cmd.py', pythonProfile);

    const externalNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(externalNodes.length).toBeGreaterThan(0);
  });

  it('classifies eval() as EXTERNAL/system_exec', () => {
    const code = `
user_input = input("Enter expression: ")
result = eval(user_input)
print(result)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'eval.py', pythonProfile);

    const externalNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(externalNodes.length).toBeGreaterThan(0);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingressNodes.length).toBeGreaterThan(0);
  });

  it('creates CONTROL nodes for Python control flow', () => {
    const code = `
def process(data):
    if data > 0:
        for i in range(data):
            try:
                result = 1 / i
            except ZeroDivisionError:
                pass
    while data > 100:
        data = data // 2
    return data
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'control.py', pythonProfile);

    const controlNodes = map.nodes.filter(n => n.node_type === 'CONTROL');
    const subtypes = controlNodes.map(n => n.node_subtype);

    expect(subtypes).toContain('branch');       // if
    expect(subtypes).toContain('loop');          // for, while
    expect(subtypes).toContain('error_handler'); // try
    expect(subtypes).toContain('return');        // return
  });

  it('handles with statement as CONTROL/resource_manager', () => {
    const code = `
with open('file.txt', 'r') as f:
    data = f.read()
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'with.py', pythonProfile);

    const withNodes = map.nodes.filter(n =>
      n.node_type === 'CONTROL' && n.node_subtype === 'resource_manager'
    );
    expect(withNodes.length).toBeGreaterThan(0);
  });

  it('handles class definition as STRUCTURAL/class', () => {
    const code = `
class UserService:
    def __init__(self, db):
        self.db = db

    def get_user(self, user_id):
        return self.db.find(user_id)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'service.py', pythonProfile);

    const classNodes = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'class'
    );
    expect(classNodes.length).toBe(1);
    expect(classNodes[0].label).toBe('UserService');

    const methodNodes = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'function'
    );
    expect(methodNodes.length).toBeGreaterThanOrEqual(2); // __init__ + get_user
  });

  it('handles import_statement and import_from_statement as STRUCTURAL/dependency', () => {
    const code = `
import os
import sys
from flask import Flask, request
from pathlib import Path
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'imports.py', pythonProfile);

    const depNodes = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'dependency'
    );
    expect(depNodes.length).toBeGreaterThanOrEqual(4);
  });

  it('the big one: SQL injection in a Flask app', () => {
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
    results = cursor.fetchall()
    return str(results)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'vuln_app.py', pythonProfile);

    // The mapper should have created:
    // - INGRESS node for request.args
    // - STORAGE node for cursor.execute(...)
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');

    expect(ingressNodes.length).toBeGreaterThan(0);
    expect(storageNodes.length).toBeGreaterThan(0);

    // Check language is python
    const allLanguages = new Set(map.nodes.map(n => n.language));
    expect(allLanguages.has('python')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Python Constant Folding — Anti-Evasion Tests
// ---------------------------------------------------------------------------

describe('PythonProfile — constant folding anti-evasion', () => {
  beforeAll(async () => {
    if (!parser) parser = await createPythonParser();
  });

  it('folds chr() concatenation via variable → resolves globals()[name] to system_exec', () => {
    const code = `
from flask import request
user_input = request.args.get('q')
name = chr(101)+chr(118)+chr(97)+chr(108)
globals()[name](user_input)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'evasion.py', pythonProfile);

    // chr(101)+chr(118)+chr(97)+chr(108) folds to "eval"
    // globals()["eval"]() resolves to EXTERNAL/system_exec
    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  it('folds string concatenation inline: globals()["ev"+"al"](x) → system_exec', () => {
    const code = `
from flask import request
user_input = request.args.get('q')
globals()["ev"+"al"](user_input)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'evasion.py', pythonProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  it('folds bytes([...]).decode() via variable → resolves to system_exec', () => {
    const code = `
from flask import request
user_input = request.args.get('q')
name = bytes([101,118,97,108]).decode()
globals()[name](user_input)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'evasion.py', pythonProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  it('folds base64.b64decode().decode() via variable → resolves to system_exec', () => {
    const code = `
import base64
from flask import request
user_input = request.args.get('q')
name = base64.b64decode("ZXZhbA==").decode()
globals()[name](user_input)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'evasion.py', pythonProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  it('resolves evasion in subscript: globals()[chr(101)+chr(118)+chr(97)+chr(108)](x)', () => {
    const code = `
from flask import request
user_input = request.args.get('q')
globals()[chr(101)+chr(118)+chr(97)+chr(108)](user_input)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'evasion.py', pythonProfile);

    // Should resolve to EXTERNAL/system_exec because chr(101)+... folds to "eval"
    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  it('resolves getattr evasion: getattr(__builtins__, chr(101)+chr(118)+chr(97)+chr(108))', () => {
    const code = `
from flask import request
user_input = request.args.get('cmd')
getattr(__builtins__, chr(101)+chr(118)+chr(97)+chr(108))(user_input)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'evasion.py', pythonProfile);

    // getattr with folded 2nd arg "eval" should resolve to EXTERNAL/system_exec
    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  it('marks unresolvable tainted dynamic dispatch with needs_runtime_eval', () => {
    const code = `
from flask import request
func_name = request.args.get('fn')
globals()[func_name]("payload")
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'evasion.py', pythonProfile);

    // The tainted subscript should produce a dynamic_dispatch node
    const dynNodes = map.nodes.filter(n =>
      n.node_subtype === 'dynamic_dispatch' &&
      n.tags.includes('needs_runtime_eval')
    );
    expect(dynNodes.length).toBeGreaterThan(0);
  });

  it('folds chr() concatenation used as variable then used in subscript', () => {
    const code = `
from flask import request
user_input = request.args.get('q')
fn_name = chr(101)+chr(118)+chr(97)+chr(108)
globals()[fn_name](user_input)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'evasion.py', pythonProfile);

    // fn_name should have constantValue "eval"
    // globals()[fn_name]() should resolve via variable lookup to EXTERNAL/system_exec
    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  it('folds concatenated_string (implicit concat): globals()["ev" "al"](x) → system_exec', () => {
    const code = `
from flask import request
user_input = request.args.get('q')
name = "ev" "al"
globals()[name](user_input)
`;
    const tree = parsePython(code);
    const { map } = buildNeuralMap(tree, code, 'evasion.py', pythonProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });
});
