/**
 * Python Profile Stress Test — try to break it.
 *
 * Nested decorators, comprehensions, walrus operator, async/await,
 * multi-line f-strings, **kwargs taint, class inheritance chains,
 * lambda abuse, and the nastiest real-world patterns.
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

beforeAll(async () => {
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../node_modules/tree-sitter-python/tree-sitter-python.wasm');
  const Python = await Language.load(fs.readFileSync(wasmPath));
  parser.setLanguage(Python);
});

const parse = (code: string) => parser.parse(code);
const map = (code: string, file = 'test.py') => buildNeuralMap(parse(code), code, file, pythonProfile);

describe('Python stress tests — try to break it', () => {

  it('survives empty file', () => {
    const { map: m } = map('');
    expect(m.nodes.length).toBeGreaterThanOrEqual(0); // just don't crash
  });

  it('survives comments only', () => {
    const { map: m } = map('# this is a comment\n# another one\n');
    expect(m).toBeDefined();
  });

  it('survives deeply nested functions', () => {
    const code = `
def a():
    def b():
        def c():
            def d():
                def e():
                    return 42
                return e()
            return d()
        return c()
    return b()
`;
    const { map: m } = map(code);
    const funcs = m.nodes.filter(n => n.node_subtype === 'function');
    expect(funcs.length).toBe(5);
  });

  it('handles list comprehension with conditional', () => {
    const code = `
data = [x * 2 for x in range(100) if x % 3 == 0]
nested = [[j for j in range(i)] for i in range(10)]
`;
    const { map: m } = map(code);
    expect(m).toBeDefined();
    // comprehensions should create nodes
    const compNodes = m.nodes.filter(n => n.node_subtype === 'comprehension');
    expect(compNodes.length).toBeGreaterThan(0);
  });

  it('handles dict comprehension', () => {
    const code = `
squares = {x: x**2 for x in range(10)}
`;
    const { map: m } = map(code);
    expect(m).toBeDefined();
  });

  it('handles generator expression', () => {
    const code = `
total = sum(x**2 for x in range(1000))
`;
    const { map: m } = map(code);
    expect(m).toBeDefined();
  });

  it('handles async def and await', () => {
    const code = `
import aiohttp

async def fetch_data(url):
    async with aiohttp.ClientSession() as session:
        async for chunk in session.get(url):
            yield chunk

async def main():
    result = await fetch_data("http://example.com")
`;
    const { map: m } = map(code);
    const funcs = m.nodes.filter(n => n.node_subtype === 'function');
    expect(funcs.length).toBeGreaterThanOrEqual(2);
  });

  it('handles decorators stacked three deep', () => {
    const code = `
def auth_required(f):
    pass

def rate_limit(n):
    pass

def cache(ttl):
    pass

@auth_required
@rate_limit(100)
@cache(ttl=300)
def get_users():
    return []
`;
    const { map: m } = map(code);
    expect(m).toBeDefined();
    // should have the function
    const funcs = m.nodes.filter(n => n.node_subtype === 'function');
    expect(funcs.length).toBeGreaterThanOrEqual(4); // auth_required, rate_limit, cache, get_users
  });

  it('handles lambda inside map/filter', () => {
    const code = `
items = [1, 2, 3, 4, 5]
evens = list(filter(lambda x: x % 2 == 0, items))
doubled = list(map(lambda x: x * 2, items))
key_func = lambda item: item['priority']
sorted_items = sorted(items, key=key_func)
`;
    const { map: m } = map(code);
    expect(m).toBeDefined();
  });

  it('handles multiple assignment targets (tuple unpacking)', () => {
    const code = `
a, b, c = 1, 2, 3
x, *rest = [1, 2, 3, 4, 5]
(first, second), third = (1, 2), 3
`;
    const { map: m } = map(code);
    expect(m).toBeDefined();
  });

  it('handles class with inheritance, staticmethod, classmethod, property', () => {
    const code = `
class Animal:
    def __init__(self, name):
        self.name = name

    def speak(self):
        raise NotImplementedError

class Dog(Animal):
    @staticmethod
    def species():
        return "Canis familiaris"

    @classmethod
    def from_dict(cls, data):
        return cls(data['name'])

    @property
    def greeting(self):
        return f"Woof! I'm {self.name}"

    def speak(self):
        return "Woof!"
`;
    const { map: m } = map(code);
    const classes = m.nodes.filter(n => n.node_subtype === 'class');
    expect(classes.length).toBe(2);
    const methods = m.nodes.filter(n => n.node_subtype === 'function');
    expect(methods.length).toBeGreaterThanOrEqual(6);
  });

  it('handles try/except/else/finally', () => {
    const code = `
try:
    result = dangerous_operation()
except ValueError as e:
    handle_value_error(e)
except (TypeError, KeyError) as e:
    handle_other(e)
except Exception:
    fallback()
else:
    on_success(result)
finally:
    cleanup()
`;
    const { map: m } = map(code);
    const errorNodes = m.nodes.filter(n => n.node_subtype === 'error_handler');
    expect(errorNodes.length).toBeGreaterThan(0);
  });

  it('handles walrus operator (:=)', () => {
    const code = `
if (n := len(data)) > 10:
    print(f"Too much data: {n} items")

while chunk := read_chunk():
    process(chunk)
`;
    const { map: m } = map(code);
    expect(m).toBeDefined();
  });

  it('handles f-string with expressions', () => {
    const code = `
name = "world"
greeting = f"Hello, {name.upper()}! The answer is {2 + 2}"
multi = f"""
SELECT * FROM users
WHERE name = '{name}'
AND active = {True}
"""
`;
    const { map: m } = map(code);
    expect(m).toBeDefined();
  });

  it('handles global and nonlocal', () => {
    const code = `
counter = 0

def increment():
    global counter
    counter += 1

def outer():
    x = 10
    def inner():
        nonlocal x
        x += 1
    inner()
    return x
`;
    const { map: m } = map(code);
    expect(m).toBeDefined();
    const funcs = m.nodes.filter(n => n.node_subtype === 'function');
    expect(funcs.length).toBe(3); // increment, outer, inner
  });

  it('handles star imports and aliased imports', () => {
    const code = `
from os.path import *
import numpy as np
from collections import defaultdict as dd, OrderedDict as OD
from . import sibling_module
from ..parent import something
`;
    const { map: m } = map(code);
    const deps = m.nodes.filter(n => n.node_subtype === 'dependency');
    expect(deps.length).toBeGreaterThanOrEqual(4);
  });

  it('handles assert statement as CONTROL/guard', () => {
    const code = `
def divide(a, b):
    assert b != 0, "Division by zero!"
    return a / b
`;
    const { map: m } = map(code);
    const guards = m.nodes.filter(n => n.node_subtype === 'guard');
    expect(guards.length).toBeGreaterThan(0);
  });

  it('handles the nastiest real pattern: Django ORM with Q objects and raw SQL', () => {
    const code = `
from django.db.models import Q
from django.http import HttpRequest

def search_users(request: HttpRequest):
    query = request.GET.get('q', '')

    # Safe: ORM query
    safe_results = User.objects.filter(
        Q(name__icontains=query) | Q(email__icontains=query)
    )

    # DANGEROUS: raw SQL with string formatting
    raw_results = User.objects.raw(
        f"SELECT * FROM auth_user WHERE name LIKE '%{query}%'"
    )

    # DANGEROUS: cursor with string concat
    from django.db import connection
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM auth_user WHERE name = '" + query + "'")

    return safe_results
`;
    const { map: m } = map(code);

    // Should have INGRESS for request.GET
    const ingress = m.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThan(0);

    // Should have STORAGE for cursor.execute and objects.raw
    const storage = m.nodes.filter(n => n.node_type === 'STORAGE');
    expect(storage.length).toBeGreaterThan(0);

    // Should not crash on Q objects, f-strings, or chained ORM calls
    expect(m.nodes.length).toBeGreaterThan(10);
  });

  it('handles 200 lines of mixed Python without crashing', () => {
    // Generate a big chunk of varied Python
    const lines: string[] = [
      'import os, sys, json',
      'from pathlib import Path',
      'from typing import Dict, List, Optional',
      '',
      'GLOBAL_CONFIG = {"debug": True, "version": "1.0"}',
      '',
    ];
    for (let i = 0; i < 20; i++) {
      lines.push(`def func_${i}(arg_${i}: str = "default") -> Optional[int]:`);
      lines.push(`    """Docstring for func_${i}."""`);
      lines.push(`    if arg_${i}:`);
      lines.push(`        result = len(arg_${i}) * ${i}`);
      lines.push(`        return result`);
      lines.push(`    return None`);
      lines.push('');
    }
    lines.push('class BigClass:');
    for (let i = 0; i < 10; i++) {
      lines.push(`    def method_${i}(self, x: int) -> int:`);
      lines.push(`        return x + ${i}`);
      lines.push('');
    }

    const code = lines.join('\n');
    const { map: m } = map(code);

    expect(m.nodes.length).toBeGreaterThan(30);

    const funcs = m.nodes.filter(n => n.node_subtype === 'function');
    expect(funcs.length).toBeGreaterThanOrEqual(20); // at least the 20 functions
  });
});
