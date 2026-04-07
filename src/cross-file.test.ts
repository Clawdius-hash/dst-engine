/**
 * Tests for cross-file analysis — import resolution, NeuralMap merging,
 * and cross-file taint propagation.
 */

import { describe, it, expect } from 'vitest';
import {
  extractImports,
  extractExports,
  resolveImportPath,
  mergeNeuralMaps,
  buildDependencyGraph,
  analyzeCrossFile,
  extractJavaPackage,
  buildJavaSamePackageEdges,
  extractJavaImports,
  detectJavaSourceRoots,
  resolveJavaImportPath,
  resolveJavaWildcardImport,
  buildJavaImportEdges,
} from './cross-file';
import { createNode, createNeuralMap, resetSequence } from './types';
import type { NeuralMap } from './types';
import { verifyAll } from './verifier';

// ---------------------------------------------------------------------------
// Import extraction tests
// ---------------------------------------------------------------------------

describe('extractImports', () => {
  it('extracts CommonJS require() with var/let/const', () => {
    const source = `
var express = require('express');
let db = require('./db');
const handler = require('../core/appHandler');
`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(3);
    expect(imports[0]).toMatchObject({
      specifier: 'express',
      localName: 'express',
      importedNames: ['*'],
    });
    expect(imports[1]).toMatchObject({
      specifier: './db',
      localName: 'db',
    });
    expect(imports[2]).toMatchObject({
      specifier: '../core/appHandler',
      localName: 'handler',
    });
  });

  it('extracts destructured require()', () => {
    const source = `const { exec } = require('child_process');`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'child_process',
      importedNames: ['exec'],
    });
  });

  it('extracts ES default import', () => {
    const source = `import express from 'express';`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'express',
      importedNames: ['default'],
      localName: 'express',
    });
  });

  it('extracts ES named imports', () => {
    const source = `import { readFile, writeFile } from 'fs';`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'fs',
      importedNames: ['readFile', 'writeFile'],
    });
  });

  it('extracts ES namespace import', () => {
    const source = `import * as path from 'path';`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'path',
      importedNames: ['*'],
      localName: 'path',
    });
  });

  it('extracts side-effect require', () => {
    const source = `require('./core/passport')(passport);`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: './core/passport',
      localName: null,
    });
  });

  it('handles mixed import styles', () => {
    const source = `
var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')
`;
    const imports = extractImports(source, '/project/routes/app.js');
    expect(imports).toHaveLength(3);
    expect(imports[1]).toMatchObject({
      specifier: '../core/appHandler',
      localName: 'appHandler',
    });
  });

  it('captures line numbers', () => {
    const source = `
const a = require('./a');
const b = require('./b');
`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports[0].line).toBe(2);
    expect(imports[1].line).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Export extraction tests
// ---------------------------------------------------------------------------

describe('extractExports', () => {
  it('extracts module.exports.name = function', () => {
    const source = `
module.exports.userSearch = function (req, res) {};
module.exports.ping = function (req, res) {};
`;
    const exports = extractExports(source);
    expect(exports).toContain('userSearch');
    expect(exports).toContain('ping');
  });

  it('extracts exports.name = function', () => {
    const source = `
exports.handler = function (req, res) {};
`;
    const exports = extractExports(source);
    expect(exports).toContain('handler');
  });

  it('extracts ES export function', () => {
    const source = `
export function processData(data) {}
export default function main() {}
`;
    const exports = extractExports(source);
    expect(exports).toContain('processData');
    expect(exports).toContain('main');
  });

  it('extracts ES export const', () => {
    const source = `export const API_KEY = 'abc123';`;
    const exports = extractExports(source);
    expect(exports).toContain('API_KEY');
  });

  it('deduplicates exports', () => {
    const source = `
module.exports.handler = function() {};
module.exports.handler = function() {};
`;
    const exports = extractExports(source);
    expect(exports.filter(e => e === 'handler')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Import path resolution tests
// ---------------------------------------------------------------------------

describe('resolveImportPath', () => {
  const allFiles = [
    '/project/app.js',
    '/project/db.js',
    '/project/core/appHandler.js',
    '/project/core/authHandler.js',
    '/project/models/index.js',
    '/project/utils.ts',
  ];

  it('resolves relative path to JS file', () => {
    const result = resolveImportPath('./db', '/project/app.js', allFiles);
    expect(result).toBe('/project/db.js');
  });

  it('resolves parent-relative path', () => {
    const result = resolveImportPath(
      '../core/appHandler',
      '/project/routes/app.js',
      allFiles,
    );
    expect(result).toBe('/project/core/appHandler.js');
  });

  it('resolves directory import to index.js', () => {
    const result = resolveImportPath('./models', '/project/app.js', allFiles);
    expect(result).toBe('/project/models/index.js');
  });

  it('resolves .ts extension', () => {
    const result = resolveImportPath('./utils', '/project/app.js', allFiles);
    expect(result).toBe('/project/utils.ts');
  });

  it('returns null for npm packages', () => {
    const result = resolveImportPath('express', '/project/app.js', allFiles);
    expect(result).toBeNull();
  });

  it('returns null for unresolvable paths', () => {
    const result = resolveImportPath('./nonexistent', '/project/app.js', allFiles);
    expect(result).toBeNull();
  });

  it('handles Windows-style paths', () => {
    const winFiles = [
      'C:/Users/pizza/project/app.js',
      'C:/Users/pizza/project/db.js',
    ];
    const result = resolveImportPath('./db', 'C:\\Users\\pizza\\project\\app.js', winFiles);
    expect(result).toBe('C:/Users/pizza/project/db.js');
  });
});

// ---------------------------------------------------------------------------
// NeuralMap merge tests
// ---------------------------------------------------------------------------

describe('mergeNeuralMaps', () => {
  function makeMap(file: string, sourceCode: string, nodeSpecs: Array<{
    id: string;
    type: 'INGRESS' | 'EGRESS' | 'STORAGE' | 'EXTERNAL' | 'STRUCTURAL' | 'TRANSFORM';
    label: string;
    code: string;
    taintedIn?: boolean;
    taintedOut?: boolean;
    edges?: Array<{ target: string; type: 'CALLS' | 'DATA_FLOW' }>;
    attackSurface?: string[];
  }>): NeuralMap {
    resetSequence();
    const map = createNeuralMap(file, sourceCode);
    for (const spec of nodeSpecs) {
      map.nodes.push(createNode({
        id: spec.id,
        node_type: spec.type,
        label: spec.label,
        code_snapshot: spec.code,
        file: file,
        data_in: spec.taintedIn ? [{ name: 'input', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }] : [],
        data_out: spec.taintedOut ? [{ name: 'output', source: spec.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }] : [],
        edges: (spec.edges ?? []).map(e => ({ target: e.target, edge_type: e.type, conditional: false, async: false })),
        attack_surface: spec.attackSurface ?? [],
      }));
    }
    return map;
  }

  it('merges nodes from multiple files without collision', () => {
    const mapA = makeMap('/project/a.js', 'const x = 1;', [
      { id: 'node1', type: 'INGRESS', label: 'input', code: 'req.body' },
    ]);
    const mapB = makeMap('/project/b.js', 'const y = 2;', [
      { id: 'node1', type: 'STORAGE', label: 'db.query', code: 'db.query(x)' },
    ]);

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/a.js', mapA);
    fileMaps.set('/project/b.js', mapB);

    const depGraph = {
      files: ['/project/a.js', '/project/b.js'],
      edges: [],
      importsOf: new Map(),
      importedBy: new Map(),
    };

    const { mergedMap } = mergeNeuralMaps(fileMaps, depGraph);
    expect(mergedMap.nodes).toHaveLength(2);
    // IDs should be prefixed to avoid collision
    const ids = mergedMap.nodes.map(n => n.id);
    expect(ids[0]).not.toBe(ids[1]);
    expect(ids[0]).toContain('project_a');
    expect(ids[1]).toContain('project_b');
  });

  it('creates cross-file CALLS edges for whole-module imports', () => {
    // File B exports: module.exports.handler = function(req, res) { ... }
    const mapB = makeMap(
      '/project/core/handler.js',
      'module.exports.handler = function(req, res) { db.query(req.body.id); };',
      [
        {
          id: 'func_handler',
          type: 'STRUCTURAL',
          label: 'handler',
          code: 'module.exports.handler = function(req, res) { db.query(req.body.id); }',
        },
      ],
    );

    // File A imports handler and calls handler.handler()
    const mapA = makeMap(
      '/project/routes/app.js',
      'var handler = require("../core/handler");\nrouter.post("/search", handler.handler);',
      [
        {
          id: 'route_search',
          type: 'STRUCTURAL',
          label: 'router.post("/search")',
          code: 'router.post("/search", handler.handler)',
        },
      ],
    );

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/routes/app.js', mapA);
    fileMaps.set('/project/core/handler.js', mapB);

    const depGraph = {
      files: ['/project/routes/app.js', '/project/core/handler.js'],
      edges: [{
        from: '/project/routes/app.js',
        to: '/project/core/handler.js',
        importInfo: {
          specifier: '../core/handler',
          resolvedPath: '/project/core/handler.js',
          importedNames: ['*'],
          localName: 'handler',
          line: 1,
        },
      }],
      importsOf: new Map([
        ['/project/routes/app.js', ['/project/core/handler.js']],
        ['/project/core/handler.js', []],
      ]),
      importedBy: new Map([
        ['/project/routes/app.js', []],
        ['/project/core/handler.js', ['/project/routes/app.js']],
      ]),
    };

    const { mergedMap, crossFileEdges } = mergeNeuralMaps(fileMaps, depGraph);
    expect(crossFileEdges).toBeGreaterThan(0);

    // Find the route node — it should have a CALLS edge to the handler
    const routeNode = mergedMap.nodes.find(n => n.label.includes('router.post'));
    expect(routeNode).toBeDefined();
    const callEdges = routeNode!.edges.filter(e => e.edge_type === 'CALLS');
    expect(callEdges.length).toBeGreaterThan(0);
  });

  it('propagates taint across file boundaries', () => {
    // File A: has tainted INGRESS that flows to EGRESS
    const mapA = makeMap(
      '/project/routes.js',
      'var handler = require("./handler");\napp.post("/search", handler.search);',
      [
        {
          id: 'ingress',
          type: 'INGRESS',
          label: 'req.body.login',
          code: 'req.body.login',
          taintedOut: true,
          edges: [{ target: 'route_call', type: 'DATA_FLOW' }],
          attackSurface: ['user_input'],
        },
        {
          id: 'route_call',
          type: 'STRUCTURAL',
          label: 'handler.search',
          code: 'handler.search',
          taintedIn: true,
        },
      ],
    );

    // File B: has a STORAGE node (SQL query) that the route calls
    const mapB = makeMap(
      '/project/handler.js',
      'module.exports.search = function(req, res) { db.query("SELECT * FROM users WHERE id=" + req.body.id); };',
      [
        {
          id: 'func_search',
          type: 'STRUCTURAL',
          label: 'search',
          code: 'module.exports.search = function(req, res)',
        },
        {
          id: 'sql_query',
          type: 'STORAGE',
          label: 'db.query()',
          code: 'db.query("SELECT * FROM users WHERE id=" + req.body.id)',
          attackSurface: ['sql_sink'],
        },
      ],
    );

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/routes.js', mapA);
    fileMaps.set('/project/handler.js', mapB);

    const depGraph = {
      files: ['/project/routes.js', '/project/handler.js'],
      edges: [{
        from: '/project/routes.js',
        to: '/project/handler.js',
        importInfo: {
          specifier: './handler',
          resolvedPath: '/project/handler.js',
          importedNames: ['*'],
          localName: 'handler',
          line: 1,
        },
      }],
      importsOf: new Map([
        ['/project/routes.js', ['/project/handler.js']],
        ['/project/handler.js', []],
      ]),
      importedBy: new Map([
        ['/project/routes.js', []],
        ['/project/handler.js', ['/project/routes.js']],
      ]),
    };

    const { mergedMap } = mergeNeuralMaps(fileMaps, depGraph);

    // The merged map should have nodes from both files
    expect(mergedMap.nodes.length).toBe(4);

    // The ingress node should still be tainted
    const ingressNode = mergedMap.nodes.find(n => n.node_type === 'INGRESS');
    expect(ingressNode).toBeDefined();
    expect(ingressNode!.data_out.some(d => d.tainted)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Integration: Cross-file findings via verifyAll
// ---------------------------------------------------------------------------

describe('cross-file verifyAll integration', () => {
  it('detects SQLi that spans two files (routes + handler)', () => {
    resetSequence();

    // Simulate what the mapper would produce for two files:
    // File 1 (routes): route that calls handler.userSearch
    // File 2 (handler): userSearch has SQL injection

    // Build the handler map (has the actual vulnerability)
    const handlerMap = createNeuralMap('/project/core/appHandler.js', `
module.exports.userSearch = function (req, res) {
  var query = "SELECT name FROM Users WHERE login='" + req.body.login + "'";
  db.sequelize.query(query);
};
`);

    handlerMap.nodes.push(createNode({
      id: 'handler_ingress',
      node_type: 'INGRESS',
      label: 'req.body.login',
      node_subtype: 'http_body',
      code_snapshot: "var query = \"SELECT name FROM Users WHERE login='\" + req.body.login + \"'\"",
      line_start: 3,
      attack_surface: ['user_input'],
      data_out: [{ name: 'login', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'handler_sql', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    }));

    handlerMap.nodes.push(createNode({
      id: 'handler_sql',
      node_type: 'STORAGE',
      label: 'db.sequelize.query()',
      node_subtype: 'sql_query',
      code_snapshot: 'db.sequelize.query(query)',
      line_start: 4,
      attack_surface: ['sql_sink'],
      data_in: [{ name: 'login', source: 'handler_ingress', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
    }));

    handlerMap.nodes.push(createNode({
      id: 'handler_func',
      node_type: 'STRUCTURAL',
      label: 'userSearch',
      node_subtype: 'function_declaration',
      code_snapshot: 'module.exports.userSearch = function (req, res)',
      line_start: 2,
      edges: [
        { target: 'handler_ingress', edge_type: 'CONTAINS', conditional: false, async: false },
        { target: 'handler_sql', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    }));

    // Build the routes map (calls the handler)
    const routesMap = createNeuralMap('/project/routes/app.js', `
var appHandler = require('../core/appHandler');
router.post('/usersearch', appHandler.userSearch);
`);

    routesMap.nodes.push(createNode({
      id: 'route_post',
      node_type: 'STRUCTURAL',
      label: "router.post('/usersearch')",
      node_subtype: 'route_handler',
      code_snapshot: "router.post('/usersearch', appHandler.userSearch)",
      line_start: 3,
    }));

    // Merge
    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/core/appHandler.js', handlerMap);
    fileMaps.set('/project/routes/app.js', routesMap);

    const depGraph = {
      files: ['/project/routes/app.js', '/project/core/appHandler.js'],
      edges: [{
        from: '/project/routes/app.js',
        to: '/project/core/appHandler.js',
        importInfo: {
          specifier: '../core/appHandler',
          resolvedPath: '/project/core/appHandler.js',
          importedNames: ['*'],
          localName: 'appHandler',
          line: 2,
        },
      }],
      importsOf: new Map([
        ['/project/routes/app.js', ['/project/core/appHandler.js']],
        ['/project/core/appHandler.js', []],
      ]),
      importedBy: new Map([
        ['/project/routes/app.js', []],
        ['/project/core/appHandler.js', ['/project/routes/app.js']],
      ]),
    };

    const { mergedMap, crossFileEdges, resolvedImports } = mergeNeuralMaps(fileMaps, depGraph);

    // Should have cross-file edges
    expect(crossFileEdges).toBeGreaterThan(0);
    expect(resolvedImports.length).toBeGreaterThan(0);

    // Run verifiers on the merged map
    const results = verifyAll(mergedMap, 'javascript');
    const sqli = results.find(r => r.cwe === 'CWE-89');
    expect(sqli).toBeDefined();
    expect(sqli!.holds).toBe(false); // Should detect the vulnerability
    expect(sqli!.findings.length).toBeGreaterThan(0);
  });

  it('merged map does not break clean code detection', () => {
    resetSequence();

    // Two clean files — no vulnerabilities
    const mapA = createNeuralMap('/project/a.js', 'const x = 1;');
    mapA.nodes.push(createNode({
      id: 'safe_auth',
      node_type: 'AUTH',
      label: 'authenticate()',
      node_subtype: 'auth_check',
      code_snapshot: 'authenticate()',
    }));

    const mapB = createNeuralMap('/project/b.js', 'const y = 2;');
    mapB.nodes.push(createNode({
      id: 'safe_control',
      node_type: 'CONTROL',
      label: 'if (authorized)',
      node_subtype: 'authorization_check',
      code_snapshot: 'if (authorized)',
    }));

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/a.js', mapA);
    fileMaps.set('/project/b.js', mapB);

    const depGraph = {
      files: ['/project/a.js', '/project/b.js'],
      edges: [],
      importsOf: new Map<string, string[]>(),
      importedBy: new Map<string, string[]>(),
    };

    const { mergedMap } = mergeNeuralMaps(fileMaps, depGraph);
    const results = verifyAll(mergedMap, 'javascript');

    // Should not produce false positives
    const critical = results.filter(r => !r.holds && r.findings.some(f => f.severity === 'critical'));
    expect(critical).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// analyzeCrossFile integration
// ---------------------------------------------------------------------------

describe('analyzeCrossFile', () => {
  it('returns complete result structure', () => {
    resetSequence();

    const mapA = createNeuralMap('/project/a.js', 'const x = 1;');
    const mapB = createNeuralMap('/project/b.js', 'const y = 2;');

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/a.js', mapA);
    fileMaps.set('/project/b.js', mapB);

    // Note: analyzeCrossFile reads files from disk, so we test the structure
    // with pre-built maps using mergeNeuralMaps directly
    const depGraph = {
      files: ['/project/a.js', '/project/b.js'],
      edges: [],
      importsOf: new Map<string, string[]>(),
      importedBy: new Map<string, string[]>(),
    };

    const { mergedMap } = mergeNeuralMaps(fileMaps, depGraph);
    expect(mergedMap).toBeDefined();
    expect(mergedMap.source_file).toBe('[merged]');
    expect(mergedMap.parser_version).toContain('crossfile');
  });
});

// ---------------------------------------------------------------------------
// Java cross-file support tests
// ---------------------------------------------------------------------------

describe('extractJavaPackage', () => {
  it('extracts a standard package declaration', () => {
    const source = `package testcases.CWE89_SQL_Injection.s01;\nimport java.sql.*;\npublic class Foo {}`;
    expect(extractJavaPackage(source)).toBe('testcases.CWE89_SQL_Injection.s01');
  });

  it('extracts package with leading whitespace', () => {
    const source = `  package com.example.app;\npublic class Bar {}`;
    expect(extractJavaPackage(source)).toBe('com.example.app');
  });

  it('returns null for files without package declaration', () => {
    const source = `public class DefaultPackage { }`;
    expect(extractJavaPackage(source)).toBeNull();
  });

  it('ignores package in comments', () => {
    // The regex matches the first occurrence with /m — a commented one won't
    // match because of the leading // or *
    const source = `// package fake.package;\npackage real.package;\npublic class X {}`;
    expect(extractJavaPackage(source)).toBe('real.package');
  });

  it('handles single-segment package', () => {
    const source = `package testcases;\npublic class Y {}`;
    expect(extractJavaPackage(source)).toBe('testcases');
  });
});

describe('buildJavaSamePackageEdges', () => {
  it('creates edges between files in the same package', () => {
    resetSequence();

    const source66a = `package testcases.CWE89.s01;
public class CWE89_66a {
    public void bad() {
        String data = "tainted";
        (new CWE89_66b()).badSink(data);
    }
}`;
    const source66b = `package testcases.CWE89.s01;
public class CWE89_66b {
    public void badSink(String data) {
        db.query("SELECT * FROM users WHERE id=" + data);
    }
}`;

    const map66a = createNeuralMap('/project/CWE89_66a.java', source66a);
    const map66b = createNeuralMap('/project/CWE89_66b.java', source66b);

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/CWE89_66a.java', map66a);
    fileMaps.set('/project/CWE89_66b.java', map66b);

    const files = ['/project/CWE89_66a.java', '/project/CWE89_66b.java'];
    const edges = buildJavaSamePackageEdges(files, fileMaps);

    // 66a references 66b (new CWE89_66b()), so there should be an edge from a -> b
    expect(edges.length).toBeGreaterThanOrEqual(1);
    const aToB = edges.find(e => e.from.includes('66a') && e.to.includes('66b'));
    expect(aToB).toBeDefined();
    expect(aToB!.importInfo.specifier).toBe('CWE89_66b');
  });

  it('does not create self-referencing edges', () => {
    resetSequence();

    const source = `package com.example;
public class Foo {
    public void test() {
        new Foo().other();
    }
    public void other() {}
}`;

    const map = createNeuralMap('/project/Foo.java', source);
    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/Foo.java', map);

    const edges = buildJavaSamePackageEdges(['/project/Foo.java'], fileMaps);
    expect(edges).toHaveLength(0); // single file, no edges
  });

  it('does not create edges between different packages', () => {
    resetSequence();

    const sourceA = `package com.example.a;
public class ServiceA {
    public void call() { new ServiceB().run(); }
}`;
    const sourceB = `package com.example.b;
public class ServiceB {
    public void run() {}
}`;

    const mapA = createNeuralMap('/project/a/ServiceA.java', sourceA);
    const mapB = createNeuralMap('/project/b/ServiceB.java', sourceB);

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/a/ServiceA.java', mapA);
    fileMaps.set('/project/b/ServiceB.java', mapB);

    const files = ['/project/a/ServiceA.java', '/project/b/ServiceB.java'];
    const edges = buildJavaSamePackageEdges(files, fileMaps);
    expect(edges).toHaveLength(0); // different packages
  });

  it('handles static field references (ClassName.field)', () => {
    resetSequence();

    const sourceA = `package testcases.CWE89;
public class Vuln68a {
    public static String data;
    public void bad() {
        data = taintedInput;
    }
}`;
    const sourceB = `package testcases.CWE89;
public class Vuln68b {
    public void badSink() {
        String data = Vuln68a.data;
        db.query(data);
    }
}`;

    const mapA = createNeuralMap('/project/Vuln68a.java', sourceA);
    const mapB = createNeuralMap('/project/Vuln68b.java', sourceB);

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/Vuln68a.java', mapA);
    fileMaps.set('/project/Vuln68b.java', mapB);

    const files = ['/project/Vuln68a.java', '/project/Vuln68b.java'];
    const edges = buildJavaSamePackageEdges(files, fileMaps);

    // 68b references Vuln68a.data, so there should be an edge from b -> a
    const bToA = edges.find(e => e.from.includes('68b') && e.to.includes('68a'));
    expect(bToA).toBeDefined();
  });
});

describe('Java cross-file merge integration', () => {
  function makeJavaMap(file: string, sourceCode: string, nodeSpecs: Array<{
    id: string;
    type: 'INGRESS' | 'EGRESS' | 'STORAGE' | 'EXTERNAL' | 'STRUCTURAL' | 'TRANSFORM';
    label: string;
    code: string;
    taintedIn?: boolean;
    taintedOut?: boolean;
    edges?: Array<{ target: string; type: 'CALLS' | 'DATA_FLOW' }>;
    attackSurface?: string[];
  }>): NeuralMap {
    resetSequence();
    const map = createNeuralMap(file, sourceCode);
    for (const spec of nodeSpecs) {
      map.nodes.push(createNode({
        id: spec.id,
        node_type: spec.type,
        label: spec.label,
        code_snapshot: spec.code,
        file: file,
        language: 'java',
        data_in: spec.taintedIn ? [{ name: 'input', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' as const }] : [],
        data_out: spec.taintedOut ? [{ name: 'output', source: spec.id, data_type: 'string', tainted: true, sensitivity: 'NONE' as const }] : [],
        edges: (spec.edges ?? []).map(e => ({ target: e.target, edge_type: e.type, conditional: false, async: false })),
        attack_surface: spec.attackSurface ?? [],
      }));
    }
    return map;
  }

  it('creates cross-file CALLS edges for Juliet 66a/66b pattern', () => {
    // Simulate the 66a/66b pattern: 66a creates new 66b() and calls badSink
    const source66a = `package testcases.CWE89_SQL_Injection.s01;
public class CWE89_SQL_Injection__connect_tcp_executeBatch_66a extends AbstractTestCase {
    public void bad() throws Throwable {
        String data = readerBuffered.readLine();
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_SQL_Injection__connect_tcp_executeBatch_66b()).badSink(dataArray);
    }
}`;

    const source66b = `package testcases.CWE89_SQL_Injection.s01;
public class CWE89_SQL_Injection__connect_tcp_executeBatch_66b {
    public void badSink(String dataArray[]) throws Throwable {
        String data = dataArray[2];
        sqlStatement.addBatch("update users set hitcount=hitcount+1 where name='" + data + "'");
    }
}`;

    const map66a = makeJavaMap(
      '/project/s01/CWE89_SQL_Injection__connect_tcp_executeBatch_66a.java',
      source66a,
      [
        {
          id: 'ingress_tcp',
          type: 'INGRESS',
          label: 'readerBuffered.readLine()',
          code: 'data = readerBuffered.readLine()',
          taintedOut: true,
          edges: [{ target: 'call_66b', type: 'DATA_FLOW' }],
          attackSurface: ['user_input'],
        },
        {
          id: 'call_66b',
          type: 'STRUCTURAL',
          label: 'CWE89_SQL_Injection__connect_tcp_executeBatch_66b.badSink',
          code: '(new CWE89_SQL_Injection__connect_tcp_executeBatch_66b()).badSink(dataArray)',
          taintedIn: true,
        },
      ],
    );

    const map66b = makeJavaMap(
      '/project/s01/CWE89_SQL_Injection__connect_tcp_executeBatch_66b.java',
      source66b,
      [
        {
          id: 'func_badSink',
          type: 'STRUCTURAL',
          label: 'badSink',
          code: 'public void badSink(String dataArray[]) throws Throwable',
          edges: [{ target: 'sql_sink', type: 'CONTAINS' }],
        },
        {
          id: 'sql_sink',
          type: 'STORAGE',
          label: 'sqlStatement.addBatch()',
          code: "sqlStatement.addBatch(\"update users set hitcount=hitcount+1 where name='\" + data + \"'\")",
          attackSurface: ['sql_sink'],
          taintedIn: true,
        },
      ],
    );

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/s01/CWE89_SQL_Injection__connect_tcp_executeBatch_66a.java', map66a);
    fileMaps.set('/project/s01/CWE89_SQL_Injection__connect_tcp_executeBatch_66b.java', map66b);

    const files = [
      '/project/s01/CWE89_SQL_Injection__connect_tcp_executeBatch_66a.java',
      '/project/s01/CWE89_SQL_Injection__connect_tcp_executeBatch_66b.java',
    ];

    // Build Java same-package edges
    const javaEdges = buildJavaSamePackageEdges(files, fileMaps);
    expect(javaEdges.length).toBeGreaterThanOrEqual(1);

    // Build dependency graph and merge edges
    const depGraph = {
      files,
      edges: [...javaEdges],
      importsOf: new Map<string, string[]>(),
      importedBy: new Map<string, string[]>(),
    };
    for (const file of files) {
      depGraph.importsOf.set(file, []);
      depGraph.importedBy.set(file, []);
    }
    for (const edge of javaEdges) {
      depGraph.importsOf.get(edge.from)!.push(edge.to);
      depGraph.importedBy.get(edge.to)!.push(edge.from);
    }

    const { mergedMap, crossFileEdges } = mergeNeuralMaps(fileMaps, depGraph);

    // Should have cross-file CALLS edges
    expect(crossFileEdges).toBeGreaterThan(0);

    // The call_66b node in 66a should have CALLS edge(s) to nodes in 66b
    const callNode = mergedMap.nodes.find(n => n.id.includes('call_66b'));
    expect(callNode).toBeDefined();
    const callEdges = callNode!.edges.filter(e => e.edge_type === 'CALLS');
    expect(callEdges.length).toBeGreaterThan(0);

    // At least one CALLS edge should target a node in 66b
    const targets66b = callEdges.filter(e => e.target.includes('66b'));
    expect(targets66b.length).toBeGreaterThan(0);
  });

  it('propagates taint across Java cross-file boundary', () => {
    // Same as above but verify taint flows through
    const source66a = `package testcases.CWE89.s01;
public class Vuln66a {
    public void bad() {
        String data = socket.readLine();
        (new Vuln66b()).badSink(data);
    }
}`;
    const source66b = `package testcases.CWE89.s01;
public class Vuln66b {
    public void badSink(String data) {
        db.query("SELECT * FROM t WHERE id=" + data);
    }
}`;

    const map66a = makeJavaMap(
      '/project/s01/Vuln66a.java',
      source66a,
      [
        {
          id: 'ingress',
          type: 'INGRESS',
          label: 'socket.readLine()',
          code: 'data = socket.readLine()',
          taintedOut: true,
          edges: [{ target: 'call_b', type: 'DATA_FLOW' }],
          attackSurface: ['user_input'],
        },
        {
          id: 'call_b',
          type: 'STRUCTURAL',
          label: 'Vuln66b.badSink',
          code: '(new Vuln66b()).badSink(data)',
          taintedIn: true,
        },
      ],
    );

    const map66b = makeJavaMap(
      '/project/s01/Vuln66b.java',
      source66b,
      [
        {
          id: 'func_badSink',
          type: 'STRUCTURAL',
          label: 'badSink',
          code: 'public void badSink(String data)',
        },
        {
          id: 'sql_sink',
          type: 'STORAGE',
          label: 'db.query()',
          code: 'db.query("SELECT * FROM t WHERE id=" + data)',
          attackSurface: ['sql_sink'],
        },
      ],
    );

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/s01/Vuln66a.java', map66a);
    fileMaps.set('/project/s01/Vuln66b.java', map66b);

    const files = ['/project/s01/Vuln66a.java', '/project/s01/Vuln66b.java'];
    const javaEdges = buildJavaSamePackageEdges(files, fileMaps);

    const depGraph = {
      files,
      edges: [...javaEdges],
      importsOf: new Map<string, string[]>(),
      importedBy: new Map<string, string[]>(),
    };
    for (const file of files) {
      depGraph.importsOf.set(file, []);
      depGraph.importedBy.set(file, []);
    }
    for (const edge of javaEdges) {
      depGraph.importsOf.get(edge.from)!.push(edge.to);
      depGraph.importedBy.get(edge.to)!.push(edge.from);
    }

    const { mergedMap, crossFileEdges } = mergeNeuralMaps(fileMaps, depGraph);
    expect(crossFileEdges).toBeGreaterThan(0);

    // After taint propagation, the structural node in 66b (badSink) should be tainted
    const badSinkNode = mergedMap.nodes.find(n => n.id.includes('func_badSink'));
    expect(badSinkNode).toBeDefined();
    // Taint should have propagated via the CALLS edge
    expect(badSinkNode!.data_in.some(d => d.tainted)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Java cross-package import resolution tests
// ---------------------------------------------------------------------------

describe('extractJavaImports', () => {
  it('extracts explicit class import with simple name specifier', () => {
    const source = `package com.example.app;
import org.apache.logging.log4j.core.net.JndiManager;
public class Foo {}`;
    const imports = extractJavaImports(source, '/project/Foo.java');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'JndiManager',
      importedNames: ['JndiManager'],
      localName: 'JndiManager',
    });
  });

  it('extracts wildcard package import', () => {
    const source = `package testcases.CWE89;
import testcasesupport.*;
public class Foo {}`;
    const imports = extractJavaImports(source, '/project/Foo.java');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'testcasesupport',
      importedNames: ['*'],
      localName: null,
    });
  });

  it('extracts static method import', () => {
    const source = `import static org.example.Utils.escape;
public class Bar {}`;
    const imports = extractJavaImports(source, '/project/Bar.java');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'Utils',
      importedNames: ['escape'],
      localName: 'escape',
    });
  });

  it('extracts static wildcard import', () => {
    const source = `import static org.example.Constants.*;
public class Baz {}`;
    const imports = extractJavaImports(source, '/project/Baz.java');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'Constants',
      importedNames: ['*'],
      localName: null,
    });
  });

  it('skips java.* and javax.* stdlib imports', () => {
    const source = `import java.sql.Connection;
import javax.servlet.http.HttpServletRequest;
import sun.misc.Unsafe;
import com.sun.net.httpserver.HttpServer;
import org.example.MyClass;
public class Test {}`;
    const imports = extractJavaImports(source, '/project/Test.java');
    expect(imports).toHaveLength(1);
    expect(imports[0].specifier).toBe('MyClass');
  });

  it('captures line numbers', () => {
    const source = `package com.example;
import org.foo.Bar;
import org.baz.Qux;`;
    const imports = extractJavaImports(source, '/project/Test.java');
    expect(imports[0].line).toBe(2);
    expect(imports[1].line).toBe(3);
  });

  it('handles multiple imports', () => {
    const source = `package com.example;
import org.foo.Bar;
import org.baz.*;
import static org.util.Helper.compute;
public class Multi {}`;
    const imports = extractJavaImports(source, '/project/Multi.java');
    expect(imports).toHaveLength(3);
  });
});

describe('detectJavaSourceRoots', () => {
  it('detects src/main/java/', () => {
    const files = [
      '/project/src/main/java/com/example/App.java',
      '/project/src/main/java/com/example/Util.java',
    ];
    const roots = detectJavaSourceRoots(files);
    expect(roots).toHaveLength(1);
    expect(roots[0]).toBe('/project/src/main/java/');
  });

  it('detects src/test/java/', () => {
    const files = ['/project/src/test/java/com/example/AppTest.java'];
    const roots = detectJavaSourceRoots(files);
    expect(roots).toContain('/project/src/test/java/');
  });

  it('detects Juliet src/testcases/ fallback', () => {
    const files = ['/juliet/src/testcases/CWE89/Foo.java'];
    const roots = detectJavaSourceRoots(files);
    expect(roots).toContain('/juliet/src/testcases/');
  });

  it('deduplicates roots', () => {
    const files = [
      '/project/src/main/java/com/a/A.java',
      '/project/src/main/java/com/b/B.java',
    ];
    const roots = detectJavaSourceRoots(files);
    expect(roots).toHaveLength(1);
  });
});

describe('resolveJavaImportPath', () => {
  const sourceRoots = ['/project/src/main/java/'];
  const fileSet = new Set([
    '/project/src/main/java/com/example/Foo.java',
    '/project/src/main/java/com/example/Bar.java',
    '/project/src/main/java/org/util/Helper.java',
  ]);

  it('resolves a FQCN to a file path', () => {
    const result = resolveJavaImportPath('com.example.Foo', sourceRoots, fileSet);
    expect(result).toBe('/project/src/main/java/com/example/Foo.java');
  });

  it('returns null for unresolvable class', () => {
    const result = resolveJavaImportPath('com.example.Missing', sourceRoots, fileSet);
    expect(result).toBeNull();
  });

  it('resolves inner class fallback', () => {
    // com.example.Foo.Inner -> com/example/Foo.java
    const result = resolveJavaImportPath('com.example.Foo.Inner', sourceRoots, fileSet);
    expect(result).toBe('/project/src/main/java/com/example/Foo.java');
  });
});

describe('resolveJavaWildcardImport', () => {
  const sourceRoots = ['/project/src/main/java/'];
  const allFiles = [
    '/project/src/main/java/com/example/Foo.java',
    '/project/src/main/java/com/example/Bar.java',
    '/project/src/main/java/com/example/sub/Nested.java',
    '/project/src/main/java/org/other/Baz.java',
  ];

  it('returns direct children of the package', () => {
    const result = resolveJavaWildcardImport('com.example', sourceRoots, allFiles);
    expect(result).toHaveLength(2);
    expect(result).toContain('/project/src/main/java/com/example/Foo.java');
    expect(result).toContain('/project/src/main/java/com/example/Bar.java');
  });

  it('excludes nested packages', () => {
    const result = resolveJavaWildcardImport('com.example', sourceRoots, allFiles);
    expect(result).not.toContain('/project/src/main/java/com/example/sub/Nested.java');
  });

  it('returns empty for unmatched package', () => {
    const result = resolveJavaWildcardImport('com.missing', sourceRoots, allFiles);
    expect(result).toHaveLength(0);
  });
});

describe('buildJavaImportEdges', () => {
  it('creates edge for explicit cross-package import', () => {
    resetSequence();

    const sourceA = `package com.example.app;
import com.example.util.Helper;
public class Service {
    public void run() { new Helper().doWork(); }
}`;
    const sourceB = `package com.example.util;
public class Helper {
    public void doWork() {}
}`;

    const mapA = createNeuralMap(
      '/project/src/main/java/com/example/app/Service.java',
      sourceA,
    );
    const mapB = createNeuralMap(
      '/project/src/main/java/com/example/util/Helper.java',
      sourceB,
    );

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/src/main/java/com/example/app/Service.java', mapA);
    fileMaps.set('/project/src/main/java/com/example/util/Helper.java', mapB);

    const files = [
      '/project/src/main/java/com/example/app/Service.java',
      '/project/src/main/java/com/example/util/Helper.java',
    ];

    const edges = buildJavaImportEdges(files, fileMaps);
    expect(edges.length).toBeGreaterThanOrEqual(1);
    const aToB = edges.find(e =>
      e.from.includes('Service') && e.to.includes('Helper'),
    );
    expect(aToB).toBeDefined();
    expect(aToB!.importInfo.specifier).toBe('Helper');
  });

  it('throttles wildcard import fanout by reference check', () => {
    resetSequence();

    const sourceA = `package testcases.CWE89;
import testcasesupport.*;
public class Vuln {
    public void bad() { new AbstractTestCase(); }
}`;
    const sourceSupport = `package testcasesupport;
public class AbstractTestCase {}`;
    const sourceIO = `package testcasesupport;
public class IO {}`;

    const mapA = createNeuralMap(
      '/project/src/testcases/testcases/CWE89/Vuln.java',
      sourceA,
    );
    const mapSupport = createNeuralMap(
      '/project/src/testcases/testcasesupport/AbstractTestCase.java',
      sourceSupport,
    );
    const mapIO = createNeuralMap(
      '/project/src/testcases/testcasesupport/IO.java',
      sourceIO,
    );

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/src/testcases/testcases/CWE89/Vuln.java', mapA);
    fileMaps.set('/project/src/testcases/testcasesupport/AbstractTestCase.java', mapSupport);
    fileMaps.set('/project/src/testcases/testcasesupport/IO.java', mapIO);

    const files = [
      '/project/src/testcases/testcases/CWE89/Vuln.java',
      '/project/src/testcases/testcasesupport/AbstractTestCase.java',
      '/project/src/testcases/testcasesupport/IO.java',
    ];

    const edges = buildJavaImportEdges(files, fileMaps);
    // Should create edge to AbstractTestCase (referenced) but NOT to IO (not referenced)
    const toAbstract = edges.find(e => e.to.includes('AbstractTestCase'));
    expect(toAbstract).toBeDefined();
    const toIO = edges.find(e => e.to.includes('IO.java'));
    expect(toIO).toBeUndefined();
  });

  it('detects FQCN usage (new org.example.ClassName())', () => {
    resetSequence();

    const sourceA = `package com.example.app;
public class Runner {
    public void run() { new com.example.util.Worker(); }
}`;
    const sourceB = `package com.example.util;
public class Worker {}`;

    const mapA = createNeuralMap(
      '/project/src/main/java/com/example/app/Runner.java',
      sourceA,
    );
    const mapB = createNeuralMap(
      '/project/src/main/java/com/example/util/Worker.java',
      sourceB,
    );

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/src/main/java/com/example/app/Runner.java', mapA);
    fileMaps.set('/project/src/main/java/com/example/util/Worker.java', mapB);

    const files = [
      '/project/src/main/java/com/example/app/Runner.java',
      '/project/src/main/java/com/example/util/Worker.java',
    ];

    const edges = buildJavaImportEdges(files, fileMaps);
    const fqcnEdge = edges.find(e =>
      e.from.includes('Runner') && e.to.includes('Worker'),
    );
    expect(fqcnEdge).toBeDefined();
    expect(fqcnEdge!.importInfo.specifier).toBe('Worker');
  });

  it('skips self-referencing edges', () => {
    resetSequence();

    const source = `package com.example;
import com.example.Foo;
public class Foo { void test() { new Foo(); } }`;

    const map = createNeuralMap(
      '/project/src/main/java/com/example/Foo.java',
      source,
    );
    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/src/main/java/com/example/Foo.java', map);

    const edges = buildJavaImportEdges(
      ['/project/src/main/java/com/example/Foo.java'],
      fileMaps,
    );
    expect(edges).toHaveLength(0);
  });
});
