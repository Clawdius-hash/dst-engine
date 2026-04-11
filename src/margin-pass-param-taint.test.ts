import { describe, it, expect, beforeEach } from 'vitest';
import { createNode, createNeuralMap, resetSequenceHard } from './types.js';
import { runMarginPass, FileSummary } from './margin-pass.js';
import type { DependencyGraph } from './cross-file.js';

describe('Cross-file parameter taint propagation', () => {
  beforeEach(() => resetSequenceHard());

  it('marks callee sink as tainted when caller passes tainted arg', () => {
    // FILE A (caller): has INGRESS, calls slugFilterOrder with tainted data
    const mapA = createNeuralMap('routes.js', '');
    const ingress = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request',
      label: 'req.query.filter',
      data_out: [{ name: 'filter', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    const callSite = createNode({
      node_type: 'TRANSFORM', node_subtype: 'local_call',
      label: 'slugFilterOrder(table, filter)',
      code_snapshot: "slugFilterOrder('posts', frame.options.filter)",
      analysis_snapshot: "slugFilterOrder('posts', frame.options.filter)",
      data_in: [{ name: 'filter', source: ingress.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    mapA.nodes = [ingress, callSite];

    // FILE B (callee): slugFilterOrder function with SQL sink, NO INGRESS
    const mapB = createNeuralMap('slug-filter-order.js', '');
    const funcDecl = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'slugFilterOrder',
      param_names: ['table', 'filter'],
      line_start: 1, line_end: 18,
      code_snapshot: 'const slugFilterOrder = (table, filter) => {',
      edges: [
        { target: 'sink_sql', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    });
    const sqlSink = createNode({
      id: 'sink_sql',
      node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'order += WHEN slug = filter',
      line_start: 9, line_end: 9,
      code_snapshot: "order += `WHEN \\`${table}\\`.\\`slug\\` = '${slug}' THEN ${index} `",
      data_in: [],
      edges: [],
    });
    mapB.nodes = [funcDecl, sqlSink];

    // FileSummaries
    const summaries = new Map<string, FileSummary>();
    summaries.set('routes.js', {
      map: mapA,
      functionReturnTaint: new Map(),
      functionRegistry: new Map(),
    });
    summaries.set('slug-filter-order.js', {
      map: mapB,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['slugFilterOrder', funcDecl.id]]),
    });

    // Dependency graph: routes.js imports slugFilterOrder from slug-filter-order.js
    const depGraph: DependencyGraph = {
      files: ['routes.js', 'slug-filter-order.js'],
      edges: [{
        from: 'routes.js',
        to: 'slug-filter-order.js',
        importInfo: {
          specifier: './utils/slug-filter-order',
          resolvedPath: 'slug-filter-order.js',
          importedNames: ['slugFilterOrder'],
          localName: 'slugFilterOrder',
          line: 1,
        },
      }],
      importsOf: new Map([['routes.js', ['slug-filter-order.js']]]),
      importedBy: new Map([['slug-filter-order.js', ['routes.js']]]),
    };

    // Run margin pass
    const dirtyFiles = runMarginPass(summaries, depGraph);

    // slug-filter-order.js should be dirty (parameter taint propagated)
    expect(dirtyFiles.has('slug-filter-order.js')).toBe(true);

    // The SQL sink in file B should now have tainted data_in
    const sink = mapB.nodes.find(n => n.node_subtype === 'sql_query');
    expect(sink).toBeDefined();
    expect(sink!.data_in.some(d => d.tainted)).toBe(true);
  });

  it('does NOT propagate when caller args are clean', () => {
    const mapA = createNeuralMap('routes.js', '');
    const cleanCall = createNode({
      node_type: 'TRANSFORM', node_subtype: 'local_call',
      label: 'slugFilterOrder(table, hardcodedValue)',
      code_snapshot: "slugFilterOrder('posts', 'safe-slug')",
      data_in: [{ name: 'safe', source: 'lit1', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    mapA.nodes = [cleanCall];

    const mapB = createNeuralMap('slug-filter-order.js', '');
    const funcDecl = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'slugFilterOrder',
      param_names: ['table', 'filter'],
      line_start: 1, line_end: 18,
      edges: [{ target: 'sink_sql', edge_type: 'CONTAINS', conditional: false, async: false }],
    });
    const sqlSink = createNode({
      id: 'sink_sql',
      node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'SQL query', data_in: [], edges: [],
      line_start: 9, line_end: 9,
    });
    mapB.nodes = [funcDecl, sqlSink];

    const summaries = new Map<string, FileSummary>();
    summaries.set('routes.js', { map: mapA, functionReturnTaint: new Map(), functionRegistry: new Map() });
    summaries.set('slug-filter-order.js', { map: mapB, functionReturnTaint: new Map(), functionRegistry: new Map([['slugFilterOrder', funcDecl.id]]) });

    const depGraph: DependencyGraph = {
      files: ['routes.js', 'slug-filter-order.js'],
      edges: [{ from: 'routes.js', to: 'slug-filter-order.js', importInfo: { specifier: './slug-filter-order', resolvedPath: 'slug-filter-order.js', importedNames: ['slugFilterOrder'], localName: 'slugFilterOrder', line: 1 } }],
      importsOf: new Map([['routes.js', ['slug-filter-order.js']]]),
      importedBy: new Map([['slug-filter-order.js', ['routes.js']]]),
    };

    const dirtyFiles = runMarginPass(summaries, depGraph);

    // Should NOT be dirty -- no tainted args
    expect(dirtyFiles.has('slug-filter-order.js')).toBe(false);
    const sink = mapB.nodes.find(n => n.node_subtype === 'sql_query');
    expect(sink!.data_in.some(d => d.tainted)).toBe(false);
  });

  it('propagates taint to TRANSFORM nodes inside callee function', () => {
    const mapA = createNeuralMap('caller.js', '');
    const callSite = createNode({
      node_type: 'TRANSFORM', node_subtype: 'local_call',
      label: 'processInput(userInput)',
      code_snapshot: 'processInput(req.body.input)',
      data_in: [{ name: 'input', source: 'ingress1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    mapA.nodes = [callSite];

    const mapB = createNeuralMap('processor.js', '');
    const funcDecl = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'processInput',
      param_names: ['input'],
      line_start: 1, line_end: 10,
      edges: [
        { target: 'transform1', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    });
    const transform = createNode({
      id: 'transform1',
      node_type: 'TRANSFORM', node_subtype: 'string_concat',
      label: 'query = "SELECT * FROM " + input',
      line_start: 3, line_end: 3,
      data_in: [{ name: 'input', source: 'param', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    mapB.nodes = [funcDecl, transform];

    const summaries = new Map<string, FileSummary>();
    summaries.set('caller.js', { map: mapA, functionReturnTaint: new Map(), functionRegistry: new Map() });
    summaries.set('processor.js', { map: mapB, functionReturnTaint: new Map(), functionRegistry: new Map([['processInput', funcDecl.id]]) });

    const depGraph: DependencyGraph = {
      files: ['caller.js', 'processor.js'],
      edges: [{ from: 'caller.js', to: 'processor.js', importInfo: { specifier: './processor', resolvedPath: 'processor.js', importedNames: ['processInput'], localName: 'processInput', line: 1 } }],
      importsOf: new Map([['caller.js', ['processor.js']]]),
      importedBy: new Map([['processor.js', ['caller.js']]]),
    };

    const dirtyFiles = runMarginPass(summaries, depGraph);

    expect(dirtyFiles.has('processor.js')).toBe(true);
    expect(transform.data_in.some(d => d.tainted)).toBe(true);
  });

  it('propagates taint to EGRESS nodes inside callee function', () => {
    const mapA = createNeuralMap('caller.js', '');
    const callSite = createNode({
      node_type: 'TRANSFORM', node_subtype: 'local_call',
      label: 'sendData(userInput)',
      code_snapshot: 'sendData(req.body.data)',
      data_in: [{ name: 'data', source: 'ingress1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    mapA.nodes = [callSite];

    const mapB = createNeuralMap('sender.js', '');
    const funcDecl = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'sendData',
      param_names: ['data'],
      line_start: 1, line_end: 10,
      edges: [
        { target: 'egress1', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    });
    const egress = createNode({
      id: 'egress1',
      node_type: 'EGRESS', node_subtype: 'http_response',
      label: 'res.send(data)',
      line_start: 5, line_end: 5,
      data_in: [{ name: 'data', source: 'param', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    mapB.nodes = [funcDecl, egress];

    const summaries = new Map<string, FileSummary>();
    summaries.set('caller.js', { map: mapA, functionReturnTaint: new Map(), functionRegistry: new Map() });
    summaries.set('sender.js', { map: mapB, functionReturnTaint: new Map(), functionRegistry: new Map([['sendData', funcDecl.id]]) });

    const depGraph: DependencyGraph = {
      files: ['caller.js', 'sender.js'],
      edges: [{ from: 'caller.js', to: 'sender.js', importInfo: { specifier: './sender', resolvedPath: 'sender.js', importedNames: ['sendData'], localName: 'sendData', line: 1 } }],
      importsOf: new Map([['caller.js', ['sender.js']]]),
      importedBy: new Map([['sender.js', ['caller.js']]]),
    };

    const dirtyFiles = runMarginPass(summaries, depGraph);

    expect(dirtyFiles.has('sender.js')).toBe(true);
    expect(egress.data_in.some(d => d.tainted)).toBe(true);
  });

  it('does not taint nodes outside the function line range', () => {
    const mapA = createNeuralMap('caller.js', '');
    const callSite = createNode({
      node_type: 'TRANSFORM', node_subtype: 'local_call',
      label: 'targetFunc(taintedInput)',
      code_snapshot: 'targetFunc(req.body.x)',
      data_in: [{ name: 'x', source: 'ingress1', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    mapA.nodes = [callSite];

    const mapB = createNeuralMap('target.js', '');
    const funcDecl = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'targetFunc',
      param_names: ['x'],
      line_start: 10, line_end: 20,
      edges: [],
    });
    // Node INSIDE function range
    const insideSink = createNode({
      node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'inside query',
      line_start: 15, line_end: 15,
      data_in: [{ name: 'x', source: 'param', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    // Node OUTSIDE function range
    const outsideSink = createNode({
      node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'outside query',
      line_start: 30, line_end: 30,
      data_in: [{ name: 'y', source: 'other', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    mapB.nodes = [funcDecl, insideSink, outsideSink];

    const summaries = new Map<string, FileSummary>();
    summaries.set('caller.js', { map: mapA, functionReturnTaint: new Map(), functionRegistry: new Map() });
    summaries.set('target.js', { map: mapB, functionReturnTaint: new Map(), functionRegistry: new Map([['targetFunc', funcDecl.id]]) });

    const depGraph: DependencyGraph = {
      files: ['caller.js', 'target.js'],
      edges: [{ from: 'caller.js', to: 'target.js', importInfo: { specifier: './target', resolvedPath: 'target.js', importedNames: ['targetFunc'], localName: 'targetFunc', line: 1 } }],
      importsOf: new Map([['caller.js', ['target.js']]]),
      importedBy: new Map([['target.js', ['caller.js']]]),
    };

    runMarginPass(summaries, depGraph);

    // Inside sink should be tainted
    expect(insideSink.data_in.some(d => d.tainted)).toBe(true);
    // Outside sink should NOT be tainted
    expect(outsideSink.data_in.some(d => d.tainted)).toBe(false);
  });
});

describe('Sink-context cataloging', () => {
  beforeEach(() => resetSequenceHard());

  it('tags function containing STORAGE/sql_query sink with sql_query in functionSinkContext', () => {
    const map = createNeuralMap('db-utils.js', '');
    const funcDecl = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'runQuery',
      param_names: ['sql'],
      line_start: 1, line_end: 10,
      edges: [
        { target: 'sink_sql', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    });
    const sqlSink = createNode({
      id: 'sink_sql',
      node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'db.query(sql)',
      line_start: 5, line_end: 5,
      data_in: [{ name: 'sql', source: 'param', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    map.nodes = [funcDecl, sqlSink];

    const summaries = new Map<string, FileSummary>();
    summaries.set('db-utils.js', {
      map,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['runQuery', funcDecl.id]]),
    });

    // Minimal dep graph — single file, no edges needed for PASS 3
    const depGraph: DependencyGraph = {
      files: ['db-utils.js'],
      edges: [],
      importsOf: new Map(),
      importedBy: new Map(),
    };

    runMarginPass(summaries, depGraph);

    const summary = summaries.get('db-utils.js')!;
    expect(summary.functionSinkContext).toBeDefined();
    expect(summary.functionSinkContext!.has(funcDecl.id)).toBe(true);
    expect(summary.functionSinkContext!.get(funcDecl.id)!.has('sql_query')).toBe(true);
  });

  it('does NOT tag function containing only TRANSFORM nodes', () => {
    const map = createNeuralMap('utils.js', '');
    const funcDecl = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'formatString',
      param_names: ['input'],
      line_start: 1, line_end: 8,
      edges: [
        { target: 'transform1', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    });
    const transformNode = createNode({
      id: 'transform1',
      node_type: 'TRANSFORM', node_subtype: 'string_concat',
      label: 'result = prefix + input',
      line_start: 3, line_end: 3,
      data_in: [{ name: 'input', source: 'param', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    map.nodes = [funcDecl, transformNode];

    const summaries = new Map<string, FileSummary>();
    summaries.set('utils.js', {
      map,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['formatString', funcDecl.id]]),
    });

    const depGraph: DependencyGraph = {
      files: ['utils.js'],
      edges: [],
      importsOf: new Map(),
      importedBy: new Map(),
    };

    runMarginPass(summaries, depGraph);

    const summary = summaries.get('utils.js')!;
    // functionSinkContext may be undefined or may exist but NOT contain this function
    const ctx = summary.functionSinkContext;
    if (ctx) {
      expect(ctx.has(funcDecl.id)).toBe(false);
    }
    // If ctx is undefined, that also means no sinks were cataloged — pass
  });

  it('pushes caller sink-context to imported function (Ghost CMS pattern)', () => {
    // File A (posts.js): has INGRESS + STORAGE/sql_query sink, imports slugFilterOrder
    const mapA = createNeuralMap('posts.js', '');
    const handlerFunc = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'browse',
      line_start: 1, line_end: 20,
      edges: [
        { target: 'sink_knex', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    });
    const knexSink = createNode({
      id: 'sink_knex',
      node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'knex.raw(query)',
      line_start: 15, line_end: 15,
      data_in: [],
      edges: [],
    });
    mapA.nodes = [handlerFunc, knexSink];

    // File B (slug-filter-order.js): has slugFilterOrder function, NO sinks
    // (builds SQL string via template literal, doesn't execute it)
    const mapB = createNeuralMap('slug-filter-order.js', '');
    const sfoFunc = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'slugFilterOrder',
      param_names: ['table', 'filter'],
      line_start: 1, line_end: 30,
      edges: [],
    });
    const templateNode = createNode({
      node_type: 'TRANSFORM', node_subtype: 'template_string',
      label: 'template literal',
      line_start: 10, line_end: 10,
      code_snapshot: "`WHEN slug = '${filter}' THEN ${index}`",
      data_in: [],
      edges: [],
    });
    mapB.nodes = [sfoFunc, templateNode];

    const summaries = new Map<string, FileSummary>();
    summaries.set('posts.js', {
      map: mapA,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['browse', handlerFunc.id]]),
    });
    summaries.set('slug-filter-order.js', {
      map: mapB,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['slugFilterOrder', sfoFunc.id]]),
    });

    const depGraph: DependencyGraph = {
      files: ['posts.js', 'slug-filter-order.js'],
      edges: [{
        from: 'posts.js',
        to: 'slug-filter-order.js',
        importInfo: {
          specifier: './slug-filter-order',
          resolvedPath: 'slug-filter-order.js',
          importedNames: ['slugFilterOrder'],
          localName: 'slugFilterOrder',
          line: 1,
        },
      }],
      importsOf: new Map([['posts.js', ['slug-filter-order.js']]]),
      importedBy: new Map([['slug-filter-order.js', ['posts.js']]]),
    };

    runMarginPass(summaries, depGraph);

    // posts.js should have browse tagged with sql_query (direct cataloging)
    const postsSummary = summaries.get('posts.js')!;
    expect(postsSummary.functionSinkContext?.get(handlerFunc.id)?.has('sql_query')).toBe(true);

    // slug-filter-order.js should have slugFilterOrder tagged with sql_query
    // (propagated from posts.js — the caller has sinks, pushes to its imports)
    const sfoSummary = summaries.get('slug-filter-order.js')!;
    expect(sfoSummary.functionSinkContext).toBeDefined();
    expect(sfoSummary.functionSinkContext!.get(sfoFunc.id)?.has('sql_query')).toBe(true);
  });

  it('multi-hop: caller sink-context propagates through chain', () => {
    // File A (controller.js): has STORAGE/sql_query, imports from B
    const mapA = createNeuralMap('controller.js', '');
    const ctrlFunc = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'handleRequest',
      line_start: 1, line_end: 20,
      edges: [
        { target: 'sink_db', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    });
    const dbSink = createNode({
      id: 'sink_db',
      node_type: 'STORAGE', node_subtype: 'sql_query',
      line_start: 15, line_end: 15,
      data_in: [],
      edges: [],
    });
    mapA.nodes = [ctrlFunc, dbSink];

    // File B (query-builder.js): imports from C, no direct sinks
    const mapB = createNeuralMap('query-builder.js', '');
    const buildFunc = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'buildQuery',
      line_start: 1, line_end: 15,
      edges: [],
    });
    mapB.nodes = [buildFunc];

    // File C (filter-utils.js): builds SQL strings, no sinks
    const mapC = createNeuralMap('filter-utils.js', '');
    const filterFunc = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'buildFilter',
      line_start: 1, line_end: 10,
      edges: [],
    });
    mapC.nodes = [filterFunc];

    const summaries = new Map<string, FileSummary>();
    summaries.set('controller.js', {
      map: mapA,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['handleRequest', ctrlFunc.id]]),
    });
    summaries.set('query-builder.js', {
      map: mapB,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['buildQuery', buildFunc.id]]),
    });
    summaries.set('filter-utils.js', {
      map: mapC,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['buildFilter', filterFunc.id]]),
    });

    // A imports from B, B imports from C
    const depGraph: DependencyGraph = {
      files: ['controller.js', 'query-builder.js', 'filter-utils.js'],
      edges: [
        {
          from: 'controller.js', to: 'query-builder.js',
          importInfo: { specifier: './query-builder', resolvedPath: 'query-builder.js', importedNames: ['buildQuery'], localName: 'buildQuery', line: 1 },
        },
        {
          from: 'query-builder.js', to: 'filter-utils.js',
          importInfo: { specifier: './filter-utils', resolvedPath: 'filter-utils.js', importedNames: ['buildFilter'], localName: 'buildFilter', line: 1 },
        },
      ],
      importsOf: new Map([
        ['controller.js', ['query-builder.js']],
        ['query-builder.js', ['filter-utils.js']],
        ['filter-utils.js', []],
      ]),
      importedBy: new Map([
        ['query-builder.js', ['controller.js']],
        ['filter-utils.js', ['query-builder.js']],
        ['controller.js', []],
      ]),
    };

    runMarginPass(summaries, depGraph);

    // controller.js: direct cataloging (handleRequest contains sql_query)
    expect(summaries.get('controller.js')!.functionSinkContext?.get(ctrlFunc.id)?.has('sql_query')).toBe(true);

    // query-builder.js: buildQuery tagged via propagation from controller.js
    expect(summaries.get('query-builder.js')!.functionSinkContext?.get(buildFunc.id)?.has('sql_query')).toBe(true);

    // filter-utils.js: buildFilter tagged via multi-hop (controller→query-builder→filter-utils)
    expect(summaries.get('filter-utils.js')!.functionSinkContext?.get(filterFunc.id)?.has('sql_query')).toBe(true);
  });
});
