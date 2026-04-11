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

  it('propagates sink-context backward to importer', () => {
    // File A (routes.js): has a call site node, no sinks
    const mapA = createNeuralMap('routes.js', '');
    const callSite = createNode({
      node_type: 'TRANSFORM', node_subtype: 'local_call',
      label: 'buildQuery(filter)',
      code_snapshot: "buildQuery(filter)",
      data_in: [],
      edges: [],
    });
    mapA.nodes = [callSite];

    // File B (query-builder.js): has function buildQuery containing a STORAGE/sql_query sink
    const mapB = createNeuralMap('query-builder.js', '');
    const funcDecl = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'buildQuery',
      param_names: ['filter'],
      line_start: 1, line_end: 10,
      edges: [
        { target: 'sink_sql', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    });
    const sqlSink = createNode({
      id: 'sink_sql',
      node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'db.query(filter)',
      line_start: 5, line_end: 5,
      data_in: [{ name: 'filter', source: 'param', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    mapB.nodes = [funcDecl, sqlSink];

    const summaries = new Map<string, FileSummary>();
    summaries.set('routes.js', {
      map: mapA,
      functionReturnTaint: new Map(),
      functionRegistry: new Map(),
    });
    summaries.set('query-builder.js', {
      map: mapB,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['buildQuery', funcDecl.id]]),
    });

    // Dep graph: routes.js imports buildQuery from query-builder.js
    const depGraph: DependencyGraph = {
      files: ['routes.js', 'query-builder.js'],
      edges: [{
        from: 'routes.js',
        to: 'query-builder.js',
        importInfo: {
          specifier: './query-builder',
          resolvedPath: 'query-builder.js',
          importedNames: ['buildQuery'],
          localName: 'buildQuery',
          line: 1,
        },
      }],
      importsOf: new Map([['routes.js', ['query-builder.js']]]),
      importedBy: new Map([['query-builder.js', ['routes.js']]]),
    };

    runMarginPass(summaries, depGraph);

    // routes.js should have functionSinkContext with sql_query propagated from query-builder.js
    const routesSummary = summaries.get('routes.js')!;
    expect(routesSummary.functionSinkContext).toBeDefined();
    // The propagated entry should be keyed by the local import name 'buildQuery'
    const hasSQL = [...routesSummary.functionSinkContext!.values()].some(s => s.has('sql_query'));
    expect(hasSQL).toBe(true);
  });

  it('propagates sink-context through multi-hop imports', () => {
    // File C (db.js): has function executeQuery containing STORAGE/sql_query
    const mapC = createNeuralMap('db.js', '');
    const execFunc = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'executeQuery',
      param_names: ['sql'],
      line_start: 1, line_end: 10,
      edges: [
        { target: 'sink_sql_c', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    });
    const sqlSinkC = createNode({
      id: 'sink_sql_c',
      node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'db.execute(sql)',
      line_start: 5, line_end: 5,
      data_in: [{ name: 'sql', source: 'param', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    mapC.nodes = [execFunc, sqlSinkC];

    // File B (query-builder.js): imports executeQuery from db.js, has function buildQuery (no direct sinks)
    const mapB = createNeuralMap('query-builder.js', '');
    const buildFunc = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'buildQuery',
      param_names: ['filter'],
      line_start: 1, line_end: 10,
      edges: [],
    });
    mapB.nodes = [buildFunc];

    // File A (routes.js): imports buildQuery from query-builder.js
    const mapA = createNeuralMap('routes.js', '');
    const callSite = createNode({
      node_type: 'TRANSFORM', node_subtype: 'local_call',
      label: 'buildQuery(filter)',
      code_snapshot: "buildQuery(filter)",
      data_in: [],
      edges: [],
    });
    mapA.nodes = [callSite];

    const summaries = new Map<string, FileSummary>();
    summaries.set('routes.js', {
      map: mapA,
      functionReturnTaint: new Map(),
      functionRegistry: new Map(),
    });
    summaries.set('query-builder.js', {
      map: mapB,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['buildQuery', buildFunc.id]]),
    });
    summaries.set('db.js', {
      map: mapC,
      functionReturnTaint: new Map(),
      functionRegistry: new Map([['executeQuery', execFunc.id]]),
    });

    // Dep graph: A→B→C
    const depGraph: DependencyGraph = {
      files: ['routes.js', 'query-builder.js', 'db.js'],
      edges: [
        {
          from: 'routes.js',
          to: 'query-builder.js',
          importInfo: {
            specifier: './query-builder',
            resolvedPath: 'query-builder.js',
            importedNames: ['buildQuery'],
            localName: 'buildQuery',
            line: 1,
          },
        },
        {
          from: 'query-builder.js',
          to: 'db.js',
          importInfo: {
            specifier: './db',
            resolvedPath: 'db.js',
            importedNames: ['executeQuery'],
            localName: 'executeQuery',
            line: 1,
          },
        },
      ],
      importsOf: new Map([
        ['routes.js', ['query-builder.js']],
        ['query-builder.js', ['db.js']],
      ]),
      importedBy: new Map([
        ['query-builder.js', ['routes.js']],
        ['db.js', ['query-builder.js']],
      ]),
    };

    runMarginPass(summaries, depGraph);

    // db.js should have executeQuery tagged with sql_query (direct sink cataloging)
    const dbSummary = summaries.get('db.js')!;
    expect(dbSummary.functionSinkContext).toBeDefined();
    expect(dbSummary.functionSinkContext!.has(execFunc.id)).toBe(true);
    expect(dbSummary.functionSinkContext!.get(execFunc.id)!.has('sql_query')).toBe(true);

    // query-builder.js should get sql_query propagated from db.js
    const qbSummary = summaries.get('query-builder.js')!;
    expect(qbSummary.functionSinkContext).toBeDefined();
    const qbHasSQL = [...qbSummary.functionSinkContext!.values()].some(s => s.has('sql_query'));
    expect(qbHasSQL).toBe(true);
  });
});
