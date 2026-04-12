# Phase A: Graph-Derived Security Domains — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the regex-based `inferPayloadClassFromContent()` with graph-derived security domain classification — the proof system reads domain tags set by backward traversal from sinks, not by scanning code content for keywords.

**Architecture:** Add `security_domain?: string` to DataFlow. Build a reverse edge index in the mapper post-processing. After all edges are built, backward-BFS from each STORAGE/EXTERNAL/EGRESS sink to tag feeding data flows with the sink's subtype. The margin pass carries these domains across file boundaries via the existing `cross_file_param_taint_via_*` entries. `generateProof` reads the domain tag instead of calling `inferPayloadClassFromContent`. The regex fallback is deleted.

**Tech Stack:** TypeScript, Vitest, tree-sitter (existing — no new deps)

---

## What to Be Careful About

1. **The reverse edge index must be built AFTER all edges are constructed.** In `buildNeuralMap`, the edge-building sequence is: `buildCallsEdges` → `buildDataFlowEdges` → `propagateInterproceduralTaint` → `buildReadsEdges` → `buildWritesEdges` → `buildDependsEdges`. The reverse index goes AFTER `buildDependsEdges` so it captures ALL edge types.

2. **Backward BFS must respect edge type filtering.** Not all edges represent data flow. CONTAINS edges mean "this node is inside that function" — following them backward would tag every function that contains a function that contains a sink. Only follow DATA_FLOW, CALLS, READS, WRITES, RETURNS edges backward.

3. **Avoid tagging the sink node itself.** The sink's subtype is already known. We're tagging UPSTREAM nodes that FEED the sink. Start BFS from the sink but don't tag it.

4. **The margin pass synthetic entries need domain.** When PASS 2 creates `cross_file_param_taint_via_*` DataFlow entries (margin-pass.ts lines 319-348), they should carry `security_domain` from the callee's `functionSinkContext` if available.

5. **Don't break the existing 1809 tests.** `security_domain` is optional. All existing code continues working without it. The proof system falls back through the chain: sink-class → CWE-class → sinkContext → domain tag → ~~content inference~~.

6. **Phase B insight to watch for:** While building the reverse index and backward BFS, note which phoneme classifications correspond to security state transitions. The backward BFS naturally identifies "sanitizer" nodes (TRANSFORM with neutralizing subtypes) that sit between sources and sinks. These are the state transition points for Phase B.

---

## Task 1: Add `security_domain` to DataFlow + Build Reverse Edge Index

**Files:**
- Modify: `src/types.ts:124-134` — add `security_domain?: string` to DataFlow
- Modify: `src/mapper.ts:1038-1051` — build reverse edge index after edge construction, store on NeuralMap
- Modify: `src/types.ts:171-179` — add `reverseEdgeIndex?: Map<string, Array<{source: string, edge_type: string}>>` to NeuralMap
- Test: `src/payload-gen.test.ts` — test reverse index construction

**Step 1: Write the failing test**

Add to `src/payload-gen.test.ts`:

```typescript
describe('reverse edge index', () => {
  beforeEach(() => resetSequence());

  it('provides predecessors for backward traversal', () => {
    const source = createNode({
      id: 'src', node_type: 'INGRESS', node_subtype: 'http_request',
      edges: [{ target: 'mid', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const mid = createNode({
      id: 'mid', node_type: 'TRANSFORM', node_subtype: 'template_string',
      edges: [{ target: 'sink', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink', node_type: 'STORAGE', node_subtype: 'sql_query',
      edges: [],
    });
    const map = buildTestMap([source, mid, sink]);

    // Build reverse index manually (same logic as mapper)
    const { buildReverseEdgeIndex } = await import('./mapper.js');
    const reverseIndex = buildReverseEdgeIndex(map);

    // sink should have mid as predecessor
    const sinkPreds = reverseIndex.get('sink') ?? [];
    expect(sinkPreds.some(e => e.source === 'mid' && e.edge_type === 'DATA_FLOW')).toBe(true);

    // mid should have src as predecessor
    const midPreds = reverseIndex.get('mid') ?? [];
    expect(midPreds.some(e => e.source === 'src' && e.edge_type === 'DATA_FLOW')).toBe(true);

    // src should have no predecessors
    const srcPreds = reverseIndex.get('src') ?? [];
    expect(srcPreds.length).toBe(0);
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd /c/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/payload-gen.test.ts -t "provides predecessors"`
Expected: FAIL — `buildReverseEdgeIndex` doesn't exist.

**Step 3: Add `security_domain` to DataFlow in `types.ts`**

In `src/types.ts`, add to the DataFlow interface (around line 134):
```typescript
export interface DataFlow {
  name: string;
  source: string;
  target?: string;
  data_type: string;
  tainted: boolean;
  sensitivity: Sensitivity;
  range?: RangeInfo;
  write_size?: RangeInfo;
  /** Security domain derived from the sink this data feeds — e.g., 'sql_query', 'system_exec'.
   *  Set by backward traversal from sinks. NOT regex — the graph tells you. */
  security_domain?: string;
}
```

**Step 4: Add `buildReverseEdgeIndex` to `mapper.ts`**

Add as an exported function at the end of the post-processing section (before `buildNeuralMap` returns):

```typescript
/**
 * Build a reverse edge index for backward traversal.
 * Maps each target nodeId → array of { source, edge_type } entries.
 * O(e) construction, enables O(1) predecessor lookup.
 */
export function buildReverseEdgeIndex(
  map: NeuralMap,
): Map<string, Array<{ source: string; edge_type: string }>> {
  const index = new Map<string, Array<{ source: string; edge_type: string }>>();
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      let arr = index.get(edge.target);
      if (!arr) {
        arr = [];
        index.set(edge.target, arr);
      }
      arr.push({ source: node.id, edge_type: edge.edge_type });
    }
  }
  return index;
}
```

And call it in `buildNeuralMap`, after `buildDependsEdges()` (line 1038):

```typescript
  ctx.buildDependsEdges();

  // Build reverse edge index for backward traversal (used by domain tagging)
  const reverseEdgeIndex = buildReverseEdgeIndex(ctx.neuralMap);
  ctx.neuralMap.reverseEdgeIndex = reverseEdgeIndex;
```

**Step 5: Add `reverseEdgeIndex` to NeuralMap in `types.ts`**

In `src/types.ts`, add to NeuralMap (around line 178):
```typescript
export interface NeuralMap {
  nodes: NeuralMapNode[];
  edges: Edge[];
  source_file: string;
  source_code: string;
  created_at: string;
  parser_version: string;
  story?: SemanticSentence[];
  /** Reverse edge index: target nodeId → sources. Built post-processing for backward BFS. */
  reverseEdgeIndex?: Map<string, Array<{ source: string; edge_type: string }>>;
}
```

**Step 6: Run test to verify it passes**

Run: `cd /c/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/payload-gen.test.ts`
Expected: ALL tests pass.

**Step 7: Run full test suite**

Run: `cd /c/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run 2>&1 | tail -5`
Expected: 1809+ tests passing, 0 failures.

**Step 8: Commit**

```bash
git commit -m "feat: add security_domain to DataFlow + reverse edge index for backward BFS

Adds optional security_domain field to DataFlow for graph-derived
vulnerability classification. Adds buildReverseEdgeIndex() to mapper
that builds a target→sources map enabling O(1) predecessor lookup.
Called during buildNeuralMap post-processing after all edges are built.

This is the foundation for replacing regex-based content inference with
graph-derived domain classification."
```

---

## Task 2: Backward BFS from Sinks — Tag Feeding Nodes with Domain

**Files:**
- Modify: `src/mapper.ts` — add `tagSecurityDomains` function, call after reverse index
- Test: `src/payload-gen.test.ts` — test domain tagging

**Step 1: Write the failing test**

```typescript
describe('security domain tagging via backward BFS', () => {
  beforeEach(() => resetSequence());

  it('tags data_in of nodes feeding a STORAGE/sql_query sink', () => {
    // Build a chain: INGRESS → TRANSFORM → STORAGE/sql_query
    // The TRANSFORM's data that feeds sql_query should get security_domain = 'sql_query'
    const source = createNode({
      id: 'src', node_type: 'INGRESS', node_subtype: 'http_request',
      line_start: 1,
      data_out: [{ name: 'input', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'mid', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const mid = createNode({
      id: 'mid', node_type: 'TRANSFORM', node_subtype: 'template_string',
      line_start: 5,
      data_in: [{ name: 'input', source: 'src', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      data_out: [{ name: 'query', source: 'mid', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'sink', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink', node_type: 'STORAGE', node_subtype: 'sql_query',
      line_start: 10,
      data_in: [{ name: 'query', source: 'mid', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    const map = buildTestMap([source, mid, sink]);

    const { buildReverseEdgeIndex, tagSecurityDomains } = await import('./mapper.js');
    const reverseIndex = buildReverseEdgeIndex(map);
    tagSecurityDomains(map, reverseIndex);

    // The TRANSFORM node feeding sql_query should have security_domain set on its data_out
    const midNode = map.nodes.find(n => n.id === 'mid')!;
    expect(midNode.data_out.some(d => d.security_domain === 'sql_query')).toBe(true);

    // The INGRESS node feeding the chain should also get tagged
    const srcNode = map.nodes.find(n => n.id === 'src')!;
    expect(srcNode.data_out.some(d => d.security_domain === 'sql_query')).toBe(true);
  });

  it('does NOT tag nodes that do not feed any sink', () => {
    const isolated = createNode({
      id: 'iso', node_type: 'TRANSFORM', node_subtype: 'format',
      data_out: [{ name: 'x', source: 'iso', data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    const map = buildTestMap([isolated]);

    const { buildReverseEdgeIndex, tagSecurityDomains } = await import('./mapper.js');
    const reverseIndex = buildReverseEdgeIndex(map);
    tagSecurityDomains(map, reverseIndex);

    expect(isolated.data_out.every(d => d.security_domain === undefined)).toBe(true);
  });
});
```

**Step 2: Run test to verify it fails**

Expected: FAIL — `tagSecurityDomains` doesn't exist.

**Step 3: Implement `tagSecurityDomains`**

Add to `src/mapper.ts`:

```typescript
/** Edge types that represent actual data flow (not structural containment). */
const FLOW_EDGE_TYPES_FOR_DOMAIN: ReadonlySet<string> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);

/**
 * Backward BFS from each sink to tag feeding nodes with the sink's security domain.
 * Sets `security_domain` on data_out entries of upstream nodes.
 *
 * The graph tells you what each data flow feeds. No regex. No keywords.
 */
export function tagSecurityDomains(
  map: NeuralMap,
  reverseIndex: Map<string, Array<{ source: string; edge_type: string }>>,
): void {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  // Find all sink nodes
  const sinkTypes = new Set(['STORAGE', 'EXTERNAL', 'EGRESS']);
  const sinks = map.nodes.filter(n => sinkTypes.has(n.node_type) && n.node_subtype);

  for (const sink of sinks) {
    const domain = sink.node_subtype;

    // Backward BFS from this sink
    const visited = new Set<string>();
    const queue = [sink.id];

    while (queue.length > 0) {
      const nodeId = queue.shift()!;
      if (visited.has(nodeId)) continue;
      visited.add(nodeId);

      // Tag data_out entries of upstream nodes (not the sink itself)
      if (nodeId !== sink.id) {
        const node = nodeMap.get(nodeId);
        if (node) {
          for (const d of node.data_out) {
            if (!d.security_domain) {
              d.security_domain = domain;
            }
          }
        }
      }

      // Follow reverse edges (predecessors)
      const preds = reverseIndex.get(nodeId) ?? [];
      for (const { source, edge_type } of preds) {
        if (FLOW_EDGE_TYPES_FOR_DOMAIN.has(edge_type) && !visited.has(source)) {
          queue.push(source);
        }
      }
    }
  }
}
```

Call it in `buildNeuralMap` after the reverse index:

```typescript
  const reverseEdgeIndex = buildReverseEdgeIndex(ctx.neuralMap);
  ctx.neuralMap.reverseEdgeIndex = reverseEdgeIndex;
  tagSecurityDomains(ctx.neuralMap, reverseEdgeIndex);
```

**Step 4: Run tests, full suite, commit**

Run tests, verify 1809+ passing, commit:
```bash
git commit -m "feat: backward BFS from sinks tags feeding nodes with security_domain

tagSecurityDomains() walks backward from every STORAGE/EXTERNAL/EGRESS
node via the reverse edge index, setting security_domain on upstream
data_out entries. The graph derives the domain — no regex needed.

A TRANSFORM/template_string feeding a STORAGE/sql_query gets
security_domain='sql_query' automatically."
```

---

## Task 3: Carry Domain in Cross-File Synthetic Entries

**Files:**
- Modify: `src/margin-pass.ts:305-350` — add security_domain to synthetic DataFlow entries
- Test: `src/margin-pass-param-taint.test.ts` — test domain propagation

**Step 1: Write the failing test**

Add to the `Sink-context cataloging` describe block:

```typescript
  it('carries security_domain in cross_file_param_taint synthetic entries', () => {
    // File A (posts.js): has INGRESS + STORAGE/sql_query, imports slugFilterOrder
    const mapA = createNeuralMap('posts.js', '');
    const handlerFunc = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'browse', line_start: 1, line_end: 20,
      edges: [{ target: 'sink_knex', edge_type: 'CONTAINS', conditional: false, async: false }],
    });
    const ingress = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request',
      label: 'req.query.filter', line_start: 2,
      data_out: [{ name: 'filter', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    const callSite = createNode({
      node_type: 'TRANSFORM', node_subtype: 'local_call',
      label: 'slugFilterOrder(filter)',
      code_snapshot: "slugFilterOrder('posts', filter)",
      data_in: [{ name: 'filter', source: ingress.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    const knexSink = createNode({
      id: 'sink_knex', node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'knex.raw(query)', line_start: 15, line_end: 15,
      data_in: [], edges: [],
    });
    mapA.nodes = [handlerFunc, ingress, callSite, knexSink];

    // File B (slug-filter-order.js): no sinks, has function
    const mapB = createNeuralMap('slug-filter-order.js', '');
    const sfoFunc = createNode({
      node_type: 'STRUCTURAL', node_subtype: 'function',
      label: 'slugFilterOrder', line_start: 1, line_end: 20,
      edges: [{ target: 'tmpl', edge_type: 'CONTAINS', conditional: false, async: false }],
    });
    const tmpl = createNode({
      id: 'tmpl', node_type: 'TRANSFORM', node_subtype: 'template_string',
      label: 'template literal', line_start: 10, line_end: 10,
      data_in: [], edges: [],
    });
    mapB.nodes = [sfoFunc, tmpl];

    const summaries = new Map<string, FileSummary>();
    summaries.set('posts.js', {
      map: mapA, functionReturnTaint: new Map(),
      functionRegistry: new Map([['browse', handlerFunc.id]]),
    });
    summaries.set('slug-filter-order.js', {
      map: mapB, functionReturnTaint: new Map(),
      functionRegistry: new Map([['slugFilterOrder', sfoFunc.id]]),
    });

    const depGraph: DependencyGraph = {
      files: ['posts.js', 'slug-filter-order.js'],
      edges: [{
        from: 'posts.js', to: 'slug-filter-order.js',
        importInfo: { specifier: './slug-filter-order', resolvedPath: 'slug-filter-order.js',
          importedNames: ['slugFilterOrder'], localName: 'slugFilterOrder', line: 1 },
      }],
      importsOf: new Map([['posts.js', ['slug-filter-order.js']]]),
      importedBy: new Map([['slug-filter-order.js', ['posts.js']]]),
    };

    runMarginPass(summaries, depGraph);

    // The template node in slug-filter-order.js should have
    // synthetic data_in with security_domain = 'sql_query'
    const tmplNode = mapB.nodes.find(n => n.id === 'tmpl')!;
    const crossFileEntry = tmplNode.data_in.find(d =>
      d.name.startsWith('cross_file_param_taint_via_')
    );
    expect(crossFileEntry).toBeDefined();
    expect(crossFileEntry!.security_domain).toBe('sql_query');
  });
```

**Step 2: Run test to verify it fails**

Expected: FAIL — synthetic entries don't have security_domain.

**Step 3: Modify margin-pass.ts PASS 2 to carry domain**

In PASS 2 (lines 305-350), where synthetic entries are pushed, extract the domain from `functionSinkContext` and set it:

Before the inner loop that creates synthetic entries, look up the function's sink context:

```typescript
// Look up security domain from functionSinkContext if available
const sinkCtx = depSummary.functionSinkContext?.get(funcNodeId);
const securityDomain = sinkCtx ? [...sinkCtx][0] : undefined;
```

Then in each `.push()` call for synthetic entries, add the domain:

```typescript
node.data_in.push({
  name: `cross_file_param_taint_via_${funcName}`,
  source: 'EXTERNAL',
  data_type: 'unknown',
  tainted: true,
  sensitivity: 'NONE',
  ...(securityDomain ? { security_domain: securityDomain } : {}),
});
```

Apply this to ALL FOUR synthetic push locations (STORAGE/EXTERNAL/EGRESS empty data_in at line 319, TRANSFORM empty data_in at line 341).

**Step 4: Run tests, full suite, commit**

```bash
git commit -m "feat: carry security_domain in cross-file synthetic taint entries

When the margin pass creates cross_file_param_taint_via_* DataFlow
entries, it now looks up the function's sink context from
functionSinkContext and sets security_domain on the synthetic entry.

This means cross-file taint carries its destination domain with it.
The proof system can read it directly."
```

---

## Task 4: generateProof Reads security_domain — Delete Content Inference

**Files:**
- Modify: `src/payload-gen.ts` — add domain-based fallback, remove `inferPayloadClassFromContent`
- Modify: `src/payload-gen.test.ts` — update tests
- Modify: `src/dst-cli.ts` — remove content inference import if needed

**Step 1: Write the failing test**

```typescript
describe('generateProof reads security_domain from data_in', () => {
  beforeEach(() => resetSequence());

  it('resolves payload class from security_domain on tainted data_in', () => {
    const source = createNode({
      id: 'src_1', node_type: 'INGRESS', node_subtype: 'framework_handler',
      line_start: 1,
      data_out: [{ name: 'frame', source: '', data_type: 'object', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1', node_type: 'TRANSFORM', node_subtype: 'template_string',
      line_start: 10,
      code_snapshot: "order += `WHEN slug = '${slug}' THEN ${index}`",
      data_in: [{
        name: 'cross_file_param_taint_via_slugFilterOrder',
        source: 'EXTERNAL', data_type: 'unknown',
        tainted: true, sensitivity: 'NONE',
        security_domain: 'sql_query',  // ← Set by margin pass
      }],
      edges: [],
    });
    const map = buildTestMap([source, sink]);
    const finding = makeFinding('src_1', 'sink_1');

    // Should resolve via security_domain, no sinkContext needed
    const proof = generateProof(map, finding, 'CWE-190');
    expect(proof).not.toBeNull();
    expect(proof!.primary_payload.canary).toBe('DST_CANARY_SQLI');
  });
});
```

**Step 2: Implement security_domain fallback in `generateProof`**

In `src/payload-gen.ts`, REPLACE the `inferPayloadClassFromContent` call with a `security_domain` check:

```typescript
  // Security domain fallback: if the node's data_in carries a domain tag
  // (set by backward BFS from sinks or cross-file margin pass), use it.
  // The graph tells you what this data feeds. No regex.
  if (!payloadClass && sinkNode) {
    for (const d of sinkNode.data_in) {
      if (d.security_domain) {
        payloadClass = resolveSinkClass(d.security_domain);
        if (payloadClass) break;
      }
    }
  }
  // Also check data_out (backward BFS tags data_out of feeding nodes)
  if (!payloadClass && sinkNode) {
    for (const d of sinkNode.data_out) {
      if (d.security_domain) {
        payloadClass = resolveSinkClass(d.security_domain);
        if (payloadClass) break;
      }
    }
  }
```

**Step 3: Delete `inferPayloadClassFromContent`**

Remove the function entirely from `payload-gen.ts`. Remove its export. Remove the call site. Remove the import in the test file if it was imported. Update any tests that relied on it to use `security_domain` instead.

**Step 4: Update tests that tested content inference**

The 4 tests for `inferPayloadClassFromContent` need to be either:
- Deleted (if they only tested the regex function)
- Or converted to test `security_domain` on data_in

Keep the test that verifies "harmless content returns null" but reframe it: a node without `security_domain` and with CWE-190 should return null (no proof). That's correct behavior — the graph didn't tag it, so we don't know what it is.

**Step 5: Run tests, full suite, commit**

```bash
git commit -m "feat: generateProof reads security_domain — delete content inference

The proof system now reads security_domain from DataFlow entries
instead of regex-matching code content. The graph tells you what
each data flow feeds. Same input → same graph → same domain → same
proof. Deterministic.

Removes inferPayloadClassFromContent() entirely. The regex-based
fallback is replaced by graph-derived classification."
```

---

## Task 5: End-to-End Verification — Ghost CMS + Full Suite

**Files:**
- None modified — verification only

**Step 1: Run full test suite**

Run: `cd /c/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run 2>&1 | tail -5`
Expected: 1809+ tests passing.

**Step 2: Run Ghost CMS scan**

Run: `cd /c/Users/pizza/DST_Alpha_v1/dst-engine && npx tsx src/dst-cli.ts /c/Users/pizza/ghost-test/ --prove --json 2>&1 | grep "inferred_class\|DST_CANARY\|sql_injection\|proof_strength\|security_domain" | head -20`

Expected: SQL injection proofs on slug-filter-order.js with `DST_CANARY_SQLI`, derived from `security_domain` not content regex.

**Step 3: Verify no content regex in codebase**

Run: `grep -r "inferPayloadClassFromContent" src/`
Expected: 0 matches. The band-aid is gone.

**Step 4: Update docs/TODO.md**

Mark Phase A complete. Note that `inferPayloadClassFromContent` has been replaced by graph-derived `security_domain`.

**Step 5: Commit**

```bash
git commit -m "docs: Phase A complete — graph-derived security domains replace content inference"
```

---

## Confidence Assessment

| Component | Confidence | Notes |
|---|---|---|
| `security_domain` on DataFlow | **0** (right) | Optional field, zero breaking changes |
| Reverse edge index | **0** (right) | Standard adjacency list inversion, O(e), well-understood |
| Backward BFS tagging | **0** (right) | Same BFS as forward, just reversed. Edge type filtering critical. |
| Cross-file domain carrying | **1** (hesitant) | Depends on PASS 3 having correct sink context on the callee's functions BEFORE PASS 2 runs. But PASS 3 runs AFTER PASS 2 in the margin pass. The domain might not be available when synthetic entries are created. May need to reorder passes or do a second PASS 2 iteration. |
| Delete content inference | **0** (right) | Clean removal of one function + its call site |
| Ghost CMS end-to-end | **1** (hesitant) | Same uncertainty as before: posts.js may not have STORAGE/sql_query node if knex.raw is in another file. The backward BFS helps within each file but cross-file depends on PASS 3 sink context. |

## Phase B Observations (Think About While Building)

While implementing the backward BFS (Task 2), observe:
- Which TRANSFORM subtypes sit between INGRESS and sinks? These are state transition candidates.
- The `neutralizing subtypes` in taint-reachability (sanitize, encrypt, hash, encode, escape, validate, parameterize, prepared_statement) are exactly the Phase B state transitions.
- The backward BFS naturally partitions the graph into "feeds sql_query" vs "feeds system_exec" vs "feeds http_response" regions. Each region has different neutralizers. This IS the state machine.
- The `security_domain` field is the first step toward `SecurityState`. In Phase B, `security_domain` becomes the REQUIRED state, and a new field `security_state` tracks the ACTUAL state. The mismatch is the finding.
