# Handler Parameter Taint Inference — Atomic Steps

> **For next session:** This is the handoff document. Context: DST needs to detect that `query(frame)` inside `module.exports = { browse: { query(frame) {} } }` has a tainted first parameter, without knowing "Ghost" by name.

**Goal:** Detect verb-named methods inside `module.exports` objects and mark their first parameter as tainted. This is the last piece needed to detect the Ghost CMS SQLi (CVE-2026-26980) end-to-end.

**Chain:** Handler inference (this) → cross-file param taint (commit 6ae1865) → taint-reachability property (Phase 1) → CWE-89 finding

---

## AST Structure (verified via tree-sitter)

```
assignment_expression
  left: member_expression "module.exports"
  right: object
    pair (key: "browse")         ← action group
      value: object
        method_definition        ← THE HANDLER
          name: property_identifier "query"   ← verb name
          formal_parameters
            identifier "frame"   ← SHOULD BE TAINTED
```

The handler is a `method_definition` whose ancestor chain goes:
`method_definition` → parent `object` → parent `pair` → parent `object` → parent `assignment_expression` with left = `module.exports`

---

## Atomic Steps

### Step 1: Test fixture file

Create `src/test-fixtures/ghost-pattern.js`:
```javascript
const db = require('./db');
module.exports = {
  browse: {
    query(frame) {
      const filter = frame.options.filter;
      const q = "SELECT * FROM posts WHERE slug = '" + filter + "'";
      return db.query(q);
    }
  }
};
```

This has: module.exports → verb method → parameter → string concat → SQL sink. All in one file.

**Run:** `npx tsx src/dst-cli.ts src/test-fixtures/ghost-pattern.js` — expect 0 findings (baseline: frame not tainted)

---

### Step 2: Failing test

Add to a new test file `src/handler-inference.test.ts`:

```typescript
it('marks first param of verb-named method in module.exports as tainted', () => {
  // Parse the ghost-pattern.js fixture
  // Check that the NeuralMap has an INGRESS node for 'frame'
  // OR that the variable 'frame' in scope is marked tainted
});
```

**Run:** confirm it fails

---

### Step 3: Detect module.exports ancestor

In `src/profiles/javascript.ts`, inside `processFunctionParams`, add a check:

```typescript
function isExportedVerbMethod(funcNode: SyntaxNode): boolean {
  // funcNode is a method_definition
  if (funcNode.type !== 'method_definition') return false;
  
  // Check method name is a verb
  const name = funcNode.childForFieldName('name')?.text;
  const HANDLER_VERBS = new Set([
    'query', 'read', 'browse', 'edit', 'destroy', 'add',
    'create', 'update', 'delete', 'list', 'find', 'search',
    'remove', 'get', 'post', 'put', 'patch', 'handle',
    'execute', 'run', 'process', 'fetch', 'save',
  ]);
  if (!name || !HANDLER_VERBS.has(name)) return false;
  
  // Walk up parent chain looking for module.exports assignment
  let node = funcNode.parent; // object (containing this method)
  while (node) {
    if (node.type === 'assignment_expression') {
      const left = node.childForFieldName('left');
      if (left?.text === 'module.exports') return true;
      if (left?.type === 'member_expression') {
        const obj = left.childForFieldName('object');
        if (obj?.text === 'module' || obj?.text === 'exports') return true;
      }
    }
    // Also handle: export default { ... }
    if (node.type === 'export_statement') return true;
    node = node.parent;
  }
  return false;
}
```

---

### Step 4: Mark parameters tainted

In `processFunctionParams`, after the existing Express handler check, add:

```typescript
// Ghost/Strapi/Keystone pattern: verb-named method in module.exports
if (isExportedVerbMethod(node)) {
  // Mark first parameter as tainted
  const params = node.childForFieldName('parameters');
  if (params && params.namedChildCount > 0) {
    const firstParam = params.namedChild(0);
    if (firstParam?.type === 'identifier') {
      ctx.declareVariable(firstParam.text, 'param', null, true, null);
      // Create INGRESS node for this parameter
      const ingressNode = createNode({
        node_type: 'INGRESS',
        node_subtype: 'framework_handler',
        label: firstParam.text,
        language: 'javascript',
        file: ctx.neuralMap.source_file,
        line_start: firstParam.startPosition.row + 1,
        line_end: firstParam.endPosition.row + 1,
        code_snapshot: firstParam.text,
        data_out: [{
          name: firstParam.text,
          source: '', // will be set by createNode
          data_type: 'object',
          tainted: true,
          sensitivity: 'NONE',
        }],
      });
      ctx.neuralMap.nodes.push(ingressNode);
      ctx.lastCreatedNodeId = ingressNode.id;
    }
  }
}
```

---

### Step 5: Verify single-file detection

**Run:** `npx tsx src/dst-cli.ts src/test-fixtures/ghost-pattern.js`
**Expected:** CWE-89 finding — frame → filter → string concat → SQL query

---

### Step 6: Run full test suite

**Run:** `npx vitest run`
**Expected:** All 1,794+ tests pass

---

### Step 7: OWASP benchmark regression gate

**Run:** `npx tsx src/sandbox/sweep-truth.ts`
**Expected:** Score >= 92.7%

---

### Step 8: Ghost CMS A/B test

1. Checkout vulnerable slug-filter-order:
   `cd Ghost && git checkout v5.40.0 -- ghost/core/.../slug-filter-order.js`

2. Scan the input serializers directory:
   `npx tsx src/dst-cli.ts Ghost/ghost/core/.../serializers/input/`

3. **Expected:** CWE-89 finding on slug-filter-order.js (via cross-file param taint)

4. Restore patched version, re-scan:
   **Expected:** 0 CWE-89 findings on slug-filter-order.js

---

## Files to modify

- `src/profiles/javascript.ts` — add `isExportedVerbMethod()` + taint marking in `processFunctionParams`
- `src/test-fixtures/ghost-pattern.js` — new fixture (create directory if needed)
- `src/handler-inference.test.ts` — new test file

## Files NOT modified

- Everything else. This is a JS profile change only.

## Risk

- The verb list (`query`, `read`, `add`, etc.) could false-positive on non-handler methods that happen to be exported with verb names. Mitigated by requiring the `module.exports` ancestor — standalone functions named `query` won't match.
- The parent-chain walk is O(depth) per method_definition — negligible since AST depth is typically < 20.

## What this enables (the full chain)

```
Step 3-4 (this plan)           Step 2 (commit 6ae1865)        Phase 1 (property engine)
Handler inference              Cross-file param taint          Taint reachability
                                                               
posts.js:                      slug-filter-order.js:           Property query:
  query(frame) {                 function(table, filter) {       INGRESS → STORAGE/sql_query
    frame = TAINTED ✓              filter = TAINTED ✓              without TRANSFORM/sanitize
    slugFilterOrder(                 sql = '...' + filter           → CWE-89 ✓
      'posts',                       ↓
      frame.options.filter           SQL SINK
    ) ← tainted arg               }
  }
```
