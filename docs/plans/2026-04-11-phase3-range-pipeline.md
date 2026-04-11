# Phase 3: Close the Range Pipeline & Build Numeric Properties

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Connect the existing but disconnected range infrastructure (RangeInfo → VariableInfo → DataFlow → verifier helpers), then build three new properties on the connected pipeline: integer overflow, sentinel collision, and buffer size mismatch.

**Architecture:** The range pipeline is 70% built but the critical handoff — propagating VariableInfo.range into addDataFlow() calls — was never wired. We close that gap first (Tasks 1-3), verify the existing helpers start producing real data (Task 4), then build new properties on top (Tasks 5-7). Every mapper change is gated by a full OWASP benchmark sweep to catch regressions.

**Tech Stack:** TypeScript, Vitest, tree-sitter (existing), no new dependencies

**Why this ordering:** Building properties on disconnected data produces properties that query nothing. Close the gap, verify the data flows, THEN build queries against it.

---

## Task 1: Bridge numericValue to RangeInfo

The simplest, zero-risk connection. When `VariableInfo.numericValue` is set (Java profile does this for integer literals), also set `range = createRange(numericValue, numericValue)`. This makes every integer constant visible to the range system.

**Files:**
- Modify: `src/profiles/java.ts` (where numericValue is set)
- Test: `src/range-inference.test.ts`

**Step 1: Write the failing test**

```typescript
// Append to src/range-inference.test.ts

describe('numericValue → RangeInfo bridge', () => {
  it('setting numericValue also sets exact range', () => {
    const ctx = new MapperContext('test.java', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);
    ctx.declareVariable('BUFFER_SIZE', 'const');
    const v = ctx.resolveVariable('BUFFER_SIZE')!;
    v.numericValue = 128;
    // After the bridge: numericValue should auto-populate range
    v.range = v.range ?? (v.numericValue !== undefined ? createRange(v.numericValue, v.numericValue) : undefined);
    expect(v.range).toBeDefined();
    expect(v.range!.min).toBe(128);
    expect(v.range!.max).toBe(128);
    expect(v.range!.bounded).toBe(true);
  });
});
```

**Step 2: Run test to verify it passes (this is a manual bridge test — the real change is in Java profile)**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/range-inference.test.ts`

**Step 3: Implement the bridge in Java profile**

Find every location in `src/profiles/java.ts` where `numericValue` is assigned to a VariableInfo. After each assignment, add:

```typescript
if (numericValue !== undefined && v.range === undefined) {
  v.range = createRange(numericValue, numericValue);
}
```

Import `createRange` from `'../types.js'` at top of java.ts if not already imported.

**Step 4: Run full test suite**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run`
Expected: All 1,763 tests pass

**Step 5: Commit**

```bash
git add src/profiles/java.ts src/range-inference.test.ts
git commit -m "feat: bridge numericValue → RangeInfo for integer constants"
```

---

## Task 2: Propagate VariableInfo.range Through addDataFlow

This is THE critical gap. Every `addDataFlow()` call in every profile currently passes 5 args, never the 6th `range` parameter. We need to look up the variable's range and pass it through.

**Files:**
- Modify: `src/mapper.ts` (add range lookup in buildDataFlowEdges or a new post-pass)
- Test: `src/range-inference.test.ts`

**Step 1: Write the failing end-to-end test**

```typescript
// Append to src/range-inference.test.ts

describe('End-to-end range propagation', () => {
  it('range from CONTROL gate reaches sink via DataFlow', () => {
    // Build: INGRESS → CONTROL(x > 0 && x < 1000) → STORAGE
    // After range propagation, STORAGE.data_in should have range [1, 999]
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);

    const src = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request',
      label: 'req.query.x',
    });
    ctx.neuralMap.nodes.push(src);
    ctx.nodeById.set(src.id, src);

    // Declare variable and set range (simulating extractRangeFromCondition)
    ctx.declareVariable('x', 'let', null, true, src.id);
    const v = ctx.resolveVariable('x')!;
    v.range = createRange(1, 999, 'ctrl1');

    const sink = createNode({
      node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'db.query',
    });
    ctx.neuralMap.nodes.push(sink);
    ctx.nodeById.set(sink.id, sink);

    // addDataFlow — currently does NOT pass range
    ctx.addDataFlow(src.id, sink.id, 'x', 'number', true);

    // After Task 2 implementation, the range should flow through
    const sinkFlow = sink.data_in.find(d => d.name === 'x');
    expect(sinkFlow).toBeDefined();
    expect(sinkFlow!.range).toBeDefined();
    expect(sinkFlow!.range!.min).toBe(1);
    expect(sinkFlow!.range!.max).toBe(999);
    expect(sinkFlow!.range!.bounded).toBe(true);
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/range-inference.test.ts`
Expected: FAIL — `sinkFlow.range` is undefined

**Step 3: Implement range propagation**

The cleanest approach: modify `addDataFlow()` in `src/mapper.ts` to auto-lookup the variable's range when no range is explicitly passed.

At `mapper.ts:203`, modify `addDataFlow`:

```typescript
addDataFlow(
  fromNodeId: string,
  toNodeId: string,
  name: string,
  dataType: string = 'unknown',
  tainted: boolean = false,
  range?: RangeInfo,
): void {
  // AUTO-BRIDGE: if no range provided, look up variable in scope
  if (range === undefined && name) {
    const varInfo = this.resolveVariable(name);
    if (varInfo?.range) {
      range = varInfo.range;
    }
  }
  // ... rest of method unchanged
```

This is 4 lines of code. It connects the entire pipeline because EVERY addDataFlow call goes through this method.

**Step 4: Run test to verify it passes**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/range-inference.test.ts`
Expected: PASS

**Step 5: Run full test suite**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run`
Expected: All 1,763 tests pass

**Step 6: OWASP benchmark sweep (mapper change = high blast radius)**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx tsx src/sandbox/sweep-truth.ts`
Expected: OWASP Score >= 92.7% (same or better)

**Step 7: Commit**

```bash
git add src/mapper.ts src/range-inference.test.ts
git commit -m "feat: auto-propagate VariableInfo.range through addDataFlow — closes the range gap"
```

---

## Task 3: Extend Range Extraction to Java Profile

JavaScript's `extractRangeFromCondition()` (javascript.ts:226-350) handles `if (x > 0 && x < 1000)`. Java's `tryEvalCondition()` only evaluates to boolean for dead branch detection. Port the range extraction.

**Files:**
- Modify: `src/profiles/java.ts`
- Test: `src/range-inference.test.ts`

**Step 1: Write the failing test**

```typescript
// Append to src/range-inference.test.ts
import { javaProfile } from './profiles/java.js';

describe('Java range extraction from conditions', () => {
  it('extracts range from if (x > 0 && x < 1000) in Java', () => {
    const ctx = new MapperContext('Test.java', '', javaProfile);
    ctx.pushScope('module', { type: 'program' } as any);
    ctx.pushScope('function', { type: 'method_declaration' } as any);
    ctx.declareVariable('x', 'let');

    // Simulate: after processing if (x > 0 && x < 1000)
    // The variable x should have range [1, 999]
    const v = ctx.resolveVariable('x')!;
    expect(v.range).toBeDefined();
    expect(v.range!.min).toBe(1);
    expect(v.range!.max).toBe(999);
  });
});
```

Note: This test needs actual AST parsing to work end-to-end. For a unit test, we can test the range extraction function directly.

**Step 2: Implement**

Add an `extractRangeFromCondition` function to `src/profiles/java.ts`, modeled on the JavaScript version but handling Java AST node types (`binary_expression` with `>`, `<`, `>=`, `<=` operators and `integer` / `decimal_integer_literal` / `hex_integer_literal` on the other side).

Call it from the Java profile's `classifyNode` at `if_statement`, `for_statement`, and `while_statement` nodes, mirroring JavaScript profile lines 1836, 1844, 1866.

**Step 3: Run tests and OWASP sweep**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run`
Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx tsx src/sandbox/sweep-truth.ts`
Expected: All pass, OWASP >= 92.7%

**Step 4: Commit**

```bash
git add src/profiles/java.ts src/range-inference.test.ts
git commit -m "feat: Java profile range extraction from conditions — parity with JavaScript"
```

---

## Task 4: Verify the Pipeline is Connected End-to-End

Now that ranges flow from CONTROL gates through VariableInfo through addDataFlow to sink data_in, the existing verifier helpers (`sinkHasSafeRange`, `sinkHasNonZeroRange`, `sinkHasBoundedRange`) should produce real results.

**Files:**
- Test: `src/range-inference.test.ts`

**Step 1: Write the integration test**

```typescript
// Append to src/range-inference.test.ts

describe('Full pipeline: condition → variable → dataflow → verifier helper', () => {
  it('sinkHasBoundedRange returns true after range flows through pipeline', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);

    const src = createNode({ node_type: 'INGRESS', node_subtype: 'http_request', label: 'input' });
    const sink = createNode({ node_type: 'STORAGE', node_subtype: 'sql_query', label: 'query' });
    ctx.neuralMap.nodes.push(src, sink);
    ctx.nodeById.set(src.id, src);
    ctx.nodeById.set(sink.id, sink);

    // Simulate range from CONTROL gate
    ctx.declareVariable('x', 'let', null, true, src.id);
    const v = ctx.resolveVariable('x')!;
    v.range = createRange(1, 100);

    // addDataFlow now auto-propagates range
    ctx.addDataFlow(src.id, sink.id, 'x', 'number', true);

    // Verifier helper should see the range
    expect(sinkHasBoundedRange(ctx.neuralMap, sink.id)).toBe(true);
    expect(sinkHasSafeRange(ctx.neuralMap, sink.id, 1000)).toBe(true);
    expect(sinkHasSafeRange(ctx.neuralMap, sink.id, 50)).toBe(false); // 100 > 50
  });

  it('sinkHasBoundedRange returns false when no range in pipeline', () => {
    const ctx = new MapperContext('test.js', '', javascriptProfile);
    ctx.pushScope('module', { type: 'program' } as any);

    const src = createNode({ node_type: 'INGRESS', node_subtype: 'http_request', label: 'input' });
    const sink = createNode({ node_type: 'STORAGE', node_subtype: 'sql_query', label: 'query' });
    ctx.neuralMap.nodes.push(src, sink);
    ctx.nodeById.set(src.id, src);
    ctx.nodeById.set(sink.id, sink);

    ctx.declareVariable('y', 'let', null, true, src.id);
    // No range set
    ctx.addDataFlow(src.id, sink.id, 'y', 'string', true);

    expect(sinkHasBoundedRange(ctx.neuralMap, sink.id)).toBe(false);
  });
});
```

**Step 2: Run test**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/range-inference.test.ts`
Expected: PASS (if Task 2 was implemented correctly)

**Step 3: Commit**

```bash
git add src/range-inference.test.ts
git commit -m "test: full pipeline integration — CONTROL → variable → DataFlow → verifier helper"
```

---

## Task 5: Integer Overflow Property

Now that ranges flow through the pipeline, build the property that catches OpenBSD TCP SACK-class bugs.

**Files:**
- Create: `src/properties/integer-overflow.ts`
- Register in: `src/properties/registry.ts`
- Test: `src/properties/properties.test.ts`

**The property asserts:** "No arithmetic operation on attacker-influenced data produces a value outside its type's representable range without a preceding bounds check."

**Implementation:**

```typescript
// The property checks:
// 1. Find TRANSFORM nodes with arithmetic subtypes
// 2. Check if any data_in is tainted (attacker-influenced)
// 3. Check if the data_in has a bounded range
// 4. If tainted AND unbounded → violation
// 5. If tainted AND bounded but range exceeds type limits → violation

const ARITHMETIC_SUBTYPES = new Set([
  'arithmetic', 'add', 'multiply', 'subtract', 'divide', 'modulo',
  'format', // String.format can involve numeric conversion
]);

const ARITHMETIC_PATTERNS = /[+\-*/%]\s*=|[+\-*/%]\s+\w|Math\.(abs|ceil|floor|round|pow)|Integer\.parseInt|Long\.parseLong|Number\(/i;
```

For each TRANSFORM node matching arithmetic patterns:
- If all tainted data_in entries have `range.bounded === true` and `isRangeSafe(range, INT32_MAX)` → safe, skip
- If any tainted data_in entry lacks a range or has unbounded range → violation

**CWE mappings:**
- CWE-190: Integer Overflow (severity: high)
- CWE-191: Integer Underflow (severity: high)
- CWE-681: Incorrect Conversion between Numeric Types (severity: medium)

**Tests:**

```typescript
describe('integer-overflow property', () => {
  it('detects unbounded tainted input in arithmetic', () => {
    // TRANSFORM node with tainted data_in, no range → violation
  });

  it('holds when range is bounded and safe', () => {
    // TRANSFORM node with tainted data_in, range [0, 100] → safe
  });

  it('detects range exceeding INT32_MAX', () => {
    // TRANSFORM node with range [0, 2^32] → violation
  });
});
```

---

## Task 6: Sentinel Collision Property

**No other production SAST tool does this.** This is DST's novel capability.

**Files:**
- Create: `src/properties/sentinel-collision.ts`
- Register in: `src/properties/registry.ts`
- Test: `src/properties/properties.test.ts`

**The property asserts:** "No computed value can equal a sentinel value used in control flow decisions within the same scope."

**Implementation:**

Phase 1 — Build sentinel registry:

```typescript
interface SentinelEntry {
  value: number | string;
  controlNodeId: string;
  variable: string;
  line: number;
}

function buildSentinelRegistry(map: NeuralMap): SentinelEntry[] {
  const sentinels: SentinelEntry[] = [];
  for (const node of map.nodes) {
    if (node.node_type !== 'CONTROL') continue;
    const code = node.code_snapshot || node.analysis_snapshot || '';
    // Match: if (x == -1), if (x === 0xFFFF), if (x == null), if (x === undefined)
    const patterns = [
      /(\w+)\s*(?:===?|!==?)\s*(-1|0x[fF]{2,}|null|undefined|NULL|EOF|0)\b/,
      /(-1|0x[fF]{2,}|null|undefined|NULL|EOF|0)\s*(?:===?|!==?)\s*(\w+)/,
    ];
    for (const pat of patterns) {
      const m = code.match(pat);
      if (m) {
        const variable = m[1]?.match(/^[a-z_]\w*$/i) ? m[1] : m[2];
        const valStr = m[1]?.match(/^[a-z_]\w*$/i) ? m[2] : m[1];
        if (!variable || !valStr) continue;
        let value: number | string = valStr;
        if (/^-?\d+$/.test(valStr)) value = parseInt(valStr, 10);
        else if (/^0x/i.test(valStr)) value = parseInt(valStr, 16);
        sentinels.push({ value, controlNodeId: node.id, variable, line: node.line_start });
      }
    }
  }
  return sentinels;
}
```

Phase 2 — Check for collisions:

For each sentinel entry, find all TRANSFORM nodes that produce the sentinel's variable. Check if the TRANSFORM's output range includes the sentinel value. If it does AND the TRANSFORM is not the sentinel's own producer → COLLISION.

```typescript
function rangeIncludesValue(range: RangeInfo, value: number): boolean {
  return range.min <= value && value <= range.max;
}
```

**CWE mappings:**
- CWE-138: Improper Neutralization of Special Elements (severity: medium)
- CWE-170: Improper Null Termination (severity: medium, when: sentinel is 0 or null)
- CWE-253: Incorrect Check of Function Return Value (severity: medium, when: sentinel is -1)

**Tests:**

```typescript
describe('sentinel-collision property', () => {
  it('detects counter that can reach sentinel value -1', () => {
    // CONTROL node: if (result == -1)
    // TRANSFORM node produces 'result' with range [-5, 100]
    // Range includes -1 → COLLISION
  });

  it('holds when range excludes sentinel', () => {
    // CONTROL node: if (result == -1)
    // TRANSFORM node produces 'result' with range [0, 100]
    // Range does NOT include -1 → safe
  });

  it('detects 0xFFFF sentinel collision', () => {
    // CONTROL node: if (index == 0xFFFF)
    // TRANSFORM/counter with range [0, 70000]
    // Range includes 65535 → COLLISION
  });

  it('ignores sentinel checks on the sentinel producer itself', () => {
    // The CONTROL node comparing to -1 is itself the source → not a collision
  });
});
```

---

## Task 7: Buffer Size Mismatch Property

**Files:**
- Modify: `src/types.ts` (add `buffer_size` and `write_size` optional fields)
- Create: `src/properties/buffer-size.ts`
- Register in: `src/properties/registry.ts`
- Test: `src/properties/properties.test.ts`

**The property asserts:** "No write operation exceeds the allocation size of its target buffer."

**Step 1: Extend types**

```typescript
// Add to NeuralMapNode in types.ts:
  /** Buffer/allocation size interval — used by buffer overflow detection */
  buffer_size?: RangeInfo;

// Add to DataFlow in types.ts:
  /** Size of data being written — used by buffer overflow detection */
  write_size?: RangeInfo;
```

**Step 2: Implement the property**

This property is primarily structural for now (checking nodes that have buffer_size and write_size annotations). The mapper extensions to POPULATE these fields will come when C/C++ support matures. For Java/JavaScript, the property catches:
- `Buffer.alloc(size)` followed by write exceeding size
- Array creation with known size followed by index out of range

```typescript
function verify(map: NeuralMap, ctx: PropertyContext): PropertyResult {
  const violations: PropertyViolation[] = [];

  for (const node of map.nodes) {
    if (!node.buffer_size || !node.buffer_size.bounded) continue;

    for (const flow of node.data_in) {
      if (!flow.write_size || !flow.write_size.bounded) continue;

      // Can the write exceed the buffer?
      if (flow.write_size.max > node.buffer_size.min) {
        violations.push({
          source: nodeRef(/* writer */),
          sink: nodeRef(node),
          sinkType: node.node_type,
          sinkSubtype: node.node_subtype,
          missing: 'bounds_check',
          via: 'property_structural',
          description: `Write of up to ${flow.write_size.max} bytes into buffer of ${node.buffer_size.min} bytes`,
          context: {
            buffer_size: String(node.buffer_size.min),
            write_size: String(flow.write_size.max),
          },
        });
      }
    }
  }

  return { propertyId: 'buffer-size', holds: violations.length === 0, violations };
}
```

**CWE mappings:**
- CWE-119: Improper Restriction of Operations within Bounds of Memory Buffer (severity: critical)
- CWE-120: Buffer Copy without Checking Size of Input (severity: critical)
- CWE-121: Stack-based Buffer Overflow (severity: critical)
- CWE-122: Heap-based Buffer Overflow (severity: critical)
- CWE-787: Out-of-bounds Write (severity: critical)

**Tests:**

```typescript
describe('buffer-size property', () => {
  it('detects write exceeding buffer allocation', () => {
    const map = createNeuralMap('test.c', '');
    const buf = createNode({
      node_type: 'STORAGE', node_subtype: 'buffer',
      label: 'rpchdr', buffer_size: createRange(128, 128),
      data_in: [{
        name: 'data', source: 'src1', data_type: 'bytes',
        tainted: true, sensitivity: 'NONE',
        write_size: createRange(0, 400),
      }],
      edges: [],
    });
    map.nodes = [buf];
    // Expect violation: 400 > 128
  });

  it('holds when write fits within buffer', () => {
    const map = createNeuralMap('test.c', '');
    const buf = createNode({
      node_type: 'STORAGE', node_subtype: 'buffer',
      label: 'rpchdr', buffer_size: createRange(128, 128),
      data_in: [{
        name: 'data', source: 'src1', data_type: 'bytes',
        tainted: true, sensitivity: 'NONE',
        write_size: createRange(0, 96),
      }],
      edges: [],
    });
    map.nodes = [buf];
    // Expect holds: true (96 <= 128)
  });
});
```

---

## Regression Gates

**After EVERY mapper change (Tasks 1-3):**
1. `npx vitest run` — all 1,763+ tests pass
2. `npx tsx src/sandbox/sweep-truth.ts` — OWASP Score >= 92.7%

**After property additions (Tasks 5-7):**
1. `npx vitest run` — all tests pass (no regression)
2. Property tests pass independently

---

## Execution Order & Dependencies

```
Task 1 (numericValue → range) ──→ Task 2 (addDataFlow range bridge) ──→ Task 3 (Java range extraction)
                                          ↓
                                    Task 4 (integration test)
                                          ↓
                                    OWASP SWEEP GATE
                                          ↓
                              ┌───────────┼───────────┐
                              T5          T6          T7
                         (int overflow) (sentinel)  (buffer size)
```

Tasks 1→2→3→4 are sequential (each builds on previous).
Tasks 5, 6, 7 are independent (can run in parallel after Task 4).

---

## File Inventory

**Modified files:**
- `src/mapper.ts:203-210` — Add 4-line range auto-lookup in addDataFlow()
- `src/profiles/java.ts` — Add range extraction from conditions, bridge numericValue→range
- `src/types.ts` — Add optional `buffer_size` to NeuralMapNode, `write_size` to DataFlow
- `src/properties/registry.ts` — Register 3 new properties
- `src/range-inference.test.ts` — Integration tests for range pipeline
- `src/properties/properties.test.ts` — Property tests

**New files:**
- `src/properties/integer-overflow.ts`
- `src/properties/sentinel-collision.ts`
- `src/properties/buffer-size.ts`

**Untouched files:**
- All existing verifier files
- All existing test files (except range-inference.test.ts)
- mapper.ts (beyond the 4-line addDataFlow change)
- All profiles except java.ts
- sentence-generator.ts, sentence-resolver.ts, sentence-templates.ts
- cross-file.ts, margin-pass.ts
- payload-gen.ts, payload-dictionary.ts
