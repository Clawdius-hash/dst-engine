# DST Property Engine: CWE-Free Semantic Verification

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace 783 CWE-indexed verifiers with ~20 universal security properties that detect the same vulnerabilities (and novel ones CWEs don't cover) by querying the NeuralMap for semantic violations, while mapping findings back to CWEs for reporting.

**Architecture:** Property Engine runs as a layer ON TOP of existing CWE verifiers. Properties execute first; anything they don't cover falls through to the legacy CWE registry. Zero regression risk — all 1,709 existing tests pass unchanged. Over time, properties subsume CWE verifiers, which become dead code and get pruned. The NeuralMap gets extended with new optional annotations (buffer sizes, type widths, sentinel values, typestate) that enable Mythos-class detection capabilities.

**Tech Stack:** TypeScript, Vitest, tree-sitter (existing), no new dependencies

**Why this matters:** Claude Mythos found thousands of zero-days by reasoning about code semantics — not by matching CWE patterns. DST already does semantic analysis (phonemes, taint graphs, sentences). The only thing holding it back is that its verification layer asks "does this match CWE-X?" instead of "is this code safe?" This plan fixes that.

---

## Phase 1: Property Engine Foundation

### Task 1: Define Property Interfaces

**Files:**
- Create: `src/properties/types.ts`
- Test: `src/properties/properties.test.ts`

**Step 1: Write the type definitions**

```typescript
// src/properties/types.ts

import type { NeuralMap, NeuralMapNode, NodeType } from '../types.js';
import type { NodeRef, Finding } from '../verifier/types.js';

/**
 * A SecurityProperty is a universal assertion about code safety.
 * It is NOT tied to any CWE — it describes WHAT should be true,
 * not which weakness taxonomy entry it maps to.
 *
 * "No tainted data reaches a dangerous operation without sanitization"
 * is a property. CWE-89, CWE-79, CWE-78 are all instances of violating it.
 */
export interface SecurityProperty {
  /** Unique property identifier (e.g., 'taint-reachability') */
  id: string;
  /** Human-readable name */
  name: string;
  /** What this property asserts about safe code */
  assertion: string;
  /** Which CWEs this property subsumes (for reporting) */
  cweMapping: CWEMapping[];
  /** Execute the property check against a NeuralMap */
  verify: (map: NeuralMap, ctx: PropertyContext) => PropertyResult;
}

/**
 * Maps a property violation to one or more CWEs based on
 * the SOURCE type, SINK type, and what's MISSING.
 */
export interface CWEMapping {
  /** CWE identifier */
  cwe: string;
  /** Human-readable CWE name */
  name: string;
  /** When does this CWE apply? */
  when: {
    sinkType?: NodeType;
    sinkSubtype?: string | string[];
    sourceType?: NodeType;
    missing?: string;
  };
  /** Default severity for this CWE */
  severity: 'critical' | 'high' | 'medium' | 'low';
}

/**
 * Runtime context passed to every property check.
 * Holds language info, story state, and flags.
 */
export interface PropertyContext {
  language: string;
  hasStory: boolean;
  isLibrary: boolean;
  pedantic: boolean;
}

/**
 * Result of a property verification.
 * Contains violations (not findings) — CWE mapping happens later.
 */
export interface PropertyResult {
  propertyId: string;
  holds: boolean;
  violations: PropertyViolation[];
}

/**
 * A single violation of a security property.
 * This is CWE-agnostic — it describes WHAT went wrong semantically.
 */
export interface PropertyViolation {
  /** Source node (where dangerous data originates) */
  source: NodeRef;
  /** Sink node (where it arrives unsafely) */
  sink: NodeRef;
  /** What semantic type the sink is (for CWE mapping) */
  sinkType: NodeType;
  sinkSubtype: string;
  /** What's missing on the path */
  missing: 'sanitization' | 'validation' | 'authentication' | 'authorization'
         | 'encryption' | 'bounds_check' | 'null_check' | 'lifecycle'
         | 'synchronization' | 'encoding';
  /** How this was detected */
  via: 'property_bfs' | 'property_sentence' | 'property_structural';
  /** Semantic description of the violation */
  description: string;
  /** Additional context for CWE mapping */
  context?: Record<string, string>;
}
```

**Step 2: Write the failing test**

```typescript
// src/properties/properties.test.ts

import { describe, it, expect } from 'vitest';
import type { SecurityProperty, PropertyViolation, PropertyResult } from './types.js';

describe('Property types', () => {
  it('PropertyViolation has no CWE field', () => {
    const v: PropertyViolation = {
      source: { id: 's1', label: 'req.body', line: 1, code: 'req.body' },
      sink: { id: 's2', label: 'db.query', line: 5, code: 'db.query(q)' },
      sinkType: 'STORAGE',
      sinkSubtype: 'sql_query',
      missing: 'sanitization',
      via: 'property_bfs',
      description: 'Tainted data reaches SQL query without sanitization',
    };
    // The violation itself has no CWE — that's the whole point
    expect(v).not.toHaveProperty('cwe');
    expect(v.missing).toBe('sanitization');
    expect(v.sinkType).toBe('STORAGE');
  });

  it('PropertyResult is CWE-free', () => {
    const r: PropertyResult = {
      propertyId: 'taint-reachability',
      holds: false,
      violations: [],
    };
    expect(r).not.toHaveProperty('cwe');
    expect(r.propertyId).toBe('taint-reachability');
  });
});
```

**Step 3: Run test**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/properties/properties.test.ts`
Expected: PASS

**Step 4: Commit**

```bash
git add src/properties/types.ts src/properties/properties.test.ts
git commit -m "feat: property engine type definitions — CWE-free violation model"
```

---

### Task 2: CWE Reverse-Mapping Engine

**Files:**
- Create: `src/properties/cwe-map.ts`
- Modify test: `src/properties/properties.test.ts`

**Step 1: Write the failing test**

```typescript
// Append to src/properties/properties.test.ts

import { mapViolationToCWE } from './cwe-map.js';
import type { CWEMapping } from './types.js';

describe('CWE reverse mapping', () => {
  const INJECTION_MAPPINGS: CWEMapping[] = [
    { cwe: 'CWE-89', name: 'SQL Injection', severity: 'critical',
      when: { sinkSubtype: ['sql_query', 'db_read', 'db_write', 'db_stored_proc'] } },
    { cwe: 'CWE-79', name: 'Cross-site Scripting', severity: 'high',
      when: { sinkType: 'EGRESS', sinkSubtype: ['http_response'] } },
    { cwe: 'CWE-78', name: 'OS Command Injection', severity: 'critical',
      when: { sinkType: 'EXTERNAL', sinkSubtype: ['system_exec'] } },
    { cwe: 'CWE-22', name: 'Path Traversal', severity: 'high',
      when: { sinkSubtype: ['file_read', 'file_write'] } },
    { cwe: 'CWE-90', name: 'LDAP Injection', severity: 'high',
      when: { sinkSubtype: ['ldap_query'] } },
  ];

  it('maps STORAGE/sql_query violation to CWE-89', () => {
    const violation: PropertyViolation = {
      source: { id: 's', label: '', line: 1, code: '' },
      sink: { id: 'k', label: '', line: 5, code: '' },
      sinkType: 'STORAGE',
      sinkSubtype: 'sql_query',
      missing: 'sanitization',
      via: 'property_bfs',
      description: '',
    };
    const result = mapViolationToCWE(violation, INJECTION_MAPPINGS);
    expect(result.cwe).toBe('CWE-89');
    expect(result.severity).toBe('critical');
  });

  it('maps EXTERNAL/system_exec to CWE-78', () => {
    const violation: PropertyViolation = {
      source: { id: 's', label: '', line: 1, code: '' },
      sink: { id: 'k', label: '', line: 5, code: '' },
      sinkType: 'EXTERNAL',
      sinkSubtype: 'system_exec',
      missing: 'sanitization',
      via: 'property_bfs',
      description: '',
    };
    const result = mapViolationToCWE(violation, INJECTION_MAPPINGS);
    expect(result.cwe).toBe('CWE-78');
    expect(result.severity).toBe('critical');
  });

  it('maps EGRESS/http_response to CWE-79', () => {
    const violation: PropertyViolation = {
      source: { id: 's', label: '', line: 1, code: '' },
      sink: { id: 'k', label: '', line: 5, code: '' },
      sinkType: 'EGRESS',
      sinkSubtype: 'http_response',
      missing: 'sanitization',
      via: 'property_bfs',
      description: '',
    };
    const result = mapViolationToCWE(violation, INJECTION_MAPPINGS);
    expect(result.cwe).toBe('CWE-79');
  });

  it('returns null when no mapping matches', () => {
    const violation: PropertyViolation = {
      source: { id: 's', label: '', line: 1, code: '' },
      sink: { id: 'k', label: '', line: 5, code: '' },
      sinkType: 'META',
      sinkSubtype: 'config',
      missing: 'sanitization',
      via: 'property_bfs',
      description: '',
    };
    const result = mapViolationToCWE(violation, INJECTION_MAPPINGS);
    expect(result).toBeNull();
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/properties/properties.test.ts`
Expected: FAIL — `mapViolationToCWE` not found

**Step 3: Implement**

```typescript
// src/properties/cwe-map.ts

import type { CWEMapping, PropertyViolation } from './types.js';
import type { Finding } from '../verifier/types.js';

/**
 * Maps a CWE-free property violation to a specific CWE for reporting.
 * Returns the first matching CWE mapping, or null if no mapping applies.
 *
 * This is the ONLY place where CWE identifiers enter the property engine.
 * Detection is semantic. Reporting is CWE.
 */
export function mapViolationToCWE(
  violation: PropertyViolation,
  mappings: CWEMapping[],
): { cwe: string; name: string; severity: Finding['severity'] } | null {
  for (const mapping of mappings) {
    const { when } = mapping;

    // Check sinkType constraint
    if (when.sinkType && when.sinkType !== violation.sinkType) continue;

    // Check sinkSubtype constraint
    if (when.sinkSubtype) {
      const subtypes = Array.isArray(when.sinkSubtype) ? when.sinkSubtype : [when.sinkSubtype];
      if (!subtypes.includes(violation.sinkSubtype)) continue;
    }

    // Check sourceType constraint
    if (when.sourceType && when.sourceType !== 'INGRESS') continue;

    // Check missing constraint
    if (when.missing && when.missing !== violation.missing) continue;

    return { cwe: mapping.cwe, name: mapping.name, severity: mapping.severity };
  }
  return null;
}

/**
 * Convert a PropertyViolation + CWE mapping into a Finding
 * compatible with the existing verification/dedup/reporting pipeline.
 */
export function violationToFinding(
  violation: PropertyViolation,
  cwe: { cwe: string; name: string; severity: Finding['severity'] },
  fix: string,
): Finding {
  return {
    source: violation.source,
    sink: violation.sink,
    missing: violation.missing.toUpperCase(),
    severity: cwe.severity,
    description: violation.description,
    fix,
    via: violation.via === 'property_bfs' ? 'bfs'
       : violation.via === 'property_sentence' ? 'bfs'
       : 'structural',
  };
}
```

**Step 4: Run tests**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/properties/properties.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/properties/cwe-map.ts src/properties/properties.test.ts
git commit -m "feat: CWE reverse-mapping engine — detect semantically, report in CWE"
```

---

### Task 3: Taint Reachability Property (the big one)

This single property replaces CWE-89, CWE-79, CWE-78, CWE-22, CWE-90, CWE-94, CWE-643, CWE-918, CWE-611, CWE-77, CWE-91, CWE-93, CWE-95, CWE-96, CWE-601, and every factory verifier pattern that checks INGRESS→{STORAGE,EGRESS,EXTERNAL} without {CONTROL,TRANSFORM}.

**Files:**
- Create: `src/properties/taint-reachability.ts`
- Modify test: `src/properties/properties.test.ts`

**Step 1: Write the failing test**

```typescript
// Append to src/properties/properties.test.ts

import { taintReachability } from './taint-reachability.js';
import { createNode, createNeuralMap, resetSequenceHard } from '../types.js';
import type { NeuralMap } from '../types.js';
import type { PropertyContext } from './types.js';

const CTX: PropertyContext = {
  language: 'javascript',
  hasStory: false,
  isLibrary: false,
  pedantic: false,
};

describe('taint-reachability property', () => {
  beforeEach(() => resetSequenceHard());

  it('detects INGRESS → STORAGE/sql_query without CONTROL or TRANSFORM', () => {
    const map = createNeuralMap('test.js', '');
    const src = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request',
      label: 'req.body', data_in: [{ name: 'input', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'sink1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink1', node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'db.query', data_in: [{ name: 'q', source: src.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    map.nodes = [src, sink];
    map.edges = [{ target: sink.id, edge_type: 'DATA_FLOW', conditional: false, async: false }];

    const result = taintReachability.verify(map, CTX);
    expect(result.holds).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].sinkSubtype).toBe('sql_query');
    expect(result.violations[0].missing).toBe('sanitization');
  });

  it('holds when TRANSFORM/sanitize exists on path', () => {
    const map = createNeuralMap('test.js', '');
    const src = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request',
      label: 'req.body',
      data_in: [{ name: 'input', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'mid1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const transform = createNode({
      id: 'mid1', node_type: 'TRANSFORM', node_subtype: 'sanitize',
      label: 'sanitize()',
      data_in: [{ name: 'input', source: src.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'sink1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink1', node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'db.query',
      data_in: [{ name: 'q', source: transform.id, data_type: 'string', tainted: false, sensitivity: 'NONE' }],
      edges: [],
    });
    map.nodes = [src, transform, sink];

    const result = taintReachability.verify(map, CTX);
    expect(result.holds).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('holds when parameterization is used', () => {
    const map = createNeuralMap('test.js', '');
    map.story = [
      { text: 'userId receives string from req.body', templateKey: 'retrieves-from-source',
        slots: { subject: 'userId', source: 'req.body' }, lineNumber: 1, nodeId: 'n1',
        taintClass: 'TAINTED', taintBasis: 'SCOPE_LOOKUP' },
      { text: 'stmt binds userId at position 1', templateKey: 'parameter-binding',
        slots: { subject: 'stmt', variable: 'userId', index: '1' }, lineNumber: 3, nodeId: 'n2',
        taintClass: 'SAFE', taintBasis: 'PHONEME_RESOLUTION' },
      { text: 'stmt executes SQL query containing userId', templateKey: 'executes-query',
        slots: { subject: 'stmt', query_type: 'SQL', variables: 'userId' }, lineNumber: 5, nodeId: 'n3',
        taintClass: 'SINK', taintBasis: 'PHONEME_RESOLUTION' },
    ];
    const src = createNode({ node_type: 'INGRESS', node_subtype: 'http_request', label: 'req.body',
      data_in: [{ name: 'userId', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'sink1', edge_type: 'DATA_FLOW', conditional: false, async: false }] });
    const sink = createNode({ id: 'sink1', node_type: 'STORAGE', node_subtype: 'sql_query', label: 'db.query',
      data_in: [{ name: 'userId', source: src.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [] });
    map.nodes = [src, sink];

    const result = taintReachability.verify(map, { ...CTX, hasStory: true });
    expect(result.holds).toBe(true);
  });

  it('CWE mappings cover all injection types', () => {
    expect(taintReachability.cweMapping.some(m => m.cwe === 'CWE-89')).toBe(true);
    expect(taintReachability.cweMapping.some(m => m.cwe === 'CWE-79')).toBe(true);
    expect(taintReachability.cweMapping.some(m => m.cwe === 'CWE-78')).toBe(true);
    expect(taintReachability.cweMapping.some(m => m.cwe === 'CWE-22')).toBe(true);
    expect(taintReachability.cweMapping.some(m => m.cwe === 'CWE-90')).toBe(true);
    expect(taintReachability.cweMapping.some(m => m.cwe === 'CWE-918')).toBe(true);
  });
});
```

**Step 2: Run test to verify it fails**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/properties/properties.test.ts`
Expected: FAIL

**Step 3: Implement taint-reachability**

```typescript
// src/properties/taint-reachability.ts

import type { NeuralMap, NeuralMapNode, NodeType, EdgeType } from '../types.js';
import type { SecurityProperty, PropertyViolation, PropertyContext, CWEMapping } from './types.js';
import type { NodeRef } from '../verifier/types.js';

/** Dangerous sink subtypes grouped by what makes them dangerous */
const DANGEROUS_SINKS: ReadonlyMap<NodeType, ReadonlySet<string>> = new Map([
  ['STORAGE', new Set([
    'sql_query', 'db_read', 'db_write', 'db_stored_proc',          // SQL injection
    'nosql_query',                                                    // NoSQL injection
    'ldap_query',                                                     // LDAP injection
    'file_write', 'file_read',                                        // Path traversal
    'cache_write',                                                    // Cache poisoning
  ])],
  ['EXTERNAL', new Set([
    'system_exec',                                                    // Command injection
    'api_call', 'http_request',                                       // SSRF
    'dynamic_import',                                                 // Code injection
  ])],
  ['EGRESS', new Set([
    'http_response', 'redirect',                                      // XSS / open redirect
    'file_serve',                                                     // File disclosure
  ])],
]);

/** Neutralizing subtypes — if a TRANSFORM has one of these, the taint is handled */
const NEUTRALIZING_SUBTYPES: ReadonlySet<string> = new Set([
  'sanitize', 'encrypt', 'hash',
]);

/** Edge types that represent data flow */
const FLOW_EDGES: ReadonlySet<EdgeType> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);

function nodeRef(node: NeuralMapNode): NodeRef {
  return { id: node.id, label: node.label, line: node.line_start, code: node.code_snapshot.slice(0, 200) };
}

/**
 * BFS: is there a path from sourceId to sinkId that
 * does NOT pass through any neutralizing node?
 *
 * A neutralizing node is TRANSFORM/sanitize, TRANSFORM/encrypt,
 * TRANSFORM/hash, CONTROL with tainted data_in, or AUTH.
 *
 * This is the same BFS as hasPathWithoutGate but with richer
 * neutralization logic — it checks node subtypes, not just types.
 */
function hasUnsanitizedPath(map: NeuralMap, sourceId: string, sinkId: string): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; neutralized: boolean }> = [
    { nodeId: sourceId, neutralized: false },
  ];
  let head = 0;

  while (head < queue.length) {
    const { nodeId, neutralized } = queue[head++];
    const key = `${nodeId}:${neutralized}`;
    if (visited.has(key)) continue;
    visited.add(key);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    // Check if this node neutralizes the taint
    let isNeutralizer = false;
    if (node.node_type === 'TRANSFORM' && NEUTRALIZING_SUBTYPES.has(node.node_subtype)) {
      isNeutralizer = true;
    }
    if (node.node_type === 'CONTROL' && node.data_in?.some(d => d.tainted)) {
      isNeutralizer = true;
    }
    if (node.node_type === 'AUTH') {
      isNeutralizer = true;
    }

    const neutralizedNow = neutralized || isNeutralizer;

    if (nodeId === sinkId) {
      if (!neutralizedNow) return true; // Unsanitized path found
      continue;
    }

    for (const edge of node.edges) {
      if (!FLOW_EDGES.has(edge.edge_type)) continue;
      queue.push({ nodeId: edge.target, neutralized: neutralizedNow });
    }
  }
  return false;
}

/**
 * Story-based detection: walk the semantic sentences and track taint.
 * Returns violations for tainted variables reaching sinks.
 *
 * Respects parameter-binding as neutralization (parameterized queries).
 * Respects resolver-proven clean variables.
 */
function storyBasedDetection(map: NeuralMap): PropertyViolation[] {
  if (!map.story || map.story.length === 0) return [];

  const taintMap = new Map<string, { tainted: boolean; nodeId: string; line: number }>();
  const resolvedClean = new Set<string>();
  const parameterizedObjects = new Set<string>();
  const violations: PropertyViolation[] = [];

  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  for (const sentence of map.story) {
    const { templateKey, slots, taintClass, nodeId, lineNumber } = sentence;
    const varName = slots.subject || slots.data_type || '';

    // Track resolver-proven clean
    if (sentence.reconciled && taintClass === 'NEUTRAL' && varName) {
      resolvedClean.add(varName);
    }

    // Parameter binding neutralizes
    if (templateKey === 'parameter-binding' && varName) {
      parameterizedObjects.add(varName);
      continue;
    }

    // String concatenation — check if all parts are clean
    if (templateKey === 'string-concatenation' && varName) {
      const parts = (slots.parts || '').split(/[,\s]+/).filter(Boolean);
      const allClean = parts.length > 0 &&
        parts.every(p => resolvedClean.has(p) && taintMap.get(p)?.tainted !== true);
      taintMap.set(varName, {
        tainted: !allClean && taintClass === 'TAINTED',
        nodeId, line: lineNumber,
      });
      continue;
    }

    // Track tainted assignments
    if (taintClass === 'TAINTED' && varName) {
      taintMap.set(varName, { tainted: true, nodeId, line: lineNumber });
      continue;
    }

    // Track clean assignments
    if ((taintClass === 'NEUTRAL' || taintClass === 'SAFE') && varName) {
      taintMap.set(varName, { tainted: false, nodeId, line: lineNumber });
      continue;
    }

    // SINK sentences — check if any variable reaching it is tainted
    if (taintClass === 'SINK') {
      const sinkNode = nodeMap.get(nodeId);
      if (!sinkNode) continue;

      const sinkObj = slots.subject || '';
      if (parameterizedObjects.has(sinkObj)) continue;

      const variables = slots.variables || '';
      for (const [tv, info] of taintMap) {
        if (info.tainted && variables.includes(tv)) {
          const sourceNode = nodeMap.get(info.nodeId);
          violations.push({
            source: sourceNode ? nodeRef(sourceNode) : { id: info.nodeId, label: tv, line: info.line, code: '' },
            sink: nodeRef(sinkNode),
            sinkType: sinkNode.node_type,
            sinkSubtype: sinkNode.node_subtype,
            missing: 'sanitization',
            via: 'property_sentence',
            description: `Tainted variable "${tv}" reaches ${sinkNode.node_subtype} sink without sanitization`,
          });
          break; // One violation per sink
        }
      }
    }
  }

  return violations;
}

/** All CWEs that taint-reachability subsumes */
const CWE_MAPPINGS: CWEMapping[] = [
  // SQL Injection family
  { cwe: 'CWE-89', name: 'SQL Injection', severity: 'critical',
    when: { sinkSubtype: ['sql_query', 'db_read', 'db_write', 'db_stored_proc'] } },
  { cwe: 'CWE-564', name: 'SQL Injection (Hibernate)', severity: 'critical',
    when: { sinkSubtype: ['sql_query'] } },
  // XSS family
  { cwe: 'CWE-79', name: 'Cross-site Scripting (XSS)', severity: 'high',
    when: { sinkType: 'EGRESS', sinkSubtype: ['http_response'] } },
  // Command injection
  { cwe: 'CWE-78', name: 'OS Command Injection', severity: 'critical',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['system_exec'] } },
  { cwe: 'CWE-77', name: 'Command Injection', severity: 'critical',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['system_exec'] } },
  // Path traversal
  { cwe: 'CWE-22', name: 'Path Traversal', severity: 'high',
    when: { sinkSubtype: ['file_read', 'file_write'] } },
  // LDAP injection
  { cwe: 'CWE-90', name: 'LDAP Injection', severity: 'high',
    when: { sinkSubtype: ['ldap_query'] } },
  // XPath injection
  { cwe: 'CWE-643', name: 'XPath Injection', severity: 'high',
    when: { sinkSubtype: ['xpath_query'] } },
  // SSRF
  { cwe: 'CWE-918', name: 'Server-Side Request Forgery', severity: 'high',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['api_call', 'http_request'] } },
  // XXE
  { cwe: 'CWE-611', name: 'XML External Entity', severity: 'high',
    when: { sinkSubtype: ['xml_parse'] } },
  // Code injection
  { cwe: 'CWE-94', name: 'Code Injection', severity: 'critical',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['dynamic_import'] } },
  // Open redirect
  { cwe: 'CWE-601', name: 'Open Redirect', severity: 'medium',
    when: { sinkType: 'EGRESS', sinkSubtype: ['redirect'] } },
  // NoSQL injection
  { cwe: 'CWE-943', name: 'NoSQL Injection', severity: 'high',
    when: { sinkSubtype: ['nosql_query'] } },
  // Deserialization
  { cwe: 'CWE-502', name: 'Deserialization of Untrusted Data', severity: 'critical',
    when: { sinkSubtype: ['deserialize'] } },
];

export const taintReachability: SecurityProperty = {
  id: 'taint-reachability',
  name: 'Taint Reachability',
  assertion: 'No tainted data from an untrusted source reaches a dangerous sink without adequate neutralization',
  cweMapping: CWE_MAPPINGS,

  verify(map: NeuralMap, ctx: PropertyContext): PropertyResult {
    const violations: PropertyViolation[] = [];

    // Strategy 1: Story-based (V2) — preferred when available
    if (ctx.hasStory && map.story && map.story.length > 0) {
      const storyViolations = storyBasedDetection(map);
      violations.push(...storyViolations);
    }

    // Strategy 2: Graph BFS — always runs as complement
    const sources = map.nodes.filter(n => n.node_type === 'INGRESS');

    for (const src of sources) {
      for (const [sinkType, subtypes] of DANGEROUS_SINKS) {
        const sinks = map.nodes.filter(n =>
          n.node_type === sinkType && subtypes.has(n.node_subtype));

        for (const sink of sinks) {
          // Skip if story already found this pair
          if (violations.some(v => v.source.id === src.id && v.sink.id === sink.id)) continue;

          // Check sink has tainted data_in from any source
          const sinkHasTaint = sink.data_in?.some(d => d.tainted) ?? false;
          if (!sinkHasTaint && !hasUnsanitizedPath(map, src.id, sink.id)) continue;

          if (hasUnsanitizedPath(map, src.id, sink.id)) {
            violations.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              sinkType: sink.node_type,
              sinkSubtype: sink.node_subtype,
              missing: 'sanitization',
              via: 'property_bfs',
              description: `Tainted input from ${src.label || src.node_subtype} reaches ${sink.node_subtype} sink at line ${sink.line_start} without sanitization`,
            });
          }
        }
      }
    }

    return {
      propertyId: 'taint-reachability',
      holds: violations.length === 0,
      violations,
    };
  },
};
```

**Step 4: Run tests**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/properties/properties.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/properties/taint-reachability.ts src/properties/properties.test.ts
git commit -m "feat: taint-reachability property — one property replaces 30+ CWE verifiers"
```

---

### Task 4: Property Registry and Engine Runner

**Files:**
- Create: `src/properties/index.ts`
- Create: `src/properties/engine.ts`
- Modify test: `src/properties/properties.test.ts`

**Step 1: Write the failing test**

```typescript
// Append to src/properties/properties.test.ts

import { runProperties, propertyResultsToFindings } from './engine.js';

describe('Property engine runner', () => {
  beforeEach(() => resetSequenceHard());

  it('runs all registered properties and collects violations', () => {
    const map = createNeuralMap('test.js', '');
    const src = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request', label: 'req.body',
      data_in: [{ name: 'x', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'sink1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink1', node_type: 'STORAGE', node_subtype: 'sql_query', label: 'db.query',
      data_in: [{ name: 'q', source: src.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    map.nodes = [src, sink];

    const results = runProperties(map, { language: 'javascript', hasStory: false, isLibrary: false, pedantic: false });
    expect(results.length).toBeGreaterThan(0);
    expect(results.some(r => r.propertyId === 'taint-reachability' && !r.holds)).toBe(true);
  });

  it('converts property results to CWE-labeled findings', () => {
    const map = createNeuralMap('test.js', '');
    const src = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request', label: 'req.body',
      data_in: [{ name: 'x', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'sink1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink1', node_type: 'STORAGE', node_subtype: 'sql_query', label: 'db.query',
      data_in: [{ name: 'q', source: src.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    map.nodes = [src, sink];

    const results = runProperties(map, { language: 'javascript', hasStory: false, isLibrary: false, pedantic: false });
    const findings = propertyResultsToFindings(results);

    expect(findings.length).toBeGreaterThan(0);
    // The finding should have a CWE label now
    expect(findings[0].cwe).toBe('CWE-89');
    expect(findings[0].name).toBe('SQL Injection');
  });
});
```

**Step 2: Run to verify failure**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/properties/properties.test.ts`
Expected: FAIL

**Step 3: Implement engine**

```typescript
// src/properties/engine.ts

import type { NeuralMap } from '../types.js';
import type { SecurityProperty, PropertyContext, PropertyResult } from './types.js';
import type { VerificationResult } from '../verifier/types.js';
import { PROPERTY_REGISTRY } from './index.js';
import { mapViolationToCWE, violationToFinding } from './cwe-map.js';

/**
 * Run all registered security properties against a NeuralMap.
 * Returns raw PropertyResults (CWE-free).
 */
export function runProperties(map: NeuralMap, ctx: PropertyContext): PropertyResult[] {
  const results: PropertyResult[] = [];
  for (const property of PROPERTY_REGISTRY) {
    results.push(property.verify(map, ctx));
  }
  return results;
}

/**
 * Convert property results into CWE-labeled VerificationResults
 * compatible with the existing dedup/reporting pipeline.
 */
export function propertyResultsToFindings(
  results: PropertyResult[],
): VerificationResult[] {
  const output: VerificationResult[] = [];
  const registry = new Map(PROPERTY_REGISTRY.map(p => [p.id, p]));

  for (const result of results) {
    if (result.holds) continue;

    const property = registry.get(result.propertyId);
    if (!property) continue;

    // Group violations by their CWE mapping
    const byCWE = new Map<string, VerificationResult>();

    for (const violation of result.violations) {
      const mapped = mapViolationToCWE(violation, property.cweMapping);
      if (!mapped) continue;

      if (!byCWE.has(mapped.cwe)) {
        byCWE.set(mapped.cwe, {
          cwe: mapped.cwe,
          name: mapped.name,
          holds: false,
          findings: [],
        });
      }

      byCWE.get(mapped.cwe)!.findings.push(
        violationToFinding(violation, mapped, `Neutralize input before it reaches the ${violation.sinkSubtype} operation`),
      );
    }

    output.push(...byCWE.values());
  }

  return output;
}
```

```typescript
// src/properties/index.ts

import type { SecurityProperty } from './types.js';
import { taintReachability } from './taint-reachability.js';

/**
 * All registered security properties.
 * Each property is a universal assertion about code safety.
 * New properties are added here — they automatically run on every scan.
 */
export const PROPERTY_REGISTRY: SecurityProperty[] = [
  taintReachability,
];

export { runProperties, propertyResultsToFindings } from './engine.js';
export type { SecurityProperty, PropertyViolation, PropertyResult, PropertyContext } from './types.js';
```

**Step 4: Run tests**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run src/properties/properties.test.ts`
Expected: PASS

**Step 5: Run full test suite to confirm zero regression**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run`
Expected: 1,709 passing, 0 new failures

**Step 6: Commit**

```bash
git add src/properties/index.ts src/properties/engine.ts src/properties/properties.test.ts
git commit -m "feat: property engine runner — runs properties, converts to CWE findings"
```

---

### Task 5: Wire Property Engine into verifyAll

This is where the property engine starts doing real work. Properties run first; CWE verifiers serve as fallback for CWEs that no property covers yet.

**Files:**
- Modify: `src/verifier/index.ts` (the `verifyAll` function)
- Add test: `src/properties/properties.test.ts`

**Step 1: Write the failing test**

```typescript
// Append to src/properties/properties.test.ts

import { verifyAll } from '../verifier/index.js';

describe('Property engine integration with verifyAll', () => {
  beforeEach(() => resetSequenceHard());

  it('property-detected SQLi appears in verifyAll results', () => {
    const map = createNeuralMap('test.js', '');
    const src = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request', label: 'req.body',
      data_in: [{ name: 'x', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'sink1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink1', node_type: 'STORAGE', node_subtype: 'sql_query', label: 'db.query',
      data_in: [{ name: 'q', source: src.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    map.nodes = [src, sink];

    const results = verifyAll(map, 'javascript');
    const sqli = results.find(r => r.cwe === 'CWE-89' && !r.holds);
    expect(sqli).toBeDefined();
  });
});
```

**Step 2: Implement the integration**

In `src/verifier/index.ts`, modify the `verifyAll` function to run properties first:

```typescript
// Add import at top of verifier/index.ts:
import { runProperties, propertyResultsToFindings } from '../properties/index.js';
import { inferMapLanguage, isLibraryCode } from './graph-helpers.ts';
```

Then modify `verifyAll` to include property engine results. The property results should be merged with CWE verifier results, with property results taking precedence for CWEs they cover.

**Key principle:** For any CWE that a property covers, the property result wins. For CWEs not covered by properties, the CWE verifier runs as before. This is a gradual transition.

**Step 3: Run full test suite**

Run: `cd C:/Users/pizza/DST_Alpha_v1/dst-engine && npx vitest run`
Expected: All 1,709 existing tests pass + new property tests pass

**Step 4: Commit**

```bash
git add src/verifier/index.ts src/properties/properties.test.ts
git commit -m "feat: wire property engine into verifyAll — properties first, CWE fallback"
```

---

## Phase 2: Universal Properties (replacing factory verifiers)

### Task 6: Missing-Auth Property

Replaces factory patterns 10 (INGRESS→STORAGE without AUTH) and 12 (INGRESS→AUTH without CONTROL).

**Files:**
- Create: `src/properties/missing-auth.ts`
- Register in: `src/properties/index.ts`
- Test: `src/properties/properties.test.ts`

The property asserts: "No untrusted input reaches a privileged operation without an authentication or authorization gate."

CWE mappings: CWE-285 (Improper Authorization), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-306 (Missing Authentication).

Implementation: BFS from INGRESS to STORAGE nodes tagged as `privileged` or with sensitivity `AUTH`/`FINANCIAL`, checking for AUTH nodes on the path.

---

### Task 7: Sensitive-Exposure Property

Replaces dozens of sensitive-data verifiers.

**Files:**
- Create: `src/properties/sensitive-exposure.ts`

The property asserts: "No data with sensitivity > NONE reaches an EGRESS or log sink without encryption or redaction."

CWE mappings: CWE-200, CWE-209, CWE-312, CWE-319, CWE-532, CWE-598.

Implementation: Find all nodes where `data_in` has `sensitivity` != 'NONE'. Check if any path from that node reaches an EGRESS/STORAGE(log) without passing through TRANSFORM/encrypt or TRANSFORM/hash.

---

### Task 8: Weak-Crypto Property

Replaces CRYPTO_REGISTRY verifiers.

**Files:**
- Create: `src/properties/weak-crypto.ts`

The property asserts: "No cryptographic operation uses a known-weak algorithm or hardcoded key material."

CWE mappings: CWE-327, CWE-328, CWE-326, CWE-261, CWE-321.

Implementation: Structural check on TRANSFORM/encrypt nodes. Check `algorithm_name` against a blocklist (MD5, SHA1, DES, RC4, ECB mode). Check for hardcoded key material in `data_in` where source is a literal.

---

### Task 9: Resource-Lifecycle Property (Typestate Foundation)

**Files:**
- Create: `src/properties/resource-lifecycle.ts`

The property asserts: "Every acquired resource (file, connection, lock) is released on all exit paths."

CWE mappings: CWE-401 (Memory Leak), CWE-404 (Improper Resource Shutdown), CWE-772 (Missing Release).

Implementation: This is the typestate foundation. For each RESOURCE node that represents an acquisition (open/connect/lock), check that a corresponding release (close/disconnect/unlock) exists on every path to function exit. This uses the STRUCTURAL/CONTAINS edges to find function boundaries.

---

## Phase 3: NeuralMap Enrichment

### Task 10: Add Buffer Size Tracking to Types

**Files:**
- Modify: `src/types.ts`
- Test: `src/properties/properties.test.ts`

**Step 1: Extend NeuralMapNode with optional buffer_size**

```typescript
// Add to NeuralMapNode interface in types.ts:
  /** Buffer/allocation size interval [min, max] — used by buffer overflow detection */
  buffer_size?: RangeInfo;
  /** Type width in bits — used for integer overflow and sentinel detection */
  type_width?: number;
```

**Step 2: Extend DataFlow with write_size**

```typescript
// Add to DataFlow interface in types.ts:
  /** Size of data being written through this flow — used for buffer overflow detection */
  write_size?: RangeInfo;
```

These are all optional fields — existing code is unaffected.

---

### Task 11: Buffer Overflow Property

**Files:**
- Create: `src/properties/buffer-overflow.ts`

The property asserts: "No write operation exceeds the allocation size of its target buffer."

This catches the FreeBSD NFS bug (128-byte buffer receiving 400 bytes) and the Linux kernel NFS bug (112-byte buffer receiving 1056 bytes) — deterministically.

CWE mappings: CWE-119, CWE-120, CWE-121, CWE-122, CWE-787.

Implementation: For each STORAGE node with `buffer_size` defined, check all incoming `data_flow` edges. If any edge has `write_size.max > buffer_size.min` (the maximum possible write exceeds the minimum possible buffer), flag a violation.

```
FIND: STORAGE nodes S where S.buffer_size exists
  AND incoming DATA_FLOW edge E where E.write_size exists
  AND E.write_size.max > S.buffer_size.min
  → VIOLATION: potential buffer overflow
```

---

### Task 12: Integer Range Property

**Files:**
- Create: `src/properties/integer-range.ts`

The property asserts: "No arithmetic operation on attacker-influenced data produces a value outside its type's representable range without a preceding bounds check."

This catches the OpenBSD TCP SACK class (signed overflow at 2^31).

CWE mappings: CWE-190 (Integer Overflow), CWE-191 (Integer Underflow), CWE-681 (Incorrect Conversion).

Implementation: For each TRANSFORM node performing arithmetic (subtype contains 'arithmetic', 'add', 'multiply', etc.), check if:
1. Any input is tainted (attacker-influenced)
2. The output range (from RangeInfo propagation) exceeds the type width
3. No preceding CONTROL node bounds-checks the input

---

### Task 13: Sentinel Collision Property

**Files:**
- Create: `src/properties/sentinel-collision.ts`

The property asserts: "No computed value can equal a sentinel value used in control flow decisions."

This catches the FFmpeg H.264 bug (16-year-old: counter reaching 65535 = sentinel). **No other production SAST tool does this.**

CWE mappings: CWE-138 (Improper Neutralization of Special Elements), CWE-170 (Improper Null Termination).

Implementation:
1. Build sentinel registry: scan CONTROL nodes for comparisons against constants (`== 0xFFFF`, `== -1`, `== NULL`). Register each constant as a sentinel for its compared variable.
2. Range check: for each variable with a registered sentinel, check if the variable's RangeInfo includes the sentinel value.
3. If the range includes the sentinel AND the variable is NOT the sentinel's expected producer → VIOLATION.

---

## Phase 4: Advanced Properties

### Task 14: Cross-Callsite Consistency Property

**Files:**
- Create: `src/properties/callsite-consistency.ts`

The property asserts: "All callsites of a function that was patched with a safety check have the same safety check."

This catches the GhostScript bug (fix in one callsite, same bug in another). Requires cross-file analysis via the margin pass.

CWE mappings: CWE-252 (Unchecked Return Value), CWE-754 (Improper Check for Exceptional Conditions).

Implementation:
1. For each function F, collect all callsites across all files
2. Check if some callsites have a preceding CONTROL node and others don't
3. If the CONTROL node at protected callsites checks for the same condition (bounds, null, auth), flag unprotected callsites

---

### Task 15: Specification Mining Property

**Files:**
- Create: `src/properties/spec-mining.ts`

The property asserts: "Code patterns that deviate from the statistical norm in the codebase are flagged for review."

This is the "deviant behavior" approach from Engler (SOSP 2001), applied to DST's semantic sentences.

Implementation:
1. Collect all sentence patterns: for each STORAGE node, what TRANSFORM/CONTROL patterns typically precede it?
2. Compute frequency: "85% of STORAGE/sql_query nodes are preceded by TRANSFORM/sanitize"
3. Flag outliers: any STORAGE/sql_query NOT preceded by TRANSFORM/sanitize is deviant
4. This catches novel vulnerability classes that no CWE covers — because it learns the codebase's own conventions

---

## Phase 5: Deprecation Path for CWE Verifiers

### Task 16: Coverage Tracking

**Files:**
- Create: `src/properties/coverage.ts`

Build a coverage map: for each CWE in the registry, does a property already cover it?

```typescript
// Returns which CWEs are covered by properties vs legacy verifiers
export function getCoverage(): {
  propertyBacked: string[];  // CWEs covered by properties
  legacyOnly: string[];      // CWEs only in CWE_REGISTRY
  uncovered: string[];       // CWEs in neither
}
```

This tracks the transition. As properties cover more CWEs, the legacy verifier code becomes dead weight and can be pruned file by file.

### Task 17: OWASP Benchmark Regression Gate

**Files:**
- Add benchmark test verifying OWASP scores are unchanged

Before any legacy verifier file is deleted, run the OWASP BenchmarkJava suite and confirm:
- SQLi score >= 92.7% (current)
- Overall score >= 83.7% (current)
- Zero new false positives introduced

---

## NOT in This Plan (Future Work)

These are important but require separate research phases:

1. **Concurrency analysis** (Pattern 4 from Mythos research): Thread context annotations, lock scope edges, reference counting. Requires significant new graph infrastructure. Separate plan after Phase 5.

2. **Patch completeness via git integration** (full version): Reading actual git diffs to find incomplete fixes. The callsite-consistency property (Task 14) is the deterministic approximation; full git integration is a separate tool.

3. **Algorithmic invariant knowledge base**: The CGIF LZW bug requires knowing that "LZW can expand data." This is a domain knowledge problem. A curated knowledge base of algorithmic assumptions (compression ratios, hash collision probabilities, counter wrap conditions) would feed into the sentinel collision and buffer overflow properties. Separate research.

4. **Dynamic verification sandbox**: Running proof certificate payloads against a live application. The RuntimeVerification types already exist in `verifier/types.ts`. Building the sandbox runner is a separate project.

---

## Architecture Summary

```
Before (current):
  NeuralMap → 783 CWE Verifiers → Findings

After (this plan):
  NeuralMap → Property Engine (20 properties) → Violations
                                                    ↓
                                              CWE Reverse Map → Findings
                        ↓ (uncovered CWEs)
                  Legacy CWE Verifiers → Findings
                                                    ↓
                                              Dedup → Report
```

The property engine is the primary detection layer. CWE verifiers are the compatibility fallback. Over time, the arrow pointing to legacy verifiers carries less and less traffic until the verifier files can be deleted.

---

## File Inventory

**New files (this plan creates):**
- `src/properties/types.ts` — Property, Violation, CWEMapping interfaces
- `src/properties/cwe-map.ts` — Violation → CWE mapping engine
- `src/properties/taint-reachability.ts` — The big one: replaces all injection verifiers
- `src/properties/missing-auth.ts` — Authorization property
- `src/properties/sensitive-exposure.ts` — Data exposure property
- `src/properties/weak-crypto.ts` — Cryptography property
- `src/properties/resource-lifecycle.ts` — Typestate foundation
- `src/properties/buffer-overflow.ts` — Buffer size checking
- `src/properties/integer-range.ts` — Integer overflow detection
- `src/properties/sentinel-collision.ts` — Novel: sentinel value collision
- `src/properties/callsite-consistency.ts` — Cross-callsite guard checking
- `src/properties/spec-mining.ts` — Deviant behavior detection
- `src/properties/coverage.ts` — Transition tracking
- `src/properties/engine.ts` — Property runner
- `src/properties/index.ts` — Registry
- `src/properties/properties.test.ts` — All property tests

**Modified files:**
- `src/types.ts` — Add optional `buffer_size`, `type_width`, `write_size` fields
- `src/verifier/index.ts` — Wire property engine into `verifyAll`

**Untouched files (zero changes):**
- All 60 existing test files
- `src/mapper.ts`
- `src/sentence-generator.ts`, `src/sentence-resolver.ts`, `src/sentence-templates.ts`
- `src/cross-file.ts`, `src/margin-pass.ts`
- `src/payload-gen.ts`, `src/payload-dictionary.ts`
- All profile files (`src/profiles/*`)
- All phoneme expansion files (`src/phoneme-expansion/*`)
- All existing verifier domain files (`src/verifier/auth.ts`, etc.)
- `src/dedup.ts`

**Eventually deletable (after property coverage reaches 100%):**
- `src/generated/batch_001.ts` through `batch_021.ts` (~12,460 lines)
- `src/generated/_helpers.ts` (shared BFS moves into property engine)
- Individual verifier domain files as properties subsume their CWEs
