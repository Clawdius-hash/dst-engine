/**
 * Property Engine — Integer Overflow Property
 *
 * Assertion: "No arithmetic operation on attacker-influenced data produces
 * a value outside its type's representable range without a preceding bounds check."
 *
 * Detection strategy (structural):
 * 1. Find TRANSFORM nodes whose code_snapshot matches arithmetic patterns
 *    OR whose node_subtype contains 'arithmetic', 'format', or 'parse'.
 * 2. For each such node, check if any data_in entry is tainted.
 * 3. If tainted, check if the data_in entry has a bounded range via data_in[].range?.bounded.
 * 4. If tainted AND (no range OR range unbounded OR range exceeds INT32 limits) -> violation.
 * 5. If tainted AND range is bounded AND fits within safe limits -> skip (bounds check exists).
 */

import type { NeuralMap, NeuralMapNode } from '../types.js';
import type { SecurityProperty, PropertyViolation, PropertyContext, CWEMapping, PropertyResult } from './types.js';
import type { NodeRef } from '../verifier/types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const INT32_MAX = 2_147_483_647;
const INT32_MIN = -2_147_483_648;

/**
 * Regex to detect arithmetic operations in code snapshots.
 * Matches: +=, -=, *=, /=, %=, binary arithmetic with identifiers,
 * Math functions, parseInt, parseLong, parseFloat, Number(), Integer.valueOf, Long.valueOf.
 */
const ARITHMETIC_RE = /[+\-*/%]\s*=|[+\-*/%]\s+\w|Math\.(abs|ceil|floor|round|pow)|parseInt|parseLong|parseFloat|Number\(|Integer\.valueOf|Long\.valueOf/i;

/**
 * Subtypes that indicate arithmetic/parsing operations.
 */
const ARITHMETIC_SUBTYPES: ReadonlySet<string> = new Set([
  'arithmetic', 'format', 'parse',
]);

// ---------------------------------------------------------------------------
// CWE Mappings
// ---------------------------------------------------------------------------

const CWE_MAPPINGS: CWEMapping[] = [
  {
    cwe: 'CWE-190',
    name: 'Integer Overflow or Wraparound',
    severity: 'high',
    when: { sinkType: 'TRANSFORM' },
  },
  {
    cwe: 'CWE-191',
    name: 'Integer Underflow',
    severity: 'high',
    when: { sinkType: 'TRANSFORM' },
  },
  {
    cwe: 'CWE-681',
    name: 'Incorrect Conversion between Numeric Types',
    severity: 'medium',
    when: { sinkType: 'TRANSFORM', sinkSubtype: ['parse', 'format'] },
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nodeRef(n: NeuralMapNode): NodeRef {
  return { id: n.id, label: n.label, line: n.line_start, code: n.code_snapshot.slice(0, 200) };
}

/**
 * Determine if a TRANSFORM node performs arithmetic.
 * Matches on node_subtype OR code_snapshot regex.
 */
function isArithmeticNode(node: NeuralMapNode): boolean {
  if (node.node_type !== 'TRANSFORM') return false;

  // Check subtype
  if (ARITHMETIC_SUBTYPES.has(node.node_subtype)) return true;

  // Check code snapshot
  const code = node.code_snapshot ?? '';
  if (code && ARITHMETIC_RE.test(code)) return true;

  return false;
}

/**
 * Check if a tainted data_in entry has a bounded range that fits within INT32 limits.
 */
function hasSafeBoundedRange(entry: { range?: { min: number; max: number; bounded: boolean } }): boolean {
  const range = entry.range;
  if (!range) return false;
  if (!range.bounded) return false;
  if (range.max > INT32_MAX) return false;
  if (range.min < INT32_MIN) return false;
  return true;
}

// ---------------------------------------------------------------------------
// The Property
// ---------------------------------------------------------------------------

export const integerOverflow: SecurityProperty = {
  id: 'integer-overflow',
  name: 'Integer Overflow',
  assertion:
    'No arithmetic operation on attacker-influenced data produces a value outside its type\'s representable range without a preceding bounds check.',
  cweMapping: CWE_MAPPINGS,

  verify(map: NeuralMap, _ctx: PropertyContext): PropertyResult {
    const violations: PropertyViolation[] = [];

    for (const node of map.nodes) {
      if (!isArithmeticNode(node)) continue;

      for (const flow of node.data_in) {
        if (!flow.tainted) continue;

        // If the input has a bounded safe range within INT32 limits, no violation
        if (hasSafeBoundedRange(flow)) continue;

        const source = map.nodes.find(n => n.id === flow.source);
        violations.push({
          source: source ? nodeRef(source) : { id: flow.source, label: flow.name, line: 0, code: '' },
          sink: nodeRef(node),
          sinkType: node.node_type,
          sinkSubtype: node.node_subtype,
          missing: 'bounds_check',
          via: 'property_structural',
          description: `Tainted input "${flow.name}" reaches arithmetic operation "${node.label || node.code_snapshot?.slice(0, 50)}" without bounds check`,
          context: {
            data_type: flow.data_type,
            operation: node.node_subtype,
          },
        });
      }
    }

    // Deduplicate by node id + input name
    const seen = new Set<string>();
    const deduped: PropertyViolation[] = [];
    for (const v of violations) {
      const key = `${v.sink.id}:${v.description}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(v);
      }
    }

    return { propertyId: 'integer-overflow', holds: deduped.length === 0, violations: deduped };
  },
};
