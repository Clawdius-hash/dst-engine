/**
 * Property Engine — Sentinel Collision Property
 *
 * Assertion: "No computed value can equal a sentinel value used in control flow
 * decisions within the same scope."
 *
 * This detects the class of bug exemplified by the FFmpeg H.264 vulnerability
 * (16 years old, found by Claude Mythos): a 16-bit lookup table initialized with
 * 0xFFFF meaning "empty slot," while a 32-bit counter could legitimately reach
 * 65535, colliding with the sentinel. This caused an out-of-bounds write that
 * 5 million fuzzer runs missed.
 *
 * No other production SAST tool detects this deterministically.
 *
 * Two phases:
 * 1. Build sentinel registry — scan CONTROL nodes for equality comparisons
 *    against special constants (-1, null, 0xFFFF, 0, etc.)
 * 2. Check for collisions — find nodes that PRODUCE the sentinel's variable
 *    with a range that INCLUDES the sentinel value.
 */

import type { NeuralMap, NeuralMapNode } from '../types.js';
import type { NodeRef } from '../verifier/types.js';
import type {
  SecurityProperty,
  CWEMapping,
  PropertyContext,
  PropertyResult,
  PropertyViolation,
} from './types.js';
import type { RangeInfo } from '../types.js';

// ---------------------------------------------------------------------------
// Sentinel Patterns — equality comparisons against special constants
// ---------------------------------------------------------------------------

/**
 * Each pattern captures: (variable, sentinelLiteral) or (sentinelLiteral, variable).
 * We use two capture groups so we can determine which is the variable and which
 * is the sentinel.
 */
const SENTINEL_PATTERNS: Array<{
  regex: RegExp;
  /** Which capture group is the variable (1 or 2) */
  varGroup: number;
  /** Which capture group is the sentinel literal (1 or 2) */
  sentinelGroup: number;
}> = [
  // if (x == -1), if (result === -1)
  { regex: /(\w+)\s*(?:===?|!==?)\s*(-1)\b/, varGroup: 1, sentinelGroup: 2 },
  // if (x == null), if (x === undefined), if (x == NULL), if (x == nullptr)
  { regex: /(\w+)\s*(?:===?|!==?)\s*(null|undefined|NULL|nullptr)\b/, varGroup: 1, sentinelGroup: 2 },
  // if (x == 0xFFFF), if (idx == 0xFF), if (x == 0xFFFFFFFF)
  { regex: /(\w+)\s*(?:===?|!==?)\s*(0x[fF]{2,})\b/, varGroup: 1, sentinelGroup: 2 },
  // if (x == 0), if (result === 0)
  { regex: /(\w+)\s*(?:===?|!==?)\s*(0)\b/, varGroup: 1, sentinelGroup: 2 },
  // Reversed forms: if (-1 == x)
  { regex: /(-1)\s*(?:===?|!==?)\s*(\w+)/, varGroup: 2, sentinelGroup: 1 },
  { regex: /(null|undefined|NULL|nullptr)\s*(?:===?|!==?)\s*(\w+)/, varGroup: 2, sentinelGroup: 1 },
  { regex: /(0x[fF]{2,})\s*(?:===?|!==?)\s*(\w+)/, varGroup: 2, sentinelGroup: 1 },
  { regex: /(0)\s*(?:===?|!==?)\s*(\w+)/, varGroup: 2, sentinelGroup: 1 },
];

// ---------------------------------------------------------------------------
// Sentinel Registry Entry
// ---------------------------------------------------------------------------

interface SentinelEntry {
  /** The variable name being compared against the sentinel */
  variable: string;
  /** The raw sentinel literal (e.g., '-1', '0xFFFF', 'null') */
  sentinelLiteral: string;
  /** Numeric value of the sentinel (NaN for null/undefined/nullptr) */
  sentinelNumeric: number;
  /** The CONTROL node performing the comparison */
  controlNode: NeuralMapNode;
}

// ---------------------------------------------------------------------------
// CWE Mappings
// ---------------------------------------------------------------------------

const SENTINEL_CWE_MAPPINGS: CWEMapping[] = [
  {
    cwe: 'CWE-138',
    name: 'Improper Neutralization of Special Elements',
    severity: 'medium',
    when: { sinkType: 'CONTROL' },
  },
  {
    cwe: 'CWE-253',
    name: 'Incorrect Check of Function Return Value',
    severity: 'medium',
    when: { sinkType: 'CONTROL' },
  },
  {
    cwe: 'CWE-170',
    name: 'Improper Null Termination',
    severity: 'medium',
    when: { sinkType: 'CONTROL' },
  },
];

// ---------------------------------------------------------------------------
// Phase 1: Build Sentinel Registry
// ---------------------------------------------------------------------------

/**
 * Parse a sentinel literal into its numeric value.
 * Returns NaN for non-numeric sentinels (null, undefined, nullptr).
 */
function parseSentinelValue(literal: string): number {
  if (literal === 'null' || literal === 'undefined' || literal === 'NULL' || literal === 'nullptr') {
    return NaN;
  }
  if (literal.startsWith('0x') || literal.startsWith('0X')) {
    return parseInt(literal, 16);
  }
  return Number(literal);
}

/**
 * Scan CONTROL nodes for sentinel comparisons.
 * Returns a registry of all sentinel-variable pairs found.
 */
function buildSentinelRegistry(nodes: NeuralMapNode[]): SentinelEntry[] {
  const registry: SentinelEntry[] = [];

  for (const node of nodes) {
    if (node.node_type !== 'CONTROL') continue;

    // Check label and code_snapshot for sentinel patterns
    const textToScan = [node.label, node.code_snapshot].filter(Boolean);

    for (const text of textToScan) {
      for (const pattern of SENTINEL_PATTERNS) {
        const match = pattern.regex.exec(text);
        if (!match) continue;

        const variable = match[pattern.varGroup];
        const sentinelLiteral = match[pattern.sentinelGroup];

        // Skip if "variable" is actually a keyword or pure numeric
        if (isKeyword(variable)) continue;

        const sentinelNumeric = parseSentinelValue(sentinelLiteral);

        // Only track numeric sentinels for range collision checks
        // (null/undefined collisions are a different class of bug)
        if (Number.isNaN(sentinelNumeric)) continue;

        registry.push({
          variable,
          sentinelLiteral,
          sentinelNumeric,
          controlNode: node,
        });
      }
    }
  }

  return registry;
}

/**
 * Filter out language keywords that look like identifiers but aren't variables.
 */
function isKeyword(name: string): boolean {
  const KEYWORDS = new Set([
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'break', 'continue',
    'return', 'true', 'false', 'var', 'let', 'const', 'function', 'class',
    'new', 'this', 'typeof', 'instanceof', 'void', 'delete', 'throw',
    'try', 'catch', 'finally', 'import', 'export', 'default', 'from',
    'async', 'await', 'yield', 'in', 'of', 'with',
    'int', 'char', 'float', 'double', 'long', 'short', 'unsigned', 'signed',
    'struct', 'enum', 'union', 'typedef', 'sizeof', 'static', 'extern',
    'register', 'volatile', 'auto', 'goto',
  ]);
  return KEYWORDS.has(name);
}

// ---------------------------------------------------------------------------
// Phase 2: Check for Collisions
// ---------------------------------------------------------------------------

/**
 * Check if a range includes a specific numeric value.
 * An unbounded range (or missing range) is treated as potentially including anything.
 */
function rangeIncludesValue(range: RangeInfo | undefined, value: number): boolean {
  if (!range || !range.bounded) return true; // unbounded = could include anything
  return range.min <= value && value <= range.max;
}

/**
 * Create a NodeRef from a NeuralMapNode.
 */
function nodeRefFrom(node: NeuralMapNode): NodeRef {
  return {
    id: node.id,
    label: node.label,
    line: node.line_start || 0,
    code: node.code_snapshot?.slice(0, 200) ?? '',
  };
}

/**
 * Format a range for display.
 */
function formatRange(range: RangeInfo | undefined): string {
  if (!range || !range.bounded) return '[unbounded]';
  return `[${range.min}, ${range.max}]`;
}

/**
 * Check all sentinel entries against all producing nodes.
 */
function checkCollisions(
  nodes: NeuralMapNode[],
  registry: SentinelEntry[],
): PropertyViolation[] {
  const violations: PropertyViolation[] = [];

  for (const entry of registry) {
    // Find nodes that PRODUCE the sentinel's variable
    // These are nodes where data_out contains the variable name
    for (const node of nodes) {
      // Skip the CONTROL node itself — the check IS the sentinel use
      if (node.id === entry.controlNode.id) continue;

      // Look for the variable in data_out
      const matchingOutput = node.data_out?.find(
        d => d.name === entry.variable,
      );
      if (!matchingOutput) continue;

      // Check if the producing node's output range includes the sentinel value
      const range = matchingOutput.range;
      if (rangeIncludesValue(range, entry.sentinelNumeric)) {
        violations.push({
          source: nodeRefFrom(node),
          sink: nodeRefFrom(entry.controlNode),
          sinkType: 'CONTROL',
          sinkSubtype: entry.controlNode.node_subtype || 'branch',
          missing: 'validation',
          via: 'property_structural',
          description:
            `Variable '${entry.variable}' can reach sentinel value ${entry.sentinelLiteral}` +
            ` (${entry.sentinelNumeric}) — range ${formatRange(range)} includes sentinel`,
          context: {
            sentinel_value: String(entry.sentinelNumeric),
            variable_range: formatRange(range),
          },
        });
      }
    }
  }

  return violations;
}

// ---------------------------------------------------------------------------
// The Property
// ---------------------------------------------------------------------------

/**
 * Sentinel Collision Property
 *
 * Asserts: "No computed value can equal a sentinel value used in control flow
 * decisions within the same scope."
 *
 * Detects the FFmpeg-class of bugs where a legitimate computed value can
 * collide with a magic sentinel constant used in equality checks.
 */
export const sentinelCollision: SecurityProperty = {
  id: 'sentinel-collision',
  name: 'Sentinel Collision',
  assertion:
    'No computed value can equal a sentinel value used in control flow decisions within the same scope.',
  cweMapping: SENTINEL_CWE_MAPPINGS,

  verify(map: NeuralMap, _ctx: PropertyContext): PropertyResult {
    // Phase 1: Build sentinel registry from CONTROL nodes
    const registry = buildSentinelRegistry(map.nodes);

    // If no sentinels found, property holds trivially
    if (registry.length === 0) {
      return {
        propertyId: 'sentinel-collision',
        holds: true,
        violations: [],
      };
    }

    // Phase 2: Check for collisions
    const violations = checkCollisions(map.nodes, registry);

    // Deduplicate by source-sink-sentinel triple
    const seen = new Set<string>();
    const deduped: PropertyViolation[] = [];
    for (const v of violations) {
      const key = `${v.source.id}:${v.sink.id}:${v.context?.sentinel_value}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(v);
      }
    }

    return {
      propertyId: 'sentinel-collision',
      holds: deduped.length === 0,
      violations: deduped,
    };
  },
};
