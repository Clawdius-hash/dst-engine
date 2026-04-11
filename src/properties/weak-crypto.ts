/**
 * Property Engine -- Weak-Crypto Property
 *
 * Assertion: "No cryptographic operation uses a known-weak algorithm or
 * hardcoded key material."
 *
 * Two sub-checks:
 * 1. Weak Algorithm Detection: TRANSFORM nodes with subtype 'encrypt' or 'hash'
 *    whose algorithm_name (or code/analysis snapshot) matches a weak algorithm
 *    blocklist (MD5, SHA-1, DES, 3DES, RC2, RC4, Blowfish, ECB mode).
 * 2. Hardcoded Key Detection: TRANSFORM/encrypt nodes whose data_in includes a
 *    flow from a literal/constant source (STRUCTURAL node or literal data_type).
 *
 * This property is STRUCTURAL -- it examines individual nodes without BFS taint
 * tracking.
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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * TRANSFORM subtypes that involve cryptographic operations.
 */
const CRYPTO_SUBTYPES: ReadonlySet<string> = new Set([
  'hash', 'encrypt', 'decrypt',
]);

/**
 * Weak algorithm patterns — matched against algorithm_name, code_snapshot,
 * and analysis_snapshot (case-insensitive).
 */
const WEAK_ALGORITHM_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /\bmd5\b/i, name: 'MD5' },
  { pattern: /\bsha-?1\b/i, name: 'SHA-1' },
  { pattern: /\bdes\b/i, name: 'DES' },
  { pattern: /\b3des\b/i, name: '3DES' },
  { pattern: /\brc4\b/i, name: 'RC4' },
  { pattern: /\brc2\b/i, name: 'RC2' },
  { pattern: /\bblowfish\b/i, name: 'Blowfish' },
];

/**
 * Weak mode patterns — matched against code_snapshot and analysis_snapshot.
 */
const WEAK_MODE_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /\becb\b/i, name: 'ECB' },
];

// ---------------------------------------------------------------------------
// CWE Mappings
// ---------------------------------------------------------------------------

const WEAK_CRYPTO_CWE_MAPPINGS: CWEMapping[] = [
  {
    cwe: 'CWE-327',
    name: 'Use of a Broken or Risky Cryptographic Algorithm',
    when: { sinkSubtype: ['hash', 'encrypt'], missing: 'encryption' },
    severity: 'high',
  },
  {
    cwe: 'CWE-328',
    name: 'Use of Weak Hash',
    when: { sinkSubtype: 'hash', missing: 'encryption' },
    severity: 'medium',
  },
  {
    cwe: 'CWE-326',
    name: 'Inadequate Encryption Strength',
    when: { sinkSubtype: 'encrypt', missing: 'encryption' },
    severity: 'high',
  },
  {
    cwe: 'CWE-261',
    name: 'Weak Encoding for Password',
    when: { sinkSubtype: 'hash', missing: 'encryption' },
    severity: 'high',
  },
  {
    cwe: 'CWE-321',
    name: 'Use of Hard-coded Cryptographic Key',
    when: { missing: 'encryption' },
    severity: 'critical',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nodeRef(n: NeuralMapNode): NodeRef {
  return {
    id: n.id,
    label: n.label,
    line: n.line_start,
    code: n.code_snapshot.slice(0, 200),
  };
}

/**
 * Detect weak algorithm in a node by checking algorithm_name, code_snapshot,
 * and analysis_snapshot against known weak algorithm patterns.
 */
function detectWeakAlgorithm(node: NeuralMapNode): string | null {
  const textsToCheck = [
    node.algorithm_name ?? '',
    node.code_snapshot ?? '',
    node.analysis_snapshot ?? '',
  ];

  for (const { pattern, name } of WEAK_ALGORITHM_PATTERNS) {
    for (const text of textsToCheck) {
      if (pattern.test(text)) return name;
    }
  }

  for (const { pattern, name } of WEAK_MODE_PATTERNS) {
    for (const text of textsToCheck) {
      if (pattern.test(text)) return name;
    }
  }

  return null;
}

/**
 * Detect hardcoded cryptographic key — a TRANSFORM/encrypt or TRANSFORM/hash
 * node that receives a data_in with data_type 'literal' from a constant source.
 */
function hasHardcodedKey(node: NeuralMapNode, map: NeuralMap): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  for (const d of node.data_in ?? []) {
    // data_type 'literal' or 'constant' indicates hardcoded value
    if (d.data_type === 'literal' || d.data_type === 'constant') return true;

    // Check if the source node is a STRUCTURAL or constant/literal node
    if (d.source) {
      const sourceNode = nodeMap.get(d.source);
      if (!sourceNode) continue;

      // STRUCTURAL nodes represent declarations/constants
      if (sourceNode.node_type === 'STRUCTURAL') return true;

      // Also check for constant/literal subtypes
      if (sourceNode.node_subtype === 'constant' || sourceNode.node_subtype === 'literal') {
        return true;
      }
    }

    // Check if the flow name suggests a hardcoded value
    const nameLower = d.name.toLowerCase();
    if (nameLower.includes('hardcoded') || nameLower.includes('hardcoded_key')) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// The Property
// ---------------------------------------------------------------------------

export const weakCrypto: SecurityProperty = {
  id: 'weak-crypto',
  name: 'Weak Cryptography',
  assertion: 'No cryptographic operation uses a weak or deprecated algorithm, and no encryption key is hardcoded.',
  cweMapping: WEAK_CRYPTO_CWE_MAPPINGS,

  verify(map: NeuralMap, _ctx: PropertyContext): PropertyResult {
    const violations: PropertyViolation[] = [];

    // Check each TRANSFORM node with crypto subtypes
    for (const node of map.nodes) {
      if (node.node_type !== 'TRANSFORM') continue;
      if (!CRYPTO_SUBTYPES.has(node.node_subtype)) continue;

      // Check for weak algorithm
      const weakAlgo = detectWeakAlgorithm(node);
      if (weakAlgo) {
        violations.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          sinkType: node.node_type,
          sinkSubtype: node.node_subtype,
          missing: 'encryption',
          via: 'property_structural',
          description: `Weak cryptographic algorithm ${weakAlgo} used in ${node.label || node.node_subtype}`,
          context: { weak_algorithm: weakAlgo },
        });
        continue; // Don't double-report weak algo + hardcoded key for same node
      }

      // Check for hardcoded key
      if (hasHardcodedKey(node, map)) {
        violations.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          sinkType: node.node_type,
          sinkSubtype: node.node_subtype,
          missing: 'encryption',
          via: 'property_structural',
          description: `Hardcoded cryptographic key in ${node.label || node.node_subtype}`,
          context: { hardcoded_key: 'true' },
        });
      }
    }

    return {
      propertyId: 'weak-crypto',
      holds: violations.length === 0,
      violations,
    };
  },
};
