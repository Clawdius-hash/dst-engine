/**
 * Property Engine — Sensitive-Exposure Property
 *
 * Assertion: "No data with sensitivity > NONE reaches an EGRESS or logging sink
 * without encryption or redaction."
 *
 * Detects:
 * - Nodes with data_in having sensitivity PII, SECRET, AUTH, or FINANCIAL
 *   that flow to EGRESS nodes or STORAGE nodes with subtype containing 'log',
 *   without passing through TRANSFORM/encrypt, TRANSFORM/hash, or TRANSFORM/sanitize.
 */

import type { NeuralMap, NeuralMapNode, NodeType, EdgeType, Sensitivity } from '../types.js';
import type { NodeRef } from '../verifier/types.js';
import type { SecurityProperty, CWEMapping, PropertyContext, PropertyResult, PropertyViolation } from './types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Sensitivity levels that require protection before exposure.
 */
const SENSITIVE_LEVELS: ReadonlySet<Sensitivity> = new Set([
  'PII', 'SECRET', 'AUTH', 'FINANCIAL',
]);

/**
 * TRANSFORM subtypes that neutralize sensitive data exposure.
 * encrypt, hash, and sanitize (redaction) all protect sensitive data.
 */
const PROTECTING_SUBTYPES: ReadonlySet<string> = new Set([
  'encrypt', 'hash', 'sanitize',
]);

/**
 * Edge types that represent actual data flow (same as taint-reachability).
 */
const FLOW_EDGE_TYPES: ReadonlySet<EdgeType> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);

// ---------------------------------------------------------------------------
// CWE Mappings
// ---------------------------------------------------------------------------

const SENSITIVE_EXPOSURE_CWE_MAPPINGS: CWEMapping[] = [
  {
    cwe: 'CWE-200',
    name: 'Exposure of Sensitive Information',
    when: { sinkType: 'EGRESS' },
    severity: 'high',
  },
  {
    cwe: 'CWE-209',
    name: 'Error Message Information Exposure',
    when: { sinkType: 'EGRESS', sinkSubtype: 'http_response', missing: 'encryption' },
    severity: 'medium',
  },
  {
    cwe: 'CWE-312',
    name: 'Cleartext Storage of Sensitive Information',
    when: { sinkType: 'STORAGE' },
    severity: 'high',
  },
  {
    cwe: 'CWE-319',
    name: 'Cleartext Transmission of Sensitive Information',
    when: { sinkType: 'EGRESS', missing: 'encryption' },
    severity: 'high',
  },
  {
    cwe: 'CWE-532',
    name: 'Insertion of Sensitive Information into Log File',
    when: { sinkType: 'STORAGE', sinkSubtype: 'log_write' },
    severity: 'medium',
  },
  {
    cwe: 'CWE-598',
    name: 'Use of GET Request Method With Sensitive Query Strings',
    when: { sinkType: 'EGRESS', sinkSubtype: 'redirect' },
    severity: 'medium',
  },
];

// ---------------------------------------------------------------------------
// Fix suggestions
// ---------------------------------------------------------------------------

const FIX_SUGGESTIONS: Record<string, string> = {
  'CWE-200': 'Encrypt or redact sensitive data before exposing it to external consumers.',
  'CWE-209': 'Avoid including sensitive information in error messages. Use generic error responses.',
  'CWE-312': 'Encrypt sensitive data before storing it, or use hashing for irreversible storage.',
  'CWE-319': 'Use TLS/encryption for transmitting sensitive data. Never send secrets in cleartext.',
  'CWE-532': 'Redact or mask sensitive fields before logging. Use structured logging with sensitivity filters.',
  'CWE-598': 'Avoid placing sensitive data in URL query strings. Use POST body or secure headers instead.',
};

// ---------------------------------------------------------------------------
// Sink detection helpers
// ---------------------------------------------------------------------------

/**
 * Check if a node is a sensitive-data sink:
 * - Any EGRESS node
 * - Any STORAGE node with subtype containing 'log'
 */
function isSensitiveSink(node: NeuralMapNode): boolean {
  if (node.node_type === 'EGRESS') return true;
  if (node.node_type === 'STORAGE' && node.node_subtype.includes('log')) return true;
  return false;
}

/**
 * Check if a node has sensitive data in its data_in.
 */
function hasSensitiveDataIn(node: NeuralMapNode): boolean {
  return node.data_in.some(d => SENSITIVE_LEVELS.has(d.sensitivity));
}

// ---------------------------------------------------------------------------
// BFS — find unprotected paths from sensitive nodes to exposure sinks
// ---------------------------------------------------------------------------

/**
 * BFS forward from a sensitive source node to find reachable sinks
 * without TRANSFORM/encrypt, TRANSFORM/hash, or TRANSFORM/sanitize on the path.
 *
 * Uses composite visited keys (nodeId:protected) to avoid safe-path pruning,
 * same pattern as taint-reachability.
 */
function hasUnprotectedPath(
  map: NeuralMap,
  nodeMap: Map<string, NeuralMapNode>,
  sourceId: string,
  sinkId: string,
): boolean {
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; protected: boolean }> = [
    { nodeId: sourceId, protected: false },
  ];
  let head = 0;

  while (head < queue.length) {
    const { nodeId, protected: isProtected } = queue[head++];
    const visitKey = `${nodeId}:${isProtected}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    // Check if this node protects the data (encrypt, hash, or sanitize/redact)
    let protectsData = false;
    if (node.node_type === 'TRANSFORM' && PROTECTING_SUBTYPES.has(node.node_subtype)) {
      protectsData = true;
    }

    const protectedNow = isProtected || protectsData;

    // Reached the sink — vulnerable only if not protected
    if (nodeId === sinkId) {
      if (!protectedNow) return true;
      continue;
    }

    // Follow data-flow edges
    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      const edgeKey = `${edge.target}:${protectedNow}`;
      if (!visited.has(edgeKey)) {
        queue.push({ nodeId: edge.target, protected: protectedNow });
      }
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nodeRefFrom(node: NeuralMapNode | undefined, id: string, line: number): NodeRef {
  if (!node) {
    return { id, label: '', line, code: '' };
  }
  return {
    id: node.id,
    label: node.label,
    line: node.line_start || line,
    code: node.code_snapshot?.slice(0, 200) ?? '',
  };
}

// ---------------------------------------------------------------------------
// The Property
// ---------------------------------------------------------------------------

/**
 * Sensitive-Exposure Property
 *
 * Asserts: "No data with sensitivity > NONE reaches an EGRESS or logging sink
 * without encryption or redaction."
 */
export const sensitiveExposure: SecurityProperty = {
  id: 'sensitive-exposure',
  name: 'Sensitive Data Exposure',
  assertion: 'No data with sensitivity > NONE reaches an EGRESS or logging sink without encryption or redaction.',
  cweMapping: SENSITIVE_EXPOSURE_CWE_MAPPINGS,

  verify(map: NeuralMap, _ctx: PropertyContext): PropertyResult {
    const violations: PropertyViolation[] = [];
    const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

    // Step 1: Find all nodes where data_in contains sensitive entries
    const sensitiveNodes = map.nodes.filter(n => hasSensitiveDataIn(n));

    // Step 2: Find all sink nodes (EGRESS or log-related STORAGE)
    const sinkNodes = map.nodes.filter(n => isSensitiveSink(n));

    // Step 3: For each sensitive source, BFS to each sink
    for (const source of sensitiveNodes) {
      for (const sink of sinkNodes) {
        // Don't check a node against itself unless it's also a sink
        if (source.id === sink.id) continue;

        if (hasUnprotectedPath(map, nodeMap, source.id, sink.id)) {
          // Determine the highest sensitivity level from the source
          const sensitivities = source.data_in
            .filter(d => SENSITIVE_LEVELS.has(d.sensitivity))
            .map(d => d.sensitivity);
          const sensitivityLabel = sensitivities[0] ?? 'PII';

          violations.push({
            source: nodeRefFrom(source, source.id, source.line_start),
            sink: nodeRefFrom(sink, sink.id, sink.line_start),
            sinkType: sink.node_type,
            sinkSubtype: sink.node_subtype,
            missing: 'encryption',
            via: 'property_bfs',
            description: `${sensitivityLabel} data from ${source.label || source.node_subtype} reaches ${sink.node_type}/${sink.node_subtype} without encryption or redaction`,
          });
        }
      }
    }

    // Deduplicate by source-sink pair
    const seen = new Set<string>();
    const deduped: PropertyViolation[] = [];
    for (const v of violations) {
      const key = `${v.source.id}:${v.sink.id}:${v.sinkSubtype}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(v);
      }
    }

    return {
      propertyId: 'sensitive-exposure',
      holds: deduped.length === 0,
      violations: deduped,
    };
  },
};

export { SENSITIVE_EXPOSURE_CWE_MAPPINGS, FIX_SUGGESTIONS };
