/**
 * Property Engine — Missing-Auth Property
 *
 * Assertion: "No untrusted input reaches a privileged operation without
 * an authentication or authorization gate."
 *
 * Detection: BFS from each INGRESS node to each privileged sink. A sink is
 * "privileged" when it handles AUTH/FINANCIAL sensitivity data, has an
 * admin/privileged attack surface, or performs destructive storage operations
 * (db_write, db_stored_proc). If any path from INGRESS to such a sink does
 * NOT traverse an AUTH node, a violation is raised.
 */

import type { NeuralMap, NeuralMapNode, EdgeType } from '../types.js';
import type { NodeRef } from '../verifier/types.js';
import type {
  SecurityProperty,
  CWEMapping,
  PropertyContext,
  PropertyResult,
  PropertyViolation,
} from './types.js';

// ---------------------------------------------------------------------------
// Edge types that represent actual data flow
// ---------------------------------------------------------------------------

const FLOW_EDGES: ReadonlySet<EdgeType> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);

// ---------------------------------------------------------------------------
// CWE Mappings
// ---------------------------------------------------------------------------

const AUTH_CWE_MAPPINGS: CWEMapping[] = [
  {
    cwe: 'CWE-285',
    name: 'Improper Authorization',
    when: { sinkType: 'STORAGE', missing: 'authorization' },
    severity: 'high',
  },
  {
    cwe: 'CWE-862',
    name: 'Missing Authorization',
    when: { missing: 'authorization' },
    severity: 'high',
  },
  {
    cwe: 'CWE-863',
    name: 'Incorrect Authorization',
    when: { missing: 'authorization' },
    severity: 'high',
  },
  {
    cwe: 'CWE-306',
    name: 'Missing Authentication for Critical Function',
    when: { missing: 'authentication' },
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
 * Determine whether a node is a "privileged sink" — an operation that
 * should only be reachable after an authentication/authorization gate.
 *
 * A node qualifies when:
 *  - Its data_in contains AUTH or FINANCIAL sensitivity data, OR
 *  - Its attack_surface mentions admin/privileged/delete/modify/write, OR
 *  - Its subtype is db_write or db_stored_proc (destructive storage ops).
 */
function isPrivilegedSink(node: NeuralMapNode): boolean {
  // Check data_in sensitivity
  if (node.data_in?.some(d => d.sensitivity === 'AUTH' || d.sensitivity === 'FINANCIAL')) {
    return true;
  }
  // Check attack surface tags
  if (node.attack_surface?.some(s => /admin|privileged|delete|modify|write/i.test(s))) {
    return true;
  }
  // Check subtype — destructive storage operations
  if (node.node_subtype === 'db_write' || node.node_subtype === 'db_stored_proc') {
    return true;
  }
  return false;
}

/**
 * BFS from sourceId to sinkId. Returns true if at least one path reaches
 * the sink WITHOUT passing through any AUTH node.
 *
 * Uses composite visited keys (nodeId:passedAuth) so that safe paths
 * (those that DID traverse AUTH) don't prune unsafe exploration branches.
 */
function hasPathWithoutAuth(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedAuth: boolean }> = [
    { nodeId: sourceId, passedAuth: false },
  ];
  let head = 0;

  while (head < queue.length) {
    const { nodeId, passedAuth } = queue[head++];
    const key = `${nodeId}:${passedAuth}`;
    if (visited.has(key)) continue;
    visited.add(key);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    const authNow = passedAuth || node.node_type === 'AUTH';

    // Reached sink — vulnerable only if no AUTH on this path
    if (nodeId === sinkId) {
      if (!authNow) return true;
      continue;
    }

    // Follow data-flow edges
    for (const edge of node.edges) {
      if (!FLOW_EDGES.has(edge.edge_type)) continue;
      queue.push({ nodeId: edge.target, passedAuth: authNow });
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// The Property
// ---------------------------------------------------------------------------

/**
 * Missing-Auth Property
 *
 * Asserts: "No untrusted input reaches a privileged operation without
 * an authentication or authorization gate."
 */
export const missingAuth: SecurityProperty = {
  id: 'missing-auth',
  name: 'Missing Authentication/Authorization',
  assertion:
    'No untrusted input reaches a privileged operation without an authentication or authorization gate.',
  cweMapping: AUTH_CWE_MAPPINGS,

  verify(map: NeuralMap, _ctx: PropertyContext): PropertyResult {
    const violations: PropertyViolation[] = [];

    // Collect INGRESS nodes (untrusted input sources)
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');

    // Collect privileged sinks
    const privilegedSinks = map.nodes.filter(isPrivilegedSink);

    for (const source of ingressNodes) {
      for (const sink of privilegedSinks) {
        if (hasPathWithoutAuth(map, source.id, sink.id)) {
          violations.push({
            source: nodeRef(source),
            sink: nodeRef(sink),
            sinkType: sink.node_type,
            sinkSubtype: sink.node_subtype,
            missing: 'authorization',
            via: 'property_bfs',
            description: `Untrusted input from ${source.label || source.node_subtype} reaches privileged operation ${sink.label || sink.node_subtype} without authentication/authorization`,
          });
        }
      }
    }

    // Deduplicate by source-sink pair
    const seen = new Set<string>();
    const deduped: PropertyViolation[] = [];
    for (const v of violations) {
      const key = `${v.source.id}:${v.sink.id}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(v);
      }
    }

    return {
      propertyId: 'missing-auth',
      holds: deduped.length === 0,
      violations: deduped,
    };
  },
};
