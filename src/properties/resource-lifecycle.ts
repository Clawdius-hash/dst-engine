/**
 * Property Engine — Resource-Lifecycle Property
 *
 * Assertion: "Every acquired resource (file handle, database connection, socket)
 * is released on all exit paths."
 *
 * This is the TYPESTATE foundation. Simple version:
 * 1. Find all RESOURCE nodes and STORAGE nodes with acquisition subtypes
 * 2. For each, find the containing function (via CONTAINS edges going upward)
 * 3. Within that function's scope, check if a corresponding close/release operation exists
 * 4. If not, flag a violation
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
 * Subtypes that represent resource acquisition — finding these nodes triggers
 * the lifecycle check.
 */
const ACQUISITION_SUBTYPES: ReadonlySet<string> = new Set([
  'file_read', 'file_write', 'db_connect',
  'socket_read', 'socket_write', 'lock_acquire',
]);

/**
 * Pattern matching labels, code_snapshot, or analysis_snapshot of nodes within
 * the same function scope. If any sibling node matches, the resource is
 * considered properly released.
 */
const RELEASE_PATTERN = /\b(close|release|disconnect|destroy|dispose|unlock|end|finish|free)\b/i;

// ---------------------------------------------------------------------------
// CWE Mappings
// ---------------------------------------------------------------------------

const LIFECYCLE_CWE_MAPPINGS: CWEMapping[] = [
  {
    cwe: 'CWE-401',
    name: 'Missing Release of Memory after Effective Lifetime',
    when: { missing: 'lifecycle' },
    severity: 'medium',
  },
  {
    cwe: 'CWE-404',
    name: 'Improper Resource Shutdown or Release',
    when: { missing: 'lifecycle' },
    severity: 'medium',
  },
  {
    cwe: 'CWE-772',
    name: 'Missing Release of Resource after Effective Lifetime',
    when: { missing: 'lifecycle' },
    severity: 'medium',
  },
  {
    cwe: 'CWE-775',
    name: 'Missing Release of File Descriptor',
    when: { sinkSubtype: ['file_read', 'file_write'], missing: 'lifecycle' },
    severity: 'medium',
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
 * Find the nearest containing function for a given node.
 *
 * Walks all STRUCTURAL nodes looking for one that has a CONTAINS edge
 * (directly or transitively) targeting the given nodeId. Returns the
 * most specific (innermost) containing function.
 */
function findContainingFunction(
  map: NeuralMap,
  nodeId: string,
): NeuralMapNode | null {
  // Build a reverse map: child -> list of parent STRUCTURAL nodes
  // Then find the innermost function parent.
  let bestFunc: NeuralMapNode | null = null;

  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL') continue;
    // Check if this structural node directly CONTAINS the target
    if (node.edges.some(e => e.edge_type === 'CONTAINS' && e.target === nodeId)) {
      // This is a direct parent — prefer it as the innermost function
      bestFunc = node;
    }
  }

  return bestFunc;
}

/**
 * Find all nodes contained by a function (via CONTAINS edges, BFS).
 * Returns the set of contained node IDs.
 */
function findNodesInFunction(
  map: NeuralMap,
  funcNode: NeuralMapNode,
): NeuralMapNode[] {
  const contained = new Set<string>();
  const queue = [funcNode.id];

  while (queue.length > 0) {
    const id = queue.shift()!;
    const node = map.nodes.find(n => n.id === id);
    if (!node) continue;

    for (const edge of node.edges) {
      if (edge.edge_type === 'CONTAINS' && !contained.has(edge.target)) {
        contained.add(edge.target);
        queue.push(edge.target);
      }
    }
  }

  return map.nodes.filter(n => contained.has(n.id));
}

/**
 * Check whether any node in the given set has a label, code_snapshot,
 * or analysis_snapshot matching the release pattern.
 */
function hasReleaseInScope(siblings: NeuralMapNode[]): boolean {
  for (const node of siblings) {
    if (RELEASE_PATTERN.test(node.label)) return true;
    if (node.code_snapshot && RELEASE_PATTERN.test(node.code_snapshot)) return true;
    if (node.analysis_snapshot && RELEASE_PATTERN.test(node.analysis_snapshot)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// The Property
// ---------------------------------------------------------------------------

export const resourceLifecycle: SecurityProperty = {
  id: 'resource-lifecycle',
  name: 'Resource Lifecycle',
  assertion: 'Every acquired resource (file handle, database connection, socket) is released on all exit paths.',
  cweMapping: LIFECYCLE_CWE_MAPPINGS,

  verify(map: NeuralMap, _ctx: PropertyContext): PropertyResult {
    const violations: PropertyViolation[] = [];

    // Find all nodes with acquisition subtypes (RESOURCE or STORAGE)
    const acquisitionNodes = map.nodes.filter(
      n => (n.node_type === 'RESOURCE' || n.node_type === 'STORAGE') &&
           ACQUISITION_SUBTYPES.has(n.node_subtype),
    );

    for (const acqNode of acquisitionNodes) {
      // Find the containing function
      const funcNode = findContainingFunction(map, acqNode.id);
      if (!funcNode) {
        // No containing function — can't verify lifecycle, skip
        continue;
      }

      // Find all nodes within the function's scope
      const scopeNodes = findNodesInFunction(map, funcNode);

      // Check if any node in scope represents a release operation
      if (!hasReleaseInScope(scopeNodes)) {
        violations.push({
          source: nodeRef(acqNode),
          sink: nodeRef(acqNode),
          sinkType: acqNode.node_type,
          sinkSubtype: acqNode.node_subtype,
          missing: 'lifecycle',
          via: 'property_structural',
          description: `Resource acquired (${acqNode.node_subtype}) in ${funcNode.label || 'anonymous function'} without corresponding release/close operation`,
        });
      }
    }

    return {
      propertyId: 'resource-lifecycle',
      holds: violations.length === 0,
      violations,
    };
  },
};
