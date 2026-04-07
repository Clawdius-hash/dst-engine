import type { NeuralMap, NeuralMapNode } from '../types.js';

export interface InvariantViolation {
  code: string;
  severity: 'error' | 'warning' | 'info';
  message: string;
  nodeIds?: string[];
}

/**
 * Summary statistics returned alongside violations.
 * One-line health check for developers; full violations array is for debugging.
 */
export interface InvariantSummary {
  errors: number;
  warnings: number;
  info: number;
  totalNodes: number;
  structuralLeafNodes: number;
  trueOrphanCount: number;
  nodesWithDataFlow: number;
  dataFlowEdgeCount: number;
  containersWithNoDataFlow: number;
  /** 'healthy' = 0 errors, <=2 warnings. 'degraded' = warnings. 'broken' = errors. */
  verdict: 'healthy' | 'degraded' | 'broken';
}

// ---------------------------------------------------------------------------
// Subtype classifications used by invariants to distinguish real warnings
// from expected structural patterns.
// ---------------------------------------------------------------------------

/**
 * STRUCTURAL subtypes that are containers -- they SHOULD have CONTAINS edges
 * pointing to their children. A class with no methods, a function with no
 * body statements -- those are real problems worth flagging.
 *
 * NOT included (leaf structural nodes that never have children):
 *   - 'dependency'    -- import declarations across all languages
 *   - 'module'        -- package declarations (top-level namespace, not a container)
 *   - 'file_include'  -- PHP include/require (non-tainted variant)
 */
const CONTAINER_SUBTYPES = new Set([
  'function', 'method', 'class', 'controller', 'route',
  'interface', 'enum', 'record',
]);

/**
 * STRUCTURAL subtypes that are leaf declarations -- they never have children.
 * Used by summarizeInvariants to count leaf nodes; INV-6 uses CONTAINER_SUBTYPES
 * as the positive filter instead.
 */
const LEAF_STRUCTURAL_SUBTYPES = new Set([
  'dependency',     // import declarations
  'module',         // package declarations
  'file_include',   // PHP include/require
]);

/**
 * CONTROL subtypes that are leaf flow nodes -- they terminate a branch and
 * never emit outgoing edges by design. Their parent function CONTAINS them
 * but they produce no data flow or calls.
 */
const LEAF_CONTROL_SUBTYPES = new Set([
  'return', 'break', 'continue', 'throw', 'assert',
]);

/**
 * TRANSFORM subtypes that can legitimately have zero outgoing edges.
 * An assignment node captures the fact that a store happened; the resulting
 * variable flows are tracked via scope, not via outgoing graph edges.
 */
const LEAF_TRANSFORM_SUBTYPES = new Set([
  'assignment',
]);

export function checkMapInvariants(map: NeuralMap): InvariantViolation[] {
  const violations: InvariantViolation[] = [];
  const nodeIndex = new Map<string, NeuralMapNode>(map.nodes.map(n => [n.id, n]));

  // Pre-compute the set of all node IDs that are targeted by at least one edge.
  // This lets INV-7 distinguish "truly disconnected" from "leaf node with
  // incoming CONTAINS from its parent."
  const hasIncomingEdge = new Set<string>();
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      hasIncomingEdge.add(edge.target);
    }
  }
  // Also count top-level map edges (cross-node relationships)
  for (const edge of map.edges) {
    hasIncomingEdge.add(edge.target);
  }

  // INV-1: Every node ID must be unique
  if (nodeIndex.size !== map.nodes.length) {
    const seen = new Map<string, number>();
    const dupes: string[] = [];
    for (const n of map.nodes) {
      const count = (seen.get(n.id) ?? 0) + 1;
      seen.set(n.id, count);
      if (count === 2) dupes.push(n.id);
    }
    violations.push({
      code: 'UNIQUE_IDS',
      severity: 'error',
      message: `Duplicate node IDs found: ${dupes.join(', ')}`,
      nodeIds: dupes,
    });
  }

  // INV-2: Every edge target must reference an existing node
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      if (!nodeIndex.has(edge.target)) {
        violations.push({
          code: 'EDGE_TARGET_EXISTS',
          severity: 'error',
          message: `Node "${node.id}" has edge targeting non-existent node "${edge.target}"`,
          nodeIds: [node.id],
        });
      }
    }
  }

  // INV-3: DATA_FLOW edges should have matching data_in/data_out entries
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      if (edge.edge_type !== 'DATA_FLOW') continue;
      const targetNode = nodeIndex.get(edge.target);
      if (!targetNode) continue; // Already caught by INV-2
      const hasMatchingDataIn = targetNode.data_in.some(d => d.source === node.id);
      if (!hasMatchingDataIn) {
        violations.push({
          code: 'DATA_FLOW_CONSISTENCY',
          severity: 'warning',
          message: `Node "${node.id}" has DATA_FLOW edge to "${edge.target}" but target has no data_in from source`,
          nodeIds: [node.id, edge.target],
        });
      }
    }
  }

  // INV-4: No node should be both INGRESS and CONTROL type
  // node_type is a single value, so this checks for nodes tagged in attack_surface
  // or metadata that contradict their primary type
  for (const node of map.nodes) {
    if (node.node_type === 'INGRESS' && node.tags.includes('control')) {
      violations.push({
        code: 'TYPE_CONFLICT',
        severity: 'warning',
        message: `Node "${node.id}" is INGRESS but tagged as control -- possible misclassification`,
        nodeIds: [node.id],
      });
    }
    if (node.node_type === 'CONTROL' && node.tags.includes('ingress')) {
      violations.push({
        code: 'TYPE_CONFLICT',
        severity: 'warning',
        message: `Node "${node.id}" is CONTROL but tagged as ingress -- possible misclassification`,
        nodeIds: [node.id],
      });
    }
  }

  // INV-5: CONTROL nodes should have non-empty code_snapshot
  for (const node of map.nodes) {
    if (node.node_type === 'CONTROL' && !node.code_snapshot.trim()) {
      violations.push({
        code: 'CONTROL_SNAPSHOT_EMPTY',
        severity: 'warning',
        message: `CONTROL node "${node.id}" has empty code_snapshot -- breaks evaluateControlEffectiveness`,
        nodeIds: [node.id],
      });
    }
  }

  // INV-6: STRUCTURAL container nodes should have at least one CONTAINS edge.
  // Uses a positive filter: only subtypes in CONTAINER_SUBTYPES are checked.
  // New/unknown subtypes default to "not checked" (safe) rather than
  // "checked and false positive" (noisy).
  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL') continue;
    if (!CONTAINER_SUBTYPES.has(node.node_subtype)) continue;
    const hasContains = node.edges.some(e => e.edge_type === 'CONTAINS');
    if (!hasContains) {
      violations.push({
        code: 'STRUCTURAL_MISSING_CONTAINS',
        severity: 'warning',
        message: `STRUCTURAL/${node.node_subtype} node "${node.id}" has no CONTAINS edges -- children are orphaned from scope analysis`,
        nodeIds: [node.id],
      });
    }
  }

  // INV-7: Orphan node detection -- every non-STRUCTURAL, non-META node should
  // be connected to the graph. A node is connected if it has:
  //   (a) at least one OUTGOING edge, OR
  //   (b) at least one INCOMING edge (e.g., parent CONTAINS it), OR
  //   (c) at least one data_in or data_out entry (participates in data flow)
  //
  // Leaf CONTROL nodes (return, break, continue, throw, assert) are excluded --
  // they terminate control flow by design and connect to the graph only via
  // incoming CONTAINS from their parent function.
  //
  // Leaf TRANSFORM nodes (assignment) are excluded -- they capture store
  // operations and connect via scope-tracked variables, not graph edges.
  for (const node of map.nodes) {
    if (node.node_type === 'STRUCTURAL' || node.node_type === 'META') continue;
    // Known leaf subtypes -- connected via incoming CONTAINS from parent scope.
    // Having zero outgoing edges is by design.
    if (node.node_type === 'CONTROL' && LEAF_CONTROL_SUBTYPES.has(node.node_subtype)) continue;
    if (node.node_type === 'TRANSFORM' && LEAF_TRANSFORM_SUBTYPES.has(node.node_subtype)) continue;

    const hasOutgoing = node.edges.length > 0;
    const hasIncoming = hasIncomingEdge.has(node.id);
    const hasDataFlow = node.data_in.length > 0 || node.data_out.length > 0;

    if (!hasOutgoing && !hasIncoming && !hasDataFlow) {
      violations.push({
        code: 'ORPHAN_NODE',
        severity: 'warning',
        message: `${node.node_type}/${node.node_subtype} node "${node.id}" is fully disconnected -- no edges in or out, no data flow`,
        nodeIds: [node.id],
      });
    }
  }

  // INV-8: Duplicate edge detector -- same source + target + edge_type
  // appearing more than once on the same node suggests a mapper loop or
  // missing dedup in addEdge.
  for (const node of map.nodes) {
    const edgeSigs = new Map<string, number>();
    for (const edge of node.edges) {
      const sig = `${edge.target}:${edge.edge_type}`;
      const count = (edgeSigs.get(sig) ?? 0) + 1;
      edgeSigs.set(sig, count);
      if (count === 2) {
        violations.push({
          code: 'DUPLICATE_EDGE',
          severity: 'warning',
          message: `Node "${node.id}" has duplicate ${edge.edge_type} edge to "${edge.target}"`,
          nodeIds: [node.id, edge.target],
        });
      }
    }
  }

  // INV-9: DATA_FLOW symmetry -- every data_in entry should have a
  // corresponding data_out on the source node. Asymmetry means addDataFlow
  // was called but one side got dropped, or manual data_out was pushed
  // without the corresponding data_in.
  for (const node of map.nodes) {
    for (const din of node.data_in) {
      if (!din.source || din.source === 'EXTERNAL') continue;
      const sourceNode = nodeIndex.get(din.source);
      if (!sourceNode) continue; // Dangling source -- caught by other checks
      const hasMatchingOut = sourceNode.data_out.some(
        d => d.name === din.name && d.source === din.source &&
             (d.target === node.id || d.target === undefined)
      );
      if (!hasMatchingOut) {
        violations.push({
          code: 'DATA_FLOW_ASYMMETRY',
          severity: 'warning',
          message: `Node "${node.id}" has data_in "${din.name}" from "${din.source}" but source has no matching data_out`,
          nodeIds: [node.id, din.source],
        });
      }
    }
  }

  // INV-10: INGRESS nodes should have at least one data_out entry or one
  // outgoing edge. An INGRESS with nothing flowing out means the taint
  // source was created but never wired -- the mapper dropped the flow.
  for (const node of map.nodes) {
    if (node.node_type !== 'INGRESS') continue;
    if (node.data_out.length === 0 && node.edges.length === 0) {
      violations.push({
        code: 'INGRESS_NO_OUTPUT',
        severity: 'warning',
        message: `INGRESS node "${node.id}" has no data_out and no edges -- taint source is dead`,
        nodeIds: [node.id],
      });
    }
  }

  // INV-11: STRUCTURAL containers with children but zero data flow activity.
  // When a function/class contains nodes (via CONTAINS edges) but NONE of those
  // children participate in data flow (zero data_in + data_out), the mapper saw
  // the AST structure but couldn't trace taint through it. This is an INFO-level
  // diagnostic -- it identifies mapper coverage gaps, not structural errors.
  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL') continue;
    if (!CONTAINER_SUBTYPES.has(node.node_subtype)) continue;
    const containedIds = node.edges
      .filter(e => e.edge_type === 'CONTAINS')
      .map(e => e.target);
    if (containedIds.length === 0) continue; // No children -- already caught by INV-6

    const hasAnyDataFlow = containedIds.some(childId => {
      const child = nodeIndex.get(childId);
      if (!child) return false;
      return child.data_in.length > 0 || child.data_out.length > 0;
    });

    if (!hasAnyDataFlow) {
      violations.push({
        code: 'CONTAINER_NO_DATA_FLOW',
        severity: 'info',
        message: `STRUCTURAL/${node.node_subtype} "${node.id}" contains ${containedIds.length} node(s) but none have data flow -- mapper may not trace taint through this scope`,
        nodeIds: [node.id],
      });
    }
  }

  // INV-12: STORAGE_SEMANTIC_VALIDATION -- check that STORAGE nodes don't
  // have receiver names that look like collections. A valuesList.remove()
  // classified as STORAGE/db_write is a misclassification. This is the
  // semantic layer -- checking not just graph shape but graph MEANING.
  const COLLECTION_SUFFIXES = ['List', 'Set', 'Map', 'Queue', 'Stack', 'Collection', 'Array', 'Vector', 'Deque'];
  const COLLECTION_NAMES = /^(values|entries|elements|keys|names|params|args|headers|cookies|parts|items|results|records|rows|columns|fields|buffer|temp|output)$/i;
  for (const node of map.nodes) {
    if (node.node_type !== 'STORAGE') continue;
    // Extract the receiver name from the node label (e.g., "valuesList.remove(0)" → "valuesList")
    const labelMatch = node.label.match(/^(?:[\w.]*\.)?(\w+)\.\w+\(/);
    if (!labelMatch) continue;
    const receiver = labelMatch[1]!;
    const looksLikeCollection = COLLECTION_SUFFIXES.some(s => receiver.endsWith(s))
      || COLLECTION_NAMES.test(receiver);
    if (looksLikeCollection) {
      violations.push({
        code: 'STORAGE_COLLECTION_MISCLASS',
        severity: 'error',
        message: `STORAGE/${node.node_subtype} node "${node.id}" has collection-like receiver "${receiver}" in label "${node.label}" -- likely misclassified collection operation, not a database call`,
        nodeIds: [node.id],
      });
    }
  }

  return violations;
}

/**
 * Compute a summary from invariant violations and map structure.
 * This is the one-liner a developer looks at; the full violations array
 * is for debugging specific issues.
 */
export function summarizeInvariants(
  map: NeuralMap,
  violations: InvariantViolation[],
): InvariantSummary {
  const errors = violations.filter(v => v.severity === 'error').length;
  const warnings = violations.filter(v => v.severity === 'warning').length;
  const info = violations.filter(v => v.severity === 'info').length;

  let structuralLeafNodes = 0;
  let nodesWithDataFlow = 0;
  let dataFlowEdgeCount = 0;

  for (const node of map.nodes) {
    if (node.node_type === 'STRUCTURAL' && LEAF_STRUCTURAL_SUBTYPES.has(node.node_subtype)) {
      structuralLeafNodes++;
    }
    if (node.data_in.length > 0 || node.data_out.length > 0) {
      nodesWithDataFlow++;
    }
    dataFlowEdgeCount += node.edges.filter(e => e.edge_type === 'DATA_FLOW').length;
  }

  const trueOrphanCount = violations.filter(v => v.code === 'ORPHAN_NODE').length;
  const containersWithNoDataFlow = violations.filter(v => v.code === 'CONTAINER_NO_DATA_FLOW').length;

  let verdict: 'healthy' | 'degraded' | 'broken';
  if (errors > 0) verdict = 'broken';
  else if (warnings > 2) verdict = 'degraded';
  else verdict = 'healthy';

  return {
    errors,
    warnings,
    info,
    totalNodes: map.nodes.length,
    structuralLeafNodes,
    trueOrphanCount,
    nodesWithDataFlow,
    dataFlowEdgeCount,
    containersWithNoDataFlow,
    verdict,
  };
}
