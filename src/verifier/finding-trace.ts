/**
 * Debug twin of hasPathWithoutGate — same BFS, full diagnostic output.
 *
 * When a finding is wrong (FP or FN), tracePath shows exactly what the BFS
 * explored: the path it found (or didn't), every gate it evaluated and why
 * it counted (or didn't), every dead end, and the final verdict.
 *
 * Pure function. No side effects, no logging, no I/O.
 */

import type { NeuralMap, NeuralMapNode, NodeType, EdgeType } from '../types.js';
import type { Finding } from './types.js';

// -------------------------------------------------------------------------
// Public types
// -------------------------------------------------------------------------

export interface TracedNode {
  id: string;
  node_type: string;
  node_subtype: string;
  label: string;
  line: number;
}

export interface GateEvaluation {
  node: TracedNode;
  effective: boolean;
  reason: string;
}

export interface PathTrace {
  /** The actual path found (source to sink), or null if no path */
  path: TracedNode[] | null;
  /** Every gate node encountered during BFS and why it did/didn't block */
  gates_evaluated: GateEvaluation[];
  /** Nodes where BFS had no outgoing flow edges (graph discontinuities) */
  dead_ends: TracedNode[];
  /** Total nodes visited during BFS */
  nodes_visited: number;
  /** Did BFS reach the sink? */
  reached_sink: boolean;
  /** Final verdict */
  verdict: 'VULNERABLE' | 'GATED' | 'NO_PATH';
}

// -------------------------------------------------------------------------
// Internals — must match _helpers.ts exactly
// -------------------------------------------------------------------------

const FLOW_EDGE_TYPES: ReadonlySet<EdgeType> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);

function toTracedNode(n: NeuralMapNode): TracedNode {
  return {
    id: n.id,
    node_type: n.node_type,
    node_subtype: n.node_subtype,
    label: n.label,
    line: n.line_start,
  };
}

// -------------------------------------------------------------------------
// tracePath — the diagnostic BFS
// -------------------------------------------------------------------------

export function tracePath(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
  gateType: NodeType | NodeType[],
): PathTrace {
  const gateSet: ReadonlySet<NodeType> = Array.isArray(gateType)
    ? new Set(gateType)
    : new Set([gateType]);

  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  // BFS state — composite visited key matches _helpers.ts
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedGate: boolean }> = [
    { nodeId: sourceId, passedGate: false },
  ];
  let head = 0;

  // Parent pointers for path reconstruction: visitKey -> parent visitKey
  const parent = new Map<string, string | null>();
  parent.set(`${sourceId}:false`, null);

  // Diagnostic accumulators
  const gatesEvaluated: GateEvaluation[] = [];
  const deadEnds: TracedNode[] = [];
  let reachedSink = false;
  let vulnerableSinkKey: string | null = null; // the visitKey that hit sink ungated
  let gatedSinkKey: string | null = null;      // first gated arrival at sink (for path if no vuln)

  while (head < queue.length) {
    const { nodeId, passedGate } = queue[head++];
    const visitKey = `${nodeId}:${passedGate}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    // Gate evaluation — mirrors _helpers.ts exactly
    const isGateType = gateSet.has(node.node_type);
    const isEffectiveGate = isGateType &&
      (node.data_in?.some(d => d.tainted || d.sensitivity !== 'NONE') ?? false);

    if (isGateType) {
      const reason = isEffectiveGate
        ? 'has tainted/sensitive data_in'
        : 'no tainted data_in';
      gatesEvaluated.push({
        node: toTracedNode(node),
        effective: isEffectiveGate,
        reason,
      });
    }

    const gateNow = passedGate || isEffectiveGate;

    // Sink check
    if (nodeId === sinkId) {
      reachedSink = true;
      if (!gateNow) {
        vulnerableSinkKey = visitKey;
        break; // same short-circuit as _helpers.ts: first ungated arrival wins
      }
      if (!gatedSinkKey) gatedSinkKey = visitKey;
      continue;
    }

    // Expand neighbors — flow edges only
    let hasFlowEdge = false;
    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      hasFlowEdge = true;
      const edgeKey = `${edge.target}:${gateNow}`;
      if (!visited.has(edgeKey)) {
        queue.push({ nodeId: edge.target, passedGate: gateNow });
        if (!parent.has(edgeKey)) {
          parent.set(edgeKey, visitKey);
        }
      }
    }

    if (!hasFlowEdge && nodeId !== sourceId) {
      deadEnds.push(toTracedNode(node));
    }
  }

  // Reconstruct path
  let path: TracedNode[] | null = null;
  const terminalKey = vulnerableSinkKey ?? gatedSinkKey;
  if (terminalKey) {
    const chain: string[] = [];
    let cur: string | null | undefined = terminalKey;
    while (cur != null) {
      chain.push(cur);
      cur = parent.get(cur);
    }
    chain.reverse();
    path = chain.map(key => {
      const nid = key.slice(0, key.lastIndexOf(':'));
      const n = nodeMap.get(nid);
      return n ? toTracedNode(n) : { id: nid, node_type: '?', node_subtype: '?', label: '?', line: 0 };
    });
  }

  // Verdict
  let verdict: PathTrace['verdict'];
  if (vulnerableSinkKey) verdict = 'VULNERABLE';
  else if (reachedSink) verdict = 'GATED';
  else verdict = 'NO_PATH';

  return {
    path,
    gates_evaluated: gatesEvaluated,
    dead_ends: deadEnds,
    nodes_visited: visited.size,
    reached_sink: reachedSink,
    verdict,
  };
}

/**
 * Returns an honest verdict string for a finding based on its provenance.
 * For BFS findings, use tracePath() as normal.
 * For non-BFS findings, return a clear message about why the trace can't help.
 */
export function findingTraceVerdict(finding: Pick<Finding, 'via'>): string {
  switch (finding.via) {
    case 'source_line_fallback':
      return 'SOURCE_LINE_FALLBACK — finding detected by regex scan of source code, not graph traversal. BFS trace unavailable because mapper could not build the taint path.';
    case 'sink_tainted':
      return 'SINK_TAINTED — finding detected because sink node has tainted data_in entries, but no explicit graph path from source to sink exists.';
    case 'scope_taint':
      return 'SCOPE_TAINT — finding detected because tainted data and sink share a function scope, but no explicit DATA_FLOW edges connect them.';
    case 'structural':
      return 'STRUCTURAL — finding detected by structural pattern match on node properties, not taint tracking. No taint path exists to trace.';
    case 'bfs':
      return 'BFS — finding detected by graph traversal. Use tracePath() for full diagnostic.';
    default:
      return 'UNKNOWN_PROVENANCE — finding has no via tag. Legacy finding or provenance not yet wired.';
  }
}
