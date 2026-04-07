import type { NeuralMap, NeuralMapNode, Edge, DataFlow } from './types.js';

/**
 * Produce a deterministic JSON serialization of a NeuralMap.
 *
 * Guarantees:
 * - Nodes sorted by sequence number (stable across runs)
 * - Edges sorted by edge_type then target (stable across runs)
 * - DataFlow arrays sorted by name (stable across runs)
 * - Non-deterministic fields (created_at) are stripped
 * - Output is pretty-printed for readable diffs
 */
export function serializeNeuralMap(map: NeuralMap): string {
  const stable = {
    source_file: map.source_file,
    parser_version: map.parser_version,
    node_count: map.nodes.length,
    edge_count: map.edges.length,
    nodes: [...map.nodes]
      .sort((a, b) => a.sequence - b.sequence)
      .map(serializeNode),
    edges: sortEdges(map.edges),
  };
  return JSON.stringify(stable, null, 2);
}

function serializeNode(node: NeuralMapNode): Record<string, unknown> {
  return {
    id: node.id,
    label: node.label,
    sequence: node.sequence,
    node_type: node.node_type,
    node_subtype: node.node_subtype,
    language: node.language,
    file: node.file,
    line_start: node.line_start,
    line_end: node.line_end,
    // code_snapshot excluded from golden reference -- too brittle to whitespace changes
    data_in: sortDataFlows(node.data_in),
    data_out: sortDataFlows(node.data_out),
    edges: sortEdges(node.edges),
    attack_surface: [...node.attack_surface].sort(),
    trust_boundary: node.trust_boundary,
    tags: [...node.tags].sort(),
  };
}

function sortEdges(edges: Edge[]): Edge[] {
  return [...edges].sort((a, b) => {
    const typeCompare = a.edge_type.localeCompare(b.edge_type);
    if (typeCompare !== 0) return typeCompare;
    return a.target.localeCompare(b.target);
  });
}

function sortDataFlows(flows: DataFlow[]): DataFlow[] {
  return [...flows].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Compare two NeuralMaps structurally (ignoring non-deterministic fields like created_at).
 * Returns a match boolean and a list of human-readable differences.
 */
export function compareNeuralMaps(
  a: NeuralMap,
  b: NeuralMap
): { match: boolean; differences: string[] } {
  const diffs: string[] = [];

  // Node count
  if (a.nodes.length !== b.nodes.length) {
    diffs.push(`Node count: ${a.nodes.length} vs ${b.nodes.length}`);
  }

  // Edge count
  if (a.edges.length !== b.edges.length) {
    diffs.push(`Edge count: ${a.edges.length} vs ${b.edges.length}`);
  }

  // Node type distribution
  const aTypes = countByField(a.nodes, 'node_type');
  const bTypes = countByField(b.nodes, 'node_type');
  for (const type of new Set([...Object.keys(aTypes), ...Object.keys(bTypes)])) {
    if ((aTypes[type] ?? 0) !== (bTypes[type] ?? 0)) {
      diffs.push(`${type} nodes: ${aTypes[type] ?? 0} vs ${bTypes[type] ?? 0}`);
    }
  }

  // Edge type distribution
  const aEdgeTypes = countEdgeTypes(a);
  const bEdgeTypes = countEdgeTypes(b);
  for (const type of new Set([...Object.keys(aEdgeTypes), ...Object.keys(bEdgeTypes)])) {
    if ((aEdgeTypes[type] ?? 0) !== (bEdgeTypes[type] ?? 0)) {
      diffs.push(`${type} edges: ${aEdgeTypes[type] ?? 0} vs ${bEdgeTypes[type] ?? 0}`);
    }
  }

  // Taint count
  const aTaint = countTainted(a);
  const bTaint = countTainted(b);
  if (aTaint !== bTaint) {
    diffs.push(`Tainted flows: ${aTaint} vs ${bTaint}`);
  }

  return { match: diffs.length === 0, differences: diffs };
}

function countByField(
  nodes: NeuralMapNode[],
  field: keyof NeuralMapNode
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const node of nodes) {
    const key = String(node[field]);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

function countEdgeTypes(map: NeuralMap): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const edge of map.edges) {
    counts[edge.edge_type] = (counts[edge.edge_type] ?? 0) + 1;
  }
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      counts[edge.edge_type] = (counts[edge.edge_type] ?? 0) + 1;
    }
  }
  return counts;
}

function countTainted(map: NeuralMap): number {
  let count = 0;
  for (const node of map.nodes) {
    for (const flow of [...node.data_in, ...node.data_out]) {
      if (flow.tainted) count++;
    }
  }
  return count;
}
