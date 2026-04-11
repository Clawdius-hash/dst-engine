/**
 * Cross-file margin pass — resolves PENDING sentences using summaries from
 * imported files. Same mechanism as the intra-file sentence-resolver, but
 * fed with cross-file functionReturnTaint + functionRegistry.
 *
 * Architecture (Nate's marginalia concept):
 *   - Each file's story is a PARAGRAPH
 *   - Margins are cross-file annotations: "this imported function returns tainted data"
 *   - The margin pass RESOLVES existing sentences — it does NOT add new ones
 *   - Same reconciliation contract as intra-file resolver:
 *       ALLOWED to change: taintClass, reconciled, originalTaintClass, reconciliationReason
 *       NOT allowed to change: text, templateKey, slots, lineNumber
 *   - After margins, verifiers read the updated story. They never know the difference
 *     between intra-file resolution and cross-file resolution.
 *
 * Addressing: chapter:verse (file:function). Each imported function is resolved
 * against its specific source file's summary. No flat merge. No same-name bleed.
 *
 * Re-exports: pointers, not definitions. export { x } from './y' follows the chain
 * to the origin file. Star re-exports expand to actual names from the source
 * file's functionRegistry at resolution time.
 */

import type { NeuralMap, SemanticSentence } from './types.js';
import type { DependencyGraph, DependencyEdge } from './cross-file.js';
import { resolveSentences } from './sentence-resolver.js';

/** Summary data extracted from the mapper context for one file. */
export interface FileSummary {
  map: NeuralMap;
  functionReturnTaint: Map<string, boolean>;
  functionRegistry: Map<string, string>;
  functionSinkContext?: Map<string, Set<string>>;
}

/**
 * Topologically sort files so dependencies are processed before dependents.
 * Kahn's algorithm. Files in cycles are appended at the end — the comparator
 * (future) handles those. For now they get conservative resolution.
 *
 * Edge direction: from=importer, to=imported. We process imported (to) first.
 */
function topoSort(depGraph: DependencyGraph): string[] {
  const inDeg = new Map<string, number>();
  for (const f of depGraph.files) inDeg.set(f, 0);

  // in-degree = number of files this file imports from (its dependencies)
  for (const e of depGraph.edges) {
    inDeg.set(e.from, (inDeg.get(e.from) ?? 0) + 1);
  }

  // Start with leaf files (no imports — in-degree 0)
  const queue: string[] = [];
  for (const [f, deg] of inDeg) {
    if (deg === 0) queue.push(f);
  }

  const sorted: string[] = [];
  while (queue.length > 0) {
    const f = queue.shift()!;
    sorted.push(f);

    // When f is processed, reduce in-degree of files that import f
    // (they have one fewer unprocessed dependency)
    for (const importer of depGraph.importedBy.get(f) ?? []) {
      const newDeg = (inDeg.get(importer) ?? 1) - 1;
      inDeg.set(importer, newDeg);
      if (newDeg === 0) queue.push(importer);
    }
  }

  // Files in cycles: not reached by Kahn's. Append at end.
  // These get processed with whatever dep summaries are available.
  for (const f of depGraph.files) {
    if (!sorted.includes(f)) sorted.push(f);
  }

  return sorted;
}

/**
 * Build a filtered registry + returnTaint for ONE dependency, containing ONLY
 * the functions that were actually imported. Prevents same-name bleed across
 * unrelated dependencies (GPT-5.4 catch: flat merge is dangerous cross-file).
 */
function buildFilteredContext(
  depSummary: FileSummary,
  importedNames: string[],
): { registry: Map<string, string>; returnTaint: Map<string, boolean> } {
  // Expand star imports to actual function names from the dependency
  const resolvedNames = importedNames.includes('*')
    ? [...depSummary.functionRegistry.keys()].filter(k => !k.includes(':'))
    : importedNames;

  const registry = new Map<string, string>();
  const returnTaint = new Map<string, boolean>();

  for (const name of resolvedNames) {
    const nodeId = depSummary.functionRegistry.get(name);
    if (nodeId) {
      registry.set(name, nodeId);
      const rt = depSummary.functionReturnTaint.get(nodeId);
      if (rt !== undefined) returnTaint.set(nodeId, rt);
    }
  }

  return { registry, returnTaint };
}

/**
 * Follow re-export pointer chains. If file B does `export { x } from './a'`,
 * resolve x's summary from file A, not file B. Walks the chain until it finds
 * the origin file that actually defines the function.
 *
 * Returns the FileSummary of the ORIGIN file, or null if chain can't resolve.
 */
function resolveReExportChain(
  depFilePath: string,
  functionName: string,
  fileSummaries: Map<string, FileSummary>,
  depGraph: DependencyGraph,
  visited: Set<string> = new Set(),
): FileSummary | null {
  if (visited.has(depFilePath)) return null; // cycle guard
  visited.add(depFilePath);

  const depSummary = fileSummaries.get(depFilePath);
  if (!depSummary) return null;

  // If this file defines the function locally, it's the origin
  if (depSummary.functionRegistry.has(functionName)) {
    return depSummary;
  }

  // Otherwise, check if this file re-exports from somewhere else
  const depEdges = depGraph.edges.filter(e => e.from === depFilePath);
  for (const edge of depEdges) {
    if (!edge.importInfo.isReExport) continue;
    const names = edge.importInfo.importedNames;
    if (names.includes(functionName) || names.includes('*')) {
      const resolved = edge.importInfo.resolvedPath;
      if (resolved) {
        return resolveReExportChain(resolved, functionName, fileSummaries, depGraph, visited);
      }
    }
  }

  return null;
}

/**
 * Run the cross-file margin pass. For each file that imports functions from
 * other files, resolve PENDING sentences using the source file's summary.
 *
 * Returns the set of file paths whose sentences changed (dirty files that
 * need re-verification).
 */
export function runMarginPass(
  fileSummaries: Map<string, FileSummary>,
  depGraph: DependencyGraph,
): Set<string> {
  const dirty = new Set<string>();
  const order = topoSort(depGraph);

  for (const file of order) {
    const summary = fileSummaries.get(file);
    if (!summary?.map.story || summary.map.story.length === 0) continue;

    // Get edges where this file is the importer
    const importEdges = depGraph.edges.filter(e => e.from === file);
    if (importEdges.length === 0) continue;

    // Count PENDING unreconciled sentences before resolution
    const pendingBefore = summary.map.story.filter(
      s => s.taintBasis === 'PENDING' && !s.reconciled
    ).length;

    for (const edge of importEdges) {
      const importedNames = edge.importInfo.importedNames;
      const depPath = edge.importInfo.resolvedPath ?? edge.to;
      let depSummary = fileSummaries.get(depPath);

      // Follow re-export chains: if dep doesn't define the function,
      // trace through re-exports to find the origin file
      if (depSummary && edge.importInfo.isReExport) {
        for (const name of importedNames) {
          if (name === '*') continue; // star re-exports handled in buildFilteredContext
          const origin = resolveReExportChain(depPath, name, fileSummaries, depGraph);
          if (origin) depSummary = origin;
        }
      }

      if (!depSummary) continue;

      const { registry, returnTaint } = buildFilteredContext(depSummary, importedNames);
      if (registry.size === 0) continue;

      // Resolve PENDING sentences using the cross-file summary.
      // Same function as intra-file resolution — different data source.
      // nodeById is empty: dep's nodes don't exist in this file's map.
      // The primary slot-based matching doesn't need nodeById.
      // The fallback (nodeById snapshot) gracefully skips (node not found → continue).
      resolveSentences({
        sentences: summary.map.story,
        functionReturnTaint: returnTaint,
        functionRegistry: registry,
        nodeById: new Map(),
      });
    }

    // Check if any sentences changed
    const pendingAfter = summary.map.story.filter(
      s => s.taintBasis === 'PENDING' && !s.reconciled
    ).length;

    if (pendingAfter < pendingBefore) {
      dirty.add(file);
    }
  }

  // ── PARAMETER TAINT PROPAGATION ──────────────────────────────
  // Second pass: for each import edge, if caller passes tainted args to an
  // imported function, mark the function's contained nodes in the callee file
  // as receiving tainted input.  This closes the gap where a callee file has
  // no INGRESS of its own — e.g. Ghost CMS slugFilterOrder receives tainted
  // filter via cross-file call but the callee map never knew about it.
  //
  // V1 over-approximation: if ANY argument at the call-site is tainted, ALL
  // sink/transform nodes inside the callee function are marked tainted.
  for (const file of order) {
    const summary = fileSummaries.get(file);
    if (!summary) continue;

    const importEdges = depGraph.edges.filter(e => e.from === file);

    for (const edge of importEdges) {
      const importedNames = edge.importInfo.importedNames;
      const depPath = edge.importInfo.resolvedPath ?? edge.to;
      const depSummary = fileSummaries.get(depPath);
      if (!depSummary) continue;

      // Expand star imports to actual function names from the callee's registry
      // (CommonJS require() resolves as ['*'] — expand to real function names)
      const resolvedNames = importedNames.includes('*')
        ? [...(depSummary.functionRegistry.keys())].filter(k => !k.includes(':'))
        : importedNames;

      for (const funcName of resolvedNames) {

        // Find call-sites in the CALLER's map that invoke this function
        const callSites = summary.map.nodes.filter(n =>
          (n.code_snapshot || '').includes(funcName + '(') ||
          (n.analysis_snapshot || '').includes(funcName + '(')
        );

        // Check if any call-site has tainted input
        let hasTaintedArgs = callSites.some(cs =>
          cs.data_in?.some(d => d.tainted) ||
          cs.data_out?.some(d => d.tainted)
        );

        // FALLBACK: if call-site nodes exist but none have tainted data_in/out,
        // OR if no call-site node was found at all, check the raw source code.
        // The taint may be in a scope variable (e.g., frame is tainted) but not
        // yet on the node's data_in (the call is a sub-expression).
        // If the source contains the call AND the file has tainted INGRESS
        // nodes, conservatively treat the call as having tainted arguments.
        if (!hasTaintedArgs) {
          const sourceHasCall = (summary.map.source_code || '').includes(funcName + '(');
          const fileHasTaint = summary.map.nodes.some(n =>
            n.node_type === 'INGRESS' && n.data_out?.some(d => d.tainted)
          );
          if (sourceHasCall && fileHasTaint) {
            hasTaintedArgs = true;
          }
        }

        if (!hasTaintedArgs) continue;

        // Find the function declaration in the CALLEE's map
        const funcNodeId = depSummary.functionRegistry.get(funcName);
        if (!funcNodeId) continue;

        const funcNode = depSummary.map.nodes.find(n => n.id === funcNodeId);
        if (!funcNode) continue;

        // Mark nodes in the callee's map that are contained by this function
        // and receive data, as having tainted input
        let propagated = false;
        for (const node of depSummary.map.nodes) {
          // Skip the function declaration itself
          if (node.id === funcNodeId) continue;

          // Check if this node is "inside" the function:
          // either via CONTAINS edge or by line range
          const isContained = funcNode.edges.some(e =>
            e.edge_type === 'CONTAINS' && e.target === node.id
          ) || (
            node.line_start >= funcNode.line_start &&
            node.line_end <= funcNode.line_end
          );

          if (!isContained) continue;

          // STORAGE, EXTERNAL, EGRESS — mark data_in as tainted
          if (
            node.node_type === 'STORAGE' ||
            node.node_type === 'EXTERNAL' ||
            node.node_type === 'EGRESS'
          ) {
            if (node.data_in.length > 0) {
              for (const d of node.data_in) {
                if (!d.tainted) {
                  d.tainted = true;
                  propagated = true;
                }
              }
            } else {
              node.data_in.push({
                name: `cross_file_param_taint_via_${funcName}`,
                source: 'EXTERNAL',
                data_type: 'unknown',
                tainted: true,
                sensitivity: 'NONE',
              });
              propagated = true;
            }
          }

          // TRANSFORM nodes that process parameters — mark data_in as tainted
          if (node.node_type === 'TRANSFORM') {
            if (node.data_in.length > 0) {
              for (const d of node.data_in) {
                if (!d.tainted) {
                  d.tainted = true;
                  propagated = true;
                }
              }
            } else {
              // No data_in yet — add synthetic tainted entry
              node.data_in.push({
                name: `cross_file_param_taint_via_${funcName}`,
                source: 'EXTERNAL',
                data_type: 'unknown',
                tainted: true,
                sensitivity: 'NONE',
              });
              propagated = true;
            }
          }
        }

        if (propagated) {
          dirty.add(depPath);
        }
      }
    }
  }

  // ── PASS 3: SINK-CONTEXT CATALOGING ─────────────────────────────
  // For each file (reverse topo order — sinks before callers), find which
  // functions contain dangerous sink nodes (STORAGE, EXTERNAL, EGRESS).
  // Tag each function with the set of sink subtypes it contains.
  // Then propagate sink context backward through import edges so that
  // importers inherit the sink context of the functions they import.
  const backwardOrder = [...order].reverse();

  for (const file of backwardOrder) {
    const summary = fileSummaries.get(file);
    if (!summary) continue;

    // ── Step 3.1–3.2: Per-file sink cataloging ──────────────────
    const sinkNodes = summary.map.nodes.filter(n =>
      n.node_type === 'STORAGE' ||
      n.node_type === 'EXTERNAL' ||
      n.node_type === 'EGRESS'
    );

    if (sinkNodes.length > 0) {
      // Initialize functionSinkContext if needed
      if (!summary.functionSinkContext) {
        summary.functionSinkContext = new Map();
      }

      // Check each function in the registry
      for (const [, funcNodeId] of summary.functionRegistry) {
        const funcNode = summary.map.nodes.find(n => n.id === funcNodeId);
        if (!funcNode) continue;

        for (const sink of sinkNodes) {
          // Skip the function node itself
          if (sink.id === funcNodeId) continue;

          // Check containment: CONTAINS edge or line range
          const isContained = funcNode.edges.some(e =>
            e.edge_type === 'CONTAINS' && e.target === sink.id
          ) || (
            funcNode.line_end > 0 &&
            sink.line_start >= funcNode.line_start &&
            sink.line_end <= funcNode.line_end
          );

          if (!isContained) continue;

          // Tag this function with the sink's subtype
          let subtypes = summary.functionSinkContext.get(funcNodeId);
          if (!subtypes) {
            subtypes = new Set<string>();
            summary.functionSinkContext.set(funcNodeId, subtypes);
          }
          if (sink.node_subtype) {
            subtypes.add(sink.node_subtype);
          }
        }
      }
    }

    // ── Step 3.3: Backward propagation through import edges ─────
    // Who imports this file? For each importer, propagate this file's
    // functionSinkContext entries to the importer's functionSinkContext,
    // keyed by the import's local name.
    const importers = depGraph.importedBy.get(file);
    if (!importers || !summary.functionSinkContext || summary.functionSinkContext.size === 0) continue;

    for (const importer of importers) {
      const importerSummary = fileSummaries.get(importer);
      if (!importerSummary) continue;

      // Find edges from importer to this file
      const edges = depGraph.edges.filter(e => e.from === importer && e.to === file);

      for (const edge of edges) {
        const importedNames = edge.importInfo.importedNames;

        // Expand star imports to actual function names (filter out namespaced entries)
        const resolvedNames = importedNames.includes('*')
          ? [...summary.functionRegistry.keys()].filter(k => !k.includes(':'))
          : importedNames;

        for (const name of resolvedNames) {
          // Look up nodeId in this file's functionRegistry
          const funcNodeId = summary.functionRegistry.get(name);
          if (!funcNodeId) continue;

          // Check if this function has sink context
          const sinkSubtypes = summary.functionSinkContext.get(funcNodeId);
          if (!sinkSubtypes || sinkSubtypes.size === 0) continue;

          // Propagate to importer's functionSinkContext
          if (!importerSummary.functionSinkContext) {
            importerSummary.functionSinkContext = new Map();
          }

          const localName = edge.importInfo.localName || name;
          // Use the localName as a synthetic key for the importer
          let importerSubtypes = importerSummary.functionSinkContext.get(localName);
          if (!importerSubtypes) {
            importerSubtypes = new Set<string>();
            importerSummary.functionSinkContext.set(localName, importerSubtypes);
          }
          // Merge sink subtypes (union, not overwrite)
          for (const subtype of sinkSubtypes) {
            importerSubtypes.add(subtype);
          }
        }
      }
    }
  }

  return dirty;
}
