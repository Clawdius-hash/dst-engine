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

  return dirty;
}
