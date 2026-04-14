/**
 * Composition engine — chains findings that share storage / file / env targets.
 *
 * Given a flat list of ComposableFinding items (each already tagged with its
 * file and CWE), this module discovers *cross-finding* relationships where one
 * finding's sink feeds into another finding's source through a shared external
 * resource (DB table, file path, env var, etc.) or through a same-node bridge
 * within the same file.
 */

import type { ComposableFinding, ChainLink, FindingChain } from './types.js';
import { extractStorageTarget, type ExtractedTarget } from './extract-target.js';

// ── AST metadata → ExtractedTarget normalisation ────────────────────────────
// StorageTarget (AST) uses kinds: table, collection, model, file, env, cache_key
// ExtractedTarget (regex) uses kinds: storage, file_io, env_var, config, network
// This maps AST kinds to composition-engine kinds so bridge classification works.

const AST_KIND_TO_EXTRACTED: Record<string, ExtractedTarget['kind']> = {
  table:      'storage',
  collection: 'storage',
  model:      'storage',
  file:       'file_io',
  env:        'env_var',
  cache_key:  'config',
};

function normaliseAstTarget(
  meta: { kind: string; name: string } | null | undefined,
): ExtractedTarget | null {
  if (!meta) return null;
  const mapped = AST_KIND_TO_EXTRACTED[meta.kind];
  if (!mapped) return null;          // unknown AST kind — fall through to regex
  return { kind: mapped, name: meta.name };
}

// ── Bridge classification ────────────────────────────────────────────────────

function classifyBridge(target: ExtractedTarget): ChainLink['bridgeType'] {
  return target.kind;
}

function bridgeDetailFromTarget(target: ExtractedTarget): string {
  switch (target.kind) {
    case 'storage':   return `shared storage: ${target.name}`;
    case 'file_io':   return `shared file: ${target.name}`;
    case 'env_var':   return `shared env var: ${target.name}`;
    case 'config':    return `shared config: ${target.name}`;
    case 'network':   return `shared network endpoint: ${target.name}`;
  }
}

// ── Severity escalation ─────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

const RANK_TO_SEVERITY: Array<FindingChain['severity']> = [
  'low', 'medium', 'high', 'critical',
];

function escalateSeverity(a: string, b: string): FindingChain['severity'] {
  const ra = SEVERITY_RANK[a] ?? 0;
  const rb = SEVERITY_RANK[b] ?? 0;
  // Escalate by one level above the max of the two
  const escalated = Math.min(Math.max(ra, rb) + 1, 3);
  return RANK_TO_SEVERITY[escalated];
}

// ── Deduplication key ────────────────────────────────────────────────────────

function pairKey(a: ComposableFinding, b: ComposableFinding): string {
  // Deterministic — always smaller id first
  const idA = `${a.file}:${a.finding.source.id}->${a.finding.sink.id}`;
  const idB = `${b.file}:${b.finding.source.id}->${b.finding.sink.id}`;
  return idA < idB ? `${idA}||${idB}` : `${idB}||${idA}`;
}

// ── Chain description ────────────────────────────────────────────────────────

function describeChain(links: ChainLink[]): string {
  if (links.length === 0) return '';
  const parts = links.map((l, i) => {
    const f = l.finding;
    const prefix = i === 0 ? '' : ` -> [${l.bridgeType}: ${l.bridgeDetail}] -> `;
    return `${prefix}${f.cwe} in ${f.file} (${f.finding.description})`;
  });
  return parts.join('');
}

// ── Count boundary crossings ─────────────────────────────────────────────────

function countBoundaries(links: ChainLink[]): number {
  const boundaries = new Set<string>();
  for (const link of links) {
    if (link.finding.sinkTrustBoundary) boundaries.add(link.finding.sinkTrustBoundary);
    if (link.finding.sourceTrustBoundary) boundaries.add(link.finding.sourceTrustBoundary);
  }
  // Remove empty strings (defensive — the `if` guards above should prevent them)
  boundaries.delete('');
  // N distinct trust boundaries means N-1 crossings
  return Math.max(0, boundaries.size - 1);
}

// ── Chain type classification ────────────────────────────────────────────────

function classifyChainType(links: ChainLink[]): string {
  const bridges = links.map(l => l.bridgeType).filter(b => b !== 'same_node');
  if (bridges.length === 0) return 'same_node';
  // Use the most specific bridge type
  const uniqueBridges = [...new Set(bridges)];
  return uniqueBridges.length === 1 ? uniqueBridges[0] : 'multi_bridge';
}

// ── Directionality: READ→READ suppression ───────────────────────────────────

const WRITE_SUBTYPES: ReadonlySet<string> = new Set([
  'db_write', 'file_write', 'env_write', 'cache_write',
  'state_write', 'log_write',
]);

const WRITE_NODE_TYPES: ReadonlySet<string> = new Set([
  'EGRESS', 'STORAGE',
]);

/**
 * Check if a finding's sink actually WRITES to a shared resource.
 * For a composition chain A→B through resource X to be real,
 * A's sink must WRITE to X (not just mention X in its code).
 *
 * Returns true if the node is a write operation, false if it's a read,
 * and false for undefined (backward compat: chains without semantics are allowed).
 */
function isWriteOperation(nodeType: string | undefined, nodeSubtype: string | undefined): boolean {
  if (!nodeType && !nodeSubtype) return false; // no semantics = unknown = don't filter
  if (nodeSubtype && WRITE_SUBTYPES.has(nodeSubtype)) return true;
  if (nodeType && WRITE_NODE_TYPES.has(nodeType) && nodeSubtype !== 'http_request') return true;
  return false;
}

/**
 * Check if neither side of a bridge performs a write to the bridged resource.
 * If A's sink doesn't write and B's source doesn't write, it's READ→READ.
 */
function isBothSidesReadOnly(
  fa: ComposableFinding,
  fb: ComposableFinding,
): boolean {
  // If either side lacks node semantics, be conservative (allow the chain)
  const aHasSemantics = fa.sinkNodeType !== undefined || fa.sinkNodeSubtype !== undefined;
  const bHasSemantics = fb.sourceNodeType !== undefined || fb.sourceNodeSubtype !== undefined;
  if (!aHasSemantics && !bHasSemantics) return false; // no data = don't filter

  const aWrites = isWriteOperation(fa.sinkNodeType, fa.sinkNodeSubtype);
  const bWrites = isWriteOperation(fb.sourceNodeType, fb.sourceNodeSubtype);

  // If neither side writes to the bridged resource, it's READ→READ
  return !aWrites && !bWrites;
}

// ── Public API ───────────────────────────────────────────────────────────────

export function composeFindings(findings: ComposableFinding[]): FindingChain[] {
  const chains: FindingChain[] = [];
  const seen = new Set<string>();

  // Pre-compute targets for each finding
  const sinkTargets = new Map<number, ExtractedTarget | null>();
  const sourceTargets = new Map<number, ExtractedTarget | null>();

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    // Prefer AST-derived metadata; fall back to regex extraction from code snapshot
    sinkTargets.set(
      i,
      normaliseAstTarget(f.sinkStorageTarget) ?? extractStorageTarget(f.finding.sink.code),
    );
    sourceTargets.set(
      i,
      normaliseAstTarget(f.sourceStorageTarget) ?? extractStorageTarget(f.finding.source.code),
    );
  }

  for (let a = 0; a < findings.length; a++) {
    for (let b = 0; b < findings.length; b++) {
      if (a === b) continue;

      const fa = findings[a];
      const fb = findings[b];
      const key = pairKey(fa, fb);
      if (seen.has(key)) continue;

      // 1. Storage / file / env bridge: A's sink target matches B's source target
      const aSinkTarget = sinkTargets.get(a)!;
      const bSourceTarget = sourceTargets.get(b)!;

      if (aSinkTarget && bSourceTarget && aSinkTarget.name === bSourceTarget.name && aSinkTarget.kind === bSourceTarget.kind) {
        // Directionality: suppress READ→READ chains.
        // For a chain through a shared resource to be real, one side must WRITE
        // to the resource and the other must READ. Two independent reads
        // (e.g., two files both reading process.env.NODE_ENV) are not a chain.
        if (isBothSidesReadOnly(fa, fb)) {
          continue;
        }

        seen.add(key);
        const bridgeType = classifyBridge(aSinkTarget);
        const links: ChainLink[] = [
          { finding: fa, bridgeType: 'same_node', bridgeDetail: 'origin' },
          { finding: fb, bridgeType, bridgeDetail: bridgeDetailFromTarget(aSinkTarget) },
        ];
        chains.push({
          links,
          chainType: classifyChainType(links),
          boundariesCrossed: countBoundaries(links),
          severity: escalateSeverity(fa.finding.severity, fb.finding.severity),
          description: describeChain(links),
        });
        continue;
      }

      // 2. Same-node bridge: A's sink id matches B's source id (same file)
      if (fa.file === fb.file && fa.finding.sink.id === fb.finding.source.id) {
        if (seen.has(key)) continue;
        seen.add(key);
        const links: ChainLink[] = [
          { finding: fa, bridgeType: 'same_node', bridgeDetail: 'origin' },
          { finding: fb, bridgeType: 'same_node', bridgeDetail: `shared node: ${fa.finding.sink.id}` },
        ];
        chains.push({
          links,
          chainType: 'same_node',
          boundariesCrossed: 0,
          severity: escalateSeverity(fa.finding.severity, fb.finding.severity),
          description: describeChain(links),
        });
      }
    }
  }

  return chains;
}
