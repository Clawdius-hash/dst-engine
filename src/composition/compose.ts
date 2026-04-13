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
  const files = new Set(links.map(l => l.finding.file));
  return Math.max(0, files.size - 1);
}

// ── Chain type classification ────────────────────────────────────────────────

function classifyChainType(links: ChainLink[]): string {
  const bridges = links.map(l => l.bridgeType).filter(b => b !== 'same_node');
  if (bridges.length === 0) return 'same_node';
  // Use the most specific bridge type
  const uniqueBridges = [...new Set(bridges)];
  return uniqueBridges.length === 1 ? uniqueBridges[0] : 'multi_bridge';
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
