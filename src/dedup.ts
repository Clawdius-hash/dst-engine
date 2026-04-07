
import type { VerificationResult, Finding } from './verifier';


const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};


/**
 * Extract the top-level category from a `missing` field.
 *
 * Examples:
 *   "CONTROL (input validation or parameterized query)" → "CONTROL"
 *   "TRANSFORM (encryption before storage)"             → "TRANSFORM"
 *   "AUTH (authentication check before sensitive op)"    → "AUTH"
 *   "META (external secret reference)"                  → "META"
 *   "RESOURCE (release/close on all code paths)"        → "RESOURCE"
 *   "EFFECTIVE_CONTROL (the control is vulnerable)"     → "EFFECTIVE_CONTROL"
 */
export function extractMissingCategory(missing: string): string {
  const match = missing.match(/^(\w+)/);
  return match ? match[1] : 'UNKNOWN';
}


function dedupKey(finding: Finding, cwe: string): string {
  const category = extractMissingCategory(finding.missing);
  return `${cwe}::${finding.source.id}::${finding.sink.id}::${category}`;
}


function cweNumber(cwe: string): number {
  const match = cwe.match(/\d+/);
  return match ? parseInt(match[0], 10) : Infinity;
}


export interface DedupStats {
  before: number;
  after: number;
  groupsCollapsed: number;
}

/**
 * Deduplicate verification results by (CWE, source, sink, missingCategory).
 *
 * Algorithm:
 * 1. Collect all findings from all VerificationResults where holds === false
 * 2. Exclude EFFECTIVE_CONTROL findings from dedup (different finding class)
 * 3. Group by dedupKey: CWE :: source.id :: sink.id :: missingCategory
 * 4. Within each group (same CWE only), keep highest severity
 * 5. Remove duplicate findings within the same CWE
 *
 * Different CWEs are NEVER collapsed — each CWE represents a distinct
 * vulnerability type that must be independently reportable.
 *
 * Returns a new array of VerificationResults. Does not mutate the input.
 */
export function deduplicateResults(results: VerificationResult[]): { results: VerificationResult[]; stats: DedupStats } {
  const out: VerificationResult[] = results.map(r => ({
    cwe: r.cwe,
    name: r.name,
    holds: r.holds,
    findings: r.findings.map(f => ({ ...f })),
  }));

  interface TaggedFinding {
    cwe: string;
    cweName: string;
    finding: Finding;
    resultIndex: number;
    findingIndex: number;
  }

  const tagged: TaggedFinding[] = [];
  for (let ri = 0; ri < out.length; ri++) {
    const r = out[ri];
    if (r.holds) continue;
    for (let fi = 0; fi < r.findings.length; fi++) {
      const f = r.findings[fi];
      if (extractMissingCategory(f.missing) === 'EFFECTIVE_CONTROL') continue;
      tagged.push({
        cwe: r.cwe,
        cweName: r.name,
        finding: f,
        resultIndex: ri,
        findingIndex: fi,
      });
    }
  }

  const beforeCount = tagged.length;

  const groups = new Map<string, TaggedFinding[]>();
  for (const t of tagged) {
    const key = dedupKey(t.finding, t.cwe);
    let group = groups.get(key);
    if (!group) {
      group = [];
      groups.set(key, group);
    }
    group.push(t);
  }

  const collapsedCWEsSet = new Set<string>();
  let groupsCollapsed = 0;

  const removals = new Set<string>();
  const winnerCollapsed = new Map<string, string[]>();

  for (const [_key, group] of groups) {
    if (group.length <= 1) continue;

    groupsCollapsed++;

    group.sort((a, b) => {
      const sevDiff = (SEVERITY_RANK[b.finding.severity] ?? 0) - (SEVERITY_RANK[a.finding.severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return cweNumber(a.cwe) - cweNumber(b.cwe);
    });

    const winner = group[0];
    const winnerKey = `${winner.resultIndex}:${winner.findingIndex}`;
    const collapsedCwes: string[] = [];

    for (let i = 1; i < group.length; i++) {
      const loser = group[i];
      collapsedCwes.push(loser.cwe);
      collapsedCWEsSet.add(loser.cwe);
      removals.add(`${loser.resultIndex}:${loser.findingIndex}`);
    }

    collapsedCwes.sort((a, b) => cweNumber(a) - cweNumber(b));

    const existing = winnerCollapsed.get(winnerKey) ?? [];
    winnerCollapsed.set(winnerKey, [...existing, ...collapsedCwes]);
  }

  for (const [key, cwes] of winnerCollapsed) {
    const [ri, fi] = key.split(':').map(Number);
    const finding = out[ri].findings[fi];
    const existingCollapsed = (finding as Finding & { collapsed_cwes?: string[] }).collapsed_cwes ?? [];
    (finding as Finding & { collapsed_cwes?: string[] }).collapsed_cwes = [...existingCollapsed, ...cwes];
  }

  const removalsByResult = new Map<number, Set<number>>();
  for (const key of removals) {
    const [ri, fi] = key.split(':').map(Number);
    let s = removalsByResult.get(ri);
    if (!s) {
      s = new Set();
      removalsByResult.set(ri, s);
    }
    s.add(fi);
  }

  for (const [ri, findingIndices] of removalsByResult) {
    const r = out[ri];
    r.findings = r.findings.filter((_f, i) => !findingIndices.has(i));
    if (r.findings.length === 0) {
      r.holds = true;
    }
  }

  const afterCount = out.reduce((sum, r) => {
    if (r.holds) return sum;
    return sum + r.findings.filter(f => extractMissingCategory(f.missing) !== 'EFFECTIVE_CONTROL').length;
  }, 0);

  const effectiveControlCount = out.reduce((sum, r) => {
    if (r.holds) return sum;
    return sum + r.findings.filter(f => extractMissingCategory(f.missing) === 'EFFECTIVE_CONTROL').length;
  }, 0);

  return {
    results: out,
    stats: {
      before: beforeCount + effectiveControlCount,
      after: afterCount + effectiveControlCount,
      groupsCollapsed,
    },
  };
}


interface CWEFamily {
  parent: string;
  children: Set<string>;
  all: Set<string>;
}

const CWE_FAMILIES: CWEFamily[] = [];

function defineFamily(parent: string, childNumbers: number[]): void {
  const children = new Set(childNumbers.map(n => `CWE-${n}`));
  const all = new Set([parent, ...children]);
  CWE_FAMILIES.push({ parent, children, all });
}

defineFamily('CWE-22', [
  23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
  39, 40,
  56,
  66,
  67,
  69,
  72,
  73,
]);

defineFamily('CWE-59', [61, 62, 64, 65]);

defineFamily('CWE-79', [80, 81, 82, 83, 84, 85, 86, 87]);

defineFamily('CWE-20', [
  228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
]);

defineFamily('CWE-790', [791, 792, 793, 794, 795, 796, 797]);

const CWE_TO_FAMILY = new Map<string, CWEFamily>();
for (const fam of CWE_FAMILIES) {
  for (const cwe of fam.all) {
    CWE_TO_FAMILY.set(cwe, fam);
  }
}

/** Exported for testing */
export function getFamilyForCWE(cwe: string): CWEFamily | undefined {
  return CWE_TO_FAMILY.get(cwe);
}

/** Exported for testing */
export { CWE_FAMILIES };

/**
 * Family-level dedup stats.
 */
export interface FamilyDedupStats {
  before: number;
  after: number;
  familiesCollapsed: number;
}

/**
 * Deduplicate CWE family siblings.
 *
 * When multiple members of the same CWE family fire on the same
 * (source.id, sink.id, missingCategory) evidence, collapse them
 * under the parent (or lowest-numbered member that fired).
 *
 * Algorithm:
 * 1. Collect all failed findings with their CWE
 * 2. Group by: family :: source.id :: sink.id :: missingCategory
 * 3. Within each group, keep the parent if present, else lowest CWE number
 * 4. Suppress siblings, record them in collapsed_cwes
 *
 * CRITICAL: CWEs that are NOT in any family pass through untouched.
 * CWEs where only one family member fires also pass through untouched.
 *
 * Returns a new array. Does not mutate the input.
 */
export function familyDedup(results: VerificationResult[]): { results: VerificationResult[]; stats: FamilyDedupStats } {
  const out: VerificationResult[] = results.map(r => ({
    cwe: r.cwe,
    name: r.name,
    holds: r.holds,
    findings: r.findings.map(f => ({ ...f })),
  }));

  const beforeCount = out.filter(r => !r.holds).length;

  interface FamilyTagged {
    cwe: string;
    family: CWEFamily;
    resultIndex: number;
    findingIndex: number;
    finding: Finding;
  }

  const familyGroups = new Map<string, FamilyTagged[]>();

  for (let ri = 0; ri < out.length; ri++) {
    const r = out[ri];
    if (r.holds) continue;

    const family = CWE_TO_FAMILY.get(r.cwe);
    if (!family) continue;

    for (let fi = 0; fi < r.findings.length; fi++) {
      const f = r.findings[fi];
      if (extractMissingCategory(f.missing) === 'EFFECTIVE_CONTROL') continue;

      const category = extractMissingCategory(f.missing);
      const key = `${family.parent}::${f.source.id}::${f.sink.id}::${category}`;

      let group = familyGroups.get(key);
      if (!group) {
        group = [];
        familyGroups.set(key, group);
      }
      group.push({ cwe: r.cwe, family, resultIndex: ri, findingIndex: fi, finding: f });
    }
  }

  const removals = new Set<string>();
  const winnerCollapsedCWEs = new Map<string, string[]>();
  let familiesCollapsed = 0;

  for (const [_key, group] of familyGroups) {
    const distinctCWEs = new Set(group.map(g => g.cwe));
    if (distinctCWEs.size <= 1) continue;

    familiesCollapsed++;

    const parentCWE = group[0].family.parent;
    group.sort((a, b) => {
      if (a.cwe === parentCWE && b.cwe !== parentCWE) return -1;
      if (b.cwe === parentCWE && a.cwe !== parentCWE) return 1;
      const sevDiff = (SEVERITY_RANK[b.finding.severity] ?? 0) - (SEVERITY_RANK[a.finding.severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return cweNumber(a.cwe) - cweNumber(b.cwe);
    });

    const winner = group[0];
    const winnerKey = `${winner.resultIndex}:${winner.findingIndex}`;
    const collapsedCwes: string[] = [];

    const winnerCWE = winner.cwe;
    const suppressedCWEs = new Set<string>();

    for (let i = 1; i < group.length; i++) {
      const sibling = group[i];
      if (sibling.cwe !== winnerCWE) {
        suppressedCWEs.add(sibling.cwe);
      }
      removals.add(`${sibling.resultIndex}:${sibling.findingIndex}`);
      if (sibling.cwe !== winnerCWE && !collapsedCwes.includes(sibling.cwe)) {
        collapsedCwes.push(sibling.cwe);
      }
    }

    collapsedCwes.sort((a, b) => cweNumber(a) - cweNumber(b));

    const existing = winnerCollapsedCWEs.get(winnerKey) ?? [];
    winnerCollapsedCWEs.set(winnerKey, [...existing, ...collapsedCwes]);
  }

  for (const [key, cwes] of winnerCollapsedCWEs) {
    const [ri, fi] = key.split(':').map(Number);
    const finding = out[ri].findings[fi];
    const existingCollapsed = (finding as Finding & { collapsed_cwes?: string[] }).collapsed_cwes ?? [];
    const merged = [...existingCollapsed, ...cwes.filter(c => !existingCollapsed.includes(c))];
    merged.sort((a, b) => cweNumber(a) - cweNumber(b));
    (finding as Finding & { collapsed_cwes?: string[] }).collapsed_cwes = merged;
  }

  const removalsByResult = new Map<number, Set<number>>();
  for (const key of removals) {
    const [ri, fi] = key.split(':').map(Number);
    let s = removalsByResult.get(ri);
    if (!s) {
      s = new Set();
      removalsByResult.set(ri, s);
    }
    s.add(fi);
  }

  for (const [ri, findingIndices] of removalsByResult) {
    const r = out[ri];
    r.findings = r.findings.filter((_f, i) => !findingIndices.has(i));
    if (r.findings.length === 0) {
      r.holds = true;
    }
  }

  const afterCount = out.filter(r => !r.holds).length;

  return {
    results: out,
    stats: {
      before: beforeCount,
      after: afterCount,
      familiesCollapsed,
    },
  };
}
