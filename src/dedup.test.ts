/**
 * CWE Source-Sink Dedup Tests
 *
 * Tests Layer 2 dedup: collapsing duplicate findings within the SAME CWE
 * that share (source.id, sink.id, missingCategory).
 *
 * Different CWEs are NEVER collapsed — they represent distinct vulnerability
 * types. This prevents false-negative regressions where e.g. CWE-338 (Weak
 * PRNG) was absorbed by CWE-336 (Same Seed) just because both fired on the
 * same source/sink pair.
 */

import { describe, it, expect } from 'vitest';
import { deduplicateResults, extractMissingCategory, familyDedup, getFamilyForCWE, CWE_FAMILIES } from './dedup';
import type { VerificationResult, Finding, NodeRef } from './verifier';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeNodeRef(id: string, label?: string, line?: number): NodeRef {
  return {
    id,
    label: label ?? id,
    line: line ?? 1,
    code: `// ${id}`,
  };
}

function makeFinding(opts: {
  sourceId: string;
  sinkId: string;
  missing: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}): Finding {
  return {
    source: makeNodeRef(opts.sourceId, `src_${opts.sourceId}`),
    sink: makeNodeRef(opts.sinkId, `sink_${opts.sinkId}`),
    missing: opts.missing,
    severity: opts.severity,
    description: `Finding for ${opts.missing}`,
    fix: `Fix for ${opts.missing}`,
  };
}

function makeResult(cwe: string, name: string, findings: Finding[]): VerificationResult {
  return {
    cwe,
    name,
    holds: findings.length === 0,
    findings,
  };
}

// ---------------------------------------------------------------------------
// extractMissingCategory tests
// ---------------------------------------------------------------------------

describe('extractMissingCategory', () => {
  it('extracts CONTROL from typical missing string', () => {
    expect(extractMissingCategory('CONTROL (input validation or parameterized query)')).toBe('CONTROL');
  });

  it('extracts TRANSFORM', () => {
    expect(extractMissingCategory('TRANSFORM (encryption before storage)')).toBe('TRANSFORM');
  });

  it('extracts AUTH', () => {
    expect(extractMissingCategory('AUTH (authentication check before sensitive operation)')).toBe('AUTH');
  });

  it('extracts META', () => {
    expect(extractMissingCategory('META (external secret reference)')).toBe('META');
  });

  it('extracts RESOURCE', () => {
    expect(extractMissingCategory('RESOURCE (release/close on all code paths)')).toBe('RESOURCE');
  });

  it('extracts EFFECTIVE_CONTROL', () => {
    expect(extractMissingCategory('EFFECTIVE_CONTROL (the control on this path is itself vulnerable)')).toBe('EFFECTIVE_CONTROL');
  });

  it('returns UNKNOWN for empty string', () => {
    expect(extractMissingCategory('')).toBe('UNKNOWN');
  });
});

// ---------------------------------------------------------------------------
// Core dedup behavior
// ---------------------------------------------------------------------------

describe('deduplicateResults', () => {
  it('does NOT collapse different CWEs even with same source, sink, and missing category', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error Message', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-82', 'Script in IMG Attributes', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);

    // All three CWEs are distinct — none should be collapsed
    const failed = deduped.filter(r => !r.holds);
    expect(failed.length).toBe(3);
    expect(failed.some(r => r.cwe === 'CWE-80')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-81')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-82')).toBe(true);
  });

  it('collapses duplicate findings within the SAME CWE on same source/sink', () => {
    // CWE-89 fires twice on the same source/sink (e.g., two traversal paths)
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (different path)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const cwe89 = deduped.find(r => r.cwe === 'CWE-89')!;

    // Both findings have same source/sink/category, so one should be deduped
    // But since the missing parenthetical differs, the full missing strings differ
    // and dedupKey includes the category prefix only — so same CONTROL category
    // means they collapse within the same CWE.
    expect(cwe89.holds).toBe(false);
    expect(cwe89.findings.length).toBe(1);
    expect(cwe89.findings[0].severity).toBe('critical'); // highest severity wins
  });

  it('does NOT collapse findings with different source IDs (even same CWE)', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const cwe89 = deduped.find(r => r.cwe === 'CWE-89')!;

    // Different sources — both findings survive
    expect(cwe89.findings.length).toBe(2);
  });

  it('does NOT collapse findings with different sink IDs (even same CWE)', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const cwe89 = deduped.find(r => r.cwe === 'CWE-89')!;

    // Different sinks — both findings survive
    expect(cwe89.findings.length).toBe(2);
  });

  it('does NOT collapse findings with different missing categories', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-134', 'Format String', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'TRANSFORM (format string neutralization)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    // Both survive — CONTROL vs TRANSFORM are different categories + different CWEs
    expect(failed.length).toBe(2);
  });

  it('excludes EFFECTIVE_CONTROL findings from dedup', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-79', 'XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'EFFECTIVE_CONTROL (the control on this path is itself vulnerable)', severity: 'high' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'EFFECTIVE_CONTROL (another weak control)', severity: 'medium' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);

    // EFFECTIVE_CONTROL findings are excluded from dedup entirely
    const cwe79 = deduped.find(r => r.cwe === 'CWE-79');
    expect(cwe79?.holds).toBe(false);
    expect(cwe79!.findings.length).toBe(2); // both survive
  });

  it('handles results that already hold (no findings)', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', []),
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);

    const cwe89 = deduped.find(r => r.cwe === 'CWE-89');
    expect(cwe89?.holds).toBe(true);

    const cwe80 = deduped.find(r => r.cwe === 'CWE-80');
    expect(cwe80?.holds).toBe(false);
  });

  it('is deterministic — same input produces same output', () => {
    const makeInput = (): VerificationResult[] => [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (alternative path)', severity: 'high' }),
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'high' }),
      ]),
    ];

    const run1 = deduplicateResults(makeInput());
    const run2 = deduplicateResults(makeInput());

    // Same results
    const failed1 = run1.results.filter(r => !r.holds);
    const failed2 = run2.results.filter(r => !r.holds);
    expect(failed1.length).toBe(failed2.length);
    expect(failed1[0].cwe).toBe(failed2[0].cwe);
    expect(failed1[0].findings.length).toBe(failed2[0].findings.length);
  });

  it('does not mutate the input array', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (alternative path)', severity: 'high' }),
      ]),
    ];

    // Snapshot before
    const findingsLenBefore = results[0].findings.length;

    deduplicateResults(results);

    // Input should be unchanged
    expect(results[0].findings.length).toBe(findingsLenBefore);
  });

  it('handles empty results', () => {
    const { results: deduped, stats } = deduplicateResults([]);
    expect(deduped).toEqual([]);
    expect(stats.before).toBe(0);
    expect(stats.after).toBe(0);
  });

  it('handles results with no failures', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', []),
      makeResult('CWE-80', 'Basic XSS', []),
    ];

    const { results: deduped, stats } = deduplicateResults(results);
    expect(deduped.every(r => r.holds)).toBe(true);
    expect(stats.before).toBe(0);
    expect(stats.after).toBe(0);
  });

  it('preserves all CWEs independently even in large families', () => {
    const cwes = ['CWE-23', 'CWE-24', 'CWE-25', 'CWE-26', 'CWE-27', 'CWE-28', 'CWE-29', 'CWE-30'];
    const results: VerificationResult[] = cwes.map(cwe =>
      makeResult(cwe, `Path Traversal variant ${cwe}`, [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ])
    );

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    // All 8 CWEs survive independently — no cross-CWE collapse
    expect(failed.length).toBe(8);
  });

  it('handles multiple distinct source-sink groups independently', () => {
    const results: VerificationResult[] = [
      // Group 1: SRC1 -> SINK1
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      // Group 2: SRC2 -> SINK2
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
      ]),
      makeResult('CWE-564', 'SQL Injection Hibernate', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    // All 4 CWEs survive — no cross-CWE collapse
    expect(failed.length).toBe(4);
    expect(failed.some(r => r.cwe === 'CWE-80')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-81')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-89')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-564')).toBe(true);
  });

  it('handles a CWE with multiple findings across different groups', () => {
    // CWE-80 fires on two different source-sink pairs
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const cwe80 = deduped.find(r => r.cwe === 'CWE-80')!;

    // Both findings survive — different source-sink pairs
    expect(cwe80.holds).toBe(false);
    expect(cwe80.findings.length).toBe(2);
  });

  it('AUTH vs CONTROL findings on same source-sink are NOT collapsed', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-306', 'Missing Authentication', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'AUTH (authentication required)', severity: 'critical' }),
      ]),
      makeResult('CWE-862', 'Missing Authorization', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (authorization check)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(2); // Different CWEs AND different categories
  });

  it('collapses within-CWE duplicates and preserves collapsed_cwes', () => {
    // Same CWE has duplicate finding on same source/sink
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (prepared statement)', severity: 'high' }),
      ]),
    ];

    const { results: deduped, stats } = deduplicateResults(results);
    const cwe89 = deduped.find(r => r.cwe === 'CWE-89')!;

    // Within-CWE dedup: both CONTROL category on same source/sink → collapse
    expect(cwe89.findings.length).toBe(1);
    expect(cwe89.findings[0].severity).toBe('critical'); // highest severity wins
    expect(stats.groupsCollapsed).toBeGreaterThanOrEqual(1);
  });
});

// ===========================================================================
// LAYER 3 — CWE Family Dedup Tests
// ===========================================================================

describe('CWE Family Definitions', () => {
  it('defines path traversal family with CWE-22 as parent', () => {
    const family = getFamilyForCWE('CWE-22');
    expect(family).toBeDefined();
    expect(family!.parent).toBe('CWE-22');
    expect(family!.all.has('CWE-23')).toBe(true);
    expect(family!.all.has('CWE-38')).toBe(true);
  });

  it('defines XSS family with CWE-79 as parent', () => {
    const family = getFamilyForCWE('CWE-79');
    expect(family).toBeDefined();
    expect(family!.parent).toBe('CWE-79');
    expect(family!.all.has('CWE-80')).toBe(true);
    expect(family!.all.has('CWE-87')).toBe(true);
  });

  it('defines input handling family with CWE-20 as parent', () => {
    const family = getFamilyForCWE('CWE-20');
    expect(family).toBeDefined();
    expect(family!.parent).toBe('CWE-20');
    expect(family!.all.has('CWE-233')).toBe(true);
  });

  it('defines filtering family with CWE-790 as parent', () => {
    const family = getFamilyForCWE('CWE-790');
    expect(family).toBeDefined();
    expect(family!.parent).toBe('CWE-790');
    expect(family!.all.has('CWE-797')).toBe(true);
  });

  it('defines link following family with CWE-59 as parent', () => {
    const family = getFamilyForCWE('CWE-59');
    expect(family).toBeDefined();
    expect(family!.parent).toBe('CWE-59');
    expect(family!.all.has('CWE-61')).toBe(true);
    expect(family!.all.has('CWE-62')).toBe(true);
  });

  it('CWEs in the same family share the same family object', () => {
    const fam23 = getFamilyForCWE('CWE-23');
    const fam24 = getFamilyForCWE('CWE-24');
    const fam22 = getFamilyForCWE('CWE-22');
    expect(fam23).toBe(fam24);
    expect(fam23).toBe(fam22);
  });

  it('CWEs NOT in any family return undefined', () => {
    expect(getFamilyForCWE('CWE-89')).toBeUndefined();
    expect(getFamilyForCWE('CWE-502')).toBeUndefined();
    expect(getFamilyForCWE('CWE-798')).toBeUndefined();
  });
});

describe('familyDedup', () => {
  it('collapses path traversal siblings under parent CWE-22', () => {
    // Simulate: CWE-22, 23, 24, 25, 26, 27 all fire on same source/sink
    const cwes = ['CWE-22', 'CWE-23', 'CWE-24', 'CWE-25', 'CWE-26', 'CWE-27'];
    const results: VerificationResult[] = cwes.map(cwe =>
      makeResult(cwe, `Path Traversal ${cwe}`, [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ])
    );

    const { results: deduped, stats } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    // Only CWE-22 (parent) should survive
    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-22');

    // The collapsed siblings should be recorded
    const collapsed = (failed[0].findings[0] as Finding & { collapsed_cwes?: string[] }).collapsed_cwes;
    expect(collapsed).toBeDefined();
    expect(collapsed).toContain('CWE-23');
    expect(collapsed).toContain('CWE-24');
    expect(collapsed).toContain('CWE-25');
    expect(collapsed).toContain('CWE-26');
    expect(collapsed).toContain('CWE-27');

    // Stats
    expect(stats.familiesCollapsed).toBeGreaterThan(0);
    expect(stats.before).toBe(6);
    expect(stats.after).toBe(1);
  });

  it('collapses XSS siblings under parent CWE-79', () => {
    const cwes = ['CWE-79', 'CWE-80', 'CWE-81', 'CWE-82', 'CWE-83'];
    const results: VerificationResult[] = cwes.map(cwe =>
      makeResult(cwe, `XSS ${cwe}`, [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'TRANSFORM (encoding)', severity: 'high' }),
      ])
    );

    const { results: deduped } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-79');
  });

  it('keeps lowest-numbered child when parent does NOT fire', () => {
    // Only children fire, no parent CWE-22
    const results: VerificationResult[] = [
      makeResult('CWE-24', "Path Traversal: '../filedir'", [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
      makeResult('CWE-25', "Path Traversal: '/../filedir'", [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
      makeResult('CWE-26', "Path Traversal: '/dir/../filename'", [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    // CWE-24 is the lowest-numbered child that fired — it wins
    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-24');
  });

  it('does NOT collapse when only ONE family member fires', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-23', 'Relative Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    // Single family member — preserved as-is
    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-23');
  });

  it('does NOT collapse CWEs that are NOT in any family', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
      ]),
      makeResult('CWE-502', 'Deserialization', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (safe deserialization)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    // Both survive — neither is in a CWE family
    expect(failed.length).toBe(2);
    expect(failed.some(r => r.cwe === 'CWE-89')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-502')).toBe(true);
  });

  it('handles multiple families independently', () => {
    const results: VerificationResult[] = [
      // Path traversal family on SRC1/SINK1
      makeResult('CWE-22', 'Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
      makeResult('CWE-23', 'Relative Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
      // XSS family on SRC2/SINK2
      makeResult('CWE-79', 'XSS', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'TRANSFORM (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'TRANSFORM (encoding)', severity: 'high' }),
      ]),
      // Non-family CWE
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC3', sinkId: 'SINK3', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
      ]),
    ];

    const { results: deduped } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    // CWE-22 survives (path trav parent), CWE-79 survives (XSS parent), CWE-89 survives (no family)
    expect(failed.length).toBe(3);
    expect(failed.some(r => r.cwe === 'CWE-22')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-79')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-89')).toBe(true);
  });

  it('does NOT collapse family members on DIFFERENT source/sink pairs', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-22', 'Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
      makeResult('CWE-23', 'Relative Path Traversal', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    // Different evidence — both survive even though they're in the same family
    expect(failed.length).toBe(2);
  });

  it('excludes EFFECTIVE_CONTROL findings from family dedup', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-22', 'Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'EFFECTIVE_CONTROL (weak path check)', severity: 'high' }),
      ]),
      makeResult('CWE-23', 'Relative Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'EFFECTIVE_CONTROL (weak path check)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    // EFFECTIVE_CONTROL findings are excluded from family dedup — both survive
    expect(failed.length).toBe(2);
  });

  it('is deterministic — same input always produces same output', () => {
    const makeInput = (): VerificationResult[] => [
      makeResult('CWE-22', 'Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
      makeResult('CWE-23', 'Relative Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
      makeResult('CWE-24', "Path Traversal: '../filedir'", [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
    ];

    const run1 = familyDedup(makeInput());
    const run2 = familyDedup(makeInput());

    const failed1 = run1.results.filter(r => !r.holds);
    const failed2 = run2.results.filter(r => !r.holds);
    expect(failed1.length).toBe(failed2.length);
    expect(failed1[0].cwe).toBe(failed2[0].cwe);
    expect(failed1[0].findings.length).toBe(failed2[0].findings.length);
  });

  it('does not mutate the input array', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-22', 'Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
      makeResult('CWE-23', 'Relative Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
    ];

    const findingsLenBefore = results[1].findings.length;
    const holdsBefore = results[1].holds;

    familyDedup(results);

    expect(results[1].findings.length).toBe(findingsLenBefore);
    expect(results[1].holds).toBe(holdsBefore);
  });

  it('handles empty results', () => {
    const { results: deduped, stats } = familyDedup([]);
    expect(deduped).toEqual([]);
    expect(stats.before).toBe(0);
    expect(stats.after).toBe(0);
  });

  it('collapses large path traversal family (17 CWEs)', () => {
    // Simulates the real-world scenario: CWE-22..38 all fire on same evidence
    const cwes = [
      'CWE-22', 'CWE-23', 'CWE-24', 'CWE-25', 'CWE-26', 'CWE-27',
      'CWE-28', 'CWE-29', 'CWE-30', 'CWE-31', 'CWE-32', 'CWE-33',
      'CWE-34', 'CWE-35', 'CWE-36', 'CWE-37', 'CWE-38',
    ];
    const results: VerificationResult[] = cwes.map(cwe =>
      makeResult(cwe, `Path Traversal ${cwe}`, [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ])
    );

    const { results: deduped, stats } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    // Only CWE-22 survives
    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-22');

    // All 16 siblings are recorded as collapsed
    const collapsed = (failed[0].findings[0] as Finding & { collapsed_cwes?: string[] }).collapsed_cwes!;
    expect(collapsed.length).toBe(16);
    expect(collapsed).toContain('CWE-23');
    expect(collapsed).toContain('CWE-38');

    // Stats reflect the collapse
    expect(stats.before).toBe(17);
    expect(stats.after).toBe(1);
  });

  it('collapses filtering family (8 CWEs)', () => {
    const cwes = ['CWE-790', 'CWE-791', 'CWE-792', 'CWE-793', 'CWE-794', 'CWE-795', 'CWE-796', 'CWE-797'];
    const results: VerificationResult[] = cwes.map(cwe =>
      makeResult(cwe, `Filtering ${cwe}`, [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (complete filtering)', severity: 'medium' }),
      ])
    );

    const { results: deduped } = familyDedup(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-790');
  });

  it('handles family members with multiple findings on different evidence', () => {
    // CWE-22 fires on SRC1/SINK1 and SRC2/SINK2
    // CWE-23 fires on SRC1/SINK1 only
    const results: VerificationResult[] = [
      makeResult('CWE-22', 'Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
      makeResult('CWE-23', 'Relative Path Traversal', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = familyDedup(results);
    const cwe22 = deduped.find(r => r.cwe === 'CWE-22')!;
    const cwe23 = deduped.find(r => r.cwe === 'CWE-23')!;

    // CWE-22 keeps both findings (SRC1/SINK1 wins family group, SRC2/SINK2 is unchallenged)
    expect(cwe22.holds).toBe(false);
    expect(cwe22.findings.length).toBe(2);

    // CWE-23's SRC1/SINK1 finding was collapsed under CWE-22
    expect(cwe23.holds).toBe(true);
    expect(cwe23.findings.length).toBe(0);
  });
});
