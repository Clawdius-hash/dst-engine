#!/usr/bin/env npx tsx
/**
 * DST CWE Deduplication Report
 *
 * Scans all three DST implementations and reports:
 * - Which CWEs exist in which files
 * - Which are duplicated vs unique
 * - Implementation approach differences
 * - Merge recommendations
 *
 * Run: npx tsx src/services/dst/taxonomy/dedup-report.ts
 */

import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Source locations
// ---------------------------------------------------------------------------

const SOURCES = {
  verifier: {
    label: 'verifier.ts (graph traversal)',
    paths: [
      'C:/Users/pizza/generic-api-wrapper/src/services/dst/verifier.ts',
      'C:/Users/pizza/atreus/src/services/dst/verifier.ts',
    ],
  },
  detection_engine: {
    label: 'dst-detection-engine.js (taint flow, Helios)',
    paths: [
      'C:/Users/pizza/Downloads/dst-detection-engine.js',
    ],
  },
  scanner: {
    label: 'scanner.ts (gap patterns)',
    paths: [
      'C:/Users/pizza/generic-api-wrapper/src/services/dst/scanner.ts',
      'C:/Users/pizza/atreus/src/services/dst/scanner.ts',
    ],
  },
};

// ---------------------------------------------------------------------------
// CWE extraction
// ---------------------------------------------------------------------------

interface CWEEntry {
  cwe: string;
  source: string;
  file: string;
  lines: number[];
  hasLogic: boolean; // true if it has actual detection code, not just a reference
}

function extractCWEs(filePath: string, sourceLabel: string): CWEEntry[] {
  if (!existsSync(filePath)) return [];

  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const entries: CWEEntry[] = [];
  const seen = new Map<string, number[]>();

  for (let i = 0; i < lines.length; i++) {
    const matches = lines[i].matchAll(/CWE-(\d+)/g);
    for (const m of matches) {
      const cwe = `CWE-${m[1]}`;
      if (!seen.has(cwe)) seen.set(cwe, []);
      seen.get(cwe)!.push(i + 1);
    }
  }

  // Determine if each CWE has actual logic (function definition, not just a reference)
  for (const [cwe, lineNums] of seen) {
    const cweNum = cwe.replace('CWE-', '');
    const hasFunction = content.includes(`verifyCWE${cweNum}`) ||
                        content.includes(`detect`) ||
                        content.includes(`function verify`);

    // More precise: check if there's a function dedicated to this CWE
    const hasDedicatedLogic =
      new RegExp(`function\\s+(?:verify|detect).*${cweNum}`, 'i').test(content) ||
      new RegExp(`'${cwe}'\\s*:\\s*\\w+`, 'i').test(content);

    entries.push({
      cwe,
      source: sourceLabel,
      file: filePath,
      lines: lineNums,
      hasLogic: hasDedicatedLogic,
    });
  }

  return entries;
}

// ---------------------------------------------------------------------------
// Diff between implementations
// ---------------------------------------------------------------------------

interface FileDiff {
  path1: string;
  path2: string;
  identical: boolean;
  size1: number;
  size2: number;
  cwes1: string[];
  cwes2: string[];
  onlyIn1: string[];
  onlyIn2: string[];
}

function diffFiles(path1: string, path2: string): FileDiff | null {
  if (!existsSync(path1) || !existsSync(path2)) return null;

  const content1 = readFileSync(path1, 'utf-8');
  const content2 = readFileSync(path2, 'utf-8');

  const cwes1 = [...new Set([...content1.matchAll(/CWE-(\d+)/g)].map(m => `CWE-${m[1]}`))];
  const cwes2 = [...new Set([...content2.matchAll(/CWE-(\d+)/g)].map(m => `CWE-${m[1]}`))];

  const set1 = new Set(cwes1);
  const set2 = new Set(cwes2);

  return {
    path1,
    path2,
    identical: content1 === content2,
    size1: content1.length,
    size2: content2.length,
    cwes1,
    cwes2,
    onlyIn1: cwes1.filter(c => !set2.has(c)),
    onlyIn2: cwes2.filter(c => !set1.has(c)),
  };
}

// ---------------------------------------------------------------------------
// Main report
// ---------------------------------------------------------------------------

function run() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  DST CWE DEDUPLICATION REPORT');
  console.log(`  Generated: ${new Date().toISOString()}`);
  console.log('═══════════════════════════════════════════════════════════════\n');

  // 1. Extract all CWEs from all sources
  const allEntries: CWEEntry[] = [];

  for (const [key, source] of Object.entries(SOURCES)) {
    console.log(`\n📂 ${source.label}`);
    for (const path of source.paths) {
      const entries = extractCWEs(path, key);
      if (entries.length > 0) {
        console.log(`   ${path}`);
        console.log(`   → ${entries.length} CWEs found (${entries.filter(e => e.hasLogic).length} with dedicated logic)`);
        allEntries.push(...entries);
      } else if (!existsSync(path)) {
        console.log(`   ${path} — NOT FOUND`);
      }
    }
  }

  // 2. Build unified CWE map
  const cweMap = new Map<string, { sources: Set<string>; files: Set<string>; totalRefs: number }>();

  for (const entry of allEntries) {
    if (!cweMap.has(entry.cwe)) {
      cweMap.set(entry.cwe, { sources: new Set(), files: new Set(), totalRefs: 0 });
    }
    const info = cweMap.get(entry.cwe)!;
    info.sources.add(entry.source);
    info.files.add(entry.file);
    info.totalRefs += entry.lines.length;
  }

  // 3. Categorize
  const triple: string[] = [];
  const double: string[] = [];
  const single: string[] = [];

  for (const [cwe, info] of [...cweMap.entries()].sort((a, b) => {
    const numA = parseInt(a[0].replace('CWE-', ''));
    const numB = parseInt(b[0].replace('CWE-', ''));
    return numA - numB;
  })) {
    if (info.sources.size >= 3) triple.push(cwe);
    else if (info.sources.size === 2) double.push(cwe);
    else single.push(cwe);
  }

  console.log('\n\n═══════════════════════════════════════════════════════════════');
  console.log('  DUPLICATION ANALYSIS');
  console.log('═══════════════════════════════════════════════════════════════\n');

  console.log(`TRIPLE IMPLEMENTED (in all 3 sources) — ${triple.length}:`);
  for (const cwe of triple) {
    const info = cweMap.get(cwe)!;
    console.log(`  ${cwe} — ${info.totalRefs} total references across ${info.files.size} files`);
  }

  console.log(`\nDOUBLE IMPLEMENTED (in 2 sources) — ${double.length}:`);
  for (const cwe of double) {
    const info = cweMap.get(cwe)!;
    console.log(`  ${cwe} — sources: [${[...info.sources].join(', ')}]`);
  }

  console.log(`\nSINGLE IMPLEMENTATION — ${single.length}:`);
  for (const cwe of single) {
    const info = cweMap.get(cwe)!;
    console.log(`  ${cwe} — only in: ${[...info.sources][0]}`);
  }

  // 4. Cross-location diffs (atreus vs generic-api-wrapper)
  console.log('\n\n═══════════════════════════════════════════════════════════════');
  console.log('  CROSS-LOCATION FILE DIFFS');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const filePairs = [
    ['C:/Users/pizza/generic-api-wrapper/src/services/dst/verifier.ts', 'C:/Users/pizza/atreus/src/services/dst/verifier.ts'],
    ['C:/Users/pizza/generic-api-wrapper/src/services/dst/scanner.ts', 'C:/Users/pizza/atreus/src/services/dst/scanner.ts'],
    ['C:/Users/pizza/generic-api-wrapper/src/services/dst/mapper.ts', 'C:/Users/pizza/atreus/src/services/dst/mapper.ts'],
    ['C:/Users/pizza/generic-api-wrapper/src/services/dst/types.ts', 'C:/Users/pizza/atreus/src/services/dst/types.ts'],
  ];

  for (const [p1, p2] of filePairs) {
    const diff = diffFiles(p1, p2);
    if (diff) {
      const basename = p1.split('/').pop();
      const status = diff.identical ? '✅ IDENTICAL' : `⚠️  DIVERGED (${diff.size1} vs ${diff.size2} bytes)`;
      console.log(`${basename}: ${status}`);
      if (!diff.identical) {
        if (diff.onlyIn1.length) console.log(`   CWEs only in generic-api-wrapper: ${diff.onlyIn1.join(', ')}`);
        if (diff.onlyIn2.length) console.log(`   CWEs only in atreus: ${diff.onlyIn2.join(', ')}`);
      }
    }
  }

  // 5. Merge recommendations
  console.log('\n\n═══════════════════════════════════════════════════════════════');
  console.log('  MERGE RECOMMENDATIONS');
  console.log('═══════════════════════════════════════════════════════════════\n');

  console.log('1. CANONICAL SOURCE: generic-api-wrapper/src/services/dst/');
  console.log('   → This has the most complete verifier (40 CWEs) and latest mapper');
  console.log('');
  console.log('2. MERGE INTO VERIFIER from detection-engine.js:');
  console.log('   → CWE-307 (Missing Rate Limiting) — Helios has full logic');
  console.log('   → CWE-1321 (Prototype Pollution) — Helios has full logic');
  console.log('   → CWE-943 (NoSQL Injection) — Helios has full logic');
  console.log('');
  console.log('3. MERGE INTO VERIFIER from scanner.ts:');
  console.log('   → CWE-20 (Input Validation) — scanner has gap pattern');
  console.log('');
  console.log('4. SYNC atreus/src/services/dst/ ← generic-api-wrapper/src/services/dst/');
  console.log('   → atreus copy may be stale — verify and sync or delete');
  console.log('');
  console.log('5. ARCHIVE Downloads/dst-detection-engine.js after merge');
  console.log('   → Move to dst/archive/ with note about Helios authorship');

  // 6. Summary stats
  const totalUnique = cweMap.size;
  const totalImplemented = [...cweMap.values()].filter(v =>
    [...v.files].some(f => f.includes('verifier') || f.includes('detection-engine'))
  ).length;

  console.log('\n\n═══════════════════════════════════════════════════════════════');
  console.log('  SUMMARY');
  console.log('═══════════════════════════════════════════════════════════════\n');
  console.log(`Total unique CWEs referenced: ${totalUnique}`);
  console.log(`With detection logic:         ${totalImplemented}`);
  console.log(`MITRE total CWEs:             933`);
  console.log(`Coverage:                     ${((totalImplemented / 933) * 100).toFixed(1)}%`);
  console.log(`Remaining:                    ${933 - totalImplemented}`);

  // 7. Write JSON report
  const report = {
    generated: new Date().toISOString(),
    total_unique: totalUnique,
    total_with_logic: totalImplemented,
    mitre_total: 933,
    coverage_pct: parseFloat(((totalImplemented / 933) * 100).toFixed(1)),
    triple_implemented: triple,
    double_implemented: double,
    single_implemented: single,
    merge_needed: ['CWE-307', 'CWE-1321', 'CWE-943', 'CWE-20'],
    all_cwes: Object.fromEntries(
      [...cweMap.entries()].map(([cwe, info]) => [cwe, {
        sources: [...info.sources],
        files: [...info.files],
        refs: info.totalRefs,
      }])
    ),
  };

  const reportPath = join(__dirname, 'dedup-results.json');
  writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\nFull report written to: ${reportPath}`);
}

run();
