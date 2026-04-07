/**
 * FULL OWASP Benchmark sweep — ALL 2,740 files, ALL 11 categories.
 * Uses the existing V1 verifier pipeline for all CWE categories.
 * Usage: npx tsx src/services/dst/sandbox/owasp-full-sweep.ts
 */

import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import type { NeuralMap } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const truthPath = 'C:/Users/pizza/vigil/BenchmarkJava/expectedresults-1.2.csv';

// Category → CWE mapping
const CATEGORY_CWE: Record<string, string[]> = {
  sqli: ['89'],
  xss: ['79'],
  cmdi: ['78'],
  pathtraver: ['22'],
  ldapi: ['90'],
  xpathi: ['643'],
  crypto: ['327', '328'],
  hash: ['328'],
  weakrand: ['330'],
  trustbound: ['501'],
  securecookie: ['614'],
};

// Import the full verifier pipeline
async function loadVerifiers() {
  const mod = await import('../verifier/index.js');
  return mod;
}

async function main() {
  await Parser.init();
  const parser = new Parser();
  const wasmPath = path.resolve(
    path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Z]:)/, '$1'),
    '../../node_modules/tree-sitter-java/tree-sitter-java.wasm'
  );
  const lang = await Language.load(fs.readFileSync(wasmPath));
  parser.setLanguage(lang);
  const javaMod = await import('../profiles/java.js');
  const javaProfile = javaMod.default ?? javaMod.javaProfile ?? javaMod.profile;
  const verifierMod = await loadVerifiers();
  const runVerifiers = verifierMod.verifyAll ?? verifierMod.default?.verifyAll;

  // Load ground truth
  const truthLines = fs.readFileSync(truthPath, 'utf-8').split('\n');
  const truth = new Map<string, { category: string; isVuln: boolean; cwe: string }>();
  for (const line of truthLines) {
    if (line.startsWith('#') || !line.trim()) continue;
    const parts = line.split(',');
    if (parts.length < 4) continue;
    truth.set(parts[0], { category: parts[1], isVuln: parts[2] === 'true', cwe: parts[3] });
  }

  const allFiles = fs.readdirSync(benchDir)
    .filter(f => f.startsWith('BenchmarkTest') && f.endsWith('.java'))
    .filter(f => truth.has(f.replace('.java', '')))
    .sort();

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  FULL OWASP BENCHMARK SWEEP — ${allFiles.length} FILES`);
  console.log(`${'='.repeat(60)}\n`);

  // Per-category stats
  const stats: Record<string, { tp: number; fp: number; tn: number; fn: number }> = {};
  for (const cat of Object.keys(CATEGORY_CWE)) {
    stats[cat] = { tp: 0, fp: 0, tn: 0, fn: 0 };
  }

  let processed = 0;
  let errors = 0;

  for (const file of allFiles) {
    const testName = file.replace('.java', '');
    const entry = truth.get(testName);
    if (!entry) continue;

    const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
    resetSequence();

    try {
      const tree = parser.parse(code);
      if (!tree) { errors++; continue; }
      const { map } = buildNeuralMap(tree, code, file, javaProfile);
      tree.delete();

      // Run verifiers and check if any finding matches this category's CWE
      let detected = false;
      if (runVerifiers) {
        const results = runVerifiers(map);
        const cwes = CATEGORY_CWE[entry.category] || [];
        for (const r of results) {
          if (!r.holds && cwes.some(c => r.cwe === `CWE-${c}`)) {
            detected = true;
            break;
          }
        }
      }

      const cat = entry.category;
      if (!stats[cat]) stats[cat] = { tp: 0, fp: 0, tn: 0, fn: 0 };

      if (detected && entry.isVuln) stats[cat].tp++;
      else if (detected && !entry.isVuln) stats[cat].fp++;
      else if (!detected && !entry.isVuln) stats[cat].tn++;
      else if (!detected && entry.isVuln) stats[cat].fn++;

    } catch (e) {
      errors++;
    }

    processed++;
    if (processed % 500 === 0) {
      console.log(`  ${processed}/${allFiles.length}...`);
    }
  }

  // Results
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  RESULTS — ${processed} files processed, ${errors} errors`);
  console.log(`${'='.repeat(60)}\n`);

  let totalTP = 0, totalFP = 0, totalTN = 0, totalFN = 0;

  console.log(`${'Category'.padEnd(14)} ${'Files'.padStart(5)} ${'TP'.padStart(4)} ${'FP'.padStart(4)} ${'TN'.padStart(4)} ${'FN'.padStart(4)} ${'TPR'.padStart(7)} ${'FPR'.padStart(7)} ${'Score'.padStart(7)}`);
  console.log('-'.repeat(62));

  for (const [cat, s] of Object.entries(stats).sort((a, b) => (b[1].tp + b[1].fp + b[1].tn + b[1].fn) - (a[1].tp + a[1].fp + a[1].tn + a[1].fn))) {
    const total = s.tp + s.fp + s.tn + s.fn;
    if (total === 0) continue;
    const tpr = s.tp / Math.max(s.tp + s.fn, 1) * 100;
    const fpr = s.fp / Math.max(s.fp + s.tn, 1) * 100;
    const score = tpr - fpr;
    totalTP += s.tp; totalFP += s.fp; totalTN += s.tn; totalFN += s.fn;

    console.log(`${cat.padEnd(14)} ${String(total).padStart(5)} ${String(s.tp).padStart(4)} ${String(s.fp).padStart(4)} ${String(s.tn).padStart(4)} ${String(s.fn).padStart(4)} ${tpr.toFixed(1).padStart(6)}% ${fpr.toFixed(1).padStart(6)}% ${score.toFixed(1).padStart(6)}%`);
  }

  console.log('-'.repeat(62));
  const totalFiles = totalTP + totalFP + totalTN + totalFN;
  const overallTPR = totalTP / Math.max(totalTP + totalFN, 1) * 100;
  const overallFPR = totalFP / Math.max(totalFP + totalTN, 1) * 100;
  const overallScore = overallTPR - overallFPR;
  console.log(`${'TOTAL'.padEnd(14)} ${String(totalFiles).padStart(5)} ${String(totalTP).padStart(4)} ${String(totalFP).padStart(4)} ${String(totalTN).padStart(4)} ${String(totalFN).padStart(4)} ${overallTPR.toFixed(1).padStart(6)}% ${overallFPR.toFixed(1).padStart(6)}% ${overallScore.toFixed(1).padStart(6)}%`);
  console.log();
}

main().catch(e => { console.error(e); process.exit(1); });
