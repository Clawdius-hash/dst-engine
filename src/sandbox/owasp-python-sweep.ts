/**
 * OWASP BenchmarkPython sweep — all 1,236 test files with ground truth.
 * Same methodology as owasp-full-sweep.ts but for Python.
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import { verifyAll } from '../verifier/index.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkPython/testcode';
const truthPath = 'C:/Users/pizza/vigil/BenchmarkPython/expectedresults-0.1.csv';

const CATEGORY_CWE: Record<string, string[]> = {
  sqli: ['89'],
  xss: ['79'],
  cmdi: ['78'],
  pathtraver: ['22'],
  ldapi: ['90'],
  xpathi: ['643'],
  hash: ['328'],
  weakrand: ['330'],
  trustbound: ['501'],
  securecookie: ['614'],
  deserialization: ['502'],
  codeinj: ['94'],
  redirect: ['601'],
  xxe: ['611'],
};

async function main() {
  await Parser.init();
  const parser = new Parser();
  const wasmPath = path.resolve(
    path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Z]:)/, '$1'),
    '../../node_modules/tree-sitter-python/tree-sitter-python.wasm'
  );
  const lang = await Language.load(fs.readFileSync(wasmPath));
  parser.setLanguage(lang);
  const pyMod = await import('../profiles/python.js');
  const pyProfile = pyMod.default ?? pyMod.pythonProfile ?? pyMod.profile;

  const truthLines = fs.readFileSync(truthPath, 'utf-8').split('\n');
  const truth = new Map<string, { category: string; isVuln: boolean; cwe: string }>();
  for (const line of truthLines) {
    if (line.startsWith('#') || !line.trim()) continue;
    const parts = line.split(',');
    if (parts.length < 4) continue;
    truth.set(parts[0], { category: parts[1], isVuln: parts[2] === 'true', cwe: parts[3] });
  }

  const allFiles = fs.readdirSync(benchDir)
    .filter(f => f.endsWith('.py'))
    .filter(f => truth.has(f.replace('.py', '')))
    .sort();

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  OWASP BENCHMARK PYTHON — ${allFiles.length} FILES`);
  console.log(`${'='.repeat(60)}\n`);

  const stats: Record<string, { tp: number; fp: number; tn: number; fn: number }> = {};
  for (const cat of Object.keys(CATEGORY_CWE)) {
    stats[cat] = { tp: 0, fp: 0, tn: 0, fn: 0 };
  }

  let processed = 0;
  let errors = 0;

  for (const file of allFiles) {
    const testName = file.replace('.py', '');
    const entry = truth.get(testName);
    if (!entry) continue;

    const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
    resetSequence();

    try {
      const tree = parser.parse(code);
      if (!tree) { errors++; continue; }
      const { map } = buildNeuralMap(tree, code, file, pyProfile);
      tree.delete();

      let detected = false;
      const results = verifyAll(map, 'python');
      const cwes = CATEGORY_CWE[entry.category] || [];
      for (const r of results) {
        if (!r.holds && cwes.some(c => r.cwe === `CWE-${c}`)) {
          detected = true;
          break;
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
    if (processed % 200 === 0) console.log(`  ${processed}/${allFiles.length}...`);
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  RESULTS — ${processed} files, ${errors} errors`);
  console.log(`${'='.repeat(60)}\n`);

  let totalTP = 0, totalFP = 0, totalTN = 0, totalFN = 0;

  console.log(`${'Category'.padEnd(16)} ${'Files'.padStart(5)} ${'TP'.padStart(4)} ${'FP'.padStart(4)} ${'TN'.padStart(4)} ${'FN'.padStart(4)} ${'TPR'.padStart(7)} ${'FPR'.padStart(7)} ${'Score'.padStart(7)}`);
  console.log('-'.repeat(66));

  for (const [cat, s] of Object.entries(stats).sort((a, b) => (b[1].tp + b[1].fp + b[1].tn + b[1].fn) - (a[1].tp + a[1].fp + a[1].tn + a[1].fn))) {
    const total = s.tp + s.fp + s.tn + s.fn;
    if (total === 0) continue;
    const tpr = s.tp / Math.max(s.tp + s.fn, 1) * 100;
    const fpr = s.fp / Math.max(s.fp + s.tn, 1) * 100;
    const score = tpr - fpr;
    totalTP += s.tp; totalFP += s.fp; totalTN += s.tn; totalFN += s.fn;

    console.log(`${cat.padEnd(16)} ${String(total).padStart(5)} ${String(s.tp).padStart(4)} ${String(s.fp).padStart(4)} ${String(s.tn).padStart(4)} ${String(s.fn).padStart(4)} ${tpr.toFixed(1).padStart(6)}% ${fpr.toFixed(1).padStart(6)}% ${score.toFixed(1).padStart(6)}%`);
  }

  console.log('-'.repeat(66));
  const totalFiles = totalTP + totalFP + totalTN + totalFN;
  const overallTPR = totalTP / Math.max(totalTP + totalFN, 1) * 100;
  const overallFPR = totalFP / Math.max(totalFP + totalTN, 1) * 100;
  const overallScore = overallTPR - overallFPR;
  console.log(`${'TOTAL'.padEnd(16)} ${String(totalFiles).padStart(5)} ${String(totalTP).padStart(4)} ${String(totalFP).padStart(4)} ${String(totalTN).padStart(4)} ${String(totalFN).padStart(4)} ${overallTPR.toFixed(1).padStart(6)}% ${overallFPR.toFixed(1).padStart(6)}% ${overallScore.toFixed(1).padStart(6)}%`);
}

main().catch(e => { console.error(e); process.exit(1); });
