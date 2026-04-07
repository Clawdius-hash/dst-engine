/**
 * V2 PURE sweep: ONLY sentence-based detection. No V1. No legacy. No regex.
 * Usage: npx tsx src/services/dst/sandbox/v2-pure-sweep.ts [count]
 */

import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import type { NeuralMap } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const truthPath = 'C:/Users/pizza/vigil/BenchmarkJava/expectedresults-1.2.csv';
const batchSize = parseInt(process.argv[2] ?? '504', 10);

// Import the sentence verifier directly
async function loadSentenceVerifier() {
  const mod = await import('../verifier/injection-taint.js');
  // We need verifyCWE89_sentences but it might not be exported
  // Let's just inline the logic here for a pure test
  return null;
}

/**
 * Pure sentence-based SQL injection detection.
 * No BFS. No regex. No source_code scanning. Just read the story.
 */
function detectSQLi_pure(map: NeuralMap): { vulnerable: boolean; reason: string; taintedVars: string[] } {
  if (!map.story || map.story.length === 0) {
    return { vulnerable: false, reason: 'no story', taintedVars: [] };
  }

  const taintMap = new Map<string, { tainted: boolean; reason: string }>();
  const parameterizedObjects = new Set<string>();
  const resolvedCleanVars = new Set<string>();
  const findings: string[] = [];

  for (const sentence of map.story) {
    const { templateKey, slots, taintClass } = sentence;

    // Track variables explicitly resolved clean by the sentence-resolver.
    if ((sentence as any).reconciled && taintClass === 'NEUTRAL') {
      const varName = slots.subject || '';
      if (varName) resolvedCleanVars.add(varName);
    }

    // Track tainted sources
    if (taintClass === 'TAINTED') {
      const varName = slots.subject || slots.variable || '';
      if (varName) {
        taintMap.set(varName, { tainted: true, reason: sentence.text });
      }
    }

    // Track safe operations
    if (taintClass === 'SAFE') {
      if (templateKey === 'parameter-binding') {
        const obj = slots.subject || '';
        if (obj) parameterizedObjects.add(obj);
      }
      if (templateKey === 'creates-instance') {
        const obj = slots.subject || '';
        if (obj) parameterizedObjects.add(obj);
      }
      // Sanitizer calls clear taint
      if (templateKey === 'calls-method') {
        const varName = slots.subject || '';
        if (varName) taintMap.set(varName, { tainted: false, reason: 'sanitized: ' + sentence.text });
      }
    }

    // Track assignments — TRUST the sentence taintClass (reconciled by mapper)
    if (templateKey === 'assigned-from-call' || templateKey === 'assigned-literal') {
      const varName = slots.subject || '';
      if (varName) {
        if (taintClass === 'TAINTED') {
          taintMap.set(varName, { tainted: true, reason: sentence.text });
        } else {
          // NEUTRAL means mapper says not tainted — trust it
          taintMap.set(varName, { tainted: false, reason: 'mapper resolved clean: ' + sentence.text });
        }
      }
    }

    // Track string concatenation.
    // Default: trust the sentence taintClass (walk-time scope knowledge).
    // Override: if a concat part was RESOLVED CLEAN by the sentence-resolver
    // (reconciled=true via functionReturnTaint), trust the resolution.
    if (templateKey === 'string-concatenation') {
      const varName = slots.subject || '';
      const parts = slots.parts || '';
      if (varName) {
        const partNames = parts.split(/[,\s]+/).filter(Boolean);
        const allPartsResolvedClean = partNames.length > 0 &&
          partNames.every(p => resolvedCleanVars.has(p) && taintMap.get(p)?.tainted !== true);
        if (allPartsResolvedClean) {
          taintMap.set(varName, { tainted: false, reason: 'concat part resolved clean: ' + sentence.text });
        } else if (taintClass === 'TAINTED') {
          taintMap.set(varName, { tainted: true, reason: 'tainted concat: ' + sentence.text });
        } else {
          taintMap.set(varName, { tainted: false, reason: 'clean concat: ' + sentence.text });
        }
      }
    }

    // Check SINK sentences
    if (taintClass === 'SINK' && templateKey === 'executes-query') {
      const sinkObj = slots.subject || '';
      const variables = slots.variables || '';

      // Skip if parameterized
      if (parameterizedObjects.has(sinkObj)) continue;
      if (map.story.some(s => s.templateKey === 'parameter-binding' && s.slots.subject === sinkObj)) continue;

      // Check if any tainted variable appears in the query
      for (const [tv, info] of taintMap) {
        if (info.tainted && variables.includes(tv)) {
          findings.push(`${tv} reaches ${sinkObj} SQL sink`);
        }
      }
    }
  }

  const taintedVars = [...taintMap.entries()].filter(([_, v]) => v.tainted).map(([k, _]) => k);

  return {
    vulnerable: findings.length > 0,
    reason: findings.length > 0 ? findings.join('; ') : 'no tainted data reaches SQL sink',
    taintedVars,
  };
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

  // Load ground truth
  const truthLines = fs.readFileSync(truthPath, 'utf-8').split('\n');
  const truth = new Map<string, boolean>();
  for (const line of truthLines) {
    if (line.startsWith('#') || !line.includes('sqli')) continue;
    const parts = line.split(',');
    truth.set(parts[0], parts[2] === 'true');
  }

  const allFiles = fs.readdirSync(benchDir)
    .filter(f => f.startsWith('BenchmarkTest') && f.endsWith('.java'))
    .filter(f => truth.has(f.replace('.java', '')))
    .slice(0, batchSize);

  console.log(`\n=== V2 PURE SENTENCE SWEEP (no V1, no regex) ===`);
  console.log(`Files: ${allFiles.length}\n`);

  let tp = 0, fp = 0, tn = 0, fn = 0;
  let noStory = 0;
  const fpReasons: string[] = [];
  const fnReasons: string[] = [];

  for (let i = 0; i < allFiles.length; i++) {
    const file = allFiles[i];
    const testName = file.replace('.java', '');
    const isRealVuln = truth.get(testName) ?? false;

    const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
    resetSequence();
    const tree = parser.parse(code);
    if (!tree) continue;
    const { map } = buildNeuralMap(tree, code, file, javaProfile);
    tree.delete();

    if (!map.story || map.story.length === 0) {
      noStory++;
      if (!isRealVuln) tn++;
      else fn++;
      continue;
    }

    const result = detectSQLi_pure(map);

    if (result.vulnerable && isRealVuln) tp++;
    else if (result.vulnerable && !isRealVuln) {
      fp++;
      if (fpReasons.length < 10) fpReasons.push(`${testName}: ${result.reason}`);
    }
    else if (!result.vulnerable && !isRealVuln) tn++;
    else if (!result.vulnerable && isRealVuln) {
      fn++;
      if (fnReasons.length < 10) fnReasons.push(`${testName}: ${result.reason} | tainted: [${result.taintedVars.join(',')}]`);
    }

    if ((i + 1) % 100 === 0) console.log(`  ${i + 1}/${allFiles.length}...`);
  }

  const tpr = tp / Math.max(tp + fn, 1) * 100;
  const fpr = fp / Math.max(fp + tn, 1) * 100;
  const score = tpr - fpr;

  console.log(`\n=== RESULTS ===`);
  console.log(`TP: ${tp}  FP: ${fp}  TN: ${tn}  FN: ${fn}  No-story: ${noStory}`);
  console.log(`TPR: ${tpr.toFixed(1)}%`);
  console.log(`FPR: ${fpr.toFixed(1)}%`);
  console.log(`SCORE: ${score.toFixed(1)}%`);

  if (fpReasons.length > 0) {
    console.log(`\nSample FPs (first ${fpReasons.length}):`);
    for (const r of fpReasons) console.log(`  ${r}`);
  }
  if (fnReasons.length > 0) {
    console.log(`\nSample FNs (first ${fnReasons.length}):`);
    for (const r of fnReasons) console.log(`  ${r}`);
  }

  console.log(`\nThis is PURE V2. No V1. No regex. Only sentences.`);
}

main().catch(e => { console.error(e); process.exit(1); });
