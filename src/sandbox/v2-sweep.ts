/**
 * V2 Sweep: OWASP Benchmark SQLi with ground truth + sentence path tracking.
 * Usage: npx tsx src/services/dst/sandbox/v2-sweep.ts [count]
 */

import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { verifyAll } from '../verifier/index.js';
import { resetSequence } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const truthPath = 'C:/Users/pizza/vigil/BenchmarkJava/expectedresults-1.2.csv';
const batchSize = parseInt(process.argv[2] ?? '100', 10);

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

  // Find SQLi files
  const allFiles = fs.readdirSync(benchDir)
    .filter(f => f.startsWith('BenchmarkTest') && f.endsWith('.java'))
    .filter(f => truth.has(f.replace('.java', '')));

  const sqliFiles = allFiles.filter(f => {
    const code = fs.readFileSync(path.join(benchDir, f), 'utf-8');
    return code.includes('sqli-') || truth.has(f.replace('.java', ''));
  }).slice(0, batchSize);

  console.log(`SQLi files: ${sqliFiles.length} (of ${truth.size} total)`);
  console.log(`Ground truth: ${[...truth.values()].filter(v => v).length} TP, ${[...truth.values()].filter(v => !v).length} TN\n`);

  let tp = 0, fp = 0, tn = 0, fn = 0;
  let sentencePath = 0, legacyPath = 0, errors = 0;
  let sentenceStoryLengths: number[] = [];

  for (let i = 0; i < sqliFiles.length; i++) {
    const file = sqliFiles[i];
    const testName = file.replace('.java', '');
    const isRealVuln = truth.get(testName) ?? false;

    try {
      const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
      resetSequence();
      const tree = parser.parse(code);
      if (!tree) { errors++; continue; }
      const { map } = buildNeuralMap(tree, code, file, javaProfile);
      tree.delete();

      // Track story
      const storyLen = map.story?.length ?? 0;
      sentenceStoryLengths.push(storyLen);

      const results = verifyAll(map, 'java');
      const sqli = results.find(r => r.cwe === 'CWE-89');
      const detected = sqli && !sqli.holds && sqli.findings.length > 0;

      // Check which path fired
      if (detected && sqli!.findings[0]?.via) {
        // If via is set, sentence path likely contributed
        if (storyLen > 0) sentencePath++;
        else legacyPath++;
      } else if (detected) {
        legacyPath++;
      }

      if (detected && isRealVuln) tp++;
      else if (detected && !isRealVuln) fp++;
      else if (!detected && !isRealVuln) tn++;
      else if (!detected && isRealVuln) fn++;

    } catch (e: any) {
      errors++;
    }

    if ((i + 1) % 50 === 0) console.log(`  ${i + 1}/${sqliFiles.length}...`);
  }

  const tpr = tp / (tp + fn) * 100;
  const fpr = fp / (fp + tn) * 100;
  const score = tpr - fpr;
  const avgStory = sentenceStoryLengths.reduce((a, b) => a + b, 0) / sentenceStoryLengths.length;

  console.log('');
  console.log('=== OWASP BENCHMARK SQLi — V2 SWEEP ===');
  console.log(`Files scanned: ${sqliFiles.length}`);
  console.log(`Errors: ${errors}`);
  console.log('');
  console.log(`True Positives:  ${tp}`);
  console.log(`False Positives: ${fp}`);
  console.log(`True Negatives:  ${tn}`);
  console.log(`False Negatives: ${fn}`);
  console.log('');
  console.log(`TPR: ${tpr.toFixed(1)}%`);
  console.log(`FPR: ${fpr.toFixed(1)}%`);
  console.log(`SCORE: ${score.toFixed(1)}%`);
  console.log('');
  console.log(`Sentence path fired: ${sentencePath}`);
  console.log(`Legacy path fired: ${legacyPath}`);
  console.log(`Avg story length: ${avgStory.toFixed(1)} sentences`);
  console.log('');
  console.log(`Previous score: 88.4% (98.6% TPR, 10.2% FPR)`);
  console.log(`Delta: ${(score - 88.4).toFixed(1)}%`);
}

main().catch(e => { console.error(e); process.exit(1); });
