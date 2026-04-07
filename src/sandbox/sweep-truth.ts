/**
 * Ground truth comparison: DST vs OWASP Benchmark expected results.
 * Produces honest TP/FP/TN/FN numbers and OWASP Score.
 */

import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { verifyAll } from '../verifier/index.js';
import { resetSequence } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const expectedFile = 'C:/Users/pizza/vigil/BenchmarkJava/expectedresults-1.2.csv';

async function main() {
  // Load ground truth
  const csv = fs.readFileSync(expectedFile, 'utf-8');
  const expected = new Map<string, boolean>();
  for (const line of csv.split('\n')) {
    if (line.startsWith('#') || !line.includes('sqli')) continue;
    const parts = line.split(',');
    expected.set(parts[0], parts[2] === 'true');
  }

  console.log(`Ground truth: ${[...expected.values()].filter(v => v).length} true positives, ${[...expected.values()].filter(v => !v).length} true negatives`);

  // Init parser
  await Parser.init();
  const parser = new Parser();
  const wasmDir = path.resolve(
    path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Z]:)/, '$1'),
    '../../node_modules'
  );
  const lang = await Language.load(fs.readFileSync(path.join(wasmDir, 'tree-sitter-java/tree-sitter-java.wasm')));
  parser.setLanguage(lang);
  const javaMod = await import('../profiles/java.js');
  const javaProfile = javaMod.default ?? javaMod.javaProfile ?? javaMod.profile;

  // Scan all SQLi files
  const allFiles = fs.readdirSync(benchDir)
    .filter(f => f.startsWith('BenchmarkTest') && f.endsWith('.java'));

  let tp = 0, fp = 0, tn = 0, fn = 0;
  const fnFiles: string[] = [];
  const fpFiles: string[] = [];

  for (let i = 0; i < allFiles.length; i++) {
    const file = allFiles[i];
    const name = file.replace('.java', '');
    const isReallyVuln = expected.get(name);
    if (isReallyVuln === undefined) continue; // not an SQLi test case

    try {
      const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
      resetSequence();
      const tree = parser.parse(code);
      if (!tree) continue;
      const { map } = buildNeuralMap(tree, code, file, javaProfile);
      tree.delete();
      const results = verifyAll(map, 'java');
      const sqli = results.find(r => r.cwe === 'CWE-89');
      const detected = !!(sqli && !sqli.holds && sqli.findings.length > 0);

      if (isReallyVuln && detected) tp++;
      else if (isReallyVuln && !detected) { fn++; fnFiles.push(name); }
      else if (!isReallyVuln && detected) { fp++; fpFiles.push(name); }
      else if (!isReallyVuln && !detected) tn++;
    } catch {
      // count as miss if it was supposed to be vulnerable
      if (isReallyVuln) { fn++; fnFiles.push(name); }
      else tn++;
    }

    if ((i + 1) % 100 === 0) console.log(`  ${i + 1}/${allFiles.length}...`);
  }

  const tpr = tp / (tp + fn) * 100;
  const fpr = fp / (fp + tn) * 100;
  const score = tpr - fpr;

  console.log('');
  console.log('=== OWASP BENCHMARK SQLi — HONEST NUMBERS ===');
  console.log(`True Positives (detected real vulns):  ${tp} / ${tp + fn}`);
  console.log(`False Negatives (missed real vulns):   ${fn} / ${tp + fn}`);
  console.log(`True Negatives (correctly safe):       ${tn} / ${tn + fp}`);
  console.log(`False Positives (false alarms):        ${fp} / ${tn + fp}`);
  console.log('');
  console.log(`TPR (sensitivity):    ${tpr.toFixed(1)}%`);
  console.log(`FPR (false alarms):   ${fpr.toFixed(1)}%`);
  console.log(`OWASP Score (TPR-FPR): ${score.toFixed(1)}%`);
  console.log('');
  if (fnFiles.length > 0 && fnFiles.length <= 20) {
    console.log('Missed (false negatives):');
    fnFiles.forEach(f => console.log(`  ${f}`));
  } else if (fnFiles.length > 20) {
    console.log(`Missed: ${fnFiles.length} files (showing first 10):`);
    fnFiles.slice(0, 10).forEach(f => console.log(`  ${f}`));
  }
  if (fpFiles.length > 0 && fpFiles.length <= 20) {
    console.log('False positives:');
    fpFiles.forEach(f => console.log(`  ${f}`));
  } else if (fpFiles.length > 20) {
    console.log(`False positives: ${fpFiles.length} files (showing first 10):`);
    fpFiles.slice(0, 10).forEach(f => console.log(`  ${f}`));
  }
}

main().catch(e => { console.error(e); process.exit(1); });
