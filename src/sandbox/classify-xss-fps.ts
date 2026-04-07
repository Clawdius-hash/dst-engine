/**
 * Classify XSS FPs from OWASP Benchmark.
 * What patterns are causing false positives?
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import { verifyAll } from '../verifier/index.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const truthPath = 'C:/Users/pizza/vigil/BenchmarkJava/expectedresults-1.2.csv';

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

  const truthLines = fs.readFileSync(truthPath, 'utf-8').split('\n');
  const truth = new Map<string, boolean>();
  for (const line of truthLines) {
    if (line.startsWith('#') || !line.includes('xss')) continue;
    const parts = line.split(',');
    truth.set(parts[0], parts[2] === 'true');
  }

  const allFiles = fs.readdirSync(benchDir)
    .filter(f => f.startsWith('BenchmarkTest') && f.endsWith('.java'))
    .filter(f => truth.has(f.replace('.java', '')));

  console.log(`XSS files: ${allFiles.length}\n`);

  const categories: Record<string, string[]> = {
    'doSomething_tracker_true': [],
    'doSomething_tracker_false': [],
    'no_doSomething': [],
    'other': [],
  };

  let fpCount = 0;
  let fnCount = 0;

  for (const file of allFiles) {
    const testName = file.replace('.java', '');
    const isRealVuln = truth.get(testName) ?? false;

    const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
    resetSequence();
    const tree = parser.parse(code);
    const result = buildNeuralMap(tree, code, file, javaProfile);
    const map = result.map;
    const ctx = (result as any).ctx;
    tree.delete();

    const cwe79 = verifyAll(map, 'java').find(r => r.cwe === 'CWE-79');
    const detected = cwe79 && !cwe79.holds;

    if (detected && !isRealVuln) {
      fpCount++;
      // Classify FP
      const funcReg = ctx?.functionRegistry;
      const funcRT = ctx?.functionReturnTaint;
      const dsNodeId = funcReg?.get('doSomething');

      if (!dsNodeId) {
        // Check what V1 detection mode triggered
        const via = cwe79.findings?.[0]?.via || 'unknown';
        categories.no_doSomething.push(`${testName} (via: ${via})`);
      } else {
        const rt = funcRT?.get(dsNodeId);
        if (rt === true) {
          categories.doSomething_tracker_true.push(testName);
        } else if (rt === false) {
          categories.doSomething_tracker_false.push(testName);
        } else {
          categories.other.push(testName);
        }
      }
    } else if (!detected && isRealVuln) {
      fnCount++;
    }
  }

  console.log(`=== XSS FP CLASSIFICATION ===\n`);
  console.log(`Total FPs: ${fpCount}`);
  console.log(`Total FNs: ${fnCount}\n`);

  for (const [cat, files] of Object.entries(categories)) {
    if (files.length === 0) continue;
    console.log(`${cat}: ${files.length}`);
    for (const f of files.slice(0, 5)) console.log(`  ${f}`);
    if (files.length > 5) console.log(`  ... and ${files.length - 5} more`);
    console.log();
  }

  // Sample a no_doSomething FP to see the pattern
  if (categories.no_doSomething.length > 0) {
    const sampleName = categories.no_doSomething[0].split(' ')[0];
    const sampleCode = fs.readFileSync(path.join(benchDir, sampleName + '.java'), 'utf-8');
    const lines = sampleCode.split('\n');
    console.log(`\n=== SAMPLE no_doSomething FP: ${sampleName} ===`);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i];
      if (ln.includes('param') || ln.includes('bar') || ln.includes('println') || ln.includes('send') || ln.includes('write') || ln.includes('getWriter') || ln.includes('getParameter') || ln.includes('doSomething') || ln.includes('doPost') || ln.includes('ESAPI') || ln.includes('encode')) {
        console.log(`  L${i+1}: ${ln.trim()}`);
      }
    }
  }

  // Sample a doSomething FP
  if (categories.doSomething_tracker_true.length > 0) {
    const sampleName = categories.doSomething_tracker_true[0];
    const sampleCode = fs.readFileSync(path.join(benchDir, sampleName + '.java'), 'utf-8');
    const lines = sampleCode.split('\n');
    console.log(`\n=== SAMPLE doSomething tracker=true FP: ${sampleName} ===`);
    let inFunc = false;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('doSomething')) inFunc = true;
      if (inFunc) {
        console.log(`  L${i+1}: ${lines[i].trimEnd()}`);
        if (lines[i].includes('return bar')) break;
      }
    }
  }
}

main().catch(e => { console.error(e); process.exit(1); });
