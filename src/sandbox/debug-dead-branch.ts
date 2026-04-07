/**
 * For each of the 17 remaining FPs, show what doSomething does.
 * What conditional pattern is the evaluator failing on?
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const truthPath = 'C:/Users/pizza/vigil/BenchmarkJava/expectedresults-1.2.csv';

// Same detection logic as sweep
function detectSQLi(map: any): boolean {
  if (!map.story || map.story.length === 0) return false;
  const taintMap = new Map<string, boolean>();
  const parameterizedObjects = new Set<string>();
  const resolvedCleanVars = new Set<string>();
  for (const sentence of map.story) {
    const { templateKey, slots, taintClass } = sentence;
    if (sentence.reconciled && taintClass === 'NEUTRAL') {
      const v = slots.subject || '';
      if (v) resolvedCleanVars.add(v);
    }
    if (taintClass === 'TAINTED') {
      const v = slots.subject || slots.variable || '';
      if (v) taintMap.set(v, true);
    }
    if (taintClass === 'SAFE') {
      if (templateKey === 'parameter-binding') parameterizedObjects.add(slots.subject || '');
      if (templateKey === 'creates-instance') parameterizedObjects.add(slots.subject || '');
      if (templateKey === 'calls-method') taintMap.set(slots.subject || '', false);
    }
    if (templateKey === 'assigned-from-call' || templateKey === 'assigned-literal') {
      const v = slots.subject || '';
      if (v) taintMap.set(v, taintClass === 'TAINTED');
    }
    if (templateKey === 'string-concatenation') {
      const varName = slots.subject || '';
      const parts = slots.parts || '';
      if (varName) {
        const partNames = parts.split(/[,\s]+/).filter(Boolean);
        const allClean = partNames.length > 0 && partNames.every(p => resolvedCleanVars.has(p) && taintMap.get(p) !== true);
        taintMap.set(varName, allClean ? false : taintClass === 'TAINTED');
      }
    }
    if (taintClass === 'SINK' && templateKey === 'executes-query') {
      if (parameterizedObjects.has(slots.subject || '')) continue;
      if (map.story.some((s: any) => s.templateKey === 'parameter-binding' && s.slots.subject === (slots.subject || ''))) continue;
      for (const [tv, tainted] of taintMap) {
        if (tainted && (slots.variables || '').includes(tv)) return true;
      }
    }
  }
  return false;
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

  const truthLines = fs.readFileSync(truthPath, 'utf-8').split('\n');
  const truth = new Map<string, boolean>();
  for (const line of truthLines) {
    if (line.startsWith('#') || !line.includes('sqli')) continue;
    const parts = line.split(',');
    truth.set(parts[0], parts[2] === 'true');
  }

  const allFiles = fs.readdirSync(benchDir)
    .filter(f => f.startsWith('BenchmarkTest') && f.endsWith('.java'))
    .filter(f => truth.has(f.replace('.java', '')));

  const patterns: Record<string, string[]> = {};

  for (const file of allFiles) {
    const testName = file.replace('.java', '');
    if (truth.get(testName)) continue; // only safe files

    const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
    resetSequence();
    const tree = parser.parse(code);
    const result = buildNeuralMap(tree, code, file, javaProfile);
    const map = result.map;
    tree.delete();

    if (!detectSQLi(map)) continue;

    // Extract the doSomething function body
    const lines = code.split('\n');
    let inFunc = false;
    let funcBody = '';
    let braceCount = 0;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('doSomething')) inFunc = true;
      if (inFunc) {
        funcBody += lines[i].trim() + '\n';
        braceCount += (lines[i].match(/\{/g) || []).length;
        braceCount -= (lines[i].match(/\}/g) || []).length;
        if (braceCount <= 0 && funcBody.includes('{')) break;
      }
    }

    // Identify the pattern: switch, if, ternary, etc.
    let pattern = 'unknown';
    if (funcBody.includes('switch')) pattern = 'switch';
    else if (funcBody.includes('? param')) pattern = 'ternary-param';
    else if (funcBody.includes('? "')) pattern = 'ternary-literal';
    else if (funcBody.includes('if (')) pattern = 'if-condition';

    if (!patterns[pattern]) patterns[pattern] = [];
    patterns[pattern].push(testName);
  }

  console.log('\n=== 17 FPs BY DEAD BRANCH PATTERN ===\n');
  for (const [pattern, files] of Object.entries(patterns)) {
    console.log(`${pattern}: ${files.length} files`);
    // Show one example
    const exFile = files[0] + '.java';
    const code = fs.readFileSync(path.join(benchDir, exFile), 'utf-8');
    const lines = code.split('\n');
    let inFunc = false;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('doSomething')) inFunc = true;
      if (inFunc) {
        console.log(`  L${i+1}: ${lines[i].trimEnd()}`);
        if (lines[i].includes('return bar')) { console.log(); break; }
      }
    }
    if (files.length > 1) console.log(`  (+ ${files.length - 1} more: ${files.slice(1, 4).join(', ')}...)\n`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
