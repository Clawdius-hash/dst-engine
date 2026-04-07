/**
 * Classify ALL 93 FPs: what does functionReturnTaint say about doSomething?
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
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
    .filter(f => truth.has(f.replace('.java', '')));

  let trackerTrue = 0, trackerFalse = 0, trackerUndefined = 0, noDoSomething = 0;
  const categories: Record<string, string[]> = {
    'tracker_true': [],
    'tracker_false': [],
    'tracker_undefined': [],
    'no_doSomething': [],
  };

  for (const file of allFiles) {
    const testName = file.replace('.java', '');
    const isRealVuln = truth.get(testName) ?? false;

    const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
    resetSequence();
    const tree = parser.parse(code);
    const result = buildNeuralMap(tree, code, file, javaProfile);
    const map = result.map;
    tree.delete();

    // Is this an FP? (we say vulnerable, truth says safe)
    const story = map.story || [];
    const taintMap = new Map<string, boolean>();
    const parameterizedObjects = new Set<string>();
    let weCallVuln = false;

    for (const s of story) {
      if (s.taintClass === 'TAINTED') {
        const v = s.slots.subject || s.slots.variable || '';
        if (v) taintMap.set(v, true);
      }
      if (s.taintClass === 'SAFE' && s.templateKey === 'parameter-binding') {
        const obj = s.slots.subject || '';
        if (obj) parameterizedObjects.add(obj);
      }
      if (s.taintClass === 'SAFE' && s.templateKey === 'calls-method') {
        const v = s.slots.subject || '';
        if (v) taintMap.set(v, false);
      }
      if (s.templateKey === 'assigned-from-call' || s.templateKey === 'assigned-literal') {
        const v = s.slots.subject || '';
        if (v) {
          taintMap.set(v, s.taintClass === 'TAINTED');
        }
      }
      if (s.templateKey === 'string-concatenation') {
        const v = s.slots.subject || '';
        if (v) taintMap.set(v, s.taintClass === 'TAINTED');
      }
      if (s.taintClass === 'SINK' && s.templateKey === 'executes-query') {
        const vars = s.slots.variables || '';
        if (!parameterizedObjects.has(s.slots.subject || '')) {
          for (const [tv, tainted] of taintMap) {
            if (tainted && vars.includes(tv)) weCallVuln = true;
          }
        }
      }
    }

    if (weCallVuln && !isRealVuln) {
      // This is an FP. Check functionReturnTaint for doSomething
      const ctx = (result as any).ctx;
      const funcReg = ctx?.functionRegistry;
      const funcRT = ctx?.functionReturnTaint;

      if (funcReg && funcRT) {
        const dsNodeId = funcReg.get('doSomething');
        if (dsNodeId) {
          const rt = funcRT.get(dsNodeId);
          if (rt === true) {
            trackerTrue++;
            if (categories.tracker_true.length < 5) categories.tracker_true.push(testName);
          } else if (rt === false) {
            trackerFalse++;
            if (categories.tracker_false.length < 5) categories.tracker_false.push(testName);
          } else {
            trackerUndefined++;
            if (categories.tracker_undefined.length < 5) categories.tracker_undefined.push(testName);
          }
        } else {
          noDoSomething++;
          // Check what functions exist
          const funcs = [...funcReg.keys()].filter(k => !k.includes(':')).join(', ');
          if (categories.no_doSomething.length < 5) categories.no_doSomething.push(`${testName} (has: ${funcs})`);
        }
      }
    }
  }

  console.log(`\n=== FP CLASSIFICATION BY functionReturnTaint ===\n`);
  console.log(`doSomething tracker says TRUE (tainted): ${trackerTrue}`);
  console.log(`  samples: ${categories.tracker_true.join(', ')}`);
  console.log(`doSomething tracker says FALSE (clean):  ${trackerFalse}`);
  console.log(`  samples: ${categories.tracker_false.join(', ')}`);
  console.log(`doSomething tracker says UNDEFINED:      ${trackerUndefined}`);
  console.log(`  samples: ${categories.tracker_undefined.join(', ')}`);
  console.log(`No doSomething in registry:              ${noDoSomething}`);
  console.log(`  samples: ${categories.no_doSomething.join(', ')}`);
  console.log(`\nTotal FPs: ${trackerTrue + trackerFalse + trackerUndefined + noDoSomething}`);
}

main().catch(e => { console.error(e); process.exit(1); });
