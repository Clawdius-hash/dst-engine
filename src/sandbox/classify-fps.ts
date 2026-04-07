/**
 * Classify ALL current FPs using the same detection logic as the sweep.
 * Groups them by root cause for targeted fixing.
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import type { NeuralMap, SemanticSentence } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const truthPath = 'C:/Users/pizza/vigil/BenchmarkJava/expectedresults-1.2.csv';

function detectSQLi(map: NeuralMap): boolean {
  if (!map.story || map.story.length === 0) return false;

  const taintMap = new Map<string, boolean>();
  const parameterizedObjects = new Set<string>();
  const resolvedCleanVars = new Set<string>();

  for (const sentence of map.story) {
    const { templateKey, slots, taintClass } = sentence;

    if ((sentence as any).reconciled && taintClass === 'NEUTRAL') {
      const v = slots.subject || '';
      if (v) resolvedCleanVars.add(v);
    }

    if (taintClass === 'TAINTED') {
      const v = slots.subject || slots.variable || '';
      if (v) taintMap.set(v, true);
    }
    if (taintClass === 'SAFE') {
      if (templateKey === 'parameter-binding') {
        const obj = slots.subject || '';
        if (obj) parameterizedObjects.add(obj);
      }
      if (templateKey === 'creates-instance') {
        const obj = slots.subject || '';
        if (obj) parameterizedObjects.add(obj);
      }
      if (templateKey === 'calls-method') {
        const v = slots.subject || '';
        if (v) taintMap.set(v, false);
      }
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
        const allClean = partNames.length > 0 &&
          partNames.every(p => resolvedCleanVars.has(p) && taintMap.get(p) !== true);
        if (allClean) {
          taintMap.set(varName, false);
        } else {
          taintMap.set(varName, taintClass === 'TAINTED');
        }
      }
    }
    if (taintClass === 'SINK' && templateKey === 'executes-query') {
      const sinkObj = slots.subject || '';
      const variables = slots.variables || '';
      if (parameterizedObjects.has(sinkObj)) continue;
      if (map.story.some(s => s.templateKey === 'parameter-binding' && s.slots.subject === sinkObj)) continue;
      for (const [tv, tainted] of taintMap) {
        if (tainted && variables.includes(tv)) return true;
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

  const categories: Record<string, string[]> = {
    'no_doSomething': [],
    'tracker_true_dead_branch': [],
    'tracker_false_not_resolved': [],
    'other': [],
  };

  for (const file of allFiles) {
    const testName = file.replace('.java', '');
    const isRealVuln = truth.get(testName) ?? false;
    if (isRealVuln) continue; // only check safe files

    const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
    resetSequence();
    const tree = parser.parse(code);
    const result = buildNeuralMap(tree, code, file, javaProfile);
    const map = result.map;
    const ctx = (result as any).ctx;
    tree.delete();

    if (!detectSQLi(map)) continue; // not an FP

    // Classify
    const funcReg = ctx?.functionRegistry;
    const funcRT = ctx?.functionReturnTaint;
    const dsNodeId = funcReg?.get('doSomething');

    if (!dsNodeId) {
      // No doSomething — different pattern
      // Check what's going on
      const story = map.story || [];
      const taintedVars = story.filter(s => s.taintClass === 'TAINTED').map(s => s.slots.subject || s.slots.variable || '').filter(Boolean);
      categories.no_doSomething.push(`${testName} (tainted: ${[...new Set(taintedVars)].join(',')})`);
    } else {
      const rt = funcRT?.get(dsNodeId);
      if (rt === true) {
        // Tracker says tainted but file is safe — dead branch evaluation failure
        // Check what doSomething does
        const funcNode = ctx.nodeById.get(dsNodeId);
        const snap = funcNode?.code_snapshot?.substring(0, 80) || '';
        categories.tracker_true_dead_branch.push(`${testName} (${snap})`);
      } else if (rt === false) {
        // Tracker says clean but we still flagged — resolution didn't propagate
        categories.tracker_false_not_resolved.push(testName);
      } else {
        categories.other.push(testName);
      }
    }
  }

  console.log(`\n=== FP CLASSIFICATION (current sweep logic) ===\n`);
  console.log(`No doSomething (different pattern): ${categories.no_doSomething.length}`);
  for (const f of categories.no_doSomething) console.log(`  ${f}`);
  console.log(`\nTracker says TRUE — dead branch failure: ${categories.tracker_true_dead_branch.length}`);
  for (const f of categories.tracker_true_dead_branch.slice(0, 10)) console.log(`  ${f}`);
  if (categories.tracker_true_dead_branch.length > 10) console.log(`  ... and ${categories.tracker_true_dead_branch.length - 10} more`);
  console.log(`\nTracker says FALSE — resolution didn't propagate: ${categories.tracker_false_not_resolved.length}`);
  for (const f of categories.tracker_false_not_resolved.slice(0, 10)) console.log(`  ${f}`);
  if (categories.tracker_false_not_resolved.length > 10) console.log(`  ... and ${categories.tracker_false_not_resolved.length - 10} more`);
  console.log(`\nOther: ${categories.other.length}`);
  for (const f of categories.other) console.log(`  ${f}`);
  console.log(`\nTOTAL FPs: ${categories.no_doSomething.length + categories.tracker_true_dead_branch.length + categories.tracker_false_not_resolved.length + categories.other.length}`);
}

main().catch(e => { console.error(e); process.exit(1); });
