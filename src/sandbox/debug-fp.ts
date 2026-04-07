/**
 * Debug: why does the resolver not fix FPs?
 * Check functionReturnTaint, functionRegistry, and sentence taintBasis
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const file = process.argv[2] ?? 'BenchmarkTest01803.java';

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

  const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
  resetSequence();
  const tree = parser.parse(code);

  // We need access to ctx - buildNeuralMap returns { map, ctx }
  const result = buildNeuralMap(tree, code, file, javaProfile);
  const map = result.map;
  const ctx = (result as any).ctx;
  tree.delete();

  console.log(`\n=== DEBUG: ${file} ===\n`);

  // 1. What does functionReturnTaint say?
  if (ctx?.functionReturnTaint) {
    console.log('--- functionReturnTaint ---');
    for (const [key, val] of ctx.functionReturnTaint) {
      console.log(`  ${key} -> ${val}`);
    }
  } else {
    console.log('--- functionReturnTaint: NOT AVAILABLE on ctx ---');
    // Try to find it on the map
    console.log('  result keys:', Object.keys(result));
  }

  // 2. What does functionRegistry say?
  if (ctx?.functionRegistry) {
    console.log('\n--- functionRegistry ---');
    for (const [key, val] of ctx.functionRegistry) {
      console.log(`  ${key} -> ${val}`);
    }
  } else {
    console.log('\n--- functionRegistry: NOT AVAILABLE on ctx ---');
  }

  // 3. Sentences about bar/doSomething/PENDING
  console.log('\n--- Relevant sentences ---');
  for (const s of map.story || []) {
    if (s.text.includes('bar') || s.text.includes('doSomething') || s.taintBasis === 'PENDING') {
      console.log(`  [L${s.lineNumber}] class=${s.taintClass} basis=${s.taintBasis} reconciled=${s.reconciled || false}`);
      console.log(`    reason: ${s.reconciliationReason || 'none'}`);
      console.log(`    nodeId: ${s.nodeId}`);
      console.log(`    text: ${s.text}`);
    }
  }

  // 4. Nodes related to doSomething
  console.log('\n--- Nodes mentioning doSomething ---');
  for (const [id, node] of Object.entries(map.nodes)) {
    const n = node as any;
    const snap = n.analysis_snapshot || n.code_snapshot || '';
    if (snap.includes('doSomething')) {
      console.log(`  ${id}: type=${n.node_type}/${n.node_subtype} tainted=${n.tainted}`);
      console.log(`    snap: ${snap.substring(0, 120)}`);
    }
  }

  // 5. What does the ACTUAL source code look like around doSomething?
  console.log('\n--- Source around doSomething ---');
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('doSomething') || lines[i].includes('class Test')) {
      console.log(`  L${i + 1}: ${lines[i].trim()}`);
    }
  }
}

main().catch(e => { console.error(e); process.exit(1); });
