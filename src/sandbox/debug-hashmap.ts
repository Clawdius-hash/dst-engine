/**
 * Debug: Why doesn't keyedTaint work for BenchmarkTest01881?
 * Check if param is tainted inside doSomething and if keyedTaint gets populated.
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const file = process.argv[2] ?? 'BenchmarkTest01881.java';

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
  const result = buildNeuralMap(tree, code, file, javaProfile);
  const map = result.map;
  const ctx = (result as any).ctx;
  tree.delete();

  console.log(`\n=== HashMap Debug: ${file} ===\n`);

  // Check functionReturnTaint
  console.log('--- functionReturnTaint ---');
  for (const [key, val] of ctx.functionReturnTaint) {
    const funcName = [...ctx.functionRegistry.entries()].find(([_, v]) => v === key)?.[0] || key;
    console.log(`  ${funcName} (${key}) -> ${val}`);
  }

  // Check ALL nodes for put/get patterns on maps
  console.log('\n--- Nodes involving put/get on maps ---');
  for (const node of map.nodes) {
    const n = node as any;
    const snap = n.code_snapshot || '';
    if (snap.includes('.put(') || snap.includes('.get(')) {
      console.log(`  ${n.id}: L${n.line_start} ${n.node_type}/${n.node_subtype} tainted=${n.tainted}`);
      console.log(`    snap: ${snap.substring(0, 100)}`);
      if (n.data_out?.length > 0) {
        for (const d of n.data_out) {
          console.log(`    data_out: ${d.name} tainted=${d.tainted}`);
        }
      }
    }
  }

  // Check: what does the scope look like inside doSomething?
  // Look at the taintLog for HashMap operations
  console.log('\n--- Taint log entries for map operations ---');
  for (const entry of ctx.taintLog || []) {
    if (entry.variable?.includes('map') || entry.variable?.includes('bar') || entry.reason?.includes('map') || entry.reason?.includes('keyed')) {
      console.log(`  L${entry.line}: ${entry.variable} ${entry.action} ${entry.reason || ''}`);
    }
  }

  // BenchmarkTest01006 comparison - that one works (inner class vs static)
  console.log('\n--- File structure ---');
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes('doSomething') || line.includes('.put(') || line.includes('.get(') || line.includes('private') && line.includes('class') || line.includes('private static') || line.includes('return bar')) {
      console.log(`  L${i + 1}: ${line.trim()}`);
    }
  }
}

main().catch(e => { console.error(e); process.exit(1); });
