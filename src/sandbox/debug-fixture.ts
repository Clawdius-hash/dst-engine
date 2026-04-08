import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import { verifyAll } from '../verifier/index.js';
import * as fs from 'fs';
import * as path from 'path';

const file = process.argv[2] ?? '';

async function main() {
  if (!file) { console.log('Usage: npx tsx debug-fixture.ts <path-to-java-file>'); return; }
  await Parser.init();
  const p = new Parser();
  const wasmPath = path.resolve(path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Z]:)/, '$1'), '../../node_modules/tree-sitter-java/tree-sitter-java.wasm');
  const l = await Language.load(fs.readFileSync(wasmPath));
  p.setLanguage(l);
  const mod = await import('../profiles/java.js');
  const prof = mod.default ?? mod.javaProfile ?? mod.profile;
  const code = fs.readFileSync(file, 'utf-8');
  resetSequence();
  const t = p.parse(code);
  const { map } = buildNeuralMap(t, code, path.basename(file), prof);
  t.delete();

  console.log(`\nStory: ${map.story?.length ?? 0} sentences\n`);
  for (const s of map.story || []) {
    console.log(`[L${s.lineNumber}] ${s.taintClass} | ${s.templateKey}`);
    console.log(`  ${s.text.substring(0, 100)}`);
  }

  console.log('\n--- CWE-89 ---');
  const r89 = verifyAll(map, 'java').find(r => r.cwe === 'CWE-89');
  console.log('holds:', r89?.holds, 'findings:', r89?.findings?.length);
  for (const f of r89?.findings ?? []) {
    console.log('  ', (f as any).via, f.description?.substring(0, 100));
  }
}
main().catch(e => { console.error(e); process.exit(1); });
