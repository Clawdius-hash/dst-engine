/**
 * Debug one file: show all sentences and their slots
 */
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const file = process.argv[2] ?? 'BenchmarkTest00008.java';

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
  const { map } = buildNeuralMap(tree, code, file, javaProfile);
  tree.delete();

  console.log(`\n=== ${file} ===`);
  console.log(`Nodes: ${map.nodes.length}`);
  console.log(`Story: ${map.story?.length ?? 0} sentences\n`);

  if (map.story) {
    for (const s of map.story) {
      const tag = s.taintClass === 'TAINTED' ? '!!TAINTED!!' :
                  s.taintClass === 'SINK' ? '>>SINK<<' :
                  s.taintClass === 'SAFE' ? '--SAFE--' : '  neutral';
      console.log(`[line ${s.lineNumber}] ${tag} | template: ${s.templateKey}`);
      console.log(`  text: ${s.text}`);
      console.log(`  slots: ${JSON.stringify(s.slots)}`);
      console.log();
    }
  }

  // Also show source lines around the SQL execution
  const lines = code.split('\n');
  console.log('=== Source lines with SQL ===');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].match(/execute|prepareStatement|prepareCall|query/i)) {
      console.log(`  L${i+1}: ${lines[i].trim()}`);
    }
  }
}

main().catch(e => { console.error(e); process.exit(1); });
