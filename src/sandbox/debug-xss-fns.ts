/**
 * Find the 52 XSS FNs when V2 is authoritative.
 * What output methods are NOT being classified as EGRESS?
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

  // Find FNs: files where truth=vulnerable but V2 says clean
  const outputPatterns: Record<string, string[]> = {};
  let fnCount = 0;

  for (const file of allFiles) {
    const testName = file.replace('.java', '');
    const isRealVuln = truth.get(testName) ?? false;
    if (!isRealVuln) continue; // only check real vulns

    const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
    resetSequence();
    const tree = parser.parse(code);
    const { map } = buildNeuralMap(tree, code, file, javaProfile);
    tree.delete();

    // Check if V2 catches it (has writes-response with tainted args)
    const story = map.story || [];
    const hasWritesResponse = story.some(s =>
      s.templateKey === 'writes-response' && s.taintClass !== 'NEUTRAL'
    );

    if (!hasWritesResponse) {
      fnCount++;
      // Find what output method the file actually uses
      const lines = code.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const ln = lines[i];
        // Look for response output patterns
        if (ln.match(/response\.|println|print\(|write\(|send|getWriter|getOutputStream|forward|dispatch|include|redirect/i)) {
          const pattern = ln.trim().substring(0, 80);
          if (!pattern.includes('import') && !pattern.includes('//') && !pattern.startsWith('*')) {
            if (!outputPatterns[pattern]) outputPatterns[pattern] = [];
            if (outputPatterns[pattern].length < 3) outputPatterns[pattern].push(testName);
          }
        }
      }
    }
  }

  console.log(`\n=== XSS V2 FNs: ${fnCount} files missing writes-response ===\n`);

  // Group by output pattern, sort by frequency
  const sorted = Object.entries(outputPatterns)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 20);

  for (const [pattern, files] of sorted) {
    console.log(`[${files.length}x] ${pattern}`);
    console.log(`  e.g.: ${files[0]}`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
