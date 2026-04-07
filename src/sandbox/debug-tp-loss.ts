/**
 * Find TPs that became FNs — what changed?
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

  let newFNs = 0;
  for (const file of allFiles) {
    const testName = file.replace('.java', '');
    const isRealVuln = truth.get(testName) ?? false;
    if (!isRealVuln) continue; // only check real vulnerabilities

    const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
    resetSequence();
    const tree = parser.parse(code);
    const result = buildNeuralMap(tree, code, file, javaProfile);
    const map = result.map;
    tree.delete();

    const story = map.story || [];
    // Check for reconciled clean vars
    const resolvedClean = new Set<string>();
    for (const s of story) {
      if ((s as any).reconciled && s.taintClass === 'NEUTRAL') {
        const v = s.slots.subject || '';
        if (v) resolvedClean.add(v);
      }
    }

    // Check for concat sentences where a part is resolved clean
    for (const s of story) {
      if (s.templateKey === 'string-concatenation') {
        const parts = (s.slots.parts || '').split(/[,\s]+/).filter(Boolean);
        const anyResolved = parts.some(p => resolvedClean.has(p));
        if (anyResolved) {
          newFNs++;
          if (newFNs <= 10) {
            console.log(`${testName}: concat of [${parts.join(', ')}], resolved clean: [${parts.filter(p => resolvedClean.has(p)).join(', ')}]`);
            // Show the resolved sentence
            for (const rs of story) {
              if ((rs as any).reconciled) {
                console.log(`  RESOLVED: ${rs.text} | reason: ${(rs as any).reconciliationReason}`);
              }
            }
          }
        }
      }
    }
  }
  console.log(`\nTotal TPs with resolved-clean concat parts: ${newFNs}`);
}

main().catch(e => { console.error(e); process.exit(1); });
