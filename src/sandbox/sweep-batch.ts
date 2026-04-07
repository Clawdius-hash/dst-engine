/**
 * Batch sweep: scan SQLi benchmark files and report proof coverage.
 * Usage: npx tsx src/services/dst/sandbox/sweep-batch.ts [count]
 */

import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { verifyAll } from '../verifier/index.js';
import { resetSequence } from '../types.js';
import { generateProof } from '../payload-gen.js';
import * as fs from 'fs';
import * as path from 'path';

const benchDir = 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
const batchSize = parseInt(process.argv[2] ?? '100', 10);

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

  // Find SQLi files
  const allFiles = fs.readdirSync(benchDir)
    .filter(f => f.startsWith('BenchmarkTest') && f.endsWith('.java'));

  const sqliFiles: string[] = [];
  for (const f of allFiles) {
    const code = fs.readFileSync(path.join(benchDir, f), 'utf-8');
    if (code.includes('sqli-')) sqliFiles.push(f);
  }

  console.log(`SQLi files found: ${sqliFiles.length}`);
  console.log(`Processing first ${batchSize}...`);

  let detected = 0, missed = 0, withProof = 0, goodRoutes = 0, errors = 0;
  const paramDist = new Map<string, number>();

  const batch = sqliFiles.slice(0, batchSize);
  for (let i = 0; i < batch.length; i++) {
    const file = batch[i];
    try {
      const code = fs.readFileSync(path.join(benchDir, file), 'utf-8');
      resetSequence();
      const tree = parser.parse(code);
      if (!tree) { errors++; continue; }
      const { map } = buildNeuralMap(tree, code, file, javaProfile);
      tree.delete();
      const results = verifyAll(map, 'java');
      const sqli = results.find(r => r.cwe === 'CWE-89');

      if (sqli && !sqli.holds && sqli.findings.length > 0) {
        detected++;
        const proof = generateProof(map, sqli.findings[0], 'CWE-89');
        if (proof) {
          withProof++;
          const p = proof.delivery?.http?.path ?? '/';
          if (p !== '/') goodRoutes++;
          const param = proof.delivery?.http?.param
            ?? proof.delivery?.http?.header
            ?? 'none';
          paramDist.set(param, (paramDist.get(param) ?? 0) + 1);
        }
      } else {
        missed++;
      }
    } catch (e: any) {
      errors++;
      if (errors <= 3) console.error(`  ERROR in ${file}: ${e.message?.substring(0, 120)}`);
    }

    if ((i + 1) % 25 === 0) {
      console.log(`  ${i + 1}/${batch.length}...`);
    }
  }

  console.log('');
  console.log('=== OWASP BENCHMARK SQLi SWEEP ===');
  console.log(`Files scanned: ${batch.length}`);
  console.log(`Detected (CWE-89): ${detected}`);
  console.log(`Not detected: ${missed}`);
  console.log(`Errors: ${errors}`);
  console.log(`Detection rate: ${(detected / batch.length * 100).toFixed(1)}%`);
  console.log(`With ProofCertificates: ${withProof}`);
  console.log(`Route paths extracted: ${goodRoutes}`);
  console.log(`Param types: ${JSON.stringify(Object.fromEntries(paramDist))}`);
}

main().catch(e => { console.error(e); process.exit(1); });
