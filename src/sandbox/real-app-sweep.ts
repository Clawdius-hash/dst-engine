/**
 * Real app sweep — scan ALL Java files in a directory, report findings by CWE.
 * Usage: npx tsx src/services/dst/sandbox/real-app-sweep.ts <directory>
 */

import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { resetSequence } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const targetDir = process.argv[2] ?? 'C:/Users/pizza/vigil/WebGoat';

function findJavaFiles(dir: string): string[] {
  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'target' && entry.name !== 'build') {
        results.push(...findJavaFiles(full));
      } else if (entry.isFile() && entry.name.endsWith('.java')) {
        results.push(full);
      }
    }
  } catch {}
  return results;
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
  const verifierMod = await import('../verifier/index.js');
  const runVerifiers = verifierMod.verifyAll ?? verifierMod.default?.verifyAll;

  const files = findJavaFiles(targetDir);
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  REAL APP SWEEP: ${targetDir}`);
  console.log(`  ${files.length} Java files found`);
  console.log(`${'='.repeat(60)}\n`);

  const findings: { file: string; cwe: string; name: string; detail: string }[] = [];
  let scanned = 0;
  let errors = 0;

  for (const file of files) {
    const code = fs.readFileSync(file, 'utf-8');
    resetSequence();
    try {
      const tree = parser.parse(code);
      if (!tree) { errors++; continue; }
      const { map } = buildNeuralMap(tree, code, path.basename(file), javaProfile);
      tree.delete();

      if (runVerifiers) {
        const results = runVerifiers(map);
        for (const r of results) {
          if (!r.holds && r.findings && r.findings.length > 0) {
            const relPath = path.relative(targetDir, file).replace(/\\/g, '/');
            for (const f of r.findings) {
              findings.push({
                file: relPath,
                cwe: r.cwe,
                name: r.name,
                detail: f.detail || f.message || f.via || '',
              });
            }
          }
        }
      }
    } catch (e) {
      errors++;
    }

    scanned++;
    if (scanned % 100 === 0) console.log(`  ${scanned}/${files.length}...`);
  }

  // Group by CWE
  const byCWE = new Map<string, { name: string; files: Set<string>; details: string[] }>();
  for (const f of findings) {
    const key = f.cwe;
    if (!byCWE.has(key)) byCWE.set(key, { name: f.name, files: new Set(), details: [] });
    const entry = byCWE.get(key)!;
    entry.files.add(f.file);
    if (entry.details.length < 5) entry.details.push(`${f.file}: ${f.detail.substring(0, 100)}`);
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  RESULTS — ${scanned} files scanned, ${errors} errors`);
  console.log(`  ${findings.length} total findings across ${byCWE.size} CWE categories`);
  console.log(`${'='.repeat(60)}\n`);

  // Sort by file count
  const sorted = [...byCWE.entries()].sort((a, b) => b[1].files.size - a[1].files.size);

  for (const [cwe, data] of sorted) {
    console.log(`${cwe} — ${data.name} (${data.files.size} files, ${findings.filter(f => f.cwe === cwe).length} findings)`);
    for (const d of data.details) {
      console.log(`  ${d}`);
    }
    console.log();
  }

  // Summary table
  console.log(`${'CWE'.padEnd(10)} ${'Name'.padEnd(40)} ${'Files'.padStart(5)} ${'Findings'.padStart(8)}`);
  console.log('-'.repeat(65));
  for (const [cwe, data] of sorted) {
    const count = findings.filter(f => f.cwe === cwe).length;
    console.log(`${cwe.padEnd(10)} ${data.name.substring(0, 40).padEnd(40)} ${String(data.files.size).padStart(5)} ${String(count).padStart(8)}`);
  }
  console.log('-'.repeat(65));
  console.log(`${'TOTAL'.padEnd(10)} ${''.padEnd(40)} ${String(new Set(findings.map(f => f.file)).size).padStart(5)} ${String(findings.length).padStart(8)}`);
}

main().catch(e => { console.error(e); process.exit(1); });
