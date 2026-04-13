
import { Parser, Language } from 'web-tree-sitter';
import { verifyAll, formatReport, registeredCWEs } from './verifier';
import { buildNeuralMap } from './mapper';
import { resetSequence } from './types';
import type { NeuralMap } from './types';
import type { LanguageProfile } from './languageProfile';
import { buildDependencyGraph } from './cross-file';
import { runMarginPass } from './margin-pass';
import { composeFindings } from './composition/index.js';
import type { ComposableFinding } from './composition/types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface LanguageConfig {
  grammarPackage: string;
  profileImport: string;
}

const LANGUAGE_MAP: Record<string, LanguageConfig> = {
  '.js':  { grammarPackage: 'tree-sitter-javascript', profileImport: 'javascript' },
  '.mjs': { grammarPackage: 'tree-sitter-javascript', profileImport: 'javascript' },
  '.cjs': { grammarPackage: 'tree-sitter-javascript', profileImport: 'javascript' },
  '.ts':  { grammarPackage: 'tree-sitter-javascript', profileImport: 'javascript' },
  '.py':  { grammarPackage: 'tree-sitter-python',     profileImport: 'python' },
  '.go':  { grammarPackage: 'tree-sitter-go',         profileImport: 'go' },
  '.rs':  { grammarPackage: 'tree-sitter-rust',       profileImport: 'rust' },
  '.java': { grammarPackage: 'tree-sitter-java',      profileImport: 'java' },
  '.php':  { grammarPackage: 'tree-sitter-php',       profileImport: 'php' },
  '.phtml': { grammarPackage: 'tree-sitter-php',      profileImport: 'php' },
  '.rb':   { grammarPackage: 'tree-sitter-ruby',      profileImport: 'ruby' },
  '.rake': { grammarPackage: 'tree-sitter-ruby',      profileImport: 'ruby' },
  '.cs':  { grammarPackage: 'tree-sitter-c-sharp',    profileImport: 'csharp' },
  '.kt':  { grammarPackage: '@tree-sitter-grammars/tree-sitter-kotlin', profileImport: 'kotlin' },
  '.kts': { grammarPackage: '@tree-sitter-grammars/tree-sitter-kotlin', profileImport: 'kotlin' },
  '.swift': { grammarPackage: 'tree-sitter-swift', profileImport: 'swift' },
};

const SCANNABLE_EXTENSIONS = new Set(Object.keys(LANGUAGE_MAP));

function detectLanguage(filename: string): LanguageConfig {
  const ext = path.extname(filename).toLowerCase();
  return LANGUAGE_MAP[ext] ?? LANGUAGE_MAP['.js'];
}

const _parsers = new Map<string, InstanceType<typeof Parser>>();
const _profiles = new Map<string, LanguageProfile>();

async function getParser(grammarPackage: string): Promise<InstanceType<typeof Parser>> {
  if (_parsers.has(grammarPackage)) return _parsers.get(grammarPackage)!;

  await Parser.init();
  const parser = new Parser();

  let wasmPath = path.resolve(
    __dirname,
    `../node_modules/${grammarPackage}/${grammarPackage}.wasm`
  );

  if (!fs.existsSync(wasmPath)) {
    const underscoreName = grammarPackage.replace(/-/g, '_');
    const altPath = path.resolve(
      __dirname,
      `../node_modules/${grammarPackage}/${underscoreName}.wasm`
    );
    if (fs.existsSync(altPath)) {
      wasmPath = altPath;
    }
  }

  if (!fs.existsSync(wasmPath) && grammarPackage.startsWith('@')) {
    const baseName = grammarPackage.split('/').pop()!;
    const scopedPath = path.resolve(
      __dirname,
      `../node_modules/${grammarPackage}/${baseName}.wasm`
    );
    if (fs.existsSync(scopedPath)) {
      wasmPath = scopedPath;
    }
  }

  if (!fs.existsSync(wasmPath)) {
    console.error(
      `${grammarPackage} WASM not found at:\n  ${wasmPath}\n\n` +
      `Run: npm install ${grammarPackage}`
    );
    process.exit(1);
  }

  const wasmBuffer = fs.readFileSync(wasmPath);
  const lang = await Language.load(wasmBuffer);
  parser.setLanguage(lang);

  _parsers.set(grammarPackage, parser);
  return parser;
}

async function getProfile(profileName: string): Promise<LanguageProfile> {
  if (_profiles.has(profileName)) return _profiles.get(profileName)!;

  const mod = await import(`./profiles/${profileName}.js`);
  const profile = mod.default ?? mod[`${profileName}Profile`] ?? mod.profile;
  if (!profile) {
    console.error(`Could not load profile '${profileName}' from ./profiles/${profileName}.js`);
    process.exit(1);
  }

  _profiles.set(profileName, profile);
  return profile;
}

function stripTypeScriptAnnotations(source: string): string {
  let result = source;

  result = result.replace(/^import\s+type\s+.*$/gm, match => ' '.repeat(match.length));

  result = result.replace(/\bimport\s*\{[^}]*\}/g, match => {
    return match.replace(/\btype\s+/g, sub => ' '.repeat(sub.length));
  });

  result = result.replace(/^(export\s+)?(interface|type)\s+\w+[\s\S]*?(?=\n(?:export|import|const|let|var|function|class|module|\/\/|\/\*|\n|$))/gm, match => {
    return match.replace(/[^\n]/g, ' ');
  });

  result = result.replace(/!(?=\.|\.?\[|\()/g, ' ');

  result = result.replace(/\bas\s+[A-Z]\w*(\s*\[?\]?)*/g, match => ' '.repeat(match.length));

  result = result.replace(/(?<=\w)<[^<>]*(?:<[^<>]*>[^<>]*)*>/g, match => ' '.repeat(match.length));

  result = result.replace(/([\]}])\s*:\s*([A-Z]\w*(?:\[\]|\s*\|\s*\w+)*)\s*(?=[,)=])/g, (match, bracket) => {
    return bracket + ' '.repeat(match.length - bracket.length);
  });

  result = result.replace(/(\w)\s*:\s*([A-Z]\w*(?:\[\]|\s*\|\s*\w+)*)\s*(?=[,)=])/g, (match, name) => {
    return name + ' '.repeat(match.length - name.length);
  });

  result = result.replace(/(let|const|var)\s+(\w+)\s*:\s*(\w+(?:\[\]|\s*\|\s*\w+)*)\s*(?==)/g, (match, keyword, varName) => {
    return keyword + ' ' + varName + ' '.repeat(match.length - keyword.length - 1 - varName.length);
  });

  result = result.replace(/\)\s*:\s*([A-Z]\w*(?:\[\]|\s*\|\s*\w+)*)\s*(?=[{=>])/g, (match) => {
    return ')' + ' '.repeat(match.length - 1);
  });

  return result;
}

/** Summary data extracted from the mapper context after scanning one file.
 *  Used by the cross-file margin pass to propagate taint across file boundaries.
 *
 *  Kept: functionReturnTaint, functionRegistry (needed for cross-file resolution).
 *  Dropped: scopeStack (walk-time only), nodeById (rebuildable from map.nodes),
 *  edgeSet (derived), sentences (on map.story), taintLog (debug provenance —
 *  add back if proof system needs it), pendingCallbackTaint (usually empty post-walk),
 *  diagnostics (per-file stats), profile (stateless, re-created per file). */
interface FileSummary {
  map: NeuralMap;
  functionReturnTaint: Map<string, boolean>;
  functionRegistry: Map<string, string>;
  functionSinkContext?: Map<string, Set<string>>;
}

async function analyzeWithRealMapper(source: string, filename: string): Promise<FileSummary> {
  const langConfig = detectLanguage(filename);
  const parser = await getParser(langConfig.grammarPackage);
  const profile = await getProfile(langConfig.profileImport);

  const ext = path.extname(filename).toLowerCase();
  const parseSource = (ext === '.ts' || ext === '.tsx')
    ? stripTypeScriptAnnotations(source)
    : source;

  const tree = parser.parse(parseSource);

  if (!tree) {
    console.error('tree-sitter failed to parse: ' + filename);
    process.exit(1);
  }

  resetSequence();
  const { map, ctx } = buildNeuralMap(tree, source, filename, profile);

  tree.delete();

  return {
    map,
    functionReturnTaint: ctx.functionReturnTaint,
    functionRegistry: ctx.functionRegistry,
  };
}

function printHeader(mode: string): void {
  const cweCount = registeredCWEs().length;
  const countLabel = `Deterministic Security Testing — ${cweCount} CWE Properties`;
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║          DST VERIFICATION ENGINE v0.2                   ║');
  console.log(`║   ${countLabel.padEnd(53)}║`);
  console.log('║   tree-sitter Neural Map → Graph Query → Pass/Fail     ║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log(`║   Mode: ${mode.padEnd(47)}║`);
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
}

function printMapStats(map: NeuralMap): void {
  const typeCounts: Record<string, number> = {};
  for (const node of map.nodes) {
    typeCounts[node.node_type] = (typeCounts[node.node_type] ?? 0) + 1;
  }

  const edgeTypeCounts: Record<string, number> = {};
  for (const edge of map.edges) {
    edgeTypeCounts[edge.edge_type] = (edgeTypeCounts[edge.edge_type] ?? 0) + 1;
  }

  const taintedFlows = map.nodes.reduce((count, n) => {
    return count + n.data_in.filter(d => d.tainted).length +
                   n.data_out.filter(d => d.tainted).length;
  }, 0);

  console.log(`Neural Map: ${map.nodes.length} nodes, ${map.edges.length} edges`);
  console.log(`  Nodes by type: ${Object.entries(typeCounts).map(([t, c]) => `${t}(${c})`).join(', ')}`);
  if (Object.keys(edgeTypeCounts).length > 0) {
    console.log(`  Edges by type: ${Object.entries(edgeTypeCounts).map(([t, c]) => `${t}(${c})`).join(', ')}`);
  }
  console.log(`  Tainted data flows: ${taintedFlows}`);
  console.log(`  CWE properties to check: ${registeredCWEs().length}`);
  console.log('');
}

const DEMO_CODE = `
const express = require('express');
const db = require('./db');
const fetch = require('node-fetch');
const { exec } = require('child_process');
const app = express();

// SQL Injection — string concatenation
app.post('/users/search', (req, res) => {
  var query = "SELECT name FROM Users WHERE login='" + req.body.login + "'";
  db.query(query, (err, results) => {
    res.render('search', { results: results });
  });
});

// XSS — reflected user input
app.get('/welcome', (req, res) => {
  res.send('<h1>Welcome, ' + req.query.name + '!</h1>');
});

// SSRF — user-controlled URL
app.get('/proxy', (req, res) => {
  fetch(req.query.url)
    .then(r => r.text())
    .then(body => res.send(body));
});

// Command injection
app.get('/convert', (req, res) => {
  exec("ffmpeg -i " + req.query.file + " output.mp4");
});

// Hardcoded credentials
const dbConfig = {
  host: "localhost",
  password: "SuperSecretPassword123",
  api_key: "sk_live_abc123def456"
};

// Missing auth on delete
app.delete('/users/:id', (req, res) => {
  db.query("DELETE FROM users WHERE id = " + req.params.id);
  res.json({ deleted: true });
});

app.listen(3000);
`;

function collectSourceFiles(dir: string): string[] {
  const files: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '__pycache__', 'venv', '.venv', 'env'].includes(entry.name)) {
        continue;
      }
      files.push(...collectSourceFiles(fullPath));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      const isEnvFile = entry.name === '.env' || entry.name.startsWith('.env.');
      if (!SCANNABLE_EXTENSIONS.has(ext) && !isEnvFile) continue;
      if (entry.name.includes('.test.') || entry.name.includes('.spec.') ||
          entry.name.includes('.min.') || entry.name.includes('.bundle.')) {
        continue;
      }
      files.push(fullPath);
    }
  }

  return files;
}

interface FileResult {
  filename: string;
  map: NeuralMap;
  results: ReturnType<typeof verifyAll>;
}

function printFileReport(fr: FileResult): void {
  const failed = fr.results.filter(r => !r.holds);
  if (failed.length === 0) return;

  console.log(`\n${'━'.repeat(60)}`);
  console.log(`  ${fr.filename}`);
  console.log(`  ${fr.map.nodes.length} nodes, ${fr.map.edges.length} edges`);
  console.log(`${'━'.repeat(60)}`);

  for (const r of failed) {
    for (const f of r.findings) {
      const icon = f.severity === 'critical' ? '!!!' :
                   f.severity === 'high' ? ' !!' :
                   f.severity === 'medium' ? '  !' : '   ';
      console.log(`  ${icon} ${r.cwe}: ${r.name}`);
      console.log(`      ${f.description.slice(0, 120)}`);
      console.log(`      L${f.source.line}: ${f.source.code.slice(0, 80)}`);
      console.log('');
    }
  }
}

function printSummary(allResults: FileResult[], elapsed: number): void {
  const totalNodes = allResults.reduce((s, r) => s + r.map.nodes.length, 0);
  const totalEdges = allResults.reduce((s, r) => s + r.map.edges.length, 0);

  let totalFindings = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  const cweHits = new Map<string, number>();

  for (const fr of allResults) {
    for (const r of fr.results) {
      if (!r.holds) {
        for (const f of r.findings) {
          totalFindings++;
          if (f.severity === 'critical') criticalCount++;
          else if (f.severity === 'high') highCount++;
          else mediumCount++;
          cweHits.set(r.cwe, (cweHits.get(r.cwe) ?? 0) + 1);
        }
      }
    }
  }

  const cleanFiles = allResults.filter(fr => fr.results.every(r => r.holds)).length;

  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║                    SCAN COMPLETE                        ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`  Files scanned:  ${allResults.length}`);
  console.log(`  Clean files:    ${cleanFiles}`);
  console.log(`  Total nodes:    ${totalNodes}`);
  console.log(`  Total edges:    ${totalEdges}`);
  console.log(`  Time:           ${elapsed}ms`);
  console.log('');

  if (totalFindings === 0) {
    console.log(`  No findings. All ${registeredCWEs().length} CWE properties verified clean across all files.`);
  } else {
    console.log(`  ${totalFindings} finding(s):`);
    if (criticalCount > 0) console.log(`    ${criticalCount} CRITICAL`);
    if (highCount > 0) console.log(`    ${highCount} HIGH`);
    if (mediumCount > 0) console.log(`    ${mediumCount} MEDIUM`);
    console.log('');

    const sorted = [...cweHits.entries()].sort((a, b) => b[1] - a[1]);
    console.log('  Most common:');
    for (const [cwe, count] of sorted.slice(0, 5)) {
      console.log(`    ${cwe}: ${count} occurrence(s)`);
    }
  }

  console.log('');
  console.log('─'.repeat(50));
  console.log('  Deterministic: same code → same report. Always.');
  console.log('─'.repeat(50));
}

async function enrichWithProofs(
  results: ReturnType<typeof verifyAll>,
  map: NeuralMap,
  fileSummaries?: Map<string, FileSummary>,
): Promise<void> {
  const { generateProof } = await import('./payload-gen.js');

  // Build name-keyed sink context for proof generation.
  // functionSinkContext is keyed by nodeId; cross_file_param_taint_via_*
  // data_in entries use function NAMEs, so we reverse-lookup via functionRegistry.
  let sinkContext: Map<string, Set<string>> | undefined;
  if (fileSummaries) {
    sinkContext = new Map<string, Set<string>>();
    for (const [, summary] of fileSummaries) {
      if (!summary.functionSinkContext) continue;
      // Reverse lookup: nodeId -> funcName from functionRegistry
      const nodeIdToName = new Map<string, string>();
      for (const [name, nodeId] of summary.functionRegistry) {
        if (!name.includes(':')) nodeIdToName.set(nodeId, name);
      }
      for (const [nodeId, subtypes] of summary.functionSinkContext) {
        const name = nodeIdToName.get(nodeId) || nodeId;
        const existing = sinkContext.get(name);
        if (existing) {
          for (const s of subtypes) existing.add(s);
        } else {
          sinkContext.set(name, new Set(subtypes));
        }
      }
    }
    if (sinkContext.size === 0) sinkContext = undefined;
  }

  const PAYLOAD_CLASS_TO_CWE: Record<string, string> = {
    sql_injection: 'CWE-89', command_injection: 'CWE-78', xss: 'CWE-79',
    path_traversal: 'CWE-22', ldap_injection: 'CWE-90', xpath_injection: 'CWE-643',
    xxe: 'CWE-611', deserialization: 'CWE-502', open_redirect: 'CWE-601',
    log_injection: 'CWE-117', ssti: 'CWE-1336',
  };
  const PAYLOAD_CLASS_TO_NAME: Record<string, string> = {
    sql_injection: 'SQL Injection', command_injection: 'OS Command Injection',
    xss: 'Cross-site Scripting (XSS)', path_traversal: 'Path Traversal',
    ldap_injection: 'LDAP Injection', xpath_injection: 'XPath Injection',
    xxe: 'XML External Entity (XXE)', deserialization: 'Deserialization of Untrusted Data',
    open_redirect: 'Open Redirect', log_injection: 'Log Injection',
    ssti: 'Server-Side Template Injection',
  };

  for (const result of results) {
    if (!result.holds) {
      for (const finding of result.findings) {
        const proof = generateProof(map, finding, result.cwe, sinkContext);
        if (proof) {
          (finding as any).proof = proof;

          if (proof.inferred_class) {
            const reclassifiedCWE = PAYLOAD_CLASS_TO_CWE[proof.inferred_class];
            if (reclassifiedCWE && reclassifiedCWE !== result.cwe) {
              result.cwe = reclassifiedCWE;
              result.name = PAYLOAD_CLASS_TO_NAME[proof.inferred_class] ?? result.name;
            }
          }
        }
      }
    }
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes('--json');
  const noDedup = args.includes('--no-dedup');
  const pedantic = args.includes('--pedantic');
  const proveMode = args.includes('--prove');
  const target = args.find(a => !a.startsWith('--'));
  const isDemo = args.includes('--demo') || !target;
  const verifyOptions = (noDedup || pedantic)
    ? { ...(noDedup ? { noDedup: true } : {}), ...(pedantic ? { pedanticMode: true } : {}) }
    : undefined;

  const startTime = Date.now();

  if (isDemo) {
    printHeader('DEMO — vulnerable Express app');
    console.log('Parsing with tree-sitter → building Neural Map...');
    console.log('');

    const { map } = await analyzeWithRealMapper(DEMO_CODE, 'demo-vulnerable-app.js');
    printMapStats(map);

    const results = verifyAll(map, 'javascript', verifyOptions);

    if (proveMode) await enrichWithProofs(results, map);

    if (jsonOutput) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      console.log(formatReport(results));

      const failed = results.filter(r => !r.holds);
      const criticals = failed.filter(r => r.findings.some(f => f.severity === 'critical'));
      const highs = failed.filter(r => r.findings.some(f => f.severity === 'high'));
      const totalFindings = failed.reduce((sum, r) => sum + r.findings.length, 0);

      console.log('');
      console.log('─'.repeat(50));
      console.log(`  ${totalFindings} finding(s) across ${failed.length} failed properties`);
      if (criticals.length > 0) console.log(`  ${criticals.length} CRITICAL`);
      if (highs.length > 0) console.log(`  ${highs.length} HIGH`);
      console.log(`  ${results.length - failed.length}/${results.length} properties verified clean`);
      console.log('─'.repeat(50));
      console.log('');
      console.log('Deterministic: same code → same report. Always.');
    }
    return;
  }

  const stat = fs.statSync(target!);

  if (stat.isFile()) {
    const source = fs.readFileSync(target!, 'utf-8');
    const langConfig = detectLanguage(target!);
    printHeader(target!);
    console.log('Parsing with tree-sitter → building Neural Map...');
    console.log('');

    const { map } = await analyzeWithRealMapper(source, target!);
    printMapStats(map);

    const results = verifyAll(map, langConfig.profileImport, verifyOptions);

    if (proveMode) await enrichWithProofs(results, map);

    if (jsonOutput) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      console.log(formatReport(results));

      const failed = results.filter(r => !r.holds);
      const totalFindings = failed.reduce((sum, r) => sum + r.findings.length, 0);
      const criticals = failed.filter(r => r.findings.some(f => f.severity === 'critical'));
      const highs = failed.filter(r => r.findings.some(f => f.severity === 'high'));

      console.log('');
      console.log('─'.repeat(50));
      console.log(`  ${totalFindings} finding(s) across ${failed.length} failed properties`);
      if (criticals.length > 0) console.log(`  ${criticals.length} CRITICAL`);
      if (highs.length > 0) console.log(`  ${highs.length} HIGH`);
      console.log(`  ${results.length - failed.length}/${results.length} properties verified clean`);
      console.log('─'.repeat(50));
      console.log('');
      console.log('Deterministic: same code → same report. Always.');
    }
  } else if (stat.isDirectory()) {
    const files = collectSourceFiles(target!);

    if (files.length === 0) {
      console.error(`No scannable files found in: ${target}`);
      process.exit(1);
    }

    printHeader(`SCAN: ${target} (${files.length} files)`);
    console.log('Scanning with tree-sitter → building Neural Maps...');
    console.log('');

    const allResults: FileResult[] = [];
    const fileSummaries = new Map<string, FileSummary>();
    let scanned = 0;

    for (const file of files) {
      scanned++;
      const shortName = path.relative(target!, file);
      process.stdout.write(`  [${scanned}/${files.length}] ${shortName}...`);

      try {
        const source = fs.readFileSync(file, 'utf-8');
        const fileLangConfig = detectLanguage(file);
        const summary = await analyzeWithRealMapper(source, file);
        const results = verifyAll(summary.map, fileLangConfig.profileImport, verifyOptions);

        if (proveMode) await enrichWithProofs(results, summary.map);

        const findings = results.filter(r => !r.holds).reduce((s, r) => s + r.findings.length, 0);

        fileSummaries.set(file.replace(/\\/g, '/'), summary);
        allResults.push({ filename: shortName, map: summary.map, results });

        if (findings > 0) {
          console.log(` ${findings} finding(s)`);
        } else {
          console.log(' clean');
        }
      } catch (err) {
        console.log(` ERROR: ${(err as Error).message?.slice(0, 60)}`);
      }
    }

    // ─── Cross-file margin pass ────────────────────────────────
    // Build dependency graph, then resolve PENDING sentences across
    // file boundaries using imported functions' summaries.
    // Same resolver mechanism as intra-file — different data source.
    // ─────────────────────────────────────────────────────────────
    if (allResults.length >= 2 && fileSummaries.size >= 2) {
      try {
        const depGraph = buildDependencyGraph(files.map(f => f.replace(/\\/g, '/')));
        const depEdgeCount = depGraph.edges.length;

        if (depEdgeCount > 0) {
          console.log('');
          console.log(`Cross-file analysis: ${depEdgeCount} import edges`);

          const dirty = runMarginPass(fileSummaries, depGraph);

          if (dirty.size > 0) {
            console.log(`  Margin pass resolved cross-file taint in ${dirty.size} file(s)`);

            // Re-verify dirty files — their sentences changed
            for (const dirtyFile of dirty) {
              const normalizedDirty = dirtyFile.replace(/\\/g, '/');
              const idx = allResults.findIndex(r =>
                dirtyFile.endsWith(r.filename.replace(/\\/g, '/')) ||
                normalizedDirty.endsWith(r.filename.replace(/\\/g, '/'))
              );
              if (idx === -1) continue;
              const summary = fileSummaries.get(normalizedDirty);
              if (!summary) continue;
              const fileLangConfig = detectLanguage(dirtyFile);
              const results = verifyAll(summary.map, fileLangConfig.profileImport, verifyOptions);
              if (proveMode) await enrichWithProofs(results, summary.map, fileSummaries);
              allResults[idx] = { filename: allResults[idx].filename, map: summary.map, results };
            }

            console.log(`  Re-verified ${dirty.size} file(s) with updated taint`);
          } else {
            console.log('  No cross-file taint propagation needed');
          }
        }
      } catch (err) {
        console.log(`  Cross-file analysis error: ${(err as Error).message?.slice(0, 80)}`);
      }
    }

    // ─── Cross-finding composition pass ────────────────────────────
    if (allResults.length >= 1) {
      const composable: ComposableFinding[] = [];
      for (const fr of allResults) {
        for (const result of fr.results) {
          if (result.holds) continue;
          for (const finding of result.findings) {
            // Look up NeuralMap nodes for AST-derived storage metadata
            const sinkNode = fr.map.nodes.find(n => n.id === finding.sink.id);
            const sourceNode = fr.map.nodes.find(n => n.id === finding.source.id);
            composable.push({
              cwe: result.cwe,
              file: fr.filename,
              finding,
              sinkStorageTarget: (sinkNode?.metadata?.storage_target as { kind: string; name: string } | undefined) ?? null,
              sourceStorageTarget: (sourceNode?.metadata?.storage_target as { kind: string; name: string } | undefined) ?? null,
              sinkTrustBoundary: sinkNode?.trust_boundary ?? '',
              sourceTrustBoundary: sourceNode?.trust_boundary ?? '',
            });
          }
        }
      }

      if (composable.length >= 2) {
        const chains = composeFindings(composable);
        if (chains.length > 0) {
          console.log(`\n  Exploit chains: ${chains.length} chain(s) detected`);
          for (const chain of chains) {
            console.log(`    [${chain.severity.toUpperCase()}] ${chain.description}`);
          }
        }
      }
    }

    if (jsonOutput) {
      const jsonResults = allResults.map(fr => ({
        file: fr.filename,
        nodes: fr.map.nodes.length,
        results: fr.results,
      }));
      console.log(JSON.stringify(jsonResults, null, 2));
    } else {
      for (const fr of allResults) {
        printFileReport(fr);
      }

      printSummary(allResults, Date.now() - startTime);
    }
  }
}

main().catch(err => {
  console.error('DST CLI error:', err);
  process.exit(1);
});
