/**
 * Verify the debug layer works against real data.
 * Tests: invariants (with summary), mapper diagnostics + timing, finding trace.
 */

import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from '../mapper.js';
import { verifyAll } from '../verifier/index.js';
import { checkMapInvariants, summarizeInvariants } from '../verifier/invariants.js';
import { tracePath } from '../verifier/finding-trace.js';
import { resetSequence } from '../types.js';
import * as fs from 'fs';
import * as path from 'path';

const testFile = process.argv[2]
  ?? 'C:/Users/pizza/vigil/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01010.java';

async function main() {
  await Parser.init();
  const parser = new Parser();
  const wasmDir = path.resolve(
    path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Z]:)/, '$1'),
    '../../node_modules'
  );
  const lang = await Language.load(fs.readFileSync(path.join(wasmDir, 'tree-sitter-java/tree-sitter-java.wasm')));
  parser.setLanguage(lang);
  const javaMod = await import('../profiles/java.js');
  const javaProfile = javaMod.default ?? javaMod.javaProfile ?? javaMod.profile;

  const code = fs.readFileSync(testFile, 'utf-8');
  resetSequence();
  const tree = parser.parse(code);
  if (!tree) { console.error('Parse failed'); return; }
  const { map, ctx } = buildNeuralMap(tree, code, path.basename(testFile), javaProfile);
  tree.delete();

  // === 1. INVARIANTS ===
  console.log('=== INVARIANT CHECK ===');
  try {
    const violations = checkMapInvariants(map);
    const summary = summarizeInvariants(map, violations);
    console.log(`Verdict: ${summary.verdict.toUpperCase()} (${summary.errors}E/${summary.warnings}W/${summary.info}I)`);
    console.log(`  Nodes: ${summary.totalNodes} total, ${summary.nodesWithDataFlow} with data flow, ${summary.structuralLeafNodes} structural leaf`);
    console.log(`  Data flow edges: ${summary.dataFlowEdgeCount}`);
    console.log(`  True orphans: ${summary.trueOrphanCount}`);
    console.log(`  Containers with no data flow: ${summary.containersWithNoDataFlow}`);
    if (violations.length > 0) {
      // Show errors and warnings, suppress info unless verbose
      const actionable = violations.filter(v => v.severity !== 'info');
      const infoCount = violations.length - actionable.length;
      if (actionable.length > 0) {
        console.log(`\n  Actionable violations (${actionable.length}):`);
        actionable.forEach(v => console.log(`    [${v.severity}] ${v.code}: ${v.message}`));
      }
      if (infoCount > 0) {
        console.log(`  (${infoCount} info-level diagnostics suppressed -- use --verbose to show)`);
      }
      // Show info-level in verbose mode
      if (process.argv.includes('--verbose')) {
        const infos = violations.filter(v => v.severity === 'info');
        if (infos.length > 0) {
          console.log(`\n  Info diagnostics (${infos.length}):`);
          infos.forEach(v => console.log(`    [info] ${v.code}: ${v.message}`));
        }
      }
    } else {
      console.log('  All 12 invariants PASS');
    }
  } catch (e: any) {
    console.error('  INVARIANTS CRASHED:', e.message);
  }

  // === 2. MAPPER DIAGNOSTICS ===
  console.log('\n=== MAPPER DIAGNOSTICS ===');
  try {
    const d = (ctx as any).diagnostics;
    if (d) {
      console.log(`Total calls: ${d.totalCalls}`);
      console.log(`Unmapped calls: ${d.unmappedCalls}`);
      console.log(`Dropped flows: ${d.droppedFlows}`);
      console.log(`Dropped edges: ${d.droppedEdges}`);
      if (d.totalCalls > 0) {
        console.log(`Coverage: ${((d.totalCalls - d.unmappedCalls) / d.totalCalls * 100).toFixed(1)}%`);
      }
      if (d.timing) {
        console.log(`Timing: walk=${d.timing.walkMs}ms, post-process=${d.timing.postProcessMs}ms, total=${d.timing.totalMs}ms`);
      }
      // sourceLineFallbacks derived from findings post-verification (see below)
    } else {
      console.error('  diagnostics object NOT FOUND on ctx');
    }
  } catch (e: any) {
    console.error('  DIAGNOSTICS CRASHED:', e.message);
  }

  // === 3. VERIFICATION + FINDING TRACE ===
  console.log('\n=== CWE-89 VERIFICATION ===');
  try {
    const results = verifyAll(map, 'java');
    const fallbackCount = results.reduce((n, r) => n + r.findings.filter(f => f.via === 'source_line_fallback').length, 0);
    if (fallbackCount > 0) {
      console.log(`Source-line fallbacks: ${fallbackCount} (findings via source_line_fallback)`);
    }
    const sqli = results.find(r => r.cwe === 'CWE-89');
    if (sqli) {
      console.log(`Holds: ${sqli.holds}`);
      console.log(`Findings: ${sqli.findings.length}`);
      if (sqli.findings.length > 0) {
        const f = sqli.findings[0];
        console.log(`  Source: ${f.source.label} (line ${f.source.line})`);
        console.log(`  Sink: ${f.sink.label} (line ${f.sink.line})`);

        // === 4. FINDING TRACE ===
        console.log('\n=== FINDING TRACE ===');
        try {
          const trace = tracePath(map, f.source.id, f.sink.id, 'CONTROL');
          console.log(`Verdict: ${trace.verdict}`);
          console.log(`Reached sink: ${trace.reached_sink}`);
          console.log(`Nodes visited: ${trace.nodes_visited}`);
          console.log(`Gates evaluated: ${trace.gates_evaluated.length}`);
          if (trace.path) {
            console.log(`Path (${trace.path.length} nodes):`);
            trace.path.forEach((n, i) => {
              console.log(`  ${i}: [${n.node_type}:${n.node_subtype}] ${n.label} (line ${n.line})`);
            });
          }
          trace.gates_evaluated.forEach(g => {
            console.log(`  Gate: ${g.node.label} -- effective=${g.effective}, reason=${g.reason}`);
          });
          if (trace.dead_ends.length > 0) {
            console.log(`Dead ends: ${trace.dead_ends.length}`);
            trace.dead_ends.forEach(d => console.log(`  ${d.label} (line ${d.line})`));
          }
        } catch (e: any) {
          console.error('  TRACE CRASHED:', e.message);
        }
      }
    } else {
      console.log('CWE-89 not in results');
    }
  } catch (e: any) {
    console.error('  VERIFICATION CRASHED:', e.message);
  }

  // === 5. NODE SUMMARY ===
  console.log('\n=== NODE SUMMARY ===');
  const typeCounts = new Map<string, number>();
  map.nodes.forEach(n => typeCounts.set(n.node_type, (typeCounts.get(n.node_type) ?? 0) + 1));
  typeCounts.forEach((count, type) => console.log(`  ${type}: ${count}`));

  // Check for STORAGE nodes that might be misclassified collections
  const storageSinks = map.nodes.filter(n => n.node_type === 'STORAGE');
  if (storageSinks.length > 0) {
    console.log('\n=== STORAGE NODES (potential fake sinks) ===');
    storageSinks.forEach(n => {
      console.log(`  ${n.id}: ${n.node_subtype} -- ${n.label} (line ${n.line_start})`);
    });
  }
}

main().catch(e => { console.error(e); process.exit(1); });
