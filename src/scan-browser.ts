/**
 * DST Browser API — browser-compatible scan for the AppsBuilderView pipeline.
 *
 * Unlike scan.ts (which uses Node.js fs to load WASM), this module uses the
 * browser-compatible parser.ts that fetches WASM over HTTP from /public/.
 *
 * Usage:
 *   import { scanCodeBrowser, initDSTBrowser } from './scan-browser';
 *   await initDSTBrowser();
 *   const result = await scanCodeBrowser(code, 'app.js');
 */

import { parseJS } from './parser';
import { buildNeuralMap } from './mapper';
import { verifyAll } from './verifier';
import { resetSequence } from './types';
import type { SecurityFinding, ScanResult } from './scan';

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

let _ready = false;
let _initPromise: Promise<void> | null = null;

/**
 * Initialize the browser-side DST engine. Must be called once before scanning.
 * Safe to call multiple times — subsequent calls are no-ops.
 * Uses the browser parser (WASM loaded via HTTP from /public/).
 */
export async function initDSTBrowser(): Promise<void> {
  if (_ready) return;
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    // Warm the parser — parseJS calls ensureInit internally
    const testTree = await parseJS('const x = 1;');
    if (testTree) {
      testTree.delete();
      _ready = true;
    } else {
      throw new Error('DST Browser: tree-sitter failed to initialize');
    }
  })();

  return _initPromise;
}

// ---------------------------------------------------------------------------
// Core scan function (browser-compatible)
// ---------------------------------------------------------------------------

/**
 * Scan JavaScript/TypeScript source for security vulnerabilities.
 * Browser-compatible — uses HTTP-loaded WASM instead of filesystem.
 *
 * For AI-generated code in the builder pipeline, runs in 'ai_generated' mode
 * which checks all CWEs (hand-written + generated).
 */
export async function scanCodeBrowser(
  code: string,
  filename: string = 'input.js',
): Promise<ScanResult> {
  if (!_ready) {
    await initDSTBrowser();
  }

  // Parse with browser-compatible parser
  resetSequence();
  const tree = await parseJS(code);

  if (!tree) {
    return {
      filename,
      propertiesChecked: 0,
      propertiesPassed: 0,
      propertiesFailed: 0,
      findings: [],
      stats: { nodes: 0, edges: 0, taintedFlows: 0 },
    };
  }

  let map;
  try {
    ({ map } = buildNeuralMap(tree, code, filename));
  } finally {
    tree.delete();
  }

  // Run all CWE verifiers
  const results = verifyAll(map);

  // Convert to SecurityFinding format
  const findings: SecurityFinding[] = [];
  let passed = 0;
  let failed = 0;

  for (const result of results) {
    if (result.holds) {
      passed++;
    } else {
      failed++;
      for (const f of result.findings) {
        findings.push({
          cwe: result.cwe,
          name: result.name,
          severity: f.severity,
          source: {
            label: f.source.label,
            line: f.source.line,
            code: f.source.code,
          },
          sink: {
            label: f.sink.label,
            line: f.sink.line,
            code: f.sink.code,
          },
          missing: f.missing,
          description: f.description,
          fix: f.fix,
        });
      }
    }
  }

  // Sort by severity: critical > high > medium > low
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  // Stats
  const taintedFlows = map.nodes.reduce(
    (sum, n) => sum + n.data_in.filter(d => d.tainted).length, 0
  );

  return {
    filename,
    propertiesChecked: results.length,
    propertiesPassed: passed,
    propertiesFailed: failed,
    findings,
    stats: {
      nodes: map.nodes.length,
      edges: map.edges.length,
      taintedFlows,
    },
  };
}

/**
 * Quick check — returns true if code has any critical or high severity findings.
 */
export async function hasSecurityIssuesBrowser(code: string, filename?: string): Promise<boolean> {
  const result = await scanCodeBrowser(code, filename);
  return result.findings.some(f => f.severity === 'critical' || f.severity === 'high');
}
