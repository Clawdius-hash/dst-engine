/**
 * DST Library API — programmatic access to the DST verification engine.
 *
 * Use this instead of dst-cli.ts when you need DST as a function call
 * inside a larger pipeline (e.g., the copilot builder flow).
 *
 * Usage:
 *   import { scanCode, initDST } from './scan';
 *   await initDST();
 *   const findings = await scanCode(sourceCode, 'app.js');
 */

import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper';
import { verifyAll } from './verifier';
import { resetSequence } from './types';
import type { NeuralMap } from './types';
import type { VerificationResult, Finding } from './verifier';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SecurityFinding {
  /** CWE identifier (e.g., "CWE-89") */
  cwe: string;
  /** Human-readable CWE name */
  name: string;
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Source of the tainted data */
  source: { label: string; line: number; code: string };
  /** Sink where the vulnerability manifests */
  sink: { label: string; line: number; code: string };
  /** What control/mitigation is missing */
  missing: string;
  /** Plain-language description */
  description: string;
  /** Remediation guidance */
  fix: string;
}

export interface DSTManifest {
  name: string;
  intentional_sinks: Array<{
    files: string[];
    patterns: string[];
    type: string;
    reason: string;
  }>;
  data_origins?: Array<{
    field: string;
    expected_source: 'STORAGE' | 'META' | 'AUTH';
    reason: string;
  }>;
  scan_policy: {
    cwes: string;
    exclude_intentional: boolean;
    severity_threshold: string;
  };
}

export type ScanMode = 'first_party' | 'ai_generated' | 'full';

export interface ScanResult {
  /** Source filename */
  filename: string;
  /** Total CWE properties checked */
  propertiesChecked: number;
  /** Properties that held (no vulnerability found) */
  propertiesPassed: number;
  /** Properties that failed (vulnerability found) */
  propertiesFailed: number;
  /** Individual findings, sorted by severity */
  findings: SecurityFinding[];
  /** Neural map stats */
  stats: {
    nodes: number;
    edges: number;
    taintedFlows: number;
  };
}

// ---------------------------------------------------------------------------
// Parser singleton
// ---------------------------------------------------------------------------

let _parser: InstanceType<typeof Parser> | null = null;
let _initPromise: Promise<void> | null = null;

/**
 * Initialize the DST engine. Must be called once before scanCode().
 * Safe to call multiple times — subsequent calls are no-ops.
 */
export async function initDST(): Promise<void> {
  if (_parser) return;
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    await Parser.init();
    _parser = new Parser();

    const wasmPath = path.resolve(
      __dirname,
      '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm'
    );

    if (!fs.existsSync(wasmPath)) {
      throw new Error(
        'DST: tree-sitter-javascript WASM not found at: ' + wasmPath +
        '\nRun: npm install tree-sitter-javascript'
      );
    }

    const wasmBuffer = fs.readFileSync(wasmPath);
    const JavaScript = await Language.load(wasmBuffer);
    _parser.setLanguage(JavaScript);
  })();

  return _initPromise;
}

// ---------------------------------------------------------------------------
// Core scan function
// ---------------------------------------------------------------------------

/**
 * Scan JavaScript/TypeScript source code for security vulnerabilities.
 *
 * Returns a structured result with findings sorted by severity.
 * Each finding maps to a specific CWE with source, sink, and remediation.
 *
 * @param code - Source code to scan
 * @param filename - Filename (used for reporting and language detection)
 * @returns Scan result with findings
 */
export async function scanCode(
  code: string,
  filename: string = 'input.js',
  options?: { manifest?: DSTManifest; mode?: ScanMode },
): Promise<ScanResult> {
  if (!_parser) {
    await initDST();
  }

  // Parse and build neural map
  resetSequence();
  const tree = _parser!.parse(code);

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

  const { map } = buildNeuralMap(tree, code, filename);
  tree.delete();

  // Run all CWE verifiers, filtering platform-specific CWEs for web languages
  const ext = path.extname(filename).toLowerCase();
  const scanLanguage = ['.js', '.mjs', '.cjs', '.ts'].includes(ext) ? 'javascript'
    : ext === '.py' ? 'python'
    : undefined;
  const results = verifyAll(map, scanLanguage);

  // Build intentional sink filter from manifest
  const manifest = options?.manifest;
  const mode = options?.mode ?? 'full';

  const HAND_WRITTEN_CWES = new Set([
    'CWE-89','CWE-79','CWE-22','CWE-502','CWE-918','CWE-798','CWE-306',
    'CWE-200','CWE-78','CWE-611','CWE-94','CWE-352','CWE-1321',
  ]);

  // Check if a finding matches an intentional sink in the manifest
  const isIntentional = (finding: { sink: { code: string } }): boolean => {
    if (!manifest) return false;
    for (const sink of manifest.intentional_sinks) {
      const fileMatches = sink.files.some(f => {
        if (f.includes('*')) {
          const prefix = f.replace(/\*.*$/, '');
          return filename.includes(prefix);
        }
        return filename.includes(f);
      });
      if (!fileMatches) continue;
      const patternMatches = sink.patterns.some(p =>
        new RegExp(p, 'i').test(finding.sink.code)
      );
      if (patternMatches) return true;
    }
    return false;
  };

  // Convert to SecurityFinding format
  const findings: SecurityFinding[] = [];
  let passed = 0;
  let failed = 0;

  for (const result of results) {
    // In first_party mode, only check hand-written CWEs
    if (mode === 'first_party' && !HAND_WRITTEN_CWES.has(result.cwe)) {
      passed++; // skip generated CWEs for first-party code
      continue;
    }

    if (result.holds) {
      passed++;
    } else {
      failed++;
      for (const f of result.findings) {
        const finding = {
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
        };

        // Skip intentional sinks (manifest-declared features)
        if (mode === 'first_party' && manifest && isIntentional(finding)) continue;

        findings.push(finding);
      }
    }
  }

  // Manifest delta check: data_origins
  // If the manifest declares a field should come from STORAGE but it comes from INGRESS, flag it.
  // This is the business logic verifier — catches "user controls the price."
  if (manifest?.data_origins) {
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');

    for (const origin of manifest.data_origins) {
      const fieldPattern = new RegExp('\\b' + origin.field + '\\b', 'i');

      // Check: does any STORAGE node use this field with data from INGRESS?
      for (const sink of storageNodes) {
        if (!fieldPattern.test(sink.code_snapshot)) continue;

        // Check if any INGRESS node feeds this field
        for (const src of ingressNodes) {
          if (!fieldPattern.test(src.code_snapshot) && !src.code_snapshot.match(/req\.(body|query|params)/)) continue;

          // The field appears in both INGRESS and STORAGE — it's sourced from user input
          // but the manifest says it should come from STORAGE
          if (origin.expected_source === 'STORAGE') {
            // Check if there's a STORAGE read that provides the field BEFORE the write
            const hasServerSideSource = map.nodes.some(n =>
              n.node_type === 'STORAGE' && n.node_subtype.includes('db_read') &&
              fieldPattern.test(n.code_snapshot) &&
              n.line_start < sink.line_start
            );

            if (!hasServerSideSource) {
              findings.push({
                cwe: 'CWE-639',
                name: 'Authorization Bypass Through User-Controlled Key',
                severity: 'critical',
                source: { label: src.label, line: src.line_start, code: src.code_snapshot.slice(0, 200) },
                sink: { label: sink.label, line: sink.line_start, code: sink.code_snapshot.slice(0, 200) },
                missing: `DATA SOURCE (${origin.field} should come from ${origin.expected_source}, not INGRESS)`,
                description: `Business logic violation: "${origin.field}" comes from user input but the manifest declares it should come from ${origin.expected_source}. ${origin.reason}`,
                fix: `Read "${origin.field}" from the database or server-side source instead of trusting user input. The manifest declares: "${origin.reason}"`,
              });
            }
          }
        }
      }
    }
  }

  // Sort by severity: critical > high > medium > low
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

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
 * Use this for gate checks in the pipeline (fail fast).
 */
export async function hasSecurityIssues(code: string, filename?: string): Promise<boolean> {
  const result = await scanCode(code, filename);
  return result.findings.some(f => f.severity === 'critical' || f.severity === 'high');
}
