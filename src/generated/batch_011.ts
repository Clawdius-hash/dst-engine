/**
 * DST Generated Verifiers — Batch 011
 * Pattern shape: CONTROL→TRANSFORM without CONTROL
 * 13 CWEs: TOCTOU, error handling, exception management, lock issues.
 *
 * A CONTROL node checks something, then a TRANSFORM acts on it, but there's
 * no second CONTROL between them to ensure the check is still valid or to
 * handle errors from the TRANSFORM. Uses hasPathWithoutIntermediateType
 * since the source IS a CONTROL node (same type as missing mediator).
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasPathWithoutIntermediateType, getContainingScopeSnapshots, stripComments,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Safe patterns
// ---------------------------------------------------------------------------

const ATOMIC_SAFE = /\batomic\b|\btransaction\b|\block\b.*\buse\b|\bcompareAndSwap\b|\bCAS\b|\bO_EXCL\b/i;
const ERROR_HANDLE_SAFE = /\btry\b|\bcatch\b|\bfinally\b|\bthrow\b|\berror\b.*\bhandl\b|\bonError\b|\bfallback\b/i;
const EXCEPTION_SAFE = /\bcatch\b.*\bspecific\b|\binstanceof\b.*Error|\bcatch\b.*\b\w+Error\b/i;
const CHECK_RESULT_SAFE = /\bif\s*\(\s*result\b|\breturn.*check\b|\bassert\s*\(|\bverify.*result\b/i;

// ---------------------------------------------------------------------------
// Factory: CONTROL→TRANSFORM without intermediate CONTROL
// ---------------------------------------------------------------------------

function createControlTransformVerifier(
  cweId: string, cweName: string, severity: Severity,
  sinkFilter: (map: NeuralMap) => NeuralMapNode[],
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const controls = nodesOfType(map, 'CONTROL');
    const sinks = sinkFilter(map);

    for (const src of controls) {
      for (const sink of sinks) {
        if (src.id === sink.id) continue;
        if (hasPathWithoutIntermediateType(map, src.id, sink.id, 'CONTROL')) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            // Check the containing function scope for both src and sink.
            // If the function that contains either node has proper exception handling
            // (try/catch/finally), suppress the finding — the scope IS handled.
            const sinkScopeSnapshots = getContainingScopeSnapshots(map, sink.id);
            const srcScopeSnapshots = getContainingScopeSnapshots(map, src.id);
            const allScopes = [...sinkScopeSnapshots, ...srcScopeSnapshots];
            // Also check the CONTAINS parent node's own analysis_snapshot (the function body itself)
            const sinkParentEdge = map.edges.find(e => e.edge_type === 'CONTAINS' && e.target === sink.id);
            const srcParentEdge = map.edges.find(e => e.edge_type === 'CONTAINS' && e.target === src.id);
            if (sinkParentEdge) {
              const parentNode = map.nodes.find(n => n.id === sinkParentEdge.source);
              if (parentNode) allScopes.push(parentNode.analysis_snapshot || parentNode.code_snapshot);
            }
            if (srcParentEdge) {
              const parentNode = map.nodes.find(n => n.id === srcParentEdge.source);
              if (parentNode) allScopes.push(parentNode.analysis_snapshot || parentNode.code_snapshot);
            }
            const scopeSafe = allScopes.some(s => safePattern.test(stripComments(s)));
            if (!scopeSafe) {
              findings.push({
                source: nodeRef(src),
                sink: nodeRef(sink),
                missing: missingDesc,
                severity,
                description: `Check at ${src.label} feeds operation at ${sink.label} without additional control. ` +
                  `Vulnerable to ${cweName}.`,
                fix: fixDesc,
                via: 'bfs',
              });
            }
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

const transformNodes = (map: NeuralMap) => nodesOfType(map, 'TRANSFORM');

// ===========================================================================
// VERIFIERS (13 CWEs)
// ===========================================================================

// TOCTOU / Race conditions
export const verifyCWE273 = createControlTransformVerifier(
  'CWE-273', 'Improper Check for Dropped Privileges', 'high',
  transformNodes, CHECK_RESULT_SAFE,
  'CONTROL (verify privilege drop succeeded before proceeding)',
  'Check the return value of privilege-dropping operations (setuid, setgid). ' +
    'If the drop fails, the process continues with elevated privileges.',
);

export const verifyCWE364 = createControlTransformVerifier(
  'CWE-364', 'Signal Handler Race Condition', 'medium',
  transformNodes, ATOMIC_SAFE,
  'CONTROL (signal-safe operations / atomic state changes)',
  'Use only async-signal-safe functions in signal handlers. ' +
    'Use volatile sig_atomic_t for shared state. Avoid locks in signal handlers.',
);

/**
 * CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
 * UPGRADED — hand-written with specific sink filters and safe patterns.
 *
 * Pattern: A CONTROL node checks file metadata (stat, access, exists),
 * then a TRANSFORM or STORAGE node operates on the same file by path.
 * Between the check and the use, an attacker can swap the file (symlink, rename).
 *
 * Specific sources: CONTROL nodes with file-checking calls
 *   (fs.stat, fs.access, fs.existsSync, os.path.exists, os.access, File.exists, lstat)
 * Specific sinks: TRANSFORM or STORAGE nodes with file-operating calls
 *   (open, readFile, writeFile, unlink, rename, createReadStream, fopen, chmod)
 * Safe patterns:
 *   - O_EXCL / O_CREAT (atomic create-if-not-exists)
 *   - fstat on file descriptor (not path — checks the actual opened file)
 *   - flock / lockf / advisory locks
 *   - atomic rename (rename is atomic on same filesystem)
 *   - openat with O_NOFOLLOW (prevents symlink following)
 *   - database transactions wrapping both check and use
 */
export function verifyCWE367(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Sources: CONTROL nodes that check file state by path
  const FILE_CHECK_PATTERN = /\b(stat|statSync|lstat|lstatSync|access|accessSync|exists|existsSync|isFile|isDirectory|os\.path\.exists|os\.access|os\.path\.isfile|File\.exists|Files\.exists|Path\.Exists)\b/i;
  const fileChecks = map.nodes.filter(n =>
    n.node_type === 'CONTROL' &&
    FILE_CHECK_PATTERN.test(n.code_snapshot)
  );

  // Sinks: TRANSFORM or STORAGE nodes that operate on files by path
  const FILE_USE_PATTERN = /\b(open|openSync|readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|rename|renameSync|createReadStream|createWriteStream|fopen|fwrite|fread|chmod|chown|copyFile|copyFileSync|appendFile|appendFileSync|truncate|rmdir|mkdir)\b/i;
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
    FILE_USE_PATTERN.test(n.code_snapshot)
  );

  // Safe patterns: atomic operations that close the TOCTOU gap
  const TOCTOU_SAFE = /\bO_EXCL\b|\bO_CREAT\b|\bfstat\w*\b|\bflock\b|\blockf\b|\bO_NOFOLLOW\b|\bopenat\b|\btransaction\b|\batomic\b|\bcompareAndSwap\b|\brename\b.*\batomic\b|\bfs\.open\b.*\bwx\b/i;

  for (const src of fileChecks) {
    for (const sink of fileOps) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutIntermediateType(map, src.id, sink.id, 'CONTROL')) {
        // Check if the sink uses an atomic pattern that prevents TOCTOU
        const isSafe = TOCTOU_SAFE.test(sink.code_snapshot) || TOCTOU_SAFE.test(src.code_snapshot);
        if (!isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (atomic check-and-use — file state can change between stat() and open())',
            severity: 'medium',
            description: `File metadata check at ${src.label} precedes file operation at ${sink.label} ` +
              `without atomic protection. An attacker can replace the file (e.g., with a symlink) ` +
              `between the check and the use.`,
            fix: 'Open the file first, then use fstat() on the file descriptor instead of stat() on the path. ' +
              'Use O_EXCL|O_CREAT for atomic file creation. Use O_NOFOLLOW to prevent symlink attacks. ' +
              'For check-then-modify, use file locks (flock) or atomic rename.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-367', name: 'Time-of-check Time-of-use (TOCTOU) Race Condition', holds: findings.length === 0, findings };
}

export const verifyCWE386 = createControlTransformVerifier(
  'CWE-386', 'Symbolic Name not Mapping to Correct Object', 'medium',
  transformNodes, ATOMIC_SAFE,
  'CONTROL (name-to-object resolution verification)',
  'Verify that symbolic names (file paths, symlinks) still resolve to the expected object at use time. ' +
    'Use file descriptors instead of paths for continued access.',
);

// Error/exception handling
export const verifyCWE390 = createControlTransformVerifier(
  'CWE-390', 'Detection of Error Condition Without Action', 'medium',
  transformNodes, ERROR_HANDLE_SAFE,
  'CONTROL (error handling — take corrective action when errors detected)',
  'Do not silently ignore detected errors. Log, retry, fail gracefully, or escalate. ' +
    'Empty catch blocks hide bugs and security issues.',
);

export const verifyCWE395 = createControlTransformVerifier(
  'CWE-395', 'Use of NullPointerException Catch to Detect NULL Pointer Dereference', 'medium',
  transformNodes,
  /\bif\s*\(\s*\w+\s*[!=]==?\s*null\b|\b\?\.\b|\bOptional\b/i,
  'CONTROL (explicit null check — not exception-driven null detection)',
  'Check for null explicitly (if x !== null) instead of catching NullPointerException. ' +
    'Use optional chaining (?.) or Optional types.',
);

export const verifyCWE396 = createControlTransformVerifier(
  'CWE-396', 'Declaration of Catch for Generic Exception', 'medium',
  transformNodes, EXCEPTION_SAFE,
  'CONTROL (specific exception handling — not catch-all)',
  'Catch specific exception types, not generic Exception/Error. ' +
    'Generic catches mask unexpected errors and hide security-relevant failures.',
);

// Synchronization / concurrency
export const verifyCWE663 = createControlTransformVerifier(
  'CWE-663', 'Use of a Non-reentrant Function in a Concurrent Context', 'medium',
  transformNodes,
  /\breentrant\b|\bthread.*safe\b|\b_r\b\s*\(|\batomic\b|\block\b|\bsynchronized\b/i,
  'CONTROL (reentrant/thread-safe function usage in concurrent context)',
  'Use reentrant (_r suffix) or thread-safe function versions in concurrent code. ' +
    'Protect non-reentrant calls with locks.',
);

export const verifyCWE670 = createControlTransformVerifier(
  'CWE-670', 'Always-Incorrect Control Flow Implementation', 'medium',
  transformNodes, CHECK_RESULT_SAFE,
  'CONTROL (correct control flow — no dead code, no impossible conditions)',
  'Review control flow for logical errors: conditions that are always true/false, ' +
    'unreachable code, inverted checks. Use static analysis tools to detect.',
);

export const verifyCWE705 = createControlTransformVerifier(
  'CWE-705', 'Incorrect Control Flow Scoping', 'medium',
  transformNodes, ERROR_HANDLE_SAFE,
  'CONTROL (correct scoping — proper block structure, no dangling else)',
  'Use explicit braces for all control flow blocks. Avoid single-line if/else. ' +
    'Review for dangling else and misscoped try/catch.',
);

export const verifyCWE755 = createControlTransformVerifier(
  'CWE-755', 'Improper Handling of Exceptional Conditions', 'medium',
  transformNodes, ERROR_HANDLE_SAFE,
  'CONTROL (exceptional condition handling — resource exhaustion, timeout, malformed data)',
  'Handle all exceptional conditions: disk full, network timeout, malformed input, ' +
    'permission denied. Do not assume operations always succeed.',
);

export const verifyCWE768 = createControlTransformVerifier(
  'CWE-768', 'Incorrect Short Circuit Evaluation', 'medium',
  transformNodes,
  /\b&&\b.*\bcheck\b|\b\|\|\b.*\bdefault\b|\bshort.*circuit\b.*\bcorrect\b/i,
  'CONTROL (correct short-circuit evaluation — side effects in right operand)',
  'Be careful with side effects in short-circuit expressions (&&, ||). ' +
    'The right operand may not execute if the left is sufficient.',
);

export const verifyCWE828 = createControlTransformVerifier(
  'CWE-828', 'Signal Handler with Functionality that is not Async-Signal-Safe', 'medium',
  transformNodes,
  /\basync.*signal.*safe\b|\bsig_atomic\b|\bvolatile\b|\bwrite\b\s*\(\s*\d/i,
  'CONTROL (async-signal-safe operations only in signal handlers)',
  'Only call async-signal-safe functions in signal handlers (write, _exit, signal). ' +
    'Do not use malloc, printf, or any function that acquires locks.',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_011_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-273': verifyCWE273,
  'CWE-364': verifyCWE364,
  'CWE-367': verifyCWE367,
  'CWE-386': verifyCWE386,
  'CWE-390': verifyCWE390,
  'CWE-395': verifyCWE395,
  'CWE-396': verifyCWE396,
  'CWE-663': verifyCWE663,
  'CWE-670': verifyCWE670,
  'CWE-705': verifyCWE705,
  'CWE-755': verifyCWE755,
  'CWE-768': verifyCWE768,
  'CWE-828': verifyCWE828,
};
