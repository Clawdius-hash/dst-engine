/**
 * DST Generated Verifiers — Batch 013
 * All remaining EGRESS-sink patterns (43 CWEs).
 *
 * Shapes covered:
 *   STORAGE→EGRESS without CONTROL    (9 CWEs) — info leakage in output
 *   TRANSFORM→EGRESS without CONTROL  (9 CWEs) — error/exception exposure
 *   STORAGE→EGRESS without TRANSFORM  (7 CWEs) — raw sensitive data output
 *   STORAGE→EGRESS without AUTH       (5 CWEs) — unauthorized data access
 *   EXTERNAL→EGRESS without TRANSFORM (5 CWEs) — external data in output
 *   META→EGRESS without CONTROL       (4 CWEs) — debug/config exposure
 *   CONTROL→EGRESS without TRANSFORM  (4 CWEs) — error info leakage
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutTransform,
  hasPathWithoutIntermediateType, detectLanguage,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Generic factory for egress-sink patterns
// ---------------------------------------------------------------------------

type BfsCheck = (map: NeuralMap, srcId: string, sinkId: string) => boolean;

function createEgressVerifier(
  cweId: string, cweName: string, severity: Severity,
  sourceType: NodeType,
  bfsCheck: BfsCheck,
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const sources = nodesOfType(map, sourceType);
    const sinks = nodesOfType(map, 'EGRESS');

    for (const src of sources) {
      for (const sink of sinks) {
        if (src.id === sink.id) continue;
        if (bfsCheck(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `Data from ${src.label} reaches output at ${sink.label} without proper controls. ` +
                `Vulnerable to ${cweName}.`,
              fix: fixDesc,
              via: 'bfs',
            });
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// BFS shortcuts
const noControl: BfsCheck = hasTaintedPathWithoutControl;
const noTransform: BfsCheck = hasPathWithoutTransform;
const noControlIntermediate: BfsCheck = (map, src, sink) =>
  hasPathWithoutIntermediateType(map, src, sink, 'CONTROL');
const noAuth: BfsCheck = (map, src, sink) =>
  hasPathWithoutIntermediateType(map, src, sink, 'AUTH');

// Safe patterns
const REDACT_SAFE = /\bredact\s*\(|\b\.filter\s*\(|\bomit\s*\(|\bselect\s*\(|\bpick\s*\(|\bsanitize\s*\(|\bstrip\s*\(|\bmask\s*\(|\bexclude\s*\(/i;
const ERROR_SAFE = /\bgeneric.*error\b|\bcustom.*error\b|\bproduction\b.*\bmode\b|\bNODE_ENV\b|\berror.*page\b|\bsafeError\b/i;
const ENCRYPT_SAFE = /\bencrypt\s*\(|\bhash\s*\(|\bcreateHash\b|\bredact\s*\(|\bmask\s*\(|\b\*\*\*\b|\btokenize\s*\(/i;
const AUTH_CHECK_SAFE = /\bauthorize\s*\(|\bhasPermission\s*\(|\bcheckAccess\s*\(|\bisOwner\s*\(|\brole\b|\bscoped\b/i;
const ENCODE_SAFE = /\bescape\s*\(|\bencode\s*\(|\bsanitize\s*\(|\bneutralize\s*\(|\b\.filter\s*\(/i;
const DEBUG_SAFE = /\bproduction\b|\bNODE_ENV\b|\bdisable.*debug\b|\bverbose.*off\b/i;

// ===========================================================================
// STORAGE→EGRESS without CONTROL (9 CWEs) — info leakage
// ===========================================================================

export const verifyCWE202 = createEgressVerifier('CWE-202', 'Exposure of Sensitive Information Through Data Queries', 'medium', 'STORAGE', noControl, REDACT_SAFE, 'CONTROL (data filtering before query results sent to client)', 'Filter query results to exclude sensitive fields. Use DTO/view models. Never send raw DB records.');
export const verifyCWE215 = createEgressVerifier('CWE-215', 'Insertion of Sensitive Information Into Debugging Code', 'medium', 'STORAGE', noControl, DEBUG_SAFE, 'CONTROL (disable debug output in production)', 'Disable debug logging and error details in production. Use NODE_ENV checks.');
export const verifyCWE260 = createEgressVerifier('CWE-260', 'Password in Configuration File', 'high', 'STORAGE', noControl, ENCRYPT_SAFE, 'CONTROL (credential protection in configuration)', 'Use environment variables or secret managers for credentials. Never hardcode in config files.');
export const verifyCWE385 = createEgressVerifier('CWE-385', 'Covert Timing Channel', 'medium', 'STORAGE', noControl, /\bconstantTime\b|\btimingSafe\b|\bfixed.*delay\b/i, 'CONTROL (constant-time operations to prevent timing leakage)', 'Use constant-time operations for security comparisons. Add fixed delays where needed.');
export const verifyCWE497 = createEgressVerifier('CWE-497', 'Exposure of Sensitive System Information to an Unauthorized Control Sphere', 'medium', 'STORAGE', noControl, REDACT_SAFE, 'CONTROL (system information filtering)', 'Do not expose system paths, versions, or configuration in responses. Use generic error messages.');
export const verifyCWE514 = createEgressVerifier('CWE-514', 'Covert Channel', 'medium', 'STORAGE', noControl, /\bno.*covert\b|\bisolat\b|\bsandbox\b/i, 'CONTROL (covert channel prevention / information isolation)', 'Isolate security domains. Minimize shared resources between trust levels.');
/**
 * CWE-532: Insertion of Sensitive Information into Log File
 * UPGRADED — hand-written with specific sink and source filters.
 *
 * Pattern: STORAGE nodes containing sensitive data (passwords, tokens, SSNs,
 * credit cards, API keys) flow to EGRESS nodes that are logging calls,
 * without a CONTROL node that redacts the sensitive fields.
 *
 * The generic version checked ALL STORAGE -> ALL EGRESS. The upgraded version:
 *   - Sources: STORAGE nodes whose code or label references sensitive data
 *     (password, token, secret, ssn, credit_card, apiKey, sessionId, etc.)
 *   - Sinks: EGRESS nodes that are specifically logging calls
 *     (console.log, logger.info, winston, pino, log4j, logging.info, syslog, etc.)
 *   - Safe patterns: explicit redaction before logging (masking, filtering fields,
 *     structured logging with field exclusion, JSON.stringify replacer)
 */
export const verifyCWE532 = (function() {
  const SENSITIVE_DATA_PATTERN = /\b(password|passwd|pwd|secret|token|apiKey|api_key|sessionId|session_id|ssn|social_security|credit_card|creditCard|cardNumber|card_number|cvv|pin|private_key|privateKey|auth_token|access_token|refresh_token)\b/i;

  const LOG_SINK_PATTERN = /\b(console\.(log|info|warn|error|debug)|logger\.(log|info|warn|error|debug|trace)|log\.(info|warn|error|debug|trace)|winston\.|pino\.|bunyan\.|log4j|logging\.(info|warning|error|debug)|syslog|print|fprintf.*stderr|NSLog|Log\.(d|i|w|e|v))\s*\(/i;

  const REDACT_SAFE_SPECIFIC = /\bredact\b|\bmask\b|\*{3,}|\bfilter\b.*\b(field|key|password)\b|\breplacer\b|\bomit\b.*\b(password|secret|token)\b|\bsanitize.*log\b|\[REDACTED\]|\[FILTERED\]|\btruncate\b.*\b(token|key)\b/i;

  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];

    // Sources: STORAGE nodes with sensitive data
    const sensitiveStorage = map.nodes.filter(n =>
      n.node_type === 'STORAGE' &&
      (SENSITIVE_DATA_PATTERN.test(n.code_snapshot) ||
       SENSITIVE_DATA_PATTERN.test(n.label) ||
       n.data_out.some(d => d.sensitivity === 'SECRET' || d.sensitivity === 'AUTH' || d.sensitivity === 'PII'))
    );

    // Sinks: EGRESS nodes that are logging calls
    const logSinks = map.nodes.filter(n =>
      n.node_type === 'EGRESS' &&
      LOG_SINK_PATTERN.test(n.code_snapshot)
    );

    for (const src of sensitiveStorage) {
      for (const sink of logSinks) {
        if (src.id === sink.id) continue;
        if (noControl(map, src.id, sink.id)) {
          const isSafe = REDACT_SAFE_SPECIFIC.test(sink.code_snapshot) ||
            REDACT_SAFE_SPECIFIC.test(src.code_snapshot);

          if (!isSafe) {
            // Identify what sensitive data is being logged
            const match = src.code_snapshot.match(SENSITIVE_DATA_PATTERN) || src.label.match(SENSITIVE_DATA_PATTERN);
            const sensitiveField = match ? match[0] : 'sensitive data';

            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (sensitive data redaction before logging)',
              severity: 'medium',
              description: `Sensitive data "${sensitiveField}" from ${src.label} is written to log at ${sink.label} ` +
                `without redaction. Log files are often stored unencrypted, shared with third-party log aggregators, ` +
                `and retained for years.`,
              fix: 'Redact sensitive fields before logging: mask passwords with "***", truncate tokens, ' +
                'remove PII. Use structured logging with a field filter (e.g., pino redact option, ' +
                'winston format with custom replacer). Never log full request bodies without filtering.',
            });
          }
        }
      }
    }

    return { cwe: 'CWE-532', name: 'Insertion of Sensitive Information into Log File', holds: findings.length === 0, findings };
  };
})();
export const verifyCWE548 = createEgressVerifier('CWE-548', 'Exposure of Information Through Directory Listing', 'medium', 'STORAGE', noControl, /\bdirectory.*listing.*off\b|\bautoindex.*off\b|\bOptions.*-Indexes\b/i, 'CONTROL (disable directory listing)', 'Disable directory listing in web server config. Use Options -Indexes (Apache) or autoindex off (nginx).');
export const verifyCWE594 = createEgressVerifier('CWE-594', 'J2EE Framework: Saving Unserializable Objects to Disk', 'medium', 'STORAGE', noControl, /\bSerializable\b|\btransient\b|\bJSON\.stringify\b/i, 'CONTROL (serialization validation before persistence)', 'Ensure objects implement Serializable. Mark sensitive fields as transient.');

// ===========================================================================
// TRANSFORM→EGRESS without CONTROL (9 CWEs) — error/exception exposure
// ===========================================================================

export const verifyCWE248 = createEgressVerifier('CWE-248', 'Uncaught Exception', 'medium', 'TRANSFORM', noControl, ERROR_SAFE, 'CONTROL (global exception handler)', 'Install global exception handlers. Return generic error responses in production. Log full details server-side only.');
export const verifyCWE392 = createEgressVerifier('CWE-392', 'Missing Report of Error Condition', 'medium', 'TRANSFORM', noControl, /\blog\b|\breport\b|\balert\b|\bnotify\b/i, 'CONTROL (error reporting / logging)', 'Report all error conditions. Silent failures mask security issues. Log errors with context.');
export const verifyCWE393 = createEgressVerifier('CWE-393', 'Return of Wrong Status Code', 'medium', 'TRANSFORM', noControl, /\bstatus\b.*\b(200|201|400|401|403|404|500)\b|\bres\.status\b/i, 'CONTROL (correct HTTP status code)', 'Return correct status codes: 401 for auth failures, 403 for forbidden, 404 for not found. Wrong codes leak information.');
export const verifyCWE474 = createEgressVerifier('CWE-474', 'Use of Function with Inconsistent Implementations', 'low', 'TRANSFORM', noControl, /\bpolyfill\b|\bstandard\b|\bcross.*platform\b/i, 'CONTROL (consistent function implementation)', 'Use well-specified standard functions. Polyfill for cross-platform consistency.');
export const verifyCWE515 = createEgressVerifier('CWE-515', 'Covert Storage Channel', 'medium', 'TRANSFORM', noControl, /\bisolat\b|\bsandbox\b|\bno.*shared\b/i, 'CONTROL (storage channel isolation)', 'Isolate storage between security domains. Clear shared storage on context switch.');
export const verifyCWE600 = createEgressVerifier('CWE-600', 'Uncaught Exception in Servlet', 'medium', 'TRANSFORM', noControl, ERROR_SAFE, 'CONTROL (servlet exception handling)', 'Catch all exceptions in servlet handlers. Return generic error pages in production.');
export const verifyCWE689 = createEgressVerifier('CWE-689', 'Permission Race Condition During Resource Copy', 'medium', 'TRANSFORM', noControl, /\batomic\b|\btransaction\b|\block\b/i, 'CONTROL (atomic permission setting during copy)', 'Set permissions atomically during resource copy. Avoid TOCTOU windows.');
export const verifyCWE780 = createEgressVerifier('CWE-780', 'Use of RSA Algorithm without OAEP', 'high', 'TRANSFORM', noControl, /\bOAEP\b|\bRSA-OAEP\b|\bPKCS1.*v2\b|\bpadding.*OAEP\b/i, 'CONTROL (RSA-OAEP padding enforcement)', 'Use RSA-OAEP (PKCS#1 v2.1) padding, not PKCS#1 v1.5 which is vulnerable to padding oracle attacks.');
export const verifyCWE838 = createEgressVerifier('CWE-838', 'Inappropriate Encoding for Output', 'medium', 'TRANSFORM', noControl, ENCODE_SAFE, 'CONTROL (context-appropriate output encoding)', 'Use encoding appropriate to the output context: HTML-encode for HTML, URL-encode for URLs.');

// ===========================================================================
// STORAGE→EGRESS without TRANSFORM (7 CWEs) — raw sensitive data
// ===========================================================================

export const verifyCWE201 = createEgressVerifier('CWE-201', 'Insertion of Sensitive Information Into Sent Data', 'high', 'STORAGE', noTransform, REDACT_SAFE, 'TRANSFORM (sensitive data filtering/redaction before output)', 'Filter sensitive data from responses. Use allowlist of fields to include, not blocklist.');
export const verifyCWE212 = createEgressVerifier('CWE-212', 'Improper Removal of Sensitive Information Before Storage or Transfer', 'high', 'STORAGE', noTransform, REDACT_SAFE, 'TRANSFORM (scrubbing sensitive data before transfer)', 'Scrub sensitive data (metadata, hidden fields, comments) before sharing or transferring.');
export const verifyCWE375 = createEgressVerifier('CWE-375', 'Returning a Mutable Object to an Untrusted Caller', 'medium', 'STORAGE', noTransform, /\bclone\b|\bcopy\b|\bfreeze\b|\bslice\b|\bspread\b|\bstructuredClone\b/i, 'TRANSFORM (defensive copy before returning internal data)', 'Return defensive copies of internal objects. Use Object.freeze() or structuredClone().');
export const verifyCWE457 = createEgressVerifier('CWE-457', 'Use of Uninitialized Variable', 'medium', 'STORAGE', noTransform, /\binit\b|\bdefault\b|\b=\s*(?:null|0|''|""|false|\[\]|\{\})\b|\b=\s*new\b|\b=\s*\w+\.\w+\(|\bString\s+\w+\s*=|\bint\s+\w+\s*=|\bvar\s+\w+\s*=/i, 'TRANSFORM (initialization before use)', 'Initialize all variables before use. Use default values. Enable strict mode.');
export const verifyCWE495 = createEgressVerifier('CWE-495', 'Private Data Structure Returned From A Public Method', 'medium', 'STORAGE', noTransform, /\bclone\b|\bcopy\b|\bfreeze\b|\bslice\b/i, 'TRANSFORM (defensive copy of private data)', 'Return copies, not references, of private data structures from public methods.');
export const verifyCWE539 = createEgressVerifier('CWE-539', 'Use of Persistent Cookies Containing Sensitive Information', 'medium', 'STORAGE', noTransform, ENCRYPT_SAFE, 'TRANSFORM (encryption/expiry for sensitive cookies)', 'Encrypt sensitive cookie data. Use session cookies (no Expires). Set Secure and HttpOnly flags.');
export const verifyCWE562 = createEgressVerifier('CWE-562', 'Return of Stack Variable Address', 'critical', 'STORAGE', noTransform, /\bheap\b|\bmalloc\b|\bnew\b|\bstatic\b|\bglobal\b/i, 'TRANSFORM (heap allocation for returned data — not stack)', 'Never return pointers/references to stack-allocated variables. Use heap allocation for returned data.');

// ===========================================================================
// STORAGE→EGRESS without AUTH (5 CWEs) — unauthorized access
// ===========================================================================

export const verifyCWE359 = createEgressVerifier('CWE-359', 'Exposure of Private Personal Information to an Unauthorized Actor', 'high', 'STORAGE', noAuth, AUTH_CHECK_SAFE, 'AUTH (authorization check before exposing personal data)', 'Verify authorization before returning PII. Implement data access controls at the query level.');
export const verifyCWE402 = createEgressVerifier('CWE-402', 'Transmission of Private Resources into a New Sphere (Resource Leak)', 'high', 'STORAGE', noAuth, AUTH_CHECK_SAFE, 'AUTH (access control on resource transfer)', 'Check authorization before transferring resources to new contexts. Verify the recipient is authorized.');
export const verifyCWE499 = createEgressVerifier('CWE-499', 'Serializable Class Containing Sensitive Data', 'medium', 'STORAGE', noAuth, /\btransient\b|\bexclude\b|\bignore\b|\bsensitive\b.*\bskip\b/i, 'AUTH (exclude sensitive fields from serialization)', 'Mark sensitive fields as transient/excluded from serialization. Override serialization to filter.');
export const verifyCWE552 = createEgressVerifier('CWE-552', 'Files or Directories Accessible to External Parties', 'high', 'STORAGE', noAuth, AUTH_CHECK_SAFE, 'AUTH (access control on file/directory serving)', 'Do not serve files outside the webroot. Apply access controls to all file-serving endpoints.');
export const verifyCWE582 = createEgressVerifier('CWE-582', 'Array Declared Public, Final, and Static', 'medium', 'STORAGE', noAuth, /\bprivate\b|\bclone\b|\bunmodifiable\b|\bCollections\.unmodifiable\b/i, 'AUTH (encapsulation — make arrays private, return copies)', 'Make arrays private. Return unmodifiable copies from public accessors.');

// ===========================================================================
// EXTERNAL→EGRESS without TRANSFORM (5 CWEs) — external data exposure
// ===========================================================================

export const verifyCWE451 = createEgressVerifier('CWE-451', 'User Interface (UI) Misrepresentation of Critical Information', 'medium', 'EXTERNAL', noTransform, /\bvalidate.*display\b|\bverify.*ui\b|\bindicator\b|\bicon\b.*\bsecure\b/i, 'TRANSFORM (UI representation validation / clear security indicators)', 'Clearly represent security state in UI. Show lock icons for HTTPS. Do not obscure certificate warnings.');
export const verifyCWE535 = createEgressVerifier('CWE-535', 'Exposure of Information Through Shell Error Message', 'medium', 'EXTERNAL', noTransform, /\bgeneric.*error\b|\bredirect.*stderr\b|\b2>\/dev\/null\b/i, 'TRANSFORM (shell error message filtering)', 'Capture and filter shell error messages. Do not expose command output to users.');
// CWE-536: Servlet-specific — only fire on Java servlet code that exposes exception details
export const verifyCWE536 = (map: NeuralMap): VerificationResult => {
  const lang = detectLanguage(map);
  // Only relevant to Java servlets
  if (lang && lang !== 'java') {
    return { cwe: 'CWE-536', name: 'Exposure of Information Through Servlet Runtime Error Message', holds: true, findings: [] };
  }
  // Check if code actually exposes exception messages to responses
  const allCode = map.nodes.map(n => n.code_snapshot).join('\n');
  const exposesException = /\be\.getMessage\s*\(\s*\)|\be\.toString\s*\(\s*\)|\bprintStackTrace\s*\(\s*\)/.test(allCode) &&
    /\bgetWriter\b|\bprintln\b|\bsendError\b/.test(allCode);
  if (!exposesException) {
    return { cwe: 'CWE-536', name: 'Exposure of Information Through Servlet Runtime Error Message', holds: true, findings: [] };
  }
  return createEgressVerifier('CWE-536', 'Exposure of Information Through Servlet Runtime Error Message', 'medium', 'EXTERNAL', noTransform, ERROR_SAFE, 'TRANSFORM (custom error pages — no runtime details)', 'Configure custom error pages. Do not expose stack traces or runtime errors to users.')(map);
};
export const verifyCWE537 = createEgressVerifier('CWE-537', 'Exposure of Information Through Java Runtime Error Message', 'medium', 'EXTERNAL', noTransform, ERROR_SAFE, 'TRANSFORM (generic error responses — no Java exception details)', 'Catch exceptions and return generic messages. Log full details server-side only.');
export const verifyCWE550 = createEgressVerifier('CWE-550', 'Server-generated Error Message Containing Sensitive Information', 'medium', 'EXTERNAL', noTransform, ERROR_SAFE, 'TRANSFORM (generic server error messages)', 'Return generic error messages in production. Do not expose paths, queries, or stack traces.');

// ===========================================================================
// META→EGRESS without CONTROL (4 CWEs) — debug/config exposure
// ===========================================================================

export const verifyCWE11 = createEgressVerifier('CWE-11', 'ASP.NET Misconfiguration: Creating Debug Binary', 'medium', 'META', noControl, DEBUG_SAFE, 'CONTROL (disable debug mode in production)', 'Set debug="false" in web.config for production. Debug binaries expose source, are slower, and leak info.');
export const verifyCWE489 = createEgressVerifier('CWE-489', 'Active Debug Code', 'medium', 'META', noControl, DEBUG_SAFE, 'CONTROL (remove/disable debug code in production)', 'Remove debug endpoints, console.log statements, and test credentials before deployment.');
export const verifyCWE541 = createEgressVerifier('CWE-541', 'Inclusion of Sensitive Information in an Include File', 'medium', 'META', noControl, ENCRYPT_SAFE, 'CONTROL (no sensitive data in include files)', 'Do not hardcode secrets in include/header files. Use environment variables or secret managers.');
export const verifyCWE615 = createEgressVerifier('CWE-615', 'Inclusion of Sensitive Information in Source Code Comments', 'low', 'META', noControl, /\bno.*comment.*secret\b|\bstrip.*comment\b|\bminif\b/i, 'CONTROL (no sensitive data in code comments)', 'Remove passwords, keys, and internal URLs from comments. Minify production code to strip comments.');

// ===========================================================================
// CONTROL→EGRESS without TRANSFORM (4 CWEs) — error detail leakage
// ===========================================================================

export const verifyCWE203 = createEgressVerifier('CWE-203', 'Observable Discrepancy', 'medium', 'CONTROL', noTransform, /\bconstantTime\b|\btimingSafe\b|\bgeneric.*response\b|\bsame.*error\b/i, 'TRANSFORM (uniform response — same error for valid/invalid)', 'Return identical responses for valid and invalid inputs to prevent oracle attacks. Use constant-time comparisons.');
export const verifyCWE205 = createEgressVerifier('CWE-205', 'Observable Behavioral Discrepancy', 'medium', 'CONTROL', noTransform, /\buniform.*response\b|\bsame.*behavior\b|\bconstant.*time\b/i, 'TRANSFORM (uniform behavior — no observable difference by input)', 'Ensure behavior is consistent regardless of input validity. Same timing, same response structure.');
export const verifyCWE460 = createEgressVerifier('CWE-460', 'Improper Cleanup on Thrown Exception', 'medium', 'CONTROL', noTransform, /\bfinally\b|\bcleanup\b|\bdispose\b|\busing\b/i, 'TRANSFORM (cleanup in finally block on exception path)', 'Release resources in finally blocks. Ensure cleanup runs even when exceptions are thrown.');
export const verifyCWE756 = createEgressVerifier('CWE-756', 'Missing Custom Error Page', 'low', 'CONTROL', noTransform, ERROR_SAFE, 'TRANSFORM (custom error pages — no default server error details)', 'Configure custom error pages for all error codes (404, 500). Default pages leak server info.');

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_013_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // STORAGE→EGRESS without CONTROL (9)
  'CWE-202': verifyCWE202, 'CWE-215': verifyCWE215, 'CWE-260': verifyCWE260,
  'CWE-385': verifyCWE385, 'CWE-497': verifyCWE497, 'CWE-514': verifyCWE514,
  'CWE-532': verifyCWE532, 'CWE-548': verifyCWE548, 'CWE-594': verifyCWE594,
  // TRANSFORM→EGRESS without CONTROL (9)
  'CWE-248': verifyCWE248, 'CWE-392': verifyCWE392, 'CWE-393': verifyCWE393,
  'CWE-474': verifyCWE474, 'CWE-515': verifyCWE515, 'CWE-600': verifyCWE600,
  'CWE-689': verifyCWE689, 'CWE-780': verifyCWE780, 'CWE-838': verifyCWE838,
  // STORAGE→EGRESS without TRANSFORM (7)
  'CWE-201': verifyCWE201, 'CWE-212': verifyCWE212, 'CWE-375': verifyCWE375,
  'CWE-457': verifyCWE457, 'CWE-495': verifyCWE495, 'CWE-539': verifyCWE539,
  'CWE-562': verifyCWE562,
  // STORAGE→EGRESS without AUTH (5)
  'CWE-359': verifyCWE359, 'CWE-402': verifyCWE402, 'CWE-499': verifyCWE499,
  'CWE-552': verifyCWE552, 'CWE-582': verifyCWE582,
  // EXTERNAL→EGRESS without TRANSFORM (5)
  'CWE-451': verifyCWE451, 'CWE-535': verifyCWE535, 'CWE-536': verifyCWE536,
  'CWE-537': verifyCWE537, 'CWE-550': verifyCWE550,
  // META→EGRESS without CONTROL (4)
  'CWE-11': verifyCWE11, 'CWE-489': verifyCWE489, 'CWE-541': verifyCWE541,
  'CWE-615': verifyCWE615,
  // CONTROL→EGRESS without TRANSFORM (4)
  'CWE-203': verifyCWE203, 'CWE-205': verifyCWE205, 'CWE-460': verifyCWE460,
  'CWE-756': verifyCWE756,
};
