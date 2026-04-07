/**
 * DST Generated Verifiers — Batch 019
 * CWEs 400-599 gap fill — real verifiers only (5 CWEs).
 *   CWE-400  Uncontrolled Resource Consumption
 *   CWE-434  Unrestricted Upload of File with Dangerous Type
 *   CWE-476  NULL Pointer Dereference
 *   CWE-522  Insufficiently Protected Credentials
 *   CWE-525  Use of Web Browser Cache Containing Sensitive Information
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutTransform,
  hasPathWithoutIntermediateType,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Compact factory (same pattern as batch_015/016)
// ---------------------------------------------------------------------------

type BfsCheck = (map: NeuralMap, srcId: string, sinkId: string) => boolean;

function v(
  cweId: string, cweName: string, severity: Severity,
  sourceType: NodeType, sinkType: NodeType,
  bfsCheck: BfsCheck,
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const sources = nodesOfType(map, sourceType);
    const sinks = nodesOfType(map, sinkType);
    for (const src of sources) {
      for (const sink of sinks) {
        if (src.id === sink.id) continue;
        if (bfsCheck(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(sink),
              missing: missingDesc, severity,
              description: `${sourceType} at ${src.label} \u2192 ${sinkType} at ${sink.label} without controls. Vulnerable to ${cweName}.`,
              fix: fixDesc,
            });
          }
        }
      }
    }
    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// BFS shortcuts
const nC: BfsCheck = hasTaintedPathWithoutControl;
const nT: BfsCheck = hasPathWithoutTransform;
const nTi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'TRANSFORM');
const nA: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'AUTH');

// ===========================================================================
// REAL VERIFIERS (5 CWEs)
// ===========================================================================

/**
 * CWE-400: Uncontrolled Resource Consumption
 * INGRESS triggers resource allocation without throttle/limit CONTROL.
 * Allows DoS via memory, CPU, connections, or file descriptor exhaustion.
 */
export const verifyCWE400 = v(
  'CWE-400', 'Uncontrolled Resource Consumption', 'high',
  'INGRESS', 'TRANSFORM', nC,
  /\bthrottle\b|\brate.*limit\b|\bquota\b|\btimeout\b|\bmax.*pool\b|\bsetLimit\b/i,
  'CONTROL (resource limits — rate limiting, quotas, timeouts)',
  'Apply rate limiting, connection quotas, and timeouts to all user-triggered resource allocations. Use middleware like express-rate-limit or equivalent.',
);

/**
 * CWE-434: Unrestricted Upload of File with Dangerous Type
 * INGRESS[file_upload] reaches STORAGE without file-type validation CONTROL.
 * Enables remote code execution via uploaded .php/.asp/.jsp etc.
 */
export const verifyCWE434 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];
  const sources = nodesOfType(map, 'INGRESS').filter(n =>
    n.node_subtype.includes('upload') || n.node_subtype.includes('file') ||
    n.attack_surface.includes('file_upload') ||
    n.code_snapshot.match(/\b(multer|formidable|busboy|upload|multipart)\b/i) !== null
  );
  const sinks = nodesOfType(map, 'STORAGE').filter(n =>
    n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
    n.node_subtype.includes('disk') || n.attack_surface.includes('file_access') ||
    n.code_snapshot.match(/\b(writeFile|createWriteStream|save|mv|pipe)\b/i) !== null
  );

  const safePattern = /\b(allowlist|whitelist|mime.*check|magic.*bytes|file.*type.*valid|extension.*check|content.*type.*valid)\b/i;

  for (const src of sources) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (file type validation — allowlist of permitted extensions/MIME types)',
            severity: 'critical',
            description: `File upload at ${src.label} reaches storage at ${sink.label} without file type validation. ` +
              `Attackers can upload executable files (.php, .asp, .jsp) for remote code execution.`,
            fix: 'Validate uploaded file types against an allowlist of safe extensions AND MIME types. ' +
              'Check magic bytes, not just extensions. Store uploads outside web-accessible directories.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-434', name: 'Unrestricted Upload of File with Dangerous Type', holds: findings.length === 0, findings };
};

/**
 * CWE-476: NULL Pointer Dereference
 * A nullable return from EXTERNAL/TRANSFORM reaches dereference without null check CONTROL.
 * Causes crashes (DoS) or, in privileged contexts, unauthorized memory access.
 *
 * Also detects Java-specific patterns:
 *  - Non-short-circuit & in null check: if (x != null & x.method()) — evaluates both sides
 *  - Variable assigned null then dereferenced without null check
 */
export const verifyCWE476 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];

  // ── Graph-based detection (original) ──
  const sources = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('nullable') || n.node_subtype.includes('optional') ||
     n.code_snapshot.match(
       /\b(find|get|query|fetch|lookup|search|match|exec|pop|shift|querySelector)\b/i
     ) !== null)
  );

  const sinks = nodesOfType(map, 'TRANSFORM').filter(n =>
    n.code_snapshot.match(
      /\.\w+\s*[\([]|\.length\b|\.toString\b|\.valueOf\b|\[\s*\d+\s*\]/i
    ) !== null
  );

  const safePattern = /\bnull.*check\b|\bif\s*\(\s*\w+\s*[!=]==?\s*null\b|\btypeof\b|\?\.\b|\?\?\b|\bassert\s*\(/i;

  for (const src of sources) {
    for (const sink of sinks) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutIntermediateType(map, src.id, sink.id, 'CONTROL')) {
        if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (null check before dereference)',
            severity: 'medium',
            description: `Potentially-null value from ${src.label} is dereferenced at ${sink.label} without a null check. ` +
              `NULL pointer dereference causes crashes or undefined behavior.`,
            fix: 'Add null/undefined check before dereferencing. Use optional chaining (?.), nullish coalescing (??), ' +
              'or explicit null guards. Consider TypeScript strict null checks.',
          });
        }
      }
    }
  }

  // ── Source-based detection (Java structural patterns) ──
  const src2 = map.source_code || '';
  if (src2) {
    const lines = src2.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

      // Pattern 1: Non-short-circuit & in null check
      // if ((x != null) & (x.method())) or if (x != null & x.length())
      // The & evaluates both sides, so x.method() runs even when x is null
      if (/\bif\s*\(/.test(line)) {
        // Check for single & (not &&) in null check context
        const condMatch = line.match(/\bif\s*\((.*)\)/);
        if (condMatch) {
          const cond = condMatch[1];
          // Has null check AND has single & (not &&)
          if (/\w+\s*!=\s*null/.test(cond) && /[^&]&[^&]/.test(cond)) {
            // And has dereference on the other side of &
            if (/\.\w+\s*\(/.test(cond) || /\.length\b/.test(cond)) {
              const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
              if (nearNode) {
                findings.push({
                  source: nodeRef(nearNode), sink: nodeRef(nearNode),
                  missing: 'CONTROL (use && not & for null guard — short-circuit evaluation)',
                  severity: 'medium',
                  description: `L${i + 1}: Non-short-circuit operator & used in null check. Both sides of & are always evaluated, so the dereference executes even when the variable is null. Use && instead.`,
                  fix: 'Use && (short-circuit AND) instead of & in null checks. With &&, the right side is only evaluated if the left side is true.',
                });
              }
            }
          }
        }
      }

      // Pattern 2: Variable explicitly assigned null, then dereferenced without reassignment or null check
      const nullAssign = line.match(/(\w+)\s*=\s*null\s*;/);
      if (nullAssign) {
        const varName = nullAssign[1];
        // Look ahead for dereference without reassignment
        let reassigned = false;
        for (let j = i + 1; j < Math.min(i + 20, lines.length); j++) {
          const ahead = lines[j];
          if (/^\s*\/\//.test(ahead) || /^\s*\*/.test(ahead)) continue;
          // Check if variable is reassigned
          const reassignPat = new RegExp(`\\b${varName}\\s*=\\s*(?!null\\s*;|=)`);
          if (reassignPat.test(ahead)) { reassigned = true; break; }
          // Check if there's a null check
          const nullCheckPat = new RegExp(`\\b${varName}\\s*!=\\s*null\\b|\\b${varName}\\s*==\\s*null\\b`);
          if (nullCheckPat.test(ahead)) { reassigned = true; break; } // null check counts as safe
          // Check if variable is dereferenced
          const derefPat = new RegExp(`\\b${varName}\\.(\\w+)\\s*\\(`);
          if (derefPat.test(ahead)) {
            // But skip if it's inside a short-circuit null guard on the same line
            if (/&&/.test(ahead) && nullCheckPat.test(ahead)) { reassigned = true; break; }
            const nearNode = map.nodes.find(n => Math.abs(n.line_start - (j + 1)) <= 2) || map.nodes[0];
            if (nearNode) {
              findings.push({
                source: nodeRef(nearNode), sink: nodeRef(nearNode),
                missing: 'CONTROL (null check before dereference)',
                severity: 'medium',
                description: `L${j + 1}: Variable '${varName}' was assigned null at L${i + 1} and is dereferenced without a null check.`,
                fix: 'Add a null check before dereferencing. Ensure the variable is assigned a non-null value before use.',
              });
            }
            break;
          }
        }
      }
    }
  }

  return { cwe: 'CWE-476', name: 'NULL Pointer Dereference', holds: findings.length === 0, findings };
};

/**
 * CWE-522: Insufficiently Protected Credentials
 * Credentials flow from INGRESS/TRANSFORM to STORAGE/EGRESS without
 * TRANSFORM[hash|encryption] — plaintext credential exposure.
 */
export const verifyCWE522 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];

  const sources = map.nodes.filter(n =>
    (n.node_type === 'INGRESS' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('credential') || n.node_subtype.includes('password') ||
     n.node_subtype.includes('secret') || n.node_subtype.includes('auth') ||
     n.attack_surface.includes('credentials') ||
     n.code_snapshot.match(
       /\b(password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\b/i
     ) !== null)
  );

  const sinks = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EGRESS'
  );

  // Password-safe hashing functions only — bcrypt/argon2/scrypt/pbkdf2 variants
  const PASSWORD_SAFE_HASH_RE = /\b(bcrypt|scrypt|argon2|pbkdf2|Argon2|PBKDF2|bcryptjs|bcryptSync|hashSync|hashpw|checkpw)\b/i;
  // Insecure fast hashes explicitly used for passwords — must flag even if createHash is present
  const INSECURE_HASH_FOR_PASSWORDS_RE = /createHash\s*\(\s*['"](?:md5|sha1|sha-1|sha128|md4|md2)['"]/i;
  // Broader encryption/transport safe patterns (non-password contexts)
  const ENCRYPT_SAFE_RE = /\bencrypt\s*\(|\bcipher\s*\(|\bcreateCipher\w*\b|\btls\b|\bhttps\b|\bAES\b/i;

  for (const src of sources) {
    for (const sink of sinks) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutTransform(map, src.id, sink.id)) {
        const combinedCode = (src.code_snapshot || '') + '\n' + (sink.code_snapshot || '');
        // If an insecure hash is explicitly used for passwords, always flag
        const hasInsecureHash = INSECURE_HASH_FOR_PASSWORDS_RE.test(combinedCode);
        // If a password-safe hash function is present, suppress
        const hasSafeHash = PASSWORD_SAFE_HASH_RE.test(combinedCode);
        // If general encryption/transport protection is present (non-password), suppress
        const hasEncryptSafe = ENCRYPT_SAFE_RE.test(combinedCode);

        if (hasInsecureHash || (!hasSafeHash && !hasEncryptSafe)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'TRANSFORM (strong password hash — bcrypt, Argon2, scrypt, PBKDF2)',
            severity: 'high',
            description: hasInsecureHash
              ? `Credentials from ${src.label} reach ${sink.label} hashed with an insecure fast hash (MD5/SHA1). ` +
                `Fast cryptographic hashes are trivially cracked with GPU rainbow tables and are NOT safe for passwords.`
              : `Credentials from ${src.label} reach ${sink.label} without cryptographic protection. ` +
                `Plaintext credentials are exposed to interception or retrieval.`,
            fix: 'Hash passwords with bcrypt/Argon2/scrypt/PBKDF2 before storage. Never use MD5, SHA1, or other fast ' +
              'cryptographic hashes for password storage. Encrypt API keys and tokens at rest. ' +
              'Transmit credentials only over TLS. Never store plaintext credentials.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-522', name: 'Insufficiently Protected Credentials', holds: findings.length === 0, findings };
};

/**
 * CWE-525: Use of Web Browser Cache Containing Sensitive Information
 * EGRESS sending sensitive response data without cache-control headers.
 * Browsers may cache passwords, credit card numbers accessible to other users.
 */
export const verifyCWE525 = v(
  'CWE-525', 'Use of Web Browser Cache Containing Sensitive Information', 'medium',
  'TRANSFORM', 'EGRESS', nC,
  /\bCache-Control\b|\bno-store\b|\bno-cache\b|\bPragma\b|\bExpires\b/i,
  'CONTROL (cache-control headers — Cache-Control: no-store for sensitive responses)',
  'Set Cache-Control: no-store, no-cache, must-revalidate on responses containing sensitive data. ' +
  'Add Pragma: no-cache and Expires: 0 for HTTP/1.0 compatibility.',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_019_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-400': verifyCWE400,
  'CWE-434': verifyCWE434,
  'CWE-476': verifyCWE476,
  'CWE-522': verifyCWE522,
  'CWE-525': verifyCWE525,
};
