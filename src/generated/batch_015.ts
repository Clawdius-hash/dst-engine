/**
 * DST Generated Verifiers — Batch 015
 * All remaining CONTROL/AUTH patterns + STORAGE→TRANSFORM + misc (105 CWEs).
 *
 * Covers ~25 small pattern shapes (2-9 CWEs each) involving CONTROL, AUTH,
 * STORAGE→TRANSFORM, and STRUCTURAL nodes.
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutTransform,
  hasPathWithoutIntermediateType,
  makeVerifier as v,
  bfs_nC as nC, bfs_nT as nT, bfs_nCi as nCi, bfs_nA as nA,
  bfs_nTi as nTi, bfs_nM as nM,
  SP_V as V, SP_S as S, SP_A as A, SP_E as E, SP_L as L, SP_R as R, SP_I as I,
  scanSourceLines, findNearestNode, detectLanguage,
  type BfsCheck,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Language-gated verifier factory — wraps makeVerifier with a language check.
// Returns PASS immediately if the scanned file doesn't match the required language(s).
// ---------------------------------------------------------------------------
function langGated(
  langs: string[],
  cweId: string, cweName: string, severity: Severity,
  sourceType: NodeType, sinkType: NodeType,
  bfsCheck: BfsCheck, safePattern: RegExp,
  missingDesc: string, fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  const inner = v(cweId, cweName, severity, sourceType, sinkType, bfsCheck, safePattern, missingDesc, fixDesc);
  return (map: NeuralMap): VerificationResult => {
    const lang = detectLanguage(map);
    if (lang && !langs.some(l => lang.includes(l))) {
      return { cwe: cweId, name: cweName, holds: true, findings: [] };
    }
    return inner(map);
  };
}

// ===========================================================================
// INGRESS→CONTROL without CONTROL (9 CWEs)
// ===========================================================================
export const verifyCWE233 = v('CWE-233', 'Improper Handling of Parameters', 'medium', 'INGRESS', 'CONTROL', nCi, V, 'CONTROL (parameter validation before control flow)', 'Validate parameters before using in control flow decisions.');
export const verifyCWE234 = v('CWE-234', 'Failure to Handle Missing Parameter', 'medium', 'INGRESS', 'CONTROL', nCi, /\brequired\b|\bdefault\b|\bnull.*check\b/i, 'CONTROL (required parameter enforcement)', 'Check for required parameters. Provide defaults or reject missing values.');
export const verifyCWE235 = v('CWE-235', 'Improper Handling of Extra Parameters', 'medium', 'INGRESS', 'CONTROL', nCi, /\bstrict\b|\badditional.*false\b|\bunknown.*reject\b/i, 'CONTROL (extra parameter rejection)', 'Reject unexpected parameters. Use strict schema validation.');
export const verifyCWE236 = v('CWE-236', 'Improper Handling of Undefined Parameters', 'medium', 'INGRESS', 'CONTROL', nCi, /\bundefined\b|\btypeof\b|\brequired\b/i, 'CONTROL (undefined parameter handling)', 'Check for undefined parameters before use. Fail explicitly.');
export const verifyCWE239 = v('CWE-239', 'Failure to Handle Incomplete Element', 'medium', 'INGRESS', 'CONTROL', nCi, V, 'CONTROL (incomplete element handling)', 'Handle incomplete/partial elements gracefully. Validate completeness before processing.');
export const verifyCWE449 = v('CWE-449', 'The UI Performs the Wrong Action', 'medium', 'INGRESS', 'CONTROL', nCi, V, 'CONTROL (action verification before execution)', 'Verify the intended action matches what will execute. Confirm destructive actions.');
export const verifyCWE472 = v('CWE-472', 'External Control of Assumed-Immutable Web Parameter', 'high', 'INGRESS', 'CONTROL', nCi, V, 'CONTROL (server-side parameter validation — do not trust hidden fields)', 'Validate all parameters server-side. Hidden fields and cookies are user-modifiable.');
export const verifyCWE478 = v('CWE-478', 'Missing Default Case in Multiple Condition Expression', 'medium', 'INGRESS', 'CONTROL', nCi, /\bdefault\b|\belse\b|\bswitch.*default\b/i, 'CONTROL (default case in switch/conditional)', 'Always include a default case in switch statements and multi-branch conditionals.');
export const verifyCWE834 = v('CWE-834', 'Excessive Iteration', 'medium', 'INGRESS', 'CONTROL', nCi, /\bmax.*iter\b|\blimit\b|\btimeout\b|\bbreak\b/i, 'CONTROL (iteration limits)', 'Limit loop iterations. Use timeouts. Prevent unbounded loops from user-controlled data.');

// ===========================================================================
// INGRESS→AUTH without TRANSFORM (7 CWEs)
// ===========================================================================
export const verifyCWE289 = v('CWE-289', 'Authentication Bypass by Alternate Name', 'high', 'INGRESS', 'AUTH', nT, S, 'TRANSFORM (canonicalization before authentication)', 'Canonicalize identifiers before auth lookup. Alternate names can bypass authentication.');
export const verifyCWE551 = v('CWE-551', 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization', 'high', 'INGRESS', 'AUTH', nT, S, 'TRANSFORM (parse and canonicalize BEFORE authorization)', 'Parse and canonicalize input before authorization checks. Raw input may bypass checks.');
export const verifyCWE565 = v('CWE-565', 'Reliance on Cookies without Validation or Integrity Checking', 'high', 'INGRESS', 'AUTH', nT, /\bsign\b|\bHMAC\b|\bverif\b|\bintegrity\b/i, 'TRANSFORM (cookie signing/integrity check)', 'Sign cookies with HMAC. Verify signatures server-side. Do not trust unsigned cookies for auth.');
export const verifyCWE647 = v('CWE-647', 'Use of Non-Canonical URL Paths for Authorization Decisions', 'high', 'INGRESS', 'AUTH', nT, /\bcanonicalize\b|\bnormalize\b|\bpath\.resolve\b/i, 'TRANSFORM (URL canonicalization before auth)', 'Canonicalize URL paths before authorization decisions. /admin/../secret bypasses path-based auth.');
export const verifyCWE784 = v('CWE-784', 'Reliance on Cookies without Validation or Integrity Checking in a Security Decision', 'high', 'INGRESS', 'AUTH', nT, /\bsign\b|\bHMAC\b|\bintegrity\b|\bverif\b/i, 'TRANSFORM (signed cookies for security decisions)', 'Sign cookies used in security decisions. Verify integrity before trusting.');
export const verifyCWE807 = v('CWE-807', 'Reliance on Untrusted Inputs in a Security Decision', 'high', 'INGRESS', 'AUTH', nT, V, 'TRANSFORM (validate untrusted inputs before security decisions)', 'Do not base security decisions on client-controlled values (Referer, cookies, hidden fields).');
export const verifyCWE836 = v('CWE-836', 'Use of Password Hash Instead of Password for Authentication', 'high', 'INGRESS', 'AUTH', nT, /\bpassword\b.*\bcompare\b|\bbcrypt.*compare\b|\bverify.*password\b/i, 'TRANSFORM (proper password comparison — hash the input, not accept pre-hashed)', 'Compare passwords by hashing the input, not by accepting pre-hashed values. Passing the hash enables bypass.');

// ===========================================================================
// INGRESS→CONTROL without TRANSFORM (6 CWEs)
// ===========================================================================
export const verifyCWE162 = v('CWE-162', 'Improper Neutralization of Trailing Special Elements', 'medium', 'INGRESS', 'CONTROL', nT, S, 'TRANSFORM (trailing special element neutralization before control)', 'Strip trailing special elements before control flow decisions.');
export const verifyCWE229 = v('CWE-229', 'Improper Handling of Values', 'medium', 'INGRESS', 'CONTROL', nT, V, 'TRANSFORM (value validation before control)', 'Validate and transform values before using in control flow.');
export const verifyCWE351 = v('CWE-351', 'Insufficient Type Distinction', 'medium', 'INGRESS', 'CONTROL', nT, /\btypeof\b|\binstanceof\b|\btype.*check\b/i, 'TRANSFORM (type distinction before control decisions)', 'Check types explicitly before branching on them.');
export const verifyCWE595 = v('CWE-595', 'Comparison of Object References Instead of Object Contents', 'medium', 'INGRESS', 'CONTROL', nT, /\b===\b.*\bvalue\b|\bequals\b|\bdeepEqual\b|\bJSON\.stringify\b/i, 'TRANSFORM (value comparison, not reference comparison)', 'Compare object contents (.equals, deepEqual), not references (===), for security decisions.');
// CWE-597: Structural — detect == or != used to compare String objects in Java (should use .equals())
export const verifyCWE597 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];
  const src = map.source_code || '';
  if (!src) return { cwe: 'CWE-597', name: 'Use of Wrong Operator in String Comparison', holds: true, findings };

  // Detect Java: check if source has Java-specific keywords
  const isJava = /\bpackage\s+\w|import\s+java\.|public\s+class\b/.test(src);
  if (!isJava) {
    // For non-Java: fall back to topology check
    const srcs = nodesOfType(map, 'INGRESS');
    const sinks = nodesOfType(map, 'CONTROL');
    for (const s of srcs) {
      for (const sk of sinks) {
        if (s.id === sk.id) continue;
        if (nT(map, s.id, sk.id)) {
          const safeRe = /\b===\b|\bstrictEqual\b|\blocaleCompare\b/i;
          if (!safeRe.test(sk.code_snapshot) && !safeRe.test(s.code_snapshot)) {
            findings.push({
              source: nodeRef(s), sink: nodeRef(sk),
              missing: 'TRANSFORM (strict string comparison)',
              severity: 'medium',
              description: `${s.label} -> ${sk.label}: string comparison uses wrong operator.`,
              fix: 'Use strict equality (===) for string comparisons, not == which coerces types.',
            });
          }
        }
      }
    }
    return { cwe: 'CWE-597', name: 'Use of Wrong Operator in String Comparison', holds: findings.length === 0, findings };
  }

  // Java-specific: find String variables compared with == or !=
  const scanned = scanSourceLines(src);

  // Collect known String variable names (declared as String, method params, or returned from readLine, etc.)
  const stringVars = new Set<string>();
  for (const { line } of scanned) {
    // String varName = ... or String varName;
    const decl = line.match(/\bString\s+(\w+)\s*[=;]/);
    if (decl) stringVars.add(decl[1]);
    // Method parameters: (String varName) or (String varName, ...) or (..., String varName)
    const paramRe = /\bString\s+(\w+)\s*[,)]/g;
    let paramMatch;
    while ((paramMatch = paramRe.exec(line)) !== null) {
      stringVars.add(paramMatch[1]);
    }
    // Also: varName = readerBuffered.readLine()
    const readLine = line.match(/(\w+)\s*=\s*\w+\.readLine\(\)/);
    if (readLine) stringVars.add(readLine[1]);
  }

  for (const { line, lineNum, isComment } of scanned) {
    if (isComment) continue;

    // Detect: stringVar == stringVar, stringVar == "literal", or "literal" == stringVar (reference comparison)
    // But NOT: stringVar == null or stringVar != null (that's valid)
    for (const v1 of stringVars) {
      // Pattern 1: v1 == v2 (where v2 is another variable OR a string literal)
      const eqPattern = new RegExp(`\\b${v1}\\s*==\\s*(?:(\\w+)\\b|("(?:[^"\\\\]|\\\\.)*"))`);
      const match = eqPattern.exec(line);
      if (match) {
        const v2 = match[1] || match[2]; // match[1] = identifier, match[2] = string literal
        if (v2 === 'null' || v2 === 'true' || v2 === 'false') continue; // null check is fine
        if (stringVars.has(v2) || (match[2] !== undefined)) {
          const nearNode = findNearestNode(map, lineNum);
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'TRANSFORM (use .equals() for String comparison)',
              severity: 'medium',
              description: `L${lineNum}: String comparison uses == operator instead of .equals(). '${v1} == ${v2}' compares object references, not string contents.`,
              fix: 'Use String.equals() for content comparison. The == operator compares object references in Java.',
            });
          }
        }
      }

      // Pattern 2: "literal" == v1 (Yoda comparison with string literal on left)
      const yodaPattern = new RegExp(`("(?:[^"\\\\]|\\\\.)*")\\s*==\\s*\\b${v1}\\b`);
      const yodaMatch = yodaPattern.exec(line);
      if (yodaMatch) {
        const lit = yodaMatch[1];
        // Avoid double-reporting if Pattern 1 already caught this line for this variable
        const alreadyReported = findings.some(f => f.description.includes(`L${lineNum}:`) && f.description.includes(v1));
        if (!alreadyReported) {
          const nearNode = findNearestNode(map, lineNum);
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'TRANSFORM (use .equals() for String comparison)',
              severity: 'medium',
              description: `L${lineNum}: String comparison uses == operator instead of .equals(). '${lit} == ${v1}' compares object references, not string contents.`,
              fix: 'Use String.equals() for content comparison. The == operator compares object references in Java.',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-597', name: 'Use of Wrong Operator in String Comparison', holds: findings.length === 0, findings };
};
export const verifyCWE606 = v('CWE-606', 'Unchecked Input for Loop Condition', 'high', 'INGRESS', 'CONTROL', nT, V, 'TRANSFORM (input validation before loop condition)', 'Validate user input used in loop conditions. Unchecked input causes infinite loops.');

// ===========================================================================
// INGRESS→TRANSFORM without AUTH (6 CWEs)
// ===========================================================================
export const verifyCWE345 = v('CWE-345', 'Insufficient Verification of Data Authenticity', 'high', 'INGRESS', 'TRANSFORM', nA, /\bsignature\b|\bHMAC\b|\bverif\b|\bintegrity\b|\bMAC\b/i, 'AUTH (data authenticity verification — signature/HMAC)', 'Verify data authenticity with HMAC or digital signatures before processing.');
// CWE-408: Only flag when there's evidence of expensive operations (crypto, DB, network I/O)
// before authentication — not on every INGRESS→TRANSFORM path.
export const verifyCWE408 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const expensiveSinks = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    /\bcrypto\b|\bhash\b|\bencrypt\b|\bdecrypt\b|\bquery\b|\bfetch\b|\bhttp\b|\brequest\b|\bspawn\b|\bexec\b/i.test(n.code_snapshot)
  );
  for (const src of ingress) {
    for (const sink of expensiveSinks) {
      if (src.id === sink.id) continue;
      if (nA(map, src.id, sink.id)) {
        if (!/\bauth\b.*\bbefore\b|\bverif.*first\b|\brate.*limit\b/i.test(sink.code_snapshot) &&
            !/\bauth\b.*\bbefore\b|\bverif.*first\b|\brate.*limit\b/i.test(src.code_snapshot)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'AUTH (authenticate before expensive operations)', severity: 'high',
            description: `INGRESS at ${src.label} → TRANSFORM at ${sink.label} without controls. Vulnerable to Incorrect Behavior Order: Early Amplification.`,
            fix: 'Authenticate requests before performing expensive operations to prevent amplification DoS.',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-408', name: 'Incorrect Behavior Order: Early Amplification', holds: findings.length === 0, findings };
};
// CWE-422: Windows Shatter attack — only relevant to C/C++ Win32 code
export const verifyCWE422 = langGated(['c', 'cpp', 'c++'], 'CWE-422', 'Unprotected Windows Messaging Channel (Shatter)', 'high', 'INGRESS', 'TRANSFORM', nA, A, 'AUTH (message authentication for IPC)', 'Authenticate sources of Windows messages. Validate message origin before processing.');
export const verifyCWE603 = v('CWE-603', 'Use of Client-Side Authentication', 'critical', 'INGRESS', 'TRANSFORM', nA, /\bserver.*side\b|\bbackend.*auth\b|\bAPI.*auth\b/i, 'AUTH (server-side authentication — never client-only)', 'Always authenticate on the server. Client-side auth can be bypassed by modifying the client.');
// CWE-782: IOCTL — only relevant to C/C++ kernel/driver code
export const verifyCWE782 = langGated(['c', 'cpp', 'c++'], 'CWE-782', 'Exposed IOCTL with Insufficient Access Control', 'high', 'INGRESS', 'TRANSFORM', nA, A, 'AUTH (IOCTL access control)', 'Restrict IOCTL access to authorized processes. Validate caller privileges.');
// CWE-925: Android BroadcastReceiver — only relevant to Java/Kotlin Android code
export const verifyCWE925 = (map: NeuralMap): VerificationResult => {
  const lang = detectLanguage(map);
  // Only applies to Java/Kotlin AND must have Android-specific patterns
  if (lang && !lang.includes('java') && !lang.includes('kotlin')) {
    return { cwe: 'CWE-925', name: 'Improper Verification of Intent by Broadcast Receiver', holds: true, findings: [] };
  }
  const allCode = map.nodes.map(n => n.code_snapshot).join('\n');
  // Must have Android BroadcastReceiver evidence
  if (!/\bBroadcastReceiver\b|\bonReceive\b|\bregisterReceiver\b|\bIntentFilter\b/i.test(allCode)) {
    return { cwe: 'CWE-925', name: 'Improper Verification of Intent by Broadcast Receiver', holds: true, findings: [] };
  }
  return v('CWE-925', 'Improper Verification of Intent by Broadcast Receiver', 'high', 'INGRESS', 'TRANSFORM', nA, /\bpermission\b|\bexport.*false\b|\bverif.*intent\b/i, 'AUTH (broadcast receiver intent verification)', 'Verify intent sources. Set exported=false for internal receivers. Require permissions.')(map);
};

// ===========================================================================
// STORAGE→TRANSFORM without CONTROL (5 CWEs)
// ===========================================================================
export const verifyCWE14 = v('CWE-14', 'Compiler Removal of Code to Clear Buffers', 'medium', 'STORAGE', 'TRANSFORM', nC, /\bvolatile\b|\bexplicit_bzero\b|\bSecureZeroMemory\b|\bmemset_s\b/i, 'CONTROL (compiler-resistant memory clearing)', 'Use volatile or explicit_bzero/SecureZeroMemory to prevent compiler from optimizing out buffer clearing.');
export const verifyCWE244 = v('CWE-244', 'Improper Clearing of Heap Memory Before Release (Heap Inspection)', 'high', 'STORAGE', 'TRANSFORM', nC, /\bzero\b|\bclear\b|\bwipe\b|\bexplicit_bzero\b/i, 'CONTROL (heap clearing before free)', 'Zero sensitive heap memory before freeing. Use explicit_bzero or memset_s.');
export const verifyCWE323 = v('CWE-323', 'Reusing a Nonce, Key Pair in Encryption', 'critical', 'STORAGE', 'TRANSFORM', nC, /\bunique\b|\brandom\b|\bnonce.*new\b|\bfresh.*key\b/i, 'CONTROL (unique nonce/key pair enforcement)', 'Never reuse nonce/key pairs. Generate fresh nonces for each encryption operation.');
export const verifyCWE324 = v('CWE-324', 'Use of a Key Past its Expiration Date', 'high', 'STORAGE', 'TRANSFORM', nC, /\bexpir\b|\brotate\b|\bvalidity\b|\brenew\b/i, 'CONTROL (key expiration / rotation enforcement)', 'Check key expiration before use. Implement automatic key rotation.');
export const verifyCWE911 = v('CWE-911', 'Improper Update of Reference Count', 'high', 'STORAGE', 'TRANSFORM', nC, /\brefCount\b|\breference.*count\b|\batomic\b|\bincrement\b.*\bdecrement\b/i, 'CONTROL (atomic reference count updates)', 'Use atomic operations for reference counting. Ensure increment/decrement are paired.');

// ===========================================================================
// EXTERNAL→STORAGE without AUTH (5 CWEs)
// ===========================================================================
export const verifyCWE412 = v('CWE-412', 'Unrestricted Externally Accessible Lock', 'medium', 'EXTERNAL', 'STORAGE', nA, A, 'AUTH (lock access restriction)', 'Restrict lock acquisition to authorized entities. Prevent external lock manipulation.');
export const verifyCWE491 = v('CWE-491', 'Public cloneable() Method Without Final (Object Hijack)', 'medium', 'EXTERNAL', 'STORAGE', nA, /\bfinal\b|\bprivate\b|\bclone.*restrict\b/i, 'AUTH (restrict cloneable — final class or controlled clone)', 'Make sensitive classes final or override clone() to restrict. Prevent object hijacking via clone.');
export const verifyCWE493 = v('CWE-493', 'Critical Public Variable Without Final Modifier', 'medium', 'EXTERNAL', 'STORAGE', nA, I, 'AUTH (immutable critical variables — final/const/frozen)', 'Make critical public variables final/const. Prevent external modification.');
export const verifyCWE498 = v('CWE-498', 'Cloneable Class Containing Sensitive Information', 'medium', 'EXTERNAL', 'STORAGE', nA, /\bfinal\b|\bclone.*override\b|\bprivate\b/i, 'AUTH (prevent cloning of sensitive objects)', 'Override clone() to throw or make class final. Prevent sensitive data exposure via cloning.');
export const verifyCWE500 = v('CWE-500', 'Public Static Field Not Marked Final', 'medium', 'EXTERNAL', 'STORAGE', nA, I, 'AUTH (immutable public static fields)', 'Mark public static fields as final. Mutable static fields can be modified by any code.');

// ===========================================================================
// CONTROL→STORAGE without CONTROL (5 CWEs)
// ===========================================================================
export const verifyCWE279 = v('CWE-279', 'Incorrect Execution-Assigned Permissions', 'medium', 'CONTROL', 'STORAGE', nCi, /\bchmod\b|\bumask\b|\bpermission\b.*\bset\b/i, 'CONTROL (correct permission assignment at execution time)', 'Set correct permissions when creating resources at runtime.');
export const verifyCWE363 = v('CWE-363', 'Race Condition Enabling Link Following', 'medium', 'CONTROL', 'STORAGE', nCi, /\bO_NOFOLLOW\b|\blstat\b|\batomic\b/i, 'CONTROL (atomic operations to prevent link following race)', 'Use O_NOFOLLOW and atomic file operations to prevent symlink races.');
export const verifyCWE432 = v('CWE-432', 'Dangerous Signal Handler not Disabled During Sensitive Operations', 'medium', 'CONTROL', 'STORAGE', nCi, /\bsigprocmask\b|\bblock.*signal\b|\bsignal.*mask\b/i, 'CONTROL (block signals during critical sections)', 'Block dangerous signals during sensitive operations using sigprocmask.');
export const verifyCWE609 = v('CWE-609', 'Double-Checked Locking', 'medium', 'CONTROL', 'STORAGE', nCi, /\bvolatile\b|\batomic\b|\bMemoryBarrier\b|\bsynchronized\b/i, 'CONTROL (correct double-checked locking with volatile/atomic)', 'Use volatile or atomic for double-checked locking. Without memory barriers, reads can be stale.');
export const verifyCWE821 = v('CWE-821', 'Incorrect Synchronization', 'medium', 'CONTROL', 'STORAGE', nCi, L, 'CONTROL (correct synchronization)', 'Use proper synchronization primitives. Verify lock granularity and ordering.');

// ===========================================================================
// STRUCTURAL→TRANSFORM without META (5 CWEs)
// ===========================================================================
export const verifyCWE506 = v('CWE-506', 'Embedded Malicious Code', 'critical', 'STRUCTURAL', 'TRANSFORM', nM, /\breview\b|\baudit\b|\bscan\b|\bverif\b/i, 'META (code review / malicious code detection)', 'Review all code for malicious payloads. Use automated scanning. Audit third-party dependencies.');
export const verifyCWE507 = v('CWE-507', 'Trojan Horse', 'critical', 'STRUCTURAL', 'TRANSFORM', nM, /\bverif\b|\bsignature\b|\bintegrity\b|\bhash\b/i, 'META (code integrity verification)', 'Verify code integrity with signatures. Review for hidden functionality.');
export const verifyCWE508 = v('CWE-508', 'Non-Replicating Malicious Code', 'critical', 'STRUCTURAL', 'TRANSFORM', nM, /\baudit\b|\breview\b|\bscan\b|\bmonitor\b/i, 'META (runtime monitoring / code audit)', 'Monitor for anomalous behavior. Conduct regular security audits.');
export const verifyCWE733 = v('CWE-733', 'Compiler Optimization Removal or Modification of Security-critical Code', 'medium', 'STRUCTURAL', 'TRANSFORM', nM, /\bvolatile\b|\bbarrier\b|\b__asm__\b|\boptimize.*off\b/i, 'META (compiler optimization awareness for security code)', 'Use volatile, barriers, or optimization pragmas to prevent compiler from removing security code.');
export const verifyCWE912 = v('CWE-912', 'Hidden Functionality', 'critical', 'STRUCTURAL', 'TRANSFORM', nM, /\baudit\b|\breview\b|\bscan\b|\bno.*backdoor\b/i, 'META (code audit for hidden functionality)', 'Audit code for hidden functionality, backdoors, and undocumented features.');

// ===========================================================================
// CONTROL→CONTROL without CONTROL (5 CWEs)
// ===========================================================================
export const verifyCWE567 = v('CWE-567', 'Unsynchronized Access to Shared Data in a Multithreaded Context', 'medium', 'CONTROL', 'CONTROL', nCi, L, 'CONTROL (synchronization for shared control data)', 'Synchronize access to shared control data in multithreaded contexts.');
export const verifyCWE764 = v('CWE-764', 'Multiple Locks of a Critical Resource', 'medium', 'CONTROL', 'CONTROL', nCi, /\brecursive.*lock\b|\btryLock\b|\bReentrantLock\b/i, 'CONTROL (reentrant lock or lock tracking)', 'Use reentrant locks or track lock state to prevent double-locking deadlocks.');
export const verifyCWE765 = v('CWE-765', 'Multiple Unlocks of a Critical Resource', 'medium', 'CONTROL', 'CONTROL', nCi, /\block.*count\b|\bbalanced\b|\btry.*finally\b/i, 'CONTROL (balanced lock/unlock)', 'Ensure each lock has exactly one unlock. Use try/finally for balanced locking.');
export const verifyCWE833 = v('CWE-833', 'Deadlock', 'high', 'CONTROL', 'CONTROL', nCi, /\block.*order\b|\btimeout\b|\btryLock\b|\bdeadlock.*detect\b/i, 'CONTROL (deadlock prevention — consistent lock ordering, timeouts)', 'Use consistent lock ordering. Apply timeouts with tryLock(). Implement deadlock detection.');
export const verifyCWE835 = v('CWE-835', 'Loop with Unreachable Exit Condition (Infinite Loop)', 'medium', 'CONTROL', 'CONTROL', nCi, /\bbreak\b|\btimeout\b|\bmax.*iter\b|\bwatchdog\b/i, 'CONTROL (reachable loop exit / iteration limit)', 'Ensure all loops have reachable exit conditions. Add iteration limits and watchdog timers.');

// ===========================================================================
// TRANSFORM→CONTROL without CONTROL (4 CWEs)
// ===========================================================================
export const verifyCWE128 = v('CWE-128', 'Wrap-around Error', 'high', 'TRANSFORM', 'CONTROL', nC, /\boverflow\b|\bchecked\b|\bsafe.*math\b|\bclamp\b/i, 'CONTROL (wrap-around detection before control flow)', 'Check for integer wrap-around before using in control decisions.');
export const verifyCWE252 = v('CWE-252', 'Unchecked Return Value', 'medium', 'TRANSFORM', 'CONTROL', nC, /\bif\s*\(\s*\w+\b|\bcheck\b|\bassert\b|\b!==?\s*(null|undefined|-1)\b/i, 'CONTROL (return value check before control flow)', 'Always check return values before using in control decisions. Handle error returns explicitly.');
export const verifyCWE253 = v('CWE-253', 'Incorrect Check of Function Return Value', 'medium', 'TRANSFORM', 'CONTROL', nC, V, 'CONTROL (correct return value interpretation)', 'Check return values correctly. Do not confuse error indicators with success (e.g., -1 vs 0).');
export const verifyCWE681 = v('CWE-681', 'Incorrect Conversion between Numeric Types', 'medium', 'TRANSFORM', 'CONTROL', nC, /\brange.*check\b|\bNumber\.isSafe\b|\btypeof\b|\bvalidate.*type\b/i, 'CONTROL (numeric type validation before conversion)', 'Validate numeric ranges before type conversion. Check for loss of precision.');

// ===========================================================================
// AUTH→CONTROL without CONTROL (4 CWEs)
// ===========================================================================
export const verifyCWE267 = v('CWE-267', 'Privilege Defined With Unsafe Actions', 'high', 'AUTH', 'CONTROL', nCi, /\bleast.*privilege\b|\bminimal\b|\brestrict\b/i, 'CONTROL (least privilege — no unsafe actions in privilege definitions)', 'Define privileges with minimum necessary permissions. Do not bundle dangerous actions.');
export const verifyCWE268 = v('CWE-268', 'Privilege Chaining', 'high', 'AUTH', 'CONTROL', nCi, /\bseparate\b|\bindependent\b|\bno.*chain\b/i, 'CONTROL (independent privilege validation — no chaining)', 'Validate each privilege independently. Do not allow one privilege to grant others.');
export const verifyCWE270 = v('CWE-270', 'Privilege Context Switching Error', 'high', 'AUTH', 'CONTROL', nCi, V, 'CONTROL (correct privilege context after switching)', 'Verify privilege context after switching. Ensure dropped privileges are actually dropped.');
export const verifyCWE368 = v('CWE-368', 'Context Switching Race Condition', 'medium', 'AUTH', 'CONTROL', nCi, L, 'CONTROL (atomic context switching)', 'Make context switches atomic. Prevent races between permission check and context change.');

// ===========================================================================
// AUTH→TRANSFORM without CONTROL (4 CWEs)
// ===========================================================================
export const verifyCWE272 = v('CWE-272', 'Least Privilege Violation', 'high', 'AUTH', 'TRANSFORM', nC, /\bleast.*privilege\b|\bdrop.*privilege\b|\bminimal\b/i, 'CONTROL (least privilege enforcement)', 'Run with minimum necessary privileges. Drop elevated privileges after use.');
export const verifyCWE274 = v('CWE-274', 'Improper Handling of Insufficient Privileges', 'medium', 'AUTH', 'TRANSFORM', nC, /\bcheck.*privilege\b|\bfail.*secure\b|\bdeny\b/i, 'CONTROL (graceful handling of insufficient privileges)', 'Handle privilege failures gracefully. Fail securely — deny access on privilege errors.');
export const verifyCWE280 = v('CWE-280', 'Improper Handling of Insufficient Permissions or Privileges', 'medium', 'AUTH', 'TRANSFORM', nC, /\bpermission\b.*\bcheck\b|\bdeny\b|\bfail.*secure\b/i, 'CONTROL (permission check error handling)', 'Check permissions before operations. Handle permission errors securely.');
export const verifyCWE520 = v('CWE-520', '.NET Misconfiguration: Use of Impersonation', 'medium', 'AUTH', 'TRANSFORM', nC, /\bimpersonat\b.*\brevert\b|\bWindowsIdentity\b.*\bUndo\b/i, 'CONTROL (revert impersonation after use)', 'Always revert impersonation in finally blocks. Impersonation should be scoped and temporary.');

// ===========================================================================
// INGRESS→AUTH without AUTH (3 CWEs) — uses nAi (intermediate)
// ===========================================================================
export const verifyCWE291 = v('CWE-291', 'Reliance on IP Address for Authentication', 'high', 'INGRESS', 'AUTH', nA, /\btoken\b|\bcertificate\b|\bcredential\b|\bpassword\b|\bMFA\b/i, 'AUTH (proper authentication — not IP-based)', 'Do not rely on IP addresses for authentication. IPs can be spoofed. Use proper credentials.');
export const verifyCWE293 = v('CWE-293', 'Using Referer Field for Authentication', 'high', 'INGRESS', 'AUTH', nA, /\btoken\b|\bsession\b|\bcredential\b/i, 'AUTH (proper authentication — not Referer-based)', 'Do not use HTTP Referer header for authentication. It is easily spoofed.');
export const verifyCWE308 = v('CWE-308', 'Use of Single-factor Authentication', 'medium', 'INGRESS', 'AUTH', nA, /\bMFA\b|\b2FA\b|\bmulti.*factor\b/i, 'AUTH (multi-factor authentication)', 'Implement MFA for sensitive operations. Single-factor auth is insufficient for high-value targets.');

// ===========================================================================
// Remaining 3-CWE shapes
// ===========================================================================

// TRANSFORM→AUTH without CONTROL (3)
/**
 * CWE-330: Use of Insufficiently Random Values
 * UPGRADED — hand-written with specific source and sink filters.
 *
 * Pattern: A TRANSFORM node uses a weak random function (Math.random,
 * random.randint, rand(), srand, etc.) and the output flows to an AUTH
 * node that uses it for security-critical purposes (tokens, session IDs,
 * passwords, nonces, CSRF tokens, encryption keys).
 *
 * The generic version checked ALL TRANSFORM -> ALL AUTH without CONTROL.
 * The upgraded version:
 *   - Sources: TRANSFORM nodes whose code uses weak random functions
 *   - Sinks: AUTH nodes using the value for security purposes
 *   - Safe patterns: crypto.randomBytes, crypto.getRandomValues, CSPRNG,
 *     uuid.v4 (which uses crypto internally), secrets module (Python)
 */
export const verifyCWE330 = (function() {
  // Weak random sources — these are NOT cryptographically secure
  const WEAK_RANDOM = /\bMath\.random\b|\brandom\.randint\b|\brandom\.random\b|\brandom\.choice\b|\brand\(\)|\bsrand\b|\bmt_rand\b|\barray_rand\b|\bRandom\(\)\.next\b|\bRandom\.Next\b|\bjava\.util\.Random\b|\bThreadLocalRandom\b/i;

  // Strong random — if present, this is safe
  const STRONG_RANDOM = /\bcrypto\.randomBytes\b|\bcrypto\.getRandomValues\b|\brandomBytes\b|\bgetRandomValues\b|\bcrypto\.randomUUID\b|\buuid\.v4\b|\bsecrets\.\b|\bcrypto\.randomInt\b|\bSecureRandom\b|\bRandomNumberGenerator\b|\bos\.urandom\b|\bCSPRNG\b|\bcrypto\/rand\b|\brand\.Read\b/i;

  // Security-critical sinks where randomness matters
  const SECURITY_SINK = /\btoken\b|\bsession\b|\bnonce\b|\bcsrf\b|\bsalt\b|\bkey\b|\biv\b|\bsecret\b|\bpassword\b|\breset\b.*\blink\b|\bverification\b.*\bcode\b|\botp\b/i;

  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];

    // Sources: TRANSFORM nodes using weak random
    const weakRandomSources = map.nodes.filter(n =>
      n.node_type === 'TRANSFORM' &&
      WEAK_RANDOM.test(n.code_snapshot) &&
      !STRONG_RANDOM.test(n.code_snapshot)
    );

    // Sinks: AUTH nodes used for security-critical purposes
    const securitySinks = map.nodes.filter(n =>
      n.node_type === 'AUTH' &&
      SECURITY_SINK.test(n.code_snapshot)
    );

    for (const src of weakRandomSources) {
      for (const sink of securitySinks) {
        if (src.id === sink.id) continue;
        if (nC(map, src.id, sink.id)) {
          // Double-check: is there a CONTROL node that upgrades the randomness?
          const hasUpgrade = map.nodes.some(n =>
            n.node_type === 'CONTROL' &&
            STRONG_RANDOM.test(n.code_snapshot)
          );

          if (!hasUpgrade) {
            const weakFunc = src.code_snapshot.match(WEAK_RANDOM);
            const weakName = weakFunc ? weakFunc[0] : 'weak random function';

            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (cryptographically secure random number generator)',
              severity: 'high',
              description: `Weak random function "${weakName}" at ${src.label} generates values used ` +
                `for security at ${sink.label}. ${weakName} is predictable — an attacker can ` +
                `reproduce the sequence and forge tokens, session IDs, or keys.`,
              fix: 'Replace Math.random() with crypto.randomBytes() or crypto.getRandomValues(). ' +
                'In Python, use the secrets module. In Java, use SecureRandom. ' +
                'In Go, use crypto/rand. Never use Math.random for security-critical values.',
            });
          }
        }
      }
    }

    return { cwe: 'CWE-330', name: 'Use of Insufficiently Random Values', holds: findings.length === 0, findings };
  };
})();
export const verifyCWE331 = v('CWE-331', 'Insufficient Entropy', 'high', 'TRANSFORM', 'AUTH', nC, /\bentropy\b|\brandomBytes\b|\bsufficient.*random\b/i, 'CONTROL (sufficient entropy for random values)', 'Ensure sufficient entropy for security-critical random generation.');
export const verifyCWE334 = v('CWE-334', 'Small Space of Random Values', 'high', 'TRANSFORM', 'AUTH', nC, /\b(128|256)\b.*\bbit\b|\bUUID\b|\blong.*random\b/i, 'CONTROL (sufficient random value space — 128+ bits)', 'Use 128+ bits for random tokens. Small spaces are brute-forceable.');

// TRANSFORM→EGRESS without TRANSFORM (3)
export const verifyCWE339 = v('CWE-339', 'Small Seed Space in PRNG', 'high', 'TRANSFORM', 'EGRESS', nTi, /\bcrypto\.random\b|\blarge.*seed\b|\bCSPRNG\b/i, 'TRANSFORM (large seed space / CSPRNG)', 'Use CSPRNG with sufficient seed space. Small seed spaces allow prediction.');
export const verifyCWE401 = v('CWE-401', 'Missing Release of Memory after Effective Lifetime', 'medium', 'TRANSFORM', 'EGRESS', nTi, R, 'TRANSFORM (memory release after use)', 'Free memory after effective lifetime. Use RAII or try/finally for cleanup.');
export const verifyCWE404 = v('CWE-404', 'Improper Resource Shutdown or Release', 'medium', 'TRANSFORM', 'EGRESS', nTi, R, 'TRANSFORM (proper resource release/shutdown)', 'Release all resources in finally blocks. Close connections, files, and handles.');

// TRANSFORM→AUTH without TRANSFORM (3)
export const verifyCWE340 = v('CWE-340', 'Generation of Predictable Numbers or Identifiers', 'high', 'TRANSFORM', 'AUTH', nTi, /\bcrypto\.random\b|\bUUID\b|\brandomBytes\b/i, 'TRANSFORM (unpredictable ID generation — CSPRNG)', 'Use cryptographically random IDs. Predictable IDs enable enumeration attacks.');
export const verifyCWE342 = v('CWE-342', 'Predictable Exact Value from Previous Values', 'high', 'TRANSFORM', 'AUTH', nTi, /\bcrypto\.random\b|\bCSPRNG\b|\bnon.*sequential\b/i, 'TRANSFORM (non-sequential, random value generation)', 'Do not use sequential or predictable values for security tokens.');
export const verifyCWE343 = v('CWE-343', 'Predictable Value Range from Previous Values', 'high', 'TRANSFORM', 'AUTH', nTi, /\bcrypto\.random\b|\bfull.*range\b|\buniform\b/i, 'TRANSFORM (full-range random generation)', 'Generate values across the full range. Narrow ranges reduce effective entropy.');

// INGRESS→CONTROL without AUTH (3)
export const verifyCWE346 = v('CWE-346', 'Origin Validation Error', 'high', 'INGRESS', 'CONTROL', nA, /\bOrigin\b|\bCORS\b|\bAccess-Control\b|\breferer\b.*\bcheck\b/i, 'AUTH (origin validation — CORS, Origin header check)', 'Validate request origin. Use CORS headers. Check Origin header for cross-origin requests.');
export const verifyCWE360 = v('CWE-360', 'Trust of System Event Data', 'medium', 'INGRESS', 'CONTROL', nA, V, 'AUTH (system event data validation)', 'Do not blindly trust system events. Validate event data and origin.');
export const verifyCWE510 = v('CWE-510', 'Trapdoor', 'critical', 'INGRESS', 'CONTROL', nA, /\baudit\b|\breview\b|\bno.*backdoor\b/i, 'AUTH (no hidden authentication bypasses)', 'Audit for trapdoors/backdoors. Review all authentication paths.');

// AUTH→EXTERNAL without CONTROL (3)
export const verifyCWE266 = v('CWE-266', 'Incorrect Privilege Assignment', 'high', 'AUTH', 'EXTERNAL', nC, /\bleast.*privilege\b|\bminimal\b|\brestrict\b/i, 'CONTROL (correct privilege assignment)', 'Assign minimum necessary privileges. Review privilege assignments regularly.');
export const verifyCWE271 = v('CWE-271', 'Privilege Dropping / Lowering Errors', 'high', 'AUTH', 'EXTERNAL', nC, /\bdrop\b.*\bcheck\b|\bverif.*privilege\b|\bgetuid\b/i, 'CONTROL (verify privilege drop succeeded)', 'Check return values of privilege-dropping calls. Verify effective UID/GID after drop.');
export const verifyCWE301 = v('CWE-301', 'Reflection Attack in an Authentication Protocol', 'high', 'AUTH', 'EXTERNAL', nC, /\bnonce\b|\bchallenge\b|\bsession.*id\b|\bdirection\b/i, 'CONTROL (directional challenge-response — prevent reflection)', 'Use distinct challenges for each direction. Include session IDs to prevent reflection attacks.');

// META→STORAGE without TRANSFORM (3)
export const verifyCWE318 = v('CWE-318', 'Cleartext Storage of Sensitive Information in Executable', 'medium', 'META', 'STORAGE', nT, E, 'TRANSFORM (encryption of sensitive data in executables)', 'Do not embed cleartext secrets in executables. Use encrypted config or environment variables.');
export const verifyCWE555 = v('CWE-555', 'J2EE Misconfiguration: Plaintext Password in Configuration File', 'high', 'META', 'STORAGE', nT, E, 'TRANSFORM (encrypt passwords in J2EE config)', 'Encrypt passwords in J2EE configuration files. Use JNDI lookups or vault integration.');
export const verifyCWE587 = v('CWE-587', 'Assignment of a Fixed Address to a Pointer', 'medium', 'META', 'STORAGE', nT, /\bdynamic\b|\bmalloc\b|\bvolatile\b|\bno.*fixed.*addr\b/i, 'TRANSFORM (dynamic address resolution, not fixed)', 'Do not assign fixed addresses to pointers. Use dynamic allocation for portability and ASLR.');

// CONTROL→STORAGE without TRANSFORM (3)
// CWE-482: Structural — detect comparison (==) used where assignment (=) was intended
export const verifyCWE482 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];
  const src = map.source_code || '';
  if (!src) return { cwe: 'CWE-482', name: 'Comparing instead of Assigning', holds: true, findings };

  const scanned = scanSourceLines(src);

  // Pattern: inside an if-condition, a comparison is used where assignment was likely intended.
  // The Juliet pattern: if((isZero == (zeroOrOne == 0)) == true) — should be =, not ==
  // General pattern: if((var == expr) == true) or standalone comparison-as-statement
  // Also: var == value; as a standalone statement (comparison result discarded)
  for (const { line, lineNum, isComment } of scanned) {
    if (isComment) continue;

    // Pattern 1: if((boolVar == (expr)) == true) — the outer == should be = (assignment inside if)
    // Detect: if( (identifier == (expr)) == true )
    if (/\bif\s*\(\s*\(\s*\w+\s*==\s*\([^)]+\)\s*\)\s*==\s*true\s*\)/.test(line)) {
      const nearNode = findNearestNode(map, lineNum);
      if (nearNode) {
        findings.push({
          source: nodeRef(nearNode), sink: nodeRef(nearNode),
          missing: 'TRANSFORM (use = for assignment, not == for comparison)',
          severity: 'medium',
          description: `L${lineNum}: Comparison (==) used where assignment (=) was likely intended inside if-condition.`,
          fix: 'Use = for assignment, == for comparison. The == operator does not modify the variable.',
        });
      }
    }

    // Pattern 2: standalone comparison-as-statement: identifier == value;
    // (a comparison whose result is discarded)
    const standalone = line.match(/^\s*(\w+)\s*==\s*[^=].*;\s*$/);
    if (standalone && !/\bif\b|\bwhile\b|\breturn\b|\bfor\b/.test(line)) {
      const nearNode = findNearestNode(map, lineNum);
      if (nearNode) {
        findings.push({
          source: nodeRef(nearNode), sink: nodeRef(nearNode),
          missing: 'TRANSFORM (use = for assignment, not == for comparison)',
          severity: 'medium',
          description: `L${lineNum}: Comparison result discarded — '${standalone[1]} ==' should likely be '${standalone[1]} =' (assignment).`,
          fix: 'Use = for assignment, == for comparison. Standalone comparisons have no effect.',
        });
      }
    }
  }

  return { cwe: 'CWE-482', name: 'Comparing instead of Assigning', holds: findings.length === 0, findings };
};
export const verifyCWE560 = v('CWE-560', 'Use of umask() with chmod()-style Argument', 'medium', 'CONTROL', 'STORAGE', nT, /\bumask\b.*\b0[0-7]{3}\b|\bcorrect.*umask\b/i, 'TRANSFORM (correct umask argument — complement of desired permissions)', 'umask takes complement of desired permissions. umask(022) not umask(755).');
export const verifyCWE656 = v('CWE-656', 'Reliance on Security Through Obscurity', 'medium', 'CONTROL', 'STORAGE', nT, E, 'TRANSFORM (proper security mechanisms, not obscurity)', 'Use encryption, authentication, and access controls — not obscurity — for security.');

// STORAGE→STORAGE without AUTH (3)
export const verifyCWE538 = v('CWE-538', 'Insertion of Sensitive Information into Externally-Accessible File or Directory', 'high', 'STORAGE', 'STORAGE', nA, A, 'AUTH (access control on files containing sensitive data)', 'Restrict access to files containing sensitive data. Do not write to publicly accessible directories.');
export const verifyCWE921 = v('CWE-921', 'Storage of Sensitive Data in a Mechanism without Access Control', 'high', 'STORAGE', 'STORAGE', nA, A, 'AUTH (access-controlled storage for sensitive data)', 'Store sensitive data in access-controlled storage. Do not use world-readable storage.');
export const verifyCWE922 = v('CWE-922', 'Insecure Storage of Sensitive Information', 'high', 'STORAGE', 'STORAGE', nA, E, 'AUTH (encrypted storage with access control)', 'Encrypt sensitive information at rest. Apply access controls to storage locations.');

// STRUCTURAL→EGRESS without CONTROL (3)
export const verifyCWE568 = v('CWE-568', 'finalize() Method Without super.finalize()', 'low', 'STRUCTURAL', 'EGRESS', nC, /\bsuper\.finalize\b|\btry.*finally\b/i, 'CONTROL (call super.finalize() in finalizer)', 'Always call super.finalize() in overridden finalizers. Use try/finally.');
export const verifyCWE583 = v('CWE-583', 'finalize() Method Declared Public', 'low', 'STRUCTURAL', 'EGRESS', nC, /\bprotected\b|\bprivate\b/i, 'CONTROL (protected finalize method)', 'Declare finalize() as protected, not public.');
export const verifyCWE657 = v('CWE-657', 'Violation of Secure Design Principles', 'medium', 'STRUCTURAL', 'EGRESS', nC, /\bsecure.*design\b|\bdefense.*depth\b|\bleast.*privilege\b/i, 'CONTROL (secure design principles)', 'Follow secure design principles: least privilege, defense in depth, fail-safe defaults.');

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_015_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-233': verifyCWE233, 'CWE-234': verifyCWE234, 'CWE-235': verifyCWE235, 'CWE-236': verifyCWE236,
  'CWE-239': verifyCWE239, 'CWE-449': verifyCWE449, 'CWE-472': verifyCWE472, 'CWE-478': verifyCWE478,
  'CWE-834': verifyCWE834, 'CWE-289': verifyCWE289, 'CWE-551': verifyCWE551, 'CWE-565': verifyCWE565,
  'CWE-647': verifyCWE647, 'CWE-784': verifyCWE784, 'CWE-807': verifyCWE807, 'CWE-836': verifyCWE836,
  'CWE-162': verifyCWE162, 'CWE-229': verifyCWE229, 'CWE-351': verifyCWE351, 'CWE-595': verifyCWE595,
  'CWE-597': verifyCWE597, 'CWE-606': verifyCWE606, 'CWE-345': verifyCWE345, 'CWE-408': verifyCWE408,
  'CWE-422': verifyCWE422, 'CWE-603': verifyCWE603, 'CWE-782': verifyCWE782, 'CWE-925': verifyCWE925,
  'CWE-14': verifyCWE14, 'CWE-244': verifyCWE244, 'CWE-323': verifyCWE323, 'CWE-324': verifyCWE324,
  'CWE-911': verifyCWE911, 'CWE-412': verifyCWE412, 'CWE-491': verifyCWE491, 'CWE-493': verifyCWE493,
  'CWE-498': verifyCWE498, 'CWE-500': verifyCWE500, 'CWE-279': verifyCWE279, 'CWE-363': verifyCWE363,
  'CWE-432': verifyCWE432, 'CWE-609': verifyCWE609, 'CWE-821': verifyCWE821, 'CWE-506': verifyCWE506,
  'CWE-507': verifyCWE507, 'CWE-508': verifyCWE508, 'CWE-733': verifyCWE733, 'CWE-912': verifyCWE912,
  'CWE-567': verifyCWE567, 'CWE-764': verifyCWE764, 'CWE-765': verifyCWE765, 'CWE-833': verifyCWE833,
  'CWE-835': verifyCWE835, 'CWE-128': verifyCWE128, 'CWE-252': verifyCWE252, 'CWE-253': verifyCWE253,
  'CWE-681': verifyCWE681, 'CWE-267': verifyCWE267, 'CWE-268': verifyCWE268, 'CWE-270': verifyCWE270,
  'CWE-368': verifyCWE368, 'CWE-272': verifyCWE272, 'CWE-274': verifyCWE274, 'CWE-280': verifyCWE280,
  'CWE-520': verifyCWE520, 'CWE-291': verifyCWE291, 'CWE-293': verifyCWE293, 'CWE-308': verifyCWE308,
  'CWE-330': verifyCWE330, 'CWE-331': verifyCWE331, 'CWE-334': verifyCWE334, 'CWE-339': verifyCWE339,
  'CWE-401': verifyCWE401, 'CWE-404': verifyCWE404, 'CWE-340': verifyCWE340, 'CWE-342': verifyCWE342,
  'CWE-343': verifyCWE343, 'CWE-346': verifyCWE346, 'CWE-360': verifyCWE360, 'CWE-510': verifyCWE510,
  'CWE-266': verifyCWE266, 'CWE-271': verifyCWE271, 'CWE-301': verifyCWE301, 'CWE-318': verifyCWE318,
  'CWE-555': verifyCWE555, 'CWE-587': verifyCWE587, 'CWE-482': verifyCWE482, 'CWE-560': verifyCWE560,
  'CWE-656': verifyCWE656, 'CWE-538': verifyCWE538, 'CWE-921': verifyCWE921, 'CWE-922': verifyCWE922,
  'CWE-568': verifyCWE568, 'CWE-583': verifyCWE583, 'CWE-657': verifyCWE657,
};
