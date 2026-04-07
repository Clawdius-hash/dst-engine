/**
 * DST Generated Verifiers — Batch 018
 * CWEs 200-399 gap fill — real verifiers only (16 CWEs).
 *
 * Sub-groups:
 *   A. Information exposure & error handling  (3 CWEs)  — factory-driven
 *   B. Authentication & auth bypass           (5 CWEs)  — factory-driven
 *   C. Cryptography & data protection         (4 CWEs)  — factory-driven (+ 2 hand-written)
 *   D. Concurrency & state                    (3 CWEs)  — factory-driven (+ 1 hand-written)
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutTransform,
  hasPathWithoutIntermediateType,
  makeVerifier as v,
  bfs_nC as nC, bfs_nT as nT, bfs_nA as nA, bfs_nCi as nCi,
  bfs_nTi as nTi, bfs_nS as nS,
  SP_V as V, SP_A as A, SP_E as E, SP_L as L,
  scanSourceLines, findNearestNode,
  type BfsCheck,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ===========================================================================
// A. INFORMATION EXPOSURE & ERROR HANDLING (3 CWEs)
// ===========================================================================

// CWE-209: Structural — detect stack trace / error details exposure in catch blocks
export const verifyCWE209 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];
  const src = map.source_code || '';
  if (!src) return { cwe: 'CWE-209', name: 'Generation of Error Message Containing Sensitive Information', holds: true, findings };

  const scanned = scanSourceLines(src);

  // Pattern 1: Java .printStackTrace() in catch blocks
  // Pattern 2: e.getMessage() / e.toString() sent to response/output
  // Pattern 3: JS/Node: err.stack sent to res.send/res.json
  for (const { line, lineNum, isComment } of scanned) {
    if (isComment) continue;

    // Java: exception.printStackTrace()
    if (/\w+\.printStackTrace\s*\(\s*\)/.test(line)) {
      const nearNode = findNearestNode(map, lineNum);
      if (nearNode) {
        findings.push({
          source: nodeRef(nearNode), sink: nodeRef(nearNode),
          missing: 'TRANSFORM (redact stack traces from error output)',
          severity: 'medium',
          description: `L${lineNum}: printStackTrace() exposes internal stack trace to output. This leaks class names, file paths, and line numbers.`,
          fix: 'Log stack traces to a secure log. Return generic error messages to users. Never expose stack traces in production.',
        });
      }
    }

    // Java: e.getMessage() or e.toString() sent to output (response, println, writeLine)
    if (/\b(res\.send|res\.json|res\.write|System\.out\.print|IO\.writeLine|response\.getWriter)\s*\(.*\b\w+\.(getMessage|toString|getStackTrace)\b/.test(line)) {
      const nearNode = findNearestNode(map, lineNum);
      if (nearNode) {
        findings.push({
          source: nodeRef(nearNode), sink: nodeRef(nearNode),
          missing: 'TRANSFORM (redact error details from user-facing output)',
          severity: 'medium',
          description: `L${lineNum}: Error message details (getMessage/toString) sent to user-facing output. May expose sensitive internals.`,
          fix: 'Sanitize error messages before returning to users. Strip SQL queries, file paths, and credentials.',
        });
      }
    }

    // JS: err.stack in res.send/res.json
    if (/\b(res\.send|res\.json|res\.status)\b.*\b(err|error)\.stack\b/.test(line)) {
      const nearNode = findNearestNode(map, lineNum);
      if (nearNode) {
        findings.push({
          source: nodeRef(nearNode), sink: nodeRef(nearNode),
          missing: 'TRANSFORM (redact stack traces from error responses)',
          severity: 'medium',
          description: `L${lineNum}: Error stack trace sent in HTTP response. Exposes internal paths and code structure.`,
          fix: 'Return generic error messages in production. Log detailed errors server-side only.',
        });
      }
    }
  }

  return { cwe: 'CWE-209', name: 'Generation of Error Message Containing Sensitive Information', holds: findings.length === 0, findings };
};

// CWE-372: Product doesn't properly distinguish internal state
export const verifyCWE372 = v(
  'CWE-372', 'Incomplete Internal State Distinction', 'medium',
  'CONTROL', 'STORAGE', nCi,
  /\bstate.*machine\b|\btrack.*state\b|\bexplicit.*state\b|\benum\b/i,
  'CONTROL (explicit state tracking before security decisions)',
  'Track internal state explicitly using state machines or enums. Do not assume state from implicit conditions.',
);

// CWE-391: Unchecked error condition
export const verifyCWE391 = v(
  'CWE-391', 'Unchecked Error Condition', 'medium',
  'TRANSFORM', 'EXTERNAL', nCi,
  /\bcatch\b|\btry\b|\berror.*check\b|\breturn.*code\b|\bif.*err\b/i,
  'CONTROL (error condition check after fallible operation)',
  'Check return values and catch exceptions from all fallible operations. Do not ignore errors.',
);

// ===========================================================================
// B. AUTHENTICATION & AUTH BYPASS (5 CWEs)
// ===========================================================================

// CWE-269: Improper privilege management — privileges not properly tracked/enforced
export const verifyCWE269 = v(
  'CWE-269', 'Improper Privilege Management', 'high',
  'AUTH', 'EXTERNAL', nCi,
  /\bprivilege\b|\brole.*check\b|\bleast.*privilege\b|\bdrop.*priv\b/i,
  'CONTROL (privilege verification before operations)',
  'Verify privileges before each privileged operation. Apply least privilege principle. Drop privileges when no longer needed.',
);

// CWE-287: Improper Authentication — identity not verified before protected resource access
// Hand-written: specific sink detection for protected resources and specific safe patterns
// for real authentication mechanisms (JWT, session, passport, bcrypt, OAuth).
export const verifyCWE287 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];

  // Sources: any user-facing ingress
  const ingress = nodesOfType(map, 'INGRESS');

  // Sinks: protected resources — database access, admin endpoints, sensitive operations
  const protectedSinks = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' &&
      (n.node_subtype.includes('sql') || n.node_subtype.includes('query') ||
       n.node_subtype.includes('database') || n.node_subtype.includes('file') ||
       n.attack_surface.includes('protected_resource') ||
       n.code_snapshot.match(
         /\b(query|exec|execute|find|findOne|findById|update|delete|remove|insertOne|aggregate|save)\s*\(/i
       ) !== null)) ||
    (n.node_type === 'EXTERNAL' &&
      (n.node_subtype.includes('admin') || n.node_subtype.includes('privileged') ||
       n.attack_surface.includes('admin') ||
       n.code_snapshot.match(
         /\b(admin|sudo|privilege|secret|internal)\b/i
       ) !== null))
  );

  // Safe patterns: real authentication mechanisms
  const hasAuth = (code: string): boolean =>
    /\bjwt\.verify\b|\bpassport\.authenticate\b|\breq\.isAuthenticated\b|\bsession\.user\b/i.test(code) ||
    /\bbcrypt\.compare\b|\bverifyToken\b|\bcheckAuth\b|\bauthMiddleware\b|\brequireAuth\b/i.test(code) ||
    /\boauth\b|\bopenid\b|\bsaml\b|\bbearer\b.*\btoken\b|\bAuthorization\b.*\bheader\b/i.test(code) ||
    /\bisLoggedIn\b|\bisAuthenticated\b|\bensureAuthenticated\b|\bguard\b.*\bauth\b/i.test(code);

  for (const src of ingress) {
    for (const sink of protectedSinks) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutIntermediateType(map, src.id, sink.id, 'AUTH')) {
        // Check if the sink or source code contains real auth mechanisms
        if (!hasAuth(sink.code_snapshot) && !hasAuth(src.code_snapshot)) {
          const sinkDesc = sink.node_type === 'EXTERNAL' ? 'privileged operation' : 'database query';
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'AUTH (identity verification — JWT, session check, or auth middleware)',
            severity: 'critical',
            description: `Unauthenticated request from ${src.label} reaches ${sinkDesc} at ${sink.label} ` +
              `without identity verification. Attackers can access protected resources directly.`,
            fix: 'Add authentication middleware before protected routes. Use JWT verification, session validation, ' +
              'or passport.authenticate(). Example: router.get("/admin", requireAuth, handler)',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-287', name: 'Improper Authentication', holds: findings.length === 0, findings };
};

// CWE-290: Auth bypass by spoofing — trusting spoofable attributes
export const verifyCWE290 = v(
  'CWE-290', 'Authentication Bypass by Spoofing', 'high',
  'INGRESS', 'AUTH', nTi,
  /\bcryptographic\b|\bsignature\b|\btoken\b|\bno.*ip.*auth\b|\bno.*header.*trust\b/i,
  'TRANSFORM (cryptographic identity verification, not spoofable attributes)',
  'Do not authenticate via IP address, DNS name, or HTTP headers alone. Use cryptographic verification.',
);

// CWE-295: Improper certificate validation
export const verifyCWE295 = v(
  'CWE-295', 'Improper Certificate Validation', 'high',
  'EXTERNAL', 'STORAGE', nA,
  /\bcertificate\b|\btls.*verif\b|\bca.*chain\b|\bhostname.*check\b|\brejectUnauthorized\b/i,
  'AUTH (certificate chain + hostname + expiration validation)',
  'Validate certificate chain, hostname match, and expiration. Never set rejectUnauthorized to false in production.',
);

// CWE-307: No rate limiting on authentication
export const verifyCWE307 = v(
  'CWE-307', 'Improper Restriction of Excessive Authentication Attempts', 'high',
  'INGRESS', 'AUTH', nCi,
  /\brate.*limit\b|\blockout\b|\bthrottle\b|\bcaptcha\b|\bdelay\b|\bbackoff\b/i,
  'CONTROL (rate limiting / lockout on authentication attempts)',
  'Implement rate limiting, account lockout, or CAPTCHA on login. Prevent brute-force attacks.',
);

// ===========================================================================
// C. CRYPTOGRAPHY & DATA PROTECTION (4 CWEs)
// ===========================================================================

// CWE-311: Missing encryption of sensitive data (class-level but still useful)
export const verifyCWE311 = v(
  'CWE-311', 'Missing Encryption of Sensitive Data', 'high',
  'INGRESS', 'STORAGE', nT,
  E,
  'TRANSFORM (encryption of sensitive data before storage or transmission)',
  'Encrypt sensitive data before storage and during transmission. Use CWE-312 (storage) and CWE-319 (transmission) for specifics.',
);

// CWE-312: Cleartext Storage of Sensitive Information
// Hand-written: detects sensitive data (passwords, SSNs, credit cards, API keys, tokens)
// flowing to storage without cryptographic transformation. Distinguishes password storage
// (needs one-way hash) from data-at-rest (needs encryption).
export const verifyCWE312 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];

  // Sources: nodes that handle sensitive data — identified by subtype, surface, or code patterns
  const sensitiveNodes = map.nodes.filter(n =>
    (n.node_type === 'INGRESS' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('password') || n.node_subtype.includes('credential') ||
     n.node_subtype.includes('secret') || n.node_subtype.includes('pii') ||
     n.attack_surface.includes('credentials') || n.attack_surface.includes('pii') ||
     n.data_out.some(d => d.sensitivity === 'SECRET' || d.sensitivity === 'PII' || d.sensitivity === 'FINANCIAL') ||
     n.code_snapshot.match(
       /\b(password|passwd|secret|api[_-]?key|token|ssn|social_security|credit[_-]?card|cvv|private[_-]?key|access[_-]?token)\b/i
     ) !== null)
  );

  // Sinks: storage nodes — database writes, file writes, localStorage, etc.
  const storageSinks = nodesOfType(map, 'STORAGE').filter(n =>
    n.code_snapshot.match(
      /\b(save|insert|create|write|set|put|store|update|push|append|localStorage|sessionStorage|cookie)\b/i
    ) !== null ||
    n.node_subtype.includes('sql') || n.node_subtype.includes('database') ||
    n.node_subtype.includes('file') || n.node_subtype.includes('cache') ||
    n.node_subtype.includes('cookie') || n.node_subtype.includes('storage')
  );

  // Safe patterns by category
  const isPasswordHashed = (code: string): boolean =>
    /\bbcrypt\b|\bargon2\b|\bscrypt\b|\bpbkdf2\b|\bcrypto\.hash\b|\bsha256\b|\bsha512\b/i.test(code);

  const isEncrypted = (code: string): boolean =>
    /\baes\b|\bcipher\b|\bencrypt\b|\bcryptoJS\b|\bgpg\b|\brsa\b|\bpublic[_-]?key\b/i.test(code) ||
    /\bcreatecipher\b|\bcreateEncrypt\b|\bsecretbox\b|\bnacl\b/i.test(code);

  for (const src of sensitiveNodes) {
    for (const sink of storageSinks) {
      if (src.id === sink.id) continue;
      // Use hasPathWithoutIntermediateType so that the source node itself (which
      // may be TRANSFORM, e.g. generateApiKey()) is not counted as a transform.
      if (hasPathWithoutIntermediateType(map, src.id, sink.id, 'TRANSFORM')) {
        const srcCode = src.code_snapshot;
        const sinkCode = sink.code_snapshot;

        // Determine if this is a password (needs hash) or general data (needs encryption)
        const isPassword = /\bpassword\b|\bpasswd\b/i.test(srcCode);

        if (isPassword) {
          if (!isPasswordHashed(sinkCode) && !isPasswordHashed(srcCode)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'TRANSFORM (one-way hash — bcrypt, Argon2, scrypt)',
              severity: 'critical',
              description: `Password from ${src.label} is stored in cleartext at ${sink.label}. ` +
                `Plaintext passwords are exposed if the database is compromised.`,
              fix: 'Hash passwords with bcrypt, Argon2, or scrypt before storage. Never store plaintext passwords. ' +
                'Example: const hash = await bcrypt.hash(password, 12); await db.save({ passwordHash: hash })',
            });
          }
        } else {
          if (!isEncrypted(sinkCode) && !isEncrypted(srcCode)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'TRANSFORM (encryption — AES, RSA, or equivalent)',
              severity: 'high',
              description: `Sensitive data from ${src.label} is stored in cleartext at ${sink.label}. ` +
                `Data-at-rest exposure enables mass data theft if storage is compromised.`,
              fix: 'Encrypt sensitive data before storage using AES-256-GCM or equivalent. ' +
                'Use envelope encryption for database fields. Example: const encrypted = crypto.encrypt(data, key)',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-312', name: 'Cleartext Storage of Sensitive Information', holds: findings.length === 0, findings };
};

// CWE-319: Cleartext transmission of sensitive information
export const verifyCWE319 = v(
  'CWE-319', 'Cleartext Transmission of Sensitive Information', 'high',
  'STORAGE', 'EGRESS', nT,
  /\bhttps\b|\btls\b|\bssl\b|\bencrypt\b|\bsecure.*channel\b/i,
  'TRANSFORM (encrypted transport for sensitive data)',
  'Use HTTPS/TLS for all sensitive data transmission. Never send credentials or PII over plaintext channels.',
);

// CWE-327: Use of broken cryptographic algorithm
export const verifyCWE327 = v(
  'CWE-327', 'Use of a Broken or Risky Cryptographic Algorithm', 'high',
  'TRANSFORM', 'STORAGE', nCi,
  /\baes.*256\b|\bsha-?256\b|\bsha-?384\b|\bsha-?512\b|\bbcrypt\b|\bargon2\b|\bscrypt\b|\bed25519\b/i,
  'CONTROL (use strong algorithms — AES-256, SHA-256+, bcrypt, argon2)',
  'Replace weak algorithms (MD5, SHA1, DES, RC4) with strong ones (AES-256, SHA-256+, bcrypt, argon2).',
);

// CWE-347: Improper verification of cryptographic signature
export const verifyCWE347 = v(
  'CWE-347', 'Improper Verification of Cryptographic Signature', 'high',
  'EXTERNAL', 'TRANSFORM', nA,
  /\bverif.*signature\b|\bsignature.*verif\b|\bjwt.*verify\b|\bhmac.*check\b|\bpublic.*key\b/i,
  'AUTH (cryptographic signature verification before processing)',
  'Verify cryptographic signatures on signed data (JWTs, packages, updates) before processing.',
);

// ===========================================================================
// D. CONCURRENCY & STATE (3 CWEs)
// ===========================================================================

// CWE-362: Race Condition / TOCTOU — concurrent access without synchronization
// Hand-written: detects check-then-act patterns (TOCTOU), shared file access,
// shared memory operations, and database read-then-write without transactions.
// Distinguishes file TOCTOU, memory races, and database races with targeted fixes.
export const verifyCWE362 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];

  // Pattern 1: TOCTOU — CONTROL(check) followed by STORAGE(act) without atomic operation
  // e.g., if (fs.existsSync(path)) { fs.writeFileSync(path, data) }
  const checks = nodesOfType(map, 'CONTROL').filter(n =>
    n.code_snapshot.match(
      /\b(exists|existsSync|access|accessSync|stat|statSync|lstat)\b/i
    ) !== null ||
    n.code_snapshot.match(
      /\bif\s*\(\s*\w+\b.*\)\s*\{?\s*$|\.then\s*\(/i
    ) !== null
  );

  const fileOps = nodesOfType(map, 'STORAGE').filter(n =>
    n.code_snapshot.match(
      /\b(writeFile|writeFileSync|unlink|unlinkSync|rename|renameSync|open|openSync|mkdir|mkdirSync|chmod)\b/i
    ) !== null ||
    n.node_subtype.includes('file') || n.node_subtype.includes('fs')
  );

  const safeSyncPattern = /\bO_CREAT\b.*\bO_EXCL\b|\block\b|\bmutex\b|\btransaction\b|\batomic\b|\bflock\b|\blockfile\b/i;

  for (const check of checks) {
    for (const op of fileOps) {
      if (check.id === op.id) continue;
      if (hasPathWithoutIntermediateType(map, check.id, op.id, 'CONTROL')) {
        if (!safeSyncPattern.test(op.code_snapshot) && !safeSyncPattern.test(check.code_snapshot)) {
          findings.push({
            source: nodeRef(check),
            sink: nodeRef(op),
            missing: 'CONTROL (atomic operation — O_CREAT|O_EXCL, lock, or atomic rename)',
            severity: 'high',
            description: `Time-of-check-time-of-use (TOCTOU) race: ${check.label} checks a condition, ` +
              `then ${op.label} acts on it. The state can change between the check and the action.`,
            fix: 'Use atomic operations: open() with O_CREAT|O_EXCL instead of exists()+write(). ' +
              'Use file locks (flock) or atomic rename patterns. Never check-then-act on filesystem state.',
          });
        }
      }
    }
  }

  // Pattern 2: Shared resource access — TRANSFORM touching STORAGE without synchronization
  const transforms = nodesOfType(map, 'TRANSFORM').filter(n =>
    n.code_snapshot.match(
      /\b(increment|decrement|balance|counter|count|total|stock|inventory|read.*write|get.*set)\b/i
    ) !== null ||
    n.node_subtype.includes('concurrent') || n.node_subtype.includes('shared') ||
    n.attack_surface.includes('shared_resource')
  );

  const sharedStorage = nodesOfType(map, 'STORAGE').filter(n =>
    n.code_snapshot.match(
      /\b(update|set|write|increment|decrement|push|pop|splice)\b/i
    ) !== null ||
    n.node_subtype.includes('shared') || n.node_subtype.includes('global') ||
    n.attack_surface.includes('shared_state')
  );

  const safeConcurrency = /\block\b|\bmutex\b|\bsynchronized\b|\batomic\b|\btransaction\b|\bserializ\b|\bBEGIN\b|\bCOMMIT\b|\bFOR UPDATE\b/i;

  for (const src of transforms) {
    for (const sink of sharedStorage) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutIntermediateType(map, src.id, sink.id, 'CONTROL')) {
        if (!safeConcurrency.test(sink.code_snapshot) && !safeConcurrency.test(src.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (lock, mutex, transaction, or atomic operation)',
            severity: 'high',
            description: `Shared resource at ${sink.label} is modified by ${src.label} without synchronization. ` +
              `Concurrent access can corrupt state, cause lost updates, or enable double-spend attacks.`,
            fix: 'Use database transactions (BEGIN/COMMIT) with FOR UPDATE locks for DB state. ' +
              'Use mutexes or atomic operations for in-memory shared state. ' +
              'Use optimistic concurrency (version checks) for distributed systems.',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-362',
    name: 'Concurrent Execution using Shared Resource with Improper Synchronization',
    holds: findings.length === 0,
    findings,
  };
};

// CWE-383: J2EE direct thread management
export const verifyCWE383 = v(
  'CWE-383', 'J2EE Bad Practices: Direct Use of Threads', 'medium',
  'TRANSFORM', 'EXTERNAL', nS,
  /\bExecutorService\b|\bManagedExecutor\b|\bcontainer.*managed\b|\bthread.*pool\b/i,
  'STRUCTURAL (container-managed concurrency — use ExecutorService)',
  'Use container-managed thread pools (ExecutorService) instead of directly creating threads in J2EE.',
);

// CWE-384: Session fixation
export const verifyCWE384 = v(
  'CWE-384', 'Session Fixation', 'high',
  'AUTH', 'STORAGE', nCi,
  /\bregenerate.*session\b|\bsession.*regenerat\b|\bnew.*session\b|\binvalidate.*session\b|\brotate.*id\b/i,
  'CONTROL (session ID regeneration after authentication)',
  'Regenerate session ID after successful authentication. Invalidate old session before issuing new one.',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_018_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // A. Information exposure & error handling
  'CWE-209': verifyCWE209,
  'CWE-372': verifyCWE372,
  'CWE-391': verifyCWE391,
  // B. Authentication & auth bypass
  'CWE-269': verifyCWE269,
  'CWE-287': verifyCWE287,
  'CWE-290': verifyCWE290,
  'CWE-295': verifyCWE295,
  'CWE-307': verifyCWE307,
  // C. Cryptography & data protection
  'CWE-311': verifyCWE311,
  'CWE-312': verifyCWE312,
  'CWE-319': verifyCWE319,
  'CWE-327': verifyCWE327,
  'CWE-347': verifyCWE347,
  // D. Concurrency & state
  'CWE-362': verifyCWE362,
  'CWE-383': verifyCWE383,
  'CWE-384': verifyCWE384,
};
