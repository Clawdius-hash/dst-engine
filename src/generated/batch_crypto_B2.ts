/**
 * DST Generated Verifiers -- Batch Crypto B2
 * Juliet-aware fixes for 4 crypto CWEs that passed OWASP Benchmark at 100%
 * but MISSED on Juliet test suite due to pattern gaps.
 *
 * ROOT CAUSE ANALYSIS (Juliet vs OWASP Benchmark):
 *
 * CWE-336: OWASP uses `new java.util.Random()` (weak PRNG class).
 *          Juliet uses `SecureRandom.setSeed(hardcoded_bytes)` — correct class,
 *          wrong usage. Old verifier skips SecureRandom nodes entirely.
 *   FIX:   Detect .setSeed() with hardcoded/static byte arrays on SecureRandom.
 *
 * CWE-614: OWASP uses explicit `cookie.setSecure(false)`.
 *          Juliet creates Cookie + addCookie() WITHOUT any setSecure() call.
 *          Old verifier only catches explicit setSecure(false), not omission.
 *   FIX:   Detect new Cookie() + response.addCookie() without setSecure(true).
 *
 * CWE-759: OWASP stores hashes in passwordFile (triggers password-context gate).
 *          Juliet uses MessageDigest.digest() with no password keyword anywhere.
 *          Old verifier gates on password/passwd/pwd keywords.
 *   FIX:   Fire on ANY MessageDigest.digest() without salt, not just password contexts.
 *
 * CWE-760: OWASP uses password-related salt contexts.
 *          Juliet uses java.util.Random for salt with hash.update() — no password keyword.
 *          Old verifier gates on password/passwd/pwd keywords.
 *   FIX:   Detect java.util.Random used as hash.update() input (predictable salt)
 *          regardless of password keyword presence.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, stripComments, sharesFunctionScope,
  type VerificationResult, type Finding,
} from './_helpers';

// ===========================================================================
// CWE-336: Same Seed in PRNG (Juliet-aware)
// ===========================================================================

export function verifyCWE336_B2(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const reported = new Set<string>();

  // --- Strategy 1: Graph-based (original STORAGE -> TRANSFORM without EXTERNAL) ---
  const storage = nodesOfType(map, 'STORAGE');
  const transforms = nodesOfType(map, 'TRANSFORM');
  for (const src of storage) {
    for (const sink of transforms) {
      if (src.id === sink.id) continue;
      // BFS check: path without EXTERNAL node
      const adj = new Map<string, string[]>();
      for (const n of map.nodes) {
        adj.set(n.id, []);
        for (const e of n.edges) adj.get(n.id)!.push(e.target);
      }
      // simple BFS
      const visited = new Set<string>();
      const queue = [src.id];
      visited.add(src.id);
      let reached = false;
      while (queue.length > 0) {
        const cur = queue.shift()!;
        if (cur === sink.id) { reached = true; break; }
        for (const next of (adj.get(cur) || [])) {
          if (visited.has(next)) continue;
          const nextNode = map.nodes.find(n => n.id === next);
          if (nextNode && nextNode.node_type === 'EXTERNAL') continue; // skip external
          visited.add(next);
          queue.push(next);
        }
      }
      if (reached) {
        if (!/\bunique.*seed\b|\bper.*instance\b|\brandom.*seed\b/i.test(sink.code_snapshot) &&
            !/\bunique.*seed\b|\bper.*instance\b|\brandom.*seed\b/i.test(src.code_snapshot)) {
          reported.add(src.id);
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'EXTERNAL (unique seed per instance from CSPRNG)',
            severity: 'high',
            description: `STORAGE at ${src.label} -> TRANSFORM at ${sink.label} without external entropy source. Vulnerable to same seed in PRNG.`,
            fix: 'Use unique seeds per PRNG instance. Same seeds produce same output.',
          });
        }
      }
    }
  }

  // --- Strategy 2: Code snapshot scan for weak PRNG patterns ---
  // Detects: java.util.Random (not SecureRandom), Math.random()
  const WEAK_PRNG = /\bnew\s+(?:java\.util\.)?Random\s*\(/i;
  const MATH_RANDOM = /\b(?:java\.lang\.)?Math\.random\s*\(\s*\)/i;
  const SECURE_RANDOM = /\bSecureRandom\b/i;

  for (const node of map.nodes) {
    if (reported.has(node.id)) continue;
    const snap = node.analysis_snapshot || node.code_snapshot;
    if ((WEAK_PRNG.test(snap) || MATH_RANDOM.test(snap)) && !SECURE_RANDOM.test(snap)) {
      reported.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EXTERNAL (use SecureRandom instead of java.util.Random/Math.random)',
        severity: 'high',
        description: `${node.label} uses a weak/predictable PRNG (java.util.Random or Math.random). ` +
          `These produce predictable sequences unsuitable for security-sensitive operations.`,
        fix: 'Use java.security.SecureRandom instead of java.util.Random. ' +
          'SecureRandom provides cryptographically strong random values.',
      });
    }
  }

  // --- Strategy 3 [NEW — Juliet gap]: SecureRandom.setSeed() with hardcoded seed ---
  // Juliet pattern: SecureRandom + setSeed(SEED) where SEED is a hardcoded byte array.
  // This is the gap: OWASP Benchmark uses java.util.Random (caught by Strategy 2),
  // but Juliet uses the CORRECT class (SecureRandom) with WRONG usage (hardcoded seed).
  // A SecureRandom seeded with a known constant is as predictable as java.util.Random.
  const SET_SEED_RE = /\.setSeed\s*\(/i;
  const HARDCODED_SEED_ARRAY = /(?:new\s+byte\s*\[\s*\]\s*\{|byte\s*\[\s*\]\s+\w+\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{)/i;
  const HARDCODED_SEED_LITERAL = /\.setSeed\s*\(\s*(?:\d+L?\s*\)|"[^"]+"\s*\.getBytes)/i;

  for (const node of map.nodes) {
    if (reported.has(node.id)) continue;
    const snap = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SET_SEED_RE.test(snap) && SECURE_RANDOM.test(snap)) {
      // Check if the seed is hardcoded (byte array literal or numeric constant)
      const hasHardcodedSeed = HARDCODED_SEED_ARRAY.test(snap) || HARDCODED_SEED_LITERAL.test(snap);
      // Also check scope snapshots for the seed variable being hardcoded nearby
      const scopeCode = map.nodes
        .filter(n => n.edges.some(e => e.target === node.id) || node.edges.some(e => e.target === n.id))
        .map(n => stripComments(n.analysis_snapshot || n.code_snapshot))
        .join('\n');
      const seedInScope = HARDCODED_SEED_ARRAY.test(scopeCode);

      if (hasHardcodedSeed || seedInScope) {
        reported.add(node.id);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'EXTERNAL (do not call setSeed with hardcoded values on SecureRandom)',
          severity: 'high',
          description: `${node.label} seeds SecureRandom with a hardcoded value via setSeed(). ` +
            `A SecureRandom with a known seed produces a deterministic, predictable sequence.`,
          fix: 'Do not call SecureRandom.setSeed() with hardcoded values. Let SecureRandom self-seed ' +
            'from the OS entropy pool, or use SecureRandom.getInstanceStrong().',
        });
      }
    }
  }

  return { cwe: 'CWE-336', name: 'Same Seed in PRNG', holds: findings.length === 0, findings };
}

// ===========================================================================
// CWE-614: Sensitive Cookie Without Secure Flag (Juliet-aware)
// ===========================================================================

export function verifyCWE614_B2(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const reported = new Set<string>();

  // --- Strategy A: JS/Python/Express cookie patterns (original) ---
  const SET_COOKIE_RE = /\b(res\.cookie|response\.set_cookie|setcookie|Set-Cookie|cookie\s*[:=]|setCookie|response\.cookies|add_header\s+Set-Cookie|\.cookie\s*\(|document\.cookie\s*=)/i;
  const SENSITIVE_COOKIE_RE = /\b(session|sess|token|auth|jwt|access.?token|refresh.?token|remember.?me|JSESSIONID|PHPSESSID|ASP\.NET_SessionId|connect\.sid|_session|csrf)\b/i;
  const SECURE_FLAG_RE = /\bsecure\s*[:=]\s*true\b|\bSecure\b|\bsecure\s*;\s*/i;
  const SESSION_CONFIG_RE = /\b(session|cookie-session|express-session)\b.*\b(cookie|options)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SET_COOKIE_RE.test(code) || SESSION_CONFIG_RE.test(code)) {
      const isSensitive = SENSITIVE_COOKIE_RE.test(code) || SENSITIVE_COOKIE_RE.test(node.label);
      if (isSensitive) {
        const hasSecureFlag = SECURE_FLAG_RE.test(code);
        if (!hasSecureFlag) {
          reported.add(node.id);
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (Secure flag on sensitive cookies)',
            severity: 'high',
            description: `Sensitive cookie set at ${node.label} without the Secure flag. ` +
              `Without Secure, the cookie will be sent over plain HTTP, ` +
              `allowing network attackers to steal session tokens via MITM.`,
            fix: 'Set the Secure flag on all cookies containing session IDs, auth tokens, or sensitive data.',
          });
        }
      }
    }
  }

  // --- Strategy B: Java explicit setSecure(false) (original) ---
  const SET_SECURE_FALSE_RE = /\.setSecure\s*\(\s*false\s*\)/;

  for (const node of map.nodes) {
    if (reported.has(node.id)) continue;
    const snap = node.analysis_snapshot || node.code_snapshot;
    if (SET_SECURE_FALSE_RE.test(snap)) {
      reported.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (Secure flag on sensitive cookies)',
        severity: 'medium',
        description: `${node.label} explicitly sets cookie Secure flag to false. ` +
          `The cookie will be sent over unencrypted HTTP connections, exposing it to interception.`,
        fix: 'Set cookie.setSecure(true) to ensure cookies are only transmitted over HTTPS.',
      });
    }
  }

  // --- Strategy C [NEW — Juliet gap]: new Cookie() + addCookie() WITHOUT setSecure(true) ---
  // Juliet pattern: creates Cookie, calls response.addCookie(), but never calls setSecure(true).
  // The old verifier only caught explicit setSecure(false), not the omission case.
  // OWASP Benchmark always calls setSecure(true) or setSecure(false) — no omission.
  //
  // Architecture note: tree-sitter splits code into separate nodes:
  //   - Method body node (STRUCTURAL): has `new Cookie()` but addCookie may be truncated
  //   - EGRESS node: has `response.addCookie(cookie)` as separate node
  // So we must check ACROSS nodes in the same function scope.
  const JAVA_NEW_COOKIE_RE = /new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(/;
  const ADD_COOKIE_RE = /(?:response|res)\.addCookie\s*\(/i;
  const SET_SECURE_TRUE_RE = /\.setSecure\s*\(\s*true\s*\)/;

  // Find nodes that create cookies
  for (const node of map.nodes) {
    if (reported.has(node.id)) continue;
    const snap = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!JAVA_NEW_COOKIE_RE.test(snap)) continue;

    // Check if addCookie is in same node OR in a sibling node in same scope
    const hasAddCookieSameNode = ADD_COOKIE_RE.test(snap);
    const hasAddCookieInScope = !hasAddCookieSameNode && map.nodes.some(other =>
      other.id !== node.id &&
      ADD_COOKIE_RE.test(stripComments(other.analysis_snapshot || other.code_snapshot)) &&
      sharesFunctionScope(map, node.id, other.id)
    );

    if (!hasAddCookieSameNode && !hasAddCookieInScope) continue;

    // Now check if setSecure(true) appears in the same scope
    const hasSecureSameNode = SET_SECURE_TRUE_RE.test(snap);
    const hasSecureInScope = !hasSecureSameNode && map.nodes.some(other =>
      other.id !== node.id &&
      SET_SECURE_TRUE_RE.test(stripComments(other.analysis_snapshot || other.code_snapshot)) &&
      sharesFunctionScope(map, node.id, other.id)
    );

    if (!hasSecureSameNode && !hasSecureInScope) {
      reported.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (call cookie.setSecure(true) before addCookie)',
        severity: 'high',
        description: `${node.label} creates a Cookie and adds it to the response without calling setSecure(true). ` +
          `By default, cookies are sent over both HTTP and HTTPS. Without the Secure flag, ` +
          `the cookie is exposed to network interception on non-HTTPS connections.`,
        fix: 'Call cookie.setSecure(true) before response.addCookie(cookie). ' +
          'Also set cookie.setHttpOnly(true) and consider SameSite attribute.',
      });
    }
  }

  return { cwe: 'CWE-614', name: 'Sensitive Cookie in HTTPS Session Without Secure Attribute', holds: findings.length === 0, findings };
}

// ===========================================================================
// CWE-759: Use of a One-Way Hash without a Salt (Juliet-aware)
// ===========================================================================

export function verifyCWE759_B2(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PW_RE = /\b(password|passwd|pwd|credential|passphrase|pin|user_pass|password_hash)\b/i;
  const HASH_RE = /\bcreateHash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]\s*\)\.update\s*\(|\bhashlib\.(?:md5|sha1|sha256|sha512)\s*\(|\bMessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1|SHA-?256|SHA-?512)['"]\s*\)|\bDigest::(?:MD5|SHA1|SHA256|SHA512)\.(?:hexdigest|digest)\s*\(|\bsha256\.New\(\)|md5\.New\(\)|sha1\.New\(\)|CC_SHA256\(|CC_MD5\(|hash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]/i;
  const SALT_RE = /\bsalt\b|\brandomBytes\b|\burandom\b|\bSecureRandom\b|\bnonce\b|\brandom_bytes\b|\bcrypto\.random\b|\bos\.urandom\b/i;
  const PROPER_RE = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bpassword_hash\b|\bGenerateFromPassword\b|\bpasslib\b/i;

  // --- Strategy A: Password-context hash detection (original) ---
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!PW_RE.test(code) && !PW_RE.test(node.label)) continue;
    if (HASH_RE.test(code) && !SALT_RE.test(code) && !PROPER_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (salted password hashing -- bcrypt, scrypt, or Argon2)',
        severity: 'high',
        description: `Password hashed without salt at ${node.label}. Unsalted hashes are vulnerable to rainbow table attacks.`,
        fix: 'Use bcrypt, scrypt, or Argon2id (they handle salting automatically).',
      });
    }
  }

  // --- Strategy B: Flow-based password->hash (original) ---
  const pwIng = nodesOfType(map, 'INGRESS').filter(n => PW_RE.test(n.label) || PW_RE.test(n.analysis_snapshot || n.code_snapshot));
  const hashSinks = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('hash') || n.node_subtype.includes('crypto') || HASH_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)))
  );
  for (const src of pwIng) {
    for (const sink of hashSinks) {
      const sc = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      if (!SALT_RE.test(sc) && !PROPER_RE.test(sc) && !findings.some(f => f.sink.id === sink.id)) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(sink),
          missing: 'TRANSFORM (salted password hashing -- unique salt per password)',
          severity: 'high',
          description: `Password from ${src.label} hashed at ${sink.label} without a salt.`,
          fix: 'Use bcrypt.hash(password, saltRounds) or argon2.hash(password).',
        });
      }
    }
  }

  // --- Strategy C: passwordFile/storage context (original) ---
  {
    const UNSALTED_API = /\bMessageDigest\.getInstance\b|\bcreateHash\b|\bhashlib\.(?:md5|sha1|sha256|sha512)\b/i;
    const PW_STORAGE = /passwordFile|password.*store|credential|hash_value/i;
    const reported = new Set<string>(findings.map(f => f.sink.id));

    const hasPasswordStorage = map.nodes.some(n => PW_STORAGE.test(n.code_snapshot));
    if (hasPasswordStorage) {
      for (const node of map.nodes) {
        if (reported.has(node.id)) continue;
        const snap = node.analysis_snapshot || node.code_snapshot;
        if (UNSALTED_API.test(snap) && !PROPER_RE.test(snap) && !SALT_RE.test(snap)) {
          reported.add(node.id);
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'TRANSFORM (salted password hashing -- bcrypt/scrypt/Argon2)',
            severity: 'high',
            description: `${node.label} uses an unsalted hash function for password storage.`,
            fix: 'Use bcrypt, scrypt, or Argon2 instead of raw MessageDigest/createHash.',
          });
        }
      }
    }
  }

  // --- Strategy D [NEW — Juliet gap]: ANY MessageDigest without salt ---
  // Juliet pattern: MessageDigest.getInstance("SHA-512") + .digest() with NO salt.
  // No password keyword anywhere. The code is hashing data without a salt, period.
  // This is the core CWE-759 definition: one-way hash without a salt.
  //
  // Key insight: OWASP Benchmark always has passwordFile/hash_value context.
  // Juliet tests are minimal — just the hash with no context keywords.
  // CWE-759 says "Use of a One-Way Hash without a Salt" — it doesn't require
  // password context. ANY unsalted hash IS the vulnerability.
  //
  // Architecture note: Juliet files contain BOTH bad() and good() methods.
  // good() has SecureRandom/salt in it. We must scope-check to avoid
  // letting good()'s salt suppress bad()'s finding.
  {
    const JAVA_DIGEST = /\bMessageDigest\.getInstance\s*\(/i;
    const DIGEST_CALL = /\.digest\s*\(/i;
    const HASH_UPDATE_SALT = /\.update\s*\([^)]*(?:salt|SecureRandom|prng|random|nonce|urandom)/i;
    const reported = new Set<string>(findings.map(f => f.sink.id));

    for (const node of map.nodes) {
      if (reported.has(node.id)) continue;
      const snap = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (JAVA_DIGEST.test(snap) && DIGEST_CALL.test(snap)) {
        // Skip if there's evidence of salting in THIS node
        if (SALT_RE.test(snap) || PROPER_RE.test(snap) || HASH_UPDATE_SALT.test(snap)) continue;
        // Skip if another node IN THE SAME FUNCTION SCOPE provides salt
        // (not in a sibling function — Juliet's good() method has salt
        //  but that shouldn't suppress bad()'s finding)
        let saltedInScope = false;
        for (const other of map.nodes) {
          if (other.id === node.id) continue;
          const otherSnap = stripComments(other.analysis_snapshot || other.code_snapshot);
          if ((HASH_UPDATE_SALT.test(otherSnap) || SALT_RE.test(otherSnap)) &&
              sharesFunctionScope(map, node.id, other.id)) {
            saltedInScope = true;
            break;
          }
        }
        if (saltedInScope) continue;

        reported.add(node.id);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (add random salt via hash.update(salt) before digest)',
          severity: 'high',
          description: `${node.label} uses MessageDigest.digest() without adding a salt via .update(). ` +
            `Unsalted hashes allow rainbow table and precomputation attacks regardless of the data being hashed.`,
          fix: 'Add a cryptographically random salt: SecureRandom prng = SecureRandom.getInstance("SHA1PRNG"); ' +
            'hash.update(prng.generateSeed(32)); then hash.digest(data). Better: use bcrypt/Argon2 for passwords.',
        });
      }
    }
  }

  return { cwe: 'CWE-759', name: 'Use of a One-Way Hash without a Salt', holds: findings.length === 0, findings };
}

// ===========================================================================
// CWE-760: Use of a One-Way Hash with a Predictable Salt (Juliet-aware)
// ===========================================================================

export function verifyCWE760_B2(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PW_RE = /\b(password|passwd|pwd|credential|passphrase|pass_hash|password_hash)\b/i;
  const HARD_SALT_RE = /salt\s*[:=]\s*['"][^'"]+['"]|SALT\s*[:=]\s*['"][^'"]+['"]|\.update\s*\(\s*['"][^'"]+['"]\s*\+|\.update\s*\(\s*password\s*\+\s*['"][^'"]+['"]/i;
  const USER_SALT_RE = /salt\s*[:=]\s*(?:user(?:name)?|email|user_id|userId|login|name)\b|\.update\s*\(\s*(?:username|email|user\.name)\s*\+/i;
  const TIME_SALT_RE = /salt\s*[:=]\s*(?:Date\.now|time|timestamp|new Date|datetime)/i;
  const RAND_SALT_RE = /\brandomBytes\b|\burandom\b|\bSecureRandom\b|\bcrypto\.random\b|\bcrypto\/rand\b|\brandom_bytes\b|\bgenerate.*salt\b|\bbcrypt\b|\bscrypt\b|\bargon2\b/i;

  // --- Strategy A: Password-context predictable salt (original) ---
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!PW_RE.test(code) && !PW_RE.test(node.label)) continue;
    if (HARD_SALT_RE.test(code) && !RAND_SALT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (unique random salt per password -- crypto.randomBytes(16))',
        severity: 'high',
        description: `Hardcoded/static salt for password hashing at ${node.label}.`,
        fix: 'Generate unique random salt per password: crypto.randomBytes(16). Better: use bcrypt/Argon2.',
      });
    }
    if (USER_SALT_RE.test(code) && !RAND_SALT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (cryptographically random salt -- not derived from user data)',
        severity: 'high',
        description: `Predictable salt (username/email) for password hashing at ${node.label}.`,
        fix: 'Use cryptographically random salt: crypto.randomBytes(16). Never use username/email as salt.',
      });
    }
    if (TIME_SALT_RE.test(code) && !RAND_SALT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (cryptographically random salt -- not time-based)',
        severity: 'high',
        description: `Time-based salt for password hashing at ${node.label}.`,
        fix: 'Use cryptographically random salt. Timestamps have low entropy.',
      });
    }
  }

  // --- Strategy B [NEW — Juliet gap]: java.util.Random as hash salt ---
  // Juliet pattern: new Random() -> random.nextInt() -> hash.update(Integer.toString(random.nextInt()))
  // This uses a weak PRNG as the salt source. No password keyword anywhere.
  // CWE-760 = one-way hash with PREDICTABLE salt. java.util.Random IS predictable.
  //
  // OWASP Benchmark has explicit password contexts. Juliet is minimal.
  {
    const JAVA_RANDOM = /\bnew\s+(?:java\.util\.)?Random\s*\(/i;
    const HASH_UPDATE = /\.update\s*\(/i;
    const MESSAGE_DIGEST = /\bMessageDigest\.getInstance\b/i;
    const reported = new Set<string>(findings.map(f => f.sink.id));

    for (const node of map.nodes) {
      if (reported.has(node.id)) continue;
      const snap = stripComments(node.analysis_snapshot || node.code_snapshot);

      // Detect: java.util.Random used alongside MessageDigest + hash.update()
      if (JAVA_RANDOM.test(snap) && MESSAGE_DIGEST.test(snap) && HASH_UPDATE.test(snap)) {
        if (RAND_SALT_RE.test(snap)) continue; // has proper randomness
        reported.add(node.id);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (cryptographically random salt -- use SecureRandom, not java.util.Random)',
          severity: 'high',
          description: `${node.label} uses java.util.Random to generate a salt for MessageDigest. ` +
            `java.util.Random is a linear congruential generator with predictable output. ` +
            `An attacker can predict or brute-force the salt values.`,
          fix: 'Use SecureRandom instead of java.util.Random for salt generation: ' +
            'SecureRandom prng = SecureRandom.getInstance("SHA1PRNG"); hash.update(prng.generateSeed(32));',
        });
      }
    }

    // Also check cross-node: Random in one node, MessageDigest in another
    for (const node of map.nodes) {
      if (reported.has(node.id)) continue;
      const snap = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (!MESSAGE_DIGEST.test(snap) || !HASH_UPDATE.test(snap)) continue;
      if (RAND_SALT_RE.test(snap)) continue;

      // Check if any connected/nearby node uses java.util.Random
      let hasWeakRandom = false;
      for (const other of map.nodes) {
        if (other.id === node.id) continue;
        const otherSnap = stripComments(other.analysis_snapshot || other.code_snapshot);
        if (JAVA_RANDOM.test(otherSnap) && !RAND_SALT_RE.test(otherSnap)) {
          hasWeakRandom = true;
          break;
        }
      }
      if (hasWeakRandom) {
        reported.add(node.id);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (cryptographically random salt -- use SecureRandom, not java.util.Random)',
          severity: 'high',
          description: `${node.label} uses MessageDigest with a salt derived from java.util.Random. ` +
            `java.util.Random is predictable and unsuitable for cryptographic salt generation.`,
          fix: 'Use SecureRandom for salt generation. java.util.Random is not cryptographically secure.',
        });
      }
    }
  }

  return { cwe: 'CWE-760', name: 'Use of a One-Way Hash with a Predictable Salt', holds: findings.length === 0, findings };
}

// ===========================================================================
// Registry
// ===========================================================================

export const BATCH_CRYPTO_B2_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-336': verifyCWE336_B2,
  'CWE-614': verifyCWE614_B2,
  'CWE-759': verifyCWE759_B2,
  'CWE-760': verifyCWE760_B2,
};
