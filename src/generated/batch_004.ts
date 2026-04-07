/**
 * DST Generated Verifiers — Batch 004
 * Pattern shape: INGRESS→STORAGE without TRANSFORM
 * 34 CWEs: path equivalence, cleartext storage, crypto weakness,
 * log injection, input neutralization, code injection, data integrity.
 *
 * Key difference from batches 001-003: the missing mediator is TRANSFORM
 * (encoding, sanitization, hashing, canonicalization), not CONTROL.
 * Data goes directly from user input to storage without processing.
 *
 * Sub-groups:
 *   A. Path equivalence       (17 CWEs) — factory-driven
 *   B. Cleartext storage       (4 CWEs) — factory-driven
 *   C. Crypto/hashing          (3 CWEs) — per-CWE
 *   D. Input neutralization    (4 CWEs) — factory-driven
 *   E. Code injection          (2 CWEs) — per-CWE
 *   F. Data integrity          (3 CWEs) — per-CWE
 *   G. Log injection           (1 CWE)  — per-CWE
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasPathWithoutTransform,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Sink filters
// ---------------------------------------------------------------------------

// Domain subtypes that must NOT match as file storage nodes (cross-domain exclusion).
const NON_FILE_DOMAINS_B4 = /^(xpath_query|ldap_query|sql_query|nosql_query|graphql_query|mongo_query|redis_query|query)$/;

function fileStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n => {
    if (NON_FILE_DOMAINS_B4.test(n.node_subtype)) return false;
    return (
      n.node_type === 'STORAGE' &&
      (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
       n.node_subtype.includes('path') || n.attack_surface.includes('file_access') ||
       n.code_snapshot.match(
         /\b(readFile|writeFile|createReadStream|createWriteStream|open|unlink|readdir|rename|access|stat|include|require)\b/i
       ) !== null)
    );
  });
}

function persistentStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('file') || n.node_subtype.includes('disk') ||
     n.node_subtype.includes('database') || n.node_subtype.includes('persist') ||
     n.attack_surface.includes('file_write') || n.attack_surface.includes('data_store') ||
     n.code_snapshot.match(
       /\b(writeFile|writeSync|createWriteStream|save|persist|store|insert|put|set)\b/i
     ) !== null)
  );
}

function credentialStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('credential') || n.node_subtype.includes('password') ||
     n.node_subtype.includes('auth') || n.attack_surface.includes('credential_store') ||
     n.data_in.some(d => d.sensitivity === 'SECRET' || d.sensitivity === 'AUTH') ||
     n.code_snapshot.match(
       /\b(password|passwd|credential|hash|digest|auth.*store|user.*save)\b/i
     ) !== null)
  );
}

function logStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('log') || n.node_subtype.includes('audit') ||
     n.attack_surface.includes('logging') ||
     n.code_snapshot.match(
       /\b(console\.(log|warn|error|info)|logger\.|log\.(info|warn|error)|winston|bunyan|pino|syslog|writeLog|appendFile.*log)\b/i
     ) !== null)
  );
}

function executableStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('executable') || n.node_subtype.includes('template') ||
     n.node_subtype.includes('script') || n.node_subtype.includes('config') ||
     n.attack_surface.includes('code_storage') ||
     n.code_snapshot.match(
       /\b(\.php|\.jsp|\.asp|\.erb|\.ejs|\.phtml|template|config|\.htaccess|crontab|\.sh)\b/i
     ) !== null)
  );
}

function trustedStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('trusted') || n.node_subtype.includes('internal') ||
     n.node_subtype.includes('config') || n.node_subtype.includes('init') ||
     n.attack_surface.includes('trusted_data') ||
     n.code_snapshot.match(
       /\b(config|settings|options|defaults|init|setup|register|global)\b/i
     ) !== null)
  );
}

// ---------------------------------------------------------------------------
// Safe pattern constants — what TRANSFORM looks like when present
// ---------------------------------------------------------------------------

const PATH_CANON_SAFE = /\bpath\.resolve\b|\bpath\.normalize\b|\brealpath\b|\bcanonicalize\b|\bpath\.basename\b|\bstrip.*trailing\b|\btrim\b|\bnormalizePath\b/i;
const ENCRYPT_SAFE = /\bencrypt\s*\(|\bcrypto\.\w|\bcipher\s*\(|\bAES\b|\bRSA\b|\bcreateCipher\w*\b|\bcreateHash\b/i;
const HASH_SALT_SAFE = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bsalt\b|\brounds\b|\bcost\b|\bworkFactor\b/i;
const LOG_ENCODE_SAFE = /\bescape\s*\(|\bencode\s*\(|\bsanitize\s*\(|\bstrip.*newline\b|\breplace.*\\n\b|\blog.*safe\b|\bneutralize\s*\(/i;
const NEUTRALIZE_SAFE = /\bescape\s*\(|\bencode\s*\(|\bsanitize\s*\(|\bstrip\s*\(|\bneutralize\s*\(|\bhtmlEntities\b|\bencodeURI\b/i;
const CODE_ESCAPE_SAFE = /\bescape\s*\(|\bsanitize\s*\(|\bhtmlspecialchars\b|\bhtmlentities\b|\bstrip_tags\b|\bparameterize\b|\btemplate.*literal\b/i;
const VALIDATE_TRANSFORM_SAFE = /\bvalidate\s*\(|\bsanitize\s*\(|\bparse\s*\(|\bcast\s*\(|\bcoerce\s*\(|\bschema\b|\bzod\b|\bjoi\b/i;

// ---------------------------------------------------------------------------
// Factory: INGRESS→STORAGE without TRANSFORM
// ---------------------------------------------------------------------------

function createNoTransformVerifier(
  cweId: string, cweName: string, severity: Severity,
  sinkFilter: (map: NeuralMap) => NeuralMapNode[],
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
  extraSafe?: RegExp,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = sinkFilter(map);

    for (const src of ingress) {
      for (const sink of sinks) {
        if (hasPathWithoutTransform(map, src.id, sink.id)) {
          const isSafe = safePattern.test(sink.code_snapshot) ||
            (extraSafe ? extraSafe.test(sink.code_snapshot) : false);

          if (!isSafe) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `User input from ${src.label} reaches ${sink.label} without transformation. ` +
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

// ===========================================================================
// A. PATH EQUIVALENCE (17 CWEs)
// ===========================================================================
// All check: INGRESS[path] → STORAGE[file] without TRANSFORM[canonicalization]
// Alternative path representations bypass security checks because no
// canonicalization transform normalizes the path before storage/access.

export const verifyCWE41 = createNoTransformVerifier(
  'CWE-41', 'Improper Resolution of Path Equivalence', 'high',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (path canonicalization before access)',
  'Canonicalize all file paths (path.resolve/realpath) before access or comparison. ' +
    'Normalize encoding, case, trailing chars, and separators.',
);

export const verifyCWE42 = createNoTransformVerifier(
  'CWE-42', "Path Equivalence: 'filename.' (Trailing Dot)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (strip trailing dots from path)',
  'Canonicalize paths to remove trailing dots. Use path.normalize() or realpath().',
);

export const verifyCWE43 = createNoTransformVerifier(
  'CWE-43', "Path Equivalence: 'filename....' (Multiple Trailing Dot)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (strip trailing dots from path)',
  'Canonicalize paths to remove multiple trailing dots before file access.',
);

export const verifyCWE44 = createNoTransformVerifier(
  'CWE-44', "Path Equivalence: 'file.name' (Internal Dot)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (path canonicalization)',
  'Canonicalize paths before comparison. Internal dots may create equivalent representations.',
);

export const verifyCWE45 = createNoTransformVerifier(
  'CWE-45', "Path Equivalence: 'file...name' (Multiple Internal Dot)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (path canonicalization)',
  'Canonicalize paths with multiple internal dots before access.',
);

export const verifyCWE46 = createNoTransformVerifier(
  'CWE-46', "Path Equivalence: 'filename ' (Trailing Space)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (strip trailing whitespace from path)',
  'Trim whitespace from file paths before access. Some OS ignore trailing spaces.',
  /\btrim\b|\bstrip\b/i,
);

export const verifyCWE47 = createNoTransformVerifier(
  'CWE-47', "Path Equivalence: ' filename' (Leading Space)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (strip leading whitespace from path)',
  'Trim leading whitespace from file paths before access.',
  /\btrim\b|\bstrip\b/i,
);

export const verifyCWE48 = createNoTransformVerifier(
  'CWE-48', "Path Equivalence: 'file name' (Internal Whitespace)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (path canonicalization / whitespace handling)',
  'Canonicalize paths before comparison. Handle internal whitespace consistently.',
);

export const verifyCWE49 = createNoTransformVerifier(
  'CWE-49', "Path Equivalence: 'filename/' (Trailing Slash)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (strip trailing slashes from path)',
  'Normalize paths to remove trailing slashes before comparison or access.',
);

export const verifyCWE50 = createNoTransformVerifier(
  'CWE-50', "Path Equivalence: '//multiple/leading/slash'", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (normalize multiple leading slashes)',
  'Collapse multiple leading slashes to a single slash. Use path.normalize().',
);

export const verifyCWE51 = createNoTransformVerifier(
  'CWE-51', "Path Equivalence: '/multiple//internal/slash'", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (normalize multiple internal slashes)',
  'Collapse multiple internal slashes. Use path.normalize() or replace(/\\/+/g, "/").',
);

export const verifyCWE52 = createNoTransformVerifier(
  'CWE-52', "Path Equivalence: '/multiple/trailing/slash//'", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (normalize trailing slashes)',
  'Strip or collapse trailing slashes before path comparison.',
);

export const verifyCWE53 = createNoTransformVerifier(
  'CWE-53', "Path Equivalence: '\\multiple\\\\internal\\\\backslash'", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (normalize backslash separators)',
  'Normalize path separators to forward slashes. Use path.normalize() for cross-platform handling.',
  /\bpath\.win32\b|\breplace.*\\\\/i,
);

export const verifyCWE54 = createNoTransformVerifier(
  'CWE-54', "Path Equivalence: 'filedir\\' (Trailing Backslash)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (strip trailing backslashes)',
  'Normalize path separators and strip trailing backslashes.',
);

export const verifyCWE55 = createNoTransformVerifier(
  'CWE-55', "Path Equivalence: '/./' (Single Dot Directory)", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (collapse single-dot directory references)',
  'Canonicalize paths to collapse /./ references. Use path.normalize().',
);

export const verifyCWE57 = createNoTransformVerifier(
  'CWE-57', "Path Equivalence: 'fakedir/../realdir/filename'", 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (resolve parent directory references)',
  'Resolve ../ traversals before comparison. A path like a/../b resolves to b.',
);

export const verifyCWE58 = createNoTransformVerifier(
  'CWE-58', 'Path Equivalence: Windows 8.3 Filename', 'medium',
  fileStorageNodes, PATH_CANON_SAFE,
  'TRANSFORM (resolve Windows short names to long names)',
  'Resolve 8.3 short file names to canonical long names on Windows. ' +
    'Use GetLongPathName() or equivalent before security comparisons.',
  /\bGetLongPathName\b|\blong.*name\b|\b8\.3\b.*reject/i,
);

// ===========================================================================
// B. CLEARTEXT STORAGE (4 CWEs)
// ===========================================================================

export const verifyCWE224 = createNoTransformVerifier(
  'CWE-224', 'Obscured Security-relevant Information by Alternate Name', 'medium',
  persistentStorageNodes, ENCRYPT_SAFE,
  'TRANSFORM (proper protection — encryption, not obscurity)',
  'Use real encryption instead of alternate names or encoding to protect sensitive data. ' +
    'Security through obscurity is not security.',
);

export const verifyCWE313 = createNoTransformVerifier(
  'CWE-313', 'Cleartext Storage in a File or on Disk', 'medium',
  persistentStorageNodes, ENCRYPT_SAFE,
  'TRANSFORM (encryption before persistent storage)',
  'Encrypt sensitive data before writing to files or disk. ' +
    'Use AES-256-GCM or similar authenticated encryption.',
);

export const verifyCWE314 = createNoTransformVerifier(
  'CWE-314', 'Cleartext Storage in the Registry', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('registry') || n.node_subtype.includes('config') ||
     n.code_snapshot.match(/\b(Registry|RegSetValue|HKEY_|localStorage|preferences|defaults)\b/i) !== null)
  ),
  ENCRYPT_SAFE,
  'TRANSFORM (encryption before registry storage)',
  'Encrypt sensitive data before storing in the registry or config stores. ' +
    'Use the platform credential manager (Keychain, Credential Manager) for secrets.',
);

export const verifyCWE316 = createNoTransformVerifier(
  'CWE-316', 'Cleartext Storage of Sensitive Information in Memory', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('memory') || n.node_subtype.includes('variable') ||
     n.node_subtype.includes('heap') ||
     n.data_in.some(d => d.sensitivity === 'SECRET' || d.sensitivity === 'AUTH') ||
     n.code_snapshot.match(/\b(password|secret|key|token|credential)\s*[=:]\s*/i) !== null)
  ),
  /\bencrypt\s*\(|\bSecureString\b|\bProtectedMemory\b|\bzero.*after\b|\bclear.*after\b|\bwipe\b/i,
  'TRANSFORM (encryption in memory / secure string / zeroing after use)',
  'Use SecureString or encrypted buffers for sensitive data in memory. ' +
    'Zero memory after use. Minimize the time sensitive data is held in cleartext.',
);

// ===========================================================================
// C. CRYPTO/HASHING (3 CWEs)
// ===========================================================================

/**
 * CWE-759: Use of a One-Way Hash without a Salt
 * Pattern: INGRESS(password) → STORAGE(credential) with either:
 *   (a) no hash at all (direct cleartext storage), OR
 *   (b) a hash that is NOT a salted adaptive hash (MD5, SHA-*, createHash)
 *
 * UPGRADED from factory: the original checked hasPathWithoutTransform, which
 * only catches case (a). Case (b) is the actual CWE-759 — there IS a hash,
 * but it has no salt. This version walks the path and inspects TRANSFORM nodes
 * to detect unsalted hashes (createHash("md5"), hashlib.sha256, etc.).
 *
 * Dangerous hashes (no built-in salt): MD5, SHA-1, SHA-256, SHA-512, createHash()
 * Safe hashes (salt built in): bcrypt, scrypt, Argon2, PBKDF2
 */
export function verifyCWE759(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const credSinks = credentialStorageNodes(map);

  // Pattern for adaptive salted hashes — these are SAFE
  const SALTED_HASH = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bpbkdf2\b/i;

  // Pattern for unsalted one-way hashes — these are VULNERABLE
  const UNSALTED_HASH = /\bcreateHash\b|\bMD5\b|\bmd5\b|\bSHA-?1\b|\bsha1\b|\bSHA-?256\b|\bsha256\b|\bSHA-?512\b|\bsha512\b|\bhashlib\b|\bMessageDigest\b|\bdigest\b|\bhash\s*\(/i;

  for (const src of ingress) {
    for (const sink of credSinks) {
      // Case A: No transform at all — direct cleartext storage
      if (hasPathWithoutTransform(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'TRANSFORM (password must be hashed with salted adaptive function — bcrypt/scrypt/Argon2)',
          severity: 'high',
          description: `Password from ${src.label} is stored in cleartext at ${sink.label}. ` +
            `No hashing of any kind was detected on the data path.`,
          fix: 'Hash passwords with bcrypt (cost >= 10), scrypt, or Argon2id before storage. ' +
            'These functions generate a unique random salt per password automatically. ' +
            'Example: const hash = await bcrypt.hash(password, 12)',
        });
        continue; // Don't double-report
      }

      // Case B: There IS a transform, but is it a salted hash?
      // Find TRANSFORM nodes between src and sink that perform hashing
      const hashTransforms = map.nodes.filter(n =>
        n.node_type === 'TRANSFORM' &&
        (n.node_subtype.includes('hash') || n.node_subtype.includes('crypto') ||
         n.node_subtype.includes('digest') ||
         n.code_snapshot.match(UNSALTED_HASH) !== null ||
         n.code_snapshot.match(SALTED_HASH) !== null)
      );

      for (const hashNode of hashTransforms) {
        const isUnsalted = UNSALTED_HASH.test(hashNode.code_snapshot) &&
                           !SALTED_HASH.test(hashNode.code_snapshot);

        // Also check for explicit salt usage (e.g., createHash + manual salt)
        const hasManualSalt = hashNode.code_snapshot.match(
          /\bsalt\b|\brandomBytes\b|\bcrypto\.random\b|\buuid\b.*\+/i
        ) !== null;

        if (isUnsalted && !hasManualSalt) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (salted hash — the hash at ' + hashNode.label + ' has no salt)',
            severity: 'high',
            description: `Password from ${src.label} is hashed with unsalted ${hashNode.label} before storage at ${sink.label}. ` +
              `Without a unique salt per password, attackers can use precomputed rainbow tables ` +
              `to crack all passwords in the database simultaneously.`,
            fix: 'Replace createHash("sha256") with bcrypt.hash(password, 12) or argon2.hash(). ' +
              'These generate a unique random salt automatically. ' +
              'If you must use createHash: generate a unique salt per user with crypto.randomBytes(16) ' +
              'and prepend it: createHash("sha256").update(salt + password).',
          });
        }
      }
    }
  }

  // --- Strategy 2: Code snapshot scan for unsalted hash patterns ---
  // Detects MessageDigest.getInstance, createHash, hashlib without salt or adaptive hash.
  // These APIs produce unsalted hashes by default (no built-in salt like bcrypt/scrypt).
  const SALTED_HASH_S2 = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bpbkdf2\b/i;
  const UNSALTED_API = /\bMessageDigest\.getInstance\b|\bcreateHash\b|\bhashlib\.(?:md5|sha1|sha256|sha512)\b/i;
  const MANUAL_SALT = /\bsalt\b|\brandomBytes\b|\bcrypto\.random\b|\bSecureRandom\b/i;
  const reported = new Set<string>(findings.map(f => f.sink.id));

  for (const node of map.nodes) {
    if (reported.has(node.id)) continue;
    const snap = node.code_snapshot;
    if (UNSALTED_API.test(snap) && !SALTED_HASH_S2.test(snap) && !MANUAL_SALT.test(snap)) {
      // Check if it writes to a file with "password" in the name
      const hasPasswordStorage = map.nodes.some(n =>
        n.code_snapshot.match(/passwordFile|password.*store|credential|hash_value/i) !== null
      );
      if (hasPasswordStorage) {
        reported.add(node.id);
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'TRANSFORM (salted adaptive hash — bcrypt/scrypt/Argon2)',
          severity: 'high',
          description: `${node.label} uses an unsalted hash function. ` +
            `Without a unique salt per password, attackers can use precomputed rainbow tables.`,
          fix: 'Use bcrypt, scrypt, or Argon2 instead of raw MessageDigest/createHash. ' +
            'These generate a unique random salt automatically.',
        });
      }
    }
  }

  return { cwe: 'CWE-759', name: 'Use of a One-Way Hash without a Salt', holds: findings.length === 0, findings };
}

/** CWE-760: Use of a One-Way Hash with a Predictable Salt */
export function verifyCWE760(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = credentialStorageNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasPathWithoutTransform(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'TRANSFORM (cryptographically random salt generation)',
          severity: 'high',
          description: `Sensitive data from ${src.label} reaches ${sink.label} without proper hashing. ` +
            `If hashing exists, the salt may be predictable (username, static value).`,
          fix: 'Use cryptographically random salts (crypto.randomBytes). ' +
            'Use bcrypt/scrypt/Argon2 which handle salt generation automatically.',
        });
      }
    }
  }

  return { cwe: 'CWE-760', name: 'Use of a One-Way Hash with a Predictable Salt', holds: findings.length === 0, findings };
}

/** CWE-916: Use of Password Hash With Insufficient Computational Effort */
export function verifyCWE916(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = credentialStorageNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasPathWithoutTransform(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'TRANSFORM (adaptive hash function — bcrypt/scrypt/Argon2 with sufficient rounds)',
          severity: 'high',
          description: `Sensitive data from ${src.label} reaches ${sink.label} without adaptive hashing. ` +
            `Fast hashes (MD5, SHA) are insufficient for password storage.`,
          fix: 'Use adaptive hash functions: bcrypt (rounds >= 10), scrypt, or Argon2. ' +
            'These are deliberately slow to resist brute-force attacks.',
        });
      }
    }
  }

  return { cwe: 'CWE-916', name: 'Use of Password Hash With Insufficient Computational Effort', holds: findings.length === 0, findings };
}

// ===========================================================================
// D. INPUT NEUTRALIZATION (4 CWEs)
// ===========================================================================

export const verifyCWE158 = createNoTransformVerifier(
  'CWE-158', 'Improper Neutralization of Null Byte or NUL Character', 'high',
  persistentStorageNodes, NEUTRALIZE_SAFE,
  'TRANSFORM (null byte stripping / neutralization before storage)',
  'Strip or reject null bytes (\\0) from input before storage. ' +
    'Null bytes can truncate strings in C-based systems, bypassing security checks.',
  /\bnull.*byte\b.*strip|\b\\0\b.*reject|\breplace.*\\x00/i,
);

export const verifyCWE163 = createNoTransformVerifier(
  'CWE-163', 'Improper Neutralization of Multiple Trailing Special Elements', 'medium',
  persistentStorageNodes, NEUTRALIZE_SAFE,
  'TRANSFORM (trailing special element neutralization)',
  'Strip or neutralize trailing special characters before storing data. ' +
    'Multiple trailing dots, slashes, or spaces can create equivalent representations.',
);

export const verifyCWE178 = createNoTransformVerifier(
  'CWE-178', 'Improper Handling of Case Sensitivity', 'medium',
  persistentStorageNodes, /\btoLowerCase\b|\btoUpperCase\b|\blocaleCompare\b|\bcaseFold\b|\bcaseInsensitive\b|\bnormalize.*case\b/i,
  'TRANSFORM (case normalization before storage/comparison)',
  'Normalize case before comparison or storage. Use toLowerCase()/toUpperCase() consistently. ' +
    'Be aware of locale-specific case folding rules (Turkish I problem).',
);

export const verifyCWE198 = createNoTransformVerifier(
  'CWE-198', 'Use of Incorrect Byte Ordering', 'medium',
  persistentStorageNodes, /\bendian\b|\bbyte.*order\b|\bBOM\b|\bBuffer\.(readUInt|writeUInt|readInt|writeInt)(16|32)(BE|LE)\b|\bhtons\b|\bntohs\b/i,
  'TRANSFORM (byte order conversion / endianness handling)',
  'Explicitly handle byte ordering when storing or reading multi-byte data. ' +
    'Use network byte order (big-endian) for protocol data. Check BOM for text files.',
);

// ===========================================================================
// E. CODE INJECTION (2 CWEs)
// ===========================================================================

/** CWE-96: Static Code Injection — user input saved to executable resource */
export function verifyCWE96(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = executableStorageNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasPathWithoutTransform(map, src.id, sink.id)) {
        if (!CODE_ESCAPE_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (code neutralization / escaping before storage in executable resource)',
            severity: 'critical',
            description: `User input from ${src.label} is stored in executable resource at ${sink.label} without neutralization. ` +
              `When the resource is later loaded/executed, injected code will run.`,
            fix: 'Never write user input directly to files that will be executed (PHP, JSP, config). ' +
              'Escape all code-significant characters. Use parameterized templates.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-96', name: 'Static Code Injection', holds: findings.length === 0, findings };
}

/** CWE-97: Server-Side Includes (SSI) Injection */
export function verifyCWE97(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = executableStorageNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasPathWithoutTransform(map, src.id, sink.id)) {
        const isSSIContext = sink.code_snapshot.match(
          /\b(SSI|<!--#|shtml|server.*side.*include|\.stm|\.shtm)\b/i
        ) !== null;

        if (isSSIContext || !CODE_ESCAPE_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (SSI directive neutralization)',
            severity: 'high',
            description: `User input from ${src.label} is stored at ${sink.label} without SSI neutralization. ` +
              `An attacker can inject <!--#exec --> directives for server-side code execution.`,
            fix: 'Escape SSI directives (<!--# -->) in user input. Disable SSI where not needed. ' +
              'Never store user input in .shtml or SSI-enabled files without sanitization.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-97', name: 'Server-Side Includes (SSI) Injection', holds: findings.length === 0, findings };
}

// ===========================================================================
// F. DATA INTEGRITY (3 CWEs)
// ===========================================================================

/** CWE-454: External Initialization of Trusted Variables or Data Stores */
export const verifyCWE454 = createNoTransformVerifier(
  'CWE-454', 'External Initialization of Trusted Variables or Data Stores', 'high',
  trustedStorageNodes, VALIDATE_TRANSFORM_SAFE,
  'TRANSFORM (validation / sanitization before trusted storage initialization)',
  'Never initialize trusted variables or config from untransformed external input. ' +
    'Validate, sanitize, and type-check all external values before using for initialization.',
);

/** CWE-464: Addition of Data Structure Sentinel */
export const verifyCWE464 = createNoTransformVerifier(
  'CWE-464', 'Addition of Data Structure Sentinel', 'high',
  (map) => {
    // Only fire if the map has at least one INGRESS node with tainted data —
    // without any tainted input flowing in, sentinel injection cannot occur.
    const hasTaintedIngress = map.nodes.some(
      n => n.node_type === 'INGRESS' && n.data_out.some(d => d.tainted),
    );
    if (!hasTaintedIngress) return [];

    return map.nodes.filter(n =>
      n.node_type === 'STORAGE' &&
      // Only fire if the STORAGE node itself has tainted data_in — meaning user
      // input actually reaches it. The previous d.source === 'EXTERNAL' fallback
      // was too broad: it fired on any STORAGE node with external data regardless
      // of whether that data was user-controlled (tainted). This caused 5/10
      // Juliet false positives where arrays/strings existed but had no taint flow.
      n.data_in.some(d => d.tainted) &&
      (n.node_subtype.includes('list') || n.node_subtype.includes('array') ||
       n.node_subtype.includes('string') || n.node_subtype.includes('buffer') ||
       n.code_snapshot.match(/\b(push|append|concat|insert|add|write|null.*terminat)\b/i) !== null)
    );
  },
  /\bstrip.*sentinel\b|\bremove.*null\b|\bvalidate.*struct\b|\bcheck.*terminat\b|\bescape\s*\(|\bvalidate\b|\bsanitize\b|\bstripNull\b|\breplace.*\\x00\b/i,
  'TRANSFORM (sentinel character stripping / neutralization)',
  'Strip or neutralize sentinel characters (null bytes, delimiters) from user input ' +
    'before adding to data structures. Uncontrolled sentinels can corrupt structure boundaries.',
);

/** CWE-496: Public Data Assigned to Private Array-Typed Field */
export const verifyCWE496 = createNoTransformVerifier(
  'CWE-496', 'Public Data Assigned to Private Array-Typed Field', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('private') || n.node_subtype.includes('internal') ||
     n.node_subtype.includes('field') || n.node_subtype.includes('member') ||
     n.code_snapshot.match(/\bprivate\b|\b#\w+\b|\bthis\.\w+\s*=\s*/i) !== null)
  ),
  /\bclone\b|\bcopy\b|\bslice\b|\bArray\.from\b|\bspread\b|\b\[\.\.\./i,
  'TRANSFORM (defensive copy before assignment to private field)',
  'Clone or copy arrays/objects before assigning to private fields. ' +
    'Direct assignment allows external code to modify internal state through the original reference.',
);

// ===========================================================================
// G. LOG INJECTION (1 CWE)
// ===========================================================================

/** CWE-117: Improper Output Neutralization for Logs */
export function verifyCWE117(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = logStorageNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasPathWithoutTransform(map, src.id, sink.id)) {
        if (!LOG_ENCODE_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (log encoding — strip newlines, control chars, delimiters)',
            severity: 'medium',
            description: `User input from ${src.label} is logged at ${sink.label} without neutralization. ` +
              `An attacker can inject fake log entries via newlines or forge audit trails.`,
            fix: 'Strip or encode newlines (\\n, \\r), control characters, and log-format delimiters ' +
              'from user input before logging. Use structured logging (JSON) to prevent injection.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-117', name: 'Improper Output Neutralization for Logs', holds: findings.length === 0, findings };
}

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_004_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Path Equivalence (17)
  'CWE-41': verifyCWE41,
  'CWE-42': verifyCWE42,
  'CWE-43': verifyCWE43,
  'CWE-44': verifyCWE44,
  'CWE-45': verifyCWE45,
  'CWE-46': verifyCWE46,
  'CWE-47': verifyCWE47,
  'CWE-48': verifyCWE48,
  'CWE-49': verifyCWE49,
  'CWE-50': verifyCWE50,
  'CWE-51': verifyCWE51,
  'CWE-52': verifyCWE52,
  'CWE-53': verifyCWE53,
  'CWE-54': verifyCWE54,
  'CWE-55': verifyCWE55,
  'CWE-57': verifyCWE57,
  'CWE-58': verifyCWE58,
  // Cleartext Storage (4)
  'CWE-224': verifyCWE224,
  'CWE-313': verifyCWE313,
  'CWE-314': verifyCWE314,
  'CWE-316': verifyCWE316,
  // Crypto/Hashing (3)
  'CWE-759': verifyCWE759,
  'CWE-760': verifyCWE760,
  'CWE-916': verifyCWE916,
  // Input Neutralization (4)
  'CWE-158': verifyCWE158,
  'CWE-163': verifyCWE163,
  'CWE-178': verifyCWE178,
  'CWE-198': verifyCWE198,
  // Code Injection (2)
  'CWE-96': verifyCWE96,
  'CWE-97': verifyCWE97,
  // Data Integrity (3)
  'CWE-454': verifyCWE454,
  'CWE-464': verifyCWE464,
  'CWE-496': verifyCWE496,
  // Log Injection (1)
  'CWE-117': verifyCWE117,
};
