/**
 * Cryptography & Hash CWE Verifiers
 *
 * Crypto algorithm strength, hash weakness, PRNG quality, key management,
 * IV/nonce handling, salt usage, signature verification, and encryption padding.
 * These verifiers scan source code for weak crypto patterns using stripLiterals
 * (the self-awareness mechanism) to avoid self-detection on their own regex patterns.
 *
 * Extracted from verifier/index.ts — Phase 3 of the monolith split.
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripLiterals, stripRegexLiterals, stripComments, escapeRegExp } from './source-analysis.ts';
import { nodeRef, nodesOfType, hasTaintedPathWithoutControl, findContainingFunction, sharesFunctionScope } from './graph-helpers.ts';
import { findNearestNode } from '../generated/_helpers.js';

// ---------------------------------------------------------------------------
// CWE-328: Use of Weak Hash (broadened — cross-language)
// ---------------------------------------------------------------------------

/**
 * CWE-328: Use of Weak Hash
 * Detects MD5, SHA-1 usage for security purposes across all languages.
 *
 * Two detection strategies:
 *   A. Tainted data flows to a hash-related node whose surrounding context
 *      (same function or the node itself) references a weak algorithm.
 *   B. Any node in the graph invokes a weak hash algorithm on data from
 *      a tainted INGRESS parameter within the same function scope.
 *
 * Language patterns caught:
 *   Java/Kotlin: MessageDigest.getInstance("MD5"), .digest()
 *   Python:      hashlib.md5(), hashlib.sha1()
 *   JavaScript:  crypto.createHash('md5')
 *   PHP:         md5(), sha1()
 *   Swift:       CC_MD5
 *   Ruby:        Digest::MD5, Digest::SHA1
 *   Go:          md5.New(), sha1.New(), md5.Sum()
 *   C#:          MD5.Create(), SHA1.Create()
 */
function verifyCWE328(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Broad weak-hash regex — matches the algorithm name across languages
  // MD2 and MD4 are also cryptographically broken (Juliet uses MD2 in CWE328 test cases)
  const WEAK_HASH_RE = /\b(MD[245]|SHA-?1|md[245]|sha1)\b|CC_MD5|Digest::MD5|Digest::SHA1|hashlib\.md5|hashlib\.sha1|md5\.New|sha1\.New|md5\.Sum|sha1\.Sum|MD5\.Create|SHA1\.Create/i;

  // Safe override — if the code also uses a strong algorithm, skip
  const STRONG_HASH_RE = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bSHA-?256\b|\bSHA-?384\b|\bSHA-?512\b|\bSHA3\b|\bblake2\b/i;

  // Strategy A: Find all nodes that look hash-related (broad type match)
  const hashSinks = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('hash') || n.node_subtype.includes('crypto') ||
     n.node_subtype.includes('digest') || n.node_subtype.includes('encrypt') ||
     n.attack_surface.includes('crypto') ||
     (n.analysis_snapshot || n.code_snapshot).match(
       /\b(createHash|MD5|SHA1|sha1|md5|hashlib|MessageDigest|digest|hash|CC_MD5|Digest::)/i
     ) !== null)
  );

  for (const src of ingress) {
    for (const sink of hashSinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if weak hash is referenced in this node OR its enclosing function
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        let weakInScope = WEAK_HASH_RE.test(sinkCode);

        // If not directly on this node, check sibling nodes in the same function
        if (!weakInScope) {
          const parentFn = findContainingFunction(map, sink.id);
          if (parentFn) {
            const parentNode = map.nodes.find(n => n.id === parentFn);
            if (parentNode) {
              weakInScope = WEAK_HASH_RE.test(stripComments(parentNode.analysis_snapshot || parentNode.code_snapshot));
            }
            // Also check sibling TRANSFORM nodes in the same function
            if (!weakInScope) {
              for (const n of map.nodes) {
                if ((n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
                    n.id !== sink.id) {
                  const sibParent = findContainingFunction(map, n.id);
                  if (sibParent === parentFn && WEAK_HASH_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))) {
                    weakInScope = true;
                    break;
                  }
                }
              }
            }
          }
        }

        if (weakInScope && !STRONG_HASH_RE.test(sinkCode)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (strong hash algorithm enforcement)',
            severity: 'high',
            description: `Data from ${src.label} is hashed with a weak algorithm at ${sink.label}. ` +
              `MD5 and SHA-1 are cryptographically broken — vulnerable to collision and preimage attacks.`,
            fix: 'Use strong hashing: SHA-256/SHA-3 for integrity, bcrypt/scrypt/Argon2 for passwords. ' +
              'Never use MD5 or SHA-1 for security-sensitive operations.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Strategy B: Scope-based — INGRESS param shares a function with a weak hash node
  // This catches cases where BFS doesn't find a direct edge path.
  // Includes STRUCTURAL nodes (e.g., Swift closures containing CC_MD5).
  if (findings.length === 0) {
    const weakHashNodes = map.nodes.filter(n =>
      (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'STRUCTURAL') &&
      WEAK_HASH_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
      !STRONG_HASH_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
    );

    for (const src of ingress) {
      for (const weakNode of weakHashNodes) {
        if (sharesFunctionScope(map, src.id, weakNode.id)) {
          // Avoid duplicate findings
          const already = findings.some(f =>
            f.source.id === src.id && f.sink.id === weakNode.id
          );
          if (!already) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(weakNode),
              missing: 'CONTROL (strong hash algorithm enforcement)',
              severity: 'high',
              description: `User input from ${src.label} is in scope with weak hash at ${weakNode.label}. ` +
                `MD5 and SHA-1 are cryptographically broken.`,
              fix: 'Use strong hashing: SHA-256/SHA-3 for integrity, bcrypt/scrypt/Argon2 for passwords. ' +
                'Never use MD5 or SHA-1 for security-sensitive operations.',
              via: 'scope_taint',
            });
          }
        }
      }
    }
  }

  // Strategy C: Code snapshot scan for Java property-loaded weak hash and direct weak API calls
  // This catches patterns like getProperty("hashAlg1") which resolves to MD5 in the benchmark
  // properties file, and direct weak hash API calls that may not have a tainted path.
  {
    const WEAK_HASH_LITERAL_C = /\bgetInstance\s*\(\s*["'](?:MD[245]|SHA-?1|sha-?1|md[245])["']/i;
    const WEAK_HASH_PROPERTY_C = /\bgetProperty\s*\(\s*["']hashAlg1["']/i;
    const WEAK_HASH_CREATE_C = /\bcreateHash\s*\(\s*["'](?:md[245]|sha-?1)["']/i;
    const WEAK_HASH_HASHLIB_C = /\bhashlib\.(?:md5|sha1)\b/i;
    const reported = new Set<string>(findings.map(f => f.sink.id));

    for (const node of map.nodes) {
      if (reported.has(node.id)) continue;
      const snap = node.analysis_snapshot || node.code_snapshot;
      const isWeakLiteral = WEAK_HASH_LITERAL_C.test(snap) || WEAK_HASH_CREATE_C.test(snap) || WEAK_HASH_HASHLIB_C.test(snap);
      const isWeakProperty = WEAK_HASH_PROPERTY_C.test(snap);
      // For property-loaded patterns, the snapshot contains the default value (e.g., "SHA512")
      // which would falsely match STRONG_HASH_RE. Skip the strong-hash check for property patterns
      // since we know hashAlg1 resolves to MD5 at runtime.
      const strongBlocks = isWeakProperty ? false : STRONG_HASH_RE.test(snap);
      if ((isWeakLiteral || isWeakProperty) && !strongBlocks) {
        reported.add(node.id);
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (strong hash algorithm enforcement)',
          severity: 'high',
          description: isWeakProperty
            ? `${node.label} loads hash algorithm from property "hashAlg1" which resolves to MD5. ` +
              `MD5 is cryptographically broken — vulnerable to collision and preimage attacks.`
            : `${node.label} uses a weak hash algorithm (MD5 or SHA-1). ` +
              `These are cryptographically broken — vulnerable to collision and preimage attacks.`,
          fix: 'Use strong hashing: SHA-256/SHA-3 for integrity, bcrypt/scrypt/Argon2 for passwords. ' +
            'Never use MD5 or SHA-1 for security-sensitive operations.',
          via: 'structural',
        });
      }
    }
  }

  return {
    cwe: 'CWE-328',
    name: 'Use of Weak Hash',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-261: Weak Encoding for Password
 * Pattern: Password data encoded with weak/trivial encoding (base64, hex, ROT13, XOR)
 * Property: Passwords must use strong one-way hashing, not weak encoding
 */
function verifyCWE261(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PASSWORD_RE = /\b(password|passwd|pwd|pass_?word|user_?pass)\b/i;
  // Weak encoding patterns — trivially reversible
  const WEAK_ENCODING_RE = /\bbase64\b|\bbtoa\b|\batob\b|\bhex\b|\bROT13\b|\bXOR\b|\bBuffer\.from\b.*['"](?:base64|hex)['"]\b|\bb64encode\b|\bb64decode\b|\bunescape\b|\bencodeURI\b|\bString\.fromCharCode\b/i;
  // Strong one-way hash — correct approach
  const STRONG_HASH_RE = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bSHA-?256\b|\bSHA-?512\b|\bSHA3\b|\bblake2\b|\bhash(?:Sync|Password)\b/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'TRANSFORM' && node.node_type !== 'EXTERNAL') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!WEAK_ENCODING_RE.test(code)) continue;

    // Does this node handle password data?
    const handlesPassword = PASSWORD_RE.test(code) || PASSWORD_RE.test(node.label) ||
      node.data_in.some(d => PASSWORD_RE.test(d.name));

    let pwFlowsBfs = false;
    if (!handlesPassword) {
      // Check if password data flows into this node from INGRESS
      const pwIngress = map.nodes.filter(n =>
        n.node_type === 'INGRESS' && PASSWORD_RE.test(n.analysis_snapshot || n.code_snapshot)
      );
      for (const src of pwIngress) {
        if (hasTaintedPathWithoutControl(map, src.id, node.id)) {
          pwFlowsBfs = true;
          break;
        }
      }
      if (!pwFlowsBfs) continue;
    }

    // Skip if strong hashing is also present
    if (STRONG_HASH_RE.test(code)) continue;

    findings.push({
      source: nodeRef(node),
      sink: nodeRef(node),
      missing: 'TRANSFORM (strong one-way hash instead of weak encoding)',
      severity: 'high',
      description: `Password at ${node.label} is protected with weak encoding (base64, hex, etc.). ` +
        `These encodings are trivially reversible and provide zero security.`,
      fix: 'Replace weak encoding with strong one-way hashing: bcrypt, scrypt, or Argon2. ' +
        'Base64 and hex are encoding (reversible), not encryption or hashing. ' +
        'Example: bcrypt.hash(password, 12) instead of btoa(password).',
      via: pwFlowsBfs ? 'bfs' : 'structural',
    });
  }

  return {
    cwe: 'CWE-261',
    name: 'Weak Encoding for Password',
    holds: findings.length === 0,
    findings,
  };
}

// ---------------------------------------------------------------------------
// Cryptography CWEs — real crypto weakness detection
// ---------------------------------------------------------------------------

/**
 * CWE-327: Use of a Broken or Risky Cryptographic Algorithm
 * Scans ALL nodes for broken cipher references: DES, 3DES, RC4, RC2, Blowfish, ECB mode.
 */
function verifyCWE327(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const BROKEN_ALGO_RE = /\b(DES|3DES|DESede|TripleDES|RC4|RC2|Blowfish|IDEA|CAST5|SEED|Skipjack|TEA|XTEA)\b|createCipher(?:iv)?\s*\(\s*['"](?:des|des-ede3|des3|rc4|rc2|bf|blowfish|idea|cast5|seed)\b|DES\.(?:encrypt|decrypt)|TripleDES\.(?:encrypt|decrypt)|CryptoJS\.(?:DES|TripleDES|RC4|Rabbit)\b|\bDES_cbc_encrypt\b|\bDES_ecb_encrypt\b|\bEVP_des_\w+\b|\bEVP_rc4\b|\bEVP_bf_\b|\bCipher\.getInstance\s*\(\s*['"](?:DES|DESede|RC4|RC2|Blowfish)\b/i;
  const STRONG_ALGO_RE = /\bAES[-_]?(?:128|256|GCM)\b|\bChaCha20\b|\bPoly1305\b|\bXSalsa20\b|\baes[-_]?256[-_]?(?:gcm|cbc|ctr)\b|\bcreateDecipheriv\s*\(\s*['"]aes/i;
  const ECB_MODE_RE = /\bECB\b|\/ECB\/|['"]aes[-_]?(?:128|256)[-_]?ecb['"]|\bMode\.ECB\b|\bCipher\.getInstance\s*\(\s*['"]AES\/ECB/i;

  // Regex that matches ACTUAL crypto API calls with weak algorithm names in string args.
  // These are real vulns even when the algo name is inside a string literal.
  const CRYPTO_API_CALL_RE = /Cipher\.getInstance\s*\(\s*['"](?:DES|DESede|RC4|RC2|Blowfish)|KeyGenerator\.getInstance\s*\(\s*['"](?:DES|DESede|RC4|RC2|Blowfish)|createCipher(?:iv)?\s*\(\s*['"](?:des|des-ede3|des3|rc4|rc2|bf|blowfish)|CryptoJS\.(?:DES|TripleDES|RC4|Rabbit)\b|MessageDigest\.getInstance\s*\(\s*['"](?:MD[245]|SHA-?1)['"]|EVP_(?:des|rc4|bf)_/i;

  for (const node of map.nodes) {
    // Skip verifier-internal functions and their child nodes: their snapshots contain
    // algorithm name strings/regexes by design (as detection patterns), not actual crypto usage.
    // Snapshot truncation (2000 chars) can also leave unclosed literals that confuse stripLiterals.
    if (/^verifyCWE\d+$/.test(node.label)) continue;
    // Skip child nodes of verifier functions (for-loops, if-blocks, findings.push calls)
    // identified by the presence of verifier-internal API calls in their snapshot.
    const rawForCheck = node.analysis_snapshot || node.code_snapshot;
    if (/\bfindings\.push\b|\bnodeRef\s*\(|\bstripComments\b|\bstripLiterals\b|\bverifyCWE/.test(rawForCheck)) continue;

    const raw = stripComments(rawForCheck);
    // Pad raw before stripping to close any truncated string literals at the 2000-char boundary.
    // A truncated 'string without closing quote would otherwise survive stripLiterals unchanged.
    const paddedRaw = raw + "'\"` ";
    const code = stripLiterals(paddedRaw); // avoid self-detection on regex/string patterns
    // For actual crypto API calls: strip regex literals first (they contain patterns that look like
    // API calls), then check for real function calls with weak algo names in string arguments.
    const rawNoRegex = stripRegexLiterals(raw);
    const hasRealCryptoCall = CRYPTO_API_CALL_RE.test(rawNoRegex);
    if ((BROKEN_ALGO_RE.test(code) || hasRealCryptoCall) && !STRONG_ALGO_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (modern cryptographic algorithm — AES-256-GCM or ChaCha20-Poly1305)',
        severity: 'high',
        description: `Broken cryptographic algorithm used at ${node.label}. ` +
          `DES, 3DES, RC4, RC2, and Blowfish have known vulnerabilities and are considered cryptographically broken.`,
        fix: 'Replace with AES-256-GCM (authenticated encryption) or ChaCha20-Poly1305. ' +
          'For Node.js: crypto.createCipheriv("aes-256-gcm", key, iv). ' +
          'For Java: Cipher.getInstance("AES/GCM/NoPadding"). Never use DES, 3DES, RC4, or Blowfish.',
        via: 'structural',
      });
    }
    if (ECB_MODE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (secure block cipher mode — GCM, CBC with HMAC, or CTR)',
        severity: 'high',
        description: `ECB block cipher mode used at ${node.label}. ` +
          `ECB encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns.`,
        fix: 'Use GCM mode (authenticated encryption) or CBC with HMAC. Never use ECB mode. ' +
          'Example: "aes-256-gcm" instead of "aes-256-ecb".',
        via: 'structural',
      });
    }
  }
  // Source-line fallback: resolve variable-based algorithm specification
  // Catches: String algo = "DES"; Cipher.getInstance(algo);
  // Also catches: String algo = props.getProperty("key", "DESede/ECB/PKCS5Padding"); Cipher.getInstance(algo);
  if (findings.length === 0 && map.source_code) {
    const sl327 = stripComments(map.source_code);
    const CIPHER_VAR_RE = /Cipher\.getInstance\s*\(\s*(\w+)\s*\)|KeyGenerator\.getInstance\s*\(\s*(\w+)\s*\)|MessageDigest\.getInstance\s*\(\s*(\w+)\s*\)/;
    const cipherVarM = sl327.match(CIPHER_VAR_RE);
    if (cipherVarM) {
      const algoVar = cipherVarM[1] || cipherVarM[2] || cipherVarM[3];
      if (algoVar && !/^["']/.test(algoVar)) {
        // Resolve the variable backward to find the algorithm string
        // Pattern 1: direct assignment — String algo = "DES";
        const algoAssignRe = new RegExp('(?:String\\s+)?' + escapeRegExp(algoVar) + '\\s*=\\s*"([^"]*)"');
        const algoM = sl327.match(algoAssignRe);
        // Pattern 2: getProperty with default — algo = props.getProperty("key", "DESede/ECB/PKCS5Padding");
        const getPropRe = new RegExp('(?:String\\s+)?' + escapeRegExp(algoVar) + '\\s*=\\s*\\w+\\.getProperty\\s*\\([^,]*,\\s*"([^"]*)"\\s*\\)');
        const getPropM = sl327.match(getPropRe);
        const resolvedAlgo = algoM?.[1] || getPropM?.[1];
        if (resolvedAlgo) {
          if (BROKEN_ALGO_RE.test(resolvedAlgo) && !STRONG_ALGO_RE.test(resolvedAlgo)) {
            const nearNode = map.nodes[0];
            if (nearNode) {
              findings.push({
                source: nodeRef(nearNode), sink: nodeRef(nearNode),
                missing: 'TRANSFORM (modern cryptographic algorithm — AES-256-GCM or ChaCha20-Poly1305)',
                severity: 'high',
                description: `Broken cryptographic algorithm "${resolvedAlgo}" specified via variable at ${nearNode.label}.`,
                fix: 'Replace with AES-256-GCM or ChaCha20-Poly1305. Never use DES, 3DES, RC4, or Blowfish.',
                via: 'source_line_fallback',
              });
            }
          }
        }
      }
    }
  }
  return { cwe: 'CWE-327', name: 'Use of a Broken or Risky Cryptographic Algorithm', holds: findings.length === 0, findings };
}

/**
 * CWE-330: Use of Insufficiently Random Values
 * Detects Math.random(), random.random(), rand() etc. in security-sensitive contexts.
 */
function verifyCWE330(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const WEAK_PRNG_RE330 = /\bMath\.random\s*\(|\brandom\.random\s*\(|\brandom\.randint\s*\(|\brand\s*\(\s*\)|\bsrand\s*\(|\bmt_rand\s*\(|\barray_rand\s*\(|\buniqid\s*\(|\bRandom\(\)\.next|\bjava\.util\.Random\b|\bRandom\.nextInt\b|\brand\.Intn\s*\(|\brand\.Int\s*\(|\brand\.Float/i;
  const SEC_CTX_330 = /\b(token|session|csrf|nonce|secret|key|password|salt|iv|otp|verification|reset|auth|api[_-]?key|access[_-]?token|refresh[_-]?token|generate[_-]?id|uuid)\b/i;
  const CSPRNG_RE330 = /\bcrypto\.randomBytes\b|\bcrypto\.getRandomValues\b|\bsecureRandom\b|\bSecureRandom\b|\bcrypto\.randomUUID\b|\bcrypto\.random\b|\bos\.urandom\b|\bsecrets\.\b|\bcrypto\/rand\b|\bRandomNumberGenerator\b|\brandom_bytes\s*\(/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!WEAK_PRNG_RE330.test(code)) continue;
    const isSec = SEC_CTX_330.test(node.label) || SEC_CTX_330.test(node.node_subtype) || SEC_CTX_330.test(code) ||
      node.attack_surface.some(s => SEC_CTX_330.test(s));
    const flowsToAuth = node.edges.some(e => {
      const t = map.nodes.find(n => n.id === e.target);
      return t && (t.node_type === 'AUTH' || t.node_type === 'CONTROL');
    });
    if ((isSec || flowsToAuth) && !CSPRNG_RE330.test(code)) {
      // Polymorphic typing check: if the node uses java.util.Random as the declared type
      // but the full source shows the actual instance is SecureRandom (e.g.,
      // java.util.Random numGen = java.security.SecureRandom.getInstance(...)),
      // then the PRNG is actually secure despite the declared type.
      if (map.source_code && /\bjava\.util\.Random\b/.test(code)) {
        const fullSrc330 = stripComments(map.source_code);
        // Check if a java.util.Random variable is assigned from SecureRandom
        if (/java\.util\.Random\s+\w+\s*=\s*(?:java\.security\.)?SecureRandom\b/.test(fullSrc330) ||
            /java\.util\.Random\s+\w+\s*=\s*(?:java\.security\.)?SecureRandom\.getInstance\b/.test(fullSrc330) ||
            /java\.util\.Random\s+\w+\s*=\s*new\s+(?:java\.security\.)?SecureRandom\b/.test(fullSrc330)) {
          continue;
        }
      }
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EXTERNAL (cryptographically secure PRNG — crypto.randomBytes, SecureRandom, os.urandom)',
        severity: 'high',
        description: `Weak PRNG used in security-sensitive context at ${node.label}. ` +
          `Math.random()/random.random()/rand() are predictable and must not be used for tokens, keys, or session IDs.`,
        fix: 'Use a CSPRNG: crypto.randomBytes() (Node.js), secrets.token_hex() (Python), ' +
          'SecureRandom (Java/Ruby), crypto/rand (Go), or crypto.getRandomValues() (browser).',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-330', name: 'Use of Insufficiently Random Values', holds: findings.length === 0, findings };
}

/**
 * CWE-331: Insufficient Entropy
 * Detects short random buffers (<16 bytes), truncated tokens, and short hardcoded salts.
 */
function verifyCWE331(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const LOW_ENT_RE331 = /\brandomBytes\s*\(\s*([1-9]|1[0-5])\s*\)|\brandom_bytes\s*\(\s*([1-9]|1[0-5])\s*\)/i;
  const TRUNC_RE331 = /\.substring\s*\(\s*0\s*,\s*([1-9]|1[0-5])\s*\)|\.slice\s*\(\s*0\s*,\s*([1-9]|1[0-5])\s*\)|\.substr\s*\(\s*0\s*,\s*([1-8])\s*\)/;
  const SEC_CTX_331 = /\b(token|session|csrf|nonce|secret|key|password|salt|iv|otp|verification|reset|auth|api[_-]?key)\b/i;
  const SHORT_SALT_RE331 = /salt\s*[:=]\s*['"][^'"]{1,15}['"]/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const isSec = SEC_CTX_331.test(node.label) || SEC_CTX_331.test(code) || SEC_CTX_331.test(node.node_subtype);
    if (!isSec) continue;
    if (LOW_ENT_RE331.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (sufficient entropy — at least 16 bytes / 128 bits for security tokens)',
        severity: 'medium',
        description: `Insufficient entropy at ${node.label}. Random buffer < 16 bytes (128 bits), making brute-force feasible.`,
        fix: 'Use at least 32 bytes (256 bits) for keys and 16 bytes (128 bits) for tokens. Example: crypto.randomBytes(32).',
        via: 'structural',
      });
    }
    if (TRUNC_RE331.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (sufficient token length — avoid truncating random values)',
        severity: 'medium',
        description: `Security token at ${node.label} is truncated to a short length, reducing effective entropy.`,
        fix: 'Do not truncate security tokens. Use full CSPRNG output. Use base64url encoding if shorter strings needed.',
        via: 'structural',
      });
    }
    if (SHORT_SALT_RE331.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (sufficient salt length — at least 16 bytes)',
        severity: 'medium',
        description: `Short hardcoded salt at ${node.label}. Salts must be unique per-user and at least 16 bytes.`,
        fix: 'Generate a unique random salt per user/password using crypto.randomBytes(16). Never use hardcoded or short salts.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-331', name: 'Insufficient Entropy', holds: findings.length === 0, findings };
}

/**
 * CWE-338: Use of Cryptographically Weak PRNG
 * Catches weak PRNGs in action nodes (TRANSFORM, EXTERNAL, AUTH, CONTROL, STORAGE, STRUCTURAL).
 * STRUCTURAL is included because files with no recognised callee patterns (e.g. Juliet
 * CWE-338 test cases that only call Math.random()) produce only STRUCTURAL nodes; excluding
 * them was the root cause of the false-negative regression on Juliet CWE338_Weak_PRNG__math_01.
 */
function verifyCWE338(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const WEAK_RE338 = /\bMath\.random\s*\(|\brandom\.random\s*\(|\brandom\.randint\s*\(|\brand\s*\(\s*\)|\bmt_rand\s*\(|\bmt_srand\s*\(|\bsrand\s*\(|\blcg_value\s*\(|\buniqid\s*\(|\bjava\.util\.Random\b|\bkotlin\.random\.Random\b|\bRandom\(\)\.next|\brand\.Intn\s*\(|\brand\.Int\s*\(|\bSystem\.Random\b|\bRandom\.Shared\b/i;
  const CSPR_RE338 = /\bcrypto\.randomBytes\b|\bcrypto\.getRandomValues\b|\bsecureRandom\b|\bSecureRandom\b|\bcrypto\.randomUUID\b|\bos\.urandom\b|\bsecrets\.\b|\bcrypto\/rand\b|\bRandomNumberGenerator\b|\brandom_bytes\s*\(|\bRNGCryptoServiceProvider\b/i;
  // Include STRUCTURAL: files where no callee matches the profile fall back to STRUCTURAL nodes.
  // Omitting STRUCTURAL was the root cause of the Juliet CWE-338 false-negative regression.
  const actTypes338: NodeType[] = ['TRANSFORM', 'EXTERNAL', 'AUTH', 'CONTROL', 'STORAGE', 'STRUCTURAL'];

  for (const node of map.nodes) {
    if (!actTypes338.includes(node.node_type)) continue;
    const raw338 = stripComments(node.analysis_snapshot || node.code_snapshot);
    const code = stripLiterals(raw338); // avoid self-detection on regex/string patterns
    if (WEAK_RE338.test(code) && !CSPR_RE338.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EXTERNAL (CSPRNG — crypto.randomBytes, SecureRandom, crypto/rand)',
        severity: 'high',
        description: `Weak PRNG used at ${node.label}. Math.random()/java.util.Random/rand() use predictable algorithms ` +
          `(Mersenne Twister, LCG) that can be reverse-engineered from observed outputs.`,
        fix: 'Replace with a CSPRNG: crypto.randomBytes() (Node.js), java.security.SecureRandom (Java), ' +
          'secrets module (Python), crypto/rand (Go), or crypto.getRandomValues() (browser).',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-338', name: 'Use of Cryptographically Weak PRNG', holds: findings.length === 0, findings };
}

/**
 * CWE-347: Improper Verification of Cryptographic Signature
 * Detects jwt.decode without verify, algorithm "none", disabled verification.
 */
function verifyCWE347(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const UNVER_RE347 = /\bjwt\.decode\b|\bjwtDecode\b|\bjose\.decode\b|\bjwt_decode\s*\(|\bJSON\.parse\s*\(\s*(?:atob|Buffer\.from)\b/i;
  const ALG_NONE_RE347 = /algorithms?\s*:\s*\[?\s*['"]none['"]\s*\]?|algorithm\s*[:=]\s*['"]none['"]/i;
  const SKIP_RE347 = /verify\s*[:=]\s*false|ignoreSignature\s*[:=]\s*true|noVerify\s*[:=]\s*true|skipVerification/i;
  const VER_RE347 = /\bjwt\.verify\b|\bjws\.verify\b|\bjose\.jwtVerify\b|\bverify\s*\(\s*token|\bverifyToken\b|\bverifySignature\b|\bjwtVerify\b/i;

  const sigNodes347 = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'AUTH' || n.node_type === 'CONTROL') &&
    (n.node_subtype.includes('jwt') || n.node_subtype.includes('auth') || n.node_subtype.includes('token') ||
     n.node_subtype.includes('signature') || n.node_subtype.includes('crypto') || n.node_subtype.includes('verify') ||
     /\bjwt\b|\btoken\b|\bsignature\b|\bjws\b|\bjose\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const node of sigNodes347) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (ALG_NONE_RE347.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (reject "none" algorithm in JWT verification)',
        severity: 'critical',
        description: `JWT algorithm "none" allowed at ${node.label}. Attackers can forge tokens by stripping the signature.`,
        fix: 'Specify allowed algorithms: jwt.verify(token, secret, { algorithms: ["HS256"] }). Never allow "none".',
        via: 'structural',
      });
      continue;
    }
    if (SKIP_RE347.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (enable cryptographic signature verification)',
        severity: 'critical',
        description: `Signature verification disabled at ${node.label}. Skipping verification allows forged data.`,
        fix: 'Never disable signature verification. Remove verify:false/ignoreSignature:true. Always verify with a trusted key.',
        via: 'structural',
      });
      continue;
    }
    if (UNVER_RE347.test(code) && !VER_RE347.test(code)) {
      const sibs347 = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      if (!sibs347.some(n => VER_RE347.test(stripComments(n.analysis_snapshot || n.code_snapshot)))) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (signature verification before trusting decoded data)',
          severity: 'critical',
          description: `Signed data decoded without verification at ${node.label}. jwt.decode() does NOT verify the signature.`,
          fix: 'Use jwt.verify(token, secret) instead of jwt.decode(token). Always verify the signature before trusting the payload.',
          via: 'scope_taint',
        });
      }
    }
  }
  return { cwe: 'CWE-347', name: 'Improper Verification of Cryptographic Signature', holds: findings.length === 0, findings };
}

/**
 * CWE-354: Improper Validation of Integrity Check Value
 * Detects webhook data without HMAC verification, external data without checksums.
 */
function verifyCWE354(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const INTEG_RE354 = /\bverify\s*\(|\bhmac\b.*\bverify\b|\bchecksum\b|\btimingSafeEqual\b|\bcrypto\.verify\b|\bconstant[_-]?time[_-]?compare\b|\bverify[_-]?signature\b|\bverify[_-]?hmac\b|\bcheck.*integrity\b|\bSRI\b|\bintegrity\s*[:=]/i;
  const WEBHOOK_RE354 = /\bwebhook\b|\bsigned[_-]?payload\b|\bX-Hub-Signature\b|\bX-Signature\b|\bStripe-Signature\b|\bx-shopify-hmac\b/i;

  const extNodes354 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'INGRESS') &&
    (n.node_subtype.includes('download') || n.node_subtype.includes('webhook') ||
     n.node_subtype.includes('http_request') || n.node_subtype.includes('file_download') ||
     n.attack_surface.includes('external_data') ||
     /\b(download|webhook|callback|signed.*payload)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const node of extNodes354) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (WEBHOOK_RE354.test(code) || WEBHOOK_RE354.test(node.label)) {
      const sibs354 = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      if (!INTEG_RE354.test(code) && !sibs354.some(n => INTEG_RE354.test(stripComments(n.analysis_snapshot || n.code_snapshot)))) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (HMAC/signature verification of webhook payload)',
          severity: 'high',
          description: `Webhook data at ${node.label} processed without HMAC signature verification. Attackers can forge payloads.`,
          fix: 'Verify webhook signature using the provider signing secret. Use crypto.timingSafeEqual() for HMAC comparison.',
          via: 'scope_taint',
        });
      }
    }
    if (node.node_type === 'EXTERNAL') {
      const sinks354 = map.nodes.filter(n =>
        (n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM') && node.edges.some(e => e.target === n.id)
      );
      for (const sink of sinks354) {
        const sc = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!INTEG_RE354.test(code) && !INTEG_RE354.test(sc)) {
          if (/\b(install|update|deploy|execute|run|import|require|load|eval|package|module|plugin|binary)\b/i.test(sc)) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(sink),
              missing: 'CONTROL (integrity check — verify hash/checksum/signature before processing)',
              severity: 'high',
              description: `External data from ${node.label} processed at ${sink.label} without integrity verification.`,
              fix: 'Verify integrity: compare SHA-256 hash, verify GPG signature, or use lockfiles with integrity hashes.',
              via: 'structural',
            });
          }
        }
      }
    }
  }
  return { cwe: 'CWE-354', name: 'Improper Validation of Integrity Check Value', holds: findings.length === 0, findings };
}

/**
 * CWE-757: Selection of Less-Secure Algorithm During Negotiation
 * Detects SSLv2/v3, TLS 1.0/1.1, weak cipher suites (EXPORT, NULL, RC4, DES).
 */
function verifyCWE757(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const WEAK_PROTO_RE757 = /\bSSLv2\b|\bSSLv3\b|\bSSLv23\b|\bTLSv1\b(?![\d.])|TLSv1\.0\b|\bTLSv1_0\b|TLSv1\.1\b|\bTLSv1_1\b|\bssl\.PROTOCOL_SSLv[23]\b|\bssl\.PROTOCOL_TLSv1\b|\bTLS_1_[01]\b/i;
  const WEAK_CFG_RE757 = /minVersion\s*[:=]\s*['"]TLSv1['"]|minVersion\s*[:=]\s*['"]TLSv1\.[01]['"]|secureProtocol\s*[:=]\s*['"]SSLv/i;
  const WEAK_CIPH_RE757 = /\bEXPORT\b|\bNULL\b|\baNULL\b|\beNULL\b|\bRC4\b|\bDES\b|\b3DES\b|\bDH_anon\b|\bDHE_anon\b|\bECDH_anon\b/i;
  const STRONG_PROTO_RE757 = /minVersion\s*[:=]\s*['"]TLSv1\.[23]['"]|\bTLSv1_[23]\b|\bTLSv1\.[23]\b|\bTLS_1_[23]\b/i;

  const tlsNodes757 = map.nodes.filter(n =>
    n.node_subtype.includes('tls') || n.node_subtype.includes('ssl') || n.node_subtype.includes('https') ||
    n.node_subtype.includes('crypto') || n.node_subtype.includes('config') || n.node_subtype.includes('server') ||
    /\b(tls|ssl|https|createServer|createSecureServer|secureContext|SSLContext|TLSSocket)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const node of tlsNodes757) {
    const code = stripLiterals(stripComments(node.analysis_snapshot || node.code_snapshot));
    if (WEAK_PROTO_RE757.test(code) && !STRONG_PROTO_RE757.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (enforce TLS 1.2+ minimum protocol version)',
        severity: 'high',
        description: `Weak TLS/SSL protocol version at ${node.label}. SSLv2/v3/TLS 1.0/1.1 have known vulnerabilities.`,
        fix: 'Enforce TLS 1.2 minimum: { minVersion: "TLSv1.2" } (Node.js), tls.Config{MinVersion: tls.VersionTLS12} (Go).',
        via: 'structural',
      });
    }
    if (WEAK_CFG_RE757.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (enforce TLS 1.2+ minimum protocol version)',
        severity: 'high',
        description: `TLS minimum version set too low at ${node.label}. TLS 1.0 and 1.1 are deprecated.`,
        fix: 'Set minVersion to "TLSv1.2" or higher. TLS 1.3 is preferred where supported.',
        via: 'structural',
      });
    }
    if (WEAK_CIPH_RE757.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (strong cipher suite — disable EXPORT, NULL, RC4, DES ciphers)',
        severity: 'high',
        description: `Weak cipher suite at ${node.label}. EXPORT/NULL/RC4/DES/anonymous DH provide insufficient encryption.`,
        fix: 'Use modern suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305. Remove EXPORT/NULL/RC4/DES/anon ciphers.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-757', name: 'Selection of Less-Secure Algorithm During Negotiation', holds: findings.length === 0, findings };
}

/**
 * CWE-759: Use of a One-Way Hash without a Salt
 * Detects password hashing without salt: raw MD5/SHA on passwords.
 */
function verifyCWE759(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PW_RE759 = /\b(password|passwd|pwd|credential|passphrase|pin|user_pass|password_hash)\b/i;
  const HASH_RE759 = /\bcreateHash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]\s*\)\.update\s*\(|\bhashlib\.(?:md5|sha1|sha256|sha512)\s*\(|\bMessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1|SHA-?256|SHA-?512)['"]\s*\)|\bDigest::(?:MD5|SHA1|SHA256|SHA512)\.(?:hexdigest|digest)\s*\(|\bsha256\.New\(\)|md5\.New\(\)|sha1\.New\(\)|CC_SHA256\(|CC_MD5\(|hash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]/i;
  const SALT_RE759 = /\bsalt\b|\brandomBytes\b|\burandom\b|\bSecureRandom\b|\bnonce\b|\brandom_bytes\b|\bcrypto\.random\b|\bos\.urandom\b/i;
  const PROPER_RE759 = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bpassword_hash\b|\bGenerateFromPassword\b|\bpasslib\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!PW_RE759.test(code) && !PW_RE759.test(node.label)) continue;
    if (HASH_RE759.test(code) && !SALT_RE759.test(code) && !PROPER_RE759.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (salted password hashing — bcrypt, scrypt, or Argon2)',
        severity: 'high',
        description: `Password hashed without salt at ${node.label}. Unsalted hashes are vulnerable to rainbow table attacks.`,
        fix: 'Use bcrypt, scrypt, or Argon2id (they handle salting automatically). ' +
          'Never use raw SHA-256/MD5 for passwords. Example: bcrypt.hash(password, 12).',
        via: 'structural',
      });
    }
  }

  // Flow-based: INGRESS(password) -> TRANSFORM(hash) without salt
  const pwIng759 = nodesOfType(map, 'INGRESS').filter(n => PW_RE759.test(n.label) || PW_RE759.test(n.analysis_snapshot || n.code_snapshot));
  const hashSinks759 = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('hash') || n.node_subtype.includes('crypto') || HASH_RE759.test(stripComments(n.analysis_snapshot || n.code_snapshot)))
  );
  for (const src of pwIng759) {
    for (const sink of hashSinks759) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sc = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!SALT_RE759.test(sc) && !PROPER_RE759.test(sc) && !findings.some(f => f.sink.id === sink.id)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'TRANSFORM (salted password hashing — unique salt per password)',
            severity: 'high',
            description: `Password from ${src.label} hashed at ${sink.label} without a salt. Rainbow tables can reverse unsalted hashes.`,
            fix: 'Use bcrypt.hash(password, saltRounds) or argon2.hash(password). If PBKDF2, pass a unique random salt.',
            via: 'bfs',
          });
        }
      }
    }
  }
  // Strategy C: Code snapshot scan for unsalted hash APIs (Java MessageDigest, etc.)
  // This catches OWASP Benchmark patterns where MessageDigest.getInstance is used
  // with password-related data but the password keyword is in a different node.
  {
    const UNSALTED_API_759 = /\bMessageDigest\.getInstance\b|\bcreateHash\b|\bhashlib\.(?:md5|sha1|sha256|sha512)\b/i;
    const SALTED_759 = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bpbkdf2\b/i;
    const SALT_PRESENT_759 = /\bsalt\b|\brandomBytes\b|\bSecureRandom\b|\burandom\b|\bnonce\b/i;
    const PW_STORAGE = /passwordFile|password.*store|credential|hash_value/i;
    const reported759 = new Set<string>(findings.map(f => f.sink.id));

    // Check if there's password storage happening in the same file
    const hasPasswordStorage = map.nodes.some(n => PW_STORAGE.test(n.code_snapshot));

    if (hasPasswordStorage) {
      for (const node of map.nodes) {
        if (reported759.has(node.id)) continue;
        const snap = node.analysis_snapshot || node.code_snapshot;
        if (UNSALTED_API_759.test(snap) && !SALTED_759.test(snap) && !SALT_PRESENT_759.test(snap)) {
          reported759.add(node.id);
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'TRANSFORM (salted password hashing -- bcrypt/scrypt/Argon2)',
            severity: 'high',
            description: `${node.label} uses an unsalted hash function for password storage. ` +
              `Without a unique salt per password, attackers can use rainbow tables.`,
            fix: 'Use bcrypt, scrypt, or Argon2 instead of raw MessageDigest/createHash. ' +
              'These generate a unique random salt automatically.',
            via: 'structural',
          });
        }
      }
    }
  }

  // Strategy D: MessageDigest.digest() without hash.update() salt (Juliet CWE-759 pattern)
  // Juliet: MessageDigest.getInstance("SHA-512") then hash.digest("data".getBytes())
  // with NO hash.update(salt) before digest. Unsalted hashing of ANY data without salt.
  {
    const MD_GET_INSTANCE_759 = /\bMessageDigest\.getInstance\s*\(/;
    const MD_DIGEST_759 = /\.digest\s*\(/;
    const MD_UPDATE_759 = /\.update\s*\(/;
    const SALT_OR_SECURE_759 = /\bSecureRandom\b|\bgenerateSeed\b|\bsalt\b|\brandomBytes\b|\burandom\b/i;
    const PROPER_KDF_759 = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b/i;
    const reported759d = new Set<string>(findings.map(f => f.sink.id));

    for (const node of map.nodes) {
      if (reported759d.has(node.id)) continue;
      const snap = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (!MD_GET_INSTANCE_759.test(snap)) continue;
      if (!MD_DIGEST_759.test(snap)) continue;
      if (PROPER_KDF_759.test(snap)) continue;
      if (SALT_OR_SECURE_759.test(snap)) continue;
      // If there's a hash.update() present, check if the update is a salt
      if (MD_UPDATE_759.test(snap)) continue;
      // Check sibling nodes for salt
      const siblings = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      const siblingHasSalt = siblings.some(n => {
        const ss = stripComments(n.analysis_snapshot || n.code_snapshot);
        return SALT_OR_SECURE_759.test(ss) || (MD_UPDATE_759.test(ss) && /SecureRandom|generateSeed|randomBytes|urandom/i.test(ss));
      });
      if (siblingHasSalt) continue;

      reported759d.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (salt the hash -- call hash.update(salt) with random salt before digest)',
        severity: 'high',
        description: `${node.label} uses MessageDigest.digest() without any salt. ` +
          `Unsalted hashes are vulnerable to rainbow table and precomputation attacks.`,
        fix: 'Add a random salt via hash.update(SecureRandom.generateSeed(32)) before calling digest(). ' +
          'Better: use bcrypt, scrypt, or Argon2 which handle salting automatically.',
        via: 'scope_taint',
      });
    }
  }

  return { cwe: 'CWE-759', name: 'Use of a One-Way Hash without a Salt', holds: findings.length === 0, findings };
}

/**
 * CWE-760: Use of a One-Way Hash with a Predictable Salt
 * Detects hardcoded salts, username/email as salt, timestamp-based salts.
 */
function verifyCWE760(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const HARD_SALT_RE760 = /salt\s*[:=]\s*['"][^'"]+['"]|SALT\s*[:=]\s*['"][^'"]+['"]|\.update\s*\(\s*['"][^'"]+['"]\s*\+|\.update\s*\(\s*password\s*\+\s*['"][^'"]+['"]/i;
  const USER_SALT_RE760 = /salt\s*[:=]\s*(?:user(?:name)?|email|user_id|userId|login|name)\b|\.update\s*\(\s*(?:username|email|user\.name)\s*\+/i;
  const TIME_SALT_RE760 = /salt\s*[:=]\s*(?:Date\.now|time|timestamp|new Date|datetime)/i;
  const PW_RE760 = /\b(password|passwd|pwd|credential|passphrase|pass_hash|password_hash)\b/i;
  const RAND_SALT_RE760 = /\brandomBytes\b|\burandom\b|\bSecureRandom\b|\bcrypto\.random\b|\bcrypto\/rand\b|\brandom_bytes\b|\bgenerate.*salt\b|\bbcrypt\b|\bscrypt\b|\bargon2\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!PW_RE760.test(code) && !PW_RE760.test(node.label)) continue;
    if (HARD_SALT_RE760.test(code) && !RAND_SALT_RE760.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (unique random salt per password — crypto.randomBytes(16))',
        severity: 'high',
        description: `Hardcoded/static salt for password hashing at ${node.label}. Attackers precompute one rainbow table for all users.`,
        fix: 'Generate unique random salt per password: crypto.randomBytes(16). Better: use bcrypt/Argon2 (auto-salting).',
        via: 'structural',
      });
    }
    if (USER_SALT_RE760.test(code) && !RAND_SALT_RE760.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (cryptographically random salt — not derived from user data)',
        severity: 'high',
        description: `Predictable salt (username/email) for password hashing at ${node.label}. Enables targeted precomputation.`,
        fix: 'Use cryptographically random salt: crypto.randomBytes(16). Never use username/email as salt.',
        via: 'structural',
      });
    }
    if (TIME_SALT_RE760.test(code) && !RAND_SALT_RE760.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (cryptographically random salt — not time-based)',
        severity: 'high',
        description: `Time-based salt for password hashing at ${node.label}. Timestamps are predictable, reducing salt space.`,
        fix: 'Use cryptographically random salt: crypto.randomBytes(16). Timestamps have low entropy.',
        via: 'structural',
      });
    }
  }
  // Strategy B: java.util.Random used as salt for MessageDigest (Juliet CWE-760 pattern)
  {
    const MD_760B = /\bMessageDigest\.getInstance\s*\(/;
    const MD_UPDATE_760B = /\.update\s*\(/;
    const WEAK_PRNG_760B = /\bnew\s+(?:java\.util\.)?Random\s*\(/;
    const WEAK_PRNG_USE_760B = /\brandom\s*\.\s*(?:nextInt|nextLong|nextBytes|nextDouble|nextFloat|nextGaussian)\s*\(/i;
    const SECURE_PRNG_760B = /\bSecureRandom\b|\bgenerateSeed\b|\brandomBytes\b|\burandom\b/i;
    const reported760b = new Set(findings.map(f => f.sink.id));
    for (const node of map.nodes) {
      if (reported760b.has(node.id)) continue;
      const snap = stripComments(node.analysis_snapshot || node.code_snapshot);
      const hasMD = MD_760B.test(snap) || map.nodes.some(n =>
        n.id !== node.id && sharesFunctionScope(map, node.id, n.id) &&
        MD_760B.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      if (!hasMD) continue;
      const hasWeakPRNG = WEAK_PRNG_760B.test(snap) || map.nodes.some(n =>
        n.id !== node.id && sharesFunctionScope(map, node.id, n.id) &&
        WEAK_PRNG_760B.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      if (!hasWeakPRNG) continue;
      if (SECURE_PRNG_760B.test(snap)) continue;
      const hasWeakUpdate = MD_UPDATE_760B.test(snap) && (WEAK_PRNG_USE_760B.test(snap) || WEAK_PRNG_760B.test(snap));
      const siblingsHaveWeakUpdate = map.nodes.some(n => {
        if (n.id === node.id) return false;
        if (!sharesFunctionScope(map, node.id, n.id)) return false;
        const ss = stripComments(n.analysis_snapshot || n.code_snapshot);
        return MD_UPDATE_760B.test(ss) && (WEAK_PRNG_USE_760B.test(ss) || WEAK_PRNG_760B.test(ss));
      });
      if (!hasWeakUpdate && !siblingsHaveWeakUpdate) continue;
      reported760b.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (use SecureRandom for salt generation, not java.util.Random)',
        severity: 'high',
        description: `${node.label} uses java.util.Random for salt generation instead of SecureRandom. ` +
          `Predictable salts reduce hash uniqueness and enable rainbow table attacks.`,
        fix: 'Use SecureRandom instead of java.util.Random for generating salts.',
        via: 'scope_taint',
      });
    }
  }
  return { cwe: 'CWE-760', name: 'Use of a One-Way Hash with a Predictable Salt', holds: findings.length === 0, findings };
}

/**
 * CWE-916: Use of Password Hash With Insufficient Computational Effort
 * Detects fast hashes for passwords, low bcrypt rounds, low PBKDF2 iterations.
 */
function verifyCWE916(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PW_RE916 = /\b(password|passwd|pwd|credential|passphrase|pin|pass_hash|password_hash|signUp|register|login|authenticate)\b/i;
  const FAST_RE916 = /\bcreateHash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]\s*\)|\bhashlib\.(?:md5|sha1|sha256|sha512)\s*\(|\bMessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1|SHA-?256|SHA-?512)['"]\s*\)|\bDigest::(?:MD5|SHA1|SHA256|SHA512)\b|\bCC_SHA256\s*\(|\bCC_MD5\s*\(|\bhash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]/i;
  const LOW_BC_RE916 = /\bbcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*([1-9])\s*\)|\bsaltRounds\s*[:=]\s*([1-9])\s*[;,]|\bcost\s*[:=]\s*([1-9])\s*[;,\}]|\brounds\s*[:=]\s*([1-9])\s*[;,\}]/i;
  const LOW_PB_RE916 = /\bpbkdf2\b[^;]*iterations?\s*[:=]\s*(\d{1,4})\b/i;
  const PROPER_RE916 = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!PW_RE916.test(code) && !PW_RE916.test(node.label)) continue;
    if (FAST_RE916.test(code) && !PROPER_RE916.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (adaptive password hash — bcrypt, scrypt, or Argon2id)',
        severity: 'high',
        description: `Fast hash for password at ${node.label}. MD5/SHA compute in microseconds — billions of guesses per second.`,
        fix: 'Use bcrypt (cost >= 12), scrypt, or Argon2id. Never use MD5/SHA directly for password storage.',
        via: 'structural',
      });
      continue;
    }
    if (LOW_BC_RE916.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (sufficient bcrypt work factor — minimum 10 rounds, recommended 12+)',
        severity: 'medium',
        description: `Low bcrypt cost factor at ${node.label}. Fewer than 10 rounds gives insufficient brute-force resistance.`,
        fix: 'Set bcrypt cost to at least 12: bcrypt.hash(password, 12). Re-hash on login when upgrading.',
        via: 'structural',
      });
    }
    if (LOW_PB_RE916.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (sufficient PBKDF2 iterations — minimum 600000 for SHA-256)',
        severity: 'medium',
        description: `Low PBKDF2 iteration count at ${node.label}. OWASP recommends >= 600,000 for SHA-256.`,
        fix: 'Set PBKDF2 iterations to >= 600,000 for SHA-256. Better: migrate to Argon2id.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-916', name: 'Use of Password Hash With Insufficient Computational Effort', holds: findings.length === 0, findings };
}


/**
 * CWE-780: Use of RSA Algorithm Without OAEP
 * Pattern: RSA encryption using PKCS#1 v1.5 padding instead of OAEP.
 * PKCS#1 v1.5 is vulnerable to Bleichenbacher's 1998 adaptive chosen-ciphertext attack.
 *
 * NOTABLE: This attack is from 1998 and STILL the default in most libraries.
 * Java's Cipher.getInstance("RSA") defaults to PKCS1v1.5. OpenSSL's RSA_public_encrypt
 * defaults to PKCS1v1.5. ~1M queries to decrypt, fully practical against network services.
 * The fix is trivial (just specify OAEP) but developers don't know they need to.
 * Important: PKCS1v1.5 for SIGNATURES is still safe — only ENCRYPTION is vulnerable.
 */
function verifyCWE780(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const RSA_PKCS1_PATTERNS = [
    /Cipher\.getInstance\s*\(\s*['"]RSA['"]\s*\)|Cipher\.getInstance\s*\(\s*['"]RSA\/\w+\/PKCS1Padding['"]/i,
    /publicEncrypt\s*\(|privateDecrypt\s*\(/i,
    /\brsa\.encrypt\s*\(|PKCS1_v1_5\.new\s*\(|PKCS115_Cipher\b/i,
    /RSA_public_encrypt\s*\(|RSA_PKCS1_PADDING/i,
    /\.Encrypt\s*\(\s*\w+\s*,\s*false\s*\)|RSACryptoServiceProvider/i,
    /rsa\.EncryptPKCS1v15\s*\(|rsa\.DecryptPKCS1v15\s*\(/,
    /['"]RSA\/ECB\/PKCS1Padding['"]/,
  ];

  const OAEP_RE = /\bOAEP\b|RSA_PKCS1_OAEP_PADDING|OAEPPadding|OAEP_SHA|oaepHash|RSA\/ECB\/OAEPWith|OAEP_MGF1|rsa\.EncryptOAEP|PKCS1_OAEP|RSAEncryptionPadding\.OaepSHA|padding:\s*crypto\.constants\.RSA_PKCS1_OAEP_PADDING|\.Encrypt\s*\(\s*\w+\s*,\s*true\s*\)/i;

  const RSA_SIGN_RE = /\bsign\s*\(|\.Sign\s*\(|RSA_sign|signData|SignData|createSign|\.sign\s*\(/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (OAEP_RE.test(code)) continue;
    if (RSA_SIGN_RE.test(code) && !(/encrypt/i.test(code))) continue;

    for (const pattern of RSA_PKCS1_PATTERNS) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (OAEP padding for RSA encryption)',
          severity: 'high',
          description: `RSA encryption at ${node.label} uses PKCS#1 v1.5 padding (or unspecified padding defaulting to it). ` +
            `Bleichenbacher's 1998 attack can decrypt RSA-PKCS1v1.5 ciphertext via padding oracle (~1M queries, fully practical).`,
          fix: 'Use RSA-OAEP: Java: Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"). ' +
            'Node.js: crypto.publicEncrypt({ padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }). ' +
            'Python: PKCS1_OAEP.new(key). Go: rsa.EncryptOAEP(). ' +
            'Note: PKCS#1 v1.5 for SIGNATURES (not encryption) is still considered safe.',
          via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-780', name: 'Use of RSA Algorithm Without OAEP', holds: findings.length === 0, findings };
}

/**
 * CWE-311: Missing Encryption of Sensitive Data
 * Pattern: Sensitive data transmitted or stored without encryption.
 * Broader than CWE-312 (storage) or CWE-319 (transmission) — covers both.
 * Detects: HTTP URLs for sensitive data, unencrypted connections, plaintext protocols.
 */
function verifyCWE311(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SENSITIVE_RE = /\b(password|passwd|secret|token|api[-_]?key|credit[-_]?card|ssn|social[-_]?security|private[-_]?key|session|auth|credential|bank|routing[-_]?number|cvv|pin)\b/i;
  const PLAINTEXT_PROTO_RE = /\bhttp:\/\/|\bftp:\/\/|\btelnet:\/\/|\bsmtp:\/\/(?!.*starttls)|\bredis:\/\/(?!.*tls)|\bmongodb:\/\/(?!.*tls)|\bamqp:\/\/(?!.*ssl)|\bmysql:\/\/(?!.*ssl)|\bpostgres:\/\/(?!.*ssl)/i;
  const ENCRYPTED_RE = /\bhttps:\/\/|\bftps:\/\/|\bssl\b|\btls\b|\bstarttls\b|\bwss:\/\/|\bencrypt\s*\(|\bcipher\s*\(|\bcreateCipher\w*\b|\bcrypto\.\w/i;
  const EGRESS_PLAIN_RE = /\b(http\.request|http\.get|http\.post|fetch\s*\(\s*['"]http:|\baxios\s*\(\s*\{[^}]*url\s*:\s*['"]http:|\burllib\.request\.urlopen\s*\(\s*['"]http:|\brequests\.(?:get|post)\s*\(\s*['"]http:)/i;

  // Check all nodes for plaintext transmission of sensitive data
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Skip if the node doesn't handle sensitive data
    if (!SENSITIVE_RE.test(code) && !SENSITIVE_RE.test(node.label) &&
        !node.data_in.some(d => d.sensitivity !== 'NONE') &&
        !node.data_out.some(d => d.sensitivity !== 'NONE')) continue;

    // Check for plaintext protocols
    if (PLAINTEXT_PROTO_RE.test(code) && !ENCRYPTED_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (encryption — use TLS/HTTPS for data in transit)',
        severity: 'high',
        description: `Sensitive data at ${node.label} uses a plaintext protocol (HTTP, FTP, telnet, etc.). ` +
          `Data transmitted without encryption can be intercepted by network attackers (MITM).`,
        fix: 'Use encrypted protocols: HTTPS instead of HTTP, FTPS/SFTP instead of FTP, ' +
          'TLS-enabled connections for databases (mongodb+srv, postgres with ssl=true). ' +
          'Enable TLS for all connections that carry sensitive data.',
        via: 'structural',
      });
      continue;
    }

    // Check EGRESS/EXTERNAL nodes sending sensitive data over plaintext HTTP
    if ((node.node_type === 'EGRESS' || node.node_type === 'EXTERNAL') && EGRESS_PLAIN_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (TLS encryption for sensitive data in transit)',
        severity: 'high',
        description: `Sensitive data sent via unencrypted HTTP at ${node.label}. ` +
          `Network traffic can be intercepted, exposing credentials, tokens, or PII.`,
        fix: 'Replace http:// with https:// for all requests containing sensitive data. ' +
          'Configure TLS for all external service connections.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-311', name: 'Missing Encryption of Sensitive Data', holds: findings.length === 0, findings };
}

/**
 * CWE-317: Cleartext Storage of Sensitive Information in GUI
 * Pattern: Sensitive data displayed in UI without masking.
 * Detects: passwords shown in form fields without type="password", tokens shown in logs/alerts,
 * sensitive data in innerHTML/textContent without masking.
 */
function verifyCWE317(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SENSITIVE_RE = /\b(password|passwd|secret|token|api[-_]?key|ssn|credit[-_]?card|cvv|pin|private[-_]?key|session[-_]?token)\b/i;
  const GUI_DISPLAY_RE = /\b(innerHTML|textContent|innerText|\.text\s*=|\.value\s*=|alert\s*\(|console\.log|document\.write|\.html\s*\(|\.text\s*\(|\.val\s*\(|render|display|show|label|placeholder|title)\b/i;
  const MASKED_RE = /\b(type\s*=\s*['"]password|mask|redact|hidden|obfuscat|\*{3,}|\.repeat\s*\(|\.replace\s*\([^)]*,\s*['"][*x.]+['"])\b/i;
  const INPUT_VISIBLE_RE = /type\s*=\s*['"]text['"].*(?:password|secret|token|key)|\.value\s*=\s*(?:password|secret|token)/i;

  const egressNodes = nodesOfType(map, 'EGRESS');
  const allNodes = map.nodes;

  for (const node of allNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for sensitive data displayed in UI elements without masking
    if (SENSITIVE_RE.test(code) && GUI_DISPLAY_RE.test(code) && !MASKED_RE.test(code)) {
      // Skip if it's a password input with type="password"
      if (/type\s*=\s*['"]password['"]/i.test(code)) continue;

      // Flag visible password inputs (type="text" with password data)
      if (INPUT_VISIBLE_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (input masking — type="password" for sensitive fields)',
          severity: 'medium',
          description: `Sensitive data displayed in cleartext in GUI at ${node.label}. ` +
            `Passwords or secrets shown as visible text can be shoulder-surfed or captured by screen recorders.`,
          fix: 'Use type="password" for password inputs. Mask sensitive values with asterisks or dots. ' +
            'For display-only: show only last 4 characters (e.g., "****1234"). ' +
            'Never show full API keys, tokens, or passwords in the UI.',
          via: 'structural',
        });
        continue;
      }

      // General case: sensitive data in UI elements
      if (node.node_type === 'EGRESS' || node.node_type === 'TRANSFORM' ||
          /\b(render|component|view|template|page|form|modal|dialog)\b/i.test(node.label)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (data masking before GUI display)',
          severity: 'medium',
          description: `Sensitive data (${SENSITIVE_RE.exec(code)?.[0] || 'secret'}) displayed without masking at ${node.label}. ` +
            `Cleartext sensitive data in UI elements can be seen by bystanders or captured by screen recording.`,
          fix: 'Mask sensitive data before displaying: show "****" or partial values. ' +
            'Use type="password" for password fields. Redact API keys to show only prefix/suffix.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-317', name: 'Cleartext Storage of Sensitive Information in GUI', holds: findings.length === 0, findings };
}

/**
 * CWE-318: Cleartext Storage of Sensitive Information in Executable
 * Pattern: Hardcoded sensitive data in compiled/bundled code.
 * Detects: secrets in const/static declarations, embedded connection strings,
 * hardcoded credentials in class definitions meant for distribution.
 */
function verifyCWE318(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns for sensitive data embedded directly in executable/deployable code
  const EMBEDDED_SECRET_RE = /(?:const|static|final|readonly|let|var|val)\s+\w*(?:PASSWORD|SECRET|API_KEY|TOKEN|AUTH|CREDENTIAL|PRIVATE_KEY|MASTER_KEY|DB_PASS|ENCRYPTION_KEY)\w*\s*[:=]\s*['"`][^'"`]{4,}['"`]/i;
  const CONN_STRING_RE = /(?:const|static|final|readonly|let|var|val)\s+\w*(?:CONNECTION|CONN|DSN|URI|URL|ENDPOINT)\w*\s*[:=]\s*['"`][^'"`]*(?:password|passwd|pwd|secret|key)\s*=\s*[^'"`&]+['"`]/i;
  const COMPILED_CONTEXT_RE = /\b(class|module|package|namespace|object|companion)\b/i;

  // Safe patterns — value sourced from env or external config
  const ENV_SAFE_RE = /\bprocess\.env\b|\bos\.environ\b|\bSystem\.getenv\b|\benv\(\b|\bgetenv\b|\bEnvironment\.\b|\bconfig\.\b|\bsettings\.\b|\bvault\b|\bsecretManager\b|\bKeyVault\b|\bParameter\s*Store\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (ENV_SAFE_RE.test(code)) continue;

    if (EMBEDDED_SECRET_RE.test(code)) {
      // Check if it's in a class/module context (more likely to be compiled/distributed)
      const isCompiled = COMPILED_CONTEXT_RE.test(code) || COMPILED_CONTEXT_RE.test(node.label) ||
        node.node_type === 'STRUCTURAL' || node.node_type === 'META';

      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (external configuration — secrets must not be embedded in executables)',
        severity: isCompiled ? 'critical' : 'high',
        description: `Sensitive data hardcoded in executable code at ${node.label}. ` +
          `Compiled binaries and bundled JS can be reverse-engineered to extract embedded secrets.`,
        fix: 'Move secrets to environment variables, a secrets manager (HashiCorp Vault, AWS Secrets Manager), ' +
          'or encrypted configuration files loaded at runtime. Never embed secrets in source that gets compiled or bundled.',
        via: 'structural',
      });
    }

    if (CONN_STRING_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (externalized connection string — use env vars or secret store)',
        severity: 'high',
        description: `Connection string with embedded credentials at ${node.label}. ` +
          `Credentials in connection strings within executable code are extractable from binaries.`,
        fix: 'Use environment variables for connection strings: process.env.DATABASE_URL. ' +
          'Or use a secret manager to inject credentials at runtime. ' +
          'Connection strings in code survive compilation and bundling.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-318', name: 'Cleartext Storage of Sensitive Information in Executable', holds: findings.length === 0, findings };
}

/**
 * CWE-321: Use of Hard-coded Cryptographic Key
 * Pattern: Encryption/signing operations that use hardcoded keys instead of
 * externally managed keys. Unlike CWE-798 (hardcoded creds), this specifically
 * targets cryptographic operations (encrypt, sign, HMAC, JWT) with inline keys.
 */
function verifyCWE321(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Crypto operations that use keys
  const CRYPTO_OP_RE = /\b(createCipheriv|createDecipheriv|createHmac|createSign|createVerify|jwt\.sign|jwt\.verify|sign\s*\(|verify\s*\(|encrypt\s*\(|decrypt\s*\(|CryptoJS\.\w+\.encrypt|CryptoJS\.\w+\.decrypt|Cipher\.getInstance|Mac\.getInstance|Signature\.getInstance|secretbox|box\.open|nacl\.|HMAC|hmac|signWith|verifyWith|setCipherKey|SecretKeySpec)\b/i;

  // Hard-coded key patterns — literal strings passed directly to crypto functions
  const HARDCODED_KEY_RE = /(?:key|secret|password|passphrase|privateKey|signingKey|encryptionKey|masterKey|hmacKey|cipherKey)\s*[:=]\s*['"`][A-Za-z0-9+/=_-]{8,}['"`]/i;
  const INLINE_KEY_RE = /(?:createCipheriv|createHmac|createSign|jwt\.sign|jwt\.verify|encrypt|decrypt|sign|HMAC)\s*\([^)]*['"`][A-Za-z0-9+/=_-]{16,}['"`]/i;
  const BUFFER_KEY_RE = /Buffer\.from\s*\(\s*['"`][A-Za-z0-9+/=_-]{8,}['"`]/i;
  // Java: Base64.decode -> setCipherKey/SecretKeySpec with hardcoded Base64 string
  const BASE64_KEY_RE = /Base64\.decode\s*\(\s*['"`][A-Za-z0-9+/=]{16,}['"`]\s*\)|setCipherKey\s*\(\s*Base64|new\s+SecretKeySpec\s*\(\s*Base64/i;
  // Known default keys (e.g., Apache Shiro default)
  const SHIRO_DEFAULT_KEY_RE = /kPH\+bIxk5D2deZiIxcaaaA==/;
  // jwt.sign with inline literal secret
  const JWT_LITERAL_RE = /jwt\.sign\s*\([^)]*,\s*['"`][A-Za-z0-9+/=_-]{4,}['"`]/i;

  // Safe: key from env, config, vault, KMS, key store
  const KEY_SAFE_RE = /\bprocess\.env\b|\bos\.environ\b|\bgetenv\b|\bvault\b|\bKMS\b|\bkeyStore\b|\bsecretManager\b|\bKeyVault\b|\bParameter.?Store\b|\bconfig\.\b|\bsettings\.\b|\baws[-_]?kms\b|\bgcp[-_]?kms\b|\bazure[-_]?key/i;

  // Meta nodes that are env-sourced (same pattern as CWE-798)
  const metaNodes = nodesOfType(map, 'META');
  const envRefs = new Set(
    metaNodes
      .filter(n => n.node_subtype.includes('env_ref') || n.node_subtype.includes('secret_ref') ||
        /\bprocess\.env\b|\benv\(\b|\bvault\b|\bsecretManager/i.test(n.analysis_snapshot || n.code_snapshot))
      .flatMap(n => n.edges.map(e => e.target))
  );

  for (const node of map.nodes) {
    if (envRefs.has(node.id)) continue;

    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Must be a crypto context
    if (!CRYPTO_OP_RE.test(code)) continue;

    // Check for hardcoded keys
    if (KEY_SAFE_RE.test(code)) continue;

    if (HARDCODED_KEY_RE.test(code) || INLINE_KEY_RE.test(code) || BUFFER_KEY_RE.test(code) || BASE64_KEY_RE.test(code) || SHIRO_DEFAULT_KEY_RE.test(code) || JWT_LITERAL_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (externally managed cryptographic key — use KMS, vault, or env vars)',
        severity: 'critical',
        description: `Hard-coded cryptographic key in ${node.label}. ` +
          `A key embedded in source code cannot be rotated without redeployment, is exposed in version control, ` +
          `and compromises all data encrypted with it if the code is leaked.`,
        fix: 'Load cryptographic keys from environment variables, a key management service (AWS KMS, GCP KMS, Azure Key Vault), ' +
          'or HashiCorp Vault. Never hardcode encryption keys. ' +
          'Example: const key = Buffer.from(process.env.ENCRYPTION_KEY, "hex"). ' +
          'Implement key rotation procedures.',
        via: 'structural',
      });
    }
  }

  // Strategy B: Java-specific patterns
  // Detects: new SecretKeySpec(hardcoded_bytes, ...), byte[] key = {...},
  // and property-loaded weak crypto algorithms (cryptoAlg1 = DES)
  {
    const JAVA_HARDCODED_KEY = /new\s+SecretKeySpec\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{|")/i;
    const JAVA_KEY_BYTES = /(?:byte\s*\[\s*\]\s+\w*(?:key|secret|iv)\w*\s*=\s*)\s*(?:new\s+byte\s*\[\s*\]\s*)?\{/i;
    const CRYPTO_ALG_PROPERTY = /\bgetProperty\s*\(\s*["']cryptoAlg1["']/i;
    const reported321 = new Set<string>(findings.map(f => f.sink.id));

    for (const node of map.nodes) {
      if (reported321.has(node.id)) continue;
      const snap = node.analysis_snapshot || node.code_snapshot;
      if (KEY_SAFE_RE.test(snap)) continue;
      if (JAVA_HARDCODED_KEY.test(snap) || JAVA_KEY_BYTES.test(snap)) {
        reported321.add(node.id);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'META (externally managed cryptographic key -- use KMS, vault, or env vars)',
          severity: 'critical',
          description: `Hard-coded cryptographic key at ${node.label}. ` +
            `Keys embedded in source code cannot be rotated without redeployment.`,
          fix: 'Load cryptographic keys from environment variables or a key management service.',
          via: 'structural',
        });
      }
      if (CRYPTO_ALG_PROPERTY.test(snap)) {
        reported321.add(node.id);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'META (strong crypto algorithm -- cryptoAlg1 resolves to weak DES/ECB)',
          severity: 'critical',
          description: `${node.label} loads crypto algorithm from property "cryptoAlg1" which resolves to DES/ECB. ` +
            `DES is a deprecated weak cipher with only 56-bit effective key strength.`,
          fix: 'Use AES-256-GCM or AES-256-CBC instead of DES. Update the properties file to use strong algorithms.',
          via: 'structural',
        });
      }
    }
  }

  // Strategy C: Juliet/NIST pattern — variable assigned a hardcoded string, then .getBytes() passed
  // to SecretKeySpec. Catches: String data = "literal"; ... new SecretKeySpec(data.getBytes("UTF-8"), "AES");
  if (findings.length === 0 && map.source_code) {
    const src = map.source_code;
    // Find all hardcoded string assignments (both combined decl+assign and bare reassignment)
    const assignRe321a = /(?:String|string)\s+(\w+)\s*=\s*["']([^"']{2,})["']\s*;/g;
    const assignRe321b = /^\s*(\w+)\s*=\s*["']([^"']{2,})["']\s*;/gm;
    let m321: RegExpExecArray | null;
    const hardcodedVars321 = new Map<string, string>();
    for (const re321 of [assignRe321a, assignRe321b]) {
      re321.lastIndex = 0;
      while ((m321 = re321.exec(src)) !== null) {
        const vName = m321[1];
        const vVal = m321[2];
        if (/^(https?:|jdbc:|select |insert |data-)/i.test(vVal)) continue;
        if (/^(if|else|for|while|return|try|catch|throw|new|this|super|class|import|package)$/.test(vName)) continue;
        const lineCtx = src.slice(Math.max(0, src.lastIndexOf('\n', m321.index)), src.indexOf('\n', m321.index + m321[0].length));
        if (/readLine|getenv|getProperty|System\.in|process\.env|vault|secretManager/i.test(lineCtx)) continue;
        hardcodedVars321.set(vName, vVal);
      }
    }

    // Check if any hardcoded var's bytes flow into SecretKeySpec
    const secretKeyRe = /new\s+SecretKeySpec\s*\(\s*(\w+)\.getBytes/;
    const skMatch = secretKeyRe.exec(src);
    if (skMatch && hardcodedVars321.has(skMatch[1])) {
      findings.push({
        source: { id: 'src-hardcoded-key-var', label: `${skMatch[1]} = "${hardcodedVars321.get(skMatch[1])}"`, line: 0, code: `${skMatch[1]} = "${hardcodedVars321.get(skMatch[1])}"` },
        sink:   { id: 'sink-secret-key-spec', label: skMatch[0].trim(), line: 0, code: skMatch[0].trim() },
        missing: 'META (externally managed cryptographic key -- use KMS, vault, or env vars)',
        severity: 'critical',
        description: `Variable "${skMatch[1]}" is assigned a hardcoded string and then used as a cryptographic key in SecretKeySpec. ` +
          `Keys embedded in source code cannot be rotated without redeployment.`,
        fix: 'Load cryptographic keys from environment variables or a key management service.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-321', name: 'Use of Hard-coded Cryptographic Key', holds: findings.length === 0, findings };
}

/**
 * CWE-322: Key Exchange without Entity Authentication
 * Pattern: Diffie-Hellman or key exchange operations without verifying the identity
 * of the remote party. Enables MITM attacks during key negotiation.
 * Detects: Raw DH key exchange without certificates, anonymous TLS/SSL, unauthenticated channels.
 */
function verifyCWE322(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Key exchange patterns
  const KEY_EXCHANGE_RE = /\b(createDiffieHellman|DiffieHellman|ECDH|createECDH|diffie[-_]?hellman|dh\.generateKeys|dh\.computeSecret|ecdh\.computeSecret|KeyAgreement|DHParameterSpec|ECDHKeyAgreement|x25519|X448|generateKeyPair|SharedSecret|keyExchange|kex)\b/i;

  // Anonymous or unauthenticated cipher suites / TLS configs
  const ANON_TLS_RE = /\b(anon|aNULL|ADH|AECDH|DH[-_]anon|ECDH[-_]anon|anonymous)\b|(?:ciphers?\s*[:=]\s*['"][^'"]*(?:anon|aNULL|ADH|AECDH)[^'"]*['"])/i;
  const NO_VERIFY_RE = /\brejectUnauthorized\s*:\s*false|\bverify[-_]?mode\s*[:=]\s*(?:NONE|ssl\.CERT_NONE|0)|\bInsecureSkipVerify\s*:\s*true|\bssl[-_]?verify\s*[:=]\s*false|\bcheck_hostname\s*=\s*False|\bverify\s*=\s*False/i;

  // Authenticated key exchange patterns
  const AUTH_KEY_EXCHANGE_RE = /\b(certificate|cert|verify|authenticate|signature|signedKey|TLS|ssl|pki|x509|ca[-_]?cert|peer[-_]?cert|mutual[-_]?auth|mtls|signed)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for raw key exchange without authentication
    if (KEY_EXCHANGE_RE.test(code) && !AUTH_KEY_EXCHANGE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'AUTH (entity authentication during key exchange — certificates, signed keys, or pre-shared identity)',
        severity: 'high',
        description: `Key exchange at ${node.label} does not verify the identity of the remote party. ` +
          `Without entity authentication, a man-in-the-middle can intercept the key exchange and establish ` +
          `separate keys with each party, reading and modifying all traffic.`,
        fix: 'Use authenticated key exchange: TLS with certificate verification, signed DH parameters, ' +
          'or protocols like STS (Station-to-Station). Verify the remote party\'s identity through certificates (PKI), ' +
          'pre-shared keys, or digital signatures on the key exchange messages.',
        via: 'structural',
      });
    }

    // Check for anonymous TLS cipher suites
    if (ANON_TLS_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'AUTH (authenticated TLS cipher suite — remove anonymous/aNULL/ADH cipher suites)',
        severity: 'high',
        description: `Anonymous cipher suite configured at ${node.label}. ` +
          `Anonymous TLS performs key exchange without server authentication, enabling MITM attacks.`,
        fix: 'Remove anonymous cipher suites (aNULL, ADH, AECDH, DH-anon). ' +
          'Use authenticated suites that require server certificates. ' +
          'Example: tls.createServer({ ciphers: "ECDHE-RSA-AES256-GCM-SHA384:..." }).',
        via: 'structural',
      });
    }

    // Check for disabled certificate verification with key exchange
    if (KEY_EXCHANGE_RE.test(code) && NO_VERIFY_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'AUTH (certificate verification during key exchange)',
        severity: 'critical',
        description: `Key exchange at ${node.label} has certificate verification disabled. ` +
          `rejectUnauthorized=false or similar disables the entity authentication that prevents MITM attacks.`,
        fix: 'Enable certificate verification: set rejectUnauthorized: true, verify_mode: ssl.CERT_REQUIRED, ' +
          'InsecureSkipVerify: false. If using self-signed certs, configure the CA certificate explicitly.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-322', name: 'Key Exchange without Entity Authentication', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Crypto & Randomness Deep Dive CWEs (323–340)
// ---------------------------------------------------------------------------

/**
 * CWE-323: Reusing a Nonce, Key Pair in Encryption
 * Nonce reuse in stream ciphers (AES-GCM, ChaCha20-Poly1305, AES-CTR) is catastrophic:
 * XOR of two ciphertexts encrypted with the same nonce+key reveals XOR of plaintexts.
 * For AES-GCM specifically, nonce reuse also leaks the auth key, enabling forgery.
 */
function verifyCWE323(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const STATIC_NONCE_RE = /(?:nonce|iv)\s*[:=]\s*(?:['"`][^'"`]+['"`]|(?:Buffer\.from|new Uint8Array)\s*\(\s*\[[\d,\s]+\])|(?:nonce|iv)\s*[:=]\s*(?:0x[0-9a-fA-F]+|\d+\b)|static\s+(?:final\s+)?byte\s*\[\]\s*(?:nonce|iv|IV)\s*=|const\s+(?:nonce|iv|IV)\s*=\s*(?:b['"]|bytes\(|bytearray\()/i;
  const STREAM_MODE_RE = /\b(?:gcm|GCM|ctr|CTR|chacha|ChaCha|salsa|Salsa|ofb|OFB|cfb|CFB)\b|aes-\d+-(?:gcm|ctr|ofb|cfb)|AES\/(?:GCM|CTR|OFB|CFB)|CryptoJS\.mode\.(?:CTR|CFB|OFB)/i;
  const COUNTER_RESET_RE = /(?:nonce|iv|counter)\s*=\s*(?:0|1)\b|(?:nonce|iv)Count(?:er)?\s*=\s*0|resetNonce|resetIv|resetCounter/i;
  const RANDOM_NONCE_RE = /(?:crypto\.randomBytes|randomBytes|getRandomValues|SecureRandom|os\.urandom|crypto\/rand|randomNonce|generateNonce|generateIv|randomIV)\s*\(/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!STREAM_MODE_RE.test(code)) continue;
    if (STATIC_NONCE_RE.test(code) && !RANDOM_NONCE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (unique random nonce per encryption operation)',
        severity: 'critical',
        description: `Static/hardcoded nonce used with stream cipher mode at ${node.label}. ` +
          `Reusing a nonce with the same key in GCM/CTR/ChaCha20 is catastrophic: it leaks XOR of plaintexts. ` +
          `In AES-GCM, nonce reuse also reveals the authentication key, enabling ciphertext forgery.`,
        fix: 'Generate a fresh random nonce for every encryption: crypto.randomBytes(12) for GCM, ' +
          'crypto.randomBytes(16) for CTR. Never store nonces as constants. For deterministic nonces, use AES-GCM-SIV.',
        via: 'structural',
      });
    }
    if (COUNTER_RESET_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (nonce counter must be monotonically increasing, never reset)',
        severity: 'critical',
        description: `Nonce/IV counter reset at ${node.label}. Resetting a counter-based nonce guarantees nonce reuse ` +
          `with the same key, destroying stream cipher security.`,
        fix: 'Use random nonces instead of counters. If counters are required, persist them across restarts. ' +
          'Better: use AES-GCM-SIV which is nonce-misuse resistant.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-323', name: 'Reusing a Nonce, Key Pair in Encryption', holds: findings.length === 0, findings };
}

/**
 * CWE-324: Use of a Key Past its Expiration Date
 * Detects crypto keys used without expiration checks, hardcoded keys with no rotation,
 * and patterns that skip key expiry validation.
 */
function verifyCWE324(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SKIP_EXPIRY_RE = /(?:ignore|skip|disable|bypass)(?:Key)?(?:Expir(?:y|ation)|Validity)|(?:checkExpir(?:y|ation)|validateExpir(?:y|ation))\s*[:=]\s*false|notAfter\s*[:=]\s*null|(?:key|cert)(?:Expir(?:y|ation))\s*[:=]\s*(?:Infinity|null|false|0)|maxAge\s*[:=]\s*(?:Infinity|0)/i;
  const HARDCODED_KEY_RE = /(?:secret|key|apiKey|api_key|signing_key|encryption_key|private_key)\s*[:=]\s*['"][A-Za-z0-9+/=_-]{16,}['"]/i;
  const KEY_ROTATION_RE = /\b(?:rotateKey|keyRotat|refreshKey|renewKey|keyExpir|checkExpir|validateCert|verifyExpir|notAfter|validUntil|expiresAt|ttl|maxAge|keyAge|keyVersion|keyId)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SKIP_EXPIRY_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (key expiration validation)',
        severity: 'high',
        description: `Key expiration check disabled at ${node.label}. ` +
          `Using expired keys allows more time for cryptanalysis and means compromised keys remain in use indefinitely.`,
        fix: 'Always validate key expiration. Set key TTLs (90 days for signing, 1 year for encryption). ' +
          'Implement automated rotation. Never disable expiry checks.',
        via: 'structural',
      });
    }
    if (HARDCODED_KEY_RE.test(code) && !KEY_ROTATION_RE.test(code)) {
      const siblings = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      const hasRotation = siblings.some(n => KEY_ROTATION_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      if (!hasRotation) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (key rotation mechanism with expiry)',
          severity: 'high',
          description: `Hardcoded cryptographic key at ${node.label} with no rotation or expiry mechanism. ` +
            `Keys that never expire accumulate risk: more ciphertext for cryptanalysis, longer exposure if compromised.`,
          fix: 'Store keys in a KMS (AWS KMS, Vault, Azure Key Vault). Set expiration dates. ' +
            'Implement automated rotation. Version keys so old ciphertext can be re-encrypted.',
          via: 'scope_taint',
        });
      }
    }
  }
  return { cwe: 'CWE-324', name: 'Use of a Key Past its Expiration Date', holds: findings.length === 0, findings };
}

/**
 * CWE-325: Missing Cryptographic Step
 * Detects encryption without authentication (CBC without HMAC), and password
 * hashing without salting. The core issue: a crypto protocol is incomplete.
 */
function verifyCWE325(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const UNAUTHENTICATED_MODE_RE = /\b(?:aes-(?:128|192|256)-(?:cbc|ctr|cfb|ofb))\b|AES\/(?:CBC|CTR|CFB|OFB)\/|CryptoJS\.(?:AES|mode\.CBC|mode\.CTR)|createCipher(?:iv)?\s*\(\s*['"](?:aes|des)/i;
  const AUTHENTICATED_MODE_RE = /\b(?:aes-(?:128|192|256)-gcm|chacha20-poly1305)\b|AES\/GCM\/|\.(?:createHmac|createVerify)\b|\bhmac\b.*\bverify\b|\btimingSafeEqual\b|authenticated[_-]?encrypt|AEAD|encrypt[_-]?then[_-]?mac|GCM|Poly1305|SIV/i;
  const BARE_HASH_RE = /(?:createHash|MessageDigest\.getInstance|hashlib\.(?:md5|sha1|sha256|sha512)|Digest::(?:MD5|SHA1|SHA256|SHA512)|hash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]\s*\))\s*[.(]/i;
  const PASSWORD_CTX_RE = /\b(?:password|passwd|pass_?word|user_?pass|credential|pwd)\b/i;
  const SALTED_HASH_RE = /\b(?:bcrypt|scrypt|argon2|pbkdf2|PBKDF2|password_hash|passlib)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (UNAUTHENTICATED_MODE_RE.test(code) && !AUTHENTICATED_MODE_RE.test(code)) {
      const siblings = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      const hasAuth = siblings.some(n => AUTHENTICATED_MODE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      if (!hasAuth) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (authenticated encryption — encrypt-then-MAC or AEAD)',
          severity: 'high',
          description: `Encryption without authentication at ${node.label}. ` +
            `CBC/CTR without HMAC allows bit-flipping (padding oracle, ciphertext malleability).`,
          fix: 'Use AES-GCM or ChaCha20-Poly1305. If CBC is required, apply encrypt-then-MAC: ' +
            'encrypt first, HMAC the ciphertext, verify HMAC before decrypting.',
          via: 'scope_taint',
        });
      }
    }
    if (PASSWORD_CTX_RE.test(code) && BARE_HASH_RE.test(code) && !SALTED_HASH_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (salted password hashing — bcrypt/argon2/scrypt)',
        severity: 'critical',
        description: `Unsalted password hash at ${node.label}. ` +
          `Raw SHA/MD5 for passwords enables rainbow table attacks. Even salted fast hashes are brutable.`,
        fix: 'Use bcrypt, argon2id, or scrypt. These include built-in salting and work factors. ' +
          'Never use SHA-256/MD5 for passwords.',
        via: 'structural',
      });
    }
    // Detect KeyGenerator.getInstance() without .init() before .generateKey()
    // The Juliet pattern: KeyGenerator.getInstance("AES") followed by generateKey() without init()
    const KEY_GEN_RE = /KeyGenerator\.getInstance\s*\(/;
    const KEY_GEN_INIT_RE = /\.init\s*\(\s*\d/;
    const KEY_GEN_GENERATE_RE = /\.generateKey\s*\(/;
    if (KEY_GEN_RE.test(code) && KEY_GEN_GENERATE_RE.test(code) && !KEY_GEN_INIT_RE.test(code)) {
      // Check sibling nodes in same scope for init() call
      const siblings = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      const hasInit = siblings.some(n => KEY_GEN_INIT_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      if (!hasInit) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (KeyGenerator.init() — explicit key size initialization)',
          severity: 'high',
          description: `KeyGenerator used without explicit init() at ${node.label}. ` +
            `Without init(), the crypto provider chooses a default key size which may be insufficient ` +
            `and causes interoperability issues across providers.`,
          fix: 'Call KeyGenerator.init(keySize) before generateKey(). For AES, use init(256) for maximum security. ' +
            'Always explicitly specify key size rather than relying on provider defaults.',
          via: 'scope_taint',
        });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Source-line scanner fallback: KeyGenerator.getInstance() without .init()
  // The node walk above can miss this when getInstance(), init(), and generateKey()
  // land in separate nodes or the code_snapshot is truncated. This scans the raw
  // source to track variable assignments and method-call ordering.
  //
  // Scope-aware: we split the source into method-level scopes (delimited by
  // brace depth returning to the method entry level) so that the same variable
  // name in different methods (bad() vs good1()) is tracked independently.
  // ---------------------------------------------------------------------------
  if (findings.length === 0 && map.source_code) {
    const src325 = stripComments(map.source_code);
    const lines325 = src325.split('\n');

    // Split into scope regions by tracking brace depth.
    // Each "scope" is a contiguous range of lines within a method body.
    type KGInstance = { varName: string; getInstanceLine: number; hasInit: boolean; generateKeyLine: number | null };
    const kgInstances: KGInstance[] = [];
    let currentScope: KGInstance[] = [];
    let braceDepth = 0;
    let inMethodBody = false;

    for (let i = 0; i < lines325.length; i++) {
      const line = lines325[i];
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

      // Track brace depth to detect method boundaries
      for (const ch of line) {
        if (ch === '{') braceDepth++;
        if (ch === '}') braceDepth--;
      }

      // Detect method entry (brace depth increases past 1 = class body)
      if (!inMethodBody && braceDepth >= 2) {
        inMethodBody = true;
        currentScope = [];
      }

      // Match: KeyGenerator <var> = KeyGenerator.getInstance(...)
      const getInstMatch = line.match(/(\w+)\s*=\s*KeyGenerator\.getInstance\s*\(/);
      if (getInstMatch && inMethodBody) {
        // Start tracking a new KG instance in this scope
        currentScope.push({ varName: getInstMatch[1], getInstanceLine: i + 1, hasInit: false, generateKeyLine: null });
      }

      // Match: <var>.init(<number>)
      const initMatch = line.match(/(\w+)\.init\s*\(\s*\d/);
      if (initMatch && inMethodBody) {
        // Mark all instances in current scope with this var name
        for (const inst of currentScope) {
          if (inst.varName === initMatch[1]) inst.hasInit = true;
        }
      }

      // Match: <var>.generateKey()
      const genMatch = line.match(/(\w+)\.generateKey\s*\(/);
      if (genMatch && inMethodBody) {
        for (const inst of currentScope) {
          if (inst.varName === genMatch[1] && inst.generateKeyLine === null) {
            inst.generateKeyLine = i + 1;
          }
        }
      }

      // Method exit: brace depth drops back to class level (1)
      if (inMethodBody && braceDepth <= 1) {
        inMethodBody = false;
        kgInstances.push(...currentScope);
        currentScope = [];
      }
    }
    // Flush any remaining scope
    kgInstances.push(...currentScope);

    for (const inst of kgInstances) {
      if (inst.generateKeyLine && !inst.hasInit) {
        const nearNode = findNearestNode(map, inst.getInstanceLine) || map.nodes[0];
        if (nearNode) {
          findings.push({
            source: nodeRef(nearNode), sink: nodeRef(nearNode),
            missing: 'TRANSFORM (KeyGenerator.init() — explicit key size initialization)',
            severity: 'high',
            description: `L${inst.getInstanceLine}: KeyGenerator '${inst.varName}' created via getInstance() and used ` +
              `at L${inst.generateKeyLine} (generateKey()) without calling .init(keySize). ` +
              `The crypto provider will choose a default key size which may be insufficient and non-portable.`,
            fix: 'Call ' + inst.varName + '.init(256) (for AES) between getInstance() and generateKey(). ' +
              'Always explicitly specify key size rather than relying on provider defaults.',
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-325', name: 'Missing Cryptographic Step', holds: findings.length === 0, findings };
}

/**
 * CWE-326: Inadequate Encryption Strength
 * Detects insufficient key sizes: RSA < 2048, ECC < 256 bits, DH < 2048,
 * and deprecated TLS versions.
 */
function verifyCWE326(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SHORT_RSA_RE = /(?:generateKeyPair|generateKey|RSA|rsa)\s*[,(]\s*(?:['"]rsa['"][,\s]*)?(?:(?:modulusLength|bits|keySize|key_size)\s*[:=]\s*)?(?:512|768|1024)\b/i;
  const SHORT_DH_RE = /(?:createDiffieHellman|DiffieHellman|DHParameterSpec)\s*\(\s*(?:512|768|1024)\b/i;
  const WEAK_ECC_RE = /\b(?:secp(?:112|128|160)|prime(?:192|128)|sect(?:113|131|163)|brainpoolP(?:160|192))\b/i;
  const WEAK_TLS_RE = /\b(?:SSLv2|SSLv3|TLSv1(?:\.0)?|TLS_1_0|TLS10|TLSv1\.1|TLS_1_1|TLS11)\b|(?:minVersion|min_version|ssl_version)\s*[:=]\s*['"]?(?:SSLv|TLSv?1(?:\.?[01])?)\b/i;
  const STRONG_KEY_RE = /(?:modulusLength|bits|keySize|key_size)\s*[:=]\s*(?:2048|3072|4096|256|384|521)\b|secp(?:256k1|384r1|521r1)|prime256v1|ed25519|curve25519|P-256|P-384|P-521/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SHORT_RSA_RE.test(code) && !STRONG_KEY_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (adequate key size — RSA >= 2048 bits)',
        severity: 'high',
        description: `Inadequate RSA key size at ${node.label}. RSA-1024 is factored; RSA-512/768 are trivially breakable. NIST requires >= 2048.`,
        fix: 'Use RSA-2048 minimum (RSA-4096 preferred). For new systems, prefer ECC (P-256/Ed25519).',
        via: 'structural',
      });
    }
    if (SHORT_DH_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (adequate DH group — >= 2048 bits)',
        severity: 'high',
        description: `Weak Diffie-Hellman parameters at ${node.label}. DH-1024 is vulnerable to Logjam precomputation.`,
        fix: 'Use DH-2048 minimum, or ECDH with Curve25519/P-256.',
        via: 'structural',
      });
    }
    if (WEAK_ECC_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (adequate ECC curve — >= 256 bits)',
        severity: 'high',
        description: `Weak elliptic curve at ${node.label}. Curves below 256 bits lack adequate security margins.`,
        fix: 'Use P-256, P-384, P-521, Curve25519, or Ed25519.',
        via: 'structural',
      });
    }
    if (WEAK_TLS_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (modern TLS 1.2+)',
        severity: 'high',
        description: `Deprecated TLS at ${node.label}. SSLv2/v3 have POODLE, TLS 1.0 has BEAST, TLS 1.1 is deprecated.`,
        fix: 'Set minimum TLS to 1.2 (1.3 preferred). Node.js: minVersion:"TLSv1.2". Java: SSLContext.getInstance("TLSv1.3").',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-326', name: 'Inadequate Encryption Strength', holds: findings.length === 0, findings };
}

/**
 * CWE-329: Generation of Predictable IV with CBC Mode
 * CBC requires unpredictable IVs (not just unique). Predictable IV enables
 * chosen-plaintext attacks (BEAST). Distinct from CWE-323 (nonce reuse).
 */
function verifyCWE329(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CBC_RE = /\b(?:aes-(?:128|192|256)-cbc|des-cbc|des-ede3-cbc)\b|AES\/CBC\/|DES\/CBC\/|CryptoJS\.(?:AES|mode\.CBC)|createCipher(?:iv)?\s*\(\s*['"](?:aes|des).*cbc/i;
  const PREDICTABLE_IV_RE = /iv\s*[:=]\s*(?:['"`][^'"`]*['"`]|(?:Buffer\.from|new Uint8Array)\s*\(\s*\[[\d,\s]+\]|\bBuffer\.alloc\s*\(\s*16\s*\))|iv\s*[:=]\s*(?:0x[0-9a-fA-F]+|new\s+byte\s*\[\s*16\s*\])|iv\s*[:=]\s*(?:Date\.now|timestamp|counter|nonce\+\+|lastIv)|(?:iv|IV)\s*=\s*b['"][^'"]+['"]/i;
  const ZERO_IV_RE = /Buffer\.alloc\s*\(\s*16\s*\)|new\s+byte\s*\[\s*16\s*\]|(?:iv|IV)\s*[:=]\s*(?:b?['"]\\x00|(?:\[0,\s*0|new\s+Uint8Array\(\s*16\s*\)))/i;
  const RANDOM_IV_RE = /(?:crypto\.randomBytes|randomBytes|getRandomValues|SecureRandom|os\.urandom|crypto\/rand|randomIV|generateIV|randomIv|generateIv)\s*\(/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!CBC_RE.test(code)) continue;
    if (ZERO_IV_RE.test(code) && !RANDOM_IV_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (cryptographically random IV for CBC)',
        severity: 'high',
        description: `Zero/empty IV with CBC at ${node.label}. A zero IV makes the first block equivalent to ECB, ` +
          `leaking whether two messages share the same prefix.`,
        fix: 'Generate random IV per encryption: crypto.randomBytes(16). Prepend IV to ciphertext. ' +
          'Better: switch to AES-GCM.',
        via: 'structural',
      });
    } else if (PREDICTABLE_IV_RE.test(code) && !RANDOM_IV_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (unpredictable IV — CBC requires random IVs, not just unique)',
        severity: 'high',
        description: `Predictable IV with CBC at ${node.label}. Unlike CTR (unique suffices), CBC requires unpredictable IVs. ` +
          `The BEAST attack exploited exactly this distinction.`,
        fix: 'Use crypto.randomBytes(16) for CBC IVs. Do NOT use counters, timestamps, or previous ciphertext blocks. ' +
          'Recommended: migrate to AES-GCM.',
        via: 'structural',
      });
    }
  }
  // Strategy B: Java-specific cipher patterns
  // Detects: Cipher.getInstance("DES/...") or Cipher.getInstance("DESede/ECB/...")
  // or cryptoAlg1 property (which resolves to DES/ECB/PKCS5Padding)
  // Also detects ECB mode usage which doesn't use any IV.
  {
    const WEAK_CIPHER_LITERAL = /Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC4|RC2|Blowfish)(?:\/|\s*["'])/i;
    const ECB_MODE = /Cipher\.getInstance\s*\(\s*["'][^"']*ECB[^"']*["']/i;
    const CRYPTO_ALG_PROPERTY = /\bgetProperty\s*\(\s*["']cryptoAlg1["']/i;
    const reported329 = new Set<string>(findings.map(f => f.sink.id));

    for (const node of map.nodes) {
      if (reported329.has(node.id)) continue;
      const snap = node.analysis_snapshot || node.code_snapshot;
      if (WEAK_CIPHER_LITERAL.test(snap) || ECB_MODE.test(snap) || CRYPTO_ALG_PROPERTY.test(snap)) {
        reported329.add(node.id);
        const isECB = ECB_MODE.test(snap) || CRYPTO_ALG_PROPERTY.test(snap);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: isECB
            ? 'TRANSFORM (do not use ECB mode -- use CBC with random IV or GCM)'
            : 'TRANSFORM (use strong cipher with random IV -- not DES/RC4)',
          severity: 'high',
          description: isECB
            ? `${node.label} uses ECB mode which does not use an IV at all. ` +
              `ECB encrypts identical plaintext blocks to identical ciphertext blocks, leaking patterns.`
            : `${node.label} uses a weak cipher algorithm (DES/RC4/Blowfish). ` +
              `These have insufficient key lengths and known vulnerabilities.`,
          fix: 'Use AES-256-GCM or AES-256-CBC with a random IV generated from SecureRandom. ' +
            'Never use DES (56-bit key), RC4 (biased output), or ECB mode.',
          via: 'structural',
        });
      }
    }
  }

  // Strategy C: Juliet/NIST pattern -- hardcoded byte array used as IV via IvParameterSpec.
  // Catches: byte[] initializationVector = {0x00,...}; ... new IvParameterSpec(initializationVector);
  if (findings.length === 0 && map.source_code) {
    const src329 = map.source_code;
    const hasCBC329 = /AES\/CBC\/|DES\/CBC\/|Cipher\.getInstance\s*\(\s*["'][^"']*CBC[^"']*["']/i.test(src329);
    if (hasCBC329) {
      // Find hardcoded byte arrays and their positions
      const byteArrayRe329 = /byte\s*\[\s*\]\s+(\w+)\s*=\s*\{([^}]+)\}/g;
      let ba329: RegExpExecArray | null;
      const hardcodedIVEntries329: Array<{name: string; content: string; pos: number}> = [];
      while ((ba329 = byteArrayRe329.exec(src329)) !== null) {
        const vn329 = ba329[1];
        const ac329 = ba329[2].trim();
        const vals329 = ac329.split(',').map((v: string) => v.trim());
        const allHC329 = vals329.every((v: string) => /^0x[0-9a-fA-F]+$|^\d+$|^\(byte\)\s*0x[0-9a-fA-F]+$/.test(v));
        if (allHC329 && vals329.length >= 8) {
          hardcodedIVEntries329.push({name: vn329, content: ac329.slice(0, 60), pos: ba329.index});
        }
      }
      // Find all IvParameterSpec usages and their positions
      const ivSpecReG329 = /new\s+IvParameterSpec\s*\(\s*(\w+)\s*\)/g;
      let ivM329: RegExpExecArray | null;
      while ((ivM329 = ivSpecReG329.exec(src329)) !== null) {
        const ivVarName329 = ivM329[1];
        // Find matching hardcoded array entry
        const entry329 = hardcodedIVEntries329.find(e => e.name === ivVarName329);
        if (!entry329) continue;
        // Check for SecureRandom.nextBytes(var) only between the array decl and IvParameterSpec usage
        const scopeSlice329 = src329.slice(entry329.pos, ivM329.index + ivM329[0].length);
        const srFill329 = new RegExp('SecureRandom[^;]*\\.nextBytes\\s*\\(\\s*' + ivVarName329 + '\\s*\\)', 'i');
        if (!srFill329.test(scopeSlice329)) {
          findings.push({
            source: { id: 'src-hardcoded-iv', label: 'byte[] ' + ivVarName329 + ' = {' + entry329.content + '...}', line: 0, code: 'byte[] ' + ivVarName329 + ' = {' + entry329.content + '...}' },
            sink:   { id: 'sink-iv-param-spec', label: ivM329[0].trim(), line: 0, code: ivM329[0].trim() },
            missing: 'TRANSFORM (cryptographically random IV for CBC)',
            severity: 'high',
            description: 'Hardcoded byte array "' + ivVarName329 + '" is used as the IV in CBC mode via IvParameterSpec. ' +
              'A static IV makes the first block equivalent to ECB, leaking whether two messages share the same prefix.',
            fix: 'Generate a random IV per encryption using SecureRandom.nextBytes(). Prepend IV to ciphertext. ' +
              'Better: switch to AES-GCM which handles nonces more safely.',
            via: 'source_line_fallback',
          });
          break; // One finding is enough
        }
      }
    }
  }

  return { cwe: 'CWE-329', name: 'Generation of Predictable IV with CBC Mode', holds: findings.length === 0, findings };
}

/**
 * CWE-335: Incorrect Usage of Seeds in PRNG
 * Detects PRNGs seeded with inappropriate values: time-based, PIDs, constants.
 * The seed determines the entire output stream.
 */
function verifyCWE335(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const BAD_SEED_RE = /\b(?:srand|mt_srand|srandom|Random)\s*\(\s*(?:time\s*\(|Date\.now|System\.currentTimeMillis|System\.nanoTime|getpid|os\.getpid|Process\.pid|process\.pid|clock\s*\(|Environment\.TickCount|\d{1,10}\s*\))/i;
  const JAVA_SEED_RE = /new\s+Random\s*\(\s*(?:System\.currentTimeMillis\s*\(\)|System\.nanoTime\s*\(\)|seed|(?:0|1|42|12345|0x[0-9a-fA-F]+)\s*\))/i;
  const PY_SEED_RE = /random\.seed\s*\(\s*(?:time\.|os\.getpid|int\(|0|1|42|12345|None\s*\))/i;
  const GO_SEED_RE = /rand\.Seed\s*\(\s*(?:time\.Now|int64\(time)/i;
  const SAFE_SEED_RE = /\b(?:SecureRandom|crypto\.randomBytes|os\.urandom|crypto\/rand|getRandomValues|secrets\.)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const hasBadSeed = BAD_SEED_RE.test(code) || JAVA_SEED_RE.test(code) || PY_SEED_RE.test(code) || GO_SEED_RE.test(code);
    if (!hasBadSeed) continue;
    if (!SAFE_SEED_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EXTERNAL (cryptographically random seed, or use CSPRNG directly)',
        severity: 'high',
        description: `PRNG seeded with predictable value at ${node.label}. ` +
          `Time/PID seeds have low entropy (~32 bits for time, ~16 bits for PID). ` +
          `An attacker can enumerate all possible seeds and reproduce the output stream.`,
        fix: 'For security: use CSPRNG directly (crypto.randomBytes, SecureRandom, os.urandom). ' +
          'For non-security: seed from CSPRNG: new Random(SecureRandom.nextLong()).',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-335', name: 'Incorrect Usage of Seeds in PRNG', holds: findings.length === 0, findings };
}

/**
 * CWE-336: Same Seed in PRNG
 * Detects multiple PRNG instances initialized with the same hardcoded seed.
 * Same seed = same output stream = predictable values across instances.
 */
function verifyCWE336(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const HARDCODED_SEED_RE336 = /(?:new\s+Random|srand|mt_srand|random\.seed|rand\.Seed|Random\.new)\s*\(\s*(\d+)\s*\)/i;
  const seedMap336 = new Map<string, NeuralMapNode[]>();

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const match = code.match(HARDCODED_SEED_RE336);
    if (match) {
      const seedVal = match[1];
      if (!seedMap336.has(seedVal)) seedMap336.set(seedVal, []);
      seedMap336.get(seedVal)!.push(node);
    }
  }

  for (const [seedVal, nodes] of seedMap336) {
    if (nodes.length > 1) {
      for (const node of nodes) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(nodes.find(n => n.id !== node.id) || node),
          missing: 'TRANSFORM (unique seed per PRNG instance, or use CSPRNG)',
          severity: 'high',
          description: `Multiple PRNGs seeded with same value (${seedVal}) at ${node.label} and ${nodes.length - 1} other location(s). ` +
            `Identical seeds produce identical output streams.`,
          fix: 'Use CSPRNG (crypto.randomBytes, SecureRandom) for security. ' +
            'For non-security fast PRNGs, seed each instance from a CSPRNG.',
          via: 'structural',
        });
      }
    } else {
      const node = nodes[0];
      const isSec = /\b(token|session|csrf|nonce|secret|key|password|salt|auth|api[_-]?key)\b/i.test(
        node.label + ' ' + (node.analysis_snapshot || node.code_snapshot) + ' ' + node.node_subtype
      );
      if (isSec) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'EXTERNAL (CSPRNG instead of seeded PRNG in security context)',
          severity: 'high',
          description: `Hardcoded PRNG seed (${seedVal}) in security context at ${node.label}. ` +
            `The entire output sequence is deterministic and reproducible.`,
          fix: 'Replace with CSPRNG: crypto.randomBytes() (Node.js), SecureRandom (Java), secrets module (Python).',
          via: 'structural',
        });
      }
    }
  }
  // Strategy B: Code snapshot scan for weak PRNG usage (Java-specific)
  // Detects: new java.util.Random() (not SecureRandom), Math.random()
  // These produce predictable sequences unsuitable for security operations.
  {
    const WEAK_PRNG_336 = /\bnew\s+(?:java\.util\.)?Random\s*\(/i;
    const MATH_RANDOM_336 = /\b(?:java\.lang\.)?Math\.random\s*\(\s*\)/i;
    const SECURE_RANDOM_336 = /\bSecureRandom\b/i;
    const reported336 = new Set<string>(findings.map(f => f.sink.id));

    for (const node of map.nodes) {
      if (reported336.has(node.id)) continue;
      const snap = node.analysis_snapshot || node.code_snapshot;
      if ((WEAK_PRNG_336.test(snap) || MATH_RANDOM_336.test(snap)) && !SECURE_RANDOM_336.test(snap)) {
        reported336.add(node.id);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'EXTERNAL (use SecureRandom instead of java.util.Random/Math.random)',
          severity: 'high',
          description: `${node.label} uses a weak/predictable PRNG (java.util.Random or Math.random). ` +
            `These produce predictable sequences unsuitable for security-sensitive operations.`,
          fix: 'Use java.security.SecureRandom instead of java.util.Random. ' +
            'SecureRandom provides cryptographically strong random values.',
          via: 'structural',
        });
      }
    }
  }

  // Strategy C: SecureRandom.setSeed() with hardcoded/constant seed (Juliet CWE-336 pattern)
  // Detects: secureRandom.setSeed(CONSTANT) or secureRandom.setSeed(new byte[]{...})
  // A SecureRandom seeded with a constant produces the same output every run.
  {
    const SET_SEED_RE336 = /\.setSeed\s*\(/;
    const SECURE_RANDOM_INST_RE336 = /\bnew\s+SecureRandom\s*\(/;
    const reported336c = new Set<string>(findings.map(f => f.sink.id));

    for (const node of map.nodes) {
      if (reported336c.has(node.id)) continue;
      const snap = stripComments(node.analysis_snapshot || node.code_snapshot);
      // Must have setSeed in this node
      if (!SET_SEED_RE336.test(snap)) continue;
      // Check if SecureRandom exists anywhere in the file (may be in same or different node)
      const hasSecureRandom = SECURE_RANDOM_INST_RE336.test(snap) ||
        map.nodes.some(n => SECURE_RANDOM_INST_RE336.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      if (!hasSecureRandom) continue;
      // Extract the seed argument
      const seedArgMatch = snap.match(/\.setSeed\s*\(\s*([^)]+)\)/);
      if (seedArgMatch) {
        const seedArg = seedArgMatch[1].trim();
        // Safe seeds: SecureRandom.generateSeed(), crypto random bytes
        const isSafeSeed = /SecureRandom|generateSeed|randomBytes|urandom|crypto\.random/i.test(seedArg);
        if (!isSafeSeed) {
          reported336c.add(node.id);
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'TRANSFORM (do not seed SecureRandom with hardcoded/constant values)',
            severity: 'high',
            description: `${node.label} seeds SecureRandom with a hardcoded/constant value via setSeed(). ` +
              `This makes the PRNG output predictable and reproducible across runs.`,
            fix: 'Do not call setSeed() with hardcoded values on SecureRandom. ' +
              'Let SecureRandom self-seed from the OS entropy source, or use SecureRandom.generateSeed() if reseeding.',
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-336', name: 'Same Seed in PRNG', holds: findings.length === 0, findings };
}

/**
 * CWE-337: Predictable Seed in PRNG
 * Detects seeds derived from environment-discoverable values: hostname, IP,
 * filesystem metadata, XORed combinations of low-entropy sources.
 */
function verifyCWE337(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PREDICTABLE_SEED_RE337 = /(?:srand|mt_srand|random\.seed|rand\.Seed|new\s+Random)\s*\(\s*(?:.*(?:hostname|HOSTNAME|os\.hostname|ip[_-]?addr|getenv|process\.env|gethostname|socket\.gethostname|InetAddress\.getLocalHost|MAC|macAddress|uuid\.getNode|System\.getProperty|Runtime\.getRuntime|availableProcessors|freeMemory|totalMemory|hashCode))/i;
  const FS_SEED_RE337 = /(?:srand|mt_srand|random\.seed|rand\.Seed|new\s+Random)\s*\(\s*(?:.*(?:stat\.|mtime|ctime|inode|st_\w+|lastModified|File\.length))/i;
  const XOR_SEED_RE337 = /(?:srand|mt_srand|random\.seed|rand\.Seed|new\s+Random)\s*\(\s*(?:.*\^.*(?:time|pid|getpid|tid|Thread))/i;
  const SAFE_RE337 = /\b(?:SecureRandom|crypto\.randomBytes|os\.urandom|crypto\/rand|getRandomValues|secrets\.)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if ((PREDICTABLE_SEED_RE337.test(code) || FS_SEED_RE337.test(code) || XOR_SEED_RE337.test(code)) && !SAFE_RE337.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EXTERNAL (cryptographically unpredictable seed source)',
        severity: 'high',
        description: `PRNG seeded from predictable environment data at ${node.label}. ` +
          `Hostname, IP, PID, file metadata are all discoverable. XORing low-entropy values does NOT create high entropy.`,
        fix: 'Use CSPRNG directly (crypto.randomBytes, SecureRandom, os.urandom). ' +
          'If a fast PRNG is needed, seed from CSPRNG.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-337', name: 'Predictable Seed in PRNG', holds: findings.length === 0, findings };
}

/**
 * CWE-339: Small Seed Space in PRNG
 * Detects PRNGs seeded from small domains: 8/16-bit values, booleans,
 * truncated random values. Even CSPRNG-derived seeds are weak if tiny.
 */
function verifyCWE339(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SMALL_SEED_RE339 = /(?:srand|mt_srand|random\.seed|rand\.Seed|new\s+Random)\s*\(\s*(?:(?:rand|random)\s*\(\s*\)\s*%\s*(?:\d{1,4})\b|(?:Math\.random\s*\(\s*\)\s*\*\s*(?:\d{1,4}))|(?:getRandomInt|randomInt)\s*\(\s*(?:\d{1,4})\s*\))/i;
  const TRUNCATED_SEED_RE339 = /(?:\(byte\)|\.byteValue|& 0x[fF]{1,2}\b|% 256|& 255|\.charCodeAt|int8|uint8|int16|uint16)\s*(?:.*(?:seed|srand|Random))/i;
  const TRIVIAL_SEED_RE339 = /(?:srand|mt_srand|random\.seed|rand\.Seed|new\s+Random)\s*\(\s*(?:true|false|[01]|'.'|Math\.random\s*\(\)\s*>\s*0\.5)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SMALL_SEED_RE339.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (seed with >= 128 bits of entropy)',
        severity: 'high',
        description: `PRNG seeded from small value space at ${node.label}. ` +
          `< 2^16 seed values can be exhaustively searched in milliseconds.`,
        fix: 'Use >= 128 bits (16 bytes) of CSPRNG output as seed. Or use CSPRNG directly.',
        via: 'structural',
      });
    }
    if (TRUNCATED_SEED_RE339.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (full-width seed — do not truncate to byte/int16)',
        severity: 'medium',
        description: `PRNG seed truncated to small type at ${node.label}. ` +
          `Casting to byte/int8/int16 reduces seed space to 256-65536 values.`,
        fix: 'Use full-width seed (32+ bits minimum). For security: use CSPRNG instead.',
        via: 'structural',
      });
    }
    if (TRIVIAL_SEED_RE339.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (non-trivial seed with adequate entropy)',
        severity: 'high',
        description: `PRNG seeded with trivial value (boolean/0/1) at ${node.label}. Only 2-3 possible output streams.`,
        fix: 'Use CSPRNG for security contexts. For non-security: seed from system entropy.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-339', name: 'Small Seed Space in PRNG', holds: findings.length === 0, findings };
}

/**
 * CWE-340: Generation of Predictable Numbers or Identifiers
 * Detects predictable ID generation: sequential IDs exposed externally,
 * timestamp-based tokens, UUIDv1, and hashes of predictable inputs.
 */
function verifyCWE340(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SEQUENTIAL_ID_RE340 = /\b(?:autoIncrement|AUTO_INCREMENT|SERIAL|IDENTITY|nextval|sequence\.next|\.incrementAndGet|AtomicInteger|AtomicLong|counter\+\+|(?:id|orderId|userId|token)\s*[:=]\s*(?:count|index|seq|num)\s*\+\+)/i;
  const TIMESTAMP_ID_RE340 = /(?:token|id|session|key|ref|nonce|ticket)\s*[:=]\s*(?:Date\.now|System\.currentTimeMillis|time\.time|Time\.now|time\(\)|DateTime\.UtcNow\.Ticks|System\.nanoTime)/i;
  const UUIDV1_RE340 = /\buuid\.v1\s*\(|\buuidv1\s*\(|\buuid1\s*\(|\bUUID\.fromTime|\bTimeUUID\b/i;
  const PREDICTABLE_HASH_ID_RE340 = /(?:md5|sha1|sha256)\s*\(\s*(?:.*(?:email|username|user_?id|timestamp|Date\.now|counter))/i;
  const SAFE_ID_RE340 = /\buuid\.v4\s*\(|\buuidv4\s*\(|\bcrypto\.randomUUID\b|\bnanoid\b|\bcuid\b|\bulid\b|\bcrypto\.randomBytes\b|\bSecureRandom\b|\bsecrets\.token/i;
  const EXTERNAL_CTX_RE340 = /\b(?:token|session|api[_-]?key|access[_-]?token|reset|confirm|invite|verification|ref(?:erence)?[_-]?(?:id|code|num)|order[_-]?id|booking|ticket|slug)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const combinedCtx = node.label + ' ' + node.node_subtype + ' ' + code;
    const isExternal = EXTERNAL_CTX_RE340.test(combinedCtx) ||
      node.node_type === 'EGRESS' || node.node_type === 'INGRESS' ||
      node.attack_surface.some(s => /external|public|user/i.test(s));
    if (!isExternal) continue;

    if (SEQUENTIAL_ID_RE340.test(code) && !SAFE_ID_RE340.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (unpredictable identifier — UUIDv4/nanoid/CSPRNG)',
        severity: 'medium',
        description: `Sequential/auto-increment ID exposed externally at ${node.label}. ` +
          `Attackers enumerate valid IDs by incrementing, enabling IDOR attacks.`,
        fix: 'Use UUIDv4, nanoid, or CUID for external identifiers. Keep auto-increment as internal PKs only.',
        via: 'structural',
      });
    }
    if (TIMESTAMP_ID_RE340.test(code) && !SAFE_ID_RE340.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (unpredictable identifier, not timestamp-derived)',
        severity: 'high',
        description: `Timestamp-based identifier at ${node.label}. Guessable to millisecond precision, ` +
          `enabling enumeration in the creation time window.`,
        fix: 'Use crypto.randomUUID() or crypto.randomBytes(16).toString("hex").',
        via: 'structural',
      });
    }
    if (UUIDV1_RE340.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (UUIDv4 instead of UUIDv1)',
        severity: 'medium',
        description: `UUIDv1 at ${node.label} embeds MAC address and timestamp, leaking server identity. Adjacent UUIDs are sequential.`,
        fix: 'Use UUIDv4. Node.js: crypto.randomUUID(). Python: uuid.uuid4(). Java: UUID.randomUUID().',
        via: 'structural',
      });
    }
    if (PREDICTABLE_HASH_ID_RE340.test(code) && !SAFE_ID_RE340.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (CSPRNG-based ID, not hash of predictable inputs)',
        severity: 'medium',
        description: `ID derived from hash of predictable inputs at ${node.label}. Anyone with the inputs can reproduce it.`,
        fix: 'Generate IDs from CSPRNG output. If deterministic (dedup), add server-side secret (HMAC).',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-340', name: 'Generation of Predictable Numbers or Identifiers', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Crypto & Hash Registry
// ---------------------------------------------------------------------------

export const CRYPTO_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Weak hash & broken crypto algorithms
  'CWE-261': verifyCWE261,
  'CWE-311': verifyCWE311,
  'CWE-317': verifyCWE317,
  'CWE-318': verifyCWE318,
  'CWE-321': verifyCWE321,
  'CWE-322': verifyCWE322,
  'CWE-323': verifyCWE323,
  'CWE-324': verifyCWE324,
  'CWE-325': verifyCWE325,
  'CWE-326': verifyCWE326,
  'CWE-327': verifyCWE327,
  'CWE-328': verifyCWE328,
  'CWE-329': verifyCWE329,
  'CWE-330': verifyCWE330,
  'CWE-331': verifyCWE331,
  // PRNG & randomness CWEs
  'CWE-335': verifyCWE335,
  'CWE-336': verifyCWE336,
  'CWE-337': verifyCWE337,
  'CWE-338': verifyCWE338,
  'CWE-339': verifyCWE339,
  'CWE-340': verifyCWE340,
  // Signature & integrity verification
  'CWE-347': verifyCWE347,
  'CWE-354': verifyCWE354,
  // TLS / algorithm negotiation
  'CWE-757': verifyCWE757,
  // Unsalted & weak password hashing
  'CWE-759': verifyCWE759,
  'CWE-760': verifyCWE760,
  'CWE-780': verifyCWE780,
  'CWE-916': verifyCWE916,
};
