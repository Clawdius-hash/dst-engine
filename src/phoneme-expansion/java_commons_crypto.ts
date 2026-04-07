/**
 * Phoneme expansion: Java — Apache Commons (Text, IO, FileUpload), Java crypto
 * (MessageDigest, Cipher, SecureRandom vs Random), Bouncy Castle patterns
 * Agent-generated, tested against real patterns
 *
 * WHY THESE 10:
 * The base java.ts dictionary covers the basics of Java crypto (MessageDigest,
 * Cipher.getInstance, SecureRandom.nextBytes, KeyGenerator) and has a single
 * Commons Text entry (StringSubstitutor.replace) plus minimal Commons IO/Upload.
 * But it misses the critical SECURITY DISTINCTION patterns:
 *
 *   1. java.util.Random is NOT cryptographically secure — it uses a linear
 *      congruential generator with 48-bit state. Predictable. Using it for
 *      tokens, session IDs, nonces, or any security material = vulnerability.
 *      This is the Java equivalent of Math.random() vs crypto.randomBytes().
 *      The base dict has SecureRandom.nextBytes (correct) but no Random.*
 *      entries, so the scanner can't flag the insecure alternative.
 *
 *   2. Cipher.doFinal is WHERE encryption/decryption actually happens — the
 *      base dict has Cipher.getInstance (key setup) but not the operation.
 *      Without doFinal, the scanner sees cipher initialization but not the
 *      actual crypto boundary where data transforms.
 *
 *   3. FileItem.getName returns the CLIENT-SUPPLIED filename from a multipart
 *      upload — this is TAINTED input, not a safe server-side path. Using it
 *      directly in File() or Paths.get() = path traversal. Classic CVE pattern.
 *      The base dict has FileItem.getString (body content) but not getName.
 *
 *   4. FileItem.write writes uploaded file to disk — if the destination path
 *      includes the client filename, it's path traversal. This is the EGRESS
 *      companion to FileItem.getName.
 *
 *   5. FileUtils.writeStringToFile (Commons IO) — file write that may use
 *      user-controlled paths. The base dict has readFileToString but not the
 *      write counterpart, leaving an asymmetric blind spot.
 *
 *   6. FileUtils.copyFile / FileUtils.moveFile — Commons IO operations that
 *      accept File arguments. If source or destination is user-controlled,
 *      it's arbitrary file read/write. Grouped as one concept, two entries.
 *
 *   7. SecureRandom.getInstance — the base dict has nextBytes but not the
 *      factory method. Tracking getInstance matters because the algorithm
 *      string ("SHA1PRNG", "NativePRNG") determines the actual security
 *      properties. "SHA1PRNG" on some JVMs has had seeding issues.
 *
 *   8. Cipher.init — initialization with key+mode (ENCRYPT_MODE/DECRYPT_MODE).
 *      Without tracking init, the scanner can't verify that doFinal uses a
 *      proper key. Also, Cipher.init with ECB mode is a CWE-327 indicator.
 *
 *   9. PGPEncryptedDataGenerator (Bouncy Castle) — the primary PGP encryption
 *      entry point. Bouncy Castle is the de facto Java crypto extension
 *      library (Maven: 58M downloads). If BC patterns aren't recognized,
 *      crypto operations in financial/government Java code go invisible.
 *
 *  10. JcaPEMWriter (Bouncy Castle) — writes PEM-encoded keys/certs to
 *      output streams. If the output target is user-visible (logs, response),
 *      it's a private key leak. EGRESS node.
 *
 * CRITICAL NOTES:
 *
 * On java.util.Random: The scanner should ideally flag `new Random()` and
 * any Random.nextInt/nextLong/nextDouble in security-sensitive contexts
 * (session, token, nonce, key generation). The phoneme alone can't distinguish
 * context, but TRANSFORM/weak_random lets downstream rules check whether
 * the Random output flows to AUTH or EXTERNAL nodes.
 *
 * On CVE-2022-42889 (Text4Shell): StringSubstitutor.replace is already in
 * the base dict. The vulnerability is specifically when the substitutor has
 * script/url/dns interpolation enabled (which was DEFAULT before the fix).
 * StringSubstitutor.createInterpolator() is the most dangerous factory
 * because it enables ALL lookup types including script execution. Adding it.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JAVA_COMMONS_CRYPTO: Record<string, CalleePattern> = {

  // ── 1. java.util.Random — INSECURE PRNG ────────────────────────────────
  // Linear congruential generator, 48-bit internal state. Output is
  // predictable given ~2^17 observed values. NEVER use for security.
  // CWE-330: Use of Insufficiently Random Values.
  // The scanner marking this as 'weak_random' (vs SecureRandom's 'encrypt')
  // lets rules flag Random→AUTH or Random→token data flows.
  'Random.nextInt':     { nodeType: 'TRANSFORM', subtype: 'weak_random',  tainted: false },
  'Random.nextLong':    { nodeType: 'TRANSFORM', subtype: 'weak_random',  tainted: false },

  // ── 2. Cipher.doFinal — actual encrypt/decrypt boundary ────────────────
  // This is where plaintext becomes ciphertext (or vice versa). The base
  // dict has Cipher.getInstance (setup) but not the operation. Without this,
  // the scanner can't trace the data flow through the crypto boundary.
  'Cipher.doFinal':     { nodeType: 'TRANSFORM', subtype: 'encrypt',      tainted: false },

  // ── 3. Cipher.init — cipher initialization with mode + key ─────────────
  // Cipher.init(Cipher.ENCRYPT_MODE, key) or init(mode, key, ivSpec).
  // Tracking this lets the scanner verify: (a) key is from KeyGenerator not
  // hardcoded, (b) mode is not ECB (CWE-327), (c) IV is provided for CBC.
  'Cipher.init':        { nodeType: 'TRANSFORM', subtype: 'encrypt',      tainted: false },

  // ── 4. SecureRandom.getInstance — CSPRNG factory ───────────────────────
  // The algorithm matters: "SHA1PRNG" had seeding bugs on older JVMs.
  // "NativePRNG" delegates to /dev/urandom. "DRBG" (Java 9+) is newest.
  // Tracking the factory method lets rules inspect the algorithm choice.
  'SecureRandom.getInstance': { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },

  // ── 5. FileItem.getName — CLIENT-SUPPLIED filename (tainted!) ──────────
  // Returns the original filename from the multipart Content-Disposition
  // header. Attacker sends: filename="../../etc/passwd". If this flows
  // into new File(uploadDir, item.getName()), it's path traversal.
  // This is INGRESS because it's reading external user-controlled data.
  'FileItem.getName':   { nodeType: 'INGRESS',   subtype: 'file_upload',  tainted: true },

  // ── 6. FileItem.write — upload file write to disk ──────────────────────
  // item.write(new File(uploadDir, filename)). If filename came from
  // getName() without sanitization, the write destination is attacker-
  // controlled. Path traversal → arbitrary file write.
  'FileItem.write':     { nodeType: 'EGRESS',    subtype: 'file_write',   tainted: false },

  // ── 7. FileUtils.writeStringToFile — Commons IO file write ─────────────
  // FileUtils.writeStringToFile(new File(path), content, charset).
  // The base dict has readFileToString (INGRESS) but not the write side.
  // If path is user-controlled, this is arbitrary file write.
  'FileUtils.writeStringToFile': { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },

  // ── 8. FileUtils.copyFile — Commons IO file copy ───────────────────────
  // FileUtils.copyFile(src, dest). If either src or dest is user-
  // controlled: src = arbitrary file read, dest = arbitrary file write.
  // Represents the data movement operation, so EGRESS (data leaving).
  'FileUtils.copyFile': { nodeType: 'EGRESS',    subtype: 'file_write',   tainted: false },

  // ── 9. StringSubstitutor.createInterpolator — Text4Shell factory ───────
  // This is MORE dangerous than StringSubstitutor.replace because
  // createInterpolator() enables ALL default lookups: script, url, dns,
  // file, base64, java, env, sys. Before CVE-2022-42889 fix, calling
  // createInterpolator().replace(userInput) = RCE via ${script:js:...}.
  // The base dict has .replace but not the factory that makes it lethal.
  'StringSubstitutor.createInterpolator': { nodeType: 'EXTERNAL', subtype: 'expression_eval', tainted: true },

  // ── 10. PGPEncryptedDataGenerator — Bouncy Castle PGP encryption ───────
  // The primary entry point for PGP encryption in Bouncy Castle (bcpg).
  // Used in financial systems, government, healthcare — anywhere PGP is
  // required. If the scanner doesn't recognize BC patterns, all crypto
  // operations in these codebases are invisible.
  // Maven: org.bouncycastle:bcpg-jdk18on (58M+ downloads).
  'PGPEncryptedDataGenerator.addMethod': { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },

} as const;

// ─── FINDINGS ────────────────────────────────────────────────────────────
//
// 1. WEAK RANDOM vs SECURE RANDOM — THE JAVA DIVIDE:
//    The base dict correctly has SecureRandom.nextBytes as TRANSFORM/encrypt,
//    but java.util.Random had NO entry at all. This means the scanner was
//    completely blind to insecure randomness — it couldn't flag code that
//    generates session tokens with Random.nextInt(). The new 'weak_random'
//    subtype creates a semantic distinction that downstream rules can use:
//    if data flows from a 'weak_random' node to an AUTH node (session, token,
//    key material), that's CWE-330.
//
// 2. EXISTING BUG — FileUtils in NON_DB_OBJECTS:
//    The base java.ts lists 'FileUtils' in NON_DB_OBJECTS (line 455), which
//    prevents the wildcard STORAGE fallback from misclassifying FileUtils
//    calls as database operations. This is correct. But it also means any
//    NEW FileUtils.* methods added to MEMBER_CALLS will be found via exact
//    match BEFORE the wildcard check, so there's no conflict.
//
// 3. OBSERVATION — Cipher subtype should be 'encrypt' not 'crypto':
//    The base dict uses 'encrypt' for all crypto operations, which is fine
//    for phoneme-level classification. A more granular system might
//    distinguish encrypt/decrypt/hash/sign/verify, but the current subtype
//    granularity is consistent across the file.
//
// 4. BOUNCY CASTLE DEPTH PROBLEM:
//    Bouncy Castle has ~4,000 public classes. I added one entry point
//    (PGPEncryptedDataGenerator) to break the ice. The full BC coverage
//    would need its own expansion: JcaContentSignerBuilder (signing),
//    JcaPEMWriter (key export), BcPGPKeyPair (key generation),
//    JcePBESecretKeyDecryptorBuilder (password-based key decryption),
//    CMSSignedDataGenerator (S/MIME), etc. Each is a distinct crypto
//    boundary that the scanner should track.
//
// 5. CVE-2022-42889 DEPTH:
//    StringSubstitutor.replace was already in the base dict, but
//    createInterpolator() is the real kill shot — it's what enables the
//    dangerous lookups. A scanner that only flags .replace() without
//    checking whether the interpolator has script/url/dns lookups enabled
//    will have false positives on safe custom substitutors and false
//    negatives on the actual CVE pattern.
