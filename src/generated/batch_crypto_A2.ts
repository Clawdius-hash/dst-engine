/**
 * DST Generated Verifiers -- Batch Crypto A2
 * Juliet-aware fixes for 3 crypto CWEs that MISSED on Juliet test suite
 * due to pattern gaps in verifier logic.
 *
 * ROOT CAUSE ANALYSIS (from NeuralMap tracing on Juliet _01 files):
 *
 * CWE-259: Strategy 3 (source scan) requires `String varname = "..."` on one line.
 *          Juliet separates declaration (`String data;`) from assignment (`data = "7e5tc4s3"`).
 *          The regex /(?:String|string)\s+(\w+)\s*=\s*["'].../ misses bare reassignments.
 *   FIX:   Also match bare `varname = "..."` without type prefix. Correlate with
 *          earlier `String varname;` declarations.
 *
 * CWE-321: HARDCODED_KEY_RE looks for `key='"..."` — variable is named `data`, not `key`.
 *          JAVA_HARDCODED_KEY looks for `new SecretKeySpec("` — Juliet uses
 *          `new SecretKeySpec(data.getBytes("UTF-8"), "AES")` where `data` is an indirect ref.
 *          Taint flow from `data = "..."` to `SecretKeySpec(data.getBytes(...))` crosses nodes.
 *   FIX:   Source-scan for variable assigned hardcoded string + same variable used in
 *          SecretKeySpec constructor via .getBytes() or directly.
 *
 * CWE-329: ZERO_IV_RE looks for `new byte[16]` or `iv[:=]0x...` — Juliet uses
 *          `byte[] initializationVector = {0x00,0x00,...}` (array initializer syntax).
 *          Variable name is `initializationVector`, not `iv/IV`.
 *          PREDICTABLE_IV_RE also needs `iv` prefix which doesn't match.
 *   FIX:   Match Java array initializer syntax with all-zero bytes. Also look for
 *          hardcoded byte array passed to IvParameterSpec regardless of variable name.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, stripComments,
  type VerificationResult, type Finding,
} from './_helpers';

// ===========================================================================
// CWE-259: Use of Hard-coded Password (Juliet-aware)
// ===========================================================================

export function verifyCWE259_A2(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const reported = new Set<string>();

  // --- Strategy 1: Graph-based (original STRUCTURAL -> AUTH without CONTROL) ---
  const structural = nodesOfType(map, 'STRUCTURAL');
  const auth = nodesOfType(map, 'AUTH');
  for (const src of structural) {
    for (const sink of auth) {
      if (src.id === sink.id) continue;
      const adj = new Map<string, string[]>();
      for (const n of map.nodes) {
        adj.set(n.id, []);
        for (const e of n.edges) adj.get(n.id)!.push(e.target);
      }
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
          if (nextNode && nextNode.node_type === 'EXTERNAL') continue;
          visited.add(next);
          queue.push(next);
        }
      }
      if (reached) {
        if (!/\benv\b|\bvault\b|\bsecret.*manager\b/i.test(sink.code_snapshot) &&
            !/\benv\b|\bvault\b|\bsecret.*manager\b/i.test(src.code_snapshot)) {
          reported.add(src.id);
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (no hard-coded passwords -- use env/vault)',
            severity: 'critical',
            description: `STRUCTURAL at ${src.label} -> AUTH at ${sink.label} without controls. Vulnerable to hard-coded password.`,
            fix: 'Never hard-code passwords. Use environment variables or secret managers.',
          });
        }
      }
    }
  }

  // --- Strategy 2: Code snapshot scan for hardcoded password patterns ---
  const HARDCODED_PW = /(?:password|passwd|pwd|pass)\s*[=:]\s*["'][^"']{2,}["']/i;
  const DRIVER_CONNECT = /DriverManager\.getConnection\s*\([^)]*["'][^"']+["']\s*,\s*["'][^"']+["']\s*,\s*["'][^"']+["']/i;
  const PW_FIELD_INIT = /(?:final\s+)?(?:String|string|char\[\])\s+\w*(?:password|passwd|pwd|pass|secret|credential)\w*\s*=\s*["'][^"']{2,}["']/i;

  for (const node of map.nodes) {
    if (reported.has(node.id)) continue;
    const snap = node.code_snapshot;
    if (HARDCODED_PW.test(snap) || DRIVER_CONNECT.test(snap) || PW_FIELD_INIT.test(snap)) {
      if (/\benv\b|\bvault\b|\bsecret.*manager\b|\bgetProperty\b|\bgetenv\b|\bprocess\.env\b/i.test(snap)) continue;
      reported.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (no hard-coded passwords -- use env/vault)',
        severity: 'critical',
        description: `${node.label} contains a hard-coded password. ` +
          `Hard-coded credentials cannot be rotated and are exposed in source control.`,
        fix: 'Never hard-code passwords. Use environment variables, secret managers, or vaults.',
      });
    }
  }

  // --- Strategy 3: Juliet/NIST pattern — IMPROVED ---
  // Original missed: `String data; ... data = "7e5tc4s3";` (separate declaration + assignment).
  // Fix: Also match bare `varname = "literal"` without type prefix, then correlate
  // with known String variable declarations from the same file.
  if (findings.length === 0 && map.source_code) {
    const src = map.source_code;

    // Phase A: collect all declared String variables
    const stringVarDecls = new Set<string>();
    const declRe = /\bString\s+(\w+)\s*[;=]/g;
    let dm: RegExpExecArray | null;
    while ((dm = declRe.exec(src)) !== null) {
      stringVarDecls.add(dm[1]);
    }

    // Phase B: collect all hardcoded string assignments (with or without type prefix)
    const hardcodedVars = new Map<string, string>();
    // Pattern 1: String varname = "literal"
    const typedAssignRe = /(?:String|string)\s+(\w+)\s*=\s*["']([^"']{2,})["']\s*;/g;
    while ((dm = typedAssignRe.exec(src)) !== null) {
      const value = dm[2];
      if (/^(https?:|jdbc:|select |insert |data-)/i.test(value)) continue;
      hardcodedVars.set(dm[1], value);
    }
    // Pattern 2: varname = "literal" (bare reassignment, for variables declared as String earlier)
    const bareAssignRe = /^\s*(\w+)\s*=\s*["']([^"']{2,})["']\s*;/gm;
    while ((dm = bareAssignRe.exec(src)) !== null) {
      const varName = dm[1];
      const value = dm[2];
      if (hardcodedVars.has(varName)) continue; // already found via typed pattern
      if (!stringVarDecls.has(varName)) continue; // only track known String variables
      if (/^(https?:|jdbc:|select |insert |data-)/i.test(value)) continue;
      // Skip if preceded by readLine/getenv/etc on any nearby line
      const lineStart = src.lastIndexOf('\n', dm.index);
      const lineEnd = src.indexOf('\n', dm.index);
      const line = src.slice(lineStart, lineEnd);
      if (/readLine|getenv|getProperty|System\.in|process\.env|vault|secretManager/i.test(line)) continue;
      hardcodedVars.set(varName, value);
    }

    // Phase C: check if any hardcoded var flows into credential sinks
    const CRED_SINKS = [
      /DriverManager\.getConnection\s*\([^)]*,\s*(\w+)\s*\)/,
      /new\s+PasswordAuthentication\s*\([^,]+,\s*(\w+)/,
      /new\s+KerberosKey\s*\([^,]+,\s*(\w+)/,
      /\.setPassword\s*\(\s*(\w+)\s*\)/,
      /\.connect\s*\([^,]*,\s*["'][^"']*["']\s*,\s*(\w+)\s*\)/,
    ];

    for (const sinkRe of CRED_SINKS) {
      const sinkMatch = sinkRe.exec(src);
      if (sinkMatch && hardcodedVars.has(sinkMatch[1])) {
        findings.push({
          source: { id: 'src-hardcoded-var', label: `${sinkMatch[1]} = "${hardcodedVars.get(sinkMatch[1])}"`, line: 0, code: `${sinkMatch[1]} = "${hardcodedVars.get(sinkMatch[1])}"` },
          sink:   { id: 'sink-credential-api', label: sinkMatch[0].trim(), line: 0, code: sinkMatch[0].trim() },
          missing: 'CONTROL (no hard-coded passwords -- use env/vault)',
          severity: 'critical',
          description: `Variable "${sinkMatch[1]}" is assigned a hardcoded string and then passed as a credential to ${sinkMatch[0].split('(')[0].trim()}. ` +
            `Hard-coded credentials cannot be rotated and are exposed in source control.`,
          fix: 'Never hard-code passwords. Read credentials from environment variables, secret managers, or vaults.',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-259', name: 'Use of Hard-coded Password', holds: findings.length === 0, findings };
}

// ===========================================================================
// CWE-321: Use of Hard-coded Cryptographic Key (Juliet-aware)
// ===========================================================================

export function verifyCWE321_A2(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const reported = new Set<string>();

  const KEY_SAFE_RE = /\bprocess\.env\b|\bos\.environ\b|\bgetenv\b|\bvault\b|\bKMS\b|\bkeyStore\b|\bsecretManager\b|\bKeyVault\b|\bParameter.?Store\b|\bconfig\.\b|\bsettings\.\b|\baws[-_]?kms\b|\bgcp[-_]?kms\b|\bazure[-_]?key/i;

  // --- Strategy 1: Node-level crypto op + hardcoded key (original, JS-focused) ---
  const CRYPTO_OP_RE = /\b(createCipheriv|createDecipheriv|createHmac|createSign|createVerify|jwt\.sign|jwt\.verify|sign\s*\(|verify\s*\(|encrypt\s*\(|decrypt\s*\(|CryptoJS\.\w+\.encrypt|CryptoJS\.\w+\.decrypt|Cipher\.getInstance|Mac\.getInstance|Signature\.getInstance|secretbox|box\.open|nacl\.|HMAC|hmac|signWith|verifyWith)\b/i;
  const HARDCODED_KEY_RE = /(?:key|secret|password|passphrase|privateKey|signingKey|encryptionKey|masterKey|hmacKey)\s*[:=]\s*['"`][A-Za-z0-9+/=_-]{8,}['"`]/i;
  const INLINE_KEY_RE = /(?:createCipheriv|createHmac|createSign|jwt\.sign|jwt\.verify|encrypt|decrypt|sign|HMAC)\s*\([^)]*['"`][A-Za-z0-9+/=_-]{16,}['"`]/i;
  const BUFFER_KEY_RE = /Buffer\.from\s*\(\s*['"`][A-Za-z0-9+/=_-]{8,}['"`]/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!CRYPTO_OP_RE.test(code)) continue;
    if (KEY_SAFE_RE.test(code)) continue;
    if (HARDCODED_KEY_RE.test(code) || INLINE_KEY_RE.test(code) || BUFFER_KEY_RE.test(code)) {
      reported.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (externally managed cryptographic key -- use KMS, vault, or env vars)',
        severity: 'critical',
        description: `Hard-coded cryptographic key in ${node.label}. ` +
          `A key embedded in source code cannot be rotated without redeployment.`,
        fix: 'Load cryptographic keys from environment variables or a key management service.',
      });
    }
  }

  // --- Strategy 2: Java-specific patterns (original) ---
  const JAVA_HARDCODED_KEY = /new\s+SecretKeySpec\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{|")/i;
  const JAVA_KEY_BYTES = /(?:byte\s*\[\s*\]\s+\w*(?:key|secret|iv)\w*\s*=\s*)\s*(?:new\s+byte\s*\[\s*\]\s*)?\{/i;

  for (const node of map.nodes) {
    if (reported.has(node.id)) continue;
    const snap = node.analysis_snapshot || node.code_snapshot;
    if (KEY_SAFE_RE.test(snap)) continue;
    if (JAVA_HARDCODED_KEY.test(snap) || JAVA_KEY_BYTES.test(snap)) {
      reported.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (externally managed cryptographic key -- use KMS, vault, or env vars)',
        severity: 'critical',
        description: `Hard-coded cryptographic key at ${node.label}. ` +
          `Keys embedded in source code cannot be rotated without redeployment.`,
        fix: 'Load cryptographic keys from environment variables or a key management service.',
      });
    }
  }

  // --- Strategy 3 [NEW -- Juliet gap]: Variable-flow to SecretKeySpec ---
  // Juliet pattern: `data = "23 ~j;asn!@#/>as"` then `new SecretKeySpec(data.getBytes("UTF-8"), "AES")`.
  // The hardcoded string is in a different node from the SecretKeySpec call.
  // Neither HARDCODED_KEY_RE nor JAVA_HARDCODED_KEY matches because:
  //   - Variable named `data` not `key`/`secret`
  //   - SecretKeySpec takes `data.getBytes(...)` not a string literal
  // Fix: source-code scan for hardcoded string variables flowing to SecretKeySpec.
  if (findings.length === 0 && map.source_code) {
    const src = map.source_code;

    // Collect all String variable declarations
    const stringVarDecls = new Set<string>();
    const declRe = /\bString\s+(\w+)\s*[;=]/g;
    let dm: RegExpExecArray | null;
    while ((dm = declRe.exec(src)) !== null) {
      stringVarDecls.add(dm[1]);
    }

    // Collect hardcoded string assignments (typed + bare)
    const hardcodedVars = new Map<string, string>();
    const typedRe = /(?:String|string)\s+(\w+)\s*=\s*["']([^"']{2,})["']\s*;/g;
    while ((dm = typedRe.exec(src)) !== null) {
      const value = dm[2];
      if (/^(https?:|jdbc:|select |insert |data-)/i.test(value)) continue;
      hardcodedVars.set(dm[1], value);
    }
    const bareRe = /^\s*(\w+)\s*=\s*["']([^"']{2,})["']\s*;/gm;
    while ((dm = bareRe.exec(src)) !== null) {
      if (hardcodedVars.has(dm[1])) continue;
      if (!stringVarDecls.has(dm[1])) continue;
      const value = dm[2];
      if (/^(https?:|jdbc:|select |insert |data-)/i.test(value)) continue;
      const lineStart = src.lastIndexOf('\n', dm.index);
      const lineEnd = src.indexOf('\n', dm.index);
      const line = src.slice(lineStart, lineEnd);
      if (/readLine|getenv|getProperty|System\.in|process\.env|vault|secretManager/i.test(line)) continue;
      hardcodedVars.set(dm[1], value);
    }

    // Check if any hardcoded var flows to crypto key sinks
    const CRYPTO_KEY_SINKS = [
      // SecretKeySpec(varname.getBytes(...), ...)
      /new\s+SecretKeySpec\s*\(\s*(\w+)\.getBytes\s*\(/,
      // SecretKeySpec(varname, ...)
      /new\s+SecretKeySpec\s*\(\s*(\w+)\s*,/,
      // PBEKeySpec(varname.toCharArray(), ...)
      /new\s+PBEKeySpec\s*\(\s*(\w+)\.toCharArray\s*\(/,
      // Cipher.init(..., varname) — less common but possible
    ];

    for (const sinkRe of CRYPTO_KEY_SINKS) {
      const sinkMatch = sinkRe.exec(src);
      if (sinkMatch && hardcodedVars.has(sinkMatch[1])) {
        findings.push({
          source: { id: 'src-hardcoded-key-var', label: `${sinkMatch[1]} = "${hardcodedVars.get(sinkMatch[1])}"`, line: 0, code: `${sinkMatch[1]} = "${hardcodedVars.get(sinkMatch[1])}"` },
          sink:   { id: 'sink-crypto-key-api', label: sinkMatch[0].trim(), line: 0, code: sinkMatch[0].trim() },
          missing: 'META (externally managed cryptographic key -- use KMS, vault, or env vars)',
          severity: 'critical',
          description: `Variable "${sinkMatch[1]}" is assigned a hardcoded string "${hardcodedVars.get(sinkMatch[1])!.slice(0, 20)}..." ` +
            `and then used as a cryptographic key in ${sinkMatch[0].split('(')[0].trim()}. ` +
            `A hardcoded key cannot be rotated and is exposed in source control.`,
          fix: 'Load cryptographic keys from environment variables, a key management service (KMS), or a vault. ' +
            'Never hardcode encryption keys.',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-321', name: 'Use of Hard-coded Cryptographic Key', holds: findings.length === 0, findings };
}

// ===========================================================================
// CWE-329: Generation of Predictable IV with CBC Mode (Juliet-aware)
// ===========================================================================

export function verifyCWE329_A2(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const reported = new Set<string>();

  const CBC_RE = /\b(?:aes-(?:128|192|256)-cbc|des-cbc|des-ede3-cbc)\b|AES\/CBC\/|DES\/CBC\/|CryptoJS\.(?:AES|mode\.CBC)|createCipher(?:iv)?\s*\(\s*['"](?:aes|des).*cbc/i;
  const RANDOM_IV_RE = /(?:crypto\.randomBytes|randomBytes|getRandomValues|SecureRandom|os\.urandom|crypto\/rand|randomIV|generateIV|randomIv|generateIv)\s*\(/i;

  // --- Strategy 1: Node-level CBC + predictable IV patterns (original, expanded) ---
  const PREDICTABLE_IV_RE = /iv\s*[:=]\s*(?:['"`][^'"`]*['"`]|(?:Buffer\.from|new Uint8Array)\s*\(\s*\[[\d,\s]+\]|\bBuffer\.alloc\s*\(\s*16\s*\))|iv\s*[:=]\s*(?:0x[0-9a-fA-F]+|new\s+byte\s*\[\s*16\s*\])|iv\s*[:=]\s*(?:Date\.now|timestamp|counter|nonce\+\+|lastIv)|(?:iv|IV)\s*=\s*b['"][^'"]+['"]/i;
  const ZERO_IV_RE = /Buffer\.alloc\s*\(\s*16\s*\)|new\s+byte\s*\[\s*16\s*\]|(?:iv|IV)\s*[:=]\s*(?:b?['"]\\x00|(?:\[0,\s*0|new\s+Uint8Array\(\s*16\s*\)))/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!CBC_RE.test(code)) continue;
    if (ZERO_IV_RE.test(code) && !RANDOM_IV_RE.test(code)) {
      reported.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (cryptographically random IV for CBC)',
        severity: 'high',
        description: `Zero/empty IV with CBC at ${node.label}. A zero IV makes the first block equivalent to ECB.`,
        fix: 'Generate random IV per encryption: crypto.randomBytes(16). Better: switch to AES-GCM.',
      });
    } else if (PREDICTABLE_IV_RE.test(code) && !RANDOM_IV_RE.test(code)) {
      reported.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (unpredictable IV -- CBC requires random IVs)',
        severity: 'high',
        description: `Predictable IV with CBC at ${node.label}. CBC requires unpredictable IVs (not just unique).`,
        fix: 'Use crypto.randomBytes(16) for CBC IVs. Migrate to AES-GCM if possible.',
      });
    }
  }

  // --- Strategy 2: Java weak cipher patterns (original) ---
  {
    const WEAK_CIPHER_LITERAL = /Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC4|RC2|Blowfish)(?:\/|\s*["'])/i;
    const ECB_MODE = /Cipher\.getInstance\s*\(\s*["'][^"']*ECB[^"']*["']/i;
    const CRYPTO_ALG_PROPERTY = /\bgetProperty\s*\(\s*["']cryptoAlg1["']/i;

    for (const node of map.nodes) {
      if (reported.has(node.id)) continue;
      const snap = node.analysis_snapshot || node.code_snapshot;
      if (WEAK_CIPHER_LITERAL.test(snap) || ECB_MODE.test(snap) || CRYPTO_ALG_PROPERTY.test(snap)) {
        reported.add(node.id);
        const isECB = ECB_MODE.test(snap) || CRYPTO_ALG_PROPERTY.test(snap);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: isECB
            ? 'TRANSFORM (do not use ECB mode -- use CBC with random IV or GCM)'
            : 'TRANSFORM (use strong cipher with random IV -- not DES/RC4)',
          severity: 'high',
          description: isECB
            ? `${node.label} uses ECB mode which does not use an IV at all. ECB leaks patterns.`
            : `${node.label} uses a weak cipher algorithm. These have known vulnerabilities.`,
          fix: 'Use AES-256-GCM or AES-256-CBC with a random IV from SecureRandom.',
        });
      }
    }
  }

  // --- Strategy 3 [NEW -- Juliet gap]: Function-scope CBC + hardcoded IV detection ---
  // Juliet pattern:
  //   byte[] initializationVector = { 0x00, 0x00, ..., 0x00 };
  //   Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
  //   IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
  //
  // The existing verifier fails because:
  //   1. ZERO_IV_RE expects `new byte[16]` but Juliet uses `byte[] name = { 0x00,... }`
  //   2. PREDICTABLE_IV_RE expects variable named `iv/IV` but name is `initializationVector`
  //   3. CBC and IV are on different nodes (Cipher.getInstance vs the byte array)
  //
  // Fix: Look at function-level nodes that contain BOTH CBC cipher init AND a hardcoded
  // byte array IV. Also look at source code for the cross-node pattern.
  if (findings.length === 0) {
    // Pattern: Java byte array initializer with all-zero or hardcoded constant values
    const JAVA_HARDCODED_IV_ARRAY = /byte\s*\[\s*\]\s+\w*(?:iv|initialization|initialisation|initVector|init_vector|nonce|vector)\w*\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{\s*(?:0x[0-9a-fA-F]+\s*,?\s*)+\}/i;
    // Broader: any byte array assigned to a var that's then used with IvParameterSpec
    const JAVA_IV_PARAM_SPEC = /new\s+IvParameterSpec\s*\(\s*(\w+)\s*\)/;
    const JAVA_BYTE_ARRAY_INIT = /byte\s*\[\s*\]\s+(\w+)\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{/;
    // All-zeros pattern for byte arrays
    const ALL_ZEROS_ARRAY = /\{\s*(?:0x0+\s*,\s*)*0x0+\s*\}/i;

    for (const node of map.nodes) {
      if (reported.has(node.id)) continue;
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (!CBC_RE.test(code)) continue;
      if (RANDOM_IV_RE.test(code)) continue;

      // Check if this function-level node contains a hardcoded IV array
      if (JAVA_HARDCODED_IV_ARRAY.test(code)) {
        reported.add(node.id);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (cryptographically random IV -- use SecureRandom, not hardcoded bytes)',
          severity: 'high',
          description: `${node.label} uses CBC mode with a hardcoded initialization vector. ` +
            `A predictable IV with CBC enables chosen-plaintext attacks (BEAST).`,
          fix: 'Generate random IV per encryption: SecureRandom sr = new SecureRandom(); ' +
            'byte[] iv = new byte[16]; sr.nextBytes(iv); new IvParameterSpec(iv). Better: use AES-GCM.',
        });
        continue;
      }

      // Check: IvParameterSpec uses a variable that was initialized from hardcoded bytes
      const ivSpecMatch = JAVA_IV_PARAM_SPEC.exec(code);
      const byteArrayMatch = JAVA_BYTE_ARRAY_INIT.exec(code);
      if (ivSpecMatch && byteArrayMatch && ivSpecMatch[1] === byteArrayMatch[1]) {
        reported.add(node.id);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (cryptographically random IV -- use SecureRandom, not hardcoded bytes)',
          severity: 'high',
          description: `${node.label} uses CBC mode with a hardcoded byte array as IV (${ivSpecMatch[1]}). ` +
            `Static IVs are predictable and enable CBC-specific attacks.`,
          fix: 'Generate IV from SecureRandom. Never reuse or hardcode IVs.',
        });
        continue;
      }
    }

    // Source-code level scan for cross-node patterns
    if (findings.length === 0 && map.source_code) {
      const src = map.source_code;
      const hasCBC = CBC_RE.test(src);
      if (hasCBC && !RANDOM_IV_RE.test(src)) {
        // Find byte array declarations with all-zero or hardcoded constant values
        const byteArrayDeclRe = /byte\s*\[\s*\]\s+(\w+)\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{([^}]+)\}/g;
        let bm: RegExpExecArray | null;
        const hardcodedIvVars = new Map<string, string>();
        while ((bm = byteArrayDeclRe.exec(src)) !== null) {
          const varName = bm[1];
          const arrayContent = bm[2];
          // Check if all values are constant (hex or decimal literals)
          const values = arrayContent.split(',').map(v => v.trim());
          const allConstant = values.every(v => /^0x[0-9a-fA-F]+$|^\d+$/.test(v));
          if (allConstant) {
            hardcodedIvVars.set(varName, arrayContent.trim());
          }
        }

        // Check if any hardcoded byte array is used as IvParameterSpec arg
        const ivSpecGlobalRe = /new\s+IvParameterSpec\s*\(\s*(\w+)\s*\)/g;
        let ivMatch: RegExpExecArray | null;
        while ((ivMatch = ivSpecGlobalRe.exec(src)) !== null) {
          if (hardcodedIvVars.has(ivMatch[1])) {
            // Also verify this isn't in the "good" function with SecureRandom
            // Check if SecureRandom.nextBytes appears for this variable nearby
            const ivVarName = ivMatch[1];
            const nextBytesRe = new RegExp(`(?:SecureRandom|secureRandom|prng)\\s*\\.\\s*nextBytes\\s*\\(\\s*${ivVarName}\\s*\\)`, 'i');
            if (nextBytesRe.test(src)) {
              // There IS a SecureRandom usage. Need to check if it's in a DIFFERENT function.
              // Simple heuristic: if both hardcoded array AND SecureRandom.nextBytes exist for
              // the same variable, it's likely good+bad functions. Still flag the hardcoded path.
              // But skip if the hardcoded array init is NOT present (good function only).
            }

            findings.push({
              source: { id: 'src-hardcoded-iv', label: `${ivVarName} = {${hardcodedIvVars.get(ivVarName)!.slice(0, 50)}...}`, line: 0, code: `byte[] ${ivVarName} = {${hardcodedIvVars.get(ivVarName)!.slice(0, 80)}}` },
              sink:   { id: 'sink-iv-param-spec', label: ivMatch[0].trim(), line: 0, code: ivMatch[0].trim() },
              missing: 'TRANSFORM (cryptographically random IV -- use SecureRandom, not hardcoded bytes)',
              severity: 'high',
              description: `Variable "${ivVarName}" is initialized with hardcoded constant bytes and used as the IV for CBC encryption via IvParameterSpec. ` +
                `A predictable IV makes the first ciphertext block deterministic, enabling chosen-plaintext and BEAST-style attacks.`,
              fix: 'Generate IV from SecureRandom: byte[] iv = new byte[16]; new SecureRandom().nextBytes(iv); ' +
                'new IvParameterSpec(iv). Prepend IV to ciphertext. Better: migrate to AES-GCM.',
            });
            break;
          }
        }
      }
    }
  }

  return { cwe: 'CWE-329', name: 'Generation of Predictable IV with CBC Mode', holds: findings.length === 0, findings };
}

// ===========================================================================
// Registry
// ===========================================================================

export const BATCH_CRYPTO_A2_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-259': verifyCWE259_A2,
  'CWE-321': verifyCWE321_A2,
  'CWE-329': verifyCWE329_A2,
};
