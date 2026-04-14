/**
 * Sensitive Data & Information Disclosure CWE Verifiers
 *
 * Hardcoded credentials, plaintext storage, cleartext transmission,
 * information exposure through error messages, logs, comments, debug info,
 * privacy violations, and password masking.
 *
 * These verifiers detect sensitive data handling weaknesses: secrets in source,
 * data leaking to responses/logs/caches, and missing redaction/filtering.
 * Some use BFS helpers (hasTaintedPathWithoutControl, hasPathWithoutControl)
 * imported from graph-helpers.ts since their PRIMARY purpose is sensitive data detection.
 *
 * Extracted from verifier/index.ts — Phase 4 of the monolith split.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments } from './source-analysis.ts';
import { nodeRef, nodesOfType, inferMapLanguage, isLibraryCode, hasTaintedPathWithoutControl, hasPathWithoutControl, findContainingFunction, sharesFunctionScope } from './graph-helpers.ts';
import { getContainingScopeSnapshots, scopeBasedTaintReaches } from '../generated/_helpers.js';

// ---------------------------------------------------------------------------
// Sensitive Data & Information Disclosure CWEs
// ---------------------------------------------------------------------------

/**
 * CWE-798: Hardcoded Credentials
 * Pattern: META missing — secrets embedded directly in source code
 * Property: No hardcoded passwords, API keys, or tokens in source code
 *
 * Unlike flow-based CWEs, this is a static scan: walk all nodes looking
 * for credential patterns in code_snapshot, flagging any node that lacks
 * a corresponding META(env_ref) node indicating the value comes from
 * an external secret store.
 */
function verifyCWE798(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns that indicate hardcoded secrets
  const secretPatterns = [
    /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/i,
    /(?:api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    /(?:secret|token)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    /(?:access[_-]?key|auth[_-]?token)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    /(?:private[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    /(?:connection[_-]?string)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    // Rust/Go/Kotlin: const/static with credential-like names (allow prefixes like JWT_SECRET, DB_PASSWORD)
    /(?:const|static|val|var)\s+\w*(?:PASSWORD|SECRET|API_KEY|TOKEN|AUTH_TOKEN|PRIVATE_KEY|ACCESS_KEY)\w*\s*[=:][^=].*['"][^'"]{4,}['"]/i,
    // Module-scope credential assignments: UPPER_CASE names with string literals
    /\b(?:PASS|SECRET|KEY|TOKEN|CRED)\w*\s*=\s*['"][^'"]{4,}['"]/,
  ];

  // Safe patterns that suppress findings
  const safePatterns = [
    /process\.env\b/,
    /config\.get\s*\(/,
    /\benv\s*\(/,
    /\bvault\b/,
    /\bsecretManager\b/,
    /\byour_|\$\{|<[A-Z]|\bREPLACE\b|\bCHANGEME\b|\bTODO\b|\bEXAMPLE\b|\bTEST\b|\bPLACEHOLDER\b/i,
    // Security tool internals: regex-literal definitions and verifier code patterns.
    // A line assigning a regex literal (/pattern/) is a detection rule, not a credential.
    /^\s*(?:const|let|var)\s+\w+\s*=\s*\//,
    // Lines from security-tool fix/description strings (e.g. 'Never log passwords...password: "[REDACTED]"')
    /\bfindings\.push\b|\bnodeRef\s*\(|\bstripComments\b|\bstripLiterals\b|\bverifyCWE/,
    // Redacted/masked credential references in examples
    /\bREDACTED\b|\bMASKED\b|\b\*{3,}\b/i,
  ];

  // Check if there's a META node that marks this value as env-sourced
  const metaNodes = nodesOfType(map, 'META');
  const envRefs = new Set(
    metaNodes
      .filter(n => n.node_subtype.includes('env_ref') || n.node_subtype.includes('secret_ref') ||
        (n.analysis_snapshot || n.code_snapshot).match(/\bprocess\.env\b|\benv\(\b|\bvault\b|\bsecretManager/i) !== null)
      .flatMap(n => n.edges.map(e => e.target))
  );

  // Phase 1: scan all neural map nodes (catches in-function and config_value nodes)
  for (const node of map.nodes) {
    // Skip META nodes — except config_value nodes which may contain hardcoded creds
    if (node.node_type === 'META' && node.node_subtype !== 'config_value') continue;
    // Skip nodes that are known to source from env
    if (envRefs.has(node.id)) continue;
    // Skip verifier-internal function nodes: their snapshots contain credential-detection
    // regex patterns by design. These function bodies are not themselves credentials.
    if (/^verifyCWE\d+$/.test(node.label)) continue;

    const nodeSnap798 = stripComments(node.analysis_snapshot || node.code_snapshot);
    // Skip entire nodes that look like security-tool verifier function bodies
    // (have findings.push / nodeRef calls indicating they're CWE detection code).
    if (/\bfindings\.push\b|\bnodeRef\s*\(|\bstripComments\b|\bstripLiterals\b|\bverifyCWE/.test(nodeSnap798)) continue;

    for (const pattern of secretPatterns) {
      // Check safePatterns only against the matched credential text (not the whole snapshot).
      // This prevents unrelated safe-looking words elsewhere in the code snapshot (e.g.
      // "db.example.com" hostname) from suppressing a real credential finding.
      const match = pattern.exec(nodeSnap798);
      if (match) {
        if (safePatterns.some(sp => sp.test(match[0]))) break;

        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'META (external secret reference — environment variable, vault, or secret manager)',
          severity: 'critical',
          description: `Hardcoded credential found in ${node.label}. ` +
            `Secrets in source code can be leaked via version control, logs, or build artifacts.`,
          fix: 'Move secrets to environment variables or a secret manager. ' +
            'Use process.env.SECRET_NAME or a vault client. ' +
            'Never commit secrets to source control.',
          via: 'structural',
        });
        break; // One finding per node is enough
      }
    }
  }

  // Phase 2: module-scope fallback — scan raw source_code line by line.
  // Module-scope const/var declarations are NOT emitted as neural map nodes
  // by the tree-sitter mapper, so the node walk above misses them entirely.
  // This fallback catches `const DB_PASSWORD = "secret"` at the top level.
  if (map.source_code) {
    const lines = map.source_code.split('\n');
    // Build a set of code already flagged by Phase 1 (node scan) so we don't double-report.
    // Use normalized (trimmed, semicolon-stripped) comparison to handle minor formatting differences.
    const phase1Snippets = findings.map(f => f.source.code.trim().replace(/;$/, ''));

    // Helper: check if a line was already covered by a Phase 1 finding
    const alreadyCoveredByNodeScan = (lineContent: string): boolean => {
      const norm = lineContent.trim().replace(/;$/, '');
      return phase1Snippets.some(s => s.includes(norm) || norm.includes(s));
    };

    const alreadyFlaggedLines = new Set<number>();

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      // Skip blank lines and pure comment lines
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;
      // Skip lines that use safe sourcing patterns
      if (safePatterns.some(sp => sp.test(line))) return;
      // Skip if already covered by Phase 1 node scan
      if (alreadyCoveredByNodeScan(line)) return;

      for (const pattern of secretPatterns) {
        if (pattern.test(line)) {
          if (alreadyFlaggedLines.has(idx)) break;
          alreadyFlaggedLines.add(idx);
          const snippet = line.trim().slice(0, 200);
          findings.push({
            source: { id: `module-scope-line-${idx + 1}`, label: `module-scope (line ${idx + 1})`, line: idx + 1, code: snippet },
            sink:   { id: `module-scope-line-${idx + 1}`, label: `module-scope (line ${idx + 1})`, line: idx + 1, code: snippet },
            missing: 'META (external secret reference — environment variable, vault, or secret manager)',
            severity: 'critical',
            description: `Hardcoded credential at module scope (line ${idx + 1}). ` +
              `Secrets in source code can be leaked via version control, logs, or build artifacts.`,
            fix: 'Move secrets to environment variables or a secret manager. ' +
              'Use process.env.SECRET_NAME or a vault client. ' +
              'Never commit secrets to source control.',
            via: 'source_line_fallback',
          });
          break; // One finding per line is enough
        }
      }
    });
  }

  return {
    cwe: 'CWE-798',
    name: 'Hardcoded Credentials',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-200: Information Exposure
 * Pattern: STORAGE → EGRESS without CONTROL (data filtering/redaction)
 * Property: Sensitive data from storage is filtered before being sent to clients
 */
function verifyCWE200(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const storage = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.data_out.some(d => d.sensitivity !== 'NONE') ||
     n.attack_surface.includes('sensitive_data') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(password|ssn|credit.?card|token|secret|private|hash)\b/i) !== null)
  );
  const egress = nodesOfType(map, 'EGRESS');

  for (const src of storage) {
    for (const sink of egress) {
      if (hasPathWithoutControl(map, src.id, sink.id)) {
        // Check if the egress node or its containing scope filters fields (V4-D: use scope snapshots)
        const scopeSnapshots200 = getContainingScopeSnapshots(map, sink.id);
        const combinedScope200 = stripComments(scopeSnapshots200.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isFiltered = combinedScope200.match(
          /\bselect\s*\(|\bpick\s*\(|\bomit\s*\(|\b\.filter\s*\(|\bredact\s*\(|\bexclude\s*\(|\bsanitize\s*\(|\btoJSON\s*\(|\b\.map\s*\(/i
        ) !== null;

        if (!isFiltered) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (data filtering or field redaction)',
            severity: 'high',
            description: `Sensitive data from ${src.label} flows to ${sink.label} without filtering. ` +
              `Internal fields (passwords, tokens, PII) may be exposed to clients.`,
            fix: 'Explicitly select which fields to return (allowlist pattern). ' +
              'Use DTO/view models to strip sensitive fields before sending. ' +
              'Never send raw database records directly to clients.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-200',
    name: 'Information Exposure',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-256: Plaintext Storage of a Password
 * Pattern: INGRESS/STORAGE containing password data → STORAGE without hashing TRANSFORM
 * Property: Passwords must be hashed (bcrypt/scrypt/argon2) before storage
 */
function verifyCWE256(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Password patterns in code snapshots
  const PASSWORD_RE = /\b(password|passwd|pwd|pass_?word|user_?pass|login_?pass)\b/i;
  // Hashing safe patterns — real password hashing functions
  const HASH_SAFE_RE = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bhash(?:Sync|Password|pwd)\b|\bcreateHash\b|\bgenSalt\b|\bhashpw\b|\bpassword_hash\b|\bgenerate_password_hash\b|\bmake_password\b/i;

  // Find STORAGE nodes that deal with passwords
  const passwordStores = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (PASSWORD_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     PASSWORD_RE.test(n.label) ||
     n.data_in.some(d => PASSWORD_RE.test(d.name)))
  );

  // For each password storage, check if a TRANSFORM(hash) precedes it
  for (const store of passwordStores) {
    const storeCode = stripComments(store.analysis_snapshot || store.code_snapshot);
    // If the store itself references hashing, it's safe
    if (HASH_SAFE_RE.test(storeCode)) continue;

    // Check if any TRANSFORM node on the path to this store performs hashing
    let hasHashTransform = false;
    for (const n of map.nodes) {
      if (n.node_type === 'TRANSFORM' && HASH_SAFE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))) {
        // Check if this hash transform feeds into the store
        for (const edge of n.edges) {
          if (edge.target === store.id) {
            hasHashTransform = true;
            break;
          }
        }
      }
      if (hasHashTransform) break;
    }

    // Also check the containing function scope for hashing
    if (!hasHashTransform) {
      const parentFn = findContainingFunction(map, store.id);
      if (parentFn) {
        const parentNode = map.nodes.find(n => n.id === parentFn);
        if (parentNode && HASH_SAFE_RE.test(stripComments(parentNode.analysis_snapshot || parentNode.code_snapshot))) {
          hasHashTransform = true;
        }
      }
    }

    if (!hasHashTransform) {
      // Find the source of the password data
      const pwSource = map.nodes.find(n =>
        n.node_type === 'INGRESS' && PASSWORD_RE.test(n.analysis_snapshot || n.code_snapshot)
      );
      findings.push({
        source: pwSource ? nodeRef(pwSource) : nodeRef(store),
        sink: nodeRef(store),
        missing: 'TRANSFORM (password hashing — bcrypt, scrypt, or argon2)',
        severity: 'critical',
        description: `Password stored in plaintext at ${store.label}. ` +
          `No hashing transform detected before storage. A database breach exposes all user passwords.`,
        fix: 'Hash passwords with bcrypt, scrypt, or Argon2 before storing. ' +
          'Example: const hashed = await bcrypt.hash(password, 12); db.store(hashed). ' +
          'Never store passwords as plaintext or with reversible encoding.',
        via: 'structural',
      });
    }
  }

  return {
    cwe: 'CWE-256',
    name: 'Plaintext Storage of a Password',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-257: Storing Passwords in a Recoverable Format
 * Pattern: Password data goes through reversible encoding (base64, AES, XOR) instead of one-way hash
 * Property: Passwords must use one-way hashing, never reversible encryption/encoding
 */
function verifyCWE257(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PASSWORD_RE = /\b(password|passwd|pwd|pass_?word|user_?pass|login_?pass)\b/i;
  // Reversible encoding/encryption — NOT one-way hashing
  const REVERSIBLE_RE = /\bbase64\b|\bbtoa\b|\batob\b|\bBuffer\.from\b.*\btoString\b|\bencode\s*\(|\bAES\b|\bDES\b|\b3DES\b|\bTripleDES\b|\bRC4\b|\bXOR\b|\bencrypt\s*\(|\bcipher\s*\(|\bcreateCipher\b|\bCryptoJS\.enc\b|\bfernet\b|\bb64encode\b/i;
  // One-way hash — the CORRECT approach for passwords
  const ONEWAY_HASH_RE = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bhash(?:Sync|Password|pwd)\b|\bgenSalt\b|\bhashpw\b|\bpassword_hash\b|\bgenerate_password_hash\b|\bmake_password\b/i;

  // Find TRANSFORM nodes that apply reversible encoding to password data
  const transforms = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    REVERSIBLE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );

  for (const txNode of transforms) {
    const code = stripComments(txNode.analysis_snapshot || txNode.code_snapshot);
    // Does this transform handle password data?
    const handlesPassword = PASSWORD_RE.test(code) ||
      PASSWORD_RE.test(txNode.label) ||
      txNode.data_in.some(d => PASSWORD_RE.test(d.name));

    let pwFlowedViaBfs = false;
    if (!handlesPassword) {
      // Check if an INGRESS with password data flows into this transform
      const pwIngress = map.nodes.filter(n =>
        n.node_type === 'INGRESS' && PASSWORD_RE.test(n.analysis_snapshot || n.code_snapshot)
      );
      let pwFlows = false;
      for (const src of pwIngress) {
        if (hasTaintedPathWithoutControl(map, src.id, txNode.id)) {
          pwFlows = true;
          break;
        }
      }
      if (!pwFlows) continue;
      pwFlowedViaBfs = true;
    }

    // Skip if a one-way hash is ALSO present (reversible encoding might be for transport, not storage)
    if (ONEWAY_HASH_RE.test(code)) continue;

    // Check containing function for one-way hash
    const parentFn = findContainingFunction(map, txNode.id);
    if (parentFn) {
      const parentNode = map.nodes.find(n => n.id === parentFn);
      if (parentNode && ONEWAY_HASH_RE.test(stripComments(parentNode.analysis_snapshot || parentNode.code_snapshot))) continue;
    }

    findings.push({
      source: nodeRef(txNode),
      sink: nodeRef(txNode),
      missing: 'TRANSFORM (one-way password hash instead of reversible encoding)',
      severity: 'critical',
      description: `Password is stored using reversible encoding/encryption at ${txNode.label}. ` +
        `An attacker who gains access to the stored data can reverse the encoding to recover plaintext passwords.`,
      fix: 'Use one-way hashing (bcrypt, scrypt, Argon2) for passwords — NEVER reversible encryption. ' +
        'Encryption (AES, base64) can be reversed with the key. Hashing cannot be reversed. ' +
        'Example: await bcrypt.hash(password, 12) instead of encrypt(password, key).',
      via: pwFlowedViaBfs ? 'bfs' : 'structural',
    });
  }

  return {
    cwe: 'CWE-257',
    name: 'Storing Passwords in a Recoverable Format',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-260: Password in Configuration File
 * Pattern: META/config_value or STORAGE nodes with password patterns in config-like contexts
 * Property: Configuration files must not contain hardcoded passwords
 */
function verifyCWE260(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PASSWORD_IN_CONFIG_RE = /(?:password|passwd|pwd|db_?pass|db_?password|mysql_?password|postgres_?password|redis_?password|smtp_?password|mail_?password|auth_?password)\s*[:=]\s*['"][^'"]{1,}['"]/i;
  // Config file patterns
  const CONFIG_FILE_RE = /\b(config|settings|\.env|\.ini|\.yaml|\.yml|\.json|\.toml|\.properties|\.conf|application)\b/i;
  // Safe: reading from environment or secret manager
  const ENV_SAFE_RE = /\bprocess\.env\b|\bos\.environ\b|\bos\.getenv\b|\benv\(\b|\bENV\[|\bvault\b|\bsecretManager\b|\baws[_-]?ssm\b|\bgetSecret\b|\bSecretClient\b|\bKeyVault\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for password values in config-related nodes
    const isConfigContext = node.node_type === 'META' ||
      (node.node_subtype.includes('config') || node.node_subtype.includes('setting') ||
       CONFIG_FILE_RE.test(node.file) || CONFIG_FILE_RE.test(node.label));

    if (!isConfigContext) continue;
    if (!PASSWORD_IN_CONFIG_RE.test(code)) continue;
    if (ENV_SAFE_RE.test(code)) continue;

    findings.push({
      source: nodeRef(node),
      sink: nodeRef(node),
      missing: 'META (external secret reference — environment variable or secret manager)',
      severity: 'high',
      description: `Password found in configuration at ${node.label}. ` +
        `Hardcoded passwords in config files are exposed via version control, backups, and deployment artifacts.`,
      fix: 'Move passwords to environment variables or a secret manager (AWS SSM, HashiCorp Vault, Azure Key Vault). ' +
        'Reference them as: process.env.DB_PASSWORD or vault.read("secret/db"). ' +
        'Never commit config files with real passwords.',
      via: 'structural',
    });
  }

  return {
    cwe: 'CWE-260',
    name: 'Password in Configuration File',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-312: Cleartext Storage of Sensitive Information
 * Pattern: Sensitive data (PII, SECRET, AUTH, FINANCIAL) flows to STORAGE without encryption TRANSFORM
 * Property: Sensitive data must be encrypted before being written to persistent storage
 */
function verifyCWE312(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SENSITIVE_RE = /\b(password|passwd|pwd|ssn|social.?security|credit.?card|card.?number|cvv|secret|token|api.?key|private.?key|health.?record|medical|dob|date.?of.?birth|bank.?account|routing.?number)\b/i;
  // Encryption or hashing safe patterns — both are valid protections for stored sensitive data
  const ENCRYPT_SAFE_RE = /\bencrypt\s*\(|\bAES\b|\bcipher\s*\(|\bcreateCipher\w*\b|\bcrypto\.subtle\b|\bCryptoJS\b|\bfernet\b|\b\.seal\s*\(|\bsecretbox\b|\bRSA\b|\bgpg\b|\bpgp\b|\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bhash(?:Sync|Password|pwd)\b|\bgenSalt\b|\bhashpw\b|\bpassword_hash\b|\bgenerate_password_hash\b|\bmake_password\b|\bcreateHash\b/i;

  // Find storage nodes that receive sensitive data without encryption
  const sensitiveStores = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.data_in.some(d => d.sensitivity !== 'NONE') ||
     SENSITIVE_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     SENSITIVE_RE.test(n.label))
  );

  for (const store of sensitiveStores) {
    const storeCode = stripComments(store.analysis_snapshot || store.code_snapshot);
    // If the storage node itself performs encryption, it's safe
    if (ENCRYPT_SAFE_RE.test(storeCode)) continue;

    // Check if an encryption TRANSFORM node feeds into this store
    let hasEncryption = false;
    for (const n of map.nodes) {
      if (n.node_type === 'TRANSFORM' && ENCRYPT_SAFE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))) {
        for (const edge of n.edges) {
          if (edge.target === store.id) {
            hasEncryption = true;
            break;
          }
        }
      }
      if (hasEncryption) break;
    }

    // Check containing function scope
    if (!hasEncryption) {
      const parentFn = findContainingFunction(map, store.id);
      if (parentFn) {
        const parentNode = map.nodes.find(n => n.id === parentFn);
        if (parentNode && ENCRYPT_SAFE_RE.test(stripComments(parentNode.analysis_snapshot || parentNode.code_snapshot))) {
          hasEncryption = true;
        }
      }
    }

    if (!hasEncryption) {
      // Escalate to critical when passwords are involved — they need hashing, not just encryption
      const PASSWORD_RE = /\b(password|passwd|pwd|pass_?word)\b/i;
      const storeCode = stripComments(store.analysis_snapshot || store.code_snapshot);
      const isPassword = PASSWORD_RE.test(storeCode) || PASSWORD_RE.test(store.label) ||
        store.data_in.some(d => PASSWORD_RE.test(d.name));

      findings.push({
        source: nodeRef(store),
        sink: nodeRef(store),
        missing: isPassword
          ? 'TRANSFORM (password hashing — bcrypt, scrypt, or argon2 before storage)'
          : 'TRANSFORM (encryption before storage)',
        severity: isPassword ? 'critical' : 'high',
        description: isPassword
          ? `Password stored in cleartext at ${store.label}. ` +
            `No hashing transform detected before storage. A database breach exposes all user passwords.`
          : `Sensitive data stored in cleartext at ${store.label}. ` +
            `No encryption transform detected before storage. A data breach exposes raw sensitive data.`,
        fix: isPassword
          ? 'Hash passwords with bcrypt, scrypt, or Argon2 before storing. ' +
            'Example: const hashed = await bcrypt.hash(password, 12); db.store(hashed). ' +
            'Never store passwords as plaintext or with reversible encryption.'
          : 'Encrypt sensitive data before writing to storage using AES-256-GCM or similar. ' +
            'Use field-level encryption for database columns containing PII, secrets, or financial data. ' +
            'Example: const encrypted = crypto.createCipheriv("aes-256-gcm", key, iv).update(data).',
        via: 'structural',
      });
    }
  }

  return {
    cwe: 'CWE-312',
    name: 'Cleartext Storage of Sensitive Information',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-313: Cleartext Storage in a File
 * Pattern: Sensitive data written to file STORAGE nodes without encryption
 * Property: Sensitive data written to files must be encrypted
 */
function verifyCWE313(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SENSITIVE_RE = /\b(password|secret|token|api.?key|private.?key|ssn|credit.?card|credentials?)\b/i;
  const FILE_WRITE_RE = /\b(writeFile|writeFileSync|appendFile|createWriteStream|fwrite|file_put_contents|open\s*\(.*['"]w|fprintf|fputs|dump|save|to_file|write_text)\b/i;
  const ENCRYPT_SAFE_RE = /\bencrypt\s*\(|\bAES\b|\bcipher\s*\(|\bcreateCipher\w*\b|\bCryptoJS\b|\bfernet\b|\bgpg\b|\bpgp\b|\b\.seal\s*\(/i;

  // Find file-write STORAGE nodes
  const fileStores = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
     n.attack_surface.includes('file_access') ||
     FILE_WRITE_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const store of fileStores) {
    const code = stripComments(store.analysis_snapshot || store.code_snapshot);
    // Does this file write contain sensitive data?
    const hasSensitive = SENSITIVE_RE.test(code) || SENSITIVE_RE.test(store.label) ||
      store.data_in.some(d => d.sensitivity !== 'NONE' || SENSITIVE_RE.test(d.name));

    if (!hasSensitive) continue;
    if (ENCRYPT_SAFE_RE.test(code)) continue;

    // Check if encryption happens upstream in the containing function
    const parentFn = findContainingFunction(map, store.id);
    if (parentFn) {
      const parentNode = map.nodes.find(n => n.id === parentFn);
      if (parentNode && ENCRYPT_SAFE_RE.test(stripComments(parentNode.analysis_snapshot || parentNode.code_snapshot))) continue;
    }

    findings.push({
      source: nodeRef(store),
      sink: nodeRef(store),
      missing: 'TRANSFORM (encryption before writing sensitive data to file)',
      severity: 'high',
      description: `Sensitive data written to file in cleartext at ${store.label}. ` +
        `Files on disk can be read by other processes, backed up unencrypted, or leaked via misconfigured permissions.`,
      fix: 'Encrypt sensitive data before writing to files. Use AES-256-GCM for field-level encryption. ' +
        'Consider using OS-level encrypted storage or a secrets manager instead of plain files. ' +
        'Set restrictive file permissions (0600) as defense in depth.',
      via: 'structural',
    });
  }

  return {
    cwe: 'CWE-313',
    name: 'Cleartext Storage in a File',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-314: Cleartext Storage in the Registry
 * Pattern: Sensitive data written to registry/system-store nodes without encryption
 * Property: Sensitive data in system registries (Windows Registry, plist, etc.) must be encrypted
 *
 * Note: This is mostly a Windows/.NET CWE but can apply to any key-value system store.
 */
function verifyCWE314(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SENSITIVE_RE = /\b(password|secret|token|api.?key|private.?key|credentials?|license.?key)\b/i;
  const REGISTRY_RE = /\b(Registry|RegKey|HKEY_|RegSetValue|RegCreateKey|reg\.set|winreg|OpenKey|SetValueEx|NSUserDefaults|UserDefaults|SharedPreferences|putString|putExtra|CFPreferences|localStorage\.setItem|sessionStorage\.setItem)\b/i;
  const ENCRYPT_SAFE_RE = /\bencrypt\s*\(|\bAES\b|\bcipher\s*\(|\bcreateCipher\w*\b|\bDPAPI\b|\bProtectedData\b|\bCryptProtectData\b|\bKeychain\b|\bKeyStore\b|\bEncryptedSharedPreferences\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!REGISTRY_RE.test(code)) continue;
    if (!SENSITIVE_RE.test(code) && !node.data_in.some(d => d.sensitivity !== 'NONE')) continue;
    if (ENCRYPT_SAFE_RE.test(code)) continue;

    findings.push({
      source: nodeRef(node),
      sink: nodeRef(node),
      missing: 'TRANSFORM (encryption before storing sensitive data in registry/system store)',
      severity: 'high',
      description: `Sensitive data stored in cleartext in system registry/store at ${node.label}. ` +
        `Registry values are readable by other applications and persist across reboots.`,
      fix: 'Encrypt sensitive values before storing in the registry. On Windows, use DPAPI (ProtectedData.Protect). ' +
        'On macOS/iOS, use Keychain. On Android, use EncryptedSharedPreferences. ' +
        'Never store plaintext passwords or API keys in system registries.',
      via: 'structural',
    });
  }

  return {
    cwe: 'CWE-314',
    name: 'Cleartext Storage in the Registry',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-315: Cleartext Storage of Sensitive Information in a Cookie
 * Pattern: Sensitive data written to cookies without encryption
 * Property: Sensitive data in cookies must be encrypted and use secure flags
 *
 * Detection strategy (three phases):
 *   Phase 1 — Node-level: check cookie-setting nodes for sensitive data directly in their snapshot.
 *   Phase 2 — Scope-trace: for each cookie node, extract the value variable, find its assignments
 *             in sibling nodes within the same function scope, check if those assignments carry
 *             sensitive data without intervening encryption.
 *   Phase 3 — Source-line scan: scan raw source lines for cookie-setting calls whose value
 *             variables trace back to sensitive data (password, credential, token, etc.)
 *             without encryption/hashing between source and sink.
 */
function verifyCWE315(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const reported = new Set<string>(); // dedup by node id or line

  // --- Regexes ---
  const SENSITIVE_RE = /\b(password|secret|token|api.?key|ssn|credit.?card|session.?id|auth.?token|user.?id|email|private.?key|credentials?|getPassword|getSecret)\b/i;
  // Cookie-setting sinks across languages
  const COOKIE_RE = /\b(setCookie|set[_-]?cookie|res\.cookie|response\.cookie|document\.cookie|Set-Cookie|cookies?\.\s*set|setcookie|http\.SetCookie|add_cookie|addCookie|Cookie\s*\(|new\s+Cookie)\b/i;
  const COOKIE_SUBTYPE_RE = /cookie/i;
  // Encryption / hashing safe patterns
  const ENCRYPT_SAFE_RE = /\b(encrypt|decrypt|AES|DES|Blowfish|cipher|createCipher\w*|jwt\.sign|JWS|JWE|MessageDigest|\.digest\b|\.hash\b|hashlib|bcrypt|scrypt|argon2|pbkdf2|SHA-?\d+|MD5|hmac|toHex|Base64\.encode|encode(?:Base64|Hex)|URLEncoder\.encode)\b/i;
  // Extract the value argument from cookie constructors / set calls
  // Java: new Cookie("name", value)  or  cookie.setValue(value)
  // JS:   res.cookie("name", value)  or  document.cookie = "name=" + value
  const COOKIE_VALUE_VAR_RE = /(?:new\s+Cookie\s*\(\s*(?:"[^"]*"|'[^']*'|\w+)\s*,\s*(\w+)|\.setValue\s*\(\s*(\w+)|res\.cookie\s*\(\s*(?:"[^"]*"|'[^']*')\s*,\s*(\w+)|document\.cookie\s*=.*?[+=]\s*(\w+))/i;

  // --- Phase 1: Node-level detection (direct sensitive data in cookie node) ---
  const cookieNodes = map.nodes.filter(n =>
    COOKIE_RE.test(n.analysis_snapshot || n.code_snapshot) ||
    COOKIE_SUBTYPE_RE.test(n.node_subtype) ||
    n.attack_surface.includes('cookie')
  );

  for (const cookie of cookieNodes) {
    if (cookie.node_type === 'STRUCTURAL' && cookie.node_subtype !== 'function') continue;
    const code = stripComments(cookie.analysis_snapshot || cookie.code_snapshot);
    const hasSensitiveDirect = SENSITIVE_RE.test(code) || SENSITIVE_RE.test(cookie.label) ||
      cookie.data_in.some(d => d.sensitivity !== 'NONE' || SENSITIVE_RE.test(d.name));

    if (hasSensitiveDirect) {
      if (ENCRYPT_SAFE_RE.test(code)) continue;
      // Check containing function for encryption
      const parentFn = findContainingFunction(map, cookie.id);
      if (parentFn) {
        const parentNode = map.nodes.find(n => n.id === parentFn);
        if (parentNode && ENCRYPT_SAFE_RE.test(stripComments(parentNode.analysis_snapshot || parentNode.code_snapshot))) continue;
      }
      if (!reported.has(cookie.id)) {
        reported.add(cookie.id);
        findings.push({
          source: nodeRef(cookie),
          sink: nodeRef(cookie),
          missing: 'TRANSFORM (encryption and secure cookie flags)',
          severity: 'high',
          description: `Sensitive data stored in cleartext in a cookie at ${cookie.label}. ` +
            `Cookies are sent with every request and can be intercepted, read by JavaScript, or stolen via XSS.`,
          fix: 'Encrypt sensitive cookie values. Use signed/encrypted cookies (e.g., jwt.sign or cookie-parser with secret). ' +
            'Set flags: httpOnly: true (prevents JS access), secure: true (HTTPS only), sameSite: "strict". ' +
            'Prefer server-side sessions over storing sensitive data in cookies.',
          via: 'structural',
        });
      }
      continue;
    }

    // --- Phase 2: Scope-trace — extract value variable, find its assignment in siblings ---
    const valueVarMatch = COOKIE_VALUE_VAR_RE.exec(code);
    const valueVar = valueVarMatch && (valueVarMatch[1] || valueVarMatch[2] || valueVarMatch[3] || valueVarMatch[4]);
    if (!valueVar) continue;

    // Find the containing function scope
    const parentFnId = findContainingFunction(map, cookie.id);
    if (!parentFnId) continue;

    // Collect sibling nodes in the same function scope
    const siblings = map.nodes.filter(n =>
      n.id !== cookie.id && sharesFunctionScope(map, cookie.id, n.id)
    );

    // Check if valueVar is assigned from sensitive data in any sibling
    const varAssignRE = new RegExp(`\\b${valueVar}\\s*=`, 'i');
    let sensitiveSource: typeof map.nodes[0] | null = null;
    for (const sib of siblings) {
      const sibCode = stripComments(sib.analysis_snapshot || sib.code_snapshot);
      if (varAssignRE.test(sibCode) && SENSITIVE_RE.test(sibCode)) {
        sensitiveSource = sib;
        break;
      }
    }

    if (!sensitiveSource) continue;

    // Check if encryption/hashing happens between source and cookie in this scope
    // Look for encrypt/hash calls that reassign the variable or transform it
    const encryptBeforeCookie = siblings.some(sib => {
      const sibCode = stripComments(sib.analysis_snapshot || sib.code_snapshot);
      // The sibling must both reference the variable AND use encryption
      return (varAssignRE.test(sibCode) || sibCode.includes(valueVar)) && ENCRYPT_SAFE_RE.test(sibCode);
    });

    // Also check for encryption TRANSFORM nodes between source and sink
    const hasEncryptTransform = siblings.some(sib =>
      sib.node_type === 'TRANSFORM' && sib.node_subtype === 'encrypt'
    );

    // If encryption is applied AND the variable is reassigned after encryption, it's safe
    if (encryptBeforeCookie || hasEncryptTransform) continue;

    if (!reported.has(cookie.id)) {
      reported.add(cookie.id);
      findings.push({
        source: nodeRef(sensitiveSource),
        sink: nodeRef(cookie),
        missing: 'TRANSFORM (encryption before cookie storage)',
        severity: 'high',
        description: `Sensitive data from ${sensitiveSource.label} stored in cleartext in a cookie at ${cookie.label}. ` +
          `Variable '${valueVar}' carries credential/sensitive data to the cookie without encryption.`,
        fix: 'Encrypt or hash sensitive cookie values before storage. Use MessageDigest/SHA-256+, AES encryption, ' +
          'or signed cookies (jwt.sign). Set flags: httpOnly, secure, sameSite.',
        via: 'scope_taint',
      });
    }
  }

  // --- Phase 3: Source-line scan — catch patterns the node graph may miss ---
  if (findings.length === 0 && map.source_code) {
    const lines = stripComments(map.source_code).split('\n');
    // Find lines that set cookies
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!COOKIE_RE.test(line)) continue;
      // Extract the value variable from this cookie-setting line
      const valMatch = COOKIE_VALUE_VAR_RE.exec(line);
      const valVar = valMatch && (valMatch[1] || valMatch[2] || valMatch[3] || valMatch[4]);
      if (!valVar) continue;

      // Scan backward from this line to find where valVar is assigned
      let hasSensitiveAssignment = false;
      let hasEncryption = false;
      for (let j = i - 1; j >= 0 && j >= i - 50; j--) {
        const prevLine = lines[j];
        const assignsVar = new RegExp(`\\b${valVar}\\s*=`).test(prevLine);
        if (assignsVar && SENSITIVE_RE.test(prevLine)) {
          hasSensitiveAssignment = true;
        }
        if (ENCRYPT_SAFE_RE.test(prevLine)) {
          hasEncryption = true;
        }
      }

      if (hasSensitiveAssignment && !hasEncryption) {
        const lineKey = `line:${i + 1}`;
        if (!reported.has(lineKey)) {
          reported.add(lineKey);
          findings.push({
            source: { id: 'source-line', label: `line ${i + 1}`, line: i + 1, code: line.trim() },
            sink: { id: 'source-line', label: `line ${i + 1}`, line: i + 1, code: line.trim() },
            missing: 'TRANSFORM (encryption before cookie storage)',
            severity: 'high',
            description: `Sensitive data stored in cleartext cookie at line ${i + 1}. ` +
              `Variable '${valVar}' carries credential/sensitive data to the cookie without encryption or hashing.`,
            fix: 'Encrypt or hash sensitive cookie values before storage. Use MessageDigest/SHA-256+, AES encryption, ' +
              'or signed cookies (jwt.sign). Set flags: httpOnly, secure, sameSite.',
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-315',
    name: 'Cleartext Storage of Sensitive Information in a Cookie',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-316: Cleartext Storage of Sensitive Information in Memory
 * Pattern: Sensitive data held in memory without scrubbing after use
 * Property: Sensitive data (passwords, keys) should be zeroed/cleared from memory when no longer needed
 *
 * Note: This is difficult to detect statically in garbage-collected languages.
 * We focus on the most detectable patterns: logging sensitive data, caching secrets in global scope.
 */
function verifyCWE316(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SECRET_RE = /\b(password|secret|private.?key|api.?key|token|credentials?|auth.?token|encryption.?key)\b/i;
  // Patterns that expose secrets in memory beyond their needed scope
  const MEMORY_EXPOSE_RE = /\bglobal\b|\bwindow\.\b|\bprocess\.\b.*(?:password|secret|key|token)|\bcache\b.*(?:password|secret|key|token)|(?:password|secret|key|token).*\bcache\b|\bstatic\s+(?:final\s+)?(?:String|string)\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)/i;
  // Logging sensitive data is a CWE-316 variant — keeps it in log buffers
  const LOG_EXPOSE_RE = /\b(console\.log|logger?\.\w+|print|puts|System\.out|NSLog|Log\.)\b.*\b(password|secret|key|token|credentials?)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for logging sensitive data
    if (LOG_EXPOSE_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (sensitive data scrubbing before logging)',
        severity: 'medium',
        description: `Sensitive data logged at ${node.label}. ` +
          `Log entries persist in memory buffers, log files, and log aggregation services.`,
        fix: 'Never log passwords, tokens, or secret keys. Redact sensitive fields before logging. ' +
          'Use structured logging with field-level redaction. Example: log({ user: id, password: "[REDACTED]" }).',
        via: 'structural',
      });
      continue;
    }

    // Check for sensitive data cached in global/static scope
    if (SECRET_RE.test(code) && MEMORY_EXPOSE_RE.test(code)) {
      // Skip environment variable reads — those are expected to be in process memory
      if (/\bprocess\.env\b|\bos\.environ\b|\bos\.getenv\b/i.test(code)) continue;

      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (memory scrubbing — clear sensitive data after use)',
        severity: 'medium',
        description: `Sensitive data held in long-lived memory at ${node.label}. ` +
          `Global/static/cached secrets remain in process memory and can be extracted via memory dumps.`,
        fix: 'Minimize the lifetime of sensitive data in memory. Zero buffers after use. ' +
          'In Node.js, use Buffer.alloc() and buf.fill(0) when done. Avoid caching secrets in global scope. ' +
          'In languages with manual memory management, explicitly zero and free secret buffers.',
        via: 'structural',
      });
    }
  }

  return {
    cwe: 'CWE-316',
    name: 'Cleartext Storage of Sensitive Information in Memory',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-319: Cleartext Transmission of Sensitive Information
 *
 * Patterns detected:
 *   A. Sensitive data sent over HTTP (not HTTPS) or via unencrypted network channels
 *   B. Credentials/passwords received from plain TCP sockets, then used in DB
 *      connections or other sensitive sinks without encryption/decryption transform
 *   C. Source-line scanning fallback for Juliet-style patterns: Socket -> readLine ->
 *      password -> DriverManager.getConnection without Cipher transform
 *
 * Property: Sensitive data must be transmitted over encrypted channels (TLS/HTTPS)
 *           OR encrypted/decrypted before use after cleartext receipt.
 */
function verifyCWE319(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SENSITIVE_RE = /\b(password|secret|token|api.?key|ssn|credit.?card|private.?key|auth|credentials?|session)\b/i;
  // HTTP (not HTTPS) URLs — cleartext transmission
  const HTTP_CLEARTEXT_RE = /['"]http:\/\/[^'"]+/i;
  // Network calls that might use cleartext
  const NET_CALL_RE = /\b(fetch|axios|request|http\.get|http\.post|urllib|requests\.\w+|HttpClient|WebClient|curl|XMLHttpRequest|ajax)\b/i;
  // Safe: HTTPS, TLS, SSL
  const TLS_SAFE_RE = /\bhttps:\/\/\b|\bTLS\b|\bSSL\b|\bsecure\s*[:=]\s*true\b|\brejectUnauthorized\b|\bcert\b|\btls\.\b/i;
  // FTP (not SFTP/FTPS)
  const FTP_CLEARTEXT_RE = /['"]ftp:\/\/[^'"]+/i;
  // Telnet
  const TELNET_RE = /\btelnet\b/i;

  // Strategy 1: Find EGRESS/EXTERNAL nodes that transmit data over HTTP
  const netNodes = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL') &&
    (NET_CALL_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     n.node_subtype.includes('http') || n.node_subtype.includes('network') ||
     n.node_subtype.includes('api_call') || n.attack_surface.includes('network'))
  );

  for (const netNode of netNodes) {
    const code = stripComments(netNode.analysis_snapshot || netNode.code_snapshot);

    // Check for explicit HTTP:// URLs (not HTTPS)
    if (HTTP_CLEARTEXT_RE.test(code) && !TLS_SAFE_RE.test(code)) {
      // Does this node handle sensitive data?
      const hasSensitive = SENSITIVE_RE.test(code) || SENSITIVE_RE.test(netNode.label) ||
        netNode.data_in.some(d => d.sensitivity !== 'NONE' || SENSITIVE_RE.test(d.name));

      if (hasSensitive) {
        findings.push({
          source: nodeRef(netNode),
          sink: nodeRef(netNode),
          missing: 'CONTROL (TLS/HTTPS encryption for sensitive data transmission)',
          severity: 'high',
          description: `Sensitive data transmitted over cleartext HTTP at ${netNode.label}. ` +
            `HTTP traffic can be intercepted and read by anyone on the network path (MITM attack).`,
          fix: 'Use HTTPS (TLS) for all endpoints that handle sensitive data. ' +
            'Replace http:// with https:// in all API URLs. Configure HSTS headers. ' +
            'In production, enforce TLS 1.2+ and reject downgrade attempts.',
          via: 'structural',
        });
        continue;
      }
    }

    // Check for FTP (not SFTP)
    if (FTP_CLEARTEXT_RE.test(code) && SENSITIVE_RE.test(code)) {
      findings.push({
        source: nodeRef(netNode),
        sink: nodeRef(netNode),
        missing: 'CONTROL (SFTP/FTPS instead of cleartext FTP)',
        severity: 'high',
        description: `Sensitive data transmitted over cleartext FTP at ${netNode.label}. ` +
          `FTP sends credentials and data in plaintext.`,
        fix: 'Use SFTP or FTPS instead of plain FTP. Never transmit sensitive data over unencrypted channels.',
        via: 'structural',
      });
      continue;
    }

    // Check for telnet
    if (TELNET_RE.test(code) && SENSITIVE_RE.test(code)) {
      findings.push({
        source: nodeRef(netNode),
        sink: nodeRef(netNode),
        missing: 'CONTROL (SSH instead of cleartext Telnet)',
        severity: 'high',
        description: `Sensitive data transmitted over Telnet at ${netNode.label}. ` +
          `Telnet sends all data including passwords in plaintext.`,
        fix: 'Use SSH instead of Telnet. Never use unencrypted protocols for sensitive data.',
        via: 'structural',
      });
    }
  }

  // Strategy 2: Check INGRESS nodes that accept data over HTTP
  const httpIngress = map.nodes.filter(n =>
    n.node_type === 'INGRESS' &&
    HTTP_CLEARTEXT_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
    !TLS_SAFE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );

  for (const ing of httpIngress) {
    const code = stripComments(ing.analysis_snapshot || ing.code_snapshot);
    if (SENSITIVE_RE.test(code) || ing.data_in.some(d => d.sensitivity !== 'NONE')) {
      const already = findings.some(f => f.source.id === ing.id);
      if (!already) {
        findings.push({
          source: nodeRef(ing),
          sink: nodeRef(ing),
          missing: 'CONTROL (HTTPS/TLS for receiving sensitive data)',
          severity: 'high',
          description: `Sensitive data received over cleartext HTTP at ${ing.label}. ` +
            `An attacker on the network can intercept passwords, tokens, and PII in transit.`,
          fix: 'Serve all sensitive endpoints over HTTPS. Redirect HTTP to HTTPS. ' +
            'Use HSTS (Strict-Transport-Security header) to prevent downgrade attacks.',
          via: 'structural',
        });
      }
    }
  }

  // ---- Strategy 3: Graph taint — socket INGRESS -> sensitive STORAGE without crypto TRANSFORM ----
  // Detects: password read from plain TCP socket -> DriverManager.getConnection(url, user, password)
  // without any Cipher/encrypt/decrypt transform in between.
  const PLAIN_SOCKET_RE_319 = /\b(new\s+Socket\s*\(|socket\.getInputStream|ServerSocket|DatagramSocket|SocketChannel\.open)\b/i;
  const SSL_SOCKET_RE_319 = /\b(SSLSocket|SSLSocketFactory|SSLServerSocket|javax\.net\.ssl|SSLContext|SSLEngine)\b/i;
  const DB_CONNECTION_RE_319 = /\b(DriverManager\.getConnection|DataSource\.getConnection|createConnection|mysql\.connect|pg\.connect|MongoClient)\b/i;
  const CRYPTO_TRANSFORM_RE_319 = /\b(Cipher\.\w+|aesCipher|encrypt|decrypt|createCipher|createDecipher|AES|RSA|DES|Blowfish|doFinal|SecretKeySpec|crypto\.subtle)\b/i;

  const socketIngress319 = map.nodes.filter(n =>
    n.node_type === 'INGRESS' && (
      PLAIN_SOCKET_RE_319.test(n.code_snapshot) ||
      PLAIN_SOCKET_RE_319.test(n.analysis_snapshot || '') ||
      n.node_subtype.includes('socket') ||
      n.node_subtype.includes('tcp') ||
      n.node_subtype.includes('network_read') ||
      n.attack_surface.includes('network') ||
      /\breadLine\b|\bgetInputStream\b|\bread\s*\(/.test(n.code_snapshot)
    )
  );

  const credSinks319 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') && (
      DB_CONNECTION_RE_319.test(n.code_snapshot) ||
      DB_CONNECTION_RE_319.test(n.analysis_snapshot || '') ||
      n.node_subtype.includes('db_connect') ||
      n.node_subtype.includes('db_read') ||
      n.node_subtype.includes('sql_query')
    )
  );

  for (const src of socketIngress319) {
    const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
    if (SSL_SOCKET_RE_319.test(srcCode) || TLS_SAFE_RE.test(srcCode)) continue;

    for (const sink of credSinks319) {
      const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      const sinkSensitive = SENSITIVE_RE.test(sinkCode) || SENSITIVE_RE.test(sink.label) ||
        sink.data_in.some(d => d.sensitivity !== 'NONE' || SENSITIVE_RE.test(d.name) || d.tainted);
      if (!sinkSensitive) continue;

      const bfsHit319 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const scopeHit319 = !bfsHit319 && scopeBasedTaintReaches(map, src.id, sink.id);

      if (bfsHit319 || scopeHit319) {
        const scopeSnaps = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnaps.join('\n'));
        if (!CRYPTO_TRANSFORM_RE_319.test(combinedScope)) {
          const already = findings.some(f => f.source.id === src.id && f.sink.id === sink.id);
          if (!already) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'TRANSFORM (encryption/decryption of credentials received over cleartext channel)',
              severity: 'high',
              description: `Sensitive data from cleartext socket at ${src.label} flows to ${sink.label} ` +
                `without encryption. Credentials read over an unencrypted TCP connection are used directly ` +
                `in a database/auth call — an attacker on the network can intercept them (MITM).`,
              fix: 'Use SSLSocket/TLS for the network connection, or decrypt credentials with Cipher ' +
                'before using them. Never transmit passwords over plain TCP sockets.',
              via: bfsHit319 ? 'bfs' : 'scope_taint',
            });
          }
        }
      }
    }
  }

  // ---- Strategy 4: Source-line scanning fallback for Juliet patterns ----
  // Catches: new Socket() -> readLine() -> password -> DriverManager.getConnection(url, user, password)
  // when graph edges are incomplete but source code clearly shows the pattern.
  const src319 = map.source_code || '';
  if (src319 && findings.length === 0) {
    const lines319 = src319.split('\n');
    const allCode319 = stripComments(src319);

    const hasPlainSocket319 = PLAIN_SOCKET_RE_319.test(allCode319) && !SSL_SOCKET_RE_319.test(allCode319);

    if (hasPlainSocket319) {
      // Find lines where sensitive data is read from socket
      const socketReadLines319: number[] = [];
      for (let i = 0; i < lines319.length; i++) {
        const ln = lines319[i];
        if (/^\s*\/\//.test(ln) || /^\s*\*/.test(ln)) continue;
        if (/\breadLine\b|\bread\s*\(/.test(ln)) {
          const assignMatch = ln.match(/^\s*(\w+)\s*=\s*.*(readLine|read\s*\()/);
          if (assignMatch && SENSITIVE_RE.test(assignMatch[1])) {
            socketReadLines319.push(i + 1);
          }
        }
        if (/\breadLine\b|\bread\s*\(|\bgetInputStream\b/.test(ln) && SENSITIVE_RE.test(ln)) {
          if (!socketReadLines319.includes(i + 1)) socketReadLines319.push(i + 1);
        }
      }

      // Find lines where credentials are used in DB connections
      const dbUseLines319: number[] = [];
      for (let i = 0; i < lines319.length; i++) {
        const ln = lines319[i];
        if (/^\s*\/\//.test(ln) || /^\s*\*/.test(ln)) continue;
        if (DB_CONNECTION_RE_319.test(ln) && SENSITIVE_RE.test(ln)) {
          dbUseLines319.push(i + 1);
        }
      }

      if (socketReadLines319.length > 0 && dbUseLines319.length > 0) {
        for (const readLine of socketReadLines319) {
          for (const useLine of dbUseLines319) {
            if (useLine <= readLine) continue;
            const betweenCode = lines319.slice(readLine - 1, useLine).join('\n');
            if (!CRYPTO_TRANSFORM_RE_319.test(betweenCode)) {
              const srcNode = map.nodes.find(n => Math.abs(n.line_start - readLine) <= 2) || map.nodes[0];
              const sinkNode = map.nodes.find(n => Math.abs(n.line_start - useLine) <= 2) || map.nodes[0];
              if (srcNode && sinkNode) {
                const already = findings.some(f =>
                  Math.abs(f.source.line - readLine) <= 3 && Math.abs(f.sink.line - useLine) <= 3);
                if (!already) {
                  findings.push({
                    source: nodeRef(srcNode),
                    sink: nodeRef(sinkNode),
                    missing: 'TRANSFORM (encryption of password received over cleartext TCP socket)',
                    severity: 'high',
                    description: `Password read from cleartext TCP socket (L${readLine}) used directly ` +
                      `in database connection (L${useLine}) without encryption. An attacker who intercepts ` +
                      `the TCP stream obtains the database password in plaintext.`,
                    fix: 'Use SSLSocket instead of plain Socket for receiving credentials. ' +
                      'Alternatively, decrypt the password with Cipher before passing to getConnection(). ' +
                      'Never transmit credentials over unencrypted channels.',
                    via: 'source_line_fallback',
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-319',
    name: 'Cleartext Transmission of Sensitive Information',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-209: Generation of Error Message Containing Sensitive Information
 * Pattern: Error/catch blocks expose stack traces, internal paths, DB errors in responses.
 * The sink must be an EGRESS node — this is about returning error details to users.
 */
function verifyCWE209(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ERROR_SOURCE_RE = /\b(catch\s*\(|\.catch\s*\(|on_error|onerror|error_handler|rescue|except\s|Exception|Error\b.*\bmessage|err\.stack|error\.stack|stackTrace|traceback|e\.getMessage|err\.toString|exception\.toString)\b/i;
  const LEAK_RE = /\b(stack|stackTrace|traceback|\.message|\.stack|toString\(\)|getMessage|getStackTrace|print_r\s*\(\s*\$e|var_dump|format_exc|exc_info|InnerException|DetailedError|internalError)\b/i;
  const SAFE_RE = /\b(generic.?error|sanitize.?error|safe.?error|error.?code|status.?code|error.?id|obfuscate|redact|custom.?error|err\.code\b|error\.code\b|HTTP.?(4|5)\d\d|statusCode|new\s+(AppError|HttpError|ApiError|CustomError))\b/i;
  // Only client-facing egress is the CWE-209 attack surface; server-side logging is safe.
  const CLIENT_EGRESS_RE = /\b(res\.send|res\.json|res\.render|res\.write|res\.end|res\.status|response\.send|response\.json|wfile\.write|self\.wfile|HttpResponse|JsonResponse|render_template|echo\s+|print\s+|printf|cout)\b/i;
  const LOG_SINK_RE = /\b(console\.(error|warn|log|debug|info)|logger\.(error|warn|info|debug)|log\.(error|warn|info|debug)|winston\.|bunyan\.|pino\.|syslog\.)\b/i;

  const errorNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'CONTROL' || n.node_type === 'STRUCTURAL' || n.node_type === 'EGRESS') &&
    ERROR_SOURCE_RE.test(n.analysis_snapshot || n.code_snapshot)
  );
  const egress = nodesOfType(map, 'EGRESS');

  for (const errNode of errorNodes) {
    for (const sink of egress) {
      const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      // Skip logging sinks — server-side logging of errors is correct practice, not a vulnerability.
      if (LOG_SINK_RE.test(sinkCode)) continue;
      if (errNode.id === sink.id) {
        const code = sinkCode;
        if (LEAK_RE.test(code) && !SAFE_RE.test(code) && CLIENT_EGRESS_RE.test(code)) {
          findings.push({ source: nodeRef(errNode), sink: nodeRef(sink), missing: 'TRANSFORM (error message sanitization before response)', severity: 'medium',
            description: `Error handler at ${errNode.label} exposes detailed error information (stack traces, internal messages) in the response.`,
            fix: 'Return generic error messages to users. Log detailed errors server-side. Use error codes instead of raw exception messages.',
            via: 'structural' });
        }
        continue;
      }
      if (hasPathWithoutControl(map, errNode.id, sink.id)) {
        const errCode = stripComments(errNode.analysis_snapshot || errNode.code_snapshot);
        if (LEAK_RE.test(errCode) && !SAFE_RE.test(sinkCode) && CLIENT_EGRESS_RE.test(sinkCode)) {
          findings.push({ source: nodeRef(errNode), sink: nodeRef(sink), missing: 'TRANSFORM (error message sanitization before response)', severity: 'medium',
            description: `Error handler at ${errNode.label} sends detailed error info to ${sink.label}. Stack traces or DB error messages may be exposed.`,
            fix: 'Return generic error messages to users. Log detailed errors server-side. Use error codes instead of raw exception messages.',
            via: 'bfs' });
        }
      }
    }
  }
  // ---------------------------------------------------------------------------
  // Java-specific: detect printStackTrace() in catch blocks (Juliet CWE-209 pattern)
  // In Java, printStackTrace() writes stack trace to stderr/stdout — it IS the leak.
  // Also detect catch blocks that expose exception details via response writers.
  // ---------------------------------------------------------------------------
  if (inferMapLanguage(map) === 'java') {
    const JAVA_PRINTSTACKTRACE_RE = /\.printStackTrace\s*\(/;
    const JAVA_CATCH_BLOCK_RE = /\bcatch\s*\(/;
    // JAVA_GENERIC_MSG_RE: string-only output = safe (reserved for future use)
    // /\b(IO\.writeLine|writeLine|println)\s*\(\s*"[^"]*"\s*\)/

    for (const node of map.nodes) {
      const code = node.analysis_snapshot || node.code_snapshot;
      if (!code) continue;
      // Pattern 1: catch block with printStackTrace() — classic Juliet bad sink
      if (JAVA_CATCH_BLOCK_RE.test(code) && JAVA_PRINTSTACKTRACE_RE.test(code)) {
        // Check if this is a "good" variant that only prints generic messages
        // Good pattern: catch block with ONLY generic string output, no printStackTrace
        const catchSection = code.match(/catch\s*\([^)]*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/s);
        if (catchSection) {
          const catchBody = catchSection[1];
          if (JAVA_PRINTSTACKTRACE_RE.test(catchBody)) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(node),
              missing: 'TRANSFORM (error message sanitization — do not call printStackTrace())',
              severity: 'medium',
              description: `Catch block at ${node.label} calls printStackTrace(), exposing full stack trace including internal class names, file paths, and line numbers.`,
              fix: 'Log exceptions server-side with a logging framework. Return generic error messages to users. Never call printStackTrace() in production code.',
              via: 'structural',
            });
          }
        }
      }
      // Pattern 2: catch block that sends exception.getMessage() or exception.toString() to response
      if (JAVA_CATCH_BLOCK_RE.test(code) &&
          /\b(getMessage|getStackTrace|toString)\s*\(/.test(code) &&
          /\b(response\.getWriter|res\.getWriter|out\.print|out\.write|println|getOutputStream)\b/.test(code) &&
          !SAFE_RE.test(code)) {
        const alreadyReported = findings.some(f => f.source.id === node.id);
        if (!alreadyReported) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'TRANSFORM (error message sanitization before response)',
            severity: 'medium',
            description: `Catch block at ${node.label} sends exception details to the HTTP response, exposing internal error information.`,
            fix: 'Return generic error messages to users. Log detailed errors server-side using a logging framework.',
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-209', name: 'Error Message Information Exposure', holds: findings.length === 0, findings };
}

/**
 * CWE-215: Insertion of Sensitive Information Into Debugging Code
 * Pattern: Debug constructs (debugger, var_dump, binding.pry, debug=true) left in production
 * without environment gating.
 */
function verifyCWE215(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const DEBUG_RE = /\b(debug\s*[:=]\s*true|DEBUG\s*[:=]\s*true|verbose\s*[:=]\s*true|NODE_ENV\s*[!=]==?\s*['"]development|FLASK_DEBUG|DJANGO_DEBUG|app\.debug|WP_DEBUG|XDEBUG|var_dump|print_r|Data\.Dumper|pp\s|pry\b|binding\.pry|byebug|debugger\b|console\.dir|inspect\b.*\bdepth|util\.inspect|Debug\.Print|Debugger\.Break|System\.Diagnostics\.Debug)\b/i;
  const SENSITIVE_DEBUG_RE = /\b(password|secret|token|key|credential|auth|session|cookie|api.?key|private)\b/i;
  const SAFE_RE = /\b(if\s*\(\s*process\.env\.NODE_ENV\s*[!=]==?\s*['"]production|isProduction|isProd|NODE_ENV\s*[!=]==?\s*['"]production|ifdef\s+DEBUG|#if\s+DEBUG|when\s*\(\s*debug|debug.?guard|assert\b)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const isEnvGate = (map.story ?? []).some(s =>
      s.templateKey === 'gate-conditional' &&
      s.nodeId === node.id &&
      /NODE_ENV|RAILS_ENV|FLASK_ENV|APP_ENV/.test(s.slots?.subject ?? '')
    );
    const isInsideEnvGate = (map.story ?? []).some(s =>
      s.templateKey === 'gate-conditional' &&
      /NODE_ENV/.test(s.slots?.subject ?? '') &&
      parseInt(s.slots?.gate_start_line ?? '0') <= node.line_start &&
      parseInt(s.slots?.gate_end_line ?? '0') >= node.line_end
    );
    if (DEBUG_RE.test(code) && !SAFE_RE.test(code) && !isEnvGate && !isInsideEnvGate) {
      const hasSensitive = SENSITIVE_DEBUG_RE.test(code);
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (production environment gate for debug code)',
        severity: hasSensitive ? 'high' : 'medium',
        description: `Debug code at ${node.label} is not gated by environment check. ` + (hasSensitive ? 'Debug output references sensitive data (credentials, tokens, keys).' : 'Diagnostic output may expose internal state in production.'),
        fix: 'Remove debug code before deployment, or gate behind environment checks: if (process.env.NODE_ENV !== "production") { ... }.',
        via: 'structural' });
    }
  }
  return { cwe: 'CWE-215', name: 'Insertion of Sensitive Info Into Debug Code', holds: findings.length === 0, findings };
}

/**
 * CWE-497: Exposure of Sensitive System Information to Unauthorized Actor
 * Pattern: System internals (OS version, internal IPs, file paths) leaked via responses.
 * Different from CWE-200 — this specifically targets SYSTEM information.
 */
function verifyCWE497(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SYSINFO_RE = /\b(os\.(platform|arch|release|hostname|cpus|networkInterfaces|userInfo|homedir|tmpdir)|process\.(version|pid|ppid|cwd|env|arch|platform|execPath|argv)|sys\.(version|platform|executable|path)|platform\.(system|node|release|version|machine|processor)|socket\.gethostname|getfqdn|uname|System\.Environment|Environment\.(OSVersion|MachineName|ProcessorCount|UserName)|Server\.MapPath|__FILE__|__DIR__|__LINE__|server_info|phpinfo|php_uname|get_include_path|sys_get_temp_dir)\b/i;
  const HEADER_RE = /\b(X-Powered-By|Server:|x-aspnet-version|x-runtime|x-version|X-Generator|X-Drupal|x-debug-token)\b/i;
  const INTERNAL_NET_RE = /\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.0\.0\.1|localhost:\d+|internal\..*\.com|\.local\b|intranet)\b/i;
  const egress = nodesOfType(map, 'EGRESS');

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!(SYSINFO_RE.test(code) || HEADER_RE.test(code) || INTERNAL_NET_RE.test(code))) continue;
    if (node.node_type === 'EGRESS') {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (system information filtering before response)', severity: 'medium',
        description: `Response at ${node.label} exposes system information (OS details, server version, internal paths, or internal network addresses).`,
        fix: 'Remove system information from responses. Disable X-Powered-By headers. Use helmet.hidePoweredBy() or equivalent.',
        via: 'structural' });
      continue;
    }
    for (const sink of egress) {
      if (node.id === sink.id) continue;
      if (hasPathWithoutControl(map, node.id, sink.id)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(sink), missing: 'CONTROL (system information filtering before response)', severity: 'medium',
          description: `System information from ${node.label} flows to response at ${sink.label}. OS details or internal network addresses may be exposed.`,
          fix: 'Remove system information from responses. Strip X-Powered-By and Server headers.',
          via: 'bfs' });
        break;
      }
    }
  }
  return { cwe: 'CWE-497', name: 'Exposure of Sensitive System Information', holds: findings.length === 0, findings };
}

/**
 * CWE-532: Insertion of Sensitive Information into Log File
 * Pattern: Sensitive data (passwords, tokens, PII) written to log files/console.
 * Different from CWE-117 (log injection from user input) — this is about the APPLICATION
 * itself logging its own sensitive data.
 */
function verifyCWE532(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SENSITIVE_RE = /\b(password|passwd|pwd|secret|token|api.?key|apikey|private.?key|access.?token|refresh.?token|bearer|authorization|session.?id|sessionId|credit.?card|cardNumber|cvv|ssn|social.?security)\b/i;
  const LOG_SINK_RE = /\b(console\.(log|warn|error|info|debug|trace)|logger\.|log\.(info|warn|error|debug|fatal|Printf|Println)|println|print\s*\(|System\.out\.print|System\.err\.print|NSLog|os_log|error_log|syslog|trigger_error|Logger\.(info|warn|error|debug|fatal)|winston|bunyan|pino|Console\.Write|ILogger|_logger\.|logging\.(info|warning|error|debug|critical)|fmt\.Print|fmt\.Fprint|writeLog|appendFile.*log)\b/i;
  const SAFE_RE = /\b(mask|redact|sanitize|censor|\*{3,}|replace\(.*\*|slice\s*\(\s*0\s*,\s*[0-4]\s*\)|substring\s*\(\s*0\s*,\s*[0-4]\s*\)|\.replace\(.*\.{3}|omit|filter.?fields|exclude.?fields|safe.?log|scrub)\b/i;

  const logSinks = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('log') || n.node_subtype.includes('audit') || n.attack_surface.includes('logging') || LOG_SINK_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const sink of logSinks) {
    const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
    if (SENSITIVE_RE.test(code) && !SAFE_RE.test(code)) {
      findings.push({ source: nodeRef(sink), sink: nodeRef(sink), missing: 'TRANSFORM (sensitive data redaction before logging)', severity: 'high',
        description: `Log statement at ${sink.label} directly references sensitive data (passwords, tokens, keys). Log files are often accessible to operators and monitoring systems.`,
        fix: 'Never log sensitive data. Mask/redact before logging: logger.info("Login", { user: email, password: "***" }). Use structured logging with field-level filtering.',
        via: 'structural' });
    }
  }

  const sensitiveStores = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'INGRESS') &&
    (n.data_out.some(d => d.sensitivity !== 'NONE') || SENSITIVE_RE.test(n.analysis_snapshot || n.code_snapshot) || SENSITIVE_RE.test(n.label))
  );
  for (const src of sensitiveStores) {
    for (const sink of logSinks) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!SAFE_RE.test(sinkCode) && !findings.some(f => f.sink.id === sink.id)) {
          findings.push({ source: nodeRef(src), sink: nodeRef(sink), missing: 'TRANSFORM (sensitive data redaction before logging)', severity: 'high',
            description: `Sensitive data from ${src.label} flows to log at ${sink.label} without redaction. Credentials, tokens, or PII may persist in log files.`,
            fix: 'Redact sensitive fields before logging. Use a logging middleware that automatically masks fields like password, token, authorization.',
            via: 'bfs' });
        }
      }
    }
  }
  return { cwe: 'CWE-532', name: 'Insertion of Sensitive Info Into Log File', holds: findings.length === 0, findings };
}

/**
 * CWE-538: Insertion of Sensitive Information Into Externally-Accessible File or Directory
 * Pattern: Sensitive data written to files in web-accessible directories (public/, static/, wwwroot/).
 * The file LOCATION matters — writing to public-serving directories is the vulnerability.
 */
function verifyCWE538(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PUBLIC_PATH_RE = /\b(public|static|www|wwwroot|htdocs|web|assets|uploads|tmp|temp|var\/www|DocumentRoot|webroot|dist|build|out)\b[/\\]/i;
  const FILE_WRITE_RE = /\b(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|fwrite|file_put_contents|fopen.*[wa]|open\(.*[wa]|dump|save|export|serialize|pickle\.dump|json\.dump|yaml\.dump|Marshal\.dump|File\.(write|open|new)|io\.open|os\.open)\b/i;
  const SENSITIVE_RE = /\b(password|secret|token|key|credential|config|database|connection.?string|dsn|private|certificate|\.pem|\.key|\.env|backup|dump|export)\b/i;
  const SAFE_RE = /\b(encrypt|cipher|protected|\.gitignore|deny\s+from\s+all|private.?dir|access.?control|auth.?required|htaccess)\b/i;

  const fileWriters = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('file') || n.node_subtype.includes('write') || FILE_WRITE_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const writer of fileWriters) {
    const code = stripComments(writer.analysis_snapshot || writer.code_snapshot);
    if (PUBLIC_PATH_RE.test(code) && (SENSITIVE_RE.test(code) || writer.data_in.some(d => d.sensitivity !== 'NONE')) && !SAFE_RE.test(code)) {
      findings.push({ source: nodeRef(writer), sink: nodeRef(writer), missing: 'CONTROL (write sensitive data outside web-accessible directories)', severity: 'high',
        description: `File write at ${writer.label} places sensitive data in a web-accessible directory. Files in public/static/uploads may be directly retrievable.`,
        fix: 'Store sensitive files outside the web root. Use application-level access controls for file downloads. Never write config or credential files to public directories.',
        via: 'structural' });
    }
  }

  const sensitiveStores = map.nodes.filter(n => n.data_out.some(d => d.sensitivity !== 'NONE') || SENSITIVE_RE.test(n.analysis_snapshot || n.code_snapshot));
  for (const src of sensitiveStores) {
    for (const writer of fileWriters) {
      if (src.id === writer.id) continue;
      const writerCode = stripComments(writer.analysis_snapshot || writer.code_snapshot);
      if (PUBLIC_PATH_RE.test(writerCode) && !SAFE_RE.test(writerCode) && hasPathWithoutControl(map, src.id, writer.id) && !findings.some(f => f.sink.id === writer.id)) {
        findings.push({ source: nodeRef(src), sink: nodeRef(writer), missing: 'CONTROL (prevent sensitive data from reaching public directories)', severity: 'high',
          description: `Sensitive data from ${src.label} flows to file write at ${writer.label} in a public directory.`,
          fix: 'Write sensitive files outside the web root, or use access-controlled download endpoints.',
          via: 'bfs' });
      }
    }
  }
  return { cwe: 'CWE-538', name: 'Insertion of Sensitive Info Into Externally-Accessible File', holds: findings.length === 0, findings };
}

/**
 * CWE-540: Inclusion of Sensitive Information in Source Code
 * Pattern: Hardcoded sensitive values (API keys, connection strings, private keys) in source.
 * Broader than CWE-798 — covers connection strings, PEM blocks, embedded API keys in URLs.
 */
function verifyCWE540(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const HARDCODED_RE = /(['"`](?:(?:mongodb|mysql|postgres|redis|amqp|smtp):\/\/[^'"`]*(?:password|pass|pwd|secret|key)[^'"`]*|(?:sk|pk|rk|ak)[-_][a-zA-Z0-9]{20,}|(?:AKIA|AIza|ghp_|gho_|glpat-|xox[bsp]-|sk-)[A-Za-z0-9_-]{10,}|-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----|[A-Za-z0-9+/]{40,}={0,2})['"`])/i;
  const INLINE_SECRET_RE = /\b(api.?key|apikey|secret.?key|access.?key|private.?key|encryption.?key|signing.?key|db.?password|database.?password|connection.?string|jwt.?secret|auth.?token)\s*[:=]\s*['"`][^'"`]{8,}['"`]/i;
  const SAFE_RE = /\b(process\.env|os\.environ|os\.getenv|ENV\[|System\.getenv|getenv|config\.|vault\.|secretManager|parameterStore|keyVault|AWS\.SSM|dotenv|configparser|\.env\b|environment\.|settings\.)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if ((HARDCODED_RE.test(code) || INLINE_SECRET_RE.test(code)) && !SAFE_RE.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (externalize secrets to environment variables or secret manager)', severity: 'high',
        description: `Source code at ${node.label} contains hardcoded sensitive values (API keys, connection strings, or cryptographic material). Source code is stored in version control and accessible to all developers.`,
        fix: 'Move secrets to environment variables or a secret manager (AWS Secrets Manager, HashiCorp Vault). Rotate any secrets committed to version control.',
        via: 'structural' });
    }
  }
  return { cwe: 'CWE-540', name: 'Inclusion of Sensitive Info in Source Code', holds: findings.length === 0, findings };
}

/**
 * CWE-548: Exposure of Information Through Directory Listing
 * Pattern: Web server configured to serve directory listings (autoindex on, Options +Indexes).
 * Configuration issue — detected via express.static, nginx autoindex, Apache Options.
 */
function verifyCWE548(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const DIR_LISTING_RE = /\b(autoindex\s+on|Options\s+\+?Indexes|directory.?listing|serve-index|serveIndex|expressStaticGzip.*index|DirectoryBrowsing|browse\s*[:=]\s*true|listObjects|ListBucket|enable_static_file_listing|showDirectoryListing)\b/i;
  const SAFE_RE = /\b(index\s*:\s*false|dotfiles\s*:\s*['"]deny|Options\s+-Indexes|autoindex\s+off|DirectoryBrowsing\s*=\s*false|listing\s*[:=]\s*false|no.?listing|disable.?browse)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (DIR_LISTING_RE.test(code) && !SAFE_RE.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (disable directory listing)', severity: 'medium',
        description: `Configuration at ${node.label} enables directory listing. Attackers can enumerate files, discovering backups, config files, and hidden endpoints.`,
        fix: 'Disable directory listing: Options -Indexes (Apache), autoindex off (nginx), remove serve-index middleware (Express).',
        via: 'structural' });
    }
  }
  return { cwe: 'CWE-548', name: 'Exposure of Info Through Directory Listing', holds: findings.length === 0, findings };
}

/**
 * CWE-550: Server-Generated Error Message Containing Sensitive Information
 * Pattern: Server frameworks configured to show detailed error pages in production.
 * Different from CWE-209 (app code) — this is about SERVER/FRAMEWORK error page configuration.
 */
function verifyCWE550(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const VERBOSE_ERROR_RE = /\b(DEBUG\s*[:=]\s*True|FLASK_DEBUG\s*[:=]\s*1|app\.debug\s*[:=]\s*true|showDetailedError|detailed.?errors?\s*[:=]\s*true|customErrors\s+mode\s*[:=]\s*["']Off|<customErrors\s+mode\s*=\s*"Off"|errorHandler\s*\(\s*\{[^}]*stack\b|express\.errorHandler|show_errors\s*[:=]\s*true|DisplayErrors\s*[:=]\s*(?:On|1|true)|DISPLAY_ERRORS|error_reporting\s*\(\s*E_ALL|expose_php\s*[:=]\s*(?:On|1)|ServerError.*stack|err\.stack|traceback.*response|format_exc.*response|development.?mode|devMode\s*[:=]\s*true)\b/i;
  const SAFE_RE = /\b(NODE_ENV\s*[!=]==?\s*['"]production|isProduction|isProd|DEBUG\s*[:=]\s*False|app\.debug\s*[:=]\s*false|customErrors\s+mode\s*[:=]\s*["'](?:RemoteOnly|On)|custom.?error.?page|error.?template|generic.?error)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (VERBOSE_ERROR_RE.test(code) && !SAFE_RE.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (disable detailed error pages in production)', severity: 'medium',
        description: `Server configuration at ${node.label} enables detailed error pages. Framework error pages expose stack traces, source paths, DB queries, and environment variables.`,
        fix: 'Disable debug error pages in production: DEBUG=False (Django), NODE_ENV=production (Express), customErrors mode="RemoteOnly" (.NET). Use custom error pages.',
        via: 'structural' });
    }
  }
  return { cwe: 'CWE-550', name: 'Server-Generated Error Message Info Leak', holds: findings.length === 0, findings };
}

/**
 * CWE-598: Use of GET Request Method With Sensitive Query Strings
 * Pattern: Sensitive data (passwords, tokens) passed as GET query parameters, exposing them
 * in URLs, server logs, referer headers, and browser history.
 */
function verifyCWE598(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const GET_SENSITIVE_RE = /\b(GET\s+.*[?&](password|token|secret|key|ssn|credit|card)|[?&](password|passwd|pwd|token|secret|api.?key|access.?token|session|auth)=|req\.query\.(password|token|secret|key|auth|session)|request\.GET\[['"](?:password|token|secret|key)|params\[['"](?:password|token|secret)|search[Pp]arams\.get\s*\(\s*['"](?:password|token|secret|key|auth)|\$_GET\s*\[\s*['"](?:password|token|secret|key|auth))\b/i;
  const GET_FORM_RE = /method\s*[:=]\s*['"]GET['"].*(?:password|token|secret|key)|action\s*[:=].*\?(?:password|token|secret)/i;
  const FETCH_GET_RE = /\b(fetch|axios\.get|http\.get|requests\.get|GET)\s*\(\s*['"`].*[?&](password|token|secret|key|auth|session)=/i;
  const ingress = nodesOfType(map, 'INGRESS');

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (GET_SENSITIVE_RE.test(code) || GET_FORM_RE.test(code) || FETCH_GET_RE.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (use POST method for sensitive data)', severity: 'medium',
        description: `Code at ${node.label} transmits sensitive data via GET query parameters. Query strings are logged by web servers, proxies, and browsers.`,
        fix: 'Use POST requests with data in the request body for sensitive fields. Never put credentials or PII in URLs. For APIs, send sensitive data in headers (Authorization) or POST body.',
        via: 'structural' });
    }
  }
  for (const src of ingress) {
    const code = stripComments(src.analysis_snapshot || src.code_snapshot);
    if (/\b(app\.get|router\.get|@app\.route.*methods.*GET|GET\s+\/|@GetMapping|@RequestMapping.*GET)\b/i.test(code) &&
        /\b(password|token|secret|key|credential|ssn|credit.?card)\b/i.test(code) &&
        !findings.some(f => f.source.id === src.id)) {
      findings.push({ source: nodeRef(src), sink: nodeRef(src), missing: 'CONTROL (use POST method for routes handling sensitive data)', severity: 'medium',
        description: `GET route at ${src.label} accepts sensitive parameters. GET parameters appear in server logs, browser history, and Referer headers.`,
        fix: 'Change to POST endpoint for sensitive data. Use req.body instead of req.query for credentials.',
        via: 'structural' });
    }
  }
  // ---------------------------------------------------------------------------
  // Java-specific: detect <form method="get"> with password fields (Juliet CWE-598)
  // Juliet pattern: response.getWriter().println("<form ... method=\"get\" ...>");
  // with an <input ... type=\"password\" ...> field
  // ---------------------------------------------------------------------------
  if (inferMapLanguage(map) === 'java') {
    const JAVA_GET_FORM_RE = /method\s*=\s*\\?"get\\?"/i;
    const JAVA_PASSWORD_FIELD_RE = /type\s*=\s*\\?"password\\?"/i;

    for (const node of map.nodes) {
      const code = node.analysis_snapshot || node.code_snapshot;
      if (!code) continue;
      // Check function bodies for the pattern: GET form + password field
      if (JAVA_GET_FORM_RE.test(code) && JAVA_PASSWORD_FIELD_RE.test(code)) {
        if (!findings.some(f => f.source.id === node.id)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (use POST method for forms with password fields)',
            severity: 'medium',
            description: `Code at ${node.label} generates an HTML form using GET method with a password field. Passwords will appear in the URL, browser history, server logs, and Referer headers.`,
            fix: 'Change the form method to POST. Sensitive data like passwords should never be transmitted as URL query parameters.',
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-598', name: 'Use of GET Request Method With Sensitive Query Strings', holds: findings.length === 0, findings };
}

/**
 * CWE-615: Inclusion of Sensitive Information in Source Code Comments
 * Pattern: Comments containing credentials, TODOs with passwords, internal URLs.
 * Explicitly targets COMMENTS — we extract comments and scan them (inverse of stripComments).
 */
function verifyCWE615(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const COMMENT_SENSITIVE_RE = /\b(password\s*[:=]\s*\S+|passwd\s*[:=]\s*\S+|secret\s*[:=]\s*\S+|token\s*[:=]\s*\S+|api.?key\s*[:=]\s*\S+|TODO.*password|FIXME.*credential|HACK.*auth|temporary.*password|default.*password|test.*password|admin.*password|root.*password|username.*[:=].*password|(?:mongodb|mysql|postgres|redis|amqp):\/\/\w+:\w+@|(?:sk|pk|ak)[-_][a-zA-Z0-9]{16,}|(?:AKIA|ghp_|gho_|glpat-|xox[bsp]-|sk-)[A-Za-z0-9]{8,})\b/i;

  function extractComments(code: string): string {
    const comments: string[] = [];
    let i = 0;
    const len = code.length;
    while (i < len) {
      const ch = code[i];
      const next = i + 1 < len ? code[i + 1] : '';
      if (ch === '"' || ch === "'" || ch === '`') {
        const quote = ch; i++;
        while (i < len) { if (code[i] === '\\') { i += 2; continue; } if (code[i] === quote) { i++; break; } i++; }
        continue;
      }
      if (ch === '/' && next === '*') {
        i += 2; let c = '';
        while (i < len) { if (code[i] === '*' && i + 1 < len && code[i + 1] === '/') { i += 2; break; } c += code[i]; i++; }
        comments.push(c); continue;
      }
      if (ch === '/' && next === '/') {
        i += 2; let c = '';
        while (i < len && code[i] !== '\n') { c += code[i]; i++; }
        comments.push(c); continue;
      }
      if (ch === '#') {
        i++; let c = '';
        while (i < len && code[i] !== '\n') { c += code[i]; i++; }
        comments.push(c); continue;
      }
      i++;
    }
    return comments.join('\n');
  }

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    const commentText = extractComments(code);
    if (commentText.length > 0 && COMMENT_SENSITIVE_RE.test(commentText)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (remove sensitive information from source code comments)', severity: 'medium',
        description: `Comments at ${node.label} contain sensitive information (credentials, API keys, internal URLs, or TODO items with passwords). Comments persist in version control and may be served to clients in JS bundles.`,
        fix: 'Remove all credentials, API keys, and internal URLs from comments. Use a secrets manager. Run pre-commit hooks (e.g., detect-secrets) to catch secrets in comments.',
        via: 'structural' });
    }

    // Check for HTML comments with credentials embedded in string literals sent to output
    // Pattern: "<!--password = xxx-->" or "<!-- username: foo, password: bar -->"
    const HTML_COMMENT_CREDS_RE = /<!--[^>]*\b(password|passwd|secret|token|api.?key|username\s*=\s*\w+[^>]*password|DB\s+password|DB\s+username)[^>]*-->/i;
    if (HTML_COMMENT_CREDS_RE.test(code) && /\b(write|print|println|send|render|getWriter|response\.|res\.|out\.)\b/i.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (no sensitive data in HTML comments sent to clients)',
        severity: 'medium',
        description: `HTML comment at ${node.label} contains sensitive information (credentials, passwords) that will be sent to the client. ` +
          `HTML comments are visible in browser "View Source" and can be harvested by attackers.`,
        fix: 'Remove all credentials from HTML comments. Never embed passwords, API keys, or database credentials ' +
          'in HTML output, even inside comments. Use server-side configuration for sensitive values.',
        via: 'structural' });
    }
  }
  return { cwe: 'CWE-615', name: 'Inclusion of Sensitive Info in Source Code Comments', holds: findings.length === 0, findings };
}

/**
 * CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
 * Focuses on PII (SSN, health data, financial records) flowing to logs,
 * third-party analytics, or API responses without redaction.
 */
function verifyCWE359(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PII_RE = /\b(ssn|social[_-]?security|date[_-]?of[_-]?birth|dob|passport[_-]?number|driver[_-]?license|national[_-]?id|tax[_-]?id|medical[_-]?record|health[_-]?data|diagnosis|prescription|salary|bank[_-]?account|routing[_-]?number|credit[_-]?score|biometric|fingerprint|facial[_-]?recognition|phone[_-]?number|home[_-]?address|email[_-]?address|maiden[_-]?name|ethnicity|religion|sexual[_-]?orientation|disability|genetic[_-]?data)\b/i;
  const REDACT_RE = /\bredact\s*\(|\bmask\s*\(|\banonymize\s*\(|\bpseudonymize\s*\(|\bhash\s*\(|\bencrypt\s*\(|\btokenize\s*\(|\bstrip[_-]?pii\b|\bsanitize[_-]?pii\b|\bremoveSensitive\b|\b\*{3,}\b|\bX{3,}\b/i;

  const piiNodes = map.nodes.filter(n =>
    n.data_out.some(d => d.sensitivity === 'PII') || PII_RE.test(n.analysis_snapshot || n.code_snapshot)
  );

  const logNodes = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    /\b(log|logger|console|syslog|winston|bunyan|pino|datadog|sentry|bugsnag|newrelic|analytics)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );

  const thirdPartyNodes = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('analytics') || n.node_subtype.includes('tracking') ||
     n.node_subtype.includes('third_party') || n.node_subtype.includes('marketing') ||
     /\b(analytics|tracking|pixel|segment|mixpanel|amplitude|google[_-]?analytics|facebook|fbevents|gtag|adwords)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  const egressNodes = nodesOfType(map, 'EGRESS');

  for (const pii of piiNodes) {
    for (const log of logNodes) {
      if (hasPathWithoutControl(map, pii.id, log.id)) {
        if (!REDACT_RE.test(stripComments(log.analysis_snapshot || log.code_snapshot))) {
          findings.push({
            source: nodeRef(pii), sink: nodeRef(log),
            missing: 'TRANSFORM (PII redaction before logging)',
            severity: 'high',
            description: `PII from ${pii.label} flows to logging at ${log.label} without redaction. ` +
              `Log systems are often less secured, exposing PII to wider audiences.`,
            fix: 'Redact or mask PII before logging. Use opaque identifiers for correlation. ' +
              'Never log full SSN, health data, or financial account numbers.',
            via: 'bfs',
          });
        }
      }
    }

    for (const tp of thirdPartyNodes) {
      if (hasPathWithoutControl(map, pii.id, tp.id)) {
        if (!REDACT_RE.test(stripComments(tp.analysis_snapshot || tp.code_snapshot))) {
          findings.push({
            source: nodeRef(pii), sink: nodeRef(tp),
            missing: 'TRANSFORM (PII anonymization before third-party transmission)',
            severity: 'high',
            description: `PII from ${pii.label} flows to third-party service at ${tp.label}. ` +
              `This may violate GDPR, CCPA, HIPAA, or other privacy regulations.`,
            fix: 'Anonymize or pseudonymize PII before sending to third parties. ' +
              'Use hashed identifiers instead of real PII for analytics.',
            via: 'bfs',
          });
        }
      }
    }

    for (const eg of egressNodes) {
      if (hasPathWithoutControl(map, pii.id, eg.id)) {
        const egCode = stripComments(eg.analysis_snapshot || eg.code_snapshot);
        const hasFieldFilter = /\bselect\s*\(|\bpick\s*\(|\bomit\s*\(|\bexclude\s*\(|\bsanitize\s*\(|\btoJSON\s*\(|\bserialize\s*\(|\b\.map\s*\(.*\breturn\b/i.test(egCode) || REDACT_RE.test(egCode);
        if (!hasFieldFilter && PII_RE.test(pii.analysis_snapshot || pii.code_snapshot)) {
          findings.push({
            source: nodeRef(pii), sink: nodeRef(eg),
            missing: 'CONTROL (PII field filtering in API response)',
            severity: 'high',
            description: `Private personal information from ${pii.label} exposed through ${eg.label} without field filtering. ` +
              `Over-exposing PII violates least-privilege and may breach privacy regulations.`,
            fix: 'Use a response DTO that explicitly includes only necessary fields. ' +
              'Apply data minimization — return only what the consumer needs.',
            via: 'bfs',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-359', name: 'Exposure of Private Personal Information to an Unauthorized Actor', holds: findings.length === 0, findings };
}

/**
 * CWE-402: Transmission of Private Resources into a New Sphere ('Resource Leak')
 * Detects private/internal resources (internal URLs, stack traces, env vars)
 * being transmitted across trust boundaries.
 */
function verifyCWE402(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const INTERNAL_RE = /\b(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|internal[_-]?url|private[_-]?key|stack[_-]?trace|__dirname|process\.env|process\.cwd|server[_-]?path|db[_-]?connection[_-]?string|connection[_-]?pool)\b/i;
  const STACK_RE = /\b(stack|stackTrace|err\.stack|error\.stack|traceback|backtrace)\b/i;
  const ENV_RE = /\bprocess\.env\b|\bos\.environ\b|\bENV\[/i;
  const SANITIZE_RE = /\bsanitizeError\b|\bcleanError\b|\bsafeError\b|\btoClientError\b|\bstatusCode\b.*\bmessage\b(?!.*stack)|\bnew\s+(?:HttpException|AppError|ClientError)\b/i;

  const egressNodes = nodesOfType(map, 'EGRESS');
  const externalNodes = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('http_response') || n.node_subtype.includes('api_response') ||
     n.node_subtype.includes('webhook_send') || n.node_subtype.includes('email'))
  );
  const sinkNodes = [...egressNodes, ...externalNodes];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (STACK_RE.test(code) && (node.node_type === 'EGRESS' || node.node_type === 'TRANSFORM')) {
      if (!SANITIZE_RE.test(code)) {
        const flowsToEgress = egressNodes.some(eg =>
          eg.id === node.id || hasTaintedPathWithoutControl(map, node.id, eg.id)
        );
        if (flowsToEgress || node.node_type === 'EGRESS') {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'TRANSFORM (error sanitization — strip internal details before response)',
            severity: 'medium',
            description: `Stack trace or internal error detail at ${node.label} may be transmitted to clients. ` +
              `Stack traces reveal file paths, library versions, and internal architecture.`,
            fix: 'Never send raw stack traces in production. Return a generic error with an error ID. ' +
              'Log the full error server-side for debugging.',
            via: node.node_type === 'EGRESS' ? 'structural' : 'bfs',
          });
        }
      }
    }

    if (INTERNAL_RE.test(code) && node.node_type === 'STORAGE') {
      for (const sink of sinkNodes) {
        if (hasPathWithoutControl(map, node.id, sink.id)) {
          if (!SANITIZE_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(sink),
              missing: 'TRANSFORM (strip internal resource references before external transmission)',
              severity: 'medium',
              description: `Internal resource from ${node.label} flows to external boundary at ${sink.label}. ` +
                `Internal IPs, file paths, or connection strings may leak across trust boundaries.`,
              fix: 'Sanitize all responses at trust boundaries. Replace internal references with public-facing equivalents.',
              via: 'bfs',
            });
            break;
          }
        }
      }
    }

    if (ENV_RE.test(code) && (node.node_type === 'EGRESS' || node.node_type === 'TRANSFORM')) {
      for (const sink of egressNodes) {
        if (sink.id === node.id || hasTaintedPathWithoutControl(map, node.id, sink.id)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(sink),
            missing: 'CONTROL (never transmit environment variables across trust boundaries)',
            severity: 'high',
            description: `Environment variable access at ${node.label} may leak to client via ${sink.label}. ` +
              `Environment variables often contain secrets, API keys, and infrastructure details.`,
            fix: 'Never include process.env values in API responses. ' +
              'Use a dedicated config endpoint that returns only public settings.',
            via: sink.id === node.id ? 'structural' : 'bfs',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-402', name: 'Transmission of Private Resources into a New Sphere', holds: findings.length === 0, findings };
}

/**
 * CWE-524: Use of Cache Containing Sensitive Information
 * Detects responses carrying sensitive data without Cache-Control: no-store.
 * If sensitive data gets cached by intermediary proxies or browsers, it can be
 * retrieved by unauthorized parties after the user's session ends.
 */
function verifyCWE524(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SENSITIVE_RE = /\b(password|token|secret|ssn|credit.?card|api.?key|session.?id|auth|private.?key|credentials?|account.?number|social.?security|dob|date.?of.?birth)\b/i;
  const CACHE_CONTROL_RE = /\b(cache-control|no-store|no-cache|private|must-revalidate|s-maxage\s*[:=]\s*0|max-age\s*[:=]\s*0)\b/i;
  const SET_HEADER_RE = /\b(setHeader|set|header|res\.set|response\.header|response\.setHeader|add_header|Header\s+(set|always\s+set)|@CacheControl|@Header|Cache-Control)\b/i;

  const egressNodes = nodesOfType(map, 'EGRESS');

  for (const node of egressNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const hasSensitive = SENSITIVE_RE.test(code) || SENSITIVE_RE.test(node.label) ||
      node.data_in.some(d => d.sensitivity !== 'NONE' || SENSITIVE_RE.test(d.name));

    if (hasSensitive) {
      // Check if this egress node or nearby nodes set cache-control headers
      const hasCacheControl = CACHE_CONTROL_RE.test(code) ||
        map.nodes.some(n =>
          n.node_type === 'CONTROL' &&
          CACHE_CONTROL_RE.test(n.analysis_snapshot || n.code_snapshot) &&
          SET_HEADER_RE.test(n.analysis_snapshot || n.code_snapshot) &&
          (hasTaintedPathWithoutControl(map, n.id, node.id) || n.line_start <= node.line_start + 10)
        );

      if (!hasCacheControl) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (Cache-Control: no-store header for sensitive response)',
          severity: 'medium',
          description: `Response at ${node.label} contains sensitive data without cache-control restrictions. ` +
            `Proxies, CDNs, and browsers may cache this response, exposing sensitive data to subsequent users.`,
          fix: 'Set Cache-Control: no-store on all responses containing sensitive data. ' +
            'Also set Pragma: no-cache for HTTP/1.0 compatibility. ' +
            'Consider adding Surrogate-Control: no-store for CDN layers.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-524', name: 'Use of Cache Containing Sensitive Information', holds: findings.length === 0, findings };
}

/**
 * CWE-525: Use of Web Browser Cache Containing Sensitive Data
 * Specifically targets form fields and pages with sensitive input that don't
 * disable autocomplete or browser caching via appropriate headers/attributes.
 */
function verifyCWE525(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const FORM_SENSITIVE_RE = /\b(type\s*[:=]\s*['"]password['"]|name\s*[:=]\s*['"](?:password|ssn|credit.?card|card.?number|cvv|cvc|pin|secret|account)['"]|autocomplete\s*[:=]\s*['"](?:cc-|new-password|current-password))\b/i;
  const SENSITIVE_INPUT_RE = /\b(input|field|form).*\b(password|credit.?card|ssn|social.?security|cvv|cvc|pin|secret)\b/i;
  const AUTOCOMPLETE_OFF_RE = /autocomplete\s*[:=]\s*['"]off['"]|autocomplete\s*[:=]\s*['"]new-password['"]/i;
  const CACHE_PREVENT_RE = /\b(no-store|no-cache|Cache-Control|must-revalidate|Pragma)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (FORM_SENSITIVE_RE.test(code) || SENSITIVE_INPUT_RE.test(code)) {
      const hasAutocompleteOff = AUTOCOMPLETE_OFF_RE.test(code);
      const hasCachePrevention = CACHE_PREVENT_RE.test(code);

      if (!hasAutocompleteOff && !hasCachePrevention) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (autocomplete="off" or Cache-Control: no-store for sensitive form fields)',
          severity: 'medium',
          description: `Sensitive form input at ${node.label} may be cached by the browser. ` +
            `Browsers cache form values and page content, allowing later retrieval from shared computers.`,
          fix: 'Add autocomplete="off" to sensitive form fields (or autocomplete="new-password" for password fields). ' +
            'Set Cache-Control: no-store on pages containing sensitive forms. ' +
            'For single-page apps, clear sensitive fields on component unmount.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-525', name: 'Use of Web Browser Cache Containing Sensitive Data', holds: findings.length === 0, findings };
}

/**
 * CWE-526: Exposure of Sensitive Information Through Environmental Variables
 * Detects direct exposure of environment variables (process.env, os.environ)
 * to clients or logs without whitelisting/filtering.
 */
function verifyCWE526(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ENV_ACCESS_RE = /\bprocess\.env\b|\bos\.environ\b|\bos\.getenv\b|\bENV\[|\bSystem\.getenv\b|\bEnvironment\.GetEnvironmentVariable\b|\b\$_ENV\b|\b\$_SERVER\b/i;
  const ENV_DUMP_RE = /\bprocess\.env\s*[,)}\]]|\bJSON\.stringify\s*\(\s*process\.env\b|\bos\.environ\.copy\b|\bdict\(os\.environ\)|\bENV\.to_hash\b|\.entries\(\s*process\.env\s*\)/i;
  const WHITELIST_RE = /\bprocess\.env\.(NODE_ENV|PORT|HOST|PUBLIC_|NEXT_PUBLIC_|REACT_APP_|VITE_)\b|\b(?:allowedEnv|publicEnv|safeEnv|whitelist|allowlist)\b/i;

  const egressNodes = nodesOfType(map, 'EGRESS');
  const logNodes = map.nodes.filter(n =>
    /\b(log|logger|console|syslog|winston|bunyan|pino)\b/i.test(n.analysis_snapshot || n.code_snapshot) &&
    (n.node_type === 'TRANSFORM' || n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL')
  );

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Detect dumping entire env object (most dangerous)
    if (ENV_DUMP_RE.test(code)) {
      const sinks = [...egressNodes, ...logNodes];
      for (const sink of sinks) {
        if (sink.id === node.id || hasTaintedPathWithoutControl(map, node.id, sink.id)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(sink),
            missing: 'CONTROL (never expose full environment object — whitelist specific variables)',
            severity: 'high',
            description: `Entire environment object dumped at ${node.label} and exposed via ${sink.label}. ` +
              `Environment variables typically contain database URLs, API keys, and secrets.`,
            fix: 'Never serialize the full process.env object. Explicitly select only public configuration values. ' +
              'Use a config module that whitelists safe environment variables.',
            via: sink.id === node.id ? 'structural' : 'bfs',
          });
          break;
        }
      }
      continue;
    }

    // Detect env var access flowing to egress without filtering
    if (ENV_ACCESS_RE.test(code) && !WHITELIST_RE.test(code)) {
      if (node.node_type === 'EGRESS' || node.node_type === 'TRANSFORM') {
        for (const eg of egressNodes) {
          if (eg.id === node.id || hasTaintedPathWithoutControl(map, node.id, eg.id)) {
            // Check if the env var being accessed is a known-safe public one
            if (!WHITELIST_RE.test(code)) {
              findings.push({
                source: nodeRef(node), sink: nodeRef(eg),
                missing: 'CONTROL (validate and whitelist environment variable exposure)',
                severity: 'medium',
                description: `Environment variable at ${node.label} may be exposed to clients via ${eg.label}. ` +
                  `Environment variables often contain secrets that should never reach client-side code.`,
                fix: 'Access only specific, known-safe environment variables. Use a PUBLIC_ or NEXT_PUBLIC_ prefix convention. ' +
                  'Never pass raw env values to client responses without explicit whitelisting.',
                via: eg.id === node.id ? 'structural' : 'bfs',
              });
              break;
            }
          }
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Java-specific: detect System.getenv() result flowing to HTTP response (Juliet CWE-526)
  // Juliet pattern: response.getWriter().println("..." + System.getenv("PATH"))
  // The INGRESS/env_read and EGRESS/http_response nodes exist but aren't connected by data flow.
  // Detect by checking if they share the same function scope.
  // ---------------------------------------------------------------------------
  if (inferMapLanguage(map) === 'java') {
    const envNodes = map.nodes.filter(n =>
      n.node_subtype === 'env_read' ||
      /\bSystem\.getenv\b|\bSystem\.getProperty\b/.test(n.analysis_snapshot || n.code_snapshot)
    );
    const javaEgressNodes = map.nodes.filter(n =>
      n.node_type === 'EGRESS' && /\b(http_response|display)\b/.test(n.node_subtype || '')
    );

    for (const envNode of envNodes) {
      for (const egNode of javaEgressNodes) {
        // Check if they share the same function scope
        if (sharesFunctionScope(map, envNode.id, egNode.id)) {
          // Verify the function actually concatenates env data into response
          const containingFuncId = findContainingFunction(map, envNode.id);
          if (containingFuncId) {
            const funcNode = map.nodes.find(n => n.id === containingFuncId);
            if (funcNode) {
              const funcCode = funcNode.analysis_snapshot || funcNode.code_snapshot;
              // Check that getenv result is in a println/print/write call, not just standalone
              if (/System\.getenv\s*\(/.test(funcCode) &&
                  /\b(println|print|write|getWriter|getOutputStream)\b/.test(funcCode) &&
                  !findings.some(f => f.source.id === envNode.id)) {
                findings.push({
                  source: nodeRef(envNode), sink: nodeRef(egNode),
                  missing: 'CONTROL (validate and filter environment variable exposure)',
                  severity: 'medium',
                  description: `Environment variable read at ${envNode.label} is exposed via HTTP response at ${egNode.label}. Environment variables contain sensitive system configuration.`,
                  fix: 'Do not expose environment variables in HTTP responses. If configuration display is needed, whitelist specific safe values.',
                  via: 'scope_taint',
                });
              }
            }
          }
        }
      }
    }

    // Also scan function bodies directly for the combined pattern
    for (const node of map.nodes) {
      if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (/System\.getenv\s*\(/.test(code) &&
          /\b(response\.getWriter|res\.getWriter|out\.print|println|getOutputStream)\b/.test(code) &&
          !findings.some(f => f.source.line === node.line_start || f.sink.line === node.line_start)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (never expose environment variables in HTTP response)',
          severity: 'medium',
          description: `Method ${node.label} reads environment variables and writes to HTTP response. Environment variables may contain PATH, credentials, or internal configuration.`,
          fix: 'Remove environment variable data from response output. Log server-side only if needed.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-526', name: 'Exposure of Sensitive Information Through Environmental Variables', holds: findings.length === 0, findings };
}

/**
 * CWE-528: Exposure of Core Dump File to an Unauthorized Actor
 * Detects code that enables core dumps without restricting file permissions,
 * or error handlers that write crash dumps to accessible locations.
 */
function verifyCWE528(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CORE_DUMP_RE = /\b(core\.dump|enable_core_dump|ulimit\s+-c|RLIMIT_CORE|prctl\s*\(\s*PR_SET_DUMPABLE|setrlimit|kern\.core|kernel\.core_pattern|process\.abort|fatalException|crash.?dump|mini.?dump|MiniDumpWriteDump|SetUnhandledExceptionFilter|google_breakpad|breakpad)\b/i;
  const SAFE_RE = /\b(RLIMIT_CORE\s*,\s*.*\b0\b|ulimit\s+-c\s+0|PR_SET_DUMPABLE\s*,\s*0|disable.?core.?dump|no.?core.?dump|restrict|chmod\s+0?[0-6]00|umask\s+0?[0-7]77)\b/i;
  const WORLD_READ_RE = /\bchmod\s+0?[0-7][4-7][4-7]\b|\bumask\s+0?0[0-2][0-2]\b|\bworld.?readable\b|\bpublic\b.*\bdump\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (CORE_DUMP_RE.test(code) && !SAFE_RE.test(code)) {
      // Check for world-readable permissions on dump files
      const hasWorldRead = WORLD_READ_RE.test(code);

      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (restrict core dump permissions or disable in production)',
        severity: hasWorldRead ? 'high' : 'medium',
        description: `Core dump configuration at ${node.label} may expose memory contents to unauthorized actors. ` +
          `Core dumps contain the full process memory, including credentials, encryption keys, and PII.`,
        fix: 'Disable core dumps in production (ulimit -c 0 or setrlimit RLIMIT_CORE to 0). ' +
          'If needed for debugging, set restrictive permissions (chmod 600) and direct dumps to a protected directory. ' +
          'Use kernel.core_pattern to pipe dumps to a secured handler.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-528', name: 'Exposure of Core Dump File to an Unauthorized Actor', holds: findings.length === 0, findings };
}

/**
 * CWE-552: Files or Directories Accessible to External Parties
 * Detects static file serving, directory listing, or file access patterns
 * that expose internal files without access control.
 */
function verifyCWE552(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const STATIC_SERVE_RE = /\b(express\.static|app\.use\s*\(\s*['"]\/|serveStatic|staticFiles|StaticFileHandler|DefaultServlet|autoindex\s+on|directory\s+listing|Options\s+\+?Indexes|sendFile|send_file|FileResponse|StreamingResponse|download|createReadStream|readFileSync)\b/i;
  const DANGEROUS_PATH_RE = /\b(\.\.\/|\.env|\.git|\.ssh|\.htaccess|\.htpasswd|\.DS_Store|node_modules|__pycache__|\.config|\.aws|\.npmrc|id_rsa|authorized_keys|shadow|passwd|web\.config|\.svn)\b/i;
  const ACCESS_CONTROL_RE = /\b(isAuthenticated|requireAuth|authorize|checkPermission|ensureLoggedIn|passport\.authenticate|jwt\.verify|verifyToken|authMiddleware|@login_required|@permission_required|@auth|canActivate|Guards|\.guard)\b/i;
  const PATH_RESTRICT_RE = /\b(path\.resolve|path\.normalize|realpath|safePath|sanitizePath|whitelist|allowedPaths|blocklist|denylist|\.startsWith\s*\(\s*['"][^'"]*['"]\s*\))\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (STATIC_SERVE_RE.test(code)) {
      const hasAccessControl = ACCESS_CONTROL_RE.test(code);
      const hasPathRestriction = PATH_RESTRICT_RE.test(code);
      const hasDangerousPath = DANGEROUS_PATH_RE.test(code);

      // Static file serving without access control
      if (!hasAccessControl && !hasPathRestriction) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (access control or path restriction on static file serving)',
          severity: hasDangerousPath ? 'high' : 'medium',
          description: `File serving at ${node.label} lacks access control. ` +
            `${hasDangerousPath ? 'Dangerous paths (.env, .git, etc.) may be exposed. ' : ''}` +
            `Unrestricted file access can leak source code, configuration, and credentials.`,
          fix: 'Add authentication middleware before static file handlers. ' +
            'Restrict served paths to a specific public directory. ' +
            'Block access to dotfiles (.env, .git, .ssh) and config files. ' +
            'Disable directory listing (autoindex off).',
          via: 'structural',
        });
      }
    }

    // Directory listing enabled
    if (/\b(autoindex\s+on|Options\s+\+?Indexes|directory.?listing\s*[:=]\s*true|DirectoryIndex)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (disable directory listing)',
        severity: 'medium',
        description: `Directory listing enabled at ${node.label}. ` +
          `Attackers can enumerate all files in the directory, discovering backup files, configs, and source code.`,
        fix: 'Disable directory listing. For Nginx: autoindex off. For Apache: Options -Indexes. ' +
          'Serve only explicitly mapped routes.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-552', name: 'Files or Directories Accessible to External Parties', holds: findings.length === 0, findings };
}

/**
 * CWE-210: Self-generated Error Message Containing Sensitive Information
 * Pattern: Application-generated error messages that include internal details
 * (stack traces, DB schema, file paths, query strings) in responses.
 *
 * Different from CWE-209 (which catches catch blocks leaking). CWE-210 targets
 * error messages the application CONSTRUCTS itself — custom error classes that
 * embed sensitive context, validation messages that reveal DB column names, etc.
 */
function verifyCWE210(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SELF_ERROR_RE = /\b(new\s+Error\s*\(|throw\s+new\s+\w*Error\s*\(|raise\s+\w*Error\s*\(|AppError\s*\(|HttpException\s*\(|createError\s*\(|Error\.new\s*\(|RuntimeError\s*\()\s*[^)]*\b(path|file|dir|table|column|schema|query|sql|database|internal|server|config|env|stack|trace|version)\b/i;
  const TEMPLATE_LEAK_RE = /\b(error|err|exception)\b[^;]*\b(path|file|table|column|schema|sql|query|config|env)\b[^;]*\b(res\.|response\.|send|json|render|write)\b/i;
  const VERBOSE_CONSTRUCT_RE = /\b(message|msg|error)\s*[:=]\s*[`'"]\s*(?:.*\$\{|.*\+\s*(?:err|error|e|ex)\.(?:message|stack|toString)|.*(?:path|file|table|column|query|schema))/i;
  const SAFE210_RE = /\b(generic.?error|error.?code|status.?code|error.?id|sanitize|redact|obfuscate|safe.?message|custom.?message|user.?friendly|client.?message)\b/i;

  const egress210 = nodesOfType(map, 'EGRESS');

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!(SELF_ERROR_RE.test(code) || TEMPLATE_LEAK_RE.test(code) || VERBOSE_CONSTRUCT_RE.test(code))) continue;
    if (SAFE210_RE.test(code)) continue;

    if (node.node_type === 'EGRESS') {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (sanitize self-generated error messages)',
        severity: 'medium',
        description: `Error response at ${node.label} includes internal details (file paths, DB schema, query text). ` +
          `These self-generated messages reveal application internals to attackers.`,
        fix: 'Construct error messages with only user-relevant info: error code + generic description. ' +
          'Log detailed context server-side. Never interpolate internal paths, table names, or SQL into user-facing errors.',
        via: 'structural' });
      continue;
    }

    for (const sink of egress210) {
      if (node.id === sink.id) continue;
      if (hasPathWithoutControl(map, node.id, sink.id) && !findings.some(f => f.source.id === node.id)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(sink),
          missing: 'TRANSFORM (sanitize self-generated error before response)',
          severity: 'medium',
          description: `Self-generated error at ${node.label} with internal details flows to response at ${sink.label}.`,
          fix: 'Map internal errors to generic user-facing messages. Use error codes, not raw details.',
          via: 'bfs' });
      }
    }
  }

  return { cwe: 'CWE-210', name: 'Self-generated Error Message Containing Sensitive Info', holds: findings.length === 0, findings };
}

/**
 * CWE-211: Externally-Generated Error Message Containing Sensitive Information
 * Pattern: Error messages from EXTERNAL systems (databases, APIs, cloud services)
 * passed through to users without filtering. External errors often contain connection
 * strings, internal hostnames, SQL state, and stack traces from the remote service.
 *
 * Key difference from CWE-210: the error originates from an EXTERNAL node, not
 * from the application itself.
 */
function verifyCWE211(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const EXT_ERROR_RE = /\b(SQLSTATE|ORA-\d+|MySQL.*Error|PG::Error|MongoError|MongoServerError|ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENOTFOUND|AxiosError|FetchError|HttpError|ServiceUnavailable|BadGateway|GatewayTimeout|upstream|backend.*error)\b/i;
  const PASSTHROUGH211_RE = /\b(err\.message|error\.message|e\.message|ex\.message|exception\.message|err\.response|error\.response|catch.*res\.(send|json|status)|\.catch.*\.json|rescue.*render)\b/i;
  const EXT_DETAIL_RE = /\b(connection.?string|host|port|endpoint|internal.?url|\.local\b|10\.\d+|172\.(1[6-9]|2\d|3[01])|192\.168)\b/i;
  const SAFE211_RE = /\b(generic.?error|wrap.?error|filter.?error|sanitize|redact|custom.?error|isOperationalError|handleExternalError|mapError|toClientError|safe.?message)\b/i;

  const externalNodes211 = nodesOfType(map, 'EXTERNAL');
  const egress211 = nodesOfType(map, 'EGRESS');

  for (const ext of externalNodes211) {
    const extCode = stripComments(ext.analysis_snapshot || ext.code_snapshot);
    if (!(EXT_ERROR_RE.test(extCode) || ext.node_subtype.includes('error') || ext.attack_surface.includes('error'))) continue;
    for (const sink of egress211) {
      if (ext.id === sink.id) continue;
      if (hasPathWithoutControl(map, ext.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!SAFE211_RE.test(sinkCode)) {
          findings.push({ source: nodeRef(ext), sink: nodeRef(sink),
            missing: 'CONTROL (filter external error messages before response)',
            severity: 'medium',
            description: `External error from ${ext.label} flows to response at ${sink.label} without filtering. ` +
              `Database/API error messages expose connection details, internal hostnames, and query structure.`,
            fix: 'Catch external errors and map them to generic user-facing messages. Log the original error server-side. ' +
              'Never pass database SQLSTATE, connection strings, or upstream service errors to clients.',
            via: 'bfs' });
          break;
        }
      }
    }
  }

  for (const node of map.nodes) {
    if (node.node_type === 'EXTERNAL') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!PASSTHROUGH211_RE.test(code)) continue;
    if (SAFE211_RE.test(code)) continue;
    if (EXT_ERROR_RE.test(code) || EXT_DETAIL_RE.test(code)) {
      for (const sink of egress211) {
        if (node.id === sink.id) {
          if (!findings.some(f => f.sink.id === sink.id)) {
            findings.push({ source: nodeRef(node), sink: nodeRef(sink),
              missing: 'CONTROL (filter external error details from response)',
              severity: 'medium',
              description: `Code at ${node.label} passes external error messages directly to the response.`,
              fix: 'Wrap external errors: catch (err) { res.status(500).json({ error: "Service unavailable" }); logger.error(err); }',
              via: 'structural' });
          }
          break;
        }
        if (hasPathWithoutControl(map, node.id, sink.id) && !findings.some(f => f.source.id === node.id)) {
          findings.push({ source: nodeRef(node), sink: nodeRef(sink),
            missing: 'CONTROL (filter external error before response)',
            severity: 'medium',
            description: `External error passthrough at ${node.label} reaches response at ${sink.label}.`,
            fix: 'Wrap external errors in generic messages. Log originals server-side.',
            via: 'bfs' });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-211', name: 'Externally-Generated Error Message Containing Sensitive Info', holds: findings.length === 0, findings };
}

/**
 * CWE-212: Improper Removal of Sensitive Information Before Storage or Transfer
 * Pattern: Data containing sensitive fields (passwords, SSNs, tokens) stored or
 * transferred without scrubbing. The data object has sensitive fields that should
 * have been removed/redacted but weren't.
 *
 * Classic: copying a user object to a response without removing password hash,
 * storing full credit card numbers instead of last-4, sharing logs without redacting PII.
 */
function verifyCWE212(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PASSTHROUGH212_RE = /\b(\.toJSON|\.toObject|Object\.assign|spread.*user|\{.*\.\.\.user|JSON\.stringify\s*\(\s*(?:user|account|profile|record|row|doc|result))|res\.(json|send)\s*\(\s*(?:user|account|profile|record|row|doc|result)\b/i;
  const SENSITIVE_FIELD212_RE = /\b(password|passwordHash|password_hash|hashed_password|secret|token|ssn|social_security|credit_card|creditCard|cardNumber|card_number|cvv|cvc|private_key|privateKey|salt|pin|taxId|tax_id|dob|date_of_birth|bank_account|routing_number)\b/i;
  const STORAGE_TRANSFER212_RE = /\b(store|save|persist|write|insert|update|send|transfer|export|share|publish|emit|dispatch|broadcast|replicate|sync|backup|cache|serialize)\b/i;
  const SAFE212_RE = /\b(delete\s+\w+\.password|omit|pick|select|exclude|redact|scrub|sanitize|mask|removeField|without|pluck|project|\.select\s*\([^)]*-password|toSafeObject|toPublic|toResponse|safeUser|publicProfile)\b/i;

  const sinks212 = [...nodesOfType(map, 'STORAGE'), ...nodesOfType(map, 'EGRESS'), ...nodesOfType(map, 'EXTERNAL')];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!PASSTHROUGH212_RE.test(code) && !SENSITIVE_FIELD212_RE.test(code)) continue;
    if (SAFE212_RE.test(code)) continue;

    const hasSensitive = SENSITIVE_FIELD212_RE.test(code);
    const hasPassthrough = PASSTHROUGH212_RE.test(code);

    if (hasSensitive && (hasPassthrough || STORAGE_TRANSFER212_RE.test(code))) {
      if (node.node_type === 'EGRESS' || node.node_type === 'EXTERNAL' || node.node_type === 'STORAGE') {
        findings.push({ source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (scrub sensitive fields before storage or transfer)',
          severity: 'high',
          description: `Code at ${node.label} stores or transfers data containing sensitive fields (passwords, tokens, PII) without scrubbing.`,
          fix: 'Explicitly select safe fields before storage/transfer: const safe = { id, email, name }. ' +
            'Or delete sensitive fields: delete user.password. Use an allowlist, not a denylist.',
          via: 'structural' });
        continue;
      }

      for (const sink of sinks212) {
        if (node.id === sink.id) continue;
        if (hasPathWithoutControl(map, node.id, sink.id) && !findings.some(f => f.source.id === node.id && f.sink.id === sink.id)) {
          findings.push({ source: nodeRef(node), sink: nodeRef(sink),
            missing: 'TRANSFORM (scrub sensitive fields before reaching sink)',
            severity: 'high',
            description: `Unscrubbed sensitive data from ${node.label} reaches ${sink.label}. ` +
              `Fields like password, token, or SSN may be stored or transmitted.`,
            fix: 'Add a data transformation step that strips sensitive fields before storage/transfer. Use DTOs or view models.',
            via: 'bfs' });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-212', name: 'Improper Removal of Sensitive Info Before Storage or Transfer', holds: findings.length === 0, findings };
}

/**
 * CWE-213: Exposure of Sensitive Information Due to Incompatible Policies
 * Pattern: Different components/layers apply inconsistent data classification — one
 * marks data as sensitive (e.g., PII), another doesn't enforce that classification.
 *
 * Example: DB column marked "sensitive" but the API endpoint has no access policy,
 * or GDPR-tagged data flowing to a region without GDPR enforcement.
 */
function verifyCWE213(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const sensitiveStores213 = map.nodes.filter(n =>
    n.data_out.some(d => d.sensitivity !== 'NONE') ||
    /\b(pii|gdpr|hipaa|sensitive|classified|restricted|confidential|internal.?only)\b/i.test(n.analysis_snapshot || n.code_snapshot) ||
    /\b(pii|gdpr|hipaa|sensitive|classified|restricted|confidential)\b/i.test(n.label)
  );

  const POLICY213_RE = /\b(classification|data.?class|sensitivity.?level|access.?policy|data.?policy|privacy.?policy|retention.?policy|compliance|gdpr.?check|hipaa.?check|pci.?check|dlp|data.?loss.?prevention|label|tag.?sensitive)\b/i;
  const INCONSISTENT213_RE = /\b(public|unrestricted|no.?auth|anonymous|open.?access|allow.?all)\b/i;

  const egress213 = nodesOfType(map, 'EGRESS');

  for (const src of sensitiveStores213) {
    for (const sink of egress213) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!POLICY213_RE.test(sinkCode) && (INCONSISTENT213_RE.test(sinkCode) || !sink.data_in.some(d => d.sensitivity !== 'NONE'))) {
          if (!findings.some(f => f.source.id === src.id && f.sink.id === sink.id)) {
            findings.push({ source: nodeRef(src), sink: nodeRef(sink),
              missing: 'META (consistent data classification policy enforcement)',
              severity: 'medium',
              description: `Sensitive data from ${src.label} (classified/tagged as sensitive) flows to ${sink.label} ` +
                `which has no corresponding policy enforcement. Data classification is inconsistent across components.`,
              fix: 'Enforce consistent data classification: if source marks data as PII/sensitive, all downstream consumers must ' +
                'enforce the same policy. Use a data classification framework and enforce it at API boundaries.',
              via: 'bfs' });
            break;
          }
        }
      }
    }
  }

  return { cwe: 'CWE-213', name: 'Exposure of Sensitive Info Due to Incompatible Policies', holds: findings.length === 0, findings };
}

/**
 * CWE-214: Invocation of Process Using Visible Sensitive Information
 * Pattern: Passing secrets as command-line arguments or environment variables that
 * are visible via /proc, `ps`, task manager, or process listing.
 *
 * Classic: exec("curl -u user:password ..."), spawn("mysql -p password"),
 * child_process with passwords in argv. These are visible to any user on the system
 * via `ps aux` or /proc/PID/cmdline.
 */
function verifyCWE214(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const EXEC_WITH_SECRET_RE = /\b(exec|spawn|system|popen|Popen|Runtime\.exec|ProcessBuilder|Process\.Start|child_process|execSync|spawnSync|execFile|ShellExecute)\s*\([^)]*\b(password|passwd|secret|token|key|credential|api.?key)\b/i;
  const CMDLINE_SECRET_RE = /\b(curl\s+.*-u\s+\w+:\w+|mysql\s+.*-p\s*\S+|psql\s+.*password|ssh\s+.*-i|scp\s+.*-i|wget\s+.*--password|ftp\s+.*--password|aws\s+.*--secret|docker\s+.*-e\s+\w*(PASSWORD|SECRET|KEY|TOKEN)=)\b/i;
  const ENV_VISIBLE_RE = /\b(process\.env\.\w*(PASSWORD|SECRET|KEY|TOKEN)\s*[+,]|putenv\s*\(\s*['"].*(?:PASSWORD|SECRET|KEY|TOKEN)=|os\.environ\[.*(?:PASSWORD|SECRET|KEY|TOKEN).*\]\s*\+|Environment\.SetEnvironmentVariable\s*\([^)]*(?:password|secret|key|token))/i;
  const SAFE214_RE = /\b(stdin|pipe|\.env\b|credential.?helper|secret.?manager|vault|ssm|keychain|keyring|stdin\.write|process\.stdin|\.my\.cnf|pgpass|netrc|--password-stdin)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!(EXEC_WITH_SECRET_RE.test(code) || CMDLINE_SECRET_RE.test(code) || ENV_VISIBLE_RE.test(code))) continue;
    if (SAFE214_RE.test(code)) continue;

    const severity = CMDLINE_SECRET_RE.test(code) ? 'high' as const : 'medium' as const;
    findings.push({ source: nodeRef(node), sink: nodeRef(node),
      missing: 'TRANSFORM (pass secrets via stdin/pipe, not command-line arguments)',
      severity,
      description: `Process invocation at ${node.label} passes sensitive data as a command-line argument. ` +
        `Command-line arguments are visible to all users via \`ps aux\`, /proc/PID/cmdline, and process monitoring tools.`,
      fix: 'Pass secrets via stdin pipe: echo "$SECRET" | command --password-stdin. ' +
        'Or use config files with restricted permissions (.my.cnf, .pgpass). ' +
        'Or use credential helpers/secret managers. Never pass secrets as argv.',
      via: 'structural' });
  }

  return { cwe: 'CWE-214', name: 'Invocation of Process Using Visible Sensitive Information', holds: findings.length === 0, findings };
}

/**
 * CWE-222: Truncation of Security-relevant Information
 * Pattern: Security data (log entries, audit trails, error messages, input) being
 * truncated, losing the security-relevant portion. Attackers craft inputs where the
 * dangerous part is beyond the truncation boundary.
 *
 * Example: WAF logs first 1024 bytes of request; attacker puts SQL injection at byte 1025.
 * Example: Audit log truncates the URL at 255 chars; attacker hides path traversal in the tail.
 */
function verifyCWE222(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const TRUNCATE222_RE = /\b(substring\s*\(\s*0|slice\s*\(\s*0|substr\s*\(\s*0|\.slice\s*\(\s*0\s*,\s*\d+|\.substring\s*\(\s*0\s*,\s*\d+|LEFT\s*\(|TRUNCATE|VARCHAR\s*\(\s*\d+\)|text\s*\[\s*:\s*\d+\]|\.{3}truncat|\.maxLength|\.take\s*\(\s*\d+\)|\.limit\s*\(\s*\d+\)|head\s*\(\s*\d+\))\b/i;
  const SECURITY_CTX222_RE = /\b(log|audit|security|alert|event|trace|error|warning|request|url|path|query|header|cookie|token|signature|certificate|rule|policy|filter|validate|sanitize|check)\b/i;
  const FIXED_BUFFER222_RE = /\b(CHAR\s*\(\s*\d+\)|NCHAR\s*\(\s*\d+\)|char\s+\w+\[\d+\]|byte\s+\w+\[\d+\]|new\s+Buffer\s*\(\s*\d+\)|Buffer\.alloc\s*\(\s*\d+\))\b/i;
  const SAFE222_RE = /\b(overflow|continuation|split|chunk|paginate|full.?log|complete|no.?truncat|warn.*truncat|if.*length.*>|check.*length)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!TRUNCATE222_RE.test(code) && !FIXED_BUFFER222_RE.test(code)) continue;
    if (!SECURITY_CTX222_RE.test(code) && !SECURITY_CTX222_RE.test(node.label)) continue;
    if (SAFE222_RE.test(code)) continue;

    const isSecurityNode = node.node_type === 'CONTROL' || node.node_type === 'AUTH' ||
      node.node_subtype.includes('log') || node.node_subtype.includes('audit') ||
      node.node_subtype.includes('validate') || node.node_subtype.includes('filter') ||
      node.attack_surface.includes('logging') || node.attack_surface.includes('validation');

    if (isSecurityNode || /\b(log|audit|security|validate|filter|sanitize)\b/i.test(node.label)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (handle truncation of security-relevant data)',
        severity: 'medium',
        description: `Security-relevant data at ${node.label} is truncated. Attackers can craft inputs where the ` +
          `malicious portion falls beyond the truncation boundary, bypassing logging, validation, or filtering.`,
        fix: 'Log complete security data or explicitly note truncation. For validation, check the FULL input before truncating. ' +
          'For audit logs, use overflow records or reference IDs pointing to complete data. ' +
          'Never validate truncated input — validate first, then truncate for display.',
        via: 'structural' });
    }
  }

  return { cwe: 'CWE-222', name: 'Truncation of Security-relevant Information', holds: findings.length === 0, findings };
}

/**
 * CWE-223: Omission of Security-relevant Information
 * Pattern: Security events (auth failures, access denials, privilege changes,
 * configuration changes) occurring without being logged. Prevents incident detection
 * and forensic analysis.
 *
 * Detects: auth handlers without logging, access control checks without audit trail,
 * configuration changes without recording who/when/what.
 */
function verifyCWE223(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const AUTH_EVENT223_RE = /\b(login|signIn|sign_in|authenticate|auth\s*\(|verify.?password|check.?credentials|validate.?token|verify.?token|logout|sign.?out|register|change.?password|reset.?password|failed.?login|invalid.?credentials)\b/i;
  const ACCESS_EVENT223_RE = /\b(authorize|isAuthorized|check.?permission|has.?role|can.?access|forbidden|deny|grant|revoke|elevate|privilege|impersonate|sudo|become)\b/i;
  const CONFIG_EVENT223_RE = /\b(update.?config|change.?setting|modify.?policy|toggle.?feature|set.?permission|create.?user|delete.?user|add.?role|remove.?role)\b/i;
  const LOG223_RE = /\b(log|logger|audit|console\.(log|warn|error|info)|winston|bunyan|pino|log4j|slf4j|logging\.|syslog|EventLog|os_log|NSLog|record|track|monitor|emit.?event)\b/i;
  const SAFE223_RE = /\b(audit.?log|security.?log|auth.?log|access.?log|event.?log|log.?auth|log.?access|log.?security|record.?event|track.?event|emit.?audit)\b/i;

  const authNodes223 = map.nodes.filter(n =>
    n.node_type === 'AUTH' || n.node_type === 'CONTROL' ||
    AUTH_EVENT223_RE.test(n.analysis_snapshot || n.code_snapshot) || ACCESS_EVENT223_RE.test(n.analysis_snapshot || n.code_snapshot) ||
    CONFIG_EVENT223_RE.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const node of authNodes223) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const isAuthEvent = AUTH_EVENT223_RE.test(code);
    const isAccessEvent = ACCESS_EVENT223_RE.test(code);
    const isConfigEvent = CONFIG_EVENT223_RE.test(code);

    if (!(isAuthEvent || isAccessEvent || isConfigEvent)) continue;

    const hasDirectLog = LOG223_RE.test(code) || SAFE223_RE.test(code);
    if (hasDirectLog) continue;

    const logSinks = map.nodes.filter(n =>
      (n.node_subtype.includes('log') || n.node_subtype.includes('audit') ||
       LOG223_RE.test(n.analysis_snapshot || n.code_snapshot)) && n.id !== node.id
    );
    const flowsToLog = logSinks.some(sink =>
      node.edges.some(e => e.target === sink.id)
    );

    if (!flowsToLog) {
      const eventType = isAuthEvent ? 'authentication' : isAccessEvent ? 'access control' : 'configuration change';
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STORAGE (security event logging/audit trail)',
        severity: 'medium',
        description: `Security event at ${node.label} (${eventType}) is not logged. Without audit trails, ` +
          `failed attacks go undetected and incident response lacks forensic data.`,
        fix: `Log all ${eventType} events with: timestamp, actor (user/IP), action, target resource, and outcome (success/failure). ` +
          'Use structured logging. Send security events to SIEM. Ensure logs are tamper-resistant.',
        via: 'structural' });
    }
  }

  return { cwe: 'CWE-223', name: 'Omission of Security-relevant Information', holds: findings.length === 0, findings };
}

/**
 * CWE-224: Obscured Security-relevant Information by Alternate Name
 * Pattern: Security-relevant operations disguised using alternate names, aliases,
 * symlinks, or encoding to bypass security controls.
 *
 * Example: calling `eval` via `window["e"+"val"]`, using `base64_decode` to reconstruct
 * a dangerous function name, aliasing `exec` to `run`, symlink-based path bypass.
 */
function verifyCWE224(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DYNAMIC_INVOKE224_RE = /\b(window\s*\[|global\s*\[|globalThis\s*\[|self\s*\[|this\s*\[)\s*[^[\]]*(?:\+|concat|charAt|fromCharCode|decode|atob)/i;
  // Case-sensitive: `Function` (constructor) must not match `function` (keyword).
  // Other dangerous names (eval, exec, system, etc.) are naturally lowercase.
  // Negative lookahead `(?!\s*\()` on the second alternative prevents matching normal
  // `require("...")` / `import("...")` calls as aliases.
  const ALIAS_DANGER224_RE = /\b(?:eval|exec|system|Function|require|import|__import__|popen|spawn|execFile)\b\s*(?:=|:)\s*\w+|\w+\s*(?:=|:)\s*\b(?:eval|exec|system|Function|require|import|__import__|popen|spawn|execFile)\b(?!\s*\()/;
  const ENCODED_INVOKE224_RE = /\b(atob|base64_decode|Buffer\.from|decode|fromCharCode|String\.fromCodePoint|unescape|decodeURIComponent)\s*\([^)]+\)\s*(?:\(|\)|;)/i;
  const CONSTRUCTOR_TRICK224_RE = /\b(constructor\s*\[\s*['"]constructor['"]\s*\]|Function\s*\(\s*(?:atob|decode|unescape))/i;
  const SAFE224_RE = /\b(allowlist|whitelist|sandbox|vm\.createContext|vm2|isolated|safeEval|jail|restrict|freeze)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (DYNAMIC_INVOKE224_RE.test(code) || CONSTRUCTOR_TRICK224_RE.test(code)) {
      if (!SAFE224_RE.test(code)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (prevent dynamic invocation of dangerous functions)',
          severity: 'high',
          description: `Code at ${node.label} uses dynamic property access to invoke functions, potentially ` +
            `constructing dangerous function names at runtime to bypass static analysis and security filters.`,
          fix: 'Use Content-Security-Policy to block eval. Do not allow dynamic construction of function names. ' +
            'Use an explicit allowlist of callable functions. Apply CSP unsafe-eval restriction.',
          via: 'structural' });
      }
    } else if (ALIAS_DANGER224_RE.test(code) && !SAFE224_RE.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (detect function aliasing of dangerous operations)',
        severity: 'medium',
        description: `Code at ${node.label} aliases a dangerous function (eval, exec, system) to an alternate name. ` +
          `This obscures the security-relevant operation from code review and static analysis.`,
        fix: 'Do not alias dangerous functions. Use explicit, well-named wrappers with security controls. ' +
          'Flag aliased dangerous functions in linting rules.',
        via: 'structural' });
    } else if (ENCODED_INVOKE224_RE.test(code) && !SAFE224_RE.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (prevent encoded/obfuscated code execution)',
        severity: 'high',
        description: `Code at ${node.label} decodes and immediately executes content, potentially ` +
          `using encoding to obscure a dangerous operation from security tools.`,
        fix: 'Never decode-then-execute. If dynamic code loading is needed, use integrity checks (SRI, signature verification). ' +
          'Apply CSP restrictions. Audit all encoded content at deploy time.',
        via: 'structural' });
    }
  }

  return { cwe: 'CWE-224', name: 'Obscured Security-relevant Info by Alternate Name', holds: findings.length === 0, findings };
}

/**
 * CWE-226: Sensitive Information in Resource Not Removed Before Reuse
 * Pattern: Buffers, data structures, or objects holding sensitive data are
 * reused (returned to a pool, realloc'd, reassigned) without being scrubbed.
 * Property: Sensitive data is explicitly cleared before resource reuse.
 *
 * Different from CWE-244 (heap clearing before free): CWE-226 is about REUSE —
 * the resource continues to exist but is handed to a different context that
 * should not see the old data. Think connection pool buffers, reused HTTP
 * response objects, recycled thread-local storage.
 */
function verifyCWE226(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SENSITIVE_DATA = /\b(password|passwd|secret|token|apiKey|api_key|privateKey|private_key|credentials|creditCard|credit_card|ssn|pin|cvv|sessionId|session_id|accessToken|access_token|refreshToken|refresh_token|authToken|auth_token|cookie|nonce|salt|seed)\b/i;
  const REUSE_PATTERN = /\b(pool\.release|pool\.return|\.recycle|\.reuse|cache\.set|cache\.put|\.reset\s*\(|\.clear\s*\(|realloc|mremap|recycleConnection|returnToPool|release.*pool|freeList\.push|objectPool|bufferPool|connectionPool|threadLocal|ThreadLocal|reusable|shared.*buffer|global.*buffer)\b/i;
  const SCRUB_PATTERN = /\b(\.fill\s*\(\s*0|memset|memset_s|explicit_bzero|SecureZeroMemory|RtlSecureZeroMemory|bzero|zeroize|wipe|scrub|sanitize.*before.*reuse|clear.*sensitive|overwrite|secureClear|OPENSSL_cleanse|sodium_memzero|crypto_wipe)\b/i;
  const STRUCT_CLEAR = /\b(Object\.keys\([^)]*\)\.forEach\s*\(\s*\w+\s*=>\s*delete|for\s*\(\s*(?:let|const|var)\s+\w+\s+in\s+\w+\)\s*delete|\.fill\(|\.zero|=\s*\{\s*\}|=\s*new\s+\w+\(\s*\))\b/i;

  // --- Phase 1: Graph-based detection (pool/reuse patterns) ---
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SENSITIVE_DATA.test(code) && REUSE_PATTERN.test(code)) {
      if (!SCRUB_PATTERN.test(code) && !STRUCT_CLEAR.test(code)) {
        const sensitive = code.match(SENSITIVE_DATA)?.[0] || 'sensitive data';
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (scrub sensitive data from resource before reuse)',
          severity: 'high',
          description: `Resource at ${node.label} contains ${sensitive} and is returned to a pool or reused ` +
            `without clearing the sensitive data first. The next consumer of this resource may read leftover secrets.`,
          fix: 'Clear all sensitive fields before returning resources to a pool: buffer.fill(0), memset_s(), ' +
            'or explicit field deletion. For connection pools, reset session state. For objects, zero all sensitive properties. ' +
            'Use explicit_bzero/SecureZeroMemory to prevent compiler optimization of the clearing.',
          via: 'structural',
        });
      }
    }
  }

  // Also check STORAGE->EXTERNAL flows where storage holds sensitive data and
  // the external node shows pooling/reuse
  const storageNodes = nodesOfType(map, 'STORAGE');
  const externalNodes = nodesOfType(map, 'EXTERNAL');
  for (const store of storageNodes) {
    if (!SENSITIVE_DATA.test(store.analysis_snapshot || store.code_snapshot)) continue;
    for (const ext of externalNodes) {
      if (REUSE_PATTERN.test(ext.analysis_snapshot || ext.code_snapshot)) {
        if (hasTaintedPathWithoutControl(map, store.id, ext.id)) {
          const storeCode = stripComments(store.analysis_snapshot || store.code_snapshot);
          const extCode = stripComments(ext.analysis_snapshot || ext.code_snapshot);
          if (!SCRUB_PATTERN.test(storeCode) && !SCRUB_PATTERN.test(extCode)) {
            findings.push({
              source: nodeRef(store), sink: nodeRef(ext),
              missing: 'TRANSFORM (clear sensitive data before resource pool return)',
              severity: 'high',
              description: `Sensitive data from ${store.label} flows to pooled/reusable resource at ${ext.label} ` +
                `without scrubbing. The resource will be reused with leftover sensitive data intact.`,
              fix: 'Add a TRANSFORM node between the sensitive storage and the pool return that zeroes all sensitive fields. ' +
                'Use language-appropriate secure zeroing (explicit_bzero, SecureZeroMemory, buffer.fill(0)).',
              via: 'bfs',
            });
          }
        }
      }
    }
  }

  // --- Phase 2: Source-line scan for mutable buffers holding sensitive data ---
  // Catches the Juliet pattern: StringBuffer password = new StringBuffer(); password.append(readLine());
  // ... method exits without calling password.delete(0, password.length()) or equivalent clearing.
  // The vulnerability is the ABSENCE of a clearing operation before scope exit.
  if (findings.length === 0 && map.source_code) {
    const src = stripComments(map.source_code);
    const lines = src.split('\n');

    // Sensitive name pattern for variable declarations
    const SENSITIVE_NAME = /\b(password|passwd|secret|token|apiKey|api_key|privateKey|private_key|credential|credentials|creditCard|credit_card|ssn|pin|cvv|sessionId|session_id|accessToken|access_token|refreshToken|refresh_token|authToken|auth_token|passphrase|masterKey|master_key|encryptionKey|encryption_key|secretKey|secret_key)\b/i;

    // Mutable buffer types that can hold and leak sensitive data
    const MUTABLE_BUFFER_DECL = /\b(StringBuffer|StringBuilder|CharBuffer|ByteBuffer)\s+(\w+)\s*=\s*new\s+(StringBuffer|StringBuilder|CharBuffer|ByteBuffer)\b/;
    const CHAR_ARRAY_DECL = /\b(char|byte)\s*\[\s*\]\s+(\w+)\s*=/;

    // Clearing operations that properly scrub mutable buffers
    // Java: buffer.delete(0, buffer.length()), buffer.setLength(0), Arrays.fill(arr, '\0'), Arrays.fill(arr, (byte)0)
    // C/C++: memset, memset_s, explicit_bzero, SecureZeroMemory
    // Generic: .fill(0), .clear(), zeroize, wipe
    const makeClearPattern = (varName: string): RegExp => new RegExp(
      `\\b${varName}\\.delete\\s*\\(\\s*0` +           // buffer.delete(0, ...)
      `|\\b${varName}\\.setLength\\s*\\(\\s*0\\s*\\)` + // buffer.setLength(0)
      `|\\b${varName}\\.replace\\s*\\(\\s*0` +          // buffer.replace(0, ...)
      `|\\bArrays\\.fill\\s*\\(\\s*${varName}` +        // Arrays.fill(arr, ...)
      `|\\b${varName}\\s*=\\s*new\\s+StringBuffer\\s*\\(\\s*\\)` + // password = new StringBuffer()
      `|\\b${varName}\\s*=\\s*new\\s+StringBuilder\\s*\\(\\s*\\)` + // password = new StringBuilder()
      `|\\b${varName}\\s*=\\s*""` +                     // password = "" (for String reassign)
      `|\\b${varName}\\s*=\\s*null` +                   // password = null (explicit nullification)
      `|\\bmemset\\s*\\(\\s*${varName}` +               // memset(buf, ...)
      `|\\bmemset_s\\s*\\(\\s*${varName}` +             // memset_s(buf, ...)
      `|\\bexplicit_bzero\\s*\\(\\s*${varName}` +       // explicit_bzero(buf, ...)
      `|\\bSecureZeroMemory\\s*\\(\\s*${varName}` +     // SecureZeroMemory(buf, ...)
      `|\\b${varName}\\.fill\\s*\\(` +                  // buf.fill(0) (JS/Node)
      `|\\bOPENSSL_cleanse\\s*\\(\\s*${varName}`,       // OPENSSL_cleanse(buf, ...)
      'i'
    );

    // Track sensitive mutable buffers: { varName, declLine, type }
    interface SensitiveBuf { varName: string; declLine: number; type: string }
    const sensitiveBufs: SensitiveBuf[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Match: StringBuffer password = new StringBuffer();
      const bufMatch = line.match(MUTABLE_BUFFER_DECL);
      if (bufMatch) {
        const varName = bufMatch[2];
        if (SENSITIVE_NAME.test(varName)) {
          sensitiveBufs.push({ varName, declLine: i, type: bufMatch[1] });
        }
        continue;
      }

      // Match: char[] password = ... or byte[] key = ...
      const arrMatch = line.match(CHAR_ARRAY_DECL);
      if (arrMatch) {
        const varName = arrMatch[2];
        if (SENSITIVE_NAME.test(varName)) {
          sensitiveBufs.push({ varName, declLine: i, type: arrMatch[1] + '[]' });
        }
      }
    }

    // For each sensitive buffer, check if it's populated and cleared within its method scope
    for (const buf of sensitiveBufs) {
      // Find the method that contains this declaration
      let methodStart = buf.declLine;
      let braceDepth = 0;
      // Walk backwards to find method start (look for method signature)
      for (let k = buf.declLine; k >= 0; k--) {
        const l = lines[k];
        // Count braces going backwards to find the enclosing method
        for (let c = l.length - 1; c >= 0; c--) {
          if (l[c] === '}') braceDepth++;
          if (l[c] === '{') braceDepth--;
        }
        if (braceDepth < 0 || /\b(public|private|protected|static|void|throws)\b/.test(l) && /\{/.test(l)) {
          methodStart = k;
          break;
        }
      }

      // Find method end by tracking brace depth forward from methodStart
      braceDepth = 0;
      let methodEnd = lines.length - 1;
      let passedFirstBrace = false;
      for (let k = methodStart; k < lines.length; k++) {
        const l = lines[k];
        for (const c of l) {
          if (c === '{') { braceDepth++; passedFirstBrace = true; }
          if (c === '}') braceDepth--;
        }
        if (passedFirstBrace && braceDepth === 0) {
          methodEnd = k;
          break;
        }
      }

      // Check if the buffer is populated (append, put, read into, etc.)
      let isPopulated = false;
      const populatePattern = new RegExp(
        `\\b${buf.varName}\\.(append|put|write|read|insert)\\s*\\(` +
        `|\\b${buf.varName}\\s*\\[\\s*\\d+\\s*\\]\\s*=` +          // arr[0] = 'x'
        `|\\bSystem\\.arraycopy\\s*\\([^,]+,\\s*[^,]+,\\s*${buf.varName}`,
        'i'
      );
      for (let k = buf.declLine + 1; k <= methodEnd; k++) {
        if (populatePattern.test(lines[k])) {
          isPopulated = true;
          break;
        }
      }

      if (!isPopulated) continue;  // Buffer declared but never populated — not a real risk

      // Check if the buffer is cleared anywhere before method exit
      const clearPat = makeClearPattern(buf.varName);
      let isCleared = false;
      for (let k = buf.declLine + 1; k <= methodEnd; k++) {
        if (clearPat.test(lines[k])) {
          isCleared = true;
          break;
        }
      }

      if (!isCleared) {
        const nearNode = map.nodes.find(n =>
          Math.abs(n.line_start - (buf.declLine + 1)) <= 3
        ) || map.nodes[0];
        if (nearNode) {
          findings.push({
            source: nodeRef(nearNode), sink: nodeRef(nearNode),
            missing: 'TRANSFORM (clear sensitive buffer before method exit)',
            severity: 'high',
            description: `L${buf.declLine + 1}: ${buf.type} '${buf.varName}' holds sensitive data but is never ` +
              `cleared before the method exits (scope ends at L${methodEnd + 1}). The sensitive data remains in memory ` +
              `and may be exposed via heap inspection, memory dumps, or reuse of the underlying storage.`,
            fix: `Clear the buffer before it goes out of scope. For StringBuffer/StringBuilder: ` +
              `${buf.varName}.delete(0, ${buf.varName}.length()). For char[]: Arrays.fill(${buf.varName}, '\\0'). ` +
              `For byte[]: Arrays.fill(${buf.varName}, (byte) 0). Do this in a finally block to ensure cleanup on exceptions.`,
            via: 'source_line_fallback',
          });
        }
      }
    }

    // Phase 2b: Detect char[]/byte[] from getPassword()/readPassword() not cleared
    // Pattern: char[] pwd = console.readPassword(); ... no Arrays.fill(pwd, ...)
    const SENSITIVE_READ = /\b(char|byte)\s*\[\s*\]\s+(\w+)\s*=\s*\w+\.(readPassword|getPassword|toCharArray)\s*\(/;
    for (let i = 0; i < lines.length; i++) {
      const readMatch = lines[i].match(SENSITIVE_READ);
      if (!readMatch) continue;
      const varName = readMatch[2];
      // Already caught above?
      if (sensitiveBufs.some(b => b.varName === varName)) continue;

      // Find enclosing method end
      let braceD = 0;
      let mEnd = lines.length - 1;
      let found = false;
      for (let k = i; k < lines.length; k++) {
        for (const c of lines[k]) {
          if (c === '{') { braceD++; found = true; }
          if (c === '}') braceD--;
        }
        if (found && braceD <= 0) { mEnd = k; break; }
      }

      const clearPat2 = makeClearPattern(varName);
      let cleared = false;
      for (let k = i + 1; k <= mEnd; k++) {
        if (clearPat2.test(lines[k])) { cleared = true; break; }
      }

      if (!cleared) {
        const nearNode = map.nodes.find(n =>
          Math.abs(n.line_start - (i + 1)) <= 3
        ) || map.nodes[0];
        if (nearNode) {
          findings.push({
            source: nodeRef(nearNode), sink: nodeRef(nearNode),
            missing: 'TRANSFORM (clear sensitive char[]/byte[] before method exit)',
            severity: 'high',
            description: `L${i + 1}: '${varName}' from ${readMatch[3]}() holds sensitive data but is never ` +
              `cleared. The char[]/byte[] remains in memory with sensitive content until garbage collection.`,
            fix: `Call Arrays.fill(${varName}, '\\0') in a finally block before the method returns. ` +
              `Using char[] for passwords is only secure if you actually zero it when done.`,
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-226', name: 'Sensitive Information in Resource Not Removed Before Reuse', holds: findings.length === 0, findings };
}

/**
 * CWE-472: External Control of Assumed-Immutable Web Parameter
 * Hidden form fields, cookies, URL params, or HTTP headers that the developer
 * assumes cannot be modified by the user, but ARE user-controlled (price, role,
 * quantity, discount, user_id in hidden fields).
 */
function verifyCWE472(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const HIDDEN_FIELD_RE = /\b(type\s*[:=]\s*['"]hidden['"]|input.*hidden|hidden.*input)\b/i;
  const IMMUTABLE_PARAM_RE = /\b(price|total|amount|discount|quantity|tax|role|user_?id|account_?id|is_?admin|privilege|level|tier|plan|subscription|order_?id|item_?id)\b/i;
  const COOKIE_RE = /\b(req\.cookies|document\.cookie|getCookie|cookie\[|cookies\[|Cookie\.get|\$_COOKIE)\b/i;
  const HEADER_RE = /\b(req\.headers|request\.headers|getHeader|X-User|X-Role|X-Admin|X-Price|X-Forwarded-For)\b/i;
  const TRUST_USE_RE = /\b(if\s*\(|switch\s*\(|price\s*[:=]|total\s*[:=]|amount\s*[:=]|role\s*[:=]|isAdmin|is_admin|permission|authorize|charge|bill|debit|credit|payment)\b/i;
  const SAFE472 = /\b(validatePrice|verifyPrice|serverSidePrice|recalculate|lookupPrice|db\.get|database|signed|hmac|jwt|verify|validate|parseInt.*>.*0|parseFloat.*>.*0)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if ((HIDDEN_FIELD_RE.test(code) || node.node_subtype.includes('hidden')) &&
        IMMUTABLE_PARAM_RE.test(code) && TRUST_USE_RE.test(code) && !SAFE472.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (server-side validation of assumed-immutable parameter)',
        severity: 'high',
        description: `Hidden field at ${node.label} contains business-critical value (${code.match(IMMUTABLE_PARAM_RE)?.[0] || 'unknown'}) ` +
          'that is used without server-side re-validation. Hidden fields are trivially modifiable via browser dev tools.',
        fix: 'Never trust hidden form fields for prices, quantities, or authorization. ' +
          'Recalculate business values server-side. Use signed tokens (HMAC/JWT) for tamper detection.',
        via: 'structural',
      });
    }

    if ((COOKIE_RE.test(code) || HEADER_RE.test(code)) &&
        IMMUTABLE_PARAM_RE.test(code) && TRUST_USE_RE.test(code) && !SAFE472.test(code)) {
      const source = COOKIE_RE.test(code) ? 'cookie' : 'HTTP header';
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate user-controlled parameter before business/security use)',
        severity: 'high',
        description: `${source} value at ${node.label} contains business-critical data used without validation. ` +
          `Users can freely modify ${source}s -- treating them as immutable is a pricing/authorization bypass.`,
        fix: 'Derive business-critical values from server-side state (database, session). ' +
          'If the value must come from the client, sign it with HMAC and verify on the server.',
        via: 'structural',
      });
    }
  }

  const ingress472 = nodesOfType(map, 'INGRESS').filter(n =>
    IMMUTABLE_PARAM_RE.test(n.label) || IMMUTABLE_PARAM_RE.test(n.analysis_snapshot || n.code_snapshot)
  );
  const businessSinks = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (TRUST_USE_RE.test(n.analysis_snapshot || n.code_snapshot) || n.node_subtype.includes('payment') ||
     n.node_subtype.includes('billing') || n.node_subtype.includes('order'))
  );
  for (const src of ingress472) {
    for (const sink of businessSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) && !SAFE472.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(sink),
          missing: 'CONTROL (server-side validation/recalculation of business-critical parameter)',
          severity: 'high',
          description: `Parameter "${src.label}" flows from user input to business logic at ${sink.label} without validation. ` +
            'If this is price/quantity/role, the user can manipulate it to bypass business rules.',
          fix: 'Recalculate prices/totals server-side from database. Validate roles against session. ' +
            'Never trust client-submitted business values.',
          via: 'bfs',
        });
      }
    }
  }

  return { cwe: 'CWE-472', name: 'External Control of Assumed-Immutable Web Parameter', holds: findings.length === 0, findings };
}

/**
 * CWE-473: PHP External Variable Modification
 * PHP's register_globals, extract(), or import_request_variables() allow
 * external request data to overwrite internal variables, including security-
 * critical ones like $is_admin, $authenticated, $price.
 */
function verifyCWE473(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const EXTRACT_RE = /\b(extract\s*\(|import_request_variables|parse_str\s*\([^,)]+\)(?!\s*,)|register_globals\s*[:=]\s*(?:on|true|1))\b/i;
  const SEC_VAR_RE = /\$\b(is_?admin|authenticated|logged_?in|role|permission|auth|user_?id|user_?level|price|total|discount|access_?level|session_?id|token|csrf|verified)\b/i;
  const SAFE473 = /\b(EXTR_SKIP|EXTR_PREFIX|EXTR_IF_EXISTS|allowedKeys|array_intersect_key|array_flip|whitelist|allowlist)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (EXTRACT_RE.test(code) && !SAFE473.test(code)) {
      const hasSecVars = SEC_VAR_RE.test(code);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (restrict extract/register_globals to safe variable set)',
        severity: hasSecVars ? 'critical' : 'high',
        description: `PHP variable import at ${node.label} uses extract() or register_globals without restriction. ` +
          (hasSecVars
            ? 'Security-critical variables in scope can be overwritten by crafted request parameters.'
            : 'Any in-scope variable can be overwritten by crafted request parameters.'),
        fix: 'Never use extract() on user input. If you must, use EXTR_SKIP or EXTR_PREFIX_ALL. ' +
          'Better: explicitly assign only the variables you need. Disable register_globals in php.ini.',
        via: 'structural',
      });
    }

    if (/\bparse_str\s*\(\s*\$/.test(code) && !/parse_str\s*\([^,]+,/.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (parse_str must use second argument to capture into array)',
        severity: 'high',
        description: `parse_str() at ${node.label} called without second parameter. ` +
          'In PHP < 8, this imports parsed values into the current scope, overwriting existing variables.',
        fix: 'Always use parse_str($string, $result) with a second argument to capture into an array. ' +
          'In PHP 8+, the second argument is required, but older code may still run on PHP 7.x.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-473', name: 'PHP External Variable Modification', holds: findings.length === 0, findings };
}

/**
 * CWE-474: Use of Function with Inconsistent Implementations
 * Functions that behave differently across platforms/compilers/runtimes
 * (e.g., atoi, gets, strtok, mktemp), leading to portability bugs that
 * create security vulnerabilities.
 */
function verifyCWE474(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const INCONSISTENT_C_RE = /\b(atoi|atol|atof|gets|strtok|asctime|ctime|gmtime|localtime|tmpnam|mktemp|signal|setjmp|longjmp|alloca|itoa|gcvt|ecvt|fcvt)\s*\(/i;
  const INCONSISTENT_JS_RE = /\bparseInt\s*\([^,)]+\)(?!\s*,)/i;
  const SAFE_C_RE = /\b(strtol|strtoul|strtod|fgets|strtok_r|strftime|mkstemp|mkdtemp|tmpfile|sigaction)\b/i;
  const SAFE_JS_RE = /\b(parseInt\s*\([^,]+,\s*(?:10|16|8|2)\s*\)|Number\s*\(|Number\.parseInt\s*\([^,]+,\s*\d)|parseFloat\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (INCONSISTENT_C_RE.test(code) && !SAFE_C_RE.test(code)) {
      const match = code.match(INCONSISTENT_C_RE);
      const fn = match ? match[1] : 'unknown';
      const alternatives: Record<string, string> = {
        atoi: 'strtol (with error checking)', atol: 'strtol', atof: 'strtod',
        gets: 'fgets', strtok: 'strtok_r (thread-safe)',
        asctime: 'strftime', ctime: 'strftime', gmtime: 'gmtime_r',
        localtime: 'localtime_r', tmpnam: 'mkstemp', mktemp: 'mkstemp',
        signal: 'sigaction', alloca: 'malloc/VLA with bounds check',
      };
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use portable, well-defined alternative function)',
        severity: fn === 'gets' ? 'critical' : 'medium',
        description: `${fn}() at ${node.label} has inconsistent behavior across platforms. ` +
          (fn === 'atoi' ? 'Returns 0 on error (indistinguishable from valid "0"), undefined on overflow.' :
           fn === 'gets' ? 'No buffer length check -- guaranteed buffer overflow on long input.' :
           fn === 'strtok' ? 'Uses static internal state -- not thread-safe, corrupts in concurrent code.' :
           'Behavior varies by platform, may cause security bugs on different compilers/OS.'),
        fix: `Replace ${fn}() with ${alternatives[fn.toLowerCase()] || 'a well-defined portable alternative'}. ` +
          'Always check return values and handle error cases explicitly.',
        via: 'structural',
      });
    }

    if (INCONSISTENT_JS_RE.test(code) && !SAFE_JS_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (specify radix parameter)',
        severity: 'medium',
        description: `parseInt() at ${node.label} called without radix. ` +
          'Leading "0" means octal in some engines, "0x" means hex. Input "08" parses as 0 or 8 depending on engine.',
        fix: 'Always use parseInt(value, 10) with explicit radix. Or use Number() for strict numeric conversion.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-474', name: 'Use of Function with Inconsistent Implementations', holds: findings.length === 0, findings };
}

/**
 * CWE-488: Exposure of Data Element to Wrong Session
 * Data from one user's session leaks to another user due to shared state,
 * static/global variables, connection pooling without cleanup, or caching
 * keyed incorrectly.
 */
function verifyCWE488(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const STATIC_STATE_RE = /\b(static\s+\w+\s*=|global\s+\w+|module\.exports\.\w+\s*=|let\s+\w+\s*=.*(?:user|session|auth|token|data|result|response|request))\b/i;
  const GLOBAL_VAR_RE = /\b(globalThis\.\w+|window\.\w+|global\.\w+|app\.locals\.\w+|this\.\w+\s*=.*(?:user|session|req|request))\b/i;
  const CACHE_SHARED_RE = /\b(cache\.set|redis\.set|memcached\.set|localStorage\.setItem|sessionStorage\.setItem)\b/i;
  const SESSION_DATA_RE = /\b(user_?id|user_?name|email|session|token|auth|role|account|profile|cart|order|balance|preference)\b/i;
  const SAFE488 = /\b(req\.session|session\[|session\.get|per.?user|user.?specific|\.bind\(\s*this\s*\)|new\s+\w+\(|class\s+\w+|ThreadLocal|AsyncLocalStorage|cls-hooked|request\.user)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if ((STATIC_STATE_RE.test(code) || GLOBAL_VAR_RE.test(code)) &&
        SESSION_DATA_RE.test(code) && !SAFE488.test(code)) {
      const isModuleLevel = node.node_type === 'STORAGE' || node.node_type === 'TRANSFORM' ||
        /\bstatic\b/.test(code) || GLOBAL_VAR_RE.test(code);
      if (isModuleLevel) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (session-scoped storage instead of shared state)',
          severity: 'high',
          description: `Shared/static variable at ${node.label} stores session-specific data (${code.match(SESSION_DATA_RE)?.[0] || 'user data'}). ` +
            'Under concurrent requests, user A will see user B\'s data -- a session data cross-contamination bug.',
          fix: 'Use request-scoped storage (req.session, AsyncLocalStorage, ThreadLocal). ' +
            'Never store per-user data in module-level or static variables in a multi-tenant server.',
          via: 'structural',
        });
      }
    }

    if (CACHE_SHARED_RE.test(code) && SESSION_DATA_RE.test(code)) {
      const hasUserKey = /\b(user_?id|userId|session_?id|sessionId|account_?id)\b.*\b(cache|redis|memcached)\b|\b(cache|redis|memcached)\b.*\b(user_?id|userId|session_?id|sessionId)\b/i.test(code);
      const hasTemplateKey = /[`$]\{.*(?:user|session|account).*\}|['"].*(?:user|session|account).*['"]\s*\+/i.test(code);
      if (!hasUserKey && !hasTemplateKey && !SAFE488.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (user-specific cache key)',
          severity: 'high',
          description: `Cache write at ${node.label} stores session-specific data without a user-scoped key. ` +
            'All users may receive the same cached user-specific data -- classic session data exposure.',
          fix: 'Include the user ID or session ID in cache keys for per-user data. ' +
            'Example: cache.set(`user:${userId}:profile`, data) instead of cache.set("profile", data).',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-488', name: 'Exposure of Data Element to Wrong Session', holds: findings.length === 0, findings };
}

/**
 * CWE-527: Exposure of Source Code in Deployed Files
 * Source code files, VCS directories (.git, .svn), IDE configs, or backup files
 * accessible via web server due to misconfigured static file serving.
 */
function verifyCWE527(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const STATIC_SERVE_RE527 = /\b(express\.static|app\.use.*static|sendFile|serveStatic|StaticFiles|whitenoise|nginx.*root|DocumentRoot|alias\s+\/|location\s+\/)\b/i;
  const VCS_RE527 = /\b(\.git|\.svn|\.hg|\.bzr|CVS|\.gitignore|\.gitmodules|\.env|\.npmrc|\.pypirc)\b/i;
  const IDE_RE527 = /\b(\.idea|\.vscode|\.project|\.classpath|\.settings|\.DS_Store)\b/i;
  const SAFE527 = /\b(whitelist|allowlist|allowedExtensions|deny\s+all|location.*deny|exclude|ignore|filter)\b/i;
  const BUILD_DIR_RE527 = /\b(dist|build|public|static|assets|wwwroot|htdocs|www)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (STATIC_SERVE_RE527.test(code) && !SAFE527.test(code)) {
      const servesRoot = /express\.static\s*\(\s*['"]\.['"]|express\.static\s*\(\s*__dirname|serveStatic\s*\(\s*['"]\.['"]|DocumentRoot\s+['"]?\/.*src/i.test(code);
      const servesBuild = BUILD_DIR_RE527.test(code);
      if (servesRoot || !servesBuild) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (restrict static file serving to safe extensions/directories)',
          severity: 'high',
          description: `Static file server at ${node.label} may expose source code. ` +
            (servesRoot ? 'Serving from project root exposes package.json, source files, .env, and .git/.' :
            'No extension filtering -- .java, .py, .env files may be accessible via direct URL.'),
          fix: 'Serve only from a dedicated build/public directory. ' +
            'Use an allowlist of safe extensions (.html, .css, .js, .png). ' +
            'Block access to .git/, .env, source files in web server config.',
          via: 'structural',
        });
      }
    }

    if ((VCS_RE527.test(code) || IDE_RE527.test(code)) && STATIC_SERVE_RE527.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (exclude VCS/IDE files from static serving)',
        severity: 'critical',
        description: `Configuration at ${node.label} may expose version control or IDE files to the web. ` +
          '.git/ exposure reveals full source history. .env exposure reveals secrets.',
        fix: 'Add explicit deny rules: location ~ /\\.git { deny all; }. ' +
          'Never serve from a directory containing .git or .env.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-527', name: 'Exposure of Source Code in Deployed Files', holds: findings.length === 0, findings };
}

/**
 * CWE-529: Exposure of Access Control List Files
 * ACL files (.htaccess, web.config, robots.txt with sensitive paths,
 * security configs) accessible to unauthorized users, revealing the
 * security structure of the application.
 */
function verifyCWE529(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ACL_FILE_RE529 = /\b(\.htaccess|web\.config|security\.xml|authorization\.xml|access\.conf|\.htpasswd|\.htgroup|shiro\.ini|security\.yml|spring-security|auth\.conf|permissions\.xml|policy\.xml|acl\.json|rbac\.yml)\b/i;
  const ROBOTS_SENSITIVE_RE529 = /robots\.txt.*\b(admin|secret|internal|private|api|login|dashboard|config|backup|database|db|phpmyadmin|wp-admin|cpanel|staging|dev)\b/i;
  const SERVE_RE529 = /\b(sendFile|readFile.*res\.|response\.send|express\.static|serveStatic|StaticFiles|app\.use|location\s+[~=]|Alias|ScriptAlias)\b/i;
  const SAFE529 = /\b(deny|forbidden|403|block|restrict|internal|private|auth_?required|satisfy\s+all)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (ACL_FILE_RE529.test(code) && SERVE_RE529.test(code) && !SAFE529.test(code)) {
      const file = code.match(ACL_FILE_RE529)?.[0] || 'ACL file';
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (deny access to ACL/security config files)',
        severity: 'high',
        description: `Security configuration file "${file}" at ${node.label} may be publicly accessible. ` +
          'Attackers can read your authorization rules to find unprotected endpoints or weak policies.',
        fix: `Block access to ${file} at the web server level. ` +
          'In Apache: <FilesMatch "^\\.ht"> Require all denied </FilesMatch>. ' +
          'In nginx: location ~ /\\.ht { deny all; }',
        via: 'structural',
      });
    }

    if (/\.htpasswd/i.test(code) && (SERVE_RE529.test(code) || /\b(public|static|www|htdocs)\b/i.test(code))) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (deny access to .htpasswd file)',
        severity: 'critical',
        description: `.htpasswd file referenced at ${node.label} may be web-accessible. ` +
          'This file contains password hashes that can be cracked offline.',
        fix: 'Store .htpasswd outside the web root. ' +
          'Add explicit deny rules: <Files ".htpasswd"> Require all denied </Files>',
        via: 'structural',
      });
    }

    if (ROBOTS_SENSITIVE_RE529.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (do not reveal sensitive paths in robots.txt)',
        severity: 'medium',
        description: `robots.txt at ${node.label} reveals sensitive directory paths. ` +
          'Disallow entries are a roadmap for attackers -- they tell bots (and attackers) exactly where the interesting stuff is.',
        fix: 'Use authentication/authorization instead of robots.txt to protect sensitive paths. ' +
          'robots.txt is for SEO, not security. Sensitive paths should return 403/404 to unauthorized users.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-529', name: 'Exposure of Access Control List Files', holds: findings.length === 0, findings };
}

/**
 * CWE-531: Inclusion of Sensitive Information in Test Code
 * Test files contain real credentials, API keys, database connection strings,
 * PII, or production secrets that get committed to source control.
 */
function verifyCWE531(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const TEST_FILE_RE531 = /\b(test|spec|__tests__|__mocks__|\.test\.|\.spec\.|_test\.|_spec\.)\b/i;
  const REAL_CRED_RE531 = /\b(password|passwd|secret|api_?key|apiKey|private_?key|client_?secret|access_?token|auth_?token|bearer)\s*[:=]\s*['"`](?!(?:test|fake|dummy|mock|example|xxx|password|123|changeme|TODO|REPLACE|placeholder|your_)['"` ])[A-Za-z0-9+/=_\-]{8,}/i;
  const CONN_STRING_RE531 = /\b(mongodb|postgres|mysql|redis|amqp|smtp):\/\/[^'"` ]*:[^'"` ]*@(?!localhost|127\.0\.0\.1|example\.com|test)/i;
  const AWS_KEY_RE531 = /\bAKIA[A-Z0-9]{16}\b/;
  const PRIVATE_KEY_RE531 = /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/;
  const PII_RE531 = /\b(ssn|social.?security|credit.?card|card.?number)\s*[:=]\s*['"`]\d{3,}/i;
  const FAKE_RE531 = /\b(mock|fake|dummy|stub|fixture|example|test_?data|sample|placeholder|TODO|REPLACE_ME)\b/i;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    const isTest = TEST_FILE_RE531.test(node.label) || TEST_FILE_RE531.test(node.id) ||
      node.node_subtype.includes('test') || node.node_subtype.includes('spec');

    if (!isTest) continue;

    if (REAL_CRED_RE531.test(code) && !FAKE_RE531.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use fake/mock credentials in test code)',
        severity: 'high',
        description: `Test code at ${node.label} contains what appears to be real credentials. ` +
          'Test files are committed to source control and may be public. Real secrets in tests get leaked.',
        fix: 'Use environment variables or a secrets manager for test credentials. ' +
          'Use obviously fake values like "test-api-key-do-not-use" for unit tests. ' +
          'Add pre-commit hooks to detect secrets (git-secrets, detect-secrets).',
        via: 'structural',
      });
    }

    if (CONN_STRING_RE531.test(code) && !FAKE_RE531.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use test/mock database connections)',
        severity: 'high',
        description: `Test code at ${node.label} contains a connection string pointing to what appears to be a real server. ` +
          'Production database credentials in test files are a common source of data breaches.',
        fix: 'Use environment variables for connection strings. Use testcontainers or in-memory databases for tests. ' +
          'Never hardcode production connection strings anywhere, especially test files.',
        via: 'structural',
      });
    }

    if (AWS_KEY_RE531.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (remove real AWS keys from test code)',
        severity: 'critical',
        description: `Test code at ${node.label} contains an AWS access key (AKIA...). ` +
          'AWS keys in source control are automatically scraped by bots. Account compromise is likely within minutes.',
        fix: 'Immediately rotate the exposed AWS key. Use IAM roles, STS, or environment variables instead. ' +
          'Add AWS key patterns to .gitignore and pre-commit hooks.',
        via: 'structural',
      });
    }

    if (PRIVATE_KEY_RE531.test(code) && !FAKE_RE531.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use generated test-only keys, not real private keys)',
        severity: 'critical',
        description: `Test code at ${node.label} contains a private key. ` +
          'If this is a real key (not a test fixture), it is compromised the moment it is committed.',
        fix: 'Generate ephemeral test-only keys in CI. Use mkcert for local development. ' +
          'Never commit real private keys to source control.',
        via: 'structural',
      });
    }

    if (PII_RE531.test(code) && !FAKE_RE531.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use synthetic PII in test data)',
        severity: 'high',
        description: `Test code at ${node.label} contains what appears to be real PII (SSN, credit card). ` +
          'Using real PII in tests violates privacy regulations (GDPR, CCPA, PCI-DSS).',
        fix: 'Use synthetic test data generators (faker.js, Bogus). ' +
          'Never use real customer data in tests. This may be a compliance violation.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-531', name: 'Inclusion of Sensitive Information in Test Code', holds: findings.length === 0, findings };
}

/**
 * CWE-535: Exposure of Information Through Shell Error Message
 * Pattern: Shell commands (exec, spawn, system) whose stderr output is returned to users
 * without filtering. Stderr from commands reveals file paths, usernames, library versions.
 */
function verifyCWE535(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SHELL_EXEC_RE = /\b(exec|execSync|spawn|spawnSync|system|popen|proc_open|Runtime\.exec|Process\.Start|subprocess\.(run|call|Popen|check_output)|os\.system|os\.popen|child_process|shell_exec)\b/i;
  const STDERR_EXPOSE_RE = /\b(stderr|err\.message|err\.output|e\.message|error\.message|output\.toString|result\.toString|\.catch\s*\([^)]*\)\s*=>\s*res\.(?:send|json|write)|process\.stderr|STDERR|2>&1)\b/i;
  const RESPONSE_RE = /\b(res\.(?:send|json|write|status|end)|response\.(?:send|write|body|json)|ctx\.body|return\s+.*(?:error|err|stderr)|render\(.*err|HttpResponse|JsonResponse|ResponseEntity)\b/i;
  const SAFE_RE = /\b(generic.?error|custom.?error|sanitize.?error|filter.?output|\.replace\(.*stderr|safe.?message|error.?code\s*(?:only|instead)|2>\/dev\/null|stderr\s*=\s*(?:subprocess\.)?DEVNULL|captureStderr\s*[:=]\s*false|suppress.?stderr)\b/i;

  const shellNodes = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM' || n.node_type === 'EGRESS') &&
    SHELL_EXEC_RE.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const node of shellNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (STDERR_EXPOSE_RE.test(code) && RESPONSE_RE.test(code) && !SAFE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (filter shell error messages before returning to user)',
        severity: 'medium',
        description: `Shell command at ${node.label} exposes stderr/error output directly in HTTP responses. ` +
          'Shell error messages reveal file paths, system usernames, installed software versions, and internal architecture.',
        fix: 'Capture stderr separately and log it server-side. Return a generic error message to users. Never include raw command output in responses.',
        via: 'structural',
      });
    }
  }

  const egressNodes = nodesOfType(map, 'EGRESS');
  for (const shell of shellNodes) {
    for (const egress of egressNodes) {
      if (shell.id === egress.id) continue;
      const egressCode = stripComments(egress.analysis_snapshot || egress.code_snapshot);
      if (hasPathWithoutControl(map, shell.id, egress.id) &&
          (STDERR_EXPOSE_RE.test(egressCode) || /\b(err|error|stderr|output)\b/i.test(egressCode)) &&
          !SAFE_RE.test(egressCode) &&
          !findings.some(f => f.sink.id === egress.id && f.source.id === shell.id)) {
        findings.push({
          source: nodeRef(shell), sink: nodeRef(egress),
          missing: 'CONTROL (filter shell error output before reaching response)',
          severity: 'medium',
          description: `Shell command output from ${shell.label} flows to response at ${egress.label} without error filtering.`,
          fix: 'Intercept shell errors. Map to generic error codes. Log details server-side only.',
          via: 'bfs',
        });
      }
    }
  }
  // ---------------------------------------------------------------------------
  // Java-specific: detect sensitive data written to System.err (Juliet CWE-535)
  // Juliet pattern: OutputStreamWriter(System.err) + println("... Session ID:" + session.getId())
  // ---------------------------------------------------------------------------
  if (inferMapLanguage(map) === 'java') {
    const JAVA_STDERR_RE = /\bSystem\.err\b/;
    const JAVA_SENSITIVE_DATA_RE = /\b(session\.getId|password|token|secret|credential|ssn|creditCard|sessionId|Session\s*ID|getId\s*\(\))\b/i;

    for (const node of map.nodes) {
      const code = node.analysis_snapshot || node.code_snapshot;
      if (!code) continue;
      // Check System.err + sensitive data — the "safe" version doesn't write sensitive data to stderr at all
      if (JAVA_STDERR_RE.test(code) && JAVA_SENSITIVE_DATA_RE.test(code)) {
        if (!findings.some(f => f.source.id === node.id)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'TRANSFORM (filter sensitive data from stderr output)',
            severity: 'medium',
            description: `Code at ${node.label} writes sensitive information (session IDs, credentials) to System.err. Shell error streams may be captured in logs or exposed to administrators.`,
            fix: 'Do not write session IDs, passwords, or other sensitive data to stderr. Use generic messages instead.',
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-535', name: 'Exposure of Info Through Shell Error Message', holds: findings.length === 0, findings };
}

/**
 * CWE-533: Exposure of Sensitive Information Through Server Log Files
 * Juliet pattern: this.log("Username: " + username + " Session ID:" + session.getId())
 */
function verifyCWE533(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const LOG_CALL_RE = /\b(?:this\.)?log\s*\(|\blogger\.\w+\s*\(|\bLOG\.\w+\s*\(|\bgetServletContext\(\)\.log\s*\(/i;
  const SENSITIVE_DATA_RE = /\b(session\.getId|password|token|secret|credential|ssn|creditCard|sessionId|Session\s*ID|getId\s*\(\))\b/i;
  const SAFE_LOG_RE = /\b(logged\s+in|login\s+successful|invalid\s+characters)\b/i;
  // Cross-domain filter: a sensitive keyword like "password" appearing as a variable name
  // in the same code block as an unrelated log call (e.g. error handling) is NOT a finding.
  // Only flag when the sensitive data keyword appears on the SAME line as a log call.
  const LOG_WITH_SENSITIVE_RE = /\b(?:(?:this\.)?log|logger\.\w+|LOG\.\w+|getServletContext\(\)\.log)\s*\([^)]*\b(session\.getId|password|token|secret|credential|ssn|creditCard|sessionId|getId\s*\(\))\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!code) continue;
    if (SAFE_LOG_RE.test(code)) continue;
    // Check line-level co-occurrence: sensitive data must appear in a line that also has a log call
    const lines = code.split('\n');
    const hasLogWithSensitive = lines.some(line =>
      LOG_CALL_RE.test(line) && SENSITIVE_DATA_RE.test(line)
    ) || LOG_WITH_SENSITIVE_RE.test(code);
    if (hasLogWithSensitive) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (filter sensitive data from server logs)', severity: 'medium',
        description: `Code at ${node.label} logs sensitive information to server log files.`,
        fix: 'Do not log session IDs, passwords, or other sensitive data.',
        via: 'structural' });
    }
  }
  if (inferMapLanguage(map) === 'java') {
    for (const node of map.nodes) {
      if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (!code) continue;
      // If the method body has log() AND session.getId(), it's logging sensitive data.
      // The "good" variants don't call session.getId() in log calls at all.
      if (/\blog\s*\(/.test(code) && /\b(session\.getId|getId\s*\(\))\b/.test(code)) {
        if (!findings.some(f => f.source.id === node.id)) {
          findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (do not log session IDs)', severity: 'medium',
            description: `Method ${node.label} logs session ID to server log. Session IDs in logs enable session hijacking.`,
            fix: 'Remove session IDs from log messages.',
            via: 'structural' });
        }
      }
    }
  }
  return { cwe: 'CWE-533', name: 'Exposure of Sensitive Information Through Server Log Files', holds: findings.length === 0, findings };
}

/**
 * CWE-534: Exposure of Sensitive Information Through Debug Log Files
 * Juliet pattern: logger.log(Level.FINEST, "Username: " + username + " Session ID:" + session.getId())
 */
function verifyCWE534(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const DEBUG_LOG_RE = /\b(Level\s*\.\s*(FINEST|FINER|FINE|ALL|DEBUG|TRACE)|\.debug\s*\(|\.trace\s*\(|logger\.debug|LOG\.debug|console\.debug|logging\.debug)\b/i;
  const SENSITIVE_DATA_RE = /\b(session\.getId|password|token|secret|credential|ssn|creditCard|sessionId|Session\s*ID|getId\s*\(\))\b/i;
  const SAFE_DEBUG_RE = /\b(logged\s+in|login\s+successful|invalid\s+characters|generic)\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!code) continue;
    if (DEBUG_LOG_RE.test(code) && SENSITIVE_DATA_RE.test(code) && !SAFE_DEBUG_RE.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (filter sensitive data from debug logs)', severity: 'medium',
        description: `Code at ${node.label} logs sensitive information to debug log files.`,
        fix: 'Do not log session IDs or credentials at any log level.',
        via: 'structural' });
    }
  }
  if (inferMapLanguage(map) === 'java') {
    for (const node of map.nodes) {
      if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (!code) continue;
      if (/\blogger\.log\s*\(/.test(code) && /Level\s*\.\s*(FINEST|FINER|FINE|ALL)/.test(code) && /\b(session\.getId|getId\s*\(\))\b/.test(code)) {
        if (!findings.some(f => f.source.id === node.id)) {
          findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (do not log session IDs to debug log)', severity: 'medium',
            description: `Method ${node.label} logs session ID to debug log via Level.FINEST/FINE.`,
            fix: 'Remove session IDs from debug log messages.',
            via: 'structural' });
        }
      }
    }
  }
  return { cwe: 'CWE-534', name: 'Exposure of Sensitive Information Through Debug Log Files', holds: findings.length === 0, findings };
}

/**
 * CWE-536: Servlet Runtime Error Message Containing Sensitive Information
 * Pattern: Java servlets exposing runtime exceptions (stack traces, class names, SQL errors)
 * via default error pages or catch blocks that write exception details to the response.
 */
function verifyCWE536(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SERVLET_RE = /\b(HttpServlet|doGet|doPost|doPut|doDelete|@WebServlet|@RequestMapping|@GetMapping|@PostMapping|@Controller|@RestController|GenericServlet|javax\.servlet|jakarta\.servlet|Spring(?:Boot|MVC))\b/;
  const EXCEPTION_EXPOSE_RE = /\b(e\.getMessage|e\.toString|e\.getStackTrace|e\.printStackTrace|ex\.getMessage|exception\.getMessage|throwable\.getMessage|getWriter\(\)\.print.*(?:exception|error|stack)|response\.getWriter.*(?:Exception|Error|Throwable)|sendError.*getMessage|\.printStackTrace\s*\(\s*(?:response|out|writer)|stackTrace|getLocalizedMessage)\b/i;
  const SAFE_RE = /\b(custom.?error.?page|error-page|@ExceptionHandler|@ControllerAdvice|ErrorController|handleException|web\.xml.*error-page|genericError|sanitize|logger\.(?:error|warn)|log\.(?:error|warn))\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SERVLET_RE.test(code) && EXCEPTION_EXPOSE_RE.test(code) && !SAFE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (custom error page — no runtime exception details in servlet response)',
        severity: 'medium',
        description: `Servlet at ${node.label} writes exception details (stack traces, messages) to the HTTP response. ` +
          'Runtime error messages reveal class names, file paths, SQL queries, and framework internals.',
        fix: 'Use @ControllerAdvice/@ExceptionHandler (Spring) or error-page directives (web.xml). Log full details server-side.',
        via: 'structural',
      });
    }
  }

  const configNodes = map.nodes.filter(n =>
    n.node_type === 'META' || n.node_type === 'STRUCTURAL' ||
    /\b(web\.xml|application\.properties|application\.yml|spring.*config)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );
  for (const cfg of configNodes) {
    const code = stripComments(cfg.analysis_snapshot || cfg.code_snapshot);
    if (SERVLET_RE.test(code) && !SAFE_RE.test(code) &&
        /\b(debug\s*[:=]\s*true|server\.error\.include-stacktrace\s*[:=]\s*always|spring\.mvc\.throw-exception-if-no-handler-found\s*[:=]\s*false)\b/i.test(code)) {
      findings.push({
        source: nodeRef(cfg), sink: nodeRef(cfg),
        missing: 'CONTROL (disable verbose error output in servlet configuration)',
        severity: 'medium',
        description: `Servlet configuration at ${cfg.label} enables detailed error output. Stack traces will be visible to users.`,
        fix: 'Set server.error.include-stacktrace=never (Spring Boot). Configure custom error pages in web.xml.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-536', name: 'Servlet Runtime Error Message Info Leak', holds: findings.length === 0, findings };
}

/**
 * CWE-537: Java Runtime Error Message Containing Sensitive Information
 * Pattern: Java catch blocks exposing exception details (getMessage, printStackTrace, toString)
 * in responses. Broader than CWE-536 — covers all Java code, not just servlets.
 */
function verifyCWE537(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const JAVA_EXCEPTION_RE = /\b(catch\s*\(\s*(?:Exception|Throwable|RuntimeException|Error|IOException|SQLException|NullPointerException|ClassNotFoundException|NoSuchMethodException))\b/;
  const EXPOSE_RE = /\b(e\.getMessage|e\.toString|e\.getStackTrace|ex\.getMessage|exception\.getMessage|throwable\.getMessage|\.printStackTrace\s*\(|getLocalizedMessage|getCause\(\)\.getMessage|Throwable\.toString|Arrays\.toString\(.*stackTrace)\b/i;
  const RESPONSE_SINK_RE = /\b(response\.|res\.|out\.print|out\.write|PrintWriter|getWriter|getOutputStream|return\s+.*(?:getMessage|toString|stackTrace)|sendError|setEntity|ResponseEntity\..*body|ObjectMapper.*write)\b/i;
  const SAFE_RE = /\b(log\.(?:error|warn|info|debug)|logger\.(?:error|warn|info|debug)|LOG\.(?:error|warn)|System\.err|generic.?error|custom.?message|sanitize|safe.?message|error.?code|user.?friendly)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (JAVA_EXCEPTION_RE.test(code) && EXPOSE_RE.test(code) && RESPONSE_SINK_RE.test(code) && !SAFE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (replace Java exception details with generic error message)',
        severity: 'medium',
        description: `Java catch block at ${node.label} exposes exception details in output. ` +
          'Java exception messages often contain SQL queries, file paths, class names, and connection strings.',
        fix: 'Log the full exception server-side: logger.error("Operation failed", e). Return a generic error with an error ID for correlation.',
        via: 'structural',
      });
    }
  }

  const DANGEROUS_OP_RE = /\b(Class\.forName|getConnection|DriverManager|PreparedStatement|createStatement|JNDI|InitialContext|lookup\s*\(|newInstance|loadClass|FileInputStream|FileOutputStream|Socket|ServerSocket|URLConnection|HttpURLConnection)\b/;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (DANGEROUS_OP_RE.test(code) && !JAVA_EXCEPTION_RE.test(code) && !/\btry\b/.test(code)) {
      const isInEgress = node.node_type === 'EGRESS' || node.node_type === 'EXTERNAL';
      if (isInEgress) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (wrap dangerous operations in try-catch with generic error response)',
          severity: 'low',
          description: `Dangerous Java operation at ${node.label} lacks exception handling. Unhandled exceptions propagate to the default error handler, which may expose internal details.`,
          fix: 'Wrap in try-catch. Log full exception server-side. Return generic error message.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-537', name: 'Java Runtime Error Message Info Leak', holds: findings.length === 0, findings };
}

/**
 * CWE-600: Uncaught Exception in Servlet
 * UPGRADED — hand-written with specific servlet method detection and try/catch analysis.
 *
 * Pattern: Java servlet handler methods (doGet, doPost, doPut, doDelete, service)
 * contain operations that can throw exceptions (Integer.parseInt, Float.parseFloat,
 * InetAddress.getByName, Class.forName, getConnection, etc.) WITHOUT being wrapped
 * in a try/catch block. The uncaught exception propagates to the servlet container,
 * which typically returns a default error page with stack traces, class names, file
 * paths, and internal structure — useful for attacker reconnaissance.
 *
 * The generic version looked for TRANSFORM->EGRESS without CONTROL. The upgraded version:
 *   - Identifies servlet handler methods and classes extending HttpServlet
 *   - Finds dangerous operations that can throw checked/unchecked exceptions
 *   - Checks whether those operations are inside a try block
 *   - Checks whether the method signature declares 'throws' (letting exceptions propagate)
 *   - Safe: dangerous call is inside a try block with appropriate catch
 *   - Safe: @ExceptionHandler / @ControllerAdvice / web.xml error-page configured
 */
function verifyCWE600(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const lang = inferMapLanguage(map);

  // Only relevant for Java servlets — skip other languages entirely
  if (lang && lang !== 'java') {
    return { cwe: 'CWE-600', name: 'Uncaught Exception in Servlet', holds: true, findings: [] };
  }

  // Servlet class / method indicators
  const SERVLET_CLASS_RE = /\b(HttpServlet|GenericServlet|extends\s+HttpServlet|extends\s+AbstractTestCaseServlet|implements\s+Servlet|javax\.servlet|jakarta\.servlet|@WebServlet)\b/;
  const SERVLET_METHOD_RE = /\b(doGet|doPost|doPut|doDelete|doHead|doOptions|doTrace|service)\s*\(/;

  // Operations that can throw exceptions in servlet context
  const THROWABLE_OP_RE = /\b(Integer\.parseInt|Integer\.valueOf|Long\.parseLong|Long\.valueOf|Float\.parseFloat|Double\.parseDouble|Short\.parseShort|Byte\.parseByte|NumberFormat|InetAddress\.getByName|InetAddress\.getLocalHost|Class\.forName|getConnection|DriverManager\.|PreparedStatement|createStatement|executeQuery|executeUpdate|FileInputStream|FileOutputStream|FileReader|FileWriter|ObjectInputStream|ObjectOutputStream|Socket\s*\(|ServerSocket|URL\s*\(|URLConnection|HttpURLConnection|newInstance|loadClass|getResourceAsStream|getRemoteAddr|getRemoteHost|getByName)\b/;

  // Method-level throws clause — indicates exceptions propagate to container
  const THROWS_RE = /\bthrows\s+\w+/;

  // Global exception handlers that make servlet exception leakage safe
  const GLOBAL_HANDLER_RE = /\b(@ExceptionHandler|@ControllerAdvice|ErrorController|handleException|error-page|web\.xml.*error-page|<error-page>|server\.error\.include-stacktrace\s*[:=]\s*never)\b/i;

  // Check for global exception handling configuration
  const allCode = map.nodes.map(n => n.analysis_snapshot || n.code_snapshot).join('\n');
  if (GLOBAL_HANDLER_RE.test(allCode)) {
    return { cwe: 'CWE-600', name: 'Uncaught Exception in Servlet', holds: true, findings: [] };
  }

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Must be servlet code
    const isServletCode = SERVLET_CLASS_RE.test(code) || SERVLET_METHOD_RE.test(code);
    if (!isServletCode) continue;

    // Must contain a throwable operation
    if (!THROWABLE_OP_RE.test(code)) continue;

    // Check: is the dangerous operation inside a try block?
    // Strategy: split the code into lines, track try/catch nesting depth,
    // and check if throwable operations occur at depth 0.
    const lines = code.split('\n');
    let tryDepth = 0;
    let hasUncaughtOp = false;
    let uncaughtOpDesc = '';

    for (const line of lines) {
      const trimmed = line.trim();

      // Track try block nesting
      if (/\btry\s*\{/.test(trimmed) || /\btry\s*$/.test(trimmed)) {
        tryDepth++;
      }
      // A closing brace followed by catch reduces try depth
      if (/\}\s*catch\s*\(/.test(trimmed)) {
        if (tryDepth > 0) tryDepth--;
      }

      // Check if this line has a throwable operation
      const opMatch = trimmed.match(THROWABLE_OP_RE);
      if (opMatch && tryDepth === 0) {
        hasUncaughtOp = true;
        uncaughtOpDesc = opMatch[0];
        break;
      }
    }

    // Also flag if the method signature throws exceptions (letting them propagate)
    const hasThrowsClause = THROWS_RE.test(code) && THROWABLE_OP_RE.test(code);

    if (hasUncaughtOp || (hasThrowsClause && !_hasTryBlockCWE600(code))) {
      const opDesc = uncaughtOpDesc || code.match(THROWABLE_OP_RE)?.[0] || 'exception-throwing operation';
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (try/catch wrapping exception-throwing operations in servlet handler)',
        severity: 'medium',
        description: `Servlet handler at ${node.label} contains ${opDesc} without try/catch. ` +
          'Uncaught exceptions propagate to the servlet container, which returns default error pages ' +
          'exposing stack traces, class names, database types, and internal file paths.',
        fix: 'Wrap all exception-throwing operations in try/catch within servlet handlers. ' +
          'Log the full exception server-side (logger.error). Return a generic error response to the client. ' +
          'Configure custom error pages in web.xml or use @ControllerAdvice (Spring).',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-600', name: 'Uncaught Exception in Servlet', holds: findings.length === 0, findings };
}

function _hasTryBlockCWE600(code: string): boolean {
  return /\btry\s*\{/.test(code) || /\btry\s*\n\s*\{/.test(code);
}

/**
 * CWE-539: Use of Persistent Cookies Containing Sensitive Information
 * Pattern: Cookies with Expires/Max-Age containing sensitive data (session tokens, user data).
 * Persistent cookies survive browser restarts and are accessible from shared machines.
 */
function verifyCWE539(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const COOKIE_SET_RE = /\b(Set-Cookie|setCookie|setcookie|res\.cookie|response\.set_cookie|addCookie|cookies\.set|Cookie\(|http\.SetCookie|setHeader\s*\(\s*['"]Set-Cookie|document\.cookie\s*=)\b/i;
  const PERSISTENT_RE = /\b(expires|max-age|maxAge|Max-Age|setMaxAge|max_age|expiry|\.setExpires|\.setMaxAge\s*\(\s*(?!0\s*\))|maxAge\s*[:=]\s*(?!0\b|false|null|undefined))\b/i;
  const SENSITIVE_COOKIE_RE = /\b(session|token|auth|user|login|credential|password|jwt|bearer|access.?token|refresh.?token|api.?key|remember.?me|identity|account|role|permission|privilege|secret)\b/i;
  const SAFE_RE = /\b(encrypt|cipher|signed.?cookie|httpOnly|HttpOnly|secure|Secure|sameSite|SameSite|session.?cookie|\.sign\(|crypto\.|jwt\.sign|maxAge\s*[:=]\s*0\b|setMaxAge\s*\(\s*0\s*\)|expires\s*[:=]\s*(?:0|new\s+Date\s*\(\s*0|'Thu, 01 Jan 1970))\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (COOKIE_SET_RE.test(code) && PERSISTENT_RE.test(code) && SENSITIVE_COOKIE_RE.test(code) && !SAFE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use session cookies for sensitive data — no Expires/Max-Age)',
        severity: 'medium',
        description: `Cookie at ${node.label} stores sensitive data with persistence (Expires/Max-Age). ` +
          'Persistent cookies survive browser restarts and are accessible on shared/public computers.',
        fix: 'Use session cookies (no Expires/Max-Age) for sensitive data. Set Secure, HttpOnly, and SameSite flags. Encrypt if persistence is required.',
        via: 'structural',
      });
    }
  }

  const REMEMBER_ME_RE = /\b(remember.?me|keep.?logged.?in|stay.?signed.?in|persistent.?login|auto.?login)\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (REMEMBER_ME_RE.test(code) && COOKIE_SET_RE.test(code)) {
      const hasEncryption = /\b(encrypt|cipher|hmac|hash|bcrypt|argon|crypto|jwt\.sign|signed)\b/i.test(code);
      const hasRotation = /\b(rotate|regenerate|refresh|invalidate|revoke|single.?use|one.?time)\b/i.test(code);
      if (!hasEncryption && !hasRotation) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (encrypt remember-me tokens with rotation)',
          severity: 'high',
          description: `Remember-me cookie at ${node.label} lacks encryption or token rotation. ` +
            'Stolen remember-me cookies provide persistent unauthorized access.',
          fix: 'Use encrypted, single-use tokens for remember-me. Rotate tokens on each use. Store server-side token hash for validation.',
          via: 'structural',
        });
      }
    }
  }
  // --- Source-based detection: Java Cookie with setMaxAge pattern ---
  // The Juliet pattern spans multiple lines: new Cookie("name", "value") on one line
  // then cookie.setMaxAge(large_number) on another. The node-level scan misses this
  // because the cookie creation and the setMaxAge call may be in different code_snapshots.
  if (findings.length === 0) {
    const src539 = map.source_code || '';
    if (src539) {
      const lines = src539.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

        // Find: new Cookie("name", "value") — track the variable name
        const cookieMatch = line.match(/(\w+)\s*=\s*new\s+Cookie\s*\(/);
        if (cookieMatch) {
          const cookieVar = cookieMatch[1];
          // Look ahead for setMaxAge with a positive value (persistent cookie)
          for (let j = i + 1; j < Math.min(i + 15, lines.length); j++) {
            const ahead = lines[j];
            if (/^\s*\/\//.test(ahead) || /^\s*\*/.test(ahead)) continue;
            // Match: cookie.setMaxAge(positive_number) but not setMaxAge(0) or setMaxAge(-1)
            const maxAgeMatch = ahead.match(new RegExp(`\\b${cookieVar}\\.setMaxAge\\s*\\(\\s*(.+?)\\s*\\)`));
            if (maxAgeMatch) {
              const ageArg = maxAgeMatch[1].trim();
              // If the argument is 0 or negative, it's safe (session cookie or deletion)
              if (/^-?\d+$/.test(ageArg) && parseInt(ageArg, 10) <= 0) continue;
              if (ageArg === '0' || ageArg.startsWith('-')) continue;
              // Persistent cookie detected
              const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 3) || map.nodes[0];
              if (nearNode) {
                findings.push({
                  source: nodeRef(nearNode), sink: nodeRef(nearNode),
                  missing: 'CONTROL (use session cookies for sensitive data — no Expires/Max-Age)',
                  severity: 'medium',
                  description: `L${i + 1}: Cookie '${cookieVar}' created and made persistent with setMaxAge at L${j + 1}. ` +
                    'Persistent cookies survive browser restarts and are accessible on shared/public computers.',
                  fix: 'Use session cookies (setMaxAge(-1)) for sensitive data. Set Secure, HttpOnly, and SameSite flags.',
                  via: 'source_line_fallback',
                });
              }
              break;
            }
          }
        }
      }
    }
  }

  return { cwe: 'CWE-539', name: 'Persistent Cookies With Sensitive Info', holds: findings.length === 0, findings };
}

/**
 * CWE-541: Inclusion of Sensitive Information in an Include File
 * Pattern: Header/include files (.h, .inc, .php includes, shared configs) containing
 * credentials, API keys, or connection strings. Include files are often less protected
 * and may be served directly by misconfigured web servers.
 */
function verifyCWE541(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const INCLUDE_FILE_RE = /\b(\.h\b|\.inc\b|\.include\b|\.conf\b|\.cfg\b|\.ini\b|include\s*\(|require\s*\(|require_once|include_once|#include|import\s+(?:config|settings|credentials|secrets|database)|from\s+(?:config|settings|credentials|secrets)\s+import|\.properties\b|shared.?config|common.?config|global.?config)\b/i;
  const SENSITIVE_VALUE_RE = /\b(password|passwd|pwd|secret|api.?key|apikey|private.?key|access.?key|connection.?string|database.?url|db.?host|db.?pass|smtp.?pass|auth.?token|encryption.?key|signing.?key|master.?key|root.?password)\s*[:=]\s*['"`][^'"`]{4,}['"`]/i;
  const HARDCODED_CRED_RE = /(?:define\s*\(\s*['"](?:DB_|MYSQL_|SMTP_|API_|SECRET_|AUTH_)[A-Z_]*['"]\s*,\s*['"][^'"]+['"]|const\s+(?:PASSWORD|SECRET|API_KEY|DB_PASS|AUTH_TOKEN)\s*=\s*['"][^'"]+['"])/i;
  const SAFE_RE = /\b(process\.env|os\.environ|os\.getenv|ENV\[|System\.getenv|getenv\(|config\.|vault\.|secretManager|parameterStore|keyVault|dotenv|configparser|placeholder|example|dummy|changeme|xxx|your.?key.?here)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const isInclude = INCLUDE_FILE_RE.test(code) || INCLUDE_FILE_RE.test(node.label) ||
      node.node_type === 'META' || node.node_subtype.includes('config') || node.node_subtype.includes('include');

    if (isInclude && (SENSITIVE_VALUE_RE.test(code) || HARDCODED_CRED_RE.test(code)) && !SAFE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (externalize secrets from include files)',
        severity: 'high',
        description: `Include/config file at ${node.label} contains hardcoded sensitive values. ` +
          'Include files are often world-readable, in VCS, and may be directly served by misconfigured web servers.',
        fix: 'Move secrets to environment variables or a secret manager. Include files should reference config sources, not contain credentials.',
        via: 'structural',
      });
    }
  }

  const WEB_SERVE_RE = /\.(inc|conf|cfg|ini|properties|bak|old|orig|save)$/i;
  for (const node of map.nodes) {
    if (WEB_SERVE_RE.test(node.label)) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (SENSITIVE_VALUE_RE.test(code) && !SAFE_RE.test(code)) {
        if (!findings.some(f => f.source.id === node.id)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (prevent web server from serving include files)',
            severity: 'high',
            description: `File ${node.label} has an extension web servers may serve directly. Contains sensitive values that would be exposed.`,
            fix: 'Move files outside web root, or deny access to .inc/.conf/.ini files. Externalize secrets.',
            via: 'structural',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-541', name: 'Sensitive Info in Include File', holds: findings.length === 0, findings };
}

/**
 * CWE-543: Use of Singleton Pattern Without Synchronization in Multithreaded Context
 * Pattern: Singleton implementations (static instance, getInstance) lacking synchronization.
 * Unsynchronized singletons can be instantiated multiple times or return partially constructed objects.
 */
function verifyCWE543(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SINGLETON_RE = /\b(getInstance|get_instance|instance\s*\(\)|\.instance\b|static\s+instance|private\s+static\s+\w+\s+instance|_instance|INSTANCE|singleton|Singleton)\b/i;
  const LAZY_INIT_RE = /\b(if\s*\(\s*!?\s*(?:instance|_instance|INSTANCE|self\._instance|cls\._instance)\s*(?:===?\s*null|===?\s*undefined|==\s*nil|!\s*=\s*null|is\s+None|\.?\s*nil\?))/i;
  const SYNC_SAFE_RE = /\b(synchronized|@Synchronized|lock\s*\(|Lock\s*\(|Mutex|mutex|ReentrantLock|AtomicReference|volatile|std::once|call_once|dispatch_once|threading\.Lock|asyncio\.Lock|Lazy<|lazy\s+val|Object\.freeze|sealed|enum\s+\w+\s*\{.*instance|double.?check|DCL|CompareAndSwap|compareAndSet|AtomicBoolean)\b/i;
  const THREAD_CONTEXT_RE = /\b(Thread|thread|Runnable|Callable|async|await|concurrent|parallel|goroutine|go\s+func|spawn|worker|Worker|multithread|pool|executor|CompletableFuture|Future|Promise|Task\.Run|tokio|actix)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SINGLETON_RE.test(code) && LAZY_INIT_RE.test(code) && !SYNC_SAFE_RE.test(code)) {
      const hasThreadContext = THREAD_CONTEXT_RE.test(code) ||
        map.nodes.some(n => n.id !== node.id && THREAD_CONTEXT_RE.test(n.analysis_snapshot || n.code_snapshot));
      if (hasThreadContext) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (synchronize singleton instantiation)',
          severity: 'medium',
          description: `Singleton at ${node.label} uses lazy initialization without synchronization in a multithreaded context. ` +
            'Race condition: two threads can create separate instances, corrupting shared state or breaking security invariants.',
          fix: 'Use double-checked locking with volatile (Java), std::call_once (C++), dispatch_once (Swift), or eager initialization.',
          via: 'structural',
        });
      }
    }
  }

  const SEC_SINGLETON_RE = /\b(SecurityManager|AuthManager|TokenStore|SessionManager|PermissionCache|RoleManager|CryptoProvider|KeyManager|TrustManager|CredentialStore|AuthenticationProvider)\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SINGLETON_RE.test(code) && SEC_SINGLETON_RE.test(code) && !SYNC_SAFE_RE.test(code)) {
      if (!findings.some(f => f.source.id === node.id)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (synchronize security-critical singleton)',
          severity: 'high',
          description: `Security-critical singleton at ${node.label} (${SEC_SINGLETON_RE.exec(code)?.[0] || 'security manager'}) lacks synchronization. ` +
            'Unsynchronized access to security state can cause auth bypass or privilege escalation.',
          fix: 'Make security singletons thread-safe. Use synchronized access or immutable state. Consider dependency injection.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-543', name: 'Singleton Without Synchronization', holds: findings.length === 0, findings };
}

/**
 * CWE-544: Missing Standardized Error Handling Mechanism
 * Pattern: Applications without centralized error handler — scattered try/catch, inconsistent
 * error responses. Leads to information leaks, inconsistent behavior, and unhandled edge cases.
 */
function verifyCWE544(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code provides error handling building blocks — it IS the standardized mechanism
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-544', name: 'Missing Standardized Error Handling Mechanism', holds: true, findings };
  }

  const CENTRALIZED_HANDLER_RE = /\b(app\.use\s*\(\s*(?:function\s*\(err|.*error.*middleware|errorHandler)|@ControllerAdvice|@ExceptionHandler|ErrorBoundary|error_handler|rescue_from|exception_handler|EXCEPTION_HANDLER|set_exception_handler|set_error_handler|sys\.excepthook|middleware.*error|error.*middleware|global.*error.*handler|unhandledRejection|uncaughtException|window\.onerror|process\.on\s*\(\s*['"](?:uncaughtException|unhandledRejection))\b/i;
  const INLINE_ERROR_RE = /\b(catch\s*\(|except\s+|rescue\s|on\s+.*catch|\.catch\s*\()\b/;
  const INCONSISTENT_RESPONSE_RE = /\b(res\.status\s*\(\s*500\s*\)\.send\s*\(\s*(?:err|e|error)|response\.sendStatus\s*\(\s*500|throw\s+new\s+Error|raise\s+\w*Error|panic\s*\()\b/i;

  let hasCentralizedHandler = false;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (CENTRALIZED_HANDLER_RE.test(code)) {
      hasCentralizedHandler = true;
      break;
    }
  }

  if (!hasCentralizedHandler) {
    let inlineHandlerCount = 0;
    let inconsistentCount = 0;
    const errorHandlerNodes: NeuralMapNode[] = [];

    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (INLINE_ERROR_RE.test(code)) {
        inlineHandlerCount++;
        errorHandlerNodes.push(node);
      }
      if (INCONSISTENT_RESPONSE_RE.test(code)) {
        inconsistentCount++;
      }
    }

    if (inlineHandlerCount >= 4 || inconsistentCount > 0) {
      const sample = errorHandlerNodes.slice(0, 3);
      for (const node of sample) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (centralized error handling mechanism)',
          severity: 'medium',
          description: `Application has ${inlineHandlerCount} scattered error handlers but no centralized mechanism. ` +
            `Error handler at ${node.label} handles errors ad-hoc. Inconsistent handling leads to information leaks.`,
          fix: 'Implement centralized error handling: app.use(errorHandler) (Express), @ControllerAdvice (Spring), ErrorBoundary (React).',
          via: 'structural',
        });
      }
    }

    const SWALLOW_RE = /catch\s*\([^)]*\)\s*\{\s*\}|except\s*:\s*pass|rescue\s*=>\s*nil|\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)/;
    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (SWALLOW_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (handle errors instead of swallowing them)',
          severity: 'medium',
          description: `Empty catch block at ${node.label} silently swallows errors. ` +
            'Swallowed errors hide failures, mask security issues, and make debugging impossible.',
          fix: 'At minimum, log caught errors. Better: propagate to a centralized error handler.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-544', name: 'Missing Standardized Error Handling', holds: findings.length === 0, findings };
}

/**
 * CWE-612: Improper Authorization of Index Containing Sensitive Information
 * Pattern: Search indexes (Elasticsearch, Solr, Algolia, database full-text search)
 * that include sensitive fields without proper access controls, allowing unauthorized
 * users to discover sensitive data through search queries.
 */
function verifyCWE612(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SEARCH_INDEX_RE = /\b(elasticsearch|elastic|solr|algolia|meilisearch|typesense|opensearch|lucene|sphinx|whoosh|createIndex|putMapping|addDocuments|indexing|searchIndex|full.?text.?search|text.?index|CREATE\s+(?:FULLTEXT\s+)?INDEX|\.index\s*\(|\.bulk\s*\(|\.search\s*\(|SearchClient|IndexWriter|addToIndex|reindex|indexDocument)\b/i;
  const SENSITIVE_FIELD_RE = /\b(password|passwd|ssn|social.?security|credit.?card|card.?number|cvv|secret|private.?key|api.?key|token|birth.?date|dob|salary|medical|diagnosis|health|income|tax.?id|bank.?account|routing.?number|national.?id|driver.?license|passport.?number|biometric|fingerprint|dna|genetic|sexual|religion|ethnicity|political|union.?membership|criminal|arrest|conviction)\b/i;
  const ACCESS_CONTROL_RE = /\b(authorization|authenticate|rbac|acl|access.?control|permission|role.?check|isAdmin|isAuthorized|canAccess|hasPermission|hasRole|security.?filter|document.?level.?security|field.?level.?security|row.?level.?security|index.?security|search.?guard|shield|x-pack|opendistro.?security|readonlyrest|filtered.?alias|_source.?excludes|stored.?fields|exclude.?fields|sensitiveFields|redact|mask)\b/i;
  const FIELD_MAPPING_RE = /\b(fields|mappings|properties|schema|columns|_source|attributes|includedFields|searchableAttributes|indexedFields)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Look for search index definitions that include sensitive fields
    if (SEARCH_INDEX_RE.test(code) && SENSITIVE_FIELD_RE.test(code)) {
      if (!ACCESS_CONTROL_RE.test(code)) {
        const sensitiveMatch = SENSITIVE_FIELD_RE.exec(code);
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (access control on search index containing sensitive fields)',
          severity: 'high',
          description: `Search index at ${node.label} includes sensitive field "${sensitiveMatch?.[0] || 'sensitive data'}" ` +
            'without access controls. Users can discover sensitive information through search queries.',
          fix: 'Exclude sensitive fields from search indexes, or implement field-level security. ' +
            'Use _source excludes, field-level security (Elasticsearch), or separate indexes with access controls. ' +
            'Never index PII/credentials in publicly searchable indexes.',
          via: 'structural',
        });
      }
    }

    // Check for field mappings that expose sensitive data in search results
    if (FIELD_MAPPING_RE.test(code) && SEARCH_INDEX_RE.test(code) && SENSITIVE_FIELD_RE.test(code)) {
      const hasExclusion = /\b(exclude|omit|remove|filter|redact|mask|_source.*(?:excludes|exclude)|(?:excludes|exclude).*_source)\b/i.test(code);
      if (!hasExclusion && !ACCESS_CONTROL_RE.test(code)) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (exclude sensitive fields from search index mappings)',
          severity: 'medium',
          description: `Index field mapping at ${node.label} does not exclude sensitive fields from search results. ` +
            'Search APIs may return sensitive data in highlighted snippets or _source.',
          fix: 'Use _source excludes to prevent sensitive fields from appearing in search results. ' +
            'Configure field-level security or filtered aliases to restrict access.',
          via: 'structural',
        });
      }
    }
  }

  // Check for search endpoints that don't enforce authorization
  const searchEndpoints = map.nodes.filter(n =>
    (n.node_type === 'INGRESS' || n.node_type === 'STRUCTURAL') &&
    /\b(search|query|find|lookup|autocomplete|suggest|typeahead)\b/i.test(n.analysis_snapshot || n.code_snapshot) &&
    /\b(get|post|route|endpoint|api|handler|controller)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );
  for (const endpoint of searchEndpoints) {
    const code = stripComments(endpoint.analysis_snapshot || endpoint.code_snapshot);
    if (!ACCESS_CONTROL_RE.test(code)) {
      // Check if any connected CONTROL node provides auth
      const hasAuthControl = map.nodes.some(n =>
        n.node_type === 'CONTROL' &&
        ACCESS_CONTROL_RE.test(n.analysis_snapshot || n.code_snapshot) &&
        (n.edges.some(e => e.target === endpoint.id) ||
        endpoint.edges.some(e => e.target === n.id))
      );
      if (!hasAuthControl) {
        // Only flag if there are sensitive-field indexes elsewhere in the map
        const hasSensitiveIndex = map.nodes.some(n =>
          SEARCH_INDEX_RE.test(n.analysis_snapshot || n.code_snapshot) && SENSITIVE_FIELD_RE.test(n.analysis_snapshot || n.code_snapshot)
        );
        if (hasSensitiveIndex) {
          findings.push({
            source: nodeRef(endpoint),
            sink: nodeRef(endpoint),
            missing: 'AUTH (authorization check on search endpoint accessing sensitive index)',
            severity: 'high',
            description: `Search endpoint at ${endpoint.label} lacks authorization but the codebase indexes sensitive data. ` +
              'Unauthenticated users could discover sensitive information through search queries.',
            fix: 'Add authentication and authorization to search endpoints. Implement query-time filtering to restrict results based on user permissions.',
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-612', name: 'Improper Authorization of Index Containing Sensitive Information', holds: findings.length === 0, findings };
}

/**
 * CWE-549: Missing Password Field Masking
 * Source scan for password fields that are not masked:
 * - HTML password inputs using type="text" instead of type="password"
 * - JPasswordField.getText() instead of getPassword()
 * The Juliet pattern: Servlet writing HTML with <input name="password" type="text">
 */
function verifyCWE549(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Pattern 1: HTML password field with type="text" (the Juliet Servlet pattern)
  // Matches: <input ... name="password" ... type="text" ...> or reverse order
  // Handles both plain quotes and backslash-escaped quotes (Java source has \" in string literals)
  const Q = `(?:\\\\?["'])`;  // matches " or ' or \" or \'
  const PASSWORD_FIELD_TEXT_RE = new RegExp(
    `name\\s*=\\s*${Q}password${Q}[^>]*type\\s*=\\s*${Q}text${Q}|type\\s*=\\s*${Q}text${Q}[^>]*name\\s*=\\s*${Q}password${Q}`, 'i'
  );

  // Pattern 2: JPasswordField.getText() — deprecated, returns password as String (stays in memory)
  const JPASSWORD_GET_TEXT_RE = /JPasswordField\b[\s\S]*?\.getText\s*\(/;

  // Pattern 3: HTML form with password field sent via GET method
  const FORM_GET_PASSWORD_RE = new RegExp(
    `method\\s*=\\s*${Q}get${Q}[\\s\\S]*?name\\s*=\\s*${Q}password${Q}|name\\s*=\\s*${Q}password${Q}[\\s\\S]*?method\\s*=\\s*${Q}get${Q}`, 'i'
  );

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (PASSWORD_FIELD_TEXT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (password field masking — type="password")',
        severity: 'medium',
        description: `Password field rendered with type="text" at ${node.label}. ` +
          `The password is visible on screen, enabling shoulder-surfing attacks.`,
        fix: 'Use type="password" for all password input fields. This masks the entered characters ' +
          'and prevents the password from being visible to bystanders.',
        via: 'structural',
      });
    }

    if (JPASSWORD_GET_TEXT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (use getPassword() instead of getText())',
        severity: 'medium',
        description: `JPasswordField.getText() used at ${node.label}. ` +
          `getText() returns a String which stays in memory until GC. getPassword() returns char[] that can be zeroed.`,
        fix: 'Use JPasswordField.getPassword() instead of getText(). After using the char[], ' +
          'zero it with Arrays.fill(password, \'\\0\') to minimize the time the password is in memory.',
        via: 'structural',
      });
    }

    if (FORM_GET_PASSWORD_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (use POST method for password forms)',
        severity: 'high',
        description: `Password field in a form using GET method at ${node.label}. ` +
          `GET puts the password in the URL, visible in browser history, server logs, and referrer headers.`,
        fix: 'Use method="post" for forms containing password fields. Never send passwords via GET — ' +
          'they appear in URLs, browser history, proxy logs, and HTTP Referer headers.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-549', name: 'Missing Password Field Masking', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const SENSITIVE_DATA_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-200': verifyCWE200,
  'CWE-209': verifyCWE209,
  'CWE-210': verifyCWE210,
  'CWE-211': verifyCWE211,
  'CWE-212': verifyCWE212,
  'CWE-213': verifyCWE213,
  'CWE-214': verifyCWE214,
  'CWE-215': verifyCWE215,
  'CWE-222': verifyCWE222,
  'CWE-223': verifyCWE223,
  'CWE-224': verifyCWE224,
  'CWE-226': verifyCWE226,
  'CWE-256': verifyCWE256,
  'CWE-257': verifyCWE257,
  'CWE-260': verifyCWE260,
  'CWE-312': verifyCWE312,
  'CWE-313': verifyCWE313,
  'CWE-314': verifyCWE314,
  'CWE-315': verifyCWE315,
  'CWE-316': verifyCWE316,
  'CWE-319': verifyCWE319,
  'CWE-359': verifyCWE359,
  'CWE-402': verifyCWE402,
  'CWE-472': verifyCWE472,
  'CWE-473': verifyCWE473,
  'CWE-474': verifyCWE474,
  'CWE-488': verifyCWE488,
  'CWE-497': verifyCWE497,
  'CWE-524': verifyCWE524,
  'CWE-525': verifyCWE525,
  'CWE-526': verifyCWE526,
  'CWE-527': verifyCWE527,
  'CWE-528': verifyCWE528,
  'CWE-529': verifyCWE529,
  'CWE-531': verifyCWE531,
  'CWE-532': verifyCWE532,
  'CWE-533': verifyCWE533,
  'CWE-534': verifyCWE534,
  'CWE-535': verifyCWE535,
  'CWE-536': verifyCWE536,
  'CWE-537': verifyCWE537,
  'CWE-538': verifyCWE538,
  'CWE-539': verifyCWE539,
  'CWE-540': verifyCWE540,
  'CWE-541': verifyCWE541,
  'CWE-543': verifyCWE543,
  'CWE-544': verifyCWE544,
  'CWE-548': verifyCWE548,
  'CWE-549': verifyCWE549,
  'CWE-550': verifyCWE550,
  'CWE-552': verifyCWE552,
  'CWE-598': verifyCWE598,
  'CWE-600': verifyCWE600,
  'CWE-612': verifyCWE612,
  'CWE-615': verifyCWE615,
  'CWE-798': verifyCWE798,
};
