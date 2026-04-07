/**
 * Malicious Code & Covert Channel CWE Verifiers
 *
 * Trojan horse, spyware, covert channels, logic bombs, virus detection,
 * trapdoors, embedded malicious code, and download integrity.
 * Pure source-code scanners: no taint dependency.
 *
 * Extracted from verifier/index.ts — Phase 7 of the monolith split.
 */

import type { NeuralMap } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments } from './source-analysis.ts';
import { nodeRef, nodesOfType, hasPathWithoutControl, findContainingFunction } from './graph-helpers.ts';

function verifyCWE494(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const REMOTE_FETCH_RE = /\b(fetch|axios|http\.get|https\.get|request|got|node-fetch|urllib|requests\.get|curl_exec|wget|file_get_contents\s*\(\s*['"]https?:)|import\s*\(\s*['"]https?:|<script\s+src\s*=\s*['"]https?:/i;
  const CODE_EXEC_RE = /\b(eval|exec|Function\s*\(|new\s+Function|execSync|spawnSync|child_process|subprocess|os\.system|os\.popen|require\s*\(|import\s*\(|execfile|compile\s*\(|load\s*\(|runInContext|vm\.run|importlib|__import__|dlopen|LoadLibrary|Assembly\.Load)/i;
  const WRITE_EXEC_RE = /\b(writeFile|writeFileSync|fs\.write|fwrite|file_put_contents|open\s*\(.*['"]w|pipe|createWriteStream)/i;
  const INTEGRITY_RE = /\b(sha256|sha384|sha512|checksum|digest|verify|createHash|hashlib|MessageDigest|integrity\s*=|SRI|subresource|gpg|pgp|sigstore|cosign|notary|createVerify|crypto\.verify|hmac|signedUrl|signature)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!REMOTE_FETCH_RE.test(code)) continue;

    for (const downstream of map.nodes) {
      if (downstream.id === node.id) continue;
      if (!(CODE_EXEC_RE.test(downstream.analysis_snapshot || downstream.code_snapshot) || WRITE_EXEC_RE.test(downstream.analysis_snapshot || downstream.code_snapshot))) continue;

      if (hasPathWithoutControl(map, node.id, downstream.id)) {
        const pathCode = stripComments(node.analysis_snapshot || node.code_snapshot) + ' ' + stripComments(downstream.analysis_snapshot || downstream.code_snapshot);
        if (!INTEGRITY_RE.test(pathCode)) {
          findings.push({
            source: nodeRef(node),
            sink: nodeRef(downstream),
            missing: 'CONTROL (integrity verification — hash check, signature validation, or SRI)',
            severity: 'high',
            description: `Remote content fetched at ${node.label} reaches code execution/write at ${downstream.label} without integrity verification. ` +
              `An attacker who compromises the remote source or performs MITM can inject arbitrary code.`,
            fix: 'Verify integrity before execution: compare SHA-256 hash against a pinned value, validate a cryptographic signature, ' +
              'or use Subresource Integrity (SRI) for browser scripts. Pin dependencies by hash (npm integrity, pip --require-hashes).',
            via: 'bfs',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-494', name: 'Download of Code Without Integrity Check', holds: findings.length === 0, findings };
}

/**
 * CWE-506: Embedded Malicious Code
 * Pattern: Code that performs suspicious operations hidden in seemingly benign contexts —
 * obfuscated eval, encoded payloads, hidden network exfiltration, steganographic data.
 * Static analysis cannot prove intent, but CAN flag high-entropy obfuscation, hidden eval,
 * and suspicious encoding patterns that warrant human review.
 */
function verifyCWE506(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const OBFUSCATED_EXEC_RE = /\b(eval\s*\(\s*atob|eval\s*\(\s*Buffer\.from|eval\s*\(\s*String\.fromCharCode|eval\s*\(\s*unescape|eval\s*\(\s*decodeURIComponent|Function\s*\(\s*atob|Function\s*\(\s*Buffer\.from|exec\s*\(\s*base64|exec\s*\(\s*decode|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}|\\u00[0-9a-f]{2}\\u00[0-9a-f]{2}|fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+)/i;
  const BASE64_PAYLOAD_RE = /['"][A-Za-z0-9+/]{80,}={0,2}['"]/;
  const HEX_PAYLOAD_RE = /(?:\\x[0-9a-fA-F]{2}){20,}|['"](?:[0-9a-fA-F]{2}){40,}['"]/;
  const HIDDEN_NET_RE = /\b(atob|Buffer\.from|fromCharCode|decode)\b.*\b(fetch|XMLHttpRequest|http|net\.connect|socket|WebSocket)/i;
  const EXEC_NEAR_RE = /\b(eval|exec|Function|spawn|system|popen|subprocess|child_process|vm\.run|execSync)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (OBFUSCATED_EXEC_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (obfuscated code execution detected)',
        severity: 'critical',
        description: `${node.label} contains obfuscated code execution (eval of decoded/encoded content). ` +
          `Runtime-decoded payloads evade static review — the primary pattern of embedded malicious code.`,
        fix: 'Remove obfuscated eval. If legitimate, refactor to clear readable logic. If a dependency, audit or replace it.',
        via: 'source_line_fallback',
      });
    } else if (BASE64_PAYLOAD_RE.test(code) && EXEC_NEAR_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (large encoded payload near code execution)',
        severity: 'high',
        description: `${node.label} contains a large base64-encoded string near code execution primitives. ` +
          `Encoded payloads combined with eval/exec are a strong indicator of embedded malicious code.`,
        fix: 'Decode and review the base64 content. If legitimate (embedded font/image), move to a separate asset file. Never eval decoded content.',
        via: 'source_line_fallback',
      });
    } else if (HEX_PAYLOAD_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (hex-encoded payload — possible shellcode)',
        severity: 'high',
        description: `${node.label} contains a long hex-encoded byte sequence, commonly used for shellcode or obfuscated payloads.`,
        fix: 'Review the hex content. If binary data (image, key), store in a separate file, not inline code.',
        via: 'source_line_fallback',
      });
    } else if (HIDDEN_NET_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (decoded content used in network call)',
        severity: 'high',
        description: `${node.label} decodes content and passes it to a network API. Hiding network destinations behind encoding is a common malware obfuscation technique.`,
        fix: 'Use plaintext URLs. If dynamic routing is needed, use a configuration file, not encoded strings.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-506', name: 'Embedded Malicious Code', holds: findings.length === 0, findings };
}

/**
 * CWE-507: Trojan Horse
 * Pattern: Code that appears to perform one function but contains hidden secondary behavior —
 * a benign-looking function/module that ALSO performs unauthorized operations (network calls,
 * file writes, process spawning) that don't match its declared purpose.
 * Detection: Find STRUCTURAL nodes whose label suggests benign purpose but whose children
 * include unexpected EXTERNAL calls or destructive STORAGE writes.
 */
function verifyCWE507(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const BENIGN_NAME_RE = /\b(format|stringify|parse|validate|sanitize|trim|capitalize|camelCase|snakeCase|pluralize|pad|truncate|sort|filter|map|reduce|utils?|helpers?|convert|transform|encode|decode|render|template|display|toString|toJSON|toArray|compare|equals|clone|copy|merge|debounce|throttle|memoize|logger|log|print)\b/i;
  const SUSPICIOUS_OP_RE = /\b(fetch|http\.get|https\.get|axios|request\(|XMLHttpRequest|net\.connect|dgram|WebSocket|child_process|exec\(|spawn|fork|cluster\.fork|os\.system|subprocess|popen|socket\.connect|dns\.resolve|fs\.write|writeFile|fs\.unlink|rm\s+-rf|process\.kill|require\s*\(\s*['"]child_process|require\s*\(\s*['"]net|require\s*\(\s*['"]dgram)/i;

  const structuralNodes = nodesOfType(map, 'STRUCTURAL');

  for (const fn of structuralNodes) {
    if (!BENIGN_NAME_RE.test(fn.label)) continue;

    const containedIds = new Set(
      fn.edges.filter(e => e.edge_type === 'CONTAINS').map(e => e.target)
    );

    for (const node of map.nodes) {
      if (!containedIds.has(node.id)) continue;
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);

      if (SUSPICIOUS_OP_RE.test(code)) {
        findings.push({
          source: nodeRef(fn),
          sink: nodeRef(node),
          missing: 'CODE REVIEW (hidden functionality in benign-appearing function)',
          severity: 'critical',
          description: `Function "${fn.label}" appears to be a utility/helper but contains ${node.node_type === 'EXTERNAL' ? 'network calls' : 'system operations'} at ${node.label}. ` +
            `Trojan horse code hides malicious operations inside trusted-looking functions.`,
          fix: 'Review this function. If the operation is intentional, rename to reflect its true purpose. If unexpected, remove — it may be injected malicious code.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-507', name: 'Trojan Horse', holds: findings.length === 0, findings };
}

/**
 * CWE-508: Non-Replicating Malicious Code
 * Pattern: Code that performs destructive or unauthorized actions but doesn't spread.
 * Detects: destructive file operations, data wiping, unauthorized data modification,
 * and kill/shutdown commands hidden in application code.
 * Key distinction from CWE-509 (virus): damages but doesn't propagate.
 */
function verifyCWE508(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DESTRUCTIVE_RE = /\b(rm\s+-rf\s+\/|rmdir\s+\/|del\s+\/[sq]|format\s+[a-z]:|DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*$|unlink\s*\(\s*['"]\/|removeSync\s*\(\s*['"]\/|shutil\.rmtree\s*\(\s*['"]\/|os\.remove|fs\.rmdirSync|rimraf\s*\(\s*['"]\/|deltree)/i;
  const SHUTDOWN_RE = /\b(process\.exit|sys\.exit|os\.kill|shutdown\s+-[hrf]|halt|poweroff|init\s+0|kill\s+-9|taskkill|TerminateProcess|ExitProcess|abort\(\))/i;
  const CORRUPT_RE = /\b(Math\.random\(\).*write|crypto\.randomBytes.*write|overwrite|corrupt|wipe|shred|zero.?fill|\/dev\/urandom.*dd\s+if)/i;
  const ADMIN_CONTEXT_RE = /\b(cleanup|teardown|shutdown.?hook|graceful.?shutdown|before.?exit|uninstall|migration|rollback|test.?fixture|afterAll|afterEach|dispose|destructor)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    const parentId = findContainingFunction(map, node.id);
    const parentNode = parentId ? map.nodes.find(n => n.id === parentId) : null;
    const inAdminContext = parentNode ? ADMIN_CONTEXT_RE.test(parentNode.label) || ADMIN_CONTEXT_RE.test(parentNode.analysis_snapshot || parentNode.code_snapshot) : false;
    if (inAdminContext) continue;

    if (DESTRUCTIVE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (destructive operation outside admin context)',
        severity: 'critical',
        description: `${node.label} contains destructive operations (mass file deletion, database wiping) outside a recognized admin/cleanup context. ` +
          `Non-replicating malicious code destroys data without spreading.`,
        fix: 'Review this destructive operation. If legitimate, wrap in admin-authenticated endpoint with confirmation. Add scope guards (never delete from root). If unexpected, may be planted malicious code.',
        via: 'source_line_fallback',
      });
    } else if (SHUTDOWN_RE.test(code) && !ADMIN_CONTEXT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (system shutdown outside graceful shutdown handler)',
        severity: 'high',
        description: `${node.label} contains system shutdown/kill commands outside a graceful shutdown handler. Unauthorized process termination can cause data loss and denial of service.`,
        fix: 'Move shutdown logic to a dedicated graceful shutdown handler. Ensure it is only triggered by legitimate signals.',
        via: 'source_line_fallback',
      });
    } else if (CORRUPT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (random data written to storage — possible corruption)',
        severity: 'high',
        description: `${node.label} writes random/garbage data to storage, a pattern consistent with data corruption malware.`,
        fix: 'Review why random data is being written. If test data generation, limit scope. If unexpected, investigate as possible malicious code.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-508', name: 'Non-Replicating Malicious Code', holds: findings.length === 0, findings };
}

/**
 * CWE-509: Replicating Malicious Code (Virus)
 * Pattern: Code that copies itself to other files, injects into other processes,
 * or modifies other executables. The key differentiator from CWE-508 is SELF-PROPAGATION.
 * Detection: Look for code that reads its own source and writes to other files,
 * or modifies other executables/scripts, or uses process injection primitives.
 */
function verifyCWE509(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SELF_READ_RE = /\b(__filename|__FILE__|process\.argv\[1\]|sys\.argv\[0\]|import\.meta\.url|module\.filename|inspect\.getfile|__file__|os\.path\.abspath\(__file__\))\b/i;
  const MODIFY_EXEC_RE = /\b(appendFile|writeFile|fs\.write|fwrite|file_put_contents|open\s*\(.*['"]a).*\.(js|py|rb|sh|bat|ps1|exe|dll|so|php|pl)|chmod\s+\+x|chmod\s+7/i;
  // Note: bare "inject" was removed — it matched "Injection" in class/package names
  // (e.g., CWE643_Xpath_Injection), causing cross-domain false positives.
  // Kept specific process-injection APIs only.
  const INJECT_RE = /\b(ptrace|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|NtWriteVirtualMemory|dlopen|LD_PRELOAD|DYLD_INSERT_LIBRARIES|process\.dlopen|ctypes\.windll|inject(?:_code|_dll|_shellcode|_payload|_thread|_process)\b|hook.*process)/i;
  const NET_SPREAD_RE = /\b(scp|rsync|psexec|wmic\s+.*process\s+call|net\s+use|ssh.*cat\s+.*>>|replicate|propagate|spread|infect)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (SELF_READ_RE.test(code)) {
      for (const target of map.nodes) {
        if (target.id === node.id) continue;
        if (MODIFY_EXEC_RE.test(stripComments(target.analysis_snapshot || target.code_snapshot))) {
          if (hasPathWithoutControl(map, node.id, target.id)) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(target),
              missing: 'CODE REVIEW (self-reading code flows to modification of other executables)',
              severity: 'critical',
              description: `Code at ${node.label} reads its own source and the content flows to file modification at ${target.label}. Self-replicating code (virus) copies itself into other files to spread.`,
              fix: 'Remove self-replication logic. If a legitimate build tool/installer, ensure it only modifies intended targets and is code-signed.',
              via: 'bfs',
            });
            break;
          }
        }
      }
    }

    if (INJECT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (process injection primitives detected)',
        severity: 'critical',
        description: `${node.label} uses process injection primitives (ptrace, WriteProcessMemory, LD_PRELOAD). These APIs inject code into other processes — a core virus/malware propagation technique.`,
        fix: 'Remove process injection calls unless this is a legitimate debugger/profiler. Use IPC instead of memory injection.',
        via: 'source_line_fallback',
      });
    }

    if (NET_SPREAD_RE.test(code) && SELF_READ_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (self-propagation over network)',
        severity: 'critical',
        description: `${node.label} contains patterns suggesting network self-propagation (copying self to remote hosts). This is the defining characteristic of a worm/virus.`,
        fix: 'Remove network propagation logic. Legitimate deployment should use CI/CD pipelines, not self-replicating code.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-509', name: 'Replicating Malicious Code (Virus)', holds: findings.length === 0, findings };
}

/**
 * CWE-510: Trapdoor
 * Pattern: Hidden logic triggered by specific identity conditions — hostname, IP address,
 * username, or environment identity checks that branch to privileged or different behavior.
 * This is the DECEPTIVE pattern: code looks normal but has a hidden branch for a specific
 * identity that grants access or alters behavior outside normal control flow.
 *
 * Detection:
 *   1. Hostname/IP identity gates: getHostName().equals("..."), getHostAddress().equals("...")
 *   2. User identity gates: getProperty("user.name").equals("..."), System.getenv("USER")
 *   3. Hardcoded backdoor credentials: master_pass, skeleton_key, god_mode, etc.
 *   4. Hidden endpoints: /_debug, /_backdoor, /__internal routes
 *   5. Environment variable auth bypass: SKIP_AUTH, NO_AUTH, DISABLE_AUTH
 *
 * Safe patterns:
 *   - Logging/auditing the identity without branching on it
 *   - Deny-list checks (blocking known-bad hosts) rather than allow-list grants
 *   - Display-only use (e.g., "Welcome, " + hostname) without conditional branching
 */
function verifyCWE510(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // --- Pattern 1: Hostname / IP identity-based trapdoor ---
  // Java: socket.getInetAddress().getHostName().equals("admin.google.com")
  // Python: socket.gethostname() ==, socket.gethostbyname("...")
  const HOSTNAME_EQUALS_RE = /(?:getHostName|getHostAddress|getCanonicalHostName|getRemoteAddr|getRemoteHost|gethostname)\s*\([\s)]*\.\s*equals\s*\(\s*["'][^"']+["']\s*\)/i;
  const IP_LITERAL_CMP_RE = /(?:\.equals|===?|==)\s*\(?\s*["']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["']\s*\)?/i;
  const HOSTNAME_CONDITIONAL_RE = /\b(?:if|when|unless|case)\b[^;{]*(?:getHostName|getHostAddress|getCanonicalHostName|getRemoteAddr|getRemoteHost|gethostname|remoteAddr|remoteAddress|REMOTE_ADDR)\s*\(/i;

  // --- Pattern 2: User identity-based trapdoor ---
  const USER_IDENTITY_RE = /(?:getProperty\s*\(\s*["']user\.name["']\)|getenv\s*\(\s*["'](?:USER|USERNAME|LOGNAME)["']\)|os\.getlogin\s*\(\)|Environment\.UserName|System\.getenv\s*\(\s*["'](?:USER|USERNAME)["']\))\s*\.\s*equals\s*\(\s*["'][^"']+["']\s*\)/i;
  const USER_IDENTITY_CMP_RE = /(?:getProperty\s*\(\s*["']user\.name["']\)|getenv\s*\(\s*["'](?:USER|USERNAME|LOGNAME)["']\)|os\.getlogin\s*\(\)|Environment\.UserName)\s*(?:===?|==|\.equals)\s*\(?["'][^"']+["']/i;

  // --- Pattern 3: Backdoor credentials ---
  const BACKDOOR_CRED_RE = /\b(master.?pass|backdoor|skeleton.?key|god.?mode|super.?user|magic.?word|debug.?pass|admin.?override|secret.?access|bypass.?auth|override.?auth)\b/i;
  // --- Pattern 4: Auth bypass via hardcoded value in conditional ---
  const AUTH_BYPASS_RE = /(?:if|when|unless)\s*\(.*(?:===?\s*['"][^'"]{3,}['"]|===?\s*['"](?:admin|root|debug|test|master)['"]).*\)\s*(?:\{|return\s+true|next\(\))/i;
  // --- Pattern 5: Hidden endpoints ---
  const HIDDEN_ENDPOINT_RE = /\b(app|router|server)\.(get|post|put|delete|all|use)\s*\(\s*['"]\/(?:_debug|_backdoor|_admin_secret|_hidden|__internal|\.well-known\/debug|_bypass|_master|_god)/i;
  // --- Pattern 6: Environment variable auth bypass ---
  const ENV_BYPASS_RE = /\b(process\.env|os\.environ|getenv)\b.*(?:BYPASS|SKIP_AUTH|NO_AUTH|DEBUG_AUTH|DISABLE_AUTH|BACKDOOR)/i;
  // --- Safe pattern: deny-list ---
  const DENY_LIST_RE = /\b(block|deny|reject|blacklist|blocklist|ban|forbidden|refuse|disallow|revoke|kick|disconnect)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // --- Check hostname/IP identity trapdoor ---
    if (HOSTNAME_EQUALS_RE.test(code) || (HOSTNAME_CONDITIONAL_RE.test(code) && IP_LITERAL_CMP_RE.test(code))) {
      const isDenyList = DENY_LIST_RE.test(code) &&
        !(/\b(admin|welcome|grant|allow|accept|privilege|elevated|secret|special)\b/i.test(code));
      if (!isDenyList) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CODE REVIEW (hostname/IP identity-based trapdoor)',
          severity: 'critical',
          description: `${node.label} branches on a hardcoded hostname or IP address. ` +
            `Code that checks for a specific host identity and grants different behavior is a trapdoor — ` +
            `a hidden branch that only activates for a known identity, bypassing normal access controls.`,
          fix: 'Remove hostname/IP-based conditional logic. All clients should receive the same behavior through the same access control path. ' +
            'If host-based access control is needed, use a configurable allowlist loaded from a secure config store, not hardcoded in source.',
          via: 'source_line_fallback',
        });
        continue;
      }
    }

    // --- Check user identity trapdoor ---
    if (USER_IDENTITY_RE.test(code) || USER_IDENTITY_CMP_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (user identity-based trapdoor)',
        severity: 'critical',
        description: `${node.label} branches on a hardcoded username or user environment variable. ` +
          `Checking for a specific user identity to grant different behavior is a trapdoor — ` +
          `a developer backdoor that activates only for the author's identity.`,
        fix: 'Remove hardcoded user identity checks. Use role-based access control (RBAC) with proper authentication, ' +
          'not checks against specific usernames embedded in source code.',
        via: 'source_line_fallback',
      });
      continue;
    }

    // --- Check backdoor credentials ---
    if (BACKDOOR_CRED_RE.test(code) && /\b(password|passwd|pwd|key|token|secret|credential|auth)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (possible backdoor credentials)',
        severity: 'critical',
        description: `${node.label} contains references to backdoor/master/bypass credentials. Trapdoor code provides hidden authentication bypass outside normal access controls.`,
        fix: 'Remove hardcoded backdoor credentials. All authentication must go through the same verified path. Use feature flags with proper access control for debug access, not hardcoded secrets.',
        via: 'source_line_fallback',
      });
    } else if (AUTH_BYPASS_RE.test(code)) {
      const parentId = findContainingFunction(map, node.id);
      const parentNode = parentId ? map.nodes.find(n => n.id === parentId) : null;
      const inAuthContext = parentNode ?
        /\b(auth|login|verify|check.?password|authenticate|isAdmin|hasPermission|middleware|guard)\b/i.test(parentNode.label) : false;

      if (inAuthContext) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CODE REVIEW (hardcoded comparison in authentication logic)',
          severity: 'critical',
          description: `${node.label} has a hardcoded string comparison inside authentication logic at ${parentNode?.label || 'unknown'}. ` +
            `Comparing against hardcoded values in auth is the classic trapdoor — a secret value that always grants access.`,
          fix: 'Remove hardcoded auth comparisons. All credentials must be verified against a proper credential store with hashing.',
          via: 'source_line_fallback',
        });
      }
    } else if (HIDDEN_ENDPOINT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (hidden debug/backdoor endpoint)',
        severity: 'high',
        description: `${node.label} registers a hidden endpoint with a debug/backdoor-style path. Undocumented endpoints that bypass normal routing are a common trapdoor mechanism.`,
        fix: 'Remove hidden endpoints. If debug endpoints are needed in dev, gate them behind NODE_ENV checks and disable in production.',
        via: 'source_line_fallback',
      });
    } else if (ENV_BYPASS_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (environment variable authentication bypass)',
        severity: 'high',
        description: `${node.label} uses an environment variable to bypass authentication. Env-based auth bypass can be exploited if the environment is compromised.`,
        fix: 'Remove auth bypass env variables. Use proper feature flags with access control if conditional auth is needed for testing.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-510', name: 'Trapdoor', holds: findings.length === 0, findings };
}

/**
 * CWE-511: Logic/Time Bomb
 * Pattern: Code that triggers destructive or unauthorized behavior based on a specific
 * date/time, counter reaching a threshold, or the presence/absence of a specific condition.
 * Detection: Date comparisons or counter checks that gate destructive operations.
 */
function verifyCWE511(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DATE_TRIGGER_RE = /\b(new\s+Date|Date\.now|Date\.parse|moment|dayjs|luxon|Instant\.now|LocalDate|datetime\.now|time\.time|Time\.now)\b.*(?:[><=!]+\s*(?:new\s+Date\s*\(\s*['"]|Date\.parse\s*\(\s*['"]|\d{10,13}|\d{4}[-/]\d{2}))/i;
  const HARDCODED_DATE_RE = /(?:['"]20\d{2}[-/]\d{2}[-/]\d{2}['"]|Date\s*\(\s*['"]20\d{2})|getTime\s*\(\s*\)\s*[><=]+\s*\d{10,13}/i;
  const COUNTER_TRIGGER_RE = /\b(count|counter|attempts|tries|iteration|cycle|run_count|execution_count|invoke_count)\b\s*(?:[><=!]+|>=|<=)\s*\d+/i;
  const DESTRUCTIVE_OPS_RE = /\b(delete|remove|drop|truncate|wipe|destroy|shutdown|exit|kill|format|unlink|rmdir|rm\s+-rf|corrupt|overwrite|disable|lock.?out|revoke|suspend|terminate|exec|Runtime)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    const hasDateTrigger = DATE_TRIGGER_RE.test(code) || HARDCODED_DATE_RE.test(code);
    const hasCounterTrigger = COUNTER_TRIGGER_RE.test(code);

    if (!hasDateTrigger && !hasCounterTrigger) continue;

    if (DESTRUCTIVE_OPS_RE.test(code)) {
      const triggerType = hasDateTrigger ? 'date/time condition' : 'counter/threshold condition';
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (destructive operation gated by ' + triggerType + ')',
        severity: 'critical',
        description: `${node.label} contains a ${triggerType} that triggers destructive operations. Logic/time bombs wait for a specific condition before executing their payload.`,
        fix: 'Review the conditional logic. If legitimate (license expiration, trial limit), ensure graceful degradation (disable features, not destroy data). Remove destructive operations from timer callbacks.',
        via: 'source_line_fallback',
      });
      continue;
    }

    for (const target of map.nodes) {
      if (target.id === node.id) continue;
      if (!DESTRUCTIVE_OPS_RE.test(stripComments(target.analysis_snapshot || target.code_snapshot))) continue;

      if (hasPathWithoutControl(map, node.id, target.id)) {
        const triggerType = hasDateTrigger ? 'date/time trigger' : 'counter trigger';
        findings.push({
          source: nodeRef(node), sink: nodeRef(target),
          missing: 'CODE REVIEW (' + triggerType + ' flows to destructive operation)',
          severity: 'critical',
          description: `A ${triggerType} at ${node.label} flows to destructive operation at ${target.label}. Time bombs use delayed triggers to execute destructive payloads at a predetermined moment.`,
          fix: 'Separate timer/counter logic from destructive operations. Scheduled tasks should be in cron/scheduler configs, not embedded in code with hardcoded dates.',
          via: 'bfs',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-511', name: 'Logic/Time Bomb', holds: findings.length === 0, findings };
}

/**
 * CWE-512: Spyware
 * Pattern: Code that covertly collects and exfiltrates user data — keylogging, screen
 * capture, clipboard monitoring, location tracking, contact harvesting, browser history
 * reading — without clear user consent indicators.
 * Detection: Surveillance/collection patterns combined with network exfiltration.
 */
function verifyCWE512(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const KEYLOG_RE = /\b(keydown|keyup|keypress|onkeydown|onkeyup|addEventListener\s*\(\s*['"]key|keyboard\.on|pynput|GetAsyncKeyState|GetKeyState|SetWindowsHookEx|CGEventTapCreate|IOHIDManager|input.?hook|key.?hook|key.?logger)\b/i;
  const SCREEN_CAP_RE = /\b(screenshot|screen.?capture|captureScreen|html2canvas|puppeteer.*screenshot|selenium.*screenshot|BitBlt|CGWindowListCreateImage|xdotool|scrot|import\s+-window|pyautogui\.screenshot|ImageGrab|robot\.createScreenCapture)\b/i;
  const CLIPBOARD_RE = /\b(clipboard|navigator\.clipboard|pbpaste|xclip|xsel|GetClipboardData|NSPasteboard|electron\.clipboard|pyperclip|readText\s*\(\s*\)|clipboard\.read)\b/i;
  const LOCATION_RE = /\b(geolocation|getCurrentPosition|watchPosition|navigator\.geolocation|CLLocationManager|FusedLocationProvider|GPS|gps.?coordinates|ip.?geolocation|geoip)\b/i;
  const CONTACTS_RE = /\b(contacts|addressBook|CNContactStore|ContactsContract|getContacts|readContacts|contact.?list|phonebook)\b/i;
  const BROWSER_HISTORY_RE = /\b(history|browsing.?history|chrome\.history|browser\.history|History\.db|places\.sqlite|WebKit.?History|IndexedDB.*history)\b/i;
  const EXFIL_RE = /\b(fetch|XMLHttpRequest|http\.request|https\.request|axios\.post|request\.post|urllib|requests\.post|socket\.send|WebSocket|navigator\.sendBeacon|new\s+Image\s*\(\s*\)\.src|postMessage|sendMessage)\b/i;

  const SURVEILLANCE_PATTERNS: Array<{ re: RegExp; name: string }> = [
    { re: KEYLOG_RE, name: 'keystroke logging' },
    { re: SCREEN_CAP_RE, name: 'screen capture' },
    { re: CLIPBOARD_RE, name: 'clipboard monitoring' },
    { re: LOCATION_RE, name: 'location tracking' },
    { re: CONTACTS_RE, name: 'contact harvesting' },
    { re: BROWSER_HISTORY_RE, name: 'browser history reading' },
  ];

  const CONSENT_RE = /\b(permission|consent|opt.?in|user.?agree|privacy.?policy|GDPR|requestPermission|checkPermission|Authorization|allowlist)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    for (const { re, name } of SURVEILLANCE_PATTERNS) {
      if (!re.test(code)) continue;

      // Check if surveillance data flows to network exfiltration
      for (const target of map.nodes) {
        if (target.id === node.id) continue;
        const targetCode = stripComments(target.analysis_snapshot || target.code_snapshot);
        if (!EXFIL_RE.test(targetCode)) continue;

        if (hasPathWithoutControl(map, node.id, target.id)) {
          if (!CONSENT_RE.test(code) && !CONSENT_RE.test(targetCode)) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(target),
              missing: 'CONTROL (user consent/permission check before data exfiltration)',
              severity: 'critical',
              description: `${name} at ${node.label} flows to network transmission at ${target.label} without consent verification. Spyware covertly collects and transmits user data without informed consent.`,
              fix: 'Add explicit user consent before collecting surveillance data. Show a clear privacy dialog. Use platform permission APIs (requestPermission). Provide opt-out. Comply with GDPR/CCPA.',
              via: 'bfs',
            });
            break;
          }
        }
      }

      // Flag keyloggers and screen capture even without exfiltration
      if ((name === 'keystroke logging' || name === 'screen capture') && !CONSENT_RE.test(code)) {
        const parentId = findContainingFunction(map, node.id);
        const parentNode = parentId ? map.nodes.find(n => n.id === parentId) : null;
        const legitimateContext = parentNode ?
          /\b(input|form|search|autocomplete|shortcut|hotkey|accessibility|a11y)\b/i.test(parentNode.label) : false;

        if (!legitimateContext && !findings.some(f => f.source.id === node.id)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CODE REVIEW (' + name + ' without clear legitimate purpose)',
            severity: 'high',
            description: `${node.label} performs ${name} outside of a recognized input-handling context. Review whether this data collection is necessary and properly disclosed.`,
            fix: 'Ensure keystroke/screen capture has a clear legitimate purpose (input handling, accessibility). If collecting for analytics, add explicit consent and minimize data.',
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-512', name: 'Spyware', holds: findings.length === 0, findings };
}

/**
 * CWE-514: Covert Channel
 * Pattern: Information transfer through mechanisms not designed for communication —
 * encoding data in timing, error messages, HTTP headers, DNS queries, image pixels,
 * or other side channels to bypass security controls.
 * Superset of CWE-515 (Covert Storage Channel) — covers BOTH timing and storage channels.
 */
function verifyCWE514(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const TIMING_CHANNEL_RE = /\b(setTimeout|setInterval|sleep|time\.sleep|Thread\.sleep|usleep|nanosleep|delay|wait)\b.*\b(if|switch|case|ternary|\?)/i;
  const DNS_EXFIL_RE = /\b(dns\.resolve|dns\.lookup|nslookup|dig\s+|resolve4|resolve6|resolveTxt|Dns\.GetHostEntry|InetAddress\.getByName)\b.*\b(encode|btoa|Buffer\.from|hex|base32|base64|concat|join|substring|slice)\b/i;
  const STEGO_RE = /\b(putImageData|getImageData|pixel|steganograph|lsb|least.?significant.?bit|embed.?data|hide.?data|watermark.*data|canvas.*toDataURL|Bitmap.*setPixel|BufferedImage.*setRGB)\b/i;
  const HEADER_EXFIL_RE = /\b(setHeader|set-cookie|X-Custom|X-Debug|X-Data|X-Token|ETag|Last-Modified|Content-Disposition)\b.*\b(encode|btoa|Buffer\.from|hex|base64|JSON\.stringify)\b/i;
  const ERROR_CHANNEL_RE = /\b(throw|Error|Exception|reject|abort)\b.*\b(encode|btoa|Buffer\.from|JSON\.stringify|serialize)\b.*\b(data|payload|secret|token|key|credential)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (DNS_EXFIL_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (data encoding combined with DNS resolution — possible DNS exfiltration)',
        severity: 'critical',
        description: `${node.label} combines data encoding with DNS queries. DNS exfiltration encodes stolen data as subdomains (e.g., "secret-data.evil.com") to bypass firewalls that allow DNS.`,
        fix: 'Review DNS usage. Legitimate DNS calls should not encode application data into hostnames. Monitor DNS query patterns for anomalous subdomain lengths.',
        via: 'source_line_fallback',
      });
    } else if (STEGO_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (steganographic data embedding in media)',
        severity: 'high',
        description: `${node.label} manipulates individual pixels or uses steganographic techniques. Covert storage channels hide data in image LSBs or media files to evade content inspection.`,
        fix: 'Review pixel manipulation code. If legitimate image processing, document it. If hiding data in images, consider whether this bypasses security controls.',
        via: 'source_line_fallback',
      });
    } else if (TIMING_CHANNEL_RE.test(code) && /\b(data|secret|token|key|char|byte|bit|password|payload)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (data-dependent timing — possible covert timing channel)',
        severity: 'high',
        description: `${node.label} uses data-dependent delays, potentially encoding information in timing. Covert timing channels modulate response delays to transmit bits of information.`,
        fix: 'Use constant-time operations for security-sensitive comparisons. Do not vary delays based on secret data. Use crypto.timingSafeEqual.',
        via: 'source_line_fallback',
      });
    } else if (HEADER_EXFIL_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (encoded data in HTTP headers)',
        severity: 'medium',
        description: `${node.label} encodes data into HTTP headers. Custom headers can serve as covert storage channels to exfiltrate data past content-inspecting firewalls/WAFs.`,
        fix: 'Review what data is placed in headers. Avoid encoding sensitive data in custom headers. Use standard headers for intended purpose only.',
        via: 'source_line_fallback',
      });
    } else if (ERROR_CHANNEL_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (encoded data in error messages — possible covert channel)',
        severity: 'medium',
        description: `${node.label} encodes data into error/exception messages. Error messages carrying encoded payloads can serve as a covert channel for data exfiltration.`,
        fix: 'Error messages should contain diagnostic information, not encoded data. Use structured logging with appropriate access controls.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-514', name: 'Covert Channel', holds: findings.length === 0, findings };
}

/**
 * CWE-515: Covert Storage Channel
 * Pattern: Information hidden in shared storage resources not designed for communication —
 * file metadata (timestamps, permissions), database fields used for signaling, shared memory,
 * filesystem attributes, or registry keys.
 * Specific subtype of CWE-514 focused on STORAGE (not timing) channels.
 */
function verifyCWE515(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const FILE_META_RE = /\b(utimes|futimes|lutimes|utime|os\.utime|touch\s+-t|touch\s+-d|SetFileTime|File\.setLastModified|chmod\s+\d{3,4}|chown|xattr|setfattr|Set-ItemProperty|alternate.?data.?stream|:.*:.*\$DATA)\b/i;
  const META_ENCODE_RE = /\b(utimes|utime|chmod|SetFileTime|setLastModified|setfattr|xattr)\b.*\b(encode|Buffer|charCodeAt|charCode|fromCharCode|btoa|atob|parseInt|toString\s*\(\s*(?:2|8|16)\s*\))\b/i;
  const SHARED_MEM_RE = /\b(SharedArrayBuffer|Atomics|shm_open|shmget|mmap.*MAP_SHARED|CreateFileMapping|MapViewOfFile|shared_memory|multiprocessing\.shared_memory)\b/i;
  const DB_SIGNAL_RE = /\b(UPDATE|INSERT)\b.*\b(last_login|metadata|notes|description|comment|reserved|unused|spare|padding)\b.*\b(encode|hex|base64|btoa|Buffer|charCode)\b/i;
  const REGISTRY_RE = /\b(RegSetValueEx|RegCreateKey|Registry\.SetValue|Set-ItemProperty\s+.*HKLM|Set-ItemProperty\s+.*HKCU|winreg\.SetValue|reg\s+add)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (META_ENCODE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (data encoding combined with file metadata modification)',
        severity: 'high',
        description: `${node.label} encodes data into file metadata (timestamps, permissions, extended attributes). File metadata as a communication channel bypasses content-level security monitoring.`,
        fix: 'Do not encode application data into file metadata. Use proper IPC mechanisms (message queues, pipes) for inter-process communication.',
        via: 'source_line_fallback',
      });
    } else if (FILE_META_RE.test(code) && /\b(data|payload|secret|message|signal|flag|bit|encode)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (file metadata manipulation with data-signaling patterns)',
        severity: 'medium',
        description: `${node.label} modifies file metadata in a pattern consistent with covert storage channels (timestamps, permissions, or extended attributes encoding data).`,
        fix: 'Review why file metadata is set based on data values. Legitimate file operations set metadata for its intended purpose (access control, timestamps).',
        via: 'source_line_fallback',
      });
    } else if (DB_SIGNAL_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (encoded data written to auxiliary database fields)',
        severity: 'medium',
        description: `${node.label} writes encoded data to auxiliary database fields (metadata, notes, description). Using database fields not designed for communication as covert storage bypasses access controls.`,
        fix: 'Store data in purpose-built columns/tables with appropriate access controls. Do not encode covert messages in metadata or description fields.',
        via: 'source_line_fallback',
      });
    } else if (SHARED_MEM_RE.test(code) && /\b(encode|decode|charCode|fromCharCode|btoa|atob|Buffer|secret|password|token|key)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (encoded data in shared memory — possible covert storage channel)',
        severity: 'medium',
        description: `${node.label} writes encoded sensitive data to shared memory. Shared memory regions accessible to multiple processes can serve as covert storage channels.`,
        fix: 'If shared memory is needed for IPC, use it explicitly with proper access controls. Do not use shared memory to circumvent process isolation.',
        via: 'source_line_fallback',
      });
    } else if (REGISTRY_RE.test(code) && /\b(encode|decode|base64|hex|payload|data|hidden|secret)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE REVIEW (encoded data in registry — possible covert storage)',
        severity: 'medium',
        description: `${node.label} writes encoded data to the Windows registry. Registry keys can serve as covert storage channels, persisting hidden data that survives reboots.`,
        fix: 'Use the registry only for legitimate configuration. Store application data in proper databases or config files.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-515', name: 'Covert Storage Channel', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const MALICIOUS_CODE_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-494': verifyCWE494,
  'CWE-506': verifyCWE506,
  'CWE-507': verifyCWE507,
  'CWE-508': verifyCWE508,
  'CWE-509': verifyCWE509,
  'CWE-510': verifyCWE510,
  'CWE-511': verifyCWE511,
  'CWE-512': verifyCWE512,
  'CWE-514': verifyCWE514,
  'CWE-515': verifyCWE515,
};
