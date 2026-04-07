/**
 * Error Handling, State Management & Side Channel CWE Verifiers
 *
 * Missing return value checks, empty catch, broad catch, error suppression,
 * privilege cleanup, session expiration, side channels, PRNG predictability,
 * hardcoded constants, upload/variable extraction, fail-open patterns.
 *
 * Extracted from verifier/index.ts - Phase 7 of the monolith split.
 */

import type { NeuralMap } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments, escapeRegExp } from './source-analysis.ts';
import { nodeRef, nodesOfType, inferMapLanguage, isLibraryCode, hasTaintedPathWithoutControl, hasPathWithoutControl, findContainingFunction, sharesFunctionScope } from './graph-helpers.ts';
import { evaluateControlEffectiveness, getContainingScopeSnapshots } from '../generated/_helpers.js';


/**
 * CWE-207: Observable Behavioral Discrepancy
 * Pattern: Different error messages/codes for different failure reasons reveal whether
 * a username exists, which auth factor failed, etc. Attackers enumerate valid inputs
 * by observing WHICH error they get back.
 *
 * Classic example: "invalid username" vs "invalid password" — reveals valid usernames.
 * Also: different HTTP status codes for "user not found" vs "wrong password".
 */
function verifyCWE207(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DISTINCT_ERROR_RE = /\b(user\s*not\s*found|account\s*not\s*found|unknown\s*user|no\s*such\s*user|invalid\s*username|email\s*not\s*registered|user\s*does\s*not\s*exist)\b/i;
  const AUTH_BRANCH_RE = /\b(invalid\s*password|wrong\s*password|incorrect\s*password|bad\s*password|password\s*mismatch|authentication\s*failed.*password)\b/i;
  const ENUM_SIGNAL_RE = /\b(user\s*exists|account\s*exists|email\s*already|is\s*registered|is\s*taken|already\s*in\s*use|duplicate\s*(?:user|email|account))\b/i;
  const STATUS_DIVERGENCE_RE = /\b(40[14]|403|404|409)\b.*\b(user|account|email|login)\b|\b(user|account|email|login)\b.*\b(40[14]|403|404|409)\b/i;
  const SAFE207_RE = /\b(invalid\s*credentials|authentication\s*failed|login\s*failed|unauthorized|generic.?error|uniform.?error|same.?message|consistent.?error)\b/i;

  const authNodes207 = map.nodes.filter(n =>
    n.node_type === 'AUTH' || n.node_type === 'CONTROL' ||
    (n.node_type === 'EGRESS' && /\b(login|auth|sign.?in|password|credential)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const node of authNodes207) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const hasDistinctUserError = DISTINCT_ERROR_RE.test(code);
    const hasDistinctPwdError = AUTH_BRANCH_RE.test(code);
    const hasEnumSignal = ENUM_SIGNAL_RE.test(code);
    const hasStatusDivergence = STATUS_DIVERGENCE_RE.test(code);

    if ((hasDistinctUserError && hasDistinctPwdError) || hasEnumSignal || hasStatusDivergence) {
      if (!SAFE207_RE.test(code)) {
        const severity = hasEnumSignal ? 'medium' as const : 'low' as const;
        findings.push({ source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (uniform error responses regardless of failure reason)',
          severity,
          description: `Auth handler at ${node.label} returns distinguishable responses for different failure reasons. ` +
            `Attackers can enumerate valid usernames/emails by observing which error message they receive.`,
          fix: 'Return a single generic message for all auth failures: "Invalid credentials." Use the same HTTP status code (401) ' +
            'regardless of whether the user exists or the password is wrong. Log the specific reason server-side only.',
          via: 'structural' });
      }
    }
  }

  const egress207 = nodesOfType(map, 'EGRESS');
  for (const sink of egress207) {
    const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
    if (DISTINCT_ERROR_RE.test(code) && !SAFE207_RE.test(code) && !findings.some(f => f.sink.id === sink.id)) {
      findings.push({ source: nodeRef(sink), sink: nodeRef(sink),
        missing: 'TRANSFORM (uniform error for auth failures)',
        severity: 'low',
        description: `Response at ${sink.label} reveals whether a specific username/email exists in the system via distinct error messages.`,
        fix: 'Use a generic error message: "Invalid credentials." Do not distinguish between user-not-found and wrong-password.',
        via: 'structural' });
    }
  }

  return { cwe: 'CWE-207', name: 'Observable Behavioral Discrepancy', holds: findings.length === 0, findings };
}

/**
 * CWE-208: Observable Timing Discrepancy
 * Pattern: Secret comparisons using non-constant-time operators (===, ==, strcmp, .equals()).
 * Timing differences reveal how many leading bytes matched, enabling byte-by-byte extraction.
 *
 * This is THE timing attack detector. The vulnerability is in the COMPARISON OPERATOR.
 * String === short-circuits on first mismatch; constant-time comparison always processes all bytes.
 *
 * Also detects: early-return patterns in auth (return false on first check), database
 * lookups that short-circuit before password check (timing reveals user existence).
 */
function verifyCWE208(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Match secret-related words even inside camelCase identifiers (storedToken, apiKey, authSecret)
  const SECRET_COMPARE_RE = /(token|secret|hmac|signature|api[_-]?key|hash|digest|nonce|csrf|otp|authorization|password|credential)/i;
  const UNSAFE_COMPARE_RE = /===?\s*['"`\w]|['"`\w]\s*===?|\.equals\s*\(|strcmp\s*\(|\.compareTo\s*\(|==\s*\w*(token|secret|key|hash|hmac|signature|nonce|csrf|otp)\b|\b(token|secret|key|hash|hmac|signature|nonce|csrf|otp)\w*\s*===?/i;
  const SAFE_COMPARE_RE = /\btimingSafeEqual\b|\bconstant[_-]?time\b|\bsecure[_-]?compare\b|\bhmac\.verify\b|\bcrypto\.subtle\.verify\b|\bbcrypt\.compare\b|\bargon2\.verify\b|\bscrypt\.verify\b|\bMessageDigest\.isEqual\b|\bOpenSSL\.secure_compare\b|\bActiveSupport::SecurityUtils\.secure_compare\b|\bSecureCompare\b/i;
  const EARLY_RETURN_AUTH_RE = /if\s*\(\s*!?\s*user\s*\)\s*(?:return|throw|res\.status)|if\s*\(\s*!?\s*(?:account|found|exists)\s*\)\s*(?:return|throw)|findOne.*then.*if.*null.*return/i;
  const TIMING_NORMALIZE_RE = /\bfake[_-]?hash\b|\bdummy[_-]?compare\b|\bbcrypt\.compare\s*\(\s*password\s*,\s*['"]\$2[aby]\$|\balways[_-]?compare\b|\bnormalize[_-]?timing\b/i;

  const authNodes208 = map.nodes.filter(n =>
    (n.node_type === 'AUTH' || n.node_type === 'CONTROL') &&
    (n.node_subtype.includes('comparison') || n.node_subtype.includes('verify') ||
     n.node_subtype.includes('hmac') || n.node_subtype.includes('token') ||
     n.attack_surface.includes('secret_comparison') ||
     SECRET_COMPARE_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const node of authNodes208) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (UNSAFE_COMPARE_RE.test(code) && SECRET_COMPARE_RE.test(code) && !SAFE_COMPARE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (constant-time comparison for secret values)',
        severity: 'medium',
        description: `Secret comparison at ${node.label} uses a non-constant-time operator (=== or strcmp). ` +
          `Timing differences reveal how many bytes matched, enabling byte-by-byte extraction of the secret.`,
        fix: 'Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) in Node.js, ' +
          'MessageDigest.isEqual() in Java, hmac.compare_digest() in Python, ' +
          'or Rack::Utils.secure_compare() in Ruby. For passwords, bcrypt.compare() is inherently constant-time.',
        via: 'structural',
      });
    }

    if (EARLY_RETURN_AUTH_RE.test(code) && !TIMING_NORMALIZE_RE.test(code)) {
      if (!findings.some(f => f.source.id === node.id)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (normalize auth timing regardless of user existence)',
          severity: 'low',
          description: `Auth handler at ${node.label} returns early when user is not found, skipping the password comparison. ` +
            `The time difference between "user not found" (fast) and "wrong password" (slow, hashes) reveals valid usernames.`,
          fix: 'Always perform the password comparison even when the user is not found. Compare against a dummy hash: ' +
            'bcrypt.compare(password, "$2b$10$invalidhashplaceholder...") to normalize timing.',
          via: 'structural',
        });
      }
    }
  }

  const egress208 = nodesOfType(map, 'EGRESS');
  for (const src of authNodes208) {
    if (SAFE_COMPARE_RE.test(src.analysis_snapshot || src.code_snapshot)) continue;
    if (!SECRET_COMPARE_RE.test(src.analysis_snapshot || src.code_snapshot)) continue;
    for (const sink of egress208) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutControl(map, src.id, sink.id)) {
        if (!findings.some(f => f.source.id === src.id)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'TRANSFORM (constant-time comparison before auth response)',
            severity: 'medium',
            description: `Auth comparison at ${src.label} reaches response at ${sink.label} without constant-time protection. ` +
              `Response timing leaks secret information.`,
            fix: 'Wrap all secret comparisons in constant-time functions. Add artificial delay or ensure consistent response timing.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-208', name: 'Observable Timing Discrepancy', holds: findings.length === 0, findings };
}

/**
 * CWE-243: Creation of chroot Jail Without Changing Working Directory
 * Pattern: chroot() is called but chdir("/") is not called before or immediately after,
 * allowing escape via relative paths from the pre-chroot working directory.
 * Property: chroot() is always accompanied by chdir("/") to close the escape.
 *
 * This is a UNIX-specific vulnerability. The chroot system call changes the root
 * directory but does NOT change the current working directory. If cwd is outside
 * the new root, relative path traversal (../../..) escapes the jail.
 */
function verifyCWE243(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CHROOT_CALL = /\b(chroot\s*\(|jail\s*\(|pivot_root\s*\(|os\.chroot|syscall\.Chroot|File\.chroot|Jail\.enter|sandbox_init)\b/i;
  const CHDIR_AFTER = /\b(chdir\s*\(\s*["']\/?["']\s*\)|os\.chdir\s*\(\s*["']\/?["']\s*\)|Dir\.chdir\s*\(\s*["']\/?["']\s*\)|syscall\.Chdir\s*\(\s*["']\/?["']\s*\)|fchdir\s*\(\s*fd_root\)|process\.chdir\s*\(\s*["']\/?["']\s*\))\b/i;
  const SAFE_WRAPPER = /\b(chrootSafe|safe_chroot|jail_attach|pledge|unveil|bubblewrap|firejail|systemd-nspawn|docker|container|nsjail|sandbox|libsandbox)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (CHROOT_CALL.test(code)) {
      const containingId = findContainingFunction(map, node.id);
      const containingCode = containingId
        ? stripComments(map.nodes.find(n => n.id === containingId)?.analysis_snapshot || map.nodes.find(n => n.id === containingId)?.code_snapshot || '')
        : '';
      const allCode = code + ' ' + containingCode;

      if (!CHDIR_AFTER.test(allCode) && !SAFE_WRAPPER.test(allCode)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (chdir("/") after chroot to prevent jail escape)',
          severity: 'high',
          description: `chroot() at ${node.label} is called without a corresponding chdir("/"). ` +
            `The current working directory remains outside the new root, allowing an attacker to escape ` +
            `the jail using relative path traversal (e.g., open("../../etc/passwd")).`,
          fix: 'Always call chdir("/") immediately after chroot(). Also close all file descriptors pointing ' +
            'outside the jail. The canonical sequence is: chroot(dir); chdir("/"); ' +
            'For better isolation, consider pivot_root (Linux) or pledge/unveil (OpenBSD). ' +
            'Drop privileges after entering the jail.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-243', name: 'Creation of chroot Jail Without Changing Working Directory', holds: findings.length === 0, findings };
}

/**
 * CWE-244: Improper Clearing of Heap Memory Before Release (Heap Inspection)
 * Pattern: Sensitive data is stored in heap memory that is freed without zeroing,
 * making the data recoverable via heap inspection, core dumps, or memory disclosure bugs.
 * Property: Heap buffers containing secrets are zeroed before free/deallocation.
 *
 * Different from CWE-226 (resource reuse): CWE-244 is about FREE — the memory goes
 * back to the OS or allocator with sensitive data still in it.
 */
function verifyCWE244(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SENSITIVE_HEAP = /\b(password|passwd|secret|token|privateKey|private_key|secretKey|secret_key|masterKey|master_key|encryptionKey|encryption_key|passphrase|pin|cvv|creditCard|credit_card|ssn)\b/i;
  const HEAP_ALLOC = /\b(malloc|calloc|realloc|new\s+\w+\[|Buffer\.alloc|Buffer\.from|HeapAlloc|GlobalAlloc|VirtualAlloc|mmap|kmalloc|kzalloc|GC\.AllocateUninitializedArray|ArrayPool|stackalloc)\b/i;
  const FREE_PATTERN = /\b(free\s*\(|delete\s+|delete\[\]|HeapFree|GlobalFree|VirtualFree|munmap|kfree|Buffer\..*=\s*null|\.dispose\(|\.close\(|\.release\(|ArrayPool.*Return|GC\.Collect)\b/i;
  const SECURE_ZERO = /\b(memset_s|explicit_bzero|SecureZeroMemory|RtlSecureZeroMemory|OPENSSL_cleanse|sodium_memzero|crypto_wipe|volatile.*memset|\.fill\s*\(\s*0\s*\).*(?:free|delete|dispose|release|close)|zeroize|wipe.*before.*free|secureFree|safeDelete|burn|crypto\.timingSafeEqual)\b/i;
  const UNSAFE_ZERO = /\bmemset\s*\([^)]+,\s*0\s*,[^)]+\)\s*;\s*(?:free|delete|kfree)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SENSITIVE_HEAP.test(code) && (HEAP_ALLOC.test(code) || FREE_PATTERN.test(code))) {
      const containingId = findContainingFunction(map, node.id);
      const funcCode = containingId
        ? stripComments(map.nodes.find(n => n.id === containingId)?.analysis_snapshot || map.nodes.find(n => n.id === containingId)?.code_snapshot || '')
        : '';
      const allCode = code + ' ' + funcCode;

      if (!SECURE_ZERO.test(allCode)) {
        const sensitive = code.match(SENSITIVE_HEAP)?.[0] || 'sensitive data';
        const usesUnsafeZero = UNSAFE_ZERO.test(allCode);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (secure zeroing of heap memory before deallocation)',
          severity: 'high',
          description: `Heap memory containing ${sensitive} at ${node.label} is freed without secure zeroing. ` +
            (usesUnsafeZero
              ? 'A regular memset() is used but compilers may optimize it away since the buffer is freed immediately after. '
              : '') +
            `The sensitive data remains in freed heap memory and can be recovered via core dumps, ` +
            `/proc/pid/mem, heap spraying, or memory disclosure vulnerabilities (like Heartbleed).`,
          fix: 'Use secure zeroing functions that cannot be optimized away: explicit_bzero() (POSIX), ' +
            'SecureZeroMemory() (Windows), memset_s() (C11), OPENSSL_cleanse(), or sodium_memzero(). ' +
            'Regular memset() before free() is NOT safe — the compiler may remove it as dead store. ' +
            'In managed languages: overwrite byte arrays (strings are immutable), use SecureString/.NET, or pin + zero.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-244', name: 'Improper Clearing of Heap Memory Before Release', holds: findings.length === 0, findings };
}

/**
 * CWE-245: J2EE Bad Practices: Direct Management of Connections
 * Pattern: J2EE/Jakarta code directly creates and manages database/network connections
 * instead of using container-managed connection pools (DataSource).
 * Property: All connections are obtained through managed DataSources, not direct drivers.
 */
function verifyCWE245(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DIRECT_CONN = /\b(DriverManager\.getConnection|new\s+(?:java\.sql\.)?Connection|Socket\s*\(\s*[^)]+\)|new\s+Socket\s*\(|new\s+ServerSocket\s*\(|java\.net\.URL\s*\(\s*[^)]*\)\.openConnection|HttpURLConnection|new\s+(?:com\.mysql|org\.postgresql|oracle)\.jdbc\.\w+|Class\.forName\s*\(\s*["'](?:com\.mysql|org\.postgresql|oracle|com\.microsoft))/i;
  const MANAGED_CONN = /\b(DataSource|getDataSource|lookup\s*\(\s*["']java:comp\/env\/jdbc|@Resource|@PersistenceContext|EntityManager|JdbcTemplate|ConnectionPool|HikariDataSource|C3P0|DBCP|InitialContext.*lookup|JNDI|connectionFactory|JmsTemplate|@Inject.*DataSource|CDI|managed.*connection)\b/i;
  const SAFE_CONTEXT = /\b(test|mock|stub|fake|embedded|h2|hsqldb|derby|sqlite|in-memory|unittest|@Test|@Before|setUp)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (DIRECT_CONN.test(code) && !MANAGED_CONN.test(code) && !SAFE_CONTEXT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (container-managed DataSource instead of direct connection)',
        severity: 'medium',
        description: `Code at ${node.label} directly manages database/network connections via DriverManager or raw sockets ` +
          `instead of using container-managed DataSources. This bypasses connection pooling, transaction management, ` +
          `and container lifecycle hooks, leading to resource leaks under load and transaction isolation bugs.`,
        fix: 'Use container-managed DataSources: configure in server.xml/application.xml and obtain via JNDI lookup or @Resource injection. ' +
          'For JPA: use @PersistenceContext with EntityManager. For Spring: use JdbcTemplate or Spring Data. ' +
          'Never call DriverManager.getConnection() in production J2EE code.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-245', name: 'J2EE Bad Practices: Direct Management of Connections', holds: findings.length === 0, findings };
}

/**
 * CWE-246: J2EE Bad Practices: Direct Use of Sockets
 * Pattern: J2EE/Jakarta code directly creates sockets instead of using container-managed
 * communication services (JMS, RMI, EJB remote interfaces, web services).
 * Property: All inter-process communication uses container-managed services.
 */
function verifyCWE246(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const RAW_SOCKET = /\b(new\s+Socket\s*\(|new\s+ServerSocket\s*\(|new\s+DatagramSocket\s*\(|SocketChannel\.open|ServerSocketChannel\.open|java\.net\.Socket|java\.net\.ServerSocket|java\.net\.DatagramSocket|SocketFactory\.createSocket|SSLSocket\s*\(|AsynchronousSocketChannel)\b/i;
  const MANAGED_COMM = /\b(JMS|MessageListener|@MessageDriven|JmsTemplate|ConnectionFactory|QueueConnectionFactory|TopicConnectionFactory|javax\.jms|jakarta\.jms|RMI|Remote|@EJB|@WebService|@WebMethod|JAX-RS|JAX-WS|RestTemplate|WebClient|HttpClient\.newBuilder|Feign|gRPC|ManagedChannel)\b/i;
  const SAFE_CONTEXT = /\b(test|mock|stub|fake|embedded|unittest|@Test|@Before|setUp|NIO.*selector|healthCheck|health_check|ping|diagnostic)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (RAW_SOCKET.test(code) && !MANAGED_COMM.test(code) && !SAFE_CONTEXT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (container-managed communication instead of raw sockets)',
        severity: 'medium',
        description: `Code at ${node.label} directly creates socket connections instead of using container-managed ` +
          `communication services. Raw sockets bypass the container's security manager, connection pooling, ` +
          `transaction coordination, and resource lifecycle management.`,
        fix: 'Replace direct socket usage with container-managed alternatives: JMS for async messaging, ' +
          'JAX-RS/JAX-WS for web services, EJB remote interfaces or gRPC for RPC. ' +
          'If raw sockets are truly needed (custom protocol), use a resource adapter (JCA) so the container can manage the lifecycle.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-246', name: 'J2EE Bad Practices: Direct Use of Sockets', holds: findings.length === 0, findings };
}

/**
 * CWE-248: Uncaught Exception
 * Pattern: Exceptions propagate to the top of a call stack without being caught,
 * potentially crashing the process, exposing stack traces, or leaving resources inconsistent.
 * Property: All exception-throwing paths have appropriate handlers; global handlers exist.
 */
function verifyCWE248(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Libraries intentionally throw exceptions for callers to handle — not a vulnerability
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-248', name: 'Uncaught Exception', holds: true, findings };
  }

  const THROW_PATTERN = /\b(throw\s+new|throw\s+\w+|raise\s+\w+|panic\s*\(|THROW_EXCEPTION|throwError|throwException)\b/i;
  const CATCH_PATTERN = /\b(catch\s*\(|rescue\s*=>|except\s*[\s(:]|recover\s*\(\s*\)|on\s+\w+Exception\s+catch|trap\s*\{)\b/i;
  const GLOBAL_HANDLER = /\b(process\.on\s*\(\s*['"]uncaughtException|process\.on\s*\(\s*['"]unhandledRejection|window\.onerror|window\.addEventListener\s*\(\s*['"]error|Thread\.UncaughtExceptionHandler|Thread\.setDefaultUncaughtExceptionHandler|AppDomain\.UnhandledException|Application_Error|@ExceptionHandler|@ControllerAdvice|ErrorBoundary|componentDidCatch|app\.use\s*\(\s*(?:function\s*\()?\s*err|expressErrorHandler|errorMiddleware|sys\.excepthook|atexit|set_exception_handler|set_error_handler|rescue_from)\b/i;
  const ERROR_LEAK = /\b(stack|stackTrace|stack_trace|traceback|e\.message|err\.message|error\.message|exception\.getMessage|toString\(\)|inspect|util\.inspect|JSON\.stringify\s*\(\s*(?:err|error|e\b)|res\.send\s*\(\s*(?:err|error)|res\.json\s*\(\s*\{[^}]*error|res\.status\s*\(\s*500\s*\)\s*\.send\s*\(\s*(?:err|error))\b/i;

  // Check 1: Functions that throw without local catch and no global handler exists
  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (THROW_PATTERN.test(code) && !CATCH_PATTERN.test(code)) {
      const hasGlobalHandler = map.nodes.some(n => GLOBAL_HANDLER.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      if (!hasGlobalHandler) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (exception handler — catch or global handler)',
          severity: 'medium',
          description: `Function at ${node.label} throws exceptions without a local catch block, and no global ` +
            `exception handler was detected. Uncaught exceptions can crash the process, expose stack traces, ` +
            `or leave resources (connections, locks, files) in an inconsistent state.`,
          fix: 'Add try/catch around exception-throwing code, or install a global exception handler: ' +
            'Node.js: process.on("uncaughtException"), Express: app.use(err, req, res, next), ' +
            'Java: Thread.setDefaultUncaughtExceptionHandler, Spring: @ControllerAdvice, ' +
            'Python: sys.excepthook. Always return generic errors to users — log details server-side.',
          via: 'structural',
        });
      }
    }
  }

  // Check 2: EGRESS nodes that leak exception details to users
  const egressNodes = nodesOfType(map, 'EGRESS');
  for (const egress of egressNodes) {
    const code = stripComments(egress.analysis_snapshot || egress.code_snapshot);
    if (ERROR_LEAK.test(code)) {
      findings.push({
        source: nodeRef(egress), sink: nodeRef(egress),
        missing: 'TRANSFORM (sanitize error details before sending to client)',
        severity: 'medium',
        description: `Error response at ${egress.label} appears to send exception details (stack trace, ` +
          `error message) directly to the client. This exposes internal implementation details, ` +
          `file paths, library versions, and potentially sensitive data to attackers.`,
        fix: 'Return generic error messages to clients: "Internal Server Error" with a correlation ID. ' +
          'Log full exception details server-side. In production, set NODE_ENV=production, DEBUG=false, ' +
          'or equivalent to suppress detailed error output.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-248', name: 'Uncaught Exception', holds: findings.length === 0, findings };
}

/**
 * CWE-252: Unchecked Return Value
 * Pattern: Functions whose return values indicate success/failure are called but
 * the return value is discarded — errors go undetected.
 * Property: Return values of security-relevant functions are always checked.
 */
function verifyCWE252(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CRITICAL_RETVAL = /\b(setuid|seteuid|setgid|setegid|setreuid|setregid|chroot|chdir|chown|chmod|fchmod|fchown|fopen|fdopen|freopen|fwrite|fread|fclose|unlink|remove|rename|mkdir|rmdir|fork|waitpid|kill\s*\(|signal\s*\(|sigaction|pthread_create|pthread_mutex_lock|pthread_mutex_unlock|mmap|munmap|mlock|mprotect|dup2?|fcntl|ioctl|stat|lstat|fstat|access|realpath)\b/;
  const RETVAL_CHECKED = /\b(if\s*\(|while\s*\(|assert\s*\(|switch\s*\(|!==?\s*(?:null|nil|NULL|undefined|-1|0|false|nullptr)|==\s*(?:null|nil|NULL|undefined|-1|false|nullptr)|!=\s*(?:null|nil|NULL|undefined|-1|0|false|nullptr)|err\s*=|ret\s*=|result\s*=|status\s*=|rc\s*=|rv\s*=|ok\s*=|success\s*=|\?\s*:|\.then\s*\(|await\s+|try\s*\{|catch\s*\(|\.catch\s*\(|or\s+die|or\s+raise|raise.*unless|throw.*unless|\.expect\s*\(|unwrap|\.ok\(\)|\.map\s*\(|\.and_then)\b/i;
  const SAFE_WRAPPER = /\b(safe_|check_|verify_|ensure_|must_|assert_|xmalloc|xrealloc|safe_open|safe_write|safeClose|checkedCall|guardedCall)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const match = code.match(CRITICAL_RETVAL);
    if (match) {
      const funcName = match[0];
      const assignedOrChecked = new RegExp(
        `(?:=\\s*|if\\s*\\(\\s*|while\\s*\\(\\s*|assert\\s*\\(\\s*|return\\s+)(?:[^;]*)?${funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`,
        'i'
      );
      if (!assignedOrChecked.test(code) && !RETVAL_CHECKED.test(code) && !SAFE_WRAPPER.test(code)) {
        if (node.node_type === 'STRUCTURAL' || node.node_type === 'TRANSFORM') {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (check return value of ' + funcName.trim() + ')',
            severity: 'medium',
            description: `Call to ${funcName.trim()} at ${node.label} may not check the return value. ` +
              `This function can fail (returning -1, NULL, or error code), and proceeding without checking ` +
              `can lead to use-after-failure, privilege escalation (unchecked setuid), or data loss (unchecked write).`,
            fix: 'Always check return values: if (' + funcName.trim() + '(...) < 0) { handle_error(); }. ' +
              'For security-critical functions (setuid, chroot), abort on failure — do not continue. ' +
              'In Rust, use Result<> and the ? operator. In Go, always check err != nil.',
            via: 'structural',
          });
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Java-specific: detect unchecked return value of read(), delete(), etc. (Juliet CWE-252)
  // Juliet pattern: streamFileInput.read(byteArray) — return value not stored or checked
  // Good pattern: int numberOfBytesRead = streamFileInput.read(byteArray); if (numberOfBytesRead == -1) ...
  // ---------------------------------------------------------------------------
  if (inferMapLanguage(map) === 'java') {
    // Methods whose return values must be checked in Java
    const JAVA_RETVAL_METHODS = /\.\s*(read|skip|delete|createNewFile|mkdir|mkdirs|renameTo|setReadOnly|setWritable|setExecutable|setLastModified)\s*\(/;
    // Pattern for unchecked: the method call appears as a standalone statement (not assigned, not in if/while)
    const JAVA_CHECKED_PATTERN = /(?:=\s*\w+\s*\.\s*(?:read|skip|delete|createNewFile|mkdir|mkdirs|renameTo)|if\s*\(\s*\w+\s*\.\s*(?:read|skip|delete|createNewFile)|int\s+\w+\s*=.*\.\s*read|long\s+\w+\s*=.*\.\s*skip|boolean\s+\w+\s*=.*\.\s*delete|numberOfBytesRead|bytesRead)/;

    for (const node of map.nodes) {
      if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
      const code = node.analysis_snapshot || node.code_snapshot;
      if (!code) continue;
      if (!JAVA_RETVAL_METHODS.test(code)) continue;

      // Check if the return value is actually used
      // Unchecked: the read/delete/etc is called as a standalone statement
      // Look for pattern like: identifier.read(args); on its own line (no assignment before it)
      const lines = code.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        // Match standalone method call: someVar.read(args);
        if (/^\w+\s*\.\s*(read|skip|delete|createNewFile|mkdir|mkdirs|renameTo)\s*\([^)]*\)\s*;/.test(trimmed)) {
          // This is an unchecked call — no assignment, no if
          const methodMatch = trimmed.match(/\.(\w+)\s*\(/);
          const methodName = methodMatch ? methodMatch[1] : 'method';
          if (!findings.some(f => f.source.id === node.id && f.description.includes(methodName))) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(node),
              missing: `CONTROL (check return value of ${methodName}())`,
              severity: 'medium',
              description: `Method ${node.label} calls ${methodName}() without checking the return value. The return value indicates success/failure or bytes read, and ignoring it can lead to data loss or incorrect behavior.`,
              fix: `Always check the return value of ${methodName}(). For read(): check for -1 (EOF) and partial reads. For delete(): verify the file was actually deleted.`,
              via: 'source_line_fallback',
            });
          }
          break; // One finding per function is enough
        }
      }
    }
  }

  return { cwe: 'CWE-252', name: 'Unchecked Return Value', holds: findings.length === 0, findings };
}

/**
 * CWE-253: Incorrect Check of Function Return Value
 * Pattern: The return value IS checked, but checked INCORRECTLY — comparing against
 * the wrong sentinel, inverting the condition, or confusing error codes.
 * Property: Return value comparisons use the correct sentinel values for each function.
 */
function verifyCWE253(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const WRONG_CHECK_PATTERNS: Array<{ pattern: RegExp; desc: string; correct: string }> = [
    { pattern: /\bif\s*\(\s*(?:strcmp|strncmp|memcmp|String\.Compare|compareTo)\s*\([^)]+\)\s*\)/i,
      desc: 'strcmp/compareTo checked for truthiness (non-zero means NOT EQUAL, zero means EQUAL)',
      correct: 'if (strcmp(a, b) == 0) for equality. The return is <0, 0, or >0 — not a boolean.' },
    { pattern: /\b(?:malloc|calloc|realloc|new\s+\w+)\s*\([^)]*\)\s*(?:==|!=)\s*-1/i,
      desc: 'malloc/new checked against -1 (it returns NULL/nullptr on failure, not -1)',
      correct: 'Check malloc() against NULL/nullptr: if (ptr == NULL) { handle_oom(); }' },
    { pattern: /\b(?:read|recv|fread)\s*\([^)]+\)\s*(?:==|!=)\s*0\s*\)\s*\{[^}]*(?:error|fail|err|abort|exit|die|panic)/i,
      desc: 'read/recv returning 0 is EOF (not error) — error returns -1',
      correct: 'Check read() == -1 for errors, == 0 for EOF, > 0 for data. Handle all three cases.' },
    { pattern: /\b(?:getuid|getgid|geteuid|getegid|getpid|getppid)\s*\(\s*\)\s*(?:==|!=)\s*-1/i,
      desc: 'getuid/getgid never returns -1 (always succeeds) — this check is vacuous',
      correct: 'getuid() always succeeds. If checking for root, compare == 0. Remove the error check.' },
    { pattern: /\bwhile\s*\(\s*!?\s*feof\s*\(/i,
      desc: 'feof() checked before read — feof is only valid AFTER a failed read',
      correct: 'Check the return value of fread/fgets directly. Only use feof() after a read returns short to distinguish EOF from error.' },
    { pattern: /\b(?:status|statusCode|status_code)\s*(?:===?|!==?)\s*['"](?:200|201|204|301|302|400|401|403|404|500)['"]/i,
      desc: 'HTTP status code compared as string — type coercion bugs or always-false strict equality',
      correct: 'Compare HTTP status codes as numbers: status === 200, not status === "200".' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const { pattern, desc, correct } of WRONG_CHECK_PATTERNS) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (correct return value check)',
          severity: 'medium',
          description: `Incorrect return value check at ${node.label}: ${desc}. ` +
            `Using the wrong sentinel or comparison means the check passes when it should fail, or vice versa.`,
          fix: correct,
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-253', name: 'Incorrect Check of Function Return Value', holds: findings.length === 0, findings };
}

/**
 * CWE-341: Predictable from Observable State
 * Detects values generated from observable system state (timestamps, PIDs,
 * sequential counters, hostnames) used in security contexts where
 * unpredictability is required (tokens, session IDs, nonces, keys).
 */
function verifyCWE341(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Observable state: timestamps, PIDs, counters, hostnames, uptime
  const OBSERVABLE_STATE_RE = /\bDate\.now\s*\(|\bnew Date\b|\bprocess\.pid\b|\bos\.getpid\s*\(|\bSystem\.currentTimeMillis\s*\(|\bSystem\.nanoTime\s*\(|\btime\.time\s*\(|\btime\.Now\s*\(|\bGetTickCount\b|\bEnvironment\.TickCount\b|\bos\.hostname\s*\(|\bSocket\.gethostname\s*\(|\bInetAddress\.getLocalHost\b|\bcounter\s*\+\+|\bcounter\s*\+=\s*1|\bsequence\s*\+\+|\bauto[_-]?increment/i;
  const SEC_CTX_341 = /\b(token|session|csrf|nonce|secret|key|password|salt|iv|otp|verification|reset|auth|api[_-]?key|access[_-]?token|refresh[_-]?token|seed|random|generate[_-]?id|uuid|unique[_-]?id)\b/i;
  const CSPRNG_RE = /\bcrypto\.randomBytes\b|\bcrypto\.getRandomValues\b|\bsecureRandom\b|\bSecureRandom\b|\bcrypto\.randomUUID\b|\bos\.urandom\b|\bsecrets\.\b|\bcrypto\/rand\b|\brandom_bytes\s*\(/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!OBSERVABLE_STATE_RE.test(code)) continue;

    const inSecCtx = SEC_CTX_341.test(node.label) || SEC_CTX_341.test(node.node_subtype) || SEC_CTX_341.test(code) ||
      node.attack_surface.some(s => SEC_CTX_341.test(s));
    // Also flag if observable state flows to AUTH/CONTROL
    const flowsToSec = node.edges.some(e => {
      const t = map.nodes.find(n => n.id === e.target);
      return t && (t.node_type === 'AUTH' || t.node_type === 'CONTROL');
    });

    if ((inSecCtx || flowsToSec) && !CSPRNG_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EXTERNAL (CSPRNG instead of observable state — crypto.randomBytes, SecureRandom)',
        severity: 'high',
        description: `Security-sensitive value at ${node.label} derived from observable state (timestamp, PID, counter). ` +
          `An attacker who can observe system state can predict these values and forge tokens or session IDs.`,
        fix: 'Use a CSPRNG (crypto.randomBytes, SecureRandom, os.urandom) instead of system state. ' +
          'Timestamps and counters are fully predictable to anyone who can observe the system.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-341', name: 'Predictable from Observable State', holds: findings.length === 0, findings };
}

/**
 * CWE-342: Predictable Exact Value from Previous Values
 * Detects sequential/incremental ID generation, auto-increment patterns,
 * and linear PRNG seeding where the next value is deterministic from the last.
 */
function verifyCWE342(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Sequential patterns: ++, += 1, auto_increment, nextval, serial
  const SEQ_RE = /\b(?:id|token|session|nonce|key)\s*(?:=\s*(?:last|prev|current)\w*\s*\+\s*1|\+\+|=\s*\w+\s*\+\s*1)/i;
  const AUTO_INC_RE = /\bAUTO_INCREMENT\b|\bSERIAL\b|\bnextval\s*\(|\bSEQUENCE\b|\bgenerateSequentialId\b|\bincrement[_-]?(?:id|counter|token)\b/i;
  const LINEAR_SEED_RE = /\bsrand\s*\(\s*(?:time|Date\.now|System\.currentTimeMillis|getpid)\b|\bRandom\s*\(\s*(?:seed|time|Date\.now)\b|\bmt_srand\s*\(\s*(?:time|microtime)\b/i;
  const SEC_CTX_342 = /\b(token|session|csrf|nonce|secret|key|auth|api[_-]?key|order[_-]?id|transaction[_-]?id|invite|voucher|coupon|reference)\b/i;
  const SAFE_RE342 = /\bcrypto\.randomBytes\b|\bcrypto\.randomUUID\b|\buuid\s*v4|\buuidv4\b|\bSecureRandom\b|\bsecrets\.\b|\bcrypto\/rand\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const hasSequential = SEQ_RE.test(code) || AUTO_INC_RE.test(code) || LINEAR_SEED_RE.test(code);
    if (!hasSequential) continue;

    const inSecCtx = SEC_CTX_342.test(node.label) || SEC_CTX_342.test(node.node_subtype) || SEC_CTX_342.test(code);
    if (inSecCtx && !SAFE_RE342.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (non-sequential ID generation — UUIDv4, CSPRNG)',
        severity: 'high',
        description: `Sequential/predictable value generation at ${node.label}. ` +
          `If an attacker observes one value (e.g., order_id=1000), the next value (1001) is trivially predictable. ` +
          `This enables enumeration attacks, IDOR, and authorization bypass.`,
        fix: 'Use non-sequential identifiers: UUIDv4, CSPRNG-generated tokens, or ULID. ' +
          'If ordering is needed, use a separate non-exposed sequence internally.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-342', name: 'Predictable Exact Value from Previous Values', holds: findings.length === 0, findings };
}

/**
 * CWE-343: Predictable Value Range from Previous Values
 * Detects values generated within a small, known range or with bounded
 * randomness that makes statistical prediction feasible. E.g., random(1,999999)
 * for a 6-digit OTP that can be brute-forced within its validity window.
 */
function verifyCWE343(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Small-range randoms: randint(0,N) where N is small, random % N where N is small
  const SMALL_RANGE_RE = /\brandint\s*\(\s*\d+\s*,\s*(\d+)\s*\)|\brand\s*\(\s*\)\s*%\s*(\d+)|\bMath\.random\s*\(\s*\)\s*\*\s*(\d+)|\bnextInt\s*\(\s*(\d+)\s*\)|\bIntn\s*\(\s*(\d+)\s*\)/;
  const SEC_CTX_343 = /\b(otp|pin|verification[_-]?code|reset[_-]?code|mfa[_-]?code|auth[_-]?code|confirm[_-]?code|two[_-]?factor|2fa|sms[_-]?code)\b/i;
  const RATE_LIMIT_RE = /\brateLimit\b|\brate[_-]?limit\b|\bthrottle\b|\blockout\b|\bmax[_-]?attempts\b|\battempt[_-]?limit\b|\bbrute[_-]?force\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const rangeMatch = SMALL_RANGE_RE.exec(code);
    if (!rangeMatch) continue;

    const rangeSize = parseInt(rangeMatch[1] || rangeMatch[2] || rangeMatch[3] || rangeMatch[4] || rangeMatch[5], 10);
    // Only flag if range is small enough to brute-force (< 10 million)
    if (isNaN(rangeSize) || rangeSize >= 10000000) continue;

    const inSecCtx = SEC_CTX_343.test(node.label) || SEC_CTX_343.test(node.node_subtype) || SEC_CTX_343.test(code);
    if (!inSecCtx) continue;

    // Check if there's rate limiting in the same scope
    const scopeNodes = map.nodes.filter(n => sharesFunctionScope(map, node.id, n.id));
    const hasRateLimit = scopeNodes.some(n => RATE_LIMIT_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
    // Even with rate limiting, a small range is concerning; just lower severity
    const sev = hasRateLimit ? 'medium' as const : 'high' as const;

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'CONTROL (rate limiting + sufficient entropy for OTP/verification codes)',
      severity: sev,
      description: `Verification code at ${node.label} uses a range of only ${rangeSize.toLocaleString()} possible values. ` +
        `${hasRateLimit ? 'Rate limiting is present but' : 'Without rate limiting,'} an attacker can enumerate all values ` +
        `within the code's validity window.`,
      fix: 'For OTPs: enforce strict rate limiting (3-5 attempts), short expiry (5 min), and lockout. ' +
        'For tokens: use at least 128 bits of CSPRNG entropy. A 6-digit OTP is only acceptable with aggressive rate limiting.',
      via: 'scope_taint',
    });
  }
  return { cwe: 'CWE-343', name: 'Predictable Value Range from Previous Values', holds: findings.length === 0, findings };
}

/**
 * CWE-344: Use of Invariant Value in Dynamically Changing Context
 * Detects hardcoded/static values used where dynamic, per-request/session
 * values are required: static CSRF tokens, hardcoded salts, fixed IVs,
 * constant nonces, static API keys shared across users.
 */
function verifyCWE344(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Hardcoded security values: string literals assigned to security-sensitive vars
  const HARDCODED_SEC_RE = /\b(csrf[_-]?token|nonce|salt|iv|initialization[_-]?vector|api[_-]?key|secret[_-]?key|session[_-]?secret|signing[_-]?key)\s*[:=]\s*['"][^'"]{1,128}['"]/i;
  // Static/const in dynamic context
  const STATIC_TOKEN_RE = /\bconst\s+(?:csrf|nonce|salt|iv|secret|token)\s*=\s*['"][^'"]+['"]/i;
  // Reused across requests — same value for all users
  const GLOBAL_STATIC_RE = /\bmodule\.exports\.\w*(?:secret|token|salt|nonce|iv|key)\s*=\s*['"]|export\s+(?:const|let)\s+\w*(?:SECRET|TOKEN|SALT|NONCE|IV|KEY)\s*=\s*['"][^'"]+['"]/i;
  const DYNAMIC_RE = /\bcrypto\.randomBytes\b|\bcrypto\.getRandomValues\b|\bSecureRandom\b|\bos\.urandom\b|\bsecrets\.\b|\bgenerate\w*Token\b|\bgenerate\w*Nonce\b|\bcrypto\.randomUUID\b|\buuid\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!(HARDCODED_SEC_RE.test(code) || STATIC_TOKEN_RE.test(code) || GLOBAL_STATIC_RE.test(code))) continue;
    if (DYNAMIC_RE.test(code)) continue; // Has dynamic generation too — likely safe

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'TRANSFORM (dynamic per-request/session value generation)',
      severity: 'high',
      description: `Static/invariant security value at ${node.label}. Using the same CSRF token, salt, IV, or nonce ` +
        `for all requests/users makes the protection worthless — replay attacks, rainbow tables, and IV reuse attacks apply.`,
      fix: 'Generate a unique value per request (CSRF tokens), per user (salts), or per encryption operation (IVs/nonces). ' +
        'Use crypto.randomBytes() or equivalent. Never hardcode security-sensitive values.',
      via: 'structural',
    });
  }
  return { cwe: 'CWE-344', name: 'Use of Invariant Value in Dynamically Changing Context', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-390: Detection of Error Condition Without Action
// ---------------------------------------------------------------------------

function verifyCWE390(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const EMPTY_CATCH = /catch\s*\([^)]*\)\s*\{\s*\}|catch\s*\([^)]*\)\s*\{\s*\/\/[^\n]*\s*\}|catch\s*\([^)]*\)\s*\{\s*\/\*[^*]*\*\/\s*\}|except\s*(?:\w+\s*(?:as\s+\w+)?\s*)?:\s*(?:\n\s*)?pass\b|rescue\s*(?:=>?\s*\w+)?\s*;\s*(?:nil|next|retry)\b/i;
  const LOG_ONLY_CATCH = /catch\s*\([^)]*\)\s*\{[^}]*(?:console\.(?:log|warn|error|info)|log(?:ger)?\.(?:error|warn|info|debug)|print(?:ln)?|System\.(?:out|err)\.print|NSLog|syslog|Log\.(?:e|w|d|i))\s*\([^)]*\)\s*;?\s*\}/i;
  const CORRECTIVE_ACTION = /\b(throw|rethrow|raise|panic|return\s+(?:false|null|nil|None|err|error|Result\.err|Err\()|process\.exit|sys\.exit|os\.Exit|abort|reject\(|callback\s*\(\s*err|next\s*\(\s*err|res\.status\s*\(\s*[45]\d\d|rollback|retry|compensat|revert|undo|cleanup|fallback|default\s*:|recover)\b/i;
  // Error-returning calls: methods that return boolean/error status. If their return value
  // is checked in an if() but the if-body is empty, that's CWE-390.
  const ERROR_RETURNING_CALL = /\b(mkdirs?|delete|renameTo|createNewFile|setReadable|setWritable|setExecutable|mkdir|exists|canRead|canWrite)\s*\(\s*\)/i;

  for (const node of map.nodes) {
    const rawCode = node.analysis_snapshot || node.code_snapshot;
    const code = stripComments(rawCode);

    // Strategy 1: Empty catch blocks
    if (EMPTY_CATCH.test(rawCode)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (error handling logic in catch block)',
        severity: 'medium',
        description: `Empty catch block at ${node.label} swallows errors silently. The error condition is detected ` +
          `(caught) but no corrective action is taken — the program continues as if nothing went wrong, ` +
          `potentially operating on invalid state, corrupted data, or with missing resources.`,
        fix: 'Either handle the error (return error status, retry, use fallback), re-throw it, ' +
          'or at minimum log it AND set an error state. If the exception truly cannot occur, ' +
          'add a comment explaining why and consider an assertion.',
        via: 'structural',
      });
    } else if (LOG_ONLY_CATCH.test(rawCode) && !CORRECTIVE_ACTION.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (corrective action after error detection)',
        severity: 'low',
        description: `Catch block at ${node.label} only logs the error but takes no corrective action. ` +
          `While better than completely empty, the program continues executing in a potentially ` +
          `invalid state. Logging alone does not fix the error condition.`,
        fix: 'After logging, take corrective action: return an error code, set a flag, ' +
          'use a fallback value, retry the operation, or re-throw for upstream handling.',
        via: 'structural',
      });
    }

    // Strategy 2: Empty if-block after error-returning call
    // Juliet pattern: if (!x.mkdirs()) { /* comment only */ }
    if (node.node_type === 'CONTROL' && node.node_subtype === 'branch') {
      // Check if the condition involves an error-returning call
      const condMatch = rawCode.match(/^if\s*\(([^)]*(?:\([^)]*\))*[^)]*)\)\s*\{/s);
      if (condMatch && ERROR_RETURNING_CALL.test(condMatch[1])) {
        // Extract the if-body (after the opening brace)
        const braceStart = rawCode.indexOf('{');
        if (braceStart !== -1) {
          const afterBrace = rawCode.slice(braceStart + 1);
          // Find the matching closing brace (handle nested braces)
          let depth = 1;
          let bodyEnd = -1;
          for (let i = 0; i < afterBrace.length; i++) {
            if (afterBrace[i] === '{') depth++;
            else if (afterBrace[i] === '}') { depth--; if (depth === 0) { bodyEnd = i; break; } }
          }
          if (bodyEnd !== -1) {
            const body = afterBrace.slice(0, bodyEnd);
            const strippedBody = stripComments(body).trim();
            if (strippedBody === '' && !CORRECTIVE_ACTION.test(body)) {
              findings.push({
                source: nodeRef(node), sink: nodeRef(node),
                missing: 'CONTROL (error handling logic in if-block after error check)',
                severity: 'medium',
                description: `Error condition detected at ${node.label} but no action taken. ` +
                  `The error-returning call result is checked but the if-body is empty — ` +
                  `the program continues as if the operation succeeded.`,
                fix: 'Handle the error: throw an exception, return an error code, log and set error state, ' +
                  'or take corrective action (retry, fallback). Do not silently ignore error conditions.',
                via: 'structural',
              });
            }
          }
        }
      }
    }
  }
  return { cwe: 'CWE-390', name: 'Detection of Error Condition Without Action', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-391: Unchecked Error Condition
// ---------------------------------------------------------------------------

function verifyCWE391(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code wraps system calls with its own error handling — callers check the wrapper's return
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-391', name: 'Unchecked Error Condition', holds: true, findings };
  }

  const ERROR_PRODUCING = /\b(strtol|strtod|strtoul|strtof|atoi|atof|atol|scanf|fscanf|sscanf|getenv|fgets|fgetc|getchar|gets|read\s*\(|write\s*\(|send\s*\(|recv\s*\(|socket\s*\(|bind\s*\(|listen\s*\(|accept\s*\(|connect\s*\(|open\s*\(|creat\s*\(|pipe\s*\(|mkstemp|tmpfile|tmpnam|opendir|readdir|closedir|exec[lv]p?e?\s*\(|system\s*\()\b/;
  const ERROR_CHECK = /\b(errno|perror|strerror|ferror|feof|GetLastError|FormatMessage|WSAGetLastError|\$\?|%ERRORLEVEL%|if\s*\(\s*!\s*|if\s*\(\s*.*\s*(?:==|!=|<|>)\s*(?:NULL|nullptr|nil|-1|0|false|INVALID_HANDLE|SOCKET_ERROR|EINVAL|ENOENT|ENOMEM))\b/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL' && node.node_type !== 'TRANSFORM') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const match = code.match(ERROR_PRODUCING);
    if (match) {
      const funcName = match[0].trim();
      if (!ERROR_CHECK.test(code)) {
        const containerId = findContainingFunction(map, node.id);
        const container = containerId ? map.nodes.find(n => n.id === containerId) : null;
        const containerChecks = container ? ERROR_CHECK.test(stripComments(container.analysis_snapshot || container.code_snapshot)) : false;
        if (!containerChecks) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (error condition check after ' + funcName + ')',
            severity: 'medium',
            description: `Call to ${funcName} at ${node.label} does not check the error condition (errno, ` +
              `return sentinel, or error flag). These functions signal failure through side-channel ` +
              `error indicators that must be explicitly checked.`,
            fix: `Check errno after ${funcName}, or verify the return value against the documented ` +
              `error sentinel. For strtol/strtod, check errno == ERANGE and endptr. ` +
              `For POSIX I/O, check both return value AND errno.`,
            via: 'structural',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-391', name: 'Unchecked Error Condition', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-392: Missing Report of Error Condition
// ---------------------------------------------------------------------------

function verifyCWE392(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CATCH_THEN_SUCCESS = /catch\s*\([^)]*\)\s*\{[^}]*(?:return\s+(?:true|0|null|undefined|void\s+0|\{\}|\[\]|""|''|``|Success|Ok)\s*[;}\n]|return\s*[;}\n])/i;
  const CATCH_DEFAULT = /catch\s*\([^)]*\)\s*\{[^}]*return\s+(?:default|fallback|cached|empty|blank|initial)/i;
  const EXCEPT_SUCCESS = /(?:except|rescue)\s*[^:]*:\s*(?:\n\s*)*(?:return\s+(?:True|None|0|\[\]|\{\}|""|''|Success)|pass\b)/i;
  const REPORTS_ERROR = /\b(throw|raise|panic|reject|callback\s*\(\s*(?:err|error|new\s+Error)|next\s*\(\s*(?:err|error)|res\.status\s*\(\s*[45]\d\d|setError|hasError|isError|\.error\s*=\s*true|errorOccurred|failed\s*=\s*true|success\s*=\s*false|return\s+(?:false|err|error|Error|Result\.err|Err\(|new\s+\w*Error|Promise\.reject))\b/i;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    const strippedCode = stripComments(code);
    if ((CATCH_THEN_SUCCESS.test(code) || CATCH_DEFAULT.test(code) || EXCEPT_SUCCESS.test(code))
        && !REPORTS_ERROR.test(strippedCode)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EGRESS (error report to caller — return error code, throw, or set error flag)',
        severity: 'medium',
        description: `Function at ${node.label} catches an error but returns a success value to the caller. ` +
          `The caller has no way to know the operation failed. This can cascade: the caller proceeds ` +
          `with stale data, missing resources, or partially completed operations.`,
        fix: 'Propagate the error to the caller: return an error code, throw/re-throw the exception, ' +
          'return a Result/Either type, or set an error flag that the caller checks. ' +
          'If returning a default is intentional, document it clearly and log the error.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-392', name: 'Missing Report of Error Condition', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-393: Return of Wrong Status Code
// ---------------------------------------------------------------------------

function verifyCWE393(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const HTTP_SUCCESS_IN_ERROR = /(?:catch|error|err|fail|exception|invalid|unauthorized|forbidden|not\s*found)[^}]*(?:res\.status\s*\(\s*200\s*\)|res\.sendStatus\s*\(\s*200\s*\)|response\.setStatus\s*\(\s*200\s*\)|statusCode\s*=\s*200|status\s*:\s*200|HttpStatus\.OK)/i;
  const C_SUCCESS_IN_ERROR = /(?:if\s*\([^)]*(?:err|error|fail|invalid|null|NULL|nullptr|<\s*0)[^)]*\)\s*\{[^}]*return\s+0\s*;|catch[^}]*return\s+0\s*;|goto\s+\w*err\w*;[^}]*return\s+0\s*;)/i;
  const WRONG_HTTP_CODE: Array<{ pattern: RegExp; desc: string }> = [
    { pattern: /(?:unauthori[sz]ed|authentication\s+(?:fail|required)|not\s+authenticated|login\s+required)[^}]*(?:res\.status\s*\(\s*(?:403|404|500)\s*\)|statusCode\s*=\s*(?:403|404|500))/i,
      desc: 'Authentication failure returns wrong status (should be 401 Unauthorized)' },
    { pattern: /(?:forbidden|not\s+allowed|permission\s+denied|access\s+denied|authori[sz]ation\s+(?:fail|denied))[^}]*(?:res\.status\s*\(\s*(?:401|404|500)\s*\)|statusCode\s*=\s*(?:401|404|500))/i,
      desc: 'Authorization failure returns wrong status (should be 403 Forbidden)' },
    { pattern: /(?:not\s*found|does\s*not\s*exist|no\s+such|missing\s+resource)[^}]*(?:res\.status\s*\(\s*(?:400|401|500)\s*\)|statusCode\s*=\s*(?:400|401|500))/i,
      desc: 'Not-found condition returns wrong status (should be 404 Not Found)' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (HTTP_SUCCESS_IN_ERROR.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (correct HTTP status code for error response)',
        severity: 'high',
        description: `Error handler at ${node.label} returns HTTP 200 (success). The client will interpret ` +
          `the response as successful, proceeding with invalid data or missing resources. ` +
          `Security tools and monitoring systems will miss the failure entirely.`,
        fix: 'Return the appropriate HTTP error status: 400 for bad input, 401 for authentication failure, ' +
          '403 for authorization failure, 404 for not found, 409 for conflicts, 500 for server errors.',
        via: 'structural',
      });
    }
    if (C_SUCCESS_IN_ERROR.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (correct return code — non-zero for error)',
        severity: 'high',
        description: `Error path at ${node.label} returns 0 (success). The caller will not detect the failure ` +
          `and will proceed as if the operation succeeded. For security-critical operations ` +
          `(setuid, chroot, authentication), this is especially dangerous.`,
        fix: 'Return a non-zero error code, -1, or a specific errno-style value in error paths. ' +
          'Never return the success sentinel from an error handler.',
        via: 'structural',
      });
    }
    for (const { pattern, desc } of WRONG_HTTP_CODE) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (correct HTTP status code)',
          severity: 'medium',
          description: `${desc} at ${node.label}. Wrong status codes confuse clients, break REST contracts, ` +
            `and can cause security issues: 404 instead of 401 hides the existence of endpoints, ` +
            `500 instead of 403 triggers unnecessary retry logic.`,
          fix: 'Use semantically correct HTTP status codes: 401 for authentication, 403 for authorization, ' +
            '404 for not found, 400 for validation, 409 for conflicts, 500 only for genuine server errors.',
          via: 'structural',
        });
        break;
      }
    }
  }
  return { cwe: 'CWE-393', name: 'Return of Wrong Status Code', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-394: Unexpected Status Code or Return Value
// ---------------------------------------------------------------------------

function verifyCWE394(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const BINARY_CHECK = /if\s*\(\s*\w+\s*===?\s*0\s*\)\s*\{[^}]*\}\s*else\s*\{/i;
  const MULTI_RETURN_FUNCS = /\b(read|write|recv|send|select|poll|waitpid|fread|fwrite|sendto|recvfrom|pread|pwrite|splice|sendmsg|recvmsg|epoll_wait|kevent|sigwait|sem_wait|sem_trywait|pthread_cond_timedwait)\b/;
  const MULTI_CASE = /(?:if.*(?:>|<|>=|<=)\s*0.*(?:else\s+if|elif))|(?:switch\s*\()|(?:(?:>|<)\s*0\s*\).*(?:==|!=)\s*0\s*\))|(?:EAGAIN|EWOULDBLOCK|EINTR|ETIMEDOUT)/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL' && node.node_type !== 'TRANSFORM') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const funcMatch = code.match(MULTI_RETURN_FUNCS);
    if (funcMatch && BINARY_CHECK.test(code) && !MULTI_CASE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (handle all return value cases: success, error, partial, and interrupted)',
        severity: 'medium',
        description: `Call to ${funcMatch[0]} at ${node.label} uses binary success/failure checking but this ` +
          `function has multiple return states: success (>0), EOF/closed (0), error (-1), ` +
          `partial completion (<requested), and EINTR (interrupted). Treating unexpected values ` +
          `as success can lead to data corruption or infinite loops.`,
        fix: `Handle all return states of ${funcMatch[0]}: (1) >0 = success/partial (may need retry loop), ` +
          `(2) 0 = EOF/peer closed, (3) -1 = error (check errno for EINTR, EAGAIN, EWOULDBLOCK). ` +
          `Never assume a non-negative return means "all bytes transferred."`,
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-394', name: 'Unexpected Status Code or Return Value', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-395: Use of NullPointerException Catch to Detect NULL Pointer Dereference
// ---------------------------------------------------------------------------

function verifyCWE395(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const NPE_CATCH_PATTERNS = [
    /catch\s*\(\s*NullPointerException/i,
    /catch\s*\(\s*(?:TypeError|ReferenceError)\s+\w*\)\s*\{[^}]*(?:null|undefined|is not a function|cannot read propert)/i,
    /except\s+(?:TypeError|AttributeError)\s*(?:as\s+\w+)?:\s*(?:\n\s*)?(?:#.*\n\s*)?(?:pass|return|None|False|0|\[\]|\{\})/i,
    /rescue\s+NoMethodError/i,
  ];
  const PROPER_NULL_CHECK = /\b(if\s*\(\s*\w+\s*(?:!=|!==|==|===)\s*(?:null|nil|None|undefined|nullptr)\s*\)|Optional\.ofNullable|\w+\?\.|Objects\.(?:requireNonNull|isNull|nonNull)|!= null\b|!== null\b|!== undefined\b|\?\?|\?\.\w+|isinstance\s*\([^,]+,\s*NoneType\))\b/i;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    for (const pattern of NPE_CATCH_PATTERNS) {
      if (pattern.test(code)) {
        if (!PROPER_NULL_CHECK.test(stripComments(code))) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (explicit null check before dereferencing)',
            severity: 'medium',
            description: `Code at ${node.label} catches NullPointerException/TypeError as control flow instead of ` +
              `checking for null before dereferencing. This is an anti-pattern: exceptions are expensive, ` +
              `the catch may mask unrelated null dereferences (hiding real bugs), and it makes the ` +
              `code's intent unclear.`,
            fix: 'Replace the catch with explicit null checks: if (obj != null) { obj.method(); }. ' +
              'In Java, use Optional<>. In JS/TS, use optional chaining (?.) and nullish coalescing (??). ' +
              'In Python, check "if value is not None" before access.',
            via: 'structural',
          });
          break;
        }
      }
    }
  }
  return { cwe: 'CWE-395', name: 'Use of NullPointerException Catch to Detect NULL Pointer Dereference', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-396: Declaration of Catch for Generic Exception
// ---------------------------------------------------------------------------

function verifyCWE396(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const GENERIC_CATCH = /catch\s*\(\s*(?:Exception|Throwable|BaseException|Error|RuntimeError|StandardError|object)\s+\w+\s*\)|catch\s*\(\s*\.\.\.\s*\)|except\s*:\s*$|except\s+(?:Exception|BaseException)\s*(?:as\s+\w+)?:/im;
  const JS_BARE_CATCH = /catch\s*\(\s*\w+\s*\)\s*\{(?![^}]*instanceof\s+\w+)(?![^}]*\.name\s*===?)(?![^}]*\.code\s*===?)[^}]*\}/i;
  const SWALLOWS = /catch\s*\([^)]*\)\s*\{\s*\}|catch\s*\([^)]*\)\s*\{\s*\/\//i;
  const LEGITIMATE_GENERIC = /\b(process\.on\s*\(\s*['"]uncaughtException|@ControllerAdvice|@ExceptionHandler|ErrorBoundary|componentDidCatch|sys\.excepthook|app\.use\s*\(\s*(?:function\s*\()?\s*err|finally|cleanup|shutdown|graceful|toplevel|main\s*\(|if\s+__name__)/i;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    const strippedCode = stripComments(code);
    if ((GENERIC_CATCH.test(code) || (JS_BARE_CATCH.test(code) && SWALLOWS.test(code)))
        && !LEGITIMATE_GENERIC.test(strippedCode)) {
      const severity: 'critical' | 'high' | 'medium' | 'low' =
        SWALLOWS.test(code) ? 'high' : 'medium';
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (specific exception type in catch clause)',
        severity,
        description: `Generic exception catch at ${node.label} catches all exception types indiscriminately. ` +
          `This masks programming errors (NPE, index out of bounds, type errors), hides bugs that ` +
          `would otherwise be immediately visible, and makes debugging extremely difficult. ` +
          `Security exceptions (AccessDenied, AuthenticationFailed) get silently swallowed.`,
        fix: 'Catch specific exception types: catch (IOException e) instead of catch (Exception e). ' +
          'Use multiple catch blocks for different exception types. If a generic catch is truly needed ' +
          '(top-level error handler), log the full exception and re-throw unexpected types. ' +
          'In Python: except ValueError, except IOError — never bare "except:".',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-396', name: 'Declaration of Catch for Generic Exception', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-397: Declaration of Throws for Generic Exception
// ---------------------------------------------------------------------------

function verifyCWE397(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const GENERIC_THROWS = /\b(?:throws|throw)\s+(?:Exception|Throwable|Error|RuntimeException|BaseException)\s*(?:\/[\/*].*)?(?:,|\{|$)/im;
  const CSHARP_GENERIC = /<exception\s+cref\s*=\s*"(?:System\.)?Exception"/i;
  const PY_GENERIC_RAISE = /raise\s+(?:Exception|BaseException)\s*\(/i;
  const LEGITIMATE_THROWS = /\b(main\s*\(|@(?:Test|Override|Bean)|test_\w+|def\s+test_|it\s*\(\s*['"]|describe\s*\(\s*['"]|@Deprecated)\b/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL') continue;
    const code = node.analysis_snapshot || node.code_snapshot;
    if ((GENERIC_THROWS.test(code) || CSHARP_GENERIC.test(code) || PY_GENERIC_RAISE.test(code))
        && !LEGITIMATE_THROWS.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (specific exception type in throws declaration)',
        severity: 'low',
        description: `Method at ${node.label} declares generic exception in its signature. This provides ` +
          `no information to callers about what can actually go wrong, forcing them to catch ` +
          `overly broad exception types (spreading CWE-396 upstream). The throws clause is part ` +
          `of the API contract — "throws Exception" means "anything can happen."`,
        fix: 'Declare specific checked exceptions: "throws IOException, SQLException" instead of ' +
          '"throws Exception". Wrap implementation-specific exceptions in domain exceptions. ' +
          'In Python, document specific exceptions in docstrings.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-397', name: 'Declaration of Throws for Generic Exception', holds: findings.length === 0, findings };
}

/**
 * CWE-546: Suspicious Comment
 * Pattern: Comments containing TODO, FIXME, HACK, XXX, VULNERABILITY, SECURITY etc.
 * indicating unfinished security work or known vulnerabilities left in production code.
 */
function verifyCWE546(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SUSPICIOUS_COMMENT_RE = /(?:\/\/|\/\*|#)\s*(?:TODO|FIXME|HACK|XXX|BUG|VULNERABILITY|SECURITY|TEMPORARY|WORKAROUND|KLUDGE|BROKEN|UNSAFE|INSECURE|DANGER|WARNING)\s*[:\-]?\s*(.{5,})/i;
  const SECURITY_COMMENT_RE = /(?:\/\/|\/\*|#)\s*(?:TODO|FIXME|HACK|XXX)\s*[:\-]?\s*(?:.*(?:auth|password|token|encrypt|hash|inject|xss|csrf|sql|sanitiz|validat|escape|permission|privilege|access.?control|bypass|vuln|exploit|attack|leak|expos|secret|credential|session|cookie|cert|ssl|tls|https|cors|csp|rate.?limit|brute.?force|dos|overflow|race.?condition))/i;
  const FALSE_POSITIVE_RE = /(?:\/\/|\/\*|#)\s*(?:TODO|FIXME)\s*[:\-]?\s*(?:.*(?:add\s+(?:unit\s+)?test|improve\s+(?:perf|readab|UX|UI)|refactor|clean.?up\s+(?:code|css|styling)|update\s+(?:docs|readme)|remove\s+(?:unused|dead)|typo|rename))/i;

  for (const node of map.nodes) {
    const code = node.code_snapshot; // Do NOT strip comments — we're scanning them
    const secMatch = SECURITY_COMMENT_RE.exec(code);
    if (secMatch && !FALSE_POSITIVE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (resolve security-related TODO/FIXME before release)',
        severity: 'medium',
        description: `Security-related suspicious comment at ${node.label}: "${secMatch[0].slice(0, 120)}". ` +
          'Indicates known but unresolved security work. Attackers study comments for vulnerability hints.',
        fix: 'Resolve the security issue. If not immediately fixable, create a tracked ticket and remove detailed comments from source.',
        via: 'structural',
      });
    } else {
      const match = SUSPICIOUS_COMMENT_RE.exec(code);
      if (match && !FALSE_POSITIVE_RE.test(code)) {
        const isSecNode = node.node_type === 'CONTROL' || node.node_type === 'AUTH' ||
          node.attack_surface.includes('auth') || node.attack_surface.includes('input') ||
          /\b(auth|crypt|secur|valid|sanit|token|session)\b/i.test(node.node_subtype);
        if (isSecNode) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (review suspicious comment in security-relevant code)',
            severity: 'low',
            description: `Suspicious comment in security-relevant code at ${node.label}: "${match[0].slice(0, 120)}". ` +
              'Unfinished work in security-critical paths may leave gaps in protection.',
            fix: 'Review and resolve. Remove or sanitize comments before production. Track in issue tracker if not immediately fixable.',
            via: 'structural',
          });
        }
      }
    }
  }
  // --- Strategy 2: Source-scan (from generated) — catches non-security-relevant nodes ---
  // This fires on ANY comment with BUG/FIXME/HACK/KLUDGE/XXX/WORKAROUND/BROKEN regardless
  // of node classification, which is what Juliet tests expect.
  const src546 = map.source_code || '';
  if (src546 && findings.length === 0) {
    const suspiciousKeywords = /\b(BUG|FIXME|HACK|KLUDGE|XXX|WORKAROUND|BROKEN)\b/;
    const lines546 = src546.split('\n');
    const reportedLines = new Set<number>();

    for (let i = 0; i < lines546.length; i++) {
      const line = lines546[i];
      // Check single-line comments
      const slComment = line.match(/\/\/(.*)$/);
      if (slComment && suspiciousKeywords.test(slComment[1])) {
        const keyword = slComment[1].match(suspiciousKeywords)![1];
        if (/\bFLAW\b|\bFIX\b|\bINCIDENTAL\b/.test(slComment[1])) continue;
        reportedLines.add(i + 1);
        const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
        if (nearNode) {
          findings.push({
            source: nodeRef(nearNode), sink: nodeRef(nearNode),
            missing: 'META (resolve suspicious comments before release)',
            severity: 'low',
            description: `L${i + 1}: Suspicious comment contains '${keyword}': ${line.trim().slice(0, 100)}`,
            fix: 'Review and resolve security-related BUG/FIXME/HACK/KLUDGE comments before release.',
            via: 'source_line_fallback',
          });
        }
      }
      // Check block comments on this line
      const blockComments = line.match(/\/\*([^*]|\*(?!\/))*\*\//g);
      if (blockComments) {
        for (const bc of blockComments) {
          if (suspiciousKeywords.test(bc)) {
            const keyword = bc.match(suspiciousKeywords)![1];
            if (/\bFLAW\b|\bFIX\b|\bINCIDENTAL\b/.test(bc)) continue;
            if (/TEMPLATE GENERATED|@description|Label Definition|Template File|Flow Variant/i.test(bc)) continue;
            if (reportedLines.has(i + 1)) continue;
            reportedLines.add(i + 1);
            const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
            if (nearNode) {
              findings.push({
                source: nodeRef(nearNode), sink: nodeRef(nearNode),
                missing: 'META (resolve suspicious comments before release)',
                severity: 'low',
                description: `L${i + 1}: Suspicious comment contains '${keyword}': ${bc.slice(0, 100)}`,
                fix: 'Review and resolve security-related BUG/FIXME/HACK/KLUDGE comments before release.',
                via: 'source_line_fallback',
              });
            }
          }
        }
      }
    }

    // Multi-line block comments spanning multiple lines
    const multiLineComments546 = src546.match(/\/\*[\s\S]*?\*\//g);
    if (multiLineComments546) {
      for (const mc of multiLineComments546) {
        if (!mc.includes('\n') && mc.includes('*/')) continue;
        if (suspiciousKeywords.test(mc) && !/\bFLAW\b|\bFIX\b|\bINCIDENTAL\b/.test(mc)) {
          const idx = src546.indexOf(mc);
          const lineNum = src546.slice(0, idx).split('\n').length;
          if (/TEMPLATE GENERATED|@description|Label Definition|Template File|Flow Variant/i.test(mc)) continue;
          if (reportedLines.has(lineNum)) continue;
          if (findings.some(f => Math.abs(f.source.line - lineNum) <= 2)) continue;
          const keyword = mc.match(suspiciousKeywords)![1];
          const nearNode = map.nodes.find(n => Math.abs(n.line_start - lineNum) <= 2) || map.nodes[0];
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'META (resolve suspicious comments before release)',
              severity: 'low',
              description: `L${lineNum}: Suspicious multi-line comment contains '${keyword}'`,
              fix: 'Review and resolve security-related BUG/FIXME/HACK/KLUDGE comments before release.',
              via: 'source_line_fallback',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-546', name: 'Suspicious Comment', holds: findings.length === 0, findings };
}

/**
 * CWE-547: Use of Hard-coded, Security-relevant Constants
 * Pattern: Security-critical values (timeouts, key sizes, iteration counts, max retries)
 * hardcoded instead of configurable. Unlike CWE-798 (credentials), this covers security
 * PARAMETERS that should be tunable without code changes.
 */
function verifyCWE547(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const WEAK_CRYPTO_CONST_RE = /\b(?:key.?(?:size|length|bits)\s*[:=]\s*(?:56|64|128|512|1024)\b|iterations?\s*[:=]\s*(?:[1-9]\d{0,3})\b|salt.?(?:length|size|rounds)\s*[:=]\s*(?:[1-8])\b|rounds?\s*[:=]\s*(?:[1-9]\d{0,2})\b)/i;
  const HARDCODED_TIMEOUT_RE = /\b(?:(?:session|token|jwt|cookie|cache|auth|lock|login).?(?:timeout|expir|ttl|duration|lifetime|max.?age|validity)\s*[:=]\s*\d+)\b/i;
  const HARDCODED_SECURITY_RE = /\b(?:max.?(?:retries|attempts|failures|login.?attempts)\s*[:=]\s*\d+|(?:rate.?limit|throttle|max.?requests)\s*[:=]\s*\d+|(?:min.?(?:password|pw).?(?:length|len)|password.?(?:min|max|length))\s*[:=]\s*\d+|(?:token.?(?:length|size|bits)|nonce.?(?:length|size))\s*[:=]\s*\d+)\b/i;
  const SAFE_RE = /\b(process\.env|os\.environ|os\.getenv|ENV\[|System\.getenv|getenv|config\.|settings\.|options\.|props\.|properties\.|\.yaml|\.yml|\.json|\.toml|\.ini|configurable|adjustable|override)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (WEAK_CRYPTO_CONST_RE.test(code) && !SAFE_RE.test(code)) {
      const match = WEAK_CRYPTO_CONST_RE.exec(code);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STORAGE (configurable crypto parameters — not hardcoded)',
        severity: 'medium',
        description: `Hard-coded cryptographic constant at ${node.label}: "${match?.[0] || 'crypto parameter'}". ` +
          'Cannot be updated when standards change without redeployment.',
        fix: 'Make crypto parameters configurable via environment variables or config. Use current recommended values (PBKDF2 >= 600000, AES-256, RSA >= 2048).',
        via: 'structural',
      });
    }

    if (HARDCODED_TIMEOUT_RE.test(code) && !SAFE_RE.test(code)) {
      const match = HARDCODED_TIMEOUT_RE.exec(code);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STORAGE (configurable security timeouts)',
        severity: 'low',
        description: `Hard-coded security timeout at ${node.label}: "${match?.[0] || 'timeout'}". ` +
          'Incident response may require immediate timeout changes without redeployment.',
        fix: 'Make timeouts configurable. Store in config/env vars. Document security implications.',
        via: 'structural',
      });
    }

    if (HARDCODED_SECURITY_RE.test(code) && !SAFE_RE.test(code)) {
      const match = HARDCODED_SECURITY_RE.exec(code);
      if (!findings.some(f => f.source.id === node.id)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STORAGE (configurable security thresholds)',
          severity: 'low',
          description: `Hard-coded security threshold at ${node.label}: "${match?.[0] || 'threshold'}". ` +
            'Security thresholds need to be adjustable for incident response and compliance changes.',
          fix: 'Externalize security constants to configuration. Use environment-specific values (stricter in production).',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-547', name: 'Hard-coded Security-relevant Constants', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-558: Use of getlogin() in Multithreaded Application
// getlogin() is not thread-safe and can return stale/wrong user info in
// multithreaded contexts. In security-sensitive code, this can lead to
// identity confusion and privilege escalation.
// ---------------------------------------------------------------------------
function verifyCWE558(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const GETLOGIN_RE = /\bgetlogin\s*\(\s*\)/;
  const SAFE_ALT_RE = /\b(getlogin_r|getpwuid|geteuid|getuid|getpwnam|os\.getlogin|pwd\.getpwuid|os\.getuid|getpass\.getuser)\b/;
  const THREAD_CONTEXT_RE = /\b(pthread|thread|Thread|threading|concurrent|parallel|async|spawn|fork|multithread|ExecutorService|ThreadPool|_beginthread|CreateThread|std::thread)\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    if (GETLOGIN_RE.test(code)) {
      // Check if there's any threading context in the same node or nearby
      const isThreaded = THREAD_CONTEXT_RE.test(code) ||
        map.nodes.some(n => n.id !== node.id && THREAD_CONTEXT_RE.test(n.analysis_snapshot || n.code_snapshot) &&
          node.edges.some(e => e.target === n.id) || n.edges.some(e => e.target === node.id));

      // Even without explicit threading context, getlogin() is inherently unsafe
      // because any process could be multithreaded
      const hasSafeAlt = SAFE_ALT_RE.test(code);

      if (!hasSafeAlt) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'STRUCTURAL (use thread-safe alternative to getlogin())',
          severity: isThreaded ? 'high' : 'medium',
          description: `getlogin() used at ${node.label}${isThreaded ? ' in a multithreaded context' : ''}. ` +
            `getlogin() is not thread-safe — it uses a static internal buffer that can be overwritten by another thread. ` +
            `In security contexts, this can return the wrong username, leading to identity confusion or privilege escalation.`,
          fix: 'Replace getlogin() with getlogin_r() (thread-safe reentrant version) or ' +
            'use getpwuid(geteuid()) to get the effective user from the process credentials. ' +
            'In Python, use getpass.getuser() or pwd.getpwuid(os.getuid()). ' +
            'Never use getlogin() for security decisions.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-558', name: 'Use of getlogin() in Multithreaded Application', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-560: Use of umask() with chmod-Style Argument
// umask() takes a MASK (bits to REMOVE), not a MODE (bits to SET).
// Passing chmod-style 0777 to umask() removes ALL permissions — the inverse
// of what was intended. Passing 0755 removes group write and all other bits.
// Common mistake: confusing umask argument semantics with chmod.
// ---------------------------------------------------------------------------
function verifyCWE560(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // chmod-style args that are almost certainly wrong when passed to umask
  // umask(0777) = remove ALL permissions (files created with mode 0000)
  // umask(0755) = remove owner-read+exec, group-read+exec, other-read+exec
  // umask(0644) = remove owner-read, group-read, other-read
  // Correct umask values are typically 0022, 0027, 0077
  const UMASK_CALL = /\bumask\s*\(\s*(0[0-7]{3}|0o[0-7]{3}|[0-7]{3,4})\s*\)/g;
  const CHMOD_STYLE_VALUES = /^0?o?(?:7[0-7]{2}|6[0-7]{2}|5[0-7]{2}|4[0-7]{2})$/;
  // Common correct umask values
  const SAFE_UMASK_VALUES = new Set(['0022', '0o022', '022', '0027', '0o027', '027', '0077', '0o077', '077', '0002', '0o002', '002', '0000', '0o000', '000']);

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let match;
    UMASK_CALL.lastIndex = 0;
    while ((match = UMASK_CALL.exec(code)) !== null) {
      const value = match[1];
      const normalizedValue = value.replace(/^0o/, '0');

      if (!SAFE_UMASK_VALUES.has(value) && CHMOD_STYLE_VALUES.test(normalizedValue)) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'STRUCTURAL (umask argument is a mask, not a mode)',
          severity: 'high',
          description: `umask(${value}) at ${node.label} appears to use a chmod-style mode instead of a mask. ` +
            `umask REMOVES bits — umask(0777) creates files with NO permissions, umask(0755) is almost certainly wrong. ` +
            `The intended umask is likely the COMPLEMENT: to create files with mode ${value}, use umask(0${(~parseInt(normalizedValue, 8) & 0o777).toString(8).padStart(3, '0')}).`,
          fix: `umask() takes a MASK of bits to REMOVE, not a MODE of bits to SET. ` +
            `Common correct values: umask(0022) for mode 0755, umask(0077) for mode 0700, umask(0027) for mode 0750. ` +
            `Formula: umask = 0777 - desired_mode. Review and fix to use the correct mask value.`,
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-560', name: 'Use of umask() with chmod-Style Argument', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-564: SQL Injection: Hibernate
// Hibernate HQL/JPQL injection — similar to SQL injection but through the
// Hibernate Query Language or JPQL. Concatenating user input into HQL/JPQL
// queries or Criteria API string expressions bypasses Hibernate's
// parameterized query support.
// ---------------------------------------------------------------------------
function verifyCWE564(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Hibernate/JPA query construction patterns
  const HQL_QUERY_RE = /\b(?:createQuery|createNativeQuery|createSQLQuery|session\.createQuery|entityManager\.createQuery|em\.createQuery)\s*\(/;
  const HQL_CONCAT_RE = /(?:createQuery|createNativeQuery|createSQLQuery)\s*\(\s*(?:["'].*["']\s*\+|\+\s*|`[^`]*\$\{|String\.format|".*"\s*\.\s*concat)/;
  const CRITERIA_STRING_RE = /\b(?:Restrictions\.sqlRestriction|session\.createCriteria|add\s*\(\s*Restrictions\.sqlRestriction\s*\()\s*.*\+/;
  // Safe patterns — parameterized HQL
  const SAFE_HQL_RE = /\b(?:setParameter|setString|setInteger|setLong|setProperties|:(\w+)|createNamedQuery|CriteriaBuilder|CriteriaQuery|NamedQuery|@Query.*\?[0-9]|@Query.*:(\w+))\b/;

  const ingress = nodesOfType(map, 'INGRESS');

  // Pattern 1: Tainted data flows to HQL query construction
  const hqlNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    HQL_QUERY_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const sink of hqlNodes) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        // Check for string concatenation in query construction
        if (HQL_CONCAT_RE.test(code) || CRITERIA_STRING_RE.test(code)) {
          if (!SAFE_HQL_RE.test(code)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (parameterized HQL/JPQL query)',
              severity: 'critical',
              description: `User input from ${src.label} is concatenated into a Hibernate/JPA query at ${sink.label}. ` +
                `HQL/JPQL injection allows an attacker to modify query logic, extract data from any entity, ` +
                `or bypass access controls. Hibernate does NOT prevent injection if you concatenate strings.`,
              fix: 'Use parameterized queries with named/positional parameters: ' +
                'session.createQuery("FROM User WHERE name = :name").setParameter("name", userInput). ' +
                'Or use the JPA Criteria API which is injection-safe by construction. ' +
                'Never concatenate user input into HQL/JPQL/native query strings.',
              via: 'bfs',
            });
          }
        }
      }
    }
  }

  // Pattern 2: Direct concatenation in query strings even without flow analysis
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    if (HQL_CONCAT_RE.test(code) && !SAFE_HQL_RE.test(code)) {
      // Check if the concatenated variable could come from user input
      const concatVar = code.match(/createQuery\s*\([^)]*\+\s*(\w+)/);
      if (concatVar) {
        const varName = concatVar[1];
        const isLikelyUserInput = /\b(input|param|request|req|query|body|arg|name|value|search|filter|sort|order|id)\b/i.test(varName);
        if (isLikelyUserInput) {
          // Check if not already found via flow analysis
          const alreadyFound = findings.some(f => f.sink.id === node.id);
          if (!alreadyFound) {
            findings.push({
              source: nodeRef(node),
              sink: nodeRef(node),
              missing: 'CONTROL (parameterized HQL/JPQL query)',
              severity: 'high',
              description: `Hibernate query at ${node.label} concatenates variable "${varName}" which appears to be user-controlled. ` +
                `HQL injection can read/modify any Hibernate-managed entity.`,
              fix: 'Use query.setParameter() instead of string concatenation. ' +
                'Or use Criteria API / JPA CriteriaBuilder for type-safe queries.',
              via: 'structural',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-564', name: 'SQL Injection: Hibernate', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-567: Unsynchronized Access to Shared Data in Multithreaded Context
// Shared mutable state accessed from multiple threads without synchronization
// causes race conditions. Unlike CWE-366 (race condition on check-then-act),
// this is about ANY unsynchronized read/write to shared data.
// ---------------------------------------------------------------------------
function verifyCWE567(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Shared mutable state patterns
  const SHARED_STATE_RE = /\b(static\s+(?!final|const|readonly)\w+\s+\w+\s*=|global\s+\w+|class\s+\w+.*\{[^}]*(?:public|protected)\s+\w+\s+\w+\s*[=;]|module\.exports\.\w+\s*=|self\.\w+\s*=|cls\.\w+\s*=)\b/;
  const THREAD_CONTEXT_RE = /\b(Thread|Runnable|ExecutorService|ThreadPool|pthread|threading|concurrent|async|spawn|fork|@Async|CompletableFuture|parallelStream|ForkJoinPool|goroutine|tokio::spawn|rayon|std::thread|multiprocessing|worker_threads|Worker|SharedArrayBuffer|Atomics)\b/;
  // Synchronization primitives
  const SYNC_RE = /\b(synchronized|volatile|AtomicInteger|AtomicLong|AtomicReference|AtomicBoolean|ReentrantLock|ReadWriteLock|ConcurrentHashMap|Collections\.synchronized|Lock\s*\(|RLock|Semaphore|Mutex|RwLock|sync\.Mutex|sync\.RWMutex|lock\s*\(|Monitor\.\w+|Interlocked\.\w+|threading\.Lock|asyncio\.Lock|@synchronized|concurrent\.futures)\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Node must have threading context
    if (!THREAD_CONTEXT_RE.test(code)) continue;

    // Look for shared mutable state without synchronization
    if (SHARED_STATE_RE.test(code) && !SYNC_RE.test(code)) {
      // Check if the shared state is actually accessed (read+write or write from multiple paths)
      const hasWrite = /\b\w+\s*(?:\+=|-=|\*=|\/=|=(?!=))\s*|\.set\s*\(|\.put\s*\(|\.add\s*\(|\.remove\s*\(|\.push\s*\(|\.pop\s*\(/.test(code);
      const hasRead = /\b(?:get|read|load|fetch|return\s+\w+|if\s*\(\s*\w+)\b/.test(code);

      if (hasWrite) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (synchronization on shared mutable state)',
          severity: 'high',
          description: `Shared mutable state at ${node.label} is accessed in a multithreaded context without synchronization. ` +
            `Concurrent unsynchronized access causes data races: torn reads/writes, stale values, ` +
            `and non-deterministic behavior. In security code, this can lead to TOCTOU vulnerabilities ` +
            `or inconsistent authorization decisions.`,
          fix: 'Protect shared state with appropriate synchronization: ' +
            'Java: synchronized blocks, volatile, AtomicXxx, or ConcurrentHashMap. ' +
            'Python: threading.Lock or queue.Queue. ' +
            'C/C++: std::mutex, std::atomic, or pthread_mutex. ' +
            'Or redesign to use immutable data and message passing.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-567', name: 'Unsynchronized Access to Shared Data in Multithreaded Context', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-568: finalize() Method Without super.finalize()
// In Java, a finalize() override that doesn't call super.finalize() breaks
// the cleanup chain — the parent class's resources are never released.
// This causes resource leaks (file handles, sockets, native memory) and
// can lead to denial of service.
// ---------------------------------------------------------------------------
function verifyCWE568(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // finalize() method declaration (any visibility)
  const FINALIZE_DECL = /\b(?:public|protected|private)?\s*(?:void\s+)?finalize\s*\(\s*\)\s*(?:throws\s+Throwable\s*)?\{/;
  const SUPER_FINALIZE = /\bsuper\s*\.\s*finalize\s*\(\s*\)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    if (FINALIZE_DECL.test(code) && !SUPER_FINALIZE.test(code)) {
      // Verify this is actually a class context (not just a method called finalize in JS/Python)
      const isJavaContext = /\b(class|extends|implements|@Override|protected\s+void|public\s+void)\b/.test(code);
      if (isJavaContext) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'STRUCTURAL (super.finalize() call in finalize() override)',
          severity: 'medium',
          description: `finalize() at ${node.label} does not call super.finalize(). ` +
            `The parent class's cleanup logic will never execute, causing resource leaks ` +
            `(file handles, sockets, database connections, native memory). ` +
            `If the parent holds security-sensitive resources (crypto keys, auth tokens), ` +
            `they will persist in memory indefinitely.`,
          fix: 'Add super.finalize() in a finally block: ' +
            'protected void finalize() throws Throwable { try { /* cleanup */ } finally { super.finalize(); } }. ' +
            'Better: avoid finalize() entirely. Use try-with-resources (AutoCloseable) or ' +
            'java.lang.ref.Cleaner (Java 9+). finalize() is deprecated since Java 9.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-568', name: 'finalize() Method Without super.finalize()', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-573: Improper Following of Specification by Caller
// Caller violates API contract: using a function/method in a way that the
// specification explicitly forbids or that produces undefined behavior.
// Common examples: calling APIs after close/dispose, passing null where
// non-null is required, violating thread-safety contracts, using
// deprecated/removed API features.
// ---------------------------------------------------------------------------
function verifyCWE573(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library/framework code defines close/end/destroy methods as primitives — not a spec violation
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-573', name: 'Improper Following of Specification by Caller', holds: true, findings };
  }

  // Pattern 1: Use after close/dispose/release
  const CLOSE_RE = /\b(?:close|dispose|release|destroy|shutdown|free|disconnect|end|finish|terminate)\s*\(\s*\)/;
  const USE_AFTER_CLOSE_RE = /(?:close|dispose|release|destroy|shutdown|free|disconnect)\s*\(\s*\)[\s\S]{0,200}?\b(?:read|write|send|recv|execute|query|get|set|put|post|fetch|call|invoke|flush|seek)\s*\(/;

  // Pattern 2: Calling methods on potentially null/undefined returns without check
  const NULL_RETURN_USE = /\b(?:get|find|lookup|search|query|fetch|load|resolve)\w*\s*\([^)]*\)\s*\.\s*\w+\s*\(/;
  const NULL_CHECK = /\b(?:if\s*\(\s*\w+\s*[!=]==?\s*(?:null|undefined|nil|None)|Optional|\.isPresent|\.isEmpty|\?\.|!\s*=\s*null|!==?\s*undefined)\b/;

  // Pattern 3: Violating immutability contracts
  const IMMUTABLE_VIOLATION = /\b(?:Collections\.unmodifiable\w+|Object\.freeze|frozenset|tuple|const\s+)\b[\s\S]{0,200}?\b(?:\.add\s*\(|\.put\s*\(|\.set\s*\(|\.remove\s*\(|\.delete\s*\(|\.push\s*\(|\.pop\s*\(|\[\w+\]\s*=)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Check for use-after-close
    if (USE_AFTER_CLOSE_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (respect resource lifecycle — do not use after close/dispose)',
        severity: 'high',
        description: `Resource at ${node.label} appears to be used after being closed/disposed. ` +
          `Using a closed resource violates the API contract and leads to undefined behavior: ` +
          `thrown exceptions, silent data loss, or corrupted state.`,
        fix: 'Restructure code to ensure all operations on a resource complete before close()/dispose(). ' +
          'Use try-with-resources (Java), using statement (C#), with statement (Python), or ' +
          'RAII patterns (C++) to ensure correct resource lifecycle.',
        via: 'structural',
      });
    }

    // Check for null-unsafe API usage (calling methods on potentially-null returns)
    if (NULL_RETURN_USE.test(code) && !NULL_CHECK.test(code)) {
      // Only flag in security-sensitive contexts to avoid noise
      const isSecurityCtx = /\b(auth|permission|credential|session|token|principal|identity|role|access|security)\b/i.test(code);
      if (isSecurityCtx) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (null check before method invocation on lookup result)',
          severity: 'medium',
          description: `Security-sensitive code at ${node.label} calls methods on a lookup/find/get result without null checking. ` +
            `If the lookup returns null, a NullPointerException crashes the security check, ` +
            `potentially bypassing authorization (fail-open on exception).`,
          fix: 'Always check the return value of lookup/find/get operations before using it. ' +
            'Use Optional (Java), ?. operator (TypeScript/Kotlin), or explicit null guards. ' +
            'Ensure the catch block does not silently grant access on failure.',
          via: 'structural',
        });
      }
    }

    // Check for immutability violations
    if (IMMUTABLE_VIOLATION.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (do not modify immutable collections/objects)',
        severity: 'medium',
        description: `Code at ${node.label} attempts to modify an immutable collection or frozen object. ` +
          `This violates the API contract and will throw UnsupportedOperationException (Java), ` +
          `TypeError (JavaScript), or similar. If this code is in an error handler or security ` +
          `path, the exception may cause a fail-open condition.`,
        fix: 'Create a mutable copy before modification: new ArrayList<>(immutableList), ' +
          '{...frozenObj}, or list(frozenTuple). Or redesign to avoid mutation.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-573', name: 'Improper Following of Specification by Caller', holds: findings.length === 0, findings };
}

/**
 * CWE-606: Unchecked Input for Loop Condition
 * User-controlled input directly controls loop bounds or termination,
 * enabling DoS (huge iteration), processing bypass (0/negative), or infinite loops.
 */
function verifyCWE606(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const LOOP_CONDITION = /\b(for|while|do)\b\s*\(/i;
  const USER_IN_LOOP = /\b(for|while)\s*\([^)]*\b(req\.|params\.|query\.|body\.|input\.|user\.|args\.|argv|request\.|form\[|GET\[|POST\[|params\[|data\[)/i;
  const BOUNDS_SAFE = /\b(Math\.min|Math\.max|clamp|MAX_|LIMIT|MAX_ITER|MAX_COUNT|MAX_ITEMS|MAX_LOOP|parseInt.*Math\.min|Number.*Math\.min|limit\s*=|maxItems|maxCount|maxIterations|\.slice\(0,\s*\d|\.substring\(0,\s*\d|if\s*\([^)]*>\s*\d+\s*\)|if\s*\([^)]*<\s*\d+\s*\))\b/i;
  const CAPPED = /\b(cap|limit|bound|clamp|truncate|ceiling|floor|constrain)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!LOOP_CONDITION.test(code)) continue;
    if (!USER_IN_LOOP.test(code)) continue;
    if (BOUNDS_SAFE.test(code) || CAPPED.test(code)) continue;

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'CONTROL (bounds validation on user-controlled loop iteration count)',
      severity: 'high',
      description: `${node.label} uses user-controlled input directly in a loop condition. ` +
        `An attacker can supply a very large value to cause CPU exhaustion (DoS), 0 to skip processing, or negative to cause unexpected behavior.`,
      fix: 'Validate and cap loop bounds: const count = Math.min(parseInt(input), MAX_ALLOWED). Always enforce an upper limit on user-controlled iteration counts.',
      via: 'structural',
    });
  }

  const loopNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STRUCTURAL' ||
     // CONTROL/loop nodes ARE loop nodes — include them for taint path analysis.
     // This is needed for Java where for/while/do are classified as CONTROL/loop.
     (n.node_type === 'CONTROL' && n.node_subtype === 'loop')) &&
    LOOP_CONDITION.test(n.analysis_snapshot || n.code_snapshot) &&
    !BOUNDS_SAFE.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
    !CAPPED.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const loop of loopNodes) {
      if (src.id === loop.id) continue;
      // For CONTROL/loop nodes: check if tainted data flows INTO the loop
      // (via data_in or the tainted_loop_bound tag set by the mapper).
      // We can't use hasTaintedPathWithoutControl here because the loop IS a CONTROL node
      // and the BFS would see it as a gate. Instead, check the loop's data_in directly.
      let loopHasTaint = false;
      let taintViaSinkTainted = false;
      if (loop.node_type === 'CONTROL' && loop.node_subtype === 'loop') {
        taintViaSinkTainted = loop.data_in.some((d: any) => d.tainted) ||
                              !!loop.tags?.includes('tainted_loop_bound');
        loopHasTaint = taintViaSinkTainted;
      } else {
        loopHasTaint = hasTaintedPathWithoutControl(map, src.id, loop.id);
      }
      if (loopHasTaint) {
        // Check if the loop is already guarded by bounds validation.
        // Look for containing branch nodes (if-statements) that check numeric bounds.
        const containingBranch606 = map.nodes.find(n =>
          n.node_type === 'CONTROL' && n.node_subtype === 'branch' &&
          n.line_start < loop.line_start && n.line_end >= loop.line_end &&
          /\b\w+\s*(?:<=?|>=?)\s*\d+/.test(n.analysis_snapshot || n.code_snapshot)
        );
        if (containingBranch606) continue;
        // Also check for bounds keywords in the containing scope
        const scopeSnaps606 = getContainingScopeSnapshots(map, loop.id);
        const scopeText606 = stripComments(scopeSnaps606.join('\n') || loop.analysis_snapshot || loop.code_snapshot);
        if (BOUNDS_SAFE.test(scopeText606) || CAPPED.test(scopeText606)) continue;
        if (!findings.some(f => f.sink.id === loop.id)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(loop),
            missing: 'CONTROL (bounds validation before user input reaches loop condition)',
            severity: 'high',
            description: `User input from ${src.label} reaches loop at ${loop.label} without bounds validation. ` +
              `Attacker can control iteration count causing denial-of-service.`,
            fix: 'Add bounds validation between input and loop: validate type is integer, enforce minimum (>= 0) and maximum (<= MAX_ALLOWED) before using in loop.',
            via: taintViaSinkTainted ? 'sink_tainted' : 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-606', name: 'Unchecked Input for Loop Condition', holds: findings.length === 0, findings };
}

/**
 * CWE-613: Insufficient Session Expiration
 * Pattern: Sessions that don't expire or have excessively long timeouts, allowing
 * stolen session tokens to be used indefinitely. Checks for missing maxAge/expires,
 * excessively long session durations, and missing idle timeout.
 */
function verifyCWE613(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Session configuration patterns
  const SESSION_CONFIG_RE = /\b(session\s*\(|express.?session|cookie.?session|SessionMiddleware|SESSION_ENGINE|session\.configure|createSession|sessionOptions|session.?config|session.?store|SessionStore|connect-redis|connect-mongo|express-mysql-session|memoryStore|fileStore)\b/i;
  // Expiration configuration
  const EXPIRY_RE = /\b(maxAge|max.?age|expires|expiration|ttl|timeout|lifetime|max.?inactive|idle.?timeout|absolute.?timeout|session.?duration|cookie.*(?:maxAge|expires)|SESSION_COOKIE_AGE|SESSION_TIMEOUT|SESSION_LIFETIME|session.?expiry|inactivity.?timeout)\b/i;
  // Excessively long session durations (> 24 hours in various units)
  const LONG_DURATION_MS_RE = /(?:maxAge|max.?age|expires|ttl|timeout|lifetime)\s*[:=]\s*(\d+)/i;
  // Safe patterns
  const SAFE_RE = /\b(rolling\s*:\s*true|resave|touch|session\.touch|session\.regenerate|session\.destroy|absolute.?timeout|idle.?timeout|sliding.?expiration|session.?cleanup|session.?gc|pruneSession|clearExpired|SESSION_COOKIE_AGE\s*[:=]\s*\d{1,5}\b|maxAge\s*[:=]\s*\d{1,7}\b)\b/i;
  // Logout/invalidation patterns
  const LOGOUT_RE = /\b(logout|log.?out|sign.?out|session\.destroy|session\.invalidate|req\.logout|endSession|clearSession|revokeSession|removeSession|deleteSession)\b/i;

  // Check 0: Java setMaxInactiveInterval with negative or zero value (session never expires)
  const JAVA_SESSION_NEVER_EXPIRE = /\bsetMaxInactiveInterval\s*\(\s*(-\d+|0)\s*\)/;
  const JAVA_SESSION_CONFIGURE = /\bsetMaxInactiveInterval\s*\(/;
  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (JAVA_SESSION_NEVER_EXPIRE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (session expiration — setMaxInactiveInterval must be positive)',
        severity: 'high',
        description: `Session at ${node.label} configured with negative/zero timeout via setMaxInactiveInterval(). ` +
          `A negative value means the session never expires, and zero means immediate expiration. ` +
          `Never-expiring sessions allow stolen session tokens to be reused indefinitely.`,
        fix: 'Set a reasonable positive timeout: session.setMaxInactiveInterval(1800) for 30 minutes. ' +
          'Enforce both idle timeout and absolute timeout. Invalidate sessions on logout.',
        via: 'structural',
      });
    }
  }

  // Check 0b: Java getSession() without setMaxInactiveInterval — no timeout configured
  const allCode613 = map.nodes.map(n => n.analysis_snapshot || n.code_snapshot).join('\n');
  if (/\bgetSession\s*\(/.test(allCode613) && !JAVA_SESSION_CONFIGURE.test(allCode613) && /\bjavax\.servlet|jakarta\.servlet/.test(allCode613)) {
    // Only flag if there's evidence of session usage without ANY timeout config
    const sessionNode = map.nodes.find(n => /\bgetSession\s*\(/.test(n.analysis_snapshot || n.code_snapshot));
    if (sessionNode && !SESSION_CONFIG_RE.test(allCode613) && !EXPIRY_RE.test(allCode613)) {
      // Don't flag — the web.xml may configure it. Only flag explicit bad values above.
    }
  }

  // Check 1: Session configuration without expiration
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SESSION_CONFIG_RE.test(code)) {
      if (!EXPIRY_RE.test(code)) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (session expiration configuration — maxAge or expires)',
          severity: 'high',
          description: `Session configuration at ${node.label} does not set an expiration time. ` +
            'Sessions without expiration remain valid indefinitely, allowing stolen tokens to be reused without limit.',
          fix: 'Set session maxAge/expires. Use both absolute timeout (max session lifetime) and idle timeout ' +
            '(inactivity limit). Recommended: 15-30 min idle, 8-24h absolute for web apps.',
          via: 'structural',
        });
      } else {
        // Check for excessively long durations
        const durationMatch = LONG_DURATION_MS_RE.exec(code);
        if (durationMatch) {
          const value = parseInt(durationMatch[1], 10);
          // If raw number > 86400000 (24h in ms) it's likely milliseconds and too long
          // If raw number > 86400 and code doesn't show * 1000, likely seconds and too long
          const isMs = /\*\s*1000/.test(code) || value > 100000;
          const durationMs = isMs ? value : value * 1000;
          const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
          if (durationMs > SEVEN_DAYS_MS) {
            findings.push({
              source: nodeRef(node),
              sink: nodeRef(node),
              missing: 'CONTROL (reasonable session timeout — current is > 7 days)',
              severity: 'medium',
              description: `Session at ${node.label} has an excessively long timeout (${Math.round(durationMs / 86400000)} days). ` +
                'Long-lived sessions increase the window for session hijacking.',
              fix: 'Reduce session timeout. For web applications: 15-30 min idle timeout, 8-24h absolute timeout. ' +
                'For APIs: use short-lived access tokens (15-60 min) with refresh tokens.',
              via: 'structural',
            });
          }
        }
      }
    }
  }

  // Check 2: JWT/token without expiration
  const JWT_RE = /\b(jwt\.sign|jsonwebtoken|jose\.|nimbus|JWT\.create|JWTCreator|createToken|generateToken|signToken|issueToken)\b/i;
  const JWT_EXPIRY_RE = /\b(expiresIn|exp|expiration|maxAge|ttl|iat.*exp|nbf|setExpiration|withExpiresAt|\.setIssuedAt|setTTL|tokenLifetime|token.?expiry)\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (JWT_RE.test(code) && !JWT_EXPIRY_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (JWT/token expiration — expiresIn or exp claim)',
        severity: 'high',
        description: `Token creation at ${node.label} does not set an expiration (exp claim). ` +
          'Tokens without expiration are valid forever and cannot be effectively revoked.',
        fix: 'Always set expiresIn/exp when creating JWTs. Use short-lived access tokens (15-60 min) ' +
          'with a refresh token rotation strategy. Validate exp on every request.',
        via: 'structural',
      });
    }
  }

  // Check 3: No logout/session-destroy endpoint
  const hasAuth = map.nodes.some(n =>
    n.node_type === 'AUTH' || /\b(login|authenticate|sign.?in)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );
  const hasLogout = map.nodes.some(n => LOGOUT_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
  if (hasAuth && !hasLogout) {
    const authNode = map.nodes.find(n =>
      n.node_type === 'AUTH' || /\b(login|authenticate|sign.?in)\b/i.test(n.analysis_snapshot || n.code_snapshot)
    );
    if (authNode) {
      findings.push({
        source: nodeRef(authNode),
        sink: nodeRef(authNode),
        missing: 'CONTROL (session invalidation / logout endpoint)',
        severity: 'medium',
        description: `Application has authentication at ${authNode.label} but no session destruction/logout mechanism. ` +
          'Users cannot explicitly end sessions, leaving tokens valid until natural expiration.',
        fix: 'Implement a logout endpoint that destroys the server-side session (req.session.destroy()) ' +
          'and clears the session cookie. For JWTs, maintain a token blocklist or use short-lived tokens with refresh token revocation.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-613', name: 'Insufficient Session Expiration', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-616: Incomplete Identification of Uploaded File Variables (PHP)
//
// In PHP, file uploads populate $_FILES with multiple properties (name, type,
// tmp_name, error, size). If code only checks $_FILES['x']['name'] or
// $_FILES['x']['type'] (client-controlled) without checking 'error' or
// using 'tmp_name' with move_uploaded_file(), attackers can bypass upload
// validation or overwrite arbitrary files.
// ---------------------------------------------------------------------------

function verifyCWE616(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const FILES_ACCESS = /\$_FILES\s*\[/i;
  const UPLOAD_VAR = /\b(req\.files?\b|request\.files?\b|\$_FILES|upload.*\bname\b|file.*\bname\b|multipart.*filename|original_?name|getClientOriginalName|getClientMimeType)\b/i;
  const CLIENT_ONLY_CHECK = /\$_FILES\s*\[\s*['"][^'"]+['"]\s*\]\s*\[\s*['"](?:name|type)['"]\s*\]/i;
  const SAFE_UPLOAD = /\b(move_uploaded_file|is_uploaded_file|tmp_name|getPathname|getRealPath|getClientOriginalExtension.*(?:allowedExtensions|whitelist|allowlist)|UPLOAD_ERR_OK|\['error'\]|finfo_file|finfo_open|mime_content_type|getimagesize|exif_imagetype|fileinfo|getMimeType|getSize|hashName|store\(|storeAs\()\b/i;
  const ERROR_CHECK = /\$_FILES\s*\[\s*['"][^'"]+['"]\s*\]\s*\[\s*['"]error['"]\s*\]/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (FILES_ACCESS.test(code)) {
      if (CLIENT_ONLY_CHECK.test(code) && !SAFE_UPLOAD.test(code) && !ERROR_CHECK.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (check $_FILES error code and use move_uploaded_file with tmp_name)',
          severity: 'high',
          description: `${node.label} accesses $_FILES name/type (client-controlled) without checking ` +
            `the error field or using move_uploaded_file(). The client can set any filename and MIME type. ` +
            `Without checking $_FILES['x']['error'] === UPLOAD_ERR_OK and using tmp_name, the upload ` +
            `handling may process non-uploaded files or miss upload failures.`,
          fix: 'Always check $_FILES["x"]["error"] === UPLOAD_ERR_OK first. Use move_uploaded_file($_FILES["x"]["tmp_name"], $dest) ' +
            'which verifies the file was actually uploaded via HTTP POST. Never trust $_FILES["x"]["name"] or ["type"] — ' +
            'validate extensions against an allowlist and check MIME with finfo_file().',
          via: 'structural',
        });
        continue;
      }
    }

    if (node.node_type === 'INGRESS' || node.node_type === 'TRANSFORM') {
      if (UPLOAD_VAR.test(code) && !SAFE_UPLOAD.test(code)) {
        const usesClientName = /\b(original_?name|getClientOriginalName|getClientMimeType|\['name'\]|\["name"\]|\.name\b|filename)\b/i.test(code);
        const hasFileWrite = /\b(rename|copy|move|fwrite|file_put_contents|writeFile|saveTo|pipe|createWriteStream)\b/i.test(code);

        if (usesClientName && hasFileWrite) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (validate upload variables server-side — do not trust client filename/MIME)',
            severity: 'high',
            description: `${node.label} uses the client-supplied filename directly in a file write operation. ` +
              `The client controls the filename and can set it to path traversal sequences (../../etc/passwd) ` +
              `or dangerous extensions (.php, .jsp). All upload variables from the client are attacker-controlled.`,
            fix: 'Generate a safe filename server-side (e.g., UUID + validated extension). ' +
              'Validate the extension against an allowlist. Check the file content with finfo/magic bytes. ' +
              'Never use the client filename directly in file system operations.',
            via: 'structural',
          });
        }
      }
    }
  }

  const ingress = nodesOfType(map, 'INGRESS');
  const uploadIngress = ingress.filter(n =>
    /\b(upload|file|multipart|\$_FILES)\b/i.test(n.analysis_snapshot || n.code_snapshot) ||
    n.node_subtype.includes('upload') || n.node_subtype.includes('file') ||
    n.attack_surface.includes('file_upload')
  );

  const fileSinks = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    /\b(rename|move|copy|writeFile|fwrite|file_put_contents|save|mv\(|move_uploaded_file)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const src of uploadIngress) {
    for (const sink of fileSinks) {
      if (src.id === sink.id) continue;
      if (findings.some(f => f.sink.id === sink.id && f.source.id === src.id)) continue;
      const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      if (SAFE_UPLOAD.test(sinkCode)) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(sink),
          missing: 'CONTROL (validate all upload file variables before file operation)',
          severity: 'high',
          description: `Upload data from ${src.label} flows to file operation at ${sink.label} without ` +
            `complete validation of upload variables. PHP $_FILES contains 5 variables per upload ` +
            `(name, type, tmp_name, error, size) — all must be checked for safe handling.`,
          fix: 'Check error code, validate file size, verify MIME type server-side (finfo_file), ' +
            'generate a safe destination filename, and use move_uploaded_file() for the actual move.',
          via: 'bfs',
        });
      }
    }
  }

  return { cwe: 'CWE-616', name: 'Incomplete Identification of Uploaded File Variables (PHP)', holds: findings.length === 0, findings };
}

/**
 * CWE-617: Reachable Assertion
 * assert() reachable by attacker-controlled input. Failed assert calls abort(),
 * crashing the process. If an attacker can trigger the assertion, it is DoS.
 */
function verifyCWE617(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const ASSERT_RE = /\b(assert\s*\(|assert\s+\w|Assert\.|ASSERT\(|NSAssert|g_assert|DEBUG_ASSERT|DCHECK\(|CHECK\(|VERIFY\(|static_assert|_Static_assert|invariant\(|precondition\(|require\s*\((?!['"]\w+['"]))/i;
  const SAFE_ASSERT = /\b(static_assert|_Static_assert|#ifndef\s*NDEBUG|@Test|test_|_test\.|\.test\.|spec\.|\.spec\.|jest\.|describe\s*\(|it\s*\(|expect\s*\(|Debug\.Assert|console\.assert|assert\.ok|assert\.equal|assert\.strict)\b/i;
  const ASSERT_INPUT_VALIDATION = /assert\s*\(.*(?:req\.|params\.|query\.|body\.|input\.|argv|args\.|request\.|user\.|form|GET|POST)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!ASSERT_RE.test(code)) continue;
    if (SAFE_ASSERT.test(code)) continue;

    if (ASSERT_INPUT_VALIDATION.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (proper error handling instead of assert on user input)',
        severity: 'high',
        description: `${node.label} uses an assertion to validate user input. If the assertion fails, ` +
          `the process aborts/crashes (C/C++) or throws an unrecoverable error. ` +
          `An attacker can craft input that fails the assertion, causing denial-of-service.`,
        fix: 'Replace assert() with proper input validation that returns an error response (400 Bad Request). ' +
          'Assertions are for invariants that should NEVER be false — user input can be anything.',
        via: 'structural',
      });
      continue;
    }

    let reachable = false;
    for (const src of ingress) {
      if (src.id === node.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, node.id)) {
        reachable = true;
        findings.push({
          source: nodeRef(src), sink: nodeRef(node),
          missing: 'CONTROL (input validation before data reaches assertion)',
          severity: 'medium',
          description: `User input from ${src.label} can reach assertion at ${node.label}. ` +
            `If crafted input causes the assertion to fail, the process will abort (DoS).`,
          fix: 'Either: (1) validate input before it reaches the assertion, or (2) replace the assertion with proper error handling that returns a graceful error instead of crashing.',
          via: 'bfs',
        });
        break;
      }
    }

    if (!reachable && node.node_type !== 'STRUCTURAL') {
      const isProductionCode = !SAFE_ASSERT.test(node.file || '');
      if (isProductionCode && /\bassert\s*\(|\bassert\s+(?:false|true|\w)/.test(code)) {
        // Detect always-failing assertions: assert(false), assert false, assert(0), assert 0
        // These are guaranteed to trigger whenever reached (Juliet CWE-617 pattern)
        const ALWAYS_FAIL_ASSERT = /\bassert\s*\(\s*(?:false|0|False|FALSE)\s*\)|\bassert\s+(?:false|0|False|FALSE)\s*;/;
        if (ALWAYS_FAIL_ASSERT.test(code)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (remove always-failing assertion or replace with proper error handling)',
            severity: 'high',
            description: `${node.label} has an assertion that ALWAYS fails (assert false). ` +
              `If this code is reachable and assertions are enabled, it will unconditionally crash the process.`,
            fix: 'Remove the always-failing assert, or replace with proper error handling (throw, return error). ' +
              'If this is meant as unreachable-code marker, use a throw statement instead.',
            via: 'structural',
          });
        } else {
          const hasErrorPath = /\b(catch|error|except|fail|invalid|unexpected)\b/i.test(code);
          if (hasErrorPath) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(node),
              missing: 'CONTROL (proper error handling instead of assert in error path)',
              severity: 'low',
              description: `${node.label} uses assert() in an error handling path. If this code is reachable in production ` +
                `(assertions not compiled out), a failed assertion will crash the process instead of handling the error gracefully.`,
              fix: 'Replace assert with proper error handling (throw, return error code, log and recover). ' +
                'Reserve assertions for truly impossible conditions, and ensure they are compiled out in production (NDEBUG).',
              via: 'structural',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-617', name: 'Reachable Assertion', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-621: Variable Extraction Error
//
// Using functions like PHP's extract(), Ruby's binding.eval, or dynamic
// variable creation from user input that overwrites existing variables.
// extract($_GET) or extract($_POST) lets attackers overwrite any local variable
// including authentication flags, configuration, and control flow variables.
// ---------------------------------------------------------------------------

function verifyCWE621(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const EXTRACT_SUPERGLOBAL = /\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\b/i;
  const EXTRACT_GENERIC = /\b(extract\s*\(|parse_str\s*\(\s*[^,)]+\s*\)|import_request_variables|mb_parse_str\s*\(\s*[^,)]+\s*\))/i;
  const VAR_VARS = /\$\$\w+\s*=/;
  const PY_EXTRACT = /\b(locals\(\)\s*\.?\s*update|globals\(\)\s*\.?\s*update|exec\s*\(|vars\(\)\s*\[|setattr\s*\(\s*(?:self|cls|module))/i;
  const RUBY_EXTRACT = /\b(binding\.eval|instance_variable_set|define_method|class_eval|module_eval|send\s*\(\s*(?:params|request))/i;
  const JS_EXTRACT = /\b(Object\.assign\s*\(\s*(?:this|global|window|globalThis|self)\s*,|with\s*\(|eval\s*\(.*(?:req\.|params\.|query\.|body\.))/i;
  const SAFE_EXTRACT = /\b(EXTR_SKIP|EXTR_PREFIX|EXTR_IF_EXISTS|extract\s*\([^)]+,\s*EXTR_|parse_str\s*\([^,]+,\s*\$|mb_parse_str\s*\([^,]+,\s*\$|Object\.freeze|Object\.seal)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (EXTRACT_SUPERGLOBAL.test(code) && !SAFE_EXTRACT.test(code)) {
      const match = code.match(EXTRACT_SUPERGLOBAL);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (never use extract() on superglobals — use explicit variable assignment)',
        severity: 'critical',
        description: `${node.label} calls extract() on $_${match?.[1] ?? 'REQUEST'}, which imports ALL user-supplied ` +
          `parameters as local variables. An attacker can overwrite ANY variable in scope — including ` +
          `$isAdmin, $authenticated, $userId, $config, etc. This is a complete variable injection attack.`,
        fix: 'Remove extract() entirely. Access request data explicitly: $name = $_POST["name"]. ' +
          'If extract is truly needed, use EXTR_SKIP to prevent overwriting: extract($data, EXTR_SKIP). ' +
          'Better: use a framework that provides structured input access (Laravel $request->input()).',
        via: 'structural',
      });
      continue;
    }

    if (EXTRACT_GENERIC.test(code) && !SAFE_EXTRACT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use EXTR_SKIP flag or explicit variable assignment instead of extract)',
        severity: 'high',
        description: `${node.label} uses extract()/parse_str() which creates variables from array keys. ` +
          `If the array source is user-controlled (even indirectly), attackers can inject variables ` +
          `that overwrite security-critical state.`,
        fix: 'Replace extract($data) with explicit assignments. If needed, use extract($data, EXTR_SKIP) ' +
          'to prevent overwriting existing variables. For parse_str(), always provide a second argument: ' +
          'parse_str($str, $result) to capture into a named array instead of local scope.',
        via: 'structural',
      });
      continue;
    }

    if (VAR_VARS.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use associative array instead of variable variables)',
        severity: 'medium',
        description: `${node.label} uses variable variables ($$var) which dynamically create/overwrite ` +
          `variables based on another variable's value. If the variable name comes from user input, ` +
          `any local variable can be overwritten.`,
        fix: 'Replace $$key = $value with an associative array: $data[$key] = $value. ' +
          'This isolates dynamic keys into a container instead of polluting the local scope.',
        via: 'structural',
      });
      continue;
    }

    if (PY_EXTRACT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use a dictionary instead of modifying locals()/globals())',
        severity: 'high',
        description: `${node.label} dynamically modifies local/global scope (locals().update, globals().update, ` +
          `exec, or setattr). If keys come from user input, attackers can overwrite security-critical variables.`,
        fix: 'Use a dictionary to store dynamic values: data[key] = value. ' +
          'Never call locals().update() or globals().update() with user-controlled data. ' +
          'Avoid exec() — use ast.literal_eval() for safe data parsing.',
        via: 'structural',
      });
      continue;
    }

    if (RUBY_EXTRACT.test(code)) {
      const hasUserInput = /\b(params|request|cookies|session)\b/i.test(code);
      if (hasUserInput) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (validate method/variable names against allowlist before dynamic dispatch)',
          severity: 'high',
          description: `${node.label} uses dynamic Ruby variable/method injection (binding.eval, instance_variable_set, ` +
            `send) with potentially user-controlled input. Attackers can invoke arbitrary methods or set ` +
            `arbitrary instance variables.`,
          fix: 'Validate method/attribute names against an explicit allowlist: ' +
            'ALLOWED = [:name, :email]; raise unless ALLOWED.include?(attr). ' +
            'Use strong_parameters in Rails to whitelist permitted attributes.',
          via: 'structural',
        });
        continue;
      }
    }

    if (JS_EXTRACT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (do not spread user input into global/this scope)',
        severity: 'high',
        description: `${node.label} spreads or assigns dynamic properties into this/global scope. ` +
          `If the source object contains user-controlled keys, attackers can overwrite critical ` +
          `properties including __proto__, constructor, or application state.`,
        fix: 'Use a dedicated data object instead of assigning to this/global. ' +
          'Filter keys against an allowlist before Object.assign(). ' +
          'Never use the "with" statement — it is deprecated and creates scope injection risks.',
        via: 'structural',
      });
    }
  }

  const extractNodes = map.nodes.filter(n => {
    const code = n.analysis_snapshot || n.code_snapshot;
    return (EXTRACT_GENERIC.test(code) || VAR_VARS.test(code) || PY_EXTRACT.test(code) ||
            RUBY_EXTRACT.test(code) || JS_EXTRACT.test(code)) &&
           !SAFE_EXTRACT.test(stripComments(code));
  });

  for (const src of ingress) {
    for (const ext of extractNodes) {
      if (src.id === ext.id) continue;
      if (findings.some(f => f.sink.id === ext.id)) continue;
      if (hasTaintedPathWithoutControl(map, src.id, ext.id)) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(ext),
          missing: 'CONTROL (validate/filter input before variable extraction)',
          severity: 'high',
          description: `User input from ${src.label} flows to variable extraction at ${ext.label}. ` +
            `The extraction function creates variables from input keys, allowing attackers to overwrite ` +
            `any variable in scope — including authentication flags and configuration.`,
          fix: 'Remove extract/dynamic variable creation, or filter the input to only contain expected keys. ' +
            'Use explicit variable assignment instead of bulk variable injection.',
          via: 'bfs',
        });
      }
    }
  }

  return { cwe: 'CWE-621', name: 'Variable Extraction Error', holds: findings.length === 0, findings };
}

/**
 * CWE-622: Improper Validation of Function Hook Arguments
 * Hook/callback/plugin systems that accept external function arguments without
 * validating them. If hook arguments come from untrusted sources, they can inject
 * malicious behavior into the application lifecycle.
 */
function verifyCWE622(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Removed require()/import() — those are normal JS module loading, not hook registration.
  // Dynamic require/import with user input is handled separately by DYNAMIC_REQUIRE above.
  // Case-insensitive for framework-specific patterns (app.use, addEventListener, etc.)
  const HOOK_REGISTER_CI = /\b(app\.use\(|router\.use\(|addEventListener|addListener|\.hook\(|\.intercept\(|\.register\(|\.plugin\(|\.middleware\(|before_request|after_request|before_action|after_action|@Hook|@Middleware|@Interceptor|\.addHook\(|\.decorate\(|dynamicImport)\b/i;
  // Case-sensitive for Function() constructor vs function() keyword, and eval()
  const HOOK_REGISTER_CS = /\b(eval\(|Function\(|new\s+Function)\b/;
  const HOOK_REGISTER_TEST = (code: string) => HOOK_REGISTER_CI.test(code) || HOOK_REGISTER_CS.test(code);
  const USER_CONTROLLED_FN = /\b(req\.|params\.|query\.|body\.|input\.|user\.)[\w.]*\s*(?:\(|=>|function|\bmodule\b|\brequire\b|\bimport\b)/i;
  const DYNAMIC_REQUIRE = /(?:require|import)\s*\(\s*(?:req\.|params\.|query\.|body\.|input\.|user\.|args\.|process\.env)/i;
  const SAFE_HOOK = /\b(typeof\s+\w+\s*===?\s*['"]function|instanceof\s+Function|isFunction\(|isCallable\(|allowedHooks|hookWhitelist|hookAllowlist|registeredHooks|validHooks|static\s+\w+Hook|@Injectable|@Component|@Module)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_HOOK.test(code)) continue;

    if (DYNAMIC_REQUIRE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate module path against allowlist before dynamic import)',
        severity: 'critical',
        description: `${node.label} dynamically loads a module/function from user-controlled input. ` +
          `An attacker can specify an arbitrary module path, leading to code execution.`,
        fix: 'Never use user input in require()/import(). Use an allowlist of permitted modules: ' +
          'const allowed = { "json": jsonPlugin, "csv": csvPlugin }; const handler = allowed[input].',
        via: 'structural',
      });
      continue;
    }

    if (HOOK_REGISTER_TEST(code) && USER_CONTROLLED_FN.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate hook function arguments — type check and allowlist)',
        severity: 'high',
        description: `${node.label} registers a hook/middleware/callback with user-controlled arguments. ` +
          `If the function reference or its arguments come from untrusted input, an attacker can inject ` +
          `malicious behavior into the hook chain.`,
        fix: 'Validate hook arguments: check types, validate against an allowlist of permitted hooks/handlers, ' +
          'and never allow user input to specify function references directly.',
        via: 'structural',
      });
    }
  }

  const hookNodes = map.nodes.filter(n =>
    HOOK_REGISTER_TEST((n.analysis_snapshot || n.code_snapshot)) &&
    !SAFE_HOOK.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const hook of hookNodes) {
      if (src.id === hook.id) continue;
      if (findings.some(f => f.sink.id === hook.id)) continue;
      if (hasTaintedPathWithoutControl(map, src.id, hook.id)) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(hook),
          missing: 'CONTROL (validate input before it reaches hook/middleware registration)',
          severity: 'high',
          description: `User input from ${src.label} flows to hook registration at ${hook.label}. ` +
            `If this input controls which hook is registered or its arguments, attackers can inject behavior.`,
          fix: 'Add input validation between the ingress and hook registration. Use allowlists for permitted hook names and validate argument types.',
          via: 'bfs',
        });
      }
    }
  }

  return { cwe: 'CWE-622', name: 'Improper Validation of Function Hook Arguments', holds: findings.length === 0, findings };
}

/**
 * CWE-624: Executable Regular Expression Error
 * User input constructs regex that gets executed. In Perl/PHP, /e flag makes regex
 * executable. Even without execution, user-controlled regex enables ReDoS.
 *
 * Key difference from CWE-1333: CWE-624 = user CONSTRUCTS the regex.
 * CWE-1333 = static regex has backtracking issues.
 *
 * SECOND-PASS NOTE: evaluateControlEffectiveness catches ReDoS in CONTROL regex,
 * but CWE-624 is about user-supplied regex that bypasses static analysis entirely.
 */
function verifyCWE624(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const lang = inferMapLanguage(map);

  const REGEX_CONSTRUCT = /\b(new\s+RegExp\s*\(|re\.compile\s*\(|Pattern\.compile\s*\(|Regex\s*\(|regexp\.Compile\s*\(|regex\.MustCompile\s*\(|Regexp\.new\s*\(|preg_match\s*\(\s*\$|preg_replace\s*\(\s*\$|ereg\s*\(|eregi\s*\()\b/i;
  // The /e regex modifier only exists in PHP (preg_replace) and Perl (s///e).
  // It does NOT exist in JavaScript, Python, Java, Go, Ruby, Rust, C#, etc.
  // Only check for it in PHP/Perl code.
  const EXEC_REGEX = /\bpreg_replace\s*\(\s*['"]\/[^'"]*\/[a-z]*e[a-z]*['"]/i;
  const USER_IN_REGEX = /(?:new\s+RegExp|re\.compile|Pattern\.compile)\s*\(\s*(?:req\.|params\.|query\.|body\.|input\.|user\.|request\.|args\.|argv)/i;
  const SAFE_REGEX = /\b(escapeRegex|escapeRegExp|escape_regex|re\.escape|Pattern\.quote|Regex\.escape|regexp\.QuoteMeta|quotemeta|preg_quote|sanitizeRegex|RegExp\.escape|_.escapeRegExp|lodash.*escape|escape.*special.*char)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_REGEX.test(code)) continue;

    // /e flag check — PHP/Perl only, skip for JavaScript/Python/etc.
    if (!['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'rust', 'csharp', 'c', 'c++', 'kotlin', 'swift'].includes(lang) && EXEC_REGEX.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (remove executable /e flag from regex, use callback replacement instead)',
        severity: 'critical',
        description: `${node.label} uses the /e flag on a regular expression, which causes the replacement string to be executed as code. ` +
          `This is equivalent to eval() and enables remote code execution if input is user-controlled.`,
        fix: 'Remove the /e flag. In PHP, use preg_replace_callback() instead of preg_replace with /e. ' +
          'In Perl, use /r with a callback or s///r with explicit evaluation only on trusted data.',
        via: 'structural',
      });
      continue;
    }

    if (USER_IN_REGEX.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (escape user input before regex construction)',
        severity: 'high',
        description: `${node.label} constructs a regex from user input without escaping. ` +
          `Attacker can inject regex metacharacters causing ReDoS, or in some languages, code execution.`,
        fix: 'Escape user input before using in regex: JS: input.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&"), ' +
          'Python: re.escape(input), Java: Pattern.quote(input), Go: regexp.QuoteMeta(input).',
        via: 'structural',
      });
    }
  }

  const regexNodes = map.nodes.filter(n =>
    REGEX_CONSTRUCT.test(n.analysis_snapshot || n.code_snapshot) &&
    !SAFE_REGEX.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const rx of regexNodes) {
      if (src.id === rx.id) continue;
      if (findings.some(f => f.sink.id === rx.id)) continue;
      if (hasTaintedPathWithoutControl(map, src.id, rx.id)) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(rx),
          missing: 'CONTROL (escape/sanitize user input before regex compilation)',
          severity: 'high',
          description: `User input from ${src.label} flows to regex construction at ${rx.label}. ` +
            `Attacker-controlled regex patterns can cause catastrophic backtracking (ReDoS) ` +
            `or, in languages with executable regex, arbitrary code execution.`,
          fix: 'Apply regex escaping (re.escape, Pattern.quote, etc.) to user input before compiling. ' +
            'Or use string matching (indexOf, includes) instead of regex for simple searches.',
          via: 'bfs',
        });
      }
    }
  }

  return { cwe: 'CWE-624', name: 'Executable Regular Expression Error', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-626: Null Byte Interaction Error (Poison Null Byte)
//
// A null byte (\0, %00) in user input can truncate strings in C-backed APIs.
// Even in higher-level languages (PHP, Python, Java), null bytes passed to
// OS-level functions (file open, path operations) get truncated by the C runtime.
// "file.php\0.jpg" passes a .jpg extension check but opens "file.php".
// ---------------------------------------------------------------------------

function verifyCWE626(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const PATH_OPS = /\b(open\s*\(|fopen\s*\(|file_get_contents\s*\(|include\s*\(|require\s*\(|include_once\s*\(|require_once\s*\(|readfile\s*\(|unlink\s*\(|rename\s*\(|mkdir\s*\(|rmdir\s*\(|stat\s*\(|lstat\s*\(|chmod\s*\(|chown\s*\(|realpath\s*\(|readlink\s*\(|symlink\s*\(|file_exists\s*\(|is_file\s*\(|is_dir\s*\(|pathinfo\s*\(|glob\s*\(|opendir\s*\(|readdir\s*\(|os\.path\.|os\.open|os\.remove|os\.rename|os\.mkdir|os\.stat|shutil\.|pathlib\.Path|File\.open|File\.read|File\.write|File\.delete|File\.exist|IO\.read|IO\.write|fs\.readFile|fs\.writeFile|fs\.open|fs\.unlink|fs\.stat|fs\.access|fs\.rename|fs\.mkdir)\b/i;

  const SAFE_NULL = /\b(str_replace\s*\(\s*['"]\\0|str_replace\s*\(\s*chr\s*\(\s*0\s*\)|replace\s*\(\s*['"]\x00|replace\s*\(\s*\/\\0|\.replace\s*\(\s*\/\\x00|\.replace\s*\(\s*\/\\u0000|strip_null|stripNull|removeNull|\\x00|\\u0000|\.includes\s*\(\s*'\\0'|\.includes\s*\(\s*'\\x00'|\.indexOf\s*\(\s*'\\0'|\.indexOf\s*\(\s*'\\x00'|preg_replace\s*\(\s*['"]\/\\0|preg_replace\s*\(\s*['"]\/\\x00)\b/i;

  const EXT_VALIDATION = /\b(endsWith|extname|extension|pathinfo\s*\([^)]+PATHINFO_EXTENSION|\.split\s*\(\s*['"]\.\s*['"]\s*\)\s*\.?\s*pop|substr\s*\(\s*strrpos)\b/i;
  const MODERN_SAFE = /\b(Path\.of\s*\(|Paths\.get\s*\(|Files\.\w+\s*\(|pathlib\.Path|nio\.file)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!PATH_OPS.test(code)) continue;
    if (SAFE_NULL.test(code)) continue;

    for (const src of ingress) {
      if (src.id === node.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, node.id)) {
        const hasExtCheck = EXT_VALIDATION.test(code);
        const isModern = MODERN_SAFE.test(code);

        if (isModern) continue;

        if (hasExtCheck) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(node),
            missing: 'CONTROL (strip null bytes before extension validation and path operations)',
            severity: 'high',
            description: `${node.label} validates file extension but does not strip null bytes. ` +
              `User input from ${src.label} could contain "file.php%00.jpg" — the extension check ` +
              `sees ".jpg" but the C runtime truncates at the null byte, opening "file.php". ` +
              `This bypasses any extension-based security check.`,
            fix: 'Strip null bytes from input BEFORE any validation: $input = str_replace(chr(0), "", $input). ' +
              'In PHP 5.3.4+, fopen() rejects null bytes — but older versions and some C extensions do not. ' +
              'Best practice: reject input containing null bytes entirely rather than stripping.',
            via: 'bfs',
          });
        } else {
          findings.push({
            source: nodeRef(src), sink: nodeRef(node),
            missing: 'CONTROL (reject or strip null bytes from user input before file/path operations)',
            severity: 'medium',
            description: `User input from ${src.label} reaches file operation at ${node.label} without ` +
              `null byte sanitization. A poison null byte (\\0, %00) in the path can truncate the string ` +
              `at the C level, potentially accessing unintended files.`,
            fix: 'Strip or reject null bytes in user input: input.replace(/\\0/g, "") (JS), ' +
              'str_replace(chr(0), "", $input) (PHP), input.replace("\\x00", "") (Python). ' +
              'Better: reject any input containing null bytes with a 400 error.',
            via: 'bfs',
          });
        }
        break;
      }
    }
  }

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_NULL.test(code)) continue;

    const PHP_INCLUDE_INJECT = /\b(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i;
    if (PHP_INCLUDE_INJECT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (never use user input in include/require — use allowlist)',
        severity: 'critical',
        description: `${node.label} passes user input directly to PHP include/require. Combined with a ` +
          `poison null byte, an attacker can include arbitrary files: include($_GET["page"].".php") ` +
          `with page=../../etc/passwd%00 truncates the .php suffix and includes /etc/passwd.`,
        fix: 'Never use user input in include/require. Use an allowlist: ' +
          '$pages = ["home" => "home.php", "about" => "about.php"]; include($pages[$input] ?? "404.php"). ' +
          'This eliminates both path traversal and null byte attacks entirely.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-626', name: 'Null Byte Interaction Error (Poison Null Byte)', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-627: Dynamic Variable Evaluation
//
// Code uses dynamic evaluation (eval, exec, Function constructor) to process
// variable names or values from user input. Similar to CWE-621 (extract) but
// focuses on eval-based variable injection: eval("$" + userInput + " = value")
// or exec(f"{var_name} = {var_value}").
// ---------------------------------------------------------------------------

function verifyCWE627(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const EVAL_VAR_PHP = /\beval\s*\(\s*['"]?\s*\$(?!\$)/i;
  const EVAL_VAR_CONCAT = /\beval\s*\(\s*(?:['"].*\$|.*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)|.*\+\s*(?:req\.|params\.|query\.|body\.))/i;
  const EXEC_VAR_PY = /\bexec\s*\(\s*(?:f['"]|['"].*\{|.*(?:format|%)\s*\()/i;
  const DYNAMIC_VAR_EVAL = /\b(eval\s*\(|exec\s*\(|compile\s*\(|ast\.literal_eval|Function\s*\()\s*[^)]*(?:\+|concat|format|`\$\{|f['"]|\.\s*\$)/i;

  // Case-sensitive: Function() constructor vs function() keyword
  const FUNCTION_CONSTRUCTOR_CS = /\bnew\s+Function\s*\(\s*[^)]*(?:\+|concat|`\$\{)/;

  const PHP_VARVAR_INPUT = /\$\{\s*\$_(GET|POST|REQUEST|COOKIE)/i;

  const PY_ATTR_INPUT = /\b(getattr|setattr|delattr)\s*\(\s*\w+\s*,\s*(?:request\.|params\.|input\[|form\[|args\[)/i;

  const SAFE_EVAL = /\b(ast\.literal_eval|JSON\.parse|json\.loads|json_decode|yaml\.safe_load|YAML\.safe_load|safe_eval|sandboxed|sandbox|safeEval|literal_eval)\b/i;
  const ALLOWLIST_CHECK = /\b(allowed|whitelist|allowlist|permitted|valid_\w+s|VALID_\w+S|in_array\s*\(.*(?:allowed|valid)|\.includes\s*\(.*(?:allowed|valid)|hasOwnProperty|\.has\s*\()\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_EVAL.test(code)) continue;
    if (ALLOWLIST_CHECK.test(code)) continue;

    if (EVAL_VAR_CONCAT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (never eval user input — use allowlist-based dispatch)',
        severity: 'critical',
        description: `${node.label} evaluates user input via eval(). The attacker controls what code gets ` +
          `executed, which enables arbitrary code execution. In PHP, eval("\\$$var = $val") with ` +
          `user-controlled $var allows overwriting any variable and injecting code.`,
        fix: 'Remove eval entirely. Use an explicit mapping: $handlers = ["x" => fn() => ...]; ' +
          '$handlers[$input]() ?? throw. For dynamic variable access, use an array: $data[$key] = $value.',
        via: 'structural',
      });
      continue;
    }

    if (PHP_VARVAR_INPUT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use array access instead of variable variables with user input)',
        severity: 'critical',
        description: `${node.label} creates a PHP variable variable from user input: \${$_GET[...]}. ` +
          `This lets attackers read or write ANY variable in scope by controlling the GET parameter. ` +
          `Combined with variable injection, this can bypass authentication or execute arbitrary code.`,
        fix: 'Replace variable variables with array access: $data[$_GET["key"]] instead of ${$_GET["key"]}. ' +
          'Validate the key against an allowlist of expected variable names.',
        via: 'structural',
      });
      continue;
    }

    if (EXEC_VAR_PY.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (never use exec() with formatted/interpolated strings)',
        severity: 'critical',
        description: `${node.label} uses Python exec() with string formatting/interpolation. ` +
          `If any interpolated value comes from user input, the attacker can inject arbitrary ` +
          `Python code. exec(f"{var_name} = {var_value}") is equivalent to eval() for injection.`,
        fix: 'Remove exec(). Use a dictionary for dynamic variable storage: data[key] = value. ' +
          'If you need dynamic attribute access, use getattr/setattr with an allowlist of permitted attributes.',
        via: 'structural',
      });
      continue;
    }

    if (PY_ATTR_INPUT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate attribute name against allowlist before getattr/setattr)',
        severity: 'high',
        description: `${node.label} uses getattr/setattr with user-controlled attribute name. ` +
          `An attacker can access or modify private attributes, call arbitrary methods, or ` +
          `access __class__, __dict__, __globals__ for code execution.`,
        fix: 'Validate attribute names against an explicit allowlist: ' +
          'ALLOWED_ATTRS = {"name", "email"}; if attr not in ALLOWED_ATTRS: raise ValueError. ' +
          'Never pass user input directly to getattr/setattr.',
        via: 'structural',
      });
      continue;
    }

    if (DYNAMIC_VAR_EVAL.test(code) || FUNCTION_CONSTRUCTOR_CS.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (eliminate eval/Function constructor — use safe alternatives)',
        severity: 'high',
        description: `${node.label} uses dynamic evaluation with string concatenation/interpolation. ` +
          `If any part of the evaluated string comes from user input, attackers can inject code ` +
          `that executes with the application's full privileges.`,
        fix: 'Replace eval/Function with structured alternatives: ' +
          'JS: use object lookup or switch/case. Python: use dict dispatch. PHP: use match/array mapping. ' +
          'For math expressions, use a safe parser library instead of eval.',
        via: 'structural',
      });
    }
  }

  const evalNodes = map.nodes.filter(n => {
    const code = n.analysis_snapshot || n.code_snapshot;
    return (EVAL_VAR_PHP.test(code) || EXEC_VAR_PY.test(code) || DYNAMIC_VAR_EVAL.test(code) ||
            FUNCTION_CONSTRUCTOR_CS.test(code) || PY_ATTR_INPUT.test(code)) &&
           !SAFE_EVAL.test(stripComments(code)) && !ALLOWLIST_CHECK.test(stripComments(code));
  });

  for (const src of ingress) {
    for (const ev of evalNodes) {
      if (src.id === ev.id) continue;
      if (findings.some(f => f.sink.id === ev.id)) continue;
      if (hasTaintedPathWithoutControl(map, src.id, ev.id)) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(ev),
          missing: 'CONTROL (sanitize/validate input before dynamic evaluation)',
          severity: 'critical',
          description: `User input from ${src.label} flows to dynamic evaluation at ${ev.label}. ` +
            `The eval/exec/Function call processes user-controlled data as code, enabling ` +
            `arbitrary variable manipulation and code execution.`,
          fix: 'Remove dynamic evaluation. Use structured alternatives (dictionary lookup, switch/case, allowlist). ' +
            'If eval is absolutely necessary, sandbox it completely and validate input against a strict grammar.',
          via: 'bfs',
        });
      }
    }
  }

  return { cwe: 'CWE-627', name: 'Dynamic Variable Evaluation', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-636: Not Failing Securely (Failing Open)
//
// When a security mechanism encounters an error or exception, it allows the
// operation to proceed instead of denying it. Auth checks that catch exceptions
// and return true, firewall rules that default to allow, access control that
// falls through to grant on error. The security decision defaults to PERMIT
// when it should default to DENY.
// ---------------------------------------------------------------------------

function verifyCWE636(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const AUTH_FUNCTION = /\b(isAuth|isAdmin|checkAuth|verifyAuth|authenticate|authorize|checkPermission|hasPermission|hasRole|isAllowed|canAccess|validateToken|verifyToken|checkAccess|requireAuth|ensureAuth|isLoggedIn|checkRole|verifySession|isAuthorized|checkCredentials|validateSession)\b/i;
  const SECURITY_CHECK = /\b(verify|validate|authenticate|authorize|check.*(?:auth|perm|role|access|token|session|cred)|is.*(?:auth|admin|valid|allowed|permitted))\b/i;

  const CATCH_RETURN_TRUE = /catch\s*(?:\(\s*\w+\s*\))?\s*\{[^}]*(?:return\s+true|return\s+null|return\s+undefined|return\s*;|pass\b|continue\b)/i;
  const CATCH_ALLOW = /catch\s*(?:\(\s*\w+\s*\))?\s*\{[^}]*(?:return\s+true|isAuth\w*\s*=\s*true|authenticated\s*=\s*true|authorized\s*=\s*true|allowed\s*=\s*true|granted\s*=\s*true|valid\s*=\s*true)/i;
  const EMPTY_CATCH = /catch\s*(?:\(\s*\w+\s*\))?\s*\{\s*\}/;
  const PY_EXCEPT_PASS = /except\s*(?:\w+\s*)?:\s*(?:\n\s*)?(?:pass|return\s+True|return\s+None)\b/i;

  const DEFAULT_ALLOW = /(?:(?:let|var|const|bool|boolean)\s+)?(?:isAuth\w*|authenticated|authorized|allowed|permitted|granted|hasAccess|valid)\s*(?::\s*\w+\s*)?=\s*(?:true|True|TRUE|1)\b/i;

  const SAFE_FAIL = /\b(return\s+false|throw\s+|raise\s+|deny|reject|forbidden|unauthorized|return\s+null.*(?:if|unless|when)|return\s+403|return\s+401|res\.status\s*\(\s*(?:401|403)|HttpStatus\.(?:UNAUTHORIZED|FORBIDDEN))\b/i;
  const DEFAULT_DENY = /(?:(?:let|var|const|bool|boolean)\s+)?(?:isAuth\w*|authenticated|authorized|allowed|permitted|granted|hasAccess|valid)\s*(?::\s*\w+\s*)?=\s*(?:false|False|FALSE|0)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if ((AUTH_FUNCTION.test(code) || SECURITY_CHECK.test(code)) &&
        (CATCH_ALLOW.test(code) || (EMPTY_CATCH.test(code) && !SAFE_FAIL.test(code)))) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (catch block in security check must deny access, not allow it)',
        severity: 'critical',
        description: `${node.label} has a security check that catches exceptions and defaults to ALLOW. ` +
          `If the auth/validation mechanism fails (DB down, token parse error, network timeout), ` +
          `the catch block returns true/null/undefined, granting access. An attacker can trigger ` +
          `the error condition to bypass authentication entirely.`,
        fix: 'Security checks MUST fail closed: catch blocks should return false, throw, or deny access. ' +
          'Pattern: try { return verifyToken(token); } catch (e) { return false; } — never catch and allow.',
        via: 'structural',
      });
      continue;
    }

    if (PY_EXCEPT_PASS.test(code) && SECURITY_CHECK.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (except clause in security check must deny access)',
        severity: 'critical',
        description: `${node.label} has a Python security check with "except: pass" or "except: return True". ` +
          `When the security check raises an exception (connection error, parse error, etc.), the code ` +
          `silently continues or returns True, effectively granting access on failure.`,
        fix: 'Replace "except: pass" with "except: return False" or "except: raise". ' +
          'Security checks must fail closed. Log the error for debugging but always deny access on exception.',
        via: 'structural',
      });
      continue;
    }

    if (DEFAULT_ALLOW.test(code) && !DEFAULT_DENY.test(code)) {
      const isScopeSecurityCheck = SECURITY_CHECK.test(code) || AUTH_FUNCTION.test(code);
      const hasConditionalDeny = /(?:if|else|unless|when)[\s\S]*?(?:=\s*false|=\s*False|=\s*FALSE|=\s*0)\b/i.test(code);

      if (isScopeSecurityCheck && !hasConditionalDeny) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (initialize security variables to false/deny, set true only on verified success)',
          severity: 'high',
          description: `${node.label} initializes a security decision variable to true/allow. If the code ` +
            `that should set it to false is skipped (early return, exception, logic error), access is ` +
            `granted by default. This is the "fail open" anti-pattern.`,
          fix: 'Initialize security variables to false/deny: let isAuthorized = false; ' +
            'Set to true ONLY after positive verification: if (validToken) isAuthorized = true. ' +
            'This ensures any unexpected code path defaults to deny.',
          via: 'structural',
        });
        continue;
      }
    }
  }

  const authNodes = nodesOfType(map, 'AUTH');
  const controlNodes = nodesOfType(map, 'CONTROL');
  for (const node of [...authNodes, ...controlNodes]) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (findings.some(f => f.source.id === node.id)) continue;

    const hasTryCatch = /\b(try\s*\{|try:|begin\b|rescue\b|except\b)/i.test(code);
    if (!hasTryCatch) continue;

    const hasSafeFail = SAFE_FAIL.test(code);
    const hasCatchAllow = CATCH_RETURN_TRUE.test(code) || EMPTY_CATCH.test(code) || PY_EXCEPT_PASS.test(code);

    if (hasCatchAllow && !hasSafeFail) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (error handler in security gate must deny access)',
        severity: 'high',
        description: `AUTH/CONTROL node ${node.label} has error handling that does not explicitly deny access. ` +
          `When this security gate throws an exception, the error handler may allow the request through. ` +
          `Security mechanisms must fail closed — deny access on any unexpected condition.`,
        fix: 'Add explicit deny in all catch/except blocks: return false, throw an auth error, or redirect to login. ' +
          'Never use empty catch blocks or "except: pass" in security-critical code paths.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-636', name: 'Not Failing Securely (Failing Open)', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-920: Improper Restriction of Power Consumption
// ---------------------------------------------------------------------------

function verifyCWE920(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const EXPENSIVE_OP_PATTERNS: Array<{ pattern: RegExp; name: string; fix: string; severity: 'medium' | 'high' }> = [
    { pattern: /\b(?:pbkdf2|scrypt|bcrypt|argon2|crypto\.createHash|hashlib\.\w+|MessageDigest\.getInstance)\s*\([^)]*(?:req\.|request\.|body\.|input\.)\b/i,
      name: 'crypto operation on unbounded user input',
      fix: 'Limit input size before hashing. For password hashing, limit password length (72 bytes for bcrypt).',
      severity: 'high' },
    { pattern: /\b(?:sharp|jimp|Pillow|PIL\.Image|ImageMagick|convert|gm\(|createCanvas|drawImage)\s*\([^)]*(?:req\.|upload|file|buffer|stream)/i,
      name: 'image processing on user upload without visible size check',
      fix: 'Limit file size (reject > 10MB). Limit dimensions. Use timeouts. Process in a worker with resource limits.',
      severity: 'medium' },
    { pattern: /\b(?:zlib\.inflate|zlib\.gunzip|zlib\.unzip|gunzip|decompress|ZipFile|ZipInputStream|tarfile\.open|tar\.Extract)\s*\([^)]*(?:req\.|upload|file|buffer|stream|body)/i,
      name: 'decompression of user-supplied data without size limit',
      fix: 'Check compressed AND uncompressed size. Limit compression ratio (reject > 100:1). This prevents zip bombs.',
      severity: 'high' },
    { pattern: /\b(?:DOMParser|xml\.parse|etree\.parse|parseString|SAXParser|XMLReader|DocumentBuilder)\s*\([^)]*(?:req\.|request\.|body\.|input\.)/i,
      name: 'XML parsing of user input without entity/depth limits',
      fix: 'Disable external entities, limit entity expansion depth, set max document size.',
      severity: 'high' },
    { pattern: /new\s+RegExp\s*\(\s*(?:req\.|request\.|body\.|input\.|params\.|query\.)\b/i,
      name: 'user-controlled regex pattern (ReDoS + CPU exhaustion)',
      fix: 'Never compile user input as a regex. Use literal string matching or a safe regex subset with a timeout.',
      severity: 'high' },
    { pattern: /\bJSON\.parse\s*\(\s*(?:req\.body|request\.body|rawBody|chunk)/i,
      name: 'JSON parsing of potentially unbounded request body',
      fix: 'Set body size limit: app.use(express.json({ limit: "1mb" })). Use a streaming parser for large payloads.',
      severity: 'medium' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const p of EXPENSIVE_OP_PATTERNS) {
      if (p.pattern.test(code)) {
        const LIMIT_RE = /\b(maxSize|max_size|limit|MAX_LENGTH|MAX_SIZE|content.?length\s*[<>]|\.length\s*[<>]|rateLimit|rate_limit|throttle|multer.*limits|bodyParser.*limit|express\.json.*limit|max_upload|upload.*size)\b/i;
        if (!LIMIT_RE.test(code)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: `CONTROL (resource limit — ${p.name})`,
            severity: p.severity,
            description: `${node.label}: ${p.name}. ` +
              `Without size/rate limits, an attacker can submit crafted input that consumes excessive ` +
              `CPU, memory, or storage — causing denial of service.`,
            fix: p.fix,
            via: 'structural',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-920', name: 'Improper Restriction of Power Consumption', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-921: Storage of Sensitive Data in a Mechanism Without Access Control
// ---------------------------------------------------------------------------

function verifyCWE921(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const INSECURE_STORAGE: Array<{ pattern: RegExp; name: string; fix: string; severity: 'high' | 'critical' }> = [
    { pattern: /\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['"`](?:token|jwt|auth|session|password|secret|api[_-]?key|credit[_-]?card|ssn|access[_-]?token|refresh[_-]?token)\b/i,
      name: 'sensitive data in localStorage/sessionStorage (XSS-accessible)',
      fix: 'Use httpOnly cookies for tokens. For other data, use encrypted storage or server-side sessions.',
      severity: 'high' },
    { pattern: /\bgetSharedPreferences\s*\([^)]+\)[\s\S]{0,200}?\.edit\s*\(\s*\)[\s\S]{0,200}?\.put(?:String|Int|Boolean)\s*\(\s*['"`](?:password|token|secret|api[_-]?key|pin|ssn|auth)\b/i,
      name: 'sensitive data in Android SharedPreferences (world-readable XML)',
      fix: 'Use EncryptedSharedPreferences from AndroidX Security library, or Android Keystore for secrets.',
      severity: 'high' },
    { pattern: /\bUserDefaults\s*\.standard\s*\.set\s*\([^,]+,\s*forKey\s*:\s*['"`](?:password|token|secret|apiKey|pin|ssn|auth)\b/i,
      name: 'sensitive data in iOS UserDefaults (unencrypted plist)',
      fix: 'Use Keychain Services for sensitive data. UserDefaults is stored in an unencrypted plist.',
      severity: 'high' },
    { pattern: /\b(?:writeFile|write|fwrite|fopen|open)\s*\(\s*['"`](?:\/tmp\/|C:\\\\temp\\\\|%TEMP%|os\.tmpdir)[\s\S]{0,100}?(?:password|secret|key|token|credential|private[_-]?key)\b/i,
      name: 'sensitive data written to /tmp (world-readable)',
      fix: 'Use mkstemp with 0600 permissions. Better: avoid writing secrets to disk entirely.',
      severity: 'high' },
    { pattern: /\b(?:ACL\s*[:=]\s*['"`]public-read|PublicRead|x-amz-acl.*public|BlockPublicAccess.*false)[\s\S]{0,200}?(?:password|secret|credential|private|pii|ssn|medical)\b/i,
      name: 'sensitive data in public S3 bucket',
      fix: 'Use private ACLs and enable S3 Block Public Access. Use server-side encryption (SSE-KMS).',
      severity: 'critical' },
    { pattern: /\b(?:chmod|fs\.chmod|os\.chmod)\s*\(\s*[^,]+,\s*(?:0?o?777|0?o?766)[\s\S]{0,100}?(?:password|secret|key|token|credential|private[_-]?key|\.pem|\.key)\b/i,
      name: 'sensitive file with world-readable permissions',
      fix: 'Use restrictive permissions: chmod 0600 (owner only). For key files, use 0400.',
      severity: 'high' },
    { pattern: /\b(?:res\.cookie|set[_-]?cookie|Set-Cookie|response\.set_cookie)\s*\(\s*['"`](?:token|session|auth|jwt|access_token)['"`]\s*,\s*[^{]*(?:\{(?![\s\S]*(?:httpOnly|HttpOnly|http_only)\s*[:=]\s*true))/i,
      name: 'auth cookie without httpOnly flag',
      fix: 'Set httpOnly: true and secure: true on all authentication cookies.',
      severity: 'high' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const p of INSECURE_STORAGE) {
      if (p.pattern.test(code)) {
        if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `CONTROL (access-controlled storage — ${p.name})`,
          severity: p.severity,
          description: `${node.label}: ${p.name}. ` +
            `Sensitive data stored without access controls can be read by other applications or attackers.`,
          fix: p.fix,
          via: 'structural',
        });
        break;
      }
    }
  }

  // Check STORAGE nodes for sensitive data without encryption indicators
  const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');
  const SENSITIVE_LABEL_RE = /\b(password|credential|secret|token|private[_-]?key|ssn|credit[_-]?card|health|medical|financial)\b/i;
  const ACCESS_CTRL_RE = /\b(encrypt|cipher|keychain|keystore|secure[_-]?storage|vault|kms|sealed|protected|private|access[_-]?control|acl|rbac|iam)\b/i;

  for (const store of storageNodes) {
    const label = store.label + ' ' + store.node_subtype;
    const code = stripComments(store.analysis_snapshot || store.code_snapshot);
    if (SENSITIVE_LABEL_RE.test(label) && !ACCESS_CTRL_RE.test(code) && !ACCESS_CTRL_RE.test(label)) {
      findings.push({
        source: nodeRef(store), sink: nodeRef(store),
        missing: 'CONTROL (access-controlled storage for sensitive data)',
        severity: 'high',
        description: `Storage node ${store.label} handles sensitive data but has no visible encryption or access control.`,
        fix: 'Use encrypted storage with access controls. Mobile: Keychain/Keystore. Server: Vault, AWS KMS.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-921', name: 'Storage of Sensitive Data in a Mechanism Without Access Control', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-922: Insecure Storage of Sensitive Information
// ---------------------------------------------------------------------------
function verifyCWE922(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const INSECURE_922: Array<{ pattern: RegExp; name: string; fix: string; severity: 'high' | 'critical' }> = [
    { pattern: /\b(?:localStorage|sessionStorage)\s*\.\s*(?:setItem|getItem)\s*\(\s*['"`](?:token|password|secret|api[_-]?key|credit|ssn|session|auth|jwt|private[_-]?key|refresh[_-]?token|access[_-]?token)\b/i,
      name: 'sensitive data in Web Storage (accessible to XSS)', fix: 'Use httpOnly secure cookies for auth tokens. For other secrets, use server-side sessions.', severity: 'high' },
    { pattern: /\b(?:indexedDB|openDatabase|webSQL|caches\.open)\b[\s\S]{0,300}?(?:password|token|secret|api[_-]?key|credential|ssn|private[_-]?key)/i,
      name: 'sensitive data in IndexedDB/WebSQL/Cache API (accessible to XSS)', fix: 'Do not store secrets in client-side databases. Use server-side sessions with httpOnly cookies.', severity: 'high' },
    { pattern: /\b(?:AsyncStorage|MMKV|realm)\b[\s\S]{0,200}?(?:password|token|secret|api[_-]?key|credential|pin|ssn|private[_-]?key)/i,
      name: 'sensitive data in React Native AsyncStorage/MMKV (unencrypted)', fix: 'Use react-native-keychain or expo-secure-store. AsyncStorage/MMKV are unencrypted.', severity: 'high' },
    { pattern: /\b(?:window\.__STATE__|window\.__INITIAL__|__NEXT_DATA__|__NUXT__)\b[\s\S]{0,300}?(?:password|secret|api[_-]?key|token|credential|private)/i,
      name: 'sensitive data serialized into SSR state (visible in page source)', fix: 'Never include secrets in server-rendered state. Fetch via authenticated API calls.', severity: 'critical' },
    { pattern: /\b(?:SharedPreferences|NSUserDefaults|UserDefaults\.standard)\b[\s\S]{0,200}?(?:password|token|secret|api[_-]?key|pin|private[_-]?key)/i,
      name: 'sensitive data in mobile defaults/preferences (unencrypted)', fix: 'Use Android Keystore/EncryptedSharedPreferences or iOS Keychain.', severity: 'high' },
    { pattern: /\b(?:cookie|document\.cookie)\s*=[\s\S]{0,100}?(?:password|secret|api[_-]?key|ssn|credit)[\s\S]{0,50}?(?!.*(?:httpOnly|HttpOnly|http_only|secure))/i,
      name: 'sensitive data in cookie without httpOnly/secure flags', fix: 'Use httpOnly and secure flags. Avoid putting raw secrets in cookies.', severity: 'high' },
  ];
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|example|fixture)\b/i.test(node.label || node.file)) continue;
    for (const p of INSECURE_922) {
      if (p.pattern.test(code)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: `CONTROL (secure storage — ${p.name})`, severity: p.severity,
          description: `${node.label}: ${p.name}. Storing sensitive information in insecure mechanisms exposes it to unauthorized access, XSS, or device compromise.`, fix: p.fix,
          via: 'structural' });
        break;
      }
    }
  }
  const storNodes922 = map.nodes.filter(n => n.node_type === 'STORAGE');
  const SENS922 = /\b(password|credential|secret|token|private[_-]?key|ssn|credit[_-]?card|health|medical|financial|pii)\b/i;
  const ENC922 = /\b(encrypt|cipher|aes|rsa|keychain|keystore|vault|kms|sealed|secure[_-]?storage|dpapi|crypto\.subtle)\b/i;
  for (const store of storNodes922) {
    const combined = store.label + ' ' + store.node_subtype + ' ' + (store.analysis_snapshot || store.code_snapshot);
    if (SENS922.test(combined) && !ENC922.test(stripComments(store.analysis_snapshot || store.code_snapshot))) {
      const sibs = map.nodes.filter(n => n.id !== store.id && sharesFunctionScope(map, store.id, n.id));
      if (!sibs.some(n => ENC922.test(stripComments(n.analysis_snapshot || n.code_snapshot)))) {
        findings.push({ source: nodeRef(store), sink: nodeRef(store), missing: 'CONTROL (encrypted/access-controlled storage)', severity: 'high',
          description: `Storage node ${store.label} handles sensitive data without encryption or access controls.`,
          fix: 'Encrypt sensitive data before storing. Use Keychain (iOS), Keystore (Android), DPAPI (Windows), or Vault/KMS.',
          via: 'scope_taint' });
      }
    }
  }
  return { cwe: 'CWE-922', name: 'Insecure Storage of Sensitive Information', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-924: Improper Enforcement of Message Integrity During Transmission
// ---------------------------------------------------------------------------
function verifyCWE924(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const MSGSEND924 = /\b(postMessage|send|emit|publish|dispatch|broadcast|push|enqueue|produce)\s*\(/i;
  const MSGRECV924 = /\b(addEventListener\s*\(\s*['"]message|onmessage|on\s*\(\s*['"](?:message|data|event)|subscribe|consume|dequeue)\b/i;
  const INTEG924 = /\b(hmac|signature|sign|digest|hash|checksum|mac|integrity|verify[_-]?signature|crypto\.sign|crypto\.verify|timingSafeEqual|createHmac|createSign)\b/i;
  const TLS924 = /\bhttps\b|\btls\b|\bssl\b/i;
  const msgN924 = map.nodes.filter(n =>
    n.node_subtype.includes('websocket') || n.node_subtype.includes('queue') || n.node_subtype.includes('ipc') ||
    n.node_subtype.includes('message') || n.node_subtype.includes('grpc') || n.node_subtype.includes('mqtt') ||
    n.node_subtype.includes('amqp') || n.node_subtype.includes('kafka') || n.node_subtype.includes('redis_pub') || n.node_subtype.includes('nats'));
  for (const node of msgN924) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!(MSGSEND924.test(code) || MSGRECV924.test(code))) continue;
    if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;
    const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
    const hasInt = INTEG924.test(code) || sibs.some(n => INTEG924.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
    if (!hasInt) {
      const tlsOnly = TLS924.test(code);
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (message integrity — HMAC/signature)', severity: 'high',
        description: `Message channel at ${node.label} lacks integrity verification. ` +
          (tlsOnly ? `TLS protects in transit but not against compromised endpoints, replays, or queue tampering.`
                   : `Without integrity checks, messages can be tampered with in transit or at rest.`),
        fix: 'Sign messages with HMAC-SHA256 or Ed25519. Include nonce/timestamp for replay prevention. Verify before processing.',
        via: 'scope_taint' });
    }
  }
  return { cwe: 'CWE-924', name: 'Improper Enforcement of Message Integrity During Transmission', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const ERROR_HANDLING_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-207': verifyCWE207,
  'CWE-208': verifyCWE208,
  'CWE-243': verifyCWE243,
  'CWE-244': verifyCWE244,
  'CWE-245': verifyCWE245,
  'CWE-246': verifyCWE246,
  'CWE-248': verifyCWE248,
  'CWE-252': verifyCWE252,
  'CWE-253': verifyCWE253,
  'CWE-341': verifyCWE341,
  'CWE-342': verifyCWE342,
  'CWE-343': verifyCWE343,
  'CWE-344': verifyCWE344,
  'CWE-390': verifyCWE390,
  'CWE-391': verifyCWE391,
  'CWE-392': verifyCWE392,
  'CWE-393': verifyCWE393,
  'CWE-394': verifyCWE394,
  'CWE-395': verifyCWE395,
  'CWE-396': verifyCWE396,
  'CWE-397': verifyCWE397,
  'CWE-546': verifyCWE546,
  'CWE-547': verifyCWE547,
  'CWE-558': verifyCWE558,
  'CWE-560': verifyCWE560,
  'CWE-564': verifyCWE564,
  'CWE-567': verifyCWE567,
  'CWE-568': verifyCWE568,
  'CWE-573': verifyCWE573,
  'CWE-606': verifyCWE606,
  'CWE-613': verifyCWE613,
  'CWE-616': verifyCWE616,
  'CWE-617': verifyCWE617,
  'CWE-621': verifyCWE621,
  'CWE-622': verifyCWE622,
  'CWE-624': verifyCWE624,
  'CWE-626': verifyCWE626,
  'CWE-627': verifyCWE627,
  'CWE-636': verifyCWE636,
  'CWE-920': verifyCWE920,
  'CWE-921': verifyCWE921,
  'CWE-922': verifyCWE922,
  'CWE-924': verifyCWE924,
};
