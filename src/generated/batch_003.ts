/**
 * DST Generated Verifiers — Batch 003
 * Pattern shape: TRANSFORM→STORAGE without CONTROL
 * 37 CWEs: memory safety, file permissions, concurrency, info exposure,
 * resource management, data structure integrity.
 *
 * Key difference from batch 001: source is TRANSFORM (internal operations)
 * not INGRESS (user input). These are internal logic errors — calculations,
 * conversions, or function calls that corrupt storage without validation.
 *
 * Sub-groups:
 *   A. Memory/buffer safety  (14 CWEs) — factory-driven
 *   B. File/permission        (6 CWEs) — factory-driven
 *   C. Concurrency/sync       (4 CWEs) — factory-driven
 *   D. Information exposure    (3 CWEs) — per-CWE
 *   E. Resource management     (7 CWEs) — factory-driven
 *   F. Data structure          (2 CWEs) — per-CWE
 *   G. Individual              (1 CWE)  — per-CWE
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, createGenericVerifier,
  detectLanguage,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Source filter — TRANSFORM nodes (internal operations producing data)
// ---------------------------------------------------------------------------

function transformSourceNodes(map: NeuralMap): NeuralMapNode[] {
  return nodesOfType(map, 'TRANSFORM');
}

// ---------------------------------------------------------------------------
// Sink filters
// ---------------------------------------------------------------------------

function bufferStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('buffer') || n.node_subtype.includes('array') ||
     n.node_subtype.includes('memory') || n.node_subtype.includes('heap') ||
     n.node_subtype.includes('stack') || n.attack_surface.includes('buffer_write') ||
     n.attack_surface.includes('buffer_read') || n.attack_surface.includes('array_access') ||
     n.code_snapshot.match(
       /\b(Buffer|memcpy|memmove|strcpy|strncpy|sprintf|gets|malloc|calloc|realloc|new\s+\w+\[|read|write|slice|subarray)\b/i
     ) !== null)
  );
}

// Domain subtypes that must NOT match as file storage nodes (cross-domain exclusion).
const NON_FILE_DOMAINS_B3 = /^(xpath_query|ldap_query|sql_query|nosql_query|graphql_query|mongo_query|redis_query|query)$/;

function fileStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n => {
    if (NON_FILE_DOMAINS_B3.test(n.node_subtype)) return false;
    return (
      n.node_type === 'STORAGE' &&
      (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
       n.node_subtype.includes('temp') || n.node_subtype.includes('directory') ||
       n.attack_surface.includes('file_access') || n.attack_surface.includes('file_write') ||
       n.code_snapshot.match(
         /\b(writeFile|createWriteStream|open|mktemp|tmpfile|tmpnam|tempnam|mkstemp|chmod|chown|mkdir)\b/i
       ) !== null)
    );
  });
}

function sharedStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('shared') || n.node_subtype.includes('global') ||
     n.node_subtype.includes('concurrent') || n.attack_surface.includes('shared') ||
     n.attack_surface.includes('concurrent') ||
     n.code_snapshot.match(
       /\b(global|shared|concurrent|atomic|volatile|static\s+\w+\s*=)\b/i
     ) !== null)
  );
}

function resourceStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('resource') || n.node_subtype.includes('handle') ||
     n.node_subtype.includes('descriptor') || n.node_subtype.includes('connection') ||
     n.node_subtype.includes('cursor') || n.node_subtype.includes('stream') ||
     n.attack_surface.includes('resource') ||
     n.code_snapshot.match(
       /\b(open|connect|createConnection|cursor|socket|pipe|fd|handle|acquire|alloc)\b/i
     ) !== null)
  );
}

// ---------------------------------------------------------------------------
// Safe pattern constants
// ---------------------------------------------------------------------------

const BOUNDS_SAFE = /\blength\b.*[<>]=?|\bsizeof\b|\bbounds\b.*check|\bBuffer\.alloc\b(?!Unsafe)|\bMath\.min\b|\bclamp\b|\bvalidate.*index|\bcheck.*range|\bArray\.isArray\b|\b>=?\s*0\b.*[<>]=?/i;
const OFFBYONE_SAFE = /\b<\s*\blength\b|\b<=\s*\blength\s*-\s*1\b|\bfence.?post\b/i;
const SIGNED_SAFE = /\b>>>\s*0\b|\bUint\b|\bunsigned\b|\bsign.*check\b|\bMath\.abs\b/i;
const MULTIBYTE_SAFE = /\bBuffer\.byteLength\b|\bTextEncoder\b|\bencoding\b|\butf-?8\b.*\blength\b|\bcharCodeAt\b/i;
const EXPIRED_PTR_SAFE = /\bnull.*after\b|\bweakRef\b|\bweakMap\b|\bdelete.*after\b|\binvalidate\b/i;
const TEMP_FILE_SAFE = /\bmkstemp\b|\btmpfile\b|\bO_EXCL\b|\bo_excl\b|\b0[67]00\b|\b0o[67]00\b|\bfs\.mkdtemp\b|\bos\.tmpfile\b|\btempfile\.NamedTemporaryFile\b/i;
const PERMISSION_SAFE = /\bchmod\b|\bchown\b|\bumask\b|\b0[67]00\b|\b0o[67]00\b|\bpermission.*preserv\b|\bcopyPermission\b|\bstat\b.*\bmode\b/i;
const SEARCH_PATH_SAFE = /\babsolute.*path\b|\bfull.*path\b|\bpath\.resolve\b|\bverify.*integrity\b|\bhash.*check\b|\bsignature.*verify\b/i;
const SYNC_SAFE = /\bmutex\b|\block\b|\bsynchronized\b|\bsemaphore\b|\batomic\b|\bcriticalSection\b|\bflock\b|\bReentrantLock\b|\bMonitor\b/i;
const CACHE_SAFE = /\bno-?cache\b|\bno-?store\b|\bprivate\b|\bCache-Control\b|\bencrypt\s*\(|\bredact\s*\(|\bclear.*cache\b/i;
const ENV_SECRET_SAFE = /\bencrypt\s*\(|\bvault\b|\bsecretManager\b|\bKMS\b|\bssm\b|\bsecure.*store\b|\bhash\s*\(|\bcreateHash\b/i;
const RESOURCE_RELEASE_SAFE = /\bclose\b|\brelease\b|\bdispose\b|\bfinally\b|\busing\b|\bwith\b|\bautoClose\b|\btry.*finally\b|\bdefer\b/i;
const DANGEROUS_FN_SAFE = /\bstrncpy\b|\bsnprintf\b|\bstrlcpy\b|\bstrlcat\b|\bsafe.*version\b|\b_s\b\s*\(/i;

// ---------------------------------------------------------------------------
// Factory: TRANSFORM→STORAGE verifier with configurable filters
// ---------------------------------------------------------------------------

function createTransformStorageVerifier(
  cweId: string, cweName: string, severity: Severity,
  sinkFilter: (map: NeuralMap) => NeuralMapNode[],
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
  extraSafe?: RegExp,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const sources = transformSourceNodes(map);
    const sinks = sinkFilter(map);

    for (const src of sources) {
      for (const sink of sinks) {
        if (src.id === sink.id) continue; // skip self-edges
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          const isSafe = safePattern.test(sink.code_snapshot) ||
            (extraSafe ? extraSafe.test(sink.code_snapshot) : false);

          if (!isSafe) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `Internal operation at ${src.label} affects ${sink.label} without proper controls. ` +
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
// A. MEMORY/BUFFER SAFETY (14 CWEs)
// ===========================================================================

export const verifyCWE118 = createTransformStorageVerifier(
  'CWE-118', 'Improper Access of Indexable Resource (Range Error)', 'high',
  bufferStorageNodes, BOUNDS_SAFE,
  'CONTROL (bounds checking / index validation)',
  'Validate all array indices and buffer offsets against valid ranges before access.',
);

export const verifyCWE124 = createTransformStorageVerifier(
  'CWE-124', 'Buffer Underwrite (Buffer Underflow)', 'critical',
  bufferStorageNodes, BOUNDS_SAFE,
  'CONTROL (lower bounds check — index >= 0)',
  'Validate that write indices are not negative. Check lower bounds before buffer writes.',
  /\b>=?\s*0\b/,
);

export const verifyCWE125 = createTransformStorageVerifier(
  'CWE-125', 'Out-of-bounds Read', 'high',
  bufferStorageNodes, BOUNDS_SAFE,
  'CONTROL (bounds checking for read operations)',
  'Validate read offsets and lengths against buffer size before reading. ' +
    'Check both lower and upper bounds.',
);

export const verifyCWE126 = createTransformStorageVerifier(
  'CWE-126', 'Buffer Over-read', 'high',
  bufferStorageNodes, BOUNDS_SAFE,
  'CONTROL (upper bounds check for reads)',
  'Ensure read operations do not exceed buffer size. Check offset + length <= buffer.length.',
);

export const verifyCWE127 = createTransformStorageVerifier(
  'CWE-127', 'Buffer Under-read', 'medium',
  bufferStorageNodes, BOUNDS_SAFE,
  'CONTROL (lower bounds check for reads — index >= 0)',
  'Validate that read indices are not negative before buffer access.',
  /\b>=?\s*0\b/,
);

export const verifyCWE135 = createTransformStorageVerifier(
  'CWE-135', 'Incorrect Calculation of Multi-Byte String Length', 'medium',
  bufferStorageNodes, MULTIBYTE_SAFE,
  'CONTROL (multi-byte aware length calculation)',
  'Use Buffer.byteLength() or TextEncoder for multi-byte strings. ' +
    'Do not use string.length for byte-level buffer sizing with UTF-8/UTF-16 data.',
);

export const verifyCWE193 = createTransformStorageVerifier(
  'CWE-193', 'Off-by-one Error', 'medium',
  bufferStorageNodes, OFFBYONE_SAFE,
  'CONTROL (correct boundary calculation — < length, not <= length)',
  'Use < length (not <= length) for zero-indexed array bounds. ' +
    'Account for null terminators in string buffers. Review fence-post conditions.',
);

export const verifyCWE195 = createTransformStorageVerifier(
  'CWE-195', 'Signed to Unsigned Conversion Error', 'medium',
  bufferStorageNodes, SIGNED_SAFE,
  'CONTROL (sign validation before unsigned conversion)',
  'Check that values are non-negative before using as unsigned. Use >>> 0 for explicit conversion. ' +
    'Validate sign before using as array index or buffer size.',
);

export const verifyCWE785 = createTransformStorageVerifier(
  'CWE-785', 'Use of Path Manipulation Function without Maximum-sized Buffer', 'high',
  bufferStorageNodes,
  /\bPATH_MAX\b|\bMAX_PATH\b|\bBuffer\.alloc\s*\(\s*\d{3,}\b|\bsafe.*buffer\b/i,
  'CONTROL (maximum-sized buffer for path operations)',
  'Allocate PATH_MAX-sized buffers for path manipulation functions. ' +
    'Never use fixed small buffers with realpath(), getcwd(), or similar.',
);

export const verifyCWE786 = createTransformStorageVerifier(
  'CWE-786', 'Access of Memory Location Before Start of Buffer', 'critical',
  bufferStorageNodes, BOUNDS_SAFE,
  'CONTROL (lower bounds validation — no negative offsets)',
  'Validate that all buffer offsets are >= 0 before access. ' +
    'Check pointer arithmetic results against buffer start address.',
  /\b>=?\s*0\b|\blowerBound\b/,
);

export const verifyCWE788 = createTransformStorageVerifier(
  'CWE-788', 'Access of Memory Location After End of Buffer', 'critical',
  bufferStorageNodes, BOUNDS_SAFE,
  'CONTROL (upper bounds validation — offset < size)',
  'Validate that offset + length <= buffer.length before access. ' +
    'Check pointer arithmetic results against buffer end address.',
);

export const verifyCWE805 = createTransformStorageVerifier(
  'CWE-805', 'Buffer Access with Incorrect Length Value', 'high',
  bufferStorageNodes, BOUNDS_SAFE,
  'CONTROL (length parameter validation)',
  'Validate length parameters against actual buffer size. ' +
    'Use sizeof/length properties rather than hardcoded values.',
);

export const verifyCWE825 = createTransformStorageVerifier(
  'CWE-825', 'Expired Pointer Dereference', 'critical',
  bufferStorageNodes, EXPIRED_PTR_SAFE,
  'CONTROL (pointer/reference validity check after potential invalidation)',
  'Set pointers to null after freeing. Check validity before dereference. ' +
    'Use WeakRef/WeakMap for references that may be garbage collected.',
);

export const verifyCWE826 = createTransformStorageVerifier(
  'CWE-826', 'Premature Release of Resource During Expected Lifetime', 'high',
  resourceStorageNodes, RESOURCE_RELEASE_SAFE,
  'CONTROL (lifetime management — no early release while references exist)',
  'Do not release resources while they are still referenced. Use reference counting ' +
    'or RAII patterns. Ensure all consumers complete before releasing shared resources.',
);

// ===========================================================================
// B. FILE/PERMISSION (6 CWEs)
// ===========================================================================

export const verifyCWE281 = createTransformStorageVerifier(
  'CWE-281', 'Improper Preservation of Permissions', 'medium',
  fileStorageNodes, PERMISSION_SAFE,
  'CONTROL (permission preservation during copy/move/restore)',
  'Explicitly preserve file permissions when copying or restoring. ' +
    'Use stat() to read source permissions and chmod() to apply them to the destination.',
);

/**
 * CWE-377: Insecure Temporary File
 * Pattern: TRANSFORM(temp path generation) → STORAGE(file write) without secure creation
 *
 * UPGRADED from factory: the generic version checked for TEMP_FILE_SAFE on the sink.
 * This version specifically detects:
 *   (a) Dangerous temp functions: tmpnam(), mktemp(), tempnam() — predictable names
 *   (b) Predictable patterns: "/tmp/" + Date.now(), "/tmp/prefix_" + pid
 *   (c) Missing O_EXCL: open() without O_EXCL creates TOCTOU race
 * And recognizes safe alternatives:
 *   (a) mkstemp() / mkdtemp() — atomic creation with unpredictable names
 *   (b) fs.mkdtemp() — Node.js secure temp directory
 *   (c) O_EXCL flag — prevents symlink TOCTOU
 *   (d) Python tempfile.NamedTemporaryFile / tempfile.mkstemp
 *
 * The TOCTOU race: attacker creates symlink at predicted temp path between
 * name generation and file creation, causing the app to write to arbitrary files.
 */
export function verifyCWE377(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const sources = nodesOfType(map, 'TRANSFORM');
  const fileSinks = fileStorageNodes(map);

  for (const src of sources) {
    for (const sink of fileSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check source for dangerous temp name generation
        const hasDangerousTempGen = src.code_snapshot.match(
          /\btmpnam\b|\bmktemp\b(?!p)|\btempnam\b|\b\/tmp\/\b.*\+|\bos\.tmpnam\b|\btmpName\b/i
        ) !== null;

        // Check source for predictable patterns (Date.now, pid, sequential counter)
        const hasPredictableName = src.code_snapshot.match(
          /\/tmp\/.*Date\.now|\/tmp\/.*getpid|\/tmp\/.*process\.pid|\/tmp\/.*Math\.random|\/tmp\/.*counter/i
        ) !== null;

        // Check if source uses secure temp creation
        const hasSecureCreation = src.code_snapshot.match(
          /\bmkstemp\b|\bmkdtemp\b|\bfs\.mkdtemp\b|\btempfile\.NamedTemporary|\btempfile\.mkstemp|\bos\.tmpfile\b/i
        ) !== null;

        // Check if sink uses O_EXCL or equivalent atomic creation
        const hasAtomicCreate = sink.code_snapshot.match(
          /\bO_EXCL\b|\bo_excl\b|\bwx\b|\b0o[67]00\b|\b0[67]00\b|\bfs\.mkdtemp\b/i
        ) !== null;

        // Flag if dangerous creation and no mitigation
        if ((hasDangerousTempGen || hasPredictableName) && !hasSecureCreation && !hasAtomicCreate) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (secure temp file creation — use mkstemp/fs.mkdtemp or O_EXCL flag)',
            severity: 'medium',
            description: `Temp file at ${sink.label} uses predictable name from ${src.label}. ` +
              `Between name generation and file creation, an attacker can create a symlink at the predicted path, ` +
              `causing the application to write to an arbitrary file (TOCTOU race).`,
            fix: 'Use mkstemp() (C) or fs.mkdtemp() (Node.js) which atomically create the file with an unpredictable name. ' +
              'If you must use open(): pass O_CREAT | O_EXCL to fail if the file already exists. ' +
              'In Python: use tempfile.NamedTemporaryFile() or tempfile.mkstemp(). ' +
              'NEVER use tmpnam(), mktemp(), or Date.now() for temp file paths.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-377', name: 'Insecure Temporary File', holds: findings.length === 0, findings };
}

export const verifyCWE378 = createTransformStorageVerifier(
  'CWE-378', 'Creation of Temporary File With Insecure Permissions', 'medium',
  fileStorageNodes, TEMP_FILE_SAFE,
  'CONTROL (restrictive permissions on temp files — 0600)',
  'Set temp file permissions to 0600 (owner read/write only). ' +
    'Use umask or explicit chmod after creation.',
);

export const verifyCWE379 = createTransformStorageVerifier(
  'CWE-379', 'Creation of Temporary File in Directory with Insecure Permissions', 'medium',
  fileStorageNodes, TEMP_FILE_SAFE,
  'CONTROL (secure temp directory — sticky bit, restricted permissions)',
  'Create temp files only in directories with the sticky bit set (/tmp on Linux). ' +
    'Verify directory permissions before creating temp files.',
);

export const verifyCWE427 = createTransformStorageVerifier(
  'CWE-427', 'Uncontrolled Search Path Element', 'high',
  fileStorageNodes, SEARCH_PATH_SAFE,
  'CONTROL (absolute path / search path integrity)',
  'Use absolute paths for loading executables and libraries. ' +
    'Do not rely on PATH or LD_LIBRARY_PATH for security-sensitive operations. ' +
    'Verify integrity of loaded resources.',
);

export const verifyCWE428 = createTransformStorageVerifier(
  'CWE-428', 'Unquoted Search Path or Element', 'high',
  fileStorageNodes, SEARCH_PATH_SAFE,
  'CONTROL (quoted paths / proper escaping)',
  'Always quote file paths in service configurations and shell commands. ' +
    'Unquoted paths with spaces can be hijacked (e.g., C:\\Program Files → C:\\Program.exe).',
  /\bquote\b|\bescapeShell\b|\b["']\b.*\bpath\b/i,
);

// ===========================================================================
// C. CONCURRENCY/SYNCHRONIZATION (4 CWEs)
// ===========================================================================

export const verifyCWE366 = createTransformStorageVerifier(
  'CWE-366', 'Race Condition within a Thread', 'medium',
  sharedStorageNodes, SYNC_SAFE,
  'CONTROL (synchronization primitives — mutex/lock/atomic)',
  'Use mutexes, locks, or atomic operations for shared data access. ' +
    'Implement proper lock ordering to prevent deadlocks.',
);

export const verifyCWE662 = createTransformStorageVerifier(
  'CWE-662', 'Improper Synchronization', 'medium',
  sharedStorageNodes, SYNC_SAFE,
  'CONTROL (correct synchronization — proper lock/unlock pairing)',
  'Ensure locks are properly acquired and released. Use try/finally for lock release. ' +
    'Avoid lock-free algorithms unless you understand memory ordering.',
);

export const verifyCWE667 = createTransformStorageVerifier(
  'CWE-667', 'Improper Locking', 'medium',
  sharedStorageNodes, SYNC_SAFE,
  'CONTROL (correct locking — proper scope, granularity, ordering)',
  'Lock at the correct granularity. Release locks in finally blocks. ' +
    'Use consistent lock ordering to prevent deadlocks.',
);

export const verifyCWE820 = createTransformStorageVerifier(
  'CWE-820', 'Missing Synchronization', 'medium',
  sharedStorageNodes, SYNC_SAFE,
  'CONTROL (synchronization for concurrent access)',
  'Add synchronization when multiple threads/processes access shared state. ' +
    'Use atomic operations for simple counters. Use locks for compound operations.',
);

// ===========================================================================
// D. INFORMATION EXPOSURE (3 CWEs)
// ===========================================================================

export const verifyCWE524 = createTransformStorageVerifier(
  'CWE-524', 'Use of Cache Containing Sensitive Information', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('cache') || n.attack_surface.includes('cache') ||
     n.code_snapshot.match(/\b(cache|Cache|redis|memcached|localStorage|sessionStorage|set\s*\(\s*['"])\b/i) !== null)
  ),
  CACHE_SAFE,
  'CONTROL (cache access restriction / sensitive data exclusion)',
  'Set Cache-Control: no-store for sensitive responses. Do not cache credentials or PII. ' +
    'Encrypt cached sensitive data. Clear caches on logout.',
);

export const verifyCWE526 = createTransformStorageVerifier(
  'CWE-526', 'Cleartext Storage of Sensitive Information in an Environment Variable', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('env') || n.node_subtype.includes('environment') ||
     n.code_snapshot.match(/\b(process\.env|os\.environ|System\.getenv|putenv|setenv)\b/i) !== null)
  ),
  ENV_SECRET_SAFE,
  'CONTROL (secrets management — vault/KMS instead of env vars)',
  'Use a secrets manager (Vault, AWS KMS, GCP Secret Manager) instead of environment variables. ' +
    'If env vars are necessary, encrypt values and restrict process access.',
);

export const verifyCWE528 = createTransformStorageVerifier(
  'CWE-528', 'Exposure of Core Dump File to an Unauthorized Control Sphere', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('dump') || n.node_subtype.includes('core') ||
     n.code_snapshot.match(/\b(core\.dump|crash.*dump|minidump|ulimit.*-c|RLIMIT_CORE)\b/i) !== null)
  ),
  /\bdisable.*core\b|\bulimit.*0\b|\bRLIMIT_CORE.*0\b|\bno.*dump\b|\brestrict.*dump\b/i,
  'CONTROL (core dump restriction / secure dump location)',
  'Disable core dumps in production (ulimit -c 0). If needed, write dumps to a secure, ' +
    'access-restricted directory. Strip sensitive data before dumping.',
);

// ===========================================================================
// E. RESOURCE MANAGEMENT (7 CWEs)
// ===========================================================================

export const verifyCWE619 = createTransformStorageVerifier(
  'CWE-619', "Dangling Database Cursor ('Cursor Injection')", 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('cursor') ||
     n.code_snapshot.match(/\b(cursor|Cursor|createCursor|ResultSet|openCursor|newCursor)\b/) !== null)
  ),
  RESOURCE_RELEASE_SAFE,
  'CONTROL (cursor cleanup — close in finally/using block)',
  'Always close database cursors in finally blocks. Use connection pooling with auto-cleanup. ' +
    'Implement cursor timeouts for long-running operations.',
);

export const verifyCWE676 = createTransformStorageVerifier(
  'CWE-676', 'Use of Potentially Dangerous Function', 'medium',
  bufferStorageNodes, DANGEROUS_FN_SAFE,
  'CONTROL (safe function alternative — strncpy, snprintf, strlcpy)',
  'Replace dangerous functions: strcpy→strncpy/strlcpy, sprintf→snprintf, gets→fgets. ' +
    'Use the _s suffix variants (strcpy_s, sprintf_s) when available.',
);

export const verifyCWE694 = createTransformStorageVerifier(
  'CWE-694', 'Use of Multiple Resources with Duplicate Identifier', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('registry') || n.node_subtype.includes('map') ||
     n.node_subtype.includes('namespace') ||
     n.code_snapshot.match(/\b(register|Map|Set|namespace|define|declare)\b/i) !== null)
  ),
  /\bunique\b|\bdedup\b|\bhas\b.*\bkey\b|\bexists\b|\bduplicate.*check\b/i,
  'CONTROL (unique identifier enforcement / duplicate detection)',
  'Check for duplicate identifiers before registration. Use unique constraints. ' +
    'Implement namespace isolation for resources with potentially conflicting names.',
);

export const verifyCWE771 = createTransformStorageVerifier(
  'CWE-771', 'Missing Reference to Active Allocated Resource', 'high',
  resourceStorageNodes, RESOURCE_RELEASE_SAFE,
  'CONTROL (resource tracking — maintain reference until released)',
  'Always store a reference to allocated resources until they are properly released. ' +
    'Use RAII, try-with-resources, or using blocks to ensure cleanup.',
);

export const verifyCWE772 = createTransformStorageVerifier(
  'CWE-772', 'Missing Release of Resource after Effective Lifetime', 'high',
  resourceStorageNodes, RESOURCE_RELEASE_SAFE,
  'CONTROL (resource release — close/dispose/free after use)',
  'Release all resources in finally blocks. Use using/with statements for automatic cleanup. ' +
    'Implement dispose patterns. Monitor for resource leaks in production.',
);

export const verifyCWE773 = createTransformStorageVerifier(
  'CWE-773', 'Missing Reference to Active File Descriptor or Handle', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('descriptor') || n.node_subtype.includes('handle') ||
     n.node_subtype.includes('fd') ||
     n.code_snapshot.match(/\b(open|fd|handle|descriptor|socket|pipe)\b/i) !== null)
  ),
  RESOURCE_RELEASE_SAFE,
  'CONTROL (file descriptor tracking — maintain reference until closed)',
  'Store file descriptor references and close them in finally blocks. ' +
    'Use try-with-resources or RAII for automatic cleanup.',
);

export const verifyCWE775 = createTransformStorageVerifier(
  'CWE-775', 'Missing Release of File Descriptor or Handle after Effective Lifetime', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('descriptor') || n.node_subtype.includes('handle') ||
     n.node_subtype.includes('fd') ||
     n.code_snapshot.match(/\b(open|fd|handle|descriptor|socket|pipe)\b/i) !== null)
  ),
  RESOURCE_RELEASE_SAFE,
  'CONTROL (file descriptor release — close after use)',
  'Close file descriptors and handles in finally blocks. ' +
    'Monitor open file descriptor counts. Set ulimits as defense in depth.',
);

// ===========================================================================
// F. DATA STRUCTURE (2 CWEs)
// ===========================================================================

/** CWE-462: Duplicate Key in Associative List (Alist) */
export const verifyCWE462 = createTransformStorageVerifier(
  'CWE-462', 'Duplicate Key in Associative List (Alist)', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('map') || n.node_subtype.includes('dict') ||
     n.node_subtype.includes('associative') || n.node_subtype.includes('hash') ||
     n.code_snapshot.match(/\b(Map|Object|dict|HashMap|set\s*\(|put\s*\()\b/i) !== null)
  ),
  /\bhas\b|\bexists\b|\bduplicate.*check\b|\bunique\b|\bdedup\b/i,
  'CONTROL (duplicate key detection before insertion)',
  'Check for existing keys before insertion into associative structures. ' +
    'Use Map.has() or Object.hasOwn() to detect duplicates.',
);

/** CWE-463: Deletion of Data Structure Sentinel */
export const verifyCWE463 = createTransformStorageVerifier(
  'CWE-463', 'Deletion of Data Structure Sentinel', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('list') || n.node_subtype.includes('linked') ||
     n.node_subtype.includes('tree') || n.node_subtype.includes('sentinel') ||
     n.code_snapshot.match(/\b(head|tail|sentinel|root|null.*terminat|end.*marker)\b/i) !== null)
  ),
  /\bsentinel\b.*\bprotect\b|\bread.*only\b|\bimmutable\b|\b\.freeze\s*\(|\bguard\s*\(/i,
  'CONTROL (sentinel protection — prevent deletion of structural markers)',
  'Protect sentinel nodes from deletion. Mark sentinels as immutable or read-only. ' +
    'Add guard checks before deleting nodes in linked data structures.',
);

// ===========================================================================
// G. INDIVIDUAL (1 CWE)
// ===========================================================================

/** CWE-588: Attempt to Access Child of a Non-structure Pointer — C/C++ only */
export const verifyCWE588 = (map: NeuralMap): VerificationResult => {
  const lang = detectLanguage(map);
  // This is a C/C++ pointer safety issue — not relevant to Java/JS/Python etc.
  if (lang && !['c', 'cpp', 'c++'].some(l => lang.includes(l))) {
    return { cwe: 'CWE-588', name: 'Attempt to Access Child of a Non-structure Pointer', holds: true, findings: [] };
  }
  return createTransformStorageVerifier(
    'CWE-588', 'Attempt to Access Child of a Non-structure Pointer', 'high',
    bufferStorageNodes,
    /\btypeof\b|\binstanceof\b|\bnull.*check\b|\bpointer.*valid\b|\bstruct.*check\b/i,
    'CONTROL (type/structure validation before member access)',
    'Validate that pointers reference valid structures before accessing members. ' +
      'Use typeof/instanceof checks. Never dereference void* without casting to correct type.',
  )(map);
};

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_003_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Memory/Buffer (14)
  'CWE-118': verifyCWE118,
  'CWE-124': verifyCWE124,
  'CWE-125': verifyCWE125,
  'CWE-126': verifyCWE126,
  'CWE-127': verifyCWE127,
  'CWE-135': verifyCWE135,
  'CWE-193': verifyCWE193,
  'CWE-195': verifyCWE195,
  'CWE-785': verifyCWE785,
  'CWE-786': verifyCWE786,
  'CWE-788': verifyCWE788,
  'CWE-805': verifyCWE805,
  'CWE-825': verifyCWE825,
  'CWE-826': verifyCWE826,
  // File/Permission (6)
  'CWE-281': verifyCWE281,
  'CWE-377': verifyCWE377,
  'CWE-378': verifyCWE378,
  'CWE-379': verifyCWE379,
  'CWE-427': verifyCWE427,
  'CWE-428': verifyCWE428,
  // Concurrency (4)
  'CWE-366': verifyCWE366,
  'CWE-662': verifyCWE662,
  'CWE-667': verifyCWE667,
  'CWE-820': verifyCWE820,
  // Information Exposure (3)
  'CWE-524': verifyCWE524,
  'CWE-526': verifyCWE526,
  'CWE-528': verifyCWE528,
  // Resource Management (7)
  'CWE-619': verifyCWE619,
  'CWE-676': verifyCWE676,
  'CWE-694': verifyCWE694,
  'CWE-771': verifyCWE771,
  'CWE-772': verifyCWE772,
  'CWE-773': verifyCWE773,
  'CWE-775': verifyCWE775,
  // Data Structure (2)
  'CWE-462': verifyCWE462,
  'CWE-463': verifyCWE463,
  // Individual (1)
  'CWE-588': verifyCWE588,
};
