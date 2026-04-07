/**
 * DST Generated Verifiers — Batch 001
 * Pattern shape: INGRESS→STORAGE without CONTROL
 * 60 CWEs: path traversal, buffer safety, integer handling,
 * trust boundaries, resource management, access control.
 *
 * Sub-groups:
 *   A. Path/file manipulation (32 CWEs) — factory-driven
 *   B. Buffer/memory safety   (9 CWEs)  — factory-driven
 *   C. Integer handling        (6 CWEs)  — factory-driven
 *   D. Trust boundary          (5 CWEs)  — factory-driven
 *   E. Resource allocation     (2 CWEs)  — factory-driven
 *   F. Individual patterns     (6 CWEs)  — unique verifiers
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, createGenericVerifier,
  sinkHasSafeRange,
  type VerificationResult, type Finding, type NodeRef, type Severity,
} from './_helpers';
export type { VerificationResult, Finding, NodeRef };

// ---------------------------------------------------------------------------
// Sink filters — each returns nodes matching a specific vulnerability class
// ---------------------------------------------------------------------------

// Domain subtypes that must NOT match as file storage nodes.
// "xpath_query" contains the substring "path" which causes cross-domain misfires
// where path traversal CWEs fire on XPath code.  Similarly "ldap_query", "sql_query"
// etc. are query-domain sinks, not file operations.
const NON_FILE_DOMAINS = /^(xpath_query|ldap_query|sql_query|nosql_query|graphql_query|mongo_query|redis_query|query)$/;

function fileStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n => {
    // Cross-domain exclusion: skip nodes that belong to query/injection domains
    if (NON_FILE_DOMAINS.test(n.node_subtype)) return false;

    return (
      // Primary: STORAGE nodes with file-related subtypes
      (n.node_type === 'STORAGE' &&
       (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
        n.node_subtype.includes('path') || n.attack_surface.includes('file_access') ||
        n.code_snapshot.match(
          /\b(readFile|writeFile|createReadStream|createWriteStream|open|unlink|readdir|rename|copyFile|stat|lstat|mkdir|rmdir|appendFile|chmod|chown|access|fopen|fread|fwrite|include|require_once)\b/i
        ) !== null)) ||
      // Fallback: INGRESS/file_read (e.g. Python open(), or legacy mistyped Java File constructors)
      (n.node_type === 'INGRESS' && n.node_subtype === 'file_read') ||
      // Fallback: EGRESS/file_write (e.g. Java FileOutputStream, Files.write) with user-controlled path
      (n.node_type === 'EGRESS' && (n.node_subtype === 'file_write' || n.node_subtype === 'file_serve'))
    );
  });
}

function bufferStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('buffer') || n.node_subtype.includes('array') ||
     n.node_subtype.includes('memory') || n.node_subtype.includes('heap') ||
     n.node_subtype.includes('stack') || n.attack_surface.includes('buffer_write') ||
     n.attack_surface.includes('array_access') ||
     n.code_snapshot.match(
       /\b(Buffer\.(alloc|from|write)|memcpy|memmove|strcpy|strncpy|sprintf|gets|malloc|calloc|realloc|new\s+\w+\[)\b/i
     ) !== null)
  );
}

function numericStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('numeric') || n.node_subtype.includes('integer') ||
     n.node_subtype.includes('arithmetic') || n.attack_surface.includes('numeric_operation') ||
     n.code_snapshot.match(
       /\b(parseInt|parseFloat|Number\(|Math\.(floor|ceil|round)|\.length\s*=|\bsize\s*=)\b/i
     ) !== null)
  );
}

function trustStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('session') || n.node_subtype.includes('config') ||
     n.node_subtype.includes('env') || n.node_subtype.includes('global') ||
     n.node_subtype.includes('internal') || n.attack_surface.includes('trusted_data') ||
     n.attack_surface.includes('session') ||
     n.code_snapshot.match(
       /\b(session|req\.session|process\.env|globalThis|window\.|document\.cookie|localStorage|sessionStorage)\b/i
     ) !== null)
  );
}

function xpathNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('xpath') || n.node_subtype.includes('xml') ||
     n.attack_surface.includes('xpath_query') ||
     n.code_snapshot.match(
       /\b(xpath|XPathExpression|evaluate|selectNodes|selectSingleNode|xmlDoc\.find)\b/i
     ) !== null)
  );
}

function protectedStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.attack_surface.includes('protected') || n.attack_surface.includes('admin') ||
     n.attack_surface.includes('sensitive') || n.attack_surface.includes('write') ||
     n.node_subtype.includes('protected') || n.node_subtype.includes('admin') ||
     n.code_snapshot.match(
       /\b(admin|protected|private|restricted|privileged|delete|drop|modify|grant|revoke)\b/i
     ) !== null)
  );
}

function resourceStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('resource') || n.node_subtype.includes('descriptor') ||
     n.node_subtype.includes('handle') || n.node_subtype.includes('connection') ||
     n.attack_surface.includes('resource_allocation') ||
     n.code_snapshot.match(
       /\b(open|socket|connect|createConnection|createServer|listen|fd|handle|pipe)\b/i
     ) !== null)
  );
}

function loggingStorageNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('log') || n.node_subtype.includes('audit') ||
     n.attack_surface.includes('logging') ||
     n.code_snapshot.match(
       /\b(console\.(log|warn|error|info|debug)|logger\.|log\.(info|warn|error|debug)|winston|bunyan|pino|syslog)\b/i
     ) !== null)
  );
}

// ---------------------------------------------------------------------------
// Safe-pattern constants — what the code looks like when the fix IS present
// ---------------------------------------------------------------------------

const PATH_SAFE = /\bpath\.resolve\b|\bpath\.normalize\b|\brealpath\b|\bstartsWith\b|\bsanitize.*path\b|\bpath\.basename\b|\bchroot\b|\bjail\b|\ballowlist\b|\bwhitelist\b/i;
const LINK_SAFE = /\bO_NOFOLLOW\b|\blstat\b|\breadlink\b|\bisSymbolicLink\b|\bfollowSymlinks?\s*:\s*false\b/i;
const ABSPATH_SAFE = /\bpath\.isAbsolute\b|\bisAbsolute\b|\breject.*absolute\b|\bstrip.*leading\b/i;
const WINPATH_SAFE = /\bpath\.win32\b|\bdeviceName\b|\bCON\b.*block|\bNUL\b.*block|\b\$DATA\b.*strip|\b\.lnk\b.*check/i;
const BUFFER_SAFE = /\blength\b.*[<>]=?|\bsizeof\b|\bbounds\b.*check|\bBuffer\.alloc\b(?!Unsafe)|\bMath\.min\b|\bclamp\b|\bvalidate.*index|\bcheck.*range|\bArray\.isArray\b/i;
const INTEGER_SAFE = /\bNumber\.isSafeInteger\b|\bMAX_SAFE_INTEGER\b|\bBigInt\b|\bNumber\.isFinite\b|\boverflow\b.*check|\brange.*valid|\bclamp\b|\bMath\.trunc\b/i;
const TRUST_SAFE = /\bObject\.freeze\b|\bObject\.seal\b|\breadonly\b|\bdeepClone\b|\bstructuredClone\b|\bvalidate\s*\(|\bsanitize\s*\(|\bEXTR_SKIP\b/i;
const XPATH_SAFE = /\bescapeXPath\b|\bxpath.*param|\bxpath.*compile|\bsanitize.*xpath|\bprepare.*xpath/i;
const AUTH_SAFE = /\bauthorize\s*\(|\bhasPermission\s*\(|\bcheckAccess\s*\(|\brole\s*[=!]==?\b|\bpolicy\b|\bRBAC\b|\bABAC\b|\bisAuthorized\b/i;
const LOCK_SAFE = /\bmutex\b|\block\b.*acquire|\bsynchronized\b|\bsemaphore\b|\batomic\b|\bcriticalSection\b|\bflock\b/i;
const RESOURCE_LIMIT_SAFE = /\blimit\b|\bthrottle\b|\bmax\b.*\b(fd|file|descriptor|connection|handle)\b|\bpool\b|\bulimit\b/i;
const LOG_SAFE = /\blog.*level|\b\.filter\s*\(|\bredact\s*\(|\btruncate\s*\(|\bmax.*log|\blog.*limit|\bsanitize\s*\(.*log/i;

// ---------------------------------------------------------------------------
// Factory: Path Traversal (source=INGRESS, sink=STORAGE[file], gap=no CONTROL)
// ---------------------------------------------------------------------------

function createPathTraversalVerifier(
  cweId: string, cweName: string, severity: Severity, extraSafe?: RegExp
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = fileStorageNodes(map);

    for (const src of ingress) {
      for (const sink of sinks) {
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          const isSafe = PATH_SAFE.test(sink.code_snapshot) ||
            (extraSafe ? extraSafe.test(sink.code_snapshot) : false);

          if (!isSafe) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (path validation / directory restriction)',
              severity,
              description: `User input from ${src.label} controls a file path at ${sink.label} without validation. ` +
                `Vulnerable to ${cweName}.`,
              fix: 'Resolve the full path with path.resolve(), verify it starts with your allowed base directory, ' +
                'and reject paths containing traversal sequences. Never use user input directly in file operations.',
              via: 'bfs',
            });
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// ---------------------------------------------------------------------------
// Factory: Buffer/Memory (source=INGRESS, sink=STORAGE[buffer], gap=no CONTROL)
// ---------------------------------------------------------------------------

function createBufferVerifier(
  cweId: string, cweName: string, severity: Severity, extraSafe?: RegExp
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = bufferStorageNodes(map);

    for (const src of ingress) {
      for (const sink of sinks) {
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          const isSafe = BUFFER_SAFE.test(sink.code_snapshot) ||
            (extraSafe ? extraSafe.test(sink.code_snapshot) : false);

          if (!isSafe) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (bounds checking / size validation)',
              severity,
              description: `User input from ${src.label} influences buffer/memory at ${sink.label} without bounds checking. ` +
                `Vulnerable to ${cweName}.`,
              fix: 'Validate buffer sizes and array indices before access. Use safe allocation methods. ' +
                'Check that write lengths do not exceed buffer capacity.',
              via: 'bfs',
            });
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// ---------------------------------------------------------------------------
// Factory: Integer Safety (source=INGRESS, sink=STORAGE[numeric], gap=no CONTROL)
// ---------------------------------------------------------------------------

function createIntegerVerifier(
  cweId: string, cweName: string, severity: Severity, extraSafe?: RegExp
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = numericStorageNodes(map);

    for (const src of ingress) {
      for (const sink of sinks) {
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          const isSafe = INTEGER_SAFE.test(sink.code_snapshot) ||
            (extraSafe ? extraSafe.test(sink.code_snapshot) : false);

          // Range check: if the variable is bounded within safe integer range,
          // integer overflow is impossible
          const isRangeBounded = sinkHasSafeRange(map, sink.id, Number.MAX_SAFE_INTEGER);

          if (!isSafe && !isRangeBounded) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (numeric range validation / overflow check)',
              severity,
              description: `User input from ${src.label} influences numeric operation at ${sink.label} without range validation. ` +
                `Vulnerable to ${cweName}.`,
              fix: 'Validate numeric inputs are within expected ranges. Use Number.isSafeInteger() for integers. ' +
                'Check for overflow before arithmetic. Use BigInt for large values.',
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
// A. PATH TRAVERSAL VERIFIERS (32 CWEs)
// ===========================================================================

// Relative traversal variants (CWE-23 through CWE-35)
export const verifyCWE23 = createPathTraversalVerifier('CWE-23', 'Relative Path Traversal', 'high');
export const verifyCWE24 = createPathTraversalVerifier('CWE-24', "Path Traversal: '../filedir'", 'high');
export const verifyCWE25 = createPathTraversalVerifier('CWE-25', "Path Traversal: '/../filedir'", 'high');
export const verifyCWE26 = createPathTraversalVerifier('CWE-26', "Path Traversal: '/dir/../filename'", 'high');
export const verifyCWE27 = createPathTraversalVerifier('CWE-27', "Path Traversal: 'dir/../../filename'", 'high');
export const verifyCWE28 = createPathTraversalVerifier('CWE-28', "Path Traversal: '..\\filedir'", 'high', WINPATH_SAFE);
export const verifyCWE29 = createPathTraversalVerifier('CWE-29', "Path Traversal: '\\..\\filename'", 'high', WINPATH_SAFE);
export const verifyCWE30 = createPathTraversalVerifier('CWE-30', "Path Traversal: '\\dir\\..\\filename'", 'high', WINPATH_SAFE);
export const verifyCWE31 = createPathTraversalVerifier('CWE-31', "Path Traversal: 'dir\\..\\..\\filename'", 'high', WINPATH_SAFE);
export const verifyCWE32 = createPathTraversalVerifier('CWE-32', "Path Traversal: '...' (Triple Dot)", 'high');
export const verifyCWE33 = createPathTraversalVerifier('CWE-33', "Path Traversal: '....' (Multiple Dots)", 'high');
export const verifyCWE34 = createPathTraversalVerifier('CWE-34', "Path Traversal: '....//'", 'high');
export const verifyCWE35 = createPathTraversalVerifier('CWE-35', "Path Traversal: '.../...//'", 'high');

// Absolute path variants (CWE-36 through CWE-40)
export const verifyCWE36 = createPathTraversalVerifier('CWE-36', 'Absolute Path Traversal', 'high', ABSPATH_SAFE);
export const verifyCWE37 = createPathTraversalVerifier('CWE-37', "Path Traversal: '/absolute/pathname/here'", 'high', ABSPATH_SAFE);
export const verifyCWE38 = createPathTraversalVerifier('CWE-38', "Path Traversal: '\\absolute\\pathname\\here'", 'high', /\bpath\.isAbsolute\b|\bpath\.win32\b/i);
export const verifyCWE39 = createPathTraversalVerifier('CWE-39', "Path Traversal: 'C:dirname'", 'high', /\b[A-Z]:\b.*reject|\bdrive.*letter\b.*check|\bpath\.win32\b/i);
export const verifyCWE40 = createPathTraversalVerifier('CWE-40', "Path Traversal: '\\\\UNC\\share\\name\\' (Windows UNC)", 'high', /\bUNC\b.*reject|\b\\\\\\\\.*block|\bpath\.win32\b/i);

// Wildcard equivalence
export const verifyCWE56 = createPathTraversalVerifier('CWE-56', "Path Equivalence: 'filedir*' (Wildcard)", 'medium');

// Link following variants
export const verifyCWE59 = createPathTraversalVerifier('CWE-59', "Improper Link Resolution Before File Access ('Link Following')", 'high', LINK_SAFE);
export const verifyCWE61 = createPathTraversalVerifier('CWE-61', 'UNIX Symbolic Link (Symlink) Following', 'high', LINK_SAFE);
export const verifyCWE62 = createPathTraversalVerifier('CWE-62', 'UNIX Hard Link', 'high', LINK_SAFE);
export const verifyCWE64 = createPathTraversalVerifier('CWE-64', 'Windows Shortcut Following (.LNK)', 'high', /\b\.lnk\b.*check|\bshortcut\b.*resolve/i);
export const verifyCWE65 = createPathTraversalVerifier('CWE-65', 'Windows Hard Link', 'high', LINK_SAFE);

// Special file handling
export const verifyCWE66 = createPathTraversalVerifier('CWE-66', 'Improper Handling of File Names that Identify Virtual Resources', 'medium', /\bvirtual\b.*check|\b\/dev\/\b.*reject|\b\/proc\/\b.*reject/i);
export const verifyCWE67 = createPathTraversalVerifier('CWE-67', 'Improper Handling of Windows Device Names', 'medium', WINPATH_SAFE);
export const verifyCWE69 = createPathTraversalVerifier('CWE-69', 'Improper Handling of Windows ::DATA Alternate Data Stream', 'medium', /\b::\$DATA\b.*strip|\bADS\b.*check|\balternate.*stream\b.*reject/i);
export const verifyCWE72 = createPathTraversalVerifier('CWE-72', 'Improper Handling of Apple HFS+ Alternate Data Stream Path', 'medium', /\bresource.*fork\b.*check|\bHFS\b.*check/i);

// File name/path control
export const verifyCWE73 = createPathTraversalVerifier('CWE-73', 'External Control of File Name or Path', 'high');
export const verifyCWE641 = createPathTraversalVerifier('CWE-641', 'Improper Restriction of Names for Files and Other Resources', 'medium', /\bname.*restrict\b|\bfilename.*valid\b|\ballowed.*names\b|\bname.*pattern\b/i);
export const verifyCWE646 = createPathTraversalVerifier('CWE-646', 'Reliance on File Name or Extension of Externally-Supplied File', 'medium', /\bmime.*type\b|\bcontent.*type\b|\bmagic.*bytes\b|\bfile.*header\b/i);
export const verifyCWE706 = createPathTraversalVerifier('CWE-706', 'Use of Incorrectly-Resolved Name or Reference', 'high', LINK_SAFE);

// ===========================================================================
// B. BUFFER/MEMORY VERIFIERS (9 CWEs)
// ===========================================================================

export const verifyCWE121 = createBufferVerifier('CWE-121', 'Stack-based Buffer Overflow', 'critical', /\bstack\b.*safe|\bstack.*guard\b|\bcanary\b/i);
export const verifyCWE122 = createBufferVerifier('CWE-122', 'Heap-based Buffer Overflow', 'critical', /\bheap\b.*safe|\bsafe.*alloc\b/i);
export const verifyCWE123 = createBufferVerifier('CWE-123', 'Write-what-where Condition', 'critical');
export const verifyCWE129 = createBufferVerifier('CWE-129', 'Improper Validation of Array Index', 'high', /\bindex\b.*[<>]=?\s*\d|\bindex\b.*\blength\b|\bisNaN\b|\bparseInt\b.*[<>]/i);
export const verifyCWE130 = createBufferVerifier('CWE-130', 'Improper Handling of Length Parameter Inconsistency', 'high', /\blength\b.*===?\s*\blength\b|\bsize.*match\b|\bconsistent.*length\b/i);
/**
 * CWE-787: Out-of-bounds Write
 * Pattern: INGRESS → STORAGE(buffer/array write) without CONTROL(bounds check)
 *
 * UPGRADED from factory: specific write-operation sinks, specific bounds-check
 * safe patterns. The generic buffer factory flags ANY buffer node; this version
 * only flags nodes performing WRITE operations (Buffer.write, memcpy, strcpy,
 * array index assignment, TypedArray.set) without explicit length/bounds guards.
 *
 * Dangerous sinks: Buffer.write(), memcpy(), strcpy(), sprintf(), gets(),
 *   array[userIdx] = val, TypedArray.set(), memmove().
 * Safe mitigations: Math.min(offset, buf.length), if (idx < arr.length),
 *   Buffer.alloc (safe alloc), clamp(), strncpy(), snprintf().
 */
export function verifyCWE787(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Only STORAGE nodes performing WRITE operations — not reads, not allocations
  const writeSinks = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('buffer') || n.node_subtype.includes('array') ||
     n.node_subtype.includes('memory') || n.node_subtype.includes('heap') ||
     n.node_subtype.includes('stack') || n.attack_surface.includes('buffer_write') ||
     n.attack_surface.includes('array_access') ||
     n.code_snapshot.match(
       /\b(Buffer\.(write|copy|fill)|memcpy|memmove|strcpy|strncpy|sprintf|gets|write\s*\(|set\s*\()\b|\[\s*\w+\s*\]\s*=/i
     ) !== null)
  );

  for (const src of ingress) {
    for (const sink of writeSinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Specific bounds-check patterns that actually prevent OOB writes
        const hasBoundsCheck = sink.code_snapshot.match(
          // Explicit comparison: offset < buf.length, idx < arr.length
          /\b\w+\s*[<>]=?\s*\w*\.?length\b/i
        ) !== null;

        const hasSafeMath = sink.code_snapshot.match(
          // Math.min to clamp, Buffer.alloc (safe), clamp(), strncpy, snprintf
          /\bMath\.min\b|\bclamp\b|\bBuffer\.alloc\b(?!Unsafe)|\bstrncpy\b|\bsnprintf\b|\bstrlcpy\b|\bbounds.*check\b|\bvalidate.*index\b|\bcheck.*range\b/i
        ) !== null;

        const hasConditionalGuard = sink.code_snapshot.match(
          // if (offset + data.length <= buf.length)
          /if\s*\(.*\+.*<=?\s*.*\.length/i
        ) !== null;

        if (!hasBoundsCheck && !hasSafeMath && !hasConditionalGuard) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (bounds check before write — validate offset + length <= buffer.length)',
            severity: 'critical',
            description: `User input from ${src.label} controls a write operation at ${sink.label} without bounds validation. ` +
              `An attacker can write past buffer boundaries, corrupting adjacent memory. ` +
              `This enables code execution, crash, or data corruption.`,
            fix: 'Validate offset + length <= buffer.length before every write. ' +
              'Use Math.min(offset, buf.length - data.length) to clamp. ' +
              'In C: use strncpy/snprintf instead of strcpy/sprintf. ' +
              'In Node.js: Buffer.alloc() (not allocUnsafe) + explicit length checks.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-787', name: 'Out-of-bounds Write', holds: findings.length === 0, findings };
}
export const verifyCWE822 = createBufferVerifier('CWE-822', 'Untrusted Pointer Dereference', 'critical', /\bnull.*check\b|\bpointer.*valid\b|\btypeof.*===\b|\binstanceof\b/i);
export const verifyCWE823 = createBufferVerifier('CWE-823', 'Use of Out-of-range Pointer Offset', 'critical', /\boffset\b.*[<>]=?|\boffset\b.*\blength\b|\bbounds\b/i);
export const verifyCWE839 = createBufferVerifier('CWE-839', 'Numeric Range Comparison Without Minimum Check', 'medium', /\b>=?\s*0\b|\bMin\b|\bminimum\b|\blower.*bound\b/i);

// ===========================================================================
// C. INTEGER VERIFIERS (6 CWEs)
// ===========================================================================

export const verifyCWE190 = createIntegerVerifier('CWE-190', 'Integer Overflow or Wraparound', 'high');
export const verifyCWE191 = createIntegerVerifier('CWE-191', 'Integer Underflow (Wrap or Wraparound)', 'high', /\b>=?\s*0\b|\bMin\b|\bminimum\b|\bunderflow\b.*check/i);
export const verifyCWE192 = createIntegerVerifier('CWE-192', 'Integer Coercion Error', 'medium', /\btypeof\b.*number|\bNumber\.isInteger\b|\bparseInt\b.*\bradix\b/i);
export const verifyCWE194 = createIntegerVerifier('CWE-194', 'Unexpected Sign Extension', 'medium', /\b>>>\s*0\b|\bUint\b|\bunsigned\b|\bsign.*check\b/i);
export const verifyCWE196 = createIntegerVerifier('CWE-196', 'Unsigned to Signed Conversion Error', 'medium', /\bUint\b|\bunsigned\b|\bsign.*convert\b|\b>>>\s*0\b/i);
export const verifyCWE197 = createIntegerVerifier('CWE-197', 'Numeric Truncation Error', 'medium', /\bMath\.trunc\b|\bMath\.floor\b|\bparseInt\b|\btruncate\b.*warn/i);

// ===========================================================================
// D. TRUST BOUNDARY VERIFIERS (5 CWEs)
// ===========================================================================

export const verifyCWE471 = createGenericVerifier(
  'CWE-471', 'Modification of Assumed-Immutable Data (MAID)', 'high',
  trustStorageNodes, TRUST_SAFE,
  'CONTROL (immutability enforcement / input validation)',
  'Use Object.freeze() for immutable data. Validate all external input before mixing with trusted state. ' +
    'Use structuredClone() when passing data across trust boundaries.',
);

export const verifyCWE473 = createGenericVerifier(
  'CWE-473', 'PHP External Variable Modification', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('global') || n.node_subtype.includes('extract') ||
     n.code_snapshot.match(/\b(extract|register_globals|\$GLOBALS|\$_SESSION|\$_SERVER)\b/i) !== null)
  ),
  /\bEXTR_SKIP\b|\bregister_globals.*off\b|\bvalidate\s*\(|\ballowlist\b|\bwhitelist\b/i,
  'CONTROL (variable extraction restriction)',
  'Never use extract() on user input. Use EXTR_SKIP or EXTR_PREFIX if unavoidable. ' +
    'Explicitly initialize all variables.',
);

export const verifyCWE501 = createGenericVerifier(
  'CWE-501', 'Trust Boundary Violation', 'high',
  trustStorageNodes, TRUST_SAFE,
  'CONTROL (trust boundary enforcement / input validation)',
  'Never mix trusted and untrusted data in the same structure. ' +
    'Validate external input before storing in session or internal state.',
);

export const verifyCWE621 = createGenericVerifier(
  'CWE-621', 'Variable Extraction Error', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('variable') || n.node_subtype.includes('extract') ||
     n.code_snapshot.match(/\b(extract|import|register|overwrite|assign.*dynamic)\b/i) !== null)
  ),
  /\bEXTR_SKIP\b|\ballowlist\b|\bwhitelist\b|\bvalidate.*variable\b|\bpermitted.*vars\b/i,
  'CONTROL (variable name validation / extraction restriction)',
  'Validate variable names against an allowlist before extraction. ' +
    'Prefer explicit assignment over bulk extraction.',
);

export const verifyCWE914 = createGenericVerifier(
  'CWE-914', 'Improper Control of Dynamically-Identified Variables', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('dynamic') || n.node_subtype.includes('variable') ||
     n.code_snapshot.match(/\b(eval|variable\s*variables|\$\$|\[.*\]\s*=|Object\.assign|Reflect\.set)\b/i) !== null)
  ),
  /\ballowlist\b|\bwhitelist\b|\bvalidate.*name\b|\bpermitted\b|\bhasOwnProperty\b/i,
  'CONTROL (variable name allowlist / dynamic access restriction)',
  'Validate dynamically-identified variable names against a strict allowlist. ' +
    'Prefer Map with validated keys over dynamic variable access.',
);

// ===========================================================================
// E. RESOURCE ALLOCATION VERIFIERS (2 CWEs)
// ===========================================================================

export const verifyCWE774 = createGenericVerifier(
  'CWE-774', 'Allocation of File Descriptors or Handles Without Limits or Throttling', 'medium',
  resourceStorageNodes, RESOURCE_LIMIT_SAFE,
  'CONTROL (resource allocation limits / throttling)',
  'Enforce limits on file descriptor and handle allocation. Use connection pooling. ' +
    'Implement per-client throttling for resource allocation.',
);

export const verifyCWE779 = createGenericVerifier(
  'CWE-779', 'Logging of Excessive Data', 'medium',
  loggingStorageNodes, LOG_SAFE,
  'CONTROL (log filtering / data redaction / size limits)',
  'Implement log level filtering and data redaction. Set maximum log message sizes. ' +
    'Never log sensitive data (passwords, tokens, PII) in plain text.',
);

// ===========================================================================
// F. INDIVIDUAL VERIFIERS (6 CWEs)
// ===========================================================================

/**
 * CWE-179: Incorrect Behavior Order: Early Validation
 * The validation happens before canonicalization, so encoded input bypasses checks.
 * Detected when: uncontrolled INGRESS→STORAGE path + canonicalization TRANSFORM present.
 */
export function verifyCWE179(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const storage = nodesOfType(map, 'STORAGE');

  for (const src of ingress) {
    for (const sink of storage) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const hasCanonTransform = map.nodes.some(n =>
          n.node_type === 'TRANSFORM' &&
          n.code_snapshot.match(/\bdecode\b|\bnormalize\b|\bcanonicalize\b|\bresolve\b|\bunescape\b|\bURLDecode\b|\bdecodeURI\b/i) !== null
        );

        if (hasCanonTransform) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (validation AFTER canonicalization — current order may be reversed)',
            severity: 'high',
            description: `User input from ${src.label} reaches ${sink.label} without effective validation. ` +
              `If validation occurs before canonicalization, encoded input can bypass security checks.`,
            fix: 'Always canonicalize input (decode, normalize, resolve) BEFORE applying validation. ' +
              'Validate on the canonical form, not the raw input.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-179', name: 'Incorrect Behavior Order: Early Validation', holds: findings.length === 0, findings };
}

/**
 * CWE-180: Incorrect Behavior Order: Validate Before Canonicalize
 * Same structural issue as CWE-179, different CWE classification.
 */
export function verifyCWE180(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const storage = nodesOfType(map, 'STORAGE');

  for (const src of ingress) {
    for (const sink of storage) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const hasCanonTransform = map.nodes.some(n =>
          n.node_type === 'TRANSFORM' &&
          n.code_snapshot.match(/\bdecode\b|\bnormalize\b|\bcanonicalize\b|\bresolve\b|\bunescape\b|\bURLDecode\b|\bdecodeURI\b/i) !== null
        );

        if (hasCanonTransform) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (validation AFTER canonicalization)',
            severity: 'high',
            description: `User input from ${src.label} reaches ${sink.label} without effective validation. ` +
              `Validation before canonicalization allows encoded bypasses.`,
            fix: 'Canonicalize all input before validation. Apply security checks to the decoded, normalized form.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-180', name: 'Incorrect Behavior Order: Validate Before Canonicalize', holds: findings.length === 0, findings };
}

/**
 * CWE-222: Truncation of Security-relevant Information
 * Security data is truncated before comparison, potentially causing incorrect matches.
 */
export function verifyCWE222(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const storage = nodesOfType(map, 'STORAGE');

  for (const src of ingress) {
    for (const sink of storage) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const hasTruncation = map.nodes.some(n =>
          n.node_type === 'TRANSFORM' &&
          n.code_snapshot.match(/\bsubstring\b|\bslice\b|\bsubstr\b|\btruncate\b|\blimit\b.*\blength\b/i) !== null
        );

        if (hasTruncation) {
          const isSafe = sink.code_snapshot.match(
            /\blength\b.*>=?\s*\d|\bminLength\b|\bfull.*length\b|\bno.*trunc/i
          ) !== null;

          if (!isSafe) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (length validation before truncation)',
              severity: 'medium',
              description: `User input from ${src.label} is truncated before reaching ${sink.label}. ` +
                `Truncation of security-relevant data can cause incorrect comparisons.`,
              fix: 'Validate input length BEFORE truncation. Reject inputs exceeding maximum length ' +
                'rather than silently truncating. Compare full values.',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-222', name: 'Truncation of Security-relevant Information', holds: findings.length === 0, findings };
}

/**
 * CWE-413: Improper Resource Locking
 * Concurrent access to shared resources without locks/mutexes.
 */
export function verifyCWE413(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const shared = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('shared') || n.node_subtype.includes('global') ||
     n.attack_surface.includes('concurrent') || n.attack_surface.includes('shared') ||
     n.code_snapshot.match(/\b(global|shared|concurrent|mutex|lock|critical)\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of shared) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!LOCK_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (resource locking / mutex / synchronization)',
            severity: 'medium',
            description: `Request from ${src.label} accesses shared resource at ${sink.label} without locking. ` +
              `Concurrent access can cause data corruption or race conditions.`,
            fix: 'Use locks, mutexes, or synchronized blocks for shared resources. ' +
              'Implement proper lock ordering to prevent deadlocks.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-413', name: 'Improper Resource Locking', holds: findings.length === 0, findings };
}

/**
 * CWE-643: XPath Injection
 * User input flows into XPath expressions without sanitization.
 */
export function verifyCWE643(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = xpathNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!XPATH_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (XPath sanitization / parameterization)',
            severity: 'high',
            description: `User input from ${src.label} flows into XPath expression at ${sink.label} without sanitization. ` +
              `An attacker can inject XPath operators to bypass authentication or access unauthorized data.`,
            fix: 'Use parameterized XPath queries or compiled expressions. ' +
              'Escape special XPath characters. Validate input against a strict allowlist.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-643', name: 'XPath Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-863: Incorrect Authorization
 * Requests reach protected resources without proper authorization checks.
 */
export function verifyCWE863(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = protectedStorageNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!AUTH_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (proper authorization check)',
            severity: 'critical',
            description: `Request from ${src.label} reaches protected resource ${sink.label} without authorization. ` +
              `An attacker can access or modify resources beyond their privilege level.`,
            fix: 'Implement authorization checks before accessing protected resources. ' +
              'Use RBAC or ABAC. Verify permissions on every request, not just at the UI level.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-863', name: 'Incorrect Authorization', holds: findings.length === 0, findings };
}

// ===========================================================================
// REGISTRY — maps CWE IDs to verifier functions for this batch
// ===========================================================================

export const BATCH_001_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Path Traversal (32)
  'CWE-23': verifyCWE23,
  'CWE-24': verifyCWE24,
  'CWE-25': verifyCWE25,
  'CWE-26': verifyCWE26,
  'CWE-27': verifyCWE27,
  'CWE-28': verifyCWE28,
  'CWE-29': verifyCWE29,
  'CWE-30': verifyCWE30,
  'CWE-31': verifyCWE31,
  'CWE-32': verifyCWE32,
  'CWE-33': verifyCWE33,
  'CWE-34': verifyCWE34,
  'CWE-35': verifyCWE35,
  'CWE-36': verifyCWE36,
  'CWE-37': verifyCWE37,
  'CWE-38': verifyCWE38,
  'CWE-39': verifyCWE39,
  'CWE-40': verifyCWE40,
  'CWE-56': verifyCWE56,
  'CWE-59': verifyCWE59,
  'CWE-61': verifyCWE61,
  'CWE-62': verifyCWE62,
  'CWE-64': verifyCWE64,
  'CWE-65': verifyCWE65,
  'CWE-66': verifyCWE66,
  'CWE-67': verifyCWE67,
  'CWE-69': verifyCWE69,
  'CWE-72': verifyCWE72,
  'CWE-73': verifyCWE73,
  'CWE-641': verifyCWE641,
  'CWE-646': verifyCWE646,
  'CWE-706': verifyCWE706,
  // Buffer/Memory (9)
  'CWE-121': verifyCWE121,
  'CWE-122': verifyCWE122,
  'CWE-123': verifyCWE123,
  'CWE-129': verifyCWE129,
  'CWE-130': verifyCWE130,
  'CWE-787': verifyCWE787,
  'CWE-822': verifyCWE822,
  'CWE-823': verifyCWE823,
  'CWE-839': verifyCWE839,
  // Integer (6)
  'CWE-190': verifyCWE190,
  'CWE-191': verifyCWE191,
  'CWE-192': verifyCWE192,
  'CWE-194': verifyCWE194,
  'CWE-196': verifyCWE196,
  'CWE-197': verifyCWE197,
  // Trust Boundary (5)
  'CWE-471': verifyCWE471,
  'CWE-473': verifyCWE473,
  'CWE-501': verifyCWE501,
  'CWE-621': verifyCWE621,
  'CWE-914': verifyCWE914,
  // Resource (2)
  'CWE-774': verifyCWE774,
  'CWE-779': verifyCWE779,
  // Individual (6)
  'CWE-179': verifyCWE179,
  'CWE-180': verifyCWE180,
  'CWE-222': verifyCWE222,
  'CWE-413': verifyCWE413,
  'CWE-643': verifyCWE643,
  'CWE-863': verifyCWE863,
};
