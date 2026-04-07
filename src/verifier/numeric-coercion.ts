/**
 * Numeric & Coercion CWE Verifiers
 *
 * Integer overflow, sign extension, truncation, type coercion, buffer overflows,
 * off-by-one errors, pointer arithmetic, and numeric conversion issues.
 *
 * Extracted from verifier/index.ts - Phase 7 of the monolith split.
 */

import type { NeuralMap } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments } from './source-analysis.ts';
import { nodeRef, nodesOfType, hasTaintedPathWithoutControl, sharesFunctionScope } from './graph-helpers.ts';


/**
 * CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
 * The parent class for all buffer overflow/underflow vulnerabilities.
 * Detects raw memory/buffer operations without bounds validation in C/C++/Rust/Go/JS.
 */
function verifyCWE119(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const UNSAFE_MEM_RE = /\b(memcpy|memmove|memset|strcpy|strcat|sprintf|vsprintf|gets|fgets|sscanf|fscanf|scanf|bcopy|bzero)\s*\(/i;
  const UNSAFE_ALLOC_RE = /\b(malloc|calloc|realloc|alloca|free)\s*\(/i;
  const POINTER_ARITH_RE = /\*\s*\(.*\+|\bptr\s*[\+\-]|\bunsafe\s*\{|\bunsafe\.Pointer|\bslice::from_raw_parts|\b\*mut\b|\b\*const\b/i;
  // UNSAFE_BUFFER_RE: Buffer.allocUnsafe, buffer.write/copy/fill without length check,
  // Buffer.from with user-controlled source (tainted copy without size check),
  // buffer.writeUInt32BE/writeInt32LE etc. (binary writes at user-controlled offset)
  const UNSAFE_BUFFER_RE = /\bBuffer\.allocUnsafe\b|\bbuffer\.(write|copy|fill|writeUInt|writeInt|writeFloat|writeDouble)\s*\((?![^)]*\.length\b[^)]*\)[^;]*if)|\bBuffer\.from\b|\bTypedArray\b.*\[/i;
  const BOUNDS_SAFE_RE = /\bbounds\b.*check|\bif\s*\(.*[<>]=?\s*.*\b(length|size|len|cap|capacity)\b|\bstrncpy\b|\bsnprintf\b|\bstrlcpy\b|\bstrlcat\b|\bmemcpy_s\b|\bstrcpy_s\b|\bsizeof\b.*[<>]=?|\bstd::copy\b|\bstd::copy_n\b|\bBuffer\.alloc\b(?!Unsafe)|\bslice\s*\(\s*\d|\bMath\.min\b.*length|\b\.len\(\)\b.*[<>]|\bchecked_add\b|\bchecked_mul\b/i;
  const memNodes = map.nodes.filter(n =>
    // Include RESOURCE nodes: Buffer.alloc/Buffer.from are classified RESOURCE/memory
    (n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'RESOURCE') &&
    (UNSAFE_MEM_RE.test(n.analysis_snapshot || n.code_snapshot) || UNSAFE_ALLOC_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     POINTER_ARITH_RE.test(n.analysis_snapshot || n.code_snapshot) || UNSAFE_BUFFER_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     n.node_subtype.includes('buffer') || n.node_subtype.includes('memory') ||
     n.node_subtype.includes('pointer') || n.attack_surface.includes('buffer_write'))
  );
  const ingress = nodesOfType(map, 'INGRESS');
  for (const src of ingress) {
    for (const sink of memNodes) {
      const hasBfs119 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const hasScope119 = sharesFunctionScope(map, src.id, sink.id);
      if (hasBfs119 || hasScope119) {
        if (!BOUNDS_SAFE_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (bounds validation before memory/buffer operation)',
            severity: 'critical',
            description: `User input from ${src.label} reaches memory operation at ${sink.label} without bounds checking. ` +
              `This can cause buffer overflow, enabling code execution, crash, or data corruption.`,
            fix: 'Validate all buffer sizes and indices before memory operations. ' +
              'Use bounded functions: strncpy/snprintf instead of strcpy/sprintf. ' +
              'In Rust: avoid unsafe blocks or use checked indexing. In Go: validate slice indices against len().',
            via: hasBfs119 ? 'bfs' : 'scope_taint',
          });
        }
      }
    }
  }
  if (findings.length === 0) {
    const ALWAYS_DANGEROUS_RE = /\b(gets|sprintf|vsprintf|strcpy|strcat)\s*\(/i;
    for (const node of memNodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (ALWAYS_DANGEROUS_RE.test(code) && !BOUNDS_SAFE_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (use of inherently unsafe memory function without bounds)',
          severity: 'critical',
          description: `${node.label} uses an inherently unsafe memory function (gets/strcpy/sprintf/strcat) ` +
            `that has no built-in bounds checking. Vulnerable to buffer overflow regardless of input source.`,
          fix: 'Replace gets() with fgets(). Replace strcpy/strcat with strncpy/strlcat or std::string. ' +
            'Replace sprintf with snprintf.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-119', name: 'Improper Restriction of Operations within the Bounds of a Memory Buffer', holds: findings.length === 0, findings };
}

/**
 * CWE-120: Buffer Copy without Checking Size of Input (Classic Buffer Overflow)
 * Targets copy operations where source size is not validated against destination capacity.
 * Classic pattern: char buf[256]; strcpy(buf, user_input);
 */
function verifyCWE120(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const COPY_RE = /\b(strcpy|strcat|memcpy|memmove|bcopy|wcscpy|wcscat|lstrcpy|_mbscpy|CopyMemory|RtlCopyMemory)\s*\(/i;
  const SAFE_COPY_RE = /\b(strncpy|strncat|memcpy_s|memmove_s|strlcpy|strlcat|snprintf|std::copy_n|std::string|copy_nonoverlapping)\s*\(/i;
  const SIZE_CHECK_RE = /\bsizeof\s*\(.*dest|\blen\s*[<>]=?\s*.*capacity|\blength\s*[<>]=?\s*sizeof|\bif\s*\(.*strlen.*[<>].*sizeof|\bmin\s*\(.*len.*sizeof|\bstrlen\b.*[<>]=?\s*\d/i;
  const ingress = nodesOfType(map, 'INGRESS');
  const copyNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (COPY_RE.test(n.analysis_snapshot || n.code_snapshot) || n.node_subtype.includes('buffer_copy') ||
     n.node_subtype.includes('memcpy') || n.attack_surface.includes('buffer_copy'))
  );
  for (const src of ingress) {
    for (const sink of copyNodes) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!SAFE_COPY_RE.test(code) && !SIZE_CHECK_RE.test(code)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (size check before buffer copy — validate source length <= dest capacity)',
            severity: 'critical',
            description: `User input from ${src.label} is copied to a buffer at ${sink.label} without checking ` +
              `that the source data fits in the destination. This is the classic buffer overflow.`,
            fix: 'Check source size before copying: if (strlen(src) >= sizeof(dest)) return error. ' +
              'Replace strcpy with strncpy/strlcpy. Replace strcat with strncat/strlcat. ' +
              'Always pass destination buffer size to copy functions.',
            via: 'bfs',
          });
        }
      }
    }
  }
  if (findings.length === 0) {
    for (const node of copyNodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (COPY_RE.test(code) && !SAFE_COPY_RE.test(code) && !SIZE_CHECK_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (bounded copy function or explicit size validation)',
          severity: 'critical',
          description: `${node.label} uses an unbounded copy function (strcpy/strcat/memcpy) without size validation. ` +
            `If the source ever exceeds the destination capacity, a buffer overflow occurs.`,
          fix: 'Replace strcpy/strcat with strncpy/strlcpy/strlcat. For memcpy, validate: n <= sizeof(dest). ' +
            'Use std::string/std::vector in C++ to avoid manual buffer management.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-120', name: 'Buffer Copy without Checking Size of Input (Classic Buffer Overflow)', holds: findings.length === 0, findings };
}

/**
 * CWE-125: Out-of-bounds Read
 * Reading data past the end or before the beginning of a buffer.
 * Can leak sensitive data (Heartbleed was CWE-125) or cause crashes.
 */
function verifyCWE125(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const READ_OP_RE = /\b(read|fread|recv|recvfrom|pread|readv|buffer\.read\w+|\.read\w*BE\b|\.read\w*LE\b|get_unchecked|from_raw_parts|ptr\.read|ptr\.add|memchr|strstr|strlen)\s*\(/i;
  const BUFFER_READ_RE = /\bbuffer\.(read|toString|slice)\s*\(|\bDataView\b.*\bget\w+\(/i;
  const SAFE_READ_RE = /\bif\s*\(.*index.*[<>]=?\s*.*length|\bif\s*\(.*offset.*[<>]=?\s*.*size|\b\.get\(\s*\w+\s*\)|\b\.at\(\s*\w+\s*\)|\bchecked\b|\b\.len\(\)\s*[<>]|\bbounds_check|\brange_check|\bslice\(\s*\d+\s*,\s*\d+\s*\)/i;
  const ingress = nodesOfType(map, 'INGRESS');
  const readNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM') &&
    (READ_OP_RE.test(n.analysis_snapshot || n.code_snapshot) || BUFFER_READ_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     n.node_subtype.includes('buffer_read') || n.node_subtype.includes('array_access') ||
     n.attack_surface.includes('buffer_read'))
  );
  for (const src of ingress) {
    for (const sink of readNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!SAFE_READ_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (bounds check before read — validate offset < buffer.length)',
            severity: 'high',
            description: `User input from ${src.label} controls a read offset/index at ${sink.label} without bounds validation. ` +
              `Out-of-bounds reads can leak sensitive memory contents (like Heartbleed) or cause crashes.`,
            fix: 'Validate read offsets against buffer length: if (offset + readSize > buf.length) return error. ' +
              'Use safe accessors: .at() in JS, .get() in Rust, bounds-checked slice in Go.',
            via: 'bfs',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-125', name: 'Out-of-bounds Read', holds: findings.length === 0, findings };
}

/**
 * CWE-126: Buffer Over-read
 * Variant of CWE-125 — specifically reading PAST the end of a buffer.
 * Often caused by incorrect length calculations or missing null terminators.
 */
function verifyCWE126(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const OVERREAD_RE = /\bstrlen\b|\bwcslen\b|\bstrnlen\b|\bmemchr\b|\bsizeof\b.*read|\bread\s*\(.*sizeof|\b\.length\b.*read|\brecv\b.*\bsizeof\b/i;
  const FIXED_SIZE_READ_RE = /\bread\s*\(\s*\w+\s*,\s*\d+\s*\)|\bmemcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*\d+\s*\)|\bfread\s*\(\s*\w+\s*,\s*\d+/i;
  const BUFFER_SLICE_RE = /\bbuffer\.(read|toString|slice)\s*\(.*\+|\bsubarray\s*\(/i;
  const SAFE_OVERREAD_RE = /\bstrnlen\b|\bnull.*termin|\b\\0\b.*check|\bif\s*\(.*recv.*[<>]=?|\bif\s*\(.*len\s*[<>]=?\s*.*size|\bmin\s*\(.*len|\bMath\.min\b/i;
  const ingress = nodesOfType(map, 'INGRESS');
  const overreadNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM') &&
    (OVERREAD_RE.test(n.analysis_snapshot || n.code_snapshot) || FIXED_SIZE_READ_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     BUFFER_SLICE_RE.test(n.analysis_snapshot || n.code_snapshot) || n.node_subtype.includes('buffer') ||
     n.attack_surface.includes('buffer_read'))
  );
  for (const src of ingress) {
    for (const sink of overreadNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!SAFE_OVERREAD_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (upper bounds validation — ensure read does not exceed buffer end)',
            severity: 'high',
            description: `User input from ${src.label} influences a read at ${sink.label} that may exceed the buffer boundary. ` +
              `Buffer over-reads leak adjacent memory contents and can expose secrets or cause crashes.`,
            fix: 'Use Math.min(requestedLength, buffer.length - offset) to cap read size. ' +
              'Validate offset + length <= buffer.length before every read. ' +
              'Use strnlen() instead of strlen() for untrusted strings.',
            via: 'bfs',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-126', name: 'Buffer Over-read', holds: findings.length === 0, findings };
}

/**
 * CWE-127: Buffer Under-read
 * Reading before the beginning of a buffer due to negative index or
 * pointer arithmetic producing a pointer before the buffer start.
 */
function verifyCWE127(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const NEGATIVE_INDEX_RE = /\[\s*\w+\s*-|\bptr\s*-\s*\d|\boffset\s*-|\b\w+\s*\[\s*-\s*\d/i;
  const SIGNED_INDEX_RE = /\bint\s+\w*index|\bint\s+\w*offset|\bint\s+\w*pos|\bsigned\b.*\[/i;
  const BUFFER_NEGATIVE_RE = /\bbuffer\.\w+\(\s*\w+\s*-|\bslice\s*\(\s*\w+\s*-/i;
  const SAFE_UNDER_RE = /\bif\s*\(.*>=\s*0|\bunsigned\b|\bsize_t\b|\busize\b|\buint\b|\bUint\b|\b>=\s*0\b.*\[|\bMath\.max\s*\(\s*0|\babs\s*\(/i;
  const ingress = nodesOfType(map, 'INGRESS');
  const underreadNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM') &&
    (NEGATIVE_INDEX_RE.test(n.analysis_snapshot || n.code_snapshot) || SIGNED_INDEX_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     BUFFER_NEGATIVE_RE.test(n.analysis_snapshot || n.code_snapshot) || n.node_subtype.includes('buffer') ||
     n.node_subtype.includes('array') || n.attack_surface.includes('array_access'))
  );
  for (const src of ingress) {
    for (const sink of underreadNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!SAFE_UNDER_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (lower bounds check — ensure index >= 0 before buffer access)',
            severity: 'medium',
            description: `User input from ${src.label} may produce a negative index at ${sink.label}, ` +
              `reading before the buffer start. Buffer under-reads leak preceding memory or cause crashes.`,
            fix: 'Validate that indices are non-negative: if (index < 0) return error. ' +
              'Use unsigned types (size_t in C, usize in Rust, uint in Go). ' +
              'Use Math.max(0, index) as a floor in JavaScript.',
            via: 'bfs',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-127', name: 'Buffer Under-read', holds: findings.length === 0, findings };
}

/**
 * CWE-131: Incorrect Calculation of Buffer Size
 * Allocated buffer is too small because size calculation is wrong.
 * Common causes: forgetting null terminator (+1), integer overflow in size*count, wrong sizeof.
 */
function verifyCWE131(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ALLOC_RE = /\b(malloc|calloc|realloc|alloca|new\s+\w+\[|Buffer\.alloc\w*|ArrayBuffer|Uint8Array|allocate)\s*\(/i;
  const DANGER_CALC_RE = /\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)|\bcalloc\s*\(\s*\w+\s*,\s*sizeof|\bstrlen\s*\(\s*\w+\s*\)\s*\)(?!\s*\+\s*1)/i;
  const SAFE_SIZE_RE = /\bchecked_mul\b|\bchecked_add\b|\bsafe_mul\b|\bMath\.min\b.*alloc|\bif\s*\(.*overflow|\bif\s*\(.*MAX_|\bSIZE_MAX\b|\bcalloc\b.*\bsizeof\b|\bstrlen\b.*\+\s*1|\bsizeof\b.*\+\s*1|\bBuffer\.alloc\b(?!Unsafe)/i;
  const ingress = nodesOfType(map, 'INGRESS');
  const allocNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (ALLOC_RE.test(n.analysis_snapshot || n.code_snapshot) || n.node_subtype.includes('alloc') ||
     n.node_subtype.includes('memory') || n.attack_surface.includes('allocation'))
  );
  for (const src of ingress) {
    for (const sink of allocNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!SAFE_SIZE_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (validated size calculation — check for overflow, off-by-one, encoding width)',
            severity: 'critical',
            description: `User input from ${src.label} influences buffer size calculation at ${sink.label}. ` +
              `Incorrect size causes buffer overflows (too small) or memory waste (too large).`,
            fix: 'Use checked arithmetic (checked_mul in Rust, __builtin_mul_overflow in GCC). ' +
              'Always add +1 for null terminator. Use calloc(count, size) instead of malloc(count*size). ' +
              'Cap maximum allocation size.',
            via: 'bfs',
          });
        }
      }
    }
  }
  if (findings.length === 0) {
    for (const node of allocNodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (DANGER_CALC_RE.test(code) && !SAFE_SIZE_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (safe size calculation — use calloc or checked arithmetic)',
          severity: 'high',
          description: `Buffer size calculation at ${node.label} may be incorrect. ` +
            `malloc(a*b) can overflow; strlen(s) without +1 forgets the null terminator.`,
          fix: 'Use calloc(count, size) instead of malloc(count*size). ' +
            'Always add 1 to strlen() for null-terminated string allocation.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-131', name: 'Incorrect Calculation of Buffer Size', holds: findings.length === 0, findings };
}

/**
 * CWE-190: Integer Overflow or Wraparound
 * Integer value increases past its maximum, wrapping to a small/negative value.
 * When used as buffer size or loop bound, causes overflow or infinite loops.
 */
function verifyCWE190(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SIZE_ARITH_RE = /\b(size|count|len|length|offset|index|width|height|num|total)\w*\s*[\*\+]|\b[\*\+]\s*\w*(size|count|len|length|num)\b/i;
  const CAST_WIDEN_RE = /\(\s*(int|short|int16_t|int32_t|uint16_t|uint32_t|i16|i32|u16|u32)\s*\)/i;
  const ARITH_RE = /\b\w+\s*[\*\+]\s*\w+|\b\w+\s*\+=\s*\w+|\b\w+\s*\*=\s*\w+|\b\w+\s*<<\s*\w+/;
  const OVERFLOW_SAFE_RE = /\bchecked_add\b|\bchecked_mul\b|\bsaturating_add\b|\bsaturating_mul\b|\b__builtin_\w+_overflow\b|\bSafeInt\b|\bNumber\.isSafeInteger\b|\bMAX_SAFE_INTEGER\b|\bif\s*\(.*>\s*MAX|\bif\s*\(.*>\s*INT_MAX|\bif\s*\(.*>\s*SIZE_MAX|\bif\s*\(.*overflow|\bclamp\b|\bMath\.min\b/i;
  const ingress = nodesOfType(map, 'INGRESS');
  // Cast-narrow patterns: (byte)(...+...), (short)(...+...) — narrowing casts on arithmetic
  // are the classic Java integer overflow pattern. The cast truncates the result.
  const CAST_NARROW_ARITH_RE = /\(\s*(byte|short|char)\s*\)\s*\([^)]*[\+\*\-][^)]*\)/i;
  // String concatenation exclusion: if the code contains a string literal immediately
  // before/after a + operator, this is string concat, NOT integer arithmetic.
  // Matches: "..." + var, var + "...", '...' + var, `...` + var
  const STRING_CONCAT_RE = /["'`]\s*\+\s*\w|\w\s*\+\s*["'`]/;
  // SQL/query/command/HTML string-building assignments — not arithmetic
  const SQL_CONCAT_RE = /\b(sql|query|statement|stmt|cmd|command|html|xml|xpath|ldap|url|uri|path|redirect|location|header)\w*\s*[=+]/i;
  const arithNodes = map.nodes.filter(n => {
    // Include RESOURCE nodes: Buffer.alloc(size + 1) is classified RESOURCE/memory
    // and contains integer arithmetic used as a size argument.
    if (n.node_type !== 'TRANSFORM' && n.node_type !== 'STORAGE' && n.node_type !== 'RESOURCE') return false;
    const snap = n.analysis_snapshot || n.code_snapshot;
    // Exclude nodes that are clearly string concatenation, not integer arithmetic.
    // The + operator in "SELECT * FROM " + data is NOT integer overflow.
    // Only exclude when there's no numeric cast (casts confirm actual arithmetic intent).
    const isStringConcat = STRING_CONCAT_RE.test(snap) || SQL_CONCAT_RE.test(snap);
    const hasNumericCast = CAST_WIDEN_RE.test(snap) || CAST_NARROW_ARITH_RE.test(snap);
    if (isStringConcat && !hasNumericCast) return false;
    return (
      SIZE_ARITH_RE.test(snap) ||
      (ARITH_RE.test(snap) && CAST_WIDEN_RE.test(snap)) ||
      // Narrowing cast on arithmetic: (byte)(data + 1), (short)(x * y) — classic overflow
      CAST_NARROW_ARITH_RE.test(snap) ||
      // Simple arithmetic on user-controlled data in variable assignments
      // BUT exclude string concatenation (var = "..." + data is not arithmetic)
      (n.node_subtype === 'assignment' && ARITH_RE.test(snap) && !isStringConcat) ||
      n.node_subtype.includes('arithmetic') || n.node_subtype.includes('numeric') ||
      n.node_subtype.includes('integer') || n.attack_surface.includes('numeric_operation') ||
      // Buffer.alloc/allocUnsafe with arithmetic argument is a direct integer overflow sink
      /\bBuffer\.(alloc|allocUnsafe)\s*\([^)]*[\*\+\-][^)]*\)/.test(snap)
    );
  });
  // Also check STRUCTURAL/function nodes whose analysis_snapshot contains
  // unchecked arithmetic — the arithmetic may be inside a local_variable_declaration
  // that doesn't create a TRANSFORM node (e.g., Java: byte result = (byte)(data + 1)).
  // Function-level fallback: only match CAST patterns (narrowing cast on arithmetic).
  // The generic \b\w+\s*[\+\*]\s*\w+ pattern matches string concat and is too broad
  // for scanning entire function bodies. Restrict to the high-signal cast patterns.
  const FUNC_ARITH_RE = /\(\s*(byte|short|char|int|long)\s*\)\s*\([^)]*[\+\*\-][^)]*\)/;
  // Real bounds check pattern: if (data < MAX_VALUE) or if (data > 0 && data < MAX)
  const REAL_BOUNDS_CHECK_RE = /\bif\s*\(.*\b(MAX_VALUE|MIN_VALUE|MAX_SAFE_INTEGER|INT_MAX|SIZE_MAX|overflow)\b|\bchecked_add\b|\bchecked_mul\b|\bsaturating_add\b|\bsaturating_mul\b|\b__builtin_\w+_overflow\b|\bSafeInt\b|\bNumber\.isSafeInteger\b|\bclamp\b|\bMath\.min\b/i;

  for (const src of ingress) {
    for (const sink of arithNodes) {
      if (src.id === sink.id) continue;
      const hasBfs190 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const hasScope190 = sharesFunctionScope(map, src.id, sink.id);
      if (hasBfs190 || hasScope190) {
        // Check the sink AND the function scope for safety patterns.
        // Only count REAL bounds checks, not NumberFormatException catches or generic error handling.
        const scopeSafe = OVERFLOW_SAFE_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) ||
          map.nodes.some(n =>
            n.id !== sink.id &&
            sharesFunctionScope(map, sink.id, n.id) &&
            OVERFLOW_SAFE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
          );
        if (!scopeSafe) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (integer overflow check before arithmetic)',
            severity: 'high',
            description: `User input from ${src.label} feeds into arithmetic at ${sink.label} without overflow protection. ` +
              `Result exceeding the type's maximum wraps to small/negative value, causing buffer overflow or infinite loops.`,
            fix: 'Use checked arithmetic: checked_add/checked_mul in Rust, __builtin_*_overflow in GCC. ' +
              'Validate input ranges before arithmetic. Use Number.isSafeInteger() in JS. ' +
              'Use int64 or BigInt for intermediate calculations.',
            via: hasBfs190 ? 'bfs' : 'scope_taint',
          });
        }
      }
    }

    // Fallback: check STRUCTURAL/function nodes containing arithmetic for cases
    // where no TRANSFORM node was created (e.g., Java local_variable_declaration
    // with cast+arithmetic: byte result = (byte)(data + 1))
    if (arithNodes.length === 0) {
      const funcNodes = map.nodes.filter(n => {
        if (n.node_type !== 'STRUCTURAL' || n.node_subtype !== 'function') return false;
        const snap = n.analysis_snapshot || '';
        if (!FUNC_ARITH_RE.test(snap)) return false;
        // Exclude functions whose only "arithmetic" is string concatenation
        // e.g., "SELECT * FROM " + data is string concat, not integer overflow
        const isStringConcat = STRING_CONCAT_RE.test(snap) || SQL_CONCAT_RE.test(snap);
        const hasNumericCast = CAST_WIDEN_RE.test(snap) || CAST_NARROW_ARITH_RE.test(snap);
        if (isStringConcat && !hasNumericCast) return false;
        return true;
      });
      for (const funcNode of funcNodes) {
        const hasScope190f = sharesFunctionScope(map, src.id, funcNode.id);
        const hasBfs190f = hasTaintedPathWithoutControl(map, src.id, funcNode.id);
        if (hasScope190f || hasBfs190f) {
          const funcCode = stripComments(funcNode.analysis_snapshot || funcNode.code_snapshot);
          // Only count REAL bounds checks as overflow protection.
          // NumberFormatException catch is parse error handling, NOT overflow protection.
          const hasBoundsCheck = REAL_BOUNDS_CHECK_RE.test(funcCode);
          if (!hasBoundsCheck) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(funcNode),
              missing: 'CONTROL (integer overflow check before arithmetic)',
              severity: 'high',
              description: `User input from ${src.label} feeds into arithmetic in ${funcNode.label} without overflow protection. ` +
                `Result exceeding the type's maximum wraps to small/negative value, causing buffer overflow or infinite loops.`,
              fix: 'Use checked arithmetic or validate input ranges before arithmetic. ' +
                'Compare against MAX_VALUE/MIN_VALUE before operations that could overflow.',
              via: hasBfs190f ? 'bfs' : 'scope_taint',
            });
          }
        }
      }
    }
  }
  return { cwe: 'CWE-190', name: 'Integer Overflow or Wraparound', holds: findings.length === 0, findings };
}

/**
 * CWE-191: Integer Underflow (Wrap or Wraparound)
 * Integer value decreases below its minimum, wrapping to a large positive (unsigned) value.
 * Classic pattern: unsigned len = packet_length - header_size; // wraps if packet < header
 */
function verifyCWE191(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SUB_RE = /\b\w+\s*-\s*\w+|\b\w+\s*-=\s*\w+/;
  const MUL_RE = /\b\w+\s*\*\s*\w+|\b\w+\s*\*=\s*\w+/;
  const ADD_RE = /\b\w+\s*\+\s*\w+|\b\w+\s*\+=\s*\w+/;
  const NARROW_CAST_ARITH_RE = /\(\s*(byte|short|char)\s*\)\s*\([^)]*[\*\+\-][^)]*\)/i;
  const SIZE_SUB_RE = /\b(size|count|len|length|offset|remaining|available)\w*\s*-|\b-\s*\w*(size|count|len|length|header)\b/i;
  const UNSIGNED_SUB_RE = /\b(size_t|unsigned|uint\d*|usize|u32|u64|uint)\b.*-/i;
  const UNDERFLOW_SAFE_RE = /\bif\s*\(.*>=\s*\w+|\bif\s*\(.*>\s*\w+.*-|\bchecked_sub\b|\bsaturating_sub\b|\b__builtin_sub_overflow\b|\bMath\.max\s*\(\s*0|\bif\s*\(\s*\w+\s*>=?\s*\w+\s*\).*-/i;
  const MUL_ADD_SAFE_RE = /\bMIN_VALUE\s*\/|\bMAX_VALUE\s*\/|\bMIN_VALUE\s*\+|\bMAX_VALUE\s*-|\bchecked_mul\b|\bsaturating_mul\b|\b__builtin_mul_overflow\b|\bMath\.multiplyHigh\b|\bchecked_add\b|\bsaturating_add\b|\b__builtin_add_overflow\b|\baddExact\b|\bmultiplyExact\b|\bsubtractExact\b/i;
  // Function-level fallback: only match CAST patterns (narrowing cast on arithmetic).
  // The generic \b\w+\s*[\+\*\-]\s*\w+ pattern matches string concat and is too broad.
  const FUNC_ARITH_RE = /\(\s*(byte|short|char|int|long)\s*\)\s*\([^)]*[\+\*\-][^)]*\)/;
  const REAL_BOUNDS_CHECK_RE = /\bif\s*\(.*\b(MIN_VALUE|MAX_VALUE)\b.*\/|\bif\s*\(.*\b(MIN_VALUE|MAX_VALUE)\b|\bchecked_sub\b|\bchecked_mul\b|\bchecked_add\b|\bsaturating_sub\b|\bsaturating_mul\b|\bsaturating_add\b|\b__builtin_\w+_overflow\b|\baddExact\b|\bmultiplyExact\b|\bsubtractExact\b/i;
  const ingress = nodesOfType(map, 'INGRESS');
  // Strip string literals to avoid false matches on e.g. "UTF-8" matching subtraction regex
  const stripStrLit = (s: string) => s.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '""');
  // String concatenation exclusion — same logic as CWE-190
  const STRING_CONCAT_RE = /["'`]\s*\+\s*\w|\w\s*\+\s*["'`]/;
  const SQL_CONCAT_RE = /\b(sql|query|statement|stmt|cmd|command|html|xml|xpath|ldap|url|uri|path|redirect|location|header)\w*\s*[=+]/i;
  const CAST_WIDEN_RE_191 = /\(\s*(int|short|int16_t|int32_t|uint16_t|uint32_t|i16|i32|u16|u32)\s*\)/i;
  const arithNodes = map.nodes.filter(n => {
    if (n.node_subtype.includes('arithmetic') || n.node_subtype.includes('numeric') ||
        n.attack_surface.includes('numeric_operation')) return true;
    if (n.node_type !== 'TRANSFORM' && n.node_type !== 'STORAGE' && n.node_type !== 'RESOURCE') return false;
    const rawSnap = n.analysis_snapshot || n.code_snapshot;
    // Exclude string concatenation: "SELECT * FROM " + data is NOT integer underflow.
    const isStringConcat = STRING_CONCAT_RE.test(rawSnap) || SQL_CONCAT_RE.test(rawSnap);
    const hasNumericCast = CAST_WIDEN_RE_191.test(rawSnap) || NARROW_CAST_ARITH_RE.test(rawSnap);
    if (isStringConcat && !hasNumericCast) return false;
    const snap = stripStrLit(rawSnap);
    return SIZE_SUB_RE.test(snap) || UNSIGNED_SUB_RE.test(snap) ||
      MUL_RE.test(snap) || ADD_RE.test(snap) ||
      NARROW_CAST_ARITH_RE.test(snap) ||
      (n.node_subtype === 'assignment' && (MUL_RE.test(snap) || SUB_RE.test(snap)));
  });
  for (const src of ingress) {
    for (const sink of arithNodes) {
      if (src.id === sink.id) continue;
      const hasBfs191 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const hasScope191 = sharesFunctionScope(map, src.id, sink.id);
      if (hasBfs191 || hasScope191) {
        const code = stripStrLit(stripComments(sink.analysis_snapshot || sink.code_snapshot));
        const scopeSafe = MUL_ADD_SAFE_RE.test(code) || UNDERFLOW_SAFE_RE.test(code) ||
          map.nodes.some(n =>
            n.id !== sink.id &&
            sharesFunctionScope(map, sink.id, n.id) &&
            (MUL_ADD_SAFE_RE.test(stripStrLit(stripComments(n.analysis_snapshot || n.code_snapshot))) ||
             UNDERFLOW_SAFE_RE.test(stripStrLit(stripComments(n.analysis_snapshot || n.code_snapshot))))
          );
        if (scopeSafe) continue;
        if (SUB_RE.test(code)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (underflow check — verify minuend >= subtrahend before subtraction)',
            severity: 'high',
            description: `User input from ${src.label} influences subtraction at ${sink.label} without underflow protection. ` +
              `Unsigned wrap to huge value causes massive allocations or out-of-bounds access.`,
            fix: 'Check before subtracting: if (a < b) return error, else result = a - b. ' +
              'Use checked_sub/saturating_sub in Rust. Use Math.max(0, a - b) in JS.',
            via: hasBfs191 ? 'bfs' : 'scope_taint',
          });
        }
        if (MUL_RE.test(code)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (underflow check — verify value > MIN_VALUE/multiplier before multiplication)',
            severity: 'high',
            description: `User input from ${src.label} influences multiplication at ${sink.label} without underflow protection. ` +
              `Multiplying a negative value can wrap past MIN_VALUE causing integer underflow.`,
            fix: 'Check before multiplying: if (data > (MIN_VALUE / N)) { result = data * N; }. ' +
              'Use Math.multiplyExact() in Java, checked_mul in Rust.',
            via: hasBfs191 ? 'bfs' : 'scope_taint',
          });
        }
      }
    }

    // Fallback: check STRUCTURAL/function nodes containing arithmetic for cases
    // where no TRANSFORM node was created (e.g., Java local_variable_declaration
    // with cast+arithmetic: byte result = (byte)(data * 2))
    if (arithNodes.length === 0) {
      const funcNodes = map.nodes.filter(n => {
        if (n.node_type !== 'STRUCTURAL' || n.node_subtype !== 'function') return false;
        const snap = n.analysis_snapshot || '';
        if (!FUNC_ARITH_RE.test(snap)) return false;
        // Exclude functions whose only "arithmetic" is string concatenation
        const isStrConcat = STRING_CONCAT_RE.test(snap) || SQL_CONCAT_RE.test(snap);
        const hasCast = CAST_WIDEN_RE_191.test(snap) || NARROW_CAST_ARITH_RE.test(snap);
        if (isStrConcat && !hasCast) return false;
        return true;
      });
      for (const funcNode of funcNodes) {
        const hasScope191f = sharesFunctionScope(map, src.id, funcNode.id);
        const hasBfs191f = hasTaintedPathWithoutControl(map, src.id, funcNode.id);
        if (hasScope191f || hasBfs191f) {
          const funcCode = stripComments(funcNode.analysis_snapshot || funcNode.code_snapshot);
          // Only count REAL bounds checks (MIN_VALUE/MAX_VALUE comparisons) as underflow protection.
          // NumberFormatException catch is parse error handling, NOT underflow protection.
          const hasBoundsCheck = REAL_BOUNDS_CHECK_RE.test(funcCode);
          if (!hasBoundsCheck) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(funcNode),
              missing: 'CONTROL (underflow check — verify bounds before arithmetic on narrow type)',
              severity: 'high',
              description: `User input from ${src.label} feeds into arithmetic in ${funcNode.label} without underflow protection. ` +
                `Arithmetic on narrow types (byte/short) without MIN_VALUE/MAX_VALUE bounds checks can wrap, causing integer underflow.`,
              fix: 'Check before arithmetic: if (data > (MIN_VALUE / N)) { result = data * N; }. ' +
                'Use Math.multiplyExact/addExact/subtractExact in Java, checked_* in Rust.',
              via: hasBfs191f ? 'bfs' : 'scope_taint',
            });
          }
        }
      }
    }
  }
  return { cwe: 'CWE-191', name: 'Integer Underflow (Wrap or Wraparound)', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-192: Integer Coercion Error
//
// Value is converted (coerced) between integer types and the conversion
// changes the value — truncation, sign change, or widening of a negative
// value to a large unsigned. Distinct from CWE-190 (overflow from arithmetic):
// this is about the CAST itself, not the math.
// ---------------------------------------------------------------------------

function verifyCWE192(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Dangerous narrowing casts (C/C++/Java/C#)
  const NARROW_CAST = /\(\s*(char|byte|short|int8_t|int16_t|uint8_t|uint16_t|i8|i16|u8|u16|BYTE|WORD)\s*\)\s*\w+/i;
  // Assignment to narrower type from wider expression
  const NARROW_ASSIGN = /\b(char|byte|short|int8_t|int16_t|uint8_t|uint16_t)\s+\w+\s*=\s*(?!.*\b(char|byte|short|int8_t|int16_t|uint8_t|uint16_t)\b)/i;
  // JavaScript-specific: bitwise ops that coerce to 32-bit int
  const JS_BITWISE_COERCE = /\b\w+\s*(?:\|0|\^0|>>0|>>>0|<<0)\b/;
  // parseInt without radix or with large values
  const PARSE_INT_TRUNC = /\bparseInt\s*\(\s*\w+\s*\)|\bNumber\(\s*\w+\s*\)\s*(?:\||\^|>>|<<)/;
  // Python int() from float — silent truncation
  const PY_INT_TRUNC = /\bint\s*\(\s*(?:float|math\.|numpy\.|np\.)/i;

  // Safe patterns
  const SAFE_COERCE = /\bif\s*\(.*(?:>|<|>=|<=)\s*(?:MAX|MIN|INT_MAX|INT_MIN|CHAR_MAX|SHORT_MAX|UINT8_MAX|UINT16_MAX|0xff|0xffff|127|255|32767|65535)\b|\bclamp\b|\bMath\.min\b.*Math\.max\b|\bsaturating_|checked_|\bas\s+\w+\s*;.*(?:debug_assert|assert)/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'TRANSFORM' && node.node_type !== 'STORAGE') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_COERCE.test(code)) continue;

    if (NARROW_CAST.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (range check before narrowing cast)',
        severity: 'high',
        description: `${node.label} performs a narrowing cast that may silently truncate or change sign. ` +
          `Casting a 32-bit value to 8-bit drops the upper 24 bits — 256 becomes 0, 257 becomes 1. ` +
          `If the value controls allocation size or loop bounds, this causes buffer overflow.`,
        fix: 'Check the value fits in the target type before casting: if (val > TYPE_MAX || val < TYPE_MIN) error. ' +
          'Use safe_cast<> utilities or Rust\'s try_from() which returns Result.',
        via: 'structural',
      });
    }

    if (JS_BITWISE_COERCE.test(code)) {
      const isAttackSurface = node.attack_surface.includes('user_input');
      const hasBfs192 = !isAttackSurface && nodesOfType(map, 'INGRESS').some(src => hasTaintedPathWithoutControl(map, src.id, node.id));
      if (isAttackSurface || hasBfs192) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (validate numeric range before bitwise coercion to Int32)',
          severity: 'medium',
          description: `${node.label} uses bitwise operation to coerce to 32-bit integer. ` +
            `In JavaScript, this silently truncates values > 2^31 - 1 and numbers > 2^53 lose precision. ` +
            `User-controlled values can overflow the 32-bit range.`,
          fix: 'Check Number.isSafeInteger() and validate range before bitwise operations. ' +
            'Consider BigInt for values that may exceed 32 bits.',
          via: hasBfs192 ? 'bfs' : 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-192', name: 'Integer Coercion Error', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-193: Off-by-One Error
//
// A loop condition uses <= array.length (or <= size()) instead of < array.length,
// causing an access one past the end of the buffer. This is a structural/syntactic
// bug — not a taint-flow bug — so we scan raw source lines for the pattern.
//
// Vulnerable patterns:
//   while (i <= arr.length)       — should be <
//   for (i = 0; i <= arr.length)  — should be <
//   while (i < arr.length + 1)    — equivalent off-by-one
//   for (i = 0; i <= sizeof(buf)) — C/C++ variant
//
// Safe patterns:
//   while (i < arr.length)        — correct strict bound
//   while (i <= arr.length - 1)   — correct adjusted bound
// ---------------------------------------------------------------------------

function verifyCWE193(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  if (!map.source_code) {
    return { cwe: 'CWE-193', name: 'Off-by-One Error', holds: true, findings };
  }

  const src = stripComments(map.source_code);
  const lines = src.split('\n');

  // Vulnerable: <= *.length, <= *.size(), <= sizeof(...)
  // These should be < not <= when used as loop bounds on zero-indexed arrays.
  const VULN_LE_LENGTH = /<=\s*\w+\s*\.\s*(length|size\s*\(\s*\)|count|Length|Count|Size)/;
  const VULN_LE_SIZEOF = /<=\s*sizeof\s*\(/;
  // Vulnerable: < *.length + 1 or < *.size() + 1 — equivalent off-by-one
  const VULN_LT_PLUS1 = /<\s*\w+\s*\.\s*(length|size\s*\(\s*\)|count|Length|Count|Size)\s*\+\s*1/;
  // Also: < sizeof(...) + 1
  const VULN_LT_SIZEOF_PLUS1 = /<\s*sizeof\s*\([^)]*\)\s*\+\s*1/;

  // Safe: <= *.length - 1 (adjusted bound is correct)
  const SAFE_LE_MINUS1 = /<=\s*\w+\s*\.\s*(length|size\s*\(\s*\)|count|Length|Count|Size)\s*-\s*1/;
  const SAFE_LE_SIZEOF_MINUS1 = /<=\s*sizeof\s*\([^)]*\)\s*-\s*1/;

  // Only flag lines that are in loop conditions (while, for, do-while)
  const LOOP_CONTEXT = /\b(while|for)\s*\(/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip blank lines and pure comment lines (residual after strip)
    if (!trimmed) continue;

    // Must be in a loop context — check current line and previous line (for do-while)
    const inLoopContext = LOOP_CONTEXT.test(line);
    // For do-while, the while(...) is on its own line after the closing brace
    const isDoWhile = /^\}?\s*while\s*\(/.test(trimmed);

    if (!inLoopContext && !isDoWhile) continue;

    // Skip safe patterns first (they contain <= but are correct)
    if (SAFE_LE_MINUS1.test(line) || SAFE_LE_SIZEOF_MINUS1.test(line)) continue;

    // Check for vulnerable patterns
    const isVuln = VULN_LE_LENGTH.test(line) || VULN_LE_SIZEOF.test(line) ||
                   VULN_LT_PLUS1.test(line) || VULN_LT_SIZEOF_PLUS1.test(line);

    if (isVuln) {
      const snippet = trimmed.slice(0, 200);
      const lineNum = i + 1;
      findings.push({
        source: { id: `obo-line-${lineNum}`, label: `loop condition (line ${lineNum})`, line: lineNum, code: snippet },
        sink:   { id: `obo-line-${lineNum}`, label: `loop condition (line ${lineNum})`, line: lineNum, code: snippet },
        missing: 'CONTROL (correct boundary — use < length, not <= length)',
        severity: 'high',
        description: `Off-by-one error at line ${lineNum}: loop condition uses <= with array/buffer length ` +
          `(or < length + 1), which iterates one past the last valid index. ` +
          `For zero-indexed arrays, the condition should be < length.`,
        fix: 'Use < array.length (not <= array.length) for zero-indexed loop bounds. ' +
          'If you need to include the last element, use <= array.length - 1. ' +
          'Account for null terminators in C string buffers.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-193', name: 'Off-by-One Error', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-194: Unexpected Sign Extension
//
// A signed value is widened (e.g., int8 to int32) and the sign bit propagates,
// turning a small negative into a very large value. Classic: char c = 0xFF;
// int i = c; // i is -1 (0xFFFFFFFF) if char is signed, 255 if unsigned.
// ---------------------------------------------------------------------------

function verifyCWE194(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Widening from signed to wider type
  const SIGNED_WIDEN = /\(\s*(int|long|int32_t|int64_t|ssize_t|ptrdiff_t|i32|i64|intptr_t|size_t)\s*\)\s*\(?\s*(?:char|int8_t|i8|short|int16_t|i16|signed\s+char)\b/i;
  // Assignment of signed char/short to int/long/size_t
  const SIGNED_ASSIGN = /\b(int|long|int32_t|int64_t|size_t|ssize_t|unsigned)\s+\w+\s*=\s*(?:\w+\s*;).*\b(char|int8_t|short|int16_t|signed)\b/i;
  // char used as array index (may sign-extend)
  const CHAR_INDEX = /\[\s*(?:char|int8_t|signed\s+char)\s+\w+\s*\]|\[\s*\w+\s*\].*\bchar\b/;
  // getchar() or fgetc() stored in char (should be int)
  const GETCHAR_CHAR = /\bchar\s+\w+\s*=\s*(?:getchar|fgetc|getc|fgetwc)\s*\(/;

  const SAFE_PATTERN = /\b(unsigned\s+char|uint8_t|u8)\s+\w+\s*=|\b\(\s*(unsigned\s+char|uint8_t|u8)\s*\)|\b&\s*0[xX]?[fF]{2}\b|\b&\s*255\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_PATTERN.test(code)) continue;

    if (SIGNED_WIDEN.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (mask or cast to unsigned before widening to prevent sign extension)',
        severity: 'high',
        description: `${node.label} widens a signed narrow type to a wider type. If the narrow value has ` +
          `its high bit set (e.g., char 0xFF = -1), sign extension fills the upper bits with 1s, ` +
          `producing 0xFFFFFFFF (-1) instead of 255. This corrupts buffer sizes and array indices.`,
        fix: 'Cast to unsigned first: (int)(unsigned char)c, or mask: (int)(c & 0xFF). ' +
          'Use uint8_t instead of char for byte data.',
        via: 'structural',
      });
    }

    if (GETCHAR_CHAR.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (store getchar/fgetc result in int, not char)',
        severity: 'medium',
        description: `${node.label} stores getchar()/fgetc() result in a char. These functions return int ` +
          `to distinguish EOF (-1) from valid byte 0xFF. Storing in char makes EOF indistinguishable ` +
          `from a valid character, causing infinite loops or premature termination.`,
        fix: 'Use int to store the return value: int c = getchar(); then check for EOF before casting to char.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-194', name: 'Unexpected Sign Extension', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-195: Signed to Unsigned Conversion Error
//
// A signed value (which may be negative) is used where an unsigned value
// is expected. Negative values become very large unsigned values.
// Classic: int len = get_user_length(); malloc(len); // -1 → 0xFFFFFFFF
// ---------------------------------------------------------------------------

function verifyCWE195(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Signed value passed to allocation/size functions
  const SIGNED_TO_SIZE = /\b(malloc|calloc|realloc|alloca|new\s+\w+\[|mmap|VirtualAlloc|HeapAlloc)\s*\(\s*(?:\w+\s*,\s*)*(\w+)\s*[,\)]/;
  // Signed → unsigned assignment or cast
  const SIGNED_TO_UNSIGNED = /\(\s*(unsigned|size_t|uint\d*_t|usize|u32|u64|DWORD|UINT|ULONG)\s*\)\s*(?:\w+)|\b(unsigned|size_t|uint\d*_t|usize|u32|u64)\s+\w+\s*=\s*\w+/i;
  // Signed variable used as array index without check
  const SIGNED_INDEX = /\[\s*(?:int|long|ssize_t|ptrdiff_t|i32|i64)\s+/;

  // Safe: explicit negative check before use
  const SAFE_PATTERN = /\bif\s*\(\s*\w+\s*<\s*0\b|\bif\s*\(\s*\w+\s*<=?\s*0\s*\)|\bassert\s*\(\s*\w+\s*>=?\s*0\b|\bif\s*\(\s*\w+\s*>=\s*0\b.*(?:malloc|calloc|size|\[)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_PATTERN.test(code)) continue;

    const allocMatch = code.match(SIGNED_TO_SIZE);
    if (allocMatch) {
      // Check if the variable is likely signed
      const varName = allocMatch[2];
      const signedDecl = new RegExp(`\\b(int|long|ssize_t|ptrdiff_t|i32|i64|int32_t|int64_t)\\s+${varName}\\b`);
      if (signedDecl.test(code) || /\bint\s+\w+\s*=/.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (check value >= 0 before using signed integer as size/length)',
          severity: 'critical',
          description: `${node.label} passes a potentially signed integer to an allocation function. ` +
            `A negative value (e.g., -1) becomes a huge unsigned value (4,294,967,295), causing ` +
            `either allocation failure or massive over-allocation exploitable for heap overflow.`,
          fix: 'Validate: if (len < 0 || len > MAX_REASONABLE_SIZE) return error; before allocation. ' +
            'Use size_t for all size variables. Apply input validation at the boundary.',
          via: 'structural',
        });
      }
    }

    if (SIGNED_TO_UNSIGNED.test(code)) {
      const hasNegativeCheck = /if\s*\(.*<\s*0|if\s*\(.*>=\s*0|assert.*>=?\s*0/i.test(code);
      if (!hasNegativeCheck && /\b(size|len|count|offset|index|alloc|buffer|capacity)\b/i.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (validate non-negative before signed-to-unsigned conversion)',
          severity: 'high',
          description: `${node.label} converts a signed integer to unsigned in a size/offset context. ` +
            `Negative values silently become very large positive values, bypassing bounds checks.`,
          fix: 'Check for negative values before conversion. Use unsigned types from the start for sizes. ' +
            'In Rust, use usize and TryFrom with error handling.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-195', name: 'Signed to Unsigned Conversion Error', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-196: Unsigned to Signed Conversion Error
//
// An unsigned value is assigned to a signed variable. If the value exceeds
// the signed maximum, it wraps to negative. Classic: unsigned int file_size
// = 3GB; int size = file_size; // size becomes negative → bypasses checks.
// ---------------------------------------------------------------------------

function verifyCWE196(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Unsigned → signed assignment or cast
  const UNSIGNED_TO_SIGNED = /\(\s*(int|long|short|int32_t|int64_t|ssize_t|i32|i64)\s*\)\s*(?:unsigned|size_t|uint\d*_t|usize|u32|u64|DWORD|UINT|ULONG)\b/i;
  const UNSIGNED_ASSIGN = /\b(int|long|short|int32_t|int64_t|ssize_t|i32|i64)\s+\w+\s*=\s*(?:\w+).*\b(unsigned|size_t|uint\d*_t|usize|u32|u64|DWORD|UINT|ULONG)\b/i;
  // size_t / unsigned value compared with signed (may always be true/false)
  const UNSIGNED_CMP = /\b(size_t|unsigned|uint\d*_t|usize|u32|u64|DWORD)\s+\w+\s*.*(?:<\s*0|>=\s*0)/i;

  const SAFE_PATTERN = /\bif\s*\(\s*\w+\s*(?:>|<=)\s*(?:INT_MAX|INT32_MAX|LONG_MAX|i32::MAX|i64::MAX|0x7[fF]{7}|0x7[fF]{15}|2147483647)\b|\btry_from\b|\btry_into\b|\bsafe_cast\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_PATTERN.test(code)) continue;

    if (UNSIGNED_TO_SIGNED.test(code) || UNSIGNED_ASSIGN.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (check value <= SIGNED_MAX before unsigned-to-signed conversion)',
        severity: 'high',
        description: `${node.label} converts an unsigned integer to signed. Values exceeding the signed ` +
          `maximum (e.g., 3GB as unsigned → negative as signed) wrap to negative, bypassing ` +
          `"if (size < MAX)" checks that assume positive values.`,
        fix: 'Validate before conversion: if (uval > INT_MAX) return error. ' +
          'Use same-signedness types throughout. In Rust, use TryFrom/TryInto.',
        via: 'structural',
      });
    }

    if (UNSIGNED_CMP.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (unsigned values are never negative — comparison is always true/false)',
        severity: 'medium',
        description: `${node.label} compares an unsigned value against 0 with < or >=. Unsigned values ` +
          `are never negative, so "unsigned x; if (x >= 0)" is always true and "if (x < 0)" is ` +
          `always false. This is a logic error that may hide a real bounds check.`,
        fix: 'Remove the tautological comparison. Check the actual upper bound instead, or convert ' +
          'to the correct signedness if negative values are expected.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-196', name: 'Unsigned to Signed Conversion Error', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-197: Numeric Truncation Error
//
// A value is stored in a smaller numeric type, losing significant bits.
// Distinct from CWE-192 (which is about the cast) — this is about the
// LOSS of data when a high-precision value is stored in a low-precision
// container. E.g., double → float loses precision, int64 → int32 loses range.
// ---------------------------------------------------------------------------

function verifyCWE197(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Float truncation
  const DOUBLE_TO_FLOAT = /\(\s*float\s*\)\s*\w+|\bfloat\s+\w+\s*=\s*(?:\w+\s*;).*\bdouble\b|\bf32\s+.*\bf64\b/i;
  // 64-bit to 32-bit truncation
  const INT64_TO_32 = /\(\s*(int|int32_t|i32|uint32_t|u32|DWORD)\s*\)\s*\(?\s*(?:\w+).*\b(long\s+long|int64_t|i64|uint64_t|u64|size_t|__int64)\b/i;
  // Java/C narrowing cast: int/long to byte, short, or char (e.g. (byte)data, (short)val)
  const NARROWING_CAST = /\(\s*(byte|short|char|int8_t|int16_t|uint8_t|uint16_t)\s*\)\s*\w+/;
  // Large return truncated to small
  const TRUNCATED_RETURN = /\b(int|short|char|int32_t|int16_t|int8_t)\s+\w+\s*\(\s*\).*return\s+\w+/;
  // JavaScript: large number operations that lose precision
  const JS_PRECISION_LOSS = /\bNumber\(\s*\w+\s*\).*(?:id|key|timestamp|snowflake)|\b(?:id|key|timestamp|snowflake)\w*\s*=\s*(?:parseInt|Number|\+)\s*\(/i;

  const SAFE_PATTERN = /\bif\s*\(.*(?:>|<=?)\s*(?:FLT_MAX|FLOAT_MAX|INT32_MAX|INT_MAX|MAX_SAFE_INTEGER|Number\.MAX_SAFE_INTEGER|2147483647|f32::MAX|Byte\.MIN_VALUE|Byte\.MAX_VALUE|Short\.MIN_VALUE|Short\.MAX_VALUE|Character\.MIN_VALUE|Character\.MAX_VALUE|CHAR_MAX|SCHAR_MAX|SHRT_MAX|UCHAR_MAX|USHRT_MAX)\b|\bBigInt\b|\btry_from\b|\btry_into\b|\bsafe_cast\b|\bnarrow_cast\b|\bMath\.toIntExact\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_PATTERN.test(code)) continue;

    if (DOUBLE_TO_FLOAT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate value fits in float range/precision before narrowing)',
        severity: 'medium',
        description: `${node.label} truncates double to float. Float has only ~7 decimal digits of precision ` +
          `vs double's ~15. Values like 16777217.0 become 16777216.0 as float. In financial or ` +
          `scientific code, this silent precision loss causes incorrect results.`,
        fix: 'Keep double precision throughout. If float is required, validate the value fits in float ' +
          'range and the precision loss is acceptable. Document the expected precision.',
        via: 'structural',
      });
    }

    if (INT64_TO_32.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate 64-bit value fits in 32-bit before truncation)',
        severity: 'high',
        description: `${node.label} truncates a 64-bit integer to 32 bits. Values above 2^31 (or 2^32 ` +
          `unsigned) silently lose their upper 32 bits. A file size of 5GB (0x140000000) becomes ` +
          `0x40000000 (1GB) — security checks on the truncated value are meaningless.`,
        fix: 'Validate before truncation: if (val > INT32_MAX) error. Use 64-bit types consistently. ' +
          'For IDs that may exceed 32 bits, use string representation.',
        via: 'structural',
      });
    }

    if (NARROWING_CAST.test(code)) {
      const m = code.match(NARROWING_CAST);
      const targetType = m ? m[1] : 'smaller type';
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: `CONTROL (validate value fits in ${targetType} range before narrowing cast)`,
        severity: 'medium',
        description: `${node.label} narrows a value to ${targetType} via cast. ` +
          `Java/C narrowing casts silently discard upper bits — an int value of 256 becomes 0 ` +
          `when cast to byte, and -129 becomes 127. Data from external sources (network, file, ` +
          `user input) can be any value, making unchecked narrowing a truncation vulnerability.`,
        fix: `Validate before cast: if (val < ${targetType === 'byte' ? 'Byte' : targetType === 'short' ? 'Short' : 'Character'}.MIN_VALUE || val > ${targetType === 'byte' ? 'Byte' : targetType === 'short' ? 'Short' : 'Character'}.MAX_VALUE) error. ` +
          'Use the wider type throughout, or use Math.toIntExact() for long-to-int in Java.',
        via: 'structural',
      });
    }

    if (JS_PRECISION_LOSS.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use BigInt or string for IDs/timestamps exceeding 2^53)',
        severity: 'medium',
        description: `${node.label} converts a large numeric ID/timestamp to JavaScript Number. ` +
          `JS Numbers are IEEE 754 doubles with 53 bits of integer precision. Snowflake IDs, ` +
          `database bigints, and epoch-nanosecond timestamps lose precision above 2^53.`,
        fix: 'Use BigInt for arithmetic on large integers. Keep IDs as strings in JSON. ' +
          'Use Number.isSafeInteger() to validate before numeric operations.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-197', name: 'Numeric Truncation Error', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-198: Use of Incorrect Byte Ordering
//
// Multi-byte values (integers, floats) are read/written without proper
// endianness conversion. Little-endian data interpreted as big-endian
// (or vice versa) produces wildly incorrect values.
// Classic: reading network data (big-endian) on x86 (little-endian)
// without ntohl/ntohs.
// ---------------------------------------------------------------------------

function verifyCWE198(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Raw multi-byte read from buffer/network without byte-order conversion
  const RAW_MULTI_READ = /\*\(\s*(?:int|uint32_t|uint16_t|int32_t|int16_t|short|long|float|double|u32|u16|i32|i16)\s*\*\s*\)\s*(?:buf|buffer|data|packet|payload|ptr|p\b)/i;
  // memcpy into integer type from buffer
  const MEMCPY_INT = /memcpy\s*\(\s*&?\s*\w+\s*,\s*(?:buf|buffer|data|packet|payload|ptr)\s*(?:\+|\[)/i;
  // Binary read without byte-order handling
  const BINARY_READ = /\b(fread|recv|recvfrom|read)\s*\(\s*(?:&?\s*\w+|(?:char|void)\s*\*)\s*,.*sizeof\s*\(\s*(?:int|uint32_t|uint16_t|short|long|float|double)\s*\)/i;
  // DataView without explicit endianness (JS — DataView.getInt32 without 2nd arg defaults to big-endian)
  const DATAVIEW_NO_ENDIAN = /\.get(?:Int|Uint|Float)(?:16|32|64)\s*\(\s*\w+\s*\)/;
  // Buffer.read without explicit endian method (Node.js)
  const BUFFER_READ = /\bbuf(?:fer)?\.read(?:Int|UInt|Float|Double)(?:16|32)(?:BE|LE)\b/;

  // Safe patterns
  const SAFE_ENDIAN = /\b(ntohl|ntohs|htonl|htons|be16toh|be32toh|be64toh|le16toh|le32toh|le64toh|htobe|htole|ByteOrder|endian|from_be_bytes|from_le_bytes|to_be_bytes|to_le_bytes|swap_bytes|BinaryPrimitives|BitConverter)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_ENDIAN.test(code)) continue;
    // Buffer.readInt32BE/LE is already endian-explicit — that's fine
    if (BUFFER_READ.test(code)) continue;

    if (RAW_MULTI_READ.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (convert byte order with ntohl/ntohs or equivalent)',
        severity: 'high',
        description: `${node.label} reads multi-byte values from a buffer by casting to an integer pointer. ` +
          `This assumes the buffer's byte order matches the CPU's. Network data is big-endian; x86 is ` +
          `little-endian. A 32-bit value 0x01020304 reads as 0x04030201 — completely wrong.`,
        fix: 'Use ntohl/ntohs (network→host) or htonl/htons (host→network). ' +
          'In Rust, use from_be_bytes/from_le_bytes. In JS, use DataView with explicit endianness arg.',
        via: 'structural',
      });
    }

    if (MEMCPY_INT.test(code)) {
      const hasEndianConvert = /ntoh|hton|bswap|swap.*byte|endian/i.test(code);
      if (!hasEndianConvert) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (apply byte-order conversion after memcpy from network/file buffer)',
          severity: 'medium',
          description: `${node.label} copies raw bytes from a buffer into an integer variable via memcpy ` +
            `without byte-order conversion. If the data source has different endianness, the resulting ` +
            `integer value will be wrong.`,
          fix: 'After memcpy, convert: value = ntohl(value) for 32-bit, ntohs(value) for 16-bit. ' +
            'Or use struct packing/unpacking with explicit byte order.',
          via: 'structural',
        });
      }
    }

    if (DATAVIEW_NO_ENDIAN.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (specify endianness in DataView.getInt/getUint calls)',
        severity: 'medium',
        description: `${node.label} uses DataView.getInt/getUint without specifying the littleEndian parameter. ` +
          `The default is big-endian (network byte order), which may not match the data source. ` +
          `Most binary file formats and protocols have specific endianness requirements.`,
        fix: 'Always pass the littleEndian parameter: view.getInt32(offset, true) for little-endian, ' +
          'view.getInt32(offset, false) for big-endian. Document which endianness the format uses.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-198', name: 'Use of Incorrect Byte Ordering', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-681: Incorrect Conversion between Numeric Types
//
// Tainted data (from user input / INGRESS) undergoes a narrowing numeric cast
// without prior range validation. This is the conversion-focused sibling of
// CWE-197 (truncation). CWE-681 specifically requires the converted value to
// originate from an untrusted source.
// Patterns: (float)double, (int)long, (byte)int, (short)int on tainted data
// ---------------------------------------------------------------------------

function verifyCWE681(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Narrowing cast patterns
  const DOUBLE_TO_FLOAT = /\(\s*float\s*\)\s*\w+/i;
  const INT64_TO_32 = /\(\s*(int|int32_t|i32|uint32_t|u32|DWORD)\s*\)\s*\w+/i;
  const NARROWING_CAST = /\(\s*(byte|short|char|int8_t|int16_t|uint8_t|uint16_t)\s*\)\s*\w+/;
  const ANY_NARROWING = /\(\s*(float|int|int32_t|i32|uint32_t|u32|DWORD|byte|short|char|int8_t|int16_t|uint8_t|uint16_t)\s*\)\s*\w+/i;

  // Safe: range check before cast
  const SAFE_PATTERN = /\bif\s*\(.*(?:>|<|>=|<=)\s*(?:Float\.MAX_VALUE|Float\.MIN_VALUE|Integer\.MAX_VALUE|Integer\.MIN_VALUE|Byte\.MIN_VALUE|Byte\.MAX_VALUE|Short\.MIN_VALUE|Short\.MAX_VALUE|Character\.MIN_VALUE|Character\.MAX_VALUE|Long\.MAX_VALUE|Long\.MIN_VALUE|FLT_MAX|INT32_MAX|INT_MAX|SHRT_MAX|SCHAR_MAX)\b|\bMath\.toIntExact\b|\btry_from\b|\btry_into\b|\bsafe_cast\b|\bnarrow_cast\b|\bNumber\.isSafeInteger\b/i;

  const ingress = nodesOfType(map, 'INGRESS');
  if (ingress.length === 0) {
    return { cwe: 'CWE-681', name: 'Incorrect Conversion between Numeric Types', holds: true, findings };
  }

  // Walk every node. If it contains a narrowing cast AND an INGRESS node shares
  // the same function scope (meaning tainted data is available), flag it unless
  // a safe range-check pattern is present in the node's code.
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!ANY_NARROWING.test(code)) continue;
    if (SAFE_PATTERN.test(code)) continue;

    // Require tainted source in the same scope
    const scopedIngress = ingress.find(src => sharesFunctionScope(map, src.id, node.id));
    if (!scopedIngress) continue;

    let castDesc = 'narrowing numeric cast';
    if (DOUBLE_TO_FLOAT.test(code)) castDesc = 'double-to-float cast';
    else if (INT64_TO_32.test(code)) castDesc = '64-bit-to-32-bit cast';
    else if (NARROWING_CAST.test(code)) {
      const m = code.match(NARROWING_CAST);
      castDesc = `narrowing cast to ${m ? m[1] : 'smaller type'}`;
    }

    findings.push({
      source: nodeRef(scopedIngress),
      sink: nodeRef(node),
      missing: 'CONTROL (validate numeric range before type conversion)',
      severity: 'medium',
      description: `Tainted input from ${scopedIngress.label} undergoes ${castDesc} at ${node.label} without ` +
        `range validation. Incorrect conversion between numeric types can silently lose data — ` +
        `e.g. a double value of 1e-50 becomes 0.0 as float, or an int value of 256 becomes 0 as byte.`,
      fix: 'Validate the value fits in the target type range before casting. ' +
        'For double-to-float: check val <= Float.MAX_VALUE && val >= Float.MIN_VALUE. ' +
        'For int narrowing: check against Byte/Short/Character MIN_VALUE and MAX_VALUE.',
      via: 'scope_taint',
    });
  }

  return { cwe: 'CWE-681', name: 'Incorrect Conversion between Numeric Types', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const NUMERIC_COERCION_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-119': verifyCWE119,
  'CWE-120': verifyCWE120,
  'CWE-125': verifyCWE125,
  'CWE-126': verifyCWE126,
  'CWE-127': verifyCWE127,
  'CWE-131': verifyCWE131,
  'CWE-190': verifyCWE190,
  'CWE-191': verifyCWE191,
  'CWE-192': verifyCWE192,
  'CWE-193': verifyCWE193,
  'CWE-194': verifyCWE194,
  'CWE-195': verifyCWE195,
  'CWE-196': verifyCWE196,
  'CWE-197': verifyCWE197,
  'CWE-198': verifyCWE198,
  'CWE-681': verifyCWE681,
};
