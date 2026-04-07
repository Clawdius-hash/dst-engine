/**
 * Code Quality & Structural CWE Verifiers
 *
 * Dead code, always-true/false, object model issues, assignment vs comparison,
 * public field exposure, type confusion, suspicious patterns, error handling,
 * and miscellaneous quality checks.
 *
 * Self-contained source-code scanners: no taint/BFS, no injection detection.
 * Extracted from verifier/index.ts — Phase 2 of the monolith split.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments } from './source-analysis.ts';
import { nodeRef, nodesOfType, inferMapLanguage, isLibraryCode } from './graph-helpers.ts';
import { findNearestNode } from '../generated/_helpers.js';

/**
 * CWE-456: Missing Initialization of a Variable
 * A variable is declared but not initialized before use. In C/C++, uninitialized stack
 * variables contain whatever was previously on the stack, which can leak sensitive data
 * or cause unpredictable behavior.
 *
 * Static detection: look for variable declarations without initializers followed by use,
 * and for malloc() without subsequent initialization (calloc is safe).
 */
function verifyCWE456(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Uninitialized declarations: int x; char buf[256]; void *ptr;
  const UNINIT_DECL_RE = /\b(int|char|short|long|float|double|unsigned|signed|void|size_t|ssize_t|uint\d+_t|int\d+_t|DWORD|BOOL|HANDLE|PVOID)\s*\**\s+\w+\s*(\[\d*\])?\s*;/;
  // Declarations with initialization
  const INIT_DECL_RE = /\b(int|char|short|long|float|double|unsigned|signed|void|size_t|ssize_t|uint\d+_t|int\d+_t)\s*\**\s+\w+\s*(\[\d*\])?\s*=\s*/;
  // malloc without memset/initialization (calloc zero-initializes, so it's safe)
  const MALLOC_NO_INIT_RE = /\bmalloc\s*\([^)]+\)(?!.*\b(memset|bzero|ZeroMemory|SecureZeroMemory|calloc|memcpy)\b)/;
  // Safe patterns that ensure initialization
  const SAFE_INIT_RE = /\bmemset\s*\(|\bbzero\s*\(|\bZeroMemory\s*\(|\bcalloc\s*\(|\b=\s*\{0\}|\b=\s*\{\s*\}|\b=\s*0\b|\b=\s*NULL\b|\b=\s*nullptr\b|\b=\s*""|\bSecureZeroMemory\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for uninitialized declarations
    if (UNINIT_DECL_RE.test(code) && !INIT_DECL_RE.test(code) && !SAFE_INIT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (initialize variable at declaration)',
        severity: 'medium',
        description: `Uninitialized variable at ${node.label}. In C/C++, stack variables contain ` +
          `whatever was previously on the stack, which can leak sensitive data (passwords, keys, addresses).`,
        fix: 'Always initialize variables at declaration: int x = 0; char buf[256] = {0}; ' +
          'Use calloc() instead of malloc() for zero-initialized memory. ' +
          'In C++, use {} initialization: int x{}; std::string s{};',
          via: 'structural',
      });
    }

    // Check for malloc without initialization
    if (MALLOC_NO_INIT_RE.test(code) && !SAFE_INIT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (initialize allocated memory — use calloc or memset after malloc)',
        severity: 'medium',
        description: `malloc() at ${node.label} does not initialize allocated memory. ` +
          `Heap memory may contain data from previous allocations, leaking sensitive information.`,
        fix: 'Use calloc() instead of malloc() for zero-initialized memory. ' +
          'Or call memset(ptr, 0, size) immediately after malloc(). ' +
          'In C++, prefer std::vector or std::make_unique which zero-initialize.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-456', name: 'Missing Initialization of a Variable', holds: findings.length === 0, findings };
}

/**
 * CWE-457: Use of Uninitialized Variable
 * Using a variable before it has been assigned a value. In C/C++, the value is
 * indeterminate and may vary across executions, making behavior unpredictable.
 * Related to CWE-456 but focuses on the USE rather than the missing initialization.
 *
 * Static detection: look for patterns where variables are declared, then used in
 * conditional paths that may skip initialization.
 */
function verifyCWE457(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // This CWE applies to C/C++ (indeterminate values) and Java/Kotlin (local variables
  // are NOT auto-initialized — only fields get defaults). JavaScript, Go, Rust, Python
  // etc. all require or enforce initialization. Skip for those languages.
  const lang = inferMapLanguage(map);
  const CWE457_LANGS = new Set(['c', 'c++', 'cpp', 'java', 'kotlin']);
  if (lang && !CWE457_LANGS.has(lang)) {
    return { cwe: 'CWE-457', name: 'Use of Uninitialized Variable', holds: true, findings };
  }

  // Variable used before init patterns — C/C++ types + Java primitive/reference types
  const UNINIT_USE_RE = /\b(int|char|short|long|float|double|unsigned|signed|size_t|uint\d+_t|int\d+_t|boolean|byte|String|Object)\s*\**\s+(\w+)\s*(\[\d*\])?\s*;[^=]*\b\2\b/;
  // Conditional init — variable initialized only in some branches
  const CONDITIONAL_INIT_RE = /\bif\b[^{]*\{[^}]*=\s*[^;]+;[^}]*\}(?!\s*else)/;
  // Patterns that prevent uninitialized use
  const ALWAYS_INIT_RE = /\b=\s*0\b|\b=\s*NULL\b|\b=\s*nullptr\b|\b=\s*\{\s*\}|\b=\s*\{0\}|\b=\s*""|\b=\s*false\b|\b=\s*'\0'|\b=\s*0\.0/;
  // Compiler/static analysis annotations that detect this
  const ANNOTATED_RE = /\b(__attribute__\s*\(\s*\(\s*warn_unused_result|Wuninitialized|Wmaybe-uninitialized|-fsanitize=memory|MSAN|valgrind|MemorySanitizer)\b/i;
  // Smart language features that prevent this
  const SAFE_LANG_RE = /\blet\s+\w+\s*:\s*\w+\s*=|\bvar\s+\w+\s*=|\bconst\s+\w+\s*=|\bval\s+\w+\s*=|\b:=\s*/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    // Skip nodes in languages with mandatory initialization (Rust, Go, JS/TS)
    if (SAFE_LANG_RE.test(code)) continue;
    if (ANNOTATED_RE.test(code)) continue;

    if (UNINIT_USE_RE.test(code) && !ALWAYS_INIT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (initialize variable before use)',
        severity: 'medium',
        description: `Variable at ${node.label} may be used before initialization. ` +
          `In C/C++, reading an uninitialized variable is undefined behavior — the value is ` +
          `indeterminate and may leak stack data or cause wrong branching.`,
        fix: 'Initialize all variables at declaration. Enable -Wuninitialized and -Wmaybe-uninitialized compiler flags. ' +
          'Use AddressSanitizer/MemorySanitizer in testing. In C++, use {} initialization.',
          via: 'structural',
      });
    }

    // Conditional initialization without else branch
    if (CONDITIONAL_INIT_RE.test(code) && !ALWAYS_INIT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (ensure all code paths initialize the variable)',
        severity: 'medium',
        description: `Variable at ${node.label} is initialized only in a conditional branch. ` +
          `If the condition is false, the variable remains uninitialized when used later.`,
        fix: 'Ensure all code paths initialize the variable. Add an else branch with a default value. ' +
          'Or initialize the variable at declaration before the conditional.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-457', name: 'Use of Uninitialized Variable', holds: findings.length === 0, findings };
}

/**
 * CWE-467: Use of sizeof() on a Pointer Type
 * Using sizeof() on a pointer instead of the pointed-to object. sizeof(ptr) returns
 * the size of the pointer (4 or 8 bytes), not the size of the buffer it points to.
 * Common cause of buffer overflows and truncated operations.
 *
 * Classic pattern: char *buf = malloc(BUF_SIZE); memset(buf, 0, sizeof(buf)); // BUG: sizeof(char*) == 8, not BUF_SIZE
 */
function verifyCWE467(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // sizeof applied to a pointer variable (heuristic: sizeof(ptr) where ptr is a pointer)
  const SIZEOF_PTR_RE = /\bsizeof\s*\(\s*\*?\s*\w+\s*\)(?!.*\[\s*\])|\bsizeof\s*\(\s*\w+\s*\*\s*\)/;
  // sizeof used correctly on arrays or types
  const SIZEOF_ARRAY_RE = /\bsizeof\s*\(\s*\w+\s*\[\s*\d*\s*\]\s*\)|\bsizeof\s*\(\s*(int|char|long|short|double|float|struct\s+\w+|union\s+\w+|enum\s+\w+|size_t|uint\d+_t|int\d+_t)\s*\)/;
  // Dangerous: sizeof(ptr) used in memcpy/memset/allocation
  const SIZEOF_IN_MEM_OP_RE = /\b(memcpy|memset|memmove|bzero|ZeroMemory|malloc|calloc|realloc|strncpy|fread|fwrite)\s*\([^)]*\bsizeof\s*\(\s*\w+\s*\)/i;
  // sizeof(*ptr) is SAFE — it gets the size of the pointed-to type
  const SIZEOF_DEREF_RE = /\bsizeof\s*\(\s*\*\s*\w+\s*\)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (SIZEOF_IN_MEM_OP_RE.test(code) && SIZEOF_PTR_RE.test(code) &&
        !SIZEOF_ARRAY_RE.test(code) && !SIZEOF_DEREF_RE.test(code)) {
      // Check if the sizeof argument looks like a pointer (declared as type* or type *name)
      const ptrDeclMatch = code.match(/\b\w+\s*\*\s+(\w+)\b|\b\w+\s*\*(\w+)\b/);
      const sizeofMatch = code.match(/\bsizeof\s*\(\s*(\w+)\s*\)/);
      if (ptrDeclMatch && sizeofMatch) {
        const ptrName = ptrDeclMatch[1] || ptrDeclMatch[2];
        const sizeofArg = sizeofMatch[1];
        if (ptrName === sizeofArg) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'TRANSFORM (use sizeof(*ptr) or sizeof(type) instead of sizeof(ptr))',
            severity: 'high',
            description: `sizeof() applied to pointer variable "${sizeofArg}" at ${node.label}. ` +
              `sizeof(ptr) returns ${node.language === 'c' ? '4 or 8' : 'pointer size'} bytes (pointer size), ` +
              `not the size of the buffer. This causes truncated memcpy/memset operations.`,
            fix: 'Use sizeof(*ptr) to get the size of the pointed-to type, or use the original allocation size. ' +
              'For arrays passed as pointers, pass the size as a separate parameter. ' +
              'Example: memset(buf, 0, buf_size) instead of memset(buf, 0, sizeof(buf)).',
              via: 'structural',
          });
          continue;
        }
      }
    }

    // General pattern: sizeof in memory operations that might be on pointers
    if (SIZEOF_IN_MEM_OP_RE.test(code) && !SIZEOF_ARRAY_RE.test(code) && !SIZEOF_DEREF_RE.test(code)) {
      // Look for pointer-like contexts: malloc result assigned to ptr, then sizeof(ptr) used
      if (/\bmalloc\s*\(/.test(code) && SIZEOF_PTR_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (sizeof on pointer only gives pointer size, not buffer size)',
          severity: 'high',
          description: `Possible sizeof-on-pointer at ${node.label}. When a heap buffer is accessed via a pointer, ` +
            `sizeof(pointer) gives the pointer size (4/8 bytes), not the allocated buffer size.`,
          fix: 'Track buffer sizes separately. Use sizeof(*ptr) for the element size, and multiply by count. ' +
            'Or use sizeof(type) * count for the total allocation size.',
            via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-467', name: 'Use of sizeof() on a Pointer Type', holds: findings.length === 0, findings };
}

/**
 * CWE-468: Incorrect Pointer Scaling
 * When pointer arithmetic is performed, the compiler automatically scales by the size of
 * the pointed-to type. Manually scaling (e.g., ptr + index * sizeof(int)) results in
 * double-scaling, accessing memory far beyond the intended location.
 *
 * Classic bug: int *p = ...; p = p + index * sizeof(int); // BUG: already scaled by sizeof(int)
 */
function verifyCWE468(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Manual scaling patterns — pointer arithmetic with explicit sizeof multiplication
  const DOUBLE_SCALE_RE = /\w+\s*[\+\-]\s*\w*\s*\*\s*sizeof\s*\(|\w+\s*[\+\-]\s*sizeof\s*\([^)]+\)\s*\*/;
  // Pointer cast followed by byte-level arithmetic (cast to char* then back)
  const CAST_ARITH_RE = /\(\s*(int|long|short|double|float|struct\s+\w+)\s*\*\s*\)\s*\(\s*\(\s*(char|unsigned\s+char|uint8_t|BYTE)\s*\*\s*\)/i;
  // Safe patterns: explicit byte-level access via char*/void* or well-known offset macros
  const SAFE_SCALE_RE = /\b(char|unsigned\s+char|uint8_t|int8_t|BYTE|void)\s*\*|\boffsetof\b|\bcontainer_of\b|\bOBJECT_OFFSET\b|\bPTR_OFFSET\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (DOUBLE_SCALE_RE.test(code) && !SAFE_SCALE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (remove manual sizeof scaling — C pointer arithmetic auto-scales)',
        severity: 'high',
        description: `Incorrect pointer scaling at ${node.label}. Pointer arithmetic in C/C++ automatically ` +
          `scales by sizeof(*ptr). Manually multiplying by sizeof() causes double-scaling, accessing ` +
          `memory N*sizeof(type) bytes beyond the intended location.`,
        fix: 'Remove the manual sizeof multiplication: use ptr + index, not ptr + index * sizeof(type). ' +
          'If you need byte-level arithmetic, cast to char* first: ((char*)ptr) + byte_offset. ' +
          'Use array indexing (ptr[index]) instead of manual pointer arithmetic when possible.',
          via: 'structural',
      });
    }

    if (CAST_ARITH_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (verify pointer scaling is correct after type cast)',
        severity: 'medium',
        description: `Pointer type cast with arithmetic at ${node.label}. Casting between pointer types ` +
          `changes the scaling factor for pointer arithmetic. The offset calculated for char* will be ` +
          `wrong when the pointer is cast back to a larger type.`,
        fix: 'Be explicit about whether offsets are in bytes or elements. ' +
          'Use offsetof() for struct member offsets. Use container_of() for container access. ' +
          'Document whether arithmetic is byte-level or element-level.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-468', name: 'Incorrect Pointer Scaling', holds: findings.length === 0, findings };
}

/**
 * CWE-469: Use of Pointer Subtraction to Determine Size
 * Subtracting two pointers to compute a buffer size. This is only valid if both pointers
 * point into the same array object. If they point to different allocations, the result is
 * undefined behavior and the computed size is meaningless.
 *
 * Additionally, pointer subtraction returns a ptrdiff_t (signed), which can be negative
 * or overflow when cast to size_t (unsigned), causing massive over-allocations or
 * buffer overflows.
 */
function verifyCWE469(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Pointer subtraction used as a size: (end - start), ptr2 - ptr1
  const PTR_SUB_SIZE_RE = /\(\s*\w+\s*-\s*\w+\s*\)\s*(?:[\*\/\+]|\bas\s+size_t|\b\(size_t\))|\b(size|len|length|count|capacity|n)\s*=\s*\w+\s*-\s*\w+/i;
  // Pointer subtraction used directly in allocation or memory operations
  const PTR_SUB_IN_ALLOC_RE = /\b(malloc|calloc|realloc|alloca|memcpy|memmove|memset|strncpy|fread|fwrite)\s*\([^)]*\w+\s*-\s*\w+/i;
  // Safe patterns: well-known size computation idioms
  const SAFE_SIZE_RE = /\bsizeof\b|\b\.size\(\)|\b\.length\b|\b\.len\(\)|\bstrlen\b|\bwcslen\b|\bstd::distance\b/i;
  // Validation that subtraction result is checked
  const VALIDATED_RE = /\bif\s*\(\s*\w+\s*[<>]=?\s*\w+\s*\)|\bassert\s*\(\s*\w+\s*[<>]=?\s*\w+|\bif\s*\(\s*\w+\s*-\s*\w+\s*[<>]=?\s*0/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (PTR_SUB_IN_ALLOC_RE.test(code) && !SAFE_SIZE_RE.test(code) && !VALIDATED_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate pointer relationship before subtraction — ensure same allocation)',
        severity: 'high',
        description: `Pointer subtraction used as size parameter at ${node.label}. If the two pointers ` +
          `do not point into the same array, the result is undefined behavior. Additionally, ptrdiff_t ` +
          `is signed — negative results cast to size_t become enormous values.`,
        fix: 'Validate that both pointers reference the same allocation before subtracting. ' +
          'Check that the result is non-negative before using as a size. ' +
          'Prefer explicit size tracking: pass buffer + size instead of start + end pointers.',
          via: 'structural',
      });
    } else if (PTR_SUB_SIZE_RE.test(code) && !SAFE_SIZE_RE.test(code) && !VALIDATED_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate pointer subtraction result is non-negative and within bounds)',
        severity: 'medium',
        description: `Pointer subtraction to determine size at ${node.label}. The result (ptrdiff_t) ` +
          `is signed and can be negative if pointers are in the wrong order. Casting to size_t without ` +
          `checking creates an integer overflow vulnerability.`,
        fix: 'Assert that end >= start before computing size. Use size_t for sizes, not pointer subtraction. ' +
          'Consider std::distance() in C++ which works with iterators safely. ' +
          'Track buffer sizes explicitly alongside pointers.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-469', name: 'Use of Pointer Subtraction to Determine Size', holds: findings.length === 0, findings };
}

/**
 * CWE-478: Missing Default Case in Multiple Condition Expression
 * A switch statement does not have a default case. If an unexpected value is encountered,
 * execution falls through silently, potentially skipping critical security checks or
 * leaving variables uninitialized.
 *
 * This is particularly dangerous when the switch controls security logic (authorization,
 * input validation, state machines).
 */
function verifyCWE478(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Switch without default (heuristic: switch { ... } without the word "default:")
  const SWITCH_RE = /\bswitch\s*\(/;
  const HAS_DEFAULT_RE = /\bdefault\s*:/;
  // Enum-based switch where all cases are covered (exhaustive match)
  const EXHAUSTIVE_RE = /\b(enum|Enum|ENUM)\b.*\bswitch\b|\bswitch\b.*\b(enum|Enum)\b|\b__exhaustive\b|\b#\[non_exhaustive\]|\bmatch\b.*\{[^}]*_\s*=>/;
  // Security-relevant switch contexts
  const SECURITY_SWITCH_RE = /\bswitch\s*\(\s*(role|permission|auth|access|privilege|action|command|operation|state|status|type|kind|method|level)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (SWITCH_RE.test(code) && !HAS_DEFAULT_RE.test(code) && !EXHAUSTIVE_RE.test(code)) {
      const isSecurity = SECURITY_SWITCH_RE.test(code);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (add default case to handle unexpected values)',
        severity: isSecurity ? 'high' : 'medium',
        description: `Switch statement at ${node.label} has no default case. ` +
          (isSecurity
            ? `This switch controls security-relevant logic — an unhandled value could bypass authorization or validation.`
            : `An unexpected value will cause silent fallthrough, potentially leaving variables uninitialized or skipping critical logic.`),
        fix: 'Add a default case that either handles the unexpected value safely or throws an error: ' +
          'default: throw new Error("Unexpected value"); or default: return -EINVAL; ' +
          'For enums in C++, use -Wswitch-enum to catch missing cases at compile time. ' +
          'In Rust, use _ => pattern in match expressions.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-478', name: 'Missing Default Case in Multiple Condition Expression', holds: findings.length === 0, findings };
}

/**
 * CWE-480: Use of Incorrect Operator
 * Using the wrong operator, especially assignment (=) instead of comparison (==),
 * bitwise AND (&) instead of logical AND (&&), or bitwise OR (|) instead of logical OR (||).
 *
 * Classic C bug: if (x = 5) instead of if (x == 5) — always true, overwrites x.
 * Also: using & when && was intended changes short-circuit behavior and can cause
 * null pointer dereferences when the right side is evaluated unconditionally.
 */
function verifyCWE480(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Assignment in conditional (if/while/for with single = that's not == or !=)
  const ASSIGN_IN_COND_RE = /\b(if|while|for)\s*\([^)]*[^!=<>]=[^=][^)]*\)/;
  // Single & or | in boolean context (not &= or |= or && or ||)
  const BITWISE_IN_BOOL_RE = /\b(if|while|for)\s*\([^)]*[^&]&[^&][^)]*\)|\b(if|while|for)\s*\([^)]*[^|]\|[^|][^)]*\)/;
  // Safe patterns: intentional assignment in condition (common C idiom with extra parens)
  const INTENTIONAL_ASSIGN_RE = /\b(if|while)\s*\(\s*\(\s*\w+\s*=[^=]|\b(if|while)\s*\([^)]*!=|==|>=|<=|>(?!=)|<(?!=)/;
  // Yoda conditions: if (5 == x) — safe against accidental assignment
  const YODA_RE = /\b(if|while)\s*\(\s*(true|false|null|NULL|nullptr|\d+|'[^']*'|"[^"]*")\s*==/;
  // Explicit parenthesized assignment (intentional idiom)
  const PARENS_ASSIGN_RE = /\b(if|while)\s*\(\s*\([^)]+=[^=][^)]*\)\s*\)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check 1: Assignment in conditional
    if (ASSIGN_IN_COND_RE.test(code) && !INTENTIONAL_ASSIGN_RE.test(code) &&
        !YODA_RE.test(code) && !PARENS_ASSIGN_RE.test(code)) {
      // Make sure it's not == or != or <= or >= or =>
      const condMatch = code.match(/\b(if|while|for)\s*\(([^)]+)\)/);
      if (condMatch) {
        const cond = condMatch[2];
        // Confirm there is a single = not part of ==, !=, <=, >=, =>
        if (/[^!=<>]=[^=]/.test(cond) && !/==|!=|<=|>=|=>/.test(cond)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (use == for comparison, not = for assignment)',
            severity: 'high',
            description: `Assignment operator (=) used in conditional at ${node.label}. ` +
              `This assigns the value and evaluates the result as boolean, almost certainly a bug. ` +
              `The condition is always true (for non-zero values), and the variable is overwritten.`,
            fix: 'Change = to == for comparison. Enable -Wparentheses or -Wconditional-assignment compiler warnings. ' +
              'Use Yoda conditions (if (5 == x)) to catch this at compile time. ' +
              'In C++, declare variables const where possible.',
              via: 'structural',
          });
        }
      }
    }

    // Check 2: Bitwise operator in boolean context
    if (BITWISE_IN_BOOL_RE.test(code)) {
      const condMatch = code.match(/\b(if|while|for)\s*\(([^)]+)\)/);
      if (condMatch) {
        const cond = condMatch[2];
        // Check for & not followed by & or |  not followed by |
        if ((/[^&]&[^&]/.test(cond) || /[^|]\|[^|]/.test(cond)) &&
            !/&&|\|\|/.test(cond) && !/&\s*0x|&\s*\d+|FLAG|MASK|BIT/i.test(cond)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (use && for logical AND, not & for bitwise AND)',
            severity: 'medium',
            description: `Bitwise operator used in boolean context at ${node.label}. ` +
              `& evaluates BOTH sides unconditionally (no short-circuit). If the left side is a null ` +
              `check and the right side dereferences, this causes null pointer dereference.`,
            fix: 'Use && for logical AND and || for logical OR. Bitwise & and | do not short-circuit. ' +
              'If bitwise operation is intentional, add a comment and parenthesize for clarity.',
              via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-480', name: 'Use of Incorrect Operator', holds: findings.length === 0, findings };
}

/**
 * CWE-561: Dead Code
 * Detects:
 *   1. Unreachable code after return/throw/break/continue
 *   2. Code inside always-false conditions
 *   3. Code after process exit calls
 *   4. Unused private methods (dead methods never called within the class)
 *
 * SECOND PASS NOTE: evaluateControlEffectiveness() already checks for
 * always-true conditions on CONTROL nodes (dead control). CWE-561 benefits
 * — if a CONTROL node is in dead code, the second pass catches the variant
 * where the control exists but is unreachable. This verifier handles the
 * broader case: ANY dead code, not just dead controls.
 */
function verifyCWE561(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Pattern 1: Code after unconditional return/throw/break/continue
  const UNREACHABLE_AFTER = /\b(return|throw|break|continue)\b[^;]*;[^\n]*\n\s*(?![\s}]*(?:$|case\b|default\b|catch\b|finally\b|else\b|\}))\S+/m;

  // Pattern 2: Always-false conditions (dead branch)
  const ALWAYS_FALSE = /\bif\s*\(\s*(?:false|0|!1|!!0|null|undefined|void\s+0)\s*\)/;

  // Pattern 3: Code after System.exit / process.exit / os._exit
  const EXIT_BEFORE_CODE = /\b(System\.exit|process\.exit|os\._exit|exit)\s*\([^)]*\)\s*;[^\n]*\n\s*\S+/;

  // Pattern 4: Unused private methods (Java/C#/TS)
  // Collect all private method names and check if they're called anywhere in the same file
  const PRIVATE_METHOD_DECL = /\bprivate\s+(?:static\s+)?(?:\w+(?:\s*<[^>]*>)?\s+)?(\w+)\s*\(/g;
  const fullCode = map.nodes.map(n => stripComments(n.analysis_snapshot || n.code_snapshot)).join('\n');
  const privateMethodNames: string[] = [];
  let pmMatch: RegExpExecArray | null;
  while ((pmMatch = PRIVATE_METHOD_DECL.exec(fullCode)) !== null) {
    const name = pmMatch[1];
    // Skip constructors, common boilerplate names, and very short names
    if (name === 'main' || name === 'toString' || name === 'hashCode' || name === 'equals' ||
        name === 'clone' || name === 'finalize' || name === 'compareTo' ||
        name.length <= 1) continue;
    privateMethodNames.push(name);
  }

  // Check which private methods are actually called somewhere in the file
  for (const methodName of privateMethodNames) {
    // Look for the method being called (methodName followed by '(' but not in its declaration)
    const callPattern = new RegExp(`(?<!private\\s+(?:static\\s+)?(?:\\w+(?:\\s*<[^>]*>)?\\s+)?)\\b${methodName}\\s*\\(`, 'g');
    const allMatches = [...fullCode.matchAll(callPattern)];
    // The declaration itself will match too, so we need at least 1 match beyond the declaration
    // Actually, with the negative lookbehind, declarations won't match.
    // But let's also exclude method references, annotations, etc.
    if (allMatches.length === 0) {
      // This private method is never called — it's dead code
      // Find the node that contains this method declaration
      for (const node of map.nodes) {
        const nodeCode = stripComments(node.analysis_snapshot || node.code_snapshot);
        if (new RegExp(`\\bprivate\\s+(?:static\\s+)?(?:\\w+(?:\\s*<[^>]*>)?\\s+)?${methodName}\\s*\\(`).test(nodeCode)) {
          findings.push({
            source: nodeRef(node),
            sink: nodeRef(node),
            missing: 'STRUCTURAL (remove dead code or fix control flow)',
            severity: 'low',
            description: `Dead code at ${node.label}: private method "${methodName}" is never called within the class. ` +
              `Unused methods increase the attack surface and maintenance burden.`,
            fix: 'Remove the unused private method, or add a call to it if it was meant to be used. ' +
              'Dead code increases attack surface and makes the codebase harder to audit.',
              via: 'structural',
          });
          break;
        }
      }
    }
  }

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|describe\s*\(|it\s*\()\b/i.test(node.label)) continue;

    let matched = false;
    let description = '';

    if (ALWAYS_FALSE.test(code)) {
      matched = true;
      description = `Dead code at ${node.label}: condition is always false — the branch body never executes. ` +
        `If this guards a security check, the check is silently disabled.`;
    } else if (UNREACHABLE_AFTER.test(code)) {
      matched = true;
      description = `Dead code at ${node.label}: statements after unconditional return/throw/break are unreachable. ` +
        `Any security logic placed after the exit point never runs.`;
    } else if (EXIT_BEFORE_CODE.test(code)) {
      matched = true;
      description = `Dead code at ${node.label}: code after process exit call is unreachable.`;
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (remove dead code or fix control flow)',
        severity: 'low',
        description,
        fix: 'Remove unreachable code. If the code was meant to execute, fix the control flow ' +
          '(e.g., move it before the return statement, or fix the always-false condition). ' +
          'Use a linter with no-unreachable and no-constant-condition rules.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-561', name: 'Dead Code', holds: findings.length === 0, findings };
}

/**
 * CWE-562: Return of Stack Variable Address
 * Detects functions that return pointers/references to stack-allocated local
 * variables. After the function returns, the stack frame is deallocated and the
 * pointer becomes dangling. Primarily C/C++, also Go (return &loopVar) and Rust.
 *
 * SECOND PASS NOTE: Limited benefit from evaluateControlEffectiveness(). The
 * pointer itself is the problem (dangling), not a control weakness.
 */
function verifyCWE562(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // C/C++: return &localVar
  const RETURN_STACK_ADDR_C = /\breturn\s+&\s*[a-zA-Z_]\w*\s*;/;
  // C/C++: return local array name (decays to dangling pointer)
  const RETURN_LOCAL_ARRAY = /\b(?:char|int|float|double|unsigned|long)\s+(\w+)\s*\[[\w\s]*\]\s*;[\s\S]*?\breturn\s+\1\s*;/;
  // C/C++: returning pointer to local struct
  const RETURN_LOCAL_STRUCT_PTR = /\b(?:struct\s+\w+|\w+_t)\s+(\w+)\s*;[\s\S]*?\breturn\s+&\1\s*;/;
  // Go: return &loopVar inside a for loop
  const GO_RETURN_LOOP_PTR = /\bfor\b[\s\S]*?\breturn\s+&\s*\w+/;
  // Rust: returning reference to local without 'static lifetime
  const RUST_RETURN_LOCAL_REF = /fn\s+\w+[^{]*->\s*&(?!'static)\s*\w+[\s\S]*?\breturn\s+&\s*\w+/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let matched = false;
    let detail = '';

    if (RETURN_STACK_ADDR_C.test(code)) {
      if (!/\bstatic\b/.test(code) && !/\bglobal\b/i.test(code)) {
        matched = true;
        detail = 'returns address of a local variable (stack-allocated)';
      }
    } else if (RETURN_LOCAL_ARRAY.test(code)) {
      matched = true;
      detail = 'returns local array name, which decays to a dangling pointer after return';
    } else if (RETURN_LOCAL_STRUCT_PTR.test(code)) {
      if (!/\bstatic\b/.test(code)) {
        matched = true;
        detail = 'returns pointer to a local struct on the stack';
      }
    } else if (GO_RETURN_LOOP_PTR.test(code)) {
      matched = true;
      detail = 'returns pointer to loop variable — all iterations share the same address';
    } else if (RUST_RETURN_LOCAL_REF.test(code)) {
      matched = true;
      detail = 'returns reference to local variable without sufficient lifetime';
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'TRANSFORM (heap allocation or copy for returned data)',
        severity: 'critical',
        description: `${node.label} ${detail}. After the function returns, the stack frame is ` +
          `deallocated and the caller receives a dangling pointer — reading it is undefined behavior.`,
        fix: 'Allocate on the heap (malloc/new/Box) and return the heap pointer. ' +
          'Or return by value (copy the struct/array). ' +
          'In Go, the compiler escape-analyzes, but beware of loop variable capture — copy first.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-562', name: 'Return of Stack Variable Address', holds: findings.length === 0, findings };
}

/**
 * CWE-563: Assignment to Variable without Use
 * Detects variables assigned a value that is never subsequently read.
 * Can indicate incomplete implementation, logic errors, or dead stores
 * that mask bugs. Especially dangerous when a security check result is
 * assigned but never examined.
 *
 * SECOND PASS NOTE: If a CONTROL node assigns a validation result that is
 * never used, the control is effectively dead. evaluateControlEffectiveness()
 * could catch this as a "dead control" variant. The overlap is meaningful.
 */
function verifyCWE563(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Pattern: variable assigned then immediately overwritten without use
  const OVERWRITTEN_ASSIGN = /\b(\w+)\s*=\s*[^;=]+;\s*\1\s*=\s*[^;=]+;/;

  // Security-relevant: result of validation/check function assigned but never used
  const UNCHECKED_RESULT = /\b(?:const|let|var|int|boolean|bool)\s+(is\w+|valid\w*|check\w*|result|status|err|error)\s*=\s*\w+\s*\([^)]*\)\s*;/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Check 1: Variable immediately overwritten
    if (OVERWRITTEN_ASSIGN.test(code)) {
      const match = code.match(OVERWRITTEN_ASSIGN);
      if (match) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'STRUCTURAL (remove dead store or use the assigned value)',
          severity: 'low',
          description: `Variable "${match[1]}" at ${node.label} is assigned a value that is immediately overwritten. ` +
            `The first assignment is wasted — this may indicate a logic error.`,
          fix: 'Remove the dead store or use the value before reassigning. ' +
            'If the first assignment has side effects, extract them.',
            via: 'structural',
        });
      }
    }

    // Check 2: Security function result assigned but likely unused
    if (UNCHECKED_RESULT.test(code)) {
      const match = code.match(UNCHECKED_RESULT);
      if (match) {
        const varName = match[1];
        const regex = new RegExp(`\\b${varName}\\b`, 'g');
        const occurrences = (code.match(regex) || []).length;
        if (occurrences <= 1) {
          findings.push({
            source: nodeRef(node),
            sink: nodeRef(node),
            missing: 'CONTROL (check the return value of validation/security functions)',
            severity: 'medium',
            description: `Return value "${varName}" from a validation/check function at ${node.label} is assigned but never used. ` +
              `If this is a security check, the result is being ignored — the check runs but has no effect.`,
            fix: 'Use the return value in a conditional: if (!isValid) { throw new Error(...); } ' +
              'Or remove the assignment if the function is called only for side effects.',
              via: 'structural',
          });
        }
      }
    }
  }

  // --- Strategy 3: Scope-aware source scan (merged from generated) ---
  // Catches Juliet patterns: int data; data = 5; /* never used */
  const src563 = map.source_code || '';
  if (src563 && findings.length === 0) {
    const lines563 = src563.split('\n');
    const javaAssign563 = /^\s*(?:final\s+)?(?:int|long|float|double|boolean|char|byte|short|String|Object|\w+(?:<[^>]+>)?)\s+(\w+)\s*=\s*(.+);/;
    const jsAssign563 = /^\s*(?:let|const|var)\s+(\w+)\s*=\s*(.+);/;
    const bareAssign563 = /^\s*(\w+)\s*=\s*(?!=)(.+);/;
    const declaredVars563 = new Set<string>();
    for (const ln of lines563) {
      const dm = ln.match(/^\s*(?:final\s+)?(?:int|long|float|double|boolean|char|byte|short|String|Object|\w+(?:<[^>]+>)?)\s+(\w+)\s*;/);
      if (dm) declaredVars563.add(dm[1]);
      const di = javaAssign563.exec(ln) || jsAssign563.exec(ln);
      if (di) declaredVars563.add(di[1]);
    }
    const flagged563 = new Set<string>();
    for (let i = 0; i < lines563.length; i++) {
      const ln = lines563[i];
      if (/^\s*\/\//.test(ln) || /^\s*\*/.test(ln) || /^\s*\/\*/.test(ln)) continue;
      let vn563: string | null = null;
      const tm = javaAssign563.exec(ln) || jsAssign563.exec(ln);
      if (tm) { vn563 = tm[1]; } else {
        const bm = bareAssign563.exec(ln);
        if (bm && declaredVars563.has(bm[1])) vn563 = bm[1];
      }
      if (!vn563) continue;
      if (['i','j','k','args','e','ex','err','_','this'].includes(vn563)) continue;
      if (/\bfor\s*\(/.test(ln)) continue;
      if (flagged563.has(`${vn563}:${i}`)) continue;
      let se563 = lines563.length - 1, bd563 = 0;
      for (let j = i; j < lines563.length; j++) {
        for (const ch of lines563[j]) { if (ch === '{') bd563++; if (ch === '}') bd563--; }
        if (bd563 < 0) { se563 = j; break; }
      }
      let used563 = false;
      const vp563 = new RegExp(`\\b${vn563}\\b`);
      for (let j = i + 1; j <= se563; j++) {
        const cl = lines563[j];
        if (/^\s*\/\//.test(cl) || /^\s*\*/.test(cl) || /^\s*\/\*/.test(cl)) continue;
        const st = cl.replace(/\/\/.*$/, '').replace(/\/\*[\s\S]*?\*\//g, '');
        if (vp563.test(st)) {
          if (!(new RegExp(`^\\s*${vn563}\\s*=\\s*(?!=)`)).test(st)) { used563 = true; break; }
        }
      }
      if (!used563) {
        flagged563.add(`${vn563}:${i}`);
        const nn = map.nodes.find(n => n.line_start === i + 1) ||
          map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2 && n.node_type === 'TRANSFORM') ||
          map.nodes[0];
        if (nn) {
          findings.push({ source: nodeRef(nn), sink: nodeRef(nn),
            missing: 'EGRESS (variable should be used after assignment)', severity: 'low',
            description: `L${i + 1}: Variable '${vn563}' is assigned but never used in its scope.`,
            fix: 'Remove unused variable assignments. They may indicate logic errors or incomplete implementation.',
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-563', name: 'Assignment to Variable without Use', holds: findings.length === 0, findings };
}

/**
 * CWE-570: Expression is Always False
 * Detects conditions that always evaluate to false, making the guarded code
 * unreachable. Can disable security checks if the check is inside the dead branch.
 *
 * SECOND PASS NOTE: evaluateControlEffectiveness() checks always-TRUE on controls.
 * CWE-570 is the inverse. A second pass could check: "does a CONTROL node contain
 * an always-false sub-condition that disables part of validation?" — partial dead
 * controls that the first pass misses.
 */
function verifyCWE570(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const ALWAYS_FALSE_LITERAL = /\bif\s*\(\s*(?:false|0|!1|!!0|null|undefined|void\s+0)\s*\)/;
  const TYPE_CONFUSION = /\bif\s*\(\s*['"][^'"]*['"]\s*===\s*\d+\s*\)|\bif\s*\(\s*\d+\s*===\s*['"][^'"]*['"]\s*\)/;
  const CONTRADICTION = /\b(\w+)\s*&&\s*!\1\b/;
  const UNSIGNED_LT_ZERO = /\b(?:unsigned|uint\d*|size_t|usize|UInt)\s+\w+[\s\S]*?\bif\s*\([^)]*<\s*0\s*\)/;
  const SIZEOF_ZERO = /\bsizeof\s*\([^)]+\)\s*==\s*0/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let matched = false;
    let detail = '';

    if (ALWAYS_FALSE_LITERAL.test(code)) {
      matched = true;
      detail = 'condition is a literal false value (false/0/null/undefined)';
    } else if (TYPE_CONFUSION.test(code)) {
      matched = true;
      detail = 'strict equality between string and number — always false without coercion';
    } else if (CONTRADICTION.test(code)) {
      matched = true;
      detail = 'contradictory condition (x && !x)';
    } else if (UNSIGNED_LT_ZERO.test(code)) {
      matched = true;
      detail = 'unsigned type compared < 0 — unsigned values are never negative';
    } else if (SIZEOF_ZERO.test(code)) {
      matched = true;
      detail = 'sizeof non-empty type compared == 0 — sizeof always returns positive';
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (fix always-false expression to reflect intended logic)',
        severity: 'medium',
        description: `Always-false expression at ${node.label}: ${detail}. ` +
          `The guarded code never executes. If it contains security logic, that logic is silently disabled.`,
        fix: 'Fix the condition to reflect the actual intent. If the dead branch is intentional ' +
          '(feature flag), use a named constant or config value instead of a literal false. ' +
          'Run static analysis (ESLint no-constant-condition, gcc -Wtype-limits) to catch these.',
          via: 'structural',
      });
    }
  }

  // --- Strategy 2: Source-scan (merged from generated) ---
  // Catches Juliet getClass().equals() patterns and other source-level always-false expressions
  const src570 = map.source_code || '';
  if (src570 && findings.length === 0) {
    const lines570 = src570.split('\n');
    const alwaysFalsePatterns570: Array<{ re: RegExp; desc: string }> = [
      { re: /\bif\s*\(\s*false\s*\)/, desc: 'if(false)' },
      { re: /\bwhile\s*\(\s*false\s*\)/, desc: 'while(false)' },
      { re: /\bif\s*\(\s*(\w+)\s*!=\s*\s*\)/, desc: 'x != x (always false)' },
      { re: /\bif\s*\(\s*(\w+)\s*>\s*Integer\.MAX_VALUE\s*\)/, desc: 'n > Integer.MAX_VALUE (always false)' },
      { re: /\bif\s*\(\s*(\w+)\s*<\s*Integer\.MIN_VALUE\s*\)/, desc: 'n < Integer.MIN_VALUE (always false)' },
      { re: /\bif\s*\(\s*(\w+)\s*==\s*\(\s*\s*-\s*1\s*\)\s*\)/, desc: 'n == (n - 1) (always false)' },
      { re: /\bif\s*\(\s*(\w+)\s*==\s*\(\s*\s*\+\s*1\s*\)\s*\)/, desc: 'n == (n + 1) (always false)' },
    ];
    // Detect different-type getClass().equals() — always false when comparing different concrete types
    // Juliet pattern: random.getClass().equals(secureRandom.getClass()) where types differ
    const CLASS_EQUALS_FALSE = /\bif\s*\(\s*(\w+)\.getClass\(\)\.equals\(\s*(\w+)\.getClass\(\)\s*\)\s*\)/;

    for (let i = 0; i < lines570.length; i++) {
      const line = lines570[i];
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*\/\*/.test(line)) continue;

      for (const pat of alwaysFalsePatterns570) {
        if (pat.re.test(line)) {
          const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'CONTROL (correct conditional expression)',
              severity: 'low',
              description: `L${i + 1}: Expression always evaluates to false: ${pat.desc}. Dead code follows.`,
              fix: 'Fix always-false expressions. They indicate logic errors or dead code.',
              via: 'source_line_fallback',
            });
          }
        }
      }

      // Check getClass().equals() with different-type variables
      const classMatch = CLASS_EQUALS_FALSE.exec(line);
      if (classMatch) {
        const var1 = classMatch[1];
        const var2 = classMatch[2];
        if (var1 !== var2) {
          // Look up declarations to see if they are different types
          let type1 = '', type2 = '';
          for (const prevLine of lines570) {
            const declRe1 = new RegExp(`\\b(\\w+(?:<[^>]+>)?)\\s+${var1}\\s*[=;]`);
            const declRe2 = new RegExp(`\\b(\\w+(?:<[^>]+>)?)\\s+${var2}\\s*[=;]`);
            const m1 = declRe1.exec(prevLine);
            const m2 = declRe2.exec(prevLine);
            if (m1) type1 = m1[1];
            if (m2) type2 = m2[1];
          }
          if (type1 && type2 && type1 !== type2) {
            const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
            if (nearNode) {
              findings.push({
                source: nodeRef(nearNode), sink: nodeRef(nearNode),
                missing: 'CONTROL (correct conditional expression)',
                severity: 'low',
                description: `L${i + 1}: getClass().equals() comparison between ${type1} and ${type2} is always false — different concrete types.`,
                fix: 'Fix always-false expressions. Comparing getClass() of different types always returns false.',
                via: 'source_line_fallback',
              });
            }
          }
        }
      }
    }
  }

  return { cwe: 'CWE-570', name: 'Expression is Always False', holds: findings.length === 0, findings };
}

/**
 * CWE-571: Expression is Always True
 * Detects conditions that always evaluate to true, making else branches
 * unreachable and while loops potentially infinite. An always-true check in
 * a validation function means the validation never rejects — false safety.
 *
 * SECOND PASS NOTE: evaluateControlEffectiveness() ALREADY checks always-true
 * on CONTROL nodes. CWE-571 broadens this to ALL nodes. The second pass is
 * directly applicable — it catches the highest-severity variant.
 */
function verifyCWE571(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const ALWAYS_TRUE_LITERAL = /\bif\s*\(\s*(?:true|1|!0|!!1)\s*\)/;
  const TRUTHY_STRING = /\bif\s*\(\s*['"][^'"]+['"]\s*\)/;
  const TAUTOLOGY_OR = /\b(\w+)\s*\|\|\s*!\1\b/;
  const UNSIGNED_GE_ZERO = /\b(?:unsigned|uint\d*|size_t|usize|UInt)\s+\w+[\s\S]*?\bif\s*\([^)]*>=\s*0\s*\)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let matched = false;
    let detail = '';
    let severity: 'critical' | 'high' | 'medium' | 'low' = 'medium';

    if (ALWAYS_TRUE_LITERAL.test(code)) {
      matched = true;
      detail = 'condition is a literal true value (true/1/!0)';
      if (node.node_type === 'CONTROL') severity = 'high';
    } else if (TRUTHY_STRING.test(code)) {
      matched = true;
      detail = 'non-empty string literal in condition — always truthy';
    } else if (TAUTOLOGY_OR.test(code)) {
      if (!/NaN|isNaN/i.test(code)) {
        matched = true;
        detail = 'tautological condition (x || !x)';
      }
    } else if (UNSIGNED_GE_ZERO.test(code)) {
      matched = true;
      detail = 'unsigned type compared >= 0 — always true for unsigned values';
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (fix always-true expression to reflect intended logic)',
        severity,
        description: `Always-true expression at ${node.label}: ${detail}. ` +
          `The else branch is dead code.` +
          (node.node_type === 'CONTROL' ? ` Because this is a validation/control node, the check never rejects anything — it provides FALSE SAFETY.` : ''),
        fix: 'Fix the condition to test what was actually intended. ' +
          'If used as a feature flag, replace with a named constant from config. ' +
          'If used as an intentional infinite loop, add a break condition and timeout.',
          via: 'structural',
      });
    }
  }

  // --- Strategy 2: Source-scan (merged from generated) ---
  // Catches Juliet !getClass().equals() patterns and other source-level always-true expressions
  const src571 = map.source_code || '';
  if (src571 && findings.length === 0) {
    const lines571 = src571.split('\n');
    const alwaysTruePatterns571: Array<{ re: RegExp; desc: string }> = [
      { re: /\bif\s*\(\s*true\s*\)/, desc: 'if(true)' },
      { re: /\bif\s*\(\s*(\w+)\s*==\s*\s*\)/, desc: 'x == x (always true)' },
      { re: /\bif\s*\(\s*\w+\s*<\s*Integer\.MAX_VALUE\s*\)/, desc: 'n < Integer.MAX_VALUE (always true for int)' },
      { re: /\bif\s*\(\s*\w+\s*>\s*Integer\.MIN_VALUE\s*\)/, desc: 'n > Integer.MIN_VALUE (always true for int)' },
      { re: /\bif\s*\(\s*\w+\s*<=\s*Integer\.MAX_VALUE\s*\)/, desc: 'n <= Integer.MAX_VALUE (always true)' },
    ];
    // Detect negated different-type getClass().equals() — always true when comparing different concrete types
    // Juliet pattern: !random.getClass().equals(secureRandom.getClass()) where types differ
    const NEG_CLASS_EQUALS_TRUE = /\bif\s*\(\s*!(\w+)\.getClass\(\)\.equals\(\s*(\w+)\.getClass\(\)\s*\)\s*\)/;

    for (let i = 0; i < lines571.length; i++) {
      const line = lines571[i];
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*\/\*/.test(line)) continue;

      for (const pat of alwaysTruePatterns571) {
        if (pat.re.test(line)) {
          if (pat.desc.includes('while(true)')) continue;
          const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'CONTROL (correct conditional expression)',
              severity: 'low',
              description: `L${i + 1}: Expression always evaluates to true: ${pat.desc}. The else branch is dead code.`,
              fix: 'Fix always-true expressions. They indicate logic errors or dead branches.',
              via: 'source_line_fallback',
            });
          }
        }
      }

      // Check negated getClass().equals() with different-type variables
      const classMatch571 = NEG_CLASS_EQUALS_TRUE.exec(line);
      if (classMatch571) {
        const var1 = classMatch571[1];
        const var2 = classMatch571[2];
        if (var1 !== var2) {
          let type1 = '', type2 = '';
          for (const prevLine of lines571) {
            const declRe1 = new RegExp(`\\b(\\w+(?:<[^>]+>)?)\\s+${var1}\\s*[=;]`);
            const declRe2 = new RegExp(`\\b(\\w+(?:<[^>]+>)?)\\s+${var2}\\s*[=;]`);
            const m1 = declRe1.exec(prevLine);
            const m2 = declRe2.exec(prevLine);
            if (m1) type1 = m1[1];
            if (m2) type2 = m2[1];
          }
          if (type1 && type2 && type1 !== type2) {
            const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
            if (nearNode) {
              findings.push({
                source: nodeRef(nearNode), sink: nodeRef(nearNode),
                missing: 'CONTROL (correct conditional expression)',
                severity: 'low',
                description: `L${i + 1}: !getClass().equals() comparison between ${type1} and ${type2} is always true — different concrete types.`,
                fix: 'Fix always-true expressions. Negated getClass() comparison of different types always returns true.',
                via: 'source_line_fallback',
              });
            }
          }
        }
      }
    }
  }

  return { cwe: 'CWE-571', name: 'Expression is Always True', holds: findings.length === 0, findings };
}

/**
 * CWE-572: Call to Thread run() Instead of start()
 * In Java, calling thread.run() executes synchronously on the current thread
 * instead of spawning a new thread. This defeats concurrency, can cause blocking
 * (DoS), and breaks timeout mechanisms that rely on threading.
 *
 * SECOND PASS NOTE: If a CONTROL node uses thread.run() for timeout enforcement
 * (expecting async execution), the control is ineffective. A variant could be
 * added: "control uses synchronous execution where async was intended."
 */
function verifyCWE572(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Java: thread.run() — check that context involves Thread creation
  const THREAD_CREATION = /\b(?:Thread|Runnable|ExecutorService)\s+(\w+)|new\s+Thread\s*\(/;
  const THREAD_RUN = /\b\w+\s*\.\s*run\s*\(\s*\)/;
  // Python: threading.Thread + .run()
  const PYTHON_THREAD = /\bthreading\.Thread\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Java / Kotlin pattern
    if (THREAD_CREATION.test(code) && THREAD_RUN.test(code) && !/\.start\s*\(\s*\)/.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (Thread.start() instead of Thread.run())',
        severity: 'medium',
        description: `Thread.run() called instead of Thread.start() at ${node.label}. ` +
          `This executes the Runnable synchronously on the calling thread — no new thread is created. ` +
          `Any timeout, concurrency, or non-blocking behavior expected from threading will not work.`,
        fix: 'Replace .run() with .start() to spawn a new thread. ' +
          'Or use ExecutorService.submit() for managed thread pools. ' +
          'If synchronous execution is truly intended, document it clearly.',
          via: 'structural',
      });
    }

    // Python pattern
    if (PYTHON_THREAD.test(code) && THREAD_RUN.test(code) && !/\.start\s*\(\s*\)/.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (Thread.start() instead of Thread.run())',
        severity: 'medium',
        description: `threading.Thread.run() called directly at ${node.label}. ` +
          `Use .start() to spawn a new thread. .run() executes synchronously.`,
        fix: 'Replace thread.run() with thread.start(). ' +
          'Or use concurrent.futures.ThreadPoolExecutor for managed parallelism.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-572', name: 'Call to Thread run() Instead of start()', holds: findings.length === 0, findings };
}

/**
 * CWE-583: finalize() Method Declared Public
 * In Java, finalize() should be protected, not public. A public finalize()
 * can be called by any code at any time, triggering premature cleanup or
 * enabling finalizer resurrection attacks (subclass overrides finalize to
 * resurrect objects).
 *
 * SECOND PASS NOTE: Not applicable to evaluateControlEffectiveness().
 * This is a declaration-level issue, not a control-flow weakness.
 */
function verifyCWE583(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PUBLIC_FINALIZE = /\bpublic\s+(?:void\s+)?finalize\s*\(\s*\)/;
  const SAFE_FINALIZE = /\b(?:protected|private)\s+(?:void\s+)?finalize\s*\(\s*\)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    if (PUBLIC_FINALIZE.test(code) && !SAFE_FINALIZE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (protected access modifier on finalize())',
        severity: 'medium',
        description: `finalize() is declared public at ${node.label}. A public finalize() can be called by ` +
          `any code, triggering premature resource cleanup or enabling finalizer resurrection attacks.`,
        fix: 'Declare finalize() as protected: "protected void finalize() throws Throwable". ' +
          'Better yet, avoid finalize() entirely — use try-with-resources (AutoCloseable) or ' +
          'java.lang.ref.Cleaner (Java 9+). finalize() is deprecated since Java 9.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-583', name: 'finalize() Method Declared Public', holds: findings.length === 0, findings };
}

/**
 * CWE-585: Empty Synchronized Block
 * An empty synchronized(obj){} acquires and immediately releases the lock
 * without protecting code. It does NOT reliably provide a memory barrier.
 * In security contexts, this creates race conditions the developer believed
 * were prevented — false safety.
 *
 * SECOND PASS NOTE: If a CONTROL node contains an empty synchronized block,
 * the control is ineffective. This is a direct match for
 * evaluateControlEffectiveness() — "dead control" variant where the
 * synchronization provides false safety.
 */
function verifyCWE585(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const EMPTY_SYNC_JAVA = /\bsynchronized\s*\([^)]+\)\s*\{\s*\}/;
  const EMPTY_LOCK_CSHARP = /\block\s*\([^)]+\)\s*\{\s*\}/;
  const EMPTY_WITH_LOCK_PYTHON = /\bwith\s+\w*[Ll]ock\w*.*:\s*\n\s*pass\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let matched = false;
    let lang = '';

    if (EMPTY_SYNC_JAVA.test(code)) {
      matched = true;
      lang = 'synchronized block';
    } else if (EMPTY_LOCK_CSHARP.test(code)) {
      matched = true;
      lang = 'lock block';
    } else if (EMPTY_WITH_LOCK_PYTHON.test(code)) {
      matched = true;
      lang = 'with-lock block';
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (meaningful synchronization logic inside the block)',
        severity: 'medium',
        description: `Empty ${lang} at ${node.label}. An empty synchronized block acquires and immediately ` +
          `releases the lock without protecting any code. This does NOT provide a reliable memory barrier ` +
          `or happens-before guarantee.`,
        fix: 'Either add the code that needs synchronization inside the block, or remove the ' +
          'empty block entirely. If you need a memory barrier, use volatile (Java), ' +
          'Interlocked (C#), or threading.Event/Condition (Python).',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-585', name: 'Empty Synchronized Block', holds: findings.length === 0, findings };
}

/**
 * CWE-586: Explicit Call to Finalize()
 * Calling finalize() explicitly in Java is dangerous — the garbage collector
 * will call it again later, leading to double-free equivalent bugs. Resources
 * may be released twice or the object may be in an inconsistent state.
 *
 * SECOND PASS NOTE: If a CONTROL node calls finalize() as part of "cleanup
 * validation," that control is actively harmful. Not a standard second-pass
 * pattern, but a variant could flag controls that invoke destructors.
 */
function verifyCWE586(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Java: obj.finalize() or this.finalize() called explicitly
  const EXPLICIT_FINALIZE_CALL = /\b\w+\s*\.\s*finalize\s*\(\s*\)/;
  // Exclude method definitions
  const FINALIZE_DEFINITION = /\b(?:void|protected|public|private)\s+finalize\s*\(\s*\)/;

  // Python: obj.__del__() called explicitly
  const EXPLICIT_DEL = /\b\w+\s*\.\s*__del__\s*\(\s*\)/;

  // C++: explicit destructor call (obj.~ClassName())
  const EXPLICIT_DESTRUCTOR = /\b\w+\s*\.\s*~\w+\s*\(\s*\)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Java finalize()
    if (EXPLICIT_FINALIZE_CALL.test(code) && !FINALIZE_DEFINITION.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (use try-with-resources or Cleaner instead of explicit finalize())',
        severity: 'medium',
        description: `Explicit call to finalize() at ${node.label}. The garbage collector will call ` +
          `finalize() again during collection, causing double cleanup — this can corrupt state, ` +
          `release resources twice, or throw unexpected exceptions during GC.`,
        fix: 'Never call finalize() explicitly. Use try-with-resources with AutoCloseable for ' +
          'deterministic cleanup. For GC-time cleanup, use java.lang.ref.Cleaner (Java 9+).',
          via: 'structural',
      });
    }

    // Python __del__
    if (EXPLICIT_DEL.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (use context managers instead of explicit __del__())',
        severity: 'medium',
        description: `Explicit call to __del__() at ${node.label}. Python's garbage collector may ` +
          `call __del__ again. Use context managers (with statement) for deterministic cleanup.`,
        fix: 'Use "with" statements and context managers for resource cleanup. ' +
          'Implement __enter__/__exit__ instead of relying on __del__.',
          via: 'structural',
      });
    }

    // C++ explicit destructor
    if (EXPLICIT_DESTRUCTOR.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (use RAII / smart pointers instead of explicit destructor calls)',
        severity: 'high',
        description: `Explicit destructor call at ${node.label}. Unless this is placement-delete, ` +
          `calling a destructor explicitly leads to double-free when the object goes out of scope.`,
        fix: 'Use RAII (unique_ptr, shared_ptr) for automatic resource management. ' +
          'Explicit destructor calls are only valid after placement new.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-586', name: 'Explicit Call to Finalize()', holds: findings.length === 0, findings };
}

/**
 * CWE-587: Assignment of a Fixed Address to a Pointer
 * Assigning a hardcoded memory address to a pointer (e.g., int *p = (int*)0x8000)
 * defeats ASLR, is non-portable, and can crash if the address is unmapped. In
 * embedded systems (memory-mapped I/O) this is intentional, but in application
 * code it is always a bug.
 *
 * SECOND PASS NOTE: If a CONTROL node references a fixed memory address (e.g.,
 * checking a security flag at a known address), an attacker who can write to
 * that address can bypass the control. evaluateControlEffectiveness() could
 * check: "does this CONTROL reference a fixed memory address?" — making ASLR
 * bypass a control-effectiveness issue.
 */
function verifyCWE587(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // C/C++: pointer = (type*)0xADDRESS
  const FIXED_ADDR_CAST = /\b\w+\s*=\s*\(\s*\w+\s*\*\s*\)\s*0x[0-9a-fA-F]+/;
  // C/C++: type *ptr = (type*)0xADDRESS or type *ptr = 0xADDRESS
  const FIXED_ADDR_DIRECT = /\b(?:int|char|void|uint\d*|unsigned)\s*\*\s*\w+\s*=\s*(?:\(\s*\w+\s*\*\s*\)\s*)?0x[0-9a-fA-F]+/;
  // Go: unsafe.Pointer(uintptr(0xADDRESS))
  const GO_FIXED_ADDR = /unsafe\.Pointer\s*\(\s*uintptr\s*\(\s*0x[0-9a-fA-F]+\s*\)\s*\)/;
  // Rust: 0xADDRESS as *const/*mut type
  const RUST_FIXED_ADDR = /0x[0-9a-fA-F]+\s+as\s+\*(?:const|mut)\s+\w+/;

  // Safe: memory-mapped I/O in embedded (volatile, MMIO, register names)
  const EMBEDDED_SAFE = /\b(?:volatile|MMIO|__IO|register|GPIO|UART|SPI|I2C|DMA|PERIPH|BASE_ADDR|__attribute__)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let matched = false;
    let detail = '';

    if (FIXED_ADDR_CAST.test(code) || FIXED_ADDR_DIRECT.test(code)) {
      if (!EMBEDDED_SAFE.test(code)) {
        matched = true;
        detail = 'hardcoded memory address assigned to pointer (C/C++)';
      }
    } else if (GO_FIXED_ADDR.test(code)) {
      matched = true;
      detail = 'fixed address cast via unsafe.Pointer(uintptr(0x...)) in Go';
    } else if (RUST_FIXED_ADDR.test(code)) {
      matched = true;
      detail = 'fixed address cast to raw pointer in Rust';
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'TRANSFORM (dynamic allocation or proper address resolution)',
        severity: 'high',
        description: `Fixed memory address assigned to pointer at ${node.label}: ${detail}. ` +
          `Hardcoded addresses defeat ASLR (Address Space Layout Randomization), are non-portable, ` +
          `and will crash if the address is not mapped in the process address space.`,
        fix: 'Use dynamic allocation (malloc/new/Box) instead of fixed addresses. ' +
          'If this is for memory-mapped I/O in embedded systems, mark it volatile and ' +
          'use platform-provided register definitions. Never use fixed addresses in application code.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-587', name: 'Assignment of a Fixed Address to a Pointer', holds: findings.length === 0, findings };
}

/**
 * CWE-481: Assigning Instead of Comparing
 * Pattern: Assignment operator (=) used inside a conditional expression where
 * comparison (==, ===) was intended. Classic bug: `if (x = 5)` instead of `if (x == 5)`.
 * Detection: Find assignment-in-condition patterns in code snapshots, excluding
 * intentional patterns like `while (line = readline())`.
 */
function verifyCWE481(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Safe patterns — intentional assign-in-condition (iterator patterns)
  const SAFE_ASSIGN_RE = /\b(while\s*\(\s*(?:line|chunk|row|record|match|result|data|buf|byte|char|item|entry|node|elem|next|val)\s*=\s*|for\s*\(\s*(?:let|var|const)\s+|if\s*\(\s*(?:const|let)\s+)/i;
  // Double-paren convention: if ((x = getValue())) signals intentional assignment
  const DOUBLE_PAREN_RE = /\b(?:if|while)\s*\(\s*\(/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const lines = code.split('\n');

    for (const line of lines) {
      if (SAFE_ASSIGN_RE.test(line)) continue;
      // Double-paren convention (e.g., `if ((x = getValue()))`) signals intentional assignment
      if (DOUBLE_PAREN_RE.test(line)) continue;

      // Look for if/while with assignment inside parens
      const condMatch = line.match(/\b(if|while)\s*\((.+)\)\s*(?:\{|$)/);
      if (!condMatch) continue;

      const condBody = condMatch[2];
      // Remove all comparison/compound operators to isolate bare =
      const neutralized = condBody
        .replace(/===|!==|==|!=|<=|>=|=>|<<|>>|>>>|\+=|-=|\*=|\/=|%=|&=|\|=|\^=|~=|&&|\|\|/g, '@@OP@@');

      // Now check if there's a bare = remaining (assignment)
      if (/[^@]=[^@=]/.test(neutralized)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (comparison operator instead of assignment in conditional)',
          severity: 'high',
          description: `${node.label} uses assignment (=) inside a conditional expression where comparison (== or ===) was likely intended. ` +
            `This always evaluates to the assigned value's truthiness, not whether values are equal.`,
          fix: 'Replace = with == or === in the conditional. If assignment is intentional, wrap in extra parentheses: if ((x = getValue())) { ... } to signal intent.',
          via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-481', name: 'Assigning Instead of Comparing', holds: findings.length === 0, findings };
}

/**
 * CWE-482: Comparing Instead of Assigning
 * Pattern: Comparison operator (==, ===) used as a standalone statement where
 * assignment (=) was intended. Example: `x == 5;` instead of `x = 5;`.
 * Detection: Find comparison expressions that appear as standalone statements
 * (not inside if/while/for/return/variable declarations).
 */
function verifyCWE482(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code often uses comparison patterns in idiomatic ways (comma expressions, etc.)
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-482', name: 'Comparing Instead of Assigning', holds: true, findings };
  }

  // A comparison as a standalone statement — not inside control flow or return
  const STANDALONE_CMP_RE = /^[ \t]*(?!(?:if|else|while|for|return|var|let|const|assert|expect|should|describe|it|test|console)\b)([a-zA-Z_$][\w$.]*)\s*(?:===?|!==?)\s*[^;]+;?\s*$/m;

  // In Python: bare comparison as statement
  const PY_STANDALONE_RE = /^[ \t]*(?!(?:if|elif|while|for|return|assert|print|yield)\b)([a-zA-Z_][\w.]*)\s*==\s*[^:]+$/m;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const lines = code.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

      if (STANDALONE_CMP_RE.test(line) || PY_STANDALONE_RE.test(line)) {
        // Exclude test assertions
        if (/\b(expect|should|assert|test|describe|it\s*\(|spec)\b/i.test(line)) continue;
        // Exclude chained method calls (fluent API)
        if (/\.\w+\(/.test(line) && !/===?/.test(line.split('(')[0])) continue;

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (assignment operator where comparison was used as no-op)',
          severity: 'medium',
          description: `${node.label} contains a comparison expression (== or ===) used as a standalone statement. ` +
            `The comparison result is discarded — this likely should be an assignment (=) instead.`,
          fix: 'Replace == or === with = if assignment was intended. If the comparison is intentional (side-effect check), store or use the result.',
          via: 'structural',
        });
        break;
      }
    }
  }

  // --- Source-based detection: if((var == (expr)) == true) pattern ---
  // Catches the Juliet pattern where == is used inside an if-condition where = was intended.
  // Example: if((isZero == (zeroOrOne == 0)) == true) should be if((isZero = (zeroOrOne == 0)) == true)
  if (findings.length === 0) {
    const src482 = map.source_code || '';
    if (src482) {
      const lines = src482.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

        // Pattern: if((boolVar == (expr)) == true) — the outer == before (expr) should be =
        if (/\bif\s*\(\s*\(\s*\w+\s*==\s*\([^)]+\)\s*\)\s*==\s*true\s*\)/.test(line)) {
          const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'TRANSFORM (use = for assignment, not == for comparison)',
              severity: 'medium',
              description: `L${i + 1}: Comparison (==) used where assignment (=) was likely intended inside if-condition.`,
              fix: 'Use = for assignment, == for comparison. The == operator does not modify the variable.',
              via: 'source_line_fallback',
            });
          }
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-482', name: 'Comparing Instead of Assigning', holds: findings.length === 0, findings };
}

/**
 * CWE-483: Incorrect Block Delimitation
 * Detects three patterns:
 *   1. Multiline: `if (cond)\n  stmt1;\n  stmt2;` — indentation suggests both are in the block but only stmt1 is.
 *   2. Semicolon: `if (cond);` — semicolon creates an empty body, the braced block below always executes.
 *   3. Single-line: `if (cond) stmt1; stmt2;` — stmt2 is NOT in the if block despite being on the same line.
 */
function verifyCWE483(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const lines = code.split('\n');
    let found = false;

    for (let i = 0; i < lines.length; i++) {
      if (found) break;
      const line = lines[i];
      const trimmed = line.trim();

      // --- Pattern 2: Semicolon after control statement: `if (cond);` ---
      // The semicolon creates an empty body; the braced block that follows always executes.
      const semicolonMatch = trimmed.match(/^(if\s*\([^)]*\)|for\s*\([^)]*\)|while\s*\([^)]*\))\s*;\s*$/);
      if (semicolonMatch) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (proper block delimitation with braces)',
          severity: 'medium',
          description: `${node.label} has a control statement (${semicolonMatch[1].split('(')[0].trim()}) immediately followed by a semicolon. ` +
            `The semicolon acts as an empty body — the block that follows always executes regardless of the condition.`,
          fix: 'Remove the erroneous semicolon and use braces: `if (cond) { ... }`. The semicolon after a control statement creates an empty body.',
          via: 'structural',
        });
        found = true;
        break;
      }

      // --- Pattern 3: Single-line multiple statements: `if (cond) stmt1; stmt2;` ---
      // Match a control keyword with condition, then look for two or more semicolons after
      const singleLineMatch = trimmed.match(/^(if\s*\([^)]*\)|else\s+if\s*\([^)]*\)|for\s*\([^)]*\)|while\s*\([^)]*\))\s+(.+)$/);
      if (singleLineMatch) {
        const body = singleLineMatch[2];
        // Count statements by splitting on ; — if there are 2+ statements, only the first is controlled
        // But skip if the body starts with { (proper braces)
        if (!body.startsWith('{')) {
          const stmts = body.split(';').filter(s => s.trim().length > 0);
          if (stmts.length >= 2) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(node),
              missing: 'CONTROL (proper block delimitation with braces)',
              severity: 'medium',
              description: `${node.label} has a control statement (${singleLineMatch[1].split('(')[0].trim()}) on a single line with multiple statements. ` +
                `Only the first statement is controlled — subsequent statements always execute regardless of the condition.`,
              fix: 'Always use braces {} with control flow statements. Separate statements onto their own lines inside a block.',
              via: 'structural',
            });
            found = true;
            break;
          }
        }
      }

      // --- Pattern 1: Multiline indentation mismatch (original) ---
      if (i >= lines.length - 2) continue;
      const controlMatch = trimmed.match(/^(if\s*\(.*\)|else\s+if\s*\(.*\)|else|for\s*\(.*\)|while\s*\(.*\))\s*$/);
      if (!controlMatch) continue;

      const nextLine = lines[i + 1];
      if (!nextLine || nextLine.trim() === '{' || nextLine.trim() === '') continue;

      const nextIndent = nextLine.match(/^(\s*)/)?.[1]?.length ?? 0;
      const controlIndent = line.match(/^(\s*)/)?.[1]?.length ?? 0;
      if (nextIndent <= controlIndent) continue;

      const afterLine = lines[i + 2];
      if (!afterLine) continue;
      const afterIndent = afterLine.match(/^(\s*)/)?.[1]?.length ?? 0;
      const afterTrimmed = afterLine.trim();

      if (!afterTrimmed || afterTrimmed.startsWith('//') || afterTrimmed.startsWith('#')) continue;

      if (afterIndent >= nextIndent && afterTrimmed !== '}' && !afterTrimmed.startsWith('else') && !afterTrimmed.startsWith('catch') && !afterTrimmed.startsWith('finally')) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (proper block delimitation with braces)',
          severity: 'medium',
          description: `${node.label} has a control statement (${controlMatch[1].split('(')[0].trim()}) without braces, ` +
            `followed by multiple statements at the same indentation level. Only the first statement is controlled — ` +
            `subsequent statements always execute regardless of the condition.`,
          fix: 'Always use braces {} with control flow statements, even for single-line bodies. This prevents misleading indentation bugs.',
          via: 'structural',
        });
        found = true;
        break;
      }
    }
  }

  // --- Source-based detection: scan raw source_code for multiline indentation mismatch ---
  // The node-level code_snapshot may not preserve multi-line indentation structure.
  // Scanning the full source catches the Juliet pattern where if(cond)\n  stmt1;\n  stmt2;
  // has stmt2 at the same indent as stmt1 but outside the if block.
  if (findings.length === 0) {
    const src483 = map.source_code || '';
    if (src483) {
      const srcLines = src483.split('\n');
      for (let i = 0; i < srcLines.length - 2; i++) {
        const line = srcLines[i];
        const trimmed = line.trim();
        if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

        // Semicolon after control: if (cond);
        const semiMatch = trimmed.match(/^(if\s*\([^)]*\)|for\s*\([^)]*\)|while\s*\([^)]*\))\s*;\s*$/);
        if (semiMatch) {
          const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'CONTROL (proper block delimitation with braces)',
              severity: 'medium',
              description: `L${i + 1}: Control statement followed by semicolon creates empty body.`,
              fix: 'Remove the erroneous semicolon and use braces: if (cond) { ... }.',
              via: 'source_line_fallback',
            });
          }
          break;
        }

        // Multiline indentation mismatch
        const controlMatch = trimmed.match(/^(if\s*\(.*\)|else\s+if\s*\(.*\)|else|for\s*\(.*\)|while\s*\(.*\))\s*$/);
        if (!controlMatch) continue;

        const nextLine = srcLines[i + 1];
        if (!nextLine || nextLine.trim() === '{' || nextLine.trim() === '') continue;

        const nextIndent = nextLine.match(/^(\s*)/)?.[1]?.length ?? 0;
        const controlIndent = line.match(/^(\s*)/)?.[1]?.length ?? 0;
        if (nextIndent <= controlIndent) continue;

        const afterLine = srcLines[i + 2];
        if (!afterLine) continue;
        const afterIndent = afterLine.match(/^(\s*)/)?.[1]?.length ?? 0;
        const afterTrimmed = afterLine.trim();

        if (!afterTrimmed || afterTrimmed.startsWith('//') || afterTrimmed.startsWith('#')) continue;

        if (afterIndent >= nextIndent && afterTrimmed !== '}' && !afterTrimmed.startsWith('else') &&
            !afterTrimmed.startsWith('catch') && !afterTrimmed.startsWith('finally')) {
          const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 3) || map.nodes[0];
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'CONTROL (proper block delimitation with braces)',
              severity: 'medium',
              description: `L${i + 1}: Control statement (${controlMatch[1].split('(')[0].trim()}) without braces, ` +
                `followed by multiple indented statements. Only the first is controlled.`,
              fix: 'Always use braces {} with control flow statements.',
              via: 'source_line_fallback',
            });
          }
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-483', name: 'Incorrect Block Delimitation', holds: findings.length === 0, findings };
}

/**
 * CWE-484: Omitted Break Statement in Switch
 * Pattern: A switch case that falls through to the next case without a break/return/throw,
 * and without an explicit fallthrough comment indicating intent.
 */
function verifyCWE484(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SWITCH_RE = /\bswitch\s*\([^)]*\)\s*\{/;
  const FALLTHROUGH_RE = /\/[/*]\s*(?:fall[s\-]?through|falls?\s+through|intentional\s+fall|no\s+break|FALLTHROUGH|FALLS?\s*THROUGH)/i;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (!SWITCH_RE.test(code)) continue;

    const lines = code.split('\n');
    let inCase = false;
    let hasTerminator = false;
    let caseLabel = '';
    let hasFallthroughComment = false;
    let hasBody = false;

    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();

      const caseMatch = trimmed.match(/^(case\s+.+?|default)\s*:/);
      if (caseMatch) {
        if (inCase && hasBody && !hasTerminator && !hasFallthroughComment && caseLabel) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (break/return/throw statement in switch case)',
            severity: 'medium',
            description: `${node.label} has a switch case "${caseLabel}" that falls through to "${caseMatch[1]}" without ` +
              `a break, return, or throw statement. If fallthrough is intentional, add a "// fallthrough" comment.`,
            fix: 'Add break; at the end of each case clause. If fallthrough is intentional, add a // fallthrough comment to document intent.',
            via: 'structural',
          });
        }

        inCase = true;
        hasTerminator = false;
        hasFallthroughComment = false;
        hasBody = false;
        caseLabel = caseMatch[1];

        const afterColon = trimmed.slice(trimmed.indexOf(':') + 1).trim();
        if (afterColon && afterColon !== '{') {
          hasBody = true;
          if (/\b(break|return|throw|continue|goto)\b/.test(afterColon)) {
            hasTerminator = true;
          }
        }
        continue;
      }

      if (!inCase) continue;

      if (trimmed && trimmed !== '{' && trimmed !== '}') {
        hasBody = true;
      }

      if (/\b(break|return|throw|continue|goto)\b/.test(stripComments(trimmed))) {
        hasTerminator = true;
      }

      if (FALLTHROUGH_RE.test(lines[i])) {
        hasFallthroughComment = true;
      }
    }
  }

  return { cwe: 'CWE-484', name: 'Omitted Break Statement in Switch', holds: findings.length === 0, findings };
}

/**
 * CWE-486: Comparison of Classes by Name
 * Pattern: Using string comparison of class/type names instead of proper type checks.
 * These break with minification, obfuscation, inheritance, and module loading.
 */
function verifyCWE486(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CLASS_NAME_CMP_PATTERNS = [
    /getClass\(\)\s*\.\s*(?:getName|getSimpleName|getCanonicalName)\(\)\s*\.\s*equals\s*\(/,
    /Class\.forName\s*\(\s*["']/,
    /constructor\.name\s*(?:===?|!==?)\s*["']/,
    /Object\.prototype\.toString\.call\([^)]*\)\s*===?\s*["']\[object\s/,
    /(?:type\s*\([^)]*\)\s*\.\s*__name__|__class__\s*\.\s*__name__)\s*==\s*["']/,
    /GetType\(\)\s*\.\s*(?:Name|ToString\(\))\s*==\s*["']/,
    /\.class\.name\s*==\s*["']/,
  ];

  const SAFE_TYPE_RE = /\b(instanceof|is_a\?|isinstance\s*\(|isInstance\s*\(|\.isAssignableFrom\s*\(|is\s+\w+|as\s+\w+|type\s+guard|narrowing)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    for (const pattern of CLASS_NAME_CMP_PATTERNS) {
      if (pattern.test(code)) {
        if (SAFE_TYPE_RE.test(code)) continue;

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (type-safe comparison using instanceof/isInstance instead of string name)',
          severity: 'medium',
          description: `${node.label} compares class/type identity using string names. ` +
            `This breaks with minification (JS), obfuscation, class renaming, subclasses, and across module boundaries. ` +
            `Two classes with the same name from different packages would match incorrectly.`,
          fix: 'Use instanceof (JS/Java), isinstance() (Python), is (C#), or is_a? (Ruby) for type checking. ' +
            'These handle inheritance correctly and survive refactoring.',
            via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-486', name: 'Comparison of Classes by Name', holds: findings.length === 0, findings };
}

/**
 * CWE-489: Active Debug Code
 * Pattern: Debug statements, breakpoints, debug flags, or diagnostic code left in
 * production code without environment gating.
 */
function verifyCWE489(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DEBUG_CODE_RE = /\b(debugger\b|console\.(log|debug|trace|dir|table|assert|count|time|timeEnd|profile|profileEnd)|System\.out\.print(?:ln)?|System\.err\.print(?:ln)?|println!\s*\(|dbg!\s*\(|print\s*\(\s*f?["'](?:debug|DEBUG|DBG)|pdb\.set_trace|breakpoint\(\)|binding\.pry|byebug|debug\.print|Debug\.(?:Log|Print|Assert|Break|Write)|Debugger\.(?:Break|Launch|Log)|DLOG|NSLog|os_log.*debug|var_dump|print_r|error_log.*debug|dd\s*\(|dump\s*\(|ray\s*\(|xdebug)/i;

  const DEBUG_FLAG_RE = /\b(debug\s*[:=]\s*true|DEBUG\s*[:=]\s*true|verbose\s*[:=]\s*true|trace\s*[:=]\s*true|FLASK_DEBUG\s*=\s*['"]?1|DJANGO_DEBUG\s*=\s*True|app\.debug\s*=\s*(?:true|True)|WP_DEBUG.*true|XDEBUG_MODE|EnableDebugging|IsDebug\s*=\s*true|LogLevel\s*[:=]\s*['"]?(?:trace|debug|verbose))\b/i;

  const DEBUG_IMPORT_RE = /\b(require\s*\(\s*['"]debug['"]|import\s+pdb|from\s+pdb\s+import|import\s+ipdb|require\s+['"]byebug|using\s+System\.Diagnostics\.Debug)\b/;

  const SAFE_RE = /\b(if\s*\(\s*process\.env\.NODE_ENV\s*[!=]==?\s*['"]production|isProduction|isProd|NODE_ENV\s*[!=]==?\s*['"]production|#ifdef\s+DEBUG|#if\s+DEBUG|when\s*\(\s*debug|debug[._]?guard|\.env\.DEBUG|process\.env\.DEBUG|BuildConfig\.DEBUG|#ifndef\s+NDEBUG|if\s*.*debug.*mode|development.*only|test.*only)\b/i;

  const TEST_FILE_RE = /\b(test|spec|__test__|\.test\.|\.spec\.|_test\.)\b/i;

  for (const node of map.nodes) {
    if (TEST_FILE_RE.test(node.file) || TEST_FILE_RE.test(node.label)) continue;
    if (node.tags.some(t => t === 'test' || t === 'spec')) continue;

    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    const hasDebugCode = DEBUG_CODE_RE.test(code);
    const hasDebugFlag = DEBUG_FLAG_RE.test(code);
    const hasDebugImport = DEBUG_IMPORT_RE.test(code);

    if ((hasDebugCode || hasDebugFlag || hasDebugImport) && !SAFE_RE.test(code)) {
      const what = hasDebugFlag ? 'debug flag/configuration' : hasDebugImport ? 'debug library import' : 'debug statement';
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (environment gate or removal of debug code)',
        severity: hasDebugFlag ? 'high' : 'medium',
        description: `${node.label} contains active ${what} that is not gated by environment checks. ` +
          `Debug code in production can expose internal state, degrade performance, and increase attack surface.`,
        fix: 'Remove debug code before deployment. If needed for diagnostics, gate behind environment checks: ' +
          'if (process.env.NODE_ENV !== "production") { ... }. Use a proper logging framework with configurable levels.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-489', name: 'Active Debug Code', holds: findings.length === 0, findings };
}

/**
 * CWE-491: Public cloneable() Method Without Final (Java/OOP)
 * Pattern: A class implements Cloneable but is not final, allowing subclasses
 * to override clone() and bypass security checks.
 */
function verifyCWE491(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const JAVA_CLONEABLE_RE = /(?:public\s+)?class\s+\w+(?:\s+extends\s+\w+)?\s+implements\s+[^{]*\bCloneable\b/;
  const JAVA_FINAL_CLASS_RE = /\bfinal\s+class\b/;
  const JAVA_FINAL_CLONE_RE = /\bfinal\s+.*\bclone\s*\(/;

  const CLONE_METHOD_RE = /\b(?:public|export)\s+(?:function\s+)?(?:clone|copy|duplicate|deepCopy|shallowCopy)\s*\(/i;
  const RETURNS_THIS_RE = /return\s+(?:this|self|@?(?:clone|dup|copy))\b/i;

  const PY_COPY_RE = /def\s+__(?:copy|deepcopy)__\s*\(/;

  const SAFE_CLONE_RE = /\b(Object\.assign\s*\(\s*\{\}|structuredClone|\{\.\.\.(?:this|self)|JSON\.parse\s*\(\s*JSON\.stringify|copy\.deepcopy|deepcopy\(|clone\(\)\s*\{[^}]*new\s+\w+|DefensiveCopy|immutable)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (JAVA_CLONEABLE_RE.test(code) && !JAVA_FINAL_CLASS_RE.test(code) && !JAVA_FINAL_CLONE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (final class or final clone() method)',
        severity: 'medium',
        description: `${node.label} implements Cloneable but the class is not final and clone() is not final. ` +
          `A malicious subclass can override clone() to return a manipulated copy, bypassing security invariants.`,
        fix: 'Declare the class as final, or make clone() final. Consider implementing a copy constructor instead of Cloneable. ' +
          'If clone() is needed, ensure it creates a truly deep copy of all mutable fields.',
          via: 'structural',
      });
    }

    if (CLONE_METHOD_RE.test(code) && RETURNS_THIS_RE.test(code) && !SAFE_CLONE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (deep copy or defensive copy in clone method)',
        severity: 'low',
        description: `${node.label} has a public clone/copy method that may return a shallow copy or direct reference. ` +
          `Callers who modify the cloned object may inadvertently modify shared mutable state.`,
        fix: 'Return a deep copy from clone/copy methods. Use structuredClone(), Object.assign({}, ...) with nested copies, ' +
          'or JSON.parse(JSON.stringify(...)) for simple objects. Ensure all mutable fields are independently copied.',
          via: 'structural',
      });
    }

    if (PY_COPY_RE.test(code) && !SAFE_CLONE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (deep copy implementation for mutable internal state)',
        severity: 'low',
        description: `${node.label} defines __copy__ or __deepcopy__ — verify that all mutable internal state is properly deep-copied. ` +
          `A shallow copy that shares mutable references with the original can lead to unintended state sharing.`,
        fix: 'Use copy.deepcopy() for nested mutable structures. Override __deepcopy__ to ensure all internal collections are independently copied.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-491', name: 'Public cloneable() Method Without Final', holds: findings.length === 0, findings };
}

/**
 * CWE-495: Private Data Structure Returned From Public Method
 * Pattern: A public method directly returns a reference to a private/internal mutable
 * data structure. Callers can modify the internal state.
 */
function verifyCWE495(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const RETURN_INTERNAL_MUTABLE_PATTERNS = [
    /return\s+this\.\s*(?:_\w+|\w+(?:List|Array|Map|Set|Items|Collection|Data|Records|Entries|Cache|Store|Queue|Stack|Buffer))\s*;/i,
    /return\s+self\.(?:_\w+|__\w+)\s*$/m,
    /return\s+(?:this\.)?(?:_\w+|\w+(?:List|Array|Map|Set|Items|Collection|Data|Records|Entries|Cache|Store))\s*;/i,
    /return\s+@\w+\s*$/m,
  ];

  const SAFE_RETURN_RE = /\b(\.slice\(\)|\.concat\(\)|Array\.from|Object\.assign\s*\(\s*\{\}|structuredClone|\[\.\.\.this\.|new\s+(?:Array|Set|Map|List|ArrayList|HashMap|HashSet)\s*\(|Collections\.unmodifiable|List\.copyOf|Map\.copyOf|Set\.copyOf|\.freeze\(|Object\.freeze|readonly|Immutable|unmodifiable|deepCopy|defensiveCopy|\.copy\(\)|copy\.copy|copy\.deepcopy|\.clone\(\)|\.toList\(\)|\.toArray\(\)|\.toMap\(\)|ImmutableList|ImmutableMap|ImmutableSet|\.dup\b|\.freeze\b|\.frozen\?)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    for (const pattern of RETURN_INTERNAL_MUTABLE_PATTERNS) {
      if (pattern.test(code) && !SAFE_RETURN_RE.test(code)) {
        if (/\b(private|protected)\s+\w+\s*\(/.test(code) && !/\bpublic\b/.test(code)) continue;

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (defensive copy before returning internal data structure)',
          severity: 'medium',
          description: `${node.label} returns a direct reference to an internal mutable data structure. ` +
            `Any caller can modify the returned reference and corrupt the object's internal state, ` +
            `violating encapsulation and potentially bypassing invariant checks.`,
          fix: 'Return a defensive copy: return [...this.items] (JS), return list(self._items) (Python), ' +
            'return Collections.unmodifiableList(this.items) (Java), or return @items.dup (Ruby). ' +
            'Alternatively, use immutable data structures.',
            via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-495', name: 'Private Data Structure Returned From Public Method', holds: findings.length === 0, findings };
}

/**
 * CWE-496: Public Data Assigned to Private Array-Typed Field
 * Pattern: A constructor/setter directly assigns an externally-provided array/collection
 * to a private field without copying. Mirror of CWE-495.
 */
function verifyCWE496(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const ASSIGN_PARAM_PATTERNS = [
    /this\.\s*(?:_?\w+(?:List|Array|Map|Set|Items|Collection|Data|Records|Entries|Cache|Store|Queue|Stack|Buffer|s))\s*=\s*(?!(?:new |Object\.|Array\.|structuredClone|\[|\{\s*\.\.\.))(\w+)\s*;/i,
    /self\.(?:_\w+|__\w+)\s*=\s*(?!(?:list\(|dict\(|set\(|copy\.|deepcopy\(|tuple\(|\[|\{))(\w+)\s*$/m,
    /this\.\s*\w+\s*=\s*(?!(?:new |Collections\.|List\.copyOf|Map\.copyOf|Set\.copyOf|Arrays\.copyOf|\w+\.clone\(\)))(\w+)\s*;/,
    /@\w+\s*=\s*(?!.*\.(?:dup|clone|freeze))(\w+)\s*$/m,
  ];

  const CONSTRUCTOR_SETTER_RE = /\b(constructor|__init__|initialize|def\s+set\w+|set\s+\w+\s*\(|set\w+\s*\(.*\)\s*\{)/i;

  const SAFE_ASSIGN_RE = /\b(\.slice\(\)|\.concat\(\)|Array\.from|\[\.\.\.|\{\.\.\.|\bnew\s+(?:Array|Set|Map|List|ArrayList|HashMap|HashSet)|structuredClone|Object\.assign|Collections\.unmodifiable|List\.copyOf|Map\.copyOf|copy\.copy|copy\.deepcopy|list\(|dict\(|set\(|tuple\(|\.dup\b|\.clone\(\)|\.freeze\b|Arrays\.copyOf|ImmutableList|ImmutableMap)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!CONSTRUCTOR_SETTER_RE.test(code)) continue;

    for (const pattern of ASSIGN_PARAM_PATTERNS) {
      if (pattern.test(code) && !SAFE_ASSIGN_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (defensive copy when storing external data in private field)',
          severity: 'medium',
          description: `${node.label} directly assigns an externally-provided collection/array to an internal field. ` +
            `The caller retains a reference to the same object and can modify internal state from outside, ` +
            `bypassing any validation or invariant enforcement.`,
          fix: 'Copy the input before storing: this.items = [...items] (JS), self._items = list(items) (Python), ' +
            'this.items = new ArrayList<>(items) (Java), @items = items.dup (Ruby). ' +
            'This breaks the aliasing link between external and internal references.',
            via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-496', name: 'Public Data Assigned to Private Array-Typed Field', holds: findings.length === 0, findings };
}

/**
 * CWE-499: Serializable Class Containing Sensitive Data
 * Pattern: A serializable class contains fields with sensitive names without
 * transient/JsonIgnore/exclude annotations.
 */
function verifyCWE499(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SERIALIZABLE_RE = /\b(implements\s+Serializable|Serializable|@Entity|@Document|@Table|@JsonSerialize|JSON\.stringify|toJSON\s*\(|Gson|ObjectMapper|pickle\.|marshal\.|serialize\(|DataContract|Parcelable|@Serializable|@Data|@Getter|@AllArgsConstructor|export\s+class\s+\w+.*(?:Entity|Model|Dto|DTO|Record|Bean))\b/i;

  const SENSITIVE_FIELD_RE = /\b(?:private|protected|public|#)?\s*(?:(?:string|String|char\[\]|byte\[\]|SecureString)\s+)?(?:_?)?(password|passwd|pwd|secret|secretKey|apiKey|api_key|token|accessToken|access_token|refreshToken|refresh_token|privateKey|private_key|ssn|socialSecurity|creditCard|credit_card|cardNumber|card_number|cvv|pin|encryptionKey|encryption_key|masterKey|master_key|authToken|auth_token|sessionSecret|session_secret)\b/i;

  const EXCLUDE_RE = /\b(transient|@JsonIgnore|@Exclude|@Transient|JsonIgnore|@XmlTransient|NonSerialized|@JsonProperty\s*\(\s*access\s*=\s*Access\.WRITE_ONLY|@Column\s*\(.*insertable\s*=\s*false|writeOnly|hidden\s*[:=]\s*true|exclude|omit|@Secret|password_digest|password_hash|hashed|encrypted)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!SERIALIZABLE_RE.test(code)) continue;
    if (!SENSITIVE_FIELD_RE.test(code)) continue;
    if (EXCLUDE_RE.test(code)) continue;

    const sensitiveMatch = code.match(SENSITIVE_FIELD_RE);
    const fieldName = sensitiveMatch ? sensitiveMatch[1] : 'sensitive data';

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'CONTROL (transient/JsonIgnore/exclude annotation on sensitive fields)',
      severity: 'high',
      description: `${node.label} is a serializable class containing a sensitive field ("${fieldName}") without exclusion from serialization. ` +
        `When this object is serialized (to JSON, to database, over network, to logs), the sensitive data is included in the output.`,
      fix: 'Mark sensitive fields as transient (Java), use @JsonIgnore (Jackson), [JsonIgnore] (C#), ' +
        'or exclude from toJSON(). In ORMs, use @Column(insertable=false) or separate DTOs that omit sensitive fields. ' +
        'Never serialize raw passwords — store only hashes.',
        via: 'structural',
    });
  }

  return { cwe: 'CWE-499', name: 'Serializable Class Containing Sensitive Data', holds: findings.length === 0, findings };
}

/**
 * CWE-500: Public Static Field Not Marked Final
 * Java: `public static String field = ...` without `final`.
 * Any code can reassign the field, leading to unexpected global state mutations.
 * Fix: add `final` modifier or make the field private.
 */
function verifyCWE500(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Match public static <type> <name> NOT preceded by final
  // Handles: public static String x, public static int x, public static MyType x
  // Must NOT match: public static final ..., public final static ..., final public static ...
  const PSF_NOT_FINAL = /\bpublic\s+static\s+(?!final\b)(\w+(?:\s*<[^>]*>)?)\s+(\w+)\s*[=;]/;
  const STATIC_PUBLIC_NOT_FINAL = /\bstatic\s+public\s+(?!final\b)(\w+(?:\s*<[^>]*>)?)\s+(\w+)\s*[=;]/;
  // Also catch: public <type> that is actually "public static" split across analysis
  const FINAL_ANYWHERE = /\bfinal\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|describe\s*\(|it\s*\()\b/i.test(node.label)) continue;

    // Check each line individually for the pattern
    const lines = code.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      let match = trimmed.match(PSF_NOT_FINAL) || trimmed.match(STATIC_PUBLIC_NOT_FINAL);
      if (!match) continue;
      // Make sure 'final' isn't elsewhere on the same line (e.g., "public static final" with odd spacing)
      if (FINAL_ANYWHERE.test(trimmed)) continue;

      const fieldType = match[1];
      const fieldName = match[2];

      // Skip main method signatures and other non-field patterns
      if (/\bvoid\b|\bclass\b|\binterface\b|\benum\b/.test(fieldType)) continue;

      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (add final modifier to public static field)',
        severity: 'medium',
        description: `${node.label} declares a public static field "${fieldName}" of type "${fieldType}" without the final modifier. ` +
          `Any code with access to the class can reassign this field, leading to unexpected global state mutations ` +
          `and potential security bypasses (e.g., overwriting a default error message or config value).`,
        fix: 'Add the final modifier: `public static final`. If the field must be mutable, make it private ' +
          'and provide controlled access through getter/setter methods with appropriate validation.',
          via: 'structural',
      });
      break; // One finding per node is sufficient
    }
  }

  return { cwe: 'CWE-500', name: 'Public Static Field Not Marked Final', holds: findings.length === 0, findings };
}

/**
 * CWE-582: Array Declared Public, Final, and Static
 * Java: `public static final int[] arr = {...}` or `public final static int arr[] = {...}`
 * The reference is final (can't reassign), but array CONTENTS are mutable.
 * Any code can do `ClassName.arr[0] = evil`. Fix: make private, return copies.
 */
function verifyCWE582(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Match public static final <type>[] name or public final static <type>[] name
  // Also handles: <type> name[] (C-style array declaration)
  const ARRAY_PSF_JAVA = /\bpublic\s+(?:static\s+final|final\s+static)\s+(\w+)\s*\[\s*\]\s+(\w+)|public\s+(?:static\s+final|final\s+static)\s+(\w+)\s+(\w+)\s*\[\s*\]/;
  // Also: static public final, final public static, etc.
  const ARRAY_PSF_ALT = /\b(?:static\s+public\s+final|final\s+public\s+static|final\s+static\s+public|static\s+final\s+public)\s+(\w+)\s*(?:\[\s*\]\s+(\w+)|(\w+)\s*\[\s*\])/;

  // Safe patterns: defensive copy, unmodifiable, or clone
  const SAFE_ARRAY = /\b(\.clone\(\)|Arrays\.copyOf|System\.arraycopy|Collections\.unmodifiable|List\.of|private\s+(?:static\s+)?final)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|describe\s*\(|it\s*\()\b/i.test(node.label)) continue;

    const lines = code.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      let match = trimmed.match(ARRAY_PSF_JAVA) || trimmed.match(ARRAY_PSF_ALT);
      if (!match) continue;

      // Extract type and name from whichever capture group matched
      const fieldType = match[1] || match[3] || 'unknown';
      const fieldName = match[2] || match[4] || 'unknown';

      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (make array private, return defensive copies)',
        severity: 'medium',
        description: `${node.label} declares a public static final array "${fieldName}" of type "${fieldType}[]". ` +
          `While the array reference cannot be reassigned (final), the array contents are mutable — any code ` +
          `can modify elements via ${node.label.split('/').pop()}.${fieldName}[i] = newValue.`,
        fix: 'Make the array private and provide a public method that returns a defensive copy: ' +
          '`private static final int[] ARR = {...}; public static int[] getArr() { return ARR.clone(); }`. ' +
          'Alternatively, use an immutable collection: Collections.unmodifiableList(Arrays.asList(...)).',
          via: 'structural',
      });
      break;
    }
  }

  return { cwe: 'CWE-582', name: 'Array Declared Public, Final, and Static', holds: findings.length === 0, findings };
}

/**
 * CWE-688: Function Call With Incorrect Variable or Reference as Argument
 *
 * Pattern: Detects common patterns where a function call likely passes the wrong
 * variable — e.g., passing `password` to a logging function, passing `req` where
 * `res` was intended, swapped arguments in common APIs.
 *
 * FUNDAMENTAL LIMITATION: True detection of "wrong variable" requires intent analysis
 * that static analysis cannot provide. This verifier catches the most detectable
 * variant: obviously suspicious argument patterns (sensitive data to logging,
 * response objects in request positions, etc.).
 */
function verifyCWE688(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Detect sensitive variables passed to output/logging functions
  const SENSITIVE_ARG_TO_OUTPUT = /\b(console\.(log|info|warn|error|debug)|logger?\.\w+|print|puts|System\.out|NSLog|os_log|syslog|fprintf\s*\(\s*stderr)\s*\([^)]*\b(password|passwd|secret|token|apiKey|api_key|privateKey|private_key|ssn|creditCard|credit_card|cvv|pin|sessionId|session_id|auth_token)\b/i;

  // Detect swapped req/res in Express-like handlers
  const SWAPPED_REQ_RES = /\b(res\.(params|query|body|headers|cookies|path|method|url|hostname|ip|protocol)|req\.(send|json|status|redirect|render|cookie|set|header|type|sendFile|download|end|write))\b/i;

  // Detect common callback argument order mistakes
  const CALLBACK_SWAP = /\b(function|=>)\s*\(\s*(err|error)\s*,\s*\w+\s*\)[^{]*\{[^}]*\b\2\s*\.\s*(data|body|result|value|json|map|forEach|length)\b/i;

  const SAFE_RE = /\b(redact|mask|sanitize|censor|\*{3,}|\.replace\(.*\*|scrub|obfuscate)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (SENSITIVE_ARG_TO_OUTPUT.test(code) && !SAFE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (review argument — sensitive data passed to output function)',
        severity: 'medium',
        description: `${node.label} passes a sensitive variable (password, token, key) directly to a logging or output function. ` +
          `This is likely an incorrect variable reference — the developer may have intended to log a different variable.`,
        fix: 'Review the function call and ensure the correct variable is passed. If logging is intentional, ' +
          'redact sensitive data: logger.info("auth attempt", { user: userId }) instead of logger.info(password). ' +
          'Use a linter rule (no-console, eslint-plugin-no-secrets) to catch these.',
          via: 'structural',
      });
    }

    if (SWAPPED_REQ_RES.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (review argument — req/res appear swapped in Express-style handler)',
        severity: 'medium',
        description: `${node.label} accesses request properties on 'res' or response methods on 'req', ` +
          `suggesting the req/res parameters may be swapped in the handler signature.`,
        fix: 'Verify the handler parameter order matches the framework convention: (req, res) for Express, ' +
          '(request, response) for Hapi, (ctx) for Koa. Swap parameters if reversed.',
          via: 'structural',
      });
    }

    if (CALLBACK_SWAP.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (review argument — error object used as data in callback)',
        severity: 'medium',
        description: `${node.label} appears to use the error parameter as if it were the data parameter in a callback, ` +
          `accessing .data, .body, .length etc. on the error variable. The callback arguments may be swapped.`,
        fix: 'Review the callback signature. Node.js convention is (err, result) — ensure you are using ' +
          'the result parameter for data access, not the error parameter.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-688', name: 'Function Call With Incorrect Variable or Reference as Argument', holds: findings.length === 0, findings };
}

/**
 * CWE-689: Permission Race Condition During Resource Copy
 *
 * Pattern: A resource is created/copied and then permissions are set in a separate
 * step, creating a TOCTOU window where the resource exists with wrong permissions.
 *
 * FUNDAMENTAL LIMITATION: True race condition detection requires dynamic analysis.
 * This verifier catches the static pattern: file creation followed by separate
 * chmod/chown/permission-setting calls, without atomic creation flags.
 */
function verifyCWE689(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // File creation/copy followed by separate permission setting
  const CREATE_THEN_CHMOD_PATTERNS = [
    // Node.js: fs.writeFile then fs.chmod
    /\b(fs\.(?:writeFile|copyFile|createWriteStream|cp|rename)(?:Sync)?)\b/i,
    // Python: open() or shutil.copy then os.chmod
    /\b(shutil\.copy(?:2|file|tree)?|open\s*\([^)]*['"]w|copyfile|copy_file)\b/i,
    // C: fopen/creat then chmod/fchmod
    /\b(fopen|creat|open)\s*\([^)]*O_CREAT/i,
    // Ruby: File.open/FileUtils.cp then File.chmod
    /\b(File\.(?:open|write|new)|FileUtils\.(?:cp|copy|mv|install))\b/i,
  ];

  const SEPARATE_CHMOD = /\b(fs\.chmod(?:Sync)?|os\.chmod|chmod|fchmod|chown|fchown|lchown|lchmod|File\.chmod|FileUtils\.chmod|set_permissions|SetFileSecurity|icacls|cacls|setfacl)\b/i;

  const ATOMIC_CREATE = /\b(O_EXCL|O_CREAT.*0[0-7]{3}|mode\s*[:=]\s*0[ox]?[0-7]{3}|umask|fs\.(?:writeFile|copyFile)(?:Sync)?\s*\([^)]*\{[^}]*mode\s*:|os\.open\s*\([^)]*0o[0-7]{3}|os\.fdopen|mkstemp|NamedTemporaryFile|tempfile\.mkstemp|opener\s*=|File\.open\s*\([^)]*0[0-7]{3}|atomic_write|write_atomic|safeWrite|install\s*\([^)]*mode)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    const hasCreate = CREATE_THEN_CHMOD_PATTERNS.some(p => p.test(code));
    const hasChmod = SEPARATE_CHMOD.test(code);

    if (hasCreate && hasChmod && !ATOMIC_CREATE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (atomic permission setting during resource creation)',
        severity: 'medium',
        description: `${node.label} creates/copies a file and then sets permissions in a separate operation. ` +
          `Between creation and chmod, the file exists with default (potentially world-readable) permissions, ` +
          `creating a race window where other processes can access the file.`,
        fix: 'Set permissions atomically during creation: use mode option in fs.writeFile({mode: 0o600}), ' +
          'os.open(path, flags, 0o600) in Python, or set umask before creation. ' +
          'For copies, use install(1) with -m flag or shutil.copy followed by immediate fchmod on the fd.',
          via: 'structural',
      });
    }
  }

  // Also check for copy-to-public-location patterns across nodes
  const copyNodes = map.nodes.filter(n => {
    const c = stripComments(n.analysis_snapshot || n.code_snapshot);
    return /\b(copy|cp|mv|rename|move|transfer|deploy|publish|upload)\b/i.test(c) &&
           /\b(public|www|htdocs|static|assets|uploads|tmp|temp|shared|world)\b/i.test(c);
  });

  for (const node of copyNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!ATOMIC_CREATE.test(code) && !SEPARATE_CHMOD.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (explicit permission setting when copying to public location)',
        severity: 'medium',
        description: `${node.label} copies/moves a resource to a public location without explicit permission control. ` +
          `The copied resource inherits default or source permissions, which may be overly permissive.`,
        fix: 'Explicitly set restrictive permissions after copying to a public location. ' +
          'Better: use atomic creation with desired permissions, or copy to a staging area first.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-689', name: 'Permission Race Condition During Resource Copy', holds: findings.length === 0, findings };
}

/**
 * CWE-698: Execution After Redirect (EAR)
 *
 * Pattern: Code continues executing after a redirect/forward response is sent.
 * The HTTP redirect is sent, but the server-side handler keeps running, potentially
 * executing sensitive operations that should be gated by the redirect.
 *
 * Classic web vulnerability: redirect("login") without return means the protected
 * page content is still generated and may be leaked.
 */
function verifyCWE698(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Redirect patterns across frameworks
  const REDIRECT_RE = /\b(res\.redirect|response\.redirect|redirect_to|redirect\s*\(|header\s*\(\s*['"]Location|http_redirect|Response\.Redirect|RedirectToAction|RedirectToRoute|RedirectResult|ctx\.redirect|flask\.redirect|return\s+redirect|HttpResponseRedirect|sendRedirect)\b/i;

  // Return/exit after redirect — the safe pattern
  const RETURN_AFTER_REDIRECT = /\b(return\s+(?:res\.)?redirect|redirect[^;]*;\s*(?:return|exit|die|throw|break|process\.exit)|(?:return|exit|die)\s*(?:\(\))?;?\s*$)/im;

  // Code that continues after redirect (dangerous operations)
  const POST_REDIRECT_CODE = /\b(redirect|sendRedirect|Response\.Redirect|header\s*\(\s*['"]Location)\b[^;]*;[^}]*\b(query|exec|execute|save|insert|update|delete|write|send|render|assign|fetch|process|eval|create|remove|destroy)\b/i;

  const SAFE_RE = /\b(return\b.*redirect|redirect.*\breturn\b|exit\s*\(|die\s*\(|throw\b|process\.exit|sys\.exit|os\._exit|System\.exit|Environment\.Exit)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!REDIRECT_RE.test(code)) continue;

    if (RETURN_AFTER_REDIRECT.test(code) || SAFE_RE.test(code)) continue;

    // Check if there's meaningful code after the redirect
    if (POST_REDIRECT_CODE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (return/exit after redirect)',
        severity: 'high',
        description: `${node.label} sends a redirect but continues executing code afterward. ` +
          `The redirect tells the browser to navigate away, but the server continues processing — ` +
          `any sensitive operations, database writes, or response body content after the redirect still execute.`,
        fix: 'Always return/exit immediately after sending a redirect. In Express: return res.redirect("/login"). ' +
          'In PHP: header("Location: ..."); exit();. In Java: response.sendRedirect(...); return;. ' +
          'In Python/Flask: return redirect(url). Never rely on the redirect alone to stop execution.',
          via: 'structural',
      });
    } else {
      // Redirect without explicit return — still suspicious
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (explicit return after redirect to prevent fall-through)',
        severity: 'medium',
        description: `${node.label} calls redirect without an explicit return/exit statement. ` +
          `Without return, subsequent code in the handler may execute, including template rendering or data operations.`,
        fix: 'Add an explicit return statement after every redirect call: return res.redirect(...). ' +
          'This prevents accidental fall-through even if no dangerous code currently follows.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-698', name: 'Execution After Redirect (EAR)', holds: findings.length === 0, findings };
}

/**
 * CWE-704: Incorrect Type Conversion or Cast
 *
 * Pattern: Unsafe type conversions that lose data, change sign, truncate, or
 * misinterpret the bit pattern. Covers: integer narrowing casts, float-to-int
 * truncation, pointer casts, unchecked type assertions, strconv without error
 * handling, parseInt without radix.
 */
function verifyCWE704(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const TYPE_CAST_PATTERNS: Array<{ pattern: RegExp; name: string; fix: string; severity: 'high' | 'medium' | 'low' }> = [
    // C/C++ dangerous casts
    { pattern: /\(\s*(char|short|int|unsigned\s+char|uint8_t|int8_t|uint16_t|int16_t)\s*\)\s*\w+/i, name: 'narrowing integer cast in C/C++', fix: 'Check value range before casting. Use safe_cast or bounds checking: if (val >= 0 && val <= INT8_MAX) { (int8_t)val; }.', severity: 'medium' },
    { pattern: /\breinterpret_cast\s*</, name: 'reinterpret_cast (bit pattern reinterpretation)', fix: 'Avoid reinterpret_cast unless absolutely necessary. Use static_cast or proper serialization/deserialization.', severity: 'high' },
    { pattern: /\(\s*(?:void|char)\s*\*\s*\)\s*(?:&?\w+)/, name: 'pointer type cast in C', fix: 'Avoid raw pointer casts. Use typed pointers and proper memory layout structures.', severity: 'medium' },
    // JavaScript/TypeScript unsafe type assertions
    { pattern: /\bas\s+any\b/, name: 'TypeScript "as any" type assertion', fix: 'Use proper type narrowing (instanceof, typeof, discriminated unions) instead of "as any". The "as any" bypasses all type safety.', severity: 'medium' },
    { pattern: /\bas\s+(?!const\b)\w+(?:\s*<[^>]+>)?\s*(?:;|\)|,|\])(?!.*(?:instanceof|typeof|is\w+|assert|guard|narrow|check))/i, name: 'unchecked TypeScript type assertion', fix: 'Validate the value matches the asserted type before casting. Use type guards or runtime validation (zod, io-ts) instead of bare type assertions.', severity: 'low' },
    // parseInt without radix (JS)
    { pattern: /\bparseInt\s*\(\s*\w+\s*\)(?!\s*,)/, name: 'parseInt without radix parameter', fix: 'Always provide a radix: parseInt(value, 10). Without it, strings starting with "0" may be parsed as octal in older engines.', severity: 'low' },
    // Go: unchecked strconv conversions
    { pattern: /\bstrconv\.(?:Atoi|ParseInt|ParseFloat|ParseUint)\s*\([^)]+\)\s*(?:\n|;)(?!.*(?:err|error|if))/i, name: 'unchecked Go strconv conversion', fix: 'Always check the error return from strconv: val, err := strconv.Atoi(s); if err != nil { ... }.', severity: 'medium' },
    // Python unsafe int/float conversions
    { pattern: /\bint\s*\(\s*(?:request\.|input\(|sys\.argv|os\.environ|form\[)/i, name: 'unchecked type conversion of user input (Python)', fix: 'Wrap in try/except ValueError: try: val = int(user_input) except ValueError: return error. Never convert untrusted input without error handling.', severity: 'medium' },
    // Java narrowing casts
    { pattern: /\(\s*(byte|short|char)\s*\)\s*\w+/i, name: 'narrowing cast in Java (byte/short/char)', fix: 'Check range before narrowing: if (val >= Byte.MIN_VALUE && val <= Byte.MAX_VALUE). Use Math.toIntExact() for checked narrowing.', severity: 'medium' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const tc of TYPE_CAST_PATTERNS) {
      if (tc.pattern.test(code)) {
        // Skip test files
        if (/\b(test|spec|mock|__test__)\b/i.test(node.label || node.file)) continue;

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `CONTROL (safe type conversion — ${tc.name})`,
          severity: tc.severity,
          description: `${node.label} contains ${tc.name}. ` +
            `Incorrect type conversions can cause data loss, sign errors, truncation, or type confusion vulnerabilities.`,
          fix: tc.fix,
          via: 'structural',
        });
        break; // One finding per node to avoid noise
      }
    }
  }

  return { cwe: 'CWE-704', name: 'Incorrect Type Conversion or Cast', holds: findings.length === 0, findings };
}

/**
 * CWE-706: Use of Incorrectly-Resolved Name or Reference
 *
 * Pattern: Code resolves a name (file path, class name, module, DNS name, URL) in
 * a context where the resolution can be manipulated — symlink following, relative
 * imports from untrusted paths, DNS rebinding, prototype chain pollution.
 *
 * CREATIVE APPROACH: Rather than just checking path traversal (CWE-22 handles that),
 * this verifier focuses on the NAME RESOLUTION mechanism itself — the indirection layer
 * where the name you ask for isn't the resource you get.
 */
function verifyCWE706(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code defines file/module resolution primitives — false positive on framework internals
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-706', name: 'Use of Incorrectly-Resolved Name or Reference', holds: true, findings };
  }

  // Symlink-following patterns (file operations without O_NOFOLLOW)
  const SYMLINK_FOLLOW = /\b(readFile|readFileSync|writeFile|writeFileSync|open|fopen|stat|access|unlink|rmdir|chmod|chown|readlink|lstat)\s*\(/i;
  const NOFOLLOW_SAFE = /\b(O_NOFOLLOW|NOFOLLOW|lstat|readlink|realpath.*compare|canonical.*path|followSymlinks\s*:\s*false|followSymbolicLinks\s*:\s*false)\b/i;

  // Dynamic import/require from user-controlled path
  const DYNAMIC_RESOLVE = /\b(require\s*\(\s*(?:\w+\s*\+|`\$\{)|import\s*\(\s*(?:\w+\s*\+|`\$\{)|__import__\s*\(\s*\w+|importlib\.import_module\s*\(\s*\w+|Class\.forName\s*\(\s*\w+|Type\.GetType\s*\(\s*\w+)\b/i;
  const DYNAMIC_RESOLVE_SAFE = /\b(allowlist|whitelist|allowed|SAFE_MODULES|validModules|moduleMap|MODULE_MAP|switch\s*\()\b/i;

  // DNS resolution without pinning/validation
  const DNS_RESOLVE = /\b(dns\.resolve|dns\.lookup|getaddrinfo|gethostbyname|nslookup|socket\.getaddrinfo|InetAddress\.getByName|Dns\.GetHostEntry)\b/i;
  const DNS_SAFE = /\b(dnsPinning|pinned|cachedDns|resolver.*cache|ttl|DNS_CACHE|allowedHosts|hostWhitelist)\b/i;

  // Prototype chain / __proto__ name resolution abuse
  const PROTO_ABUSE = /\b(__proto__|constructor\s*\.\s*prototype|Object\.setPrototypeOf|Object\.create\s*\(\s*(?:null\s*\))?[^)])/i;
  const PROTO_SAFE = /\b(Object\.create\s*\(\s*null|Map\(|freeze|seal|hasOwnProperty|Object\.hasOwn)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for symlink-following in security-sensitive contexts
    if (SYMLINK_FOLLOW.test(code) && !NOFOLLOW_SAFE.test(code)) {
      // Only flag if the path seems user-influenced or is in a temp/public directory
      if (/\b(tmp|temp|upload|public|shared|user|input|param|req\.|request\.|args)\b/i.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (symlink-safe file operation — O_NOFOLLOW or lstat check)',
          severity: 'medium',
          description: `${node.label} performs a file operation that follows symlinks on a potentially user-influenced path. ` +
            `An attacker can create a symlink pointing to a sensitive file, causing the operation to act on the wrong resource.`,
          fix: 'Use O_NOFOLLOW flag, lstat() to check for symlinks before operating, or realpath() followed by prefix validation. ' +
            'On Node.js, use fs.lstat to detect symlinks before reading/writing.',
            via: 'structural',
        });
      }
    }

    // Dynamic import/require resolution
    if (DYNAMIC_RESOLVE.test(code) && !DYNAMIC_RESOLVE_SAFE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (module name allowlist for dynamic imports)',
        severity: 'high',
        description: `${node.label} dynamically resolves a module/class name from a variable. ` +
          `If the variable is attacker-controlled, they can load arbitrary modules or classes, ` +
          `executing unexpected code through the module resolution mechanism.`,
        fix: 'Use an allowlist/map of permitted module names: const modules = { "a": moduleA, "b": moduleB }; ' +
          'modules[name]. Never pass user input directly to require/import/Class.forName.',
          via: 'structural',
      });
    }

    // Prototype chain abuse
    if (PROTO_ABUSE.test(code) && !PROTO_SAFE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (prototype chain protection — Object.create(null) or Map)',
        severity: 'high',
        description: `${node.label} manipulates or exposes the prototype chain. ` +
          `Name resolution through the prototype chain can be abused to override methods or properties, ` +
          `causing the code to resolve a different function/value than intended.`,
        fix: 'Use Object.create(null) for lookup dictionaries, Map for key-value stores, ' +
          'Object.freeze to prevent prototype modification, and hasOwnProperty/Object.hasOwn for property checks.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-706', name: 'Use of Incorrectly-Resolved Name or Reference', holds: findings.length === 0, findings };
}

/**
 * CWE-732: Incorrect Permission Assignment for Critical Resource
 *
 * Pattern: File, directory, or resource created with overly permissive permissions.
 * Covers: world-writable files, 777/666 permissions, PUBLIC_READ ACLs, overly
 * broad IAM policies, database grants to PUBLIC.
 */
function verifyCWE732(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const OVERLY_PERMISSIVE_PATTERNS: Array<{ pattern: RegExp; name: string; fix: string; severity: 'critical' | 'high' | 'medium' }> = [
    // Unix permission patterns
    { pattern: /\b(?:0o?)?(?:777|776|766|667|666)\b/, name: 'world-readable/writable file permissions', fix: 'Use restrictive permissions: 0o600 for secrets, 0o644 for config, 0o755 for executables. Never use 777 or 666.', severity: 'high' },
    { pattern: /\bchmod\s*\([^)]*(?:0o?)?(?:777|776|766|667|666)\b/i, name: 'chmod to world-accessible', fix: 'chmod to restrictive permissions: 0o600 for sensitive files, 0o644 for public-readable.', severity: 'high' },
    { pattern: /\bumask\s*\(\s*0+\s*\)/, name: 'umask set to 0 (no permission restriction)', fix: 'Set a restrictive umask: umask(0o077) to create files as owner-only by default.', severity: 'high' },
    // Cloud storage ACLs
    { pattern: /\b(public-read|public-read-write|PublicRead|PublicReadWrite|authenticated-read|ACL\s*[:=]\s*['"]public|AllUsers|allAuthenticatedUsers|s3:GetObject.*\*|Effect.*Allow.*Action.*\*.*Resource.*\*)\b/i, name: 'public cloud storage ACL', fix: 'Use private ACLs. Grant access to specific IAM roles/users, not public. Enable S3 Block Public Access. Review bucket policies.', severity: 'critical' },
    // Database grants
    { pattern: /\b(GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+\*|GRANT\s+\w+\s+TO\s+PUBLIC|GRANT\s+ALL\s+TO\s+PUBLIC)\b/i, name: 'overly broad database GRANT', fix: 'Grant minimum required privileges to specific users/roles. Never GRANT ALL ON * or GRANT to PUBLIC.', severity: 'high' },
    // Docker/container
    { pattern: /\b(--privileged|privileged\s*:\s*true|securityContext.*privileged|capabilities.*ALL)\b/i, name: 'privileged container/excessive capabilities', fix: 'Run containers without --privileged. Drop all capabilities and add only needed ones: cap_drop: ALL, cap_add: [NET_BIND_SERVICE].', severity: 'critical' },
    // API keys in environment with no restriction
    { pattern: /\bAPI_KEY_PERMISSIONS?\s*[:=]\s*['"](?:\*|all|admin|full)/i, name: 'unrestricted API key permissions', fix: 'Scope API keys to minimum required permissions. Use separate keys for different operations.', severity: 'high' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const pp of OVERLY_PERMISSIVE_PATTERNS) {
      if (pp.pattern.test(code)) {
        if (/\b(test|spec|mock|example|sample|demo|tutorial)\b/i.test(node.label || node.file)) continue;

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `CONTROL (restrictive permissions — ${pp.name})`,
          severity: pp.severity,
          description: `${node.label} assigns overly permissive access: ${pp.name}. ` +
            `Critical resources with excessive permissions can be read, modified, or deleted by unauthorized actors.`,
          fix: pp.fix,
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-732', name: 'Incorrect Permission Assignment for Critical Resource', holds: findings.length === 0, findings };
}

/**
 * CWE-749: Exposed Dangerous Method or Function
 *
 * Pattern: A dangerous/sensitive method is exposed via a public interface (API endpoint,
 * RPC, WebSocket, exported module method) without access control.
 *
 * Covers: admin endpoints without auth, exposed eval/exec, debug endpoints, internal
 * service methods made public, unprotected file operations via API.
 */
function verifyCWE749(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Dangerous operation patterns
  const DANGEROUS_OP = /\b(eval|exec|system|spawn|execFile|child_process|subprocess|os\.system|Runtime\.exec|ProcessBuilder|shell_exec|passthru|popen|proc_open|file_put_contents|unlink|rmdir|rmtree|shutil\.rmtree|fs\.rm|dropDatabase|dropTable|truncate|DELETE\s+FROM|DROP\s+TABLE|TRUNCATE|shutdown|restart|reboot|kill|terminate|destroy|format|wipe|purge|reset_password|admin_reset|grant_admin|elevate|setRole|deleteUser|createUser)\b/i;

  // Exposed via API/route/endpoint patterns
  const EXPOSED_VIA = /\b(app\.(get|post|put|delete|patch|all|use)|router\.(get|post|put|delete|patch|all)|@(Get|Post|Put|Delete|Patch|RequestMapping|ApiOperation|api_view|route)|\.route\s*\(|expose|export|public\s+(?:async\s+)?(?:static\s+)?(?:function|method|def)|@rpc|@websocket|@grpc|@endpoint|addEventListener|onmessage|on\s*\(\s*['"]message)\b/i;

  // Access control patterns — these make the exposure safe
  const ACCESS_CONTROL = /\b(auth|authenticate|authorize|isAdmin|isAuthenticated|requireAuth|requireAdmin|requireRole|checkPermission|@Secured|@PreAuthorize|@RolesAllowed|@RequiresPermission|@login_required|@permission_required|@admin_required|middleware.*auth|guard|protect|rbac|acl|jwt\.verify|passport\.authenticate|session\.user|req\.user|currentUser|bearer|token.*verify|apiKey.*check)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (DANGEROUS_OP.test(code) && EXPOSED_VIA.test(code) && !ACCESS_CONTROL.test(code)) {
      const dangerousMatch = code.match(DANGEROUS_OP);
      const opName = dangerousMatch ? dangerousMatch[1] : 'dangerous operation';

      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'AUTH (access control on exposed dangerous method)',
        severity: 'critical',
        description: `${node.label} exposes a dangerous operation (${opName}) via a public interface without access control. ` +
          `Any unauthenticated user can invoke this operation, potentially leading to code execution, ` +
          `data destruction, or privilege escalation.`,
        fix: 'Add authentication and authorization middleware before dangerous operations. ' +
          'Use @RequiresPermission, requireAdmin middleware, or RBAC checks. ' +
          'Never expose eval, exec, file deletion, or admin functions without strict access control.',
          via: 'structural',
      });
    }
  }

  // Also check: EXTERNAL nodes (representing APIs/services) that reach dangerous operations
  const externals = nodesOfType(map, 'EXTERNAL');
  for (const ext of externals) {
    const code = stripComments(ext.analysis_snapshot || ext.code_snapshot);
    if (DANGEROUS_OP.test(code) && !ACCESS_CONTROL.test(code)) {
      findings.push({
        source: nodeRef(ext), sink: nodeRef(ext),
        missing: 'AUTH (access control on external service exposing dangerous operation)',
        severity: 'high',
        description: `External service node ${ext.label} contains a dangerous operation without access control. ` +
          `If this service is reachable from untrusted networks, the dangerous operation is exploitable.`,
        fix: 'Add authentication (API keys, JWT, mTLS) to external service endpoints. ' +
          'Apply principle of least privilege — only expose operations that the caller legitimately needs.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-749', name: 'Exposed Dangerous Method or Function', holds: findings.length === 0, findings };
}

/**
 * CWE-754: Improper Check for Unusual or Exceptional Conditions
 *
 * Pattern: Code fails to check for error returns, null/undefined results, edge cases
 * (empty arrays, zero-length strings, NaN, Infinity), or exceptional states from
 * system/library calls.
 *
 * This is the "you forgot to check the return value" CWE — one of the most common
 * root causes of real-world crashes and security issues.
 */
function verifyCWE754(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const mapLang = inferMapLanguage(map);

  // Each pattern has an optional `langs` array — when set, the pattern only fires if the
  // map language matches one of those languages. This prevents Go error-handling rules from
  // firing on JavaScript, C malloc checks from firing on Python, etc.
  const UNCHECKED_PATTERNS: Array<{ pattern: RegExp; name: string; fix: string; severity: 'high' | 'medium' | 'low'; langs?: string[] }> = [
    // C: unchecked malloc/calloc/realloc
    { pattern: /\b(malloc|calloc|realloc)\s*\([^)]+\)\s*;(?!.*(?:if|assert|!=\s*NULL|==\s*NULL|\?\?))/i, name: 'unchecked malloc/calloc/realloc return', fix: 'Always check for NULL: void *p = malloc(n); if (!p) { handle_error(); }. Unchecked NULL dereference is undefined behavior.', severity: 'high', langs: ['c', 'c++', 'cpp'] },
    // C: unchecked fopen
    { pattern: /\bfopen\s*\([^)]+\)\s*;(?!.*(?:if|assert|!=\s*NULL|==\s*NULL))/i, name: 'unchecked fopen return', fix: 'Check for NULL: FILE *f = fopen(path, "r"); if (!f) { perror("fopen"); return; }.', severity: 'medium', langs: ['c', 'c++', 'cpp'] },
    // JS/TS: JSON.parse without try-catch
    { pattern: /\bJSON\.parse\s*\([^)]+\)(?!.*(?:try|catch|\.catch|\?\.|&&))/i, name: 'JSON.parse without error handling', fix: 'Wrap in try-catch: try { const data = JSON.parse(input); } catch (e) { handleParseError(e); }. Invalid JSON throws SyntaxError.', severity: 'medium', langs: ['javascript', 'typescript'] },
    // JS: Array methods on possibly-undefined
    { pattern: /\.\s*(find|findIndex|indexOf|includes)\s*\([^)]*\)\s*\.\s*(id|name|value|data|label|toString|map|filter|reduce)\b/i, name: 'chained property access on possibly-undefined find result', fix: 'Use optional chaining: arr.find(x => x.id === id)?.name, or check the result before accessing properties.', severity: 'medium', langs: ['javascript', 'typescript'] },
    // Go: error return ignored (single-return call) — Go-only
    { pattern: /\b\w+\s*(?::=|=)\s*\w+\.\w+\([^)]*\)\s*(?:\n|;)(?!.*(?:err|error|if|!=\s*nil))/i, name: 'Go function call with ignored error return', fix: 'Always check error returns: result, err := fn(); if err != nil { return err }. Use errcheck linter.', severity: 'medium', langs: ['go'] },
    // Python: unchecked .get() used directly (dict access without default)
    { pattern: /\b\w+\[['"][^'"]+['"]\]\s*\.\s*\w+/i, name: 'dict key access without KeyError handling', fix: 'Use .get(key, default) for optional keys, or wrap in try/except KeyError. Direct bracket access raises KeyError on missing keys.', severity: 'low', langs: ['python'] },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const nodeLang = node.language?.toLowerCase() || mapLang;
    for (const up of UNCHECKED_PATTERNS) {
      // Language guard: skip language-specific patterns when the source language doesn't match
      if (up.langs && up.langs.length > 0 && nodeLang && !up.langs.includes(nodeLang)) continue;
      if (up.pattern.test(code)) {
        if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `CONTROL (error/edge-case check — ${up.name})`,
          severity: up.severity,
          description: `${node.label}: ${up.name}. ` +
            `Failing to check for unusual conditions (null, error, empty, NaN) can cause crashes, ` +
            `undefined behavior, or security bypasses when the unexpected state is exploited.`,
          fix: up.fix,
          via: 'structural',
        });
        break; // One finding per node
      }
    }
  }

  return { cwe: 'CWE-754', name: 'Improper Check for Unusual or Exceptional Conditions', holds: findings.length === 0, findings };
}

/**
 * CWE-755: Improper Handling of Exceptional Conditions
 *
 * Pattern: Code catches exceptions but handles them improperly — swallowing errors
 * silently, catching overly broad exception types, using empty catch blocks,
 * logging but not propagating security-critical errors, or catching and continuing
 * in a corrupted state.
 *
 * Distinct from CWE-754 (failing to CHECK for conditions) — CWE-755 is about
 * catching the exception but HANDLING it wrong.
 */
function verifyCWE755(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code has intentional error-handling patterns (broad catches for robustness)
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-755', name: 'Improper Handling of Exceptional Conditions', holds: true, findings };
  }

  // Empty catch blocks (swallowed exceptions)
  const EMPTY_CATCH_PATTERNS = [
    /\bcatch\s*\([^)]*\)\s*\{\s*\}/,                    // JS/Java/C# empty catch
    /\bcatch\s*\{\s*\}/,                                 // Swift/Kotlin empty catch
    /\bexcept\s*(?::\s*)?\s*(?:pass|\.\.\.)\s*$/m,       // Python except: pass
    /\brescue\s*(?:=>?\s*\w+)?\s*(?:nil|;\s*end)\b/,     // Ruby rescue nil
  ];

  // Overly broad exception catching
  const BROAD_CATCH_PATTERNS = [
    /\bcatch\s*\(\s*(?:Exception|Error|Throwable|BaseException|object)\s+\w+\s*\)/i,  // Java/Python/C# catch-all
    /\bcatch\s*\(\s*(?:e|err|error|ex)\s*\)\s*\{/,       // JS catch without type narrowing
    /\bexcept\s+(?:Exception|BaseException)\s*(?:as\s+\w+)?\s*:/,  // Python except Exception
    /\brescue\s*(?:Exception|StandardError|RuntimeError)?\s*=>/,    // Ruby broad rescue
  ];

  // Catch with only a log (no re-throw, no error response)
  const LOG_AND_SWALLOW = /\bcatch\s*\([^)]*\)\s*\{[^}]*\b(console\.(log|error|warn)|log\.\w+|logger\.\w+|print|puts|System\.err|NSLog|os_log|syslog)\b[^}]*\}(?!\s*(?:throw|return\s+(?:err|error|null|false)|reject|next\s*\(|process\.exit))/i;

  const SAFE_HANDLER = /\b(throw|rethrow|re-throw|reject|next\s*\(|return\s+(?:err|error|Result\.Err|Err\()|process\.exit|sys\.exit|abort|panic|raise|handleError|errorHandler|onError|respondWithError|sendError|res\.status\s*\(\s*[45]\d{2}|HttpStatus\.|StatusCode\.|response\.setStatus)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for empty catch blocks
    for (const pattern of EMPTY_CATCH_PATTERNS) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (proper exception handling — empty catch block swallows errors)',
          severity: 'medium',
          description: `${node.label} has an empty catch/except/rescue block that silently swallows exceptions. ` +
            `Errors are hidden, making debugging impossible and potentially leaving the application in a corrupted state. ` +
            `Security-critical errors (auth failures, permission denied, input validation) are silently ignored.`,
          fix: 'At minimum, log the error. Better: re-throw specific exceptions, return error responses, ' +
            'or take corrective action. Only swallow exceptions when you can prove the error is truly benign.',
            via: 'structural',
        });
        break;
      }
    }

    // Check for overly broad exception catching without re-throw
    for (const pattern of BROAD_CATCH_PATTERNS) {
      if (pattern.test(code) && !SAFE_HANDLER.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (specific exception handling — overly broad catch without re-throw)',
          severity: 'medium',
          description: `${node.label} catches a broad exception type (Exception/Error/Throwable) without re-throwing. ` +
            `This catches and swallows ALL errors including OutOfMemoryError, StackOverflow, SecurityException, ` +
            `and other conditions that should terminate or escalate.`,
          fix: 'Catch specific exception types. If catching broadly, re-throw unexpected exceptions: ' +
            'catch (e) { if (e instanceof SpecificError) { handle(); } else { throw e; } }. ' +
            'Never catch Throwable/BaseException without re-throwing.',
            via: 'structural',
        });
        break;
      }
    }

    // Check for log-and-swallow pattern
    if (LOG_AND_SWALLOW.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (error propagation — exception logged but not propagated)',
        severity: 'medium',
        description: `${node.label} catches an exception, logs it, but does not propagate the error. ` +
          `The caller receives no indication of failure and continues with potentially invalid state. ` +
          `This is especially dangerous for auth/payment/security operations.`,
        fix: 'After logging, either re-throw the exception, return an error result, or send an error response. ' +
          'The caller must know the operation failed: catch (e) { logger.error(e); throw e; }.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-755', name: 'Improper Handling of Exceptional Conditions', holds: findings.length === 0, findings };
}

/**
 * CWE-756: Missing Custom Error Page
 * Pattern: Web application error handling that exposes default framework error pages
 * (stack traces, debug info) to users instead of custom error pages.
 *
 * NOTABLE: This is a "config smell" CWE — the vulnerability is the ABSENCE of something,
 * not the presence. Detecting missing configuration statically is inherently harder than
 * detecting bad code, so we look for telltale signs: frameworks in debug/development mode,
 * raw exception forwarding to response objects, and missing error handler middleware.
 */
function verifyCWE756(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DEBUG_MODE_RE = /\b(DEBUG\s*[:=]\s*True|app\.debug\s*=\s*true|NODE_ENV\s*(?:===?|!==?)\s*['"]development['"]|FLASK_DEBUG\s*=\s*1|\.set\s*\(\s*['"]env['"]\s*,\s*['"]development['"]|config\.debug\s*=\s*true|DJANGO_DEBUG\s*=\s*True|Rails\.env\.development|APP_DEBUG\s*=\s*true|WEB_DEBUG\s*=\s*1|SHOW_ERRORS\s*=\s*true)\b/i;

  const RAW_ERROR_RESPONSE_RE = /\b(res\.send\s*\(\s*(?:err|error|e)(?:\.message|\.stack|\.toString\(\))?\s*\)|res\.status\s*\(\s*500\s*\)\.send\s*\(\s*(?:err|error|e)|response\.write\s*\(\s*(?:traceback|exception|err)|render_exception|raise_error_page|send_error_response\s*\(\s*(?:err|error|e))\b/i;

  const CUSTOM_ERROR_PAGE_RE = /\b(render\s*\(\s*['"](?:error|errors\/|error_page|4\d\d|5\d\d)|errorPage|error_template|custom_error|handler404|handler500|pages\/error|views\/error|error\.html|error\.ejs|error\.pug|error\.hbs|@error_page|rescue_from\s+\w+Exception)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (DEBUG_MODE_RE.test(code)) {
      const hasEnvGuard = /\bif\s*\(\s*(?:process\.env|NODE_ENV|FLASK_ENV|RAILS_ENV|APP_ENV)\b/.test(code);
      if (!hasEnvGuard) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (disable debug mode in production; configure custom error pages)',
          severity: 'medium',
          description: `${node.label} enables debug/development mode unconditionally. ` +
            `Default framework error pages in debug mode expose stack traces, source code paths, ` +
            `environment variables, and database queries to attackers.`,
          fix: 'Disable debug mode in production: set DEBUG=False (Django), app.debug=false (Flask/Express), ' +
            'NODE_ENV=production. Configure custom error pages for 4xx and 5xx status codes.',
            via: 'structural',
        });
      }
    }

    if (RAW_ERROR_RESPONSE_RE.test(code) && !CUSTOM_ERROR_PAGE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (custom error page that sanitizes error details before display)',
        severity: 'medium',
        description: `${node.label} forwards raw error/exception objects directly to the HTTP response. ` +
          `Without a custom error page, users see default framework error output including stack traces and internal paths.`,
        fix: 'Create custom error pages: Express: app.use((err, req, res, next) => res.render("error")). ' +
          'Django: templates/500.html. Flask: @app.errorhandler(500).',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-756', name: 'Missing Custom Error Page', holds: findings.length === 0, findings };
}

/**
 * CWE-778: Insufficient Logging
 * Pattern: Security-critical operations (authentication, authorization, data access)
 * that lack audit logging. Without logs, security incidents go undetected.
 *
 * NOTABLE: This is a "negative space" CWE — we look for what ISN'T there. The approach:
 * find AUTH/CONTROL nodes handling security decisions, then check for logging nearby.
 * Security decisions happening in silence is the vulnerability.
 */
function verifyCWE778(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SEC_OPERATION_RE = /\b(login|logout|authenticate|authorize|signIn|sign_in|signOut|sign_out|changePassword|change_password|resetPassword|reset_password|deleteUser|delete_user|grantRole|grant_role|revokeRole|revoke_role|createAdmin|create_admin|elevatePrivilege|sudo|impersonate|transferFunds|transfer_funds|deleteAccount|delete_account|approveTransaction|updatePermission|modifyAcl)\b/i;

  const AUTH_FAILURE_RE = /\b(invalid.*password|wrong.*password|authentication.*fail|login.*fail|unauthorized|access.*denied|forbidden|invalid.*credentials|bad.*credentials|invalid.*token|expired.*token|permission.*denied)\b/i;

  const LOG_RE = /\b(console\.(?:log|warn|error|info)|logger\.(?:info|warn|error|debug|log|audit|security)|log\.(?:info|warn|error|debug|Printf|Println)|logging\.(?:info|warn|error|warning|critical|debug)|Log\.(?:i|w|e|d|v)\s*\(|syslog|audit_log|auditLog|EventLog|SecurityEvent|AuditEvent|winston|pino|bunyan|log4j|slf4j|NLog|Serilog|structlog|loguru)\b/i;

  const securityNodes = [...nodesOfType(map, 'AUTH'), ...nodesOfType(map, 'CONTROL')];

  for (const node of securityNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    const isSecOp = SEC_OPERATION_RE.test(code) || SEC_OPERATION_RE.test(node.label) ||
      AUTH_FAILURE_RE.test(code) || node.node_subtype.includes('auth');

    if (!isSecOp) continue;

    if (!LOG_RE.test(code)) {
      const opMatch = code.match(SEC_OPERATION_RE) || code.match(AUTH_FAILURE_RE);
      const opName = opMatch ? opMatch[1] : 'security operation';

      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EGRESS (audit logging for security-critical operation)',
        severity: 'medium',
        description: `Security-critical operation "${opName}" at ${node.label} has no logging. ` +
          `Without audit logs, authentication failures, privilege escalations, and security breaches go undetected.`,
        fix: 'Add structured audit logging for all security events. Log WHO (user/IP), WHAT (action), ' +
          'WHEN (timestamp), WHERE (endpoint), SUCCESS/FAILURE. Use a dedicated audit logger.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-778', name: 'Insufficient Logging', holds: findings.length === 0, findings };
}

/**
 * CWE-779: Logging of Excessive Data
 * Pattern: Logging statements that include sensitive data (passwords, tokens, full
 * request bodies, credit cards) or verbose levels in production.
 *
 * NOTABLE: CWE-778 (too little) and CWE-779 (too much) are OPPOSITES in the same family.
 * The sweet spot: log security EVENTS without logging security DATA. Many codebases fail
 * BOTH simultaneously — they log full request bodies (779) but not auth failures (778).
 */
function verifyCWE779(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const LOG_CALL_RE = /\b(console\.(?:log|warn|error|info|debug)|logger\.(?:info|warn|error|debug|log|trace)|log\.(?:info|warn|error|debug|trace|Printf|Println)|logging\.(?:info|warn|error|warning|debug)|Log\.(?:i|w|e|d|v)\s*\(|print\s*\(|puts\s|fmt\.Print|System\.out\.print)/i;

  const SENSITIVE_LOG_PATTERNS = [
    /(?:log|print|console|logger|puts|fmt)\S*\s*\(.*\b(?:password|passwd|pwd|secret|apiKey|api_key|token|accessToken|access_token|refreshToken|refresh_token|privateKey|private_key|ssn|creditCard|credit_card|cardNumber|card_number|cvv)\b/i,
    /(?:log|print|console|logger)\S*\s*\(.*(?:req\.body|request\.body|request\.data|request\.json|params|request\.POST|request\.GET)\s*\)/i,
    /(?:log|print|console|logger)\S*\s*\(.*JSON\.stringify\s*\(\s*(?:req|request|user|session|config|credentials|auth)\b/i,
  ];

  const REDACT_RE = /\b(redact|mask|obfuscate|sanitize|scrub|filter|censor|hideSecret|hide_secret|maskSensitive|mask_sensitive|\*{3,}|\.replace\s*\(.*\*|REDACTED|MASKED|FILTERED)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!LOG_CALL_RE.test(code)) continue;

    for (const pattern of SENSITIVE_LOG_PATTERNS) {
      if (pattern.test(code) && !REDACT_RE.test(code)) {
        const sensitiveMatch = code.match(/\b(password|passwd|pwd|secret|apiKey|api_key|token|accessToken|access_token|refreshToken|refresh_token|privateKey|private_key|ssn|creditCard|credit_card|cardNumber|cvv|req\.body|request\.body)\b/i);
        const dataType = sensitiveMatch ? sensitiveMatch[1] : 'sensitive data';

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (redaction/masking of sensitive data before logging)',
          severity: 'high',
          description: `${node.label} logs "${dataType}" without redaction. ` +
            `Logs are stored in plaintext, shipped to centralized systems, and accessed by operations staff. ` +
            `Sensitive data in logs creates a secondary attack surface.`,
          fix: 'Never log passwords, tokens, or credit card numbers. Redact sensitive fields: ' +
            'logger.info({ ...user, password: "[REDACTED]" }). Use structured logging with auto-redaction.',
            via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-779', name: 'Logging of Excessive Data', holds: findings.length === 0, findings };
}

/**
 * CWE-804: Guessable CAPTCHA
 * Pattern: CAPTCHA implementations that are trivially bypassable — client-side only,
 * hardcoded answers, simple math, or missing server-side verification.
 *
 * NOTABLE: Many "CAPTCHAs" just check a hidden form field or do client-side JS validation.
 * A surprising number use simple math ("What is 2+3?") which any bot solves instantly.
 * The actual security comes from server-side verification against the CAPTCHA service —
 * and that's what's most often missing.
 */
function verifyCWE804(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CAPTCHA_RE = /\b(captcha|recaptcha|hcaptcha|turnstile|challenge|bot[_-]?check|human[_-]?verification|anti[_-]?bot)\b/i;

  const CLIENT_SIDE_CAPTCHA = /\b(document\.getElementById\s*\(\s*['"]captcha|\.value\s*===?\s*['"]|captchaAnswer\s*===?\s*|validateCaptcha\s*=\s*function|grecaptcha\.getResponse\s*\(\s*\)(?!.*fetch|.*axios|.*post|.*send|.*request))\b/i;

  const HARDCODED_CAPTCHA = /\b(captcha\s*(?:===?|==)\s*['"][^'"]+['"]|captcha_answer\s*[:=]\s*['"][^'"]+['"]|answer\s*[:=]\s*['"](?:\d{1,4}|[a-z]{1,4})['"]|Math\.\s*(?:floor|round|random).*captcha)\b/i;

  const MATH_CAPTCHA = /\b(num1\s*\+\s*num2|a\s*\+\s*b|firstNumber\s*\+\s*secondNumber|math.*captcha|captcha.*math|simple.*math|what\s+is\s+\d+\s*[+\-*/]\s*\d+)\b/i;

  const SERVER_VERIFY_RE = /\b(verify.*captcha|captcha.*verify|recaptcha.*verify|siteverify|secret.*captcha|captcha.*secret|g-recaptcha-response|h-captcha-response|cf-turnstile-response|fetch\s*\(\s*['"]https:\/\/.*(?:recaptcha|hcaptcha|turnstile)|axios\.post\s*\(\s*['"].*(?:recaptcha|hcaptcha|turnstile)|requests\.post\s*\(\s*['"].*(?:recaptcha|hcaptcha|turnstile))\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!CAPTCHA_RE.test(code) && !CAPTCHA_RE.test(node.label)) continue;

    if (CLIENT_SIDE_CAPTCHA.test(code) && !SERVER_VERIFY_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EXTERNAL (server-side CAPTCHA verification via provider API)',
        severity: 'high',
        description: `CAPTCHA at ${node.label} validates client-side only. ` +
          `Bypassed by submitting the form directly without JavaScript or setting expected form values.`,
        fix: 'Always verify CAPTCHA server-side: reCAPTCHA: POST google.com/recaptcha/api/siteverify. ' +
          'hCaptcha: POST hcaptcha.com/siteverify. Never trust client-side CAPTCHA validation alone.',
          via: 'structural',
      });
    }

    if (HARDCODED_CAPTCHA.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (dynamic CAPTCHA generation with unpredictable answers)',
        severity: 'high',
        description: `CAPTCHA at ${node.label} uses hardcoded or predictable answers. ` +
          `An attacker who reads the source can bypass it entirely.`,
        fix: 'Use a proven CAPTCHA service (reCAPTCHA v3, hCaptcha, Turnstile) instead of rolling your own.',
        via: 'structural',
      });
    }

    if (MATH_CAPTCHA.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (CAPTCHA that resists automated solving)',
        severity: 'medium',
        description: `CAPTCHA at ${node.label} uses simple arithmetic. ` +
          `Math CAPTCHAs are trivially solvable by any bot using basic parsing.`,
        fix: 'Replace with behavioral analysis CAPTCHA (reCAPTCHA v3) or proof-of-work (Turnstile).',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-804', name: 'Guessable CAPTCHA', holds: findings.length === 0, findings };
}

/**
 * CWE-806: Buffer Access Using Size of Source Buffer
 * Pattern: Using the size of the SOURCE buffer (not the destination) when copying data.
 * Classic C/C++ bug: memcpy(dest, src, sizeof(src)) when dest is smaller than src.
 *
 * NOTABLE: strncpy(dest, src, strlen(src)) is SEMANTICALLY IDENTICAL to strcpy(dest, src) —
 * the 'n' is the source length, so it copies everything. Developers think they're safe
 * using strncpy, but they've made it pointless. One of the most common C security
 * misunderstandings.
 */
function verifyCWE806(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MEMCPY_SRC_SIZE = [
    /\bmemcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(?:sizeof\s*\(\s*\2\s*\)|strlen\s*\(\s*\2\s*\))/,
    /\bmemmove\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(?:sizeof\s*\(\s*\2\s*\)|strlen\s*\(\s*\2\s*\))/,
    /\bstrncpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*strlen\s*\(\s*\2\s*\)/,
    /\bstrncat\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*strlen\s*\(\s*\2\s*\)/,
  ];

  const SAFE_SIZE_RE = /\bsizeof\s*\(\s*dest|sizeof\s*\(\s*buffer|sizeof\s*\(\s*out|dest_size|dst_size|buf_size|capacity|BUFFER_SIZE|MAX_\w+_LEN/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    for (const pattern of MEMCPY_SRC_SIZE) {
      if (pattern.test(code) && !SAFE_SIZE_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (use destination buffer size, not source size, for copy length)',
          severity: 'high',
          description: `${node.label} uses the source buffer's size as the copy length. ` +
            `If the source exceeds the destination, this overflows. ` +
            `strncpy(dest, src, strlen(src)) is semantically identical to strcpy(dest, src).`,
          fix: 'Use DESTINATION buffer size: strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1]="\\0"; ' +
            'memcpy(dest, src, MIN(src_len, dest_capacity)). Better: strlcpy() or snprintf().',
            via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-806', name: 'Buffer Access Using Size of Source Buffer', holds: findings.length === 0, findings };
}

/**
 * CWE-807: Reliance on Untrusted Inputs in a Security Decision
 * Pattern: Security decisions based on client-controlled values like cookies,
 * hidden form fields, HTTP headers, URL parameters, or client-side JS variables.
 *
 * NOTABLE: Philosophically fascinating CWE — "what inputs can you trust?" Almost none
 * from the client. Even Referer, X-Forwarded-For, Accept-Language are attacker-controlled.
 * Classic: if (req.cookies.isAdmin === "true") to grant admin access.
 */
function verifyCWE807(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const UNTRUSTED_INPUT_PATTERNS = [
    /\b(?:req\.cookies|request\.cookies|cookie|getCookie|document\.cookie)\s*(?:\[['"]|\.)(?:isAdmin|is_admin|role|admin|privilege|permission|access_level|user_type|auth|authorized|logged_in|loggedIn)\b/i,
    /\b(?:req\.body|request\.form|request\.POST)\s*(?:\[['"]|\.)(?:isAdmin|is_admin|role|admin|privilege|permission|access_level|user_type|authorized)\b/i,
    /\b(?:req\.headers|request\.headers)\s*\[?\s*['"](?:referer|x-forwarded-for|x-real-ip|origin|x-custom-auth|x-user-role|x-admin)['"].*?(?:if|===?|!==?|switch|grant|allow|deny|permit|authorize)/i,
    /\bif\s*\(\s*(?:req\.query|req\.params|request\.args|request\.GET)\s*(?:\[['"]|\.)(?:admin|role|is_admin|privilege|auth|permission)\b/i,
    /\b(?:localStorage|sessionStorage)\.getItem\s*\(\s*['"](?:token|auth|role|isAdmin|is_admin|admin|user_role|access_level)['"]\s*\).*?(?:if|===?|grant|allow)/i,
  ];

  const SERVER_VERIFY_RE = /\b(?:jwt\.verify|verifyToken|verify_token|authenticate|validateSession|validate_session|checkPermission|check_permission|passport\.authenticate|req\.isAuthenticated|session\.\w+|req\.user\.\w+|auth\.check|authorize|@RequiresRole|@PreAuthorize|@Secured|has_perm|has_role|current_user)\b/i;

  const CRYPTO_VERIFY_RE = /\b(?:hmac|signature|jwt|signed|encrypt|decrypt|hash\.compare|bcrypt\.compare|crypto\.timingSafeEqual|verify_signature)\b/i;

  const checkNodes = [...nodesOfType(map, 'INGRESS'), ...nodesOfType(map, 'AUTH'), ...nodesOfType(map, 'CONTROL')];

  for (const node of checkNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (SERVER_VERIFY_RE.test(code) || CRYPTO_VERIFY_RE.test(code)) continue;

    for (const pattern of UNTRUSTED_INPUT_PATTERNS) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'AUTH (server-side verification, not client-supplied values)',
          severity: 'critical',
          description: `Security decision at ${node.label} relies on client-controlled input. ` +
            `Cookies, hidden fields, HTTP headers, and query parameters are fully attacker-controlled. ` +
            `Checking req.cookies.isAdmin for authorization is trivially bypassable.`,
          fix: 'Use server-side sessions (req.session.user), JWT with signature verification (jwt.verify()), ' +
            'or database-backed permission checks. Never trust client-supplied role/permission values.',
            via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-807', name: 'Reliance on Untrusted Inputs in a Security Decision', holds: findings.length === 0, findings };
}

/**
 * CWE-829: Inclusion of Functionality from Untrusted Control Sphere
 * Pattern: Loading scripts, libraries, or code from external sources without integrity
 * verification. Includes CDN script tags without SRI, dynamic require/import of
 * user-controlled paths, and runtime remote code execution.
 *
 * NOTABLE: The 2018 British Airways breach was exactly this — Magecart injected a skimmer
 * into a third-party CDN script loaded without integrity checks. 380,000 credit cards stolen.
 * SRI (Subresource Integrity) would have prevented it entirely.
 */
function verifyCWE829(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const INTEGRITY_RE = /\bintegrity\s*=\s*['"]sha(?:256|384|512)-|\.verify\s*\(|checksum|hashCheck|verifyIntegrity|signatureVerif|allowlist|whitelist|safelist|ALLOWED_MODULES|trustedTypes/i;

  const CSP_RE = /\bContent-Security-Policy|script-src\s+'(?:self|nonce-|strict-dynamic)|helmet\.contentSecurityPolicy|csp\s*\(/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // External script tags without SRI
    if (/\<script\s+[^>]*src\s*=\s*['"]https?:\/\//.test(code) && !/integrity\s*=/.test(code) && !CSP_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (Subresource Integrity hash or Content-Security-Policy)',
        severity: 'high',
        description: `${node.label} loads an external script without SRI. ` +
          `If the CDN is compromised, the attacker's script runs with full page access.`,
        fix: 'Add integrity and crossorigin attributes: ' +
          '<script src="..." integrity="sha384-..." crossorigin="anonymous">. ' +
          'Also deploy Content-Security-Policy with script-src restrictions.',
          via: 'structural',
      });
    }

    // Dynamic require/import with user-controlled path
    if (/\b(?:require|import)\s*\(\s*(?!['"`])[^)]+\)/.test(code) && !INTEGRITY_RE.test(code)) {
      const hasUserInput = /\b(?:req\.|request\.|params\.|query\.|body\.|input\.|user\.|process\.env|argv)\b/.test(code);
      if (hasUserInput) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (allowlist of permitted modules, integrity verification)',
          severity: 'critical',
          description: `${node.label} dynamically loads modules from user-controlled paths. ` +
            `An attacker who controls the module path can execute arbitrary code.`,
          fix: 'Use an allowlist: const ALLOWED = new Set(["./mod1"]); if (!ALLOWED.has(path)) throw. ' +
            'Never construct require/import paths from user input.',
            via: 'structural',
        });
      }
    }

    // PHP include with variable
    if (/\b(?:include|require|include_once|require_once)\s*\(\s*\$(?!__DIR__|_SERVER\['DOCUMENT_ROOT'\])\w+/.test(code) && !INTEGRITY_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (allowlist of includable files, path validation)',
        severity: 'critical',
        description: `${node.label} includes a PHP file from a variable path. ` +
          `If the variable is user-controlled, this enables Remote File Inclusion (RFI).`,
        fix: 'Use an allowlist of includable files. Disable allow_url_include in php.ini. ' +
          'Use __DIR__ . "/allowed_file.php" instead of variable paths.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-829', name: 'Inclusion of Functionality from Untrusted Control Sphere', holds: findings.length === 0, findings };
}

/**
 * CWE-835: Loop with Unreachable Exit Condition — Infinite Loop
 * Pattern: Loops where the exit condition can never be reached — while(true) without
 * break, loop variable never changed, polling without timeout.
 *
 * NOTABLE: Most production infinite loops aren't the obvious while(true). They're subtle:
 * a loop waiting for a network response that never comes (no timeout), or a retry loop
 * where retries is never incremented inside the catch block. The most insidious:
 * while(retries < maxRetries) where retries++ is accidentally outside the catch.
 */
function verifyCWE835(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const INFINITE_LOOP_PATTERNS = [
    /\bwhile\s*\(\s*(?:true|1|!0|!!1)\s*\)\s*\{/,
    /\bfor\s*\(\s*;?\s*;?\s*\)\s*\{/,
    /\bloop\s*(?:\(\s*true\s*\))?\s*\{/,
  ];

  const EXIT_RE = /\b(?:break|return|throw|exit|process\.exit|sys\.exit|os\.Exit|panic!|raise|abort)\b/;

  const TIMEOUT_RE = /\b(?:timeout|setTimeout|deadline|maxWait|max_wait|TimeoutError|context\.WithTimeout|ctx\.Done|time\.After|signal\.alarm|AbortController|AbortSignal)\b/i;

  const POLLING_NO_TIMEOUT = /\bwhile\s*\(\s*!?\s*(?:ready|done|finished|complete|available|connected|isReady|isDone|isFinished|isComplete|isAvailable|isConnected)\b[^{]*\{(?:(?!\btimeout\b|\bsetTimeout\b|\bdeadline\b|\bmax\w*Wait\b)[\s\S])*?\}/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    for (const pattern of INFINITE_LOOP_PATTERNS) {
      if (pattern.test(code)) {
        if (!EXIT_RE.test(code) && !TIMEOUT_RE.test(code)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (loop exit condition — break, return, timeout, or bounded iteration)',
            severity: 'high',
            description: `${node.label} contains an unconditional infinite loop without a visible break, return, or timeout. ` +
              `If the expected exit condition never occurs, this hangs the thread/process permanently.`,
            fix: 'Add a timeout: const deadline = Date.now() + TIMEOUT_MS; while (true) { if (Date.now() > deadline) break; }. ' +
              'For retries: while (retries++ < MAX_RETRIES). For events: use AbortController for cancellation.',
              via: 'structural',
          });
        }
      }
    }

    if (POLLING_NO_TIMEOUT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (timeout/deadline for polling loop)',
        severity: 'medium',
        description: `${node.label} has a polling loop waiting for a condition without a timeout. ` +
          `If the condition never becomes true (crashed service, network partition), the loop runs forever.`,
        fix: 'Add timeout: const start = Date.now(); while (!ready && (Date.now()-start) < TIMEOUT) { await sleep(100); }. ' +
          'Use exponential backoff. In Go: select { case <-ctx.Done(): return }.',
          via: 'structural',
      });
    }

    // Retry loops where counter is never incremented
    const retryMatch = code.match(/\bwhile\s*\(\s*(\w+)\s*<\s*(?:\w+|\d+)\s*\)\s*\{((?:(?!\bwhile\b)[\s\S])*?)\}/);
    if (retryMatch) {
      const varName = retryMatch[1];
      const loopBody = retryMatch[2];
      const incrementRE = new RegExp(`\\b${varName}\\s*(?:\\+\\+|\\+=|=\\s*${varName}\\s*\\+)`);
      if (!incrementRE.test(loopBody)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `CONTROL (loop counter increment — "${varName}" never incremented in loop body)`,
          severity: 'high',
          description: `${node.label} has a loop bounded by "${varName}" but the variable is never incremented ` +
            `inside the loop body — a de facto infinite loop that appears bounded. ` +
            `Common in retry loops where the increment is accidentally outside the catch block.`,
          fix: `Ensure "${varName}" is incremented every iteration: ` +
            `while (${varName} < max) { try { ... } finally { ${varName}++; } }.`,
            via: 'structural',
        });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Source-line scanner fallback: detect infinite loops in raw source code.
  // The node walk above can miss loops when the loop construct spans multiple
  // nodes or the code_snapshot is truncated. This scans the full source to find:
  //   1. while(true) / for(;;) / do...while(true) without break/return/throw
  //   2. do...while with always-true condition (e.g., modulo ensures non-negative)
  //   3. while/for loops where the counter is never modified in the body
  // ---------------------------------------------------------------------------
  if (findings.length === 0 && map.source_code) {
    const src835 = stripComments(map.source_code);
    const lines835 = src835.split('\n');
    const SRC_EXIT_RE = /\b(?:break|return|throw|exit|System\.exit|process\.exit|sys\.exit|os\.Exit|panic|raise|abort)\b/;

    for (let i = 0; i < lines835.length; i++) {
      const line = lines835[i];
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

      // Pattern 1: while(true) / while(1) / while(!0) without break in surrounding body
      if (/\bwhile\s*\(\s*(?:true|1|!0|!!1)\s*\)/.test(line) && !/^\s*\}\s*while/.test(line)) {
        const loopBody = extractBraceBlock835(lines835, i);
        if (loopBody !== null && !SRC_EXIT_RE.test(loopBody)) {
          const nearNode = findNearestNode(map, i + 1) || map.nodes[0];
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'CONTROL (loop exit condition — break, return, timeout, or bounded iteration)',
              severity: 'high',
              description: `L${i + 1}: while(true) loop without break, return, or throw in the loop body. ` +
                `This is an unconditional infinite loop that will hang the thread/process.`,
              fix: 'Add a break condition, timeout, or bounded iteration count inside the loop.',
              via: 'source_line_fallback',
            });
          }
        }
      }

      // Pattern 2: for(;;) without break in body
      if (/\bfor\s*\(\s*;?\s*;?\s*\)/.test(line)) {
        const loopBody = extractBraceBlock835(lines835, i);
        if (loopBody !== null && !SRC_EXIT_RE.test(loopBody)) {
          const nearNode = findNearestNode(map, i + 1) || map.nodes[0];
          if (nearNode) {
            findings.push({
              source: nodeRef(nearNode), sink: nodeRef(nearNode),
              missing: 'CONTROL (loop exit condition — break, return, timeout, or bounded iteration)',
              severity: 'high',
              description: `L${i + 1}: for(;;) loop without break, return, or throw in the loop body. ` +
                `This is an unconditional infinite loop.`,
              fix: 'Add a break condition, timeout, or bounded iteration count inside the loop.',
              via: 'source_line_fallback',
            });
          }
        }
      }

      // Pattern 3: do { ... } while(<always-true condition>) without break/return/throw
      if (/^\s*do\s*\{?\s*$/.test(line)) {
        const doBlock = extractDoWhileBlock835(lines835, i);
        if (doBlock) {
          const { body, conditionLine, condition } = doBlock;
          let isAlwaysTrue = false;

          // while(true) / while(1)
          if (/^\s*(?:true|1|!0|!!1)\s*$/.test(condition)) {
            isAlwaysTrue = true;
          }

          // while(VAR >= 0) where VAR = (... % N) — modulo always >= 0
          const geZeroMatch = condition.match(/^\s*(\w+)\s*>=\s*0\s*$/);
          if (geZeroMatch) {
            const vn = geZeroMatch[1];
            const modRE = new RegExp(`\\b${vn}\\s*=\\s*.*%\\s*\\d+`);
            if (modRE.test(body)) {
              isAlwaysTrue = true;
            }
          }

          if (isAlwaysTrue && !SRC_EXIT_RE.test(body)) {
            const nearNode = findNearestNode(map, i + 1) || map.nodes[0];
            if (nearNode) {
              findings.push({
                source: nodeRef(nearNode), sink: nodeRef(nearNode),
                missing: 'CONTROL (loop exit condition — break, return, or reachable termination)',
                severity: 'high',
                description: `L${i + 1}: do...while loop at L${conditionLine} has an always-true condition ` +
                  `(${condition.trim()}) and no break/return/throw in the body. This is an infinite loop.`,
                fix: 'Add a break condition inside the loop body, or ensure the while condition can become false. ' +
                  'For bounded iteration, add a counter: if (++count > MAX) break;',
                  via: 'source_line_fallback',
              });
            }
          }
        }
      }

      // Pattern 4: while(VAR >= 0) with modulo (non-do-while)
      const whileGeMatch = line.match(/\bwhile\s*\(\s*(\w+)\s*>=?\s*0\s*\)/);
      if (whileGeMatch && !/^\s*\}\s*while/.test(line)) {
        const vn = whileGeMatch[1];
        const loopBody = extractBraceBlock835(lines835, i);
        if (loopBody !== null) {
          const modRE = new RegExp(`\\b${vn}\\s*=\\s*.*%\\s*\\d+`);
          if (modRE.test(loopBody) && !SRC_EXIT_RE.test(loopBody)) {
            const nearNode = findNearestNode(map, i + 1) || map.nodes[0];
            if (nearNode) {
              findings.push({
                source: nodeRef(nearNode), sink: nodeRef(nearNode),
                missing: 'CONTROL (loop exit condition — modulo result is always non-negative)',
                severity: 'high',
                description: `L${i + 1}: while(${vn} >= 0) loop where ${vn} is assigned via modulo. ` +
                  `Modulo of non-negative values always yields >= 0, making the condition always true.`,
                fix: 'Add a break condition, or change the loop bound to a finite counter.',
                via: 'source_line_fallback',
              });
            }
          }
        }
      }
    }
  }

  return { cwe: 'CWE-835', name: 'Loop with Unreachable Exit Condition (Infinite Loop)', holds: findings.length === 0, findings };
}

/**
 * Helper: Extract the brace-delimited block starting from a line containing '{'.
 * Returns the text inside the braces, or null if no balanced block found.
 */
function extractBraceBlock835(lines: string[], startIdx: number): string | null {
  let depth = 0;
  let started = false;
  const bodyLines: string[] = [];
  for (let j = startIdx; j < Math.min(startIdx + 200, lines.length); j++) {
    const ln = lines[j];
    for (const ch of ln) {
      if (ch === '{') { depth++; started = true; }
      if (ch === '}') { depth--; }
    }
    if (started) bodyLines.push(ln);
    if (started && depth <= 0) return bodyLines.join('\n');
  }
  return null;
}

/**
 * Helper: Extract a do { ... } while(COND) block.
 * Returns { body, conditionLine, condition } or null.
 */
function extractDoWhileBlock835(lines: string[], startIdx: number): { body: string; conditionLine: number; condition: string } | null {
  let depth = 0;
  let started = false;
  const bodyLines: string[] = [];
  let closeLine = -1;
  for (let j = startIdx; j < Math.min(startIdx + 200, lines.length); j++) {
    const ln = lines[j];
    for (const ch of ln) {
      if (ch === '{') { depth++; started = true; }
      if (ch === '}') { depth--; }
    }
    if (started) bodyLines.push(ln);
    if (started && depth <= 0) { closeLine = j; break; }
  }
  if (closeLine < 0) return null;

  // The while(...) is on the same line as '}' or the next line(s)
  for (let j = closeLine; j < Math.min(closeLine + 3, lines.length); j++) {
    const whileMatch = lines[j].match(/while\s*\(\s*(.*?)\s*\)\s*;/);
    if (whileMatch) {
      return { body: bodyLines.join('\n'), conditionLine: j + 1, condition: whileMatch[1] };
    }
  }
  return null;
}

/**
 * CWE-595: Comparison of Object References Instead of Object Contents
 * Pattern: Using reference equality (==, ===, is, eq?) on objects/strings where
 * content comparison (.equals(), deep compare, JSON.stringify compare) is needed.
 *
 * SECOND-PASS NOTE: evaluateControlEffectiveness could catch a variant where a
 * CONTROL node uses reference equality for an authorization check — the control
 * "exists" but is semantically wrong (comparing object identity instead of value).
 */
function verifyCWE595(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const JAVA_REF_CMP = /\b(\w+)\s*==\s*(\w+).*(?:String|Integer|Long|Boolean|Double|Float|BigDecimal|BigInteger|Object|Date|UUID)/;
  const PYTHON_IS_CMP = /\b(\w+)\s+is\s+(?!None\b|True\b|False\b|not\b)(\w+)/;
  const JS_OBJ_CMP = /\b(?:new\s+\w+|JSON\.parse|Object\.assign|\w+\.parse|\[\s*\]|\{\s*\})\s*===?\s*(?:new\s+\w+|JSON\.parse|Object\.assign|\w+\.parse|\[\s*\]|\{\s*\})/;
  const ARRAY_OBJ_REF = /\b(\w+)\s*===?\s*(\w+)\b.*(?:\.length|\.push|\.pop|\.map|\.filter|\.keys|\.values|\.entries)/;

  const SAFE_COMPARE = /\b(\.equals\(|deepEqual|deepStrictEqual|isEqual|_.isEqual|assert\.equal|JSON\.stringify\(.+\)\s*===?\s*JSON\.stringify|lodash.*equal|shallowEqual|Object\.is\(|compareTo\(|\.localeCompare\(|\.compareTo\(|assertEqual|assertEquals)\b/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'CONTROL' && node.node_type !== 'TRANSFORM' && node.node_type !== 'STRUCTURAL') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_COMPARE.test(code)) continue;

    const lang = node.language?.toLowerCase() || '';

    if (lang.includes('java') && !lang.includes('javascript')) {
      const match = code.match(JAVA_REF_CMP);
      if (match) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (use .equals() for content comparison, not == for reference comparison)',
          severity: 'high',
          description: `${node.label} compares objects with == which checks reference identity in Java, not content equality. ` +
            `Two String objects with the same content are NOT == unless interned.`,
          fix: 'Use .equals() for String/boxed type comparison. For null-safe comparison use Objects.equals(a, b) or "literal".equals(var).',
          via: 'structural',
        });
      }
    }

    if (lang.includes('python')) {
      const match = code.match(PYTHON_IS_CMP);
      if (match) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (use == for value comparison, not "is" for identity comparison)',
          severity: 'high',
          description: `${node.label} uses "is" for comparison which checks object identity in Python, not value equality. ` +
            `This works for small integers (-5 to 256) and interned strings but fails unpredictably for other values.`,
          fix: 'Use == for value comparison. Reserve "is" only for None, True, False, and sentinel objects.',
          via: 'structural',
        });
      }
    }

    if (lang.includes('javascript') || lang.includes('typescript') || lang === '') {
      if (JS_OBJ_CMP.test(code) || ARRAY_OBJ_REF.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (use deep comparison for objects, not === reference check)',
          severity: 'medium',
          description: `${node.label} compares objects/arrays with === which checks reference identity in JavaScript. ` +
            `Two objects with identical contents are NOT === unless they are the same reference.`,
          fix: 'Use deep comparison: JSON.stringify for simple cases, lodash isEqual, or a custom deepEqual. For arrays, compare element-by-element.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-595', name: 'Comparison of Object References Instead of Object Contents', holds: findings.length === 0, findings };
}

/**
 * CWE-597: Use of Wrong Operator in String Comparison
 * Narrower than CWE-595 — specifically about strings, not all objects.
 * Java == on strings is a classic beginner mistake that can work sometimes
 * (due to string interning) and fail unpredictably.
 */
function verifyCWE597(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const JAVA_STR_LITERAL_CMP = /"[^"]*"\s*==\s*\w+|\w+\s*==\s*"[^"]*"/;
  const SHELL_STR_WRONG = /\[\[\s*\$\w+\s*=\s*[^=]|\[\s*\$\w+\s*=\s*[^=]/;
  const SAFE_STR_CMP = /\b(\.equals\(|\.equalsIgnoreCase\(|\.compareTo\(|\.contentEquals\(|Objects\.equals\(|StringUtils\.equals|strcmp|str[n]?cmp|\.localeCompare\()\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_STR_CMP.test(code)) continue;
    const lang = node.language?.toLowerCase() || '';

    if (lang.includes('java') && !lang.includes('javascript')) {
      if (JAVA_STR_LITERAL_CMP.test(code)) {
        const notNull = /==\s*null|null\s*==/;
        if (!notNull.test(code)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (use .equals() for String comparison in Java)',
            severity: 'high',
            description: `${node.label} compares a String with == operator. In Java, == compares references, not string content. ` +
              `This may pass for string literals (interned) but fail for dynamically created strings (from user input, DB, etc.).`,
            fix: 'Use "literal".equals(variable) for null-safe comparison, or Objects.equals(a, b). Never use == for String comparison in Java.',
            via: 'structural',
          });
        }
      }
    }

    if (lang.includes('bash') || lang.includes('shell') || lang.includes('sh')) {
      if (SHELL_STR_WRONG.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (use == for string comparison in shell, not single =)',
          severity: 'medium',
          description: `${node.label} uses single = for string comparison in a test expression. While this works in [[ ]], ` +
            `it can cause assignment instead of comparison in other contexts.`,
          fix: 'Use == for string comparison in [[ ]] or test expressions. Quote variables: [[ "$var" == "value" ]].',
          via: 'structural',
        });
      }
    }
  }

  // --- Strategy 2: Source-scan with String variable tracking (merged from generated) ---
  // Catches Juliet patterns: String s1 = readLine(); String s2 = readLine(); if (s1 == s2)
  const src597 = map.source_code || '';
  const isJava597 = /\bpackage\s+\w|import\s+java\.|public\s+class\b/.test(src597);
  if (src597 && isJava597 && findings.length === 0) {
    const lines597 = src597.split('\n');
    // Collect known String variable names
    const stringVars597 = new Set<string>();
    for (const ln of lines597) {
      const decl = ln.match(/\bString\s+(\w+)\s*[=;]/);
      if (decl) stringVars597.add(decl[1]);
      const paramRe = /\bString\s+(\w+)\s*[,)]/g;
      let pm;
      while ((pm = paramRe.exec(ln)) !== null) stringVars597.add(pm[1]);
      const rl = ln.match(/(\w+)\s*=\s*\w+\.readLine\(\)/);
      if (rl) stringVars597.add(rl[1]);
    }

    for (let i = 0; i < lines597.length; i++) {
      const line = lines597[i];
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*\/\*/.test(line)) continue;
      // Skip null checks
      if (/==\s*null|null\s*==|!=\s*null|null\s*!=/.test(line)) continue;

      for (const sv of stringVars597) {
        // Pattern: sv == otherVar or sv == "literal"
        const eqRe = new RegExp(`\\b${sv}\\s*==\\s*(?:(\\w+)\\b|("(?:[^"\\\\]|\\\\.)*"))`);
        const m = eqRe.exec(line);
        if (m) {
          const other = m[1] || m[2];
          if (other === 'null' || other === 'true' || other === 'false') continue;
          if (stringVars597.has(other) || m[2] !== undefined) {
            const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
            if (nearNode) {
              findings.push({
                source: nodeRef(nearNode), sink: nodeRef(nearNode),
                missing: 'TRANSFORM (use .equals() for String comparison)',
                severity: 'medium',
                description: `L${i + 1}: String comparison uses == operator instead of .equals(). '${sv} == ${other}' compares object references, not string contents.`,
                fix: 'Use String.equals() for content comparison. The == operator compares object references in Java.',
                via: 'source_line_fallback',
              });
            }
            break; // One finding per line is enough
          }
        }
      }
    }
  }

  return { cwe: 'CWE-597', name: 'Use of Wrong Operator in String Comparison', holds: findings.length === 0, findings };
}

/**
 * CWE-607: Public Static Final Field References Mutable Object
 * Java: public static final List = new ArrayList<>();  JS: export const CFG = {};
 * The reference is immutable but the object contents can be mutated by any caller.
 */
function verifyCWE607(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Match any ordering of public/static/final with a mutable type
  const JAVA_PSF_MUTABLE = /\bpublic\s+(?:static\s+final|final\s+static)\s+(?:List|ArrayList|LinkedList|Set|HashSet|TreeSet|Map|HashMap|TreeMap|Collection|Vector|Stack|Queue|Deque|Date|Calendar|StringBuilder|StringBuffer|int\[\]|String\[\]|byte\[\]|Object\[\]|\w+\[\])\s*(?:<[^>]*>)?\s+(\w+)/;
  const JS_CONST_MUTABLE = /export\s+const\s+([A-Z_][A-Z0-9_]*)\s*(?::\s*\w+(?:<[^>]*>)?\s*)?=\s*(?:\{|\[|new\s+(?:Map|Set|Date|Array|WeakMap|WeakSet))/;
  const PY_CLASS_MUTABLE = /^\s*([A-Z_][A-Z0-9_]*)\s*(?::\s*\w+)?\s*=\s*(?:\[|\{|set\(|dict\(|list\(|defaultdict\()/m;
  const SAFE_IMMUTABLE = /\b(Collections\.unmodifiable\w*|List\.of\s*\(|Set\.of\s*\(|Map\.of\s*\(|Map\.copyOf|List\.copyOf|Set\.copyOf|ImmutableList|ImmutableSet|ImmutableMap|freeze|Object\.freeze|deepFreeze|readonly|ReadonlyArray|Readonly<|as\s+const|frozenset|tuple\s*\(|MappingProxyType)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const lang = node.language?.toLowerCase() || '';
    if (SAFE_IMMUTABLE.test(code)) continue;

    let match: RegExpMatchArray | null = null;
    let fieldName = '';

    if (lang.includes('java') && !lang.includes('javascript')) {
      match = code.match(JAVA_PSF_MUTABLE);
      if (match) fieldName = match[1];
    } else if (lang.includes('javascript') || lang.includes('typescript') || lang === '') {
      match = code.match(JS_CONST_MUTABLE);
      if (match) fieldName = match[1];
    } else if (lang.includes('python')) {
      match = code.match(PY_CLASS_MUTABLE);
      if (match) fieldName = match[1];
    }

    if (match && fieldName) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use immutable wrapper — Collections.unmodifiableList, Object.freeze, tuple)',
        severity: 'medium',
        description: `${node.label} declares a constant "${fieldName}" referencing a mutable object. ` +
          `While the reference cannot be reassigned, the object contents can be modified by any code ` +
          `that accesses it, leading to unexpected global state mutations and potential security bypasses ` +
          `(e.g., adding roles to a "constant" allowlist).`,
        fix: 'Java: Collections.unmodifiableList(List.of(...)) or List.of() directly. ' +
          'JS/TS: Object.freeze() or use "as const" for type-level immutability. ' +
          'Python: Use tuple instead of list, frozenset instead of set, MappingProxyType for dicts.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-607', name: 'Public Static Final Field References Mutable Object', holds: findings.length === 0, findings };
}

/**
 * CWE-609: Double-Checked Locking
 * Broken concurrency pattern: check condition, acquire lock, check again.
 * Without volatile/memory barriers, the second check can see a partially
 * constructed object due to instruction reordering.
 */
function verifyCWE609(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DCL_CHECK_LOCK_CHECK = /if\s*\([^)]*(?:==\s*null|===?\s*null|null\s*==|null\s*===?|==\s*None|is\s+None)[^)]*\)\s*\{?\s*(?:synchronized|lock|Lock|mutex|Mutex|acquire|with\s+\w*lock)/i;
  const INNER_CHECK = /(?:synchronized|lock|Lock|mutex|acquire|with\s+\w*lock)[\s\S]{0,200}if\s*\([^)]*(?:==\s*null|===?\s*null|is\s+None)/i;
  const FULL_DCL = /if\s*\([^)]*null[^)]*\)[\s\S]{0,50}(?:synchronized|lock)[\s\S]{0,200}if\s*\([^)]*null[^)]*\)[\s\S]{0,100}(?:new\s+\w+|=\s*\w+\.\w+\()/i;
  const SAFE_DCL = /\b(volatile|AtomicReference|Atomic\w+|LazyHolder|Lazy<|lazy\s*\{|@Synchronized|by\s+lazy|Once|dispatch_once|std::call_once|pthread_once|Interlocked|MemoryBarrier|memory_order|std::atomic|__sync_|_Atomic)\b/i;
  const SAFE_SINGLETON = /\benum\s+\w+\s*\{|class\s+\w+\s*\(.*object.*\)|val\s+\w+\s*by\s+lazy/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_DCL.test(code) || SAFE_SINGLETON.test(code)) continue;

    if (FULL_DCL.test(code) || (DCL_CHECK_LOCK_CHECK.test(code) && INNER_CHECK.test(code))) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (volatile keyword, AtomicReference, or safe lazy initialization pattern)',
        severity: 'high',
        description: `${node.label} uses double-checked locking without proper memory barriers. ` +
          `Without volatile (Java) or memory_order_acquire/release (C++), the JIT/CPU can reorder instructions ` +
          `so a thread sees a non-null reference to a partially constructed object.`,
        fix: 'Java: Mark the field volatile, or use an enum singleton, or use the holder class pattern (LazyHolder). ' +
          'C++: Use std::call_once or std::atomic with memory_order_acquire/release. ' +
          'Kotlin: Use "by lazy" or a companion object. Python: Generally unnecessary due to the GIL.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-609', name: 'Double-Checked Locking', holds: findings.length === 0, findings };
}

/**
 * CWE-619: Dangling Database Cursor
 * Database cursor/result set opened but not properly closed, causing resource leaks
 * that exhaust database connections in long-running servers.
 */
function verifyCWE619(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CURSOR_CREATE = /\b(createStatement|prepareStatement|prepareCall|\.cursor\(\)|\.execute\w*\(|\.query\(|resultSet|ResultSet|createQuery|createNativeQuery|\.rawQuery\(|\.raw\(|db\.prepare|connection\.query|pool\.query|client\.query|knex\.raw|sequelize\.query|prisma\.\$queryRaw|mongoose\.\w+\.find|collection\.find|collection\.aggregate)\b/i;
  const SAFE_CURSOR = /\b(\.close\(\)|\.release\(\)|\.end\(\)|\.destroy\(\)|\.dispose\(\)|\.finally\s*\(|finally\s*\{|try\s*\(|try-with-resources|with\s+\w+\.cursor|with\s+\w+\.connect|using\s*\(|await\s+\w+\.close|\.then\([^)]*close|pool\.release|client\.release|connection\.release|\.done\(\)|\.finish\(\)|defer\s+\w+\.Close|AutoCloseable|Closeable|IDisposable|context\s*manager)\b/i;
  const POOL_MANAGED = /\b(pool\.|connectionPool|DataSource|getConnection\(\).*try|DriverManager.*try|knex\(|createPool|ConnectionPool|pgPool|mysql\.createPool)\b/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'STORAGE' && node.node_type !== 'EXTERNAL' && node.node_type !== 'TRANSFORM') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!CURSOR_CREATE.test(code)) continue;
    if (SAFE_CURSOR.test(code)) continue;
    if (POOL_MANAGED.test(code)) continue;

    const scopeNodes = map.nodes.filter(n =>
      n.line_start >= node.line_start - 5 &&
      n.line_end <= node.line_end + 20 &&
      n.file === node.file
    );
    const hasCleanup = scopeNodes.some(n => SAFE_CURSOR.test(n.analysis_snapshot || n.code_snapshot));
    if (hasCleanup) continue;

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'CONTROL (cursor/resultset close in finally block or try-with-resources)',
      severity: 'medium',
      description: `${node.label} creates a database cursor/result set without visible cleanup. ` +
        `If this code path throws an exception, the cursor leaks. In a server handling many requests, ` +
        `leaked cursors exhaust the database connection limit.`,
      fix: 'Java: Use try-with-resources: try (var rs = stmt.executeQuery()) { ... }. ' +
        'Python: Use "with" context manager: with conn.cursor() as cur: ... ' +
        'Node: Use pool.query() which auto-releases, or ensure client.release() in finally.',
        via: 'structural',
    });
  }

  return { cwe: 'CWE-619', name: 'Dangling Database Cursor', holds: findings.length === 0, findings };
}

/**
 * CWE-625: Permissive Regular Expression
 * Regex used for security validation is too permissive — missing anchors, overly
 * broad character classes, unescaped dots. Allows values that should be rejected.
 *
 * SECOND-PASS NOTE: evaluateControlEffectiveness catches ReDoS (hangs on input),
 * but CWE-625 is about regex that PASSES malicious input (false negative).
 * Opposite failure modes, both are CONTROL weaknesses.
 */
function verifyCWE625(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const VALIDATION_REGEX = /\b(\.test\(|\.match\(|\.search\(|re\.match|re\.search|re\.fullmatch|Pattern\.matches|Regex\.IsMatch|\.matches\(|preg_match|=~|!~)\b/i;
  const DOMAIN_VALIDATE = /(?:domain|host|ip|email|url|origin)/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'CONTROL' && node.node_type !== 'TRANSFORM') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!VALIDATION_REGEX.test(code)) continue;

    const regexMatches = code.matchAll(/\/([^/]{3,})\/[gimsuy]*/g);
    for (const rm of regexMatches) {
      const pattern = rm[1];

      const isValidation = /\b(valid|check|verify|allow|match|filter|test|accept|restrict|deny|block)\b/i.test(code);
      if (!isValidation) continue;

      const hasStartAnchor = pattern.startsWith('^');
      const hasEndAnchor = pattern.endsWith('$');

      if (!hasStartAnchor || !hasEndAnchor) {
        const isSecurityContext = /\b(auth|admin|role|permission|token|session|password|secret|api[_-]?key|cors|origin|domain|host|ip|whitelist|allowlist|blacklist|blocklist)\b/i.test(code);

        if (isSecurityContext) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (anchor regex with ^ and $ for full-string matching)',
            severity: 'high',
            description: `${node.label} uses an unanchored regex /${pattern}/ for security validation. ` +
              `Without ^...$ anchors, the regex matches a SUBSTRING — an attacker can prepend or append ` +
              `malicious content that passes validation. E.g., /admin/ matches "not-admin-really".`,
            fix: 'Add ^ and $ anchors: /^pattern$/ for full-string matching. ' +
              'Or use re.fullmatch() (Python) instead of re.match()/re.search().',
              via: 'structural',
          });
          continue;
        }
      }

      if (DOMAIN_VALIDATE.test(code)) {
        const unescapedDots = pattern.match(/(?<!\\)\./g);
        if (unescapedDots && unescapedDots.length > 0) {
          const hasDomainLiteral = /\d+\.\d+\.\d+\.\d+|[\w-]+\.[\w-]+\.[\w-]+/.test(pattern);
          if (hasDomainLiteral) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(node),
              missing: 'CONTROL (escape dots in domain/IP regex: use \\. not .)',
              severity: 'medium',
              description: `${node.label} validates a domain/IP with unescaped dots in regex /${pattern}/. ` +
                `An unescaped dot matches ANY character, so "192.168.1.1" also matches "192x168x1x1". ` +
                `An attacker can bypass IP/domain restrictions with substitute characters.`,
              fix: 'Escape dots: use \\. instead of . in IP/domain regex. Better yet, parse the URL/IP ' +
                'with a library (new URL(), ipaddress.ip_address()) and compare programmatically.',
                via: 'structural',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-625', name: 'Permissive Regular Expression', holds: findings.length === 0, findings };
}

function verifyCWE908(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const UNINIT_PATTERNS: Array<{ pattern: RegExp; name: string; fix: string; severity: 'high' | 'medium' }> = [
    // C/C++: local variable declared without initialization then used
    { pattern: /\b(?:int|char|float|double|long|short|unsigned|size_t|ssize_t|uint\d+_t|int\d+_t|DWORD|HANDLE|BOOL)\s+(\w+)\s*;[^=]*?\b\1\b/,
      name: 'C/C++ variable declared without initialization',
      fix: 'Initialize at declaration: int x = 0; Compilers with -Wuninitialized can catch some cases.',
      severity: 'high' },
    // C: malloc without memset or initialization
    { pattern: /\bmalloc\s*\([^)]+\)\s*;(?!.*(?:memset|memcpy|bzero|calloc|ZeroMemory|SecureZeroMemory|={))/i,
      name: 'malloc without initialization (heap contains stale data)',
      fix: 'Use calloc() for zero-initialized memory, or memset() immediately after malloc().',
      severity: 'high' },
    // C: struct on stack without initialization
    { pattern: /\bstruct\s+\w+\s+(\w+)\s*;(?!.*(?:memset|=\s*\{|bzero|ZeroMemory))/i,
      name: 'stack struct declared without initialization',
      fix: 'Initialize with = {0} or memset(&var, 0, sizeof(var)).',
      severity: 'high' },
    // C: array on stack without initialization
    { pattern: /\b(?:char|int|uint8_t|unsigned\s+char)\s+(\w+)\s*\[\s*\d+\s*\]\s*;(?!.*(?:memset|=\s*\{|bzero|ZeroMemory|strncpy|snprintf))/i,
      name: 'stack buffer declared without initialization',
      fix: 'Initialize: char buf[256] = {0}; or memset(buf, 0, sizeof(buf)).',
      severity: 'high' },
    // Go: pointer var without value
    { pattern: /\bvar\s+\w+\s+\*(?:os\.File|net\.Conn|http\.Response|sql\.DB|sql\.Tx)\b(?!\s*=)/,
      name: 'Go pointer variable declared without initialization',
      fix: 'Initialize pointer types or check for nil before use.',
      severity: 'medium' },
    // Rust: MaybeUninit used without assume_init safety
    { pattern: /\bMaybeUninit\s*::\s*uninit\s*\(\)(?!.*(?:assume_init|write|as_mut_ptr))/i,
      name: 'Rust MaybeUninit without proper initialization',
      fix: 'Always initialize MaybeUninit before calling assume_init().',
      severity: 'high' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const up of UNINIT_PATTERNS) {
      if (up.pattern.test(code)) {
        if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `TRANSFORM (initialization — ${up.name})`,
          severity: up.severity,
          description: `${node.label}: ${up.name}. ` +
            `Using uninitialized memory can expose sensitive data from previous operations, ` +
            `cause crashes, or produce undefined behavior exploitable for code execution.`,
          fix: up.fix,
          via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-908', name: 'Use of Uninitialized Resource', holds: findings.length === 0, findings };
}

function verifyCWE909(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MISSING_INIT_PATTERNS: Array<{ allocRE: RegExp; initRE: RegExp; name: string; fix: string; severity: 'high' | 'medium' }> = [
    { allocRE: /\bSSL_CTX_new\s*\(/,
      initRE: /\bSSL_CTX_(?:set_cipher_list|set_options|load_verify_locations|use_certificate|set_min_proto_version)\s*\(/,
      name: 'SSL context created without security configuration',
      fix: 'After SSL_CTX_new(), call SSL_CTX_set_min_proto_version(), SSL_CTX_set_cipher_list(), and load trusted CAs.',
      severity: 'high' },
    { allocRE: /\bEVP_(?:CIPHER|MD)_CTX_new\s*\(/,
      initRE: /\bEVP_(?:Encrypt|Decrypt|Digest)Init(?:_ex)?\s*\(/,
      name: 'Crypto context allocated but not initialized',
      fix: 'Call EVP_EncryptInit_ex() or EVP_DigestInit_ex() immediately after EVP_*_CTX_new().',
      severity: 'high' },
    { allocRE: /\bpthread_mutex_t\s+/,
      initRE: /\bpthread_mutex_init\s*\(|PTHREAD_MUTEX_INITIALIZER/,
      name: 'POSIX mutex declared but not initialized',
      fix: 'Use PTHREAD_MUTEX_INITIALIZER or pthread_mutex_init(). Locking an uninitialized mutex is UB.',
      severity: 'high' },
    { allocRE: /\bCRITICAL_SECTION\s+/,
      initRE: /\bInitializeCriticalSection(?:AndSpinCount)?\s*\(/,
      name: 'CRITICAL_SECTION declared without initialization',
      fix: 'Call InitializeCriticalSection() before EnterCriticalSection().',
      severity: 'high' },
    { allocRE: /\blogging\.getLogger\s*\(/,
      initRE: /\blogging\.basicConfig\s*\(|logging\.config\.|addHandler\s*\(/,
      name: 'Logger created without handler configuration',
      fix: 'Call logging.basicConfig() or add handlers. Unconfigured loggers silently drop messages.',
      severity: 'medium' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const mp of MISSING_INIT_PATTERNS) {
      if (mp.allocRE.test(code) && !mp.initRE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `TRANSFORM (resource initialization — ${mp.name})`,
          severity: mp.severity,
          description: `${node.label}: ${mp.name}. ` +
            `The resource is allocated but its required initialization step is missing. ` +
            `Using an uninitialized resource can cause UB, security bypasses, or silent data corruption.`,
          fix: mp.fix,
          via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-909', name: 'Missing Initialization of Resource', holds: findings.length === 0, findings };
}

function verifyCWE910(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CLOSE_THEN_USE: Array<{ pattern: RegExp; name: string; fix: string; severity: 'high' | 'medium' }> = [
    { pattern: /\bclose\s*\(\s*(\w+)\s*\)[\s\S]{0,200}?\b(?:read|write|send|recv|ioctl|fcntl|fstat|lseek|select|poll|dup|mmap)\s*\(\s*\1\b/,
      name: 'POSIX fd used after close()',
      fix: 'Set fd = -1 after close(). The OS recycles fd numbers — a stale fd may operate on a different file/socket.',
      severity: 'high' },
    { pattern: /\bfclose\s*\(\s*(\w+)\s*\)[\s\S]{0,200}?\b(?:fread|fwrite|fprintf|fscanf|fgets|fputs|fseek|ftell|fflush)\s*\([^)]*\1\b/,
      name: 'FILE* used after fclose()',
      fix: 'Set fp = NULL after fclose(). Using a closed FILE* is undefined behavior.',
      severity: 'high' },
    { pattern: /\b(\w+)\s*\.\s*close\s*\(\s*\)[\s\S]{0,200}?\b\1\s*\.\s*(?:read|write|flush|available|skip|getChannel)\s*\(/,
      name: 'stream used after close()',
      fix: 'Use try-with-resources (Java) or using statement (C#). Set reference to null after close.',
      severity: 'medium' },
    { pattern: /\b(\w+)\s*\.\s*close\s*\(\s*\)[\s\S]{0,200}?\b\1\s*\.\s*(?:read|write|readline|readlines|seek|tell|flush|fileno)\s*\(/,
      name: 'Python file used after close()',
      fix: 'Use "with open(...) as f:" context manager to prevent use-after-close.',
      severity: 'medium' },
    { pattern: /\b(\w+)\s*\.\s*Close\s*\(\s*\)[\s\S]{0,200}?\b\1\s*\.\s*(?:Read|Write|SetDeadline|LocalAddr|RemoteAddr)\s*\(/,
      name: 'Go connection/file used after Close()',
      fix: 'Set variable to nil after Close(). Use defer only when the function is about to return.',
      severity: 'medium' },
    { pattern: /\b(?:closesocket|shutdown)\s*\(\s*(\w+)[\s\S]{0,200}?\b(?:send|recv|WSASend|WSARecv)\s*\(\s*\1\b/,
      name: 'Winsock handle used after closesocket()',
      fix: 'Set socket = INVALID_SOCKET after closesocket(). The OS may reassign the handle.',
      severity: 'high' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const p of CLOSE_THEN_USE) {
      if (p.pattern.test(code)) {
        if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `CONTROL (fd lifecycle — ${p.name})`,
          severity: p.severity,
          description: `${node.label}: ${p.name}. ` +
            `After close, the OS can reassign that descriptor to a new resource. ` +
            `Subsequent operations silently affect the wrong resource.`,
          fix: p.fix,
          via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-910', name: 'Use of Expired File Descriptor', holds: findings.length === 0, findings };
}

function verifyCWE911(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const REFCOUNT_PATTERNS: Array<{ pattern: RegExp; name: string; fix: string; severity: 'high' | 'medium' }> = [
    { pattern: /\b(\w+)\s*->\s*Release\s*\(\s*\)[\s\S]{0,200}?\b\1\s*->\s*Release\s*\(\s*\)/,
      name: 'COM double Release() without intervening AddRef()',
      fix: 'Each AddRef() must have exactly one matching Release(). Use CComPtr/ComPtr<T> smart pointers.',
      severity: 'high' },
    { pattern: /\bPy_DECREF\s*\(\s*(\w+)\s*\)[\s\S]{0,200}?\bPy_DECREF\s*\(\s*\1\s*\)/,
      name: 'CPython double Py_DECREF (use-after-free)',
      fix: 'Each Py_INCREF must pair with exactly one Py_DECREF. Set pointer to NULL after final DECREF.',
      severity: 'high' },
    { pattern: /\[\s*(\w+)\s+release\s*\][\s\S]{0,200}?\[\s*\1\s+release\s*\]/,
      name: 'Objective-C double release',
      fix: 'Enable ARC or ensure each retain pairs with exactly one release. Set to nil after release.',
      severity: 'high' },
    { pattern: /\bkref_put\s*\([^,]+,\s*NULL\s*\)/,
      name: 'Linux kernel kref_put with NULL destructor',
      fix: 'Provide a proper release function: kref_put(&obj->ref, my_release_func).',
      severity: 'high' },
    { pattern: /\b(?:ref_?count|refCount|nRef|m_ref)\s*(?:\+\+|--|\+=\s*1|\-=\s*1)(?!.*(?:lock|mutex|atomic|synchronized|critical_section|InterlockedIncrement|InterlockedDecrement|__sync_|std::atomic))/i,
      name: 'reference count modified without synchronization',
      fix: 'Use atomic operations (std::atomic, InterlockedIncrement) or hold a lock when modifying reference counts.',
      severity: 'high' },
    { pattern: /\bManuallyDrop\s*::\s*drop\s*\([^)]+\)[\s\S]{0,100}?\bManuallyDrop\s*::\s*drop\s*\(/,
      name: 'Rust double ManuallyDrop::drop (double-free)',
      fix: 'Use ManuallyDrop::take to extract the value exactly once.',
      severity: 'high' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const p of REFCOUNT_PATTERNS) {
      if (p.pattern.test(code)) {
        if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `CONTROL (reference count correctness — ${p.name})`,
          severity: p.severity,
          description: `${node.label}: ${p.name}. ` +
            `Incorrect reference counting leads to use-after-free (exploitable for code execution) or memory leaks.`,
          fix: p.fix,
          via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-911', name: 'Improper Update of Reference Count', holds: findings.length === 0, findings };
}

function verifyCWE912(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const HIDDEN_ENDPOINT_RE = /\b(?:app|router|server|express)\s*\.\s*(?:get|post|put|delete|all|use)\s*\(\s*['"`](?:\/(?:backdoor|debug|hidden|secret|admin[-_]?panel|master[-_]?key|god[-_]?mode|shadow|internal[-_]?api|_debug|__admin|\.secret|test[-_]?bypass))\b/i;
  const HARDCODED_BYPASS_RE = /\b(?:if|when|case)\s*\([^)]*(?:===?\s*['"`](?:master[-_]?key|backdoor|god[-_]?mode|super[-_]?admin|debug[-_]?mode|skeleton[-_]?key|override|bypass)['"`]|password\s*===?\s*['"`][^'"]{3,}['"`])\s*\)/i;
  const BACKDOOR_FUNC_RE = /\b(?:function|def|func|fn|sub|proc)\s+(?:backdoor|debugAccess|masterOverride|bypassAuth|secretAdmin|hiddenRoute|godMode|shadowAccess|internalBypass|debugLogin)\b/i;
  const EVAL_ENDPOINT_RE = /\b(?:req|request|ctx)\s*\.\s*(?:body|query|params)\s*(?:\.\w+|\[['"`]\w+['"`]\])\s*[\s\S]{0,50}?\b(?:eval|exec|Function\s*\(|vm\.runInContext|child_process|subprocess)\b/i;
  const SECRET_TOGGLE_RE = /\bprocess\.env\s*\.\s*(?:BACKDOOR|SECRET_ADMIN|DEBUG_AUTH|BYPASS_AUTH|GOD_MODE|MASTER_KEY)\b|os\.(?:environ|getenv)\s*(?:\[|\()\s*['"`](?:BACKDOOR|SECRET_ADMIN|DEBUG_AUTH|BYPASS_AUTH)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (HIDDEN_ENDPOINT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (no undocumented endpoints — hidden route detected)',
        severity: 'critical',
        description: `${node.label} defines a hidden/undocumented endpoint with a suspicious name. ` +
          `Hidden endpoints bypass normal access control and audit logging.`,
        fix: 'Remove the hidden endpoint or document it with proper auth, authorization, and audit logging.',
        via: 'structural',
      });
    }

    if (HARDCODED_BYPASS_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (no hardcoded bypass credentials)',
        severity: 'critical',
        description: `${node.label} contains a hardcoded bypass credential or magic value that grants elevated access.`,
        fix: 'Remove all hardcoded bypass values. Use a proper break-glass procedure with audit logging.',
        via: 'structural',
      });
    }

    if (BACKDOOR_FUNC_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (no backdoor functions)',
        severity: 'critical',
        description: `${node.label} defines a function with a name suggesting hidden/backdoor functionality.`,
        fix: 'Remove the backdoor function or rename it and add proper access controls.',
        via: 'structural',
      });
    }

    if (EVAL_ENDPOINT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (no remote code execution endpoints)',
        severity: 'critical',
        description: `${node.label} passes request input directly to eval/exec — functionally a webshell.`,
        fix: 'Remove the eval/exec endpoint. Use a sandboxed interpreter with allowlists if dynamic behavior is needed.',
        via: 'structural',
      });
    }

    if (SECRET_TOGGLE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (no secret environment toggles for auth bypass)',
        severity: 'high',
        description: `${node.label} reads a secret environment variable that toggles backdoor/bypass functionality.`,
        fix: 'Remove secret toggle variables. Use proper feature flags with access controls and audit logging.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-912', name: 'Hidden Functionality', holds: findings.length === 0, findings };
}

/**
 * CWE-581: Object Model Violation: Just One of Equals and Hashcode Defined
 * When a class overrides equals() but not hashCode() (or vice versa), objects
 * that are "equal" can hash to different buckets — breaking HashMap/HashSet
 * contracts. In security contexts, this causes identity/session lookup failures,
 * authorization bypasses (two "equal" users map to different permission sets),
 * and cache poisoning.
 */
function verifyCWE581(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Java: equals without hashCode or vice versa
  const HAS_EQUALS_JAVA = /\bpublic\s+boolean\s+equals\s*\(\s*Object\b/;
  const HAS_HASHCODE_JAVA = /\bpublic\s+int\s+hashCode\s*\(\s*\)/;

  // C#: Equals without GetHashCode or vice versa
  const HAS_EQUALS_CSHARP = /\boverride\s+bool\s+Equals\s*\(/;
  const HAS_GETHASHCODE_CSHARP = /\boverride\s+int\s+GetHashCode\s*\(\s*\)/;

  // Python: __eq__ without __hash__ or vice versa
  const HAS_EQ_PYTHON = /\bdef\s+__eq__\s*\(\s*self/;
  const HAS_HASH_PYTHON = /\bdef\s+__hash__\s*\(\s*self/;

  // Kotlin: equals without hashCode
  const HAS_EQUALS_KOTLIN = /\boverride\s+fun\s+equals\s*\(/;
  const HAS_HASHCODE_KOTLIN = /\boverride\s+fun\s+hashCode\s*\(\s*\)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let hasEquals = false;
    let hasHashCode = false;
    let lang = '';

    if (HAS_EQUALS_JAVA.test(code) || HAS_HASHCODE_JAVA.test(code)) {
      hasEquals = HAS_EQUALS_JAVA.test(code);
      hasHashCode = HAS_HASHCODE_JAVA.test(code);
      lang = 'Java';
    } else if (HAS_EQUALS_CSHARP.test(code) || HAS_GETHASHCODE_CSHARP.test(code)) {
      hasEquals = HAS_EQUALS_CSHARP.test(code);
      hasHashCode = HAS_GETHASHCODE_CSHARP.test(code);
      lang = 'C#';
    } else if (HAS_EQ_PYTHON.test(code) || HAS_HASH_PYTHON.test(code)) {
      hasEquals = HAS_EQ_PYTHON.test(code);
      hasHashCode = HAS_HASH_PYTHON.test(code);
      lang = 'Python';
    } else if (HAS_EQUALS_KOTLIN.test(code) || HAS_HASHCODE_KOTLIN.test(code)) {
      hasEquals = HAS_EQUALS_KOTLIN.test(code);
      hasHashCode = HAS_HASHCODE_KOTLIN.test(code);
      lang = 'Kotlin';
    }

    if (hasEquals && !hasHashCode) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (hashCode/GetHashCode/__hash__ override)',
        severity: 'medium',
        description: `${node.label} overrides equals() but not hashCode() (${lang}). Objects that are ` +
          `"equal" can hash to different buckets, breaking HashMap/HashSet contracts. In auth contexts, ` +
          `this can cause session lookup failures or authorization bypass.`,
        fix: `Override hashCode() consistently with equals(). In ${lang}, ensure that ` +
          `a.equals(b) implies a.hashCode() == b.hashCode(). Use Objects.hash() (Java), ` +
          `HashCode.Combine() (C#), or tuple hashing (Python).`,
          via: 'structural',
      });
    } else if (!hasEquals && hasHashCode) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (equals/Equals/__eq__ override)',
        severity: 'medium',
        description: `${node.label} overrides hashCode() but not equals() (${lang}). Two objects with ` +
          `the same hash may not compare equal, causing phantom duplicates in hash-based collections. ` +
          `Identity checks become inconsistent.`,
        fix: `Override equals() consistently with hashCode(). The contract requires that ` +
          `equal objects have equal hash codes, but also that the equality check is meaningful.`,
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-581', name: 'Object Model Violation: Just One of Equals and Hashcode Defined', holds: findings.length === 0, findings };
}

/**
 * CWE-584: Return Inside Finally Block
 * A return statement in a finally block silently swallows any exception from
 * the try block and overrides any return value from try/catch. This hides
 * security-critical errors (failed auth, failed validation) and makes the
 * function appear to succeed when it should have failed.
 */
function verifyCWE584(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Java/C#/JS/TS: return inside finally
  const FINALLY_RETURN = /\bfinally\s*\{[^}]*\breturn\b/;
  // More thorough: multi-line finally with return
  const FINALLY_BLOCK_RETURN = /\bfinally\s*\{[\s\S]{0,500}?\breturn\s/;
  // Python: return inside finally
  const PYTHON_FINALLY_RETURN = /\bfinally\s*:[\s\S]{0,300}?\breturn\s/;

  // Safe: return in a nested function/lambda inside finally (not the finally's return)
  const NESTED_FN = /\bfinally\s*\{[\s\S]*?(?:function\s*\(|=>\s*\{|lambda\s)[\s\S]*?\breturn\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    const hasReturn = FINALLY_RETURN.test(code) || FINALLY_BLOCK_RETURN.test(code) || PYTHON_FINALLY_RETURN.test(code);
    const isNested = NESTED_FN.test(code);

    if (hasReturn && !isNested) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (no return/throw in finally blocks)',
        severity: 'high',
        description: `${node.label} has a return statement inside a finally block. This silently ` +
          `swallows any exception thrown in the try/catch block and overrides the try block's return ` +
          `value. If the try block throws a security exception (auth failure, validation error), ` +
          `the finally return hides it — the caller sees success.`,
        fix: 'Remove the return from the finally block. Use a variable to store the return value ' +
          'in try/catch, then return it after the finally block. The finally block should only ' +
          'perform cleanup (close resources, release locks).',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-584', name: 'Return Inside Finally Block', holds: findings.length === 0, findings };
}

/**
 * CWE-588: Attempt to Access Child of a Non-existent Index Entry
 * Accessing a nested property/index without checking the parent exists.
 * Classic pattern: array[i].field without bounds check, or map.get(key).method()
 * without null check. This causes null pointer dereferences or undefined behavior
 * that can crash services (DoS) or skip security checks.
 */
function verifyCWE588(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const mapLang = inferMapLanguage(map);

  // Library code accesses deeply nested properties on known internal structures — not external data
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-588', name: 'Attempt to Access Child of Non-existent Index Entry', holds: true, findings };
  }

  // C/C++: array[expr].member without bounds check
  const C_NESTED_ACCESS = /\w+\s*\[[^\]]+\]\s*\.\s*\w+/;
  const C_BOUNDS_CHECK = /\bif\s*\([^)]*(?:>=?\s*0|<\s*\w+|!=\s*NULL|!=\s*nullptr)\b/;

  // Java: .get(key).method() without null check
  const JAVA_CHAINED_GET = /\.get\s*\([^)]*\)\s*\.\s*\w+/;
  const JAVA_NULL_CHECK = /\bif\s*\([^)]*!=\s*null\b|Optional\.|\.orElse\(|\.ifPresent\(/;

  // JS/TS: deeply nested property access without optional chaining or guard
  const JS_DEEP_ACCESS = /\w+(?:\[[^\]]+\]|\.\w+){3,}/;
  const JS_OPTIONAL_CHAIN = /\?\./;
  const JS_GUARD = /\bif\s*\([^)]*(?:!=\s*(?:null|undefined)|typeof\s+\w+\s*!==?\s*['"]undefined['"])\b/;

  // Python: dict[key][nested] without .get() or try/except
  const PY_NESTED_DICT = /\w+\[[^\]]+\]\s*\[[^\]]+\]/;
  const PY_SAFE = /\.get\s*\(|try\s*:|KeyError|IndexError/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let matched = false;
    let detail = '';

    if (C_NESTED_ACCESS.test(code) && !C_BOUNDS_CHECK.test(code) &&
        /\b(?:int|char|struct|float|double|void)\b/.test(code)) {
      matched = true;
      detail = 'accesses member of array element without bounds checking the index';
    } else if (JAVA_CHAINED_GET.test(code) && !JAVA_NULL_CHECK.test(code) &&
               /\b(?:Map|HashMap|List|ArrayList|get)\b/.test(code)) {
      matched = true;
      detail = 'chains method call on .get() result without null check — NPE if key missing';
    } else if (JS_DEEP_ACCESS.test(code) && !JS_OPTIONAL_CHAIN.test(code) && !JS_GUARD.test(code) &&
               /\b(?:req\.|params|query|body|config|data|response|result)\b/.test(code) &&
               // Only flag for JS/TS/Python — Java method chaining is normal, not a CWE-588 pattern
               (['javascript', 'typescript', 'python', ''].some(l => mapLang === l))) {
      matched = true;
      detail = 'deeply nested property access on external data without optional chaining or null guard';
    } else if (PY_NESTED_DICT.test(code) && !PY_SAFE.test(code)) {
      matched = true;
      detail = 'nested dict/list indexing without .get() or try/except — KeyError/IndexError if missing';
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (existence check before nested access)',
        severity: 'medium',
        description: `${node.label} ${detail}. If the parent entry does not exist, ` +
          `this causes a null dereference, TypeError, or undefined behavior. In request handlers, ` +
          `this is a crash vector (DoS). In auth paths, it can skip security checks entirely.`,
        fix: 'Check parent existence before accessing children. Use optional chaining (?.) in JS/TS, ' +
          'Optional.map() in Java, .get() with default in Python, or explicit bounds/null checks in C.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-588', name: 'Attempt to Access Child of Non-existent Index Entry', holds: findings.length === 0, findings };
}

/**
 * CWE-589: Call to Non-ubiquitous API
 * Using platform-specific APIs that are not available across all deployment
 * targets. This causes runtime failures in production when code runs on a
 * different OS/platform than development. Security impact: features that
 * "work in dev" silently fail in production, including security controls.
 */
function verifyCWE589(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Windows-only APIs used in presumably cross-platform code
  const WIN_ONLY_API = /\b(?:GetWindowsDirectory|RegOpenKey|RegQueryValue|CreateFile[AW]|WinExec|ShellExecute[AW]|MessageBox[AW]|FindFirstFile[AW]|GetModuleHandle|LoadLibrary[AW]|HKEY_\w+|HANDLE\s+\w+\s*=\s*CreateFile)\b/;

  // Unix-only APIs that fail on Windows
  const UNIX_ONLY_API = /\b(?:fork\s*\(|execvp?\s*\(|setuid\s*\(|setgid\s*\(|chroot\s*\(|syslog\s*\(|getpwnam\s*\(|getgrnam\s*\(|fchmod\s*\(|mmap\s*\((?!.*MAP_ANON))\b/;

  // Deprecated/removed APIs across versions
  const DEPRECATED_API = /\b(?:gets\s*\(|sprintf\s*\((?!.*snprintf)|tmpnam\s*\(|mktemp\s*\(|asctime\s*\(|ctime\s*\(|rand\s*\()\b/;

  // Python: platform-specific modules
  const PY_PLATFORM = /\b(?:import\s+(?:winreg|_winapi|msvcrt|posix|fcntl|termios|grp|pwd))\b/;

  // Node.js: Windows vs Unix differences
  const NODE_PLATFORM = /\b(?:child_process\.exec(?:Sync)?\s*\([^)]*(?:cmd\.exe|powershell|\/bin\/sh))\b/;

  // Safe: platform checks guard the call
  const PLATFORM_GUARD = /\b(?:process\.platform|os\.platform|sys\.platform|os\.name|RuntimeInformation|Platform\.OS|navigator\.platform|Environment\.OSVersion)\b/;
  const IFDEF_GUARD = /\b(?:#ifdef\s+(?:_WIN32|__linux__|__APPLE__)|#if\s+defined\s*\((?:_WIN32|__linux__))\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    const hasPlatformGuard = PLATFORM_GUARD.test(code) || IFDEF_GUARD.test(code);
    if (hasPlatformGuard) continue;

    let matched = false;
    let detail = '';

    if (WIN_ONLY_API.test(code)) {
      matched = true;
      detail = 'uses Windows-only API without platform guard — fails on Linux/macOS deployments';
    } else if (UNIX_ONLY_API.test(code) && !/\b_WIN32\b/.test(code)) {
      matched = true;
      detail = 'uses Unix-only API without platform guard — fails on Windows deployments';
    } else if (DEPRECATED_API.test(code) && !/(snprintf|fgets|mkstemp|tmpfile)/.test(code)) {
      matched = true;
      detail = 'uses deprecated/removed C API that may not exist on all platforms or compiler versions';
    } else if (PY_PLATFORM.test(code)) {
      matched = true;
      detail = 'imports platform-specific Python module without platform check';
    } else if (NODE_PLATFORM.test(code)) {
      matched = true;
      detail = 'hardcodes platform-specific shell path in child_process call';
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (platform detection guard before platform-specific API)',
        severity: 'low',
        description: `${node.label} ${detail}. Code that works in development may fail silently ` +
          `or crash in production on a different platform. If security controls depend on this code, ` +
          `they are silently disabled on unsupported platforms.`,
        fix: 'Guard platform-specific calls with runtime platform detection (process.platform, ' +
          'sys.platform, #ifdef _WIN32, etc.) or use cross-platform abstractions.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-589', name: 'Call to Non-ubiquitous API', holds: findings.length === 0, findings };
}

/**
 * CWE-590: Free of Memory not on the Heap
 * Calling free()/delete on stack-allocated memory, global/static memory, or
 * already-freed memory. This corrupts the heap allocator metadata and leads
 * to arbitrary code execution via heap exploitation.
 */
function verifyCWE590(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // free() or delete on address-of local variable: free(&localVar)
  const FREE_ADDR_OF = /\bfree\s*\(\s*&\s*\w+\s*\)/;
  // delete on stack variable
  const DELETE_STACK = /\bdelete\s+(?:&\s*)?\w+\s*;/;

  // free() on a string literal or static buffer
  const FREE_LITERAL = /\bfree\s*\(\s*(?:"[^"]*"|'[^']*')\s*\)/;

  // free() inside a function where the variable was declared as local array
  const LOCAL_ARRAY_FREE = /\b(?:char|int|float|double|unsigned|long|short)\s+(\w+)\s*\[[\w\s]*\]\s*;[\s\S]{0,500}?\bfree\s*\(\s*\1\s*\)/;

  // free() on a static variable
  const STATIC_FREE = /\bstatic\s+\w+\s*\*?\s*(\w+)[\s\S]{0,500}?\bfree\s*\(\s*\1\s*\)/;

  // Safe: variable was obtained from malloc/calloc/realloc/strdup
  const HEAP_ALLOC = /\b(?:malloc|calloc|realloc|strdup|strndup|new\s+\w+|new\s*\[)\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let matched = false;
    let detail = '';

    if (FREE_ADDR_OF.test(code)) {
      matched = true;
      detail = 'calls free() on address of a local (stack) variable';
    } else if (FREE_LITERAL.test(code)) {
      matched = true;
      detail = 'calls free() on a string literal (read-only data segment)';
    } else if (LOCAL_ARRAY_FREE.test(code)) {
      matched = true;
      detail = 'calls free() on a stack-allocated array';
    } else if (STATIC_FREE.test(code) && !HEAP_ALLOC.test(code)) {
      matched = true;
      detail = 'calls free() on a static variable (not heap-allocated)';
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (only free heap-allocated memory)',
        severity: 'critical',
        description: `${node.label} ${detail}. Freeing non-heap memory corrupts the heap allocator's ` +
          `internal metadata. An attacker can exploit this to achieve arbitrary write (heap ` +
          `corruption → controlled allocation → code execution).`,
        fix: 'Only call free()/delete on pointers returned by malloc()/calloc()/realloc()/new. ' +
          'Never free stack variables, string literals, or static data. ' +
          'Use AddressSanitizer (-fsanitize=address) to detect at runtime.',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-590', name: 'Free of Memory not on the Heap', holds: findings.length === 0, findings };
}

/**
 * CWE-591: Sensitive Data Storage in Improperly Locked Memory
 * Sensitive data (keys, passwords, tokens) stored in memory that can be
 * swapped to disk. When memory pages are swapped out, secrets end up in
 * the swap file/partition where they persist after the process exits.
 * Proper handling: mlock()/VirtualLock() to pin pages, or secure memory
 * allocators like sodium_malloc().
 */
function verifyCWE591(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns indicating sensitive data in memory
  const SENSITIVE_VAR = /\b(?:password|secret|private[_]?key|priv[_]?key|master[_]?key|encryption[_]?key|api[_]?key|token|credential|passphrase|signing[_]?key|session[_]?key)\b/i;

  // C/C++: sensitive buffer without mlock
  const C_BUFFER = /\b(?:char|unsigned\s+char|uint8_t|BYTE)\s+\*?\s*\w*(?:password|secret|key|token|cred)\w*\s*(?:\[[\w\s]*\]|\s*=\s*(?:malloc|calloc|new))/i;

  // Safe: memory locking APIs
  const MLOCK_SAFE = /\b(?:mlock|mlockall|VirtualLock|sodium_malloc|sodium_mlock|SecureString|OPENSSL_secure_malloc|OPENSSL_cleanse|SecureZeroMemory|explicit_bzero|memset_s)\b/;

  // Safe: secure memory wrappers
  const SECURE_WRAPPER = /\b(?:SecureString|ProtectedData|CryptProtectMemory|SecureBuffer|sodium_memzero|OPENSSL_secure_free)\b/;

  // Rust: sensitive data without zeroize
  const RUST_SENSITIVE = /\b(?:let\s+(?:mut\s+)?(?:password|secret|key|token)\s*(?::\s*(?:Vec<u8>|String|\[u8))?)/;
  const RUST_SAFE = /\b(?:zeroize|secrecy::Secret|Zeroizing)\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|example|demo)\b/i.test(node.label)) continue;

    const hasSensitiveData = SENSITIVE_VAR.test(code);
    if (!hasSensitiveData) continue;

    const hasMemoryLock = MLOCK_SAFE.test(code) || SECURE_WRAPPER.test(code) || RUST_SAFE.test(code);
    if (hasMemoryLock) continue;

    let matched = false;
    let detail = '';

    if (C_BUFFER.test(code)) {
      matched = true;
      detail = 'stores sensitive data in unlocked memory buffer — can be swapped to disk';
    } else if (RUST_SENSITIVE.test(code) && !RUST_SAFE.test(code)) {
      matched = true;
      detail = 'stores sensitive data without zeroize/secrecy — remains in memory after drop';
    } else if (/\b(?:private_key|secret_key|password|master_key)\s*=\s*(?:new\s+(?:byte|char)|Buffer\.(?:from|alloc))/i.test(code)) {
      matched = true;
      detail = 'stores cryptographic material in standard (swappable) memory';
    }

    if (matched) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (memory locking for sensitive data)',
        severity: 'high',
        description: `${node.label} ${detail}. The OS can swap these memory pages to disk, where ` +
          `secrets persist in the swap file after the process exits. Core dumps also capture ` +
          `unlocked pages. An attacker with disk access recovers secrets from swap/core.`,
        fix: 'Use mlock()/VirtualLock() to pin sensitive pages in RAM. Use sodium_malloc() for ' +
          'guard-paged, locked allocations. In Rust, use secrecy::Secret<T> with Zeroize. ' +
          'In .NET, use SecureString. Always zero memory before freeing (explicit_bzero, ' +
          'SecureZeroMemory, sodium_memzero).',
          via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-591', name: 'Sensitive Data Storage in Improperly Locked Memory', holds: findings.length === 0, findings };
}

/**
 * CWE-605: Multiple Binds to the Same Port
 * Pattern: Server code that binds/listens on a port without checking if it's already
 * in use, or multiple listen() calls on the same port. This can cause race conditions,
 * service denial, or port hijacking where an attacker binds first.
 */
function verifyCWE605(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code defines server/listen primitives — not actually binding ports
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-605', name: 'Multiple Binds to Same Port', holds: true, findings };
  }

  const LISTEN_RE = /\b(\.listen\s*\(|\.bind\s*\(|createServer|net\.createServer|http\.createServer|https\.createServer|express\(\)|app\.listen|server\.listen|socket\.bind|dgram\.createSocket|new\s+Server|ServerSocket|socket\.listen|SOCK_STREAM|SO_REUSEADDR|SO_REUSEPORT|bind\s*\(\s*['"]?(?:0\.0\.0\.0|localhost|127\.0\.0\.1|::))\b/i;
  const PORT_RE = /\b(?:port|PORT|listen)\s*[:=(\s]\s*(\d{2,5})\b/;
  const SAFE_RE = /\b(SO_EXCLUSIVEADDRUSE|exclusive\s*:\s*true|address\s*already\s*in\s*use|EADDRINUSE|port.?in.?use|isPortAvailable|checkPort|portfinder|detect-port|get-port|getPort|find.?free.?port|freeport|cluster\.fork|cluster\.isMaster|cluster\.isPrimary|process\.env\.PORT|\.on\s*\(\s*['"]error['"])\b/i;

  // Collect all nodes that listen/bind on ports
  const listenNodes: Array<{ node: NeuralMapNode; port: string }> = [];
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (LISTEN_RE.test(code)) {
      const portMatch = PORT_RE.exec(code);
      const port = portMatch ? portMatch[1] : 'unknown';
      listenNodes.push({ node, port });
    }
  }

  // Check 1: Multiple binds to the same port
  const portMap = new Map<string, NeuralMapNode[]>();
  for (const { node, port } of listenNodes) {
    if (port !== 'unknown') {
      const arr = portMap.get(port) ?? [];
      arr.push(node);
      portMap.set(port, arr);
    }
  }
  for (const [port, nodes] of portMap) {
    if (nodes.length > 1) {
      findings.push({
        source: nodeRef(nodes[0]),
        sink: nodeRef(nodes[1]),
        missing: 'CONTROL (single bind per port — avoid duplicate listeners)',
        severity: 'medium',
        description: `Multiple bind/listen calls on port ${port}: ${nodes[0].label} and ${nodes[1].label}. ` +
          'Duplicate port binds cause EADDRINUSE errors or race conditions where an attacker can bind first.',
        fix: 'Ensure only one process/server binds to each port. Use cluster module for multi-process, or use SO_EXCLUSIVEADDRUSE to prevent port hijacking.',
        via: 'structural',
      });
    }
  }

  // Check 2: Listen without error handling for EADDRINUSE
  for (const { node } of listenNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!SAFE_RE.test(code)) {
      // Check if there's an error handler nearby in the same scope
      const nearbyNodes = map.nodes.filter(n =>
        Math.abs(n.line_start - node.line_start) < 15 &&
        SAFE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
      );
      if (nearbyNodes.length === 0) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (port-in-use error handling)',
          severity: 'low',
          description: `Server at ${node.label} binds to a port without checking availability or handling EADDRINUSE. ` +
            'An attacker could bind to the port first, intercepting traffic (port hijacking).',
          fix: 'Handle EADDRINUSE errors. Use exclusive address binding (SO_EXCLUSIVEADDRUSE on Windows, ' +
            'exclusive: true in Node.js). Check port availability before binding.',
            via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-605', name: 'Multiple Binds to the Same Port', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Registry export
// ---------------------------------------------------------------------------

export const CODE_QUALITY_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-456': verifyCWE456,
  'CWE-457': verifyCWE457,
  'CWE-467': verifyCWE467,
  'CWE-468': verifyCWE468,
  'CWE-469': verifyCWE469,
  'CWE-478': verifyCWE478,
  'CWE-480': verifyCWE480,
  'CWE-481': verifyCWE481,
  'CWE-482': verifyCWE482,
  'CWE-483': verifyCWE483,
  'CWE-484': verifyCWE484,
  'CWE-486': verifyCWE486,
  'CWE-489': verifyCWE489,
  'CWE-491': verifyCWE491,
  'CWE-495': verifyCWE495,
  'CWE-496': verifyCWE496,
  'CWE-499': verifyCWE499,
  'CWE-500': verifyCWE500,
  'CWE-561': verifyCWE561,
  'CWE-562': verifyCWE562,
  'CWE-563': verifyCWE563,
  'CWE-570': verifyCWE570,
  'CWE-571': verifyCWE571,
  'CWE-572': verifyCWE572,
  'CWE-581': verifyCWE581,
  'CWE-582': verifyCWE582,
  'CWE-583': verifyCWE583,
  'CWE-584': verifyCWE584,
  'CWE-585': verifyCWE585,
  'CWE-586': verifyCWE586,
  'CWE-587': verifyCWE587,
  'CWE-588': verifyCWE588,
  'CWE-589': verifyCWE589,
  'CWE-590': verifyCWE590,
  'CWE-591': verifyCWE591,
  'CWE-595': verifyCWE595,
  'CWE-597': verifyCWE597,
  'CWE-605': verifyCWE605,
  'CWE-607': verifyCWE607,
  'CWE-609': verifyCWE609,
  'CWE-619': verifyCWE619,
  'CWE-625': verifyCWE625,
  'CWE-688': verifyCWE688,
  'CWE-689': verifyCWE689,
  'CWE-698': verifyCWE698,
  'CWE-704': verifyCWE704,
  'CWE-706': verifyCWE706,
  'CWE-732': verifyCWE732,
  'CWE-749': verifyCWE749,
  'CWE-754': verifyCWE754,
  'CWE-755': verifyCWE755,
  'CWE-756': verifyCWE756,
  'CWE-778': verifyCWE778,
  'CWE-779': verifyCWE779,
  'CWE-804': verifyCWE804,
  'CWE-806': verifyCWE806,
  'CWE-807': verifyCWE807,
  'CWE-829': verifyCWE829,
  'CWE-835': verifyCWE835,
  'CWE-908': verifyCWE908,
  'CWE-909': verifyCWE909,
  'CWE-910': verifyCWE910,
  'CWE-911': verifyCWE911,
  'CWE-912': verifyCWE912,
};
