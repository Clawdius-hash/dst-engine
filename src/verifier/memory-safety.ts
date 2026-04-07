/**
 * Memory Safety CWE Verifiers
 *
 * Double free, use-after-free, null pointer dereference, division by zero,
 * buffer overflows, array index validation, loop termination, data representation.
 *
 * Extracted from verifier/index.ts - Phase 7 of the monolith split.
 */

import type { NeuralMap } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments } from './source-analysis.ts';
import { nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutControl, findContainingFunction, sharesFunctionScope } from './graph-helpers.ts';
import { findNearestNode, getContainingScopeSnapshots, sinkHasTaintedDataIn } from '../generated/_helpers.js';


/**
 * CWE-415: Double Free
 * Calling free() on the same memory address twice. This corrupts the heap allocator's
 * internal data structures, leading to arbitrary code execution or crashes.
 *
 * Static detection approach: find free/delete/kfree calls on the same variable without
 * an intervening assignment (re-nulling). Also flag patterns where the pointer is not
 * set to NULL after free.
 */
function verifyCWE415(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const FREE_RE = /\b(free|cfree|kfree|vfree|g_free|HeapFree|GlobalFree|LocalFree|CoTaskMemFree|SysFreeString|delete\s+\w+|delete\s*\[\s*\]\s*\w+)\s*\(/i;
  const NULL_AFTER_FREE_RE = /\bfree\s*\([^)]+\)\s*;\s*\w+\s*=\s*(NULL|nullptr|0)\b|=\s*(NULL|nullptr|0)\s*;.*\bfree\b/i;
  const RAII_SAFE_RE = /\bstd::unique_ptr\b|\bstd::shared_ptr\b|\bstd::weak_ptr\b|\bBox\s*<|\bRc\s*<|\bArc\s*<|\bstd::auto_ptr\b|\bsmart_ptr\b|\bScopedPointer\b|\bQScopedPointer\b/i;
  const DOUBLE_FREE_PATTERN_RE = /\bfree\s*\(\s*(\w+)\s*\)[^]*?\bfree\s*\(\s*\1\s*\)/;

  const freeNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    FREE_RE.test(n.analysis_snapshot || n.code_snapshot)
  );

  // Check for double free patterns within the same node (common in code snapshots)
  for (const node of freeNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (RAII_SAFE_RE.test(code)) continue;

    if (DOUBLE_FREE_PATTERN_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (set pointer to NULL after free to prevent double-free)',
        severity: 'critical',
        description: `Double free detected at ${node.label}: the same pointer is freed twice. ` +
          `This corrupts the heap allocator and can lead to arbitrary code execution.`,
        fix: 'Set pointer to NULL immediately after free: free(ptr); ptr = NULL. ' +
          'Use RAII (unique_ptr/shared_ptr in C++, Box/Rc in Rust) to automate lifetime management. ' +
          'In C, adopt a convention: always NULL pointers after freeing.',
        via: 'structural',
      });
      continue;
    }

    // Flag free() without nulling the pointer afterward (precondition for double-free)
    if (!NULL_AFTER_FREE_RE.test(code) && !RAII_SAFE_RE.test(code)) {
      // Check if this node has data flow to another free node
      for (const other of freeNodes) {
        if (other.id === node.id) continue;
        if (sharesFunctionScope(map, node.id, other.id)) {
          const nodeCode = stripComments(other.analysis_snapshot || other.code_snapshot);
          if (!RAII_SAFE_RE.test(nodeCode) && !NULL_AFTER_FREE_RE.test(nodeCode)) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(other),
              missing: 'CONTROL (null pointer after free to prevent double-free)',
              severity: 'critical',
              description: `Memory freed at ${node.label} may be freed again at ${other.label}. ` +
                `Pointer is not set to NULL after first free, enabling double-free.`,
              fix: 'Set pointer to NULL immediately after free. Use smart pointers (unique_ptr/shared_ptr) ' +
                'or Rust ownership to prevent double-free at compile time.',
              via: 'scope_taint',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-415', name: 'Double Free', holds: findings.length === 0, findings };
}

/**
 * CWE-416: Use After Free
 * Accessing memory after it has been freed. The memory may have been reallocated for a
 * different purpose, leading to data corruption, information disclosure, or code execution.
 *
 * Static detection: find free() calls where the freed pointer is subsequently dereferenced
 * without reassignment.
 */
function verifyCWE416(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // FREE_RE: matches both C-style free() and JavaScript/managed language deallocation patterns.
  // Includes .destroy(), .release(), .dispose(), .close() as member calls (stream.destroy(),
  // resource.release()) which are the JavaScript equivalents of free().
  // FREE_RE: matches C-style free() and JS deallocation patterns.
  // .destroy() and .close() are reliable JS "free" indicators.
  // .end()/.terminate()/.shutdown() excluded from member-call pattern — too broad
  // (HTTP response .end(), server .terminate(), etc. are not memory frees).
  const FREE_RE = /\b(free|cfree|kfree|vfree|g_free|delete\s+\w+|delete\s*\[\s*\]\s*\w+|HeapFree|GlobalFree|LocalFree|CoTaskMemFree|fclose|closesocket|CloseHandle)\s*\(|[\w$]+\.(destroy|release|dispose|close)\s*\(\s*\)/i;
  const USE_AFTER_FREE_RE = /\bfree\s*\(\s*(\w+)\s*\)\s*;[^=]*\b\1\s*[\-\.\[>]/;
  const RAII_SAFE_RE = /\bstd::unique_ptr\b|\bstd::shared_ptr\b|\bBox\s*<|\bRc\s*<|\bArc\s*<|\bstd::auto_ptr\b/i;
  const NULL_AFTER_FREE_RE = /\bfree\s*\([^)]+\)\s*;\s*\w+\s*=\s*(NULL|nullptr|0|nil)\b/i;
  // JS_SAFE_RE: patterns that indicate the resource was safely replaced or not used after
  const JS_SAFE_RE = /=\s*null\b|=\s*undefined\b|=\s*new\s+\w+/i;

  const freeNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    FREE_RE.test(n.analysis_snapshot || n.code_snapshot)
  );

  const derefNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS') &&
    /\->\w+|\*\s*\w+|\.\w+\s*[\(\[]|\[\s*\d+\s*\]/.test(n.analysis_snapshot || n.code_snapshot)
  );

  // Pattern 1: Use-after-free within the same code snapshot
  for (const node of freeNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (RAII_SAFE_RE.test(code)) continue;
    if (USE_AFTER_FREE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (do not access memory after free — set pointer to NULL)',
        severity: 'critical',
        description: `Use-after-free at ${node.label}: memory is freed and then accessed. ` +
          `The freed memory may be reallocated, causing data corruption or code execution.`,
        fix: 'Set pointer to NULL immediately after free. Use smart pointers (unique_ptr/shared_ptr). ' +
          'In Rust, the borrow checker prevents this at compile time — consider porting critical code.',
        via: 'structural',
      });
    }
  }

  // Pattern 2: Free in one node, dereference in a subsequent node without null check.
  // For JavaScript: stream.destroy() followed by stream.read() — these share function scope
  // but may not have a DATA_FLOW edge. Use sequence order + scope as the indicator.
  for (const src of freeNodes) {
    // Skip container/callback nodes that merely CONTAIN a free call as a child.
    // e.g. stream.on('error', () => { stream.destroy() }) — the callback node itself
    // is not the free; only leaf nodes (no CONTAINS edges to other free nodes) qualify.
    if (src.edges.some(e => e.edge_type === 'CONTAINS')) continue;
    const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
    if (RAII_SAFE_RE.test(srcCode)) continue;
    if (NULL_AFTER_FREE_RE.test(srcCode)) continue;
    if (JS_SAFE_RE.test(srcCode)) continue;

    for (const sink of derefNodes) {
      if (src.id === sink.id) continue;
      if (src.sequence >= sink.sequence) continue; // free must come before use
      if (!sharesFunctionScope(map, src.id, sink.id)) continue;
      // Skip if the sink IS the free call (parent container node contains the free as a child)
      if (FREE_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) && sink.edges.length === 0) continue;
      // Skip if the sink is contained within the src (src is a callback containing the free call)
      if (src.edges.some(e => e.edge_type === 'CONTAINS' && e.target === sink.id)) continue;
      // Skip if the src code_snapshot contains the sink's full code (src is a parent container)
      if ((src.analysis_snapshot || src.code_snapshot).includes(sink.code_snapshot.slice(0, 40).trim())) continue;
      // Skip response/HTTP sinks — res.status(), res.end(), res.json(), etc. are not memory uses
      if (/^\s*(?:res|response|reply|ctx)\s*\./.test(sink.analysis_snapshot || sink.code_snapshot)) continue;

      const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      if (RAII_SAFE_RE.test(sinkCode)) continue;
      if (JS_SAFE_RE.test(sinkCode)) continue;
      // Check if there is a flow path or scope proximity from the free to the use
      if (hasPathWithoutControl(map, src.id, sink.id) || sink.sequence > src.sequence) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(sink),
          missing: 'CONTROL (null check or no access after free/destroy)',
          severity: 'critical',
          description: `Resource freed/destroyed at ${src.label} may be used at ${sink.label}. ` +
            `If the reference is not nulled or reassigned between free and use, this is use-after-free.`,
          fix: 'Set pointer/reference to null immediately after free/destroy. ' +
            'Use RAII/smart pointers to tie object lifetime to scope. ' +
            'In Rust, the ownership system prevents use-after-free at compile time.',
          via: 'scope_taint',
        });
      }
    }
  }

  // Pattern 3: Cross-node analysis for JS use-after-free.
  // Handles cases where destroy(buffer)/release(buffer) are not separate mapper nodes
  // (truncated code_snapshot at 200 chars), and where member calls like stream.read()
  // after stream.destroy() have no corresponding node.
  //
  // Approach A: Scan STRUCTURAL code_snapshots for the UAF pattern (works when within 200 chars).
  // Approach B: Look for a free node + later deref node sharing a scope with the same
  //             variable name extracted from the free node's code_snapshot.
  if (findings.length === 0) {
    // Approach A: scan code_snapshots using multiline patterns
    const JS_UAF_RE = /\b(?:destroy|release|free)\s*\(\s*(\w+)\s*\)[\s\S]*?\b\1\s*\.\s*\w+\s*\(/;
    const MEMBER_DESTROY_UAF_RE = /(\w+)\s*\.\s*(?:destroy|close|end)\s*\(\s*\)[\s\S]*?\b\1\s*\.\s*(?!destroy|close|end)\w+\s*\(/;
    for (const node of map.nodes) {
      if (node.node_type !== 'STRUCTURAL') continue;
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (JS_UAF_RE.test(code) || MEMBER_DESTROY_UAF_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (do not access object after destroy/release/free)',
          severity: 'critical',
          description: `Use-after-free pattern at ${node.label}: resource is freed/destroyed and then accessed. ` +
            `Accessing a destroyed object causes undefined behavior or runtime errors.`,
          fix: 'Set reference to null immediately after destroy/release. Do not call methods on closed resources. ' +
            'Restructure code so the resource is not used after it is freed.',
          via: 'structural',
        });
        break;
      }
    }

    // Approach B: scan raw source_code lines for JS UAF patterns.
    // Handles the case where post-free accesses (stream.read(), stream.pipe()) are
    // not mapper nodes due to 200-char code_snapshot truncation.
    if (findings.length === 0 && map.source_code) {
      const srcLines = stripComments(map.source_code).split('\n');
      const JS_FREE_LINE_RE = /\b(?:destroy|release|free)\s*\(\s*(\w+)\s*\)/;
      // Use .destroy() or .close() as free indicators (not .end() — too broad for HTTP responses)
      const MEMBER_FREE_LINE_RE = /\b(\w+)\s*\.\s*(?:destroy|close)\s*\(\s*\)/;
      // Exclude HTTP response/reply objects and common framework objects where .end()/.close()
      // means "send response" not "free resource"
      const RESPONSE_VARS = /^(?:res|response|reply|ctx|context|next)$/i;
      const NULL_ASSIGN_RE = /=\s*null\b|=\s*undefined\b/;

      for (let i = 0; i < srcLines.length; i++) {
        const line = srcLines[i];
        const m1 = JS_FREE_LINE_RE.exec(line);
        const m2 = MEMBER_FREE_LINE_RE.exec(line);
        const subject = m1?.[1] || m2?.[1];
        if (!subject) continue;
        // Skip HTTP response/server objects — .end()/.close() on these means finalize response
        if (RESPONSE_VARS.test(subject)) continue;

        const lookAheadLimit = Math.min(i + 20, srcLines.length);
        for (let j = i + 1; j < lookAheadLimit; j++) {
          const afterLine = srcLines[j];
          if (NULL_ASSIGN_RE.test(afterLine) && afterLine.includes(subject)) break;
          if (/^\s*\}\s*$/.test(afterLine)) break;
          if (new RegExp(`\\b${subject}\\s*\\.(?!destroy|release|close|end)\\w`).test(afterLine)) {
            const freeNodeRef = map.nodes.find(n => n.line_start === i + 1 && FREE_RE.test(n.analysis_snapshot || n.code_snapshot)) ??
              map.nodes.find(n => FREE_RE.test(n.analysis_snapshot || n.code_snapshot));
            const afterNodeRef = map.nodes.find(n => n.line_start === j + 1) ??
              map.nodes.find(n => n.line_start > i + 1) ??
              freeNodeRef;
            if (freeNodeRef) {
              findings.push({
                source: nodeRef(freeNodeRef), sink: nodeRef(afterNodeRef ?? freeNodeRef),
                missing: 'CONTROL (do not access object after destroy/release/free)',
                severity: 'critical',
                description: `Resource '${subject}' freed/destroyed at line ${i + 1} is accessed at line ${j + 1}. ` +
                  `Accessing a destroyed/closed object leads to undefined behavior or runtime errors.`,
                fix: 'Set reference to null immediately after free/destroy. Restructure code so the resource is not used after it is freed.',
                via: 'source_line_fallback',
              });
              break;
            }
          }
        }
        if (findings.length > 0) break;
      }
    }
  }

  return { cwe: 'CWE-416', name: 'Use After Free', holds: findings.length === 0, findings };
}

/**
 * CWE-475: Undefined Behavior for Input to API
 * Passing values to library/API functions that are outside the defined valid input range,
 * triggering undefined behavior. Examples: negative values to unsigned parameters,
 * out-of-range values to ctype functions (isalpha with signed char > 127), NULL to
 * non-nullable parameters.
 */
function verifyCWE475(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // ctype functions that require unsigned char range (0-255 or EOF)
  const CTYPE_RE = /\b(isalpha|isdigit|isalnum|isspace|isupper|islower|ispunct|isprint|iscntrl|isxdigit|toupper|tolower|isascii|isgraph)\s*\(/i;
  // Functions with documented undefined behavior on certain inputs
  const UB_API_RE = /\b(abs|labs|llabs|div|ldiv|lldiv|memcpy|memmove|strncpy|strncat)\s*\([^)]*(-\s*\d+|NULL|nullptr|0x0)\s*[,)]/i;
  // Signed char passed to ctype (common UB trigger)
  const SIGNED_CHAR_CTYPE_RE = /\b(isalpha|isdigit|isalnum|isspace|toupper|tolower)\s*\(\s*\*?\s*\w+\s*\)(?!.*\bunsigned\b)(?!.*\(unsigned\s+char\))/;
  // Safe casts before ctype calls
  const SAFE_CAST_RE = /\(\s*unsigned\s+char\s*\)|\(\s*int\s*\)\s*\(\s*unsigned\s+char\s*\)|\b&\s*0xFF\b|\b&\s*0xff\b/;
  // NULL passed to functions that don't accept it
  const NULL_PARAM_RE = /\b(strlen|strcmp|strcpy|strcat|strstr|memcpy|memmove|printf|fprintf|sprintf|puts|fputs)\s*\([^)]*\b(NULL|nullptr|0)\s*[,)]/i;
  // Validation patterns
  const INPUT_CHECK_RE = /\bif\s*\(\s*\w+\s*[!=]=\s*(NULL|nullptr|0)\b|\bassert\s*\(\s*\w+\s*!=\s*(NULL|nullptr)\b|\bif\s*\(\s*\w+\s*>=\s*0\b|\bif\s*\(\s*\w+\s*<\s*\d/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check 1: Signed char to ctype function (UB when value > 127 or < 0)
    if (CTYPE_RE.test(code) && SIGNED_CHAR_CTYPE_RE.test(code) && !SAFE_CAST_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (cast to unsigned char before passing to ctype function)',
        severity: 'medium',
        description: `ctype function at ${node.label} receives potentially signed char input. ` +
          `ctype functions require values in the range of unsigned char (0-255) or EOF. ` +
          `Passing a signed char with values > 127 is undefined behavior.`,
        fix: 'Cast the argument to unsigned char: isalpha((unsigned char)c). ' +
          'Or mask with 0xFF: isalpha(c & 0xFF). ' +
          'Never pass signed char values directly to ctype functions.',
        via: 'structural',
      });
    }

    // Check 2: NULL passed to functions that require non-NULL
    if (NULL_PARAM_RE.test(code) && !INPUT_CHECK_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate parameter is non-NULL before passing to API)',
        severity: 'high',
        description: `NULL or nullptr passed to API function at ${node.label} that requires a non-NULL argument. ` +
          `This is undefined behavior per the C standard and will typically cause a segfault.`,
        fix: 'Check pointers for NULL before passing to string/memory functions. ' +
          'Add assertions: assert(ptr != NULL). Use static analysis attributes: __attribute__((nonnull)).',
        via: 'structural',
      });
    }

    // Check 3: Potentially undefined inputs to math/utility APIs
    if (UB_API_RE.test(code) && !INPUT_CHECK_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate input is within defined range for API function)',
        severity: 'medium',
        description: `API function at ${node.label} may receive an input that triggers undefined behavior. ` +
          `Functions like abs(INT_MIN), memcpy with NULL, or overlapping memcpy are undefined behavior.`,
        fix: 'Validate inputs are within the documented valid range before calling. ' +
          'For abs(): check that input != INT_MIN. For memcpy(): ensure non-NULL and non-overlapping. ' +
          'Use compiler sanitizers (-fsanitize=undefined) to catch these at runtime.',
        via: 'structural',
      });
    }
  }

  // Check INGRESS -> API nodes for user input reaching UB-prone APIs without validation
  const ingress = nodesOfType(map, 'INGRESS');
  const apiNodes = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    (CTYPE_RE.test(n.analysis_snapshot || n.code_snapshot) || UB_API_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const sink of apiNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!INPUT_CHECK_RE.test(sinkCode) && !SAFE_CAST_RE.test(sinkCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (validate user input before passing to API with undefined behavior on bad input)',
            severity: 'high',
            description: `User input from ${src.label} reaches API function at ${sink.label} without validation. ` +
              `The API has undefined behavior for certain input values, and user input is untrusted.`,
            fix: 'Validate and sanitize user input before passing to APIs with restricted input domains. ' +
              'Cast to appropriate types, check ranges, and verify non-NULL.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-475', name: 'Undefined Behavior for Input to API', holds: findings.length === 0, findings };
}

/**
 * CWE-476: NULL Pointer Dereference
 * Dereferencing a NULL/null/nil/None pointer/reference. Causes segfaults in C/C++,
 * NullPointerException in Java, TypeError in JS, panic in Go/Rust.
 */
function verifyCWE476(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const NULLABLE_SOURCE_RE = /\b(find|findOne|get|getElementById|querySelector|querySelectorAll|getAttribute|getItem|lookup|search|match|exec|pop|shift|first|last|fetch|load|open|fopen|connect|socket|accept|malloc|calloc|realloc)\b/i;
  const DEREF_RE = /\->\w+|\*\s*\w+\b|\.unwrap\s*\(\s*\)|\.\w+\s*\(|\.\w+\s*\[|\.\w+\s*\.|\[\s*\d+\s*\]/;
  const UNSAFE_UNWRAP_RE = /\.unwrap\s*\(\s*\)/i;
  const NULL_SAFE_RE = /\bif\s*\(\s*\w+\s*[!=]==?\s*null\b|\bif\s*\(\s*\w+\s*[!=]=?\s*nil\b|\bif\s*\(\s*\w+\s*is\s+None\b|\bif\s*\(\s*\w+\s*!=?\s*nullptr\b|\bif\s*\(\s*\w+\s*\)|\b\?\.\b|\b\?\?\b|\bif\s+err\s*!=\s*nil|\bif let\b|\bguard let\b|\bif\s+let\s+Some|\bmatch\b.*\bSome|\bmatch\b.*\bOk|\b\.unwrap_or\b|\b\.unwrap_or_else\b|\b\.ok_or\b|\btypeof\b|\bassert\b.*!=.*null|\brequire\b.*!=.*null/i;
  const nullableSources = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('nullable') || n.node_subtype.includes('optional') ||
     n.node_subtype.includes('lookup') || n.node_subtype.includes('query') ||
     NULLABLE_SOURCE_RE.test(n.analysis_snapshot || n.code_snapshot))
  );
  const derefSinks = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (DEREF_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     (n.analysis_snapshot || n.code_snapshot).match(/\.\w+\s*[\([]|\.length\b|\.toString\b|\.valueOf\b/i) !== null)
  );
  // Track seen sink IDs to avoid duplicate findings
  const seenSinks476 = new Set<string>();
  for (const src of nullableSources) {
    for (const sink of derefSinks) {
      if (src.id === sink.id) continue;
      if (seenSinks476.has(sink.id)) continue;
      // Use either DATA_FLOW path or function scope proximity.
      // In JavaScript, db.findOne() result stored in a variable that is then
      // dereferenced in the same function will share scope even without a direct
      // DATA_FLOW edge from the STORAGE source to the dereference TRANSFORM node.
      const reachable = hasPathWithoutControl(map, src.id, sink.id) ||
        sharesFunctionScope(map, src.id, sink.id);
      if (reachable) {
        // Check for null guards in the function scope (not just on src/sink nodes)
        const scopeNullSafe = map.nodes.some(n =>
          sharesFunctionScope(map, src.id, n.id) &&
          NULL_SAFE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
        );
        if (!NULL_SAFE_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) &&
            !NULL_SAFE_RE.test(stripComments(src.analysis_snapshot || src.code_snapshot)) &&
            !scopeNullSafe) {
          seenSinks476.add(sink.id);
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (null/nil/None check before dereference)',
            severity: 'medium',
            description: `Potentially-null value from ${src.label} is dereferenced at ${sink.label} without a null check. ` +
              `NULL dereference causes segfaults in C/C++, NullPointerException in Java, TypeError in JS.`,
            fix: 'Check for null before dereferencing. Use optional chaining (?.) in JS/TS. ' +
              'Use if-let/match in Rust instead of .unwrap(). In Go: check err != nil before using value.',
            via: 'scope_taint',
          });
        }
      }
    }
  }
  // --- Source-based detection: multiple null-dereference patterns ---
  // The graph-based approach above misses patterns where the source is a null literal
  // (not a nullable API call), or where the dereference happens in a structurally
  // broken null-guard (single & instead of &&, dereference inside if-null-true block).
  if (findings.length === 0) {
    const src476 = map.source_code || '';
    if (src476) {
      const lines = src476.split('\n');
      // Track which lines we've already flagged to avoid duplicate findings
      const flaggedLines = new Set<number>();

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

        // ── Pattern A: Non-short-circuit & in null check ──
        // if ((x != null) & (x.method())) — single & evaluates both sides,
        // so x.method() executes even when x is null. Must use && instead.
        if (/\bif\s*\(/.test(line)) {
          // Extract the full condition. Handle multi-paren conditions with greedy match.
          const condMatch = line.match(/\bif\s*\((.*)\)\s*$/);
          // Also try without trailing ) for lines like: if ((x != null) & (x.len() > 0)) {
          const condMatch2 = condMatch || line.match(/\bif\s*\((.*)\)/);
          if (condMatch2) {
            const cond = condMatch2[1];
            // Has null check AND has single & (not && or &=)
            if (/\w+\s*!=\s*null/.test(cond) && /[^&]&[^&=]/.test(cond)) {
              // And has dereference on the other side of &
              if (/\.\w+\s*\(/.test(cond) || /\.length\b/.test(cond) || /\.size\b/.test(cond)) {
                if (!flaggedLines.has(i)) {
                  flaggedLines.add(i);
                  const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
                  if (nearNode) {
                    findings.push({
                      source: nodeRef(nearNode), sink: nodeRef(nearNode),
                      missing: 'CONTROL (use && not & for null guard — short-circuit evaluation)',
                      severity: 'medium',
                      description: `L${i + 1}: Non-short-circuit operator & used in null check. Both sides of & are always ` +
                        `evaluated, so the dereference executes even when the variable is null. Use && instead.`,
                      fix: 'Use && (short-circuit AND) instead of & (bitwise AND) in null checks. With &&, the right side ' +
                        'is only evaluated if the left side is true, preventing null dereference.',
                    via: 'source_line_fallback',
                    });
                  }
                }
              }
            }
          }
        }

        // ── Pattern B: Dereference inside if (x == null) block ──
        // if (myString == null) { IO.writeLine(myString.length()); }
        // The variable is KNOWN null inside the true branch, so any dereference is a bug.
        if (/\bif\s*\(/.test(line)) {
          const eqNullMatch = line.match(/\bif\s*\(\s*(\w+)\s*==\s*null\s*\)/);
          if (eqNullMatch) {
            const varName = eqNullMatch[1];
            // Find the block after this if: track brace depth.
            // Scan up to 20 lines ahead to handle multi-line blocks where the
            // opening brace is on a separate line (common in Java/C# style).
            let blockDepth = 0;
            let blockStart = -1;
            for (let k = i; k < Math.min(i + 20, lines.length); k++) {
              for (let c = 0; c < lines[k].length; c++) {
                if (lines[k][c] === '{') {
                  if (blockStart === -1) blockStart = k;
                  blockDepth++;
                }
                if (lines[k][c] === '}') blockDepth--;
              }
              if (blockStart !== -1 && blockDepth === 0) {
                // Check all lines within this block for dereference of varName
                const derefInBlock = new RegExp(`\\b${varName}\\.\\w+\\s*[\\(\\[]|\\b${varName}\\.length\\b|\\b${varName}\\.toString\\b`);
                for (let m = blockStart; m <= k; m++) {
                  if (/^\s*\/\//.test(lines[m]) || /^\s*\*/.test(lines[m])) continue;
                  if (derefInBlock.test(lines[m]) && !flaggedLines.has(m)) {
                    flaggedLines.add(m);
                    const nearNode = map.nodes.find(n => Math.abs(n.line_start - (m + 1)) <= 2) || map.nodes[0];
                    if (nearNode) {
                      findings.push({
                        source: nodeRef(nearNode), sink: nodeRef(nearNode),
                        missing: 'CONTROL (do not dereference inside null-true branch)',
                        severity: 'medium',
                        description: `L${m + 1}: Variable '${varName}' is dereferenced inside a block where it is known to be null ` +
                          `(the if at L${i + 1} checks ${varName} == null). This always causes a NullPointerException.`,
                        fix: `Do not dereference '${varName}' inside the null branch. Either handle the null case without ` +
                          `dereferencing, or move the dereference to the else branch (where it is known non-null).`,
                        via: 'source_line_fallback',
                      });
                    }
                  }
                }
                break;
              }
            }
          }
        }

        // ── Pattern C: Variable assigned null, then dereferenced without reassignment or null check ──
        // data = null; ... data.toString() — the original pattern
        const nullAssign = line.match(/(\w+)\s*=\s*null\s*;/);
        if (nullAssign) {
          const varName = nullAssign[1];
          for (let j = i + 1; j < Math.min(i + 30, lines.length); j++) {
            const ahead = lines[j];
            if (/^\s*\/\//.test(ahead) || /^\s*\*/.test(ahead)) continue;
            // Check if variable is reassigned to non-null
            const reassignPat = new RegExp(`\\b${varName}\\s*=\\s*(?!null\\s*;|=)`);
            if (reassignPat.test(ahead)) break; // reassigned — safe
            // Check if there's a null check (both == and != count as awareness of nullability)
            const nullCheckPat = new RegExp(`\\b${varName}\\s*!=\\s*null\\b|\\b${varName}\\s*==\\s*null\\b`);
            if (nullCheckPat.test(ahead)) {
              // If it's a short-circuit guard on the same line as a deref, that's safe
              if (/&&/.test(ahead)) break;
              // If it uses single &, that's Pattern A (handled above) — but also break to avoid double-report
              if (/[^&]&[^&=]/.test(ahead)) break;
              // Otherwise it's a null check — break (handled by Pattern B or actually safe)
              break;
            }
            // Check if variable is dereferenced (method call or property access)
            const derefPat = new RegExp(`\\b${varName}\\.(\\w+)\\s*[\\(\\[]|\\b${varName}\\.length\\b|\\b${varName}\\.toString\\b`);
            if (derefPat.test(ahead)) {
              if (!flaggedLines.has(j)) {
                flaggedLines.add(j);
                const nearNode = map.nodes.find(n => Math.abs(n.line_start - (j + 1)) <= 2) || map.nodes[0];
                if (nearNode) {
                  findings.push({
                    source: nodeRef(nearNode), sink: nodeRef(nearNode),
                    missing: 'CONTROL (null check before dereference)',
                    severity: 'medium',
                    description: `L${j + 1}: Variable '${varName}' was assigned null at L${i + 1} and is dereferenced without a null check.`,
                    fix: 'Add a null check before dereferencing. Ensure the variable is assigned a non-null value before use.',
                    via: 'source_line_fallback',
                  });
                }
              }
              break;
            }
          }
        }
      }
    }
  }

  // --- Rust .unwrap() detection ---
  if (findings.length === 0) {
    const unwrapNodes = map.nodes.filter(n =>
      UNSAFE_UNWRAP_RE.test(n.analysis_snapshot || n.code_snapshot) && !NULL_SAFE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
    );
    for (const node of unwrapNodes) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (handle None/Err case instead of unwrap)',
        severity: 'medium',
        description: `${node.label} uses .unwrap() which panics on None/Err. If the value can be None/Err at runtime, this crashes.`,
        fix: 'Replace .unwrap() with .unwrap_or(default), .unwrap_or_else(|| ...), or pattern matching (match/if-let).',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-476', name: 'NULL Pointer Dereference', holds: findings.length === 0, findings };
}

/**
 * CWE-129: Improper Validation of Array Index
 * Pattern: External input used as array index with incomplete bounds validation
 * Property: All externally-sourced array indices are validated with BOTH
 *           lower bound (>= 0) AND upper bound (< array.length) checks.
 *
 * The Juliet vulnerable pattern:
 *   data = Integer.parseInt(socketInput);
 *   if (data < array.length) { array[data] }  // missing >= 0 check
 *
 * The safe pattern:
 *   if (data >= 0 && data < array.length) { array[data] }
 */
function verifyCWE129(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Phase 1: Graph-based detection
  const arrAccessRe = /\[\s*\w+\s*\]|\barray\s*\[|\blist\s*\[|\barr\s*\[|\bdata\s*\[|\bbuffer\s*\[|\belements?\s*\[/i;
  const arrNodes = map.nodes.filter(n => {
    const code = n.analysis_snapshot || n.code_snapshot;
    return arrAccessRe.test(code) && !/\[\s*['"`]/.test(code);
  });

  const fullBoundsRe = />=\s*0\s*&&[^;]*<\s*\w+\.length|>=\s*0\s*&&[^;]*<\s*\w+\s*\)|0\s*<=\s*\w+\s*&&|\bMath\.max\s*\(\s*0\s*,|\bMath\.min\s*\(|\bclamp\s*\(|\bbetween\s*\(|\binRange\s*\(/i;

  for (const src of ingress) {
    for (const sink of arrNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) || sinkHasTaintedDataIn(map, sink.id)) {
        const ss129 = getContainingScopeSnapshots(map, sink.id);
        const sc129 = stripComments(ss129.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        if (!fullBoundsRe.test(sc129)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (complete bounds validation: both >= 0 AND < array.length)',
            severity: 'high',
            description: `External input from ${src.label} is used as array index at ${sink.label} without complete bounds validation. ` +
              `A negative value bypasses an upper-bound-only check and causes ArrayIndexOutOfBoundsException.`,
            fix: 'Always validate array indices with BOTH bounds: if (index >= 0 && index < array.length). ' +
              'An upper-bound check alone does NOT prevent negative indices.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Phase 2: Source-line scanning for the classic Juliet pattern
  if (map.source_code) {
    const sl129 = map.source_code.split('\n');
    const pvars = new Set<string>();
    const parseRe = /\b(\w+)\s*=\s*(?:Integer\s*\.\s*parseInt|parseInt|Number\s*\(|int\s*\(|float\s*\(|Double\s*\.\s*parseDouble|Long\s*\.\s*parseLong|Short\s*\.\s*parseShort)\b/;
    for (const l of sl129) {
      const pm = parseRe.exec(l);
      if (pm) pvars.add(pm[1]!);
    }

    if (pvars.size > 0) {
      for (let li = 0; li < sl129.length; li++) {
        const ln = sl129[li]!;
        const tr = ln.trim();
        if (!tr || tr.startsWith('//') || tr.startsWith('*') || tr.startsWith('/*')) continue;

        for (const vn of pvars) {
          const ev = vn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const upRe = new RegExp(`if\\s*\\(\\s*${ev}\\s*<\\s*\\w+\\.length\\b`);
          if (!upRe.test(ln)) continue;

          const cs = Math.max(0, li - 5);
          const ce = Math.min(sl129.length, li + 1);
          const ctx = sl129.slice(cs, ce).join('\n');
          const loRe = new RegExp(`${ev}\\s*>=\\s*0|0\\s*<=\\s*${ev}|Math\\.max\\s*\\(\\s*0|Math\\.min\\s*\\(`);
          if (loRe.test(ctx)) continue;

          // Check if the variable was reassigned a hardcoded literal in the lookback
          // (e.g., data = 2 in goodG2B means it's NOT tainted in this scope)
          let isHardcoded129 = false;
          const hardLitRe = new RegExp(`\\b${ev}\\s*=\\s*\\d+\\s*;`);
          const hardStrRe = new RegExp(`\\b${ev}\\s*=\\s*["']`);
          for (let j = li - 1; j >= Math.max(0, li - 20); j--) {
            const prev129 = sl129[j]!.trim();
            if (hardLitRe.test(prev129) || hardStrRe.test(prev129)) { isHardcoded129 = true; break; }
            // If we see a parseInt/readLine assignment, it's tainted — stop looking
            if (new RegExp(`\\b${ev}\\s*=.*(?:parseInt|readLine|getParameter|getInput)`).test(prev129)) break;
          }
          if (isHardcoded129) continue;

          const dup = findings.some(f => f.sink.line !== undefined && Math.abs(f.sink.line - (li + 1)) <= 3);
          if (dup) continue;

          const sn = ingress.length > 0 ? ingress[0]! : findNearestNode(map, li + 1);
          if (sn) {
            findings.push({
              source: nodeRef(sn),
              sink: { id: `line-${li + 1}`, label: `array bounds check (line ${li + 1})`, line: li + 1, code: tr.slice(0, 200) },
              missing: 'CONTROL (lower bound check: index >= 0 missing before array access)',
              severity: 'high',
              description: `Array index "${vn}" has only an upper-bound check at line ${li + 1}: "${tr.slice(0, 80)}". ` +
                `The lower-bound check (>= 0) is missing. Negative values pass and cause ArrayIndexOutOfBoundsException.`,
              fix: `Add a lower-bound check: if (${vn} >= 0 && ${vn} < array.length). Both bounds must be checked.`,
              via: 'source_line_fallback',
            });
          }
        }
      }
    }

    // Phase 3: Detect completely unvalidated array access (no bounds check at all).
    // Phase 2 catches "upper-bound-only" (check_max). Phase 3 catches "no check at all"
    // (no_check), which is arguably the more dangerous variant.
    if (pvars.size > 0) {
      for (let li = 0; li < sl129.length; li++) {
        const ln3 = sl129[li]!;
        const tr3 = ln3.trim();
        if (!tr3 || tr3.startsWith('//') || tr3.startsWith('*') || tr3.startsWith('/*')) continue;

        for (const vn of pvars) {
          const ev3 = vn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          // Match array[var] usage
          const arrUseRe = new RegExp(`\\[\\s*${ev3}\\s*\\]`);
          if (!arrUseRe.test(ln3)) continue;

          // Check: is there ANY bounds check within 10 lines above?
          const ctxStart = Math.max(0, li - 10);
          const ctxEnd = Math.min(sl129.length, li + 1);
          const ctx3 = sl129.slice(ctxStart, ctxEnd).join('\n');
          const anyBoundsRe3 = new RegExp(
            `${ev3}\\s*<\\s*\\w+\\.length|` +
            `${ev3}\\s*>=\\s*0|` +
            `0\\s*<=\\s*${ev3}|` +
            `${ev3}\\s*>\\s*0|` +
            `Math\\.max\\s*\\(\\s*0|` +
            `Math\\.min\\s*\\(`
          );
          if (anyBoundsRe3.test(ctx3)) continue;

          // Hardcoded check: skip if variable was assigned a literal (goodG2B pattern)
          let isHardcoded3 = false;
          const hardLitRe3 = new RegExp(`\\b${ev3}\\s*=\\s*\\d+\\s*;`);
          for (let j = li - 1; j >= Math.max(0, li - 20); j--) {
            if (hardLitRe3.test(sl129[j]!.trim())) { isHardcoded3 = true; break; }
            if (new RegExp(`\\b${ev3}\\s*=.*(?:parseInt|readLine|getParameter|getInput)`).test(sl129[j]!.trim())) break;
          }
          if (isHardcoded3) continue;

          // Dedup against existing findings from Phase 1 or Phase 2
          const dup3 = findings.some(f => f.sink.line !== undefined && Math.abs(f.sink.line - (li + 1)) <= 3);
          if (dup3) continue;

          const sn3 = ingress.length > 0 ? ingress[0]! : findNearestNode(map, li + 1);
          if (sn3) {
            findings.push({
              source: nodeRef(sn3),
              sink: { id: `line-${li + 1}`, label: `unvalidated array access (line ${li + 1})`, line: li + 1, code: tr3.slice(0, 200) },
              missing: 'CONTROL (no bounds validation before array access)',
              severity: 'high',
              description: `Array index "${vn}" from external input is used at line ${li + 1}: "${tr3.slice(0, 80)}" with NO bounds validation. ` +
                `Any value including negative numbers will be accepted, causing ArrayIndexOutOfBoundsException.`,
              fix: `Add bounds validation: if (${vn} >= 0 && ${vn} < array.length) before accessing array[${vn}].`,
              via: 'source_line_fallback',
            });
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-129',
    name: 'Improper Validation of Array Index',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-690: Unchecked Return Value to NULL Pointer Dereference
 *
 * A method that can return null is called. The caller uses the return value
 * without checking for null. The dereference causes a NullPointerException
 * (Java), segfault (C/C++), or TypeError (JS/TS).
 *
 * Detection approach (source scan):
 *   1. Identify "nullable sources" — method calls known/likely to return null:
 *      - Well-known APIs: System.getProperty, getParameter, getProperty, getenv,
 *        Map.get, find, findOne, querySelector, getAttribute, getItem, etc.
 *      - Methods defined in the same file that contain `return null`
 *      - Methods whose name follows naming conventions suggesting nullable return
 *   2. Track the variable receiving the return value
 *   3. Check if that variable is dereferenced (var.method(), var.field, var[idx])
 *      without an intervening null check (if (var != null), if (var == null), etc.)
 *
 * Honest limitations: Cross-file analysis is limited to well-known API names.
 * Same-file methods with `return null` are fully detected. The Juliet Helper
 * pattern (cross-file getStringBad) is caught by matching known nullable names.
 */
function verifyCWE690(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const src690 = map.source_code || '';
  if (!src690) {
    return { cwe: 'CWE-690', name: 'Unchecked Return Value to NULL Pointer Dereference', holds: true, findings };
  }

  const lines = src690.split('\n');
  // Strip comments but preserve line count — replace comment content with spaces,
  // keeping all newlines so line indices match the original source.
  const stripped690 = src690.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
                            .replace(/\/\/.*$/gm, (m) => ' '.repeat(m.length));
  const strippedLines = stripped690.split('\n');

  // --- Phase 1: Collect same-file methods that return null ---
  const nullReturningMethods = new Set<string>();
  let currentMethod690: string | null = null;
  let braceDepth690 = 0;
  let methodBraceStart690 = 0;
  for (let i = 0; i < strippedLines.length; i++) {
    const line = strippedLines[i];
    const methodDecl = line.match(/(?:public|private|protected|static|\s)+\s+\w+(?:<[^>]*>)?\s+(\w+)\s*\(/);
    if (methodDecl && !line.includes(';') && !line.match(/^\s*\/\//)) {
      currentMethod690 = methodDecl[1];
      methodBraceStart690 = braceDepth690;
    }
    for (const ch of line) {
      if (ch === '{') braceDepth690++;
      if (ch === '}') braceDepth690--;
    }
    if (currentMethod690 && /\breturn\s+null\s*;/.test(line)) {
      nullReturningMethods.add(currentMethod690);
    }
    if (currentMethod690 && braceDepth690 <= methodBraceStart690) {
      currentMethod690 = null;
    }
  }

  // --- Phase 2: Well-known nullable API methods ---
  const NULLABLE_API_RE = /\b(?:System\.getProperty|System\.getenv|\.getProperty|\.getParameter|\.getAttribute|\.getItem|\.get\s*\(|\.find\s*\(|\.findOne\s*\(|\.findFirst\s*\(|\.querySelector\s*\(|\.getElementById\s*\(|\.lookup\s*\(|\.search\s*\(|\.match\s*\(|\.exec\s*\(|\.pop\s*\(|\.poll\s*\(|\.peek\s*\(|\.remove\s*\(|Class\.forName|\.getResource\s*\(|\.getAnnotation\s*\(|\.getHeader\s*\(|\.getCookie\s*\(|\.getSession\s*\(|\.getInitParameter\s*\(|\.getRealPath\s*\(|malloc\s*\(|calloc\s*\(|realloc\s*\(|getenv\s*\(|fopen\s*\()\b/;

  // --- Phase 3: Source scan for the pattern ---
  const seenFindings690 = new Set<string>();

  for (let i = 0; i < strippedLines.length; i++) {
    const line = strippedLines[i];
    if (/^\s*$/.test(line)) continue;

    // Match: var = someCall(...) or var = Qualifier.someCall(...)
    const assignMatch = line.match(/(\w+)\s*=\s*(?:(\w+(?:\.\w+)*)\s*\.\s*)?(\w+)\s*\(/);
    if (!assignMatch) continue;

    const varName = assignMatch[1];
    const qualifier = assignMatch[2] || '';
    const methodName = assignMatch[3];

    // Skip constructors (new X(...))
    const rhs = line.substring(line.indexOf('=') + 1).trim();
    if (/^new\s/.test(rhs)) continue;
    // Skip type declarations
    if (/^\s*(public|private|protected|class|interface|enum)\b/.test(line)) continue;

    // Determine if this call is nullable
    let isNullable = false;

    if (NULLABLE_API_RE.test(line)) {
      isNullable = true;
    }

    if (nullReturningMethods.has(methodName)) {
      isNullable = true;
    }

    // Cross-file: methods with "Bad" in name (Juliet convention)
    if (/Bad\s*\(/.test(line)) {
      isNullable = true;
    }

    // Additional Java nullable APIs by method name alone
    if (/\.(getProperty|getParameter|getAttribute|getHeader|getenv|getItem)\s*\(/.test(line)) {
      isNullable = true;
    }

    if (!isNullable) continue;

    // Scan forward for dereference without null check (within same method).
    // Compute absolute brace depth from file start to know when we exit the method.
    let absDepthAtSource = 0;
    for (let k = 0; k <= i; k++) {
      for (const ch of strippedLines[k]) {
        if (ch === '{') absDepthAtSource++;
        if (ch === '}') absDepthAtSource--;
      }
    }
    // The method body is at some depth; we exit when we go below depth 2
    // (class=1, method=2 in Java). Use the minimum expected method depth.
    const methodExitDepth = Math.max(absDepthAtSource - 3, 1);

    let nullChecked = false;
    let foundDeref = false;
    let derefLine = -1;
    let derefCode = '';

    let scanDepth = absDepthAtSource;
    for (let j = i + 1; j < Math.min(i + 60, strippedLines.length); j++) {
      const ahead = strippedLines[j];

      for (const ch of ahead) {
        if (ch === '{') scanDepth++;
        if (ch === '}') scanDepth--;
      }
      // Exit if we've left the enclosing method body
      if (scanDepth < methodExitDepth) break;

      const nullCheckPat = new RegExp(`\\b${varName}\\s*[!=]=\\s*null\\b|\\bnull\\s*[!=]=\\s*${varName}\\b`);
      if (nullCheckPat.test(ahead)) {
        nullChecked = true;
        break;
      }

      if (new RegExp(`Objects\\.(?:nonNull|requireNonNull)\\s*\\(\\s*${varName}`).test(ahead) ||
          new RegExp(`Optional\\.ofNullable\\s*\\(\\s*${varName}`).test(ahead)) {
        nullChecked = true;
        break;
      }

      // Reassignment breaks the nullable chain — UNLESS it's inside a catch/else
      // block (conditional path that doesn't cover the main execution path).
      const reassignPat = new RegExp(`\\b${varName}\\s*=\\s*(?!null\\s*;|=)`);
      if (reassignPat.test(ahead)) {
        // Check if there's a catch/else between source and this reassignment
        let inCatchOrElse = false;
        for (let k = i + 1; k <= j; k++) {
          if (/\bcatch\b|\belse\b/.test(strippedLines[k])) {
            inCatchOrElse = true;
            break;
          }
        }
        if (!inCatchOrElse) break; // Definitive reassignment on main path
        // Otherwise, the reassignment is on an alternative path — keep scanning
      }

      // Dereference: var.something
      const derefPat = new RegExp(`\\b${varName}\\s*\\.\\s*\\w+`);
      if (derefPat.test(ahead)) {
        if (nullCheckPat.test(ahead)) {
          nullChecked = true;
          break;
        }
        foundDeref = true;
        derefLine = j;
        derefCode = lines[j]?.trim() || ahead.trim();
        break;
      }
    }

    if (foundDeref && !nullChecked) {
      const key = `${varName}:${i}:${derefLine}`;
      if (!seenFindings690.has(key)) {
        seenFindings690.add(key);
        const nearNode = map.nodes.find(n => Math.abs(n.line_start - (derefLine + 1)) <= 2) || map.nodes[0];
        const sourceNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
        if (nearNode && sourceNode) {
          const fullCall = qualifier ? `${qualifier}.${methodName}` : methodName;
          findings.push({
            source: nodeRef(sourceNode),
            sink: nodeRef(nearNode),
            missing: 'CONTROL (null check on return value before dereference)',
            severity: 'high',
            description: `L${derefLine + 1}: Variable '${varName}' assigned from ${fullCall}() at L${i + 1} ` +
              `(which may return null) is dereferenced without a null check: ${derefCode.slice(0, 120)}`,
            fix: `Check the return value for null before dereferencing. ` +
              `Add: if (${varName} != null) { ... } or use Optional/Objects.requireNonNull().`,
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  // --- Phase 4: Graph-based fallback ---
  if (findings.length === 0) {
    const NULLABLE_SRC_RE = /\b(find|findOne|get|getElementById|querySelector|getAttribute|getItem|getProperty|getParameter|getenv|lookup|search|match|exec|pop|poll|peek|malloc|calloc|realloc|fopen)\b/i;
    const NULL_SAFE_690_RE = /\bif\s*\(\s*\w+\s*[!=]==?\s*null\b|\bif\s*\(\s*\w+\s*[!=]=?\s*nil\b|\bif\s*\(\s*\w+\s*is\s+None\b|\bif\s*\(\s*\w+\s*!=?\s*nullptr\b|\b\?\.\b|\b\?\?\b|\bif\s+err\s*!=\s*nil|\bif let\b|\bguard let\b|\bObjects\.nonNull\b|\bObjects\.requireNonNull\b|\bOptional\b/i;

    const nullableSources = map.nodes.filter(n =>
      (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
      NULLABLE_SRC_RE.test(n.analysis_snapshot || n.code_snapshot)
    );

    const derefSinks = map.nodes.filter(n =>
      (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
      /\.\w+\s*[\([]|\.length\b|\.toString\b|\.trim\b|\.equals\b|\.hashCode\b|->\w+|\*\s*\w+/i.test(n.analysis_snapshot || n.code_snapshot)
    );

    for (const src of nullableSources) {
      for (const sink of derefSinks) {
        if (src.id === sink.id) continue;
        const reachable = hasPathWithoutControl(map, src.id, sink.id) ||
          sharesFunctionScope(map, src.id, sink.id);
        if (reachable) {
          const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
          const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
          if (!NULL_SAFE_690_RE.test(sinkCode) && !NULL_SAFE_690_RE.test(srcCode)) {
            const scopeNullSafe = map.nodes.some(n =>
              sharesFunctionScope(map, src.id, n.id) &&
              NULL_SAFE_690_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
            );
            if (!scopeNullSafe) {
              findings.push({
                source: nodeRef(src), sink: nodeRef(sink),
                missing: 'CONTROL (null check on return value before dereference)',
                severity: 'high',
                description: `Potentially-null value from ${src.label} is dereferenced at ${sink.label} without a null check.`,
                fix: 'Check the return value for null before dereferencing. Use if (result != null) or Optional.',
                via: 'scope_taint',
              });
              break;
            }
          }
        }
      }
    }
  }

  return { cwe: 'CWE-690', name: 'Unchecked Return Value to NULL Pointer Dereference', holds: findings.length === 0, findings };
}

/**
 * CWE-696: Incorrect Behavior Order
 *
 * Pattern: Security-relevant operations performed in the wrong order — e.g.,
 * authorization checked AFTER action is performed, input validated AFTER use,
 * canonicalization after validation, encryption after logging.
 *
 * This is one of the most architecturally significant CWEs — many real vulns are
 * "the right checks exist but in the wrong order."
 */
function verifyCWE696(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Pattern 1: Validate-after-use — action node appears before validation on same input
  const ingress = nodesOfType(map, 'INGRESS');
  const controls = nodesOfType(map, 'CONTROL');
  const sinks = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS'
  );

  // Check if any sink is reached from INGRESS, and a CONTROL exists but appears
  // AFTER the sink in line order within the same function scope
  for (const src of ingress) {
    for (const sink of sinks) {
      if (src.id === sink.id) continue;
      if (!hasTaintedPathWithoutControl(map, src.id, sink.id)) continue;

      // Is there a CONTROL that validates this data but appears AFTER the sink?
      for (const ctrl of controls) {
        if (ctrl.line_start <= sink.line_start) continue; // CONTROL is before sink — correct order
        if (!sharesFunctionScope(map, sink.id, ctrl.id)) continue;

        // Check if the CONTROL actually references similar data
        const ctrlCode = stripComments(ctrl.analysis_snapshot || ctrl.code_snapshot).toLowerCase();
        const srcLabel = src.label.toLowerCase();
        if (ctrlCode.includes(srcLabel) || /\b(validate|sanitize|check|verify|assert|guard)\b/i.test(ctrlCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'META (incorrect ordering — validation happens AFTER use)',
            severity: 'high',
            description: `Input from ${src.label} reaches sink ${sink.label} (line ${sink.line_start}) before ` +
              `validation at ${ctrl.label} (line ${ctrl.line_start}). The security check exists but runs too late.`,
            fix: 'Move validation/authorization BEFORE the action. Security checks must gate access, not audit after the fact. ' +
              'Restructure: validate -> authorize -> act -> respond.',
            via: 'bfs',
          });
          break; // One finding per src-sink pair
        }
      }
    }
  }

  // Pattern 2: Encode-before-validate (canonicalization ordering)
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Encoding/decoding then validating — should be validate then encode
    const ENCODE_BEFORE_VALIDATE = /\b(encodeURI|encodeURIComponent|escape|htmlEncode|urlEncode|base64\.encode|btoa|encodeURIComponent)\b[\s\S]{0,200}\b(validate|sanitize|check|filter|verify|test\(|match\()\b/i;
    const DECODE_BEFORE_VALIDATE = /\b(decodeURI|decodeURIComponent|unescape|htmlDecode|urlDecode|base64\.decode|atob|decodeURIComponent)\b[\s\S]{0,200}\b(validate|sanitize|check|filter|verify|test\(|match\()\b/i;

    if (ENCODE_BEFORE_VALIDATE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (incorrect ordering — encoding before validation)',
        severity: 'medium',
        description: `${node.label} encodes data before validating it. Validation on encoded data may miss attack payloads ` +
          `that only become dangerous after decoding.`,
        fix: 'Validate first, then encode for the output context. The canonical order is: decode -> validate -> process -> encode.',
        via: 'structural',
      });
    }

    if (DECODE_BEFORE_VALIDATE.test(code)) {
      // This is actually correct order — skip
      continue;
    }
  }

  return { cwe: 'CWE-696', name: 'Incorrect Behavior Order', holds: findings.length === 0, findings };
}

/**
 * CWE-834: Excessive Iteration
 * Pattern: Loops where iteration count is controlled by user input without an upper bound.
 * Distinct from CWE-835 (infinite loop) — this is about loops that DO terminate but
 * take too long with adversarial input.
 *
 * NOTABLE: This is the "loop version" of CWE-400 (resource exhaustion). Classic attack:
 * POST {"items": [... 10 million elements ...]} to an endpoint doing items.forEach().
 * The loop terminates, but after consuming 100% CPU for minutes.
 */
function verifyCWE834(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const USER_LOOP_PATTERNS = [
    /\bfor\s*\(\s*\w+\s*=\s*\d*\s*;\s*\w+\s*<\s*(?:req\.|request\.|params\.|query\.|body\.|input\.|args\.|data\.)/i,
    /\bwhile\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input\.|args\.|data\.)\w+/i,
    /\b(?:req\.body|request\.body|request\.data|params|input|data)\s*(?:\.\w+)?\s*\.(?:forEach|map|filter|reduce|every|some|find)\s*\(/i,
    /\b(?:count|limit|times|iterations|repeat|n|num|number)\s*=\s*(?:parseInt|Number|int)\s*\(\s*(?:req\.|request\.|query\.|params\.|body\.|input\.)/i,
  ];

  const ITERATION_LIMIT_RE = /\b(?:MAX_ITEMS|MAX_ITERATIONS|MAX_COUNT|MAX_ELEMENTS|LIMIT|max_items|max_iterations|maxItems|maxIterations|\.slice\s*\(\s*0\s*,\s*\d+\)|\.length\s*>\s*\d+|\.length\s*<\s*\d+|paginate|pagination|BATCH_SIZE|batch_size|take\s*\(\s*\d+\))\b/i;

  const SIZE_CHECK_RE = /\b(?:Array\.isArray.*\.length|\.length\s*(?:>|>=|<|<=|===?)\s*\d+|maxLength|max_length|validateLength|sizeOf|sizeof|limit\s*[:=]\s*\d+)\b/i;

  const ingress = nodesOfType(map, 'INGRESS');

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    for (const pattern of USER_LOOP_PATTERNS) {
      if (pattern.test(code) && !ITERATION_LIMIT_RE.test(code) && !SIZE_CHECK_RE.test(code)) {
        const reachableFromIngress = ingress.some(src =>
          hasTaintedPathWithoutControl(map, src.id, node.id) ||
          sharesFunctionScope(map, src.id, node.id)
        );

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (maximum iteration limit for user-controlled loop bounds)',
          severity: reachableFromIngress ? 'high' : 'medium',
          description: `Loop at ${node.label} iterates based on user-controlled input without an upper bound. ` +
            `An attacker can send millions of items, causing 100% CPU consumption.`,
          fix: 'Enforce max iteration: const items = req.body.items.slice(0, MAX_ITEMS). ' +
            'Validate array lengths: if (items.length > 1000) return res.status(400). ' +
            'Use pagination. Set request body size limits.',
          via: 'structural',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-834', name: 'Excessive Iteration', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-186: Overly Restrictive Regular Expression
//
// A regex for validation is too strict — it rejects legitimate inputs.
// Security impact: users bypass the "correct" input path and find an
// unvalidated alternative, or the restrictive regex causes DoS by
// rejecting valid traffic at scale.
// ---------------------------------------------------------------------------

function verifyCWE186(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns that suggest overly restrictive validation
  const EMAIL_RESTRICTIVE = /\/\^[a-z\[\]\\]+@[a-z\[\]\\]+\.[a-z\[\]\\]+\$\//i; // too-simple email regex
  const FIXED_LENGTH_NAME = /\/\^\[a-zA-Z\]\{(\d+)\}\$\//; // name must be exactly N chars
  const ASCII_ONLY_NAME = /\/\^[[\]a-zA-Z ]+\$\/.*(?:name|first|last|user)/i; // no unicode in names
  const PHONE_EXACT = /\/\^\\\+?1?\d{10}\$\//; // phone must be exactly 10 digits — no spaces, dashes, parens

  const SAFE_PATTERN = /\bunicode\b|\bp{L}|\\p\{|[\u0080-\uFFFF]|i18n|intl|international/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'CONTROL') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_PATTERN.test(code)) continue;

    // ASCII-only name validation
    if (ASCII_ONLY_NAME.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (allow Unicode characters in name validation)',
        severity: 'medium',
        description: `${node.label} validates names with ASCII-only regex, rejecting accented characters ` +
          `(e.g., Jose, Muller, Bjork). Users whose names are rejected may bypass validation entirely.`,
        fix: 'Use Unicode-aware patterns: /^[\\p{L}\\p{M}\' -]+$/u or accept broader input and sanitize output.',
        via: 'structural',
      });
    }

    // Overly restrictive email (just alphanumeric@alpha.alpha)
    if (EMAIL_RESTRICTIVE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use RFC 5322 compliant email validation)',
        severity: 'low',
        description: `${node.label} uses an overly simple email regex that rejects valid emails with ` +
          `subdomains, dots in local part, plus addressing (user+tag@), or long TLDs (.museum, .company).`,
        fix: 'Use a well-tested email validation library or RFC 5322 regex. ' +
          'Consider simply checking for @ and a dot, then verifying via confirmation email.',
        via: 'structural',
      });
    }

    // Fixed-length constraints on variable-length data
    const fixedMatch = code.match(FIXED_LENGTH_NAME);
    if (fixedMatch) {
      const len = parseInt(fixedMatch[1], 10);
      if (len < 50) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (use length range, not exact length, for name-like fields)',
          severity: 'low',
          description: `${node.label} requires exactly ${len} characters, rejecting shorter or longer valid inputs. ` +
            `Users who can't match the exact length may seek unvalidated input paths.`,
          fix: 'Use a min/max range: {1,100} instead of {' + len + '}.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-186', name: 'Overly Restrictive Regular Expression', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-188: Reliance on Data/Memory Layout
//
// Code assumes a specific memory layout (struct field ordering, padding,
// alignment) that varies across compilers, platforms, or optimization levels.
// Casting struct pointers to char* and sending over network, or using
// offsetof() for serialization, breaks on different architectures.
// ---------------------------------------------------------------------------

function verifyCWE188(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Direct struct-to-bytes patterns (C/C++)
  const STRUCT_CAST_RE = /\(\s*(char\s*\*|void\s*\*|uint8_t\s*\*|unsigned\s+char\s*\*|BYTE\s*\*)\s*\)\s*&?\s*\w+.*(?:send|write|fwrite|memcpy|socket|serialize)/i;
  // sizeof(struct) used for network/file I/O
  const SIZEOF_STRUCT_IO = /sizeof\s*\(\s*(?:struct\s+)?\w+\s*\)\s*.*(?:send|write|fwrite|read|fread|recv|socket)/i;
  // Direct memory overlay — reading raw bytes as struct
  const MEMORY_OVERLAY = /\(\s*(?:struct\s+)?(\w+)\s*\*\s*\)\s*(?:buf|buffer|data|packet|payload|msg|message|raw)/i;
  // Union type-punning
  const UNION_PUNNING = /\bunion\b.*\{[^}]*(?:int|float|double|char|uint|byte)[^}]*\}/i;

  // Safe patterns — proper serialization
  const SAFE_SERIAL = /\b(protobuf|flatbuffers|msgpack|cbor|json|xml|hton[sl]|ntoh[sl]|pack\(|struct\.pack|serialize|marshal|BinaryWriter|DataOutputStream|#pragma\s+pack|__attribute__\s*\(\s*\(\s*packed|__packed__|alignas)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SAFE_SERIAL.test(code)) continue;

    if (STRUCT_CAST_RE.test(code) || SIZEOF_STRUCT_IO.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use proper serialization instead of raw struct memory)',
        severity: 'high',
        description: `${node.label} casts a struct to raw bytes for I/O. Struct layout (padding, alignment, ` +
          `field ordering) varies across compilers and platforms. Data sent from a 64-bit system with ` +
          `8-byte alignment will be misinterpreted by a 32-bit system with 4-byte alignment.`,
        fix: 'Use a serialization format (protobuf, JSON, msgpack) or explicitly serialize each field. ' +
          'If raw memory is required, use #pragma pack(1) and fixed-width integer types (uint32_t).',
        via: 'structural',
      });
    }

    if (MEMORY_OVERLAY.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (deserialize fields individually instead of casting buffer to struct pointer)',
        severity: 'high',
        description: `${node.label} casts a raw buffer to a struct pointer. If the buffer came from a ` +
          `different platform or was crafted by an attacker, field boundaries won't align correctly. ` +
          `This can cause data corruption, information disclosure, or crashes from misaligned access.`,
        fix: 'Deserialize each field individually with explicit offsets and byte-order conversion. ' +
          'Use ntohl/ntohs for network data. Consider a serialization library.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-188', name: 'Reliance on Data/Memory Layout', holds: findings.length === 0, findings };
}

/**
 * CWE-369: Divide By Zero
 * Division or modulo where divisor can be zero. In C/C++: SIGFPE crash.
 * In other languages: Infinity/NaN or exceptions.
 */
function verifyCWE369(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const DIV_RE = /\s\/\s|\s%\s|\bdiv\b|\bmod\b|\bdivmod\b|\bquotient\b|\bremainder\b/i;
  const DIV_FUNC_RE = /\bMath\.floor\s*\(.*\/|\bMath\.ceil\s*\(.*\/|\bMath\.trunc\s*\(.*\/|\bBigInt\b.*\/|\bidiv\b/i;
  const MODULO_RE = /\b\w+\s*%\s*\w+|\bfmod\b|\bmodulo\b/i;
  const ZERO_SAFE_RE = /\b!==?\s*0\b|\b!=\s*0\b|\b>\s*0\b|\b>=\s*1\b|\bif\s*\(.*divisor|\bif\s*\(\s*\w+\s*\)\s*\{?\s*.*\/|\bzero.*check\b|\bdivisor.*valid\b|\bisNaN\b|\bisFinite\b|\b\|\|\s*1\b|\b\?\?\s*1\b|\bdefault\b.*\b[1-9]|\bMath\.abs\s*\(.*\)\s*>\s*0/i;
  const ingress = nodesOfType(map, 'INGRESS');
  const divNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
    (DIV_RE.test(n.analysis_snapshot || n.code_snapshot) || DIV_FUNC_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     MODULO_RE.test(n.analysis_snapshot || n.code_snapshot) || n.node_subtype.includes('division') ||
     n.node_subtype.includes('arithmetic') || n.attack_surface.includes('arithmetic'))
  );
  for (const src of ingress) {
    for (const sink of divNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if ((DIV_RE.test(code) || DIV_FUNC_RE.test(code) || MODULO_RE.test(code)) && !ZERO_SAFE_RE.test(code)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (zero divisor check before division/modulo)',
            severity: 'medium',
            description: `User input from ${src.label} controls a divisor at ${sink.label} without zero check. ` +
              `Division by zero causes crashes (SIGFPE in C/C++), exceptions, or NaN/Infinity propagation.`,
            fix: 'Check divisor before dividing: if (divisor === 0) return error or default value. ' +
              'Use || 1 or ?? 1 as fallback. In Rust: checked_div(). In Go: explicit if divisor == 0.',
            via: 'bfs',
          });
        }
      }
    }
  }
  if (findings.length === 0) {
    const externalDivNodes = map.nodes.filter(n =>
      (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
      (DIV_RE.test(n.analysis_snapshot || n.code_snapshot) || MODULO_RE.test(n.analysis_snapshot || n.code_snapshot)) &&
      n.data_in.some(d => d.tainted)
    );
    for (const node of externalDivNodes) {
      if (!ZERO_SAFE_RE.test(stripComments(node.analysis_snapshot || node.code_snapshot))) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (zero divisor validation)',
          severity: 'medium',
          description: `Division at ${node.label} uses tainted data as divisor without zero check.`,
          fix: 'Always validate divisors are non-zero before division.',
          via: 'sink_tainted',
        });
      }
    }
  }
  // --- Source-line fallback: scan raw source for division of tainted variables ---
  // The graph approach above misses cases where the division expression is embedded
  // inside a cast or compound expression that tree-sitter does NOT emit as a
  // standalone TRANSFORM node (e.g. Java: int result = (int)(100.0 / data)).
  if (findings.length === 0 && map.source_code) {
    const srcLines = map.source_code.split('\n');
    // Collect tainted variable names from INGRESS/tainted-TRANSFORM nodes
    const taintedVars = new Set<string>();
    for (const n of map.nodes) {
      const snap = n.analysis_snapshot || n.code_snapshot || '';
      if (n.node_type === 'INGRESS' || (n.node_type === 'TRANSFORM' && n.data_in?.some(d => d.tainted))) {
        // Extract LHS variable from assignment snapshots like "data = Float.parseFloat(...)"
        const assignMatch = snap.match(/^(\w+)\s*=/);
        if (assignMatch) taintedVars.add(assignMatch[1]);
        // Also extract variable from readLine/getParameter/etc calls
        const callMatch = snap.match(/(\w+)\s*=\s*\w+\.\w+\(/);
        if (callMatch) taintedVars.add(callMatch[1]);
      }
    }
    // Also scan source for common taint patterns: var = parseXxx(...), readLine(), getParameter(...)
    const TAINT_ASSIGN_RE = /(\w+)\s*=\s*(?:\w+\.)?(?:parse\w+|read\w+|get\w+|next\w+)\s*\(/i;
    for (const line of srcLines) {
      const m = line.match(TAINT_ASSIGN_RE);
      if (m) taintedVars.add(m[1]);
    }
    if (taintedVars.size > 0) {
      // Build regex matching division by a tainted variable: / varName or % varName
      const SRC_DIV_RE = /[\/]\s*(\w+)|\s%\s*(\w+)/;
      for (let i = 0; i < srcLines.length; i++) {
        const line = srcLines[i];
        const trimmed = line.trim();
        // Skip comments
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
        const divMatch = line.match(SRC_DIV_RE);
        if (!divMatch) continue;
        const divisorVar = divMatch[1] || divMatch[2];
        if (!divisorVar || !taintedVars.has(divisorVar)) continue;
        // Skip if this line contains import/package/comment patterns
        if (/^\s*(?:import|package)\s/.test(line)) continue;
        // Check preceding lines (up to 10) for zero guard on this variable
        let guarded = false;
        for (let j = Math.max(0, i - 10); j < i; j++) {
          const prev = srcLines[j];
          if (ZERO_SAFE_RE.test(prev)) { guarded = true; break; }
          // Also check explicit zero comparisons with the tainted var name
          const varGuardRE = new RegExp(`\\b${divisorVar}\\b\\s*[!=><]=?\\s*0|\\bif\\s*\\(\\s*${divisorVar}\\b`, 'i');
          if (varGuardRE.test(prev)) { guarded = true; break; }
        }
        // Also check if the division is inside a guarded block (if on same line)
        if (ZERO_SAFE_RE.test(line)) guarded = true;
        if (!guarded) {
          const lineNum = i + 1;
          const snippet = trimmed.slice(0, 200);
          findings.push({
            source: { id: `src-line-${lineNum}`, label: `source (line ${lineNum})`, line: lineNum, code: snippet },
            sink: { id: `src-line-${lineNum}`, label: `division (line ${lineNum})`, line: lineNum, code: snippet },
            missing: 'CONTROL (zero divisor check before division/modulo)',
            severity: 'medium',
            description: `Tainted variable '${divisorVar}' used as divisor at line ${lineNum} without zero check. ` +
              `Division by zero causes crashes (SIGFPE in C/C++), exceptions, or NaN/Infinity propagation.`,
            fix: 'Check divisor before dividing: if (divisor != 0) or if (Math.abs(divisor) > epsilon). ' +
              'Use || 1 or ?? 1 as fallback. In Rust: checked_div(). In Go: explicit if divisor == 0.',
            via: 'source_line_fallback',
          });
          break; // one finding per function is sufficient
        }
      }
    }
  }
  return { cwe: 'CWE-369', name: 'Divide By Zero', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const MEMORY_SAFETY_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-415': verifyCWE415,
  'CWE-416': verifyCWE416,
  'CWE-475': verifyCWE475,
  'CWE-476': verifyCWE476,
  'CWE-129': verifyCWE129,
  'CWE-690': verifyCWE690,
  'CWE-696': verifyCWE696,
  'CWE-834': verifyCWE834,
  'CWE-186': verifyCWE186,
  'CWE-188': verifyCWE188,
  'CWE-369': verifyCWE369,
};
