/**
 * Phoneme expansion: PHP 8 Modern Features
 * Agent-generated, tested against real patterns
 *
 * This expansion covers PHP 8.0–8.3 features that matter for security scanning:
 *
 * 1. PHP 8 Attributes (#[Route], #[Security], #[Cache]) — META
 *    Attributes replaced docblock annotations in PHP 8.0. Security-critical
 *    attributes like #[IsGranted], #[Security], and #[Cache] control access
 *    and caching behavior declaratively. If the scanner doesn't see these as
 *    META/config nodes, it misses entire authorization layers in Symfony 6+.
 *
 * 2. Fibers (Fiber::start, resume, suspend) — CONTROL
 *    PHP 8.1 Fibers enable cooperative concurrency. Fiber::suspend() yields
 *    control mid-execution, creating non-obvious control flow. A tainted value
 *    could enter before suspend() and be consumed after resume() in a completely
 *    different call stack. The scanner needs to track these as CONTROL/concurrency.
 *
 * 3. ReflectionAttribute::newInstance() — META
 *    Instantiates an attribute class from reflection. This is how frameworks
 *    (Symfony, Laravel) read attribute metadata at runtime. It can trigger
 *    constructor side effects — META/reflection.
 *
 * 4. Enum::from() / Enum::tryFrom() — CONTROL
 *    PHP 8.1 backed enums with from()/tryFrom() are used for input validation.
 *    from() throws on invalid input, tryFrom() returns null. These are
 *    CONTROL/validation — they gate untrusted input into a fixed set of values.
 *
 * 5. WeakMap — STORAGE
 *    PHP 8.0 WeakMap stores object-keyed data without preventing GC. Used for
 *    caching computed values per-object (e.g., permission caches, serialization
 *    caches). STORAGE/cache_write and cache_read.
 *
 * 6. str_contains/str_starts_with/str_ends_with — CONTROL
 *    PHP 8.0 added these as replacements for strpos() !== false patterns.
 *    They're used for input validation (checking allowed prefixes, suffixes,
 *    substrings). CONTROL/validation.
 *
 * SECURITY INSIGHT: PHP 8 Attributes are the new blind spot. In Symfony 6+,
 * entire auth layers are expressed as #[IsGranted('ROLE_ADMIN')] on controller
 * methods. If the scanner only looks at function calls, it misses all of this.
 * The attribute system is PHP's equivalent of Java annotations — and it's now
 * the primary way security is configured in modern PHP frameworks.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// =============================================================================
// NEW ENTRIES — to be wired into php.ts
// =============================================================================

export const PHONEMES_PHP_MODERN = {

  // -- PHP 8 string validation functions (DIRECT_CALLS) -----------------------
  // Added in PHP 8.0 as replacements for the error-prone strpos() !== false
  // pattern. These are used ubiquitously for input validation: checking URL
  // prefixes, file extensions, content-type headers, allowed substrings.
  // CONTROL/validation because they gate logic based on string content.

  str_contains:       { nodeType: 'CONTROL' as NodeType,     subtype: 'validation',    tainted: false },
  str_starts_with:    { nodeType: 'CONTROL' as NodeType,     subtype: 'validation',    tainted: false },
  str_ends_with:      { nodeType: 'CONTROL' as NodeType,     subtype: 'validation',    tainted: false },

  // -- PHP 8.1 Enum validation (MEMBER_CALLS) ---------------------------------
  // Backed enums (enum Status: string) with from()/tryFrom() are THE idiomatic
  // PHP 8.1+ way to validate that a value belongs to a known set.
  // from() throws ValueError on invalid input, tryFrom() returns null.
  // These replace switch/match + manual validation. CONTROL/validation.

  'Enum.from':        { nodeType: 'CONTROL' as NodeType,     subtype: 'validation',    tainted: false },
  'Enum.tryFrom':     { nodeType: 'CONTROL' as NodeType,     subtype: 'validation',    tainted: false },

  // -- PHP 8.1 Fibers (MEMBER_CALLS) ------------------------------------------
  // Cooperative concurrency primitives. Fiber::start() begins execution,
  // suspend() yields mid-function, resume() continues. These create non-linear
  // control flow that the scanner must track — a tainted value can cross
  // suspend/resume boundaries invisibly.

  'Fiber.start':      { nodeType: 'CONTROL' as NodeType,     subtype: 'concurrency',   tainted: false },
  'Fiber.resume':     { nodeType: 'CONTROL' as NodeType,     subtype: 'concurrency',   tainted: false },
  'Fiber.suspend':    { nodeType: 'CONTROL' as NodeType,     subtype: 'concurrency',   tainted: false },

  // -- ReflectionAttribute (MEMBER_CALLS) -------------------------------------
  // newInstance() instantiates an attribute class from reflection metadata.
  // This is the runtime bridge between declarative attributes and executable
  // code. Frameworks use this to read #[Route], #[Security], #[Cache] etc.
  // META/reflection because it accesses metadata that controls system behavior.

  'ReflectionAttribute.newInstance': { nodeType: 'META' as NodeType, subtype: 'reflection', tainted: false },

  // -- WeakMap (MEMBER_CALLS) -------------------------------------------------
  // GC-friendly object-keyed storage. Used for per-object caching (permission
  // lookups, serialized forms, computed properties). The security relevance:
  // if a WeakMap caches auth decisions, stale entries could grant access after
  // the backing object is modified.

  'WeakMap.offsetSet': { nodeType: 'STORAGE' as NodeType,    subtype: 'cache_write',   tainted: false },
  'WeakMap.offsetGet': { nodeType: 'STORAGE' as NodeType,    subtype: 'cache_read',    tainted: false },
};
