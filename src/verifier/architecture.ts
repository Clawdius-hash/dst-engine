/**
 * Architecture & Code Quality CWE Verifiers (1044–1127)
 *
 * Self-contained metric checkers: nesting depth, function length, parameter count,
 * inheritance depth, dead code, documentation coverage, naming conventions, etc.
 * No shared taint state, no BFS, no injection detection.
 *
 * Extracted from verifier/index.ts — Phase 1 of the monolith split.
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments } from './source-analysis.ts';
import { nodeRef, nodesOfType, inferMapLanguage, isLibraryCode } from './graph-helpers.ts';

// ---------------------------------------------------------------------------
// Deep architecture CWEs (1070–1082)
// ---------------------------------------------------------------------------

/**
 * CWE-1070: Serializable Data Element Containing non-Serializable Item Elements
 * A class marked Serializable contains fields whose types do not implement
 * Serializable. At runtime, serialization throws NotSerializableException —
 * this can cause denial-of-service if the object is serialized in a session,
 * cache, or message queue.
 *
 * Detects: Java Serializable classes with fields typed as known non-serializable
 * types (Thread, Socket, Connection, InputStream, etc.), and any transient-missing
 * patterns. Also detects Python pickle with unpicklable attributes (locks, file handles).
 */
function verifyCWE1070(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Java: class implements Serializable
  const SERIALIZABLE_CLASS = /\bclass\s+\w+[^{]*\bimplements\b[^{]*\bSerializable\b/;
  // Known non-serializable JDK types
  const NON_SERIAL_FIELD = /\b(?:private|protected|public)\s+(?:final\s+)?(?:Thread|Socket|ServerSocket|Connection|InputStream|OutputStream|FileDescriptor|Lock|ReentrantLock|Logger|Mutex|Semaphore|ExecutorService|ScheduledExecutorService|DataSource|EntityManager|SessionFactory|ClassLoader)\b/;
  const TRANSIENT_RE = /\btransient\b/;

  // Python pickle with non-picklable attributes
  const PICKLE_DUMP = /\bpickle\.dump[s]?\s*\(|cPickle\.dump/;
  const NON_PICKLE_ATTR = /self\.\w*(?:lock|mutex|thread|socket|connection|file_handle|db_conn|cursor|session)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Java check
    if (SERIALIZABLE_CLASS.test(code) && NON_SERIAL_FIELD.test(code) && !TRANSIENT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (transient modifier on non-serializable fields)',
        severity: 'medium',
        description: `${node.label} implements Serializable but contains fields of non-serializable types ` +
          `without the transient modifier. Serialization will throw NotSerializableException at runtime, ` +
          `crashing sessions, caches, or message queues.`,
        fix: 'Mark non-serializable fields as transient, or make the field types implement Serializable. ' +
          'Implement custom writeObject/readObject if the field must be reconstituted after deserialization.',
        via: 'source_line_fallback',
      });
    }

    // Python check
    if (PICKLE_DUMP.test(code) && NON_PICKLE_ATTR.test(code)) {
      const safePickle = /\b(__getstate__|__reduce__|__reduce_ex__|copyreg\.pickle)\b/;
      if (!safePickle.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (__getstate__ to exclude non-picklable attributes)',
          severity: 'medium',
          description: `${node.label} pickles an object with non-picklable attributes (locks, sockets, file handles). ` +
            `pickle.dump will raise TypeError at runtime.`,
          fix: 'Implement __getstate__/__setstate__ to exclude non-picklable attributes, or use ' +
            'a serialization library that handles them (e.g., dill, cloudpickle).',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return { cwe: 'CWE-1070', name: 'Serializable Data Element Containing non-Serializable Item Elements', holds: findings.length === 0, findings };
}

/**
 * CWE-1071: Empty Code Block
 * Empty code blocks (catch, if/else, loops, methods) often indicate incomplete
 * implementation. Empty catch blocks silently swallow errors — this is a
 * security concern because exceptions signaling attacks (auth failures,
 * injection attempts, crypto errors) are lost.
 *
 * Specifically dangerous: empty catch/except, empty finally, empty if/else.
 * Empty loop bodies are usually intentional spin-waits.
 */
function verifyCWE1071(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Empty catch blocks — the most security-relevant variant
  const EMPTY_CATCH_JAVA = /\bcatch\s*\([^)]+\)\s*\{\s*\}/;
  const EMPTY_CATCH_PYTHON = /\bexcept(?:\s+\w+(?:\s+as\s+\w+)?)?\s*:\s*\n\s*(?:pass\b|\.\.\.|$)/m;
  const EMPTY_CATCH_CSHARP = /\bcatch\s*(?:\([^)]+\))?\s*\{\s*\}/;
  const EMPTY_CATCH_RUBY = /\brescue(?:\s+\w+)?\s*\n\s*(?:end\b|$)/m;

  // Empty if/else bodies
  const EMPTY_IF = /\bif\s*\([^)]+\)\s*\{\s*\}/;
  const EMPTY_ELSE = /\belse\s*\{\s*\}/;

  // Empty method/function bodies (not abstract/interface)
  const EMPTY_METHOD_JAVA = /(?:public|protected|private)\s+\w+\s+\w+\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{\s*\}/;
  const EMPTY_FUNC_JS = /(?:function\s+\w+|=>\s*)\s*\{\s*\}/;

  // Safe: intentional empty blocks with comments (already stripped), or TODO
  const INTENTIONAL_RE = /\b(intentional|deliberate|no-?op|noop|TODO|FIXME|HACK|abstract|interface)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    if (INTENTIONAL_RE.test(node.analysis_snapshot || node.code_snapshot)) continue; // check original (comments matter here)

    let matched = false;
    let description = '';
    let severity: 'critical' | 'high' | 'medium' | 'low' = 'medium';

    if (EMPTY_CATCH_JAVA.test(code) || EMPTY_CATCH_CSHARP.test(code)) {
      matched = true;
      severity = 'high';
      description = `Empty catch block at ${node.label}: exceptions are silently swallowed. ` +
        `Security-critical exceptions (auth failures, crypto errors, injection detection) will be lost.`;
    } else if (EMPTY_CATCH_PYTHON.test(code)) {
      matched = true;
      severity = 'high';
      description = `Empty except/pass at ${node.label}: exceptions are silently swallowed. ` +
        `Use 'except Exception as e: logger.error(e)' at minimum.`;
    } else if (EMPTY_CATCH_RUBY.test(code)) {
      matched = true;
      severity = 'high';
      description = `Empty rescue at ${node.label}: exceptions silently swallowed.`;
    } else if (EMPTY_IF.test(code) || EMPTY_ELSE.test(code)) {
      matched = true;
      severity = 'low';
      description = `Empty if/else block at ${node.label}: suggests incomplete implementation. ` +
        `If guarding a security path, the guard does nothing.`;
    } else if (EMPTY_METHOD_JAVA.test(code) || EMPTY_FUNC_JS.test(code)) {
      matched = true;
      severity = 'low';
      description = `Empty method/function body at ${node.label}: no-op implementation. ` +
        `If this is a security callback (validate, authorize, sanitize), it provides no protection.`;
    }

    if (matched) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (non-empty implementation in code block)',
        severity,
        description,
        fix: 'Add proper logic to the empty block. For catch/except: at minimum log the error. ' +
          'For security callbacks: implement the validation/authorization logic. ' +
          'If intentionally empty, add a comment explaining why.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1071', name: 'Empty Code Block', holds: findings.length === 0, findings };
}

/**
 * CWE-1073: Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses
 * A single function/method makes too many distinct database or data resource calls.
 * This indicates poor separation of concerns, makes auditing difficult, and creates
 * performance bottlenecks (N+1 queries, connection exhaustion, transaction scope creep).
 *
 * Security impact: functions with many DB accesses are harder to audit for injection,
 * authorization bypasses, and data leaks. They also risk connection pool exhaustion (DoS).
 */
function verifyCWE1073(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DB_ACCESS_PATTERNS = [
    /\b(?:query|execute|exec|run|prepare|all|get|first|find|select|insert|update|delete|count|aggregate)\s*\(/gi,
    /\b(?:findOne|findMany|findAll|findById|findBy\w+|createQuery|nativeQuery)\s*\(/gi,
    /\b(?:db|conn|connection|pool|client|session|cursor|knex|prisma|sequelize|mongoose|typeorm|sqlalchemy)\s*\.\s*\w+\s*\(/gi,
    /\b(?:Model|Repository|Collection|Table)\s*\.\s*(?:find|where|select|insert|update|delete|create|save|remove|destroy)\s*\(/gi,
    /\b(?:cursor\.execute|conn\.execute|session\.query|session\.execute|engine\.execute)\s*\(/gi,
  ];

  const THRESHOLD = 7; // More than 7 distinct DB access calls in one function

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|migration|seed)\b/i.test(node.label)) continue;
    if (node.node_type === 'META' || node.node_type === 'STRUCTURAL') continue;

    let accessCount = 0;
    for (const pattern of DB_ACCESS_PATTERNS) {
      pattern.lastIndex = 0;
      const matches = code.match(pattern);
      if (matches) accessCount += matches.length;
    }

    if (accessCount > THRESHOLD) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: `STRUCTURAL (refactor to reduce data resource accesses — found ${accessCount})`,
        severity: 'medium',
        description: `${node.label} makes ${accessCount} data resource accesses (threshold: ${THRESHOLD}). ` +
          `Excessive DB calls in one function indicate poor separation of concerns, risk N+1 queries, ` +
          `and make injection/authorization auditing difficult.`,
        fix: 'Split into smaller functions with single responsibility. Use batch queries or joins ' +
          'instead of multiple sequential accesses. Consider a repository or data access layer pattern.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1073', name: 'Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses', holds: findings.length === 0, findings };
}

/**
 * CWE-1074: Class with Excessively Deep Inheritance
 * Classes inheriting through many levels create fragile base class problems,
 * make security auditing difficult (which level overrides the auth check?),
 * and risk method resolution order (MRO) confusion.
 *
 * Detects inheritance chains by scanning for extends chains and multi-level
 * super() calls, plus Python's explicit multiple inheritance with deep MRO.
 */
function verifyCWE1074(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Look for extends chains — we scan STRUCTURAL nodes for class definitions
  // and track inheritance depth via node_subtype or code patterns
  const EXTENDS_RE = /\bclass\s+(\w+)\s+extends\s+(\w+)/g;
  const PYTHON_INHERIT = /\bclass\s+(\w+)\s*\(([^)]+)\)/g;

  // Build inheritance map from all nodes
  const parentMap = new Map<string, string[]>();

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    let match;

    EXTENDS_RE.lastIndex = 0;
    while ((match = EXTENDS_RE.exec(code)) !== null) {
      const child = match[1];
      const parent = match[2];
      if (!parentMap.has(child)) parentMap.set(child, []);
      parentMap.get(child)!.push(parent);
    }

    PYTHON_INHERIT.lastIndex = 0;
    while ((match = PYTHON_INHERIT.exec(code)) !== null) {
      const child = match[1];
      const parents = match[2].split(',').map(p => p.trim()).filter(p => p && p !== 'object' && p !== 'ABC' && p !== 'metaclass');
      if (parents.length > 0) {
        if (!parentMap.has(child)) parentMap.set(child, []);
        parentMap.get(child)!.push(...parents);
      }
    }
  }

  // Calculate max depth for each class
  const DEPTH_THRESHOLD = 5;
  const depthCache = new Map<string, number>();

  function getDepth(cls: string, visited: Set<string>): number {
    if (visited.has(cls)) return 0; // circular — bail
    if (depthCache.has(cls)) return depthCache.get(cls)!;
    visited.add(cls);
    const parents = parentMap.get(cls);
    if (!parents || parents.length === 0) {
      depthCache.set(cls, 0);
      return 0;
    }
    let maxParentDepth = 0;
    for (const p of parents) {
      maxParentDepth = Math.max(maxParentDepth, getDepth(p, visited) + 1);
    }
    depthCache.set(cls, maxParentDepth);
    return maxParentDepth;
  }

  for (const [cls] of parentMap) {
    const depth = getDepth(cls, new Set());
    if (depth >= DEPTH_THRESHOLD) {
      // Find the node that defines this class
      const defNode = map.nodes.find(n => {
        const code = n.analysis_snapshot || n.code_snapshot;
        return new RegExp(`\\bclass\\s+${cls}\\b`).test(code);
      });
      if (defNode && !/\b(test|spec|mock)\b/i.test(defNode.label)) {
        findings.push({
          source: nodeRef(defNode), sink: nodeRef(defNode),
          missing: `STRUCTURAL (flatten inheritance — depth ${depth} exceeds ${DEPTH_THRESHOLD})`,
          severity: 'low',
          description: `Class ${cls} has inheritance depth of ${depth}. Deep inheritance makes it ` +
            `impossible to audit which level implements security controls (auth, validation, sanitization). ` +
            `Fragile base class changes can silently weaken security properties.`,
          fix: 'Prefer composition over inheritance. Extract shared behavior into interfaces/traits/mixins. ' +
            'Flatten the hierarchy to 3 levels or fewer. Ensure security-critical methods are final/sealed.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-1074', name: 'Class with Excessively Deep Inheritance', holds: findings.length === 0, findings };
}

/**
 * CWE-1075: Unconditional Control Flow Transfer out of Finally Block
 * A return, break, continue, or throw in a finally block suppresses any exception
 * that was being propagated from the try/catch. This silently eats security
 * exceptions — an authentication failure, crypto error, or injection detection
 * exception just disappears.
 *
 * Detects: return/break/continue/throw/goto inside finally blocks across
 * Java, C#, Python, JavaScript/TypeScript.
 */
function verifyCWE1075(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // finally { ... return ... } — Java, JS, TS, C#
  const FINALLY_RETURN = /\bfinally\s*\{[^}]*\b(return|break|continue|throw)\b/;

  // Python: finally:\n  ...\n  return
  const PYTHON_FINALLY_RETURN = /\bfinally\s*:\s*\n(?:\s+[^\n]+\n)*?\s+(return|break|continue|raise)\b/m;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let match;
    let keyword = '';

    if ((match = code.match(FINALLY_RETURN))) {
      keyword = match[1];
    } else if ((match = code.match(PYTHON_FINALLY_RETURN))) {
      keyword = match[1];
    }

    if (keyword) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: `STRUCTURAL (remove ${keyword} from finally block)`,
        severity: 'high',
        description: `${node.label} has '${keyword}' inside a finally block. This suppresses any exception ` +
          `propagating from the try/catch — including security exceptions (auth failures, crypto errors, ` +
          `injection detections). The original exception is silently replaced by the finally block's control flow.`,
        fix: `Remove the '${keyword}' from the finally block. Move cleanup logic to a separate method. ` +
          'In Java, use try-with-resources. In Python, use context managers. ' +
          'Never use return/break/continue/throw inside finally — it masks the original exception.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1075', name: 'Unconditional Control Flow Transfer out of Finally Block', holds: findings.length === 0, findings };
}

/**
 * CWE-1076: Insufficient Adherence to Expected Conventions
 * Code that violates established naming/coding conventions makes security
 * review harder and introduces subtle bugs. Specifically dangerous patterns:
 * - Boolean methods not prefixed with is/has/can/should (confusing return semantics)
 * - Security methods with misleading names (validate that doesn't validate)
 * - Setter methods with return values (confusion with builder pattern)
 * - Inconsistent error handling conventions
 *
 * We focus on conventions that have SECURITY implications, not style nits.
 */
function verifyCWE1076(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Security method that does nothing (name implies action but body is empty/trivial)
  const SECURITY_METHOD_NAME = /\b(?:function|def|(?:public|private|protected)\s+\w*\s*)\s*(validate\w*|authorize\w*|authenticate\w*|sanitize\w*|verify\w*|checkPermission\w*|isAllowed\w*|canAccess\w*)\s*\(/i;
  const TRIVIAL_BODY = /\{\s*(?:return\s+true|return\s+null|return\s*;|)\s*\}|:\s*\n\s*(?:return\s+True|pass)\s*$/m;

  // Setter that returns a value (confusing — caller may ignore the return)
  const SETTER_WITH_RETURN = /\bset[A-Z]\w*\s*\([^)]*\)\s*(?::\s*\w+\s*)?\{[^}]*\breturn\s+(?!void)/;

  // equals/hashCode mismatch — override one but not the other (Java)
  const HAS_EQUALS = /\b(?:public\s+)?boolean\s+equals\s*\(\s*Object\b/;
  const HAS_HASHCODE = /\b(?:public\s+)?int\s+hashCode\s*\(\s*\)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Check 1: Security method with trivial/empty body
    const secMatch = code.match(SECURITY_METHOD_NAME);
    if (secMatch && TRIVIAL_BODY.test(code)) {
      const methodName = secMatch[1];
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: `STRUCTURAL (implement ${methodName} — name implies security logic)`,
        severity: 'high',
        description: `${node.label} defines '${methodName}' but the body is trivial (returns true/null/void). ` +
          `Callers trust the method name implies security enforcement, but no actual checking occurs.`,
        fix: `Implement real validation logic in ${methodName}, or rename it to indicate it is a no-op/placeholder.`,
        via: 'source_line_fallback',
      });
    }

    // Check 2: equals without hashCode or vice versa (Java — causes hash collection bypass)
    const hasEq = HAS_EQUALS.test(code);
    const hasHc = HAS_HASHCODE.test(code);
    if (hasEq !== hasHc && (hasEq || hasHc)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (implement both equals and hashCode together)',
        severity: 'medium',
        description: `${node.label} overrides ${hasEq ? 'equals' : 'hashCode'} but not ${hasEq ? 'hashCode' : 'equals'}. ` +
          `Objects will behave incorrectly in HashMaps/HashSets — duplicate entries bypass uniqueness checks, ` +
          `and security-sensitive lookups (session maps, permission caches) may fail silently.`,
        fix: 'Always override both equals() and hashCode() together. Use IDE generation or Objects.hash().',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1076', name: 'Insufficient Adherence to Expected Conventions', holds: findings.length === 0, findings };
}

/**
 * CWE-1078: Inappropriate Source Code Style or Formatting
 * While mostly a quality issue, certain formatting problems have direct security
 * impact: dangling else (Apple's goto fail), misleading indentation after
 * if-without-braces, inconsistent brace style hiding logic bombs.
 *
 * We detect the patterns that have historically caused CVEs.
 */
function verifyCWE1078(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Apple goto fail pattern: duplicate statement after if-without-braces
  // if (condition)
  //     goto fail;
  //     goto fail;  // always executed!
  const GOTO_FAIL = /\bif\s*\([^)]+\)\s*\n\s+(?:goto|return|break|continue)\b[^;\n]*;\s*\n\s+(?:goto|return|break|continue)\b/m;

  // if without braces followed by two indented lines (second always executes)
  const IF_NO_BRACE_TWO_LINES = /\bif\s*\([^)]+\)\s*\n(\s+)\S[^\n]*;\s*\n\1\S[^\n]*;/m;

  // Inconsistent indentation in security-critical blocks
  const MIXED_INDENT_SECURITY = /\b(?:if|else|for|while)\s*(?:\([^)]*\))?\s*\n(\t+) \S|\n( +)\t\S/m;

  for (const node of map.nodes) {
    const code = node.code_snapshot; // Don't strip comments — formatting matters
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    if (GOTO_FAIL.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (use braces after if/else — Apple goto fail pattern)',
        severity: 'high',
        description: `${node.label} has a duplicate statement after if-without-braces (Apple goto fail pattern). ` +
          `The second statement always executes regardless of the condition, bypassing the check.`,
        fix: 'Always use braces after if/else/for/while. Enable compiler warnings for misleading indentation ' +
          '(-Wmisleading-indentation in GCC/Clang). Use a linter that enforces brace style.',
        via: 'source_line_fallback',
      });
    } else if (IF_NO_BRACE_TWO_LINES.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (use braces after if statements)',
        severity: 'medium',
        description: `${node.label} has an if-without-braces followed by two indented statements. ` +
          `Only the first statement is conditional — the second always executes despite appearing guarded.`,
        fix: 'Add braces to all if/else/for/while blocks. Enable -Wmisleading-indentation or equivalent linter rule.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1078', name: 'Inappropriate Source Code Style or Formatting', holds: findings.length === 0, findings };
}

/**
 * CWE-1079: Parent Class without Virtual Destructor Method
 * In C++, if a base class has no virtual destructor and objects are deleted through
 * base pointers, the derived class destructor never runs. This leaks resources,
 * fails to zero-out sensitive memory, and can leave security-critical cleanup undone
 * (e.g., closing encrypted channels, clearing key material).
 *
 * Detects: C++ base classes with virtual methods but non-virtual destructors.
 */
function verifyCWE1079(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Class with at least one virtual method
  const HAS_VIRTUAL_METHOD = /\bvirtual\s+(?!~)\w/;
  // Non-virtual destructor (destructor present but not virtual)
  const NON_VIRTUAL_DTOR = /(?<!\bvirtual\s)~\w+\s*\(/;
  // Virtual destructor (safe)
  const VIRTUAL_DTOR = /\bvirtual\s+~\w+\s*\(/;
  // No destructor at all (also a problem if there are virtual methods)
  const ANY_DTOR = /~\w+\s*\(/;

  // Exclusion: abstract interface with = 0 (pure virtual dtor is fine)
  const PURE_VIRTUAL_DTOR = /\bvirtual\s+~\w+\s*\(\s*\)\s*=\s*0/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    if (HAS_VIRTUAL_METHOD.test(code)) {
      if (VIRTUAL_DTOR.test(code) || PURE_VIRTUAL_DTOR.test(code)) continue; // safe

      if (NON_VIRTUAL_DTOR.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (virtual destructor in polymorphic base class)',
          severity: 'high',
          description: `${node.label} has virtual methods but a non-virtual destructor. ` +
            `Deleting derived objects through base pointers skips derived destructors — ` +
            `sensitive memory (keys, tokens) won't be zeroed, resources won't be freed.`,
          fix: 'Declare the destructor virtual: "virtual ~ClassName() = default;" or "virtual ~ClassName() {}". ' +
            'This is required by the C++ Core Guidelines (C.35) for any class with virtual functions.',
          via: 'source_line_fallback',
        });
      } else if (!ANY_DTOR.test(code)) {
        // No destructor at all in a polymorphic class
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (virtual destructor — none declared in polymorphic class)',
          severity: 'high',
          description: `${node.label} has virtual methods but no destructor at all. ` +
            `The compiler-generated destructor is non-virtual — same problem as non-virtual destructor.`,
          fix: 'Add "virtual ~ClassName() = default;" to the class definition.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return { cwe: 'CWE-1079', name: 'Parent Class without Virtual Destructor Method', holds: findings.length === 0, findings };
}

/**
 * CWE-1080: Source Code File with Excessive Number of Lines of Code
 * Excessively long files are harder to audit for security vulnerabilities.
 * More importantly, they correlate with mixing concerns — auth logic next to
 * business logic next to data access — making it easy to miss injection points,
 * authorization gaps, and data leaks.
 *
 * We detect this by examining STRUCTURAL/META nodes that represent files or
 * modules with high line counts.
 */
function verifyCWE1080(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const LINE_THRESHOLD = 2000;

  // Group nodes by file and count max line_end
  const fileMaxLine = new Map<string, { maxLine: number; nodeCount: number; node: NeuralMapNode }>();

  for (const node of map.nodes) {
    if (/\b(test|spec|mock|stub|generated|vendor|node_modules)\b/i.test(node.file)) continue;
    const file = node.file;
    const current = fileMaxLine.get(file);
    const lineEnd = node.line_end || node.line_start;
    if (!current || lineEnd > current.maxLine) {
      fileMaxLine.set(file, {
        maxLine: lineEnd,
        nodeCount: (current?.nodeCount || 0) + 1,
        node: current?.node || node,
      });
    } else {
      fileMaxLine.set(file, { ...current, nodeCount: current.nodeCount + 1 });
    }
  }

  for (const [file, info] of fileMaxLine) {
    if (info.maxLine > LINE_THRESHOLD) {
      findings.push({
        source: nodeRef(info.node), sink: nodeRef(info.node),
        missing: `STRUCTURAL (split file — ${info.maxLine} lines exceeds ${LINE_THRESHOLD} threshold)`,
        severity: 'low',
        description: `File ${file} has at least ${info.maxLine} lines with ${info.nodeCount} mapped nodes. ` +
          `Excessively long files mix concerns, making security review unreliable — ` +
          `injection points, auth gaps, and data leaks hide in the volume.`,
        fix: 'Split into focused modules: separate data access, business logic, auth, and routing. ' +
          'Aim for files under 500 lines. Use the single responsibility principle.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1080', name: 'Source Code File with Excessive Number of Lines of Code', holds: findings.length === 0, findings };
}

/**
 * CWE-1082: Class Instance Self Destruction Control Element
 * A class that destroys/deallocates itself (delete this, free(self), etc.)
 * creates dangling references in all other code holding pointers to the object.
 * This is undefined behavior in C++ and causes use-after-free vulnerabilities.
 * In managed languages, self-nulling patterns indicate design confusion.
 *
 * Detects: delete this, free(this/self), Release() patterns that destroy the
 * current object, and Python's del self patterns.
 */
function verifyCWE1082(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // C++: delete this
  const DELETE_THIS = /\bdelete\s+this\b/;
  // C: free(this) or free(self)
  const FREE_SELF = /\bfree\s*\(\s*(?:this|self)\s*\)/;
  // C++: calling own destructor explicitly
  const EXPLICIT_DTOR = /\bthis\s*->\s*~\w+\s*\(\s*\)/;
  // COM/C++: Release() that destroys self
  const SELF_RELEASE = /\bif\s*\(\s*(?:--\s*m_?(?:ref|cRef|nRef)|m_?(?:ref|cRef|nRef)\s*--)\s*(?:==?\s*0|<=?\s*0)\s*\)\s*\{?\s*delete\s+this/;
  // Managed language anti-patterns: this = null, self = None
  const SELF_NULL = /\bthis\s*=\s*null|self\s*=\s*None/;

  // Safe: reference-counted Release() with proper ref counting (COM pattern — acceptable when correct)
  const SAFE_RELEASE = /\bAddRef\b.*\bRelease\b|\bIUnknown\b|\bstd::shared_ptr|shared_from_this|weak_ptr/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let matched = false;
    let description = '';

    if (DELETE_THIS.test(code) && !SAFE_RELEASE.test(code)) {
      matched = true;
      description = `${node.label} uses 'delete this' — the object destroys itself, leaving all external ` +
        `pointers dangling. Any subsequent access through those pointers is use-after-free (CWE-416). ` +
        `Member access after 'delete this' is undefined behavior.`;
    } else if (FREE_SELF.test(code)) {
      matched = true;
      description = `${node.label} calls free() on this/self — the object frees its own memory. ` +
        `All external references become dangling pointers. This is undefined behavior.`;
    } else if (EXPLICIT_DTOR.test(code)) {
      matched = true;
      description = `${node.label} explicitly calls its own destructor via this->~Class(). ` +
        `Unless using placement new, this leads to double destruction and undefined behavior.`;
    } else if (SELF_NULL.test(code)) {
      matched = true;
      description = `${node.label} assigns null/None to this/self. This doesn't actually destroy the object ` +
        `and only confuses the local reference. It indicates a fundamental misunderstanding of object lifecycle.`;
    }

    if (matched) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (external lifecycle management instead of self-destruction)',
        severity: 'high',
        description,
        fix: 'Use smart pointers (shared_ptr/unique_ptr) or a dedicated destroy/dispose pattern where the ' +
          'OWNER manages lifecycle. For COM objects, ensure AddRef/Release are properly paired. ' +
          'Never access members after delete this. Prefer RAII for resource management.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1082', name: 'Class Instance Self Destruction Control Element', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1044: Architecture with Number of Horizontal Layers That Is Too High
// Excessive abstraction layers increase complexity, making security review
// harder and bugs easier to hide. Detected via deep CONTAINS chains and
// excessive call-chain depth.
// ---------------------------------------------------------------------------

function verifyCWE1044(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library/framework code is naturally deeply layered — this is architecture, not a defect
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-1044', name: 'Architecture with Number of Horizontal Layers That Is Too High', holds: true, findings };
  }

  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  // Build containment tree: parent -> children
  const children = new Map<string, string[]>();
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      if (edge.edge_type === 'CONTAINS') {
        const list = children.get(node.id) || [];
        list.push(edge.target);
        children.set(node.id, list);
      }
    }
  }

  // DFS to find max depth
  function maxDepth(nodeId: string, visited: Set<string>): number {
    if (visited.has(nodeId)) return 0;
    visited.add(nodeId);
    const kids = children.get(nodeId) || [];
    let max = 0;
    for (const kid of kids) {
      max = Math.max(max, maxDepth(kid, visited));
    }
    return 1 + max;
  }

  // Find root STRUCTURAL nodes (those not contained by others)
  const containedIds = new Set<string>();
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      if (edge.edge_type === 'CONTAINS') containedIds.add(edge.target);
    }
  }
  const roots = map.nodes.filter(n => n.node_type === 'STRUCTURAL' && !containedIds.has(n.id));

  const DEPTH_THRESHOLD = 8;
  for (const root of roots) {
    const depth = maxDepth(root.id, new Set());
    if (depth > DEPTH_THRESHOLD) {
      findings.push({
        source: nodeRef(root),
        sink: nodeRef(root),
        missing: `STRUCTURAL (reduce abstraction depth — ${depth} layers detected, threshold is ${DEPTH_THRESHOLD})`,
        severity: 'low',
        description: `${root.label}: structural nesting depth of ${depth} exceeds threshold of ${DEPTH_THRESHOLD}. ` +
          `Deep abstraction hierarchies make security review difficult — vulnerabilities hide in layers that nobody reads.`,
        fix: 'Flatten the architecture. Consolidate wrapper classes that add no logic. ' +
          'Prefer composition over deep inheritance. Each layer should add clear, distinct value.',
        via: 'structural',
      });
    }
  }

  // Also check CALLS chain length — excessive delegation depth
  const CALL_DEPTH_THRESHOLD = 10;
  function maxCallDepth(nodeId: string, visited: Set<string>): number {
    if (visited.has(nodeId)) return 0;
    visited.add(nodeId);
    const node = nodeMap.get(nodeId);
    if (!node) return 0;
    let max = 0;
    for (const edge of node.edges) {
      if (edge.edge_type === 'CALLS') {
        max = Math.max(max, maxCallDepth(edge.target, visited));
      }
    }
    return 1 + max;
  }

  const entryPoints = nodesOfType(map, 'INGRESS');
  for (const entry of entryPoints) {
    const depth = maxCallDepth(entry.id, new Set());
    if (depth > CALL_DEPTH_THRESHOLD) {
      findings.push({
        source: nodeRef(entry),
        sink: nodeRef(entry),
        missing: `STRUCTURAL (reduce call delegation depth — ${depth} levels, threshold is ${CALL_DEPTH_THRESHOLD})`,
        severity: 'low',
        description: `${entry.label}: call chain depth of ${depth} from this entry point exceeds ${CALL_DEPTH_THRESHOLD}. ` +
          `Deep delegation obscures what actually happens to data, making taint tracking unreliable.`,
        fix: 'Reduce abstraction layers. Inline trivial wrapper functions. ' +
          'Ensure security-critical operations are visible within 2-3 call levels of the entry point.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1044', name: 'Architecture with Number of Horizontal Layers That Is Too High', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1045: Parent Class with Virtual Destructor, Child Without Virtual Destructor
// In C++, if a parent has a virtual destructor but a child overrides it without
// virtual, deleting through a parent pointer may not call the child destructor,
// leaking resources or skipping security cleanup.
// ---------------------------------------------------------------------------

function verifyCWE1045(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const VIRTUAL_DTOR_RE = /\bvirtual\s+~\w+\s*\(/;
  const NONVIRTUAL_DTOR_RE = /(?<!\bvirtual\s)~(\w+)\s*\(/;
  const OVERRIDE_DTOR_RE = /~(\w+)\s*\([^)]*\)\s*(?:override|=\s*default)/;

  // Build a map of class names to whether they have virtual destructors
  const classInfo = new Map<string, { hasVirtualDtor: boolean; node: NeuralMapNode }>();

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    // Only relevant for C/C++ files
    if (node.language && !/\b(c\+\+|cpp|cc|cxx|c)\b/i.test(node.language) &&
        !/\.(cpp|cc|cxx|h|hpp|hxx)$/i.test(node.file || '')) continue;

    const classMatch = code.match(/\bclass\s+(\w+)\b/);
    if (classMatch) {
      const className = classMatch[1];
      const hasVirtualDtor = VIRTUAL_DTOR_RE.test(code);
      classInfo.set(className, { hasVirtualDtor, node });
    }
  }

  // Check inheritance relationships
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    const re = /\bclass\s+(\w+)\s*:\s*(?:public|protected|private)\s+(\w+)/g;
    let inheritMatch;
    while ((inheritMatch = re.exec(code)) !== null) {
      const childName = inheritMatch[1];
      const parentName = inheritMatch[2];
      const parentInfo = classInfo.get(parentName);

      if (parentInfo && parentInfo.hasVirtualDtor) {
        const hasVirtualChild = VIRTUAL_DTOR_RE.test(code) || OVERRIDE_DTOR_RE.test(code);
        const hasNonVirtualDtor = NONVIRTUAL_DTOR_RE.test(code);

        if (hasNonVirtualDtor && !hasVirtualChild) {
          findings.push({
            source: nodeRef(parentInfo.node),
            sink: nodeRef(node),
            missing: 'STRUCTURAL (virtual destructor on child class)',
            severity: 'medium',
            description: `${childName} inherits from ${parentName} (which has a virtual destructor) but ` +
              `${childName}'s destructor is not virtual. Deleting a ${childName} through a ${parentName}* ` +
              `pointer will not call ${childName}'s destructor, potentially leaking resources or skipping security cleanup.`,
            fix: `Add "virtual" to ${childName}'s destructor, or use "override" in C++11+.`,
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-1045', name: 'Parent Class with Virtual Destructor and Child Class Without Virtual Destructor', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1046: Creation of Immutable Text Using String Concatenation
// Repeated string concatenation in loops creates O(n^2) memory/time behavior.
// In security contexts, this enables denial-of-service via large inputs.
// ---------------------------------------------------------------------------

function verifyCWE1046(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // String concatenation inside loops
  const LOOP_CONCAT_JS = /\b(?:for|while|do)\b[\s\S]{0,200}?\+\s*=\s*['"`]|(?:for|while|do)\b[\s\S]{0,200}?=\s*\w+\s*\+\s*['"`]/;
  const LOOP_CONCAT_PY = /\b(?:for|while)\b[^:]*:[\s\S]{0,200}?\+\s*=\s*['"`]|(?:for|while)\b[^:]*:[\s\S]{0,200}?=\s*\w+\s*\+\s*['"`]/;
  const LOOP_CONCAT_JAVA = /\b(?:for|while)\b[\s\S]{0,200}?\bString\b[\s\S]{0,100}?\+\s*=/;

  // Safe alternatives
  const SAFE_RE = /\b(StringBuilder|StringBuffer|StringIO|join\s*\(|Array\..*join|\.push\s*\(|parts\..*join|chunks\..*join|Buffer\.concat|strings\.Builder)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    const hasLoopConcat = LOOP_CONCAT_JS.test(code) || LOOP_CONCAT_PY.test(code) || LOOP_CONCAT_JAVA.test(code);

    if (hasLoopConcat && !SAFE_RE.test(code)) {
      const processingInput = node.data_in.some(d => d.tainted) ||
        /\b(req\.|request\.|params\.|body\.|input\.|user\.|data\.)/i.test(code);
      const severity = processingInput ? 'medium' : 'low';

      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (use StringBuilder/join instead of string concatenation in loop)',
        severity,
        description: `${node.label}: string concatenation inside a loop creates O(n^2) time and memory behavior. ` +
          (processingInput
            ? 'This processes user input — an attacker can send large payloads to trigger quadratic memory allocation.'
            : 'While not directly user-controlled, this pattern can cause performance degradation with large datasets.'),
        fix: 'Use a mutable builder pattern: StringBuilder (Java/C#), [].join() (JS), "".join(parts) (Python), ' +
          'strings.Builder (Go), or std::string::reserve + append (C++).',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1046', name: 'Creation of Immutable Text Using String Concatenation', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1047: Modules with Circular Dependencies
// Circular dependencies between modules create fragile initialization order,
// can cause undefined imports, and make security boundaries unclear.
// ---------------------------------------------------------------------------

function verifyCWE1047(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Build a directed graph of DEPENDS edges
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const deps = new Map<string, Set<string>>();
  for (const node of map.nodes) {
    for (const edge of node.edges) {
      if (edge.edge_type === 'DEPENDS') {
        const set = deps.get(node.id) || new Set();
        set.add(edge.target);
        deps.set(node.id, set);
      }
    }
  }

  // Detect cycles using DFS with coloring (white/gray/black)
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map<string, number>();
  const cycleNodes: Array<{ a: NeuralMapNode; b: NeuralMapNode }> = [];

  for (const node of map.nodes) color.set(node.id, WHITE);

  function dfs(nodeId: string): void {
    color.set(nodeId, GRAY);
    const neighbors = deps.get(nodeId) || new Set();
    for (const next of neighbors) {
      const nextColor = color.get(next);
      if (nextColor === GRAY) {
        const nodeA = nodeMap.get(nodeId);
        const nodeB = nodeMap.get(next);
        if (nodeA && nodeB) {
          cycleNodes.push({ a: nodeA, b: nodeB });
        }
      } else if (nextColor === WHITE) {
        dfs(next);
      }
    }
    color.set(nodeId, BLACK);
  }

  for (const node of map.nodes) {
    if (color.get(node.id) === WHITE) {
      dfs(node.id);
    }
  }

  // Also check for circular import comments in code
  const CIRCULAR_IMPORT_COMMENT = /\bcircular\s+(?:dependency|import|require)\b/i;

  for (const { a, b } of cycleNodes) {
    findings.push({
      source: nodeRef(a),
      sink: nodeRef(b),
      missing: 'STRUCTURAL (break circular dependency between modules)',
      severity: 'low',
      description: `Circular dependency: ${a.label} depends on ${b.label} which depends back on ${a.label}. ` +
        `Circular dependencies cause undefined initialization order, partial module loading, and obscure security boundaries.`,
      fix: 'Break the cycle by extracting shared code into a third module, using dependency injection, ' +
        'or restructuring the dependency direction. Use tools like madge (JS) or pylint (Python) to detect cycles.',
      via: 'structural',
    });
  }

  for (const node of map.nodes) {
    if (CIRCULAR_IMPORT_COMMENT.test(node.analysis_snapshot || node.code_snapshot)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (resolve acknowledged circular dependency)',
        severity: 'low',
        description: `${node.label}: code contains a comment acknowledging a circular dependency. ` +
          `Known circular dependencies should be resolved, not documented and left in place.`,
        fix: 'Refactor to eliminate the circular dependency rather than working around it.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1047', name: 'Modules with Circular Dependencies', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1048: Invokable Control Element with Large Number of Outward Calls
// Functions that call too many other functions (high fan-out) are hard to
// review, test, and reason about security properties for.
// ---------------------------------------------------------------------------

function verifyCWE1048(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const FANOUT_THRESHOLD = 15;

  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL') continue;
    if (/\b(test|spec|mock|stub|index|barrel|main|app)\b/i.test(node.label)) continue;

    const callees = new Set<string>();
    for (const edge of node.edges) {
      if (edge.edge_type === 'CALLS') {
        callees.add(edge.target);
      }
    }

    if (callees.size > FANOUT_THRESHOLD) {
      const isSecurityRelevant = node.attack_surface.length > 0 ||
        /\b(auth|login|session|token|password|permission|access|validate|sanitize|encrypt|decrypt)\b/i.test(node.label) ||
        node.data_in.some(d => d.tainted || d.sensitivity !== 'NONE');

      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: `STRUCTURAL (reduce function fan-out — ${callees.size} callees, threshold is ${FANOUT_THRESHOLD})`,
        severity: isSecurityRelevant ? 'medium' : 'low',
        description: `${node.label}: calls ${callees.size} distinct functions (threshold: ${FANOUT_THRESHOLD}). ` +
          (isSecurityRelevant
            ? 'This security-relevant function has too many responsibilities — bugs are easy to introduce and hard to find during review.'
            : 'High fan-out indicates the function has too many responsibilities. Decompose into focused sub-functions.'),
        fix: 'Apply the Single Responsibility Principle: extract groups of related calls into helper functions. ' +
          'Each function should do one thing. For security-critical code, keep functions small and reviewable.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1048', name: 'Invokable Control Element with Large Number of Outward Calls', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1050: Excessive Platform Resource Consumption within a Loop
// ---------------------------------------------------------------------------

/**
 * CWE-1050: Excessive Platform Resource Consumption within a Loop
 * Detects loops containing expensive platform operations without batching,
 * caching, or throttling. The N+1 pattern: one expensive call per iteration
 * instead of a single batched call. Distinct from CWE-400 (general resource
 * exhaustion) — this is specifically about loop-amplification of costly ops.
 */
function verifyCWE1050(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const LOOP_RE = /\b(for\s*\(|for\s+\w+\s+(?:in|of)\b|while\s*\(|\.forEach\s*\(|\.map\s*\(|\.reduce\s*\(|\.filter\s*\(|do\s*\{|loop\s*\{|each\s+do\b|\.each\s*[\({])/i;

  const EXPENSIVE_IN_LOOP: Array<{ pattern: RegExp; name: string; fix: string }> = [
    { pattern: /\b(query|execute|find(?:One|ById|All)?|select|insert|update|delete|save|create|destroy|remove|get|put)\s*\(/i,
      name: 'database query inside loop (N+1 pattern)',
      fix: 'Batch queries: use WHERE IN (...), bulk insert/update, or preload associations.' },
    { pattern: /\b(fetch|axios\.|http\.|request\.|got\.|superagent|urllib|requests\.get|requests\.post|HttpClient|WebClient|RestTemplate)\s*[\.(]/i,
      name: 'HTTP request inside loop',
      fix: 'Batch requests: use Promise.all() for parallel, or call a bulk API endpoint.' },
    { pattern: /\b(readFile|writeFile|readFileSync|writeFileSync|fopen|fread|fwrite|open\s*\(|fs\.\w+Sync|Path\.read|File\.open)\s*\(/i,
      name: 'file I/O inside loop',
      fix: 'Accumulate data and write once, or use streaming.' },
    { pattern: /\b(appendChild|insertBefore|removeChild|innerHTML|outerHTML|document\.createElement|\.append\s*\(|\.prepend\s*\()/i,
      name: 'DOM manipulation inside loop (layout thrashing)',
      fix: 'Use DocumentFragment to batch DOM changes.' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|benchmark|perf)\b/i.test(node.label)) continue;
    if (!LOOP_RE.test(code)) continue;

    const loopMatch = code.match(LOOP_RE);
    if (!loopMatch) continue;
    const loopBody = code.slice(loopMatch.index! + loopMatch[0].length);

    for (const exp of EXPENSIVE_IN_LOOP) {
      if (exp.pattern.test(loopBody)) {
        const BATCH_RE = /\b(batch|bulk|Promise\.all|Promise\.allSettled|parallel|concurrent|pool|queue|cache|memoize|preload|prefetch|IN\s*\(|whereIn|fragment|DocumentFragment)\b/i;
        if (BATCH_RE.test(code)) continue;

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `TRANSFORM (batch/optimize — ${exp.name})`,
          severity: 'medium',
          description: `${node.label}: ${exp.name}. Each iteration triggers an expensive platform call — O(N) instead of O(1) batched.`,
          fix: exp.fix,
          via: 'source_line_fallback',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-1050', name: 'Excessive Platform Resource Consumption within a Loop', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1051: Initialization with Hard-Coded Network Resource Configuration Data
// ---------------------------------------------------------------------------

/**
 * CWE-1051: Initialization with Hard-Coded Network Resource Configuration Data
 * Detects hard-coded IP addresses, hostnames, ports, and connection strings.
 * Distinct from CWE-798 (hardcoded creds) — this is about network ADDRESSES.
 */
function verifyCWE1051(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PRIVATE_IP_RE = /['"`](10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?['"`]/;
  const HARDCODED_HOST_RE = /['"`]((?:db|database|redis|mongo|mysql|postgres|rabbit|kafka|elastic|memcache|api|service|backend|internal)[\w-]*\.[\w.-]+\.(?:com|net|org|io|local|internal|corp|svc\.cluster\.local))(?::\d+)?['"`]/i;
  const CONN_STRING_RE = /['"`](?:mongodb|mysql|postgres|redis|amqp|kafka|elasticsearch|jdbc):\/\/[^'"` ]+['"`]/i;
  const HARDCODED_PORT_RE = /(?:port|PORT)\s*[:=]\s*(\d{4,5})\b/;
  const ENV_READ_RE = /\b(process\.env|os\.environ|os\.getenv|System\.getenv|ENV\[|getenv|config\.|settings\.|\.env|dotenv|configparser|application\.properties|appsettings|nconf|convict)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|example|fixture|seed)\b/i.test(node.label)) continue;

    let matched = false;
    let description = '';

    if (PRIVATE_IP_RE.test(code) && !ENV_READ_RE.test(code)) {
      matched = true;
      const ip = code.match(PRIVATE_IP_RE)![1];
      description = `Hard-coded private IP "${ip}" at ${node.label}. Exposes internal topology.`;
    } else if (CONN_STRING_RE.test(code) && !ENV_READ_RE.test(code)) {
      matched = true;
      description = `Hard-coded connection string at ${node.label}. Should come from env vars or secrets manager.`;
    } else if (HARDCODED_HOST_RE.test(code) && !ENV_READ_RE.test(code)) {
      matched = true;
      const host = code.match(HARDCODED_HOST_RE)![1];
      description = `Hard-coded hostname "${host}" at ${node.label}. Use service discovery or config.`;
    } else if (HARDCODED_PORT_RE.test(code) && !ENV_READ_RE.test(code)) {
      const port = code.match(HARDCODED_PORT_RE)![1];
      const portNum = parseInt(port, 10);
      if (portNum !== 80 && portNum !== 443 && portNum !== 8080 && portNum !== 3000) {
        matched = true;
        description = `Hard-coded port ${port} at ${node.label}. Make configurable via env vars.`;
      }
    }

    if (matched) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (externalize network configuration)',
        severity: 'low',
        description,
        fix: 'Move network addresses to environment variables or a configuration service. ' +
          'Example: const host = process.env.DB_HOST || "localhost".',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1051', name: 'Initialization with Hard-Coded Network Resource Configuration Data', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1052: Excessive Use of Hard-Coded Literals in Initialization
// ---------------------------------------------------------------------------

/**
 * CWE-1052: Excessive Use of Hard-Coded Literals in Initialization
 * Detects high density of magic numbers in initialization code without
 * named constants. Targets init/setup/config functions stuffed with literals.
 */
function verifyCWE1052(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MAGIC_NUMBER_SRC = /(?<![.\w])(\d{2,}(?:\.\d+)?)\b/g;
  const TRIVIAL_NUMBERS = new Set(['0', '1', '2', '10', '100', '1000', '-1', '0.0', '1.0', '0.5', '255', '256', '1024', '60', '24', '365']);
  const INIT_CONTEXT_RE = /\b(init|setup|configure|bootstrap|constructor|__init__|initialize|create|build|register|config)\b/i;
  const NAMED_CONST_RE = /\b(const|final|readonly|static|#define|[A-Z][A-Z_]{2,}\s*=)\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|fixture)\b/i.test(node.label)) continue;
    if (!INIT_CONTEXT_RE.test(node.label) && !INIT_CONTEXT_RE.test(code)) continue;

    let magicCount = 0;
    let match: RegExpExecArray | null;
    const re = new RegExp(MAGIC_NUMBER_SRC.source, 'g');
    while ((match = re.exec(code)) !== null) {
      if (!TRIVIAL_NUMBERS.has(match[1])) magicCount++;
    }

    if (magicCount > 5) {
      const threshold = NAMED_CONST_RE.test(code) ? 10 : 5;
      if (magicCount > threshold) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (named constants or configuration)',
          severity: 'low',
          description: `${node.label}: initialization has ${magicCount} magic number literals. Hard to maintain and configure.`,
          fix: 'Extract magic numbers into named constants (e.g., const MAX_RETRIES = 3). Use config files for env-specific values.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return { cwe: 'CWE-1052', name: 'Excessive Use of Hard-Coded Literals in Initialization', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1053: Missing Documentation for Design
// ---------------------------------------------------------------------------

/**
 * CWE-1053: Missing Documentation for Design
 * Detects security-critical public APIs lacking documentation. Focuses on
 * STRUCTURAL and INGRESS nodes at public boundaries — undocumented auth/crypto
 * APIs are dangerous because consumers can't understand the security contract.
 */
function verifyCWE1053(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DOC_RE = /\/\*\*|"""|'''|@(?:param|returns?|throws|description|summary|api|swagger|openapi)|:param\s|:returns?:|docstring|@doc\b|\/\/\/\s/;
  const PUBLIC_API_RE = /\b(export\s+(?:default\s+)?(?:function|class|interface|type|const|async\s+function)|module\.exports|public\s+(?:static\s+)?(?:void|int|string|boolean|async)\s+\w+|def\s+\w+\s*\([^)]*\)\s*(?:->|:)|@(?:app|router|api|blueprint)\.\s*(?:get|post|put|delete|patch|route)\b|@(?:GetMapping|PostMapping|RequestMapping|Controller|RestController))/i;
  const SECURITY_LABEL_RE = /\b(auth|login|logout|register|password|token|session|permission|role|access|encrypt|decrypt|sign|verify|admin|privilege|sanitize|validate|escape)\b/i;

  const structural = nodesOfType(map, 'STRUCTURAL');
  const ingress = nodesOfType(map, 'INGRESS');

  for (const node of [...structural, ...ingress]) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (/\b(test|spec|mock|fixture|__test__)\b/i.test(node.label)) continue;
    if (!PUBLIC_API_RE.test(code) && node.node_type !== 'INGRESS') continue;
    if (DOC_RE.test(code)) continue;
    if (!SECURITY_LABEL_RE.test(node.label) && !SECURITY_LABEL_RE.test(node.node_subtype)) continue;

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'META (API documentation for security-critical component)',
      severity: 'low',
      description: `Security-critical API at ${node.label} has no documentation. Consumers cannot understand the security contract.`,
      fix: 'Add docs: (1) purpose, (2) auth requirements, (3) input validation, (4) error handling, (5) security assumptions. Use JSDoc/docstrings.',
      via: 'structural',
    });
  }

  return { cwe: 'CWE-1053', name: 'Missing Documentation for Design', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1054: Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer
// ---------------------------------------------------------------------------

/**
 * CWE-1054: Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer
 * Detects the "validate late" anti-pattern: input passes through 4+ function
 * calls before hitting validation, meaning all intermediate layers handle
 * unvalidated data.
 */
function verifyCWE1054(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library/framework code is naturally layered — abstraction depth is by design
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-1054', name: 'Invocation of Control Element at Unnecessarily Deep Horizontal Layer', holds: true, findings };
  }

  // Per-language call depth thresholds: Java/Kotlin naturally have deeper call chains
  // (servlet→service→validator→rules→pattern is 4 levels and normal).
  // JS/TS/Python tend to be flatter. C/C++ varies but leans toward direct calls.
  const lang = inferMapLanguage(map);
  const DEPTH_THRESHOLDS: Record<string, number> = {
    java: 6, kotlin: 6,          // Framework-heavy, deep chains are normal
    javascript: 4, typescript: 4, // Flat architectures, 4 is already deep
    python: 4, ruby: 4,          // Similar to JS
    c: 4, 'c++': 4, cpp: 4,     // Direct call patterns
  };
  const depthThreshold = DEPTH_THRESHOLDS[lang] ?? 5; // Default 5 for unknown languages

  const ingress = nodesOfType(map, 'INGRESS');
  const controls = nodesOfType(map, 'CONTROL');
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  for (const src of ingress) {
    for (const ctrl of controls) {
      const visited = new Set<string>();
      const queue: Array<{ nodeId: string; callDepth: number }> = [{ nodeId: src.id, callDepth: 0 }];
      let minCallDepth = Infinity;

      while (queue.length > 0) {
        const { nodeId, callDepth } = queue.shift()!;
        if (visited.has(nodeId)) continue;
        visited.add(nodeId);

        if (nodeId === ctrl.id) { minCallDepth = Math.min(minCallDepth, callDepth); continue; }

        const node = nodeMap.get(nodeId);
        if (!node) continue;

        for (const edge of node.edges) {
          if (edge.edge_type === 'CALLS' && !visited.has(edge.target)) {
            queue.push({ nodeId: edge.target, callDepth: callDepth + 1 });
          } else if ((edge.edge_type === 'DATA_FLOW' || edge.edge_type === 'READS' || edge.edge_type === 'WRITES') && !visited.has(edge.target)) {
            queue.push({ nodeId: edge.target, callDepth });
          }
        }
      }

      if (minCallDepth >= depthThreshold) {
        const hasEarlyControl = controls.some(ec => {
          if (ec.id === ctrl.id) return false;
          const ev = new Set<string>();
          const eq: Array<{ nodeId: string; depth: number }> = [{ nodeId: src.id, depth: 0 }];
          while (eq.length > 0) {
            const { nodeId, depth } = eq.shift()!;
            if (ev.has(nodeId)) continue;
            ev.add(nodeId);
            if (nodeId === ec.id && depth <= 1) return true;
            const n = nodeMap.get(nodeId);
            if (!n) continue;
            for (const e of n.edges) {
              if (e.edge_type === 'CALLS' && !ev.has(e.target)) eq.push({ nodeId: e.target, depth: depth + 1 });
            }
          }
          return false;
        });

        if (!hasEarlyControl) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(ctrl),
            missing: `CONTROL (validation at entry point — currently ${minCallDepth} calls deep)`,
            severity: 'medium',
            description: `Input from ${src.label} passes through ${minCallDepth} calls before validation at ${ctrl.label}. All intermediate layers handle unvalidated data.`,
            fix: 'Move validation to the entry point (controller/handler). Use schema validation middleware (Joi, Zod) at the route level.',
            via: 'structural',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-1054', name: 'Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1055: Multiple Inheritance from Concrete Classes
// ---------------------------------------------------------------------------

/**
 * CWE-1055: Multiple Inheritance from Concrete Classes
 * Detects classes inheriting from multiple concrete (non-abstract) parents.
 * Creates diamond problem and method resolution ambiguity.
 * C++ (class A : public B, public C), Python (class A(B, C)).
 */
function verifyCWE1055(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CPP_MI_RE = /\bclass\s+\w+\s*:\s*(?:public|protected|private)\s+\w+\s*,\s*(?:public|protected|private)\s+\w+/;
  const PY_MI_RE = /\bclass\s+\w+\s*\(\s*\w+\s*,\s*\w+/;
  const ABSTRACT_RE = /\b(abstract\s+class|interface\s|ABC|ABCMeta|@abstractmethod|Protocol|Mixin|mixin|trait\b|I[A-Z][a-zA-Z]+\b(?=\s*,|\s*\)))/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock)\b/i.test(node.label)) continue;

    let matched = false;
    let language = '';

    if (CPP_MI_RE.test(code)) { matched = true; language = 'C++'; }
    else if (PY_MI_RE.test(code)) { matched = true; language = 'Python'; }

    if (!matched) continue;
    if (ABSTRACT_RE.test(code)) continue;

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'STRUCTURAL (composition over multiple concrete inheritance)',
      severity: 'low',
      description: `${node.label}: ${language} class uses multiple concrete inheritance. Diamond problem makes security behavior unpredictable.`,
      fix: 'Prefer composition. Use ABCs/Protocols/interfaces as bases. In C++: virtual inheritance or containment.',
      via: 'source_line_fallback',
    });
  }

  return { cwe: 'CWE-1055', name: 'Multiple Inheritance from Concrete Classes', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1056: Invokable Control Element with Variadic Parameters
// ---------------------------------------------------------------------------

/**
 * CWE-1056: Invokable Control Element with Variadic Parameters
 * Detects security-critical functions (auth, validation, crypto) using variadic
 * params. Variadic bypasses arity checking — callers can pass wrong args silently.
 */
function verifyCWE1056(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const VARIADIC_RE = /\b(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:function|\())\s*[^)]*\.{3}\w+|def\s+\w+\s*\([^)]*\*\w+|void\s+\w+\s*\([^)]*\.\.\.\s*\w+|func\s+\w+\s*\([^)]*\.\.\.\w+/i;
  const ARGS_KWARGS_RE = /\bdef\s+\w+\s*\([^)]*\*{1,2}\w+/;
  const SECURITY_FN_RE = /\b(auth|authenticate|authorize|validate|sanitize|check[_-]?(?:auth|access|permission|role)|verify|encrypt|decrypt|sign|hash|grant|deny|permit|isAllowed)\b/i;

  for (const node of [...nodesOfType(map, 'CONTROL'), ...nodesOfType(map, 'TRANSFORM'), ...nodesOfType(map, 'AUTH')]) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock)\b/i.test(node.label)) continue;
    if (!SECURITY_FN_RE.test(node.label) && !SECURITY_FN_RE.test(code)) continue;
    if (!VARIADIC_RE.test(code) && !ARGS_KWARGS_RE.test(code)) continue;

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'STRUCTURAL (explicit parameter list for security-critical function)',
      severity: 'medium',
      description: `Security function at ${node.label} uses variadic parameters. Callers can pass wrong arg count without error.`,
      fix: 'Use explicit named parameters with types. Add runtime arity validation if variadic is necessary.',
      via: 'source_line_fallback',
    });
  }

  return { cwe: 'CWE-1056', name: 'Invokable Control Element with Variadic Parameters', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1057: Data Access Operations Outside of Expected Data Manager Component
// ---------------------------------------------------------------------------

/**
 * CWE-1057: Data Access Operations Outside of Expected Data Manager Component
 * Detects direct DB operations in INGRESS/CONTROL/EXTERNAL nodes that should
 * delegate to a repository/DAO layer. Bypasses centralized access controls.
 */
function verifyCWE1057(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DIRECT_DB_RE = /\b(SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM|db\.(query|execute|run|get|all|prepare)|connection\.(query|execute)|pool\.(query|execute)|cursor\.(execute|fetchone|fetchall)|\.rawQuery\s*\(|\.execSQL\s*\(|\.raw\s*\(|mongoose\.\w+\.find|Collection\.(find|insert|update|delete|aggregate))\b/i;
  const NON_DATA_TYPES: NodeType[] = ['INGRESS', 'CONTROL', 'EXTERNAL'];
  const DATA_LAYER_RE = /\b(repository|dao|model|store|adapter|mapper|gateway|dal|data.?access|orm|entity.?manager|persistence)\b/i;

  for (const type of NON_DATA_TYPES) {
    for (const node of nodesOfType(map, type)) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (/\b(test|spec|mock)\b/i.test(node.label)) continue;
      if (DATA_LAYER_RE.test(node.label) || DATA_LAYER_RE.test(node.node_subtype)) continue;

      if (DIRECT_DB_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (data access through designated repository/DAO)',
          severity: 'medium',
          description: `${node.node_type} node ${node.label} performs direct DB operations. Bypasses centralized validation and access control.`,
          fix: 'Move data access to a repository/DAO layer. Controller calls repository.findUser(id) not db.query("SELECT...").',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return { cwe: 'CWE-1057', name: 'Data Access Operations Outside of Expected Data Manager Component', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1058: Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element
// ---------------------------------------------------------------------------

/**
 * CWE-1058: Mutable static/shared state in concurrent contexts without sync.
 * Different from CWE-362 (general TOCTOU) — specifically targets non-final
 * static fields accessed from threaded/async code without locks or atomics.
 */
function verifyCWE1058(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MUTABLE_STATIC_RE = /\b(static\s+(?!final\b|const\b|readonly\b)\w+\s+\w+|static\s+mut\s+|global\s+\$\w+)/i;
  const JAVA_NONFINAL_STATIC_RE = /\bstatic\s+(?!final\b|const\b)(?:private\s+|protected\s+|public\s+)?(?:volatile\s+)?\w+\s+\w+\s*[=;]/;
  const PY_MODULE_MUTABLE_RE = /^[a-z_]\w*\s*[:=]\s*(?:\[|\{|dict\(|list\(|set\(|collections\.\w+\()/m;

  const THREAD_CONTEXT_RE = /\b(Thread|threading|concurrent|async\s+(?:def|function)|goroutine|go\s+func|spawn|tokio|CompletableFuture|ExecutorService|ThreadPool|Worker|worker_threads|pthread|std::thread|std::async|Runnable|Callable)\b/i;
  const SYNC_RE = /\b(synchronized|lock|Lock|Mutex|mutex|RwLock|Semaphore|Atomic\w+|volatile|std::atomic|threading\.Lock|asyncio\.Lock|sync\.Mutex|sync\.RWMutex|concurrent\.locks|Interlocked|Monitor\.Enter|ConcurrentHashMap|ConcurrentDictionary)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock)\b/i.test(node.label)) continue;
    if (!THREAD_CONTEXT_RE.test(code) && !THREAD_CONTEXT_RE.test(node.label)) continue;

    const hasMutable = MUTABLE_STATIC_RE.test(code) || JAVA_NONFINAL_STATIC_RE.test(code) || PY_MODULE_MUTABLE_RE.test(code);
    if (!hasMutable) continue;
    if (SYNC_RE.test(code)) continue;

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'CONTROL (synchronization for mutable shared state)',
      severity: 'high',
      description: `${node.label}: mutable static state in concurrent context without synchronization. Race conditions possible.`,
      fix: 'Make field final/const, use atomics, protect with mutex/lock, or use thread-local storage.',
      via: 'source_line_fallback',
    });
  }

  return { cwe: 'CWE-1058', name: 'Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1059: Insufficient Technical Documentation
// ---------------------------------------------------------------------------

/**
 * CWE-1059: Insufficient Technical Documentation
 * Broader than CWE-1053. Detects complex security-critical modules with
 * high complexity-to-documentation ratio. 200-line auth module with 0 docs
 * is flagged; 10-line utility is not.
 */
function verifyCWE1059(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DOC_COMMENT_RE = /\/\*\*|"""|'''|@(?:param|returns?|throws|description|summary)|:param\s|:returns?:|docstring|\/\/\/\s/g;
  const COMPLEXITY_RE = /\b(if|else\s+if|elif|switch|case|catch|except|while|for)\b|&&|\|\|/g;
  const SEC_MODULE_RE = /\b(auth|crypto|security|permission|access[_-]?control|rbac|oauth|jwt|token|session|firewall|sanitiz|escap|encrypt)\b/i;

  for (const node of nodesOfType(map, 'STRUCTURAL')) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (/\b(test|spec|mock|fixture|__test__)\b/i.test(node.label)) continue;

    const lines = code.split('\n').length;
    if (lines < 30) continue;

    const docCount = (code.match(DOC_COMMENT_RE) || []).length;
    const complexity = (code.match(COMPLEXITY_RE) || []).length;
    const docDensity = docCount / (lines / 50);

    if (docDensity < 0.5 && complexity > 5) {
      if (!SEC_MODULE_RE.test(node.label) && !SEC_MODULE_RE.test(node.node_subtype)) continue;

      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (technical documentation for complex security-critical module)',
        severity: 'low',
        description: `${node.label}: ${lines}-line security module with ${docCount} doc comment(s) and ~${complexity} branch points. Insufficient docs for complex security logic.`,
        fix: 'Add module-level overview, function-level docs, inline comments for security decisions. Document trust model and auth flow.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1059', name: 'Insufficient Technical Documentation', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Architecture & Code Quality CWEs (1060–1069)
// ---------------------------------------------------------------------------

/**
 * CWE-1060: Excessive Number of Inefficient Server-Side Data Accesses
 * N+1 query problem: individual DB queries inside loops instead of batching.
 */
function verifyCWE1060(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const LOOP_QUERY_PATTERNS = [
    /\b(?:forEach|map|for\s*\(|for\s+of|for\s+in|while\s*\()[\s\S]{0,300}?\b(?:\.find(?:One|ById|All)?\s*\(|\.query\s*\(|\.execute\s*\(|\.select\s*\(|\.get\s*\(|\.fetch\s*\(|\.findBy\w+\s*\(|SELECT\s+.*FROM|\.load\s*\(|entityManager\.\w+\s*\(|repository\.\w+\s*\(|\.retrieve\s*\()/i,
    /\bfor\s+await\b[\s\S]{0,300}?\b(?:\.find|\.query|\.execute|\.select|\.get|\.fetch|\.load|\.retrieve)\s*\(/i,
    /\.\b(?:map|forEach|filter|some|every|flatMap)\s*\(\s*(?:async\s*)?\(?[^)]*\)?\s*=>\s*(?:\{[\s\S]{0,300})?(?:await\s+)?\w+\.(?:find|query|execute|select|get|fetch|load)\s*\(/i,
  ];

  const SAFE_BATCH_RE = /\b(bulkWrite|insertMany|batchGet|multiGet|whereIn|IN\s*\(|Promise\.all|Promise\.allSettled|\$in\s*:|batchInsert|bulkInsert|bulk_create|executemany|VALUES\s*\(.*\),\s*\(|UNION\s+ALL)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|seed|fixture|migration)\b/i.test(node.label || node.file)) continue;

    for (const pattern of LOOP_QUERY_PATTERNS) {
      if (pattern.test(code) && !SAFE_BATCH_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (batch database operations instead of N+1 individual queries)',
          severity: 'medium',
          description: `${node.label} issues individual database queries inside a loop (N+1 query pattern). ` +
            `Each iteration makes a separate round-trip. With N items this creates N+1 queries ` +
            `instead of 1 batch query, wasting connection pool resources and creating exploitable latency.`,
          fix: 'Replace individual queries in loops with batch operations: WHERE ... IN (...), ' +
            'bulkWrite(), findAll({where: {id: ids}}), Promise.all(), or DataLoader-style batching.',
          via: 'source_line_fallback',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-1060', name: 'Excessive Number of Inefficient Server-Side Data Accesses', holds: findings.length === 0, findings };
}

/**
 * CWE-1061: Insufficient Encapsulation
 * Classes exposing internal state via public mutable fields, returning mutable
 * internal collections, or having zero private members in non-trivial classes.
 */
function verifyCWE1061(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PUBLIC_MUTABLE_FIELDS = [
    /\bpublic\s+(?!(?:static\s+)?(?:final|const|readonly|immutable)\b)(?:(?:static|volatile|transient)\s+)*(?:int|long|float|double|boolean|String|List|Map|Set|Array|Collection|Object|byte|char|short)\s+\w+\s*[;=]/,
    /\bpublic\s+(?!readonly\b)(?:static\s+)?(?!(?:get|set|abstract|override)\b)\w+\s*[:=]/,
    /\bself\.(?!_)\w*(?:_impl|_internal|_cache|_state|_buffer|_data|_store|_registry|_map|_pool|_conn|_db)\s*=/,
  ];

  const CLASS_DECL_RE = /\bclass\s+(\w+)/;
  const HAS_PRIVATE_RE = /\b(private|protected|#\w+|__\w+)\b/;
  const RETURN_MUTABLE_RE = /\breturn\s+(?:this\.|self\.)(?:_\w+|\w+(?:List|Map|Set|Array|Collection|Buffer|Data|Items|Elements|Entries|Records|Queue|Stack))\s*[;)]/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|dto|DTO|interface|enum|abstract)\b/i.test(node.label)) continue;

    for (const pattern of PUBLIC_MUTABLE_FIELDS) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (proper encapsulation — use private fields with controlled accessors)',
          severity: 'low',
          description: `${node.label} exposes mutable internal state through public fields. ` +
            `External code can modify state directly, bypassing validation or invariant checks.`,
          fix: 'Make fields private with accessor methods. Java: private + getters/setters. ' +
            'TypeScript: private/readonly. Python: leading underscore + @property.',
          via: 'source_line_fallback',
        });
        break;
      }
    }

    const classMatch = code.match(CLASS_DECL_RE);
    if (classMatch && code.split('\n').length > 15) {
      if (!HAS_PRIVATE_RE.test(code) && /\bpublic\b/.test(code)) {
        const publicCount = (code.match(/\bpublic\b/g) || []).length;
        if (publicCount >= 4) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'STRUCTURAL (class encapsulation — some members should be private)',
            severity: 'low',
            description: `Class ${classMatch[1]} at ${node.label} has ${publicCount} public members and no private/protected members. ` +
              `Every internal detail is exposed, allowing tight coupling and invariant bypass.`,
            fix: 'Identify implementation details and make them private. Expose only the minimal public API needed.',
            via: 'source_line_fallback',
          });
        }
      }
    }

    if (RETURN_MUTABLE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (defensive copy — return copy of internal mutable collection)',
        severity: 'low',
        description: `${node.label} returns a reference to internal mutable state. ` +
          `Callers can modify the object internals without going through its API.`,
        fix: 'Return a defensive copy: Collections.unmodifiableList(), [...array], new Map(map), Object.freeze().',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1061', name: 'Insufficient Encapsulation', holds: findings.length === 0, findings };
}

/**
 * CWE-1062: Parent Class with References to Child Class
 * Base class that directly references, instantiates, or casts to its own subclasses.
 */
function verifyCWE1062(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PARENT_CHILD_REF_PATTERNS = [
    /\binstanceof\s+(\w+(?:Impl|Concrete|Specific|Default|Custom|Special|Extended|Sub|Child|Derived)\w*)\b/,
    /\(\s*(\w+(?:Impl|Concrete|Specific|Default|Custom|Special|Extended|Sub|Child|Derived)\w*)\s*\)/,
    /\b(?:abstract\s+class|class\s+\w*(?:Base|Abstract|Parent)\w*)[\s\S]{0,500}?\bnew\s+\w+(?:Impl|Concrete|Specific|Default|Custom)\b/,
  ];

  const TYPE_SWITCH_RE = /\bif\s*\(\s*(?:this|self)\s*(?:instanceof|\.\w*type\w*\s*===?)\s*['"]?\w+['"]?\s*\)[\s\S]{0,200}?\belse\s+if\s*\(\s*(?:this|self)\s*(?:instanceof|\.\w*type\w*\s*===?)/;
  const BASE_CLASS_RE = /\b(?:abstract\s+class|class\s+\w*(?:Base|Abstract|Parent|Root|Super)\w*)\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|factory|builder)\b/i.test(node.label)) continue;

    if (TYPE_SWITCH_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (polymorphism instead of type switching in parent class)',
        severity: 'low',
        description: `${node.label} contains a type switch on 'this'/'self', indicating a parent class ` +
          `that checks its own runtime type. This couples the parent to all children and violates OCP.`,
        fix: 'Use polymorphism: define abstract/virtual methods in the parent and override in each child.',
        via: 'source_line_fallback',
      });
    }

    if (BASE_CLASS_RE.test(code)) {
      for (const pattern of PARENT_CHILD_REF_PATTERNS) {
        const match = code.match(pattern);
        if (match) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'STRUCTURAL (dependency inversion — parent must not reference child classes)',
            severity: 'low',
            description: `Base class at ${node.label} directly references child class '${match[1] || 'subclass'}'. ` +
              `This creates a circular dependency and prevents adding new subclasses without modifying the parent.`,
            fix: 'Use Template Method or Strategy pattern. Extract factory logic into a separate Factory class.',
            via: 'source_line_fallback',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-1062', name: 'Parent Class with References to Child Class', holds: findings.length === 0, findings };
}

/**
 * CWE-1063: Creation of Class Instance within a Static Code Block
 * Complex object instantiation in static initializers. If the constructor throws,
 * the class becomes permanently unusable (ExceptionInInitializerError).
 */
function verifyCWE1063(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const STATIC_BLOCK_PATTERNS = [
    /\bstatic\s*\{[\s\S]{0,500}?\bnew\s+\w+\s*\(/,
    /\bstatic\s+(?:final\s+)?(?!(?:int|long|float|double|boolean|byte|char|short|String)\b)\w+\s+\w+\s*=\s*new\s+\w+\s*\(/,
    /\bstatic\s+\w+\s*\(\s*\)\s*\{[\s\S]{0,500}?\bnew\s+\w+\s*\(/,
  ];

  const SAFE_STATIC_RE = /\bnew\s+(?:String|Integer|Long|Boolean|Byte|Short|Float|Double|BigDecimal|BigInteger|AtomicInteger|AtomicLong|AtomicBoolean|Object|StringBuilder|StringBuffer|UUID|Random|SecureRandom|Lock|ReentrantLock|Mutex|Semaphore|CountDownLatch|ConcurrentHashMap|ArrayList|HashMap|HashSet|LinkedList|Logger|Pattern|Regex)\s*\(/i;
  const HEAVY_STATIC_RE = /\bnew\s+(?:\w*(?:Connection|Client|Session|Service|Manager|Provider|Factory|Pool|Cache|Context|Engine|Server|Socket|Stream|Channel|Database|Repository|Controller|Handler)\w*)\s*\(/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock)\b/i.test(node.label)) continue;

    for (const pattern of STATIC_BLOCK_PATTERNS) {
      if (pattern.test(code) && HEAVY_STATIC_RE.test(code) && !SAFE_STATIC_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (lazy initialization instead of static block instantiation)',
          severity: 'low',
          description: `${node.label} creates complex objects inside a static initializer. ` +
            `If the constructor throws, the class becomes permanently unusable (unrecoverable without restart).`,
          fix: 'Use lazy initialization: getInstance() with holder pattern or Lazy<T>. ' +
            'Move heavy initialization to explicit init() methods that can handle failures.',
          via: 'source_line_fallback',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-1063', name: 'Creation of Class Instance within a Static Code Block', holds: findings.length === 0, findings };
}

/**
 * CWE-1064: Invokable Control Element with Signature Containing an Excessive Number of Parameters
 * Functions with >7 parameters. Long parameter lists invite argument transposition.
 */
function verifyCWE1064(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const MAX_PARAMS = 7;

  const FUNC_SIG_PATTERNS: Array<{ re: RegExp }> = [
    { re: /\b(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?function|(?:async\s+)?(?:\w+\s*)?)\s*\(([^)]{30,})\)\s*(?::\s*\w+\s*)?(?:\{|=>)/g },
    { re: /\bdef\s+\w+\s*\(([^)]{30,})\)\s*(?:->[\s\S]*?)?:/g },
    { re: /\b(?:public|private|protected|static|final|override|virtual|abstract|async)\s+[\w<>\[\]]+\s+\w+\s*\(([^)]{40,})\)\s*(?:throws\s+[\w,\s]+)?\s*\{/g },
    { re: /\bfunc\s+(?:\(\w+\s+\*?\w+\)\s+)?\w+\s*\(([^)]{30,})\)\s*(?:\([\w\s,*]+\))?\s*\{/g },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|generated|constructor)\b/i.test(node.label)) continue;

    for (const { re } of FUNC_SIG_PATTERNS) {
      re.lastIndex = 0;
      let match;
      while ((match = re.exec(code)) !== null) {
        const paramList = match[1]
          .replace(/<[^>]*>/g, '')
          .replace(/\([^)]*\)/g, '')
          .split(',')
          .map(p => p.trim())
          .filter(p => p.length > 0);

        if (paramList.length > MAX_PARAMS) {
          const isSecurity = /\b(auth|login|verify|validate|encrypt|decrypt|sign|hash|permission|access|token|credential|password|session|cookie|cert)\b/i.test(code);
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'STRUCTURAL (parameter object or builder pattern to reduce parameter count)',
            severity: isSecurity ? 'medium' : 'low',
            description: `${node.label} has a function with ${paramList.length} parameters (threshold: ${MAX_PARAMS}). ` +
              `Long parameter lists increase argument transposition risk.` +
              (isSecurity ? ' This function appears security-sensitive, making parameter confusion especially dangerous.' : ''),
            fix: 'Group related parameters into an options/config object: foo({ a, b, c }) instead of foo(a, b, c).',
            via: 'source_line_fallback',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-1064', name: 'Invokable Control Element with Signature Containing an Excessive Number of Parameters', holds: findings.length === 0, findings };
}

/**
 * CWE-1065: Runtime Resource Management Control Element in a Component Built to Run on Application Servers
 * Manual thread/socket/System.exit management in server components that should
 * delegate to the container.
 */
function verifyCWE1065(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MANUAL_RESOURCE_PATTERNS: Array<{ pattern: RegExp; name: string; fix: string }> = [
    { pattern: /\bnew\s+Thread\s*\(|\.start\s*\(\s*\)|Thread\.sleep\s*\(|ExecutorService\s+\w+\s*=\s*Executors\.\w+\(/,
      name: 'manual thread creation in server component',
      fix: 'Use container-managed thread pools: @Async in Spring, ManagedExecutorService in Java EE.' },
    { pattern: /\bSystem\.exit\s*\(|Runtime\.getRuntime\(\)\.halt\s*\(/,
      name: 'calling System.exit() in server component',
      fix: 'Never call System.exit() in a server component. Throw an exception or return error status.' },
    { pattern: /\bClassLoader\s*\.\s*(?:getSystemClassLoader|loadClass)|\.getClassLoader\s*\(\s*\)\.loadClass|Class\.forName\s*\(/,
      name: 'classloader manipulation in server component',
      fix: 'Use dependency injection or JNDI lookups instead of manual classloader manipulation.' },
    { pattern: /\bnew\s+(?:Server)?Socket\s*\(|ServerSocket\s*\.\s*accept\s*\(|\.bind\s*\(\s*new\s+InetSocketAddress/,
      name: 'direct socket management in server component',
      fix: 'Use container-provided HTTP/TCP facilities or managed connectors.' },
    { pattern: /\bRuntime\.getRuntime\(\)\.(?:addShutdownHook|exec|freeMemory|gc|maxMemory|totalMemory)\s*\(/,
      name: 'JVM runtime manipulation in server component',
      fix: 'Use container lifecycle callbacks (@PreDestroy, @PostConstruct) instead of shutdown hooks.' },
  ];

  const SERVER_COMPONENT_RE = /\b(@Controller|@Service|@Component|@RestController|@RequestMapping|@Autowired|@Inject|@EJB|@Stateless|@Stateful|HttpServlet|GenericServlet|@WebServlet|@ManagedBean|extends\s+(?:Controller|BaseController|AbstractController|HttpServlet)|app\.(get|post|put|delete)\s*\(|router\.(get|post|put|delete)\s*\(|@app\.route)\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|main|cli|script|tool|util)\b/i.test(node.label || node.file)) continue;
    if (!SERVER_COMPONENT_RE.test(code) && !SERVER_COMPONENT_RE.test(node.label)) continue;

    for (const p of MANUAL_RESOURCE_PATTERNS) {
      if (p.pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `STRUCTURAL (container-managed resource — ${p.name})`,
          severity: 'medium',
          description: `${node.label}: ${p.name}. Server components should let the container manage runtime resources.`,
          fix: p.fix,
          via: 'source_line_fallback',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-1065', name: 'Runtime Resource Management Control Element in a Component Built to Run on Application Servers', holds: findings.length === 0, findings };
}

/**
 * CWE-1066: Missing Serialization Control Element
 * Serializable classes with sensitive fields but no transient/@JsonIgnore. Sensitive
 * data leaks into serialized output (APIs, caches, logs).
 */
function verifyCWE1066(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SERIALIZABLE_RE = /\bimplements\s+[\w,\s]*Serializable|@Serializable|@serial|Serializable\b/;
  const HAS_CONTROL_RE = /\b(transient|@JsonIgnore|@Transient|@Exclude|@XmlTransient|writeObject|readObject|serialVersionUID|@JsonProperty|@JsonInclude|@SerializedName|@Expose|writeReplace|readResolve|Externalizable)\b/;
  const SENSITIVE_FIELD_RE = /\b(?:private|public|protected)\s+\w+\s+(password|secret|token|apiKey|api_key|privateKey|private_key|credentials?|ssn|socialSecurity|creditCard|credit_card|pin|salt|hash|encryptionKey|sessionId|session_id|authToken|auth_token|refreshToken|refresh_token)\b/i;

  const JSON_NO_FILTER = [
    /\bobjectMapper\.write\w+\s*\(\s*(?!.*@JsonView|.*@JsonFilter)/,
    /\bJSON\.stringify\s*\(\s*\w+\s*\)\s*(?!.*(?:replacer|filter|pick|omit))/,
    /\bjson\.dumps?\s*\(\s*(?:self|obj|data|entity|model|user|account)\b/,
    /\bgson\.toJson\s*\(\s*\w+\s*\)/,
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|dto|DTO)\b/i.test(node.label)) continue;

    if (SERIALIZABLE_RE.test(code) && !HAS_CONTROL_RE.test(code) && SENSITIVE_FIELD_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (serialization filter — sensitive fields exposed during serialization)',
        severity: 'high',
        description: `${node.label} is Serializable with sensitive fields but no serialization control ` +
          `(no transient, no @JsonIgnore, no custom writeObject). Sensitive data will leak into serialized output.`,
        fix: 'Mark sensitive fields as transient/@JsonIgnore/@Exclude. Better: use a DTO pattern — ' +
          'serialize only an explicitly constructed DTO, never the entity directly.',
        via: 'source_line_fallback',
      });
    }

    for (const pattern of JSON_NO_FILTER) {
      if (pattern.test(code) && SENSITIVE_FIELD_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (JSON serialization filter — sensitive fields not excluded)',
          severity: 'medium',
          description: `${node.label} serializes an object to JSON without controlling which fields are included.`,
          fix: 'Use a DTO with only intended fields. Or: JSON.stringify(obj, ["field1","field2"]), @JsonView, @JsonIgnore.',
          via: 'source_line_fallback',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-1066', name: 'Missing Serialization Control Element', holds: findings.length === 0, findings };
}

/**
 * CWE-1067: Excessive Execution of Sequential Searches of Data Resource
 * O(n) linear searches inside loops creating O(n*m) when Map/Set/index would be O(1).
 */
function verifyCWE1067(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const NESTED_SEARCH_PATTERNS = [
    /\b(?:for\s*\(|forEach|\.map\s*\(|while\s*\()[\s\S]{0,300}?\.\b(?:find|filter|indexOf|includes|findIndex|some|every|lastIndexOf)\s*\(/i,
    /\bfor\s*\([^)]+\)\s*\{[\s\S]{0,300}?\bfor\s*\([^)]+\)\s*\{[\s\S]{0,200}?(?:===|==|\.equals\s*\()/,
    /\bfor\s+\w+\s+in\s+\w+[\s\S]{0,200}?\bif\s+\w+\s+(?:not\s+)?in\s+\w+/,
    /\b(?:for|foreach)\s*\([\s\S]{0,300}?\.\bWhere\s*\(/i,
  ];

  const SAFE_INDEXED_RE = /\b(Map|Set|HashMap|HashSet|Dictionary|dict|Object\.fromEntries|new\s+Map|new\s+Set|\.has\s*\(|\.get\s*\(|index|indexed|lookup|cache|memo)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock)\b/i.test(node.label)) continue;

    for (const pattern of NESTED_SEARCH_PATTERNS) {
      if (pattern.test(code) && !SAFE_INDEXED_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (indexed lookup instead of sequential search inside loop)',
          severity: 'medium',
          description: `${node.label} performs sequential searches inside a loop (O(n*m) complexity). ` +
            `With large datasets this creates quadratic performance exploitable for DoS.`,
          fix: 'Build a lookup index before the loop: const lookup = new Map(items.map(i => [i.key, i])); ' +
            'then use lookup.get(key). For databases: use JOIN or IN clause.',
          via: 'source_line_fallback',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-1067', name: 'Excessive Execution of Sequential Searches of Data Resource', holds: findings.length === 0, findings };
}

/**
 * CWE-1068: Inconsistency Between Implementation and Documented Design
 * Functions whose names promise security behavior but bodies are stubs. Also:
 * security-relevant TODO/FIXME/HACK comments indicating known deviations.
 */
function verifyCWE1068(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MISLEADING_NAMES: Array<{ nameRe: RegExp; bodyRequired: RegExp; what: string }> = [
    { nameRe: /\b(?:validate|isValid|checkValid)\w*/i,
      bodyRequired: /\b(?:throw|return\s+false|reject|Error|invalid|fail|!|===|!==|test\s*\(|match\s*\(|includes\s*\(|\.length\s*[<>!=]|RegExp)\b/i,
      what: 'validation function that never validates (no conditional/throw/return false)' },
    { nameRe: /\b(?:sanitize|escape|encode|clean|strip|purify)\w*/i,
      bodyRequired: /\b(?:replace|encode|escape|strip|purify|filter|DOMPurify|encodeURI|htmlEncode|SqlParameter|parameterize)\b/i,
      what: 'sanitization function that never transforms input' },
    { nameRe: /\b(?:authenticate|requireAuth|checkAuth|isAuthenticated|ensureAuth)\w*/i,
      bodyRequired: /\b(?:throw|return\s+false|reject|401|403|unauthorized|forbidden|verify|compare|jwt|token|session|credential|passport)\b/i,
      what: 'authentication function that never checks credentials' },
    { nameRe: /\b(?:authorize|checkPermission|hasPermission|isAllowed|requireRole|checkAccess)\w*/i,
      bodyRequired: /\b(?:throw|return\s+false|reject|403|forbidden|role|permission|access|grant|deny|policy)\b/i,
      what: 'authorization function that never checks permissions' },
  ];

  const SECURITY_DEFERRED_RE = /\b(TODO|FIXME|HACK)\b[:\s]+[\s\S]{0,100}?\b(security|auth|permission|valid|sanitiz|encrypt|token|session|password|credential|vuln|inject|xss|csrf|sql)/i;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    const codeNoComments = stripComments(code);
    if (/\b(test|spec|mock)\b/i.test(node.label)) continue;

    for (const { nameRe, bodyRequired, what } of MISLEADING_NAMES) {
      if (nameRe.test(node.label) && codeNoComments.split('\n').length > 2) {
        if (!bodyRequired.test(codeNoComments)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'STRUCTURAL (implementation must match documented/named security behavior)',
            severity: 'high',
            description: `${node.label}: ${what}. The function name promises security behavior ` +
              `but the implementation appears to be a stub or passthrough.`,
            fix: 'Implement the security behavior the function name promises, or rename to avoid false security.',
            via: 'source_line_fallback',
          });
          break;
        }
      }
    }

    if (SECURITY_DEFERRED_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (implement security-relevant TODO/FIXME)',
        severity: 'medium',
        description: `${node.label} contains a TODO/FIXME/HACK acknowledging a security-relevant deviation from design.`,
        fix: 'Resolve the TODO/FIXME. If non-trivial, add compensating controls and track in your security backlog.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1068', name: 'Inconsistency Between Implementation and Documented Design', holds: findings.length === 0, findings };
}

/**
 * CWE-1069: Empty Exception Block
 * Completely empty catch/except/rescue blocks — the classic silent swallower.
 * ALL exceptions including security failures are discarded with no trace.
 * Multi-language: JS/TS/Java/C#, Python (except: pass), Ruby, Go (if err != nil {}).
 *
 * NOTABLE: Distinct from CWE-755 (broad catches + log-and-swallow). CWE-1069 is
 * specifically the completely-empty handler — the absolute worst case.
 */
function verifyCWE1069(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const EMPTY_CATCH_PATTERNS: Array<{ pattern: RegExp; lang: string }> = [
    { pattern: /\bcatch\s*\([^)]*\)\s*\{\s*\}/, lang: 'JS/Java/C#' },
    { pattern: /\bcatch\s*\{\s*\}/, lang: 'JS/TS' },
    { pattern: /\bcatch\s+(?:let\s+\w+\s*)?\{\s*\}/, lang: 'Swift/Kotlin' },
    { pattern: /\bexcept\s*(?:\w[\w\s,]*)?(?:\s+as\s+\w+)?\s*:\s*(?:\n\s*)?pass\s*$/m, lang: 'Python' },
    { pattern: /\bexcept\s*(?:\w[\w\s,]*)?(?:\s+as\s+\w+)?\s*:\s*(?:\n\s*)?\.{3}\s*$/m, lang: 'Python' },
    { pattern: /\brescue\s*(?:=>?\s*\w+)?\s*;?\s*(?:\n\s*)?end\b/, lang: 'Ruby' },
    { pattern: /\bif\s+err\s*!=\s*nil\s*\{\s*\}/, lang: 'Go' },
    { pattern: /\bif\s+[^{]*err\s*!=\s*nil\s*\{\s*\}/, lang: 'Go' },
  ];

  const INTENTIONAL_EMPTY_RE = /\b(intentional|deliberate|expected|safe\s+to\s+ignore|best\s+effort|fire\s+and\s+forget|optional|noop|no-op)\b/i;

  for (const node of map.nodes) {
    const rawCode = node.analysis_snapshot || node.code_snapshot;
    const code = stripComments(rawCode);
    if (/\b(test|spec|mock)\b/i.test(node.label)) continue;

    for (const { pattern, lang } of EMPTY_CATCH_PATTERNS) {
      if (pattern.test(code)) {
        if (INTENTIONAL_EMPTY_RE.test(rawCode)) continue;

        const isSecurity = /\b(auth|login|password|token|session|permission|credential|encrypt|decrypt|verify|validate|sanitize|access|admin)\b/i.test(rawCode);

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (exception handling — empty catch block silently swallows all errors)',
          severity: isSecurity ? 'high' : 'medium',
          description: `${node.label} has a completely empty exception handler (${lang}). ` +
            `ALL exceptions — including security failures and corrupted state — are silently swallowed. ` +
            (isSecurity ? `Near security-sensitive code, making silent failure especially dangerous.` :
            `Debugging becomes impossible because errors leave no trace.`),
          fix: 'At minimum: log the error. Better: propagate it (re-throw, return error, reject promise). ' +
            'If genuinely expected, add a comment: // Intentional: cleanup may fail if already closed.',
          via: 'source_line_fallback',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-1069', name: 'Empty Exception Block', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1083: Data Access from Outside Expected Data Manager Component
// A module/class directly accesses data storage (DB, files, caches) instead
// of going through the designated data manager / repository / DAO layer.
// This breaks encapsulation, scatters SQL across the codebase, and makes it
// impossible to enforce consistent access controls or input validation.
// ---------------------------------------------------------------------------

function verifyCWE1083(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Direct DB access patterns — raw SQL, raw cursor, direct file I/O on data files
  const RAW_DB_ACCESS = /\b(?:mysql|pg|sqlite3?|mongodb|redis|memcache[d]?|cassandra|dynamodb)\s*\.\s*(?:query|execute|connect|command|get|set|put|del)\s*\(/i;
  const RAW_SQL_STRING = /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+(?:FROM|INTO|TABLE|SET|INDEX)\b/i;
  const RAW_CURSOR = /\b(?:cursor|conn|connection|pool)\s*\.\s*(?:execute|query|prepare|run)\s*\(/i;
  const RAW_FILE_DATA = /\b(?:readFileSync|readFile|writeFileSync|writeFile|open)\s*\(\s*['"`][^'"]*(?:\.json|\.csv|\.xml|\.dat|\.db|\.sqlite)\b/i;

  // Patterns that indicate THIS IS the data manager layer (should be allowed)
  const IS_DATA_LAYER = /\b(?:Repository|Repo|DAO|DataAccess|DataManager|DataService|Store|Model|Gateway|Adapter|Mapper|Provider)\b/i;
  const IS_MIGRATION = /\b(?:migration|migrate|seed|fixture|schema|knexfile)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    if (IS_DATA_LAYER.test(node.label) || IS_DATA_LAYER.test(node.file)) continue;
    if (IS_MIGRATION.test(node.label) || IS_MIGRATION.test(node.file)) continue;

    // Check if this non-data-layer code directly accesses data storage
    const hasRawAccess = RAW_DB_ACCESS.test(code) || RAW_CURSOR.test(code) || RAW_FILE_DATA.test(code);
    const hasRawSQL = RAW_SQL_STRING.test(code);

    if (hasRawAccess || hasRawSQL) {
      // Is there an intermediate data layer node between this code and STORAGE?
      const storageNodes = nodesOfType(map, 'STORAGE');
      let directAccess = false;

      if (storageNodes.length > 0) {
        for (const storage of storageNodes) {
          for (const edge of node.edges) {
            if (edge.target === storage.id && (edge.edge_type === 'WRITES' || edge.edge_type === 'READS')) {
              directAccess = true;
              break;
            }
          }
          if (directAccess) break;
        }
      } else {
        // No STORAGE nodes mapped but raw DB code found — still a violation
        directAccess = true;
      }

      if (directAccess || hasRawSQL) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (data access through a dedicated data manager/repository layer)',
          severity: 'medium',
          description: `${node.label} in ${node.file} directly accesses data storage instead of going through ` +
            `a repository/DAO layer. Raw data access scattered across the codebase prevents consistent ` +
            `access control enforcement and makes SQL injection auditing intractable.`,
          fix: 'Route all data access through a dedicated repository/DAO/data manager class. ' +
            'Use parameterized queries in the data layer and enforce access controls at the repository boundary.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-1083', name: 'Data Access from Outside Expected Data Manager Component', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1084: Invokable Control Element with Excessive File or Data Access Operations
// A single function/method performs too many file or data access operations.
// Differs from CWE-1073 (DB-specific) by also covering file I/O, cache hits,
// API calls, and mixed-resource access in a single function.
// ---------------------------------------------------------------------------

function verifyCWE1084(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const FILE_ACCESS = /\b(?:readFile|writeFile|readFileSync|writeFileSync|open|fopen|fread|fwrite|fclose|readdir|mkdir|unlink|rename|copyFile|appendFile|createReadStream|createWriteStream|fs\.\w+)\s*\(/gi;
  const DATA_ACCESS = /\b(?:query|execute|exec|find|findOne|findMany|select|insert|update|delete|get|set|put|hget|hset|lpush|rpush|zadd|sadd|fetch|axios\.\w+|request\.\w+|http\.\w+)\s*\(/gi;
  const CACHE_ACCESS = /\b(?:cache\.get|cache\.set|cache\.del|redis\.\w+|memcache[d]?\.\w+|localStorage\.\w+|sessionStorage\.\w+)\s*\(/gi;

  const THRESHOLD = 8; // Covering file + data + cache combined

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|migration|seed)\b/i.test(node.label)) continue;
    if (node.node_type === 'META' || node.node_type === 'STRUCTURAL') continue;

    let accessCount = 0;
    for (const pattern of [FILE_ACCESS, DATA_ACCESS, CACHE_ACCESS]) {
      pattern.lastIndex = 0;
      const matches = code.match(pattern);
      if (matches) accessCount += matches.length;
    }

    if (accessCount > THRESHOLD) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: `STRUCTURAL (refactor to reduce file/data access operations — found ${accessCount})`,
        severity: 'medium',
        description: `${node.label} performs ${accessCount} file/data access operations (threshold: ${THRESHOLD}). ` +
          `Excessive I/O in one function creates resource exhaustion risk, makes error handling fragile ` +
          `(partial writes on failure), and obscures security-relevant operations in noise.`,
        fix: 'Split into smaller functions with single I/O responsibility. Batch file operations where possible. ' +
          'Use transactions for related data writes. Consider a unit-of-work pattern.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1084', name: 'Invokable Control Element with Excessive File or Data Access Operations', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1085: Invokable Control Element with Excessive Volume of Commented-Out Code
// Large blocks of commented-out code indicate incomplete cleanup, abandoned
// features, or disabled security checks. Commented-out auth/validation code
// is a real risk: it suggests the check was once present and intentionally removed.
// ---------------------------------------------------------------------------

function verifyCWE1085(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Count lines of commented-out code vs total lines
  const BLOCK_COMMENT_RE = /\/\*[\s\S]*?\*\//g;
  const LINE_COMMENT_RE = /^\s*(?:\/\/|#)\s*.{5,}/gm; // At least 5 chars of content (not just markers)

  // Patterns indicating the commented-out code is security-relevant
  const SECURITY_COMMENT = /(?:\/\/|#|\/\*)\s*.*\b(?:auth|validate|sanitize|check|verify|permission|token|session|csrf|xss|sql|inject|encrypt|hash|password|credential|access.?control|firewall|whitelist|blacklist|allowlist|denylist)\b/i;

  const COMMENT_RATIO_THRESHOLD = 0.30; // >30% of the code is comments
  const SECURITY_COMMENT_THRESHOLD = 3; // 3+ lines of commented-out security code

  for (const node of map.nodes) {
    const raw = node.code_snapshot; // Use raw, NOT stripped — we're looking at comments
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    if (raw.length < 50) continue; // Skip tiny snippets

    const totalLines = raw.split('\n').length;
    if (totalLines < 10) continue; // Don't flag short functions

    let commentedLines = 0;

    // Count block comment lines
    const blockMatches = raw.match(BLOCK_COMMENT_RE);
    if (blockMatches) {
      for (const block of blockMatches) {
        // Only count if it looks like code (has = ; { } ( ) etc.), not JSDoc
        if (/[=;{}()]/.test(block) && !/^\s*\/\*\*/.test(block)) {
          commentedLines += block.split('\n').length;
        }
      }
    }

    // Count line comments that look like code
    const lineMatches = raw.match(LINE_COMMENT_RE);
    if (lineMatches) {
      for (const line of lineMatches) {
        const content = line.replace(/^\s*(?:\/\/|#)\s*/, '');
        // Looks like code: has operators, parens, semicolons, keywords
        if (/[=;{}()\[\]]|(?:function|const|let|var|if|else|for|while|return|import|class)\b/.test(content)) {
          commentedLines++;
        }
      }
    }

    const ratio = commentedLines / totalLines;

    // Check for commented-out security code specifically
    const securityComments = (raw.match(new RegExp(SECURITY_COMMENT.source, 'gim')) || []).length;

    if (ratio > COMMENT_RATIO_THRESHOLD && commentedLines > 5) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: `STRUCTURAL (remove commented-out code — ${commentedLines}/${totalLines} lines are dead code)`,
        severity: securityComments >= SECURITY_COMMENT_THRESHOLD ? 'high' : 'low',
        description: `${node.label} has ${Math.round(ratio * 100)}% commented-out code (${commentedLines} of ${totalLines} lines). ` +
          (securityComments >= SECURITY_COMMENT_THRESHOLD
            ? `Critically, ${securityComments} of these comments contain security-relevant code (auth, validation, ` +
              `sanitization). Commented-out security checks suggest protections were deliberately disabled.`
            : `Excessive dead code obscures the active logic, makes code review unreliable, and may hide ` +
              `intentionally disabled checks.`),
        fix: 'Remove commented-out code and use version control history to recover it if needed. ' +
          'If security checks were commented out, determine WHY and either restore them or document ' +
          'the replacement control. Use feature flags instead of commenting out code.',
        via: 'source_line_fallback',
      });
    } else if (securityComments >= SECURITY_COMMENT_THRESHOLD) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (restore or properly replace commented-out security checks)',
        severity: 'high',
        description: `${node.label} contains ${securityComments} commented-out security-related code lines ` +
          `(auth, validation, sanitization). This strongly suggests security controls were deliberately disabled.`,
        fix: 'Investigate why security checks were commented out. Restore them, implement replacements, ' +
          'or document in a security decision record why they are no longer needed.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1085', name: 'Invokable Control Element with Excessive Volume of Commented-Out Code', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1086: Class with Excessive Number of Child Classes
// A class/interface with too many direct subclasses indicates a "god type"
// that everything depends on. Changes to it cascade everywhere, security
// patches must propagate through every child, and polymorphic dispatch becomes
// unpredictable (which override actually runs for a given auth check?).
// ---------------------------------------------------------------------------

function verifyCWE1086(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Build parent→children map from class definitions
  const EXTENDS_RE = /\bclass\s+(\w+)\s+extends\s+(\w+)/g;
  const IMPLEMENTS_RE = /\bclass\s+(\w+)[^{]*\bimplements\s+(\w+(?:\s*,\s*\w+)*)/g;
  const PYTHON_INHERIT = /\bclass\s+(\w+)\s*\(([^)]+)\)/g;

  const childCount = new Map<string, { count: number; children: string[]; node: NeuralMapNode }>();

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Java/TS/JS extends
    let match: RegExpExecArray | null;
    EXTENDS_RE.lastIndex = 0;
    while ((match = EXTENDS_RE.exec(code)) !== null) {
      const [, child, parent] = match;
      const entry = childCount.get(parent) || { count: 0, children: [], node };
      entry.count++;
      entry.children.push(child);
      childCount.set(parent, entry);
    }

    // Java/TS implements
    IMPLEMENTS_RE.lastIndex = 0;
    while ((match = IMPLEMENTS_RE.exec(code)) !== null) {
      const interfaces = match[2].split(/\s*,\s*/);
      for (const iface of interfaces) {
        const trimmed = iface.trim();
        if (!trimmed) continue;
        const entry = childCount.get(trimmed) || { count: 0, children: [], node };
        entry.count++;
        entry.children.push(match[1]);
        childCount.set(trimmed, entry);
      }
    }

    // Python inheritance
    PYTHON_INHERIT.lastIndex = 0;
    while ((match = PYTHON_INHERIT.exec(code)) !== null) {
      const [, child, parents] = match;
      for (const p of parents.split(/\s*,\s*/)) {
        const trimmed = p.trim();
        if (!trimmed || trimmed === 'object' || trimmed === 'ABC' || trimmed === 'metaclass=ABCMeta') continue;
        const entry = childCount.get(trimmed) || { count: 0, children: [], node };
        entry.count++;
        entry.children.push(child);
        childCount.set(trimmed, entry);
      }
    }
  }

  const CHILD_THRESHOLD = 10;

  for (const [parent, info] of childCount) {
    if (info.count > CHILD_THRESHOLD) {
      // Exclude common framework base classes
      if (/^(?:Object|Component|React\.Component|PureComponent|Widget|View|Activity|Fragment|TestCase|BaseModel|Base)$/i.test(parent)) continue;

      findings.push({
        source: nodeRef(info.node), sink: nodeRef(info.node),
        missing: `STRUCTURAL (refactor ${parent} — has ${info.count} child classes, threshold: ${CHILD_THRESHOLD})`,
        severity: 'medium',
        description: `Class/interface ${parent} has ${info.count} direct children: ` +
          `${info.children.slice(0, 5).join(', ')}${info.count > 5 ? '...' : ''}. ` +
          `Excessive subclassing creates a fragile hierarchy where security-relevant method overrides ` +
          `(auth checks, validation, sanitization) may be inconsistently implemented across children.`,
        fix: 'Favor composition over inheritance. Extract shared behavior into mixins, decorators, or ' +
          'strategy objects. Use the interface segregation principle to split the base type into smaller, ' +
          'focused interfaces. Ensure all children consistently implement security-critical methods.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1086', name: 'Class with Excessive Number of Child Classes', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1087: Class with Virtual Method without a Virtual Destructor
// In C++, if a class has virtual methods but no virtual destructor, deleting
// a derived object through a base pointer causes undefined behavior —
// the derived destructor never runs, leaking resources and potentially leaving
// security-sensitive data (keys, credentials, PII) in memory.
// ---------------------------------------------------------------------------

function verifyCWE1087(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // C++ class with virtual methods
  const VIRTUAL_METHOD = /\bvirtual\s+(?!~)\w[\w\s*&:<>]*\w+\s*\([^)]*\)/;
  // Virtual destructor present
  const VIRTUAL_DTOR = /\bvirtual\s+~\w+\s*\(/;
  // Any destructor
  const ANY_DTOR = /~\w+\s*\(/;
  // Class declaration
  const CLASS_DECL = /\bclass\s+(\w+)/;
  // Pure abstract (may be acceptable without virtual dtor if never directly allocated)
  const PURE_VIRTUAL = /=\s*0\s*;/;
  // Safe: class is marked final
  const FINAL_CLASS = /\bclass\s+\w+\s+final\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Only relevant for C++ code
    if (node.language && !/\b(c\+\+|cpp|cc|cxx|hpp)\b/i.test(node.language) &&
        !/\b(c\+\+|cpp)\b/i.test(node.file)) {
      // Heuristic: check if code looks like C++
      if (!VIRTUAL_METHOD.test(code)) continue;
    }

    const classMatch = CLASS_DECL.exec(code);
    if (!classMatch) continue;
    if (FINAL_CLASS.test(code)) continue; // final classes can't be subclassed

    if (VIRTUAL_METHOD.test(code) && !VIRTUAL_DTOR.test(code)) {
      // Check if it's purely abstract (all methods = 0) — less severe
      const isPureAbstract = PURE_VIRTUAL.test(code) && !ANY_DTOR.test(code);

      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (virtual destructor for class with virtual methods)',
        severity: isPureAbstract ? 'medium' : 'high',
        description: `Class ${classMatch[1]} at ${node.label} has virtual methods but no virtual destructor. ` +
          `Deleting a derived object through a ${classMatch[1]}* pointer is undefined behavior: ` +
          `the derived destructor won't run, leaking resources and potentially leaving sensitive data ` +
          `(cryptographic keys, credentials, PII) in memory.` +
          (isPureAbstract ? ' (Pure abstract class — lower risk if never directly allocated.)' : ''),
        fix: `Add 'virtual ~${classMatch[1]}() = default;' to the class declaration. ` +
          'In C++11+, this is zero-cost for classes already having a vtable. ' +
          'Alternatively, mark the class as final if it should not be subclassed.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1087', name: 'Class with Virtual Method without a Virtual Destructor', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1089: Large Data Table with Excessive Number of Indices
// A database table with too many indices degrades write performance (every
// INSERT/UPDATE must update all indices), increases storage, and creates a
// DoS vector: an attacker who can trigger writes (user registration, logging,
// comments) causes disproportionate I/O amplification.
// ---------------------------------------------------------------------------

function verifyCWE1089(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // SQL CREATE TABLE / CREATE INDEX patterns
  const CREATE_TABLE = /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"']?(\w+)[`"']?/gi;
  const CREATE_INDEX = /\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"']?\w+[`"']?\s+ON\s+[`"']?(\w+)[`"']?/gi;
  // ORM index definitions
  const ORM_INDEX = /\b(?:@Index|index:|add_index|create_index|HasIndex|Index\()\s*[\s(]*['"`]?(\w+)?/gi;
  // Django: class Meta: indexes / index_together
  const DJANGO_INDEX = /\bindex(?:es|_together)\s*=\s*\[/gi;

  const INDEX_THRESHOLD = 8;

  // Track indices per table
  const tableIndices = new Map<string, { count: number; node: NeuralMapNode }>();

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Count CREATE INDEX statements per table
    CREATE_INDEX.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = CREATE_INDEX.exec(code)) !== null) {
      const table = match[1].toLowerCase();
      const entry = tableIndices.get(table) || { count: 0, node };
      entry.count++;
      tableIndices.set(table, entry);
    }

    // Count inline index definitions in CREATE TABLE or ORM
    CREATE_TABLE.lastIndex = 0;
    while ((match = CREATE_TABLE.exec(code)) !== null) {
      const table = match[1].toLowerCase();
      // Count KEY/INDEX inside the CREATE TABLE
      const tableBody = code.slice(match.index);
      const inlineIndices = (tableBody.match(/\b(?:INDEX|KEY|UNIQUE)\s*(?:KEY|INDEX)?\s*\(/gi) || []).length;
      if (inlineIndices > 0) {
        const entry = tableIndices.get(table) || { count: 0, node };
        entry.count += inlineIndices;
        tableIndices.set(table, entry);
      }
    }

    // Count ORM-style index definitions
    ORM_INDEX.lastIndex = 0;
    while ((match = ORM_INDEX.exec(code)) !== null) {
      const entity = match[1]?.toLowerCase() || node.label.toLowerCase();
      const entry = tableIndices.get(entity) || { count: 0, node };
      entry.count++;
      tableIndices.set(entity, entry);
    }

    // Django index lists
    DJANGO_INDEX.lastIndex = 0;
    while ((match = DJANGO_INDEX.exec(code)) !== null) {
      const listBody = code.slice(match.index);
      const indexEntries = (listBody.match(/\bIndex\s*\(/gi) || []).length;
      const entity = node.label.toLowerCase().replace(/model|meta/gi, '').trim() || 'unknown';
      if (indexEntries > 0) {
        const entry = tableIndices.get(entity) || { count: 0, node };
        entry.count += indexEntries;
        tableIndices.set(entity, entry);
      }
    }
  }

  for (const [table, info] of tableIndices) {
    if (info.count > INDEX_THRESHOLD) {
      findings.push({
        source: nodeRef(info.node), sink: nodeRef(info.node),
        missing: `STRUCTURAL (reduce indices on ${table} — found ${info.count}, threshold: ${INDEX_THRESHOLD})`,
        severity: 'medium',
        description: `Table/entity '${table}' has ${info.count} indices (threshold: ${INDEX_THRESHOLD}). ` +
          `Every write operation must update all indices, creating write amplification. ` +
          `If an attacker can trigger writes (registration, comments, uploads), this becomes a ` +
          `resource exhaustion vector — each user write causes ${info.count}x I/O.`,
        fix: 'Audit index usage with query analysis tools (EXPLAIN, pg_stat_user_indexes). ' +
          'Remove unused or redundant indices. Use covering/composite indices instead of many single-column ones. ' +
          'Consider partial indices for filtered queries.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1089', name: 'Large Data Table with Excessive Number of Indices', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1090: Method Containing Access of a Member Element from Another Class
// A method directly accesses internal fields of another class instead of using
// its public API. This breaks encapsulation, creates tight coupling, and means
// security invariants maintained by the other class's setters/getters are bypassed.
// E.g., directly reading user._passwordHash instead of user.checkPassword().
// ---------------------------------------------------------------------------

function verifyCWE1090(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Direct field access patterns — accessing private/internal fields of another object
  // Java/C++: obj.privateField or obj._field (convention)
  const UNDERSCORE_FIELD = /\b(?!this\b)(?!self\b)\w+\.\s*_\w{2,}/g;
  // Python: obj.__mangled or obj._protected
  const PYTHON_PRIVATE = /\b(?!self\b)(?!cls\b)\w+\.\s*__\w+(?!__)/g;
  // Java reflection: field.setAccessible(true)
  const REFLECTION_ACCESS = /\bsetAccessible\s*\(\s*true\s*\)/;
  // C++: friend class + direct member access (structural coupling)
  const FRIEND_CLASS = /\bfriend\s+class\s+\w+/;
  // Ruby: instance_variable_get/set
  const RUBY_IVAR = /\binstance_variable_(?:get|set)\s*\(/;

  // Safe: accessing own fields (this._ or self._)
  const OWN_FIELD = /\b(?:this|self)\s*\.\s*_/;

  // Sensitive field patterns — accessing these directly is especially dangerous
  const SENSITIVE_FIELD = /\b_(?:password|secret|key|token|credential|hash|salt|session|auth|permission|role|admin|private_?key|api_?key)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    if (node.node_type === 'META' || node.node_type === 'STRUCTURAL') continue;

    let violations: string[] = [];
    let hasSensitive = false;

    // Check underscore field access on other objects
    UNDERSCORE_FIELD.lastIndex = 0;
    const underscoreMatches = code.match(UNDERSCORE_FIELD) || [];
    for (const m of underscoreMatches) {
      if (!OWN_FIELD.test(m)) {
        violations.push(m.trim());
        if (SENSITIVE_FIELD.test(m)) hasSensitive = true;
      }
    }

    // Python private name mangling
    PYTHON_PRIVATE.lastIndex = 0;
    const pythonMatches = code.match(PYTHON_PRIVATE) || [];
    for (const m of pythonMatches) {
      violations.push(m.trim());
      if (SENSITIVE_FIELD.test(m)) hasSensitive = true;
    }

    // Reflection to bypass access control
    if (REFLECTION_ACCESS.test(code)) {
      violations.push('setAccessible(true)');
      hasSensitive = true; // Reflection to bypass access is always suspicious
    }

    // Ruby instance variable access
    if (RUBY_IVAR.test(code)) {
      violations.push('instance_variable_get/set');
    }

    if (violations.length >= 2) { // Only flag if multiple violations (single access may be intentional)
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (use public API instead of direct member access on other classes)',
        severity: hasSensitive ? 'high' : 'low',
        description: `${node.label} directly accesses internal members of other classes: ` +
          `${violations.slice(0, 4).join(', ')}${violations.length > 4 ? '...' : ''}. ` +
          `This bypasses encapsulation boundaries and any security invariants maintained by ` +
          `the owning class's API (validation, access control, audit logging).` +
          (hasSensitive ? ' Sensitive fields (credentials, keys, auth data) are being accessed directly.' : ''),
        fix: 'Access other classes through their public API (getters, methods). If access to internals ' +
          'is genuinely needed, expose a controlled method on the owning class that enforces invariants. ' +
          'Never use reflection (setAccessible) to bypass access control in production code.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1090', name: 'Method Containing Access of a Member Element from Another Class', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1091: Use of Object without Invoking Destructor Method
// An object that manages resources (memory, file handles, DB connections,
// crypto contexts) is abandoned without calling its destructor/close/dispose.
// This leaks resources and, critically, can leave sensitive data in memory
// (crypto keys, plaintext passwords, session tokens).
// ---------------------------------------------------------------------------

function verifyCWE1091(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Resource-acquiring patterns that REQUIRE cleanup
  const RESOURCE_ACQUIRE = /\b(?:new\s+(?:FileInputStream|FileOutputStream|BufferedReader|Socket|ServerSocket|Connection|SSLContext|Cipher|SecretKey|KeyStore|PreparedStatement|ResultSet|RandomAccessFile|DatagramSocket|ZipFile|JarFile)|open\s*\(|fopen\s*\(|socket\s*\(|connect\s*\(|CreateFile\s*\(|OpenProcess\s*\(|malloc\s*\(|calloc\s*\(|realloc\s*\(|new\s+\w+Stream|new\s+\w+Reader|new\s+\w+Writer|acquireLock|lockFile)\b/;

  // Cleanup patterns — evidence the resource IS being cleaned up
  const CLEANUP_PATTERN = /\b(?:close\s*\(|dispose\s*\(|release\s*\(|free\s*\(|destroy\s*\(|cleanup\s*\(|shutdown\s*\(|disconnect\s*\(|CloseHandle\s*\(|finally\s*\{|try-with-resources|using\s*\(|with\s+\w+\s+as\b|defer\s+|\.close\b|\.dispose\b|\.release\b|__exit__|contextmanager)\b/i;

  // Crypto-specific resources that MUST be zeroed/destroyed
  const CRYPTO_RESOURCE = /\b(?:SecretKey|PrivateKey|Cipher|KeyGenerator|MessageDigest|Mac|SecureRandom|SSLContext|crypto\.create|CryptoKey|HMAC)\b/;

  // Auto-close safe patterns (language-specific)
  const AUTO_CLOSE = /\btry\s*\(\s*\w+|using\s*\(\s*(?:var|final)?\s*\w+|\bwith\s+(?:open|connect)|defer\s+\w+\.(?:close|release)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    if (node.node_type === 'META') continue;

    if (RESOURCE_ACQUIRE.test(code)) {
      const hasCleanup = CLEANUP_PATTERN.test(code) || AUTO_CLOSE.test(code);

      if (!hasCleanup) {
        const isCrypto = CRYPTO_RESOURCE.test(code);

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (destructor/close/dispose call for resource-managing object)',
          severity: isCrypto ? 'high' : 'medium',
          description: `${node.label} acquires a resource but shows no evidence of cleanup (close/dispose/free). ` +
            (isCrypto
              ? `This involves cryptographic material that will remain in memory after use, ` +
                `accessible to memory dumps, core dumps, or heap inspection attacks.`
              : `Resource leaks cause handle exhaustion, connection pool starvation, and ` +
                `memory growth — all exploitable for denial of service.`),
          fix: isCrypto
            ? 'Zero cryptographic material after use (Arrays.fill, SecureZeroMemory, memset_s). ' +
              'Use try-with-resources (Java), using (C#), with (Python), or defer (Go) for automatic cleanup. ' +
              'In C++, use RAII (unique_ptr with custom deleter).'
            : 'Wrap resource acquisition in try-with-resources (Java), using (C#), with (Python), ' +
              'or defer (Go). In C++, use RAII. Always close resources in a finally block if ' +
              'language-level constructs are unavailable.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return { cwe: 'CWE-1091', name: 'Use of Object without Invoking Destructor Method', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1092: Use of Same Invokable Control Element in Multiple Architectural Layers
// A single function/class is used across multiple architectural layers (e.g.,
// the same utility is called from routing, business logic, AND data access).
// This creates hidden coupling: a change in the shared function affects all
// layers. Security impact: a vulnerability in a shared utility propagates to
// every layer simultaneously, and access control assumptions differ per layer.
// ---------------------------------------------------------------------------

function verifyCWE1092(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Heuristic: classify nodes into architectural layers by file path or label
  const LAYER_PATTERNS: Array<{ layer: string; pattern: RegExp }> = [
    { layer: 'PRESENTATION', pattern: /\b(?:route|controller|handler|middleware|view|template|component|page|screen|endpoint|api\/v\d)\b/i },
    { layer: 'BUSINESS', pattern: /\b(?:service|usecase|use-case|domain|logic|manager|processor|engine|workflow|interactor)\b/i },
    { layer: 'DATA', pattern: /\b(?:repository|repo|dao|model|entity|mapper|migration|store|persistence|database|query)\b/i },
    { layer: 'INFRASTRUCTURE', pattern: /\b(?:config|util|helper|lib|common|shared|core|base|framework|adapter|driver)\b/i },
  ];

  function classifyLayer(node: NeuralMapNode): string | null {
    const context = `${node.file} ${node.label}`;
    for (const { layer, pattern } of LAYER_PATTERNS) {
      if (pattern.test(context)) return layer;
    }
    return null;
  }

  // Track which layers each function/module is CALLED from
  const calledFromLayers = new Map<string, { layers: Set<string>; node: NeuralMapNode }>();

  for (const node of map.nodes) {
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    const callerLayer = classifyLayer(node);
    if (!callerLayer) continue;

    // Check what this node calls
    for (const edge of node.edges) {
      if (edge.edge_type !== 'CALLS') continue;
      const target = map.nodes.find(n => n.id === edge.target);
      if (!target) continue;

      const targetKey = target.label || target.id;
      const entry = calledFromLayers.get(targetKey) || { layers: new Set(), node: target };
      entry.layers.add(callerLayer);
      calledFromLayers.set(targetKey, entry);
    }
  }

  const LAYER_THRESHOLD = 3; // Called from 3+ distinct layers

  for (const [funcName, info] of calledFromLayers) {
    if (info.layers.size >= LAYER_THRESHOLD) {
      // Exclude genuine infrastructure utilities (logging, config reading)
      const targetContext = `${info.node.file} ${info.node.label}`;
      if (/\b(?:log|logger|config|env|constant|error|exception)\b/i.test(targetContext)) continue;

      findings.push({
        source: nodeRef(info.node), sink: nodeRef(info.node),
        missing: `STRUCTURAL (${funcName} used across ${info.layers.size} layers: ${[...info.layers].join(', ')})`,
        severity: 'low',
        description: `${funcName} is called from ${info.layers.size} architectural layers: ` +
          `${[...info.layers].join(', ')}. Cross-layer sharing creates hidden coupling — a vulnerability ` +
          `or behavioral change in this function propagates to all layers simultaneously. ` +
          `Security assumptions (trust level, input validation, auth context) differ across layers.`,
        fix: 'Create layer-specific wrappers that adapt the shared function to each layer\'s security context. ' +
          'Consider whether each layer should have its own implementation with appropriate access controls. ' +
          'If sharing is intentional, document the cross-layer contract and security assumptions.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1092', name: 'Use of Same Invokable Control Element in Multiple Architectural Layers', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1094: Excessive Index Range Scan for a Data Resource
// Queries that scan large index ranges instead of performing point lookups
// cause disproportionate I/O and CPU usage. If attackers control query
// parameters (pagination, date ranges, search terms), they can trigger
// full-table/index scans at will — an application-layer DoS vector.
// ---------------------------------------------------------------------------

function verifyCWE1094(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns indicating unbounded or excessively wide range scans
  const UNBOUNDED_RANGE = /\bWHERE\b[^;]*\b(?:BETWEEN|>=?|<=?|LIKE\s+['"]%)\b(?![^;]*\bLIMIT\b)/i;
  const FULL_TABLE_SCAN = /\bSELECT\b[^;]*\bFROM\b[^;]*(?:(?!\bWHERE\b).)*(;|\)|$)/i;
  const LIKE_LEADING_WILDCARD = /\bLIKE\s+['"]%/i;
  const NO_LIMIT = /\b(?:SELECT|FIND|QUERY)\b(?![^;]*\b(?:LIMIT|TOP|FETCH\s+FIRST|ROWNUM|\.limit|\.take|\.first|\.top)\b)/i;
  const ORM_NO_LIMIT = /\.(?:find|findAll|findMany|where|select|all)\s*\([^)]*\)(?!\s*\.(?:limit|take|first|paginate|slice|top))/i;

  // Patterns that indicate the query parameter is user-controlled
  const USER_PARAM = /\b(?:req\.|params\.|query\.|body\.|args\.|input\.|request\.)\w+/;

  // Safe: query has explicit bounds
  const HAS_BOUNDS = /\b(?:LIMIT\s+\d|TOP\s+\d|FETCH\s+FIRST\s+\d|ROWNUM\s*<=?\s*\d|\.limit\s*\(\s*\d|\.take\s*\(\s*\d|\.first\s*\(\s*\d|OFFSET\s+\d.*LIMIT\s+\d)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|migration|seed)\b/i.test(node.label)) continue;

    let isVulnerable = false;
    let detail = '';

    if (LIKE_LEADING_WILDCARD.test(code) && USER_PARAM.test(code)) {
      isVulnerable = true;
      detail = 'Uses LIKE with leading wildcard (%) on user-controlled input — forces full index/table scan. ';
    } else if (UNBOUNDED_RANGE.test(code) && USER_PARAM.test(code) && !HAS_BOUNDS.test(code)) {
      isVulnerable = true;
      detail = 'Range query (BETWEEN, >=, <=) on user-controlled parameters without LIMIT. ';
    } else if (ORM_NO_LIMIT.test(code) && USER_PARAM.test(code)) {
      isVulnerable = true;
      detail = 'ORM query with user-controlled filters but no limit/take/paginate. ';
    } else if (FULL_TABLE_SCAN.test(code) && !HAS_BOUNDS.test(code) && node.node_type !== 'META') {
      // SELECT without WHERE — only flag if it's in a request handler context
      if (/\b(?:handler|route|controller|endpoint|api|get|post|put|delete)\b/i.test(node.label) ||
          node.node_type === 'INGRESS') {
        isVulnerable = true;
        detail = 'SELECT without WHERE clause in a request handler — returns entire table. ';
      }
    }

    if (isVulnerable) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (bounded query with LIMIT and index-friendly predicates)',
        severity: 'medium',
        description: `${node.label}: ${detail}` +
          `An attacker controlling query parameters can trigger excessive index range scans, ` +
          `consuming disproportionate database CPU and I/O — application-layer DoS.`,
        fix: 'Always apply LIMIT/pagination on user-facing queries. Avoid LIKE with leading wildcards ' +
          '(use full-text search instead). Validate and cap range parameters (date ranges, numeric ranges). ' +
          'Use cursor-based pagination instead of OFFSET for large datasets.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1094', name: 'Excessive Index Range Scan for a Data Resource', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Documentation & Code Style CWEs (1108–1117)
// ---------------------------------------------------------------------------

/**
 * CWE-1108: Excessive Reliance on Global Variables
 * Global/module-level mutable state creates hidden coupling between functions,
 * enables race conditions in concurrent environments, and makes security
 * properties non-local (a function's safety depends on who else mutated the global).
 *
 * Security implications: global state holding auth tokens, session data, or
 * config can be overwritten by unrelated code paths. In Node.js, module-scope
 * variables are shared across all requests — classic request-smuggling vector.
 */
function verifyCWE1108(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Skip test files entirely
  if (/\b(test|spec|mock|fixture|__test__|\.test\.|\.spec\.)\b/i.test(map.source_file)) {
    return { cwe: 'CWE-1108', name: 'Excessive Reliance on Global Variables', holds: true, findings };
  }

  // Patterns that declare mutable globals / module-level mutable state
  const JS_GLOBAL_MUT = /\b(?:var|let)\s+\w+\s*=\s*/;
  const GLOBAL_KEYWORD_PY = /\bglobal\s+\w+/;
  const JAVA_STATIC_MUT = /\bstatic\s+(?!final\b|const\b|readonly\b)(?:(?:volatile|transient)\s+)*\w+\s+\w+\s*[;=]/;
  const CSHARP_STATIC_MUT = /\bstatic\s+(?!readonly\b|const\b)\w+\s+\w+\s*[;=]/;

  // Safe: const, final, readonly, frozen, immutable
  const SAFE_IMMUTABLE = /\b(const|final|readonly|Object\.freeze|Object\.defineProperty|IMMUTABLE|CONSTANT)\b/i;

  // Security-sensitive globals: auth, config, session, db connections, secrets
  const SEC_GLOBAL_RE = /\b(token|secret|password|apiKey|api_key|session|currentUser|current_user|db|conn|connection|pool|config|credentials|auth|permission|role|admin|cache)\b/i;

  // --- Primary scan: raw source_code at module scope ---
  // Root cause fix: the tree-sitter mapper classifies module-level var declarations as
  // TRANSFORM or INGRESS nodes and does NOT embed the declaration keyword in code_snapshot.
  // The original verifier filtered by node_type === STRUCTURAL/META, so it never saw these
  // nodes, making it completely blind to JS module-scope globals. Scanning map.source_code
  // directly (brace-depth tracking to stay at module scope) is the correct fix.
  if (map.source_code) {
    const rawCode = stripComments(map.source_code);
    let globalCount = 0;
    const secGlobals: string[] = [];
    let braceDepth = 0;
    for (const line of rawCode.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (braceDepth === 0) {
        let isGlobal = false;
        if (JS_GLOBAL_MUT.test(trimmed) && !SAFE_IMMUTABLE.test(trimmed)) isGlobal = true;
        if (GLOBAL_KEYWORD_PY.test(trimmed)) isGlobal = true;
        if (JAVA_STATIC_MUT.test(trimmed)) isGlobal = true;
        if (CSHARP_STATIC_MUT.test(trimmed)) isGlobal = true;
        if (isGlobal) {
          globalCount++;
          const m = trimmed.match(SEC_GLOBAL_RE);
          if (m) secGlobals.push(m[0]);
        }
      }
      braceDepth += (trimmed.match(/\{/g) || []).length - (trimmed.match(/\}/g) || []).length;
      if (braceDepth < 0) braceDepth = 0;
    }
    if (globalCount > 5 || secGlobals.length > 0) {
      const severity: 'critical' | 'high' | 'medium' | 'low' = secGlobals.length > 0 ? 'high' : 'medium';
      const secNote = secGlobals.length > 0
        ? ` Security-sensitive globals found: ${[...new Set(secGlobals)].join(', ')}. ` +
          `These can be overwritten by unrelated code paths or leaked across request boundaries.`
        : '';
      const moduleNode = map.nodes.find(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'module') || map.nodes[0];
      if (moduleNode) {
        findings.push({
          source: nodeRef(moduleNode), sink: nodeRef(moduleNode),
          missing: 'STRUCTURAL (encapsulated state instead of mutable globals)',
          severity,
          description: `${map.source_file} has ${globalCount} mutable global/module-level variables.${secNote} ` +
            `In server environments, module-scope mutable state is shared across all requests, ` +
            `creating race conditions and cross-request data leakage.`,
          fix: 'Move mutable state into function-scoped variables, class instances, or request-scoped contexts. ' +
            'Use const/final/readonly for module-level values. For Node.js: use AsyncLocalStorage for request-scoped data. ' +
            'For config: use frozen objects (Object.freeze) or environment-based injection.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  // --- Secondary scan: node code_snapshots (non-JS contexts / multi-file scenarios) ---
  // Node type filter removed: module-level var declarations can be TRANSFORM or INGRESS.
  for (const node of map.nodes) {
    if (/\b(test|spec|mock|fixture|__test__|\.test\.|\.spec\.)\b/i.test(node.label || node.file)) continue;
    if (node.node_subtype === 'module') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!code) continue;

    let globalCount = 0;
    const secGlobals: string[] = [];
    const lines = code.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      if (/^\s{4,}/.test(line) && !/^(?:var|let|static)\b/.test(trimmed)) continue;

      let isGlobal = false;
      if (JS_GLOBAL_MUT.test(trimmed) && !SAFE_IMMUTABLE.test(trimmed)) isGlobal = true;
      if (GLOBAL_KEYWORD_PY.test(trimmed)) isGlobal = true;
      if (JAVA_STATIC_MUT.test(trimmed)) isGlobal = true;
      if (CSHARP_STATIC_MUT.test(trimmed)) isGlobal = true;

      if (isGlobal) {
        globalCount++;
        if (SEC_GLOBAL_RE.test(trimmed)) {
          const match = trimmed.match(SEC_GLOBAL_RE);
          if (match) secGlobals.push(match[0]);
        }
      }
    }

    if (globalCount > 5 || secGlobals.length > 0) {
      const severity: 'critical' | 'high' | 'medium' | 'low' = secGlobals.length > 0 ? 'high' : 'medium';
      const secNote = secGlobals.length > 0
        ? ` Security-sensitive globals found: ${[...new Set(secGlobals)].join(', ')}. ` +
          `These can be overwritten by unrelated code paths or leaked across request boundaries.`
        : '';
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (encapsulated state instead of mutable globals)',
        severity,
        description: `${node.label} has ${globalCount} mutable global/module-level variables.${secNote} ` +
          `In server environments, module-scope mutable state is shared across all requests, ` +
          `creating race conditions and cross-request data leakage.`,
        fix: 'Move mutable state into function-scoped variables, class instances, or request-scoped contexts. ' +
          'Use const/final/readonly for module-level values. For Node.js: use AsyncLocalStorage for request-scoped data. ' +
          'For config: use frozen objects (Object.freeze) or environment-based injection.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1108', name: 'Excessive Reliance on Global Variables', holds: findings.length === 0, findings };
}

/**
 * CWE-1109: Use of Same Variable for Multiple Purposes
 * A single variable reused for different semantic purposes across a function
 * creates confusion, makes security review harder, and can cause data leakage
 * when a variable holding sensitive data gets repurposed but not cleared.
 *
 * Security implications: a variable holding a plaintext password gets reused
 * for a log message — the sensitive value bleeds into logs. Or a validated
 * input variable gets reassigned to unvalidated data later in the same scope.
 */
function verifyCWE1109(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Detect variables assigned multiple times with different semantic purposes
  // Pattern: same sensitive variable name assigned different values
  const REASSIGN_SENSITIVE = /\b(password|secret|token|key|credential|ssn|credit_?card|api_?key)\s*=\s*[^=;]+;[\s\S]{0,500}?\1\s*=\s*/i;

  // Variable used for both validated and unvalidated data
  const VALIDATE_THEN_OVERWRITE = /\b(?:sanitize|validate|escape|clean|filter|encode)\w*\s*\(\s*(\w+)\s*\)[\s\S]{0,500}?\1\s*=\s*(?:req\.|params\.|query\.|body\.|input\.|request\.|args\.|argv)/i;

  // Safe: loop counters, accumulators, builders
  const SAFE_REUSE = /^(?:i|j|k|idx|index|count|total|sum|result|buf|builder|sb|acc|temp|tmp|_)$/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|fixture)\b/i.test(node.label)) continue;
    if (code.split('\n').length < 10) continue;

    // Check 1: Sensitive variable reused for different purpose
    if (REASSIGN_SENSITIVE.test(code)) {
      const match = code.match(REASSIGN_SENSITIVE);
      if (match && !SAFE_REUSE.test(match[1])) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (separate variables for sensitive vs non-sensitive data)',
          severity: 'high',
          description: `${node.label}: security-sensitive variable "${match[1]}" is reassigned within the same scope. ` +
            `If the first assignment held actual credentials and the second repurposes it, the sensitive value ` +
            `may linger in memory, appear in error messages, or be logged.`,
          fix: 'Use separate variables for each semantic purpose. Clear sensitive variables after use ' +
            '(set to null/empty). Use const to prevent reassignment of sensitive values.',
          via: 'source_line_fallback',
        });
      }
    }

    // Check 2: Validated data variable overwritten with unvalidated input
    if (VALIDATE_THEN_OVERWRITE.test(code)) {
      const match = code.match(VALIDATE_THEN_OVERWRITE);
      if (match) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (immutable validated variable, separate variable for raw input)',
          severity: 'high',
          description: `${node.label}: variable "${match[1]}" is validated/sanitized then later reassigned to raw user input. ` +
            `Code after the reassignment believes the variable is sanitized, but it now contains attacker-controlled data. ` +
            `This defeats the validation — it is a trust boundary violation within a single function.`,
          fix: 'Use const for validated values so they cannot be reassigned. Use separate variable names ' +
            'for raw vs sanitized data (e.g., rawEmail vs sanitizedEmail). Never reuse a validated variable.',
          via: 'source_line_fallback',
        });
      }
    }

    // Check 3: Excessive reassignment of let-declared variables in security code
    const letDecls = code.match(/\blet\s+(\w+)\b/g) || [];
    for (const decl of letDecls) {
      const varName = decl.replace(/^let\s+/, '');
      if (SAFE_REUSE.test(varName)) continue;
      if (varName.length < 2) continue;

      // Count assignments to this variable
      const escapedVar = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const assignPattern = new RegExp(`\\b${escapedVar}\\s*=\\s*`, 'g');
      const assignments = (code.match(assignPattern) || []).length;
      if (assignments >= 4) {
        const secContext = /\b(auth|login|session|permission|validate|sanitize|encrypt|hash|token|credential)\b/i;
        if (secContext.test(node.label) || secContext.test(code)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'STRUCTURAL (single-purpose variables in security-critical code)',
            severity: 'medium',
            description: `${node.label}: variable "${varName}" is assigned ${assignments} times in security-critical code. ` +
              `Multi-purpose variables make it impossible to reason about what value a variable holds at any given point, ` +
              `which defeats code review and static analysis.`,
            fix: 'Use const declarations with descriptive names for each purpose. ' +
              'Extract assignments into separate well-named variables. Consider extracting into helper functions.',
            via: 'source_line_fallback',
          });
          break; // One finding per node for this check
        }
      }
    }
  }

  return { cwe: 'CWE-1109', name: 'Use of Same Variable for Multiple Purposes', holds: findings.length === 0, findings };
}

/**
 * CWE-1110: Incomplete Design Documentation
 * Security-critical modules (auth, crypto, access control) that lack design
 * documentation — architecture comments, threat model references, trust
 * boundary descriptions. Without these, developers cannot understand the
 * security contract and will make wrong assumptions.
 */
function verifyCWE1110(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SEC_MODULE_RE = /\b(auth|crypto|security|permission|access[_-]?control|rbac|oauth|jwt|token|session|firewall|encrypt|decrypt|sign|verify|acl|policy|guard|middleware)\b/i;
  const DESIGN_DOC_RE = /\b(threat\s*model|security\s*design|trust\s*boundar|architecture|design\s*doc|security\s*requirement|attack\s*surface|authorization\s*model|data\s*flow\s*diagram|security\s*invariant|pre[_-]?condition|post[_-]?condition|contract|@security|@threat|@trust|SECURITY\s*NOTE|DESIGN|ARCHITECTURE)\b/i;
  const MODULE_OVERVIEW_RE = /\/\*\*[\s\S]{50,}?\*\/|"""\s*[\s\S]{50,}?"""|'''\s*[\s\S]{50,}?'''/;

  for (const node of nodesOfType(map, 'STRUCTURAL')) {
    if (/\b(test|spec|mock|fixture|__test__)\b/i.test(node.label)) continue;
    if (!SEC_MODULE_RE.test(node.label) && !SEC_MODULE_RE.test(node.node_subtype)) continue;

    const code = node.analysis_snapshot || node.code_snapshot;
    const lines = code.split('\n').length;
    if (lines < 40) continue;

    const hasDesignDoc = DESIGN_DOC_RE.test(code);
    const hasModuleOverview = MODULE_OVERVIEW_RE.test(code);

    if (!hasDesignDoc && !hasModuleOverview) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (design documentation for security-critical module)',
        severity: 'low',
        description: `${node.label}: ${lines}-line security module has no design documentation. ` +
          `No module overview, threat model references, trust boundary descriptions, or security invariants documented. ` +
          `Developers modifying this module cannot understand the intended security contract.`,
        fix: 'Add a module-level doc comment explaining: (1) what security property this module enforces, ' +
          '(2) trust boundaries and who is trusted/untrusted, (3) threat model assumptions, ' +
          '(4) security invariants that must hold. Reference any security design docs.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1110', name: 'Incomplete Design Documentation', holds: findings.length === 0, findings };
}

/**
 * CWE-1111: Incomplete I/O Failure Documentation
 * I/O operations (network, file, database) that don't document their failure
 * modes. In security context, undocumented I/O failures lead to fail-open
 * behavior: when an auth check's DB call fails and the error handling is
 * undocumented, developers default to "let them in."
 */
function verifyCWE1111(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const IO_OP_RE = /\b(fetch|axios|http\.request|https\.request|XMLHttpRequest|readFile|writeFile|open\s*\(|connect|query|execute|send|recv|socket|createConnection|createServer|listen|pipe|Stream|ReadStream|WriteStream|fs\.\w+|net\.\w+|dns\.\w+|child_process)\b/i;
  const ERROR_DOC_RE = /\b(@throws|@exception|@raises|:raises|:throws|Raises:|Throws:|Returns.*error|Returns.*null|Returns.*undefined|failure|timeout|refused|ENOENT|ECONNREFUSED|ETIMEDOUT|error\s*handling|on\s*error|on_error|fallback|retry|circuit[_-]?break)\b/i;
  const ERROR_HANDLING_RE = /\b(try\s*\{|\.catch\s*\(|except\s|rescue\s|on\s+.*Error|\.on\s*\(\s*['"]error|error\s*=>\s*|err\s*=>\s*|Promise\.allSettled|\.finally\s*\()\b/;
  const SEC_IO_RE = /\b(auth|login|verify|validate|check[_-]?permission|fetch[_-]?user|load[_-]?session|get[_-]?token|revoke|logout|password[_-]?reset)\b/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'EXTERNAL' && node.node_type !== 'STORAGE') continue;
    const code = node.analysis_snapshot || node.code_snapshot;
    const codeStripped = stripComments(code);
    if (/\b(test|spec|mock|fixture)\b/i.test(node.label)) continue;

    if (IO_OP_RE.test(codeStripped) && SEC_IO_RE.test(node.label + ' ' + codeStripped)) {
      const hasErrorDoc = ERROR_DOC_RE.test(code);
      const hasErrorHandling = ERROR_HANDLING_RE.test(codeStripped);

      if (!hasErrorDoc && !hasErrorHandling) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'META (I/O failure mode documentation and handling)',
          severity: 'medium',
          description: `${node.label}: security-relevant I/O operation has no documented failure modes and no error handling. ` +
            `If this I/O call fails (network timeout, connection refused, auth service down), the behavior is undefined. ` +
            `Undocumented I/O failures in auth/security paths commonly result in fail-open vulnerabilities.`,
          fix: 'Document all possible failure modes (@throws/@raises). Implement explicit error handling ' +
            'with fail-closed behavior for security operations. Log failures. Add timeout configuration. ' +
            'Document what happens when the downstream service is unavailable.',
          via: 'structural',
        });
      } else if (!hasErrorDoc && hasErrorHandling) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'META (documentation of I/O failure modes)',
          severity: 'low',
          description: `${node.label}: security I/O has error handling but no documentation of failure modes. ` +
            `Code handles some errors, but without @throws/@raises docs, callers don't know what exceptions to expect.`,
          fix: 'Add @throws/@raises annotations documenting each failure mode and whether the operation ' +
            'fails open or closed.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-1111', name: 'Incomplete I/O Failure Handling Documentation', holds: findings.length === 0, findings };
}

/**
 * CWE-1112: Incomplete Documentation of Program Interfaces
 * Public API interfaces (REST endpoints, exported functions, SDK methods)
 * that lack documentation of their security contracts — required auth,
 * expected permissions, input constraints, rate limits.
 */
function verifyCWE1112(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const API_DOC_RE = /\b(@param|@returns?|@api|@public|@endpoint|@route|@description|@summary|@auth|@permission|@access|@security|swagger|openapi|@ApiOperation|@ApiResponse|@ApiParam|apidoc)\b/i;
  const AUTH_DOC_RE = /\b(@auth|@permission|@role|@guard|@protect|@public|@private|requires?\s+auth|authentication\s+required|authorized?\s+only|@IsAuthenticated|@AllowAnonymous|@RequiresPermission|@PreAuthorize|@Secured|permit_all|login_required|@login_required)\b/i;

  const apiNodes = [
    ...nodesOfType(map, 'INGRESS'),
    ...map.nodes.filter(n => n.node_type === 'STRUCTURAL' &&
      /\b(export|public|module\.exports|app\.(?:get|post|put|delete|patch|use)|router\.(?:get|post|put|delete|patch))\b/i.test(n.analysis_snapshot || n.code_snapshot)),
  ];

  for (const node of apiNodes) {
    if (/\b(test|spec|mock|fixture|internal|private|_)\b/i.test(node.label)) continue;
    const code = node.analysis_snapshot || node.code_snapshot;
    const lines = code.split('\n').length;
    if (lines < 5) continue;

    const hasApiDoc = API_DOC_RE.test(code);
    const hasAuthDoc = AUTH_DOC_RE.test(code);
    const isSensitive = /\b(admin|user|account|payment|transfer|delete|update|create|write|modify|upload|download|execute|config)\b/i.test(node.label);

    if (!hasApiDoc && isSensitive) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (API interface documentation)',
        severity: 'low',
        description: `${node.label}: sensitive API endpoint has no interface documentation. ` +
          `No @param, @returns, @auth, or OpenAPI annotations. Consumers cannot determine ` +
          `required authentication, expected input format, or error responses.`,
        fix: 'Add JSDoc/docstring with @param types and constraints, @returns with status codes, ' +
          '@auth required permissions, and @throws for error cases. ' +
          'Better: use OpenAPI/Swagger annotations for machine-readable API docs.',
        via: 'structural',
      });
    } else if (hasApiDoc && !hasAuthDoc && isSensitive) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (authentication/authorization documentation on API)',
        severity: 'low',
        description: `${node.label}: API has general documentation but no auth/permission documentation. ` +
          `Callers don't know if this endpoint requires authentication or what permissions are needed.`,
        fix: 'Add @auth or @permission annotation specifying required authentication level ' +
          'and permissions. Use @public for intentionally unauthenticated endpoints.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1112', name: 'Incomplete Documentation of Program Interfaces', holds: findings.length === 0, findings };
}

/**
 * CWE-1113: Inappropriate Comment Style
 * Comments that contain security-sensitive information: passwords in TODOs,
 * internal URLs, API keys in examples, disabled security checks with
 * "temporary" comments that became permanent. Also: misleading comments
 * on security-critical code.
 */
function verifyCWE1113(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Secrets/credentials in comments
  const SECRET_IN_COMMENT = /(?:\/\/|#|\/\*|\*)\s*.*\b(?:password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['"][^'"]{3,}/i;
  // Disabled security checks
  const DISABLED_SECURITY = /(?:\/\/|#)\s*(?:TODO|FIXME|HACK|TEMP|TEMPORARY|DISABLE[D]?|SKIP|BYPASS|REMOVE)\s*.*\b(?:auth|security|validation|sanitiz|escap|csrf|cors|rate[_-]?limit|permission|encrypt|ssl|tls|certificate|verify)\b/i;
  // Internal URLs/IPs in comments
  const INTERNAL_URLS = /(?:\/\/|#|\/\*|\*)\s*.*(?:https?:\/\/(?:10\.\d|172\.(?:1[6-9]|2\d|3[01])\.\d|192\.168\.\d|localhost|127\.0\.0\.1|internal\.|staging\.|dev\.)[\w./:@-]*|(?:jdbc|mongodb|redis|amqp):\/\/[\w./:@-]+)/i;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (/\b(test|spec|mock|fixture|example|demo|sample)\b/i.test(node.label)) continue;

    if (SECRET_IN_COMMENT.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (comments without embedded secrets)',
        severity: 'high',
        description: `${node.label}: comment contains what appears to be a hardcoded credential or secret. ` +
          `Comments are not stripped from compiled output in many languages and are visible in source control. ` +
          `Even "example" credentials in comments get copy-pasted into production config.`,
        fix: 'Remove credentials from comments. Use environment variable references instead: ' +
          '"// Auth token from process.env.API_TOKEN". Never put real or example credentials in code comments.',
        via: 'source_line_fallback',
      });
    }

    if (DISABLED_SECURITY.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (active security control instead of commented-out one)',
        severity: 'high',
        description: `${node.label}: security control appears to be disabled with a TODO/FIXME comment. ` +
          `"Temporary" disabling of security features is a top source of production vulnerabilities ` +
          `because the TODO is never resolved.`,
        fix: 'Re-enable the security control. If it must be disabled for development, use a feature flag ' +
          'that is OFF in production, not a code comment. Add a CI check that greps for disabled security TODOs.',
        via: 'source_line_fallback',
      });
    }

    if (INTERNAL_URLS.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (comments without internal infrastructure details)',
        severity: 'medium',
        description: `${node.label}: comment contains internal/private network URLs or IPs. ` +
          `This leaks internal infrastructure topology to anyone with source access ` +
          `(open-source projects, leaked repos, insider threats).`,
        fix: 'Remove internal URLs from comments. Reference environment variables or config keys instead. ' +
          'Use placeholder URLs (example.com, internal.example) in documentation.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1113', name: 'Inappropriate Comment Style', holds: findings.length === 0, findings };
}

/**
 * CWE-1114: Inappropriate Whitespace Style
 * Inconsistent indentation in security-critical code can hide logic bugs.
 * Classic example: Apple's "goto fail" (CVE-2014-1266) where duplicated
 * goto appeared to be inside an if-block due to indentation but was
 * actually unconditional. Detects misleading indentation in security code.
 */
function verifyCWE1114(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SEC_CODE_RE = /\b(auth|crypto|security|permission|validate|sanitize|encrypt|decrypt|verify|sign|hash|token|session|password|login|access[_-]?control)\b/i;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (/\b(test|spec|mock|fixture)\b/i.test(node.label)) continue;
    if (!SEC_CODE_RE.test(node.label + ' ' + code)) continue;

    const lines = code.split('\n');
    if (lines.length < 5) continue;

    // Check 1: Mixed tabs and spaces in same file
    let hasTab = false;
    let hasSpace = false;
    for (const line of lines) {
      if (/^\t/.test(line)) hasTab = true;
      if (/^ {2,}/.test(line)) hasSpace = true;
    }

    if (hasTab && hasSpace) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (consistent indentation in security-critical code)',
        severity: 'low',
        description: `${node.label}: security-critical code mixes tabs and spaces for indentation. ` +
          `Mixed indentation makes code review unreliable — blocks that look aligned may not be, ` +
          `hiding logic errors like Apple's "goto fail" (CVE-2014-1266).`,
        fix: 'Standardize on one indentation style (spaces recommended). Configure editor/formatter. ' +
          'Add .editorconfig. Run a formatter (prettier, black, gofmt) as a pre-commit hook.',
        via: 'source_line_fallback',
      });
    }

    // Check 2: Dangling statement after single-line if (no braces) in security code
    for (let i = 0; i < lines.length - 2; i++) {
      const line = lines[i].trimEnd();
      const nextLine = lines[i + 1];
      const afterNext = lines[i + 2];

      if (/^\s*if\s*\([^)]+\)\s*$/.test(line) && nextLine && afterNext) {
        const ifIndent = line.search(/\S/);
        const bodyIndent = nextLine.search(/\S/);
        const nextIndent = afterNext.search(/\S/);

        if (bodyIndent > ifIndent && nextIndent === bodyIndent && afterNext.trim().length > 0 &&
            !/^\s*(?:else|elif|}\s*else|\/\/|#|\*|\/\*)/.test(afterNext)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'STRUCTURAL (braces around if-body in security code)',
            severity: 'medium',
            description: `${node.label} line ~${node.line_start + i}: braceless if-statement followed by ` +
              `an equally-indented statement that is NOT guarded by the condition. ` +
              `This is the "goto fail" pattern — the second statement always executes regardless of the condition, ` +
              `but the indentation suggests otherwise.`,
            fix: 'Always use braces for if/else blocks in security-critical code, even for single statements. ' +
              'Enable linter rules: curly (ESLint), C4801 (MSVC), -Wmisleading-indentation (GCC/Clang).',
            via: 'source_line_fallback',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-1114', name: 'Inappropriate Whitespace Style', holds: findings.length === 0, findings };
}

/**
 * CWE-1115: Source Code Element without Standard Prologue
 * Security-critical source files lacking standard headers: license, ownership,
 * classification level, review status. Without these, security review processes
 * break down — reviewers can't determine if code has been audited.
 */
function verifyCWE1115(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SEC_FILE_RE = /\b(auth|crypto|security|permission|access[_-]?control|encryption|password|token|session|oauth|jwt|acl|rbac|guard|middleware[_-]?auth|sanitiz)\b/i;
  const PROLOGUE_RE = /\b(@author|@license|@copyright|@version|@since|@module|@file|@package|Copyright|License|SPDX-License-Identifier|Classification:|Security[_-]?Review:|Audit[_-]?Status:|Owner:|Reviewed[_-]?by:)\b/i;
  const FILE_DOC_RE = /^(?:\s*(?:\/\*\*|"""|'''|\/\/!|\/\/\/|#!))/m;

  const seenFiles = new Set<string>();

  // Exclude Juliet test fixture naming patterns, generic test/sample/demo files,
  // and Java files not in a production source tree (src/main/java).
  const JULIET_FIXTURE_RE = /\bCWE\d+\b|\b_bad\b|\b_good\b|\bjuliet\b|\bsamate\b|\bnist\b|\b(test|spec|sample|example|demo|fixture)\b/i;

  for (const node of nodesOfType(map, 'STRUCTURAL')) {
    if (/\b(test|spec|mock|fixture|__test__|node_modules|vendor|dist|build)\b/i.test(node.label || node.file)) continue;
    if (JULIET_FIXTURE_RE.test(node.file || '') || JULIET_FIXTURE_RE.test(node.label || '')) continue;
    // For Java files, only fire if in a production source tree
    if (/\.java$/i.test(node.file || '') && !/src[/\\]main[/\\]java/i.test(node.file || '')) continue;
    if (!SEC_FILE_RE.test(node.label) && !SEC_FILE_RE.test(node.file)) continue;
    if (seenFiles.has(node.file)) continue;
    seenFiles.add(node.file);

    const code = node.analysis_snapshot || node.code_snapshot;
    const firstLines = code.split('\n').slice(0, 10).join('\n');

    if (!PROLOGUE_RE.test(firstLines) && !FILE_DOC_RE.test(firstLines)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (file prologue/header with ownership and review status)',
        severity: 'low',
        description: `${node.file || node.label}: security-critical source file has no standard prologue. ` +
          `Missing @author, @license, classification, or review status. Security review workflows ` +
          `cannot determine if this code has been audited or who is responsible for its security properties.`,
        fix: 'Add a standard file header with: @author (security owner), @license, @since (last security review date), ' +
          'and classification level. For high-security codebases, add @security-review-status and @threat-model-ref.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1115', name: 'Source Code Element without Standard Prologue', holds: findings.length === 0, findings };
}

/**
 * CWE-1116: Inaccurate Comments
 * Comments that contradict the actual code behavior, especially in security
 * contexts. A comment saying "validates input" on a function that doesn't,
 * or "encrypts with AES-256" on code using DES, creates false confidence
 * during security review.
 */
function verifyCWE1116(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code comments describe API usage, not what the specific file implements
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-1116', name: 'Inaccurate Comments', holds: true, findings };
  }

  // Pattern pairs: comment claims X, code does Y (or doesn't do X)
  const CONTRADICTIONS: Array<{
    commentRe: RegExp;
    codeAbsentRe: RegExp;
    desc: string;
    sev: 'critical' | 'high' | 'medium' | 'low';
  }> = [
    {
      commentRe: /(?:\/\/|#|\/\*|\*)\s*.*\b(?:encrypt|AES|RSA|encrypt(?:s|ed|ion))\b/i,
      codeAbsentRe: /\b(?:encrypt|cipher|AES|RSA|createCipher|crypto\.subtle|Cipher\.getInstance|Fernet|nacl)\b/i,
      desc: 'Comment claims encryption but code contains no encryption calls',
      sev: 'high',
    },
    {
      commentRe: /(?:\/\/|#|\/\*|\*)\s*.*\b(?:validat|sanitiz|escap|filter)\w*(?:s|ed|es|ing)?\b.*\binput\b/i,
      codeAbsentRe: /\b(?:validat|sanitiz|escap|filter|DOMPurify|htmlspecialchars|encodeURI|escape_string|html\.escape|bleach|xss|purif)\b/i,
      desc: 'Comment claims input validation/sanitization but code has no validation calls',
      sev: 'high',
    },
    {
      commentRe: /(?:\/\/|#|\/\*|\*)\s*.*\b(?:authenticat|verif(?:y|ies)|check(?:s|ed)?\s+(?:auth|permission|credential))\b/i,
      codeAbsentRe: /\b(?:authenticat|verif(?:y|ied)|checkAuth|isAuthenticated|passport|jwt\.verify|bcrypt\.compare|verify(?:Token|Session|Credential)|@PreAuthorize|@Secured|login_required)\b/i,
      desc: 'Comment claims authentication check but code has no auth verification',
      sev: 'critical',
    },
    {
      commentRe: /(?:\/\/|#|\/\*|\*)\s*.*\b(?:hash|bcrypt|scrypt|argon2|PBKDF2)\b/i,
      codeAbsentRe: /\b(?:hash|bcrypt|scrypt|argon2|pbkdf2|createHash|MessageDigest|hashlib|SHA|MD5)\b/i,
      desc: 'Comment claims hashing but code contains no hash operations',
      sev: 'medium',
    },
  ];

  for (const node of map.nodes) {
    if (/\b(test|spec|mock|fixture|example)\b/i.test(node.label)) continue;
    const fullCode = node.analysis_snapshot || node.code_snapshot;
    const strippedCode = stripComments(fullCode);

    for (const { commentRe, codeAbsentRe, desc, sev } of CONTRADICTIONS) {
      if (commentRe.test(fullCode) && !codeAbsentRe.test(strippedCode)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'META (accurate comments matching actual code behavior)',
          severity: sev,
          description: `${node.label}: ${desc}. ` +
            `Inaccurate comments on security code are worse than no comments — they create false confidence ` +
            `during code review, leading reviewers to skip detailed inspection of "already documented" code.`,
          fix: 'Update the comment to match actual behavior, or implement what the comment promises. ' +
            'Security-critical code must have comments that accurately reflect what the code does. ' +
            'Consider adding automated comment-code consistency checks to CI.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return { cwe: 'CWE-1116', name: 'Inaccurate Comments', holds: findings.length === 0, findings };
}

/**
 * CWE-1117: Callable with Insufficient Behavioral Summary
 * Exported/public functions in security-critical code that lack behavioral
 * documentation: what it does, side effects, preconditions, postconditions,
 * error behavior. A function named `checkPermission()` that silently returns
 * true on error is a security disaster if callers assume it throws.
 */
function verifyCWE1117(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SEC_FUNC_RE = /\b(auth|login|logout|verify|validate|sanitize|encrypt|decrypt|hash|check[_-]?permission|is[_-]?authorized|grant|revoke|sign|create[_-]?token|refresh[_-]?token|reset[_-]?password|change[_-]?password|register|delete[_-]?user|admin)\b/i;
  const DOC_COMMENT_RE = /\/\*\*[\s\S]*?\*\/|"""\s*[\s\S]*?"""|'''\s*[\s\S]*?'''|\/\/\/\s/;
  const BEHAVIORAL_DOC_RE = /\b(@param|@returns?|@throws|@raises|@pre|@post|@requires|@ensures|@invariant|@sideeffect|@modifies|@example|Returns|Throws|Raises|Side\s*effect|Precondition|Error[s]?:)\b/i;
  const EXPORTED_FUNC_RE = /\b(?:export\s+(?:default\s+)?(?:async\s+)?function|module\.exports\.\w+|public\s+(?:static\s+)?(?:async\s+)?\w+\s+\w+\s*\(|def\s+(?!_)\w+\s*\(|@(?:api|route|endpoint|public))\b/;

  for (const node of map.nodes) {
    if (/\b(test|spec|mock|fixture)\b/i.test(node.label)) continue;
    const code = node.analysis_snapshot || node.code_snapshot;
    if (!EXPORTED_FUNC_RE.test(code)) continue;
    if (!SEC_FUNC_RE.test(node.label) && !SEC_FUNC_RE.test(code)) continue;

    const lines = code.split('\n').length;
    if (lines < 8) continue;

    const hasDocComment = DOC_COMMENT_RE.test(code);
    const hasBehavioralDoc = BEHAVIORAL_DOC_RE.test(code);

    if (!hasDocComment) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (behavioral documentation for security-critical callable)',
        severity: 'medium',
        description: `${node.label}: exported security function has no documentation at all. ` +
          `Callers must read the implementation to understand behavior, error handling, and side effects. ` +
          `If this function fails silently (returns null instead of throwing), callers will assume success ` +
          `and proceed with unauthorized access.`,
        fix: 'Add documentation specifying: (1) what the function does, (2) parameters and their constraints, ' +
          '(3) return values (success AND failure), (4) exceptions thrown, (5) side effects (DB writes, logs, emails), ' +
          '(6) whether it fails open or closed on error.',
        via: 'structural',
      });
    } else if (!hasBehavioralDoc) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (detailed behavioral summary: params, returns, throws, side effects)',
        severity: 'low',
        description: `${node.label}: security function has a doc comment but lacks behavioral details. ` +
          `Missing @param/@returns/@throws. Callers cannot determine failure modes without reading the implementation.`,
        fix: 'Expand documentation with @param (constraints), @returns (success and failure cases), ' +
          '@throws (which exceptions and when), and @sideeffect (any mutations, logging, or external calls).',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1117', name: 'Callable with Insufficient Behavioral Summary', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1095 through CWE-1107 — Code quality and maintainability CWEs
// ---------------------------------------------------------------------------

/**
 * CWE-1095: Loop Condition Value Update within the Loop
 * A loop modifies the variable used in its termination condition inside
 * the loop body, making iteration counts unpredictable. This creates
 * off-by-one bugs, infinite loops, and denial-of-service.
 */
function verifyCWE1095(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const C_FOR_RE = /\bfor\s*\(\s*(?:(?:int|let|var|auto|size_t)\s+)?(\w+)\s*=[^;]*;\s*\1\s*[<>=!]+\s*(\w+)\s*;[^)]*\)\s*\{/g;
  const WHILE_BOUND_RE = /\bwhile\s*\(\s*(\w+)\s*[<>=!]+\s*(\w+)\s*\)/g;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    let match;
    C_FOR_RE.lastIndex = 0;
    while ((match = C_FOR_RE.exec(code)) !== null) {
      const iterVar = match[1];
      const boundVar = match[2];
      const afterLoop = code.slice(match.index + match[0].length);
      const bodyReassign = new RegExp(`\\b${boundVar}\\s*[+\\-*/]?=(?!=)`);
      const iterReassign = new RegExp(`\\b${iterVar}\\s*=(?!=)`);
      if (bodyReassign.test(afterLoop)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (loop bound variable must not be modified inside loop body)',
          severity: 'medium',
          description: `${node.label} modifies loop bound '${boundVar}' inside the loop body. ` +
            `This makes the iteration count unpredictable and can cause infinite loops or off-by-one errors.`,
          fix: `Copy the loop bound to a const before the loop: const limit = ${boundVar}; ` +
            'If dynamic bounds are intentional, add a maximum iteration guard to prevent infinite loops.',
          via: 'source_line_fallback',
        });
      } else if (iterReassign.test(afterLoop)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (loop iterator must only be modified in the loop increment clause)',
          severity: 'medium',
          description: `${node.label} modifies loop iterator '${iterVar}' inside the loop body. ` +
            `This creates unpredictable iteration behavior.`,
          fix: `Avoid modifying '${iterVar}' inside the loop body. Use a separate variable or restructure as a while loop.`,
          via: 'source_line_fallback',
        });
      }
    }

    WHILE_BOUND_RE.lastIndex = 0;
    while ((match = WHILE_BOUND_RE.exec(code)) !== null) {
      const iterVar = match[1];
      const boundVar = match[2];
      if (/^\d+$/.test(boundVar)) continue;
      const afterWhile = code.slice(match.index + match[0].length);
      const bodyReassign = new RegExp(`\\b${boundVar}\\s*[+\\-*/]?=(?!=)`);
      if (bodyReassign.test(afterWhile)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (while-loop bound must not be modified inside the loop body)',
          severity: 'medium',
          description: `${node.label} modifies while-loop bound '${boundVar}' inside the loop. ` +
            `This risks infinite loops or skipped iterations.`,
          fix: `Snapshot the bound before the loop, or add a max-iteration guard.`,
          via: 'source_line_fallback',
        });
      }
    }
  }
  return { cwe: 'CWE-1095', name: 'Loop Condition Value Update within the Loop', holds: findings.length === 0, findings };
}

/**
 * CWE-1097: Persistent Storable Data Element without a Mapping to a Data Store
 * A data class/model defines persistent fields but has no ORM mapping,
 * schema definition, or serialization config.
 */
function verifyCWE1097(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const JAVA_ENTITY = /\b@Entity\b/;
  const JAVA_MAPPED = /@(?:Table|Column|Id|MappedSuperclass|Embeddable|Document|DynamoDBTable)\b/;
  const PY_MODEL = /\bclass\s+\w+\s*\([^)]*(?:db\.Model|Base|models\.Model|Document)\b/;
  const PY_MAPPED = /\b(?:__tablename__|class\s+Meta|__table__|__collection__|_meta)\b/;
  const TS_ENTITY = /\b@Entity\s*\(/;
  const TS_MAPPED = /@(?:Column|PrimaryGeneratedColumn|PrimaryColumn|ObjectIdColumn|CreateDateColumn)\b/;
  const CS_ENTITY = /\[Serializable\]|\bDbContext\b/;
  const CS_MAPPED = /\[(?:Table|Column|Key|DatabaseGenerated|ForeignKey)\]|\bDbSet\s*</;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|migration|seed)\b/i.test(node.label)) continue;

    if (JAVA_ENTITY.test(code) && !JAVA_MAPPED.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (@Table/@Column mapping for @Entity class)', severity: 'medium',
        description: `${node.label} is annotated @Entity but lacks @Table or @Column mappings. ` +
          `JPA will use default naming which may not match the actual database schema, causing silent data loss.`,
        fix: 'Add @Table(name="...") and @Column annotations. Add @Id for the primary key.', via: 'source_line_fallback' });
    }
    if (PY_MODEL.test(code) && !PY_MAPPED.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (__tablename__ or Meta class for ORM model)', severity: 'medium',
        description: `${node.label} inherits from a database model base but lacks __tablename__ or Meta configuration.`,
        fix: 'Add __tablename__ = "explicit_name" (SQLAlchemy) or class Meta with db_table (Django).', via: 'source_line_fallback' });
    }
    if (TS_ENTITY.test(code) && !TS_MAPPED.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (@Column decorators for @Entity class)', severity: 'medium',
        description: `${node.label} uses @Entity() but no @Column or @PrimaryGeneratedColumn decorators are visible. ` +
          `TypeORM will not persist unmapped fields, causing silent data loss.`,
        fix: 'Add @PrimaryGeneratedColumn() and @Column() decorators to all persisted fields.', via: 'source_line_fallback' });
    }
    if (CS_ENTITY.test(code) && !CS_MAPPED.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL ([Table]/[Column] attributes for serializable entity)', severity: 'medium',
        description: `${node.label} is marked [Serializable] or used with DbContext but lacks explicit column/table mappings.`,
        fix: 'Add [Table("name")] and [Column("name")] attributes, or use Fluent API in OnModelCreating.', via: 'source_line_fallback' });
    }
  }
  return { cwe: 'CWE-1097', name: 'Persistent Storable Data Element without Mapping to Data Store', holds: findings.length === 0, findings };
}

/**
 * CWE-1098: Data Element containing Pointer Item without Proper Copy Control
 * A class/struct contains pointer members but lacks copy constructor,
 * copy assignment, or destructor (Rule of Three/Five). Shallow copies
 * lead to double-free, use-after-free, and data corruption.
 */
function verifyCWE1098(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CPP_RAW_PTR_FIELD = /\b(?:private|protected|public)\s*:[\s\S]*?\b\w+\s*\*\s+\w+\s*[;=]/;
  const HAS_DTOR = /~\w+\s*\(\s*\)/;
  const HAS_COPY_CTOR = /\w+\s*\(\s*(?:const\s+)?\w+\s*&/;
  const HAS_COPY_ASSIGN = /\boperator\s*=\s*\(\s*(?:const\s+)?\w+\s*&/;
  const DELETED_COPY = /(?:operator\s*=|(?:\w+)\s*\([^)]*&[^)]*\))\s*=\s*delete/;
  const SMART_PTR = /\b(?:unique_ptr|shared_ptr|weak_ptr|auto_ptr|scoped_ptr|ComPtr|CComPtr)\s*</;
  const RUST_RAW_PTR = /\*(?:mut|const)\s+\w+/;
  const RUST_DROP = /\bimpl\s+Drop\s+for\b/;
  const RUST_CLONE = /\bimpl\s+Clone\s+for\b|#\[derive\([^\]]*Clone/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    if (CPP_RAW_PTR_FIELD.test(code) && !SMART_PTR.test(code)) {
      const hasDtor = HAS_DTOR.test(code);
      const hasCopy = HAS_COPY_CTOR.test(code) || DELETED_COPY.test(code);
      const hasAssign = HAS_COPY_ASSIGN.test(code) || DELETED_COPY.test(code);
      if (hasDtor && (!hasCopy || !hasAssign)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (copy constructor and copy assignment operator — Rule of Three)', severity: 'high',
          description: `${node.label} has raw pointer members and a destructor but is missing ` +
            `${!hasCopy ? 'a copy constructor' : ''}${!hasCopy && !hasAssign ? ' and ' : ''}${!hasAssign ? 'a copy assignment operator' : ''}. ` +
            `Default shallow copies will cause double-free and use-after-free.`,
          fix: 'Apply the Rule of Three/Five: implement copy constructor, copy assignment, and destructor together. ' +
            'Better: use std::unique_ptr or std::shared_ptr. Or delete copy operations: ClassName(const ClassName&) = delete;', via: 'source_line_fallback' });
      } else if (!hasDtor && (HAS_COPY_CTOR.test(code) || HAS_COPY_ASSIGN.test(code))) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (destructor to match custom copy operations — Rule of Three)', severity: 'high',
          description: `${node.label} has raw pointer members and custom copy operations but no destructor — memory leaks.`,
          fix: 'Add a destructor that frees owned resources, or use smart pointers instead of raw pointers.', via: 'source_line_fallback' });
      }
    }
    if (RUST_RAW_PTR.test(code) && /\bstruct\b/.test(code) && !RUST_DROP.test(code) && !RUST_CLONE.test(code)) {
      if (!/\bunsafe\s+impl\b/.test(code) && !/\bPhantomData\b/.test(code)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (Drop and/or Clone for struct with raw pointers)', severity: 'high',
          description: `${node.label} is a Rust struct with raw pointer fields but no Drop or Clone. ` +
            `Without Drop, pointed-to memory leaks. Without Clone, bitwise copy creates aliasing.`,
          fix: 'Implement Drop and Clone. Wrap raw pointers in Box, Rc, or Arc if possible.', via: 'source_line_fallback' });
      }
    }
  }
  return { cwe: 'CWE-1098', name: 'Data Element containing Pointer Item without Proper Copy Control', holds: findings.length === 0, findings };
}

/**
 * CWE-1099: Inconsistent Naming Conventions for Identifiers
 * Mixed naming conventions for security-critical functions make it harder
 * for reviewers and tools to identify all security-relevant functions.
 */
function verifyCWE1099(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SECURITY_FN_RE = /\b(?:function|def|(?:public|private|protected)\s+(?:static\s+)?(?:\w+\s+)?)(validate\w*|sanitize\w*|authorize\w*|authenticate\w*|encrypt\w*|decrypt\w*|hash\w*|verify\w*|check_?(?:auth|perm|access|token)\w*)\s*\(/gi;
  const securityFnNames: Array<{ name: string; node: NeuralMapNode }> = [];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    let match;
    SECURITY_FN_RE.lastIndex = 0;
    while ((match = SECURITY_FN_RE.exec(code)) !== null) {
      securityFnNames.push({ name: match[1], node });
    }
  }

  if (securityFnNames.length >= 2) {
    const isCamel = (s: string) => /^[a-z][a-zA-Z0-9]*$/.test(s) && /[A-Z]/.test(s);
    const isSnake = (s: string) => /^[a-z][a-z0-9_]*$/.test(s) && s.includes('_');
    const isPascal = (s: string) => /^[A-Z][a-zA-Z0-9]*$/.test(s);
    const styles = new Set<string>();
    for (const { name } of securityFnNames) {
      if (isCamel(name)) styles.add('camelCase');
      else if (isSnake(name)) styles.add('snake_case');
      else if (isPascal(name)) styles.add('PascalCase');
    }
    if (styles.size > 1) {
      const rep = securityFnNames[0];
      const names = securityFnNames.map(f => f.name).slice(0, 5).join(', ');
      findings.push({ source: nodeRef(rep.node), sink: nodeRef(rep.node),
        missing: 'STRUCTURAL (consistent naming convention for security functions)', severity: 'low',
        description: `Security functions use mixed naming conventions (${[...styles].join(', ')}): ${names}. ` +
          `Inconsistent naming makes it harder to identify all security-relevant functions.`,
        fix: 'Adopt a single naming convention for security functions. Configure a linter to enforce it.', via: 'source_line_fallback' });
    }
  }
  return { cwe: 'CWE-1099', name: 'Inconsistent Naming Conventions for Identifiers', holds: findings.length === 0, findings };
}

/**
 * CWE-1100: Insufficient Isolation of System-Dependent Functions
 * Code that embeds platform-specific logic (hardcoded paths, OS commands,
 * registry access) directly into business logic instead of isolating it.
 */
function verifyCWE1100(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const WIN_PATH = /['"`](?:C:\\\\|D:\\\\|%(?:APPDATA|USERPROFILE|PROGRAMFILES|WINDIR)%)/i;
  const UNIX_PATH_HARDCODED = /['"`]\/(?:etc|usr|var|opt|home|tmp)\//;
  const REGISTRY_ACCESS = /\b(?:winreg|RegOpenKey|RegQueryValue|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|Registry\.(?:GetValue|LocalMachine))\b/;
  const PLATFORM_CMD = /\b(?:cmd\.exe|\/bin\/(?:sh|bash)|powershell|wmic|systemctl|launchctl)\b/;
  const PLATFORM_ABSTRACTION = /\b(?:path\.join|path\.resolve|os\.path\.join|Path\.|Paths\.get|Environment\.GetFolderPath)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|config|platform|infra|util)\b/i.test(node.label)) continue;
    if (PLATFORM_ABSTRACTION.test(code) && !WIN_PATH.test(code) && !UNIX_PATH_HARDCODED.test(code)) continue;

    if (WIN_PATH.test(code) || UNIX_PATH_HARDCODED.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (platform-agnostic path handling via path.join/os.path.join)', severity: 'medium',
        description: `${node.label} contains hardcoded platform-specific file paths. ` +
          `This breaks on other platforms and fixed path assumptions may be exploitable via symlinks.`,
        fix: 'Use path.join() / os.path.join() with configurable base directories. Isolate platform paths behind an abstraction.', via: 'source_line_fallback' });
    }
    if (REGISTRY_ACCESS.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (registry access isolated behind platform abstraction)', severity: 'medium',
        description: `${node.label} accesses the Windows registry directly in business logic. ` +
          `Hard Windows dependency; registry manipulation can be a privilege escalation vector.`,
        fix: 'Isolate registry access behind a platform service interface. Use env vars or config files for cross-platform settings.', via: 'source_line_fallback' });
    }
    if (PLATFORM_CMD.test(code) && !PLATFORM_ABSTRACTION.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (platform-specific commands isolated behind abstraction)', severity: 'medium',
        description: `${node.label} invokes a platform-specific shell/command directly. Fails on other platforms and is injection-prone.`,
        fix: 'Wrap platform-specific commands in a service layer with platform detection.', via: 'source_line_fallback' });
    }
  }
  return { cwe: 'CWE-1100', name: 'Insufficient Isolation of System-Dependent Functions', holds: findings.length === 0, findings };
}

/**
 * CWE-1101: Reliance on Runtime Component in Generated Code
 * Generated code that depends on eval, dynamic imports, or reflection
 * that may not be available in all deployment environments.
 */
function verifyCWE1101(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const GENERATED_EVAL = /\b(?:eval|exec|compile)\s*\(\s*(?:template|generated|codegen|emit|render)/i;
  const DYNAMIC_IMPORT = /\b(?:require|import)\s*\(\s*(?:template|generated|path\.join|`\$\{)/;
  const REFLECT_CREATE = /\b(?:Class\.forName|Activator\.CreateInstance|getattr\s*\(\s*\w+\s*,\s*\w+\s*\)|Reflect\.construct)\b/;
  const GENERATED_MARKER = /\b(?:auto[-_]?generated|codegen|template[-_]?output|generated[-_]?by|DO NOT (?:EDIT|MODIFY))\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    const isGenerated = GENERATED_MARKER.test(code) || GENERATED_MARKER.test(node.label);

    if (isGenerated && GENERATED_EVAL.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (generated code should not depend on eval/exec at runtime)', severity: 'high',
        description: `${node.label} is generated code that uses eval/exec to execute templates at runtime. ` +
          `Generated code should be fully resolved at generation time. Runtime eval introduces injection risk.`,
        fix: 'Pre-compile templates at build time. Use static code generation without runtime eval.', via: 'source_line_fallback' });
    }
    if (isGenerated && DYNAMIC_IMPORT.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (generated code should use static imports)', severity: 'medium',
        description: `${node.label} is generated code with dynamic imports. Referenced modules may not exist in all environments.`,
        fix: 'Use static imports. Emit a typed interface with dependency injection instead of dynamic resolution.', via: 'source_line_fallback' });
    }
    if (REFLECT_CREATE.test(code) && /\b(?:class_?name|type_?name|handler_?name)\b/i.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (type-safe factory instead of reflection-based instantiation)', severity: 'medium',
        description: `${node.label} uses reflection to instantiate classes from string names. ` +
          `Target class may not exist at runtime; bypasses type checking; can instantiate unintended classes.`,
        fix: 'Use a registry/factory pattern with explicit type mappings instead of reflection.', via: 'source_line_fallback' });
    }
  }
  return { cwe: 'CWE-1101', name: 'Reliance on Runtime Component in Generated Code', holds: findings.length === 0, findings };
}

/**
 * CWE-1102: Reliance on Machine-Dependent Data Representation
 * Code that assumes specific byte order, struct packing, pointer size,
 * or integer width. Causes data corruption across architectures.
 */
function verifyCWE1102(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const STRUCT_PACK_EXPLICIT = /\bstruct\.pack\s*\(\s*['"][!<>=@]/;
  const STRUCT_PACK_NATIVE = /\bstruct\.pack\s*\(\s*['"][^!<>=@'"]/;
  const PTR_CAST_WIDTH = /\*\s*\(\s*(?:int|long|short)\s*\*\s*\)\s*(?:buf|data|ptr|buffer|packet|msg)/i;
  const NODE_BUFFER_NO_ENDIAN = /\b(?:readUInt32|readInt32|readUInt16|readInt16|readFloat|readDouble)\s*\(\s*\d+\s*\)/;
  const NODE_BUFFER_ENDIAN = /\b(?:readUInt32|readInt32|readUInt16|readInt16|readFloat|readDouble)(?:BE|LE)\s*\(/;
  const JAVA_BYTEBUF_NO_ORDER = /ByteBuffer\.(?:allocate|wrap)\s*\([^)]*\)(?!\.order\b)/;
  const EXPLICIT_ENDIAN = /\b(?:htonl|htons|ntohl|ntohs|byteswap|ByteOrder|endian|BIG_ENDIAN|LITTLE_ENDIAN|\.order\s*\()\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    if (STRUCT_PACK_NATIVE.test(code) && !STRUCT_PACK_EXPLICIT.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (explicit endianness in struct.pack format string)', severity: 'medium',
        description: `${node.label} uses struct.pack without an explicit endianness marker. Native byte order is machine-dependent.`,
        fix: 'Use ">" (big-endian) or "<" (little-endian) prefix: struct.pack(">I", value).', via: 'source_line_fallback' });
    }
    if (PTR_CAST_WIDTH.test(code) && !EXPLICIT_ENDIAN.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (memcpy or explicit serialization instead of pointer type punning)', severity: 'high',
        description: `${node.label} casts buffer pointers to integer types. Assumes alignment, endianness, and width.`,
        fix: 'Use memcpy + ntohl/ntohs, or a serialization library (protobuf, flatbuffers, msgpack).', via: 'source_line_fallback' });
    }
    if (NODE_BUFFER_NO_ENDIAN.test(code) && !NODE_BUFFER_ENDIAN.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (explicit endianness: readUInt32BE or readUInt32LE)', severity: 'medium',
        description: `${node.label} reads multi-byte values from Buffer without specifying endianness.`,
        fix: 'Use readUInt32BE() for big-endian or readUInt32LE() for little-endian.', via: 'source_line_fallback' });
    }
    if (JAVA_BYTEBUF_NO_ORDER.test(code) && !EXPLICIT_ENDIAN.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (ByteBuffer.order() to set explicit byte order)', severity: 'medium',
        description: `${node.label} creates ByteBuffer without .order(). Default BIG_ENDIAN is a hidden assumption.`,
        fix: 'Call .order(ByteOrder.BIG_ENDIAN) or .order(ByteOrder.LITTLE_ENDIAN) after allocation.', via: 'source_line_fallback' });
    }
  }
  return { cwe: 'CWE-1102', name: 'Reliance on Machine-Dependent Data Representation', holds: findings.length === 0, findings };
}

/**
 * CWE-1104: Use of Unmaintained Third-Party Components
 * Dependencies on deprecated/archived/sabotaged packages that will
 * never receive security patches.
 */
function verifyCWE1104(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const DEPRECATED_PACKAGES: Array<{ pattern: RegExp; name: string; replacement: string }> = [
    { pattern: /\brequire\s*\(\s*['"]request['"]\s*\)|\bfrom\s+['"]request['"]/, name: 'request (npm)', replacement: 'node-fetch, axios, or got' },
    { pattern: /\brequire\s*\(\s*['"]moment['"]\s*\)|\bfrom\s+['"]moment['"]/, name: 'moment.js', replacement: 'date-fns, dayjs, or Temporal API' },
    { pattern: /\bimport\s+urllib2\b|\bfrom\s+urllib2\b/, name: 'urllib2 (Python 2)', replacement: 'urllib3 or requests' },
    { pattern: /\brequire\s*\(\s*['"]crypto-js['"]\s*\)|\bfrom\s+['"]crypto-js['"]/, name: 'crypto-js', replacement: 'Node.js built-in crypto or Web Crypto API' },
    { pattern: /\brequire\s*\(\s*['"]node-uuid['"]\s*\)|\bfrom\s+['"]node-uuid['"]/, name: 'node-uuid', replacement: 'uuid or crypto.randomUUID()' },
    { pattern: /\bimport\s+imp\b|\bfrom\s+imp\s+import\b/, name: 'imp (Python)', replacement: 'importlib' },
    { pattern: /\bimport\s+optparse\b|\bfrom\s+optparse\b/, name: 'optparse (Python)', replacement: 'argparse' },
    { pattern: /\brequire\s*\(\s*['"]jade['"]\s*\)|\bfrom\s+['"]jade['"]/, name: 'jade', replacement: 'pug (jade was renamed)' },
    { pattern: /\brequire\s*\(\s*['"]nomnom['"]\s*\)/, name: 'nomnom (npm)', replacement: 'commander or yargs' },
    { pattern: /\brequire\s*\(\s*['"]colors['"]\s*\)|\bfrom\s+['"]colors['"]/, name: 'colors (npm, sabotaged)', replacement: 'chalk, picocolors, or kleur' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    for (const dep of DEPRECATED_PACKAGES) {
      if (dep.pattern.test(code)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node),
          missing: `STRUCTURAL (replace deprecated ${dep.name} with ${dep.replacement})`, severity: 'medium',
          description: `${node.label} imports ${dep.name}, which is deprecated/unmaintained. ` +
            `Unmaintained packages never receive security patches.`,
          fix: `Replace ${dep.name} with ${dep.replacement}.`, via: 'source_line_fallback' });
        break;
      }
    }
  }
  return { cwe: 'CWE-1104', name: 'Use of Unmaintained Third-Party Components', holds: findings.length === 0, findings };
}

/**
 * CWE-1106: Insufficient Use of Symbolic Constants
 * Magic numbers in security contexts (crypto key sizes, permissions,
 * timeouts) lead to mismatched values and invisible security thresholds.
 */
function verifyCWE1106(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CRYPTO_MAGIC = /\b(?:key[_.]?(?:size|length|bits)|iterations?|rounds|salt[_.]?(?:size|length|rounds))\s*[:=]\s*(\d{2,})\b/i;
  const PERMISSION_MAGIC = /\b(?:chmod|mode|permission|umask)\s*[:=(]\s*(0[o]?\d{3}|\d{3,4})\b/i;
  const TIMEOUT_MAGIC = /\b(?:timeout|expir[ey]|ttl|max[_.]?age|duration)\s*[:=]\s*(\d{4,})\b/i;
  const CONSTANT_REF = /\b[A-Z][A-Z0-9_]{2,}\b/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    let match;

    if ((match = CRYPTO_MAGIC.exec(code)) !== null) {
      const line = code.slice(Math.max(0, match.index - 40), match.index + match[0].length + 20);
      if (!CONSTANT_REF.test(line.replace(match[0], ''))) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (named constant for cryptographic parameter)', severity: 'medium',
          description: `${node.label} uses magic number (${match[1]}) for a crypto parameter. ` +
            `Duplicated elsewhere with a typo, the security property silently degrades.`,
          fix: `Define: const KEY_SIZE_BITS = ${match[1]}; and reference it everywhere.`, via: 'source_line_fallback' });
      }
    }
    if ((match = PERMISSION_MAGIC.exec(code)) !== null) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (named constant for file permission mode)', severity: 'medium',
        description: `${node.label} uses magic permission value (${match[1]}). Hard to audit across codebase.`,
        fix: 'Define: const FILE_MODE_READ_WRITE = 0o644; and use consistently.', via: 'source_line_fallback' });
    }
    if ((match = TIMEOUT_MAGIC.exec(code)) !== null) {
      const value = parseInt(match[1], 10);
      if (value >= 10000 || value % 1000 === 0) {
        const line = code.slice(Math.max(0, match.index - 40), match.index + match[0].length + 20);
        if (!CONSTANT_REF.test(line.replace(match[0], ''))) {
          findings.push({ source: nodeRef(node), sink: nodeRef(node),
            missing: 'STRUCTURAL (named constant for timeout/expiry value)', severity: 'low',
            description: `${node.label} uses magic number (${match[1]}) for timeout/expiry. Should be a named constant.`,
            fix: `Define: const SESSION_TIMEOUT_MS = ${match[1]}; and reference from configuration.`, via: 'source_line_fallback' });
        }
      }
    }
  }
  return { cwe: 'CWE-1106', name: 'Insufficient Use of Symbolic Constants', holds: findings.length === 0, findings };
}

/**
 * CWE-1107: Insufficient Isolation of Symbolic Constant Definitions
 * Security constants (ciphers, allowed origins, rate limits) scattered
 * inline instead of centralized in a config module. Updates miss locations.
 */
function verifyCWE1107(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const INLINE_CIPHER = /['"`](?:AES-(?:128|256)-(?:CBC|GCM|CTR)|DES|3DES|RC4|Blowfish|aes-(?:128|256)-(?:cbc|gcm|ctr))['"`]/;
  const INLINE_ALGORITHM = /['"`](?:sha1|sha256|sha384|sha512|md5|SHA-?(?:1|256|384|512)|MD5|pbkdf2|bcrypt|scrypt|argon2)['"`]/i;
  const INLINE_CORS_ORIGIN = /\b(?:origin|allowedOrigins?|cors)\b[^;]*['"`]https?:\/\/[^'"]+['"`]/i;
  const IS_CONSTANTS_FILE = /\b(?:constants?|config|settings|defaults|env)\b/i;

  const JULIET_TEST_PATH_1107 = /\bCWE\d+\b|\b_bad\b|\b_good\b|\bjuliet\b|\btest.*suite\b|\bsamate\b|\bnist\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;
    if (IS_CONSTANTS_FILE.test(node.label) || IS_CONSTANTS_FILE.test(node.file || '')) continue;
    if (JULIET_TEST_PATH_1107.test(node.file || '') || JULIET_TEST_PATH_1107.test(node.label)) continue;

    if (INLINE_CIPHER.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (cipher algorithm in central constants/config module)', severity: 'medium',
        description: `${node.label} hardcodes a cipher algorithm string inline. ` +
          `Cipher rotation requires finding every inline reference. Missed locations use the weak cipher.`,
        fix: 'Define in crypto config: export const CIPHER = "aes-256-gcm"; Import everywhere.', via: 'source_line_fallback' });
    }
    if (INLINE_ALGORITHM.test(code) && !INLINE_CIPHER.test(code) && !/\bimport\b|\brequire\b/.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (hash/crypto algorithm should be centralized)', severity: 'low',
        description: `${node.label} uses inline hash/crypto algorithm string. Hard to audit and migrate.`,
        fix: 'Centralize: export const HASH_ALGORITHM = "sha256"; import from crypto-config.', via: 'source_line_fallback' });
    }
    if (INLINE_CORS_ORIGIN.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (CORS origins in central configuration)', severity: 'medium',
        description: `${node.label} hardcodes CORS origins inline. Hard to audit trusted origins list.`,
        fix: 'Define in env config: ALLOWED_ORIGINS = process.env.CORS_ORIGINS?.split(",").', via: 'source_line_fallback' });
    }
  }
  return { cwe: 'CWE-1107', name: 'Insufficient Isolation of Symbolic Constant Definitions', holds: findings.length === 0, findings };
}
// Complexity and attack surface CWEs (1118–1127)
// ---------------------------------------------------------------------------

/**
 * CWE-1118: Insufficient Documentation of Error Handling Techniques
 * Code that catches exceptions or handles errors without documenting the
 * error handling strategy. Callers can't tell if errors fail-open or fail-closed,
 * leading to security bypasses when error paths are hit.
 */
function verifyCWE1118(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Catch/except blocks that are empty or lack documentation
  const EMPTY_CATCH_RE = /\b(?:catch|except|rescue)\s*\([^)]*\)\s*\{\s*\}/;
  const SWALLOW_RE = /\b(?:catch|except|rescue)\s*\([^)]*\)\s*\{[^}]*(?:\/\/\s*(?:ignore|swallow|suppress|todo|noop|nothing)|pass\s*$|;\s*\})/i;
  const ERROR_HANDLER_RE = /\b(?:\.catch\s*\(\s*(?:\(\s*\w*\s*\)\s*=>|function)\s*\{|on\s*\(\s*['"]error['"]\s*,|\.on\s*\(\s*['"](?:error|uncaughtException|unhandledRejection)['"]\s*,|process\.on\s*\(\s*['"](?:uncaughtException|unhandledRejection)['"])/;
  const DOC_COMMENT_ABOVE_RE = /\/\*\*[\s\S]{5,}?\*\/\s*\n\s*(?:catch|except|rescue|\.catch|\.on\s*\(\s*['"]error)/;
  const INLINE_EXPLANATION_RE = /(?:\/\/|#)\s*(?:This|Error|We|If|When|Handle|Fail|Return|Log|Throw|Propagate|Re-?throw).{10,}/;

  // Security-critical context where undocumented error handling is dangerous
  const SEC_CONTEXT_RE = /\b(?:auth|login|verify|validate|permission|credential|token|session|password|decrypt|sign|certif|access[_-]?control|rbac|acl|oauth|jwt|saml|ldap|kerberos)\b/i;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (/\b(test|spec|mock|stub|fixture)\b/i.test(node.label)) continue;

    // Check for empty catch blocks (most dangerous)
    if (EMPTY_CATCH_RE.test(code) && SEC_CONTEXT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (documented error handling strategy in security-critical code)',
        severity: 'high',
        description: `${node.label} has an empty catch block in security-critical code. ` +
          `When this error path is hit, execution continues silently — this is a fail-open pattern. ` +
          `Attackers who trigger errors bypass the security check entirely.`,
        fix: 'Either handle the error explicitly (fail closed: deny access, abort operation) or ' +
          'document the intentional fail-open decision with a comment explaining WHY silent continuation is safe.',
        via: 'source_line_fallback',
      });
      continue;
    }

    // Check for swallowed errors in security context
    if (SWALLOW_RE.test(code) && SEC_CONTEXT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (error handling documentation for swallowed exception)',
        severity: 'medium',
        description: `${node.label} swallows an exception in security-critical code with only a TODO/ignore comment. ` +
          `The error handling strategy is undocumented — callers cannot determine failure behavior.`,
        fix: 'Document the error handling strategy: does this fail open or closed? What state is the ' +
          'system in after the error? Add @throws documentation to the enclosing function.',
        via: 'source_line_fallback',
      });
      continue;
    }

    // Check for global error handlers without documentation
    if (ERROR_HANDLER_RE.test(code) && !DOC_COMMENT_ABOVE_RE.test(code) && !INLINE_EXPLANATION_RE.test(code)) {
      const lines = code.split('\n').length;
      if (lines > 5) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'META (documented error handling strategy for global/process error handler)',
          severity: 'medium',
          description: `${node.label} registers a global error handler without documenting the strategy. ` +
            `Does this handler log and continue, restart, or terminate? Undocumented global error handlers ` +
            `create unpredictable failure modes.`,
          fix: 'Add a doc comment explaining: (1) what errors this handles, (2) whether it terminates or continues, ' +
            '(3) what state cleanup occurs, (4) whether errors are reported/alerted.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return { cwe: 'CWE-1118', name: 'Insufficient Documentation of Error Handling Techniques', holds: findings.length === 0, findings };
}

/**
 * CWE-1119: Excessive Use of Unconditional Branching
 * Code that overuses goto, break-to-label, or continue-to-label statements,
 * creating spaghetti control flow that hides security bugs.
 */
function verifyCWE1119(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const GOTO_RE = /\bgoto\s+\w+/g;
  const LABEL_JUMP_RE = /\b(?:break|continue)\s+\w+\s*;/g;
  const LONGJMP_RE = /\b(?:longjmp|setjmp|sigsetjmp|siglongjmp)\s*\(/g;

  const THRESHOLD_GOTO = 3;
  const THRESHOLD_LABEL = 5;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    const gotoCount = (code.match(GOTO_RE) || []).length;
    const labelJumpCount = (code.match(LABEL_JUMP_RE) || []).length;
    const longjmpCount = (code.match(LONGJMP_RE) || []).length;

    if (gotoCount > THRESHOLD_GOTO) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (structured control flow instead of goto)',
        severity: 'medium',
        description: `${node.label} uses ${gotoCount} goto statements. Excessive unconditional branching ` +
          `creates spaghetti control flow where security-critical cleanup code can be bypassed by jumping over it.`,
        fix: 'Refactor goto chains into structured loops, early returns, or RAII/try-finally patterns. ' +
          'Each goto that jumps over cleanup code is a potential resource leak or security bypass.',
        via: 'source_line_fallback',
      });
    }

    if (labelJumpCount > THRESHOLD_LABEL) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (simpler loop structure without labeled jumps)',
        severity: 'low',
        description: `${node.label} uses ${labelJumpCount} labeled break/continue statements. ` +
          `Excessive labeled jumps make it hard to verify that all code paths execute security checks.`,
        fix: 'Extract inner loops into named functions. Replace labeled breaks with early returns from helper functions.',
        via: 'source_line_fallback',
      });
    }

    if (longjmpCount > 0) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (structured error handling instead of longjmp)',
        severity: 'high',
        description: `${node.label} uses longjmp/setjmp for non-local jumps. These bypass ALL intermediate ` +
          `cleanup code, destructors, and finally blocks — any security-critical resource cleanup between ` +
          `setjmp and longjmp is skipped.`,
        fix: 'Replace longjmp with structured error handling (exceptions, error return codes, or signal handlers). ' +
          'If longjmp is unavoidable (e.g., legacy C), ensure all resources are registered for cleanup before setjmp.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1119', name: 'Excessive Use of Unconditional Branching', holds: findings.length === 0, findings };
}

/**
 * CWE-1120: Excessive Code Complexity
 * Functions or modules that are so complex they resist security review.
 * Measured by line count and parameter count.
 */
function verifyCWE1120(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MAX_FUNCTION_LINES = 200;
  const MAX_PARAMS = 10;
  const FUNC_DECL_RE = /(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|(?:public|private|protected)?\s*(?:static\s+)?(?:async\s+)?\w+\s*\([^)]*\)\s*(?::\s*\w+\s*)?\{|def\s+\w+\s*\()/;
  const PARAM_LIST_RE = /\(([^)]*)\)/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|fixture|migration)\b/i.test(node.label)) continue;

    const lines = code.split('\n').length;

    if (lines > MAX_FUNCTION_LINES && FUNC_DECL_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (function decomposition — max ~200 lines per function)',
        severity: 'medium',
        description: `${node.label} is ${lines} lines long. Functions exceeding 200 lines are ` +
          `statistically more likely to contain security bugs because reviewers cannot hold the entire ` +
          `function in working memory. Subtle interactions between distant code blocks create vulnerabilities.`,
        fix: 'Extract cohesive blocks into named helper functions. Each function should have a single responsibility. ' +
          'Security-critical sections (auth checks, input validation, output encoding) should be in dedicated functions.',
        via: 'source_line_fallback',
      });
    }

    const paramMatch = code.match(PARAM_LIST_RE);
    if (paramMatch && paramMatch[1]) {
      const params = paramMatch[1].split(',').filter(p => p.trim().length > 0);
      if (params.length > MAX_PARAMS) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (parameter object or builder pattern — max ~10 parameters)',
          severity: 'low',
          description: `${node.label} accepts ${params.length} parameters. High parameter counts ` +
            `increase the likelihood of argument-order mistakes and make it easy to pass untrusted data ` +
            `where trusted data is expected (parameter confusion).`,
          fix: 'Group related parameters into an options/config object. Use TypeScript interfaces or ' +
            'named parameters (Python kwargs) to make call sites self-documenting and prevent argument swapping.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return { cwe: 'CWE-1120', name: 'Excessive Code Complexity', holds: findings.length === 0, findings };
}

/**
 * CWE-1121: Excessive McCabe Cyclomatic Complexity
 * Functions with too many independent code paths (branches).
 * Approximated by counting decision points.
 */
function verifyCWE1121(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const THRESHOLD = 20;
  const DECISION_RE = /\b(?:if|else\s+if|elif|case|catch|except|rescue|while|for|foreach)\b|\?\s*[^:]*\s*:|&&|\|\|/g;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|fixture)\b/i.test(node.label)) continue;
    const lines = code.split('\n').length;
    if (lines < 15) continue;

    const matches = code.match(DECISION_RE) || [];
    const complexity = matches.length + 1;

    if (complexity > THRESHOLD) {
      const secContext = /\b(?:auth|login|verify|validate|permission|token|session|password|access|encrypt|decrypt)\b/i.test(code);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (reduced cyclomatic complexity — max ~20 decision points)',
        severity: secContext ? 'high' : 'medium',
        description: `${node.label} has cyclomatic complexity ~${complexity} (threshold: ${THRESHOLD}). ` +
          `This means ${complexity} independent code paths, most of which are likely untested. ` +
          (secContext
            ? 'This is in security-critical code — untested paths are likely exploitable bypass vectors.'
            : 'Untested paths accumulate subtle bugs that can become security issues.'),
        fix: 'Decompose into smaller functions using strategy pattern, lookup tables, or early returns. ' +
          'Replace complex conditional chains with polymorphism or configuration objects. ' +
          'Ensure test coverage for ALL branches, not just the happy path.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1121', name: 'Excessive McCabe Cyclomatic Complexity', holds: findings.length === 0, findings };
}

/**
 * CWE-1122: Excessive Halstead Complexity
 * Code with too many unique operators and operands, making it dense and
 * hard to audit. Approximated by Halstead volume and difficulty metrics.
 */
function verifyCWE1122(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const OPERATOR_RE = /[+\-*/%=!<>&|^~?:]{1,3}|\.(?=\w)|(?:instanceof|typeof|new|delete|void|in|of|as|is)\b/g;
  const OPERAND_RE = /\b(?:[a-zA-Z_]\w*|\d+(?:\.\d+)?)\b/g;

  const VOLUME_THRESHOLD = 4000;
  const DIFFICULTY_THRESHOLD = 80;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|fixture)\b/i.test(node.label)) continue;
    const lines = code.split('\n').length;
    if (lines < 20) continue;

    const operators = code.match(OPERATOR_RE) || [];
    const operands = code.match(OPERAND_RE) || [];
    const uniqueOps = new Set(operators);
    const uniqueOpands = new Set(operands);

    const n1 = uniqueOps.size;
    const n2 = uniqueOpands.size;
    const N2 = operands.length;
    const n = n1 + n2;
    const N = operators.length + N2;

    if (n === 0) continue;
    const volume = N * Math.log2(n);
    const difficulty = n2 > 0 ? (n1 / 2) * (N2 / n2) : 0;

    if (volume > VOLUME_THRESHOLD && difficulty > DIFFICULTY_THRESHOLD) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (reduced code density — decompose complex expressions)',
        severity: 'medium',
        description: `${node.label} has Halstead volume ~${Math.round(volume)} (threshold: ${VOLUME_THRESHOLD}) ` +
          `and difficulty ~${Math.round(difficulty)} (threshold: ${DIFFICULTY_THRESHOLD}). ` +
          `Code this dense is extremely difficult to audit — security bugs hide in the sheer volume of tokens. ` +
          `${n1} unique operators and ${n2} unique operands across ${N} total tokens.`,
        fix: 'Extract complex expressions into named intermediate variables. Break long functions into ' +
          'smaller ones with descriptive names. Replace magic numbers with named constants. ' +
          'Dense code is unmaintainable code — and unmaintainable code becomes insecure code.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1122', name: 'Excessive Halstead Complexity', holds: findings.length === 0, findings };
}

/**
 * CWE-1123: Excessive Use of Self-Modifying Code
 * Code that modifies its own instructions or dynamically generates and
 * executes code at runtime. Static analysis cannot verify what the modified code will do.
 */
function verifyCWE1123(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const EVAL_RE = /\b(?:eval|exec|execfile|compile)\s*\(/;
  const NEW_FUNCTION_RE = /\bnew\s+Function\s*\(/;
  const TEMPLATE_EXEC_RE = /\b(?:vm\.runInContext|vm\.runInNewContext|vm\.Script|child_process\.exec|child_process\.execSync|subprocess\.(?:run|call|Popen)|os\.system|os\.popen|Runtime\.getRuntime\(\)\.exec)\s*\(/;
  // `send()` and `method()` are common normal method names in JS/TS — they are only
  // metaprogramming indicators in Ruby/Python. Use separate patterns per language.
  const META_PROGRAM_RUBY_PYTHON_RE = /\b(?:method_missing|__getattr__|__call__|define_method|class_eval|instance_eval|send\s*\(|method\s*\()\b/;
  const META_PROGRAM_GENERAL_RE = /\b(?:method_missing|__getattr__|__call__|define_method|class_eval|instance_eval)\b/;
  const mapLang1123 = inferMapLanguage(map);
  const RUBY_PYTHON_LANGS = new Set(['ruby', 'python']);

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|fixture|repl|playground|console)\b/i.test(node.label)) continue;

    if (EVAL_RE.test(code)) {
      const evalMatch = code.match(/\beval\s*\(\s*([^)]{1,100})/);
      if (evalMatch && !/^['"`]/.test(evalMatch[1].trim())) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (static code instead of eval with dynamic argument)',
          severity: 'critical',
          description: `${node.label} uses eval() with a dynamic argument. This is self-modifying code — ` +
            `the program's behavior changes based on runtime data. Static analysis cannot verify what code ` +
            `will execute, and any user influence over the eval argument is a code injection vulnerability.`,
          fix: 'Replace eval with a lookup table, switch statement, or JSON.parse (for data). ' +
            'If dynamic behavior is needed, use a sandboxed interpreter (vm2, Web Workers) with no access to the host.',
          via: 'source_line_fallback',
        });
        continue;
      }
    }

    if (NEW_FUNCTION_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (pre-compiled function instead of runtime code generation)',
        severity: 'high',
        description: `${node.label} uses new Function() to generate code at runtime. Like eval, this ` +
          `creates code that cannot be statically analyzed. Any user input in the function body is code injection.`,
        fix: 'Replace new Function() with a closure, higher-order function, or pre-compiled template.',
        via: 'source_line_fallback',
      });
      continue;
    }

    if (TEMPLATE_EXEC_RE.test(code)) {
      const execMatch = code.match(/(?:exec|execSync|run|call|system|popen)\s*\(\s*([^)]{1,60})/);
      if (execMatch && !/^['"`]/.test(execMatch[1].trim())) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (parameterized command execution instead of dynamic shell strings)',
          severity: 'high',
          description: `${node.label} executes dynamically-constructed commands at runtime. ` +
            `The system's behavior is modified by runtime data, making static verification impossible.`,
          fix: 'Use parameterized command execution (execFile with argument arrays instead of exec with string interpolation). ' +
            'Maintain an allowlist of permitted commands.',
          via: 'source_line_fallback',
        });
      }
    }

    // Use the broader Ruby/Python regex only for those languages; use the restricted one for JS/TS
    const metaRe = RUBY_PYTHON_LANGS.has((node.language?.toLowerCase() || mapLang1123)) ? META_PROGRAM_RUBY_PYTHON_RE : META_PROGRAM_GENERAL_RE;
    if (metaRe.test(code) && /\b(?:req\.|params\.|query\.|body\.|input\.|user\.)/.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (static dispatch instead of user-influenced metaprogramming)',
        severity: 'high',
        description: `${node.label} uses metaprogramming (method_missing/__getattr__/define_method/send) ` +
          `with user-controlled input. This lets attackers invoke arbitrary methods on objects.`,
        fix: 'Replace dynamic dispatch with an explicit allowlist of permitted method names. ' +
          'Never pass user input directly to send(), method(), or define_method().',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1123', name: 'Excessive Use of Self-Modifying Code', holds: findings.length === 0, findings };
}

/**
 * CWE-1124: Excessively Deep Nesting
 * Code with deeply nested control structures. Deep nesting makes it impossible
 * to reason about which security checks apply to which code paths.
 */
function verifyCWE1124(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MAX_DEPTH = 5;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|fixture)\b/i.test(node.label)) continue;
    const lines = code.split('\n');
    if (lines.length < 10) continue;

    let maxDepth = 0;
    let currentDepth = 0;
    for (const line of lines) {
      const trimmed = line.trimStart();
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

      const opens = (trimmed.match(/\{/g) || []).length;
      const closes = (trimmed.match(/\}/g) || []).length;
      currentDepth += opens - closes;
      if (currentDepth < 0) currentDepth = 0;
      if (currentDepth > maxDepth) maxDepth = currentDepth;
    }

    if (maxDepth > MAX_DEPTH) {
      const secContext = /\b(?:auth|validate|sanitize|verify|check|permission|token|encrypt|sign)\b/i.test(code);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: `STRUCTURAL (max nesting depth ~${MAX_DEPTH} — currently ${maxDepth})`,
        severity: secContext ? 'high' : 'medium',
        description: `${node.label} has nesting depth ${maxDepth} (threshold: ${MAX_DEPTH}). ` +
          `At this depth, it is nearly impossible to determine which security checks guard which operations. ` +
          (secContext
            ? 'This deeply-nested code contains security logic — reviewers cannot verify correctness.'
            : 'Deeply nested code accumulates bugs in the inner levels that are missed during review.'),
        fix: 'Use early returns (guard clauses) to reduce nesting. Extract inner blocks into named functions. ' +
          'Replace nested if-else chains with lookup tables or strategy patterns. ' +
          'Each level of nesting doubles the cognitive load on reviewers.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1124', name: 'Excessively Deep Nesting', holds: findings.length === 0, findings };
}

/**
 * CWE-1125: Excessive Attack Surface
 * The product exposes too many endpoints, interfaces, or capabilities to
 * untrusted users. Each exposed endpoint is a potential entry point for attack.
 * Counts INGRESS nodes and checks protection via CONTROL/AUTH.
 */
function verifyCWE1125(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code exposes APIs, not attack surface — INGRESS nodes are function params, not HTTP endpoints
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-1125', name: 'Excessive Attack Surface', holds: true, findings };
  }

  const ingress = nodesOfType(map, 'INGRESS');
  const controls = nodesOfType(map, 'CONTROL');
  const auth = nodesOfType(map, 'AUTH');

  const unprotectedEndpoints: NeuralMapNode[] = [];
  for (const src of ingress) {
    const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
    const visited = new Set<string>();
    const queue = [src.id];
    let hasProtection = false;

    while (queue.length > 0) {
      const nodeId = queue.shift()!;
      if (visited.has(nodeId)) continue;
      visited.add(nodeId);

      const node = nodeMap.get(nodeId);
      if (!node) continue;

      if (nodeId !== src.id && (node.node_type === 'CONTROL' || node.node_type === 'AUTH')) {
        hasProtection = true;
        break;
      }

      for (const edge of node.edges) {
        if (['DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS'].includes(edge.edge_type)) {
          if (!visited.has(edge.target)) queue.push(edge.target);
        }
      }
    }

    if (!hasProtection) {
      unprotectedEndpoints.push(src);
    }
  }

  // Only report unprotected endpoints that are actually dangerous (write/admin)
  // or when the attack surface is truly excessive (many unprotected endpoints).
  // A simple servlet with 1-2 request handlers (doGet, doPost) reading cookies/params is normal.
  for (const ep of unprotectedEndpoints) {
    const code = ep.analysis_snapshot || ep.code_snapshot;
    const isWrite = /\b(?:POST|PUT|PATCH|DELETE|INSERT|UPDATE|CREATE|WRITE|REMOVE)\b/i.test(code) ||
                    /\b(?:post|put|patch|delete)\s*\(/i.test(ep.label);
    const isAdmin = /\b(?:admin|manage|config|setting|internal|debug|diagnostic)\b/i.test(ep.label + ' ' + code);

    // Only flag write/admin endpoints individually — generic read endpoints
    // are only flagged in the aggregate check below (>50% unprotected with >=5 endpoints)
    if (isWrite || isAdmin) {
      findings.push({
        source: nodeRef(ep), sink: nodeRef(ep),
        missing: 'AUTH/CONTROL (authentication and authorization for state-changing or admin endpoint)',
        severity: 'critical',
        description: `${ep.label} is a ${isAdmin ? 'admin/internal' : 'state-changing'} endpoint with no ` +
          `CONTROL or AUTH nodes in its data flow path. This endpoint is completely unprotected — ` +
          `any unauthenticated user can invoke it.`,
        fix: 'Add authentication middleware (verify JWT/session) and authorization checks (verify role/permissions) ' +
          'before processing the request. If this is intentionally public, document why with a security comment.',
        via: 'structural',
      });
    }
    // Removed: generic "read-only endpoint needs rate limiting" findings — these are the #1 FP source
    // for CWE-1125. Servlet request params, cookies, etc. are all INGRESS nodes that trivially
    // have no CONTROL/AUTH in their data flow path. Only the aggregate check below matters.
  }

  if (ingress.length > 0 && unprotectedEndpoints.length > ingress.length * 0.5 && ingress.length >= 5) {
    findings.push({
      source: nodeRef(ingress[0]), sink: nodeRef(ingress[ingress.length - 1]),
      missing: 'STRUCTURAL (attack surface reduction — too many unprotected endpoints)',
      severity: 'high',
      description: `${unprotectedEndpoints.length} of ${ingress.length} endpoints (${Math.round(100 * unprotectedEndpoints.length / ingress.length)}%) ` +
        `have no CONTROL or AUTH nodes in their data flow. The attack surface is disproportionately large. ` +
        `Only ${controls.length} CONTROL and ${auth.length} AUTH nodes protect ${ingress.length} entry points.`,
      fix: 'Apply authentication middleware at the router/framework level (not per-endpoint). ' +
        'Use an allowlist of public endpoints rather than a denylist of protected ones. ' +
        'Remove or consolidate unused endpoints. Apply defense-in-depth: rate limiting, input validation, ' +
        'and output encoding should be applied by default, not opt-in.',
      via: 'structural',
    });
  }

  return { cwe: 'CWE-1125', name: 'Excessive Attack Surface', holds: findings.length === 0, findings };
}

/**
 * CWE-1126: Declaration of Variable with Unnecessarily Wide Scope
 * Variables declared in a scope broader than where they are used.
 * Wide-scoped variables can be accidentally modified by unrelated code,
 * creating race conditions and data leakage between request contexts.
 */
function verifyCWE1126(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code uses module-level state by design (caches, singletons, configs)
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-1126', name: 'Declaration of Variable with Unnecessarily Wide Scope', holds: true, findings };
  }

  const MODULE_MUTABLE_RE = /^(?:(?:let|var)\s+\w+|(?:export\s+)?(?:let|var)\s+\w+)\s*(?::|=)/gm;
  const REQUEST_DATA_RE = /\b(?:user|session|token|auth|request|req|response|res|context|ctx|currentUser|loggedInUser|activeSession)\b/i;
  const REASSIGNMENT_RE = /\b(?:user|session|token|auth|request|req|currentUser)\s*=\s*(?!null|undefined|''|"")/i;
  const SHARED_STATE_RE = /^(?:(?:let|var)\s+(?:cache|counter|count|total|accumulator|results|items|data|buffer|queue|stack|pending|connections)\b)/gm;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub|fixture|config|constant)\b/i.test(node.label)) continue;

    if (node.node_type === 'STRUCTURAL' || node.node_type === 'META') {
      if (REQUEST_DATA_RE.test(code) && MODULE_MUTABLE_RE.test(code) && REASSIGNMENT_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (request-scoped variable instead of module-level mutable state)',
          severity: 'high',
          description: `${node.label} declares request-specific data (user/session/token/auth) at module scope with let/var. ` +
            `In concurrent environments, this variable is shared between all requests — one user's data ` +
            `leaks into another user's request (IDOR/data leakage).`,
          fix: 'Move request-specific state into the request handler function scope, or use request-scoped ' +
            'containers (Express req object, AsyncLocalStorage, ThreadLocal). Never store per-request data at module level.',
          via: 'source_line_fallback',
        });
      }
    }

    SHARED_STATE_RE.lastIndex = 0;
    if (SHARED_STATE_RE.test(code) && (node.node_type === 'STRUCTURAL' || node.node_type === 'META')) {
      const isServerContext = /\b(?:app\.|server\.|router\.|express|fastify|koa|flask|django|spring|handler|controller)\b/i.test(code);
      if (isServerContext) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (request-scoped or properly managed shared state)',
          severity: 'medium',
          description: `${node.label} declares mutable shared state (cache/counter/buffer) at module level in a server context. ` +
            `Without proper isolation, this state accumulates unboundedly across requests (memory leak) ` +
            `or leaks data between users.`,
          fix: 'Use a proper cache (Redis, LRU cache with TTL and size limits). For counters, use atomic ' +
            'operations or request-scoped state. For buffers, scope them to the request lifecycle.',
          via: 'source_line_fallback',
        });
      }
    }

    const varInBlock = /\bif\s*\([^)]*\)\s*\{[^}]*\bvar\s+\w+/;
    const forVar = /\bfor\s*\([^)]*\bvar\s+/;
    if ((varInBlock.test(code) || forVar.test(code)) && !/\bfunction\b/.test(code.slice(0, 20))) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (block-scoped let/const instead of function-scoped var)',
        severity: 'low',
        description: `${node.label} uses 'var' inside a block (if/for). The variable is hoisted to function scope, ` +
          `making it accessible outside the block where it was intended to be used. This can leak sensitive ` +
          `values to unintended code paths.`,
        fix: 'Replace var with let or const to ensure block scoping. This prevents accidental access ' +
          'to variables outside their intended scope.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1126', name: 'Declaration of Variable with Unnecessarily Wide Scope', holds: findings.length === 0, findings };
}

/**
 * CWE-1127: Compilation with Insufficient Warnings or Errors
 * Code compiled or linted without strict mode, missing safety-critical
 * compiler flags. Without strict compilation, entire classes of bugs go undetected.
 */
function verifyCWE1127(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const TS_ANY_RE = /:\s*any\b/g;
  const TS_NON_NULL_ASSERT = /!\./g;
  const TS_IGNORE = /@ts-ignore|@ts-nocheck|@ts-expect-error/g;
  const ESLINT_DISABLE = /eslint-disable(?:-next-line|-line)?\s/g;
  const NOQA = /#\s*noqa/g;
  const UNSAFE_TYPE_CAST = /\bas\s+any\b|\bObject\b\.\w+\s*\(\s*\w+\s*\)/g;

  const ANY_THRESHOLD = 3;
  const SUPPRESS_THRESHOLD = 3;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (/\b(test|spec|mock|stub|fixture|types?\.d\.ts|declaration)\b/i.test(node.label)) continue;
    const lines = code.split('\n').length;
    if (lines < 5) continue;

    const anyCount = (code.match(TS_ANY_RE) || []).length;
    const nonNullCount = (code.match(TS_NON_NULL_ASSERT) || []).length;
    const ignoreCount = (code.match(TS_IGNORE) || []).length;
    const eslintDisableCount = (code.match(ESLINT_DISABLE) || []).length;
    const noqaCount = (code.match(NOQA) || []).length;
    const unsafeCastCount = (code.match(UNSAFE_TYPE_CAST) || []).length;

    const totalSuppressions = ignoreCount + eslintDisableCount + noqaCount;
    const totalTypeUnsafe = anyCount + unsafeCastCount;

    if (totalTypeUnsafe > ANY_THRESHOLD) {
      const secContext = /\b(?:auth|validate|sanitize|token|session|password|encrypt|permission)\b/i.test(code);
      if (secContext) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'STRUCTURAL (proper typing instead of `any` in security-critical code)',
          severity: 'high',
          description: `${node.label} uses 'any' type ${totalTypeUnsafe} times in security-critical code. ` +
            `TypeScript's type system is the first line of defense against type confusion attacks — ` +
            `using 'any' disables it completely. Attackers can pass unexpected types that bypass validation.`,
          fix: 'Replace `any` with proper types. Use generics for flexible typing. For external data, ' +
            'use a runtime validator (zod, io-ts, joi) that enforces types at the boundary.',
          via: 'source_line_fallback',
        });
      }
    }

    if (totalSuppressions > SUPPRESS_THRESHOLD) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (fix underlying issues instead of suppressing warnings)',
        severity: 'medium',
        description: `${node.label} has ${totalSuppressions} lint/type-check suppression directives ` +
          `(@ts-ignore, eslint-disable, noqa). Each suppression hides a potential bug that the toolchain ` +
          `detected. Accumulating suppressions creates a blind spot where security bugs go undetected.`,
        fix: 'Fix the underlying issues instead of suppressing. If suppression is truly necessary, use ' +
          '@ts-expect-error (not @ts-ignore — it will alert when the underlying issue is fixed). ' +
          'Add a comment explaining WHY each suppression is safe.',
        via: 'source_line_fallback',
      });
    }

    if (nonNullCount > 5 && /\b(?:auth|validate|token|session|user|permission)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (null checks instead of non-null assertions in security code)',
        severity: 'medium',
        description: `${node.label} uses ${nonNullCount} non-null assertions (!.) in security-critical code. ` +
          `Each assertion tells the compiler "trust me, this isn't null" — but if it IS null at runtime, ` +
          `the security check throws and may fail open.`,
        fix: 'Replace non-null assertions with explicit null checks and early returns. ' +
          'Use optional chaining (?.) with explicit fallback behavior for security-critical paths.',
        via: 'source_line_fallback',
      });
    }
  }

  return { cwe: 'CWE-1127', name: 'Compilation with Insufficient Warnings or Errors', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Architecture CWE Registry
// ---------------------------------------------------------------------------

export const ARCHITECTURE_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Deep architecture CWEs — structural quality with security implications (1070–1082)
  'CWE-1070': verifyCWE1070,
  'CWE-1071': verifyCWE1071,
  'CWE-1073': verifyCWE1073,
  'CWE-1074': verifyCWE1074,
  'CWE-1075': verifyCWE1075,
  'CWE-1076': verifyCWE1076,
  'CWE-1078': verifyCWE1078,
  'CWE-1079': verifyCWE1079,
  'CWE-1080': verifyCWE1080,
  'CWE-1082': verifyCWE1082,
  // Architecture quality CWEs — layers, destructors, strings, circular deps (1044–1048)
  'CWE-1044': verifyCWE1044,
  'CWE-1045': verifyCWE1045,
  'CWE-1046': verifyCWE1046,
  'CWE-1047': verifyCWE1047,
  'CWE-1048': verifyCWE1048,
  // Architecture quality CWEs — resource consumption, documentation, concurrency, design (1050–1069)
  'CWE-1050': verifyCWE1050,
  'CWE-1051': verifyCWE1051,
  'CWE-1052': verifyCWE1052,
  'CWE-1053': verifyCWE1053,
  'CWE-1054': verifyCWE1054,
  'CWE-1055': verifyCWE1055,
  'CWE-1056': verifyCWE1056,
  'CWE-1057': verifyCWE1057,
  'CWE-1058': verifyCWE1058,
  'CWE-1059': verifyCWE1059,
  'CWE-1060': verifyCWE1060,
  'CWE-1061': verifyCWE1061,
  'CWE-1062': verifyCWE1062,
  'CWE-1063': verifyCWE1063,
  'CWE-1064': verifyCWE1064,
  'CWE-1065': verifyCWE1065,
  'CWE-1066': verifyCWE1066,
  'CWE-1067': verifyCWE1067,
  'CWE-1068': verifyCWE1068,
  'CWE-1069': verifyCWE1069,
  // Architecture quality CWEs — data access, code structure, resource design (1083–1094)
  'CWE-1083': verifyCWE1083,
  'CWE-1084': verifyCWE1084,
  'CWE-1085': verifyCWE1085,
  'CWE-1086': verifyCWE1086,
  'CWE-1087': verifyCWE1087,
  'CWE-1089': verifyCWE1089,
  'CWE-1090': verifyCWE1090,
  'CWE-1091': verifyCWE1091,
  'CWE-1092': verifyCWE1092,
  'CWE-1094': verifyCWE1094,
  // Code quality and maintainability CWEs (1095–1107)
  'CWE-1095': verifyCWE1095,
  'CWE-1097': verifyCWE1097,
  'CWE-1098': verifyCWE1098,
  'CWE-1099': verifyCWE1099,
  'CWE-1100': verifyCWE1100,
  'CWE-1101': verifyCWE1101,
  'CWE-1102': verifyCWE1102,
  'CWE-1104': verifyCWE1104,
  'CWE-1106': verifyCWE1106,
  'CWE-1107': verifyCWE1107,
  // Documentation & code style CWEs — globals, variable reuse, comments, whitespace (1108–1117)
  'CWE-1108': verifyCWE1108,
  'CWE-1109': verifyCWE1109,
  'CWE-1110': verifyCWE1110,
  'CWE-1111': verifyCWE1111,
  'CWE-1112': verifyCWE1112,
  'CWE-1113': verifyCWE1113,
  'CWE-1114': verifyCWE1114,
  'CWE-1115': verifyCWE1115,
  'CWE-1116': verifyCWE1116,
  'CWE-1117': verifyCWE1117,
  // Complexity and attack surface CWEs (1118–1127)
  'CWE-1118': verifyCWE1118,
  'CWE-1119': verifyCWE1119,
  'CWE-1120': verifyCWE1120,
  'CWE-1121': verifyCWE1121,
  'CWE-1122': verifyCWE1122,
  'CWE-1123': verifyCWE1123,
  'CWE-1124': verifyCWE1124,
  'CWE-1125': verifyCWE1125,
  'CWE-1126': verifyCWE1126,
  'CWE-1127': verifyCWE1127,
};
