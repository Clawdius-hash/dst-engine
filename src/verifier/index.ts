/**
 * DST Verification Engine
 *
 * Walks a NeuralMap and verifies security properties hold.
 * Each CWE maps to a verification path: a specific gap pattern
 * checked against the graph structure.
 *
 * The neural map IS the query. The node types ARE the verification logic.
 * The CWE→assertion mapping is just an index into which path to run.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import { evaluateControlEffectiveness, getContainingScopeSnapshots, sinkHasTaintedDataIn, scopeBasedTaintReaches, findNearestNode } from '../generated/_helpers.js';
import { GENERATED_REGISTRY } from '../generated/index.js';
import { verifyCWE336_B2, verifyCWE614_B2, verifyCWE759_B2, verifyCWE760_B2 } from '../generated/batch_crypto_B2.js';
import { deduplicateResults, familyDedup } from '../dedup.js';
import { filterCWEsForLanguage } from '../cwe-filter.js';

// Extracted shared utilities
import { stripLiterals, stripRegexLiterals, stripComments, escapeRegExp, wholeWord, detectDeadBranchNeutralization, detectStaticValueNeutralization, resolveMapKeyTaint, detectInterproceduralNeutralization90 } from './source-analysis.ts';
import { FLOW_EDGE_TYPES, nodeRef, nodesOfType, inferMapLanguage, isLibraryCode, hasTaintedPathWithoutControl, hasPathWithoutControl, findContainingFunction, sharesFunctionScope } from './graph-helpers.ts';

// Extracted architecture CWE verifiers (1044–1127)
import { ARCHITECTURE_REGISTRY } from './architecture.ts';

// Extracted crypto & hash CWE verifiers (261, 311, 317-340, 347, 354, 757, 759, 760, 780, 916)
import { CRYPTO_REGISTRY } from './crypto.ts';

// Extracted sensitive data & information disclosure CWE verifiers (200, 209-215, 222-226, 256-260, 312-319, 359, 402, 472-474, 488, 497, 524-552, 598-615, 798)
import { SENSITIVE_DATA_REGISTRY } from './sensitive-data.ts';

// Extracted auth & access control CWE verifiers (250, 266-297, 302-309, 345-360, 384, 419-455, 434, 436, 470, 501, 521-566, 602-654, 862-863, 913, 915, 939-1036)
import { AUTH_REGISTRY } from './auth.ts';

// Extracted resource management & concurrency CWE verifiers (362-386, 400-410, 426-428, 459-464, 662-694, 764-775, 832-833, 1333)
import { RESOURCE_REGISTRY } from './resource.ts';

// Extracted code quality & structural CWE verifiers (456-912, 64 functions)
import { CODE_QUALITY_REGISTRY } from './code-quality.ts';

// Extracted malicious code & covert channel CWE verifiers (494-515, 10 functions)
import { MALICIOUS_CODE_REGISTRY } from './malicious-code.ts';

// Extracted error handling, state management & side channel CWE verifiers (43 functions)
import { ERROR_HANDLING_REGISTRY } from './error-handling.ts';

// Extracted numeric & coercion CWE verifiers (16 functions)
import { NUMERIC_COERCION_REGISTRY } from './numeric-coercion.ts';

// Extracted encoding & validation CWE verifiers (13 functions)
import { ENCODING_VALIDATION_REGISTRY } from './encoding-validation.ts';

// Extracted memory safety CWE verifiers (11 functions)
import { MEMORY_SAFETY_REGISTRY } from './memory-safety.ts';

// Extracted injection & taint-tracking CWE verifiers (33 functions)
import { INJECTION_TAINT_REGISTRY } from './injection-taint.ts';

// Import types used by remaining verifiers + re-export public types
import type { VerificationResult, Finding } from './types.ts';
export type { VerificationResult, Finding, NodeRef } from './types.ts';

// Re-export string utilities (consumed by comment-strip.test.ts)
export { stripLiterals, stripRegexLiterals, stripComments };

// Satisfy TS — these are used throughout the 509 verifyCWE functions below
void FLOW_EDGE_TYPES;

// Utilities extracted to source-analysis.ts and graph-helpers.ts
// Types extracted to types.ts

// ---------------------------------------------------------------------------
// CWE Verification Paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-117: Improper Output Neutralization for Logs (broadened — cross-language)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-601: Open Redirect (broadened — cross-language)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Sensitive Data Exposure CWEs (CWE-256 through CWE-319)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AUTHENTICATION & CREDENTIAL CWE Verification Paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Memory Safety & Arithmetic CWE Verification Paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ACCESS CONTROL, INJECTION & FILE HANDLING CWEs
// ---------------------------------------------------------------------------

/** CWE-610: Externally Controlled Reference to a Resource in Another Sphere */
/** CWE-643: XPath Injection */
/** CWE-776: XML Entity Expansion (Billion Laughs) */
// ---------------------------------------------------------------------------
// Privilege & Permission CWEs (CWE-250 through CWE-279)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Encoding, neutralization, and validation ordering CWEs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Data authenticity & privacy CWEs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Cache, Cookie, Session, and Access Control CWEs
// ---------------------------------------------------------------------------

/**
 * CWE-579: J2EE Bad Practices: Non-serializable Object Stored in Session
 * Detects objects stored in HTTP sessions that don't implement Serializable,
 * which causes session replication failures in clustered J2EE environments.
 */
function verifyCWE579(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SESSION_SET_RE = /\b(session\.setAttribute|session\.putValue|session\.set|httpSession\.setAttribute|HttpSession.*\.set|\.getSession\s*\(.*\)\s*\.\s*setAttribute)\b/i;
  const NON_SERIALIZABLE_RE = /\b(Connection|DataSource|EntityManager|Thread|Socket|InputStream|OutputStream|Logger|Lock|ReentrantLock|Semaphore|ExecutorService|ClassLoader)\b/;
  const SERIALIZABLE_RE = /\b(implements\s+Serializable|implements\s+java\.io\.Serializable|@Serial|serialVersionUID|Externalizable)\b/i;

  // Collect all class definitions in the file to check Serializable implementation
  const allCode = map.nodes.map(n => n.analysis_snapshot || n.code_snapshot).join('\n');
  const hasSessionSetAttribute = /\.\s*setAttribute\s*\(/.test(allCode) && /\bgetSession\b/.test(allCode);

  // Find inner/static classes that DON'T implement Serializable
  const nonSerializableClasses: string[] = [];
  for (const node of map.nodes) {
    if (node.node_type === 'STRUCTURAL' && node.node_subtype === 'class') {
      const classCode = node.analysis_snapshot || node.code_snapshot;
      // Check if this is a data class (not the main servlet class)
      if (/\bclass\s+\w+\b/.test(classCode) && !SERIALIZABLE_RE.test(classCode)) {
        // Extract class name
        const classMatch = classCode.match(/\bclass\s+(\w+)/);
        if (classMatch && !classMatch[1].includes('Servlet') && !classMatch[1].includes('TestCase')) {
          nonSerializableClasses.push(classMatch[1]);
        }
      }
    }
  }

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (SESSION_SET_RE.test(code) || (/\.setAttribute\s*\(/.test(code) && /getSession/.test(code))) {
      // Check 1: Known non-serializable types being stored
      if (NON_SERIALIZABLE_RE.test(code) && !SERIALIZABLE_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (store only Serializable objects in HTTP sessions)',
          severity: 'medium',
          description: `Non-serializable object stored in session at ${node.label}. ` +
            `In clustered J2EE environments, session replication will fail, causing data loss or errors.`,
          fix: 'Ensure all objects stored in HttpSession implement java.io.Serializable. ' +
            'Avoid storing connections, streams, threads, or locks in sessions. ' +
            'Use transient fields for non-serializable references.',
          via: 'source_line_fallback',
        });
      }
      // Check 2: Custom class instances stored that don't implement Serializable
      for (const className of nonSerializableClasses) {
        if (new RegExp(`\\bnew\\s+${className}\\s*\\(`).test(code) ||
            new RegExp(`\\b${className}\\b`).test(code)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (store only Serializable objects in HTTP sessions)',
            severity: 'medium',
            description: `Object of class ${className} stored in session at ${node.label}, but ${className} does not implement Serializable. ` +
              `Session replication will fail in clustered environments.`,
            fix: `Make ${className} implement java.io.Serializable and add a serialVersionUID field. ` +
              'All objects stored in HttpSession must be serializable for session replication.',
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-579', name: 'J2EE Bad Practices: Non-serializable Object Stored in Session', holds: findings.length === 0, findings };
}

/**
 * CWE-580: clone() Method Without super.clone()
 * Detects Java clone() method implementations that don't call super.clone(),
 * which breaks the clone contract and causes type errors in subclasses.
 */
function verifyCWE580(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CLONE_METHOD_RE = /\b(public\s+\w+\s+clone\s*\(\s*\)|protected\s+\w+\s+clone\s*\(\s*\)|Object\s+clone\s*\(\s*\)|\boverride\b.*\bclone\b)/i;
  const SUPER_CLONE_RE = /\bsuper\.clone\s*\(\s*\)/;
  const NEW_INSTEAD_RE = /\bnew\s+\w+\s*\(/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (CLONE_METHOD_RE.test(code)) {
      const callsSuperClone = SUPER_CLONE_RE.test(code);
      const usesNewInstead = NEW_INSTEAD_RE.test(code);

      if (!callsSuperClone && usesNewInstead) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (call super.clone() instead of using new in clone() method)',
          severity: 'low',
          description: `clone() at ${node.label} uses "new" instead of super.clone(). ` +
            `If this class is subclassed, clone() will return the wrong type, violating the clone() contract.`,
          fix: 'Replace "new ClassName()" with "super.clone()" in clone() implementations. ' +
            'Cast the result: MyClass copy = (MyClass) super.clone(). ' +
            'Consider using copy constructors or static factory methods instead of Cloneable.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return { cwe: 'CWE-580', name: 'clone() Method Without super.clone()', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Trust boundary & authorization bypass CWEs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Memory corruption & code quality CWEs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-834: Excessive Iteration
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1022: Use of Web Link to Untrusted Target Without rel noopener
// Links with target="_blank" without rel="noopener noreferrer" let the opened
// page access window.opener, enabling reverse-tabnabbing attacks.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1023: Incomplete Comparison with Missing Factors
// Comparisons that check only part of what matters: e.g., comparing only
// username without domain, or using startsWith instead of exact match for auth.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1024: Comparison of Incompatible Types
// Comparing values of fundamentally different types where the language
// silently coerces, producing incorrect results (e.g., string vs number).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1025: Comparison Using Wrong Factors
// The comparison is syntactically valid but semantically wrong — it compares
// the wrong fields, variables, or expressions (e.g., x == x instead of x == y).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1036: Class Based on Externally-Controlled Resource Name
// Dynamically instantiating classes or loading modules based on user input
// without validation — enables arbitrary class instantiation / module loading.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-939: Improper Authorization in Handler for Custom URL Scheme
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-940: Improper Verification of Source of a Communication Channel
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-941: Incorrectly Specified Destination in a Communication Channel
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-942: Permissive Cross-domain Policy with Untrusted Domains
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-943: Improper Neutralization of Special Elements in Data Query Logic
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1004: Sensitive Cookie Without HttpOnly Flag
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1007: Insufficient Visual Distinction of Homoglyphs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1021: Improper Restriction of Rendered UI Layers (Clickjacking)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Side Channel, Error Handling & Information Exposure CWEs (207, 208, 210, 211, 212, 213, 214, 222, 223, 224)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Auth mechanisms & encryption CWEs (CWE-305, 307, 308, 309, 311, 317, 318, 321, 322)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Access Control & Authentication CWEs (280, 282, 283, 284, 285, 286, 289, 291, 302, 304)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Resource cleanup, return values, privilege CWEs (226, 243, 244, 245, 246,
// 248, 252, 253, 266, 268) — real CWE-specific verification
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Predictability, UI security, trust boundary CWEs (341–360)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Channel security & deployment CWEs (419–439)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-551: Incorrect Behavior Order: Authorization Before Parsing and Canonicalization
// Authorization checks performed BEFORE input is fully parsed/canonicalized
// can be bypassed with encoded payloads (e.g., %2e%2e/ bypasses path auth
// checks, then gets decoded to ../ after auth succeeds).
// ---------------------------------------------------------------------------

// CWE-545: DEPRECATED — SKIP

// ---------------------------------------------------------------------------
// CWE-111: Direct Use of Unsafe JNI
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// CWE-114: Process Control
// ---------------------------------------------------------------------------
// Registry — CWE → verification function
// ---------------------------------------------------------------------------

const CWE_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Generated-only verifiers (base layer — hand-written overlaps override these)
  ...GENERATED_REGISTRY,
  // Domain registries (each overrides generated entries for its CWEs)
  ...CODE_QUALITY_REGISTRY,
  ...SENSITIVE_DATA_REGISTRY,
  ...AUTH_REGISTRY,
  ...RESOURCE_REGISTRY,
  ...CRYPTO_REGISTRY,
  ...ARCHITECTURE_REGISTRY,
  ...MALICIOUS_CODE_REGISTRY,
  ...ERROR_HANDLING_REGISTRY,
  ...NUMERIC_COERCION_REGISTRY,
  ...ENCODING_VALIDATION_REGISTRY,
  ...MEMORY_SAFETY_REGISTRY,
  ...INJECTION_TAINT_REGISTRY,
  // Remaining hand-written verifiers (J2EE session/clone — code-quality domain, stay in index.ts)
  'CWE-579': verifyCWE579,
  'CWE-580': verifyCWE580,
  // B2 batch overrides (most optimized — MUST come last to override everything)
  'CWE-336': verifyCWE336_B2,
  'CWE-614': verifyCWE614_B2,
  'CWE-759': verifyCWE759_B2,
  'CWE-760': verifyCWE760_B2,
};

// ---------------------------------------------------------------------------
// Registry collision detection
// ---------------------------------------------------------------------------

function detectRegistryCollisions(): number {
  const namedRegistries: { name: string; registry: Record<string, Function> }[] = [
    { name: 'GENERATED_REGISTRY', registry: GENERATED_REGISTRY },
    { name: 'CODE_QUALITY_REGISTRY', registry: CODE_QUALITY_REGISTRY },
    { name: 'SENSITIVE_DATA_REGISTRY', registry: SENSITIVE_DATA_REGISTRY },
    { name: 'AUTH_REGISTRY', registry: AUTH_REGISTRY },
    { name: 'RESOURCE_REGISTRY', registry: RESOURCE_REGISTRY },
    { name: 'CRYPTO_REGISTRY', registry: CRYPTO_REGISTRY },
    { name: 'ARCHITECTURE_REGISTRY', registry: ARCHITECTURE_REGISTRY },
    { name: 'MALICIOUS_CODE_REGISTRY', registry: MALICIOUS_CODE_REGISTRY },
    { name: 'ERROR_HANDLING_REGISTRY', registry: ERROR_HANDLING_REGISTRY },
    { name: 'NUMERIC_COERCION_REGISTRY', registry: NUMERIC_COERCION_REGISTRY },
    { name: 'ENCODING_VALIDATION_REGISTRY', registry: ENCODING_VALIDATION_REGISTRY },
    { name: 'MEMORY_SAFETY_REGISTRY', registry: MEMORY_SAFETY_REGISTRY },
    { name: 'INJECTION_TAINT_REGISTRY', registry: INJECTION_TAINT_REGISTRY },
  ];

  const owners = new Map<string, string[]>();
  for (const { name, registry } of namedRegistries) {
    for (const key of Object.keys(registry)) {
      if (!owners.has(key)) owners.set(key, []);
      owners.get(key)!.push(name);
    }
  }

  let collisions = 0;
  for (const [key, sources] of owners) {
    if (sources.length > 1) {
      const winner = sources[sources.length - 1];
      const others = sources.slice(0, -1).join(', ');
      process.stderr.write(`[DST] Registry collision: ${key} defined in ${others} and ${winner} (${winner} wins)\n`);
      collisions++;
    }
  }
  return collisions;
}

if (process.env.DST_DEBUG) {
  detectRegistryCollisions();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify a specific CWE against a neural map.
 */
export function verify(map: NeuralMap, cwe: string): VerificationResult {
  const fn = CWE_REGISTRY[cwe];
  if (!fn) {
    return {
      cwe,
      name: 'Unknown',
      holds: true,
      findings: [{ source: { id: '', label: '', line: 0, code: '' }, sink: { id: '', label: '', line: 0, code: '' }, missing: 'verification path', severity: 'low', description: `No verification path registered for ${cwe}`, fix: `Register a verification function for ${cwe}` }],
    };
  }
  return fn(map);
}

/**
 * CWEs that should ALWAYS be checked even on library/framework code because they
 * represent real injection, crypto, or data-flow vulnerabilities that can exist anywhere.
 * All other CWEs are skipped on library code to prevent false positives from code-quality
 * and architecture CWEs that fire on idiomatic library patterns.
 */
const ALWAYS_CHECK_CWES: ReadonlySet<string> = new Set([
  // Injection CWEs — real vulnerabilities even in library code
  'CWE-89', 'CWE-79', 'CWE-78', 'CWE-94', 'CWE-77',
  // Path traversal
  'CWE-22', 'CWE-23', 'CWE-36',
  // Deserialization
  'CWE-502',
  // SSRF
  'CWE-918',
  // Hardcoded credentials
  'CWE-798', 'CWE-259',
  // XXE
  'CWE-611',
  // Prototype pollution
  'CWE-1321',
  // Crypto weaknesses
  'CWE-327', 'CWE-328', 'CWE-330', 'CWE-338',
  // Auth bypass
  'CWE-306', 'CWE-287',
  // Info exposure
  'CWE-200', 'CWE-209',
]);

/**
 * Code-quality CWEs that fire on virtually every file but represent style/architecture
 * observations, not exploitable security vulnerabilities. These are gated behind
 * pedanticMode — excluded from default scans to reduce noise.
 *
 * IMPORTANT: CWE-397 and CWE-563 are NOT in this set because they are NIST Juliet
 * target CWEs. Gating them would regress the Juliet sweep.
 */
export const CODE_QUALITY_CWES: ReadonlySet<string> = new Set([
  'CWE-544',   // Missing Standardized Error Handling
  'CWE-755',   // Improper Handling of Exceptional Conditions
  'CWE-1124',  // Excessive Attack Surface (deep nesting)
  'CWE-1054',  // Input passes through "Infinity" call layers before validation
  'CWE-1091',  // Object not explicitly destroyed/closed (Use of Predictable Algorithm)
  'CWE-457',   // Use of Uninitialized Variable (Java auto-inits to null/0)
  'CWE-245',   // Direct use of DriverManager instead of DataSource (J2EE)
  'CWE-246',   // Direct use of Sockets (J2EE bad practice)
  'CWE-460',   // Cleanup not in catch block
  'CWE-1125',  // Excessive attack surface (too many unprotected endpoints)
  'CWE-1118',  // Insufficient documentation of error handling
  'CWE-1100',  // Insufficient isolation of system-dependent functions
  'CWE-1057',  // Data access outside expected data manager
  'CWE-1116',  // Inaccurate comments
  'CWE-1123',  // Excessive use of self-modifying code
  'CWE-628',   // Function Call with Incorrectly Specified Arguments
  'CWE-710',   // Improper Adherence to Coding Standards
  'CWE-653',   // Insufficient Compartmentalization
  // --- Category B: Generic Taint-to-Anything (factory verifiers with overly broad sinks) ---
  // These fire on virtually every taint flow regardless of whether the operation is relevant.
  'CWE-675',   // Multiple Operations on Resource — fires on any InputStreamReader→BufferedReader chain
  'CWE-666',   // Operation on Resource in Wrong Phase — fires on any TRANSFORM→TRANSFORM chain
  'CWE-683',   // Incorrect Argument Order — fires on any two TRANSFORMs without META
  'CWE-685',   // Incorrect Number of Arguments — same broad TRANSFORM→TRANSFORM pattern
  'CWE-686',   // Incorrect Argument Type — same broad TRANSFORM→TRANSFORM pattern
  'CWE-593',   // OpenSSL CTX Modified after SSL Objects — fires on any stream code
  'CWE-695',   // Use of Low-Level Functionality — fires on any socket/raw API usage
  // --- Category F: Auth/Authz on non-auth code (require web framework context) ---
  // These fire on ANY code that reads input without auth, but standalone test code never has auth.
  'CWE-638',   // Complete Mediation — "auth on every access" fires on everything
  'CWE-655',   // Psychological Acceptability — "usable security" fires on everything
]);

/** Options for verifyAll() */
export interface VerifyAllOptions {
  /** When true, skip source-sink dedup and return raw results (for Juliet scoring, debugging) */
  noDedup?: boolean;
  /** When true, include code-quality CWEs that are normally suppressed to reduce noise */
  pedanticMode?: boolean;
}

/**
 * Verify all registered CWEs against a neural map.
 *
 * When `language` is provided, CWEs are filtered by platform overlap using
 * MITRE CWE data. Each CWE is only skipped when its applicable platforms
 * have ZERO overlap with the language's target platforms. This correctly:
 * - Keeps J2EE/Struts/EJB/Servlet CWEs for Java and Kotlin scans
 * - Keeps .NET/ASP.NET CWEs for C# scans
 * - Keeps Android CWEs for Java and Kotlin scans
 * - Skips Windows kernel CWEs for all non-C/C++ languages
 * - Skips J2EE CWEs for JavaScript/Python/Go/etc.
 *
 * When the code is detected as library/framework code, only injection/crypto/auth
 * CWEs are checked — code-quality and architecture CWEs are skipped to prevent FPs.
 *
 * By default, code-quality CWEs (style/architecture observations that aren't security
 * vulnerabilities) are suppressed. Pass `{ pedanticMode: true }` to include them.
 *
 * By default, results are deduplicated by (source, sink, missingCategory) to collapse
 * CWE family explosions. Pass `{ noDedup: true }` to get raw results.
 */
export function verifyAll(map: NeuralMap, language?: string, options?: VerifyAllOptions): VerificationResult[] {
  const isLibrary = isLibraryCode(map);
  let cwes = Object.keys(CWE_REGISTRY);

  // Filter CWEs by language-platform overlap (MITRE-sourced, replaces WEB_LANGUAGES gate)
  cwes = filterCWEsForLanguage(cwes, language);

  // For library code, only check injection/crypto/auth CWEs
  // (hand-written verifiers also have individual library guards as defense-in-depth)
  if (isLibrary) {
    cwes = cwes.filter(cwe => ALWAYS_CHECK_CWES.has(cwe));
  }

  // Gate code-quality CWEs behind pedanticMode (default: OFF).
  // These fire on virtually every file with no security relevance — they're style/architecture
  // observations, not exploitable vulnerabilities. Reduces FP noise by ~31.5%.
  if (!options?.pedanticMode) {
    cwes = cwes.filter(cwe => !CODE_QUALITY_CWES.has(cwe));
  }

  const results = cwes.map(cwe => verify(map, cwe));

  // ── SECOND PASS: Evaluate controls on mediated paths ──────────────
  // When a path passes because a CONTROL mediates it, check whether
  // that CONTROL is actually effective. Weak controls = false safety.
  const ingress = nodesOfType(map, 'INGRESS');
  const dangerousSinks = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS'
  );

  for (const src of ingress) {
    for (const sink of dangerousSinks) {
      if (src.id === sink.id) continue;
      // Only evaluate controls on paths that PASSED (had a mediator)
      if (!hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const weaknesses = evaluateControlEffectiveness(map, src.id, sink.id);
        for (const w of weaknesses) {
          // Find or create the result for this CWE
          let result = results.find(r => r.cwe === w.cwe);
          if (!result) {
            result = { cwe: w.cwe, name: w.weakness, holds: true, findings: [] };
            results.push(result);
          }
          result.holds = false;
          result.findings.push({
            source: nodeRef(src),
            sink: nodeRef(w.controlNode),
            missing: 'EFFECTIVE_CONTROL (the control on this path is itself vulnerable)',
            severity: w.severity,
            description: w.description,
            fix: `The validation/sanitization at ${w.controlNode.label} needs to be replaced or hardened. ` +
              `The current control provides false safety — it appears to protect the path but is itself exploitable.`,
            via: 'bfs',
          });
        }
      }
    }
  }

  // ── THIRD PASS: Scope-based threat-control mismatch ────────────────
  // For Java/multi-language patterns where BFS doesn't create rich DATA_FLOW
  // paths, check if INGRESS→STORAGE pairs in the same scope have controls
  // that address the wrong threat class. This is the CWE-566 detector.
  //
  // Pattern: parameterized query (injection control) present, but no
  // ownership check (authorization control) in scope.
  const SQL_PK_RE_3P = /(?:WHERE\s+(?:uid|id|user_id|pk|primary_key)\s*=\s*\?|\bfindById\b|\bfindByPk\b|\bget_object_or_404\b|\.get\s*\(\s*pk\b)/i;
  const INJECTION_CONTROL_RE_3P = /\b(preparedStatement|PreparedStatement|prepared_statement|parameteriz|\.setInt|\.setString|\.setLong|\.setDouble|\.setFloat|\.setBoolean|\.setDate|\.setTimestamp|\.setObject)\b/i;
  const OWNERSHIP_AUTH_RE_3P = /\b(session\.getAttribute|getSession\s*\(\s*\)\s*\.\s*getAttribute|session\.user[_.]?id|request\.getUserPrincipal|SecurityContext|getRemoteUser|getUserName|currentUser|req\.user\.id|req\.user\b|user_id\s*===?\s*|AND\s+(?:user_id|owner_id|created_by)\s*=|owned_by|belongs_to|checkOwnership|isOwner|verifyOwner|authorize[!]?|hasPermission|can\?\s*:|ability\.can|@PreAuthorize|@Secured|@RolesAllowed|\.where\s*\(.*(?:user_id|owner_id|created_by))/i;
  // Only INGRESS nodes that carry user-controlled data (not just type declarations)
  const USER_INPUT_RE_3P = /\b(getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString|getPathInfo|getRequestURI|getRequestURL|req\.params|req\.query|req\.body|request\.args|request\.form|request\.GET|request\.POST|\$_GET|\$_POST|@PathVariable|@RequestParam|@RequestBody|@RequestHeader)\b/i;

  // Track which functions have already been flagged to avoid duplicate findings per function
  const flaggedFunctions = new Set<string>();

  for (const src of ingress) {
    // Only flag INGRESS nodes that carry user data extraction (e.g., request.getParameter),
    // NOT just HttpServletRequest parameter type declarations. A method that receives
    // HttpServletRequest but only uses hardcoded data (like Juliet's good() variant)
    // should NOT be flagged.
    const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
    const srcIsDataExtraction = USER_INPUT_RE_3P.test(srcCode);
    if (!srcIsDataExtraction) continue;

    for (const sink of dangerousSinks) {
      if (src.id === sink.id) continue;
      if (sink.node_type !== 'STORAGE') continue;

      // Only flag the STORAGE node that has the actual SQL PK lookup
      const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      if (!SQL_PK_RE_3P.test(sinkCode)) continue;

      // Check if source and sink share a function scope
      if (!sharesFunctionScope(map, src.id, sink.id)) continue;

      // Get the scope code to check for injection control
      const sinkScopeSnaps = getContainingScopeSnapshots(map, sink.id);
      const fullScopeCode = stripComments(sinkScopeSnaps.join('\n') + '\n' + sinkCode);

      // Is there an injection control in scope (parameterized query)?
      if (!INJECTION_CONTROL_RE_3P.test(fullScopeCode)) continue;

      // Deduplicate by containing function — one finding per (function, src INGRESS)
      const functionKey = sinkScopeSnaps[0]?.slice(0, 40) + ':' + src.id;
      if (flaggedFunctions.has(functionKey)) continue;

      // Is there an ownership/authorization check in scope?
      const hasOwnershipCheck = map.nodes.some(n => {
        if (!sharesFunctionScope(map, n.id, sink.id)) return false;
        const nodeCode = n.code_snapshot + ' ' + (n.analysis_snapshot || '');
        return OWNERSHIP_AUTH_RE_3P.test(nodeCode);
      });

      if (!hasOwnershipCheck) {
        flaggedFunctions.add(functionKey);

        // CWE-566: Parameterized query present (injection control) but no ownership check
        let cwe566Result = results.find(r => r.cwe === 'CWE-566');
        if (!cwe566Result) {
          cwe566Result = { cwe: 'CWE-566', name: 'Authorization Bypass Through User-Controlled SQL Primary Key', holds: true, findings: [] };
          results.push(cwe566Result);
        }

        // Avoid duplicating if the first-pass CWE-566 verifier already found this pair
        const alreadyFound = cwe566Result.findings.some(f =>
          f.source.id === src.id && f.sink.id === sink.id
        );
        if (!alreadyFound) {
          cwe566Result.holds = false;
          cwe566Result.findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'EFFECTIVE_CONTROL (control addresses injection, not authorization — missing ownership check)',
            severity: 'high',
            description: `User input from ${src.label} flows to SQL query at ${sink.label}. ` +
              `A parameterized query prevents injection, but no ownership check verifies that ` +
              `the authenticated user is authorized to access the queried record. ` +
              `The control addresses the wrong threat class (injection vs authorization).`,
            fix: 'Add ownership verification: WHERE uid = ? AND user_id = :currentUserId. ' +
              'Or verify session.getAttribute("user_id") == queried_id after fetch. ' +
              'The parameterized query is necessary but insufficient — it only prevents SQL injection, ' +
              'not authorization bypass (IDOR).',
            via: 'scope_taint',
          });
        }
      }
    }
  }

  // ── LAYER 2: Source-sink dedup ─────────────────────────────────────
  // Collapse findings that share (source, sink, missingCategory) within
  // the SAME CWE. Keeps highest severity. Different CWEs are never
  // collapsed at this layer.
  // EFFECTIVE_CONTROL findings are excluded from dedup.
  if (!options?.noDedup) {
    const { results: deduped } = deduplicateResults(results);

    // ── LAYER 3: CWE Family dedup ───────────────────────────────────
    // Collapse CWE family siblings (e.g., CWE-23..38 under CWE-22) when
    // they fire on the same (source, sink, missingCategory) evidence.
    // Keeps the parent CWE. This eliminates the "family explosion" where
    // one real finding produces 10-20 duplicate sibling CWE findings.
    const { results: familyDeduped } = familyDedup(deduped);
    return familyDeduped;
  }

  return results;
}

/**
 * List all CWEs that have verification paths.
 */
export function registeredCWEs(): string[] {
  return Object.keys(CWE_REGISTRY);
}

/**
 * Print a human-readable verification report.
 */
export function formatReport(results: VerificationResult[]): string {
  const lines: string[] = ['DST VERIFICATION REPORT', '=' .repeat(50), ''];

  for (const r of results) {
    const status = r.holds ? '✓ PASS' : '✗ FAIL';
    lines.push(`[${status}] ${r.cwe}: ${r.name}`);

    if (!r.holds) {
      for (const f of r.findings) {
        lines.push(`  ${f.severity.toUpperCase()}: ${f.description}`);
        lines.push(`    Source: ${f.source.label} (line ${f.source.line})`);
        lines.push(`    Sink:   ${f.sink.label} (line ${f.sink.line})`);
        lines.push(`    Missing: ${f.missing}`);
        lines.push(`    Fix: ${f.fix}`);
        if (f.collapsed_cwes && f.collapsed_cwes.length > 0) {
          lines.push(`    Also covers: ${f.collapsed_cwes.join(', ')}`);
        }
        // Show proof data when present (--prove mode)
        const proof = (f as any).proof;
        if (proof) {
          lines.push(`    PROOF [${proof.proof_strength}]:`);
          lines.push(`      Payload: ${proof.primary_payload.value}`);
          lines.push(`      Canary:  ${proof.primary_payload.canary || '(timing-based)'}`);
          lines.push(`      Context: ${proof.primary_payload.context}`);
          lines.push(`      Deliver: ${proof.delivery.channel}${proof.delivery.http ? ` ${proof.delivery.http.method} ${proof.delivery.http.path}` : ''}`);
          lines.push(`      Oracle:  ${proof.oracle.type} — ${proof.oracle.static_proof.slice(0, 100)}`);
          if (proof.variants.length > 0) {
            lines.push(`      Variants: ${proof.variants.length} additional payload(s)`);
          }
          if (!proof.primary_payload.execution_safe) {
            lines.push(`      WARNING: Not safe for automated execution`);
          }
        }
        lines.push('');
      }
    }
  }

  const passed = results.filter(r => r.holds).length;
  const total = results.length;
  lines.push(`${passed}/${total} properties verified.`);

  return lines.join('\n');
}