/**
 * DST Generated Verifiers — Batch 014
 * All remaining EXTERNAL-related patterns (39 CWEs).
 *
 * Shapes covered:
 *   STRUCTURAL→EXTERNAL without CONTROL  (9 CWEs)
 *   EXTERNAL→AUTH without CONTROL         (8 CWEs)
 *   INGRESS→EXTERNAL without CONTROL      (7 CWEs)
 *   EXTERNAL→STORAGE without CONTROL      (5 CWEs)
 *   EXTERNAL→TRANSFORM without CONTROL    (5 CWEs)
 *   STORAGE→EXTERNAL without AUTH         (5 CWEs)
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl,
  hasPathWithoutIntermediateType, cweDomainMatchesSink,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Generic factory
// ---------------------------------------------------------------------------

type BfsCheck = (map: NeuralMap, srcId: string, sinkId: string) => boolean;

function createVerifier(
  cweId: string, cweName: string, severity: Severity,
  sourceType: NodeType, sinkType: NodeType,
  bfsCheck: BfsCheck,
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const sources = nodesOfType(map, sourceType);
    const sinks = nodesOfType(map, sinkType);

    for (const src of sources) {
      for (const sink of sinks) {
        if (src.id === sink.id) continue;
        // Domain filter: skip sinks whose domain doesn't match this CWE
        if (!cweDomainMatchesSink(cweId, sink)) continue;
        if (bfsCheck(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `${sourceType} at ${src.label} connects to ${sinkType} at ${sink.label} without proper controls. ` +
                `Vulnerable to ${cweName}.`,
              fix: fixDesc,
            });
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

const noControl: BfsCheck = hasTaintedPathWithoutControl;
const noAuth: BfsCheck = (map, src, sink) => hasPathWithoutIntermediateType(map, src, sink, 'AUTH');

// Safe patterns
const RESTRICT_SAFE = /\ballowlist\b|\bwhitelist\b|\brestrict\b|\bvalidate\s*\(|\bpermit\b|\bblock\b|\bdeny\b/i;
const VERIFY_SAFE = /\bverif\w*\s*\(|\bvalidate\s*\(|\bcheck\s*\(|\bconfirm\s*\(|\bassert\s*\(|\bensure\s*\(/i;
const CERT_SAFE = /\bcertificate\b|\bpin\b|\bfingerprint\b|\bCA\b|\btrust\b|\bverif.*cert\b|\brejectUnauthorized\b/i;
const INTEGRITY_SAFE = /\bhash\s*\(|\bcreateHash\b|\bsignature\b|\bHMAC\b|\bdigest\b|\bchecksum\b|\bintegrity\b|\bverif\w*\s*\(/i;
const AUTH_SAFE = /\bauthorize\s*\(|\bhasPermission\s*\(|\bcheckAccess\s*\(|\bisOwner\s*\(|\brole\b|\btoken\b.*\bverif\w*\s*\(/i;

// ===========================================================================
// STRUCTURAL→EXTERNAL without CONTROL (9 CWEs)
// ===========================================================================

export const verifyCWE111 = createVerifier('CWE-111', 'Direct Use of Unsafe JNI', 'high', 'STRUCTURAL', 'EXTERNAL', noControl, RESTRICT_SAFE, 'CONTROL (JNI usage restriction / input validation)', 'Validate all data passed to JNI calls. Restrict which native methods can be called. Sanitize inputs.');
export const verifyCWE479 = createVerifier('CWE-479', 'Signal Handler Use of a Non-Reentrant Function', 'medium', 'STRUCTURAL', 'EXTERNAL', noControl, /\basync.*signal.*safe\b|\bsig_atomic\b|\bwrite\b\s*\(\d/i, 'CONTROL (async-signal-safe function enforcement)', 'Only use async-signal-safe functions in signal handlers.');
export const verifyCWE509 = createVerifier('CWE-509', 'Replicating Malicious Code (Virus)', 'critical', 'STRUCTURAL', 'EXTERNAL', noControl, /\bsandbox\b|\bisolat\b|\bverif\b|\bsignature\b/i, 'CONTROL (code integrity verification / sandboxing)', 'Verify code integrity before execution. Use sandboxing and code signing.');
export const verifyCWE575 = createVerifier('CWE-575', 'EJB Bad Practices: Use of AWT Swing', 'low', 'STRUCTURAL', 'EXTERNAL', noControl, /\bheadless\b|\bno.*gui\b|\bserver.*side\b/i, 'CONTROL (no GUI operations in server components)', 'Do not use AWT/Swing in EJBs or server-side components.');
export const verifyCWE577 = createVerifier('CWE-577', 'EJB Bad Practices: Use of Sockets', 'medium', 'STRUCTURAL', 'EXTERNAL', noControl, RESTRICT_SAFE, 'CONTROL (managed connections — no direct socket usage in EJBs)', 'Use managed resources (connection pools, JMS) instead of raw sockets in EJBs.');
export const verifyCWE607 = createVerifier('CWE-607', 'Public Static Final Field References Mutable Object', 'medium', 'STRUCTURAL', 'EXTERNAL', noControl, /\bfreeze\b|\bunmodifiable\b|\bimmutable\b|\bCollections\.unmodifiable\b/i, 'CONTROL (immutable public constants)', 'Make public static final fields immutable. Wrap collections with Collections.unmodifiableList().');
export const verifyCWE648 = createVerifier('CWE-648', 'Incorrect Use of Privileged APIs', 'high', 'STRUCTURAL', 'EXTERNAL', noControl, /\bprivilege\b|\bleast.*privilege\b|\bdropPrivilege\b|\bsandbox\b/i, 'CONTROL (least-privilege API usage)', 'Use privileged APIs with minimum necessary permissions. Drop privileges after use.');
/**
 * CWE-829: Inclusion of Functionality from Untrusted Control Sphere
 * UPGRADED — hand-written with specific sink filters and safe patterns.
 *
 * Pattern: STRUCTURAL nodes (module definitions, build configs, HTML pages)
 * include/require/import code from EXTERNAL sources (CDNs, URLs, dynamic paths)
 * without integrity verification.
 *
 * This is the "supply chain attack" CWE. It catches:
 *   - <script src="http://cdn.example.com/lib.js"> without integrity attribute
 *   - require(userControlledPath) — dynamic require with untrusted path
 *   - eval(fetchedCode) — executing code fetched at runtime
 *   - import('http://...') — dynamic import from URL
 *   - pip install / npm install from untrusted registries
 *
 * Specific sources: STRUCTURAL nodes that load external code
 * Specific sinks: EXTERNAL nodes that represent untrusted code inclusion
 * Safe patterns: SRI integrity attribute, CSP nonce, lockfile hash verification,
 *   GPG signature check, pinned versions with hash, vendored dependencies
 */
export const verifyCWE829 = (function() {
  // Sources: STRUCTURAL nodes that include/load code
  const CODE_INCLUSION_PATTERN = /\b(require|import|include|load|source|eval|exec|execFile|dlopen|LoadLibrary|System\.load)\s*\(|<script\b.*\bsrc\s*=/i;

  // Sinks: EXTERNAL nodes representing untrusted code sources
  const UNTRUSTED_SOURCE_PATTERN = /https?:\/\/|\bcdn\b|\bunpkg\b|\bjsdelivr\b|\bcloudflare\b|\bdynamic\b.*\b(require|import)\b|\beval\b|\bFunction\b\s*\(|\bnew\s+Function\b|\bvm\.run\b|\bchild_process\b/i;

  // Safe: integrity verification present
  const INTEGRITY_SAFE_SPECIFIC = /\bintegrity\s*=\s*"sha(256|384|512)-|\bSRI\b|\bcrossorigin\b.*\bintegrity\b|\bCSP\b.*\bnonce\b|\block\s*file\b|\bpackage-lock\b|\byarn\.lock\b|\bhash\b.*\bverif\b|\bsignature\b.*\bverif\b|\bgpg\b.*\bverif\b|\bvendor\b|\bpinned\b|\bchecksum\b/i;

  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];

    const structuralSources = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' &&
      CODE_INCLUSION_PATTERN.test(n.code_snapshot)
    );

    const externalSinks = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' &&
      UNTRUSTED_SOURCE_PATTERN.test(n.code_snapshot)
    );

    for (const src of structuralSources) {
      for (const sink of externalSinks) {
        if (src.id === sink.id) continue;
        if (noControl(map, src.id, sink.id)) {
          const isSafe = INTEGRITY_SAFE_SPECIFIC.test(sink.code_snapshot) ||
            INTEGRITY_SAFE_SPECIFIC.test(src.code_snapshot);

          if (!isSafe) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (integrity verification — SRI hash, signature check, or pinned dependency)',
              severity: 'high',
              description: `Code inclusion at ${src.label} loads from untrusted source at ${sink.label} ` +
                `without integrity verification. If the external source is compromised, ` +
                `malicious code runs in your application's context.`,
              fix: 'For CDN scripts: add integrity="sha384-..." and crossorigin attributes (SRI). ' +
                'For npm/pip: use lockfiles with verified hashes. ' +
                'For dynamic imports: validate paths against an allowlist. ' +
                'Never eval() code fetched from external sources.',
            });
          }
        }
      }
    }

    return { cwe: 'CWE-829', name: 'Inclusion of Functionality from Untrusted Control Sphere', holds: findings.length === 0, findings };
  };
})();
export const verifyCWE830 = createVerifier('CWE-830', 'Inclusion of Web Functionality from an Untrusted Source', 'high', 'STRUCTURAL', 'EXTERNAL', noControl, /\bSRI\b|\bintegrity\b|\bcrossorigin\b|\bCSP\b|\bnonce\b/i, 'CONTROL (SRI / CSP for external scripts)', 'Use Subresource Integrity (SRI) for CDN scripts. Set CSP to restrict script sources.');

// ===========================================================================
// EXTERNAL→AUTH without CONTROL (8 CWEs)
// ===========================================================================

export const verifyCWE296 = createVerifier('CWE-296', 'Improper Following of a Certificate\'s Chain of Trust', 'high', 'EXTERNAL', 'AUTH', noControl, CERT_SAFE, 'CONTROL (full certificate chain validation)', 'Validate the entire certificate chain to a trusted root CA. Do not skip chain verification.');
export const verifyCWE297 = createVerifier('CWE-297', 'Improper Validation of Certificate with Host Mismatch', 'high', 'EXTERNAL', 'AUTH', noControl, /\bhostname\b.*\bverif\b|\bcheckServerIdentity\b|\bSAN\b|\bsubjectAltName\b/i, 'CONTROL (hostname verification against certificate)', 'Verify that the certificate hostname matches the requested host. Check SANs and CN.');
export const verifyCWE298 = createVerifier('CWE-298', 'Improper Validation of Certificate Expiration', 'high', 'EXTERNAL', 'AUTH', noControl, /\bexpir\b|\bnotAfter\b|\bvalidity\b|\bdate\b.*\bcheck\b/i, 'CONTROL (certificate expiration validation)', 'Check certificate expiration dates. Reject expired certificates.');
export const verifyCWE299 = createVerifier('CWE-299', 'Improper Check for Certificate Revocation', 'high', 'EXTERNAL', 'AUTH', noControl, /\bOCSP\b|\bCRL\b|\brevocation\b|\bstapl\b/i, 'CONTROL (certificate revocation checking — OCSP/CRL)', 'Check certificate revocation status via OCSP or CRL. Enable OCSP stapling.');
export const verifyCWE332 = createVerifier('CWE-332', 'Insufficient Entropy in PRNG', 'high', 'EXTERNAL', 'AUTH', noControl, /\bcrypto\.random\b|\brandomBytes\b|\bgetRandomValues\b|\bCSPRNG\b|\b\/dev\/urandom\b/i, 'CONTROL (sufficient entropy for security-critical random values)', 'Use CSPRNG (crypto.randomBytes) for security-critical values. Ensure sufficient entropy source.');
export const verifyCWE333 = createVerifier('CWE-333', 'Improper Handling of Insufficient Entropy in TRNG', 'high', 'EXTERNAL', 'AUTH', noControl, /\bentropy\b|\bpool\b|\bseed\b|\b\/dev\/random\b|\bblock\b.*\bentropy\b/i, 'CONTROL (entropy sufficiency check before generation)', 'Check available entropy before generating security-critical values. Block or fail if insufficient.');
export const verifyCWE350 = createVerifier('CWE-350', 'Reliance on Reverse DNS Resolution for a Security-Critical Action', 'high', 'EXTERNAL', 'AUTH', noControl, /\bforward.*lookup\b|\bIP.*direct\b|\bno.*reverse.*dns\b|\bverify.*forward\b/i, 'CONTROL (no reverse DNS for security — use forward-confirmed reverse DNS at minimum)', 'Do not rely on reverse DNS for access control. IP addresses can have arbitrary PTR records. Use forward lookup verification.');
export const verifyCWE558 = createVerifier('CWE-558', 'Use of getlogin() in Multithreaded Application', 'medium', 'EXTERNAL', 'AUTH', noControl, /\bgetuid\b|\bgeteuid\b|\bgetpwuid\b|\bthread.*local\b/i, 'CONTROL (thread-safe user identification — getuid/geteuid, not getlogin)', 'Use getuid()/geteuid() instead of getlogin() in multithreaded apps. getlogin() is not thread-safe.');

// ===========================================================================
// INGRESS→EXTERNAL without CONTROL (7 CWEs)
// ===========================================================================

export const verifyCWE88 = createVerifier('CWE-88', 'Improper Neutralization of Argument Delimiters in a Command', 'critical', 'INGRESS', 'EXTERNAL', noControl, /\bexecFile\b|\bspawn\b.*\[|\bescapeShell\b|\bparameteriz\b/i, 'CONTROL (argument delimiter neutralization / safe command API)', 'Use execFile/spawn with argument arrays, not shell string interpolation. Escape argument delimiters.');
export const verifyCWE99 = createVerifier('CWE-99', 'Improper Control of Resource Identifiers (Resource Injection)', 'high', 'INGRESS', 'EXTERNAL', noControl, RESTRICT_SAFE, 'CONTROL (resource identifier validation / allowlist)', 'Validate resource identifiers against an allowlist. Do not let user input directly select resources.');
export const verifyCWE114 = createVerifier('CWE-114', 'Process Control', 'critical', 'INGRESS', 'EXTERNAL', noControl, RESTRICT_SAFE, 'CONTROL (process control restriction)', 'Do not allow user input to control process execution (loaded libraries, spawned processes). Use allowlists.');
export const verifyCWE564 = createVerifier('CWE-564', 'SQL Injection: Hibernate', 'high', 'INGRESS', 'EXTERNAL', noControl, /\bparameteriz\b|\bcriteria\b|\bnamedQuery\b|\bsetParameter\b/i, 'CONTROL (Hibernate parameterized queries / Criteria API)', 'Use Hibernate Criteria API or named queries with setParameter(). Do not concatenate HQL strings.');
export const verifyCWE610 = createVerifier('CWE-610', 'Externally Controlled Reference to a Resource in Another Sphere', 'high', 'INGRESS', 'EXTERNAL', noControl, RESTRICT_SAFE, 'CONTROL (external reference validation / allowlist)', 'Validate external references against an allowlist. Do not allow user input to control cross-sphere resource access.');
export const verifyCWE827 = createVerifier('CWE-827', 'Improper Control of Document Type Definition', 'high', 'INGRESS', 'EXTERNAL', noControl, /\bnoent\b|\bdisable.*dtd\b|\bdefusedxml\b|\bresolveEntities.*false\b/i, 'CONTROL (DTD processing restriction)', 'Disable DTD processing in XML parsers. Use defusedxml. Set resolveEntities: false.');
export const verifyCWE920 = createVerifier('CWE-920', 'Improper Restriction of Power Consumption', 'medium', 'INGRESS', 'EXTERNAL', noControl, /\blimit\b|\bthrottle\b|\bquota\b|\btimeout\b|\bmax\b/i, 'CONTROL (resource consumption limits)', 'Limit CPU, memory, and power consumption per request. Implement timeouts and quotas.');

// ===========================================================================
// EXTERNAL→STORAGE without CONTROL (5 CWEs)
// ===========================================================================

export const verifyCWE278 = createVerifier('CWE-278', 'Insecure Preservation of Permissions During Resource Copy', 'medium', 'EXTERNAL', 'STORAGE', noControl, /\bchmod\b|\bpermission.*preserv\b|\bumask\b/i, 'CONTROL (permission preservation during copy from external source)', 'Set restrictive permissions on resources copied from external sources. Do not inherit source permissions blindly.');
export const verifyCWE353 = createVerifier('CWE-353', 'Missing Support for Integrity Check', 'high', 'EXTERNAL', 'STORAGE', noControl, INTEGRITY_SAFE, 'CONTROL (integrity verification of external data before storage)', 'Verify integrity (hash, signature, HMAC) of data from external sources before storing.');
export const verifyCWE608 = createVerifier('CWE-608', 'Struts: Non-private Field in ActionForm Class', 'medium', 'EXTERNAL', 'STORAGE', noControl, /\bprivate\b|\bgetter\b|\bsetter\b|\bencapsulat\b/i, 'CONTROL (field encapsulation — private fields with accessors)', 'Make ActionForm fields private with getters/setters for proper encapsulation.');
export const verifyCWE669 = createVerifier('CWE-669', 'Incorrect Resource Transfer Between Spheres', 'high', 'EXTERNAL', 'STORAGE', noControl, VERIFY_SAFE, 'CONTROL (validation during cross-sphere resource transfer)', 'Validate and sanitize resources when transferring between trust domains.');
export const verifyCWE767 = createVerifier('CWE-767', 'Access to Critical Private Variable via Public Method', 'medium', 'EXTERNAL', 'STORAGE', noControl, /\bprivate\b|\bencapsulat\b|\bimmutable\b|\breadonly\b/i, 'CONTROL (encapsulation of critical variables)', 'Make critical variables private. Return defensive copies from public accessors.');

// ===========================================================================
// EXTERNAL→TRANSFORM without CONTROL (5 CWEs)
// ===========================================================================

export const verifyCWE354 = createVerifier('CWE-354', 'Improper Validation of Integrity Check Value', 'high', 'EXTERNAL', 'TRANSFORM', noControl, INTEGRITY_SAFE, 'CONTROL (integrity check value validation before processing)', 'Validate integrity check values (hashes, MACs, signatures) before processing external data.');
export const verifyCWE426 = createVerifier('CWE-426', 'Untrusted Search Path', 'high', 'EXTERNAL', 'TRANSFORM', noControl, /\babsolute.*path\b|\bfull.*path\b|\bpath\.resolve\b/i, 'CONTROL (absolute paths / trusted search path)', 'Use absolute paths for critical resources. Do not rely on PATH for security-sensitive operations.');
export const verifyCWE439 = createVerifier('CWE-439', 'Behavioral Change in New Version or Environment', 'medium', 'EXTERNAL', 'TRANSFORM', noControl, /\bversion\b.*\bcheck\b|\bcompat\b|\bfeature.*detect\b/i, 'CONTROL (version/environment compatibility check)', 'Check version compatibility. Use feature detection instead of version detection.');
export const verifyCWE622 = createVerifier('CWE-622', 'Improper Validation of Function Hook Arguments', 'high', 'EXTERNAL', 'TRANSFORM', noControl, VERIFY_SAFE, 'CONTROL (hook argument validation)', 'Validate all arguments passed through function hooks. Do not trust hook-provided data without verification.');
export const verifyCWE623 = createVerifier('CWE-623', 'Unsafe ActiveX Control Marked Safe For Scripting', 'high', 'EXTERNAL', 'TRANSFORM', noControl, /\bkill.*bit\b|\bsafe.*init\b.*\bfalse\b|\bdisable.*activex\b/i, 'CONTROL (ActiveX safety marking / disable)', 'Do not mark ActiveX controls as safe for scripting unless thoroughly reviewed. Prefer modern APIs.');

// ===========================================================================
// STORAGE→EXTERNAL without AUTH (5 CWEs)
// ===========================================================================

export const verifyCWE219 = createVerifier('CWE-219', 'Storage of File with Sensitive Data Under Web Root', 'high', 'STORAGE', 'EXTERNAL', noAuth, /\boutside.*webroot\b|\bprivate.*dir\b|\baccess.*denied\b/i, 'AUTH (sensitive files outside web root / access control)', 'Store sensitive files outside the web root. Apply access controls to all served directories.');
export const verifyCWE220 = createVerifier('CWE-220', 'Storage of File with Sensitive Data Under FTP Root', 'high', 'STORAGE', 'EXTERNAL', noAuth, /\boutside.*ftp\b|\baccess.*control\b|\brestrict\b/i, 'AUTH (sensitive files outside FTP root / access control)', 'Store sensitive files outside FTP-accessible directories.');
export const verifyCWE487 = createVerifier('CWE-487', 'Reliance on Package-level Scope', 'medium', 'STORAGE', 'EXTERNAL', noAuth, /\bprivate\b|\bprotected\b|\bencapsulat\b/i, 'AUTH (proper access modifiers — private/protected, not package)', 'Use private/protected access, not package-level. Package scope is too permissive for security.');
export const verifyCWE492 = createVerifier('CWE-492', 'Use of Inner Class Containing Sensitive Data', 'medium', 'STORAGE', 'EXTERNAL', noAuth, /\bstatic.*inner\b|\bprivate.*class\b|\bencapsulat\b/i, 'AUTH (inner class data protection)', 'Make inner classes static to prevent access to outer class sensitive data. Use private access.');
export const verifyCWE927 = createVerifier('CWE-927', 'Use of Implicit Intent for Sensitive Communication', 'high', 'STORAGE', 'EXTERNAL', noAuth, /\bexplicit.*intent\b|\bsetPackage\b|\bsetComponent\b|\bpermission\b/i, 'AUTH (explicit intents for sensitive data)', 'Use explicit intents (setComponent/setPackage) for sensitive communication. Implicit intents can be intercepted.');

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_014_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // STRUCTURAL→EXTERNAL without CONTROL (9)
  'CWE-111': verifyCWE111, 'CWE-479': verifyCWE479, 'CWE-509': verifyCWE509,
  'CWE-575': verifyCWE575, 'CWE-577': verifyCWE577, 'CWE-607': verifyCWE607,
  'CWE-648': verifyCWE648, 'CWE-829': verifyCWE829, 'CWE-830': verifyCWE830,
  // EXTERNAL→AUTH without CONTROL (8)
  'CWE-296': verifyCWE296, 'CWE-297': verifyCWE297, 'CWE-298': verifyCWE298,
  'CWE-299': verifyCWE299, 'CWE-332': verifyCWE332, 'CWE-333': verifyCWE333,
  'CWE-350': verifyCWE350, 'CWE-558': verifyCWE558,
  // INGRESS→EXTERNAL without CONTROL (7)
  'CWE-88': verifyCWE88, 'CWE-99': verifyCWE99, 'CWE-114': verifyCWE114,
  'CWE-564': verifyCWE564, 'CWE-610': verifyCWE610, 'CWE-827': verifyCWE827,
  'CWE-920': verifyCWE920,
  // EXTERNAL→STORAGE without CONTROL (5)
  'CWE-278': verifyCWE278, 'CWE-353': verifyCWE353, 'CWE-608': verifyCWE608,
  'CWE-669': verifyCWE669, 'CWE-767': verifyCWE767,
  // EXTERNAL→TRANSFORM without CONTROL (5)
  'CWE-354': verifyCWE354, 'CWE-426': verifyCWE426, 'CWE-439': verifyCWE439,
  'CWE-622': verifyCWE622, 'CWE-623': verifyCWE623,
  // STORAGE→EXTERNAL without AUTH (5)
  'CWE-219': verifyCWE219, 'CWE-220': verifyCWE220, 'CWE-487': verifyCWE487,
  'CWE-492': verifyCWE492, 'CWE-927': verifyCWE927,
};
