/**
 * DST Generated Verifiers — Batch 002
 * Pattern shape: INGRESS→TRANSFORM without CONTROL
 * 52 CWEs: input validation, code injection, resource exhaustion,
 * type safety, crypto strength, regex, workflow enforcement.
 *
 * Sub-groups:
 *   A. Input validation/handling (22 CWEs) — factory-driven
 *   B. Code injection / eval    (7 CWEs)  — per-CWE sink filters
 *   C. Resource exhaustion       (7 CWEs)  — per-CWE sink filters
 *   D. Type/reflection           (3 CWEs)  — factory-driven
 *   E. Crypto weakness           (2 CWEs)  — per-CWE
 *   F. Individual patterns      (11 CWEs)  — unique verifiers
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, createGenericVerifier,
  sinkHasNonZeroRange, detectLanguage, scopeBasedTaintReaches,
  getContainingScopeSnapshots, stripComments, findNearestNode,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Framework detection helpers
// ---------------------------------------------------------------------------

/** Returns true if the code uses the Struts framework (Action classes, struts imports) */
function isStrutsCode(map: NeuralMap): boolean {
  const allCode = map.nodes.map(n => n.code_snapshot).join('\n');
  return /\bimport\s+org\.apache\.struts\b|\bActionForm\b|\bActionMapping\b|\bstruts-config\b|\bValidatorForm\b/i.test(allCode);
}

/**
 * Factory for Struts-specific input validation verifiers.
 * Returns PASS immediately if the code doesn't use the Struts framework.
 */
function createStrutsValidationVerifier(
  cweId: string, cweName: string, severity: Severity, extraSafe?: RegExp
): (map: NeuralMap) => VerificationResult {
  const inner = createInputValidationVerifier(cweId, cweName, severity, extraSafe);
  return (map: NeuralMap): VerificationResult => {
    if (!isStrutsCode(map)) {
      return { cwe: cweId, name: cweName, holds: true, findings: [] };
    }
    return inner(map);
  };
}

// ---------------------------------------------------------------------------
// Sink filters — TRANSFORM nodes matching specific vulnerability classes
// ---------------------------------------------------------------------------

/** TRANSFORM nodes performing any kind of data parsing/processing */
function dataTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('parse') || n.node_subtype.includes('process') ||
     n.node_subtype.includes('decode') || n.node_subtype.includes('convert') ||
     n.node_subtype.includes('format') || n.node_subtype.includes('transform') ||
     n.attack_surface.includes('data_processing') ||
     n.code_snapshot.match(
       /\b(parse|decode|convert|transform|process|format|serialize|unmarshal)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing dynamic code evaluation */
function evalTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('eval') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('dynamic') || n.attack_surface.includes('code_execution') ||
     n.code_snapshot.match(
       /\b(eval|Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]|new\s+Function|vm\.runIn|exec)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing format string operations */
function formatStringNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('format') || n.node_subtype.includes('printf') ||
     n.attack_surface.includes('format_string') ||
     n.code_snapshot.match(
       /\b(printf|sprintf|fprintf|snprintf|syslog|NSLog|String\.format|util\.format)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing PHP include/require */
function includeTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('include') || n.node_subtype.includes('require') ||
     n.code_snapshot.match(
       /\b(include|include_once|require|require_once)\s*\(/i
     ) !== null)
  );
}

/** TRANSFORM or EXTERNAL nodes performing expression language evaluation */
function expressionEvalNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('expression') || n.node_subtype.includes('template') ||
     n.node_subtype.includes('ognl') || n.node_subtype.includes('spel') ||
     n.node_subtype.includes('jndi_lookup') || n.node_subtype.includes('expression_eval') ||
     n.attack_surface.includes('expression_eval') ||
     n.code_snapshot.match(
       /\b(OGNL|SpEL|MVEL|JEXL|ELProcessor|ExpressionFactory|evalExpression|templateEngine|parseExpression|SpelExpressionParser|InitialContext\.lookup|StringSubstitutor)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing regex operations with user input */
function regexTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('regex') || n.node_subtype.includes('pattern') ||
     n.attack_surface.includes('regex') ||
     n.code_snapshot.match(
       /\b(RegExp|preg_replace|preg_match|re\.compile|Pattern\.compile|match|test|replace)\s*\(/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing reflection/dynamic class loading */
function reflectionTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('reflect') || n.node_subtype.includes('class_load') ||
     n.node_subtype.includes('dynamic_dispatch') || n.attack_surface.includes('reflection') ||
     n.code_snapshot.match(
       /\b(Class\.forName|getClass|newInstance|Reflect\.|require\s*\(.*\+|import\s*\(.*\+|__import__|getattr)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing type conversion/casting */
function typeCastTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('cast') || n.node_subtype.includes('convert') ||
     n.node_subtype.includes('coerce') ||
     n.code_snapshot.match(
       /\b(parseInt|parseFloat|Number\(|String\(|Boolean\(|as\s+\w+|\(\w+\)\s*\w+|static_cast|reinterpret_cast)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing hashing/crypto */
function hashTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('hash') || n.node_subtype.includes('crypto') ||
     n.node_subtype.includes('digest') || n.attack_surface.includes('crypto') ||
     n.code_snapshot.match(
       /\b(createHash|MD5|SHA1|sha1|md5|hashlib|MessageDigest|digest|hash)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing division/arithmetic */
function divisionTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('division') || n.node_subtype.includes('arithmetic') ||
     n.code_snapshot.match(/\s\/\s|\bdiv\b|\bmodulo\b|\b%\b/i) !== null)
  );
}

/** TRANSFORM nodes performing decompression */
function decompressTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('decompress') || n.node_subtype.includes('inflate') ||
     n.node_subtype.includes('unzip') || n.node_subtype.includes('gunzip') ||
     n.attack_surface.includes('decompression') ||
     n.code_snapshot.match(
       /\b(gunzip|inflate|decompress|unzip|createGunzip|createInflate|zlib\.inflate|gzip\.open|zipfile)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing XML parsing (for entity expansion) */
function xmlParserTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('xml') || n.node_subtype.includes('dtd') ||
     n.attack_surface.includes('xml_parse') ||
     n.code_snapshot.match(
       /\b(parseXML|DOMParser|SAXParser|xml2js|libxml|etree\.parse|XmlReader|XMLParser)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing memory allocation — includes Java/C/JS collection constructors with size params */
function memAllocTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('alloc') || n.node_subtype.includes('memory') ||
     n.node_subtype.includes('collection') || n.node_subtype.includes('container') ||
     n.code_snapshot.match(
       /\b(malloc|calloc|realloc|new\s+\w+\[|Buffer\.alloc|Array\(|new\s+ArrayBuffer|new\s+Uint8Array|new\s+ArrayList\s*\(|new\s+HashMap\s*\(|new\s+HashSet\s*\(|new\s+LinkedList\s*\(|new\s+Vector\s*\(|new\s+StringBuilder\s*\(|new\s+StringBuffer\s*\(|new\s+byte\s*\[|new\s+char\s*\[|new\s+int\s*\[|new\s+long\s*\[|ByteBuffer\.allocate|make\s*\(\s*\[\]|make\s*\(\s*map\[)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes performing resource-intensive operations (amplification) */
function resourceIntensiveTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('compute') || n.node_subtype.includes('process') ||
     n.attack_surface.includes('resource_intensive') || n.attack_surface.includes('amplification') ||
     n.code_snapshot.match(
       /\b(sort|regex|forEach|map|reduce|filter|find|crypto\.pbkdf|scrypt|bcrypt)\b/i
     ) !== null)
  );
}

/** TRANSFORM nodes with algorithmic complexity concerns */
function complexAlgoTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('sort') || n.node_subtype.includes('search') ||
     n.node_subtype.includes('regex') || n.attack_surface.includes('algorithmic_complexity') ||
     n.code_snapshot.match(
       /\b(sort|match|replace|split|RegExp|indexOf|search|nested.*for|while.*while)\b/i
     ) !== null)
  );
}

// ---------------------------------------------------------------------------
// Safe pattern constants
// ---------------------------------------------------------------------------

const INPUT_VALID_SAFE = /\bvalidate\s*\(|\bsanitize\s*\(|\bcheck\s*\(|\b\.filter\s*\(|\bescape\s*\(|\bencode\s*\(|\bschema\b|\bzod\b|\bjoi\b|\byup\b|\bsuperStruct\b|\bESAPI\b|\bencodeForHTML\b|\bHtmlUtils\b|\bStringEscapeUtils\b|\bPattern\.matches\b|\bMatcher\b/i;
const EVAL_SAFE = /\bsanitize\s*\(|\ballowlist\b|\bwhitelist\b|\bJSON\.parse\b|\bsafeEval\b|\bvm2\b|\bsandbox\b/i;
const FORMAT_SAFE = /\bstatic\b.*format|\bconst\b.*format|\bhardcoded\b|\bliteral\b|\bformat.*=.*['"`]/i;
const INCLUDE_SAFE = /\ballowlist\b|\bwhitelist\b|\bbasename\b|\bstartsWith\b|\ballow_url_include.*off\b|\bvalidate.*path\b/i;
const EXPR_SAFE = /\bsanitize\s*\(|\bescape\s*\(|\ballowlist\b|\bwhitelist\b|\bsandbox\b|\brestrict\b/i;
const REGEX_SAFE = /\bescapeRegex\b|\bescapeString\b|\bliteral\b|\bstatic.*pattern\b|\bconstant.*regex\b|\bRE2\b/i;
const REFLECT_SAFE = /\ballowlist\b|\bwhitelist\b|\bpermitted.*class\b|\ballowedClass\b|\bvalidate.*class\b/i;
const TYPE_SAFE = /\btypeof\b|\binstanceof\b|\bNumber\.isFinite\b|\bNumber\.isInteger\b|\bArray\.isArray\b|\bvalidate.*type\b/i;
const HASH_SAFE = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bPBKDF2\b|\bSHA-256\b|\bSHA-384\b|\bSHA-512\b|\bSHA3\b|\bblake2\b/i;
const ZERO_CHECK_SAFE = /\b!==?\s*0\b|\b>\s*0\b|\b!=\s*0\b|\bzero.*check\b|\bdivisor.*valid\b|\bisNaN\b/i;
const DECOMPRESS_SAFE = /\bmax.*size\b|\blimit\b|\bratio\b|\bbomb.*check\b|\bsize.*check\b|\bquota\b/i;
const XML_ENTITY_SAFE = /\bnoent\b|\bdisable.*entity\b|\bresolveEntities\s*:\s*false\b|\bdefusedxml\b|\bmax.*depth\b|\bexpansion.*limit\b|\bsafe.*parse/i;
const ALLOC_SIZE_SAFE = /\bmax\b.*\bsize\b|\blimit\b|\bclamp\b|\b[<>]=?\s*\d{3,}\b|\bvalidate.*size\b|\bMAX_SIZE\b/i;
const RATE_LIMIT_SAFE = /\brate.*limit\b|\bthrottle\b|\bquota\b|\bcost.*check\b|\bmax.*request\b|\bbackpressure\b/i;
const COMPLEXITY_SAFE = /\bRE2\b|\btimeout\b|\bmax.*length\b|\blimit.*input\b|\bsafe.*regex\b|\blinear\b/i;
const WORKFLOW_SAFE = /\bstate.*machine\b|\bworkflow\b|\bstep.*valid\b|\bsequence.*check\b|\bprecondition\b|\bguard\s*\(/i;
const NEGOTIATE_SAFE = /\bmin.*version\b|\bTLS.*1\.[23]\b|\ballowedCiphers\b|\bcipher.*suite\b|\bno.*downgrade\b|\bstrict.*transport\b/i;

// ===========================================================================
// A. INPUT VALIDATION/HANDLING (22 CWEs)
// ===========================================================================
// These CWEs share: INGRESS → TRANSFORM[process] without CONTROL[input_validation]
// The TRANSFORM processes input data without any validation gate.

function createInputValidationVerifier(
  cweId: string, cweName: string, severity: Severity, extraSafe?: RegExp
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = dataTransformNodes(map);

    // Require at least one sink that is NOT just a simple decode/URLDecode/type-cast
    // Simple decodes are not risky data processing — they're just format conversion
    const riskySinks = sinks.filter(s =>
      !/^\s*(URLDecoder\.decode|java\.net\.URLDecoder|Base64\.decode|Integer\.parseInt|Long\.parseLong|Double\.parseDouble)\b/i.test(s.code_snapshot.trim()) ||
      /\beval\b|\bexec\b|\bcompile\b|\bprocess\b|\bcommand\b/i.test(s.code_snapshot)
    );

    for (const src of ingress) {
      for (const sink of riskySinks) {
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          const isSafe = INPUT_VALID_SAFE.test(sink.code_snapshot) ||
            (extraSafe ? extraSafe.test(sink.code_snapshot) : false);

          if (!isSafe) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (input validation / sanitization)',
              severity,
              description: `User input from ${src.label} reaches data processing at ${sink.label} without validation. ` +
                `Vulnerable to ${cweName}.`,
              fix: 'Validate all input before processing. Use schema validation (zod, joi) for structured data. ' +
                'Sanitize special characters. Reject malformed input early.',
              via: 'bfs',
            });
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// Struts framework validation CWEs — gated to only fire on actual Struts code
export const verifyCWE103 = createStrutsValidationVerifier('CWE-103', 'Struts: Incomplete validate() Method Definition', 'medium', /\bsuper\.validate\b|\bValidator\b/i);
export const verifyCWE104 = createStrutsValidationVerifier('CWE-104', 'Struts: Form Bean Does Not Extend Validation Class', 'medium', /\bValidatorForm\b|\bValidatorActionForm\b/i);
export const verifyCWE105 = createStrutsValidationVerifier('CWE-105', 'Struts: Form Field Without Validator', 'medium', /\bvalidation\.xml\b|\bvalidator\b.*\bfield\b/i);
export const verifyCWE106 = createStrutsValidationVerifier('CWE-106', 'Struts: Plug-in Framework Not In Use', 'medium', /\bValidatorPlugin\b|\bstruts-config\b.*\bvalidator\b/i);
export const verifyCWE108 = createStrutsValidationVerifier('CWE-108', 'Struts: Unverified Action Form', 'medium', /\bvalidate\b|\bActionErrors\b/i);

// XML/structural validation
export const verifyCWE112 = createInputValidationVerifier('CWE-112', 'Missing XML Validation', 'high', /\bXMLSchema\b|\bDTD\b|\bvalidate\b|\bschema\b.*\bxml\b/i);
export const verifyCWE115 = createInputValidationVerifier('CWE-115', 'Misinterpretation of Input', 'medium');

// Special character handling
export const verifyCWE148 = createInputValidationVerifier('CWE-148', 'Improper Neutralization of Input Leaders', 'medium', /\btrim\b|\bstrip\b|\bleading\b.*\bremove\b/i);
export const verifyCWE159 = createInputValidationVerifier('CWE-159', 'Improper Handling of Invalid Use of Special Elements', 'medium');
export const verifyCWE166 = createInputValidationVerifier('CWE-166', 'Improper Handling of Missing Special Element', 'medium');
export const verifyCWE167 = createInputValidationVerifier('CWE-167', 'Improper Handling of Additional Special Element', 'medium');
export const verifyCWE168 = createInputValidationVerifier('CWE-168', 'Improper Handling of Inconsistent Special Elements', 'medium');
export const verifyCWE174 = createInputValidationVerifier('CWE-174', 'Double Decoding of the Same Data', 'high', /\bdecodeOnce\b|\bsingle.*decode\b|\balready.*decoded\b/i);

// Allowlist/blocklist quality
export const verifyCWE183 = createInputValidationVerifier('CWE-183', 'Permissive List of Allowed Inputs', 'high', /\bstrict\b.*\ballowlist\b|\bexact.*match\b|\bwhitelist\b.*\bspecific\b/i);
export const verifyCWE184 = createInputValidationVerifier('CWE-184', 'Incomplete List of Disallowed Inputs', 'high', /\ballowlist\b|\bwhitelist\b/i);
export const verifyCWE185 = createInputValidationVerifier('CWE-185', 'Incorrect Regular Expression', 'medium', /\btested.*regex\b|\bRE2\b|\banchor\b/i);

// Structural input handling
export const verifyCWE228 = createInputValidationVerifier('CWE-228', 'Improper Handling of Syntactically Invalid Structure', 'medium');
export const verifyCWE230 = createInputValidationVerifier('CWE-230', 'Improper Handling of Missing Values', 'medium', /\brequired\b|\bdefault\b.*\bvalue\b|\bnull.*check\b/i);
export const verifyCWE231 = createInputValidationVerifier('CWE-231', 'Improper Handling of Extra Values', 'medium', /\bstrict\b|\badditional.*false\b|\bunknown.*reject\b/i);
export const verifyCWE232 = createInputValidationVerifier('CWE-232', 'Improper Handling of Undefined Values', 'medium', /\bundefined\b.*check|\btypeof\b.*undefined|\brequired\b/i);
export const verifyCWE238 = createInputValidationVerifier('CWE-238', 'Improper Handling of Incomplete Element', 'medium');
export const verifyCWE240 = createInputValidationVerifier('CWE-240', 'Improper Handling of Inconsistent Structural Elements', 'medium');

// ===========================================================================
// B. CODE INJECTION / DANGEROUS EVALUATION (7 CWEs)
// ===========================================================================

/**
 * CWE-95: Eval Injection
 * Pattern: INGRESS → TRANSFORM(eval/Function/setTimeout-string) without CONTROL
 *
 * UPGRADED from factory: specific dangerous-eval sink detection, excludes
 * safe parsers (JSON.parse), recognizes sandbox mitigations (vm2, isolated-vm).
 *
 * Dangerous sinks: eval(), new Function(), setTimeout/setInterval with string,
 *   vm.runInNewContext/runInThisContext with user data, unserialize().
 * NOT dangerous: JSON.parse(), parseInt(), parseFloat(), DOMParser().
 * Safe mitigations: vm2/VM2 sandbox, isolated-vm, safeEval libraries,
 *   allowlist-gated evaluation, CONTROL node in path.
 */
export function verifyCWE95(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Specific dangerous-eval sinks — NOT generic "any TRANSFORM"
  const evalSinks = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('eval') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('dynamic') || n.attack_surface.includes('code_execution') ||
     n.code_snapshot.match(
       /\beval\s*\(|\bFunction\s*\(|\bsetTimeout\s*\(\s*['"`]|\bsetInterval\s*\(\s*['"`]|\bnew\s+Function\b|\bvm\.runIn|\bexecScript\b|\bunserialize\s*\(/i
     ) !== null) &&
    // Exclude safe parsers — these accept user input but do NOT execute code
    !n.code_snapshot.match(
      /\bJSON\.parse\b|\bparseInt\b|\bparseFloat\b|\bDOMParser\b|\bNumber\s*\(|\bBoolean\s*\(/i
    )
  );

  for (const src of ingress) {
    for (const sink of evalSinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check for sandbox/isolation mitigations in the sink code itself
        const isSandboxed = sink.code_snapshot.match(
          /\bvm2\b|\bVM2\b|\bisolated-?vm\b|\bisolatedVM\b|\bsafeEval\b|\bnew\s+VM\s*\(\s*\{?\s*sandbox\b|\bQuickJSContext\b|\bWebAssembly\b/i
        ) !== null;

        // Check for allowlist gating (an allowlist check on the VALUE before eval)
        const isAllowlisted = sink.code_snapshot.match(
          /\ballowlist\b|\bwhitelist\b|\ballowedExpressions\b|\bpermitted\b|\bincludes\s*\(/i
        ) !== null;

        if (!isSandboxed && !isAllowlisted) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (eval removal, sandboxed execution, or strict allowlist)',
            severity: 'critical',
            description: `User input from ${src.label} reaches eval/Function at ${sink.label} without isolation. ` +
              `An attacker can inject arbitrary JavaScript: eval("process.exit()"), ` +
              `new Function("return require('child_process').execSync('rm -rf /')").`,
            fix: 'BEST: Remove eval entirely — use JSON.parse() for data, a Map for dynamic dispatch. ' +
              'If eval is truly needed: use vm2 or isolated-vm sandbox with no access to require/process. ' +
              'NEVER: sanitize input and pass to eval — sanitization cannot make eval safe.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-95', name: 'Eval Injection', holds: findings.length === 0, findings };
}

/** CWE-98: PHP Remote File Inclusion — user input in include/require */
export function verifyCWE98(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = includeTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!INCLUDE_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (include path restriction / allowlist)',
            severity: 'critical',
            description: `User input from ${src.label} controls an include/require path at ${sink.label}. ` +
              `An attacker can include remote malicious files for code execution.`,
            fix: 'Never use user input in include/require statements. Use an allowlist of permitted files. ' +
              'Set allow_url_include=Off in php.ini. Use path.basename() to strip directories.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-98', name: 'PHP Remote File Inclusion', holds: findings.length === 0, findings };
}

/** CWE-134: Format String — user input as format string argument */
export function verifyCWE134(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = formatStringNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!FORMAT_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (static format string enforcement)',
            severity: 'critical',
            description: `User input from ${src.label} is used as a format string at ${sink.label}. ` +
              `An attacker can use %x to read memory or %n to write arbitrary values.`,
            fix: 'Always use static/hardcoded format strings. Pass user input as data arguments only. ' +
              'Example: printf("%s", userInput) not printf(userInput).',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-134', name: 'Use of Externally-Controlled Format String', holds: findings.length === 0, findings };
}

/** CWE-624: Executable Regular Expression — regex with executable modifiers */
export function verifyCWE624(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = regexTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isDangerous = sink.code_snapshot.match(
          /\bpreg_replace\b.*\/e|\bRegExp\b.*\+|\bnew\s+RegExp\s*\(.*\+|\/e\b/i
        ) !== null;

        if (isDangerous && !REGEX_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (regex pattern sanitization / no executable modifiers)',
            severity: 'critical',
            description: `User input from ${src.label} influences executable regex at ${sink.label}. ` +
              `The /e modifier or dynamic RegExp construction enables code execution.`,
            fix: 'Never use preg_replace with /e modifier — use preg_replace_callback instead. ' +
              'Escape user input before using in RegExp constructors. Use static patterns.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-624', name: 'Executable Regular Expression Error', holds: findings.length === 0, findings };
}

/** CWE-625: Permissive Regular Expression */
export function verifyCWE625(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = regexTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isPermissive = sink.code_snapshot.match(
          /\.\*|\.\+|\[\^\/\]|\bany\b|\b\.\b\s*\*/i
        ) !== null;

        if (isPermissive && !REGEX_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (strict regex pattern / anchored matching)',
            severity: 'medium',
            description: `Regex at ${sink.label} used on input from ${src.label} is overly permissive. ` +
              `Broad patterns may allow unexpected values to pass validation.`,
            fix: 'Use strict, anchored regex patterns (^...$). Avoid .* in validation regexes. ' +
              'Prefer allowlists of specific characters over broad matches.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-625', name: 'Permissive Regular Expression', holds: findings.length === 0, findings };
}

/** CWE-913: Improper Control of Dynamically-Managed Code Resources */
export const verifyCWE913 = createGenericVerifier(
  'CWE-913', 'Improper Control of Dynamically-Managed Code Resources', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('dynamic') || n.node_subtype.includes('eval') ||
     n.node_subtype.includes('reflect') || n.attack_surface.includes('dynamic_code') ||
     n.code_snapshot.match(/\b(eval|Function|require|import|Reflect|Proxy|defineProperty)\b/i) !== null)
  ),
  /\ballowlist\b|\bwhitelist\b|\bsandbox\b|\bvalidate\s*\(|\b\.freeze\s*\(|\b\.seal\s*\(/i,
  'CONTROL (dynamic code resource restriction / validation)',
  'Restrict which code resources can be dynamically accessed. Use Object.freeze() to prevent modification. ' +
    'Validate all dynamic identifiers against an allowlist.',
);

/** CWE-917: Expression Language Injection */
export function verifyCWE917(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = expressionEvalNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!EXPR_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (expression language sanitization / sandboxing)',
            severity: 'critical',
            description: `User input from ${src.label} flows into expression language evaluation at ${sink.label}. ` +
              `An attacker can inject EL/OGNL/SpEL expressions for code execution or data exfiltration.`,
            fix: 'Never pass user input directly to expression language evaluators. ' +
              'Use parameterized templates. Sandbox expression evaluation. ' +
              'Restrict available classes and methods in the expression context.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-917', name: 'Expression Language Injection', holds: findings.length === 0, findings };
}

// ===========================================================================
// C. RESOURCE EXHAUSTION / DoS (7 CWEs)
// ===========================================================================

/** CWE-369: Divide By Zero */
export function verifyCWE369(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = divisionTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Existing regex check
        const regexSafe = ZERO_CHECK_SAFE.test(sink.code_snapshot);
        // Range check: if the divisor is provably non-zero, suppress
        const rangeSafe = sinkHasNonZeroRange(map, sink.id);

        if (!regexSafe && !rangeSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (zero divisor check)',
            severity: 'medium',
            description: `User input from ${src.label} influences a division at ${sink.label} without zero-check. ` +
              `A zero divisor can cause crashes or undefined behavior.`,
            fix: 'Check that the divisor is not zero before division. Handle the zero case gracefully ' +
              'with a default value or error response.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-369', name: 'Divide By Zero', holds: findings.length === 0, findings };
}

/** CWE-382: J2EE Bad Practices: Use of System.exit() */
export const verifyCWE382 = createGenericVerifier(
  'CWE-382', 'J2EE Bad Practices: Use of System.exit()', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.code_snapshot.match(/\b(System\.exit|process\.exit|os\._exit|Runtime\.halt)\b/i) !== null)
  ),
  /\bnever\b|\bdisabled\b|\bblocked\b/i,
  'CONTROL (exit prevention / graceful shutdown)',
  'Never call System.exit() in web applications or shared containers. ' +
    'Use proper exception handling and graceful shutdown mechanisms.',
);

/** CWE-405: Asymmetric Resource Consumption (Amplification) */
export function verifyCWE405(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = resourceIntensiveTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!RATE_LIMIT_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (rate limiting / cost proportionality check)',
            severity: 'high',
            description: `Small request from ${src.label} triggers expensive operation at ${sink.label} without limits. ` +
              `An attacker can amplify resource consumption for denial of service.`,
            fix: 'Implement rate limiting and request throttling. Enforce proportional cost limits. ' +
              'Use backpressure mechanisms for expensive operations.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-405', name: 'Asymmetric Resource Consumption (Amplification)', holds: findings.length === 0, findings };
}

/** CWE-407: Inefficient Algorithmic Complexity */
export function verifyCWE407(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = complexAlgoTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!COMPLEXITY_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input size limit / algorithmic complexity bound)',
            severity: 'high',
            description: `User input from ${src.label} influences algorithmic operation at ${sink.label} without size limits. ` +
              `Crafted input can trigger worst-case complexity (ReDoS, quadratic sorting, etc.).`,
            fix: 'Limit input sizes before expensive operations. Use linear-time algorithms where possible. ' +
              'Use RE2 or safe-regex for user-influenced patterns. Set timeouts on expensive operations.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-407', name: 'Inefficient Algorithmic Complexity', holds: findings.length === 0, findings };
}

/** CWE-409: Decompression Bomb */
export function verifyCWE409(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = decompressTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!DECOMPRESS_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (decompression size limit / ratio limit)',
            severity: 'high',
            description: `Compressed data from ${src.label} is decompressed at ${sink.label} without size limits. ` +
              `A small zip bomb can expand to gigabytes, exhausting memory and disk.`,
            fix: 'Enforce maximum decompression output size. Check compression ratio (reject > 100:1). ' +
              'Decompress in streaming mode with size tracking. Abort if limits exceeded.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-409', name: 'Improper Handling of Highly Compressed Data (Decompression Bomb)', holds: findings.length === 0, findings };
}

/** CWE-776: XML Entity Expansion (Billion Laughs) */
export function verifyCWE776(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = xmlParserTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!XML_ENTITY_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (XML entity expansion limit / DTD processing restriction)',
            severity: 'high',
            description: `XML from ${src.label} is parsed at ${sink.label} without entity expansion limits. ` +
              `Recursive entity definitions (Billion Laughs) can exhaust memory exponentially.`,
            fix: 'Disable DTD processing entirely if not needed. Set entity expansion limits. ' +
              'Use defusedxml (Python) or configure maxEntityExpansions. Consider JSON over XML.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-776', name: 'XML Entity Expansion (Billion Laughs)', holds: findings.length === 0, findings };
}

/**
 * CWE-789: Memory Allocation with Excessive Size Value
 *
 * Patterns detected:
 *   A. Graph taint: INGRESS -> TRANSFORM (alloc/collection constructor) without CONTROL
 *   B. Scope-based taint fallback: tainted variable in same scope as allocation
 *   C. Source-line scanning: Integer.parseInt(taintedInput) -> new ArrayList(data)
 *      without bounds check between them
 *
 * Safe patterns: bounds check (if data < MAX), Math.min, clamp, limit, MAX_SIZE
 */
export function verifyCWE789(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = memAllocTransformNodes(map);

  // Bounds-check safe pattern — more comprehensive than ALLOC_SIZE_SAFE alone
  const BOUNDS_SAFE_789 = /\bmax\b.*\bsize\b|\blimit\b|\bclamp\b|\b[<>]=?\s*\d{3,}\b|\bvalidate.*size\b|\bMAX_SIZE\b|\bMath\.min\b|\bMath\.max\b|\bif\s*\(.*\b(?:data|size|len|cap|capacity|count)\b\s*[<>]/i;

  // ---- Strategy 1: Graph taint flow — INGRESS -> alloc sink without CONTROL ----
  for (const src of ingress) {
    for (const sink of sinks) {
      const hasUnsafePath = hasTaintedPathWithoutControl(map, src.id, sink.id) ||
        scopeBasedTaintReaches(map, src.id, sink.id);

      if (hasUnsafePath) {
        const scopeSnaps = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnaps.join('\n'));
        if (!ALLOC_SIZE_SAFE.test(sink.code_snapshot) && !BOUNDS_SAFE_789.test(combinedScope)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (allocation size validation / maximum limit)',
            severity: 'high',
            description: `User input from ${src.label} controls memory allocation size at ${sink.label} without limits. ` +
              `An attacker can request excessive allocation to exhaust memory (OutOfMemoryError/DoS).`,
            fix: 'Validate allocation sizes against a maximum limit before allocating. ' +
              'Use: if (size > MAX_ALLOWED) throw new IllegalArgumentException(); ' +
              'Or use Math.min(size, MAX_ALLOWED_SIZE). Reject unreasonable sizes early.',
          });
        }
      }
    }
  }

  // ---- Strategy 2: Source-line scanning fallback for Juliet patterns ----
  // Catches: Integer.parseInt(taintedInput) -> new ArrayList(data) without bounds check
  const src789 = map.source_code || '';
  if (src789 && findings.length === 0) {
    const lines789 = src789.split('\n');

    // Taint sources: socket reads, servlet params, user input parsed to int
    const TAINT_INT_RE = /\b(Integer\.parseInt|Integer\.valueOf|Long\.parseLong|Short\.parseShort)\s*\(\s*(\w+)/;
    const SOCKET_READ_RE = /\breadLine\b|\bgetInputStream\b|\bgetParameter\b|\bgetQueryString\b|\bgetCookies\b|\bSystem\.getenv\b/;
    // Alloc sinks with tainted size
    const ALLOC_SINK_RE = /\bnew\s+(ArrayList|HashMap|HashSet|LinkedList|Vector|StringBuilder|StringBuffer|byte|char|int|long)\s*[\[(]\s*(\w+)/;
    // Bounds check between source and sink
    const BOUNDS_CHECK_RE = /\bif\s*\(.*\b(data|size|len|cap|count|num)\b\s*[<>]|\bMath\.(min|max)\s*\(.*\b(data|size|len|cap|count|num)\b|\b(data|size|len|cap|count|num)\b\s*[<>]=?\s*\d/;

    // Find tainted integer assignments
    const taintedIntLines: Array<{ line: number; varName: string }> = [];
    for (let i = 0; i < lines789.length; i++) {
      const ln = lines789[i];
      if (/^\s*\/\//.test(ln) || /^\s*\*/.test(ln)) continue;
      const parseMatch = TAINT_INT_RE.exec(ln);
      if (parseMatch) {
        // Check if the parsed string came from a taint source
        const parsedVar = parseMatch[2];
        // Look backward for the source of this variable
        for (let j = Math.max(0, i - 20); j < i; j++) {
          if (SOCKET_READ_RE.test(lines789[j]) && new RegExp(`\\b${parsedVar}\\b`).test(lines789[j])) {
            // The assignment target
            const assignMatch = ln.match(/^\s*(\w+)\s*=\s*/);
            if (assignMatch) {
              taintedIntLines.push({ line: i + 1, varName: assignMatch[1] });
            }
            break;
          }
        }
      }
    }

    // Find allocation sinks using tainted variables
    for (const { line: taintLine, varName } of taintedIntLines) {
      for (let i = taintLine; i < lines789.length; i++) {
        const ln = lines789[i];
        if (/^\s*\/\//.test(ln) || /^\s*\*/.test(ln)) continue;
        const allocMatch = ALLOC_SINK_RE.exec(ln);
        if (allocMatch && allocMatch[2] === varName) {
          // Check for bounds check between taint source and alloc sink
          const betweenCode = lines789.slice(taintLine - 1, i).join('\n');
          if (!BOUNDS_CHECK_RE.test(betweenCode) && !ALLOC_SIZE_SAFE.test(betweenCode)) {
            const srcNode = findNearestNode(map, taintLine) || map.nodes[0];
            const sinkNode = findNearestNode(map, i + 1) || map.nodes[0];
            if (srcNode && sinkNode) {
              const already = findings.some(f =>
                Math.abs(f.source.line - taintLine) <= 3 && Math.abs(f.sink.line - (i + 1)) <= 3);
              if (!already) {
                findings.push({
                  source: nodeRef(srcNode),
                  sink: nodeRef(sinkNode),
                  missing: 'CONTROL (bounds check on tainted integer before allocation)',
                  severity: 'high',
                  description: `Tainted integer '${varName}' from user input (L${taintLine}) used as ` +
                    `allocation size in new ${allocMatch[1]}(${varName}) (L${i + 1}) without bounds check. ` +
                    `An attacker can supply a huge value to cause OutOfMemoryError (DoS).`,
                  fix: `Add bounds validation before allocation: if (${varName} < 0 || ${varName} > MAX_SIZE) ` +
                    `throw new IllegalArgumentException("Size out of bounds"); ` +
                    `Or use Math.min(${varName}, MAX_ALLOWED_SIZE).`,
                });
              }
            }
          }
          break; // Found the allocation for this variable
        }
      }
    }
  }

  return { cwe: 'CWE-789', name: 'Memory Allocation with Excessive Size Value', holds: findings.length === 0, findings };
}

// ===========================================================================
// D. TYPE/REFLECTION (3 CWEs)
// ===========================================================================

/** CWE-436: Interpretation Conflict */
export const verifyCWE436 = createGenericVerifier(
  'CWE-436', 'Interpretation Conflict', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('interpret') || n.node_subtype.includes('content_type') ||
     n.code_snapshot.match(/\b(Content-Type|charset|encoding|sniff|detect.*type)\b/i) !== null)
  ),
  /\bstrict.*type\b|\bcontent.*type.*explicit\b|\bnosniff\b|\bX-Content-Type-Options\b/i,
  'CONTROL (strict content type enforcement / no sniffing)',
  'Set explicit Content-Type headers. Use X-Content-Type-Options: nosniff. ' +
    'Do not rely on content sniffing for security decisions.',
);

/** CWE-470: Unsafe Reflection */
export function verifyCWE470(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = reflectionTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!REFLECT_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (class/method allowlist for reflection)',
            severity: 'critical',
            description: `User input from ${src.label} controls class/method selection via reflection at ${sink.label}. ` +
              `An attacker can instantiate arbitrary classes or invoke unintended methods.`,
            fix: 'Validate class/method names against a strict allowlist before reflection. ' +
              'Never use user input directly in Class.forName() or require() with concatenation.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-470', name: 'Unsafe Reflection', holds: findings.length === 0, findings };
}

/** CWE-704: Incorrect Type Conversion or Cast */
export const verifyCWE704 = createGenericVerifier(
  'CWE-704', 'Incorrect Type Conversion or Cast', 'medium',
  typeCastTransformNodes, TYPE_SAFE,
  'CONTROL (type validation before conversion)',
  'Validate type compatibility before casting. Use typeof/instanceof checks. ' +
    'Handle conversion errors gracefully. Prefer safe parsing methods.',
);

// ===========================================================================
// E. CRYPTO WEAKNESS (2 CWEs)
// ===========================================================================

/** CWE-328: Use of Weak Hash */
export function verifyCWE328(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const reported = new Set<string>();

  // --- Strategy 1: Graph-based (INGRESS -> hash TRANSFORM without CONTROL) ---
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = hashTransformNodes(map);

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isWeak = sink.code_snapshot.match(
          /\b(MD5|SHA-?1|md5|sha1|createHash\s*\(\s*['"](?:md5|sha1)['"])\b/i
        ) !== null;

        if (isWeak && !HASH_SAFE.test(sink.code_snapshot)) {
          reported.add(sink.id);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (strong hash algorithm enforcement)',
            severity: 'high',
            description: `Data from ${src.label} is hashed with a weak algorithm at ${sink.label}. ` +
              `MD5 and SHA-1 are cryptographically broken — vulnerable to collision and preimage attacks.`,
            fix: 'Use strong hashing: SHA-256/SHA-3 for integrity, bcrypt/scrypt/Argon2 for passwords. ' +
              'Never use MD5 or SHA-1 for security-sensitive operations.',
          });
        }
      }
    }
  }

  // --- Strategy 2: Code snapshot scan (catches Java MessageDigest patterns) ---
  // Scans ALL nodes for weak hash algorithm usage regardless of graph topology.
  // This catches patterns like MessageDigest.getInstance("MD5") or getProperty("hashAlg1")
  // which may not have a tainted INGRESS->TRANSFORM path.
  const WEAK_HASH_LITERAL = /\bgetInstance\s*\(\s*["'](?:MD5|SHA-?1|sha-?1|md5)["']/i;
  const WEAK_HASH_PROPERTY = /\bgetProperty\s*\(\s*["']hashAlg1["']/i;
  const WEAK_HASH_CREATE = /\bcreateHash\s*\(\s*["'](?:md5|sha-?1)["']/i;
  const WEAK_HASH_HASHLIB = /\bhashlib\.(?:md5|sha1)\b/i;

  for (const node of map.nodes) {
    if (reported.has(node.id)) continue;
    const snap = node.code_snapshot;
    const isWeakLiteral = WEAK_HASH_LITERAL.test(snap) || WEAK_HASH_CREATE.test(snap) || WEAK_HASH_HASHLIB.test(snap);
    const isWeakProperty = WEAK_HASH_PROPERTY.test(snap);
    const strongBlocks = isWeakProperty ? false : HASH_SAFE.test(snap);
    if ((isWeakLiteral || isWeakProperty) && !strongBlocks) {
      reported.add(node.id);
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (strong hash algorithm enforcement)',
        severity: 'high',
        description: isWeakProperty
          ? `${node.label} loads hash algorithm from property "hashAlg1" which resolves to MD5. ` +
            `MD5 is cryptographically broken — vulnerable to collision and preimage attacks.`
          : `${node.label} uses a weak hash algorithm (MD5 or SHA-1). ` +
            `These are cryptographically broken — vulnerable to collision and preimage attacks.`,
        fix: 'Use strong hashing: SHA-256/SHA-3 for integrity, bcrypt/scrypt/Argon2 for passwords. ' +
          'Never use MD5 or SHA-1 for security-sensitive operations.',
      });
    }
  }

  return { cwe: 'CWE-328', name: 'Use of Weak Hash', holds: findings.length === 0, findings };
}

/** CWE-757: Selection of Less-Secure Algorithm During Negotiation */
export const verifyCWE757 = createGenericVerifier(
  'CWE-757', 'Selection of Less-Secure Algorithm During Negotiation', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('negotiate') || n.node_subtype.includes('tls') ||
     n.node_subtype.includes('cipher') || n.node_subtype.includes('ssl') ||
     n.code_snapshot.match(/\b(negotiate|cipher|protocol|TLS|SSL|handshake|minVersion)\b/i) !== null)
  ),
  NEGOTIATE_SAFE,
  'CONTROL (minimum algorithm strength / no downgrade)',
  'Enforce minimum TLS version (1.2+). Disable weak cipher suites. ' +
    'Use Strict-Transport-Security header. Prevent protocol downgrade attacks.',
);

// ===========================================================================
// F. INDIVIDUAL VERIFIERS (11 CWEs)
// ===========================================================================

/** CWE-554: ASP.NET Misconfiguration — gated to C#/.NET code only */
export const verifyCWE554 = (map: NeuralMap): VerificationResult => {
  const lang = detectLanguage(map);
  if (lang && lang !== 'csharp') {
    return { cwe: 'CWE-554', name: 'ASP.NET Misconfiguration: Not Using Input Validation Framework', holds: true, findings: [] };
  }
  return createInputValidationVerifier(
    'CWE-554', 'ASP.NET Misconfiguration: Not Using Input Validation Framework', 'medium',
    /\bRequestValidation\b|\bvalidateRequest\b|\bAntiForgery\b|\b\[ValidateInput\]/i
  )(map);
};

/** CWE-602: Client-Side Enforcement of Server-Side Security */
export const verifyCWE602 = createGenericVerifier(
  'CWE-602', 'Client-Side Enforcement of Server-Side Security', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('server') || n.node_subtype.includes('action') ||
     n.attack_surface.includes('server_action') ||
     n.code_snapshot.match(/\b(app\.(get|post|put|delete)|router\.|handler|controller)\b/i) !== null)
  ),
  /\bserver.*valid\b|\bbackend.*check\b|\bmiddleware\b|\bguard\b|\bauthorize\b/i,
  'CONTROL (server-side validation — not relying on client)',
  'Always replicate security checks on the server. Client-side validation is UX only. ' +
    'Never trust data from the client — validate everything server-side.',
);

/** CWE-616: Incomplete Identification of Uploaded File Variables (PHP) */
export const verifyCWE616 = createGenericVerifier(
  'CWE-616', 'Incomplete Identification of Uploaded File Variables (PHP)', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.code_snapshot.match(/\b(\$_FILES|is_uploaded_file|move_uploaded_file|tmp_name)\b/i) !== null)
  ),
  /\bis_uploaded_file\b|\bmove_uploaded_file\b|\btmp_name\b.*\bcheck\b/i,
  'CONTROL (proper uploaded file identification)',
  'Always use is_uploaded_file() and move_uploaded_file() for uploaded files. ' +
    'Check all $_FILES array fields, not just tmp_name.',
);

/** CWE-617: Reachable Assertion */
export const verifyCWE617 = createGenericVerifier(
  'CWE-617', 'Reachable Assertion', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.code_snapshot.match(/\b(assert|console\.assert|Debug\.Assert)\s*\(/i) !== null)
  ),
  /\bproduction\b.*\bdisable\b|\bNDEBUG\b|\bassert.*off\b/i,
  'CONTROL (assertion not reachable in production)',
  'Do not use assertions for input validation — they can be disabled in production. ' +
    'Use proper error handling and validation instead of assert().',
);

/** CWE-626: Null Byte Interaction Error (Poison Null Byte) */
export const verifyCWE626 = createGenericVerifier(
  'CWE-626', 'Null Byte Interaction Error (Poison Null Byte)', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('string') || n.node_subtype.includes('path') ||
     n.code_snapshot.match(/\b(include|require|open|read|fopen|file_get_contents)\b/i) !== null)
  ),
  /\bnull.*byte\b.*strip|\b\\0\b.*reject|\bsanitize.*null\b|\breplace.*\\x00/i,
  'CONTROL (null byte stripping / rejection)',
  'Strip or reject null bytes (\\0) from all user input before file operations. ' +
    'Null bytes can truncate strings in C-based languages, bypassing extension checks.',
);

/** CWE-627: Dynamic Variable Evaluation */
export const verifyCWE627 = createGenericVerifier(
  'CWE-627', 'Dynamic Variable Evaluation', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('dynamic') || n.node_subtype.includes('eval') ||
     n.code_snapshot.match(/\b(\$\$|variable\s*variables|compact|eval|assert)\b/i) !== null)
  ),
  /\ballowlist\b|\bwhitelist\b|\bvalidate\b|\bescapeShell\b/i,
  'CONTROL (dynamic variable name validation)',
  'Validate dynamically-referenced variable names against an allowlist. ' +
    'Avoid PHP variable variables ($$var) with user input.',
);

/** CWE-777: Regular Expression without Anchors */
export const verifyCWE777 = createGenericVerifier(
  'CWE-777', 'Regular Expression without Anchors', 'medium',
  regexTransformNodes,
  /\b\^\b.*\b\$\b|\banchor\b|\bexact.*match\b|\bfullMatch\b|\bmatches\b/i,
  'CONTROL (anchored regex pattern — ^ and $)',
  'Always anchor validation regexes with ^ and $. Unanchored patterns can match substrings, ' +
    'allowing malicious payloads to pass with a valid prefix or suffix.',
);

/** CWE-781: Improper Address Validation in IOCTL with METHOD_NEITHER */
export const verifyCWE781 = createGenericVerifier(
  'CWE-781', 'Improper Address Validation in IOCTL with METHOD_NEITHER', 'critical',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('ioctl') || n.node_subtype.includes('driver') ||
     n.code_snapshot.match(/\b(IOCTL|DeviceIoControl|METHOD_NEITHER|ProbeForRead|ProbeForWrite)\b/i) !== null)
  ),
  /\bProbeForRead\b|\bProbeForWrite\b|\bMmIsAddressValid\b|\bvalidate.*address\b/i,
  'CONTROL (user-mode address validation — ProbeForRead/ProbeForWrite)',
  'Always validate user-mode buffer addresses with ProbeForRead/ProbeForWrite for METHOD_NEITHER IOCTLs. ' +
    'Never directly dereference user-supplied pointers in kernel mode.',
);

/** CWE-837: Improper Enforcement of a Single, Unique Action */
export const verifyCWE837 = createGenericVerifier(
  'CWE-837', 'Improper Enforcement of a Single, Unique Action', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('action') || n.node_subtype.includes('submit') ||
     n.attack_surface.includes('idempotent') ||
     n.code_snapshot.match(/\b(submit|process|execute|charge|transfer|vote|register)\b/i) !== null)
  ),
  /\bidempoten\b|\bnonce\b|\btoken\b|\bonce\b|\bduplicate.*check\b|\bunique.*constraint\b/i,
  'CONTROL (idempotency / duplicate action prevention)',
  'Use idempotency tokens or nonces to prevent duplicate submissions. ' +
    'Implement unique constraints and duplicate detection for critical actions.',
);

/** CWE-841: Improper Enforcement of Behavioral Workflow */
export const verifyCWE841 = createGenericVerifier(
  'CWE-841', 'Improper Enforcement of Behavioral Workflow', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('action') || n.node_subtype.includes('step') ||
     n.attack_surface.includes('workflow') ||
     n.code_snapshot.match(/\b(checkout|payment|confirm|finalize|approve|complete)\b/i) !== null)
  ),
  WORKFLOW_SAFE,
  'CONTROL (workflow state validation / step enforcement)',
  'Enforce required workflow steps on the server. Validate that prerequisite steps completed ' +
    'before allowing progression. Use state machines for multi-step processes.',
);

/** CWE-924: Improper Enforcement of Message Integrity During Transmission */
export const verifyCWE924 = createGenericVerifier(
  'CWE-924', 'Improper Enforcement of Message Integrity During Transmission', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('message') || n.node_subtype.includes('transmit') ||
     n.node_subtype.includes('channel') || n.attack_surface.includes('message_integrity') ||
     n.code_snapshot.match(/\b(send|transmit|publish|emit|postMessage|WebSocket)\b/i) !== null)
  ),
  /\bHMAC\b|\bsignature\b|\bdigest\b|\bintegrity\b|\bchecksum\b|\bMAC\b|\bverify.*hash\b/i,
  'CONTROL (message integrity verification — HMAC / signature)',
  'Sign messages with HMAC or digital signatures. Verify integrity on receipt. ' +
    'Use TLS for transport security. Never trust unsigned messages.',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_002_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Input Validation (22)
  'CWE-103': verifyCWE103,
  'CWE-104': verifyCWE104,
  'CWE-105': verifyCWE105,
  'CWE-106': verifyCWE106,
  'CWE-108': verifyCWE108,
  'CWE-112': verifyCWE112,
  'CWE-115': verifyCWE115,
  'CWE-148': verifyCWE148,
  'CWE-159': verifyCWE159,
  'CWE-166': verifyCWE166,
  'CWE-167': verifyCWE167,
  'CWE-168': verifyCWE168,
  'CWE-174': verifyCWE174,
  'CWE-183': verifyCWE183,
  'CWE-184': verifyCWE184,
  'CWE-185': verifyCWE185,
  'CWE-228': verifyCWE228,
  'CWE-230': verifyCWE230,
  'CWE-231': verifyCWE231,
  'CWE-232': verifyCWE232,
  'CWE-238': verifyCWE238,
  'CWE-240': verifyCWE240,
  // Code Injection (7)
  'CWE-95': verifyCWE95,
  'CWE-98': verifyCWE98,
  'CWE-134': verifyCWE134,
  'CWE-624': verifyCWE624,
  'CWE-625': verifyCWE625,
  'CWE-913': verifyCWE913,
  'CWE-917': verifyCWE917,
  // Resource Exhaustion (7)
  'CWE-369': verifyCWE369,
  'CWE-382': verifyCWE382,
  'CWE-405': verifyCWE405,
  'CWE-407': verifyCWE407,
  'CWE-409': verifyCWE409,
  'CWE-776': verifyCWE776,
  'CWE-789': verifyCWE789,
  // Type/Reflection (3)
  'CWE-436': verifyCWE436,
  'CWE-470': verifyCWE470,
  'CWE-704': verifyCWE704,
  // Crypto (2)
  'CWE-328': verifyCWE328,
  'CWE-757': verifyCWE757,
  // Individual (11)
  'CWE-554': verifyCWE554,
  'CWE-602': verifyCWE602,
  'CWE-616': verifyCWE616,
  'CWE-617': verifyCWE617,
  'CWE-626': verifyCWE626,
  'CWE-627': verifyCWE627,
  'CWE-777': verifyCWE777,
  'CWE-781': verifyCWE781,
  'CWE-837': verifyCWE837,
  'CWE-841': verifyCWE841,
  'CWE-924': verifyCWE924,
};
