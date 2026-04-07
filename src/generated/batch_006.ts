/**
 * DST Generated Verifiers — Batch 006
 * Pattern shape: INGRESS→TRANSFORM without TRANSFORM
 * 20 CWEs: delimiter neutralization, input handling, encoding, PRNG seeding.
 *
 * User input reaches a processing TRANSFORM (the sink) without first passing
 * through a sanitization TRANSFORM (the missing mediator). Uses
 * hasPathWithoutIntermediateType to avoid counting the sink itself.
 *
 * Sub-groups:
 *   A. Delimiter neutralization (12 CWEs) — factory-driven
 *   B. Input handling            (4 CWEs) — factory-driven
 *   C. Individual patterns       (4 CWEs) — per-CWE
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasPathWithoutIntermediateType, hasTaintedPathWithoutControl,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Sink filters — TRANSFORM nodes that process user input
// ---------------------------------------------------------------------------

function delimiterProcessNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('parse') || n.node_subtype.includes('split') ||
     n.node_subtype.includes('delimiter') || n.node_subtype.includes('csv') ||
     n.node_subtype.includes('format') || n.attack_surface.includes('data_processing') ||
     n.code_snapshot.match(
       /\b(split|join|parse|format|CSV|TSV|serialize|concat|template|interpolat)\b/i
     ) !== null)
  );
}

function dataProcessNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('parse') || n.node_subtype.includes('process') ||
     n.node_subtype.includes('decode') || n.node_subtype.includes('convert') ||
     n.code_snapshot.match(
       /\b(parse|decode|convert|process|transform|handle|interpret|unmarshal)\b/i
     ) !== null)
  );
}

// ---------------------------------------------------------------------------
// Safe pattern constants
// ---------------------------------------------------------------------------

const DELIMITER_ESCAPE_SAFE = /\bescape\s*\(|\bquote\s*\(|\bencode\s*\(|\bsanitize\s*\(|\bstrip\s*\(|\bneutralize\s*\(|\bparameteriz\b|\bCSV\.stringify\b|\bjson\.stringify\b/i;
const ENCODING_SAFE = /\bencodeURI\b|\bencodeURIComponent\b|\bpercentEncode\b|\bhtmlEntities\b|\bencoding.*check\b|\bcharset.*valid\b/i;
const DATA_TYPE_SAFE = /\btypeof\b|\binstanceof\b|\bNumber\.isFinite\b|\bArray\.isArray\b|\bschema\b|\bvalidate.*type\b|\bzod\b|\bjoi\b/i;

// ---------------------------------------------------------------------------
// Factory: INGRESS→TRANSFORM(sink) without intermediate TRANSFORM
// ---------------------------------------------------------------------------

function createIntermediateTransformVerifier(
  cweId: string, cweName: string, severity: Severity,
  sinkFilter: (map: NeuralMap) => NeuralMapNode[],
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
  extraSafe?: RegExp,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = sinkFilter(map);

    for (const src of ingress) {
      for (const sink of sinks) {
        if (hasPathWithoutIntermediateType(map, src.id, sink.id, 'TRANSFORM')) {
          const isSafe = safePattern.test(sink.code_snapshot) ||
            (extraSafe ? extraSafe.test(sink.code_snapshot) : false);

          if (!isSafe) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `User input from ${src.label} reaches processing at ${sink.label} without prior sanitization. ` +
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
// A. DELIMITER NEUTRALIZATION (12 CWEs)
// ===========================================================================

export const verifyCWE140 = createIntermediateTransformVerifier(
  'CWE-140', 'Improper Neutralization of Delimiters', 'high',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (delimiter escaping / quoting before processing)',
  'Escape or quote delimiter characters in user input before incorporating into delimited structures. ' +
    'Use proper serialization libraries (JSON.stringify, csv-stringify).',
);

export const verifyCWE141 = createIntermediateTransformVerifier(
  'CWE-141', 'Improper Neutralization of Parameter/Argument Delimiters', 'high',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (parameter delimiter escaping)',
  'Escape parameter delimiters (& ; = in URLs, ; in shell) before building parameter strings. ' +
    'Use URL/URLSearchParams API instead of manual string construction.',
  /\bURLSearchParams\b|\burl\.format\b/i,
);

export const verifyCWE142 = createIntermediateTransformVerifier(
  'CWE-142', 'Improper Neutralization of Value Delimiters', 'high',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (value delimiter escaping)',
  'Escape value delimiters (quotes, equals signs) in user input before embedding in key=value pairs.',
);

export const verifyCWE143 = createIntermediateTransformVerifier(
  'CWE-143', 'Improper Neutralization of Record Delimiters', 'high',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (record delimiter escaping — newlines, row separators)',
  'Escape record delimiters (newlines, \\r\\n) before incorporating user input into record-based data. ' +
    'Use proper CSV/TSV libraries that handle quoting.',
);

export const verifyCWE144 = createIntermediateTransformVerifier(
  'CWE-144', 'Improper Neutralization of Line Delimiters', 'high',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (line delimiter escaping — \\n, \\r)',
  'Strip or escape line delimiters from user input before placing in line-oriented contexts ' +
    '(log files, HTTP headers, CSV rows).',
);

export const verifyCWE145 = createIntermediateTransformVerifier(
  'CWE-145', 'Improper Neutralization of Section Delimiters', 'medium',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (section delimiter escaping)',
  'Escape section delimiters before user input is placed in structured documents (INI, config files).',
);

export const verifyCWE147 = createIntermediateTransformVerifier(
  'CWE-147', 'Improper Neutralization of Input Terminators', 'high',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (input terminator neutralization — null bytes, EOF markers)',
  'Strip or escape input terminators (null bytes, EOF markers) from user input. ' +
    'Terminators can truncate data or cause premature end of processing.',
);

export const verifyCWE149 = createIntermediateTransformVerifier(
  'CWE-149', 'Improper Neutralization of Quoting Syntax', 'high',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (quote escaping before embedding in quoted contexts)',
  'Escape quote characters in user input before embedding in quoted strings. ' +
    'Use parameterized queries or proper escaping functions for the target context.',
);

export const verifyCWE155 = createIntermediateTransformVerifier(
  'CWE-155', 'Improper Neutralization of Wildcards or Matching Symbols', 'medium',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (wildcard escaping before pattern operations)',
  'Escape wildcard characters (*, ?, %, _) in user input before using in glob, LIKE, or regex. ' +
    'Use parameterized queries for SQL LIKE clauses.',
  /\bescapeGlob\b|\bescapeLike\b|\bparameteriz\b/i,
);

export const verifyCWE156 = createIntermediateTransformVerifier(
  'CWE-156', 'Improper Neutralization of Whitespace', 'medium',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (whitespace normalization / escaping)',
  'Normalize or escape whitespace in user input before delimiter-sensitive processing. ' +
    'Tabs, non-breaking spaces, and Unicode whitespace can alter field boundaries.',
  /\btrim\b|\bnormalize.*space\b/i,
);

export const verifyCWE157 = createIntermediateTransformVerifier(
  'CWE-157', 'Failure to Sanitize Paired Delimiters', 'medium',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (paired delimiter balancing / escaping — parentheses, brackets, quotes)',
  'Escape or balance paired delimiters ((), [], {}, "") in user input. ' +
    'Unbalanced delimiters can alter parsing structure.',
);

export const verifyCWE164 = createIntermediateTransformVerifier(
  'CWE-164', 'Improper Neutralization of Internal Special Elements', 'medium',
  delimiterProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (internal special element neutralization)',
  'Neutralize special elements that appear within the data, not just at boundaries. ' +
    'Internal delimiters, escape sequences, and control characters need handling.',
);

// ===========================================================================
// B. INPUT HANDLING (4 CWEs)
// ===========================================================================

export const verifyCWE165 = createIntermediateTransformVerifier(
  'CWE-165', 'Improper Neutralization of Multiple Internal Special Elements', 'medium',
  dataProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (multiple internal special element neutralization)',
  'Handle cases where multiple special elements interact or compound. ' +
    'Apply neutralization comprehensively, not just to the first occurrence.',
);

export const verifyCWE172 = createIntermediateTransformVerifier(
  'CWE-172', 'Encoding Error', 'medium',
  dataProcessNodes, ENCODING_SAFE,
  'TRANSFORM (character encoding validation / normalization)',
  'Validate and normalize character encoding before processing. ' +
    'Ensure consistent encoding (UTF-8) throughout the pipeline. Reject invalid sequences.',
);

export const verifyCWE177 = createIntermediateTransformVerifier(
  'CWE-177', 'Improper Handling of URL Encoding (Hex Encoding)', 'high',
  dataProcessNodes, ENCODING_SAFE,
  'TRANSFORM (URL decoding / hex encoding normalization)',
  'Decode URL encoding before validation. Double-encoded input (%2527 → %27 → \') can bypass checks. ' +
    'Decode fully before applying security checks.',
);

export const verifyCWE237 = createIntermediateTransformVerifier(
  'CWE-237', 'Improper Handling of Structural Elements', 'medium',
  dataProcessNodes, DELIMITER_ESCAPE_SAFE,
  'TRANSFORM (structural element validation / sanitization)',
  'Validate structural elements in user input before processing. ' +
    'Reject input with malformed structure rather than attempting to fix it.',
);

// ===========================================================================
// C. INDIVIDUAL PATTERNS (4 CWEs)
// ===========================================================================

/** CWE-241: Improper Handling of Unexpected Data Type */
export const verifyCWE241 = createIntermediateTransformVerifier(
  'CWE-241', 'Improper Handling of Unexpected Data Type', 'medium',
  dataProcessNodes, DATA_TYPE_SAFE,
  'TRANSFORM (type checking / coercion before processing)',
  'Check data types before processing. Use typeof, instanceof, or schema validation. ' +
    'Reject unexpected types rather than silently coercing.',
);

/** CWE-337: Predictable Seed in PRNG */
export function verifyCWE337(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sinks = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('random') || n.node_subtype.includes('prng') ||
     n.node_subtype.includes('seed') ||
     n.code_snapshot.match(/\b(seed|srand|Random\(|Math\.random|mt_rand|setSeed)\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of sinks) {
      if (hasPathWithoutIntermediateType(map, src.id, sink.id, 'TRANSFORM')) {
        const isSafe = sink.code_snapshot.match(
          /\bcrypto\.random\b|\bsecureRandom\b|\bCSPRNG\b|\brandomBytes\b|\bgetRandomValues\b|\b\/dev\/urandom\b/i
        ) !== null;

        if (!isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (entropy mixing / CSPRNG seeding)',
            severity: 'high',
            description: `Predictable value from ${src.label} seeds PRNG at ${sink.label} without entropy mixing. ` +
              `An attacker can reconstruct all random output.`,
            fix: 'Use cryptographically secure random generators (crypto.randomBytes, window.crypto.getRandomValues). ' +
              'Never seed PRNGs with timestamps, PIDs, or other predictable values.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-337', name: 'Predictable Seed in PRNG', holds: findings.length === 0, findings };
}

/** CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data */
export const verifyCWE349 = createIntermediateTransformVerifier(
  'CWE-349', 'Acceptance of Extraneous Untrusted Data With Trusted Data', 'high',
  dataProcessNodes,
  /\bvalidate\s*\(|\bsanitize\s*\(|\bstrip.*extra\b|\bschema\b|\bstrict\b|\badditionalProperties.*false\b/i,
  'TRANSFORM (strict parsing — reject extraneous data)',
  'Use strict parsing that rejects unexpected fields. Set additionalProperties: false in JSON schemas. ' +
    'Never merge untrusted data into trusted structures without validation.',
);

/**
 * CWE-91: XML Injection / Blind XPath Injection (UPGRADED — hand-written quality)
 *
 * Detects user input flowing into XML document construction or XPath query
 * building without proper encoding or parameterization.
 *
 * Two distinct attack vectors:
 *
 * 1. XML Element Injection — user input embedded in XML document via string
 *    concatenation. Attacker injects new elements or attributes.
 *    Sinks: createElement+string, template literals building XML, xml string concat,
 *           etree.SubElement with unescaped text, DOMParser.parseFromString
 *
 * 2. XPath Injection — user input embedded in XPath query string.
 *    Attacker alters query logic (e.g., ' or '1'='1 bypasses auth).
 *    Sinks: selectNodes, evaluate, xpath.select, doc.find (lxml)
 *
 * Safe patterns:
 *   - createTextNode() — DOM API that auto-escapes text content
 *   - escapeXml() / xmlEncode() — explicit XML entity encoding
 *   - Parameterized XPath (XPathEvaluator with variables)
 *   - xml2js / fast-xml-parser builder APIs (structured, not string-based)
 *   - lxml.etree.SubElement with .text= (auto-escapes)
 *   - CDATA sections for known text blocks
 *
 * NOT safe:
 *   - innerHTML / outerHTML with XML (browser context)
 *   - String concatenation: '<user>' + input + '</user>'
 *   - Template literals: `//user[name='${input}']`
 *   - etree.fromstring('<root>' + input + '</root>')
 */
export function verifyCWE91(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // XML construction sinks — both TRANSFORM and EXTERNAL types
  const xmlSinks = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('xml') || n.node_subtype.includes('xpath') ||
     n.attack_surface.includes('xml_construct') || n.attack_surface.includes('xpath_query') ||
     n.code_snapshot.match(
       /\b(createElement|appendChild|parseFromString|selectNodes|xpath\.select|evaluate|etree\.(SubElement|fromstring|XML)|DOMParser|xml2js|XPathExpression)\b/i
     ) !== null ||
     // String-based XML construction
     n.code_snapshot.match(/<\w+[^>]*>.*(\+|\$\{)/) !== null)
  );

  for (const src of ingress) {
    for (const sink of xmlSinks) {
      // Use path-without-control for this CWE: the issue is reaching XML
      // construction without ANY control node validating/encoding the input
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code = sink.code_snapshot;

        // Safe: DOM API createTextNode — auto-escapes text content
        const usesCreateTextNode = /\bcreateTextNode\s*\(/i.test(code);

        // Safe: explicit XML encoding functions
        const usesXmlEncode = /\b(escapeXml|xmlEncode|xmlEscape|encodeXml|he\.encode|entities\.encode)\s*\(/i.test(code);

        // Safe: parameterized XPath (variable binding, not string concat)
        const usesParamXpath = /\bXPathEvaluator\b|\bxpath.*variable\b|\bbindVariable\b|\bNSResolver\b/i.test(code);

        // Safe: structured XML builder APIs (not string-based)
        const usesStructuredBuilder = /\b(xml2js\.Builder|xmlbuilder|create\(\{|js2xml)\b/i.test(code);

        // Safe: etree with .text property assignment (auto-escapes)
        const usesEtreeText = /\.text\s*=\s*\w/i.test(code) && /\betree\b/i.test(code);

        // Safe: sanitizeXml or similar explicit sanitization
        const usesSanitize = /\bsanitize.*xml\b|\bxmlSanitize\b/i.test(code);

        const isSafe = usesCreateTextNode || usesXmlEncode || usesParamXpath ||
          usesStructuredBuilder || usesEtreeText || usesSanitize;

        if (!isSafe) {
          // Classify: is this XPath injection or XML element injection?
          const isXpath = /\bxpath\b|\bselectNodes\b|\bevaluate\b|\b\/\/\w+\[/i.test(code);
          const attackType = isXpath ? 'XPath query manipulation' : 'XML element/attribute injection';

          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (XML entity encoding or parameterized XPath before document construction)',
            severity: 'high',
            description: `User input from ${src.label} flows into XML construction at ${sink.label} without encoding. ` +
              `Vulnerable to ${attackType}. ` +
              (isXpath
                ? `An attacker can inject XPath operators to bypass authentication or extract data (e.g., ' or '1'='1).`
                : `An attacker can inject XML elements or attributes to alter document structure.`),
            fix: isXpath
              ? 'Use parameterized XPath queries with variable binding instead of string concatenation. ' +
                'Example: use XPathEvaluator with resolver, not "//user[name=\'" + input + "\']". ' +
                'If concatenation is unavoidable, escape \' " / and XPath operators in user input.'
              : 'Use DOM APIs (createTextNode, setAttribute) instead of string concatenation for XML. ' +
                'Example: instead of "<name>" + input + "</name>", use el.textContent = input. ' +
                'Encode XML special characters (&, <, >, \', ") with escapeXml() or he.encode().',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-91', name: 'XML Injection', holds: findings.length === 0, findings };
}

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_006_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Delimiter Neutralization (12)
  'CWE-140': verifyCWE140,
  'CWE-141': verifyCWE141,
  'CWE-142': verifyCWE142,
  'CWE-143': verifyCWE143,
  'CWE-144': verifyCWE144,
  'CWE-145': verifyCWE145,
  'CWE-147': verifyCWE147,
  'CWE-149': verifyCWE149,
  'CWE-155': verifyCWE155,
  'CWE-156': verifyCWE156,
  'CWE-157': verifyCWE157,
  'CWE-164': verifyCWE164,
  // Input Handling (4)
  'CWE-165': verifyCWE165,
  'CWE-172': verifyCWE172,
  'CWE-177': verifyCWE177,
  'CWE-237': verifyCWE237,
  // Individual (4)
  'CWE-241': verifyCWE241,
  'CWE-337': verifyCWE337,
  'CWE-349': verifyCWE349,
  'CWE-91': verifyCWE91,
};
