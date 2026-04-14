/**
 * Encoding & Validation CWE Verifiers
 *
 * Output encoding, format strings, null termination, case sensitivity,
 * incomplete filtering, regex validation, double encoding.
 *
 * Extracted from verifier/index.ts - Phase 7 of the monolith split.
 */

import type { NeuralMap } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments } from './source-analysis.ts';
import { nodeRef, nodesOfType, hasTaintedPathWithoutControl, sharesFunctionScope } from './graph-helpers.ts';
import { getContainingScopeSnapshots, sinkHasTaintedDataIn, scopeBasedTaintReaches } from '../generated/_helpers.js';


/**
 * CWE-116: Improper Encoding or Escaping of Output
 * Pattern: INGRESS → EGRESS/EXTERNAL(structured output context) without TRANSFORM(encoding)
 * Property: Data is context-appropriately encoded before being embedded in structured output.
 *
 * Unlike CWE-79 (XSS-specific) or CWE-89 (SQL-specific), CWE-116 is the PARENT for
 * ALL output encoding failures. Catches data flowing to ANY structured output context
 * without context-appropriate encoding — including CSV, email headers, LDAP, log formats.
 */
function verifyCWE116(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const STRUCTURED_OUTPUT116 = /\b(render|template|write|send|respond|output|format|serialize|stringify|toJSON|toXML|toCSV|setHeader|header\(|fprintf|sprintf|printf|writeln|print|echo|emit|publish|dispatch)\b/i;

  const structuredSinks = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('html') || n.node_subtype.includes('response') ||
     n.node_subtype.includes('header') || n.node_subtype.includes('log') ||
     n.node_subtype.includes('xml') || n.node_subtype.includes('json') ||
     n.node_subtype.includes('csv') || n.node_subtype.includes('sql') ||
     n.node_subtype.includes('shell') || n.node_subtype.includes('template') ||
     n.node_subtype.includes('render') || n.node_subtype.includes('email') ||
     n.attack_surface.includes('output') || n.attack_surface.includes('html_output') ||
     n.attack_surface.includes('structured_output') ||
     STRUCTURED_OUTPUT116.test(n.analysis_snapshot || n.code_snapshot))
  );

  const ENCODING_SAFE116 = /\b(escape|encode|encodeURI|encodeURIComponent|htmlEncode|escapeHtml|he\.encode|sanitize|DOMPurify|textContent|parameteriz|prepared|placeholder|createTextNode|cgi\.escape|html\.escape|markupsafe|bleach|xss\(|validator\.escape|encodeForHTML|encodeForJS|encodeForCSS|encodeForURL|ESAPI|owasp|Content-Type.*charset|json_encode|JSON\.stringify|csv\.writer|writerow)\b/i;

  for (const src of ingress) {
    for (const sink of structuredSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!ENCODING_SAFE116.test(sinkCode)) {
          let context116 = 'structured output';
          if (sink.node_subtype.includes('html') || /innerHTML|render/i.test(sinkCode)) context116 = 'HTML';
          else if (sink.node_subtype.includes('sql')) context116 = 'SQL';
          else if (sink.node_subtype.includes('shell')) context116 = 'shell command';
          else if (sink.node_subtype.includes('header') || /setHeader|header\(/i.test(sinkCode)) context116 = 'HTTP header';
          else if (sink.node_subtype.includes('xml') || /toXML/i.test(sinkCode)) context116 = 'XML';
          else if (sink.node_subtype.includes('json') || /toJSON|stringify/i.test(sinkCode)) context116 = 'JSON';
          else if (sink.node_subtype.includes('log') || /log\.|logger/i.test(sinkCode)) context116 = 'log output';

          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: `TRANSFORM (context-appropriate output encoding for ${context116})`,
            severity: 'high',
            description: `User input from ${src.label} is embedded in ${context116} at ${sink.label} without encoding. ` +
              `The output context has special characters that must be escaped to prevent injection.`,
            fix: `Apply context-appropriate encoding before output. HTML: escapeHtml()/textContent. ` +
              `SQL: parameterized queries. Shell: avoid string concat, use execFile(). ` +
              `Headers: reject newlines. JSON: JSON.stringify(). XML: XML encoding. ` +
              `CSV: csv.writer with proper quoting. Use OWASP ESAPI encoders for multi-context output.`,
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-116', name: 'Improper Encoding or Escaping of Output', holds: findings.length === 0, findings };
}

/**
 * CWE-134: Use of Externally-Controlled Format String
 * Pattern: INGRESS → TRANSFORM/EXTERNAL(format function) where user input IS the format string
 * Property: Format strings are always static literals; user input is only passed as arguments.
 *
 * Critical in C/C++ (printf family), but also relevant in Python (str.format),
 * Ruby (%), Java (String.format), and JS (template literals from user input).
 */
function verifyCWE134(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const FORMAT_FUNC134 = /\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|syslog|format|String\.format|str\.format|\.format\s*\(|Template\(|template\.render|render_template_string|Formatter\(\)|FormatMessage|NSLog|os_log)\b/;

  const formatSinks = map.nodes.filter(n => {
    // Console/log output uses template literals, not printf — exclude
    if (n.node_subtype === 'display' || n.node_subtype === 'log_write') return false;

    return (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' ||
     n.node_type === 'EGRESS' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('format') || n.node_subtype.includes('printf') ||
     FORMAT_FUNC134.test(n.analysis_snapshot || n.code_snapshot));
  });

  const FORMAT_SAFE134 = /\b(static.*format|const.*format|literal|hardcoded|fixed.*format|format.*constant)\b/i;

  for (const src of ingress) {
    for (const sink of formatSinks) {
      if (src.id === sink.id) continue;

      // Primary: BFS taint path
      const bfs134 = hasTaintedPathWithoutControl(map, src.id, sink.id);

      // Fallback 1: sink has tainted data_in
      const sinkTainted134 = !bfs134 && sinkHasTaintedDataIn(map, sink.id);

      // Fallback 2: scope-based — tainted TRANSFORM in same scope as sink
      const scope134 = !bfs134 && !sinkTainted134 && scopeBasedTaintReaches(map, src.id, sink.id);

      const vulnerable134 = bfs134 || sinkTainted134 || scope134;

      if (vulnerable134) {
        const scopeSnaps134 = getContainingScopeSnapshots(map, sink.id);
        const sinkCode = stripComments(scopeSnaps134.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const directFormatUse = /\b(printf|sprintf|fprintf|snprintf|syslog|String\.format|str\.format|\.format)\s*\(\s*[a-zA-Z_]/.test(sinkCode) ||
          /\b(printf|sprintf|fprintf)\s*\(\s*[^"'`]/.test(sinkCode) ||
          /render_template_string\s*\(/.test(sinkCode) ||
          /System\.out\.format\s*\(/.test(sinkCode);

        if (directFormatUse && !FORMAT_SAFE134.test(sinkCode)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (static format string enforcement — user input must not be the format specifier)',
            severity: 'critical',
            description: `User input from ${src.label} may be used as a format string at ${sink.label}. ` +
              `In C/C++, %x reads stack memory and %n writes to arbitrary addresses. ` +
              `In Python, .format() can access object attributes. In Java, format strings can cause DoS.`,
            fix: 'NEVER use user input as a format string. Always use static/hardcoded format strings. ' +
              'Pass user input only as format arguments: printf("%s", userInput) not printf(userInput). ' +
              'In Python, avoid str.format(userInput) — use f-strings with sanitized values or %-formatting with %s.',
            via: bfs134 ? 'bfs' : sinkTainted134 ? 'sink_tainted' : 'scope_taint',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-134', name: 'Use of Externally-Controlled Format String', holds: findings.length === 0, findings };
}

/**
 * CWE-170: Improper Null Termination
 * Pattern: TRANSFORM/STORAGE(string/buffer copy) where null terminator may be missing
 * Property: All string operations properly null-terminate output buffers.
 *
 * Primarily C/C++: strncpy doesn't guarantee null termination, snprintf truncates
 * without warning, manual buffer copies may skip the terminator.
 */
function verifyCWE170(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const NULL_TERM_RISK170 = /\b(strncpy|memcpy|memmove|recv|read|fread|fgets|snprintf|strncat|MultiByteToWideChar|WideCharToMultiByte|bcopy|recvfrom|strncpy_s)\b/;

  const bufferOps = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('buffer') || n.node_subtype.includes('string') ||
     n.node_subtype.includes('memory') || n.node_subtype.includes('copy') ||
     NULL_TERM_RISK170.test(n.analysis_snapshot || n.code_snapshot))
  );

  const NULL_SAFE170 = /\[\s*\w+\s*(-\s*1)?\s*\]\s*=\s*['"]?\\?0['"]?|\bnull.?terminat|\bstrlcpy\b|\bstrcpy_s\b|\bStringCch|\bSecureZeroMemory|\bmemset\s*\([^,]+,\s*0|\bbuf\s*\[\s*len\s*\]\s*=\s*0|\bbuf\s*\[\s*sizeof|\bnul\b/i;

  for (const src of ingress) {
    for (const sink of bufferOps) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (NULL_TERM_RISK170.test(sinkCode) && !NULL_SAFE170.test(sinkCode)) {
          const dangerousFunc170 = sinkCode.match(NULL_TERM_RISK170)?.[0] || 'buffer operation';
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (explicit null termination after buffer copy)',
            severity: 'high',
            description: `User input from ${src.label} is copied at ${sink.label} using ${dangerousFunc170}, ` +
              `which may not null-terminate the destination buffer. ` +
              `Reading the unterminated string can leak adjacent memory or cause a crash.`,
            fix: `Always explicitly null-terminate after ${dangerousFunc170}: buf[len-1] = '\\0'. ` +
              `Prefer strlcpy() or strcpy_s() which guarantee null termination. ` +
              `For strncpy: always set dest[sizeof(dest)-1] = 0 after the call. ` +
              `For binary reads (recv, fread): track length separately, don't treat as C strings.`,
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-170', name: 'Improper Null Termination', holds: findings.length === 0, findings };
}

/**
 * CWE-176: Improper Handling of Unicode Encoding
 * Pattern: INGRESS → CONTROL/STORAGE where Unicode normalization is missing
 * Property: Unicode input is normalized (NFC/NFKC) before security checks.
 *
 * Detects: homograph attacks (Cyrillic a vs Latin a), overlong UTF-8,
 * right-to-left override (U+202E), zero-width characters, normalization mismatches.
 */
function verifyCWE176(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const unicodeSinks176 = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'STORAGE' ||
     n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('validation') || n.node_subtype.includes('compare') ||
     n.node_subtype.includes('file') || n.node_subtype.includes('display') ||
     n.node_subtype.includes('auth') || n.node_subtype.includes('search') ||
     n.node_subtype.includes('path') || n.node_subtype.includes('url') ||
     n.node_subtype.includes('username') || n.node_subtype.includes('domain') ||
     n.attack_surface.includes('identity') || n.attack_surface.includes('file_access') ||
     /\b(compare|equals|match|indexOf|includes|startsWith|endsWith|lookup|find|search|\.test\(|toLowerCase|toUpperCase|username|domain|host|path|filename)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  const UNICODE_SAFE176 = /\b(normalize\s*\(\s*['"]NF[KCD]{0,2}['"]\s*\)|\.normalize\(|unicodedata\.normalize|Normalizer\.normalize|NFC|NFKC|NFKD|NFD|ICU|icu4j|unorm|unicode.*normal|punycode|toASCII|idn|homoglyph|confusable|\.isASCII|ascii.*only|reject.*non.?ascii)\b/i;

  for (const src of ingress) {
    for (const sink of unicodeSinks176) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
        if (!UNICODE_SAFE176.test(sinkCode) && !UNICODE_SAFE176.test(srcCode)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (Unicode normalization — NFC/NFKC before security checks)',
            severity: 'high',
            description: `User input from ${src.label} reaches ${sink.label} without Unicode normalization. ` +
              `Homograph attacks, overlong UTF-8, right-to-left override (U+202E), ` +
              `and zero-width characters can bypass security checks on unnormalized input.`,
            fix: 'Normalize all user input to NFC or NFKC before validation, comparison, or storage. ' +
              'JS: str.normalize("NFC"). Python: unicodedata.normalize("NFKC", s). ' +
              'Java: Normalizer.normalize(s, Form.NFKC). ' +
              'For usernames/domains, consider restricting to ASCII or using IDNA/Punycode.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-176', name: 'Improper Handling of Unicode Encoding', holds: findings.length === 0, findings };
}

/**
 * CWE-177: Improper Handling of URL Encoding (Hex Encoding)
 * Pattern: INGRESS → CONTROL(security check) where URL-encoded input isn't decoded first
 * Property: URL-encoded input is fully decoded before security checks are applied.
 *
 * Double encoding (%2527 -> %27 -> ') and hex encoding (%3C -> <) bypass
 * security filters that check the raw encoded form instead of the decoded form.
 */
function verifyCWE177(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const securityChecks177 = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('validation') || n.node_subtype.includes('filter') ||
     n.node_subtype.includes('sanitize') || n.node_subtype.includes('check') ||
     n.node_subtype.includes('blacklist') || n.node_subtype.includes('blocklist') ||
     /\b(match|test|indexOf|includes|search|replace|filter|block|deny|reject|startsWith|endsWith|contains)\b/i.test(n.analysis_snapshot || n.code_snapshot) ||
     /[/].*[<>"'\\].*[/]/.test(n.analysis_snapshot || n.code_snapshot))
  );

  const dataSinks177 = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL'
  );

  const URL_DECODE_SAFE177 = /\b(decodeURI|decodeURIComponent|URLDecoder\.decode|urllib\.parse\.unquote|urllib\.unquote|url\.unescape|CGI\.unescape|unescape|urldecode|percent_decode|rawurldecode|url_decode|HttpUtility\.UrlDecode|WebUtility\.UrlDecode)\b/i;

  for (const src of ingress) {
    for (const check of securityChecks177) {
      if (src.id === check.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, check.id)) {
        const checkCode = stripComments(check.analysis_snapshot || check.code_snapshot);
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);

        const hasPatternCheck177 = /[/].*[<>"'\\./].*[/]|\b(match|test|indexOf|includes|search|startsWith|endsWith)\b.*['"][<>"'\\./]/.test(checkCode);

        if (hasPatternCheck177 && !URL_DECODE_SAFE177.test(checkCode) && !URL_DECODE_SAFE177.test(srcCode)) {
          for (const sink of dataSinks177) {
            if (hasTaintedPathWithoutControl(map, check.id, sink.id)) {
              findings.push({
                source: nodeRef(src),
                sink: nodeRef(sink),
                missing: 'TRANSFORM (URL decoding BEFORE security checks)',
                severity: 'high',
                description: `User input from ${src.label} undergoes pattern-matching at ${check.label} without prior URL decoding. ` +
                  `Encoded input like %3Cscript%3E or double-encoded %253Cscript%253E bypasses the check ` +
                  `and is decoded later by the framework, reaching ${sink.label} as dangerous content.`,
                fix: 'Fully decode URL-encoded input BEFORE applying security checks: ' +
                  'decodeURIComponent() in JS, urllib.parse.unquote() in Python, ' +
                  'URLDecoder.decode() in Java. Decode iteratively until no changes ' +
                  'to defeat double/triple encoding. Then validate the decoded form.',
                via: 'bfs',
              });
              break;
            }
          }
        }
      }
    }
  }

  return { cwe: 'CWE-177', name: 'Improper Handling of URL Encoding (Hex Encoding)', holds: findings.length === 0, findings };
}

/**
 * CWE-178: Improper Handling of Case Sensitivity
 * Pattern: CONTROL(comparison/lookup) without case normalization
 * Property: Security-relevant string comparisons normalize case before matching.
 *
 * Affects: filename extension checks (.PHP vs .php), username comparison,
 * URL path matching (/Admin vs /admin), MIME type checks, HTTP headers.
 */
function verifyCWE178(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const CASE_SENSITIVE_CHECK178 = /\b(===?\s*['"][A-Za-z]|\.endsWith\s*\(\s*['"]\.(?:php|asp|jsp|exe|bat|cmd|sh|py|rb|pl|cgi|aspx|PHP|ASP)|\.includes\s*\(\s*['"][A-Za-z]|indexOf\s*\(\s*['"][A-Za-z]|strcmp\s*\(|equals\s*\(|match\s*\(\s*\/[^/]*[A-Z]|switch\s*\(.*\)\s*\{[^}]*case\s+['"][A-Za-z]|==\s+['"][A-Za-z])\b/;

  const comparisonNodes178 = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('check') || n.node_subtype.includes('validation') ||
     n.node_subtype.includes('comparison') || n.node_subtype.includes('lookup') ||
     n.node_subtype.includes('filter') || n.node_subtype.includes('extension') ||
     n.node_subtype.includes('auth') || n.node_subtype.includes('route') ||
     n.node_subtype.includes('path') || n.node_subtype.includes('mime') ||
     CASE_SENSITIVE_CHECK178.test(n.analysis_snapshot || n.code_snapshot))
  );

  const CASE_SAFE178 = /\b(toLowerCase|toUpperCase|toLower|toUpper|casefold|lower\(\)|upper\(\)|strings\.EqualFold|strings\.ToLower|strings\.ToUpper|ILIKE|case.?insensitive|\/[^\/]+\/i\b|equalsIgnoreCase|CompareOrdinalIgnoreCase|strcasecmp|stricmp|_wcsicmp|localeCompare)\b/i;

  for (const src of ingress) {
    for (const sink of comparisonNodes178) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (CASE_SENSITIVE_CHECK178.test(sinkCode) && !CASE_SAFE178.test(sinkCode)) {
          let context178 = 'security comparison';
          if (/\.endsWith.*\.\w{2,4}|extension|mime/i.test(sinkCode)) context178 = 'file extension/MIME check';
          else if (/user|login|name/i.test(sinkCode)) context178 = 'username comparison';
          else if (/path|route|url/i.test(sinkCode)) context178 = 'URL/path comparison';
          else if (/role|admin|permission/i.test(sinkCode)) context178 = 'authorization check';

          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (case normalization before security comparison)',
            severity: 'medium',
            description: `User input from ${src.label} undergoes case-sensitive ${context178} at ${sink.label}. ` +
              `An attacker can bypass via alternate casing ` +
              `(e.g., ".PHP" bypasses ".php" check, "Admin" bypasses "admin" check).`,
            fix: 'Normalize case before security comparisons: toLowerCase()/toUpperCase() on both sides. ' +
              'For filenames on Windows: always normalize case. For usernames: case-fold at registration/login. ' +
              'For regex: use /i flag. Java: equalsIgnoreCase(). Go: strings.EqualFold(). ' +
              'SQL: use ILIKE or LOWER() on both sides.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-178', name: 'Improper Handling of Case Sensitivity', holds: findings.length === 0, findings };
}

/**
 * CWE-179: Incorrect Behavior Order: Early Validation
 * Pattern: CONTROL(validation) occurs before TRANSFORM(canonicalization) on the data path
 * Property: Validation is applied AFTER canonicalization (decode, normalize, resolve).
 *
 * If you validate first and canonicalize second, encoded input passes validation,
 * then gets decoded into a dangerous form.
 */
function verifyCWE179(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const CANON179 = /\b(decode|decodeURI|decodeURIComponent|unescape|URLDecoder|unquote|urldecode|rawurldecode|normalize|canonicalize|realpath|resolve|readlink|followSymlinks|path\.resolve|path\.normalize|fs\.realpath|unicode.*normal|\.normalize\(|NFC|NFKC|base64.*decode|atob|Buffer\.from|fromBase64)\b/i;

  const canonTransforms179 = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('decode') || n.node_subtype.includes('normalize') ||
     n.node_subtype.includes('canonicalize') || n.node_subtype.includes('resolve') ||
     CANON179.test(n.analysis_snapshot || n.code_snapshot))
  );

  const VALIDATION179 = /\b(validate|check|verify|match|test|includes|indexOf|startsWith|endsWith|filter|block|deny|reject|allowlist|whitelist|blacklist|blocklist|regex|sanitize|assert)\b/i;

  const validationControls179 = map.nodes.filter(n =>
    n.node_type === 'CONTROL' &&
    (n.node_subtype.includes('validation') || n.node_subtype.includes('check') ||
     n.node_subtype.includes('filter') || n.node_subtype.includes('sanitize') ||
     VALIDATION179.test(n.analysis_snapshot || n.code_snapshot))
  );

  const sinks179 = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL'
  );

  for (const src of ingress) {
    for (const canon of canonTransforms179) {
      for (const validator of validationControls179) {
        // Dangerous order: src -> validator -> canon (validation before canonicalization)
        if (validator.line_start < canon.line_start) {
          for (const sink of sinks179) {
            if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
              const srcToValidator = hasTaintedPathWithoutControl(map, src.id, validator.id);
              const validatorToCanon = hasTaintedPathWithoutControl(map, validator.id, canon.id);

              if (srcToValidator && validatorToCanon) {
                const canonCode = stripComments(canon.analysis_snapshot || canon.code_snapshot);
                const canonFunc = canonCode.match(CANON179)?.[0] || 'canonicalization';

                findings.push({
                  source: nodeRef(src),
                  sink: nodeRef(sink),
                  missing: 'CONTROL (validation AFTER canonicalization — current order is reversed)',
                  severity: 'high',
                  description: `Validation at ${validator.label} (line ${validator.line_start}) occurs BEFORE ` +
                    `canonicalization at ${canon.label} (line ${canon.line_start}, ${canonFunc}). ` +
                    `Encoded input passes the validator, then gets decoded into a dangerous form.`,
                  fix: 'Reverse the order: canonicalize first (decode, normalize, resolve), then validate. ' +
                    'Apply ALL transformations (URL decoding, Unicode normalization, path resolution) ' +
                    'BEFORE running security checks. Validate the canonical form, not the raw input.',
                  via: 'bfs',
                });
                break;
              }
            }
          }
        }
      }
    }
  }

  // Fallback: canonicalization exists but validation order is suspect
  if (findings.length === 0 && canonTransforms179.length > 0) {
    for (const src of ingress) {
      for (const sink of sinks179) {
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          const canonAfterValidation = canonTransforms179.some(ct =>
            validationControls179.some(vc => vc.line_start < ct.line_start)
          );
          if (canonAfterValidation) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (validation AFTER canonicalization — current order may be reversed)',
              severity: 'high',
              description: `User input from ${src.label} reaches ${sink.label} on a path where ` +
                `validation may occur before canonicalization. Encoded input can bypass checks.`,
              fix: 'Always canonicalize input (decode, normalize, resolve) BEFORE applying validation. ' +
                'Validate on the canonical form, not the raw input.',
              via: 'bfs',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-179', name: 'Incorrect Behavior Order: Early Validation', holds: findings.length === 0, findings };
}

/**
 * CWE-180: Incorrect Behavior Order: Validate Before Canonicalize
 * Pattern: Same as CWE-179, but specifically about file path canonicalization.
 * Property: File paths are resolved to canonical form before access control checks.
 *
 * Classic: validate path doesn't contain "..", then resolve symlinks —
 * but a symlink at /safe/link -> /etc/passwd bypasses the ".." check.
 */
function verifyCWE180(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const PATH_CANON180 = /\b(realpath|path\.resolve|path\.normalize|fs\.realpath|readlink|followSymlinks|canonicalize|canonical|Path\.toRealPath|Paths\.get\(.*\.normalize|File\.getCanonicalPath|os\.path\.realpath|os\.path\.abspath|os\.path\.normpath|filepath\.Clean|filepath\.EvalSymlinks)\b/i;

  const pathCanonTransforms180 = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('path') || n.node_subtype.includes('file') ||
     n.node_subtype.includes('resolve') || n.node_subtype.includes('canonical') ||
     PATH_CANON180.test(n.analysis_snapshot || n.code_snapshot))
  );

  const PATH_VALIDATION180 = /\b(startsWith|includes\s*\(\s*['"]\.\.['"]|indexOf\s*\(\s*['"]\.\.['"]|match.*\.\.|test.*\.\.|\.\.\/|\.\.\\|path.*check|validate.*path|allowed.*dir|base.*dir|root.*dir|chroot|jail)\b/i;

  const pathValidators180 = map.nodes.filter(n =>
    n.node_type === 'CONTROL' &&
    (n.node_subtype.includes('path') || n.node_subtype.includes('traversal') ||
     n.node_subtype.includes('directory') || n.node_subtype.includes('file') ||
     PATH_VALIDATION180.test(n.analysis_snapshot || n.code_snapshot))
  );

  const fileOps180 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'INGRESS') &&
    (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
     n.attack_surface.includes('file_access') ||
     /\b(readFile|writeFile|open|unlink|readdir|createReadStream|fopen|fwrite|fread|os\.open|os\.remove|shutil)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const validator of pathValidators180) {
      for (const canon of pathCanonTransforms180) {
        if (validator.line_start < canon.line_start) {
          for (const sink of fileOps180) {
            const srcToValidator = hasTaintedPathWithoutControl(map, src.id, validator.id);
            if (!srcToValidator) continue;

            const canonReachable = hasTaintedPathWithoutControl(map, validator.id, canon.id) ||
              hasTaintedPathWithoutControl(map, src.id, canon.id);
            if (!canonReachable) continue;

            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (path validation AFTER canonicalization — resolve paths before checking)',
              severity: 'high',
              description: `Path validation at ${validator.label} (line ${validator.line_start}) occurs BEFORE ` +
                `path canonicalization at ${canon.label} (line ${canon.line_start}). ` +
                `Symlinks, "." segments, or encoded path components bypass the validation ` +
                `and resolve to unauthorized files after canonicalization.`,
              fix: 'Canonicalize paths FIRST (realpath, path.resolve), THEN validate. ' +
                'Use realpath() to resolve symlinks, then check that the canonical path ' +
                'starts with the allowed base directory. Java: getCanonicalPath() before startsWith(). ' +
                'Go: filepath.EvalSymlinks() then filepath.Clean() before checking prefix.',
              via: 'bfs',
            });
            break;
          }
        }
      }
    }
  }

  // Fallback
  if (findings.length === 0 && pathCanonTransforms180.length > 0 && pathValidators180.length > 0) {
    for (const src of ingress) {
      for (const sink of fileOps180) {
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          const validatorBeforeCanon = pathValidators180.some(v =>
            pathCanonTransforms180.some(c => v.line_start < c.line_start)
          );
          if (validatorBeforeCanon) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (path validation AFTER canonicalization)',
              severity: 'high',
              description: `User input from ${src.label} reaches file operation at ${sink.label}. ` +
                `Path validation appears to occur before path canonicalization — symlinks and encoded ` +
                `segments can bypass the validation.`,
              fix: 'Always resolve path to canonical form (realpath/resolve) before validation. ' +
                'Then verify the resolved path is within allowed directories.',
              via: 'bfs',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-180', name: 'Incorrect Behavior Order: Validate Before Canonicalize', holds: findings.length === 0, findings };
}

/**
 * CWE-182: Collapse of Data into Unsafe Value
 * Pattern: INGRESS → TRANSFORM(character-removal filter) → EGRESS without re-validation
 * Property: After removing characters, the result is re-validated to ensure removal
 *   didn't create a new dangerous value.
 *
 * Classic: "<scr<script>ipt>" -> strip "<script>" -> "<script>" (XSS)
 */
function verifyCWE182(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const removalFilters182 = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    ((n.analysis_snapshot || n.code_snapshot).match(/\.replace\s*\([^,]+,\s*['"]\s*['"]\s*\)/i) !== null ||
    (n.analysis_snapshot || n.code_snapshot).match(/\b(strip|stripTags|removeTags|removeScripts|blacklist|filter|preg_replace|re\.sub|gsub|tr\/.*\/\/d|delete|reject)\s*\(/i) !== null ||
    n.node_subtype.includes('filter') || n.node_subtype.includes('strip') ||
    n.node_subtype.includes('remove') || n.node_subtype.includes('blacklist'))
  );

  const outputSinks182 = map.nodes.filter(n =>
    n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE'
  );

  for (const src of ingress) {
    for (const filter of removalFilters182) {
      if (!hasTaintedPathWithoutControl(map, src.id, filter.id)) continue;

      for (const sink of outputSinks182) {
        if (!hasTaintedPathWithoutControl(map, filter.id, sink.id)) continue;

        const filterCode = stripComments(filter.analysis_snapshot || filter.code_snapshot);
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);

        const usesEncoding = /\b(encode|escape|encodeURI|encodeURIComponent|htmlEncode|escapeHtml|he\.encode|cgi\.escape|html\.escape)\s*\(/i.test(filterCode);
        const recursiveFilter = /\bwhile\b.*\breplace\b|\bdo\b.*\breplace\b|\bloop\b.*\bsanitize\s*\(|\brecursive\b|\biterative\b|\brepeat\b/i.test(filterCode);
        const postFilterValidation = /\bvalidate\s*\(|\bcheck\s*\(|\bassert\s*\(|\bverif\w*\s*\(/i.test(sinkCode);
        const allowlistFilter = /\ballowlist\b|\bwhitelist\b|\b\/\[\^a-z/i.test(filterCode) ||
          /\.match\s*\(\s*\/\[a-z/i.test(filterCode);
        const libraryClean = /\bDOMPurify\b|\bsanitize-html\b|\bbleach\b|\bclean\(/i.test(filterCode);

        if (!(usesEncoding || recursiveFilter || postFilterValidation || allowlistFilter || libraryClean)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (post-collapse re-validation — verify filtered output is safe after character removal)',
            severity: 'high',
            description: `User input from ${src.label} passes through character-removal filter at ${filter.label} ` +
              `then reaches ${sink.label} without re-validation. ` +
              `Removing characters can cause the string to collapse into a dangerous value ` +
              `(e.g., "<scr<script>ipt>" after strip becomes "<script>").`,
            fix: 'Prefer encoding over removal: use escapeHtml() instead of stripTags(). ' +
              'If removal is necessary, apply recursively until no changes: ' +
              'while (input !== sanitize(input)) input = sanitize(input). ' +
              'Or use allowlist approach: keep only known-good characters. ' +
              'Libraries like DOMPurify handle recursive sanitization correctly.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-182', name: 'Collapse of Data into Unsafe Value', holds: findings.length === 0, findings };
}

/**
 * CWE-183: Permissive List of Allowed Inputs
 * Pattern: CONTROL(allowlist) that is too broad — wildcards, wide regex,
 *   or overly permissive patterns allowing dangerous values through.
 * Property: Allowlists use strict, specific exact-match patterns.
 *
 * Detects: wildcard allowlists, overly broad regex, type-only checks,
 *   MIME type wildcards, directory traversal gaps.
 */
function verifyCWE183(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const allowlistNodes183 = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('allowlist') || n.node_subtype.includes('whitelist') ||
     n.node_subtype.includes('filter') || n.node_subtype.includes('validation') ||
     /\b(allowlist|whitelist|allowed|permit|accept|approved)\b/i.test(n.analysis_snapshot || n.code_snapshot) ||
     /\b(includes\(|indexOf\(|has\(|in\s+\[|Set\(|Array\.\w+)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  const PERMISSIVE183 = /\*\.\w|\.\*|\/\.\+\/|\/\.\*\/|\[\^?\w\]\+|typeof\s+\w+\s*===?\s*'string'|\bany\b|\ball\b|text\/\*|image\/\*|application\/\*|\*\/\*|\.endsWith\s*\(\s*['"]\.(?:com|org|net|io)['"]|\/\.\{1,\}\/|\.+|\w+\|\w+\|\w+\|\w+\|\w+/i;

  const STRICT_SAFE183 = /\b(===\s*['"][^'"]+['"]|Set\(\s*\[['"][^'"]+['"]\s*(?:,\s*['"][^'"]+['"]\s*)*\]|enum|switch\s*\(\s*\w+\s*\)\s*\{(?:\s*case\s+['"]|\.has\s*\(\s*\w+\s*\)))/i;

  for (const src of ingress) {
    for (const allowlist of allowlistNodes183) {
      if (src.id === allowlist.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, allowlist.id)) {
        const code = stripComments(allowlist.analysis_snapshot || allowlist.code_snapshot);
        if (PERMISSIVE183.test(code) && !STRICT_SAFE183.test(code)) {
          let listType183 = 'input allowlist';
          if (/domain|host|origin|cors|url/i.test(code)) listType183 = 'domain/origin allowlist';
          else if (/mime|content.?type/i.test(code)) listType183 = 'MIME type allowlist';
          else if (/extension|\.php|\.exe|\.js/i.test(code)) listType183 = 'file extension allowlist';
          else if (/ip|addr|cidr|subnet/i.test(code)) listType183 = 'IP address allowlist';
          else if (/redirect|return.*url/i.test(code)) listType183 = 'redirect URL allowlist';

          findings.push({
            source: nodeRef(src),
            sink: nodeRef(allowlist),
            missing: 'CONTROL (strict allowlist — use exact matches, not wildcards or broad patterns)',
            severity: 'high',
            description: `The ${listType183} at ${allowlist.label} uses overly permissive patterns. ` +
              `Wildcards, broad regex, or type-only checks allow dangerous values through. ` +
              `For example, *.example.com also matches evil.com if the check uses endsWith().`,
            fix: 'Use strict exact-match allowlists: Set(["value1", "value2"]) or switch/case. ' +
              'For domains: compare against a fixed Set, don\'t use endsWith(). ' +
              'For MIME types: enumerate specific types, no wildcards (*/*, image/*). ' +
              'For file extensions: strict Set after case normalization. ' +
              'For regex: anchored patterns (^...$) with specific character classes.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-183', name: 'Permissive List of Allowed Inputs', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-185: Incorrect Regular Expression
//
// A regex is syntactically valid but semantically wrong — it doesn't match
// what the developer intended. Common: unescaped metacharacters (. instead
// of \.), missing anchors, wrong quantifiers, overly broad character classes.
// ---------------------------------------------------------------------------

function verifyCWE185(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const REGEX_USE = /\b(\.test\(|\.match\(|\.search\(|\.replace\(|re\.match|re\.search|re\.sub|re\.compile|Pattern\.compile|Regex\(|preg_match|preg_replace|=~|!~|RegExp\()\b/i;
  // Patterns that indicate a semantically incorrect regex:
  // 1. Unescaped dot in domain/IP/version literals
  const UNESCAPED_DOT_LITERAL = /\/[^/]*\d+\.\d+[^/]*\//; // e.g., /192.168.1.1/ — dots match any char
  // 2. Character class mistakes: [A-z] includes [\]^_` between Z and a
  const BAD_CHAR_CLASS = /\[A-z\]|\[a-Z\]/;
  // 3. Unescaped hyphen in middle of character class (not first/last): [a-b-c]
  const BAD_HYPHEN = /\[[^\]]*\w-\w-\w[^\]]*\]/;
  // 4. Empty alternation: (|something) or (something|)
  const EMPTY_ALT = /\(\||\|\)/;
  // 5. Backslash before non-metachar in a way that's likely a mistake
  const WRONG_ESCAPE = /\\[aAbBcCdDfFrRsSwWvVnNtT].*\\[0-9]{4,}/; // confusing \digit with backreference

  const SAFE_PATTERN = /\bnew RegExp\(\s*\w+\.replace\(|escape[Rr]eg[Ee]x|escapeStringRegexp|lodash.*escape|quotemeta|re\.escape|Pattern\.quote|Regex\.Escape/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'CONTROL' && node.node_type !== 'TRANSFORM') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!REGEX_USE.test(code)) continue;
    if (SAFE_PATTERN.test(code)) continue;

    const regexMatches = code.matchAll(/\/([^/]{3,})\/[gimsuy]*/g);
    for (const rm of regexMatches) {
      const pattern = rm[1];

      if (BAD_CHAR_CLASS.test(pattern)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (fix character class range: [A-z] includes non-alpha chars)',
          severity: 'medium',
          description: `${node.label} uses [A-z] in regex /${pattern}/. ASCII range A(65)-z(122) includes ` +
            `six non-alpha characters: [\\]^_\`. Use [A-Za-z] instead.`,
          fix: 'Replace [A-z] with [A-Za-z] or use the /i flag with [a-z].',
          via: 'structural',
        });
        continue;
      }

      if (EMPTY_ALT.test(pattern)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (remove empty alternation branch in regex)',
          severity: 'medium',
          description: `${node.label} has empty alternation in regex /${pattern}/. An empty branch matches ` +
            `the empty string, making the entire group effectively optional — probably not intended.`,
          fix: 'Remove the empty alternation branch: (|foo) should be (foo)? if optional was intended.',
          via: 'structural',
        });
        continue;
      }
    }

    // Check for unescaped dots in IP/domain patterns
    const ipLikeRegex = code.match(/\/(\d+\.\d+\.\d+\.\d+)\/|\/([^/]*\d+\.\d+[^/]*)\/[gimsuy]*/);
    if (ipLikeRegex) {
      const pat = ipLikeRegex[1] || ipLikeRegex[2] || '';
      if (pat && !pat.includes('\\.')) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (escape dots in IP/domain regex literal)',
          severity: 'medium',
          description: `${node.label} uses unescaped dots in a numeric regex pattern /${pat}/. ` +
            `The dot metacharacter matches ANY character, so "192.168.1.1" also matches "192X168Y1Z1".`,
          fix: 'Escape literal dots with \\. — e.g., /192\\.168\\.1\\.1/. Better yet, parse the IP ' +
            'with a library and compare programmatically.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-185', name: 'Incorrect Regular Expression', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-187: Partial String Comparison
//
// Comparing only part of a string (e.g., first N characters) for security
// decisions. Attacker can craft input that matches the prefix/suffix but
// contains malicious content in the unchecked portion.
// Classic: strncmp(input, "admin", 5) matches "admin; DROP TABLE users"
// ---------------------------------------------------------------------------

function verifyCWE187(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // C/C++ partial comparisons
  const STRNCMP_RE = /\bstrncmp\s*\(|strncasecmp\s*\(|_strnicmp\s*\(|_strncmp\s*\(|wcsncmp\s*\(|memcmp\s*\(/;
  // JavaScript partial comparisons
  const JS_PARTIAL = /\b(\.startsWith\(|\.endsWith\(|\.indexOf\(\s*['"`]|\.substring\(|\.substr\(|\.slice\().*(?:===?|!==?|if|&&|\|\|)/;
  // Python partial comparisons
  const PY_PARTIAL = /\b(\.startswith\(|\.endswith\(|\.find\().*(?:==|!=|if|and|or)/;
  // Java partial comparisons
  const JAVA_PARTIAL = /\b(\.startsWith\(|\.endsWith\(|\.regionMatches\().*(?:==|!=|if|&&|\|\|)/;

  // Security context — only flag when used in auth/security decisions
  const SECURITY_CONTEXT = /\b(auth|admin|role|permission|token|secret|api[_-]?key|password|credential|session|allow|deny|grant|access|privilege|type|content.?type|mime)/i;

  const SAFE_FULL_CMP = /\b(strcmp\s*\(|\.equals\(|===\s*['"`]|==\s*['"`]|\.localeCompare\(|Objects\.equals)\b/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'CONTROL' && node.node_type !== 'TRANSFORM') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!SECURITY_CONTEXT.test(code)) continue;
    if (SAFE_FULL_CMP.test(code)) continue;

    let partialType = '';
    if (STRNCMP_RE.test(code)) partialType = 'strncmp/memcmp (C/C++)';
    else if (JS_PARTIAL.test(code)) partialType = 'startsWith/indexOf/substring (JavaScript)';
    else if (PY_PARTIAL.test(code)) partialType = 'startswith/endswith/find (Python)';
    else if (JAVA_PARTIAL.test(code)) partialType = 'startsWith/endsWith/regionMatches (Java)';

    if (partialType) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use full string comparison for security decisions, not partial match)',
        severity: 'high',
        description: `${node.label} uses partial string comparison (${partialType}) in a security context. ` +
          `An attacker can craft input that matches the checked prefix/suffix but contains malicious ` +
          `content in the unchecked portion. E.g., startsWith("admin") matches "admin; DROP TABLE".`,
        fix: 'Use full-string comparison: strcmp (C), === (JS), == (Python), .equals() (Java). ' +
          'If partial match is intentional (e.g., URL prefix), validate the REMAINDER too.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-187', name: 'Partial String Comparison', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-838: Inappropriate Encoding for Output
//
// Pattern: Data is encoded using one scheme but the output context expects
// another (e.g., URL-encoding data that will be placed in HTML context,
// or HTML-encoding data going into a SQL query). The encoding is PRESENT
// but WRONG for the context — distinct from CWE-116 (missing encoding).
// ---------------------------------------------------------------------------

function verifyCWE838(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const ENCODING_CONTEXT_MAP: Array<{
    encoderRE: RegExp;
    encoderName: string;
    wrongContextRE: RegExp;
    wrongContext: string;
    severity: 'high' | 'medium';
  }> = [
    // URL-encoding used before HTML output
    { encoderRE: /\b(encodeURIComponent|encodeURI|urllib\.quote|url_encode|CGI\.escape|URLEncoder\.encode|Uri\.EscapeDataString|rawurlencode)\s*\(/i,
      encoderName: 'URL encoding',
      wrongContextRE: /\b(innerHTML|outerHTML|document\.write|\.html\s*\(|dangerouslySetInnerHTML|render_template|@Html\.Raw|<%-|v-html|ng-bind-html)\b/i,
      wrongContext: 'HTML output',
      severity: 'high' },
    // HTML-encoding used before SQL
    { encoderRE: /\b(htmlspecialchars|htmlentities|escapeHtml|sanitizeHtml|DOMPurify\.sanitize|Encoder\.htmlEncode|StringEscapeUtils\.escapeHtml|CGI\.escapeHTML|ERB::Util\.html_escape)\b/i,
      encoderName: 'HTML encoding',
      wrongContextRE: /\b(query|execute|exec|prepare|rawQuery|raw_query|cursor\.execute|Statement\.|PreparedStatement|SqlCommand|db\.\w+\.\w*(?:find|insert|update|delete|aggregate))\s*\(/i,
      wrongContext: 'SQL/database context',
      severity: 'high' },
    // HTML-encoding used before shell execution
    { encoderRE: /\b(htmlspecialchars|htmlentities|escapeHtml|sanitizeHtml|DOMPurify\.sanitize)\b/i,
      encoderName: 'HTML encoding',
      wrongContextRE: /\b(exec|spawn|system|popen|subprocess|child_process|Process\.Start|Runtime\.exec|ShellExecute)\s*\(/i,
      wrongContext: 'shell/command execution',
      severity: 'high' },
    // Base64 used as "sanitization" before output
    { encoderRE: /\b(btoa|atob|base64_encode|Base64\.encode|base64\.b64encode|Buffer\.from\([^)]+\)\.toString\s*\(\s*['"]base64)/i,
      encoderName: 'Base64 encoding (not a security encoding)',
      wrongContextRE: /\b(innerHTML|document\.write|exec|query|eval)\s*\(/i,
      wrongContext: 'security-sensitive context',
      severity: 'medium' },
    // URL-encoding used before SQL
    { encoderRE: /\b(encodeURIComponent|encodeURI|urllib\.quote|url_encode)\s*\(/i,
      encoderName: 'URL encoding',
      wrongContextRE: /\b(query|execute|exec|prepare|cursor\.execute)\s*\(/i,
      wrongContext: 'SQL/database context',
      severity: 'high' },
  ];

  // For each TRANSFORM node (encoding), check if any downstream sink expects a different context
  const transforms = map.nodes.filter(n => n.node_type === 'TRANSFORM');
  const sinks = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL'
  );

  for (const txNode of transforms) {
    const txCode = stripComments(txNode.analysis_snapshot || txNode.code_snapshot);
    for (const mismatch of ENCODING_CONTEXT_MAP) {
      if (mismatch.encoderRE.test(txCode)) {
        for (const sink of sinks) {
          const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
          if (mismatch.wrongContextRE.test(sinkCode)) {
            const hasPath = txNode.edges.some(e => e.target === sink.id) ||
              hasTaintedPathWithoutControl(map, txNode.id, sink.id);
            if (hasPath) {
              findings.push({
                source: nodeRef(txNode), sink: nodeRef(sink),
                missing: `TRANSFORM (context-appropriate encoding — ${mismatch.encoderName} used for ${mismatch.wrongContext})`,
                severity: mismatch.severity,
                description: `${txNode.label} applies ${mismatch.encoderName}, but the output reaches ` +
                  `${sink.label} which is a ${mismatch.wrongContext}. The encoding does not neutralize ` +
                  `characters dangerous in the output context.`,
                fix: `Use context-appropriate encoding: HTML context needs HTML encoding, SQL needs parameterized queries, ` +
                  `shell needs shell escaping. Each output context has its own dangerous characters.`,
                via: 'bfs',
              });
              break;
            }
          }
        }
      }
    }
  }

  // Scan all nodes for inline encoding mismatch in the same code block
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(encodeURIComponent|encodeURI|url_encode)\s*\(/.test(code) &&
        /\b(innerHTML|document\.write|\.html\s*\(|dangerouslySetInnerHTML)\b/.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (context-appropriate encoding — URL encoding used in HTML context within same block)',
        severity: 'high',
        description: `${node.label} URL-encodes data and then places it in an HTML context. ` +
          `URL encoding converts spaces to %20 but does NOT neutralize < > " & which are dangerous in HTML.`,
        fix: 'Use HTML encoding (escapeHtml, htmlspecialchars, textContent) for HTML contexts.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-838', name: 'Inappropriate Encoding for Output', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const ENCODING_VALIDATION_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-116': verifyCWE116,
  'CWE-134': verifyCWE134,
  'CWE-170': verifyCWE170,
  'CWE-176': verifyCWE176,
  'CWE-177': verifyCWE177,
  'CWE-178': verifyCWE178,
  'CWE-179': verifyCWE179,
  'CWE-180': verifyCWE180,
  'CWE-182': verifyCWE182,
  'CWE-183': verifyCWE183,
  'CWE-185': verifyCWE185,
  'CWE-187': verifyCWE187,
  'CWE-838': verifyCWE838,
};
