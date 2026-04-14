/**
 * DST Generated Verifiers — Batch 005
 * Pattern shape: INGRESS→EGRESS without TRANSFORM
 * 22 CWEs: XSS variants, output injection, HTTP response issues,
 * cleartext cookies/GUI, response smuggling.
 *
 * User input flows directly to output (HTML, HTTP headers, cookies)
 * without encoding/escaping transformation.
 *
 * Sub-groups:
 *   A. XSS variants          (8 CWEs) — factory-driven
 *   B. Output injection       (6 CWEs) — per-CWE sink filters
 *   C. HTTP/cookie/GUI issues (8 CWEs) — per-CWE
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasPathWithoutTransform,
  sinkHasTaintedDataIn, scopeBasedTaintReaches, sharesFunctionScope,
  hasTaintedPathWithoutControl, stripComments, getContainingScopeSnapshots,
  cweDomainMatchesSink,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Sink filters — EGRESS nodes
// ---------------------------------------------------------------------------

function htmlEgressNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'EGRESS' &&
    (n.node_subtype.includes('html') || n.node_subtype.includes('render') ||
     n.node_subtype.includes('template') || n.node_subtype.includes('display') ||
     n.node_subtype.includes('http_response') ||
     n.attack_surface.includes('html_output') ||
     n.code_snapshot.match(
       /\b(innerHTML|render|res\.send|res\.write|document\.write|\.html\(|template|\.ejs|\.pug|\.hbs|response\.getWriter|response\.sendError|out\.println|out\.print|writer\.print|PrintWriter)\b/i
     ) !== null) &&
    !n.code_snapshot.match(/\bres\.json\s*\(/i)
  );
}

function headerEgressNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'EGRESS' &&
    (n.node_subtype.includes('header') || n.node_subtype.includes('http') ||
     n.attack_surface.includes('http_header') ||
     n.code_snapshot.match(
       /\b(setHeader|writeHead|res\.header|res\.set|addHeader|response\.header)\b/i
     ) !== null)
  );
}

function allEgressNodes(map: NeuralMap): NeuralMapNode[] {
  return nodesOfType(map, 'EGRESS');
}

function cookieEgressNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'EGRESS' &&
    (n.node_subtype.includes('cookie') || n.attack_surface.includes('cookie') ||
     n.code_snapshot.match(
       /\b(Set-Cookie|res\.cookie|document\.cookie|setCookie)\b/i
     ) !== null)
  );
}

// ---------------------------------------------------------------------------
// Safe pattern constants
// ---------------------------------------------------------------------------

const HTML_ENCODE_SAFE = /\bescape\s*\(|\bencode\s*\(|\bsanitize\s*\(|\bDOMPurify\b|\btextContent\b|\bhtmlEntities\b|\bhtmlspecialchars\b|\bencodeHtml\b|\bencodeForHTML\b|\bESAPI\b|\bEncoder\b.*\bencode\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b|\bOwasp\b.*\bencode\b/i;
const CRLF_SAFE = /\bstrip.*crlf\b|\breplace.*\\r\\n\b|\bstrip.*newline\b|\bcrlf.*reject\b|\bsanitize.*header\b|\bencodeURI\b/i;
const NEUTRALIZE_SAFE = /\bescape\s*\(|\bencode\s*\(|\bsanitize\s*\(|\bneutralize\s*\(|\bparameterize\b|\bstrip\s*\(|\b\.filter\s*\(|\bencodeForHTML\b|\bESAPI\b|\bEncoder\b.*\bencode\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b/i;
const ENCRYPT_SAFE = /\bencrypt\s*\(|\bcrypto\.\w|\bAES\b|\bhttps\b|\bSecure\b|\bhash\s*\(|\bcreateHash\b|\bcipher\s*\(|\bcreateCipher\w*\b/i;
const NORMALIZE_SAFE = /\bnormalize\s*\(|\bcanonicalize\s*\(|\bstrip\s*\(|\bencode\s*\(|\bsanitize\s*\(/i;

// ---------------------------------------------------------------------------
// Factory: INGRESS→EGRESS without TRANSFORM
// ---------------------------------------------------------------------------

function createOutputVerifier(
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

    // Dead-branch and list-offset neutralization: suppress findings when constant
    // arithmetic ternary/switch guarantees the tainted branch is never taken, or
    // when ArrayList remove+get retrieves a safe value.
    let hasNeutralization = false;
    if (map.source_code) {
      const cleanSrc = stripComments(map.source_code);
      // Dead-branch: arithmetic ternary/if-else with constant condition
      const arithM = cleanSrc.match(/\((\d+)\s*\*\s*(\d+)\)\s*([+-])\s*(\w+)\s*([><=!]+)\s*(\d+)/);
      if (arithM) {
        const a = parseInt(arithM[1]!); const b = parseInt(arithM[2]!);
        const op = arithM[3]!; const varName = arithM[4]!;
        const cmpOp = arithM[5]!; const threshold = parseInt(arithM[6]!);
        const varDeclM = cleanSrc.match(new RegExp('int\\s+' + varName + '\\s*=\\s*(\\d+)'));
        if (varDeclM) {
          const varVal = parseInt(varDeclM[1]!);
          const lhs = op === '+' ? (a * b) + varVal : (a * b) - varVal;
          if ((cmpOp === '>' && lhs > threshold) || (cmpOp === '>=' && lhs >= threshold) ||
              (cmpOp === '<' && lhs < threshold) || (cmpOp === '<=' && lhs <= threshold)) {
            hasNeutralization = true;
          }
        }
      }
      // Dead-branch: switch on charAt of literal
      const charAtM = cleanSrc.match(/(\w+)\.charAt\s*\((\d+)\)[\s\S]*?switch/);
      if (charAtM) {
        const strDeclM = cleanSrc.match(new RegExp('String\\s+' + charAtM[1]! + '\\s*=\\s*"([^"]*)"'));
        if (strDeclM) {
          const ci = parseInt(charAtM[2]!);
          if (ci >= 0 && ci < strDeclM[1]!.length) {
            const sc = strDeclM[1]![ci]!;
            const caseM = cleanSrc.match(new RegExp("case\\s+'" + sc + "'\\s*:[^}]*?\\b\\w+\\s*=\\s*\""));
            if (caseM) hasNeutralization = true;
          }
        }
      }
      // List-offset neutralization
      const getM = cleanSrc.match(/(\w+)\.get\s*\(\s*(\d+)\s*\)/);
      if (getM) {
        const listVar = getM[1]!; const getIdx = parseInt(getM[2]!);
        const addRe = new RegExp(listVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)', 'g');
        const removeRe = new RegExp(listVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\.remove\\s*\\(', 'g');
        const items: { tainted: boolean }[] = [];
        let removeCount = 0;
        let am: RegExpExecArray | null;
        while ((am = addRe.exec(cleanSrc)) !== null) items.push({ tainted: !!am[1] });
        while (removeRe.exec(cleanSrc) !== null) removeCount++;
        const adjusted = items.slice(removeCount);
        if (getIdx < adjusted.length && !adjusted[getIdx]!.tainted) hasNeutralization = true;
      }
    }

    for (const src of ingress) {
      for (const sink of sinks) {
        if (!cweDomainMatchesSink(cweId, sink)) continue;
        // Primary: BFS taint path without TRANSFORM gate
        let vulnerable = hasPathWithoutTransform(map, src.id, sink.id);
        let detectedVia: 'bfs' | 'sink_tainted' | 'scope_taint' = 'bfs';

        // Fallback 1: sink has tainted data_in (mapper captured taint but no edge path)
        if (!vulnerable && sinkHasTaintedDataIn(map, sink.id)) {
          vulnerable = true;
          detectedVia = 'sink_tainted';
        }

        // Fallback 2: scope-based — INGRESS and sink share a function scope
        // and a tainted TRANSFORM (assignment) exists in the same scope.
        // Catches Java Juliet patterns: data = request.getParameter("x"); ... response.getWriter().println(data);
        if (!vulnerable && scopeBasedTaintReaches(map, src.id, sink.id)) {
          vulnerable = true;
          detectedVia = 'scope_taint';
        }

        if (vulnerable) {
          // Skip if dead-branch or list-offset neutralization proves taint is killed
          if (hasNeutralization) continue;

          // Check safe patterns in scope context (not just sink code)
          const scopeSnaps = getContainingScopeSnapshots(map, sink.id);
          const combinedScope = stripComments(scopeSnaps.join('\n') || sink.code_snapshot);
          const isSafe = safePattern.test(combinedScope) ||
            (extraSafe ? extraSafe.test(combinedScope) : false);

          if (!isSafe) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `User input from ${src.label} reaches output at ${sink.label} without transformation. ` +
                `Vulnerable to ${cweName}.`,
              fix: fixDesc,
              via: detectedVia,
            });
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// ===========================================================================
// A. XSS VARIANTS (8 CWEs)
// ===========================================================================
// All share: INGRESS → EGRESS[html] without TRANSFORM[encoding]

export const verifyCWE80 = createOutputVerifier(
  'CWE-80', 'Basic XSS', 'high',
  htmlEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (HTML entity encoding — escape <, >, &, quotes)',
  'Encode HTML special characters (<, >, &, ", \') before inserting user input into HTML. ' +
    'Use textContent instead of innerHTML. Use DOMPurify for rich text.',
);

export const verifyCWE81 = createOutputVerifier(
  'CWE-81', 'Improper Neutralization of Script in an Error Message Web Page', 'high',
  htmlEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (HTML encoding in error messages)',
  'Encode user-controlled values in error pages. Error messages often reflect input ' +
    '(search terms, usernames) — these must be HTML-encoded to prevent reflected XSS.',
);

export const verifyCWE82 = createOutputVerifier(
  'CWE-82', 'Improper Neutralization of Script in Attributes of IMG Tags', 'high',
  htmlEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (attribute encoding for IMG tags)',
  'Encode user input placed in IMG tag attributes (src, onerror, onload). ' +
    'Validate URLs against an allowlist for image sources.',
  /\ballowlist\b|\bsrc.*valid\b/i,
);

export const verifyCWE83 = createOutputVerifier(
  'CWE-83', 'Improper Neutralization of Script in Attributes in a Web Page', 'high',
  htmlEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (attribute encoding)',
  'Encode user input placed in HTML attributes. Use attribute-context encoding, not just HTML encoding. ' +
    'Wrap attribute values in quotes and encode quotes within.',
);

export const verifyCWE84 = createOutputVerifier(
  'CWE-84', 'Improper Neutralization of Encoded URI Schemes in a Web Page', 'high',
  htmlEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (URI scheme validation / encoding)',
  'Validate URI schemes (javascript:, data:, vbscript:) before inserting in href/src attributes. ' +
    'Use URL allowlisting (http:, https: only) for user-controlled URLs.',
  /\ballowlist\b|\bhttp[s]?:\/\/\b.*\bonly\b|\burl.*valid\b/i,
);

export const verifyCWE85 = createOutputVerifier(
  'CWE-85', 'Doubled Character XSS Manipulations', 'high',
  htmlEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (complete encoding — handle doubled characters)',
  'Apply encoding recursively or use canonical encoding to prevent doubled character bypasses. ' +
    'Encode AFTER all other transformations to prevent double-encoding attacks.',
);

export const verifyCWE86 = createOutputVerifier(
  'CWE-86', 'Improper Neutralization of Invalid Characters in Identifiers in Web Pages', 'medium',
  htmlEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (identifier character validation / encoding)',
  'Validate and encode characters used in HTML/CSS/JS identifiers. ' +
    'Reject or strip invalid characters that could alter identifier meaning.',
);

export const verifyCWE87 = createOutputVerifier(
  'CWE-87', 'Improper Neutralization of Alternate XSS Syntax', 'high',
  htmlEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (comprehensive XSS encoding — handle alternate syntax)',
  'Use context-aware encoding libraries that handle alternate XSS vectors ' +
    '(backtick execution, expression() in CSS, etc.). Do not rely on simple regex blocklists.',
);

// ===========================================================================
// B. OUTPUT INJECTION (6 CWEs)
// ===========================================================================

/** CWE-74: Injection (generic output injection to downstream component) */
export const verifyCWE74 = createOutputVerifier(
  'CWE-74', 'Injection', 'critical',
  allEgressNodes, NEUTRALIZE_SAFE,
  'TRANSFORM (context-appropriate neutralization before output)',
  'Neutralize special elements for the target context: HTML-encode for HTML, ' +
    'URL-encode for URLs, parameterize for SQL, shell-escape for commands.',
);

/** CWE-75: Failure to Sanitize Special Elements into a Different Plane */
export const verifyCWE75 = createOutputVerifier(
  'CWE-75', 'Failure to Sanitize Special Elements into a Different Plane', 'high',
  allEgressNodes, NEUTRALIZE_SAFE,
  'TRANSFORM (plane-crossing neutralization)',
  'When data crosses planes (data→code, user→structure), neutralize special elements ' +
    'for the target plane. Never mix user data with structural elements without encoding.',
);

/** CWE-93: CRLF Injection */
export const verifyCWE93 = createOutputVerifier(
  'CWE-93', 'CRLF Injection', 'high',
  allEgressNodes, CRLF_SAFE,
  'TRANSFORM (CRLF stripping / encoding)',
  'Strip or reject CR (\\r) and LF (\\n) from user input before placing in headers or logs. ' +
    'CRLF injection enables HTTP response splitting and log forging.',
);

/**
 * CWE-113: HTTP Response Splitting
 * Pattern: INGRESS → EGRESS(HTTP header) without TRANSFORM(CRLF neutralization)
 *
 * UPGRADED from factory: specific HTTP header sinks (setHeader, writeHead,
 * res.header, addHeader), specific CRLF mitigation patterns (replace \\r\\n,
 * encodeURIComponent, header-safe libraries), checks both sink and source context.
 *
 * Dangerous sinks: res.setHeader(), res.writeHead(), res.header(), addHeader()
 *   — any API that sets HTTP response header values from user input.
 * NOT dangerous: res.json(), res.send() (body output, not headers).
 * Safe mitigations: CRLF stripping (replace /[\\r\\n]/g), encodeURIComponent(),
 *   encodeURI(), framework header APIs that auto-reject CRLF (Express 4.x+),
 *   sanitizeHeader() library functions.
 */
export function verifyCWE113(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // EGRESS nodes that set HTTP headers OR cookies (cookies are Set-Cookie headers)
  const headerSinks = map.nodes.filter(n =>
    n.node_type === 'EGRESS' &&
    (n.node_subtype.includes('header') || n.attack_surface.includes('http_header') ||
     n.node_subtype.includes('cookie') || n.attack_surface.includes('cookie') ||
     n.code_snapshot.match(
       /\b(setHeader|writeHead|res\.header|res\.set|addHeader|addCookie|response\.header|response\.setHeader|response\.addHeader|response\.addCookie|Set-Cookie)\b/i
     ) !== null) &&
    // Exclude body-output APIs — they don't set headers
    !n.code_snapshot.match(/\bres\.json\b|\bres\.send\b|\bres\.end\b|\bres\.render\b/i)
  );

  for (const src of ingress) {
    for (const sink of headerSinks) {
      // Primary: BFS path
      let vulnerable = hasPathWithoutTransform(map, src.id, sink.id);

      // Fallback 1: sink has tainted data_in
      if (!vulnerable && sinkHasTaintedDataIn(map, sink.id)) {
        vulnerable = true;
      }

      // Fallback 2: scope-based taint
      if (!vulnerable && scopeBasedTaintReaches(map, src.id, sink.id)) {
        vulnerable = true;
      }

      if (vulnerable) {
        // Check for CRLF-specific sanitization — use FUNCTION scope, not class scope.
        // Find the STRUCTURAL/function that contains this sink (by line range).
        const containingFunc = map.nodes.find(n =>
          n.node_type === 'STRUCTURAL' && n.node_subtype === 'function' &&
          sink.line_start >= n.line_start && sink.line_start <= n.line_end
        );
        const funcScope113 = containingFunc
          ? stripComments(containingFunc.analysis_snapshot || containingFunc.code_snapshot)
          : stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const hasCRLFStrip = funcScope113.match(
          /replace\s*\(.*\\r.*\\n|replace\s*\(.*\\n.*\\r|strip.*crlf|strip.*newline|sanitize.*header|URLEncoder\.encode/i
        ) !== null;

        // Check for encoding that neutralizes CRLF
        const hasEncoding = funcScope113.match(
          /\bencodeURIComponent\b|\bencodeURI\b|\bencodeHeader\b|\bsanitizeHeader\b|\bURLEncoder\.encode\b/i
        ) !== null;

        if (!hasCRLFStrip && !hasEncoding) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (CRLF neutralization — strip \\r\\n or encodeURIComponent before header)',
            severity: 'high',
            description: `User input from ${src.label} is placed in HTTP header at ${sink.label} without CRLF neutralization. ` +
              `An attacker can inject \\r\\n to split the response, enabling: ` +
              `cache poisoning, XSS via injected body, and session fixation via Set-Cookie.`,
            fix: 'Strip CR/LF: value.replace(/[\\r\\n]/g, ""). Or use encodeURIComponent(). ' +
              'Modern Express (4.x+) rejects CRLF in setHeader — ensure your framework version is current. ' +
              'Never place raw user input in Location, Set-Cookie, or Content-Disposition headers.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-113', name: 'HTTP Response Splitting', holds: findings.length === 0, findings };
}

/** CWE-138: Improper Neutralization of Special Elements */
export const verifyCWE138 = createOutputVerifier(
  'CWE-138', 'Improper Neutralization of Special Elements', 'high',
  allEgressNodes, NEUTRALIZE_SAFE,
  'TRANSFORM (special element neutralization for output context)',
  'Identify and neutralize all special elements relevant to the output context. ' +
    'Use proven encoding libraries rather than custom regex-based sanitization.',
);

/** CWE-150: Improper Neutralization of Escape, Meta, or Control Sequences */
export const verifyCWE150 = createOutputVerifier(
  'CWE-150', 'Improper Neutralization of Escape, Meta, or Control Sequences', 'medium',
  allEgressNodes, NEUTRALIZE_SAFE,
  'TRANSFORM (escape/meta/control sequence neutralization)',
  'Strip or encode escape sequences, meta characters, and control characters ' +
    'before output. These can alter terminal behavior, log output, or downstream parsing.',
);

// ===========================================================================
// C. HTTP/COOKIE/GUI ISSUES (8 CWEs)
// ===========================================================================

/** CWE-315: Cleartext Storage of Sensitive Information in a Cookie */
export const verifyCWE315 = createOutputVerifier(
  'CWE-315', 'Cleartext Storage of Sensitive Information in a Cookie', 'medium',
  cookieEgressNodes, ENCRYPT_SAFE,
  'TRANSFORM (encryption before cookie storage)',
  'Encrypt sensitive data before storing in cookies. Use signed/encrypted cookie sessions. ' +
    'Set Secure and HttpOnly flags. Never store passwords or tokens in cleartext cookies.',
);

/** CWE-317: Cleartext Storage of Sensitive Information in GUI */
export const verifyCWE317 = createOutputVerifier(
  'CWE-317', 'Cleartext Storage of Sensitive Information in GUI', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'EGRESS' &&
    (n.node_subtype.includes('gui') || n.node_subtype.includes('ui') ||
     n.node_subtype.includes('display') ||
     n.code_snapshot.match(/\b(alert|prompt|textField|label|display|show|modal|toast)\b/i) !== null)
  ),
  /\bmask\b|\bredact\b|\bhide\b|\b\*\*\*\b|\btype.*password\b/i,
  'TRANSFORM (masking / redaction before GUI display)',
  'Mask sensitive information in GUI elements. Use type="password" for input fields. ' +
    'Redact credit card numbers (show last 4 digits only). Never display secrets in alerts.',
);

/** CWE-325: Missing Cryptographic Step */
export const verifyCWE325 = createOutputVerifier(
  'CWE-325', 'Missing Required Cryptographic Step', 'high',
  allEgressNodes, ENCRYPT_SAFE,
  'TRANSFORM (required cryptographic operation — encryption, signing, MAC)',
  'Apply all required cryptographic steps before transmission. ' +
    'Missing steps (encryption, signing, MAC verification) break the security of the protocol.',
);

/** CWE-433: Unparsed Raw Web Content Delivery */
export const verifyCWE433 = createOutputVerifier(
  'CWE-433', 'Unparsed Raw Web Content Delivery', 'medium',
  htmlEgressNodes, NORMALIZE_SAFE,
  'TRANSFORM (content parsing / encoding before delivery)',
  'Parse and encode web content before delivery. Do not serve raw user-uploaded content ' +
    'directly — process it to neutralize embedded scripts and active content.',
);

/** CWE-444: HTTP Request/Response Smuggling */
export const verifyCWE444 = createOutputVerifier(
  'CWE-444', 'HTTP Request/Response Smuggling', 'high',
  headerEgressNodes, NORMALIZE_SAFE,
  'TRANSFORM (HTTP header normalization / ambiguity resolution)',
  'Normalize HTTP headers before forwarding. Reject requests with ambiguous Content-Length ' +
    'and Transfer-Encoding. Use HTTP/2 where possible to prevent smuggling.',
  /\bContent-Length\b.*\breject\b|\bTransfer-Encoding\b.*\bnormalize\b|\bHTTP\/2\b/i,
);

/** CWE-549: Missing Password Field Masking — only fires when password-related fields are present */
export const verifyCWE549 = createOutputVerifier(
  'CWE-549', 'Missing Password Field Masking', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'EGRESS' &&
    /\bpassword\b|\bpasswd\b|\bsecret\b|\bcredential\b/i.test(n.code_snapshot) &&
    !n.code_snapshot.match(/\bres\.json\s*\(/i)
  ),
  /\btype\s*=\s*['"]password['"]\b|\btype.*password\b|\bmask\b|\b\*\*\*\b/i,
  'TRANSFORM (password field masking — type="password")',
  'Use type="password" for all password input fields. This prevents shoulder surfing ' +
    'and ensures the password is not visible in the UI.',
);

/** CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax */
export const verifyCWE644 = createOutputVerifier(
  'CWE-644', 'Improper Neutralization of HTTP Headers for Scripting Syntax', 'high',
  headerEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (neutralization of scripting syntax in HTTP headers)',
  'Encode scripting syntax in HTTP header values. Headers reflected in HTML contexts ' +
    '(error pages, debug output) can enable XSS if not encoded.',
);

/** CWE-692: Incomplete Denylist to Cross-Site Scripting */
export const verifyCWE692 = createOutputVerifier(
  'CWE-692', 'Incomplete Denylist to Cross-Site Scripting', 'high',
  htmlEgressNodes, HTML_ENCODE_SAFE,
  'TRANSFORM (comprehensive encoding — not denylist-based)',
  'Use allowlist-based encoding, not denylists. Denylists always miss edge cases. ' +
    'Use context-aware encoding libraries (DOMPurify, encode.js) instead of regex blocklists.',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_005_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // XSS Variants (8)
  'CWE-80': verifyCWE80,
  'CWE-81': verifyCWE81,
  'CWE-82': verifyCWE82,
  'CWE-83': verifyCWE83,
  'CWE-84': verifyCWE84,
  'CWE-85': verifyCWE85,
  'CWE-86': verifyCWE86,
  'CWE-87': verifyCWE87,
  // Output Injection (6)
  'CWE-74': verifyCWE74,
  'CWE-75': verifyCWE75,
  'CWE-93': verifyCWE93,
  'CWE-113': verifyCWE113,
  'CWE-138': verifyCWE138,
  'CWE-150': verifyCWE150,
  // HTTP/Cookie/GUI (8)
  'CWE-315': verifyCWE315,
  'CWE-317': verifyCWE317,
  'CWE-325': verifyCWE325,
  'CWE-433': verifyCWE433,
  'CWE-444': verifyCWE444,
  'CWE-549': verifyCWE549,
  'CWE-644': verifyCWE644,
  'CWE-692': verifyCWE692,
};
