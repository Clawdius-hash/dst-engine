/**
 * DST Generated Verifiers — Batch 009
 * Pattern shape: INGRESS→EXTERNAL without TRANSFORM
 * 15 CWEs: command injection, LDAP injection, neutralization of special
 * elements before sending to external systems, encoding issues.
 *
 * User input flows to external systems (shell, LDAP, XQuery, processes)
 * without encoding/neutralization transformation.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasPathWithoutTransform, cweDomainMatchesSink,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Sink filters — EXTERNAL nodes
// ---------------------------------------------------------------------------

function externalNodes(map: NeuralMap): NeuralMapNode[] {
  return nodesOfType(map, 'EXTERNAL');
}

function commandExternalNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('command') || n.node_subtype.includes('shell') ||
     n.node_subtype.includes('exec') || n.attack_surface.includes('shell_exec') ||
     n.code_snapshot.match(
       /\b(exec|execSync|spawn|system|popen|shell_exec|child_process|Runtime\.exec|subprocess)\b/i
     ) !== null)
  );
}

function ldapExternalNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('ldap') || n.attack_surface.includes('ldap_query') ||
     n.code_snapshot.match(/\b(ldap|LDAP|ldapSearch|ldap_search|bind|searchFilter)\b/i) !== null)
  );
}

function xqueryExternalNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('xquery') || n.node_subtype.includes('xml') ||
     n.code_snapshot.match(/\b(XQuery|xquery|xmldb|eXist|BaseX|MarkLogic)\b/i) !== null)
  );
}

// ---------------------------------------------------------------------------
// Safe patterns
// ---------------------------------------------------------------------------

const CMD_NEUTRALIZE_SAFE = /\bexecFile\b|\bspawn\b.*\[|\bshellEscape\b|\bescapeShell\b|\bparameteriz\b|\bsanitize\s*\(/i;
const LDAP_NEUTRALIZE_SAFE = /\bescapeLdap\b|\bldap.*escape\b|\bldap.*sanitize\b|\bparameteriz\b|\bfilter.*encode\b/i;
const GENERAL_NEUTRALIZE_SAFE = /\bescape\s*\(|\bencode\s*\(|\bsanitize\s*\(|\bneutralize\s*\(|\bparameteriz\b|\bstrip\s*\(|\b\.filter\s*\(/i;
const ENCODING_SAFE = /\bencodeURI\b|\bpercentEncode\b|\bUTF-8\b|\bnormalize.*encoding\b|\bcharset.*valid\b|\biconv\b/i;

// ---------------------------------------------------------------------------
// Factory: INGRESS→EXTERNAL without TRANSFORM
// ---------------------------------------------------------------------------

function createExternalNoTransformVerifier(
  cweId: string, cweName: string, severity: Severity,
  sinkFilter: (map: NeuralMap) => NeuralMapNode[],
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = sinkFilter(map);

    for (const src of ingress) {
      for (const sink of sinks) {
        // Domain filter: skip sinks whose domain doesn't match this CWE
        if (!cweDomainMatchesSink(cweId, sink)) continue;
        if (hasPathWithoutTransform(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `User input from ${src.label} reaches external system at ${sink.label} without transformation. ` +
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
// COMMAND/QUERY INJECTION (3 CWEs)
// ===========================================================================

/**
 * CWE-77: Command Injection (UPGRADED — hand-written quality)
 *
 * Detects user input flowing to OS command execution without neutralization.
 *
 * Dangerous sinks (shell interpretation):
 *   - exec(), execSync() — runs through shell, metacharacters interpreted
 *   - child_process.exec — same
 *   - system(), popen(), shell_exec() — C/PHP shell execution
 *   - os.system(), subprocess.call(shell=True) — Python shell execution
 *   - Runtime.exec() with string arg — Java shell execution
 *
 * Safe patterns (NO shell interpretation):
 *   - execFile() / execFileSync() — no shell, args as array
 *   - spawn() with array args and NO {shell:true}
 *   - subprocess.run([...]) without shell=True
 *   - Allowlist validation: input checked against known-good values before exec
 *   - shellEscape() / escapeShellArg() — explicit escaping
 *
 * Key distinction: exec("ls " + input) is dangerous because the shell
 * interprets metacharacters (;, |, &&, $(), ``) in the input.
 * execFile("ls", [input]) is safe because args are passed directly to
 * the process without shell interpretation.
 */
export function verifyCWE77(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Specific dangerous sinks: nodes that execute OS commands through a shell
  const shellSinks = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('command') || n.node_subtype.includes('shell') ||
     n.node_subtype.includes('exec') || n.attack_surface.includes('shell_exec') ||
     n.code_snapshot.match(
       /\b(exec|execSync|system|popen|shell_exec|child_process\.exec|os\.system|subprocess\.call|Runtime\.exec)\s*\(/i
     ) !== null)
  );

  for (const src of ingress) {
    for (const sink of shellSinks) {
      if (hasPathWithoutTransform(map, src.id, sink.id)) {
        const code = sink.code_snapshot;

        // Safe: execFile / execFileSync (no shell interpretation)
        const usesExecFile = /\b(execFile|execFileSync)\s*\(/i.test(code);

        // Safe: spawn with array args and no shell:true
        const usesSpawnArray = /\bspawn\s*\(\s*['"][^'"]+['"]\s*,\s*\[/i.test(code) &&
          !/shell\s*:\s*true/i.test(code);

        // Safe: Python subprocess with list args and no shell=True
        const usesPythonSafeSubprocess = /\bsubprocess\.(run|Popen|call)\s*\(\s*\[/i.test(code) &&
          !/shell\s*=\s*True/i.test(code);

        // Safe: explicit shell escaping
        const usesShellEscape = /\b(shellEscape|escapeShell|escapeShellArg|shlex\.quote|shellescape)\s*\(/i.test(code);

        // Safe: allowlist validation (input checked against known values)
        const usesAllowlist = /\b(allowlist|whitelist|allowedCommands|validCommands)\b/i.test(code) ||
          /\b(includes|indexOf|has)\s*\([^)]*\)\s*[!><=]/i.test(code);

        const isSafe = usesExecFile || usesSpawnArray || usesPythonSafeSubprocess ||
          usesShellEscape || usesAllowlist;

        if (!isSafe) {
          // Determine the specific dangerous pattern for targeted advice
          const usesExec = /\bexec\s*\(/i.test(code);
          const usesTemplate = /`[^`]*\$\{/i.test(code) || /\+\s*\w/.test(code);
          const detail = usesExec && usesTemplate
            ? 'String concatenation or template literal builds shell command with user input.'
            : 'User input reaches shell execution without sanitization.';

          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (command parameterization — use execFile/spawn with argument arrays, not exec with string concatenation)',
            severity: 'critical',
            description: `User input from ${src.label} flows to command execution at ${sink.label}. ${detail} ` +
              `Shell metacharacters (; | && \`\` $()) in the input will be interpreted, allowing arbitrary command execution.`,
            fix: 'Replace exec() with execFile() or spawn() using argument arrays. ' +
              'Example: instead of exec("grep " + input + " file.txt"), use ' +
              'execFile("grep", [input, "file.txt"]). If shell is absolutely required, ' +
              'validate input against a strict allowlist of permitted values. ' +
              'In Python, use subprocess.run(["cmd", arg]) without shell=True.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-77', name: 'Command Injection', holds: findings.length === 0, findings };
}

export const verifyCWE90 = createExternalNoTransformVerifier(
  'CWE-90', 'LDAP Injection', 'high',
  ldapExternalNodes, LDAP_NEUTRALIZE_SAFE,
  'TRANSFORM (LDAP character encoding / parameterized queries)',
  'Escape LDAP special characters (*, (, ), \\, NUL) in user input. ' +
    'Use parameterized LDAP search filters. Validate input against expected patterns.',
);

export const verifyCWE652 = createExternalNoTransformVerifier(
  'CWE-652', 'Improper Neutralization of Data within XQuery Expressions', 'high',
  xqueryExternalNodes,
  /\bescapeXQuery\b|\bparameteriz\b|\bsanitize.*xquery\b|\bbind.*variable\b/i,
  'TRANSFORM (XQuery parameterization / character encoding)',
  'Use parameterized XQuery with bound variables. Escape XQuery special characters. ' +
    'Never concatenate user input into XQuery expressions.',
);

// ===========================================================================
// SPECIAL ELEMENT NEUTRALIZATION (8 CWEs)
// ===========================================================================

export const verifyCWE76 = createExternalNoTransformVerifier(
  'CWE-76', 'Improper Neutralization of Equivalent Special Elements', 'high',
  externalNodes, GENERAL_NEUTRALIZE_SAFE,
  'TRANSFORM (equivalent special element neutralization)',
  'Neutralize all equivalent representations of special elements (Unicode, hex, octal, alternate encodings). ' +
    'Canonicalize before neutralization to catch all variants.',
);

export const verifyCWE146 = createExternalNoTransformVerifier(
  'CWE-146', 'Improper Neutralization of Expression/Command Delimiters', 'high',
  externalNodes, GENERAL_NEUTRALIZE_SAFE,
  'TRANSFORM (expression/command delimiter neutralization)',
  'Escape or strip expression and command delimiters (;, |, &&, ||, `) before passing to external systems.',
);

export const verifyCWE151 = createExternalNoTransformVerifier(
  'CWE-151', 'Improper Neutralization of Comment Delimiters', 'medium',
  externalNodes, GENERAL_NEUTRALIZE_SAFE,
  'TRANSFORM (comment delimiter neutralization — //, /* */, #, --)',
  'Neutralize comment delimiters before embedding in SQL, shell, or scripting contexts. ' +
    'Comment injection can truncate queries or commands.',
);

export const verifyCWE152 = createExternalNoTransformVerifier(
  'CWE-152', 'Improper Neutralization of Macro Symbols', 'medium',
  externalNodes, GENERAL_NEUTRALIZE_SAFE,
  'TRANSFORM (macro symbol neutralization)',
  'Neutralize macro symbols ($, %, {}, #define) before passing to template engines or preprocessors.',
);

export const verifyCWE153 = createExternalNoTransformVerifier(
  'CWE-153', 'Improper Neutralization of Substitution Characters', 'medium',
  externalNodes, GENERAL_NEUTRALIZE_SAFE,
  'TRANSFORM (substitution character neutralization — $, `, %)',
  'Escape substitution characters before passing to shells, template engines, or string formatters.',
);

export const verifyCWE154 = createExternalNoTransformVerifier(
  'CWE-154', 'Improper Neutralization of Variable Name Delimiters', 'medium',
  externalNodes, GENERAL_NEUTRALIZE_SAFE,
  'TRANSFORM (variable name delimiter neutralization — ${}, $(), %%)',
  'Escape variable delimiters before embedding in shell scripts or template strings.',
);

export const verifyCWE160 = createExternalNoTransformVerifier(
  'CWE-160', 'Improper Neutralization of Leading Special Elements', 'medium',
  externalNodes, GENERAL_NEUTRALIZE_SAFE,
  'TRANSFORM (leading special element neutralization)',
  'Strip or escape leading special elements (-, ~, /) that could alter command or path interpretation.',
);

export const verifyCWE161 = createExternalNoTransformVerifier(
  'CWE-161', 'Improper Neutralization of Multiple Leading Special Elements', 'medium',
  externalNodes, GENERAL_NEUTRALIZE_SAFE,
  'TRANSFORM (multiple leading special element neutralization)',
  'Handle multiple leading special elements that may compound or interact.',
);

// ===========================================================================
// ENCODING/HANDLING (4 CWEs)
// ===========================================================================

export const verifyCWE173 = createExternalNoTransformVerifier(
  'CWE-173', 'Improper Handling of Alternate Encoding', 'high',
  externalNodes, ENCODING_SAFE,
  'TRANSFORM (encoding normalization before external system interaction)',
  'Normalize encoding before passing data to external systems. Alternate encodings ' +
    '(UTF-7, overlong UTF-8) can bypass security filters.',
);

export const verifyCWE175 = createExternalNoTransformVerifier(
  'CWE-175', 'Improper Handling of Mixed Encoding', 'medium',
  externalNodes, ENCODING_SAFE,
  'TRANSFORM (encoding consistency enforcement)',
  'Ensure consistent encoding when mixing data from different sources. ' +
    'Normalize all input to a single encoding (UTF-8) before processing.',
);

export const verifyCWE176 = createExternalNoTransformVerifier(
  'CWE-176', 'Improper Handling of Unicode Encoding', 'high',
  externalNodes, ENCODING_SAFE,
  'TRANSFORM (Unicode normalization — NFC/NFKC)',
  'Normalize Unicode (NFC or NFKC) before security checks. Homograph attacks use ' +
    'lookalike characters. Overlong UTF-8 can bypass byte-level filters.',
);

export const verifyCWE214 = createExternalNoTransformVerifier(
  'CWE-214', 'Invocation of Process Using Visible Sensitive Information', 'medium',
  commandExternalNodes,
  /\benv\b|\benviron\b|\bstdin\b|\bpipe\b|\bfile.*pass\b/i,
  'TRANSFORM (sensitive data passed via secure channel — env/stdin, not command line)',
  'Pass sensitive data via environment variables, stdin, or files — not command-line arguments. ' +
    'Command lines are visible in process listings (ps, /proc).',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_009_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-77': verifyCWE77,
  'CWE-90': verifyCWE90,
  'CWE-652': verifyCWE652,
  'CWE-76': verifyCWE76,
  'CWE-146': verifyCWE146,
  'CWE-151': verifyCWE151,
  'CWE-152': verifyCWE152,
  'CWE-153': verifyCWE153,
  'CWE-154': verifyCWE154,
  'CWE-160': verifyCWE160,
  'CWE-161': verifyCWE161,
  'CWE-173': verifyCWE173,
  'CWE-175': verifyCWE175,
  'CWE-176': verifyCWE176,
  'CWE-214': verifyCWE214,
};
