/**
 * Security-Cap-Fail-Open Detector
 *
 * Extends CWE-636 (Not Failing Securely) to detect patterns where security
 * checks silently degrade under load/size caps:
 *
 * 1. Cap-based bypass: if (items.length > 50) { return true; }
 *    When a collection exceeds a size threshold, ALL security checks are
 *    skipped and access is granted. Attackers flood the system to bypass.
 *
 * 2. Default-allow initialization: let authorized = true;
 *    Security variable starts permissive; if the deny path is skipped
 *    (exception, early return, cap bypass), access is granted by default.
 *
 * This is a standalone verifier that complements the existing CWE-636 in
 * error-handling.ts. Results use CWE-636 as the CWE identifier.
 */

import type { NeuralMap } from '../types.js';
import type { VerificationResult, Finding } from './types.js';
import { nodeRef } from './graph-helpers.js';
import { stripComments } from './source-analysis.js';

// ---------------------------------------------------------------------------
// Regex patterns
// ---------------------------------------------------------------------------

/**
 * Cap-based bypass: if (x.length > N) { return true/allow/null/undefined }
 * Also matches size, count properties and continue/break in the branch.
 */
const CAP_BYPASS = /if\s*\([^)]{0,80}\.(?:length|size|count)\s*(?:>|>=)\s*\d+[^)]*\)\s*\{[^}]*(?:return\s+(?:true|null|undefined)|continue\s*;|break\s*;)/s;

/**
 * Default-allow: let authorized = true (in function with auth/permission/access context)
 */
const DEFAULT_ALLOW = /(?:let|var|const)\s+(\w*(?:auth|allow|permit|grant|access|approved|verified)\w*)\s*=\s*true\b/i;

/**
 * Auth context: function names or body keywords suggesting security
 */
const AUTH_CONTEXT = /(?:check|verify|validate|authorize|authenticate|permission|access|security|auth|grant|deny|allow)\w*/i;

/**
 * Safe denial patterns -- if the cap branch DENIES access, it's not fail-open
 */
const SAFE_DENY = /(?:throw\s|reject|abort|exit|process\.exit|return\s+false|return\s+null|deny|forbid|unauthorized|res\.status\s*\(\s*4[0-9]{2}\)|Error\(|error\()/;

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/**
 * Detect security-cap-fail-open patterns in the given NeuralMap.
 *
 * Returns a VerificationResult under CWE-636.
 * `holds === true` means no fail-open patterns detected (safe).
 * `holds === false` means at least one fail-open pattern found (vulnerable).
 */
export function detectFailOpen(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // --- Cap-based bypass detection ---
    if (CAP_BYPASS.test(code)) {
      // Extract the cap branch to check if it safely denies
      const capMatch = code.match(CAP_BYPASS);
      if (capMatch) {
        const capBranch = capMatch[0];

        // If the cap branch denies access (throw, return false, error, etc.), it's safe
        if (SAFE_DENY.test(capBranch)) {
          continue;
        }

        // Check that we're in an auth/security context
        if (AUTH_CONTEXT.test(code)) {
          findings.push({
            source: nodeRef(node),
            sink: nodeRef(node),
            missing: 'CONTROL (security check must not skip validation when collection exceeds cap)',
            severity: 'critical',
            description: `${node.label} bypasses security checks when a collection exceeds a size cap. ` +
              `An attacker can flood the input with entries to exceed the threshold, causing ALL ` +
              `security validation to be silently skipped. This is the "cap-based fail-open" pattern.`,
            fix: 'When a collection exceeds the size cap, DENY the request instead of skipping validation. ' +
              'Pattern: if (items.length > MAX) { return false; } or throw an error. ' +
              'Never return true/null/undefined when a security cap is exceeded.',
            via: 'structural',
          });
          continue;
        }
      }
    }

    // --- Default-allow initialization detection ---
    if (DEFAULT_ALLOW.test(code)) {
      // Check surrounding function is auth-related
      if (AUTH_CONTEXT.test(code)) {
        // Check that there isn't already a proper deny path that always sets to false
        let hasConditionalDeny = /(?:if|else|unless|when)[\s\S]*?=\s*false\b/i.test(code);

        // If a deny path exists, check whether it's wrapped in a try block
        // whose catch does NOT deny. If so, the deny is unreliable because an
        // exception in the try body would skip the deny and the permissive
        // catch would leave the security variable in its default-allow state.
        if (hasConditionalDeny) {
          // Find CONTROL/catch nodes sharing the same function scope
          const funcScope = map.nodes.find(
            n => n.node_type === 'STRUCTURAL' &&
              /function|method/i.test(n.node_subtype) &&
              n.line_start <= node.line_start &&
              n.line_end >= node.line_end,
          );
          if (funcScope) {
            const catchNodes = map.nodes.filter(
              n => n.node_type === 'CONTROL' &&
                (n.node_subtype === 'catch' || n.node_subtype === 'error_handling') &&
                n.line_start >= funcScope.line_start &&
                n.line_end <= funcScope.line_end,
            );
            for (const catchNode of catchNodes) {
              const catchCode = stripComments(
                catchNode.analysis_snapshot || catchNode.code_snapshot,
              );
              if (!SAFE_DENY.test(catchCode)) {
                // Catch block doesn't deny -> deny in try body is unreliable
                hasConditionalDeny = false;
                break;
              }
            }
          }
        }

        if (!hasConditionalDeny) {
          const varMatch = code.match(DEFAULT_ALLOW);
          const varName = varMatch ? varMatch[1] : 'security variable';

          findings.push({
            source: nodeRef(node),
            sink: nodeRef(node),
            missing: 'CONTROL (initialize security variables to false/deny, set true only on verified success)',
            severity: 'high',
            description: `${node.label} initializes "${varName}" to true (default-allow). ` +
              `If the code that should set it to false is skipped (early return, exception, cap bypass), ` +
              `access is granted by default. This is the "fail-open" anti-pattern.`,
            fix: 'Initialize security variables to false/deny: let authorized = false; ' +
              'Set to true ONLY after positive verification succeeds. ' +
              'This ensures any unexpected code path defaults to deny.',
            via: 'structural',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-636',
    name: 'Not Failing Securely (Cap-Based Fail-Open)',
    holds: findings.length === 0,
    findings,
  };
}
