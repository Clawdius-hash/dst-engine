/**
 * DST Generated Verifiers — Batch 012
 * Pattern shape: INGRESS→AUTH without CONTROL
 * 12 CWEs: authentication bypass, weak passwords, replay attacks,
 * credential management, brute force prevention.
 *
 * User input reaches the AUTH system without a CONTROL node enforcing
 * security policies (replay protection, rate limiting, password strength).
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Sink filter — AUTH nodes
// ---------------------------------------------------------------------------

function authNodes(map: NeuralMap): NeuralMapNode[] {
  return nodesOfType(map, 'AUTH');
}

// ---------------------------------------------------------------------------
// Safe patterns
// ---------------------------------------------------------------------------

const REPLAY_SAFE = /\bnonce\b|\btimestamp\b.*\bvalid\b|\bsequence\b|\bone.*time\b|\bexpir\b|\bchallenge.*response\b/i;
const RATE_LIMIT_SAFE = /\brate.*limit\b|\bthrottle\b|\blockout\b|\bmax.*attempt\b|\bfail.*count\b|\bcaptcha\b|\bdelay\b/i;
const PASSWORD_SAFE = /\bmin.*length\b|\bcomplexity\b|\bstrength\b|\bzxcvbn\b|\bentropy\b|\bpolicy\b|\brequire.*upper\b/i;
const AUTH_CONTROL_SAFE = /\bverif\w*\s*\(|\bvalidate\s*\(|\bcheck\s*\(|\bmiddleware\b|\bguard\s*\(|\bsecure\s*\(|\bprotect\s*\(/i;

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

function createAuthControlVerifier(
  cweId: string, cweName: string, severity: Severity,
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = authNodes(map);

    for (const src of ingress) {
      for (const sink of sinks) {
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `Authentication at ${sink.label} receives input from ${src.label} without security controls. ` +
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
// VERIFIERS (12 CWEs)
// ===========================================================================

export const verifyCWE187 = createAuthControlVerifier(
  'CWE-187', 'Partial String Comparison', 'high',
  /\b===\b|\bstrictEqual\b|\btimingSafeEqual\b|\bconstantTime\b|\bfull.*compare\b/i,
  'CONTROL (full string comparison — not partial/prefix match)',
  'Use full strict equality (===) for authentication comparisons. Partial comparisons ' +
    '(startsWith, indexOf) allow crafted inputs to match. Use timing-safe comparison for secrets.',
);

export const verifyCWE294 = createAuthControlVerifier(
  'CWE-294', 'Authentication Bypass by Capture-replay', 'high',
  REPLAY_SAFE,
  'CONTROL (replay protection — nonce, timestamp, sequence number)',
  'Implement replay protection: use nonces, timestamps with expiry, or sequence numbers. ' +
    'Each authentication exchange must be unique and non-replayable.',
);

export const verifyCWE302 = createAuthControlVerifier(
  'CWE-302', 'Authentication Bypass by Assumed-Immutable Data', 'high',
  AUTH_CONTROL_SAFE,
  'CONTROL (server-side auth state — do not trust client-supplied auth claims)',
  'Never trust client-supplied authentication state (cookies, hidden fields, headers). ' +
    'Verify all authentication claims server-side against authoritative data.',
);

export const verifyCWE304 = createAuthControlVerifier(
  'CWE-304', 'Missing Critical Step in Authentication', 'critical',
  AUTH_CONTROL_SAFE,
  'CONTROL (complete authentication — all required steps enforced)',
  'Enforce all authentication steps. Do not skip steps based on client state. ' +
    'Multi-step auth must verify each step completed before progressing.',
);

export const verifyCWE309 = createAuthControlVerifier(
  'CWE-309', 'Use of Password System for Primary Authentication', 'medium',
  /\bMFA\b|\b2FA\b|\bmulti.*factor\b|\bsecond.*factor\b|\btotp\b|\bwebauthn\b/i,
  'CONTROL (multi-factor authentication for sensitive operations)',
  'Use MFA for sensitive operations. Password-only auth is insufficient for high-value targets. ' +
    'Implement TOTP, WebAuthn, or hardware keys as second factors.',
);

export const verifyCWE521 = createAuthControlVerifier(
  'CWE-521', 'Weak Password Requirements', 'medium',
  PASSWORD_SAFE,
  'CONTROL (password strength enforcement — minimum length, complexity, breach check)',
  'Enforce minimum password length (12+), check against breached password lists (HIBP), ' +
    'and use a strength estimator (zxcvbn). Do not rely solely on complexity rules.',
);

/**
 * CWE-620: Unverified Password Change
 * UPGRADED — hand-written with specific sink filters and safe patterns.
 *
 * Pattern: User input (INGRESS) reaches a password-changing AUTH node
 * without passing through a CONTROL node that verifies the current password.
 *
 * This is an authentication bypass: if an attacker has a stolen session token,
 * they can change the password without knowing the original, permanently
 * locking out the legitimate user.
 *
 * Specific sinks: AUTH nodes whose code contains password-changing operations
 *   (setPassword, updatePassword, changePassword, password =, hash(newPassword),
 *    bcrypt.hash, UPDATE users SET password)
 * Specific safe patterns:
 *   - Verifying current/old password before setting new one
 *   - bcrypt.compare / argon2.verify on the old password
 *   - Re-authentication before password change
 *   - Password reset via email token (different flow, not same-session change)
 */
export function verifyCWE620(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const ingress = nodesOfType(map, 'INGRESS');

  // Sinks: AUTH nodes that change/set/update passwords
  const PASSWORD_CHANGE_PATTERN = /\b(setPassword|updatePassword|changePassword|resetPassword|hashPassword|password\s*=|SET\s+password|UPDATE.*password|bcrypt\.hash|argon2\.hash)\b/i;
  const passwordChangeSinks = map.nodes.filter(n =>
    n.node_type === 'AUTH' &&
    PASSWORD_CHANGE_PATTERN.test(n.code_snapshot)
  );

  // Safe: current password verified before change
  const VERIFY_CURRENT_SAFE = /\b(currentPassword|oldPassword|current_password|old_password|existingPassword)\b|\bbcrypt\.compare\b|\bargon2\.verify\b|\bverifyPassword\b|\bcheckPassword\b|\bvalidatePassword\b|\breauth|compareSync\b/i;

  for (const src of ingress) {
    for (const sink of passwordChangeSinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if the surrounding code verifies the current password
        const isSafe = VERIFY_CURRENT_SAFE.test(sink.code_snapshot) ||
          VERIFY_CURRENT_SAFE.test(src.code_snapshot);

        // Also check: is there any node in the graph that verifies the old password?
        // Look for a CONTROL node on the path that does password comparison
        const hasPasswordVerifyControl = map.nodes.some(n =>
          n.node_type === 'CONTROL' &&
          VERIFY_CURRENT_SAFE.test(n.code_snapshot)
        );

        if (!isSafe && !hasPasswordVerifyControl) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (current password verification before allowing password change)',
            severity: 'high',
            description: `User input from ${src.label} reaches password change at ${sink.label} ` +
              `without verifying the current password. An attacker with a stolen session ` +
              `can change the password and permanently lock out the legitimate user.`,
            fix: 'Require the current password in the password change form. ' +
              'Verify it with bcrypt.compare() or equivalent before setting the new password. ' +
              'For admin resets, use a separate authenticated admin endpoint with audit logging.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-620', name: 'Unverified Password Change', holds: findings.length === 0, findings };
}

export const verifyCWE640 = createAuthControlVerifier(
  'CWE-640', 'Weak Password Recovery Mechanism for Forgotten Password', 'high',
  /\btoken\b.*\bexpir\b|\bone.*time\b|\bsecure.*link\b|\brandom.*token\b|\btime.*limit\b/i,
  'CONTROL (secure password reset — random tokens, time-limited, single-use)',
  'Use cryptographically random, time-limited, single-use tokens for password reset. ' +
    'Do not use security questions. Send reset links, not passwords.',
);

export const verifyCWE645 = createAuthControlVerifier(
  'CWE-645', 'Overly Restrictive Account Lockout Mechanism', 'medium',
  /\bprogressive.*delay\b|\bCAPTCHA\b|\bexponential.*back\b|\btemp.*lock\b|\bunlock.*time\b/i,
  'CONTROL (balanced lockout — prevent brute force without enabling DoS)',
  'Use progressive delays or temporary lockouts, not permanent ones. ' +
    'Permanent lockout enables denial-of-service against legitimate users. Use CAPTCHA as fallback.',
);

export const verifyCWE649 = createAuthControlVerifier(
  'CWE-649', 'Reliance on Obfuscation or Protection Mechanism that is Not Constant-Time', 'high',
  /\btimingSafeEqual\b|\bconstantTime\b|\bcrypto\.timingSafeEqual\b|\bhmac\b.*\bcompare\b/i,
  'CONTROL (constant-time comparison for authentication secrets)',
  'Use timing-safe comparison (crypto.timingSafeEqual) for comparing secrets, tokens, and MACs. ' +
    'Regular string comparison leaks information via timing side-channels.',
);

export const verifyCWE799 = createAuthControlVerifier(
  'CWE-799', 'Improper Control of Interaction Frequency', 'medium',
  RATE_LIMIT_SAFE,
  'CONTROL (rate limiting / interaction frequency control)',
  'Rate-limit authentication attempts. Implement account lockout after N failures. ' +
    'Use progressive delays. Apply rate limiting per IP and per account.',
);

export const verifyCWE804 = createAuthControlVerifier(
  'CWE-804', 'Guessable CAPTCHA', 'medium',
  /\breCAPTCHA\b|\bhCaptcha\b|\bturnstile\b|\bserver.*verify\b|\bsecure.*captcha\b/i,
  'CONTROL (strong CAPTCHA — reCAPTCHA v3, hCaptcha, Turnstile)',
  'Use modern CAPTCHA services (reCAPTCHA v3, hCaptcha, Cloudflare Turnstile). ' +
    'Verify CAPTCHA responses server-side. Do not use simple text/math CAPTCHAs.',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_012_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-187': verifyCWE187,
  'CWE-294': verifyCWE294,
  'CWE-302': verifyCWE302,
  'CWE-304': verifyCWE304,
  'CWE-309': verifyCWE309,
  'CWE-521': verifyCWE521,
  'CWE-620': verifyCWE620,
  'CWE-640': verifyCWE640,
  'CWE-645': verifyCWE645,
  'CWE-649': verifyCWE649,
  'CWE-799': verifyCWE799,
  'CWE-804': verifyCWE804,
};
