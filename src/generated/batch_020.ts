/**
 * DST Generated Verifiers -- Batch 020
 * Gap-fill for CWEs 600-799 that were missing from GENERATED_REGISTRY
 * and CWE_REGISTRY despite having taxonomy definitions.
 *
 * 8 CWEs:
 *   CWE-601  Open Redirect                        (INGRESS->EGRESS without CONTROL)
 *   CWE-613  Insufficient Session Expiration       (STORAGE->AUTH without CONTROL)
 *   CWE-614  Cookie without Secure attribute       (TRANSFORM->EGRESS without CONTROL)
 *   CWE-668  Resource Exposure to Wrong Sphere     (STORAGE->EGRESS without AUTH)
 *   CWE-696  Incorrect Behavior Order              (TRANSFORM->CONTROL without META)
 *   CWE-732  Incorrect Permission Assignment       (TRANSFORM->STORAGE without CONTROL)
 *   CWE-770  Resource Allocation Without Limits    (INGRESS->STORAGE without CONTROL)
 *   CWE-778  Insufficient Logging                  (AUTH->META without META)
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl,
  hasPathWithoutIntermediateType, cweDomainMatchesSink,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Compact factory (same pattern as batch_015/016)
// ---------------------------------------------------------------------------

type BfsCheck = (map: NeuralMap, srcId: string, sinkId: string) => boolean;

function v(
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
        if (!cweDomainMatchesSink(cweId, sink)) continue;
        if (bfsCheck(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(sink),
              missing: missingDesc, severity,
              description: `${sourceType} at ${src.label} -> ${sinkType} at ${sink.label} without controls. Vulnerable to ${cweName}.`,
              fix: fixDesc,
            });
          }
        }
      }
    }
    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// BFS shortcuts
const nC: BfsCheck = hasTaintedPathWithoutControl;
const nA: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'AUTH');
const nM: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'META');
const nCi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'CONTROL');

// ===========================================================================
// CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
// Pattern: INGRESS[url_param] -> EGRESS[http_redirect] without CONTROL[url_allowlist]
// Severity: medium | OWASP A01:2021 | SANS Top 25
// ===========================================================================

// CWE-601: Open Redirect
// Hand-written: detects user-controlled URL parameters reaching redirect/location sinks
// without allowlist validation. Distinguishes relative-path (safe) from absolute URL
// (dangerous). Knows about res.redirect, Location header, window.location, meta refresh.
export const verifyCWE601 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];

  // Sources: user input that could contain URLs
  const urlInputs = nodesOfType(map, 'INGRESS').filter(n =>
    n.node_subtype.includes('query') || n.node_subtype.includes('param') ||
    n.node_subtype.includes('url') || n.node_subtype.includes('header') ||
    n.attack_surface.includes('user_input') || n.attack_surface.includes('url_input') ||
    n.code_snapshot.match(
      /\b(req\.query|req\.params|req\.body|request\.args|request\.form|request\.GET|searchParams|url|redirect|next|return_?to|goto|target|dest|forward|continue|callback)\b/i
    ) !== null
  );

  // Sinks: redirect operations
  const redirectSinks = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('redirect') || n.node_subtype.includes('location') ||
     n.attack_surface.includes('redirect') ||
     n.code_snapshot.match(
       /\b(res\.redirect|response\.redirect|redirect|Location\s*[=:]|window\.location|document\.location|meta.*refresh|header\s*\(\s*['"]Location)/i
     ) !== null)
  );

  // Safe patterns: allowlist check, relative-path enforcement, same-origin check
  const safeRedirect = (code: string): boolean =>
    /\ballowlist\b|\bwhitelist\b|\ballowed[_-]?(?:urls?|domains?|hosts?)\b/i.test(code) ||
    /\bstartsWith\s*\(\s*['"]\/[^\/]/i.test(code) ||         // starts with / but not //
    /\bnew URL\b.*\.(?:host|origin|hostname)\b/i.test(code) || // URL parsing + host check
    /\bsame[_-]?origin\b|\burl\.parse\b.*\bhost\b/i.test(code) ||
    /\brelative[_-]?path\b|\bpath\.resolve\b/i.test(code);

  for (const src of urlInputs) {
    for (const sink of redirectSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!safeRedirect(sink.code_snapshot) && !safeRedirect(src.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (URL allowlist or relative-path enforcement before redirect)',
            severity: 'medium',
            description: `User input from ${src.label} controls redirect destination at ${sink.label}. ` +
              `Attackers can craft URLs like ?next=https://evil.com to phish users via your domain.`,
            fix: 'Validate redirect URLs against an allowlist of trusted domains. ' +
              'Use relative paths only: if (!url.startsWith("/") || url.startsWith("//")) reject. ' +
              'Parse with new URL() and check .hostname against allowed origins.',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-601',
    name: 'URL Redirection to Untrusted Site (Open Redirect)',
    holds: findings.length === 0,
    findings,
  };
};

// ===========================================================================
// CWE-613: Insufficient Session Expiration
// Pattern: STORAGE[session] -> AUTH[session_check] without CONTROL[session_expiration]
// Severity: medium | OWASP A07:2021
// ===========================================================================

export const verifyCWE613 = v(
  'CWE-613',
  'Insufficient Session Expiration',
  'medium',
  'STORAGE', 'AUTH',
  nCi,
  /\bmaxAge\b|\bexpir\b|\bttl\b|\btimeout\b|\bidleTimeout\b|\babsoluteTimeout\b|\bsession.*destroy\b|\binvalidate\b/i,
  'CONTROL (session expiration and timeout enforcement)',
  'Set session idle timeout and absolute timeout. Invalidate sessions on logout. Use server-side session storage with TTL.',
);

// ===========================================================================
// CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
// Pattern: TRANSFORM[set_cookie] -> EGRESS[http_response] without CONTROL[secure_flag]
// Severity: medium | OWASP A05:2021
// ===========================================================================

export const verifyCWE614 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];
  const reported = new Set<string>();

  // --- Strategy 1: Graph-based (TRANSFORM -> EGRESS without CONTROL) ---
  const transforms = nodesOfType(map, 'TRANSFORM');
  const egresses = nodesOfType(map, 'EGRESS');
  const safePattern = /\bsecure\s*[=:]\s*true\b|\bSecure\b|\b__Secure-\b|\bcookie.*secure\b/i;
  for (const src of transforms) {
    for (const sink of egresses) {
      if (src.id === sink.id) continue;
      if (nC(map, src.id, sink.id)) {
        if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
          reported.add(src.id);
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (Secure attribute on sensitive cookies)',
            severity: 'medium',
            description: `TRANSFORM at ${src.label} -> EGRESS at ${sink.label} without controls. Vulnerable to Sensitive Cookie Without 'Secure' Attribute.`,
            fix: 'Set the Secure attribute on all sensitive cookies so they are only transmitted over HTTPS. Use __Secure- prefix where supported.',
          });
        }
      }
    }
  }

  // --- Strategy 2: Code snapshot scan for Java setSecure(false) pattern ---
  // Detects cookie.setSecure(false) which explicitly disables the Secure flag.
  // Also detects cookies created without any setSecure call (missing Secure flag).
  const SET_SECURE_FALSE = /\.setSecure\s*\(\s*false\s*\)/;
  const SET_SECURE_TRUE = /\.setSecure\s*\(\s*true\s*\)/;
  const COOKIE_CREATION = /new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(/;
  const ADD_COOKIE = /\.addCookie\s*\(/;

  for (const node of map.nodes) {
    if (reported.has(node.id)) continue;
    const snap = (node as any).analysis_snapshot || node.code_snapshot;
    // Explicit setSecure(false) — clear vulnerability
    if (SET_SECURE_FALSE.test(snap)) {
      reported.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (Secure attribute on sensitive cookies)',
        severity: 'medium',
        description: `${node.label} explicitly sets cookie Secure flag to false. ` +
          `The cookie will be sent over unencrypted HTTP connections, exposing it to interception.`,
        fix: 'Set cookie.setSecure(true) to ensure cookies are only transmitted over HTTPS.',
      });
    }
  }

  return {
    cwe: 'CWE-614',
    name: "Sensitive Cookie Without 'Secure' Attribute",
    holds: findings.length === 0,
    findings,
  };
};

// ===========================================================================
// CWE-668: Exposure of Resource to Wrong Sphere
// Pattern: STORAGE[protected_resource] -> EGRESS|EXTERNAL without AUTH|CONTROL[access_control]
// Severity: high | OWASP A01:2021
// ===========================================================================

export const verifyCWE668 = v(
  'CWE-668',
  'Exposure of Resource to Wrong Sphere',
  'high',
  'STORAGE', 'EGRESS',
  nA,
  /\bauthoriz\b|\baccess.*control\b|\bpermission\b|\brole\b|\bacl\b|\bprivate\b|\brestrict\b|\bcheckAccess\b/i,
  'AUTH (access control enforcing sphere boundaries)',
  'Enforce access control on all resources. Validate that the requesting actor belongs to the correct sphere before granting access.',
);

// ===========================================================================
// CWE-696: Incorrect Behavior Order
// Pattern: TRANSFORM -> CONTROL where canonicalization/normalization happens
//          after validation instead of before it
// Severity: medium
// ===========================================================================

export const verifyCWE696 = v(
  'CWE-696',
  'Incorrect Behavior Order',
  'medium',
  'TRANSFORM', 'CONTROL',
  nM,
  /\bcanonicalize.*then.*valid\b|\bnormalize.*before\b|\border.*enforc\b|\bpipeline\b|\bmiddleware.*order\b/i,
  'META (behavior ordering documentation and enforcement)',
  'Canonicalize and normalize input before validation. Authenticate before authorizing. Document and enforce operation ordering in middleware pipelines.',
);

// ===========================================================================
// CWE-732: Incorrect Permission Assignment for Critical Resource
// Pattern: TRANSFORM[resource_create|chmod] -> STORAGE[critical_resource]
//          without CONTROL[least_privilege_permissions]
// Severity: high | OWASP A01:2021 | SANS Top 25
// ===========================================================================

export const verifyCWE732 = v(
  'CWE-732',
  'Incorrect Permission Assignment for Critical Resource',
  'high',
  'TRANSFORM', 'STORAGE',
  nC,
  /\b0[0-7]{3}\b|\bchmod\b|\bchown\b|\bleast.*privilege\b|\bprivate\b|\breadonly\b|\b0600\b|\b0400\b|\bumask\b/i,
  'CONTROL (least-privilege permission enforcement)',
  'Apply least-privilege permissions to critical resources. Use restrictive defaults (0600 for files, 0700 for directories). Validate permissions after creation.',
);

// ===========================================================================
// CWE-770: Allocation of Resources Without Limits or Throttling
// Pattern: INGRESS -> TRANSFORM|STORAGE[resource_alloc] without CONTROL[quota|throttle]
// Severity: high | SANS Top 25
// ===========================================================================

export const verifyCWE770 = v(
  'CWE-770',
  'Allocation of Resources Without Limits or Throttling',
  'high',
  'INGRESS', 'STORAGE',
  nC,
  /\brateLimit\b|\bthrottle\b|\bquota\b|\bmaxSize\b|\bmaxCount\b|\bpool\b|\blimit\b|\bconcurrency\b/i,
  'CONTROL (resource allocation limits and throttling)',
  'Impose limits on resource allocation: max size, max count, per-user quotas, rate limiting, and connection pool bounds. Reject requests that exceed thresholds.',
);

// ===========================================================================
// CWE-778: Insufficient Logging
// Pattern: AUTH[security_event] -> processing without META[comprehensive_logging]
// Severity: medium | OWASP A09:2021
// ===========================================================================

export const verifyCWE778 = v(
  'CWE-778',
  'Insufficient Logging',
  'medium',
  'AUTH', 'META',
  nM,
  /\blog\b|\baudit\b|\brecord\b|\btrack\b|\bmonitor\b|\bjournal\b|\bevent.*log\b|\bsecurity.*log\b/i,
  'META (comprehensive security event logging)',
  'Log all security-critical events with who, what, when, where, and outcome. Include failed auth attempts, privilege changes, and access denials. Use structured logging.',
);

// ===========================================================================
// BATCH REGISTRY
// ===========================================================================

export const BATCH_020_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-601': verifyCWE601,
  'CWE-613': verifyCWE613,
  'CWE-614': verifyCWE614,
  'CWE-668': verifyCWE668,
  'CWE-696': verifyCWE696,
  'CWE-732': verifyCWE732,
  'CWE-770': verifyCWE770,
  'CWE-778': verifyCWE778,
};
