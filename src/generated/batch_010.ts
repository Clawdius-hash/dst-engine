/**
 * DST Generated Verifiers — Batch 010
 * Pattern shape: INGRESS→STORAGE without AUTH
 * 15 CWEs: authorization bypass, IDOR, access control, info exposure.
 *
 * User input reaches storage/resources without passing through an AUTH
 * node that verifies identity and permissions.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasPathWithoutIntermediateType,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hasPathWithoutAuth(map: NeuralMap, srcId: string, sinkId: string): boolean {
  return hasPathWithoutIntermediateType(map, srcId, sinkId, 'AUTH');
}

function storageNodes(map: NeuralMap): NeuralMapNode[] {
  return nodesOfType(map, 'STORAGE');
}

const AUTH_SAFE = /\bauthorize\b|\bhasPermission\b|\bcheckAccess\b|\brole\b|\bisOwner\b|\bRBAC\b|\bABAC\b|\bpolicy\b|\bisAuthorized\b|\bcanAccess\b|\bauth\b.*\bmiddleware\b/i;

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

function createAuthVerifier(
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
        if (hasPathWithoutAuth(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `Request from ${src.label} reaches ${sink.label} without authentication/authorization. ` +
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
// VERIFIERS (15 CWEs)
// ===========================================================================

export const verifyCWE285 = createAuthVerifier(
  'CWE-285', 'Improper Authorization', 'high',
  storageNodes, AUTH_SAFE,
  'AUTH (authorization check before resource access)',
  'Implement authorization checks on every request. Use RBAC or ABAC. ' +
    'Verify permissions server-side, not just in the UI.',
);

export const verifyCWE288 = createAuthVerifier(
  'CWE-288', 'Authentication Bypass Using an Alternate Path or Channel', 'critical',
  storageNodes, AUTH_SAFE,
  'AUTH (authentication on ALL paths — no alternate unauthenticated routes)',
  'Ensure authentication is enforced on all paths to protected resources. ' +
    'Check for alternate routes (direct API, debug endpoints, legacy paths) that bypass auth.',
);

export const verifyCWE305 = createAuthVerifier(
  'CWE-305', 'Authentication Bypass by Primary Weakness', 'critical',
  storageNodes, AUTH_SAFE,
  'AUTH (robust authentication mechanism)',
  'Use proven authentication mechanisms. Do not implement custom auth. ' +
    'Use established libraries (Passport.js, Spring Security, Auth0).',
);

export const verifyCWE420 = createAuthVerifier(
  'CWE-420', 'Unprotected Alternate Channel', 'high',
  storageNodes, AUTH_SAFE,
  'AUTH (authentication on alternate channels — APIs, WebSockets, debug ports)',
  'Apply authentication to all channels: REST APIs, GraphQL, WebSocket, gRPC, debug endpoints. ' +
    'A single unprotected channel compromises all protected ones.',
);

export const verifyCWE424 = createAuthVerifier(
  'CWE-424', 'Improper Protection of Alternate Path', 'high',
  storageNodes, AUTH_SAFE,
  'AUTH (protection of all access paths)',
  'Identify and protect all paths to sensitive resources. Use centralized auth middleware ' +
    'applied at the router level, not per-handler.',
);

export const verifyCWE425 = createAuthVerifier(
  'CWE-425', 'Direct Request (Forced Browsing)', 'high',
  storageNodes, AUTH_SAFE,
  'AUTH (access control on direct resource requests)',
  'Do not rely on navigation flow for access control. Every direct URL request must be ' +
    'independently authenticated and authorized. Use deny-by-default.',
);

export const verifyCWE527 = createAuthVerifier(
  'CWE-527', 'Exposure of Version-Control Repository to an Unauthorized Control Sphere', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.code_snapshot.match(/\b(\.git|\.svn|\.hg|\.bzr|CVS|\.env)\b/i) !== null ||
     n.node_subtype.includes('repository'))
  ),
  /\bdeny\b|\bblock\b|\b403\b|\b\.htaccess\b|\bnginx.*deny\b/i,
  'AUTH (block access to version control directories)',
  'Block web access to .git, .svn, .env and other VCS directories. ' +
    'Configure web server rules to return 403 for these paths.',
);

export const verifyCWE529 = createAuthVerifier(
  'CWE-529', 'Exposure of Access Control List Files to an Unauthorized Control Sphere', 'medium',
  storageNodes,
  /\bdeny\b|\bblock\b|\b403\b|\brestrict\b/i,
  'AUTH (block access to ACL configuration files)',
  'Restrict access to ACL and configuration files. Never serve them via the web server.',
);

export const verifyCWE530 = createAuthVerifier(
  'CWE-530', 'Exposure of Backup File to an Unauthorized Control Sphere', 'medium',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.code_snapshot.match(/\b(\.bak|\.old|\.backup|\.tmp|\.swp|~)\b/i) !== null ||
     n.node_subtype.includes('backup'))
  ),
  /\bdeny\b|\bblock\b|\b403\b|\bremove.*backup\b/i,
  'AUTH (block access to backup files)',
  'Remove or block access to backup files (.bak, .old, ~) in production. ' +
    'Configure web server to deny requests for backup file extensions.',
);

export const verifyCWE638 = createAuthVerifier(
  'CWE-638', 'Not Using Complete Mediation', 'high',
  storageNodes, AUTH_SAFE,
  'AUTH (complete mediation — check every access, not just first)',
  'Check authorization on every access, not just the initial one. ' +
    'Do not cache authorization decisions unless cache invalidation is guaranteed.',
);

/**
 * CWE-639: Authorization Bypass Through User-Controlled Key — IDOR / BOLA
 * (UPGRADED — hand-written quality)
 *
 * Detects when a user-supplied identifier (ID, key, filename) is used to
 * access a resource without verifying that the authenticated user is
 * authorized to access THAT SPECIFIC resource.
 *
 * This is distinct from CWE-285 (missing authorization entirely). IDOR means
 * authentication exists but object-level authorization is missing — the user
 * IS logged in, but can access other users' data by changing the ID.
 *
 * Dangerous patterns:
 *   - req.params.id used directly in DB lookup: findById(req.params.id)
 *   - req.query.userId → SELECT * FROM orders WHERE user_id = ?
 *   - req.body.fileId → fs.readFile(uploads/ + fileId)
 *   - Path parameter used in storage access without ownership check
 *
 * Safe patterns:
 *   - Scoped queries: findOne({ id: req.params.id, userId: req.user.id })
 *   - Ownership check: if (resource.userId !== req.user.id) return 403
 *   - belongsTo() / isOwner() / canAccess() authorization functions
 *   - Policy-based access: authorize(req.user, 'read', resource)
 *   - Row-level security in database (RLS)
 *
 * Key insight: the INGRESS provides a user-controlled key. The STORAGE
 * looks up a resource by that key. The question is: does ANY node between
 * them (or at the sink) verify ownership?
 */
export function verifyCWE639(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Storage nodes that look up resources by ID/key
  const lookupSinks = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('query') || n.node_subtype.includes('read') ||
     n.node_subtype.includes('lookup') || n.node_subtype.includes('find') ||
     n.code_snapshot.match(
       /\b(findById|findOne|findByPk|findUnique|getItem|getObject|get\s*\(|SELECT\b|readFile|download)\b/i
     ) !== null ||
     n.code_snapshot.match(
       /\b(where|filter|params|key|id)\b/i
     ) !== null)
  );

  // Only consider INGRESS nodes that carry user-controlled identifiers
  // (object keys like IDs, filenames, slugs — NOT search terms or free text)
  const idIngress = ingress.filter(n => {
    // Path/route parameters are almost always object identifiers
    const isPathParam = n.node_subtype.includes('param') || n.node_subtype.includes('path');

    // Request body with ID-like fields
    const isBodyId = n.node_subtype.includes('body') &&
      (n.code_snapshot.match(/\b(id|Id|ID|key|fileId|userId|docId|orderId)\b/) !== null ||
       n.data_out.some(d => /\bid\b|key|slug|filename/i.test(d.name)));

    // Query string with ID-like parameter names (not search/filter terms)
    const isQueryId = n.node_subtype === 'http_query' &&
      (n.code_snapshot.match(/\b(id|Id|ID|key|fileId|userId|docId)\b/) !== null ||
       n.data_out.some(d => /\bid\b|key|slug|filename/i.test(d.name)));

    // Code references req.params (strong signal for object identifier)
    const codeRefsParam = n.code_snapshot.match(
      /\b(req\.params|request\.param|args\.id|params\[|:id|:userId|:fileId)\b/i
    ) !== null;

    // Data output names suggest identifiers
    const dataIsId = n.data_out.some(d => /^(id|key|slug|filename|fileId|userId|docId|orderId)$/i.test(d.name));

    return isPathParam || isBodyId || isQueryId || codeRefsParam || dataIsId;
  });

  for (const src of idIngress) {
    for (const sink of lookupSinks) {
      if (hasPathWithoutAuth(map, src.id, sink.id)) {
        const sinkCode = sink.code_snapshot;
        const srcCode = src.code_snapshot;

        // Safe: scoped query includes the authenticated user's ID
        const scopedQuery = /\b(userId|user_id|owner_id|ownerId|createdBy|author_id)\b.*\b(req\.user|session\.user|currentUser|ctx\.user)\b/i.test(sinkCode) ||
          /\b(req\.user|session\.user|currentUser|ctx\.user)\b.*\b(userId|user_id|owner_id)\b/i.test(sinkCode);

        // Safe: explicit ownership check function
        const ownershipCheck = /\b(isOwner|belongsTo|canAccess|hasAccess|checkOwnership|authorize|isAuthorized)\s*\(/i.test(sinkCode);

        // Safe: policy / RBAC / ABAC check
        const policyCheck = /\b(policy|ability|casl|casbin|permit|rbac|abac)\b/i.test(sinkCode);

        // Safe: row-level security or scoped ORM
        const rowLevelSecurity = /\bRLS\b|\b\.scope\s*\(|\bwithUser\b|\bscopedTo\b|\bbelongsToMany.*through\b/i.test(sinkCode);

        // Also check upstream: is there a CONTROL or AUTH node in the path that checks ownership?
        const hasUpstreamAuth = map.nodes.some(n =>
          n.node_type === 'AUTH' &&
          /\b(isOwner|belongsTo|ownership|authorize|canAccess)\s*\(/i.test(n.code_snapshot)
        );

        const isSafe = scopedQuery || ownershipCheck || policyCheck || rowLevelSecurity || hasUpstreamAuth;

        if (!isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'AUTH (object-level authorization — verify the authenticated user owns or can access the specific resource identified by the user-supplied key)',
            severity: 'high',
            description: `User-controlled identifier from ${src.label} is used to access resource at ${sink.label} ` +
              `without verifying the authenticated user is authorized to access that specific object. ` +
              `An attacker can change the ID parameter to access other users' data (IDOR/BOLA).`,
            fix: 'Add object-level authorization. Scope queries to the authenticated user: ' +
              'db.findOne({ id: req.params.id, userId: req.user.id }) instead of db.findById(req.params.id). ' +
              'Alternatively, load the resource then check ownership: ' +
              'if (resource.userId !== req.user.id) return res.status(403). ' +
              'Use UUIDs instead of sequential IDs to reduce enumeration risk (but this is NOT a substitute for authorization).',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-639',
    name: 'Authorization Bypass Through User-Controlled Key (IDOR)',
    holds: findings.length === 0,
    findings,
  };
}

export const verifyCWE642 = createAuthVerifier(
  'CWE-642', 'External Control of Critical State Data', 'high',
  (map) => map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('state') || n.node_subtype.includes('session') ||
     n.node_subtype.includes('config') ||
     n.code_snapshot.match(/\b(state|session|config|role|permission|isAdmin|privilege)\b/i) !== null)
  ),
  AUTH_SAFE,
  'AUTH (protection of critical state — no external modification of auth state)',
  'Never allow external input to directly set critical state (roles, permissions, admin flags). ' +
    'Derive authorization state from server-side session, not client-supplied values.',
);

export const verifyCWE650 = createAuthVerifier(
  'CWE-650', 'Trusting HTTP Permission Methods on the Server Side', 'medium',
  storageNodes,
  /\bmethod\b.*\bcheck\b|\bOPTIONS\b|\ballow\b.*\bmethod\b|\bmethod.*restrict\b/i,
  'AUTH (HTTP method enforcement — do not trust client method declarations)',
  'Enforce allowed HTTP methods per endpoint. Do not allow arbitrary method override. ' +
    'Validate that the HTTP method matches the intended operation.',
);

export const verifyCWE654 = createAuthVerifier(
  'CWE-654', 'Reliance on a Single Factor in a Security Decision', 'medium',
  storageNodes,
  /\bmulti.*factor\b|\bMFA\b|\b2FA\b|\bsecond.*factor\b|\badditional.*check\b/i,
  'AUTH (multi-factor security decision — not relying on a single check)',
  'Do not rely on a single factor (IP address, cookie, referer) for security decisions. ' +
    'Use defense in depth with multiple independent checks.',
);

export const verifyCWE655 = createAuthVerifier(
  'CWE-655', 'Insufficient Psychological Acceptability', 'low',
  storageNodes,
  /\busable\b|\buser.*friendly\b|\baccessib\b/i,
  'AUTH (usable security — security mechanisms that users can follow correctly)',
  'Design security mechanisms that are easy to use correctly. Overly complex auth ' +
    'leads users to find workarounds that weaken security.',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_010_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-285': verifyCWE285,
  'CWE-288': verifyCWE288,
  'CWE-305': verifyCWE305,
  'CWE-420': verifyCWE420,
  'CWE-424': verifyCWE424,
  'CWE-425': verifyCWE425,
  'CWE-527': verifyCWE527,
  'CWE-529': verifyCWE529,
  'CWE-530': verifyCWE530,
  'CWE-638': verifyCWE638,
  'CWE-639': verifyCWE639,
  'CWE-642': verifyCWE642,
  'CWE-650': verifyCWE650,
  'CWE-654': verifyCWE654,
  'CWE-655': verifyCWE655,
};
