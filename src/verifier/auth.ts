/**
 * Auth & Access Control CWE Verifiers
 *
 * Authentication, authorization, privilege management, session handling,
 * certificate validation, CSRF, trust boundaries, channel security,
 * and access control bypass detection.
 *
 * These verifiers detect weaknesses in authentication mechanisms,
 * authorization enforcement, privilege escalation, session management,
 * and trust boundary violations. Many use BFS helpers
 * (hasTaintedPathWithoutAuth, hasTaintedPathWithoutControl, hasWebFrameworkContext)
 * imported from graph-helpers.ts.
 *
 * Extracted from verifier/index.ts -- Phase 5 of the monolith split.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments, resolveMapKeyTaint } from './source-analysis.ts';
import { FLOW_EDGE_TYPES, nodeRef, nodesOfType, isLibraryCode, hasWebFrameworkContext, hasTaintedPathWithoutControl, hasTaintedPathWithoutAuth, findContainingFunction, sharesFunctionScope, hasDeadBranchForNode, isLineInDeadBranchFunction } from './graph-helpers.ts';

// Satisfy TS -- FLOW_EDGE_TYPES is used in BFS within verifyCWE352
void FLOW_EDGE_TYPES;


// ---------------------------------------------------------------------------
// Access Control & Authentication Mechanisms
// ---------------------------------------------------------------------------

/**
 * CWE-306: Missing Authentication
 * Pattern: INGRESS → sensitive operation (STORAGE/EXTERNAL) without AUTH
 * Property: All sensitive operations are gated by authentication checks
 *
 * Similar to CONTROL-gating but checks specifically for AUTH nodes.
 */
function verifyCWE306(map: NeuralMap): VerificationResult {
  // Auth CWEs only apply to web/API code. Standalone utilities, console apps,
  // math operations, etc. have no expectation of authentication.
  if (!hasWebFrameworkContext(map)) {
    return { cwe: 'CWE-306', name: 'Missing Authentication', holds: true, findings: [] };
  }
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sensitive = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.attack_surface.includes('sensitive') || n.attack_surface.includes('admin') ||
     n.attack_surface.includes('write') || n.attack_surface.includes('delete') ||
     n.node_subtype.includes('write') || n.node_subtype.includes('delete') ||
     n.node_subtype.includes('admin') || n.node_subtype.includes('update') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(delete|remove|update|insert|drop|admin|modify|destroy)\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of sensitive) {
      if (hasTaintedPathWithoutAuth(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'AUTH (authentication check before sensitive operation)',
          severity: 'critical',
          description: `Request from ${src.label} reaches sensitive operation ${sink.label} without authentication. ` +
            `An unauthenticated attacker can perform privileged actions.`,
          fix: 'Add authentication middleware before sensitive routes. ' +
            'Use session tokens, JWTs, or API keys to verify identity. ' +
            'Example: app.delete("/users/:id", requireAuth, handler)',
          via: 'bfs',
        });
      }
    }
  }

  return {
    cwe: 'CWE-306',
    name: 'Missing Authentication',
    holds: findings.length === 0,
    findings,
  };
}


// ---------------------------------------------------------------------------
// Data Authenticity & Integrity Verification
// ---------------------------------------------------------------------------

/**
 * CWE-352: Cross-Site Request Forgery (CSRF)
 * Pattern: INGRESS → STORAGE(write) without CONTROL(csrf)
 * Property: All state-changing operations from user requests are protected by CSRF tokens
 */
function verifyCWE352(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Fix 2: Check for global CSRF middleware anywhere in the map
  const GLOBAL_CSRF_MW = /\bapp\.use\s*\(\s*(?:csrf|csurf)\s*\(|\bapp\.use\s*\(\s*(?:csrfProtection|csrfMiddleware)\b/i;
  const hasGlobalCsrfMiddleware = map.nodes.some(n => GLOBAL_CSRF_MW.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
  if (hasGlobalCsrfMiddleware) {
    return { cwe: 'CWE-352', name: 'Cross-Site Request Forgery (CSRF)', holds: true, findings };
  }

  // Fix 1: Broaden sink detection beyond raw SQL DML
  const STATE_CHANGE_PATTERN = /\b(transfer|delete|remove|update|create|send|pay|purchase|withdraw|admin)\b/i;
  const stateChanging = map.nodes.filter(n => {
    if (n.node_type === 'STORAGE') {
      if (n.node_subtype.includes('write') || n.node_subtype.includes('delete') ||
          n.node_subtype.includes('update') || n.node_subtype.includes('insert') ||
          n.node_subtype.includes('db_write') || n.node_subtype.includes('file_write') ||
          n.node_subtype.includes('cache_write') ||
          (n.analysis_snapshot || n.code_snapshot).match(/\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE)\b/i) !== null) {
        return true;
      }
    }
    if (n.node_type === 'EGRESS') {
      return true;
    }
    if (n.node_type === 'TRANSFORM' && STATE_CHANGE_PATTERN.test(n.label + ' ' + (n.analysis_snapshot || n.code_snapshot))) {
      return true;
    }
    return false;
  });

  // CSRF-specific CONTROL check: look for CONTROL nodes with csrf-related labels
  function hasCsrfControl(map: NeuralMap, sourceId: string, sinkId: string): boolean {
    const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
    const visited = new Set<string>();
    const queue: Array<{ nodeId: string; passedCsrf: boolean }> = [
      { nodeId: sourceId, passedCsrf: false },
    ];

    while (queue.length > 0) {
      const { nodeId, passedCsrf } = queue.shift()!;
      const visitKey = `${nodeId}:${passedCsrf}`;
      if (visited.has(visitKey)) continue;
      visited.add(visitKey);

      const node = nodeMap.get(nodeId);
      if (!node) continue;

      const isCsrf = node.node_type === 'CONTROL' &&
        (node.node_subtype.includes('csrf') || node.label.match(/csrf/i) !== null ||
         (node.analysis_snapshot || node.code_snapshot).match(/\bcsrf\b|\b_token\b|\bCSRFProtect\b|\bcsurf\b/i) !== null);
      const csrfNow = passedCsrf || isCsrf;

      if (nodeId === sinkId) {
        return csrfNow;
      }

      for (const edge of node.edges) {
        if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
        const edgeKey = `${edge.target}:${csrfNow}`;
        if (!visited.has(edgeKey)) {
          queue.push({ nodeId: edge.target, passedCsrf: csrfNow });
        }
      }
    }

    return false;
  }

  for (const src of ingress) {
    // Only check ingress from HTTP POST/PUT/DELETE (state-changing methods)
    const isStateChangingIngress = (src.analysis_snapshot || src.code_snapshot).match(
      /\b(post|put|delete|patch)\b/i
    ) !== null || src.node_subtype.includes('http');

    if (!isStateChangingIngress) continue;

    for (const sink of stateChanging) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) && !hasCsrfControl(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'CONTROL (CSRF token validation)',
          severity: 'high',
          description: `State-changing request from ${src.label} modifies data at ${sink.label} without CSRF protection. ` +
            `An attacker can forge requests from a victim's browser to perform unauthorized actions.`,
          fix: 'Add CSRF token validation middleware. Use csurf (Express), CSRFProtect (Flask), ' +
            'or framework-provided CSRF protection. Ensure all state-changing endpoints verify the token.',
          via: 'bfs',
        });
      }
    }
  }

  return {
    cwe: 'CWE-352',
    name: 'Cross-Site Request Forgery (CSRF)',
    holds: findings.length === 0,
    findings,
  };
}


// ---------------------------------------------------------------------------
// Session Management
// ---------------------------------------------------------------------------

/**
 * CWE-384: Session Fixation
 * Pattern: AUTH(login/authenticate) → STORAGE/EGRESS(session write/redirect) without
 *          TRANSFORM(session regeneration like req.session.regenerate)
 * When a user authenticates, the session ID should be regenerated to prevent
 * an attacker from fixing the session ID before authentication.
 */
function verifyCWE384(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Auth/login patterns - look for authentication actions
  // The BCRYPT_AUTH_RE covers cases where bcrypt.compareSync appears in a CONTROL
  // node (if-condition) rather than as a standalone AUTH node.
  const BCRYPT_AUTH_RE = /\bbcrypt\.(compare|compareSync|hash|hashSync)\b/i;
  const authNodes = map.nodes.filter(n =>
    (n.node_type === 'AUTH' ||
     // Also check STRUCTURAL nodes that define login/auth routes
     (n.node_type === 'STRUCTURAL' && n.node_subtype === 'route') ||
     // CONTROL nodes that contain bcrypt auth checks (bcrypt.compareSync in if-condition)
     (n.node_type === 'CONTROL' && BCRYPT_AUTH_RE.test(n.analysis_snapshot || n.code_snapshot))) &&
    (n.analysis_snapshot || n.code_snapshot).match(/\b(login|authenticate|passport\.authenticate|sign\s*in|logIn|createSession|doLogin|bcrypt\.compare|bcrypt\.compareSync)\b/i) !== null
  );

  // Also check for direct passport strategy patterns
  const passportStrategies = map.nodes.filter(n =>
    (n.analysis_snapshot || n.code_snapshot).match(/\bpassport\.use\s*\(\s*['"]login['"]/i) !== null ||
    (n.analysis_snapshot || n.code_snapshot).match(/\bLocalStrategy\b/i) !== null ||
    (n.analysis_snapshot || n.code_snapshot).match(/\bdone\s*\(\s*null\s*,\s*user\b/i) !== null
  );

  // Session regeneration patterns — must match actual regeneration calls, not words like
  // "regenerated" in comments. Use \b on both sides of the root word.
  const sessionRegenPattern = /\bregenerate\s*\(|\bsession\.regenerate\b|\breq\.session\.regenerate\b|\bsession\.destroy\b|\brotateSession\b|\bnewSession\b|\breq\.session\.destroy\s*\(\s*\)\s*.*session/i;

  // Check if there are auth nodes but no session regeneration anywhere in the map
  const allAuthNodes = [...authNodes, ...passportStrategies];

  if (allAuthNodes.length > 0) {
    // Check if session regeneration exists anywhere in the graph
    const hasSessionRegen = map.nodes.some(n =>
      sessionRegenPattern.test(n.analysis_snapshot || n.code_snapshot)
    );

    if (!hasSessionRegen) {
      // Authentication happens but no session regeneration found
      // SUCCESS_PATH_RE: patterns that indicate a successful login completes
      const SUCCESS_PATH_RE = /\bdone\s*\(\s*null\s*,\s*user\b|\bres\.\s*(redirect|json|send)\b|\breq\.login\b|\breq\.logIn\b|\bpassport\.authenticate\b|\breq\.session\.\w+\s*=/i;
      for (const authNode of allAuthNodes) {
        // Check if this auth node (or any node in the same function scope) leads to a successful login
        const hasSuccessPath = SUCCESS_PATH_RE.test(authNode.analysis_snapshot || authNode.code_snapshot) ||
          map.nodes.some(n =>
            n.line_start >= authNode.line_start &&
            n.line_start <= authNode.line_start + 30 &&
            SUCCESS_PATH_RE.test(n.analysis_snapshot || n.code_snapshot)
          );

        if (hasSuccessPath) {
          // Build a reasonable sink - find the closest session/redirect action
          const loginSuccess = map.nodes.find(n =>
            n.line_start >= authNode.line_start &&
            (n.analysis_snapshot || n.code_snapshot).match(/\bdone\s*\(\s*null\s*,\s*user\b|\bres\.\s*(redirect|json|send)\b|\breq\.session\.\w+\s*=/i) !== null
          ) ?? authNode;

          findings.push({
            source: nodeRef(authNode),
            sink: nodeRef(loginSuccess),
            missing: 'TRANSFORM (session ID regeneration after authentication)',
            severity: 'high',
            description: `Authentication at ${authNode.label} succeeds without regenerating the session ID. ` +
              `An attacker who knows or sets the session ID before login can hijack the authenticated session.`,
            fix: 'Call req.session.regenerate() after successful authentication. ' +
              'This creates a new session ID while preserving session data. ' +
              'Example: req.session.regenerate((err) => { req.session.userId = user.id; ... }). ' +
              'For Passport.js, add session regeneration in the login callback.',
            via: 'structural',
          });
          break; // One finding per auth flow is sufficient
        }
      }
    }
  }

  return {
    cwe: 'CWE-384',
    name: 'Session Fixation',
    holds: findings.length === 0,
    findings,
  };
}


// ---------------------------------------------------------------------------
// Access Control & Authentication Mechanisms
// ---------------------------------------------------------------------------

/**
 * CWE-287: Improper Authentication
 * Pattern: INGRESS → sensitive STORAGE/EXTERNAL without AUTH node in path
 * Property: All sensitive operations are gated by proper authentication checks.
 *
 * Unlike CWE-306 (Missing Authentication for Critical Function), CWE-287 is broader:
 * it covers cases where authentication exists but is IMPROPERLY implemented —
 * e.g., checking username but not password, using client-side auth only,
 * or accepting self-signed identity tokens without server-side validation.
 *
 * Detection strategy:
 *  1. Find INGRESS → sensitive sinks without ANY auth node
 *  2. Find AUTH nodes that use weak/improper patterns (client-only checks, always-true)
 */
function verifyCWE287(map: NeuralMap): VerificationResult {
  // Auth CWEs only apply to web/API code. Standalone utilities, console apps,
  // math operations, etc. have no expectation of authentication.
  if (!hasWebFrameworkContext(map)) {
    return { cwe: 'CWE-287', name: 'Improper Authentication', holds: true, findings: [] };
  }
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const authNodes = nodesOfType(map, 'AUTH');

  // Auth middleware patterns in source code_snapshot — if present, the route is protected
  // even if there's no explicit AUTH node in the graph (middleware runs before handler).
  const authMiddlewarePattern = /\b(passport\.authenticate|requireAuth|isAuthenticated|ensureAuthenticated|authMiddleware|verifyToken|requireLogin|checkAuth|jwt\.verify|authGuard)\b/i;

  // Sensitive operations: STORAGE (including database reads with protected_resource),
  // EXTERNAL calls, admin endpoints, writes, deletes
  const sensitiveSinks = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('write') || n.node_subtype.includes('delete') ||
     n.node_subtype.includes('update') || n.node_subtype.includes('admin') ||
     n.node_subtype.includes('db_write') || n.node_subtype.includes('database') ||
     n.attack_surface.includes('sensitive') || n.attack_surface.includes('admin') ||
     n.attack_surface.includes('protected_resource') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(delete|remove|update|insert|drop|admin|modify|destroy|grant|revoke|createUser|changeRole|findOne|find|query)\b/i) !== null)
  );

  // Strategy 1: INGRESS → sensitive sink with NO auth node in the path
  for (const src of ingress) {
    // Skip if the source code_snapshot references auth middleware (route-level protection)
    if (authMiddlewarePattern.test(src.analysis_snapshot || src.code_snapshot)) continue;

    for (const sink of sensitiveSinks) {
      if (hasTaintedPathWithoutAuth(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'AUTH (proper authentication check before sensitive operation)',
          severity: 'critical',
          description: `Request from ${src.label} reaches sensitive operation ${sink.label} without authentication. ` +
            `Any unauthenticated user can perform this action.`,
          fix: 'Add server-side authentication middleware that validates credentials or session tokens. ' +
            'Use established libraries (passport.js, flask-login, Spring Security). ' +
            'Never rely on client-side authentication checks alone.',
          via: 'bfs',
        });
      }
    }
  }

  // Strategy 2: AUTH nodes with improper implementation
  const weakAuthPatterns = [
    /\btrue\b\s*;\s*$/m,                      // always returns true
    /return\s+true/i,                           // unconditional return true in auth
    /isAdmin\s*[:=]\s*req\.(body|query|params)/i, // role from user input
    /role\s*[:=]\s*req\.(body|query)/i,         // role assignment from request body
    /if\s*\(\s*username\s*\)\s*\{/i,            // checks username exists but not password
    /auth.*skip|bypass.*auth|disable.*auth/i,   // explicit auth bypass
  ];

  for (const authNode of authNodes) {
    const code = stripComments(authNode.analysis_snapshot || authNode.code_snapshot);
    for (const pattern of weakAuthPatterns) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(authNode),
          sink: nodeRef(authNode),
          missing: 'AUTH (proper credential validation — current check is weak or bypassable)',
          severity: 'critical',
          description: `Authentication at ${authNode.label} uses an improper pattern that can be bypassed. ` +
            `The auth check appears to always succeed, check only partial credentials, or accept user-controlled role claims.`,
          fix: 'Implement proper authentication: validate both username AND password against a secure store. ' +
            'Never derive authorization roles from user input. ' +
            'Never hardcode auth bypasses in production code.',
          via: 'structural',
        });
        break;
      }
    }
  }

  return {
    cwe: 'CWE-287',
    name: 'Improper Authentication',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-288: Authentication Bypass Using an Alternate Path or Channel
 * Pattern: Multiple INGRESS nodes reach the same sensitive sink, but only SOME paths
 *          have AUTH nodes — at least one alternate path bypasses auth entirely.
 *
 * Classic examples: admin panel accessible via /admin AND /api/admin (API lacks auth),
 * debug endpoints that skip auth, alternative protocols (HTTP vs WebSocket).
 *
 * Detection: For each sensitive sink reachable via an authenticated path,
 * check if ANY other INGRESS can reach the same sink WITHOUT auth.
 */
function verifyCWE288(map: NeuralMap): VerificationResult {
  // Auth bypass via alternate path only applies to web/API code.
  if (!hasWebFrameworkContext(map)) {
    return { cwe: 'CWE-288', name: 'Authentication Bypass Using an Alternate Path or Channel', holds: true, findings: [] };
  }
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const sensitiveSinks = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('write') || n.node_subtype.includes('delete') ||
     n.node_subtype.includes('update') || n.node_subtype.includes('admin') ||
     n.attack_surface.includes('sensitive') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(delete|remove|update|insert|admin|modify|destroy)\b/i) !== null)
  );

  // Alternate path patterns: debug routes, internal APIs, websockets
  const altPathPattern = /\b(debug|internal|_internal|test|backdoor|ws:\/\/|websocket|socket\.on|graphql|grpc)\b/i;

  for (const sink of sensitiveSinks) {
    // Find all INGRESS nodes that can reach this sink
    const authedPaths: NeuralMapNode[] = [];
    const unauthedPaths: NeuralMapNode[] = [];

    for (const src of ingress) {
      // Check if there is an unauthed taint path
      if (hasTaintedPathWithoutAuth(map, src.id, sink.id)) {
        unauthedPaths.push(src);
      } else {
        // Check if there is ANY taint path (which means it exists but goes through AUTH)
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          authedPaths.push(src);
        }
      }
    }

    // CWE-288 fires when SOME paths are authed but OTHERS are not
    if (authedPaths.length > 0 && unauthedPaths.length > 0) {
      for (const bypass of unauthedPaths) {
        findings.push({
          source: nodeRef(bypass),
          sink: nodeRef(sink),
          missing: 'AUTH (authentication on alternate path — other paths to the same sink ARE authenticated)',
          severity: 'critical',
          description: `${bypass.label} can reach ${sink.label} without authentication, but other paths to the same operation require auth. ` +
            `An attacker can bypass authentication by using the unprotected alternate path.`,
          fix: 'Ensure ALL paths to sensitive operations require authentication. ' +
            'Apply auth middleware at the operation/service layer, not just at individual routes. ' +
            'Audit debug endpoints, internal APIs, WebSocket handlers, and GraphQL resolvers.',
          via: 'bfs',
        });
      }
    }

    // Also flag INGRESS nodes with alt-path patterns that reach sinks without auth
    if (authedPaths.length === 0 && unauthedPaths.length > 0) {
      for (const bypass of unauthedPaths) {
        if (altPathPattern.test(bypass.analysis_snapshot || bypass.code_snapshot) || altPathPattern.test(bypass.label)) {
          findings.push({
            source: nodeRef(bypass),
            sink: nodeRef(sink),
            missing: 'AUTH (authentication on debug/internal/alternate endpoint)',
            severity: 'high',
            description: `Alternate endpoint ${bypass.label} (debug/internal/websocket) reaches ${sink.label} without authentication. ` +
              `These alternate channels are often deployed to production without auth.`,
            fix: 'Remove debug/test endpoints from production builds. ' +
              'If internal APIs must exist, protect them with the same auth as primary endpoints. ' +
              'Use environment-based feature flags to disable debug routes.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-288',
    name: 'Authentication Bypass Using Alternate Path or Channel',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-290: Authentication Bypass by Spoofing
 * Pattern: AUTH or CONTROL nodes that make decisions based on spoofable inputs:
 *          IP addresses (X-Forwarded-For, REMOTE_ADDR behind proxies),
 *          DNS names, Referer headers, or client-side cookies without HMAC.
 *
 * Detection: Scan AUTH/CONTROL nodes for spoofable-source patterns in code_snapshot.
 */
function verifyCWE290(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Spoofable source patterns in code — these are NOT reliable for authentication
  const spoofablePatterns: Array<{ pattern: RegExp; desc: string }> = [
    {
      pattern: /\b(x[_-]forwarded[_-]for|x[_-]real[_-]ip|x[_-]client[_-]ip|cf[_-]connecting[_-]ip)\b/i,
      desc: 'IP address from X-Forwarded-For/X-Real-IP header (trivially spoofable)',
    },
    {
      pattern: /\bremote[_-]?addr\b.*\b(auth|allow|trust|whitelist|grant)\b|\b(auth|allow|trust|whitelist|grant)\b.*\bremote[_-]?addr\b/i,
      desc: 'IP-based authentication (spoofable behind proxies, NAT)',
    },
    {
      pattern: /\b(referer|referrer)\b.*\b(check|verify|auth|valid|allow)\b|\b(check|verify|auth|valid|allow)\b.*\b(referer|referrer)\b/i,
      desc: 'Referer header-based authentication (trivially spoofable)',
    },
    {
      pattern: /\b(dns[_-]?lookup|reverse[_-]?dns|gethostbyaddr|gethostbyname)\b.*\b(auth|trust|allow)\b/i,
      desc: 'DNS-based authentication (spoofable via DNS poisoning)',
    },
    {
      pattern: /\b(origin)\b\s*===?\s*['"][^'"]+['"]/i,
      desc: 'Origin header comparison for authentication (can be spoofed in non-browser contexts)',
    },
  ];

  // Check AUTH and CONTROL nodes for spoofable source usage
  const authAndControl = map.nodes.filter(n =>
    n.node_type === 'AUTH' || n.node_type === 'CONTROL'
  );

  for (const node of authAndControl) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const { pattern, desc } of spoofablePatterns) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'AUTH (non-spoofable authentication mechanism — use cryptographic tokens instead of network metadata)',
          severity: 'high',
          description: `${node.label} uses ${desc} for security decisions. ` +
            `These values are controlled by the client or intermediary proxies and can be forged.`,
          fix: 'Never use IP addresses, DNS names, Referer headers, or Origin headers as the sole authentication mechanism. ' +
            'Use cryptographic tokens (JWT, session cookies with HMAC, mutual TLS) for identity verification. ' +
            'IP-based restrictions are acceptable as ADDITIONAL defense-in-depth but never as primary auth.',
          via: 'structural',
        });
        break;
      }
    }
  }

  // Also check INGRESS nodes that read spoofable headers and flow to AUTH
  const spoofableIngress = map.nodes.filter(n =>
    n.node_type === 'INGRESS' &&
    /\b(x[_-]forwarded[_-]for|x[_-]real[_-]ip|referer|referrer|remote[_-]?addr)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const src of spoofableIngress) {
    for (const authNode of authAndControl) {
      if (hasTaintedPathWithoutControl(map, src.id, authNode.id)) {
        // The spoofable header flows into an auth decision without validation
        const hasIntegrityCheck = stripComments(authNode.analysis_snapshot || authNode.code_snapshot).match(
          /\bhmac\b|\bsignature\b|\bcryptographic\b|\bjwt\b|\bverify\s*\(.*\btoken\b|\bverifyToken\b/i
        ) !== null;

        if (!hasIntegrityCheck) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(authNode),
            missing: 'AUTH (cryptographic identity verification instead of spoofable header)',
            severity: 'high',
            description: `Spoofable header from ${src.label} flows to auth decision at ${authNode.label}. ` +
              `An attacker can forge this header to bypass authentication.`,
            fix: 'Replace header-based auth with cryptographic authentication (JWT, session tokens, mutual TLS). ' +
              'If IP-based restrictions are needed, enforce them at the network/firewall level, not in application code.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-290',
    name: 'Authentication Bypass by Spoofing',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-294: Authentication Bypass by Capture-Replay
 * Pattern: AUTH nodes that use static tokens, single-use tokens reused,
 *          or authentication without nonce/timestamp/challenge-response.
 *
 * Detection: Find AUTH nodes that validate tokens/credentials without
 * replay protection (no nonce, no timestamp check, no TOTP/HOTP).
 * Also flags: session tokens sent over non-HTTPS, no token expiry.
 */
function verifyCWE294(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const authNodes = nodesOfType(map, 'AUTH');

  // Replay protection patterns — if present, the auth is likely protected
  const replayProtectionPattern = /\b(nonce|timestamp|exp|expires|expiresIn|maxAge|ttl|totp|hotp|challenge|one[_-]?time|otp|replay[_-]?check|used[_-]?tokens?|token[_-]?blacklist|jti)\b/i;

  // Static/hardcoded token patterns that are vulnerable to replay
  const staticTokenPatterns = [
    /api[_-]?key\s*===?\s*['"][^'"]+['"]/i,      // hardcoded API key comparison
    /token\s*===?\s*['"][^'"]+['"]/i,              // hardcoded token comparison
    /secret\s*===?\s*['"][^'"]+['"]/i,             // hardcoded secret comparison
    /\b(compare|equals)\s*\(\s*['"][^'"]{8,}['"]/i, // comparing against static string
  ];

  for (const authNode of authNodes) {
    const code = stripComments(authNode.analysis_snapshot || authNode.code_snapshot);

    // Check for static token comparison (most obvious replay vulnerability)
    for (const pattern of staticTokenPatterns) {
      if (pattern.test(code)) {
        // Only flag if there's no replay protection
        if (!replayProtectionPattern.test(code)) {
          findings.push({
            source: nodeRef(authNode),
            sink: nodeRef(authNode),
            missing: 'AUTH (replay protection — nonce, timestamp, or one-time token)',
            severity: 'high',
            description: `Authentication at ${authNode.label} compares against a static token without replay protection. ` +
              `An attacker who captures this token (via network sniffing, logs, or client-side inspection) can reuse it indefinitely.`,
            fix: 'Use time-limited tokens with expiry (JWT with exp claim). ' +
              'Add nonce or challenge-response to prevent replay. ' +
              'Rotate API keys regularly. Use HTTPS to prevent capture.',
            via: 'structural',
          });
          break;
        }
      }
    }

    // Check for basic auth without TLS indication in the same scope
    if (/\b(basic[_-]?auth|authorization.*basic|atob|base64decode)\b/i.test(code)) {
      if (!replayProtectionPattern.test(code)) {
        findings.push({
          source: nodeRef(authNode),
          sink: nodeRef(authNode),
          missing: 'AUTH (replay protection for Basic Auth — credentials are sent in cleartext per request)',
          severity: 'medium',
          description: `${authNode.label} uses HTTP Basic Authentication. ` +
            `Credentials are base64-encoded (NOT encrypted) and sent with every request, making capture-replay trivial without HTTPS.`,
          fix: 'If Basic Auth is required, ensure HTTPS is enforced (redirect HTTP to HTTPS). ' +
            'Prefer token-based authentication (JWT, OAuth2) with expiry. ' +
            'Add rate limiting to slow brute-force attacks with captured credentials.',
          via: 'structural',
        });
      }
    }
  }

  return {
    cwe: 'CWE-294',
    name: 'Authentication Bypass by Capture-Replay',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-295: Improper Certificate Validation
 * Pattern: EXTERNAL (HTTP/TLS) nodes where certificate validation is explicitly disabled.
 *          e.g., rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0,
 *          verify=False (Python requests), InsecureSkipVerify: true (Go),
 *          -k / --insecure (curl).
 *
 * Detection: Scan ALL nodes for certificate-disabling patterns in code_snapshot.
 * Unlike flow-based CWEs, this is a static configuration scan.
 */
function verifyCWE295(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns that DISABLE certificate validation — language-specific
  const certDisablePatterns: Array<{ pattern: RegExp; lang: string; desc: string }> = [
    {
      pattern: /rejectUnauthorized\s*:\s*false/i,
      lang: 'Node.js',
      desc: 'rejectUnauthorized: false disables TLS certificate validation',
    },
    {
      pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/i,
      lang: 'Node.js',
      desc: 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables ALL TLS validation globally',
    },
    {
      pattern: /process\.env\s*\[\s*['"]NODE_TLS_REJECT_UNAUTHORIZED['"]\s*\]\s*=\s*['"]?0/i,
      lang: 'Node.js',
      desc: 'Programmatic global TLS disable via process.env',
    },
    {
      pattern: /verify\s*=\s*False/,
      lang: 'Python',
      desc: 'requests.get(url, verify=False) disables certificate verification',
    },
    {
      pattern: /CERT_NONE|ssl\._create_unverified_context|check_hostname\s*=\s*False/i,
      lang: 'Python',
      desc: 'SSL context with certificate verification disabled',
    },
    {
      pattern: /InsecureSkipVerify\s*:\s*true/i,
      lang: 'Go',
      desc: 'InsecureSkipVerify: true disables TLS certificate validation',
    },
    {
      pattern: /curl\b.*\s-k\b|curl\b.*--insecure/i,
      lang: 'Shell/curl',
      desc: 'curl --insecure / -k disables certificate validation',
    },
    {
      pattern: /CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0|FALSE)/i,
      lang: 'PHP/C',
      desc: 'CURLOPT_SSL_VERIFYPEER disabled',
    },
    {
      pattern: /ServerCertificateValidationCallback\s*=.*=>\s*true|ServicePointManager\.ServerCertificateValidationCallback/i,
      lang: '.NET',
      desc: 'ServerCertificateValidationCallback always returns true',
    },
    {
      pattern: /\.danger_accept_invalid_certs\s*\(\s*true\s*\)/i,
      lang: 'Rust',
      desc: 'danger_accept_invalid_certs(true) disables cert validation',
    },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const { pattern, lang, desc } of certDisablePatterns) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (TLS certificate validation — currently disabled)',
          severity: 'critical',
          description: `${node.label} disables certificate validation [${lang}]: ${desc}. ` +
            `This allows man-in-the-middle attacks — an attacker on the network can intercept, read, and modify all traffic.`,
          fix: 'NEVER disable certificate validation in production. ' +
            'If connecting to services with self-signed certs, add the CA to the trust store instead. ' +
            'For development, use environment-specific configuration that is NEVER deployed to production.',
          via: 'structural',
        });
        break;
      }
    }
  }

  return {
    cwe: 'CWE-295',
    name: 'Improper Certificate Validation',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-296: Improper Following of a Certificate's Chain of Trust
 * Pattern: TLS/SSL configuration that doesn't validate the full certificate chain.
 *          e.g., custom SSL contexts that skip chain verification, accepting self-signed
 *          certs without pinning, custom trust managers that accept all certificates.
 *
 * Detection: Scan for custom TLS/SSL context creation that skips chain validation.
 */
function verifyCWE296(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns that break the chain of trust
  const chainBreakPatterns: Array<{ pattern: RegExp; desc: string }> = [
    {
      pattern: /TrustManager|X509TrustManager|checkServerTrusted\s*\([^)]*\)\s*\{[\s\S]{0,20}\}/i,
      desc: 'Custom TrustManager that may accept all certificates without chain validation',
    },
    {
      pattern: /SSLContext\.getInstance.*\btrust.*=.*new\b.*TrustManager/i,
      desc: 'Custom SSLContext with custom TrustManager (potentially bypasses chain validation)',
    },
    {
      pattern: /createSSLContext|ssl\.create_default_context.*\bload_default_certs\s*=\s*False/i,
      desc: 'Custom SSL context that skips loading default CA certificates',
    },
    {
      pattern: /ca\s*:\s*\[\s*\]|ca\s*:\s*undefined|ca\s*:\s*null/i,
      desc: 'Empty or null CA list — no chain of trust can be established',
    },
    {
      pattern: /setDefaultSSLSocketFactory|AllowAllHostnameVerifier|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER/i,
      desc: 'Hostname verifier that accepts all hostnames regardless of certificate CN/SAN',
    },
    {
      pattern: /\.selfSigned\s*\(\s*true\s*\)|self[_-]?signed\s*[:=]\s*true/i,
      desc: 'Explicitly accepting self-signed certificates without pinning',
    },
    {
      pattern: /checkRevocation\s*[:=]\s*false|enableOCSP\s*[:=]\s*false|disableCRL/i,
      desc: 'Revocation checking disabled — cannot detect compromised certificates',
    },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const { pattern, desc } of chainBreakPatterns) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (proper certificate chain validation using system CA store)',
          severity: 'high',
          description: `${node.label}: ${desc}. ` +
            `Without full chain-of-trust validation, the application cannot verify the identity of remote servers, ` +
            `enabling man-in-the-middle attacks.`,
          fix: 'Use the system CA certificate store for chain validation. ' +
            'Do not implement custom TrustManagers unless you are adding certificate pinning. ' +
            'If self-signed certs are needed, add the specific CA to the trust store rather than disabling chain validation. ' +
            'Enable OCSP/CRL checking for revocation detection.',
          via: 'structural',
        });
        break;
      }
    }
  }

  return {
    cwe: 'CWE-296',
    name: 'Improper Following of Chain of Trust',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-297: Improper Validation of Certificate with Host Mismatch
 * Pattern: TLS connections where hostname verification is disabled or overridden.
 *          A valid certificate for evil.com could be presented for bank.com if
 *          hostname matching is skipped.
 *
 * Detection: Scan for hostname verification disabling patterns.
 */
function verifyCWE297(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const hostMismatchPatterns: Array<{ pattern: RegExp; desc: string }> = [
    {
      pattern: /checkServerIdentity\s*:\s*\(\s*\)\s*=>|checkServerIdentity\s*:\s*function\s*\(\s*\)\s*\{/i,
      desc: 'Node.js checkServerIdentity overridden with no-op function — hostname matching disabled',
    },
    {
      pattern: /AllowAllHostnameVerifier|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER/i,
      desc: 'Java/Android hostname verifier accepts all hostnames',
    },
    {
      pattern: /check_hostname\s*=\s*False/i,
      desc: 'Python SSL check_hostname disabled — any certificate accepted regardless of hostname',
    },
    {
      pattern: /HostnameVerifier\s*\(\s*\)\s*\{[^}]*return\s+true/i,
      desc: 'Custom HostnameVerifier that always returns true',
    },
    {
      pattern: /verify_peer_name\s*[:=]\s*false|ssl_verify_host\s*[:=]\s*0/i,
      desc: 'Peer name verification disabled',
    },
    {
      pattern: /ServerName\s*[:=]\s*['"]['"]|servername\s*:\s*['"]['"]|sni\s*[:=]\s*false/i,
      desc: 'Empty ServerName / SNI disabled — server cannot select the correct certificate',
    },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const { pattern, desc } of hostMismatchPatterns) {
      if (pattern.test(code)) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (TLS hostname verification — ensure certificate matches the requested host)',
          severity: 'high',
          description: `${node.label}: ${desc}. ` +
            `Without hostname verification, a valid certificate for any domain will be accepted, ` +
            `enabling man-in-the-middle attacks with a legitimately-issued certificate.`,
          fix: 'Never disable hostname verification. Use the default TLS configuration which includes hostname checking. ' +
            'If custom TLS setup is needed, ensure checkServerIdentity (Node.js) or check_hostname (Python) remains enabled. ' +
            'For Java, use the default HostnameVerifier, never AllowAllHostnameVerifier.',
          via: 'structural',
        });
        break;
      }
    }
  }

  return {
    cwe: 'CWE-297',
    name: 'Improper Validation of Certificate with Host Mismatch',
    holds: findings.length === 0,
    findings,
  };
}


// ---------------------------------------------------------------------------
// Credential & Cookie Security
// ---------------------------------------------------------------------------

/**
 * CWE-521: Weak Password Requirements
 * Pattern: AUTH/CONTROL nodes that validate passwords with insufficient constraints.
 *          e.g., minimum length < 8, no complexity requirements, no check against
 *          breached password lists.
 *
 * Also detects: password fields with no validation at all (INGRESS->STORAGE direct).
 *
 * Detection:
 *  1. Find password validation nodes and check if constraints are too weak
 *  2. Find password storage paths with no validation
 */
function verifyCWE521(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Find password-related nodes
  const passwordNodes = map.nodes.filter(n =>
    /\b(password|passwd|pwd|passphrase)\b/i.test(n.analysis_snapshot || n.code_snapshot) ||
    /\b(password|passwd|pwd)\b/i.test(n.label)
  );

  // Weak length patterns — min length below 8
  // Note: The first alternative requires a password-related identifier before .length
  // to avoid false positives from array-length checks like tokens.length < 2 in non-password contexts.
  const weakLengthPattern = /\b(?:password|passwd|pwd|passphrase|pass)\w*\.(length|len)\s*(<|<=|>=?|==)\s*[1-7]\b|minlength\s*[:=]\s*[1-7]\b|min\s*[:=]\s*[1-7]\b.*password|password.*min\s*[:=]\s*[1-7]\b/i;

  // Good password validation patterns
  const strongPasswordPattern = /\b(minlength|min[_-]?length)\s*[:=]\s*([89]|\d{2,})\b|\.(length|len)\s*>=?\s*([89]|\d{2,})\b|\b(zxcvbn|haveibeenpwned|breach|complexity|strength)\b/i;

  // Registration/signup patterns — password is being SET (not just checked)
  const passwordSetPattern = /\b(register|signup|sign[_-]?up|create[_-]?user|new[_-]?password|change[_-]?password|reset[_-]?password|set[_-]?password)\b/i;

  for (const node of passwordNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for explicitly weak length requirements
    if (weakLengthPattern.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (password length requirement >= 8 characters, ideally >= 12)',
        severity: 'medium',
        description: `${node.label} enforces a password length below 8 characters. ` +
          `Short passwords are vulnerable to brute-force and dictionary attacks.`,
        fix: 'Require passwords of at least 8 characters (NIST SP 800-63B recommends 8+, 12+ is better). ' +
          'Use a password strength estimator (zxcvbn). ' +
          'Check passwords against known breached password lists (HaveIBeenPwned API).',
        via: 'structural',
      });
      continue;
    }

    // Check for password storage without ANY validation
    if (passwordSetPattern.test(code) && node.node_type === 'INGRESS') {
      // Find if this password flows to STORAGE without a CONTROL node
      const storageSinks = nodesOfType(map, 'STORAGE');
      for (const sink of storageSinks) {
        if (hasTaintedPathWithoutControl(map, node.id, sink.id)) {
          // No CONTROL between password input and storage — no validation at all
          if (!strongPasswordPattern.test(code)) {
            findings.push({
              source: nodeRef(node),
              sink: nodeRef(sink),
              missing: 'CONTROL (password strength validation before storage)',
              severity: 'medium',
              description: `Password from ${node.label} is stored at ${sink.label} without strength validation. ` +
                `Users can set arbitrarily weak passwords (including empty or single-character).`,
              fix: 'Add password validation before storage: minimum 8 characters, ' +
                'check against breached password lists, use a strength estimator. ' +
                'NIST SP 800-63B: no composition rules (uppercase/special), but enforce minimum length and breach checking.',
              via: 'bfs',
            });
            break;
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-521',
    name: 'Weak Password Requirements',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-522: Insufficiently Protected Credentials
 * Pattern: Credentials transmitted in cleartext or stored without hashing.
 *          e.g., password stored as plaintext in DB, credentials sent over HTTP (not HTTPS),
 *          credentials logged to console/file, passwords in URL query strings.
 *
 * Detection:
 *  1. Password INGRESS->STORAGE without TRANSFORM(hash/encrypt) in between
 *  2. Credentials in query strings or URLs
 *  3. Credentials sent to logging sinks
 */
function verifyCWE522(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Hashing/encryption patterns — these PROTECT credentials
  const hashPattern = /\b(bcrypt|scrypt|argon2|pbkdf2|hash|sha256|sha512|crypto\.hash|hashSync|createHash|password_hash|generate_password_hash|make_password|hashpw)\b/i;

  // Password-related INGRESS nodes
  const passwordIngress = ingress.filter(n =>
    /\b(password|passwd|pwd|passphrase|credential|secret|token)\b/i.test(n.analysis_snapshot || n.code_snapshot) ||
    /\b(password|passwd|pwd)\b/i.test(n.label)
  );

  // Storage sinks (databases, files)
  const storageSinks = nodesOfType(map, 'STORAGE');

  // Strategy 1: Password stored without hashing
  for (const src of passwordIngress) {
    for (const sink of storageSinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if there's a TRANSFORM node with hashing between them
        const hasHashing = map.nodes.some(n =>
          n.node_type === 'TRANSFORM' && hashPattern.test(n.analysis_snapshot || n.code_snapshot)
        );

        // Also check if the sink code itself includes hashing
        const sinkHashes = hashPattern.test(stripComments(sink.analysis_snapshot || sink.code_snapshot));

        if (!hasHashing && !sinkHashes) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (password hashing — bcrypt, scrypt, argon2, or PBKDF2)',
            severity: 'critical',
            description: `Password from ${src.label} is stored at ${sink.label} without hashing. ` +
              `If the database is breached, all passwords are exposed in cleartext.`,
            fix: 'ALWAYS hash passwords before storage using bcrypt, scrypt, or argon2id. ' +
              'NEVER store plaintext passwords. NEVER use MD5/SHA1/SHA256 alone (use PBKDF2 with high iterations at minimum). ' +
              'Use a per-user salt (bcrypt includes this automatically).',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Strategy 2: Credentials in query strings or URLs
  const queryStringCreds = map.nodes.filter(n =>
    n.node_type === 'INGRESS' &&
    /\b(query|params|searchParams|url)\b/i.test(n.analysis_snapshot || n.code_snapshot) &&
    /\b(password|passwd|pwd|token|secret|api[_-]?key)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const node of queryStringCreds) {
    findings.push({
      source: nodeRef(node),
      sink: nodeRef(node),
      missing: 'CONTROL (credentials must be sent in request body or Authorization header, never in URL)',
      severity: 'high',
      description: `${node.label} reads credentials from URL query parameters. ` +
        `Query strings are logged in server access logs, browser history, proxy logs, and Referer headers.`,
      fix: 'Send credentials in the request body (POST) or Authorization header, never in URL query strings. ' +
        'Use HTTPS to encrypt credentials in transit. ' +
        'Implement token-based auth where the token is sent in the Authorization header.',
      via: 'structural',
    });
  }

  // Strategy 3: Credentials sent to logging sinks
  const loggingNodes = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL') &&
    /\b(log|logger|console\.(log|info|debug|warn|error)|syslog|winston|bunyan|pino|print|fprintf.*stderr)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const src of passwordIngress) {
    for (const logSink of loggingNodes) {
      if (hasTaintedPathWithoutControl(map, src.id, logSink.id)) {
        // Check if the log entry mentions redaction
        const isRedacted = stripComments(logSink.analysis_snapshot || logSink.code_snapshot).match(
          /\bredact\s*\(|\bmask\s*\(|\b\*{3,}\b|\[REDACTED\]|\[FILTERED\]/i
        ) !== null;

        if (!isRedacted) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(logSink),
            missing: 'CONTROL (credential redaction before logging)',
            severity: 'high',
            description: `Credential from ${src.label} flows to logging at ${logSink.label} without redaction. ` +
              `Credentials in log files can be read by developers, ops staff, log aggregation services, and attackers who gain log access.`,
            fix: 'Never log credentials. Redact sensitive fields before logging. ' +
              'Use structured logging with an automatic PII/credential filter. ' +
              'If debugging auth, log success/failure status only, never the actual credentials.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-522',
    name: 'Insufficiently Protected Credentials',
    holds: findings.length === 0,
    findings,
  };
}


// ---------------------------------------------------------------------------
// Authorization Bypass & Enforcement
// ---------------------------------------------------------------------------

/**
 * CWE-620: Unverified Password Change
 * Pattern: Password change operation that does NOT verify the current password first.
 *          If an attacker has a session (via XSS, session fixation, shared computer),
 *          they can change the password without knowing the current one.
 *
 * Detection: Find password change flows and check if current-password is verified.
 *  1. Look for password change endpoints/functions
 *  2. Check if current password is required and verified before the change
 */
function verifyCWE620(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Password change patterns
  const passwordChangePattern = /\b(change[_-]?password|update[_-]?password|reset[_-]?password|set[_-]?password|modify[_-]?password|new[_-]?password|password[_-]?update|passwd[_-]?change)\b/i;

  // Current password verification patterns — these are SAFE
  const currentPasswordCheckPattern = /\b(current[_-]?password|old[_-]?password|existing[_-]?password|previous[_-]?password|original[_-]?password|confirm[_-]?current|verify[_-]?password|bcrypt\.compare|checkPassword|validatePassword|password_verify|check_password_hash)\b/i;

  // Find password change functions/routes
  const passwordChangeNodes = map.nodes.filter(n =>
    (n.node_type === 'STRUCTURAL' && n.node_subtype === 'route' &&
     passwordChangePattern.test(n.analysis_snapshot || n.code_snapshot)) ||
    (n.node_type === 'STRUCTURAL' && n.node_subtype === 'function' &&
     passwordChangePattern.test(n.analysis_snapshot || n.code_snapshot)) ||
    (n.node_type === 'STRUCTURAL' && n.node_subtype === 'function' &&
     passwordChangePattern.test(n.label))
  );

  // Also look at AUTH nodes that handle password changes
  const authPasswordChange = map.nodes.filter(n =>
    n.node_type === 'AUTH' && passwordChangePattern.test(n.analysis_snapshot || n.code_snapshot)
  );

  const allPasswordChangeNodes = [...passwordChangeNodes, ...authPasswordChange];

  for (const changeNode of allPasswordChangeNodes) {
    // Get all nodes within this function's scope
    const scopedNodes = map.nodes.filter(n =>
      n.line_start >= changeNode.line_start &&
      n.line_start <= changeNode.line_end
    );

    // Check if current password is verified within this scope
    const hasCurrentPasswordCheck = scopedNodes.some(n =>
      currentPasswordCheckPattern.test(n.analysis_snapshot || n.code_snapshot)
    ) || currentPasswordCheckPattern.test(changeNode.analysis_snapshot || changeNode.code_snapshot);

    // Also check for password reset tokens (valid alternative to current password)
    const hasResetToken = scopedNodes.some(n =>
      /\b(reset[_-]?token|password[_-]?token|token[_-]?verify|verify[_-]?token|resetToken|passwordResetToken)\b/i.test(n.analysis_snapshot || n.code_snapshot)
    );

    if (!hasCurrentPasswordCheck && !hasResetToken) {
      // Find the actual STORAGE node where the new password is written
      const passwordWrite = scopedNodes.find(n =>
        n.node_type === 'STORAGE' &&
        /\b(password|passwd|pwd)\b/i.test(n.analysis_snapshot || n.code_snapshot)
      );

      const sinkNode = passwordWrite ?? changeNode;

      findings.push({
        source: nodeRef(changeNode),
        sink: nodeRef(sinkNode),
        missing: 'AUTH (current password verification before allowing password change)',
        severity: 'high',
        description: `Password change at ${changeNode.label} does not verify the current password. ` +
          `If an attacker gains access to an active session (via XSS, session fixation, or shared computer), ` +
          `they can change the password and lock out the legitimate user.`,
        fix: 'Require the current password before allowing password changes. ' +
          'The flow should be: (1) user submits current password + new password, ' +
          '(2) verify current password against stored hash (bcrypt.compare), ' +
          '(3) only then update to the new password. ' +
          'Exception: password RESET via email token is OK (user proves identity via email).',
        via: 'structural',
      });
    }
  }

  return {
    cwe: 'CWE-620',
    name: 'Unverified Password Change',
    holds: findings.length === 0,
    findings,
  };
}


// ---------------------------------------------------------------------------
// Channel Security & Deployment
// ---------------------------------------------------------------------------

/** CWE-434: Unrestricted Upload of File with Dangerous Type */
function verifyCWE434(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const uploadSources = map.nodes.filter(n =>
    n.node_type === 'INGRESS' &&
    (n.node_subtype.includes('upload') || n.node_subtype.includes('file') ||
     n.node_subtype.includes('multipart') || n.attack_surface.includes('file_upload') ||
     /\b(multer|formidable|busboy|upload|multipart|req\.file|req\.files|request\.files|enctype.*multipart)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  const writeSinks = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
     n.node_subtype.includes('disk') || n.node_subtype.includes('s3') ||
     n.node_subtype.includes('blob') || n.attack_surface.includes('file_access') ||
     /\b(writeFile|createWriteStream|save|mv|pipe|putObject|upload|copyFile|rename|fwrite|move_uploaded_file)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  const hasExtChk = (c: string) => /\b(endsWith|extension|extname|path\.extname|allowedExtensions|allowedTypes|validExtension)\b/i.test(c) || /\.(jpg|jpeg|png|gif|pdf|doc|csv|txt|zip)\b/i.test(c);
  const hasMimeChk = (c: string) => /\b(mimetype|content-?type|magic.*bytes|file-?type|mmmagic|mime\.lookup|mime\.getType|validateMime|fileTypeFromBuffer)\b/i.test(c);
  const isTrulySafe434 = (codes: string[]) => { const j = stripComments(codes.join(' ')); return hasExtChk(j) && hasMimeChk(j); };

  for (const src of uploadSources) {
    for (const sink of writeSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const ctrls = nodesOfType(map, 'CONTROL').map(n => n.analysis_snapshot || n.code_snapshot);
        const all = [(src.analysis_snapshot || src.code_snapshot), (sink.analysis_snapshot || sink.code_snapshot), ...ctrls];
        if (!isTrulySafe434(all)) {
          const j = stripComments(all.join(' '));
          const mp: string[] = [];
          if (!hasExtChk(j)) mp.push('file extension allowlist');
          if (!hasMimeChk(j)) mp.push('MIME type / magic byte validation');
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: `CONTROL (${mp.join(' + ') || 'file type validation'})`,
            severity: 'critical',
            description: `File upload at ${src.label} reaches storage at ${sink.label} without ${mp.join(' or ') || 'proper file type validation'}. Attackers can upload executable files (.php, .asp, .jsp) for RCE.`,
            fix: 'Validate with BOTH extension allowlist AND MIME/magic byte check. Use file-type or mmmagic. Store outside web root. Rename with random names.',
            via: 'bfs',
          });
        }
      }
    }
  }
  if (findings.length === 0 && uploadSources.length > 0 && writeSinks.length > 0) {
    for (const src of uploadSources) {
      for (const sink of writeSinks) {
        if (src.id === sink.id) continue;
        if (sharesFunctionScope(map, src.id, sink.id) && !isTrulySafe434([(src.analysis_snapshot || src.code_snapshot), (sink.analysis_snapshot || sink.code_snapshot)])) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (file extension allowlist + MIME type / magic byte validation)',
            severity: 'critical',
            description: `File upload at ${src.label} stored at ${sink.label} in same scope without complete file type validation.`,
            fix: 'Validate with BOTH extension allowlist AND MIME/magic byte check. Store outside web root.',
            via: 'scope_taint',
          }); break;
        }
      }
    }
  }
  return { cwe: 'CWE-434', name: 'Unrestricted Upload of File with Dangerous Type', holds: findings.length === 0, findings };
}

/** CWE-436: Interpretation Conflict */
function verifyCWE436(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress436 = nodesOfType(map, 'INGRESS');
  const responseSinks436 = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('response') || n.node_subtype.includes('http') ||
     n.node_subtype.includes('render') || n.node_subtype.includes('file_serve') ||
     /\b(res\.send|res\.write|res\.end|response\.write|sendFile|serveFile|HttpResponse|StreamingResponse)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  for (const src of ingress436) {
    for (const sink of responseSinks436) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const combined = stripComments(sink.analysis_snapshot || sink.code_snapshot + ' ' + src.code_snapshot);
        const hasCT = /\bcontent-?type\b/i.test(combined);
        const hasNS = /\bnosniff\b|\bX-Content-Type-Options\b/i.test(combined);
        const hasCS = /\bcharset\b|\butf-?8\b/i.test(combined);
        const hasDI = /\bcontent-?disposition\b|\battachment\b/i.test(combined);
        if (!(hasCT && (hasNS || hasCS || hasDI))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (explicit Content-Type with X-Content-Type-Options: nosniff)',
            severity: 'medium',
            description: `User input from ${src.label} in response at ${sink.label} without explicit Content-Type. Browsers may MIME-sniff and interpret content differently.`,
            fix: 'Set explicit Content-Type with charset. Add X-Content-Type-Options: nosniff. Use Content-Disposition: attachment for downloads.',
            via: 'bfs',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-436', name: 'Interpretation Conflict', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// File Upload & Trust Boundary
// ---------------------------------------------------------------------------

/** CWE-470: Use of Externally-Controlled Input in Unsafe Reflection */
function verifyCWE470(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress470 = nodesOfType(map, 'INGRESS');
  const REFLECT470 = /\b(Class\.forName|forName|Method\.invoke|Constructor\.newInstance|getDeclaredMethod|getDeclaredConstructor|Type\.GetType|Activator\.CreateInstance|Assembly\.Load|getattr|__import__|importlib\.import_module|call_user_func|call_user_func_array|const_get|public_send|Object\.const_get|Reflect\.(get|set|apply|construct))\b/i;
  const DYN470 = /\bnew\s+\$\w|\$\w+\s*->\s*\$\w|\[\s*\w+\s*\]\s*\(/i;
  const reflSinks470 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('reflect') || n.node_subtype.includes('dynamic') ||
     n.node_subtype.includes('class_load') || n.attack_surface.includes('reflection') ||
     REFLECT470.test(n.analysis_snapshot || n.code_snapshot) || DYN470.test(n.analysis_snapshot || n.code_snapshot))
  );
  const SAFE470 = /\ballowlist\b|\bwhitelist\b|\ballowed.*class\b|\bclass.*map\b|\bmethod.*map\b|\bswitch\b.*\bcase\b|\bvalidate.*class\b|\bEnum\b|\bhas\s*\(\s*\w/i;
  for (const src of ingress470) {
    for (const sink of reflSinks470) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!SAFE470.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) && !SAFE470.test(stripComments(src.analysis_snapshot || src.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (allowlist of permitted classes/methods for reflection)',
            severity: 'high',
            description: `User input from ${src.label} controls reflection at ${sink.label}. Attacker can instantiate arbitrary classes or invoke unexpected methods.`,
            fix: 'Use a strict allowlist (Map/switch) to map input to permitted classes. Never use Class.forName/getattr/call_user_func with unsanitized input.',
            via: 'bfs',
          });
        }
      }
    }
  }
  if (findings.length === 0 && ingress470.length > 0) {
    const reflScope470 = map.nodes.filter(n => n.node_type !== 'META' && (REFLECT470.test(n.analysis_snapshot || n.code_snapshot) || DYN470.test(n.analysis_snapshot || n.code_snapshot)));
    for (const src of ingress470) {
      for (const sink of reflScope470) {
        if (src.id === sink.id) continue;
        if (sharesFunctionScope(map, src.id, sink.id) && !SAFE470.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (allowlist of permitted classes/methods for reflection)',
            severity: 'high',
            description: `User input from ${src.label} in scope with reflection at ${sink.label}. If input controls reflected name, arbitrary code invocation possible.`,
            fix: 'Use a strict allowlist mapping input to permitted class/method names.',
            via: 'scope_taint',
          }); break;
        }
      }
    }
  }
  return { cwe: 'CWE-470', name: 'Use of Externally-Controlled Input in Unsafe Reflection', holds: findings.length === 0, findings };
}

/**
 * CWE-501: Trust Boundary Violation
 *
 * Detects untrusted/unvalidated user input stored directly in a trusted store
 * (HttpSession, environment, global state, cache) without validation.
 *
 * Phase 1: Graph approach - INGRESS -> STORAGE/EXTERNAL session/trust nodes
 * Phase 2: Source-line fallback for Java HttpSession patterns
 *
 * Key design: output encoding (htmlEscape, encodeForHTML) does NOT kill taint
 * for CWE-501. Trust boundary violation is about storing UNVALIDATED data.
 * Only real input validation kills taint: parseInt, parseLong, Pattern.matches, etc.
 */
function verifyCWE501(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Phase 1: graph-based detection
  const ingress501 = nodesOfType(map, 'INGRESS');
  const SESS501 = /\b(req\.session|session\[|session\.put|session\.set|session\.setAttribute|request\.session|\$_SESSION|flask\.session|HttpSession)\b/i;
  const ENV501 = /\b(process\.env|os\.environ|System\.setProperty|putenv|setenv|globalThis|global\.\w)\b/i;
  const CACHE501 = /\b(redis\.set|cache\.put|cache\.set|memcached\.set|config\.set|app\.locals)\b/i;
  const trustSinks501 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('session') || n.node_subtype.includes('trust') ||
     n.node_subtype.includes('config') || n.node_subtype.includes('env') ||
     n.node_subtype.includes('global') || n.node_subtype.includes('cache') ||
     n.attack_surface.includes('trust_boundary') ||
     SESS501.test(n.analysis_snapshot || n.code_snapshot) || ENV501.test(n.analysis_snapshot || n.code_snapshot) || CACHE501.test(n.analysis_snapshot || n.code_snapshot))
  );
  const SAFE501 = /\bvalidate\s*\(|\bsanitize\s*\(|\bschema\b|\bz\.\w|\bjoi\b|\byup\b|\bclass-?validator\b|\bassert\s*\(|\bverify\s*\(|\bisValid\s*\(|\bclean\s*\(/i;

  for (const src of ingress501) {
    for (const sink of trustSinks501) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (hasDeadBranchForNode(map, sink.id)) continue;
        if (!SAFE501.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) && !SAFE501.test(stripComments(src.analysis_snapshot || src.code_snapshot))) {
          const st = SESS501.test(sink.analysis_snapshot || sink.code_snapshot) ? 'session' : ENV501.test(sink.analysis_snapshot || sink.code_snapshot) ? 'environment/global' : 'trusted cache/config';
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (input validation before crossing trust boundary)',
            severity: 'high',
            description: `User input from ${src.label} stored in ${st} at ${sink.label} without validation. Downstream code will treat it as pre-validated.`,
            fix: `Validate all input BEFORE storing in ${st}. Use schema validation (zod, joi). Never copy raw request data into session/global state.`,
            via: 'bfs',
          });
        }
      }
    }
  }

  // Phase 2: source-line fallback for Java HttpSession patterns
  if (findings.length === 0 && map.source_code) {
    // Join multi-line assignments: if a line ends without semicolon, join with next line.
    // Strip inline comments (// ...) before checking line endings so that
    // "valuesList.remove(0); // comment" is recognized as ending with ";".
    const stripTrailingComment501 = (s: string): string => {
      const t = s.trim();
      if (t.startsWith('//')) return t;
      const idx = t.indexOf('//');
      if (idx > 0) {
        const before = t.substring(0, idx);
        const dq = (before.match(/"/g) || []).length;
        if (dq % 2 === 0) return before.trimEnd();
      }
      return t;
    };
    const rawLines501 = map.source_code.split('\n');
    const srcLines: string[] = [];
    for (let i = 0; i < rawLines501.length; i++) {
      let line = rawLines501[i]!;
      let code = stripTrailingComment501(line);
      while (i + 1 < rawLines501.length && !code.endsWith(';') && !code.endsWith('{') && !code.endsWith('}') && !line.trim().startsWith('//') && !line.trim().startsWith('*') && !line.trim().startsWith('/*') && line.trim().length > 0) {
        i++;
        line += ' ' + rawLines501[i]!.trim();
        code = stripTrailingComment501(line);
      }
      srcLines.push(line);
    }
    const USER_INPUT_API = /(?:getParameter|getParameterValues|getParameterMap|getParameterNames|getCookies|getHeader|getHeaders|getHeaderNames|getTheParameter|getInputStream|getReader|readLine|getQueryString|System\.getenv)\s*\(/;
    const COOKIE_API = /(?:\w+\.getValue\s*\(|theCookie\.getValue\s*\()/;
    const ENUM_API = /\w+\.nextElement\s*\(/;
    const VALIDATE_RE = /\b(?:parseInt|parseLong|parseFloat|parseDouble|Integer\.valueOf|Long\.valueOf|Double\.valueOf|Float\.valueOf|Boolean\.valueOf|Boolean\.parseBoolean|Short\.parseShort|Byte\.parseByte|Pattern\.matches|Pattern\.compile|\.matches\s*\(\s*"[^"]*"|validate\s*\(|sanitize\s*\(|isValid\s*\(|allowlist|whitelist|checkInput|verifyInput)\b/i;
    const SESSION_SINK = /\.getSession\s*\(\s*\)\s*\.\s*(?:setAttribute|putValue)\s*\(\s*(?:"[^"]*"\s*,\s*(\w+)|(\w+)\s*[,)])/;

    // Extract the variable name from the LHS of an assignment, handling Java type declarations
    const extractVar = (l: string): string | null => {
      const eqIdx = l.indexOf('=');
      if (eqIdx < 0) return null;
      const after = l.charAt(eqIdx + 1);
      if (after === '=') return null; // skip ==
      const before = l.substring(0, eqIdx).trim();
      const words = before.split(/\s+/);
      const last = words[words.length - 1].replace(/[^a-zA-Z0-9_]/g, '');
      if (!last || /^(?:if|for|while|return|new|class|void)$/.test(last)) return null;
      return last;
    };

    const taintedVars = new Set<string>();
    let srcLineNum = 0;
    let srcLineCode = '';

    for (let i = 0; i < srcLines.length; i++) {
      const line = srcLines[i].trim();
      if (line.startsWith('//') || line.startsWith('*') || line.startsWith('/*')) continue;

      // Source identification: taint the LHS if the line has a user input API on the RHS
      if (USER_INPUT_API.test(line) || COOKIE_API.test(line) || ENUM_API.test(line)) {
        const v = extractVar(line);
        if (v) { taintedVars.add(v); srcLineNum = i + 1; srcLineCode = line; }
      }

      // Generic taint propagation: any assignment where the RHS mentions a tainted var
      // Handles: bar = param, String[] values = map.get(...), param = values[0],
      //          bar = SomeLib.method(param), StringBuilder sb = new StringBuilder(param), etc.
      const lhsV = extractVar(line);
      if (lhsV) {
        const eqIdx = line.indexOf('=');
        const rhs = line.substring(eqIdx + 1);
        for (const tv of taintedVars) {
          if (new RegExp('\\b' + tv + '\\b').test(rhs)) { taintedVars.add(lhsV); break; }
        }
      }

      // Also handle inline conditional assignments: if (x != null) param = values[0];
      const inlineM = line.match(/\)\s*(\w+)\s*=\s*(.+)/);
      if (inlineM) {
        const inlineVar = inlineM[1];
        const inlineRhs = inlineM[2];
        if (!/^(?:if|for|while|return|new)$/.test(inlineVar)) {
          for (const tv of taintedVars) {
            if (new RegExp('\\b' + tv + '\\b').test(inlineRhs)) { taintedVars.add(inlineVar); break; }
          }
        }
      }

      // Interprocedural: bar = doSomething(request, param) or bar = new Test().doSomething(request, param)
      const callM = line.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?(\w+)\s*\(\s*(?:request\s*,\s*)?(\w+)\s*\)/);
      if (callM && taintedVars.has(callM[3])) {
        const methName = callM[2];
        let methodKillsTaint = false;
        for (let j = 0; j < srcLines.length; j++) {
          if (j === i) continue; // skip the call site itself — look for the actual definition
          const mdef = srcLines[j].trim();
          if (mdef.includes(`${methName}(`) && (mdef.includes('String ') || mdef.includes('public '))) {
            let braceDepth = 0; let foundOpen = false;
            for (let k = j; k < Math.min(j + 40, srcLines.length); k++) {
              if (srcLines[k].includes('{')) { braceDepth++; foundOpen = true; }
              if (srcLines[k].includes('}')) braceDepth--;
              if (foundOpen && braceDepth <= 0) break;
              const mtl = srcLines[k].trim();
              if (VALIDATE_RE.test(mtl)) { methodKillsTaint = true; break; }
              // Static constant replaces tainted data entirely
              if (/^\w+\s*=\s*"[^"]{5,}"/.test(mtl) && !/param/.test(mtl) && !/request/.test(mtl)) {
                const cv = mtl.match(/(\w+)\s*=\s*"[^"]*"/);
                if (cv) {
                  for (let n = k + 1; n < Math.min(k + 10, srcLines.length); n++) {
                    if (srcLines[n].trim().includes(`return ${cv[1]}`)) { methodKillsTaint = true; break; }
                  }
                }
              }
              // ArrayList remove+get neutralization inside method body:
              // Collect add/remove/get from the method body and verify the retrieved index is safe.
              if (/\.remove\s*\(\s*\d+\s*\)/.test(mtl)) {
                const methodSlice = srcLines.slice(k, Math.min(k + 10, srcLines.length)).join(' ');
                const getM501 = methodSlice.match(/\.get\s*\(\s*(\d+)\s*\)/);
                if (getM501) {
                  // Scan backwards from remove line to find the list variable and adds
                  const listVarM = mtl.match(/(\w+)\.remove/);
                  if (listVarM) {
                    const lv = listVarM[1];
                    let adds = 0; let paramAdds = 0; let removes = 0;
                    for (let m = j; m <= k; m++) {
                      const ml = srcLines[m].trim();
                      if (ml.includes(`${lv}.add(`)) {
                        adds++;
                        if (/param|request|tainted/.test(ml) && !/"[^"]*"/.test(ml.match(new RegExp(lv + '\\.add\\s*\\((.*)\\)'))?.[1] || '')) paramAdds++;
                      }
                      if (ml.includes(`${lv}.remove(`)) removes++;
                    }
                    // Also count removes+get on lines after k
                    for (let m = k + 1; m < Math.min(k + 10, srcLines.length); m++) {
                      const ml = srcLines[m].trim();
                      if (ml.includes(`${lv}.remove(`)) removes++;
                    }
                    const getIdx = parseInt(getM501[1]);
                    // After 'removes' removals from front, the item at getIdx maps to original index getIdx + removes
                    const origIdx = getIdx + removes;
                    // Build a taint map: which add indices are tainted?
                    // Pattern: add("safe"), add(param), add("moresafe") -> indices 0=safe, 1=tainted, 2=safe
                    // If origIdx points to a non-param add, taint is killed
                    let addIdx = 0; let taintedAtOrig = true; // default: assume tainted
                    for (let m = j; m <= k + 10 && m < srcLines.length; m++) {
                      const ml = srcLines[m].trim();
                      const addMatch = ml.match(new RegExp(lv + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
                      if (addMatch) {
                        if (addIdx === origIdx) {
                          taintedAtOrig = !!addMatch[1]; // true if variable (param), false if string literal
                          break;
                        }
                        addIdx++;
                      }
                    }
                    if (!taintedAtOrig) { methodKillsTaint = true; break; }
                  }
                }
              }
            }
            break;
          }
        }
        if (methodKillsTaint) taintedVars.delete(callM[1]);
        else taintedVars.add(callM[1]);
      }

      // Taint killing: constant assignment (only standalone, not inside conditionals)
      // "bar = "";" or "String bar = "safe";" — but NOT "if (x) param = "";"
      if (!/^\s*(?:if|else|for|while)\b/.test(srcLines[i])) {
        const constM = line.match(/^(?:(?:final\s+)?(?:[\w.]+(?:<[^>]*>)?(?:\[\])?)\s+)?(\w+)\s*=\s*(?:"[^"]*"|'[^']*'|\d+(?:\.\d+)?|true|false|null)\s*;/);
        if (constM) taintedVars.delete(constM[1]);
      }

      // Taint killing: real input validation (NOT output encoding)
      if (VALIDATE_RE.test(line) && lhsV) taintedVars.delete(lhsV);

      // Taint killing: ternary always-true
      // bar = (7 * 18) + num > 200 ? "constant" : param
      const ternM = line.match(/(\w+)\s*=\s*\(?\s*(\d+)\s*\*\s*(\d+)\s*\)?\s*\+\s*(\w+)\s*>\s*(\d+)\s*\?\s*"[^"]*"\s*:\s*(\w+)\s*;/);
      if (ternM) {
        const product = parseInt(ternM[2]) * parseInt(ternM[3]);
        const threshold = parseInt(ternM[5]);
        let addend = 0;
        for (let j = Math.max(0, i - 10); j < i; j++) {
          const numRe = new RegExp('(?:int\\s+)?' + ternM[4] + '\\s*=\\s*(\\d+)\\s*;');
          const nm = srcLines[j].trim().match(numRe);
          if (nm) { addend = parseInt(nm[1]); break; }
        }
        if (product + addend > threshold) taintedVars.delete(ternM[1]);
      }

      // Taint killing: if-always-true
      const ifM = line.match(/if\s*\(\s*\(?\s*(\d+)\s*\*\s*(\d+)\s*\)?\s*-\s*\w+\s*>\s*(\d+)\s*\)\s+(\w+)\s*=\s*"[^"]*"\s*;/);
      if (ifM) {
        const product = parseInt(ifM[1]) * parseInt(ifM[2]);
        if (product > parseInt(ifM[3]) + 200) taintedVars.delete(ifM[4]);
      }

      // Taint killing: switch with deterministic safe target
      const switchM = line.match(/switchTarget\s*=\s*(\w+)\.charAt\s*\(\s*(\d+)\s*\)/);
      if (switchM) {
        let guessVal: string | null = null;
        for (let j = Math.max(0, i - 5); j < i; j++) {
          const gm = srcLines[j].trim().match(/(\w+)\s*=\s*"([^"]*)"/);
          if (gm && gm[1] === switchM[1]) { guessVal = gm[2]; break; }
        }
        if (guessVal) {
          const ci = parseInt(switchM[2]);
          if (ci < guessVal.length) {
            const rc = guessVal[ci];
            for (let j = i + 1; j < Math.min(i + 40, srcLines.length); j++) {
              if (srcLines[j].trim().startsWith(`case '${rc}':`)) {
                for (let k = j + 1; k < Math.min(j + 5, srcLines.length); k++) {
                  const ca = srcLines[k].trim().match(/^(\w+)\s*=\s*"[^"]*"\s*;/);
                  if (ca) { taintedVars.delete(ca[1]); break; }
                  if (srcLines[k].trim() === 'break;') break;
                }
                break;
              }
            }
          }
        }
      }

      // Taint killing: HashMap safe-key retrieval
      const mapGetM = line.match(/(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
      if (mapGetM) {
        const mkResult = resolveMapKeyTaint(srcLines, taintedVars, mapGetM[2]!, mapGetM[3]!, i);
        if (mkResult === 'tainted') taintedVars.add(mapGetM[1]!);
        else if (mkResult === 'safe') taintedVars.delete(mapGetM[1]!);
        else if (mkResult === 'unknown' && taintedVars.has(mapGetM[2]!)) taintedVars.add(mapGetM[1]!);
        else taintedVars.delete(mapGetM[1]!);
      }

      // Taint killing: ArrayList safe-index retrieval
      const listGetM = line.match(/(\w+)\s*=\s*(\w+)\.get\s*\(\s*(\d+)\s*\)/);
      if (listGetM) {
        const listVar = listGetM[2]; const getIdx = parseInt(listGetM[3]);
        const items: { tainted: boolean }[] = [];
        let removeCount = 0;
        for (let j = 0; j < i; j++) {
          const aLine = srcLines[j].trim();
          const addM = aLine.match(new RegExp(listVar + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
          if (addM) items.push({ tainted: addM[1] ? taintedVars.has(addM[1]) : false });
          if (aLine.includes(`${listVar}.remove(`)) removeCount++;
        }
        const adjusted = items.slice(removeCount);
        if (getIdx < adjusted.length && !adjusted[getIdx].tainted) taintedVars.delete(listGetM[1]);
        else taintedVars.add(listGetM[1]);
      }

      // Sink detection
      const sinkM = line.match(SESSION_SINK);
      if (sinkM) {
        const sinkVar = sinkM[1] || sinkM[2];
        if (sinkVar && taintedVars.has(sinkVar)) {
          if (isLineInDeadBranchFunction(map, i + 1)) continue;
          findings.push({
            source: { id: `src-line-${srcLineNum}`, label: `user input (line ${srcLineNum})`, line: srcLineNum, code: srcLineCode.slice(0, 200) },
            sink: { id: `src-line-${i + 1}`, label: `session store (line ${i + 1})`, line: i + 1, code: line.slice(0, 200) },
            missing: 'CONTROL (input validation before crossing trust boundary)',
            severity: 'high',
            description: `Untrusted input stored in HttpSession via ${sinkVar} at line ${i + 1} without validation. ` +
              `Data from user input flows to session.setAttribute()/putValue() without type-safe conversion or allowlist check. ` +
              `Downstream code will treat session data as pre-validated.`,
            fix: 'Validate all input BEFORE storing in session. Use type conversion (parseInt, parseLong), ' +
              'schema validation, or allowlist checks. Output encoding (htmlEscape) does NOT constitute validation for trust boundaries.',
            via: 'source_line_fallback',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-501', name: 'Trust Boundary Violation', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Missing Authorization
// ---------------------------------------------------------------------------

/** CWE-862: Missing Authorization */
function verifyCWE862(map: NeuralMap): VerificationResult {
  // Auth CWEs only apply to web/API code. Standalone utilities, console apps,
  // math operations, etc. have no expectation of authorization.
  if (!hasWebFrameworkContext(map)) {
    return { cwe: 'CWE-862', name: 'Missing Authorization', holds: true, findings: [] };
  }
  const findings: Finding[] = [];
  const ingressNodes862 = nodesOfType(map, 'INGRESS');
  // Always use INGRESS nodes as sources. In Express middleware patterns, AUTH nodes
  // (e.g. jwt.verify in a global middleware) are structurally parallel to route handlers
  // and have no DATA_FLOW edges to STORAGE sinks. The correct check is whether
  // user-controlled INGRESS data reaches a state-changing STORAGE without authorization.
  const sources862 = ingressNodes862;
  const stateChanging862 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('write') || n.node_subtype.includes('delete') ||
     n.node_subtype.includes('update') || n.node_subtype.includes('insert') ||
     n.node_subtype.includes('admin') || n.node_subtype.includes('config') ||
     n.attack_surface.includes('state_modification') || n.attack_surface.includes('data_access') ||
     n.attack_surface.includes('admin') || n.attack_surface.includes('write') ||
     /\b(INSERT|UPDATE|DELETE|DROP|ALTER|GRANT|REVOKE|TRUNCATE|destroy|remove|purge|modify|create|save|put|patch|admin|write|deleteOne|deleteMany|updateOne|updateMany|findOneAndUpdate|findOneAndDelete)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  const AUTHZ862 = /\b(authorize|hasPermission|checkPermission|checkAccess|isAuthorized|requireRole|hasRole|can\s*\(\s*['"]|ability|policy|guard|rbac|abac|acl|permission|isOwner|ownerCheck|belongsTo|createdBy|userId\s*===|user\.id\s*===|currentUser\.id)\b/i;
  function pathNoAuthz862(srcId: string, sinkId: string): boolean {
    const nm = new Map(map.nodes.map(n => [n.id, n]));
    const vis = new Set<string>();
    const q: Array<{ nid: string; pa: boolean }> = [{ nid: srcId, pa: false }];
    while (q.length > 0) {
      const { nid, pa } = q.shift()!;
      const vk = `${nid}:${pa}`;
      if (vis.has(vk)) continue;
      vis.add(vk);
      const nd = nm.get(nid);
      if (!nd) continue;
      const isAz = (nd.node_type === 'CONTROL' || nd.node_type === 'AUTH') &&
        (nd.node_subtype.includes('authorization') || nd.node_subtype.includes('permission') ||
         nd.node_subtype.includes('access_control') || AUTHZ862.test(nd.analysis_snapshot || nd.code_snapshot));
      const now = pa || isAz;
      if (nid === sinkId) { if (!now) return true; continue; }
      for (const e of nd.edges) {
        if (!FLOW_EDGE_TYPES.has(e.edge_type)) continue;
        if (!vis.has(`${e.target}:${now}`)) q.push({ nid: e.target, pa: now });
      }
    }
    return false;
  }
  // Scope-based authorization check for a sink node.
  // Checks three sources of auth coverage:
  //   1. Any sibling node in the direct containing STRUCTURAL scope matches AUTHZ862
  //   2. The scope node's own code matches (e.g. the containing function IS the auth check)
  //   3. Any route node whose line range encompasses the sink — this catches auth middleware
  //      passed as an argument to the route: app.delete('/path', authorize, handler)
  function scopeHasAuthz862(sink: { id: string; line_start: number; line_end: number }): boolean {
    // Find all STRUCTURAL nodes that directly CONTAIN the sink
    const parentScopes = map.nodes.filter(n =>
      (n.node_type === 'STRUCTURAL' && (n.node_subtype === 'function' || n.node_subtype === 'route')) &&
      n.edges.some(e => e.edge_type === 'CONTAINS' && e.target === sink.id)
    );

    for (const scope of parentScopes) {
      // Check if the scope's own code_snapshot mentions auth (catches named auth functions as parent)
      if (AUTHZ862.test(stripComments(scope.analysis_snapshot || scope.code_snapshot))) return true;

      // Check all children within the scope for auth patterns
      const scopeChildren = scope.edges
        .filter(e => e.edge_type === 'CONTAINS')
        .map(e => map.nodes.find(n => n.id === e.target))
        .filter((n): n is NonNullable<typeof n> => n != null);
      if (scopeChildren.some(n => AUTHZ862.test(stripComments(n.analysis_snapshot || n.code_snapshot)))) return true;

      // Check any route that wraps the same line range as this scope.
      // A route like app.delete('/path', authorize, handler) captures the auth middleware
      // in its code_snapshot even though the handler function is a separate STRUCTURAL node.
      const routeDefsWrappingScope = map.nodes.filter(n =>
        n.node_type === 'STRUCTURAL' && n.node_subtype === 'route' &&
        n.line_start <= scope.line_start && n.line_end >= scope.line_end
      );
      if (routeDefsWrappingScope.some(rd => AUTHZ862.test(stripComments(rd.analysis_snapshot || rd.code_snapshot)))) return true;
    }

    // Fallback: check any route that directly encompasses the sink's line
    const routeDefsCoveringSink = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'route' &&
      n.line_start <= sink.line_start && n.line_end >= sink.line_end
    );
    if (routeDefsCoveringSink.some(rd => AUTHZ862.test(stripComments(rd.analysis_snapshot || rd.code_snapshot)))) return true;

    return false;
  }
  const seenSinks = new Set<string>();
  for (const src of sources862) {
    for (const sink of stateChanging862) {
      if (src.id === sink.id) continue;
      if (seenSinks.has(sink.id)) continue;
      // A sink is vulnerable only if:
      //   - There is a data-flow path (BFS) from source to sink with no auth intermediate, OR
      //     the source and sink share a function scope with no auth in that scope
      //   - AND the containing scope (or its route wrapper) has NO authorization coverage
      // The scope check is the authoritative gate: if the scope has auth, suppress the finding.
      const bfsHit862 = pathNoAuthz862(src.id, sink.id);
      const scopeHit862 = !bfsHit862 && sharesFunctionScope(map, src.id, sink.id);
      const reachable = bfsHit862 || scopeHit862;
      const hasVulnPath = reachable && !scopeHasAuthz862(sink);
      if (hasVulnPath) {
        if (!AUTHZ862.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) && !AUTHZ862.test(stripComments(src.analysis_snapshot || src.code_snapshot))) {
          seenSinks.add(sink.id);
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (authorization -- verify user has permission for this resource/action)',
            severity: 'critical',
            description: `Request at ${src.label} reaches state-changing operation at ${sink.label} without authorization. Any authenticated user could modify unauthorized resources.`,
            fix: 'Add authorization checks before state-changing ops. Use RBAC/ABAC. Verify req.user.id === resource.ownerId.',
            via: bfsHit862 ? 'bfs' : 'scope_taint',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-862', name: 'Missing Authorization', holds: findings.length === 0, findings };
}

/** CWE-863: Incorrect Authorization */
function verifyCWE863(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress863 = nodesOfType(map, 'INGRESS');
  const AZ863 = /\b(authorize|hasPermission|checkPermission|checkAccess|isAuthorized|requireRole|hasRole|isAdmin|role|permission|isOwner|can\s*\()\b/i;
  const authzCtrls863 = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'AUTH') &&
    (n.node_subtype.includes('authorization') || n.node_subtype.includes('permission') ||
     n.node_subtype.includes('access_control') || n.node_subtype.includes('role_check') ||
     AZ863.test(n.analysis_snapshot || n.code_snapshot))
  );
  const INSECURE863 = /==(?!=)|\btoString\b.*===|\b==\s*['"]admin['"]\b/i;
  for (const az of authzCtrls863) {
    const c = stripComments(az.analysis_snapshot || az.code_snapshot);
    if (INSECURE863.test(c)) {
      let src863: typeof ingress863[0] | undefined;
      let via863: 'bfs' | 'scope_taint' = 'bfs';
      for (const s of ingress863) {
        if (hasTaintedPathWithoutControl(map, s.id, az.id)) { src863 = s; via863 = 'bfs'; break; }
        if (!src863 && sharesFunctionScope(map, s.id, az.id)) { src863 = s; via863 = 'scope_taint'; }
      }
      if (src863) {
        findings.push({
          source: nodeRef(src863), sink: nodeRef(az),
          missing: 'CONTROL (secure authorization comparison -- strict equality with server-side data)',
          severity: 'high',
          description: `Authorization at ${az.label} uses insecure comparison (loose equality/type coercion). Attacker may bypass via type confusion.`,
          fix: 'Use strict equality (===). Compare against server-side role data. Use integer/UUID for IDs.',
          via: via863,
        });
      }
    }
  }
  const CLIENT863 = /\b(req\.body|req\.query|req\.params|req\.headers|request\.form|request\.args)\b.*\b(role|admin|permission|privilege|isAdmin|level|access)\b/i;
  for (const az of authzCtrls863) {
    if (CLIENT863.test(stripComments(az.analysis_snapshot || az.code_snapshot)) && ingress863[0] && !findings.some(f => f.sink.id === az.id)) {
      findings.push({
        source: nodeRef(ingress863[0]), sink: nodeRef(az),
        missing: 'CONTROL (server-side authorization -- use session/token role, not request body)',
        severity: 'critical',
        description: `Authorization at ${az.label} uses client-controlled data for privilege decisions. Attacker can set role=admin.`,
        fix: 'Get role from server-side session, verified JWT, or DB lookup. Never from req.body/query/headers.',
        via: 'structural',
      });
    }
  }
  const idInputs863 = ingress863.filter(n => /\b(params\.id|params\.\w*[iI]d|query\.id|req\.params\.\w*[iI]d|:id|:userId|:resourceId)\b/i.test(n.analysis_snapshot || n.code_snapshot));
  const dataStores863 = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('db_read') || n.node_subtype.includes('db_write') ||
     n.node_subtype.includes('query') || n.node_subtype.includes('find') ||
     /\b(findById|findOne|findByPk|getOne|SELECT.*WHERE.*id|deleteById|updateById)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  const OWN863 = /\buserId\s*[=!]==?\s*\w|\.userId\s*[=!]==?\s*req\b|\bownerId\b|\bcreatedBy\b|\bbelongsTo\b|\buser\.id\s*[=!]==?\b|\breq\.user\.id\s*[=!]==?\b|\bauthorId\b/i;
  for (const src of idInputs863) {
    for (const sink of dataStores863) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const hasOwn = map.nodes.some(n =>
          (n.node_type === 'CONTROL' || n.node_type === 'AUTH') && OWN863.test(n.analysis_snapshot || n.code_snapshot) && sharesFunctionScope(map, n.id, sink.id)
        ) || OWN863.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) || OWN863.test(stripComments(src.analysis_snapshot || src.code_snapshot));
        if (!hasOwn && !findings.some(f => f.source.id === src.id && f.sink.id === sink.id)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (resource ownership verification -- IDOR protection)',
            severity: 'high',
            description: `Resource ID from ${src.label} accesses data at ${sink.label} without ownership check. Attacker can access other users' resources.`,
            fix: 'Verify user owns the resource. Add WHERE user_id = req.user.id. Check resource.ownerId === req.user.id.',
            via: 'bfs',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-863', name: 'Incorrect Authorization', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Privilege & Permission Management
// ---------------------------------------------------------------------------

/**
 * CWE-250: Execution with Unnecessary Privileges
 * Pattern: Code runs as root/admin/SYSTEM when it doesn't need to, OR calls
 * privileged APIs (exec, spawn, file ops) without first dropping privileges.
 * Property: Processes drop to least privilege before performing non-privileged work.
 *
 * Key insight: The danger isn't HAVING privileges — it's performing ordinary work
 * (file I/O, network, user-facing logic) while STILL elevated. If attacker finds
 * any bug in elevated code, they inherit the full privilege level.
 */
function verifyCWE250(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Detect nodes that run with elevated privileges
  // TIGHTENED: Only match specific, unambiguous privilege-escalation patterns.
  // Removed: bare \broot\b, \bSYSTEM\b, \bsudo\b, \belevate\b, \bisAdmin\b,
  //   \bhasRoot\b, \brunAsRoot\b, \bAllowElevation\b, \brequireAdmin\b —
  //   all match normal Java/comment code (System.out, rootDir, isAdmin flag, etc).
  // Retained: compound patterns that require privilege-specific context.
  const ELEVATED_PRIV = /(?:\b(?:setuid\s*\(\s*0|seteuid\s*\(\s*0|setgid\s*\(\s*0|run\s*[Aa]s\s*[Aa]dministrator|RunAsAdministrator|NT\s*AUTHORITY\\SYSTEM|setuid.*root|su\s+root|sudo\s+-u\s+root|CAP_SYS_ADMIN|CAP_NET_RAW|RequestedExecutionLevel.*requireAdministrator|<requestedExecutionLevel\s+level=["']requireAdministrator)\b|--privileged\b)/i;
  const DROP_PRIV = /\b(setuid|seteuid|setgid|setegid|setreuid|setregid|initgroups|drop.*priv|lowerPriv|switchUser|Process\.setuid|process\.setuid|process\.setgid|setrlimit|pledge|unveil|seccomp|sandbox|chroot|unshare|capabilities.*drop|cap_drop|no-new-privileges)\b/i;
  const PRIV_GUARD = /\b(if\s*\(\s*(getuid|geteuid|process\.getuid|os\.getuid)\s*\(\s*\)|checkPrivilege|requiresElevation|isElevated\s*\(\))\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (ELEVATED_PRIV.test(code) && !DROP_PRIV.test(code) && !PRIV_GUARD.test(code)) {
      // Check if this elevated node also does regular work (file I/O, network, user input)
      const REGULAR_WORK = /\b(readFile|writeFile|fs\.|open\(|fopen|createServer|listen|bind|socket|connect|accept|request\.|response\.|render|send|json\(|query|exec|spawn)\b/i;
      if (REGULAR_WORK.test(code) || node.node_type === 'INGRESS' || node.node_type === 'EGRESS') {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (privilege dropping — setuid/setgid after initialization, or run as non-root)',
          severity: 'high',
          description: `Code at ${node.label} runs with elevated privileges while performing regular operations. ` +
            `If any vulnerability exists in this code path, the attacker inherits the elevated privilege level.`,
          fix: 'Drop privileges immediately after performing privileged initialization (binding to port 80, reading config). ' +
            'Use setuid()/setgid() to switch to a non-root user. In containers, avoid --privileged and drop unnecessary capabilities. ' +
            'In Node.js: process.setuid("nobody") after binding.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-250', name: 'Execution with Unnecessary Privileges', holds: findings.length === 0, findings };
}

/**
 * CWE-269: Improper Privilege Management
 * Pattern: Code grants/modifies privileges without proper validation, or
 * privilege escalation paths exist (e.g., user can change their own role).
 * Property: Privilege modifications are always mediated by proper authorization checks.
 *
 * Broader than CWE-250: covers any mismanagement — granting too much, failing to
 * revoke, allowing self-escalation, or using privilege APIs incorrectly.
 */
function verifyCWE269(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Nodes that modify privileges/roles
  const PRIV_MODIFY = /\b(setRole|assignRole|grantPermission|addPermission|setAdmin|makeAdmin|updateRole|changeRole|elevateUser|promote|setPrivilege|addToGroup|role\s*[:=]\s*['"]admin|isAdmin\s*[:=]\s*true|permission\s*[:=]|setCapabilities|grant\s+\w+\s+to|GRANT\s+|chmod|chown|setfacl|icacls|cacls|adduser.*sudo|usermod.*-G|SECURITY_ATTRIBUTES)\b/i;

  const privModNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    PRIV_MODIFY.test(n.analysis_snapshot || n.code_snapshot)
  );

  const PRIV_SAFE = /\b(requireAdmin|isAdmin\s*\(\)|checkAdmin|adminOnly|superuserRequired|staff_member_required|@admin_required|isSuperUser|hasRole\s*\(\s*['"]admin|authorize|checkPermission|rbac|abac|policy\.check|currentUser\.role\s*===\s*['"]admin)\b/i;

  for (const src of ingress) {
    for (const sink of privModNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!PRIV_SAFE.test(sinkCode) && !PRIV_SAFE.test(stripComments(src.analysis_snapshot || src.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (authorization check — only admins can modify privileges)',
            severity: 'critical',
            description: `User input from ${src.label} can modify privilege assignments at ${sink.label} without admin authorization. ` +
              `Attacker can escalate their own privileges or grant unauthorized access to other accounts.`,
            fix: 'Restrict privilege-modifying operations to admin-only endpoints. Verify the requesting user has privilege management permission. ' +
              'Never accept role/permission values from user input without validation against an allowlist. ' +
              'Log all privilege changes for audit.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-269', name: 'Improper Privilege Management', holds: findings.length === 0, findings };
}

/**
 * CWE-270: Privilege Context Switching Error
 * Pattern: Code switches privilege context (setuid, impersonate, runas) but doesn't
 * properly restore the original context, or switches to the WRONG context.
 * Property: Privilege context switches are always paired with proper restoration.
 *
 * Classic example: a setuid program that calls setuid(0) to become root for one op
 * but forgets to call setuid(original_uid) afterward, leaving the process elevated.
 * Also covers Windows impersonation (ImpersonateLoggedOnUser / RevertToSelf).
 */
function verifyCWE270(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CONTEXT_SWITCH = /\b(setuid|seteuid|setreuid|setresuid|setgid|setegid|setregid|setresgid|ImpersonateLoggedOnUser|ImpersonateNamedPipeClient|SetThreadToken|LogonUser|CreateProcessAsUser|su\s+-|sudo\s+-u|runuser|nsenter|unshare|setns|Process\.setuid|process\.setuid|process\.setgid|os\.setuid|os\.seteuid|os\.setgid|runas|become_user|assume_role|sts\.assumeRole|AssumeRole)\b/i;
  const CONTEXT_RESTORE = /\b(RevertToSelf|setuid\s*\(\s*saved_uid|seteuid\s*\(\s*orig|setuid\s*\(\s*old_uid|restorePriv|revert.*priv|dropBack|process\.setuid\s*\(\s*(?!0)\d|finally\s*\{[^}]*setuid|finally\s*\{[^}]*RevertToSelf)\b/i;

  const switchNodes = map.nodes.filter(n =>
    CONTEXT_SWITCH.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const node of switchNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (CONTEXT_SWITCH.test(code) && !CONTEXT_RESTORE.test(code)) {
      // Look for context restore in nodes reachable from this one
      let foundRestore = false;
      const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
      const visited = new Set<string>();
      const queue = [node.id];
      while (queue.length > 0) {
        const nid = queue.shift()!;
        if (visited.has(nid)) continue;
        visited.add(nid);
        const nd = nodeMap.get(nid);
        if (!nd || nd.id === node.id) {
          if (nd) for (const e of nd.edges) {
            if (!visited.has(e.target)) queue.push(e.target);
          }
          continue;
        }
        if (CONTEXT_RESTORE.test(stripComments(nd.analysis_snapshot || nd.code_snapshot))) { foundRestore = true; break; }
        for (const e of nd.edges) {
          if (!visited.has(e.target)) queue.push(e.target);
        }
      }
      if (!foundRestore) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (privilege context restoration — RevertToSelf, setuid(saved_uid), or try/finally)',
          severity: 'high',
          description: `Privilege context switch at ${node.label} without corresponding restoration. ` +
            `If the elevated context is not restored, subsequent code runs with wrong privileges.`,
          fix: 'Always pair privilege escalation with restoration in a try/finally block. ' +
            'Windows: pair ImpersonateLoggedOnUser with RevertToSelf. ' +
            'POSIX: save original UID with getuid() before setuid(0), restore with setuid(saved_uid) in finally. ' +
            'AWS: use session tokens with expiry, not long-lived assumed roles.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-270', name: 'Privilege Context Switching Error', holds: findings.length === 0, findings };
}

/**
 * CWE-271: Privilege Dropping / Lowering Errors
 * Pattern: Code attempts to drop privileges but does so incorrectly — e.g., drops
 * UID but not GID, drops effective UID but not real/saved UID, or doesn't verify
 * the drop succeeded.
 * Property: Privilege drops are complete and verified.
 *
 * Subtly different from CWE-273 (checking return value): CWE-271 is about the
 * DROP ITSELF being incomplete (wrong call, partial drop, ordering error).
 */
function verifyCWE271(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Detect nodes that drop UID but not GID (or vice versa)
  const DROP_UID = /\b(setuid|seteuid|setresuid|process\.setuid|os\.setuid|os\.seteuid)\b/i;
  const DROP_GID = /\b(setgid|setegid|setresgid|process\.setgid|os\.setgid|os\.setegid|initgroups|setgroups)\b/i;
  const FULL_DROP = /\b(drop.*all.*priv|dropPrivileges|lowerAllPriv|pledge|seccomp|sandbox)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const hasUidDrop = DROP_UID.test(code);
    const hasGidDrop = DROP_GID.test(code);

    if (hasUidDrop && !hasGidDrop && !FULL_DROP.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (complete privilege drop — must drop GID/supplementary groups BEFORE UID)',
        severity: 'high',
        description: `Privilege drop at ${node.label} is incomplete: UID is dropped but GID/supplementary groups are not. ` +
          `The process retains group-based access to files and resources owned by the original group.`,
        fix: 'Drop privileges in the correct order: (1) setgroups([]) to clear supplementary groups, ' +
          '(2) setgid(target_gid) to drop group, (3) setuid(target_uid) to drop user. ' +
          'Dropping UID first makes it impossible to drop GID afterward (unprivileged setgid fails).',
        via: 'structural',
      });
    }

    if (hasGidDrop && !hasUidDrop && !FULL_DROP.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (complete privilege drop — must also drop UID after GID)',
        severity: 'high',
        description: `Privilege drop at ${node.label} is incomplete: GID is dropped but UID is not. ` +
          `Process still runs as root/elevated user despite group change.`,
        fix: 'After dropping GID, also drop UID with setuid(target_uid). ' +
          'Verify drops succeeded by checking getuid() and getgid() return values.',
        via: 'structural',
      });
    }

    // Detect using seteuid instead of setuid (leaves saved-set-user-ID = root)
    const SETEUID_ONLY = /\bseteuid\s*\(\s*(?!0)\d/i;
    const SETUID_FULL = /\bsetuid\s*\(\s*(?!0)\d/i;
    if (SETEUID_ONLY.test(code) && !SETUID_FULL.test(code) && !FULL_DROP.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (permanent privilege drop — use setuid not seteuid)',
        severity: 'medium',
        description: `Privilege drop at ${node.label} uses seteuid() instead of setuid(). ` +
          `seteuid only changes the effective UID — the saved-set-user-ID remains root, allowing re-escalation via seteuid(0).`,
        fix: 'Use setuid() (not seteuid()) for permanent privilege drops. setuid() sets real, effective, AND saved UIDs. ' +
          'Or use setresuid(uid, uid, uid) to explicitly set all three.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-271', name: 'Privilege Dropping / Lowering Errors', holds: findings.length === 0, findings };
}

/**
 * CWE-272: Least Privilege Violation
 * Pattern: Code requests more permissions/capabilities than necessary, or runs
 * with broad permissions when narrow ones would suffice.
 * Property: Each component operates with minimum necessary privileges.
 *
 * This is the design-level counterpart to CWE-250: not just "running as root" but
 * requesting broad OAuth scopes, AWS IAM wildcards, Android permissions,
 * database grants, or file access beyond what's needed.
 */
function verifyCWE272(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const EXCESSIVE_PRIV = /\b(Action['":\s]*\*|Resource['":\s]*\*|Effect['":\s]*Allow.*Action['":\s]*\*|arn:aws:[^"]*:\*|GRANT\s+ALL|GRANT\s+.*\*\s+TO|chmod\s+777|chmod\s+666|0o?777|0o?666|\.scope\s*\(\s*['"][\w\s]*:?\*['"]|scope.*\*|admin:all|permissions.*all|full.?control|GENERIC_ALL|FILE_ALL_ACCESS|KEY_ALL_ACCESS|--cap-add\s+ALL|privileged:\s*true|SecurityPermissionFlag\.AllFlags|android\.permission\.READ_CONTACTS.*android\.permission\.CAMERA.*android\.permission\.RECORD_AUDIO)\b/i;
  const SCOPED_PRIV = /\b(Action['":\s]*['"][a-z]+:[A-Z][a-zA-Z]+['"]|Resource['":\s]*['"]arn:aws:[^"*]+['"]|Condition|GRANT\s+SELECT|GRANT\s+INSERT|GRANT\s+UPDATE|chmod\s+[0-6][04][04]|0o?[0-6][04][04]|scope.*readonly|scope.*read[_-]only|minimal|least.?priv|narrow|specific|--cap-drop|--cap-add\s+(?!ALL)[A-Z_]+|required.*only)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (EXCESSIVE_PRIV.test(code) && !SCOPED_PRIV.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (least privilege — scope permissions to minimum required)',
        severity: 'medium',
        description: `Excessive permissions granted at ${node.label}. ` +
          `Wildcard/all permissions (IAM *, GRANT ALL, chmod 777, cap-add ALL) violate least privilege principle. ` +
          `If this component is compromised, the attacker gains unnecessarily broad access.`,
        fix: 'Replace wildcard permissions with specific ones: IAM Action:"s3:GetObject" instead of "*". ' +
          'Use GRANT SELECT instead of GRANT ALL. Set file permissions to 0644 or 0600 instead of 0777. ' +
          'Drop unnecessary container capabilities. Request only necessary OAuth scopes.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-272', name: 'Least Privilege Violation', holds: findings.length === 0, findings };
}

/**
 * CWE-273: Improper Check for Dropped Privileges
 * Pattern: Code drops privileges (setuid, setgid) but doesn't check the return value.
 * Property: All privilege-dropping syscalls have their return values checked.
 *
 * The critical detail: setuid() can FAIL (e.g., RLIMIT_NPROC reached, or on some
 * systems when dropping from non-root). If the return is unchecked, the code
 * continues running with ELEVATED privileges while believing it dropped them.
 */
function verifyCWE273(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Calls to privilege-dropping functions
  const PRIV_DROP_CALL = /\b(setuid|seteuid|setreuid|setresuid|setgid|setegid|setregid|setresgid|initgroups|setgroups)\s*\(/i;
  // Checked patterns: if(setuid()), retval = setuid(); if(retval), assert, or throw
  const CHECKED_DROP = /\b(if\s*\(\s*(setuid|seteuid|setreuid|setresuid|setgid|setegid|setregid|setresgid|initgroups|setgroups)|assert\s*\(\s*(setuid|seteuid|setgid|setegid)|err\s*=\s*(setuid|seteuid|setgid|setegid)|ret\s*=\s*(setuid|seteuid|setgid|setegid)|result\s*=\s*(setuid|seteuid|setgid|setegid)|!=\s*0|==\s*-1|throw|raise|panic|die|abort|exit\s*\(|fatal|process\.exit)\b/i;
  // Higher-level safe wrappers that handle errors internally
  const SAFE_WRAPPER = /\b(dropPrivileges|drop_privileges|changeUser|switchUser|permanently_set_uid|daemon\(|pledge|process\.setuid|os\.setuid)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (PRIV_DROP_CALL.test(code) && !CHECKED_DROP.test(code) && !SAFE_WRAPPER.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (check return value of privilege drop — abort on failure)',
        severity: 'critical',
        description: `Privilege drop at ${node.label} does not check the return value. ` +
          `setuid()/setgid() can fail (RLIMIT_NPROC, EPERM). If unchecked, the process ` +
          `continues running as root while believing it has dropped privileges.`,
        fix: 'Always check the return value: if (setuid(uid) != 0) { perror("setuid"); abort(); }. ' +
          'After dropping, verify with getuid() == target_uid. In security-critical code, call abort() — NOT continue — on failure. ' +
          'Note: on Linux, setuid() for root always sets all three UIDs, but can still fail due to RLIMIT_NPROC.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-273', name: 'Improper Check for Dropped Privileges', holds: findings.length === 0, findings };
}

/**
 * CWE-274: Improper Handling of Insufficient Privileges
 * Pattern: Code doesn't handle the case where it lacks necessary privileges,
 * leading to silent failures, data corruption, or insecure fallbacks.
 * Property: Privilege insufficiency is detected and handled gracefully.
 *
 * The inverse of CWE-250: instead of having TOO MANY privileges, the code has
 * TOO FEW and doesn't handle it — falling back to insecure defaults, silently
 * skipping security operations, or crashing in an unsafe state.
 */
function verifyCWE274(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Operations that require privileges and may fail
  const PRIV_OPS = /\b(bind\s*\(\s*[^,]*,\s*(80|443)\b|chroot|chown|chmod|setuid|setgid|mlock|mlockall|nice\s*\(\s*-|sched_setscheduler|iptables|netfilter|raw.*socket|SOCK_RAW|cap_set|setrlimit|mount\s*\(|umount|pivot_root|keyctl|ptrace|kexec)\b/i;
  // Insecure fallback patterns
  const INSECURE_FALLBACK = /\b(catch\s*\([^)]*\)\s*\{[^}]*continue|catch\s*\([^)]*\)\s*\{\s*\}|on_error.*continue|rescue\s*=>\s*nil|except:\s*pass|\.catch\(\s*\(\s*\)\s*=>\s*\{\s*\}|EACCES.*ignore|EPERM.*ignore|fallback.*http|fallback.*insecure|disable.*tls|skip.*auth|skip.*check)\b/i;
  const PROPER_HANDLING = /\b(EACCES|EPERM|AccessDenied|PermissionError|UnauthorizedAccess|InsufficientPrivilege|throw|raise|abort|exit|fatal|log\.error|console\.error|process\.exit|sys\.exit|die|panic)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (PRIV_OPS.test(code)) {
      if (INSECURE_FALLBACK.test(code) || (!PROPER_HANDLING.test(code) && /\bcatch\b|\brescue\b|\bexcept\b/i.test(code))) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (handle privilege insufficiency — fail securely, not silently)',
          severity: 'medium',
          description: `Privileged operation at ${node.label} may fail due to insufficient privileges, but the error is ` +
            `silently swallowed or handled with an insecure fallback. Security operations that fail should fail CLOSED, not open.`,
          fix: 'Handle EACCES/EPERM explicitly. Do NOT silently continue — either abort with a clear error message, ' +
            'or fail to a secure default (deny access, not allow it). Never fall back from HTTPS to HTTP or skip auth on permission errors. ' +
            'Log the failure for operational visibility.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-274', name: 'Improper Handling of Insufficient Privileges', holds: findings.length === 0, findings };
}

/**
 * CWE-276: Incorrect Default Permissions
 * Pattern: Files, directories, or resources created with world-readable/writable
 * permissions, or sensitive files without restrictive permissions.
 * Property: All created files/resources use restrictive default permissions.
 *
 * Broader than CWE-378 (temp files): covers ALL file creation, config files,
 * database files, log files, socket files, IPC endpoints, shared memory.
 */
function verifyCWE276(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // File/resource creation patterns
  const FILE_CREATE = /\b(writeFile|writeFileSync|createWriteStream|open\s*\(|fopen|creat\s*\(|mkdir|mkdirSync|fs\.open|fs\.writeFile|fs\.mkdir|os\.open|os\.mkdir|os\.makedirs|File\.(new|create|open)|FileOutputStream|BufferedWriter|StreamWriter|Path\.write|IO\.write|socket\(.*AF_UNIX|shm_open|mq_open|sem_open|mkfifo)\b/i;
  // Insecure permissions (world-readable, world-writable, or excessively broad)
  const INSECURE_DEFAULT = /\b(0o?777|0o?766|0o?755|0o?666|0o?664|0o?644|S_IRWXO|S_IROTH|S_IWOTH|world.?read|world.?writ|umask\s*\(\s*0+\s*\)|umask\s*\(\s*0o?0+\s*\)|mode\s*[:=]\s*['"]?0?[67][0-7][4-7]|FileMode\.Parse\s*\(\s*['"]0?[67][0-7][4-7]|File\.umask\s*\(\s*0\s*\))\b/i;
  // Secure permissions
  const SECURE_DEFAULT = /\b(0o?600|0o?700|0o?400|0o?500|0o?640|S_IRUSR|S_IWUSR|owner.?only|umask\s*\(\s*0o?[0]?77\s*\)|umask\s*\(\s*0o?[0]?[0]?77\s*\)|mode\s*[:=]\s*['"]?0?[0-5]00|FileAttribute|OWNER_READ|OWNER_WRITE|restrictive|private)\b/i;

  const fileNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    FILE_CREATE.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const node of fileNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (INSECURE_DEFAULT.test(code) && !SECURE_DEFAULT.test(code)) {
      // Check if this is a sensitive file (config, credentials, keys, database)
      const SENSITIVE_FILE = /\b(config|credential|password|secret|key|cert|pem|token|database|\.db|\.sqlite|\.log|\.env|private|shadow|htpasswd|authorized_keys|id_rsa|\.pfx|\.jks)\b/i;
      const isSensitive = SENSITIVE_FILE.test(code) || SENSITIVE_FILE.test(node.label);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (restrictive file permissions — 0600 for sensitive, 0644 max for public)',
        severity: isSensitive ? 'high' : 'medium',
        description: `File/resource at ${node.label} created with overly permissive default permissions. ` +
          (isSensitive
            ? `This appears to contain sensitive data — world-readable permissions expose it to all local users.`
            : `Other users on the system can read or modify this resource.`),
        fix: 'Set permissions to 0600 (owner read/write) for sensitive files. ' +
          'Use umask(0077) before file creation to ensure restrictive defaults. ' +
          'For directories, use 0700 (owner only) or 0750 (owner + group). ' +
          'Never use 0777/0666 — even 0644 is too broad for secrets, keys, and configs.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-276', name: 'Incorrect Default Permissions', holds: findings.length === 0, findings };
}

/**
 * CWE-277: Insecure Inherited Permissions
 * Pattern: Child processes, threads, or objects inherit permissions from their parent
 * without explicit restriction, or files inherit directory ACLs that are too permissive.
 * Property: Inherited permissions are explicitly scoped or reduced for child entities.
 *
 * Common in: forked processes inheriting open file descriptors, child threads inheriting
 * security tokens, objects inheriting container/directory ACLs, subprocess inheriting
 * environment variables with secrets.
 */
function verifyCWE277(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns where inheritance creates risk
  const INHERIT_RISK = /\b(fork\s*\(|CreateProcess|Process\.Start|spawn|child_process\.(fork|exec|spawn)|subprocess\.(Popen|call|run)|os\.(fork|exec|spawn)|Runtime\.exec|ProcessBuilder|exec\.Command|Thread\.new|threading\.Thread|new\s+Thread|clone\s*\(|CLONE_|posix_spawn|CreateThread)\b/i;
  // Failing to restrict inherited permissions
  const INHERITS_PARENT = /\b(inherit.*handle|bInheritHandles\s*[:=]\s*true|close_fds\s*[:=]\s*False|HANDLE_FLAG_INHERIT|FD_CLOEXEC|O_CLOEXEC|inherit.*env|env\s*[:=]\s*process\.env|env\s*[:=]\s*os\.environ|shell\s*[:=]\s*true|SecurityImpersonation|TokenPrimary|DUPLICATE_SAME_ACCESS)\b/i;
  // Safe patterns — explicitly restricting inheritance
  const INHERIT_SAFE = /\b(close_fds\s*[:=]\s*True|CLOEXEC|FD_CLOEXEC|O_CLOEXEC|closefrom|fcntl.*F_SETFD|bInheritHandles\s*[:=]\s*false|env\s*[:=]\s*\{|env\s*[:=]\s*\[\]|env\s*[:=]\s*\{\s*\}|CreateRestrictedToken|dropInheritedPrivileges|clearenv|sanitize.*env|strip.*env|allowedEnv|PROC_THREAD_ATTRIBUTE_HANDLE_LIST)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (INHERIT_RISK.test(code) && INHERITS_PARENT.test(code) && !INHERIT_SAFE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (restrict inherited permissions — close FDs, sanitize env, restrict token)',
        severity: 'medium',
        description: `Child process/thread at ${node.label} inherits parent permissions without restriction. ` +
          `Open file descriptors, environment variables with secrets, and security tokens are passed to the child. ` +
          `A compromised child inherits the parent's full access.`,
        fix: 'Set close_fds=True (Python) or use O_CLOEXEC/FD_CLOEXEC to prevent FD inheritance. ' +
          'Pass a minimal env dict instead of inheriting process.env. ' +
          'Windows: set bInheritHandles=FALSE in CreateProcess, or use PROC_THREAD_ATTRIBUTE_HANDLE_LIST. ' +
          'Use CreateRestrictedToken to limit child token privileges.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-277', name: 'Insecure Inherited Permissions', holds: findings.length === 0, findings };
}

/**
 * CWE-279: Incorrect Execution-Assigned Permissions
 * Pattern: Executable files with setuid/setgid bit, or programs that request
 * execution-time permissions incorrectly (Android runtime permissions,
 * iOS entitlements, browser permission API without user gesture).
 * Property: Execution-time permissions are minimal and properly gated.
 *
 * Covers: setuid/setgid binaries, Windows manifest requestedExecutionLevel,
 * Android runtime permission requests, browser Permission API abuse,
 * macOS entitlements, and capability-based execution.
 */
function verifyCWE279(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Execution-assigned permission patterns
  const EXEC_PERM = /\b(chmod\s+[ug]\+s|chmod\s+[2-7][0-7]{3}|setuid\s+bit|setgid\s+bit|SUID|SGID|S_ISUID|S_ISGID|4[0-7]{3}|2[0-7]{3}|requestedExecutionLevel|requireAdministrator|highestAvailable|navigator\.permissions\.request|Notification\.requestPermission|getUserMedia|requestPermissions|ActivityCompat\.requestPermissions|NSCameraUsageDescription|entitlements|com\.apple\.security|capabilities\s*[:=]|cap_set_file|setcap|getcap)\b/i;
  // Overly broad execution permissions
  const BROAD_EXEC = /\b(requireAdministrator|highestAvailable|chmod\s+[ug]\+s|SUID.*root|setuid.*root|4755|4711|cap_set.*ALL|all.*permissions|permissions.*all|CAMERA.*MICROPHONE.*LOCATION|ACCESS_FINE_LOCATION.*READ_CONTACTS)\b/i;
  // Properly scoped
  const SCOPED_EXEC = /\b(asInvoker|chmod\s+0?755\b|cap_set.*(specific|minimal|net_bind)|single.*permission|one.*permission|user.*gesture|user.*interaction|userActivation|isUserGesture|requiresUserAction)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (EXEC_PERM.test(code)) {
      if (BROAD_EXEC.test(code) && !SCOPED_EXEC.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (scope execution-assigned permissions to minimum required)',
          severity: 'high',
          description: `Overly broad execution-assigned permissions at ${node.label}. ` +
            `Setuid-root binaries, requireAdministrator manifests, or bulk permission requests ` +
            `grant more privilege than needed at execution time.`,
          fix: 'Avoid setuid-root — use capabilities (setcap cap_net_bind_service=ep) for specific privileges. ' +
            'Windows: use asInvoker in manifest, elevate only specific operations via COM elevation moniker. ' +
            'Mobile: request permissions one at a time, at the moment they are needed, not at launch. ' +
            'Browser: only request permissions in response to user gestures.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-279', name: 'Incorrect Execution-Assigned Permissions', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Data Authenticity & Integrity Verification
// ---------------------------------------------------------------------------

/**
 * CWE-345: Insufficient Verification of Data Authenticity
 * Detects external/incoming data consumed without verifying its origin or integrity.
 * Covers postMessage without origin check, external data without authenticity
 * verification, webhook consumption without HMAC, IPC without validation.
 */
function verifyCWE345(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const POST_MSG_RE = /\b(addEventListener\s*\(\s*['"]message['"]|onmessage\s*=|\.on\s*\(\s*['"]message['"])\b/i;
  const ORIGIN_CHECK_RE = /\b(event\.origin|e\.origin|msg\.origin)\b.*===|===.*\b(event\.origin|e\.origin)\b|\borigin\s*!==?\b/i;
  const DESER_RE = /\bJSON\.parse\b|\byaml\.load\b|\bpickle\.loads?\b|\bunserialize\b|\beval\s*\(/i;
  const AUTH_VERIFY_RE = /\bverify\s*\(|\bhmac\b|\bsignature\b|\bauthenticate\s*\(|\bvalidateOrigin\b|\bcheckIntegrity\b|\btimingSafeEqual\b|\bcrypto\.verify\b/i;
  const FETCH_RE = /\bfetch\s*\(|\baxios\b|\bhttps?\.get\b|\brequest\s*\(|\bgot\s*\(|\bsuperagent\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (POST_MSG_RE.test(code)) {
      const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      const hasOriginCheck = ORIGIN_CHECK_RE.test(code) || sibs.some(n => ORIGIN_CHECK_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      if (!hasOriginCheck) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (origin validation for incoming messages)',
          severity: 'high',
          description: `Message listener at ${node.label} accepts messages without verifying event.origin. ` +
            `Any window or frame can send messages to this handler, enabling data injection.`,
          fix: 'Always check event.origin against an allowlist of trusted origins before processing postMessage data. ' +
            'Example: if (event.origin !== "https://trusted.example.com") return;',
          via: 'scope_taint',
        });
      }
    }
  }

  const externalDataNodes = map.nodes.filter(n =>
    (n.node_type === 'INGRESS' || n.node_type === 'EXTERNAL') &&
    (DESER_RE.test(n.analysis_snapshot || n.code_snapshot) || FETCH_RE.test(n.analysis_snapshot || n.code_snapshot)) &&
    (n.node_subtype.includes('webhook') || n.node_subtype.includes('ipc') ||
     n.node_subtype.includes('message') || n.node_subtype.includes('external') ||
     n.attack_surface.includes('external_data'))
  );

  for (const node of externalDataNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!AUTH_VERIFY_RE.test(code)) {
      const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      if (!sibs.some(n => AUTH_VERIFY_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)))) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (data authenticity verification — HMAC, signature, or origin check)',
          severity: 'high',
          description: `External data at ${node.label} is consumed without authenticity verification. ` +
            `An attacker could inject forged data via man-in-the-middle, DNS hijacking, or compromised upstream.`,
          fix: 'Verify data authenticity before processing: validate HMAC signatures for webhooks, ' +
            'check TLS certificate pinning for API calls, verify event.origin for postMessage, ' +
            'or use cryptographic signatures for deserialized data.',
          via: 'scope_taint',
        });
      }
    }
  }

  return { cwe: 'CWE-345', name: 'Insufficient Verification of Data Authenticity', holds: findings.length === 0, findings };
}

/**
 * CWE-346: Origin Validation Error
 * Detects CORS misconfigurations, missing or permissive origin checks,
 * wildcard Access-Control-Allow-Origin with credentials, and reflected origins.
 */
function verifyCWE346(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const WILDCARD_CORS_RE = /Access-Control-Allow-Origin['":\s]*\*|cors\s*\(\s*\)|origin\s*:\s*(?:true|\*|['"]?\*['"]?)/i;
  const CREDS_RE = /Access-Control-Allow-Credentials['":\s]*true|credentials\s*:\s*true/i;
  const REFLECT_RE = /origin\s*[:=]\s*(?:req\.headers?\.origin|request\.headers?\.origin|event\.origin|origin)/i;
  const SAFE_CORS_RE = /\ballowedOrigins\b|\bwhitelist\b|\ballowlist\b|\bcorsOptions\b.*\borigin\s*:\s*\[|\borigin\s*:\s*function|\borigin\s*:\s*\(|\.includes\s*\(\s*origin\b|\bvalidateOrigin\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (REFLECT_RE.test(code) && CREDS_RE.test(code)) {
      if (!SAFE_CORS_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (origin allowlist — never reflect arbitrary origins with credentials)',
          severity: 'critical',
          description: `CORS at ${node.label} reflects the request Origin header while allowing credentials. ` +
            `This is equivalent to no origin restriction — any website can make authenticated cross-origin requests.`,
          fix: 'Validate the Origin header against a strict allowlist of trusted domains. ' +
            'Never reflect the Origin header directly. ' +
            'Example: const allowed = ["https://app.example.com"]; if (allowed.includes(origin)) res.setHeader("Access-Control-Allow-Origin", origin);',
          via: 'structural',
        });
        continue;
      }
    }

    if (WILDCARD_CORS_RE.test(code) && CREDS_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (specific origin allowlist instead of wildcard)',
        severity: 'critical',
        description: `CORS at ${node.label} uses wildcard origin (*) with credentials enabled. ` +
          `Browsers block this, but misconfigured proxies may not — and it signals broken CORS logic.`,
        fix: 'Replace wildcard "*" with specific trusted origins. Credentials require an exact origin, not a wildcard.',
        via: 'structural',
      });
      continue;
    }

    if (WILDCARD_CORS_RE.test(code) && (node.node_type === 'AUTH' || node.node_type === 'STORAGE' ||
        node.attack_surface.includes('sensitive_data'))) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (restrictive CORS policy on sensitive endpoint)',
        severity: 'high',
        description: `Sensitive endpoint ${node.label} has wildcard CORS. ` +
          `While browsers enforce same-origin policy, wildcard CORS exposes data to any website.`,
        fix: 'Restrict Access-Control-Allow-Origin to specific trusted domains for sensitive endpoints. ' +
          'Use an allowlist and validate Origin before reflecting it.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-346', name: 'Origin Validation Error', holds: findings.length === 0, findings };
}

/**
 * CWE-348: Use of Less Trusted Source
 * Detects security decisions based on client-controlled or lower-trust data
 * when a higher-trust source is available.
 */
function verifyCWE348(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CLIENT_ROLE_RE = /\b(req\.body\.role|req\.body\.isAdmin|req\.body\.permissions|req\.query\.admin|user\.role\s*=\s*req\.(body|query|params)|claims?\.\w+\s*=\s*req\.(body|query))/i;
  const HEADER_TRUST_RE = /\b(x[_-]forwarded[_-]for|x[_-]real[_-]ip|x[_-]client[_-]ip)\b/i;
  const RATE_LIMIT_RE = /\b(rateLimit|rateLimiter|throttle|limiter|ban|block|allow|trust)\b/i;
  const PROXY_TRUST_RE = /\btrust\s*proxy\b|\bset\s*\(\s*['"]trust proxy['"]\b|\brealIp\b.*\bmodule\b|\bproxy_set_header\b/i;

  const decisionNodes = map.nodes.filter(n =>
    n.node_type === 'AUTH' || n.node_type === 'CONTROL'
  );

  for (const node of decisionNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (CLIENT_ROLE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'AUTH (server-side role lookup instead of client-supplied claims)',
        severity: 'critical',
        description: `Security decision at ${node.label} uses client-supplied role/permission data. ` +
          `Clients can trivially modify request body fields to escalate privileges.`,
        fix: 'Never trust client-supplied role or permission claims. ' +
          'Look up the user role from a server-side session or database after authentication.',
        via: 'structural',
      });
    }

    if (HEADER_TRUST_RE.test(code) && RATE_LIMIT_RE.test(code)) {
      if (!PROXY_TRUST_RE.test(code)) {
        const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
        if (!sibs.some(n => PROXY_TRUST_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)))) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (configure trusted proxy chain before using forwarded headers)',
            severity: 'medium',
            description: `Rate limiting at ${node.label} uses X-Forwarded-For without configuring trusted proxies. ` +
              `Attackers can bypass rate limits by spoofing the header.`,
            fix: 'Configure trust proxy settings (Express: app.set("trust proxy", 1)) so the framework ' +
              'correctly parses the client IP from the proxy chain.',
            via: 'scope_taint',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-348', name: 'Use of Less Trusted Source', holds: findings.length === 0, findings };
}

/**
 * CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data
 * Detects mass assignment, prototype pollution via spread/Object.assign,
 * and accepting extra untrusted fields merged into trusted objects.
 */
function verifyCWE349(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MASS_ASSIGN_RE = /Object\.assign\s*\(\s*\w+\s*,\s*req\.(body|query|params)|\.\.\.req\.(body|query|params)|\.update\s*\(\s*req\.body\s*\)|\.create\s*\(\s*req\.body\s*\)|new\s+\w+\s*\(\s*req\.body\s*\)/i;
  const SPREAD_RE = /\{[^}]*\.\.\.(?:body|input|data|payload|params|args)[^}]*\}/i;
  const SAFE_PICK_RE = /\bpick\b|\bonly\b|\ballowedFields\b|\bwhitelist\b|\ballowlist\b|\bfillable\b|\b(?:const|let|var)\s*\{\s*\w+(?:\s*,\s*\w+)*\s*\}\s*=/i;

  const ingress = nodesOfType(map, 'INGRESS');
  const storage = nodesOfType(map, 'STORAGE');

  for (const src of ingress) {
    for (const sink of storage) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
        if (MASS_ASSIGN_RE.test(sinkCode) || MASS_ASSIGN_RE.test(srcCode)) {
          if (!SAFE_PICK_RE.test(sinkCode)) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(sink),
              missing: 'CONTROL (field allowlist — accept only expected fields)',
              severity: 'high',
              description: `User input from ${src.label} is mass-assigned to ${sink.label} without field filtering. ` +
                `Attackers can inject extra fields (e.g., isAdmin=true) into trusted objects.`,
              fix: 'Explicitly pick only expected fields from user input. ' +
                'Use a DTO/schema validator (Joi, Zod, class-validator) to define accepted fields. ' +
                'Never spread raw req.body into database models or config objects.',
              via: 'bfs',
            });
          }
        }
      }
    }
  }

  const transformAndStorage = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE'
  );
  for (const node of transformAndStorage) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SPREAD_RE.test(code) && !SAFE_PICK_RE.test(code)) {
      const hasUntrustedInput = ingress.some(src =>
        hasTaintedPathWithoutControl(map, src.id, node.id)
      );
      if (hasUntrustedInput) {
        const alreadyReported = findings.some(f => f.sink.id === node.id);
        if (!alreadyReported) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (destructure only expected fields from untrusted objects)',
            severity: 'medium',
            description: `Untrusted data is spread into a trusted object at ${node.label}. ` +
              `Extra fields from the untrusted source contaminate the trusted object.`,
            fix: 'Destructure only known fields: const { name, email } = input; ' +
              'Or use a schema validator to strip unknown fields before merging.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-349', name: 'Acceptance of Extraneous Untrusted Data With Trusted Data', holds: findings.length === 0, findings };
}

/**
 * CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action
 * Detects DNS lookups used for authentication, access control, or trust decisions.
 */
function verifyCWE350(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const RDNS_RE = /\b(gethostbyaddr|reverse[_-]?dns|dns\.reverse|dns\.resolvePtr|ptr[_-]?record|nslookup|gethostbyname)\b/i;
  const DNS_TRUST_RE = /\b(hostname|host)\b.*\b(auth|allow|trust|whitelist|grant|verify|check|permit|deny|block)\b|\b(auth|allow|trust|whitelist|grant|verify)\b.*\b(hostname|host)\b/i;
  const LOG_ONLY_RE = /\b(log|logger|console\.log|debug|info|audit|trace|print)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (RDNS_RE.test(code)) {
      if (node.node_type === 'AUTH' || node.node_type === 'CONTROL') {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'AUTH (cryptographic identity instead of reverse DNS)',
          severity: 'high',
          description: `Reverse DNS lookup at ${node.label} is used for a security decision. ` +
            `PTR records are controlled by the IP address owner and can be set to any value.`,
          fix: 'Never use reverse DNS for authentication or access control. ' +
            'Use cryptographic authentication (TLS client certificates, JWT, API keys) instead. ' +
            'Reverse DNS is acceptable for logging and diagnostics only.',
          via: 'structural',
        });
        continue;
      }

      if (DNS_TRUST_RE.test(code) && !LOG_ONLY_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'AUTH (non-DNS-based authentication)',
          severity: 'high',
          description: `DNS hostname at ${node.label} appears to influence a trust decision. ` +
            `DNS responses can be spoofed via cache poisoning, BGP hijacking, or rogue PTR records.`,
          fix: 'Replace DNS-based trust with cryptographic identity verification. ' +
            'If hostname checking is needed, use forward-confirmed reverse DNS as defense-in-depth only.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-350', name: 'Reliance on Reverse DNS Resolution for a Security-Critical Action', holds: findings.length === 0, findings };
}

/**
 * CWE-353: Missing Support for Integrity Check
 * Detects data transmission, file download, or configuration loading without
 * integrity verification (checksums, HMAC, digital signatures, SRI).
 */
function verifyCWE353(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SCRIPT_RE = /\bsrc\s*=\s*['"]https?:\/\/|\blink\s*.*\bhref\s*=\s*['"]https?:\/\/|\bscript\b.*\bsrc\b/i;
  const SRI_RE = /\bintegrity\s*=\s*['"]sha(256|384|512)-|\bcrossorigin\b|\bsubresource[_-]?integrity\b|\bSRI\b/i;
  const DOWNLOAD_RE = /\b(download|fetch|get|pull|wget|curl|pipe)\b.*\b(file|binary|package|update|artifact|asset|zip|tar)\b/i;
  const CHECKSUM_RE = /\b(checksum|sha256|sha384|sha512|md5|hash|digest|integrity|verify)\b/i;
  const REMOTE_CONFIG_RE = /\b(loadConfig|fetchConfig|remoteConfig|getSettings)\b.*\bhttps?:\/\/|\bhttp\b.*\bconfig\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (SCRIPT_RE.test(code) && node.node_type !== 'META') {
      if (!SRI_RE.test(code)) {
        const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
        if (!sibs.some(n => SRI_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)))) {
          const cdnPattern = /src\s*=\s*['"]https?:\/\/(?!localhost|127\.0\.0\.1)/i;
          if (cdnPattern.test(code)) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(node),
              missing: 'CONTROL (Subresource Integrity hash for external scripts/styles)',
              severity: 'medium',
              description: `External resource loaded at ${node.label} without integrity checking. ` +
                `If the CDN is compromised, malicious code will be silently loaded.`,
              fix: 'Add SRI attributes: <script src="..." integrity="sha384-..." crossorigin="anonymous">.',
              via: 'scope_taint',
            });
          }
        }
      }
    }

    if (DOWNLOAD_RE.test(code) && (node.node_type === 'EXTERNAL' || node.node_type === 'INGRESS')) {
      if (!CHECKSUM_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (checksum/hash verification after download)',
          severity: 'medium',
          description: `File download at ${node.label} has no integrity check. ` +
            `A compromised mirror or MITM attacker could serve malicious content.`,
          fix: 'Verify downloaded file integrity against a known-good hash before use.',
          via: 'structural',
        });
      }
    }

    if (REMOTE_CONFIG_RE.test(code)) {
      if (!CHECKSUM_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (integrity verification for remote configuration)',
          severity: 'high',
          description: `Remote configuration loaded at ${node.label} without integrity verification. ` +
            `Compromised config server or MITM could inject malicious settings.`,
          fix: 'Sign configuration data and verify the signature before applying. ' +
            'Or pin the TLS certificate and verify response checksums.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-353', name: 'Missing Support for Integrity Check', holds: findings.length === 0, findings };
}

/**
 * CWE-356: Product UI does not Warn User of Unsafe Actions
 * Detects dangerous operations (deletion, payment, privilege changes) without
 * confirmation dialogs or user acknowledgment.
 */
function verifyCWE356(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DESTRUCTIVE_RE = /\b(delete|destroy|remove|drop|truncate|purge|wipe|erase)\b.*\b(all|account|user|data|database|table|collection)\b/i;
  const PRIVILEGE_RE = /\b(grant|revoke|setAdmin|makeAdmin|changeRole|escalate|elevate)\b/i;
  const PAYMENT_RE = /\b(charge|payment|transfer|withdraw|purchase|subscribe)\b.*\b(create|process|execute|submit)\b/i;
  const CONFIRM_RE = /\bconfirm\s*\(|\bwindow\.confirm\b|\bconfirmation\b|\bconfirmDialog\b|\bshowConfirm\b|\bare[_-]?you[_-]?sure\b|\bconfirm[_-]?action\b|\bconfirmDelete\b|\brequireConfirmation\b|\b2fa\b|\btwo[_-]?factor\b|\bverifyAction\b|\bre[_-]?authenticate\b|\bpassword[_-]?confirm\b/i;

  const actionNodes = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE' || n.node_type === 'EGRESS') &&
    (DESTRUCTIVE_RE.test(n.analysis_snapshot || n.code_snapshot) || PRIVILEGE_RE.test(n.analysis_snapshot || n.code_snapshot) || PAYMENT_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const node of actionNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!CONFIRM_RE.test(code)) {
      const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      const hasConfirm = sibs.some(n => CONFIRM_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      const hasControlConfirm = map.nodes.some(n =>
        n.node_type === 'CONTROL' && CONFIRM_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
      );

      if (!hasConfirm && !hasControlConfirm) {
        const actionType = DESTRUCTIVE_RE.test(code) ? 'destructive' :
          PRIVILEGE_RE.test(code) ? 'privilege-changing' : 'financial';
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (user confirmation before dangerous operation)',
          severity: 'medium',
          description: `${actionType.charAt(0).toUpperCase() + actionType.slice(1)} operation at ${node.label} proceeds without user confirmation. ` +
            `Accidental clicks, CSRF, or clickjacking could trigger irreversible ${actionType} actions.`,
          fix: `Add a confirmation step before ${actionType} operations: ` +
            'server-side confirmation token, re-authentication, or confirmation dialog. ' +
            'For high-value actions, require password re-entry or 2FA.',
          via: 'scope_taint',
        });
      }
    }
  }

  return { cwe: 'CWE-356', name: 'Product UI does not Warn User of Unsafe Actions', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Credential & Cookie Security
// ---------------------------------------------------------------------------

/**
 * CWE-565: Reliance on Cookies without Validation or Integrity Checking
 * Detects use of cookie values in security decisions without HMAC/signature
 * verification, allowing attackers to tamper with cookie-based auth.
 */
function verifyCWE565(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const COOKIE_READ_RE = /\b(req\.cookies|request\.cookies|document\.cookie|getCookie|cookie\.get|Cookies\.get|\$_COOKIE|cookies\[|cookie\[|request\.COOKIES|@CookieValue|@CookieParam)\b/i;
  const SECURITY_DECISION_RE = /\b(isAdmin|is_admin|role|permission|admin|moderator|authorized|privilege|access.?level|trust.?level|user.?type|membership|subscription|plan|tier|pricing)\b/i;
  const SIGNED_COOKIE_RE = /\b(signedCookies|req\.signedCookies|cookie-signature|cookie-parser.*secret|signed\s*[:=]\s*true|cookieSigner|hmac|jwt\.verify|verifySignature|validateToken|JSON\.parse.*verify)\b/i;
  const SESSION_RE = /\b(req\.session|session\[|express-session|cookie-session|flask\.session|session_start|Session\.get)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (COOKIE_READ_RE.test(code) && !SESSION_RE.test(code)) {
      // Cookie is read directly (not via session middleware)
      const usedInSecurityDecision = SECURITY_DECISION_RE.test(code);
      const hasSignatureCheck = SIGNED_COOKIE_RE.test(code);

      if (usedInSecurityDecision && !hasSignatureCheck) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (HMAC/signature verification on cookie values used in security decisions)',
          severity: 'high',
          description: `Cookie value at ${node.label} is used in a security decision (roles/permissions) without integrity verification. ` +
            `Attackers can modify client-side cookies to escalate privileges or bypass authorization.`,
          fix: 'Never trust raw cookie values for security decisions. Use signed cookies (cookie-parser with secret) ' +
            'or server-side sessions. For stateless auth, use JWTs with signature verification. ' +
            'Store roles and permissions server-side, not in client-modifiable cookies.',
          via: 'structural',
        });
      }

      // Check if cookie flows to storage/auth without validation
      if (!usedInSecurityDecision && !hasSignatureCheck) {
        const storageNodes = nodesOfType(map, 'STORAGE');
        const authNodes = map.nodes.filter(n => n.node_type === 'AUTH');
        for (const sink of [...storageNodes, ...authNodes]) {
          if (hasTaintedPathWithoutControl(map, node.id, sink.id)) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(sink),
              missing: 'CONTROL (validate cookie integrity before using in application logic)',
              severity: 'medium',
              description: `Unvalidated cookie from ${node.label} flows to ${sink.label}. ` +
                `Client-controlled cookies should not be trusted without server-side validation.`,
              fix: 'Validate cookie values server-side. Use signed cookies or HMAC to ensure integrity. ' +
                'Treat cookie data as untrusted user input requiring validation.',
              via: 'bfs',
            });
            break;
          }
        }
      }
    }
  }

  return { cwe: 'CWE-565', name: 'Reliance on Cookies without Validation or Integrity Checking', holds: findings.length === 0, findings };
}

/**
 * CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key
 * Detects patterns where user input directly controls SQL primary key lookups
 * without authorization checks, enabling IDOR-style access control bypass.
 */
function verifyCWE566(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PK_QUERY_RE = /\b(WHERE\s+id\s*=|findById|findByPk|get_object_or_404|\.get\s*\(\s*pk|primaryKey|\.find\s*\(\s*(?:req\.|params\.|request\.)|\[['"]id['"]\]|params\.id|params\[:id\]|request\.params\.\s*id)\b/i;
  const USER_INPUT_RE = /\b(req\.params|req\.query|req\.body|request\.args|request\.form|params\[|request\.GET|request\.POST|\$_GET|\$_POST|@PathVariable|@RequestParam|@PathParam)\b/i;
  const AUTH_CHECK_RE = /\b(req\.user\.id\s*===?\s*|currentUser|session\.userId|user_id\s*==?\s*|belongs_to|owned_by|authorize|checkOwnership|isOwner|verifyOwner|can\?\s*:|ability\.can|authorize!|policy|@PreAuthorize|@Secured|\.where\s*\(\s*.*user_id|\.filter\s*\(\s*.*owner)\b/i;

  const storageNodes = nodesOfType(map, 'STORAGE');
  const ingressNodes = nodesOfType(map, 'INGRESS');

  for (const node of storageNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (PK_QUERY_RE.test(code)) {
      // Check if user input flows to this PK query without authorization
      for (const src of ingressNodes) {
        if (USER_INPUT_RE.test(stripComments(src.analysis_snapshot || src.code_snapshot)) &&
            hasTaintedPathWithoutControl(map, src.id, node.id)) {
          // Check if there's an ownership/authorization check
          const hasAuthCheck = AUTH_CHECK_RE.test(code) ||
            map.nodes.some(n =>
              n.node_type === 'CONTROL' &&
              AUTH_CHECK_RE.test(n.analysis_snapshot || n.code_snapshot) &&
              n.line_start >= src.line_start && n.line_start <= node.line_start
            );

          if (!hasAuthCheck) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(node),
              missing: 'CONTROL (authorization check — verify user owns the resource before access)',
              severity: 'high',
              description: `User-supplied ID from ${src.label} used directly in primary key lookup at ${node.label} without ownership verification. ` +
                `Attackers can change the ID to access other users' records (IDOR).`,
              fix: 'Add ownership verification: WHERE id = :id AND user_id = :currentUserId. ' +
                'Use authorization middleware (e.g., CASL, Pundit, Spring Security) to enforce row-level access control. ' +
                'Never rely on the client-supplied ID alone for access control.',
              via: 'bfs',
            });
            break;
          }
        }
      }
    }
  }

  return { cwe: 'CWE-566', name: 'Authorization Bypass Through User-Controlled SQL Primary Key', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Authorization Bypass & Enforcement
// ---------------------------------------------------------------------------

/**
 * CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
 * Detects cookies carrying sensitive data (session IDs, auth tokens) that
 * don't set the Secure flag, allowing them to be sent over HTTP.
 */
function verifyCWE614(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SET_COOKIE_RE = /\b(res\.cookie|response\.set_cookie|setcookie|Set-Cookie|cookie\s*[:=]|setCookie|response\.cookies|add_header\s+Set-Cookie|\.cookie\s*\(|document\.cookie\s*=)/i;
  const SENSITIVE_COOKIE_RE = /\b(session|sess|token|auth|jwt|access.?token|refresh.?token|remember.?me|JSESSIONID|PHPSESSID|ASP\.NET_SessionId|connect\.sid|_session|csrf)\b/i;
  const SECURE_FLAG_RE = /\bsecure\s*[:=]\s*true\b|\bSecure\b|\bsecure\s*;\s*/i;
  const SESSION_CONFIG_RE = /\b(session|cookie-session|express-session)\b.*\b(cookie|options)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (SET_COOKIE_RE.test(code) || SESSION_CONFIG_RE.test(code)) {
      const isSensitive = SENSITIVE_COOKIE_RE.test(code) || SENSITIVE_COOKIE_RE.test(node.label);

      if (isSensitive) {
        const hasSecureFlag = SECURE_FLAG_RE.test(code);

        if (!hasSecureFlag) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (Secure flag on sensitive cookies)',
            severity: 'high',
            description: `Sensitive cookie set at ${node.label} without the Secure flag. ` +
              `Without Secure, the cookie will be sent over plain HTTP if a user visits an HTTP URL, ` +
              `allowing network attackers to steal session tokens via MITM.`,
            fix: 'Set the Secure flag on all cookies containing session IDs, auth tokens, or sensitive data. ' +
              'For Express: res.cookie("session", value, { secure: true, httpOnly: true, sameSite: "strict" }). ' +
              'Also set HttpOnly to prevent XSS theft and SameSite to prevent CSRF.',
            via: 'structural',
          });
        }
      }
    }
  }

  // Strategy B: Java-specific cookie patterns
  // Detects: cookie.setSecure(false) — explicit insecure flag
  // Also detects: new Cookie() followed by addCookie() without setSecure(true)
  const SET_SECURE_FALSE_RE = /\.setSecure\s*\(\s*false\s*\)/;
  const JAVA_COOKIE_RE = /new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(/;
  const SET_SECURE_TRUE_RE = /\.setSecure\s*\(\s*true\s*\)/;
  const reported614 = new Set<string>(findings.map(f => f.sink.id));

  for (const node of map.nodes) {
    if (reported614.has(node.id)) continue;
    const snap = node.analysis_snapshot || node.code_snapshot;
    // Explicit setSecure(false) — clear vulnerability
    if (SET_SECURE_FALSE_RE.test(snap)) {
      // Verify this isn't a mixed case where setSecure(true) is ALSO present for the SAME cookie
      // In BenchmarkTest00087, doGet sets setSecure(true) and doPost sets setSecure(false) on different cookies
      reported614.add(node.id);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (Secure flag on sensitive cookies)',
        severity: 'medium',
        description: `${node.label} explicitly sets cookie Secure flag to false. ` +
          `The cookie will be sent over unencrypted HTTP connections, exposing it to interception.`,
        fix: 'Set cookie.setSecure(true) to ensure cookies are only transmitted over HTTPS.',
        via: 'structural',
      });
    }
  }

  // Strategy C: Java new Cookie() + addCookie() without setSecure(true) (Juliet CWE-614 pattern)
  // The Juliet pattern: `new Cookie("name","value")` -> `response.addCookie(cookie)` with NO setSecure(true) call.
  // Scan per-function: if a function creates a Cookie and adds it but never calls setSecure(true), flag it.
  {
    const ADD_COOKIE_RE614 = /\.addCookie\s*\(/;
    for (const node of map.nodes) {
      if (reported614.has(node.id)) continue;
      const snap = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (!JAVA_COOKIE_RE.test(snap)) continue;
      if (!ADD_COOKIE_RE614.test(snap)) {
        const siblings = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
        const siblingHasAddCookie = siblings.some(n =>
          ADD_COOKIE_RE614.test(stripComments(n.analysis_snapshot || n.code_snapshot))
        );
        if (!siblingHasAddCookie) continue;
        const allHasSecure = SET_SECURE_TRUE_RE.test(snap) ||
          siblings.some(n => SET_SECURE_TRUE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
        if (!allHasSecure) {
          reported614.add(node.id);
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (cookie.setSecure(true) before addCookie)',
            severity: 'high',
            description: `${node.label} creates a Cookie and adds it to the response without calling setSecure(true). ` +
              `The cookie will be transmitted over unencrypted HTTP, exposing it to interception.`,
            fix: 'Call cookie.setSecure(true) before response.addCookie(cookie) to ensure the cookie is only sent over HTTPS.',
            via: 'scope_taint',
          });
        }
      } else {
        if (!SET_SECURE_TRUE_RE.test(snap)) {
          reported614.add(node.id);
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (cookie.setSecure(true) before addCookie)',
            severity: 'high',
            description: `${node.label} creates a Cookie and adds it to the response without calling setSecure(true). ` +
              `The cookie will be transmitted over unencrypted HTTP, exposing it to interception.`,
            fix: 'Call cookie.setSecure(true) before response.addCookie(cookie) to ensure the cookie is only sent over HTTPS.',
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-614', name: 'Sensitive Cookie in HTTPS Session Without Secure Attribute', holds: findings.length === 0, findings };
}

/**
 * CWE-602: Client-Side Enforcement of Server-Side Security
 * The server relies on the client to enforce security constraints that should
 * be checked server-side. Classic: hidden fields, disabled buttons, JS validation
 * with no server mirror. We look for INGRESS->STORAGE/EXTERNAL paths where
 * the only CONTROL nodes are client-side (contain client-side validation
 * patterns) with no server-side validation present.
 */
function verifyCWE602(map: NeuralMap): VerificationResult {
  // Client-side enforcement only matters in web/API contexts where there IS a client.
  if (!hasWebFrameworkContext(map)) {
    return { cwe: 'CWE-602', name: 'Client-Side Enforcement of Server-Side Security', holds: true, findings: [] };
  }
  const findings: Finding[] = [];
  const ingress602 = nodesOfType(map, 'INGRESS');
  const sinks602 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('write') || n.node_subtype.includes('db') ||
     n.node_subtype.includes('update') || n.node_subtype.includes('insert') ||
     n.node_subtype.includes('delete') || n.node_subtype.includes('api_call') ||
     n.attack_surface.includes('state_modification') ||
     /\b(INSERT|UPDATE|DELETE|save|create|put|patch|post|execute)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  // Client-side-only validation patterns -- these don't count as real server controls
  const CLIENT_ONLY602 = /\b(maxlength|minlength|pattern=|required\b.*type=|disabled|readonly|hidden|\.setCustomValidity|HTML5.*valid|onsubmit.*return|form\.check|clientSideValid|angular.*validator|v-model.*required|react-hook-form)\b/i;
  // Real server-side validation
  const SERVER_VALID602 = /\b(validate|sanitize|schema|z\.\w|joi\b|yup\b|class-?validator|express-validator|celebrate|checkBody|checkParams|assert|isValid|parseInt|parseFloat|Number\(|\.test\(|RegExp)\b/i;
  for (const src of ingress602) {
    for (const sink of sinks602) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const relatedControls = map.nodes.filter(n =>
          n.node_type === 'CONTROL' && sharesFunctionScope(map, n.id, sink.id)
        );
        const hasServerValid = relatedControls.some(c => SERVER_VALID602.test(stripComments(c.analysis_snapshot || c.code_snapshot)));
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!hasServerValid && !SERVER_VALID602.test(srcCode) && !SERVER_VALID602.test(sinkCode)) {
          const hasClientOnly = relatedControls.some(c => CLIENT_ONLY602.test(stripComments(c.analysis_snapshot || c.code_snapshot)));
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (server-side validation mirroring client-side constraints)',
            severity: 'high',
            description: `Input from ${src.label} reaches ${sink.label} without server-side validation.` +
              (hasClientOnly ? ' Client-side validation exists but is trivially bypassable.' : ' No validation found on either side.') +
              ' An attacker can replay requests with arbitrary data using curl/Burp.',
            fix: 'Duplicate ALL client-side validation on the server. Use schema validation (zod, joi, express-validator). ' +
              'Never trust maxlength, disabled, hidden, or JS-only checks.',
            via: 'bfs',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-602', name: 'Client-Side Enforcement of Server-Side Security', holds: findings.length === 0, findings };
}

/**
 * CWE-603: Use of Client-Side Authentication
 * Authentication happens in client-side code (browser JS, mobile app) and
 * the server trusts the result. The check: any AUTH node whose code contains
 * client-side auth patterns without corresponding server-side verification.
 */
function verifyCWE603(map: NeuralMap): VerificationResult {
  // Client-side auth only matters in web contexts.
  if (!hasWebFrameworkContext(map)) {
    return { cwe: 'CWE-603', name: 'Use of Client-Side Authentication', holds: true, findings: [] };
  }
  const findings: Finding[] = [];
  const ingress603 = nodesOfType(map, 'INGRESS');
  // Client-side auth patterns -- auth logic that runs in the browser
  const CLIENT_AUTH603 = /\b(localStorage\.getItem\(['"]token|sessionStorage\.getItem|document\.cookie.*auth|window\.auth|isAuthenticated\s*=\s*(true|false)|client.*auth|firebase\.auth\(\)\.currentUser|auth0\.isAuthenticated|Cookies\.get\(['"]token|jwt_decode)\b/i;
  // Server-side auth verification patterns
  const SERVER_AUTH603 = /\b(verify[TJ]oken|jwt\.verify|passport\.(authenticate|session)|requireAuth|isAuthenticated.*middleware|bcrypt\.compare|session\.\w+Id|req\.session\.user|verifySession|authenticate.*middleware|auth.*guard|@Authorized|@UseGuards|verify.*signature)\b/i;
  const authNodes603 = map.nodes.filter(n =>
    (n.node_type === 'AUTH' || n.node_type === 'CONTROL') &&
    (n.node_subtype.includes('auth') || n.node_subtype.includes('login') ||
     n.node_subtype.includes('session') ||
     /\b(auth|login|session|token|credential)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  for (const auth of authNodes603) {
    const code = stripComments(auth.analysis_snapshot || auth.code_snapshot);
    if (CLIENT_AUTH603.test(code) && !SERVER_AUTH603.test(code)) {
      let src603: typeof ingress603[0] | undefined;
      let via603: 'bfs' | 'scope_taint' = 'bfs';
      for (const s of ingress603) {
        if (hasTaintedPathWithoutControl(map, s.id, auth.id)) { src603 = s; via603 = 'bfs'; break; }
        if (!src603 && sharesFunctionScope(map, s.id, auth.id)) { src603 = s; via603 = 'scope_taint'; }
      }
      if (src603) {
        findings.push({
          source: nodeRef(src603), sink: nodeRef(auth),
          missing: 'AUTH (server-side authentication verification -- never trust client-side auth state)',
          severity: 'critical',
          description: `Authentication at ${auth.label} relies on client-side state (localStorage, cookies, client SDK). ` +
            `An attacker can forge auth tokens or set isAuthenticated=true in devtools.`,
          fix: 'Verify authentication server-side on every request. Use jwt.verify() or session lookup in middleware. ' +
            'Client-side auth state is only for UX -- never for security decisions.',
          via: via603,
        });
      }
    }
  }
  // Also check: ingress nodes with client-side auth leading to sensitive ops without server auth
  const sensitiveOps603 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.attack_surface.includes('admin') || n.attack_surface.includes('sensitive') ||
     n.node_subtype.includes('user_data') || n.node_subtype.includes('payment') ||
     /\b(user|account|payment|order|profile|settings|admin)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  for (const src of ingress603) {
    const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
    if (CLIENT_AUTH603.test(srcCode)) {
      for (const sink of sensitiveOps603) {
        if (src.id === sink.id) continue;
        if (hasTaintedPathWithoutAuth(map, src.id, sink.id)) {
          if (!findings.some(f => f.source.id === src.id && f.sink.id === sink.id)) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(sink),
              missing: 'AUTH (server-side auth middleware -- client-side auth check cannot protect server resources)',
              severity: 'critical',
              description: `Route at ${src.label} uses client-side auth before accessing ${sink.label}. ` +
                `Server never verifies identity. Attacker sends requests directly.`,
              fix: 'Add server-side auth middleware (passport, jwt.verify, session check) to protect this endpoint.',
              via: 'bfs',
            });
          }
        }
      }
    }
  }
  return { cwe: 'CWE-603', name: 'Use of Client-Side Authentication', holds: findings.length === 0, findings };
}

/**
 * CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
 * User supplies a resource identifier (ID, key, filename) and the server
 * uses it directly without verifying the user owns/has access to that resource.
 */
function verifyCWE639(map: NeuralMap): VerificationResult {
  // IDOR / user-controlled key only applies to web/API code with user-facing endpoints.
  if (!hasWebFrameworkContext(map)) {
    return { cwe: 'CWE-639', name: 'Authorization Bypass Through User-Controlled Key', holds: true, findings: [] };
  }
  const findings: Finding[] = [];
  const ingress639 = nodesOfType(map, 'INGRESS');
  const idInputs639 = ingress639.filter(n =>
    /\b(params\.\w*[iI]d|params\.\w*[kK]ey|query\.\w*[iI]d|query\.\w*[kK]ey|req\.params|req\.query|req\.body\.\w*[iI]d|request\.args|request\.form|:id|:userId|:orderId|:accountId|:fileId|:documentId|:resourceId)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );
  const keySources639 = idInputs639.length > 0 ? idInputs639 : ingress639;
  const lookupSinks639 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('db_read') || n.node_subtype.includes('db_write') ||
     n.node_subtype.includes('query') || n.node_subtype.includes('find') ||
     n.node_subtype.includes('lookup') || n.node_subtype.includes('file_read') ||
     /\b(findById|findOne|findByPk|getOne|get\(|SELECT.*WHERE|findUnique|findFirst|readFile|getObject|getBlob|getDocument|collection\.\w+\(|\.get\(\s*\w*[iI]d)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  const OWNER_CHECK639 = /\b(userId\s*[=!]==?\s*\w|user_id\s*[=!]==?\s*\w|ownerId|createdBy|belongsTo|author[iI]d|\.where\(\s*['"]user|WHERE\s+user_id|AND\s+user_id|req\.user\.id\s*[=!]==?|currentUser\.id|session\.user|checkOwnership|isOwner|verifyOwner|canAccess|hasAccess|authorize.*resource)\b/i;
  for (const src of keySources639) {
    for (const sink of lookupSinks639) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
        const hasOwnerCheck = OWNER_CHECK639.test(sinkCode) || OWNER_CHECK639.test(srcCode) ||
          map.nodes.some(n =>
            (n.node_type === 'CONTROL' || n.node_type === 'AUTH') &&
            OWNER_CHECK639.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
            sharesFunctionScope(map, n.id, sink.id)
          );
        if (!hasOwnerCheck && !findings.some(f => f.source.id === src.id && f.sink.id === sink.id)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (ownership/access verification for user-controlled key)',
            severity: 'high',
            description: `User-supplied key from ${src.label} directly controls resource lookup at ${sink.label} without ownership check. ` +
              `Attacker can enumerate or access other users' resources by changing the ID (IDOR).`,
            fix: 'Add ownership check: WHERE user_id = req.user.id. Or verify resource.ownerId === req.user.id after fetch. ' +
              'Use UUIDs instead of sequential IDs to reduce enumeration risk. Apply ABAC/RBAC.',
            via: 'bfs',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-639', name: 'Authorization Bypass Through User-Controlled Key', holds: findings.length === 0, findings };
}

/**
 * CWE-640: Weak Password Recovery Mechanism for Forgotten Password
 * Password reset flows that use predictable tokens, security questions,
 * or send passwords in plaintext.
 */
function verifyCWE640(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const RESET_FLOW640 = /\b(resetPassword|forgotPassword|password.*reset|reset.*password|recover.*password|password.*recover|send.*reset.*link|reset.*token|password.*recovery|recoverAccount|accountRecovery)\b/i;
  const WEAK_TOKEN640 = /\b(Math\.random|uuid\.v1|Date\.now|timestamp|sequential|predictable|md5\(.*email|md5\(.*user|btoa\(|base64.*encode.*email|encodeURIComponent.*email)\b/i;
  const SECURITY_QUESTION640 = /\b(securityQuestion|security_question|secretQuestion|secret_question|mother.*maiden|pet.*name|favorite.*color|born.*city|school.*attended)\b/i;
  const PLAINTEXT_PWD640 = /\b(send.*password|email.*password|password.*email|password.*plain|plain.*password|current.*password.*body|body.*contains.*password)\b/i;
  const SECURE_RESET640 = /\b(crypto\.randomBytes|crypto\.randomUUID|uuid\.v4|nanoid|secure.*random|randomBytes|generateToken|createSecureToken|bcrypt|argon2|scrypt|\.hash\(|tokenExpir|expir.*token|one.*time|otp|totp)\b/i;
  const RATE_LIMIT640 = /\b(rateLimit|rate_limit|throttle|rateLimiter|slowDown|brute.*force|attempts.*limit|max.*attempts|lockout|cooldown)\b/i;

  const resetNodes640 = map.nodes.filter(n => RESET_FLOW640.test(n.analysis_snapshot || n.code_snapshot));
  for (const node of resetNodes640) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (WEAK_TOKEN640.test(code) && !SECURE_RESET640.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (cryptographically secure reset token generation)',
        severity: 'high',
        description: `Password reset at ${node.label} uses weak/predictable token generation (Math.random, timestamps, MD5 of email). ` +
          `Attacker can predict reset tokens and take over accounts.`,
        fix: 'Use crypto.randomBytes(32) or uuid.v4() for reset tokens. Add expiration (15-60 min). ' +
          'Hash tokens before storing in DB. Rate-limit reset requests.',
        via: 'structural',
      });
    }
    if (SECURITY_QUESTION640.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (eliminate security questions -- use email/SMS token verification)',
        severity: 'medium',
        description: `Password recovery at ${node.label} uses security questions. ` +
          `Answers are often guessable or discoverable via social media.`,
        fix: 'Replace security questions with email/SMS OTP. Use TOTP-based recovery codes. ' +
          'Security questions are considered deprecated by NIST 800-63B.',
        via: 'structural',
      });
    }
    if (PLAINTEXT_PWD640.test(code) && !SECURE_RESET640.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (never send existing passwords -- use one-time reset links)',
        severity: 'critical',
        description: `Password recovery at ${node.label} appears to send the actual password. ` +
          `This implies passwords are stored reversibly (CWE-257) and exposes them in transit.`,
        fix: 'Never send existing passwords. Generate a one-time reset link with a cryptographic token. ' +
          'Force password change on use. Expire link after single use or timeout.',
        via: 'structural',
      });
    }
  }
  const resetIngress640 = nodesOfType(map, 'INGRESS').filter(n => RESET_FLOW640.test(n.analysis_snapshot || n.code_snapshot));
  for (const src of resetIngress640) {
    const hasRateLimit = map.nodes.some(n =>
      (n.node_type === 'CONTROL' || n.node_type === 'AUTH') &&
      RATE_LIMIT640.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
      sharesFunctionScope(map, n.id, src.id)
    ) || RATE_LIMIT640.test(stripComments(src.analysis_snapshot || src.code_snapshot));
    if (!hasRateLimit && !findings.some(f => f.source.id === src.id)) {
      findings.push({
        source: nodeRef(src), sink: nodeRef(src),
        missing: 'CONTROL (rate limiting on password reset endpoint)',
        severity: 'medium',
        description: `Password reset endpoint at ${src.label} has no rate limiting. ` +
          `Attacker can enumerate valid emails and brute-force reset tokens.`,
        fix: 'Rate-limit reset requests by IP and email. Limit to 3-5 requests per hour per email. ' +
          'Return the same response for valid and invalid emails to prevent enumeration.',
        via: 'scope_taint',
      });
    }
  }
  return { cwe: 'CWE-640', name: 'Weak Password Recovery Mechanism for Forgotten Password', holds: findings.length === 0, findings };
}

/**
 * CWE-645: Overly Restrictive Account Lockout Mechanism
 * Account lockout that is too aggressive, enabling denial-of-service via
 * intentional failed login attempts against target accounts.
 */
function verifyCWE645(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const LOCKOUT645 = /\b(lockout|lock_out|accountLock|account_lock|loginAttempts|login_attempts|failedAttempts|failed_attempts|maxAttempts|max_attempts|lockedUntil|locked_until|isLocked|is_locked|brute.*force.*protect|consecutiveFails)\b/i;
  const PERMANENT645 = /\b(permanent.*lock|lock.*permanent|disable.*account|account.*disable|isLocked\s*=\s*true(?!.*time)|locked\s*=\s*true(?!.*expir)|delete.*account.*lock|admin.*unlock.*only|require.*admin.*reset)\b/i;
  const LOW_THRESHOLD645 = /\b(maxAttempts|max_attempts|failedAttempts|attempts.*limit)\s*[=<>:]+\s*[12]\b|>=?\s*[12]\s*\).*lock|attempts\s*>=?\s*[12]/i;
  const GOOD_LOCKOUT645 = /\b(exponential.*delay|progressive.*delay|backoff|lockedUntil.*Date|locked.*expir|unlock.*after|cooldown.*period|captcha|recaptcha|hCaptcha|turnstile|temporary.*lock|time.*based.*lock|unlock.*time)\b/i;

  const lockoutNodes645 = map.nodes.filter(n => LOCKOUT645.test(n.analysis_snapshot || n.code_snapshot));
  for (const node of lockoutNodes645) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (PERMANENT645.test(code) && !GOOD_LOCKOUT645.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (time-based unlock or progressive delay instead of permanent lockout)',
        severity: 'medium',
        description: `Account lockout at ${node.label} appears permanent with no automatic recovery. ` +
          `Attacker can intentionally lock out target accounts as a denial-of-service attack.`,
        fix: 'Use progressive delay (exponential backoff) instead of hard lockout. ' +
          'If lockout is used, make it temporary (15-30 min). Add CAPTCHA after 3 failures. ' +
          'Lock by IP+account pair, not just account. Alert the user via secondary channel.',
        via: 'structural',
      });
    }
    if (LOW_THRESHOLD645.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (reasonable lockout threshold -- 3-5 attempts minimum)',
        severity: 'medium',
        description: `Account lockout at ${node.label} triggers after only 1-2 failed attempts. ` +
          `A single typo locks the user out. Attacker can trivially lock any account.`,
        fix: 'Set threshold to 5-10 attempts. Use progressive delay: 1s, 2s, 4s, 8s... ' +
          'Add CAPTCHA at attempt 3. Consider device/IP fingerprinting before locking.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-645', name: 'Overly Restrictive Account Lockout Mechanism', holds: findings.length === 0, findings };
}

/**
 * CWE-646: Reliance on File Name or Extension of Externally-Supplied File
 * Security decisions based on the file extension or name provided by the user
 * rather than inspecting file content (magic bytes, MIME sniffing).
 */
function verifyCWE646(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const FILE_UPLOAD646 = /\b(upload|multer|formidable|busboy|multipart|file\.\w*name|originalname|filename|req\.file|req\.files|request\.files|FileUpload|MultipartFile|IFormFile)\b/i;
  const EXT_CHECK646 = /\b(endsWith|\.ext\b|\.extension\b|path\.extname|\.split\(['"]\.['"]|mime.*type.*=.*['"].*\/|allowedExtensions|fileExtension|\.jpg|\.png|\.pdf|\.doc|acceptedTypes|file_type_check)\b/i;
  const CONTENT_CHECK646 = /\b(file-type|fileType|magic.*bytes|magic.*number|mime.*magic|image.*dimensions|sharp\(|jimp\.|Pillow|imghdr|filetype\.guess|readChunk|fromBuffer|createReadStream.*pipe|file.*signature|Buffer\.from.*slice|header.*bytes)\b/i;

  const fileNodes646 = map.nodes.filter(n =>
    FILE_UPLOAD646.test(n.analysis_snapshot || n.code_snapshot) &&
    (n.node_type === 'INGRESS' || n.node_type === 'CONTROL' || n.node_type === 'TRANSFORM')
  );
  for (const node of fileNodes646) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (EXT_CHECK646.test(code) && !CONTENT_CHECK646.test(code)) {
      const hasContentCheck = map.nodes.some(n =>
        CONTENT_CHECK646.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
        sharesFunctionScope(map, n.id, node.id)
      );
      if (!hasContentCheck) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (content-based file type validation -- inspect magic bytes, not extension)',
          severity: 'high',
          description: `File handling at ${node.label} validates by extension/name only. ` +
            `Attacker can rename malicious.php to malicious.jpg to bypass the filter.`,
          fix: 'Use file-type or mmmagic to inspect file content (magic bytes). ' +
            'Validate both extension AND content match. Store files with server-generated names. ' +
            'Serve uploads from a separate domain with Content-Disposition: attachment.',
          via: 'scope_taint',
        });
      }
    }
  }
  const UNSAFE_NAME646 = /\b(originalname|filename|file\.name|req\.file\.originalname|upload.*name)\b.*\b(path\.join|writeFile|createWriteStream|moveFile|saveTo|destination)/i;
  const storageSinks646 = map.nodes.filter(n =>
    n.node_type === 'STORAGE' && UNSAFE_NAME646.test(n.analysis_snapshot || n.code_snapshot)
  );
  for (const sink of storageSinks646) {
    if (!findings.some(f => f.sink.id === sink.id)) {
      findings.push({
        source: nodeRef(sink), sink: nodeRef(sink),
        missing: 'CONTROL (server-generated filename -- never use client-supplied names for storage)',
        severity: 'high',
        description: `File stored at ${sink.label} using client-supplied filename. ` +
          `Attacker can use path traversal in filename or overwrite critical files.`,
        fix: 'Generate a unique filename server-side (uuid + validated extension). ' +
          'Never use originalname directly. Sanitize and validate against an allowlist of extensions.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-646', name: 'Reliance on File Name or Extension of Externally-Supplied File', holds: findings.length === 0, findings };
}

/**
 * CWE-649: Reliance on Obfuscation or Encryption of Security-Relevant Inputs
 * Using encoding/obfuscation/encryption as a substitute for proper validation
 * or access control. E.g., Base64-encoding an admin flag, encrypting a user ID
 * in a URL instead of checking authorization server-side.
 */
function verifyCWE649(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const OBFUSCATION_AS_AUTH649 = /\b(base64.*decode.*role|decode.*admin|atob.*permission|btoa.*auth|encrypt.*userId.*url|encrypted.*parameter|obfuscat.*security|encoded.*token.*=|decode.*access.*level|rot13|xor.*password|encode.*permission)\b/i;
  const SECURITY_BY_OBSCURITY649 = /\b(hidden.*field.*admin|secret.*url|admin.*path.*obscur|unguessable.*url|security.*through.*obscurity|secret.*endpoint|hidden.*api|private.*url.*no.*auth)\b/i;
  const REAL_ACCESS_CTRL649 = /\b(authorize|checkPermission|hasRole|rbac|abac|acl|jwt\.verify|verifyToken|session\.user|req\.user\.role|isAuthorized|@Authorized|@UseGuards|policy|guard|requireRole)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (OBFUSCATION_AS_AUTH649.test(code) && !REAL_ACCESS_CTRL649.test(code)) {
      const hasAuth = map.nodes.some(n =>
        (n.node_type === 'AUTH' || n.node_type === 'CONTROL') &&
        REAL_ACCESS_CTRL649.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
        sharesFunctionScope(map, n.id, node.id)
      );
      if (!hasAuth) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (real authorization -- encoding/encryption is not access control)',
          severity: 'high',
          description: `Code at ${node.label} uses encoding/obfuscation for security-relevant inputs. ` +
            `Base64 and encryption can be reversed; they are not access control.`,
          fix: 'Replace obfuscation with real authorization checks. Verify permissions server-side. ' +
            'Encoding hides data from casual inspection, not from attackers.',
          via: 'scope_taint',
        });
      }
    }
    if (SECURITY_BY_OBSCURITY649.test(code) && !REAL_ACCESS_CTRL649.test(code)) {
      const hasAuth = map.nodes.some(n =>
        (n.node_type === 'AUTH' || n.node_type === 'CONTROL') &&
        REAL_ACCESS_CTRL649.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
        sharesFunctionScope(map, n.id, node.id)
      );
      if (!hasAuth && !findings.some(f => f.source.id === node.id)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (real access control -- "unguessable" URLs/endpoints are not security)',
          severity: 'medium',
          description: `Code at ${node.label} relies on obscurity (secret URLs, hidden endpoints) for security. ` +
            `URLs leak through logs, referer headers, browser history, and sharing.`,
          fix: 'Add proper authentication and authorization. Secret URLs can supplement but never replace access control.',
          via: 'scope_taint',
        });
      }
    }
  }
  return { cwe: 'CWE-649', name: 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Access Control', holds: findings.length === 0, findings };
}

/**
 * CWE-650: Trusting HTTP Permission Methods on the Server Side
 * Server uses the HTTP method (GET vs POST) as a security control --
 * e.g., only applying CSRF protection to POST but not PUT/DELETE/PATCH,
 * or assuming GET requests are safe and skipping auth.
 */
function verifyCWE650(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const METHOD_AS_SECURITY650 = /\b(if\s*\(\s*req\.method\s*[=!]==?\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]|method\s*[=!]==?\s*['"](?:GET|POST)['"].*(?:auth|csrf|token|verify)|skip.*(?:csrf|auth).*GET|GET.*safe|safe.*method.*GET|req\.method\s*!==?\s*['"]POST['"].*return)\b/i;
  const CSRF_SKIP_GET650 = /\b(csurf|csrf).*(?:ignore|exclude|skip).*(?:GET|HEAD|OPTIONS)|(?:GET|HEAD|OPTIONS).*(?:ignore|exclude|skip).*(?:csurf|csrf)/i;
  const AUTH_SKIP_GET650 = /\b(if\s*\(\s*req\.method\s*===?\s*['"]GET['"].*(?:next\(\)|return|skip))|(?:GET|HEAD).*(?:no.*auth|skip.*auth|public)/i;
  const METHOD_AGNOSTIC650 = /\b(app\.all\(|router\.all\(|@All\(|method.*agnostic|apply.*all.*methods|middleware.*before.*route)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (METHOD_AS_SECURITY650.test(code) || CSRF_SKIP_GET650.test(code) || AUTH_SKIP_GET650.test(code)) {
      if (!METHOD_AGNOSTIC650.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (apply security controls regardless of HTTP method)',
          severity: 'medium',
          description: `Security at ${node.label} depends on HTTP method. ` +
            `GET requests can have side effects and carry tokens in query strings. ` +
            `Attacker can change method to bypass CSRF/auth checks.`,
          fix: 'Apply auth and CSRF protection to ALL methods. GET is not inherently safe. ' +
            'Use SameSite cookies and check Origin/Referer for CSRF regardless of method. ' +
            'If skipping CSRF for GET, ensure the endpoint truly has no side effects.',
          via: 'structural',
        });
      }
    }
  }
  const GET_STATE_CHANGE650 = /\b(app\.get|router\.get|@Get)\b.*\b(delete|remove|update|create|modify|admin|logout|transfer|approve|execute|confirm)\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (GET_STATE_CHANGE650.test(code)) {
      if (!findings.some(f => f.source.id === node.id)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (use POST/PUT/DELETE for state-changing operations, not GET)',
          severity: 'medium',
          description: `State-changing operation at ${node.label} is accessible via GET. ` +
            `GET requests can be triggered by img tags, link prefetching, and are logged in browser history.`,
          fix: 'Move state-changing operations to POST/PUT/DELETE. Apply CSRF protection. ' +
            'GET should only be used for idempotent read operations.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-650', name: 'Trusting HTTP Permission Methods on the Server Side', holds: findings.length === 0, findings };
}

/**
 * CWE-653: Improper Isolation or Compartmentalization
 * Components that should be isolated share resources, processes, or trust
 * boundaries. E.g., running admin and user code in the same process without
 * separation, shared database credentials between micro-services.
 */
function verifyCWE653(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SHARED_CREDS653 = /\b(shared.*connection|same.*db.*cred|global.*pool|single.*pool|connection.*string.*shared|universal.*api.*key|one.*key.*for.*all|master.*key.*everywhere)\b/i;
  const ISOLATION653 = /\b(sandbox|isolat|compartment|separate.*process|microservice|worker|container|namespace|security.*context|privilege.*separat|least.*privilege|jail|chroot|seccomp|AppArmor|SELinux)\b/i;

  const adminNodes653 = map.nodes.filter(n =>
    n.attack_surface.includes('admin') || n.node_subtype.includes('admin') ||
    /\b(admin|superuser|root|elevated|privileged|system)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );
  const userNodes653 = map.nodes.filter(n =>
    n.node_type === 'INGRESS' &&
    !n.attack_surface.includes('admin') && !n.node_subtype.includes('admin')
  );
  for (const admin of adminNodes653) {
    for (const user of userNodes653) {
      if (sharesFunctionScope(map, admin.id, user.id)) {
        const hasIsolation = ISOLATION653.test(stripComments(admin.analysis_snapshot || admin.code_snapshot)) ||
          map.nodes.some(n =>
            ISOLATION653.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
            sharesFunctionScope(map, n.id, admin.id)
          );
        if (!hasIsolation && !findings.some(f => f.sink.id === admin.id)) {
          findings.push({
            source: nodeRef(user), sink: nodeRef(admin),
            missing: 'STRUCTURAL (privilege isolation -- separate admin operations from user context)',
            severity: 'medium',
            description: `Admin operation at ${admin.label} shares execution context with user entry point at ${user.label}. ` +
              `A vulnerability in user-facing code could escalate to admin privileges.`,
            fix: 'Isolate admin operations in separate modules/processes/containers. ' +
              'Use separate DB credentials with minimal privileges per component. ' +
              'Apply principle of least privilege at every boundary.',
            via: 'scope_taint',
          });
        }
      }
    }
  }
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SHARED_CREDS653.test(code) && !ISOLATION653.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (separate credentials per trust level / component)',
        severity: 'medium',
        description: `Code at ${node.label} uses shared credentials or connection pools across trust boundaries. ` +
          `Compromise of any component grants access to all shared resources.`,
        fix: 'Use separate credentials per service/component. Apply least-privilege DB grants. ' +
          'Separate read/write connection pools. Use service accounts with minimal permissions.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-653', name: 'Improper Isolation or Compartmentalization', holds: findings.length === 0, findings };
}

/**
 * CWE-654: Reliance on a Single Factor in a Security Decision
 * Security decisions based on exactly one signal -- a single cookie, a single
 * IP address, a single header, or a single password without MFA.
 */
function verifyCWE654(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SINGLE_FACTOR654 = /\b(password\s*===|password\s*==\s*|apiKey\s*===|api_key\s*===|token\s*===|x-api-key|Bearer\s+\w|cookie\s*===|req\.headers\['x-|single.*auth|one.*factor)\b/i;
  const HIGH_ASSURANCE654 = /\b(admin|transfer|payment|withdraw|delete.*account|change.*password|change.*email|update.*role|export.*data|download.*all|bulk.*delete|api.*key.*create|grant.*permission|elevat.*privilege)\b/i;
  const MULTI_FACTOR654 = /\b(mfa|2fa|two.?factor|multi.?factor|totp|authenticator|sms.*code|email.*verif|device.*fingerprint|ip.*check.*\+.*token|step.?up.*auth|re.?authenticat|confirm.*password.*\+|second.*factor|biometric|webauthn|fido|passkey)\b/i;

  const authNodes654 = map.nodes.filter(n =>
    n.node_type === 'AUTH' ||
    (n.node_type === 'CONTROL' && (n.node_subtype.includes('auth') || n.node_subtype.includes('login')))
  );
  const sensitiveOps654 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    HIGH_ASSURANCE654.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const auth of authNodes654) {
    const authCode = stripComments(auth.analysis_snapshot || auth.code_snapshot);
    if (SINGLE_FACTOR654.test(authCode) && !MULTI_FACTOR654.test(authCode)) {
      for (const sink of sensitiveOps654) {
        if (auth.id === sink.id) continue;
        const scopeHit654 = sharesFunctionScope(map, auth.id, sink.id);
        const bfsHit654 = !scopeHit654 && hasTaintedPathWithoutControl(map, auth.id, sink.id);
        const connected = scopeHit654 || bfsHit654;
        if (connected) {
          const hasMFA = map.nodes.some(n =>
            MULTI_FACTOR654.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
            sharesFunctionScope(map, n.id, sink.id)
          );
          if (!hasMFA && !findings.some(f => f.source.id === auth.id && f.sink.id === sink.id)) {
            findings.push({
              source: nodeRef(auth), sink: nodeRef(sink),
              missing: 'AUTH (multi-factor authentication for sensitive operations)',
              severity: 'medium',
              description: `Sensitive operation at ${sink.label} is protected only by single-factor auth at ${auth.label}. ` +
                `If the single factor (password, token, key) is compromised, there is no fallback.`,
              fix: 'Add step-up authentication for sensitive operations: require MFA/2FA. ' +
                'Combine something you know (password) + something you have (TOTP/SMS) + something you are (biometric). ' +
                'At minimum, require re-authentication for critical actions.',
              via: scopeHit654 ? 'scope_taint' : 'bfs',
            });
          }
        }
      }
    }
  }
  const IP_ONLY654 = /\b(req\.ip\s*===|remoteAddress\s*===|x-forwarded-for.*===|ipWhitelist|allowedIPs|ip.*filter|ip.*restrict)\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (IP_ONLY654.test(code) && !MULTI_FACTOR654.test(code) && !SINGLE_FACTOR654.test(code)) {
      if (!findings.some(f => f.source.id === node.id)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'AUTH (IP-based access control alone is insufficient -- add authentication)',
          severity: 'medium',
          description: `Access control at ${node.label} relies only on IP address. ` +
            `IPs can be spoofed, shared (NAT/VPN), or changed. X-Forwarded-For is client-controlled.`,
          fix: 'Use IP restrictions as defense-in-depth, not as sole access control. ' +
            'Combine with authentication (JWT/session) + authorization (RBAC). ' +
            'Never trust X-Forwarded-For without trusted proxy configuration.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-654', name: 'Reliance on a Single Factor in a Security Decision', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Dynamic Code & Mass Assignment
// ---------------------------------------------------------------------------

function verifyCWE913(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DYNAMIC_CODE_PATTERNS: Array<{ pattern: RegExp; name: string; fix: string }> = [
    { pattern: /\b(?:require|import)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input\.|user\.|args\.|argv\.|process\.env\b)/i,
      name: 'dynamic require/import from user input',
      fix: 'Use an allowlist: const ALLOWED = new Set(["mod1","mod2"]); if (!ALLOWED.has(name)) throw new Error("forbidden");' },
    { pattern: /\b(?:__import__|importlib\.import_module|exec|execfile)\s*\(\s*(?:request\.|params\.|args\.|input\.|sys\.argv|os\.environ)\b/i,
      name: 'Python dynamic import from user input',
      fix: 'Use an allowlist: ALLOWED = {"mod1", "mod2"}; assert name in ALLOWED' },
    { pattern: /\b(?:include|require|include_once|require_once)\s*(?:\(\s*)?(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)/i,
      name: 'PHP include/require from user input (LFI/RFI)',
      fix: 'Use an allowlist. Never pass user input to include/require. Disable allow_url_include.' },
    { pattern: /\b(?:Class\.forName|URLClassLoader|ServiceLoader\.load|loadClass)\s*\(\s*(?:request\.|params\.|getParameter|getHeader)\b/i,
      name: 'Java dynamic class loading from user input',
      fix: 'Use an allowlist of permitted class names. Never load classes from user-controlled paths.' },
    { pattern: /\b(?:const_get|constantize|send|public_send|method)\s*\(\s*(?:params|request|session)\b/i,
      name: 'Ruby dynamic dispatch from user input',
      fix: 'Use an allowlist: ALLOWED = %w[action1 action2]; raise unless ALLOWED.include?(name)' },
    { pattern: /\b(?:Assembly\.Load(?:From|File)?|Activator\.CreateInstance|Type\.GetType)\s*\(\s*(?:Request|QueryString|Form|HttpContext)\b/i,
      name: '.NET dynamic assembly loading from user input',
      fix: 'Use an allowlist of permitted assembly/type names.' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const p of DYNAMIC_CODE_PATTERNS) {
      if (p.pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `CONTROL (code loading allowlist — ${p.name})`,
          severity: 'critical',
          description: `${node.label}: ${p.name}. ` +
            `Dynamically loading code from external input allows attackers to execute arbitrary code.`,
          fix: p.fix,
          via: 'structural',
        });
        break;
      }
    }
  }

  // Check INGRESS->EXTERNAL paths where external is a code resource
  const ingress = nodesOfType(map, 'INGRESS');
  const externals = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    /\b(plugin|module|import|load|class|script|require|eval|exec)\b/i.test(n.node_subtype + ' ' + n.label)
  );
  for (const src of ingress) {
    for (const ext of externals) {
      if (hasTaintedPathWithoutControl(map, src.id, ext.id)) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(ext),
          missing: 'CONTROL (code resource integrity validation)',
          severity: 'critical',
          description: `User input from ${src.label} reaches code loading at ${ext.label} without validation.`,
          fix: 'Implement an allowlist of permitted code resources. Verify integrity with checksums or signatures.',
          via: 'bfs',
        });
      }
    }
  }

  return { cwe: 'CWE-913', name: 'Improper Control of Dynamically-Managed Code Resources', holds: findings.length === 0, findings };
}

function verifyCWE915(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MASS_ASSIGN_PATTERNS: Array<{ pattern: RegExp; name: string; fix: string; severity: 'high' | 'critical' }> = [
    { pattern: /\bObject\.assign\s*\(\s*\w+\s*,\s*(?:req\.body|request\.body|ctx\.request\.body|params|args)\b/i,
      name: 'Object.assign from request body (mass assignment)',
      fix: 'Extract only allowed fields: const { name, email } = req.body; Object.assign(user, { name, email });',
      severity: 'high' },
    { pattern: /\{\s*\.\.\.(?:req\.body|request\.body|ctx\.request\.body|params|args)\s*\}/i,
      name: 'Spread operator from request body (mass assignment)',
      fix: 'Destructure only allowed fields: const { name, email } = req.body;',
      severity: 'high' },
    { pattern: /\b(?:create|update|new|build|assign_attributes)\s*\(\s*params(?!\s*\.\s*(?:require|permit))\b/i,
      name: 'Rails params used without strong parameters (permit)',
      fix: 'Use strong parameters: Model.create(params.require(:model).permit(:name, :email)).',
      severity: 'high' },
    { pattern: /\bclass\s+\w+\s*\(\s*(?:ModelForm|ModelSerializer)\s*\)[\s\S]{0,200}?fields\s*=\s*['"]__all__['"]/i,
      name: 'Django ModelForm/Serializer with fields = "__all__"',
      fix: 'Explicitly list allowed fields: fields = ["name", "email"]. Never use "__all__".',
      severity: 'high' },
    { pattern: /\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+(?:req\.body|request\.body|params|input)\s*\)\s*\{[\s\S]{0,200}?\[\s*\w+\s*\]\s*=/i,
      name: 'for-in loop copying arbitrary properties from user input',
      fix: 'Use an allowlist: const ALLOWED = ["name", "email"]; for (const key of ALLOWED) { target[key] = input[key]; }',
      severity: 'high' },
    { pattern: /\bextract\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|json_decode)\b/i,
      name: 'PHP extract() on user input (overwrites local variables)',
      fix: 'Never use extract() on user input. Access fields individually: $name = $_POST["name"];',
      severity: 'critical' },
    { pattern: /\b(?:findOneAndUpdate|updateOne|updateMany|findByIdAndUpdate)\s*\([^,]+,\s*(?:req\.body|request\.body|\{\s*\$set\s*:\s*req\.body)\b/i,
      name: 'Mongoose update with full request body (mass assignment)',
      fix: 'Pick only allowed fields: Model.updateOne(query, { $set: { name: req.body.name } })',
      severity: 'high' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const p of MASS_ASSIGN_PATTERNS) {
      if (p.pattern.test(code)) {
        if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `CONTROL (property allowlist — ${p.name})`,
          severity: p.severity,
          description: `${node.label}: ${p.name}. ` +
            `User input controls which properties are set. Attackers can add fields like "isAdmin: true".`,
          fix: p.fix,
          via: 'structural',
        });
        break;
      }
    }
  }

  // Check INGRESS->STORAGE paths for uncontrolled attribute assignment
  const ingress = nodesOfType(map, 'INGRESS');
  const storages = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    /\b(model|entity|record|user|account|profile|document|collection)\b/i.test(n.node_subtype + ' ' + n.label)
  );
  for (const src of ingress) {
    for (const sink of storages) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (/\b(create|save|insert|update|assign|merge|patch)\b/i.test(sinkCode) &&
            !/\b(permit|allowlist|whitelist|pick|only|schema\.validate|joi\.|yup\.|zod\.)\b/i.test(sinkCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (field allowlist before persistence)',
            severity: 'high',
            description: `User input from ${src.label} reaches persistence at ${sink.label} without field filtering.`,
            fix: 'Add an explicit allowlist of mutable fields. Use schema validation (Joi, Zod, strong params) to reject unexpected fields.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-915', name: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// URL Schemes, Cross-Domain & UI Security
// ---------------------------------------------------------------------------

function verifyCWE1022(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // target="_blank" without noopener — the classic reverse-tabnabbing vector
  const TARGET_BLANK_RE = /target\s*=\s*['"`]_blank['"`]/i;
  const REL_NOOPENER_RE = /rel\s*=\s*['"`][^'"]*noopener[^'"]*['"`]/i;

  // window.open without noopener in features string
  const WINDOW_OPEN_RE = /window\.open\s*\(/;
  const WINDOW_OPEN_NOOPENER_RE = /window\.open\s*\([^)]*['"`][^'"]*noopener[^'"]*['"`]/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    if (TARGET_BLANK_RE.test(code) && !REL_NOOPENER_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (rel="noopener noreferrer" on target="_blank" link)',
        severity: 'medium',
        description: `${node.label}: anchor tag uses target="_blank" without rel="noopener noreferrer". ` +
          `The opened page can access window.opener and redirect the original tab (reverse-tabnabbing).`,
        fix: 'Add rel="noopener noreferrer" to all <a target="_blank"> links. ' +
          'For React 17+, the framework handles this automatically, but explicit is safer for SSR/older builds.',
        via: 'structural',
      });
    }

    if (WINDOW_OPEN_RE.test(code) && !WINDOW_OPEN_NOOPENER_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (noopener in window.open features)',
        severity: 'medium',
        description: `${node.label}: window.open() called without "noopener" in features string. ` +
          `The opened window gets a reference to the opener via window.opener.`,
        fix: 'Pass "noopener,noreferrer" as the windowFeatures parameter: ' +
          'window.open(url, "_blank", "noopener,noreferrer")',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1022', name: 'Use of Web Link to Untrusted Target Without rel noopener', holds: findings.length === 0, findings };
}

function verifyCWE1023(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // startsWith / endsWith used in auth/access control checks without exact match
  const PARTIAL_COMPARE_AUTH_RE = /\b(?:startsWith|endsWith|indexOf\s*\(\s*[^)]+\)\s*===?\s*0|\.slice\s*\([^)]*\)\s*===?)\b/;
  const AUTH_CONTEXT_RE = /\b(auth|permission|role|admin|allow|deny|access|token|credential|password|origin|host|domain|url|path|route)\b/i;

  // == instead of === in security-sensitive comparisons (type coercion is a missing factor)
  const LOOSE_EQUALITY_RE = /(?<!=)(?<!!)==(?!=)/;
  const SECURITY_COMPARE_RE = /\b(password|token|secret|hash|signature|nonce|csrf|session|api[_-]?key)\b/i;

  // String comparison for what should be constant-time (timing as missing factor)
  const TIMING_VULN_RE = /\b(===?|!==?|strcmp|equals)\b[\s\S]{0,80}?\b(hmac|digest|hash|signature|mac|tag)\b/i;
  const CONSTANT_TIME_RE = /\b(timingSafeEqual|constantTimeCompare|constant_time_compare|secure_compare|hmac\.equal|crypto\.timingSafeEqual|MessageDigest\.isEqual)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    // Partial string comparison in auth context
    if (PARTIAL_COMPARE_AUTH_RE.test(code) && AUTH_CONTEXT_RE.test(code)) {
      // Ensure it's not just a URL routing check
      if (!/\b(router|app\.\w+|express|route)\b/i.test(code)) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (full comparison instead of partial match in security context)',
          severity: 'medium',
          description: `${node.label}: uses partial string comparison (startsWith/endsWith/indexOf) in an authentication or access control context. ` +
            `Partial matches can be bypassed: startsWith("admin") matches "administrator-evil".`,
          fix: 'Use exact equality for security-critical comparisons. If prefix/suffix matching is needed, ' +
            'combine with length checks or use allowlists instead of prefix patterns.',
          via: 'structural',
        });
      }
    }

    // Loose equality in security comparison (JS-specific)
    if (LOOSE_EQUALITY_RE.test(code) && SECURITY_COMPARE_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (strict equality === instead of == for security values)',
        severity: 'medium',
        description: `${node.label}: uses loose equality (==) to compare security-sensitive values. ` +
          `Type coercion means "0" == 0 == false — an attacker can bypass checks with type confusion.`,
        fix: 'Use strict equality (===) for all security comparisons. In Python, use "is" for None/True/False checks.',
        via: 'structural',
      });
    }

    // Non-constant-time comparison of cryptographic material
    if (TIMING_VULN_RE.test(code) && !CONSTANT_TIME_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (constant-time comparison for cryptographic values)',
        severity: 'high',
        description: `${node.label}: compares cryptographic values (HMAC/hash/signature) using standard equality. ` +
          `Standard comparison short-circuits on first mismatch, leaking information via timing side-channels.`,
        fix: 'Use crypto.timingSafeEqual (Node.js), hmac.compare_digest (Python), ' +
          'MessageDigest.isEqual (Java), or constant_time_compare (Ruby).',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1023', name: 'Incomplete Comparison with Missing Factors', holds: findings.length === 0, findings };
}

function verifyCWE1024(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // typeof x === typeof y where one side is clearly wrong type
  // null == undefined is true in JS; NaN !== NaN; [] == false is true
  const TYPEOF_MISMATCH_RE = /typeof\s+\w+\s*===?\s*['"`](number|string|boolean|object|undefined)['"`][\s\S]{0,100}?(?:===?|!==?)\s*(?:null|undefined|NaN|\[\s*\]|true|false)/;

  // Comparing string to number without explicit cast in security context
  const STRING_NUM_COMPARE = /(?:['"`]\d+['"`]\s*(?:===?|!==?|[<>]=?)\s*\d+|\d+\s*(?:===?|!==?|[<>]=?)\s*['"`]\d+['"`])/;

  // PHP-specific: loose comparison with type juggling
  const PHP_TYPE_JUGGLE_RE = /(?:==\s*(?:0|true|false|null|''|""|'0'|"0"|\[\s*\]))\s*[;)]/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    if (TYPEOF_MISMATCH_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (type-consistent comparison)',
        severity: 'medium',
        description: `${node.label}: comparison mixes incompatible types after typeof check. ` +
          `This can produce silently wrong results due to type coercion or special-case semantics (NaN !== NaN, null == undefined).`,
        fix: 'Ensure both sides of a comparison are the same type. Use explicit type conversion before comparing. ' +
          'Use linter rules like @typescript-eslint/no-unsafe-comparison.',
        via: 'structural',
      });
    }

    if (STRING_NUM_COMPARE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (explicit type conversion before comparison)',
        severity: 'low',
        description: `${node.label}: directly compares a string literal with a number literal. ` +
          `In JS, "1" == 1 is true but "1" === 1 is false — inconsistent behavior depending on operator.`,
        fix: 'Convert to the same type explicitly before comparing: Number(str) === num or str === String(num).',
        via: 'structural',
      });
    }

    if (PHP_TYPE_JUGGLE_RE.test(code) && /\.php/i.test(node.file || '')) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (strict comparison === to prevent PHP type juggling)',
        severity: 'high',
        description: `${node.label}: PHP loose comparison (==) with a type-juggling-prone value. ` +
          `In PHP, "0e123" == "0e456" is true (both cast to 0 in scientific notation) — this breaks password hash comparison.`,
        fix: 'Use strict comparison (===) in PHP. For hash comparison, use hash_equals() which is also timing-safe.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1024', name: 'Comparison of Incompatible Types', holds: findings.length === 0, findings };
}

function verifyCWE1025(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Self-comparison: x === x, x == x, x !== x, x != x (always true or always false)
  const SELF_COMPARE_RE = /\b(\w+(?:\.\w+)*)\s*(?:===?|!==?)\s*\1\b/;
  // Except: NaN check (x !== x is the canonical NaN test)
  const NAN_CHECK_RE = /\b(\w+)\s*!==?\s*\1\b/;

  // Comparing loop counter to itself or wrong bound
  const LOOP_SELF_COMPARE_RE = /for\s*\([^;]*;\s*(\w+)\s*(?:<|<=|>|>=|===?|!==?)\s*\1\s*;/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    const selfMatch = code.match(SELF_COMPARE_RE);
    if (selfMatch) {
      const varName = selfMatch[1];
      // x !== x is the canonical NaN check — don't flag it
      const isNanCheck = NAN_CHECK_RE.test(code) && /NaN|nan|isNaN/i.test(code);
      if (!isNanCheck) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'STRUCTURAL (comparison uses wrong variable — both sides identical)',
          severity: 'medium',
          description: `${node.label}: compares "${varName}" to itself. ` +
            `This is always true (===) or always false (!==) — likely a copy-paste bug where one side should be a different variable.`,
          fix: 'Review the comparison and use the correct variable on one side. ' +
            'If checking for NaN, use Number.isNaN(x) instead of x !== x.',
          via: 'structural',
        });
      }
    }

    if (LOOP_SELF_COMPARE_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'STRUCTURAL (loop condition compares counter to itself)',
        severity: 'medium',
        description: `${node.label}: for-loop condition compares the counter variable to itself. ` +
          `This creates either an infinite loop or a never-executing loop.`,
        fix: 'Fix the loop condition to compare the counter to the correct bound variable.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-1025', name: 'Comparison Using Wrong Factors', holds: findings.length === 0, findings };
}

function verifyCWE1036(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Dynamic require/import with user input
  const DYNAMIC_REQUIRE_RE = /\brequire\s*\(\s*(?:req\.|params\.|query\.|body\.|input\.|user\.|args\.|data\.|\w+Input|config\[)/i;
  const DYNAMIC_IMPORT_RE = /\bimport\s*\(\s*(?:req\.|params\.|query\.|body\.|input\.|user\.|args\.|data\.|\w+Input|config\[)/i;

  // Dynamic class instantiation: new X[userInput] or eval("new " + className)
  const DYNAMIC_NEW_RE = /\bnew\s+\w+\s*\[\s*(?:req\.|params\.|query\.|body\.|input\.|user\.|args\.|data\.)/i;
  const REFLECT_CONSTRUCT_RE = /\bReflect\.construct\s*\(\s*(?:\w+\[|eval)/i;

  // Java/C# reflection: Class.forName(userInput), Type.GetType(userInput)
  const JAVA_FORNAME_RE = /\bClass\.forName\s*\(\s*(?:request\.|param|input|args|data\.)/i;
  const CSHARP_GETTYPE_RE = /\bType\.GetType\s*\(\s*(?:request\.|param|input|args|data\.)/i;

  // Python: __import__(userInput), importlib.import_module(userInput), getattr
  const PY_IMPORT_RE = /\b(?:__import__|importlib\.import_module)\s*\(\s*(?:request\.|param|input|args|data\.)/i;
  const PY_GETATTR_RE = /\bgetattr\s*\(\s*\w+\s*,\s*(?:request\.|param|input|args|data\.)/i;

  // PHP: new $className
  const PHP_DYNAMIC_CLASS_RE = /\bnew\s+\$\w+\s*\(/;

  // Allowlist check — if there's an explicit allowlist, it's safe
  const ALLOWLIST_RE = /\b(allowlist|whitelist|allowed|ALLOWED|validClasses|safeModules|permitted|knownTypes)\b/i;

  const ingress = nodesOfType(map, 'INGRESS');

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|stub)\b/i.test(node.label)) continue;

    const isDynamic = DYNAMIC_REQUIRE_RE.test(code) || DYNAMIC_IMPORT_RE.test(code) ||
      DYNAMIC_NEW_RE.test(code) || REFLECT_CONSTRUCT_RE.test(code) ||
      JAVA_FORNAME_RE.test(code) || CSHARP_GETTYPE_RE.test(code) ||
      PY_IMPORT_RE.test(code) || PY_GETATTR_RE.test(code) ||
      PHP_DYNAMIC_CLASS_RE.test(code);

    if (isDynamic && !ALLOWLIST_RE.test(code)) {
      findings.push({
        source: nodeRef(node),
        sink: nodeRef(node),
        missing: 'CONTROL (allowlist for dynamically-loaded class/module names)',
        severity: 'high',
        description: `${node.label}: dynamically loads a class or module using an externally-influenced name. ` +
          `An attacker can specify arbitrary class names to instantiate dangerous classes or load malicious modules.`,
        fix: 'Use an allowlist of permitted class/module names. Map user input to a fixed set of known-safe values: ' +
          'const ALLOWED = { "csv": CsvParser, "json": JsonParser }; const Parser = ALLOWED[input];',
        via: 'structural',
      });
    }
  }

  // Also check INGRESS -> EXTERNAL paths where external node does dynamic loading
  const externalLoaders = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('require') || n.node_subtype.includes('import') ||
     n.node_subtype.includes('reflection') || n.node_subtype.includes('class_load'))
  );

  for (const src of ingress) {
    for (const sink of externalLoaders) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!ALLOWLIST_RE.test(code)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (allowlist validation before dynamic class/module loading)',
            severity: 'high',
            description: `User input from ${src.label} flows to dynamic class/module loader at ${sink.label}. ` +
              `Without an allowlist, an attacker controls which code gets loaded and executed.`,
            fix: 'Validate the class/module name against an explicit allowlist before loading. ' +
              'Never pass raw user input to require(), import(), Class.forName(), or similar.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-1036', name: 'Class Based on Externally-Controlled Resource Name', holds: findings.length === 0, findings };
}

function verifyCWE939(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SCHEMES939: Array<{ pattern: RegExp; name: string }> = [
    { pattern: /\bapplication\s*\(\s*_\s*:?\s*open\s*:\s*url\b|\bfunc\s+application\s*\([^)]*url\s*:\s*URL/i, name: 'iOS URL scheme handler' },
    { pattern: /\bonNewIntent\b|\bhandleIntent\b|\bintent\.getData\(\)|intent\.getDataString\(\)|<intent-filter>[\s\S]*?<data\s+android:scheme/i, name: 'Android intent/deep link handler' },
    { pattern: /\bprotocol\.registerHttpProtocol\b|\bprotocol\.handle\b|\bapp\.setAsDefaultProtocolClient\b|\bopen-url\b|\belectron.*protocol/i, name: 'Electron custom protocol handler' },
    { pattern: /\bCFBundleURLSchemes\b|\bNSUserActivity.*webpageURL\b|\bUIApplication\.shared\.open\b/i, name: 'iOS Info.plist URL scheme' },
    { pattern: /\bwindow\.handleOpenURL\b|\bApp\.addListener\s*\(\s*['"]appUrlOpen['"]\b|\bCapacitor.*appUrlOpen\b|\bLinking\.addEventListener\b/i, name: 'hybrid app deep link handler' },
  ];
  const AUTH939 = /\b(auth|authorize|verify|validate|check[_-]?permission|isAllowed|canHandle|allowedSchemes|trustedSources|sourceApplication|callingPackage|getReferrer)\b/i;
  const INP939 = /\b(sanitize|escape|encode|whitelist|allowlist|parseURL|new\s+URL|url\.parse|URLComponents)\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const sch of SCHEMES939) {
      if (sch.pattern.test(code)) {
        const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
        const allC = code + ' ' + sibs.map(n => stripComments(n.analysis_snapshot || n.code_snapshot)).join(' ');
        if (!AUTH939.test(allC)) {
          findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (authorization in URL scheme handler)', severity: 'high',
            description: `${sch.name} at ${node.label} processes requests without authorization. Any app can invoke this handler.`,
            fix: 'Verify source app (iOS: sourceApplication, Android: callingPackage/getReferrer). Allowlist URL parameters.', via: 'scope_taint' });
        }
        if (!INP939.test(allC)) {
          findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (input validation in URL scheme handler)', severity: 'medium',
            description: `${sch.name} at ${node.label} uses URL scheme data without input validation. Malicious apps can craft attack URLs.`,
            fix: 'Parse and validate all URL components. Use URL/URLComponents. Allowlist expected hosts, paths, and parameters.', via: 'scope_taint' });
        }
        break;
      }
    }
  }
  return { cwe: 'CWE-939', name: 'Improper Authorization in Handler for Custom URL Scheme', holds: findings.length === 0, findings };
}

function verifyCWE940(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CH940: Array<{ pattern: RegExp; name: string; severity: 'high' | 'critical' }> = [
    { pattern: /\brejectUnauthorized\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|\bssl_verify\s*[:=]\s*(?:false|0|False)\b|\bverify\s*[:=]\s*False\b|\bInsecureRequestWarning\b/i,
      name: 'TLS certificate verification disabled', severity: 'critical' },
    { pattern: /\bServerCertificateCustomValidationCallback\s*=\s*\(\s*[^)]*\)\s*=>\s*true\b|\bServicePointManager\.ServerCertificateValidationCallback\b[\s\S]{0,100}?(?:return\s+true|=>\s*true)/i,
      name: '.NET certificate validation bypassed', severity: 'critical' },
    { pattern: /\bsetHostnameVerifier\s*\(\s*(?:new\s+)?(?:AllowAll|NoOp|NullHostnameVerifier|ALLOW_ALL)\b|\bHostnameVerifier\b[\s\S]{0,100}?return\s+true/i,
      name: 'Java hostname verification disabled', severity: 'critical' },
    { pattern: /\bATS[\s\S]{0,100}?NSAllowsArbitraryLoads\s*[:=]\s*(?:true|YES)\b|\bNSExceptionAllowsInsecureHTTPLoads\b/i,
      name: 'iOS App Transport Security disabled', severity: 'high' },
    { pattern: /\bandroid:usesCleartextTraffic\s*=\s*['"]true['"]\b|\bcleartextTrafficPermitted\s*=\s*['"]true['"]/i,
      name: 'Android cleartext traffic enabled', severity: 'high' },
    { pattern: /\b(?:ws:\/\/|http:\/\/)(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\b[\s\S]{0,50}?(?:connect|open|send|subscribe)/i,
      name: 'unencrypted channel to remote host', severity: 'high' },
  ];
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|example|dev|development)\b/i.test(node.label || node.file)) continue;
    for (const ch of CH940) {
      if (ch.pattern.test(code)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: `CONTROL (source verification — ${ch.name})`, severity: ch.severity,
          description: `${node.label}: ${ch.name}. App may connect to or accept data from a spoofed server.`,
          fix: 'Enable TLS certificate verification. Use certificate pinning for high-security channels. Never disable in production.', via: 'structural' });
        break;
      }
    }
  }
  return { cwe: 'CWE-940', name: 'Improper Verification of Source of a Communication Channel', holds: findings.length === 0, findings };
}

function verifyCWE941(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const DEST941 = /\b(?:fetch|axios|request|got|http\.get|https\.get|urllib|httpClient)\s*\(\s*(?:req\.|params\.|query\.|body\.|input\.|user\.|args\.|config\[)/i;
  const REDIR941 = /\b(?:res\.redirect|response\.redirect|redirect|location\.href|window\.location)\s*(?:=|\()\s*(?:req\.|params\.|query\.|body\.|input\.|user\.)/i;
  const HTTP941 = /\b(?:fetch|axios|request|got|http\.get|urllib)\s*\(\s*['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)/i;
  const DYN941 = /\b(?:url|endpoint|host|baseUrl|apiUrl)\s*(?:=|\+=)\s*(?:req\.|params\.|query\.|body\.|input\.|user\.|args\.)/i;
  const SAFE941 = /\ballowedHosts\b|\bwhitelist\b|\ballowlist\b|\btrustedDomains\b|\bvalidateUrl\b|\burl\.parse[\s\S]{0,50}?hostname[\s\S]{0,50}?(?:includes|indexOf|===)/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;
    if (DEST941.test(code) || DYN941.test(code)) {
      const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      if (!SAFE941.test(code) && !sibs.some(n => SAFE941.test(stripComments(n.analysis_snapshot || n.code_snapshot)))) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (destination validation for outbound connection)', severity: 'high',
          description: `Outbound connection at ${node.label} uses user-controlled destination. Attacker can redirect to malicious server.`,
          fix: 'Validate destination URLs against an allowlist of trusted hosts. Parse URL and check hostname.', via: 'scope_taint' });
      }
    }
    if (REDIR941.test(code) && !SAFE941.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (redirect destination validation)', severity: 'medium',
        description: `Redirect at ${node.label} uses user-controlled destination, enabling open redirect.`,
        fix: 'Validate redirect destinations against an allowlist. Use relative URLs where possible.', via: 'structural' });
    }
    if (HTTP941.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (use HTTPS for remote destinations)', severity: 'medium',
        description: `${node.label} connects to remote host over plain HTTP. DNS hijacking can redirect without detection.`,
        fix: 'Use HTTPS for all remote connections to ensure correct destination.', via: 'structural' });
    }
  }
  return { cwe: 'CWE-941', name: 'Incorrectly Specified Destination in a Communication Channel', holds: findings.length === 0, findings };
}

function verifyCWE942(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const WCORS942 = /Access-Control-Allow-Origin['":\s]*\*|cors\s*\(\s*\)|origin\s*:\s*(?:true|\*|['"]?\*['"]?)/i;
  const XDOM942 = /\bcrossdomain\.xml\b|\ballowDomain\s*\(\s*['"]?\*['"]?\s*\)|\b<allow-access-from\s+domain\s*=\s*['"]?\*['"]?\s*\/>/i;
  const PM942 = /\bpostMessage\s*\(\s*[^,]+,\s*['"]?\*['"]?\s*\)/i;
  const CSP942 = /\bContent-Security-Policy\b[\s\S]{0,200}?(?:default-src\s+\*|script-src[^;]*\*[^;]*|frame-ancestors\s+\*)/i;
  const REFL942 = /\bAccess-Control-Allow-Origin\b[\s\S]{0,50}?(?:req\.headers?\.origin|request\.headers?\.origin|origin)/i;
  const CRED942 = /Access-Control-Allow-Credentials['":\s]*true|credentials\s*:\s*true/i;
  const SAFE942 = /\ballowedOrigins\b|\bwhitelist\b|\ballowlist\b|\bcorsOptions\b.*\borigin\s*:\s*\[|\borigin\s*:\s*function|\borigin\s*:\s*\(|\bvalidateOrigin\b|\b\.includes\s*\(\s*origin\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;
    if (XDOM942.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (restrictive cross-domain policy)', severity: 'high',
        description: `${node.label} has permissive crossdomain.xml or allowDomain("*") allowing any domain cross-origin access.`,
        fix: 'Restrict to specific trusted domains. Remove crossdomain.xml if Flash/Silverlight not needed.', via: 'structural' });
    }
    if (REFL942.test(code) && CRED942.test(code) && !SAFE942.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (origin allowlist for CORS with credentials)', severity: 'critical',
        description: `${node.label} reflects Origin with credentials. Any website can make authenticated cross-origin requests.`,
        fix: 'Validate Origin against a strict allowlist. Never reflect arbitrary origins with credentials.', via: 'structural' });
    } else if (WCORS942.test(code)) {
      const sens = node.node_type === 'AUTH' || node.node_type === 'STORAGE' || node.attack_surface.includes('sensitive_data') || /\b(user|account|payment|admin|internal|private)\b/i.test(node.label);
      if (sens) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (restrictive CORS on sensitive endpoint)', severity: 'high',
          description: `Sensitive endpoint ${node.label} has wildcard CORS. Any website can read responses.`,
          fix: 'Use specific trusted origins instead of wildcard for sensitive endpoints.', via: 'structural' });
      }
    }
    if (PM942.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (specific target origin for postMessage)', severity: 'medium',
        description: `${node.label} sends postMessage with targetOrigin "*". Any window can receive these messages.`,
        fix: 'Specify exact target origin: window.postMessage(data, "https://trusted.example.com").', via: 'structural' });
    }
    if (CSP942.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (restrictive CSP)', severity: 'medium',
        description: `${node.label} sets permissive CSP with wildcard sources, defeating its purpose.`,
        fix: 'Use specific origins in CSP. Avoid wildcards in default-src and script-src.', via: 'structural' });
    }
  }
  return { cwe: 'CWE-942', name: 'Permissive Cross-domain Policy with Untrusted Domains', holds: findings.length === 0, findings };
}

function verifyCWE943(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const NOSQL_SAFE_RE = /\b(?:sanitize|mongo-sanitize|express-mongo-sanitize|mongoSanitize|ObjectId\.isValid|Types\.ObjectId|validator|Joi|yup|zod)\b/i;
  const Q943: Array<{ pattern: RegExp; name: string; safeRe: RegExp; severity: 'critical' | 'high' }> = [
    // MongoDB operator injection: user input with $ operators
    { pattern: /\b(?:find|findOne|findMany|aggregate|updateOne|updateMany|deleteOne|deleteMany|countDocuments|findOneAndUpdate|findOneAndDelete)\s*\(\s*(?:\{[\s\S]*?\$(?:where|regex|expr|gt|lt|ne|in|nin|exists|or|and|not)[\s\S]*?(?:req\.|params\.|query\.|body\.|input\.|user\.))/i,
      name: 'NoSQL injection via MongoDB operator injection', safeRe: NOSQL_SAFE_RE, severity: 'critical' },
    // Direct user input as argument to any NoSQL query method — covers chained calls like
    // db.collection('users').findOne(req.query) and db.find(req.body) and JSON.parse variants
    { pattern: /\b(?:find|findOne|findMany|findById|aggregate|updateOne|updateMany|deleteOne|deleteMany|countDocuments|findOneAndUpdate|findOneAndDelete|remove)\s*\(\s*(?:JSON\.parse\s*\(\s*(?:req\.|body\.|query\.|params\.)|(?:req|body|query|params)\.\w)/i,
      name: 'NoSQL query built from user input (direct argument)', safeRe: NOSQL_SAFE_RE, severity: 'critical' },
    { pattern: /\b(?:graphql|gql)\b[\s\S]{0,200}?(?:\$\{|` ?\+|req\.|body\.query)/i,
      name: 'GraphQL query built via string concatenation', safeRe: /\b(?:gql`|graphql-tag|preparedStatement|parameterized)\b/i, severity: 'high' },
    { pattern: /\b(?:ldap_search|LDAPConnection\.search|search_s|search_ext_s)\s*\([^)]*?(?:req\.|params\.|query\.|body\.|input\.|user\.)/i,
      name: 'LDAP query with user input', safeRe: /\b(?:ldap_escape|escape_filter|escapeLDAPFilter|filter\.escape)\b/i, severity: 'high' },
    { pattern: /\b(?:xpath|evaluate|selectNodes|selectSingleNode|xmlquery)\s*\([^)]*?(?:req\.|params\.|query\.|body\.|input\.|user\.|` ?\+|\$\{)/i,
      name: 'XPath query with user input', safeRe: /\b(?:parameterized|preparedXPath|escapeXpath|XPathExpression\.compile)\b/i, severity: 'high' },
    { pattern: /\b(?:where|having|orderBy|groupBy|select|from)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"] ?\+)\s*(?:req\.|params\.|query\.|body\.|input\.|user\.)/i,
      name: 'ORM/query-builder with interpolated user input', safeRe: /\b(?:parameterized|prepared|placeholder|\?\s*,|:[\w]+|\$\d+)\b/i, severity: 'high' },
  ];
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (/\b(test|spec|mock|example)\b/i.test(node.label || node.file)) continue;
    for (const q of Q943) {
      if (q.pattern.test(code)) {
        const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
        if (!q.safeRe.test(code) && !sibs.some(n => q.safeRe.test(stripComments(n.analysis_snapshot || n.code_snapshot)))) {
          findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: `CONTROL (query parameterization — ${q.name})`, severity: q.severity,
            description: `${node.label}: ${q.name}. User input reaches data query without neutralization.`,
            fix: 'Use parameterized queries. NoSQL: mongo-sanitize / express-mongo-sanitize. LDAP: ldap_escape. GraphQL: use variables.', via: 'scope_taint' });
          break;
        }
      }
    }
  }
  // BFS taint path: INGRESS -> STORAGE(db_read|db_write) where the storage node contains a NoSQL method call.
  // The previous sink filter required subtype "nosql"/"mongo" which the mapper never assigns (it uses db_read/db_write).
  // Fix: also accept db_read/db_write nodes whose code contains a NoSQL query method call.
  const NOSQL_METHOD_RE = /\b(?:find|findOne|findMany|findById|aggregate|updateOne|updateMany|deleteOne|deleteMany|countDocuments|findOneAndUpdate|findOneAndDelete|remove)\s*\(/i;
  const src943 = nodesOfType(map, 'INGRESS');
  const qSinks943 = map.nodes.filter(n =>
    n.node_type === 'STORAGE' && (
      n.node_subtype.includes('nosql') ||
      n.node_subtype.includes('mongo') ||
      n.node_subtype.includes('ldap') ||
      n.node_subtype.includes('xpath') ||
      n.node_subtype.includes('graphql') ||
      n.node_subtype.includes('query') ||
      // Accept standard db_read/db_write nodes that contain NoSQL method calls
      ((n.node_subtype.includes('db_read') || n.node_subtype.includes('db_write')) &&
        NOSQL_METHOD_RE.test(n.analysis_snapshot || n.code_snapshot))
    )
  );
  for (const s of src943) {
    for (const sk of qSinks943) {
      if (hasTaintedPathWithoutControl(map, s.id, sk.id)) {
        const code = stripComments(sk.analysis_snapshot || sk.code_snapshot);
        if (!NOSQL_SAFE_RE.test(code) && !/\b(parameterized|prepared|sanitize|escape|bind|placeholder)\b/i.test(code)) {
          findings.push({ source: nodeRef(s), sink: nodeRef(sk), missing: 'CONTROL (query neutralization)', severity: 'critical',
            description: `User input from ${s.label} reaches NoSQL query at ${sk.label} without sanitization.`,
            fix: 'Add input sanitization: mongo-sanitize, express-mongo-sanitize, or validate/whitelist query fields.', via: 'bfs' });
        }
      }
    }
  }
  return { cwe: 'CWE-943', name: 'Improper Neutralization of Special Elements in Data Query Logic', holds: findings.length === 0, findings };
}

function verifyCWE1004(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SC1004 = /\b(res\.cookie|response\.set_cookie|setcookie|Set-Cookie|setCookie|response\.cookies|add_header\s+Set-Cookie|\.cookie\s*\(|document\.cookie\s*=|cookie\s*[:=])/i;
  const SENS1004 = /\b(session|sess|token|auth|jwt|access[_-]?token|refresh[_-]?token|remember[_-]?me|JSESSIONID|PHPSESSID|ASP\.NET_SessionId|connect\.sid|_session|csrf|xsrf|sid)\b/i;
  const HO1004 = /\bhttpOnly\s*[:=]\s*true\b|\bHttpOnly\b|\bhttponly\s*;\s*|\bhttp_only\s*[:=]\s*(?:true|True|1)\b/i;
  const SCFG1004 = /\b(?:session|cookie-session|express-session)\b[\s\S]{0,200}?\b(?:cookie|options)\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SC1004.test(code)) {
      const isSens = SENS1004.test(code) || SENS1004.test(node.label);
      if (isSens && !HO1004.test(code)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (httpOnly flag on sensitive cookie)', severity: 'high',
          description: `Sensitive cookie at ${node.label} set without HttpOnly. XSS can steal it via document.cookie.`,
          fix: 'Set httpOnly: true. Express: res.cookie("session", val, { httpOnly: true, secure: true, sameSite: "strict" }).', via: 'structural' });
      }
    }
    if (SCFG1004.test(code) && /\bhttpOnly\s*[:=]\s*false\b|\bhttp_only\s*[:=]\s*(?:false|False|0)\b/i.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (httpOnly explicitly disabled)', severity: 'high',
        description: `Session config at ${node.label} explicitly disables httpOnly, exposing cookies to XSS.`,
        fix: 'Remove httpOnly: false. Most frameworks default to httpOnly: true.', via: 'structural' });
    }
    if (/\bdocument\.cookie\s*=/.test(code) && SENS1004.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (server-side cookie setting)', severity: 'high',
        description: `${node.label} sets sensitive cookie via document.cookie. JS cookies cannot have HttpOnly.`,
        fix: 'Set sensitive cookies server-side with Set-Cookie header and HttpOnly flag.', via: 'structural' });
    }
  }
  return { cwe: 'CWE-1004', name: 'Sensitive Cookie Without HttpOnly Flag', holds: findings.length === 0, findings };
}

function verifyCWE1007(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const UD1007 = /\b(?:username|displayName|display_name|nickname|email|domain|hostname|url|link|sender|from)\b/i;
  const UN1007 = /\b(?:normalize\s*\(\s*['"]NFK?[CD]['"]|\.normalize\b|unicodedata\.normalize|Normalizer\.normalize|IDN\.toASCII|punycode|toASCII|idn_to_ascii|confusable|homoglyph|skeleton)\b/i;
  const DC1007 = /\b(?:render|display|show|innerHTML|textContent|innerText|\.text\s*=|label\s*=|title\s*=|alert\s*\(|notification|toast|badge|chip|avatar|profile)\b/i;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (UD1007.test(code) && DC1007.test(code)) {
      const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      const allC = code + ' ' + sibs.map(n => stripComments(n.analysis_snapshot || n.code_snapshot)).join(' ');
      if (!UN1007.test(allC)) {
        const sec = /\b(auth|login|verify|trust|approve|confirm|transfer|payment|admin)\b/i.test(allC) || node.attack_surface.includes('phishing') || node.attack_surface.includes('identity');
        if (sec) {
          findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (Unicode normalization/homoglyph detection)', severity: 'medium',
            description: `${node.label} displays user-controlled identifiers in security context without homoglyph detection. Attackers can impersonate via confusable Unicode.`,
            fix: 'Normalize Unicode (NFKC). Use ICU confusable detection for usernames. Convert IDN to Punycode.', via: 'scope_taint' });
        }
      }
    }
  }
  const uN1007 = map.nodes.filter(n => (n.node_subtype.includes('url') || n.node_subtype.includes('domain') || n.node_subtype.includes('link') || n.node_subtype.includes('redirect')) && (n.node_type === 'INGRESS' || n.node_type === 'TRANSFORM' || n.node_type === 'EGRESS'));
  for (const node of uN1007) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!UN1007.test(code) && /\b(display|show|render|href|src)\b/i.test(code)) {
      findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (IDN homoglyph detection for URLs)', severity: 'medium',
        description: `${node.label} displays URLs without IDN normalization. Homoglyphs can mimic trusted domains.`,
        fix: 'Convert IDN domains to Punycode for display. Show xn-- form for non-ASCII domains.', via: 'structural' });
    }
  }
  return { cwe: 'CWE-1007', name: 'Insufficient Visual Distinction of Homoglyphs', holds: findings.length === 0, findings };
}

function verifyCWE1021(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library/framework code doesn't define application routes — clickjacking is irrelevant
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-1021', name: 'Improper Restriction of Rendered UI Layers', holds: true, findings };
  }

  const FR1021 = /\bX-Frame-Options\b|\bframe-ancestors\b|\bCSP.*frame-ancestors/i;
  const GD1021 = /\bframeguard\b|\bhelmet\.frameguard\b|\bhelmet\s*\(\s*\)/i;
  const BU1021 = /\btop\s*!==?\s*self\b|\btop\s*!==?\s*window\b|\bself\s*!==?\s*top\b|\bwindow\.top\s*!==?\s*window\.self\b/i;
  const DN1021 = /X-Frame-Options['":\s]*(?:DENY|SAMEORIGIN)\b|frame-ancestors\s+(?:'self'|'none'|https?:\/\/[\w.]+)/i;
  let globalProt = false;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (GD1021.test(code) || DN1021.test(code)) {
      if (node.node_subtype.includes('middleware') || node.node_subtype.includes('config') || /\bapp\.use\b|\bserver\.use\b|\badd_header\b|\bheader\s+always\b/i.test(code)) {
        globalProt = true; break;
      }
    }
  }
  if (!globalProt) {
    // Require actual route definitions — files without routes cannot have clickjacking
    const hasRoutes = map.nodes.some(n =>
      /\b(app\.get|app\.post|app\.put|app\.delete|app\.patch|router\.get|router\.post|app\.route|@Get|@Post|@RequestMapping)\b/i.test(n.analysis_snapshot || n.code_snapshot) ||
      (n.node_subtype.includes('route'))
    );
    if (!hasRoutes) {
      return { cwe: 'CWE-1021', name: 'Improper Restriction of Rendered UI Layers', holds: true, findings };
    }

    const rN1021 = map.nodes.filter(n => n.node_type === 'EGRESS' || n.node_type === 'CONTROL' || n.node_subtype.includes('middleware') || n.node_subtype.includes('response') || n.node_subtype.includes('header') || n.node_subtype.includes('route') || n.node_subtype.includes('handler') || n.node_subtype.includes('controller') || /\b(res\.|response\.|setHeader|writeHead|add_header|header\s*\()\b/i.test(n.analysis_snapshot || n.code_snapshot));
    const sP1021 = rN1021.filter(n => /\b(login|auth|account|payment|transfer|admin|settings|profile|password|checkout|confirm)\b/i.test(n.label) || n.node_type === 'AUTH' || n.attack_surface.includes('authentication') || n.attack_surface.includes('state_modification'));
    for (const node of sP1021) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      const sibs = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
      const allC = code + ' ' + sibs.map(n => stripComments(n.analysis_snapshot || n.code_snapshot)).join(' ');
      if (!FR1021.test(allC) && !GD1021.test(allC) && !BU1021.test(allC)) {
        findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (X-Frame-Options or CSP frame-ancestors)', severity: 'medium',
          description: `Sensitive page ${node.label} has no clickjacking protection. Attacker can embed in iframe for click hijacking.`,
          fix: 'Set X-Frame-Options: DENY globally. Better: CSP frame-ancestors \'self\'. Express: app.use(helmet()).', via: 'scope_taint' });
      }
    }
    if (sP1021.length === 0) {
      const hasMut = map.nodes.some(n => /\b(POST|PUT|DELETE|PATCH)\b/i.test(n.label) || n.node_subtype.includes('form') || /\b(submit|action|method\s*=\s*['"]post)\b/i.test(n.analysis_snapshot || n.code_snapshot));
      if (hasMut) {
        const tgt = rN1021[0] || nodesOfType(map, 'EGRESS')[0];
        if (tgt) {
          findings.push({ source: nodeRef(tgt), sink: nodeRef(tgt), missing: 'CONTROL (global clickjacking protection)', severity: 'medium',
            description: `App has state-changing endpoints but no global clickjacking protection.`,
            fix: 'Add X-Frame-Options: DENY or CSP frame-ancestors \'self\' as global middleware.', via: 'structural' });
        }
      }
    }
  }
  return { cwe: 'CWE-1021', name: 'Improper Restriction of Rendered UI Layers', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Access Control & Authentication Mechanisms
// ---------------------------------------------------------------------------

/**
 * CWE-305: Authentication Bypass by Primary Weakness
 * Pattern: AUTH nodes that rely on a single weak factor (IP, Referer, user-agent)
 * or auth checks that can be bypassed because the primary mechanism is weak.
 * Detects: IP-based auth, Referer-based auth, user-agent checks as sole auth.
 */
function verifyCWE305(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns indicating weak primary authentication mechanisms
  const WEAK_PRIMARY_RE = /\b(req\.ip|request\.ip|remoteAddr|remote_addr|getRemoteAddr|REMOTE_ADDR|x[-_]forwarded[-_]for|client[-_]ip)\b/i;
  const REFERER_AUTH_RE = /\b(referer|referrer)\b.*(?:===?|!==?|match|test|includes|indexOf|startsWith)/i;
  const USER_AGENT_AUTH_RE = /\b(user[-_]?agent|userAgent)\b.*(?:===?|!==?|match|test|includes|indexOf)/i;

  // Strong auth patterns that would make the primary weakness less critical
  const STRONG_AUTH_RE = /\b(jwt|jsonwebtoken|passport|bcrypt|argon2|scrypt|session\.userId|req\.user|token\.verify|verifyToken|authenticate|requireAuth|isAuthenticated|oauth|saml|openid|mfa|totp|2fa|two.?factor)\b/i;

  const authNodes = nodesOfType(map, 'AUTH');
  const controlNodes = nodesOfType(map, 'CONTROL');
  const authLike = [...authNodes, ...controlNodes.filter(n =>
    n.node_subtype.includes('auth') || n.node_subtype.includes('access') ||
    /\b(auth|login|verify|check.?access|permission|allowed|authorized)\b/i.test(n.label)
  )];

  for (const node of authLike) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for IP-based authentication as primary mechanism
    if (WEAK_PRIMARY_RE.test(code) && !STRONG_AUTH_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'AUTH (strong authentication mechanism — tokens, passwords, certificates)',
        severity: 'high',
        description: `Authentication at ${node.label} relies on IP address or network identity as primary factor. ` +
          `IP addresses can be spoofed, proxied, or shared (NAT). This is not a reliable authentication mechanism.`,
        fix: 'Replace IP-based authentication with a proper mechanism (JWT, session tokens, API keys). ' +
          'IP-based checks can supplement but should never be the primary authentication factor. ' +
          'Use IP allowlisting only as defense-in-depth alongside strong auth.',
        via: 'structural',
      });
    }

    // Check for Referer-based auth
    if (REFERER_AUTH_RE.test(code) && !STRONG_AUTH_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'AUTH (non-spoofable authentication — the Referer header is attacker-controlled)',
        severity: 'high',
        description: `Authentication at ${node.label} relies on the HTTP Referer header. ` +
          `The Referer header is user-controlled and trivially spoofed by attackers.`,
        fix: 'Never use Referer for authentication. Use CSRF tokens, session-based auth, or JWTs instead. ' +
          'Referer checking is acceptable only as a supplementary CSRF defense, not as primary auth.',
        via: 'structural',
      });
    }

    // Check for User-Agent-based auth
    if (USER_AGENT_AUTH_RE.test(code) && !STRONG_AUTH_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'AUTH (non-spoofable authentication — User-Agent is attacker-controlled)',
        severity: 'high',
        description: `Authentication at ${node.label} relies on User-Agent string matching. ` +
          `User-Agent is trivially spoofed. An attacker can impersonate any client.`,
        fix: 'Replace User-Agent checking with proper authentication (API keys, OAuth tokens, client certificates). ' +
          'User-Agent strings are not credentials and must not gate access to resources.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-305', name: 'Authentication Bypass by Primary Weakness', holds: findings.length === 0, findings };
}

/**
 * CWE-307: Improper Restriction of Excessive Authentication Attempts
 * Pattern: AUTH/login endpoints without rate limiting or account lockout.
 * Detects login/auth handlers that don't enforce brute-force protections.
 */
function verifyCWE307(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const LOGIN_RE = /\b(login|signin|sign[-_]?in|authenticate|auth|verify.?password|check.?password|compare.?password|validateCredentials|logIn|doLogin)\b/i;
  const RATE_LIMIT_RE = /\b(rateLimit|rate[-_]?limit|rateLimiter|slowDown|brute[-_]?force|express[-_]?rate[-_]?limit|throttle|loginAttempts|max[-_]?attempts|lockout|account[-_]?lock|failedAttempts|failed[-_]?attempts|maxRetries|loginRateLimit|express[-_]?brute|RateLimiter|Throttle|too[-_]?many[-_]?requests|429|cooldown|backoff|exponential[-_]?backoff|captcha|recaptcha|hcaptcha)\b/i;

  // Find auth/login nodes
  const authNodes = nodesOfType(map, 'AUTH');
  const ingressNodes = nodesOfType(map, 'INGRESS');
  const controlNodes = nodesOfType(map, 'CONTROL');

  // Check login-related INGRESS and AUTH nodes
  const loginNodes = [
    ...authNodes.filter(n => LOGIN_RE.test(n.label) || LOGIN_RE.test(n.analysis_snapshot || n.code_snapshot)),
    ...ingressNodes.filter(n => LOGIN_RE.test(n.label) || LOGIN_RE.test(n.node_subtype) ||
      /\b(\/login|\/signin|\/auth|\/token)\b/i.test(n.analysis_snapshot || n.code_snapshot)),
  ];

  for (const node of loginNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check the node itself for rate limiting
    if (RATE_LIMIT_RE.test(code)) continue;

    // Check if any CONTROL node on the same scope has rate limiting
    let hasRateLimit = false;

    // Check direct edges from this node for rate limit controls
    for (const edge of node.edges) {
      const target = map.nodes.find(n => n.id === edge.target);
      if (target && (target.node_type === 'CONTROL' || target.node_type === 'META') &&
        RATE_LIMIT_RE.test(stripComments(target.analysis_snapshot || target.code_snapshot))) {
        hasRateLimit = true;
        break;
      }
    }

    // Check if any node that points TO this login node has rate limiting (middleware)
    if (!hasRateLimit) {
      for (const n of map.nodes) {
        for (const edge of n.edges) {
          if (edge.target === node.id && RATE_LIMIT_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))) {
            hasRateLimit = true;
            break;
          }
        }
        if (hasRateLimit) break;
      }
    }

    // Check containing function scope
    if (!hasRateLimit) {
      const parentFn = findContainingFunction(map, node.id);
      if (parentFn) {
        const parentNode = map.nodes.find(n => n.id === parentFn);
        if (parentNode && RATE_LIMIT_RE.test(stripComments(parentNode.analysis_snapshot || parentNode.code_snapshot))) {
          hasRateLimit = true;
        }
      }
    }

    if (!hasRateLimit) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (rate limiting or account lockout for authentication endpoint)',
        severity: 'high',
        description: `Login/auth endpoint at ${node.label} lacks brute-force protection. ` +
          `Without rate limiting or account lockout, an attacker can try unlimited password guesses.`,
        fix: 'Add rate limiting to authentication endpoints. Use express-rate-limit, express-brute, or similar. ' +
          'Implement progressive delays or account lockout after N failed attempts. ' +
          'Example: app.post("/login", rateLimit({ windowMs: 15*60*1000, max: 5 }), loginHandler). ' +
          'Consider CAPTCHA after failed attempts.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-307', name: 'Improper Restriction of Excessive Authentication Attempts', holds: findings.length === 0, findings };
}

/**
 * CWE-308: Use of Single-factor Authentication
 * Pattern: AUTH nodes protecting sensitive operations that only use password/token
 * without a second factor (MFA/2FA/TOTP/SMS/biometric).
 * Focus: admin panels, financial operations, account settings changes.
 */
function verifyCWE308(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MFA_RE = /\b(mfa|2fa|two[-_]?factor|multi[-_]?factor|totp|hotp|otp|authenticator|speakeasy|otplib|authy|google[-_]?auth|sms[-_]?code|verification[-_]?code|security[-_]?code|second[-_]?factor|step[-_]?up|step.?up.?auth|biometric|fido|webauthn|u2f|yubikey|passkey)\b/i;
  const HIGH_VALUE_RE = /\b(admin|financial|payment|transfer|withdraw|bank|account[-_]?settings|change[-_]?password|change[-_]?email|delete[-_]?account|privilege|elevat|escalat|sudo|superuser|root|manage[-_]?users|role[-_]?assign|payout|wire[-_]?transfer)\b/i;

  const authNodes = nodesOfType(map, 'AUTH');

  for (const authNode of authNodes) {
    const code = stripComments(authNode.analysis_snapshot || authNode.code_snapshot);
    const label = authNode.label;

    // Only flag auth nodes protecting high-value operations
    const isHighValue = HIGH_VALUE_RE.test(code) || HIGH_VALUE_RE.test(label) ||
      authNode.attack_surface.some(s => HIGH_VALUE_RE.test(s));

    if (!isHighValue) {
      // Also check if auth flows to a high-value sink
      let flowsToHighValue = false;
      for (const edge of authNode.edges) {
        const target = map.nodes.find(n => n.id === edge.target);
        if (target && HIGH_VALUE_RE.test(stripComments(target.analysis_snapshot || target.code_snapshot))) {
          flowsToHighValue = true;
          break;
        }
      }
      if (!flowsToHighValue) continue;
    }

    // Check if MFA is present
    if (MFA_RE.test(code)) continue;

    // Check scope for MFA
    const parentFn = findContainingFunction(map, authNode.id);
    if (parentFn) {
      const parentNode = map.nodes.find(n => n.id === parentFn);
      if (parentNode && MFA_RE.test(stripComments(parentNode.analysis_snapshot || parentNode.code_snapshot))) continue;
    }

    // Check connected nodes for MFA
    let hasMFA = false;
    for (const edge of authNode.edges) {
      const target = map.nodes.find(n => n.id === edge.target);
      if (target && MFA_RE.test(stripComments(target.analysis_snapshot || target.code_snapshot))) {
        hasMFA = true;
        break;
      }
    }
    if (hasMFA) continue;

    findings.push({
      source: nodeRef(authNode), sink: nodeRef(authNode),
      missing: 'AUTH (multi-factor authentication for high-value operation)',
      severity: 'medium',
      description: `High-value operation protected by ${authNode.label} uses single-factor authentication. ` +
        `If the single factor (password/token) is compromised, the attacker gains full access.`,
      fix: 'Implement MFA for sensitive operations. Use TOTP (speakeasy/otplib), WebAuthn/FIDO2, or SMS verification. ' +
        'At minimum: admin panels, financial operations, password changes, and account deletion should require 2FA. ' +
        'Example: require TOTP verification before allowing fund transfers.',
      via: 'structural',
    });
  }

  return { cwe: 'CWE-308', name: 'Use of Single-factor Authentication', holds: findings.length === 0, findings };
}

/**
 * CWE-309: Use of Password System for Primary Authentication
 * Pattern: Systems that use only passwords (no token/cert/key alternative) for
 * machine-to-machine or API authentication where passwords are inappropriate.
 * Passwords are weak for: service accounts, API integrations, automated systems.
 */
function verifyCWE309(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PASSWORD_AUTH_RE = /\b(password|passwd|pwd|pass_?word)\s*[:=]/i;
  const PASSWORD_COMPARE_RE = /\b(password|passwd|pwd)\b.*(?:===?|!==?|compare|verify|match|equals)/i;
  const API_CONTEXT_RE = /\b(api|service|client|integration|webhook|cron|worker|daemon|bot|automated|machine|server[-_]?to[-_]?server|m2m|microservice|internal[-_]?service)\b/i;
  const STRONG_AUTH_RE = /\b(api[-_]?key|bearer|oauth|jwt|token|certificate|cert|mutual[-_]?tls|mtls|client[-_]?cert|x509|hmac|signature|signing[-_]?key|ssh[-_]?key|public[-_]?key|private[-_]?key|oidc|saml)\b/i;

  const authNodes = nodesOfType(map, 'AUTH');
  const ingressNodes = nodesOfType(map, 'INGRESS');

  // Check AUTH nodes that accept passwords in API/service contexts
  for (const node of [...authNodes, ...ingressNodes]) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const isApiContext = API_CONTEXT_RE.test(code) || API_CONTEXT_RE.test(node.label) ||
      node.node_subtype.includes('api') || node.node_subtype.includes('service');

    if (!isApiContext) continue;

    const usesPassword = PASSWORD_AUTH_RE.test(code) || PASSWORD_COMPARE_RE.test(code);
    if (!usesPassword) continue;

    // If it also supports strong auth, it's less critical (password as fallback)
    if (STRONG_AUTH_RE.test(code)) continue;

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'AUTH (token-based or certificate-based authentication for service/API context)',
      severity: 'medium',
      description: `Service/API authentication at ${node.label} uses password-based auth. ` +
        `Passwords are inappropriate for machine-to-machine communication: they encourage credential sharing, ` +
        `cannot be easily rotated, and are vulnerable to brute-force.`,
      fix: 'Use API keys, OAuth2 client credentials, mutual TLS, or JWT-based auth for service accounts. ' +
        'Passwords should be reserved for human interactive login. ' +
        'Example: use Bearer tokens with short expiration for API-to-API calls.',
      via: 'structural',
    });
  }

  return { cwe: 'CWE-309', name: 'Use of Password System for Primary Authentication', holds: findings.length === 0, findings };
}

/**
 * CWE-280: Improper Handling of Insufficient Permissions or Privileges
 * Pattern: Code catches/ignores permission errors instead of failing safely,
 *          or proceeds without checking permission-granting call results.
 */
function verifyCWE280(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PERM_ERROR_SWALLOW_RE = /\bcatch\b[^{]*\{[^}]*(?:\/\/\s*ignore|\/\/\s*ok|\/\/\s*noop|continue|pass|\{\s*\})|except\s+(?:Permission|PermissionError|AccessDenied|Forbidden|UnauthorizedError|EACCES)[^:]*:\s*(?:pass|continue|\.\.\.|#)/i;
  const IGNORE_PERM_RESULT_RE = /\b(chmod|chown|setPermissions|grantAccess|setACL|fs\.chmod|os\.chmod|setfacl|setuid|setgid|seteuid|setegid|initgroups|setgroups)\s*\([^)]*\)\s*;?\s*(?:\/\/|$|\n)/i;
  const EMPTY_CATCH_RE = /\bcatch\s*\([^)]*\)\s*\{\s*\}|\bcatch\s*\(\s*\w+\s*\)\s*\{\s*(?:\/\/[^\n]*)?\s*\}/;
  const PERM_CONTEXT_RE = /\b(permission|privilege|access|chmod|chown|grant|deny|forbid|EACCES|EPERM|AccessDenied|Forbidden|403|Unauthorized)\b/i;
  const SAFE280_RE = /\b(throw|reject|abort|exit|process\.exit|raise|deny|forbid|return\s+false|return\s+null|next\s*\(\s*err|callback\s*\(\s*err|res\.status\s*\(\s*403\)|res\.status\s*\(\s*401\)|logging\.error|logger\.error|console\.error)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (PERM_ERROR_SWALLOW_RE.test(code)) {
      if (!SAFE280_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (proper handling of permission denial — must fail safely, not silently continue)',
          severity: 'high',
          description: `Code at ${node.label} catches permission/access errors and silently continues. ` +
            `When a privilege check fails, the code proceeds as though it succeeded.`,
          fix: 'When permission checks fail, propagate the error or deny the operation. ' +
            'Never catch permission errors with empty handlers. Log the failure and return an appropriate error response.',
          via: 'structural',
        });
      }
    }

    if (IGNORE_PERM_RESULT_RE.test(code)) {
      const resultChecked = /\b(result|status|ret|err|error|ok|success)\s*=.*\b(chmod|chown|setPermissions|grantAccess)\b|if\s*\(.*\b(chmod|chown|setPermissions)\b|\bawait\b.*\b(chmod|chown|setPermissions)\b.*\bthen\b/i;
      if (!resultChecked.test(code) && !SAFE280_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (check return value of permission-setting operations)',
          severity: 'medium',
          description: `Code at ${node.label} calls a permission-setting function without checking its return value. ` +
            `If the permission change fails silently, the application may operate with incorrect access controls.`,
          fix: 'Always check return values or catch errors from permission-setting operations. ' +
            'If chmod/chown/setACL fails, the operation that depends on those permissions must not proceed.',
          via: 'structural',
        });
      }
    }

    if (EMPTY_CATCH_RE.test(code) && PERM_CONTEXT_RE.test(code)) {
      if (!SAFE280_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (handle permission exceptions — empty catch in security-critical code)',
          severity: 'high',
          description: `Code at ${node.label} has an empty catch block in permission-related context. ` +
            `Permission failures are silently ignored.`,
          fix: 'Populate the catch block with proper error handling. For permission failures, deny the operation or escalate the error.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-280', name: 'Improper Handling of Insufficient Permissions or Privileges', holds: findings.length === 0, findings };
}

/**
 * CWE-282: Improper Ownership Management
 * Pattern: Resources created without ownership assignment, or ownership modified
 *          via user-controlled input without authorization.
 */
function verifyCWE282(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress282 = nodesOfType(map, 'INGRESS');

  const CREATE_RE = /\b(create|insert|save|add|new|put|POST|store|register|signup|upload)\b/i;
  const OWNER_FIELD_RE = /\b(owner|ownerId|owner_id|userId|user_id|createdBy|created_by|authorId|author_id|belongsTo|creator|uploaded_by|uploadedBy)\b/i;
  const OWNERSHIP_CHANGE_RE = /\b(owner|ownerId|owner_id|createdBy|created_by)\s*[:=]\s*(?:req\.|params\.|query\.|body\.|input\.|args\.)/i;
  const SAFE282_OWNER_RE = /\b(owner|ownerId|owner_id|userId|user_id|createdBy|created_by|authorId|author_id)\s*[:=]\s*(?:req\.user|session\.user|currentUser|auth\.user|token\.sub|jwt\.sub|ctx\.user|context\.user)/i;

  const creators282 = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('write') || n.node_subtype.includes('insert') ||
     n.node_subtype.includes('create') || CREATE_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const creator of creators282) {
    const code = stripComments(creator.analysis_snapshot || creator.code_snapshot);
    if (!OWNER_FIELD_RE.test(code) && !SAFE282_OWNER_RE.test(code) && CREATE_RE.test(code)) {
      findings.push({
        source: nodeRef(creator), sink: nodeRef(creator),
        missing: 'CONTROL (resource ownership assignment at creation time)',
        severity: 'medium',
        description: `Resource creation at ${creator.label} does not assign an owner. ` +
          `Without ownership, authorization checks on the resource cannot determine who should have access.`,
        fix: 'Set an owner field (e.g., ownerId: req.user.id) when creating resources. ' +
          'Use the authenticated user identity from the server-side session/token, not from client input.',
        via: 'structural',
      });
    }
  }

  for (const src of ingress282) {
    for (const node of map.nodes) {
      if (node.node_type !== 'STORAGE' && node.node_type !== 'CONTROL') continue;
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      if (OWNERSHIP_CHANGE_RE.test(code)) {
        if (hasTaintedPathWithoutControl(map, src.id, node.id)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(node),
            missing: 'CONTROL (prevent user-controlled ownership reassignment)',
            severity: 'high',
            description: `Ownership field at ${node.label} is set from user-controlled input (${src.label}). ` +
              `An attacker can claim ownership of any resource by supplying an arbitrary owner ID.`,
            fix: 'Never allow ownership to be set from request body/params. Derive ownership from the authenticated session. ' +
              'Ownership transfers should require admin approval or the current owner\'s verified consent.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-282', name: 'Improper Ownership Management', holds: findings.length === 0, findings };
}

/**
 * CWE-283: Unverified Ownership
 * Pattern: Resources accessed/modified using user-supplied IDs without verifying
 *          the requesting user owns (or has rights to) the resource. IDOR family.
 */
function verifyCWE283(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress283 = nodesOfType(map, 'INGRESS');

  const ID_INPUT_RE = /\b(params\.\w*[iI]d|params\.\w*[uU]uid|query\.\w*[iI]d|req\.params\.\w*[iI]d|:id|:userId|:resourceId|:postId|:orderId|:fileId|:docId|args\.\w*[iI]d|input\.\w*[iI]d)\b/i;
  const idInputs283 = ingress283.filter(n => ID_INPUT_RE.test(n.analysis_snapshot || n.code_snapshot));

  const stores283 = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('db_read') || n.node_subtype.includes('db_write') ||
     n.node_subtype.includes('query') || n.node_subtype.includes('find') ||
     n.node_subtype.includes('read') || n.node_subtype.includes('write') ||
     /\b(findById|findOne|findByPk|getOne|SELECT|findUnique|get|read|load|fetch|retrieve|download)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  const OWN_CHECK_RE = /\b(ownerId|owner_id|userId|user_id|createdBy|created_by|authorId|author_id|belongsTo)\s*[=!]==?\s*(?:req\.user|session\.user|currentUser|auth\.user|ctx\.user)|WHERE\s+.*user_id\s*=\s*\$?\w*user|\buser\.id\s*===?\s*\w+\.(?:owner|user|author|creator)/i;

  for (const src of idInputs283) {
    for (const store of stores283) {
      if (src.id === store.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, store.id)) {
        const storeCode = stripComments(store.analysis_snapshot || store.code_snapshot);
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
        if (!OWN_CHECK_RE.test(storeCode) && !OWN_CHECK_RE.test(srcCode)) {
          const intermediateCheck = map.nodes.some(n =>
            (n.node_type === 'CONTROL' || n.node_type === 'AUTH') &&
            OWN_CHECK_RE.test(n.analysis_snapshot || n.code_snapshot) &&
            sharesFunctionScope(map, n.id, store.id)
          );
          if (!intermediateCheck) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(store),
              missing: 'CONTROL (ownership verification — confirm requesting user owns the resource)',
              severity: 'high',
              description: `Resource ID from ${src.label} is used to access ${store.label} without verifying the requesting user owns the resource. ` +
                `An attacker can access or modify other users' resources by changing the ID parameter.`,
              fix: 'Add an ownership check: WHERE user_id = req.user.id, or verify resource.ownerId === req.user.id before access. ' +
                'Use row-level security policies if your database supports them.',
              via: 'bfs',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-283', name: 'Unverified Ownership', holds: findings.length === 0, findings };
}

/**
 * CWE-284: Improper Access Control
 * Pattern: Parent CWE for access control issues. Detects sensitive resources/operations
 *          with NO access control of any kind (no auth, no authz, no ownership check).
 */
function verifyCWE284(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress284 = nodesOfType(map, 'INGRESS');

  const ACCESS_CTRL_RE = /\b(auth|authorize|permission|privilege|role|isAdmin|requireRole|hasRole|checkAccess|isAuthenticated|requireAuth|verifyToken|jwt\.verify|passport|guard|acl|rbac|abac|policy|session\.user|req\.user|currentUser|isOwner|belongsTo|canAccess|allowedTo)\b/i;

  const sensitiveSinks284 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('admin') || n.node_subtype.includes('config') ||
     n.node_subtype.includes('user_management') || n.node_subtype.includes('financial') ||
     n.attack_surface.includes('admin') || n.attack_surface.includes('sensitive') ||
     n.attack_surface.includes('protected_resource') || n.attack_surface.includes('pii') ||
     /\b(admin|config|setting|user.*(?:create|delete|update|modify)|password|credential|payment|billing|role.*(?:assign|change|grant)|privilege|secret|key|token|apiKey|account.*(?:delete|suspend|close))\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress284) {
    const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
    if (ACCESS_CTRL_RE.test(srcCode)) continue;

    for (const sink of sensitiveSinks284) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutAuth(map, src.id, sink.id) &&
          hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!ACCESS_CTRL_RE.test(sinkCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'AUTH + CONTROL (no access control of any kind — neither authentication nor authorization)',
            severity: 'critical',
            description: `Sensitive operation at ${sink.label} is reachable from ${src.label} with NO access control. ` +
              `No authentication, no authorization, no permission check.`,
            fix: 'Add access control: (1) Authentication — verify identity via session/token, ' +
              '(2) Authorization — verify permissions via RBAC/ABAC, ' +
              '(3) Ownership — verify the user has rights to the specific resource.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-284', name: 'Improper Access Control', holds: findings.length === 0, findings };
}

/**
 * CWE-285: Improper Authorization
 * Pattern: Authorization checks exist but are implemented incorrectly — return values
 *          ignored, roles from client input, wrong operators, dev/test bypasses.
 */
function verifyCWE285(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress285 = nodesOfType(map, 'INGRESS');

  const AUTHZ_NODE_RE = /\b(authorize|hasPermission|checkPermission|checkAccess|isAuthorized|requireRole|hasRole|can\s*\(|isAdmin|role|permission|privilege|acl|rbac|policy|guard)\b/i;

  const authzNodes285 = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'AUTH') &&
    (n.node_subtype.includes('authorization') || n.node_subtype.includes('permission') ||
     n.node_subtype.includes('access_control') || n.node_subtype.includes('role') ||
     AUTHZ_NODE_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  const flawPatterns285: Array<{ pattern: RegExp; desc: string; sev: 'critical' | 'high' | 'medium' }> = [
    {
      pattern: /\b(?:authorize|checkPermission|hasRole|isAuthorized|checkAccess)\s*\([^)]*\)\s*;(?!\s*(?:if|return|\?\?|&&|\|\||\?|throw))/i,
      desc: 'Authorization function called but return value ignored — check result is discarded',
      sev: 'critical',
    },
    {
      pattern: /\brole\s*[:=]\s*(?:req\.body|req\.query|req\.params|request\.form|request\.args|input\.|args\.)/i,
      desc: 'Role/privilege derived from client-controlled input instead of server-side session',
      sev: 'critical',
    },
    {
      pattern: /\bisAdmin\s*[:=]\s*(?:req\.body|req\.query|req\.params|request\.form|args\.|input\.)/i,
      desc: 'Admin flag derived from client-controlled input — attacker can set isAdmin=true',
      sev: 'critical',
    },
    {
      pattern: /\b(?:role|permission|privilege|access[_-]?level)\s*==(?!=)\s*['"][^'"]+['"]/i,
      desc: 'Authorization uses loose equality (==) — type coercion can bypass the check',
      sev: 'high',
    },
    {
      pattern: /\b(?:or|OR|\|\|)\s*(?:true|1|isDebug|isDev|isTest|process\.env\.NODE_ENV\s*[!=]==?\s*['"](?:dev|test|development)['"])\b/i,
      desc: 'Authorization has OR-bypass with debug/dev/test condition — may remain in production',
      sev: 'high',
    },
  ];

  for (const az of authzNodes285) {
    const code = stripComments(az.analysis_snapshot || az.code_snapshot);
    for (const { pattern, desc, sev } of flawPatterns285) {
      if (pattern.test(code)) {
        let src285: typeof ingress285[0] | undefined;
        let via285: 'bfs' | 'scope_taint' | 'structural' = 'structural';
        for (const s of ingress285) {
          if (hasTaintedPathWithoutControl(map, s.id, az.id)) { src285 = s; via285 = 'bfs'; break; }
          if (!src285 && sharesFunctionScope(map, s.id, az.id)) { src285 = s; via285 = 'scope_taint'; }
        }
        findings.push({
          source: src285 ? nodeRef(src285) : nodeRef(az),
          sink: nodeRef(az),
          missing: 'CONTROL (correct authorization implementation)',
          severity: sev,
          description: `Authorization at ${az.label}: ${desc}. ` +
            `The authorization check exists but is implemented incorrectly, making it bypassable.`,
          fix: 'Fix the authorization implementation: (1) Always check and act on the result of authorization calls. ' +
            '(2) Derive roles from server-side session/JWT, never from request body. ' +
            '(3) Use strict equality (===). (4) Return/throw on authorization failure.',
          via: via285,
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-285', name: 'Improper Authorization', holds: findings.length === 0, findings };
}

/**
 * CWE-286: Incorrect User Management
 * Pattern: User management operations (create/delete/modify role) without proper admin
 *          authorization, or self-elevation of privileges via user input.
 */
function verifyCWE286(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress286 = nodesOfType(map, 'INGRESS');

  const USER_MGMT_RE = /\b(createUser|deleteUser|removeUser|updateUser|modifyUser|addUser|registerAdmin|changeRole|assignRole|setRole|grantAdmin|promoteUser|demoteUser|suspendUser|activateUser|resetPassword|setPassword|changePassword|updatePassword|disableAccount|enableAccount|blockUser|unblockUser|banUser|updateRole|manageUsers?|userManagement|user_management)\b/i;
  const SELF_ELEVATE_RE = /\b(role|isAdmin|admin|privilege|access[_-]?level|permission|is[_-]?super)\s*[:=]\s*(?:req\.body|req\.query|req\.params|request\.form|input\.|args\.)/i;
  const ADMIN_CHECK_RE = /\b(isAdmin|isSuperAdmin|requireAdmin|adminOnly|superuser|hasRole\s*\(\s*['"]admin['"]|role\s*===?\s*['"]admin['"]|checkAdmin|ensureAdmin|requireRole\s*\(\s*['"]admin['"])\b/i;

  const userMgmtSinks286 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('user_management') || n.node_subtype.includes('user_write') ||
     n.node_subtype.includes('role') || USER_MGMT_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress286) {
    for (const sink of userMgmtSinks286) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutAuth(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
        if (!ADMIN_CHECK_RE.test(sinkCode) && !ADMIN_CHECK_RE.test(srcCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'AUTH (admin/superuser check before user management operation)',
            severity: 'critical',
            description: `User management operation at ${sink.label} is reachable from ${src.label} without admin authorization. ` +
              `A regular user could create/delete/modify other user accounts or elevate privileges.`,
            fix: 'Require admin or superuser role for all user management operations. ' +
              'Use middleware like requireRole("admin"). Never allow users to modify their own role via request body.',
            via: 'bfs',
          });
        }
      }
    }
  }

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SELF_ELEVATE_RE.test(code) && USER_MGMT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (prevent self-elevation — roles must not come from user input)',
        severity: 'critical',
        description: `Code at ${node.label} sets user roles/privileges from client-controlled input in a user management context. ` +
          `An attacker can escalate their own privileges by setting role=admin in the request.`,
        fix: 'Never accept role assignments from client input. ' +
          'Roles must be assigned by authorized admins through a separate, protected operation.',
        via: 'bfs',
      });
    }
  }

  return { cwe: 'CWE-286', name: 'Incorrect User Management', holds: findings.length === 0, findings };
}

/**
 * CWE-289: Authentication Bypass by Alternate Name
 * Pattern: Auth/access control checks resource names via string comparison without
 *          canonicalization — bypassable via URL encoding, Unicode, case tricks, symlinks.
 */
function verifyCWE289(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PATH_AUTH_RE = /\b(url|path|pathname|filename|resource|route|endpoint|uri)\s*(?:===?|\.startsWith|\.endsWith|\.includes|\.match|\.test|\.indexOf)\s*[^;\n]*['"`\/]/i;
  const ALT_NAME_VULN_RE = /['"`](?:\/|\\|\.\.)[^'"`]*['"`]\s*(?:===?|!==?|\.startsWith|\.includes)/i;
  const CANON_SAFE_RE = /\b(realpath|normalize|resolve|canonical|canonicalize|decodeURIComponent|decodeURI|path\.resolve|path\.normalize|os\.path\.realpath|os\.path\.abspath|Paths\.get.*\.normalize|new\s+URL\s*\(|\.toLowerCase\s*\(\s*\).*(?:===|startsWith|endsWith|includes)|\.toUpperCase\s*\(\s*\).*(?:===|startsWith|endsWith|includes))\b/i;

  const authAndControl289 = map.nodes.filter(n =>
    n.node_type === 'AUTH' || n.node_type === 'CONTROL'
  );

  for (const node of authAndControl289) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (PATH_AUTH_RE.test(code) || ALT_NAME_VULN_RE.test(code)) {
      if (!CANON_SAFE_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'TRANSFORM (input canonicalization before name-based access control check)',
          severity: 'high',
          description: `Access control at ${node.label} makes decisions based on path/resource names without canonicalizing first. ` +
            `An attacker can bypass using URL encoding (%2e%2e), Unicode normalization, case tricks, or alternate path representations.`,
          fix: 'Canonicalize paths before comparing: use path.resolve/realpath, decodeURIComponent, toLowerCase(). ' +
            'Compare canonical forms only. Reject requests with encoded separators (../, %2e, %2f). ' +
            'Use allowlists of canonical resource names rather than denylists.',
          via: 'structural',
        });
      }
    }
  }

  const ingress289 = nodesOfType(map, 'INGRESS');
  for (const src of ingress289) {
    for (const ctrl of authAndControl289) {
      const ctrlCode = stripComments(ctrl.analysis_snapshot || ctrl.code_snapshot);
      if (PATH_AUTH_RE.test(ctrlCode) && !CANON_SAFE_RE.test(ctrlCode)) {
        if (hasTaintedPathWithoutControl(map, src.id, ctrl.id)) {
          if (!findings.some(f => f.sink.id === ctrl.id)) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(ctrl),
              missing: 'TRANSFORM (canonicalize user input before path-based auth comparison)',
              severity: 'high',
              description: `User input from ${src.label} reaches name-based access control at ${ctrl.label} without canonicalization. ` +
                `The attacker can encode or alias the resource name to bypass the check.`,
              fix: 'Normalize and canonicalize all user-supplied paths/names before any security decision. ' +
                'Apply decoding, case normalization, and path resolution before comparison.',
              via: 'bfs',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-289', name: 'Authentication Bypass by Alternate Name', holds: findings.length === 0, findings };
}

/**
 * CWE-291: Reliance on IP Address for Authentication
 * Pattern: IP address used as sole/primary authentication factor. More specific than CWE-290
 *          (spoofing) — targets IP-as-authentication specifically.
 */
function verifyCWE291(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const IP_AUTH_RE = /\b(?:x[_-]forwarded[_-]for|x[_-]real[_-]ip|x[_-]client[_-]ip|cf[_-]connecting[_-]ip|remote[_-]?addr|client[_-]?ip|REMOTE_ADDR|remoteAddress|socket\.remoteAddress|request\.ip|req\.ip|request\.remote_ip|getpeername|inet_addr|peer_addr|clientAddress)\b/i;
  const AUTH_DECISION_RE = /\b(allow|deny|trust|block|reject|grant|accept|whitelist|blacklist|authenticate|authorize|auth|permit|forbid|access)\b/i;
  const IP_WHITELIST_RE = /\b(?:allowed[_-]?ips?|trusted[_-]?ips?|whitelist[_-]?ips?|ip[_-]?whitelist|ip[_-]?allowlist|admin[_-]?ips?|internal[_-]?ips?)\b/i;
  const SAFE291_RE = /\b(jwt|token|session|cookie|apiKey|api[_-]key|bearer|oauth|saml|certificate|tls|ssl|mutual[_-]?auth|hmac|signature)\b/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'AUTH' && node.node_type !== 'CONTROL' && node.node_type !== 'INGRESS') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (IP_AUTH_RE.test(code) && AUTH_DECISION_RE.test(code)) {
      if (!SAFE291_RE.test(code)) {
        const isAuthNode = node.node_type === 'AUTH';
        const hasIpWhitelist = IP_WHITELIST_RE.test(code);
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'AUTH (cryptographic authentication — IP addresses are not identity proof)',
          severity: isAuthNode ? 'critical' : 'high',
          description: `${node.label} uses IP address for authentication/trust decisions${hasIpWhitelist ? ' (IP whitelist)' : ''}. ` +
            `IP addresses can be spoofed via X-Forwarded-For headers and are unreliable behind NAT/proxies.`,
          fix: 'Use cryptographic authentication (JWT, session tokens, mutual TLS, API keys) as the PRIMARY auth mechanism. ' +
            'IP-based restrictions are acceptable as ADDITIONAL defense-in-depth but never as the sole authentication factor.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-291', name: 'Reliance on IP Address for Authentication', holds: findings.length === 0, findings };
}

/**
 * CWE-302: Authentication Bypass by Assumed-Immutable Data
 * Pattern: Auth trusts client-supplied data that APPEARS immutable but is controllable —
 *          hidden form fields, unsigned cookies, localStorage, custom HTTP headers.
 */
function verifyCWE302(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const ASSUMED_IMMUTABLE_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
    {
      pattern: /\b(hidden|type\s*=\s*['"]hidden['"])\b[^;]*\b(auth|token|role|admin|user|session|level|permission)\b/i,
      desc: 'hidden form field carrying auth/role data',
    },
    {
      pattern: /\bcookie\b[^;]*\b(role|admin|isAdmin|is[_-]?admin|authenticated|loggedIn|logged_in|user[_-]?type|access[_-]?level|privilege)\b|\b(role|admin|isAdmin|authenticated|loggedIn|user[_-]?type|access[_-]?level)\b[^;]*\bcookie\b/i,
      desc: 'unsigned cookie carrying auth/role state',
    },
    {
      pattern: /\blocalStorage\b[^;]*\b(token|auth|role|admin|permission|session|user)\b|\bsessionStorage\b[^;]*\b(token|auth|role|admin|permission|user)\b/i,
      desc: 'localStorage/sessionStorage carrying auth data (client-controlled)',
    },
    {
      pattern: /\breq\.headers\b[^;]*\b(role|admin|isAdmin|privilege|access[_-]?level|user[_-]?type|authenticated)\b/i,
      desc: 'custom HTTP header carrying role/privilege data',
    },
    {
      pattern: /\b(req\.body|req\.query|request\.form|request\.args)\b[^;]*\b(isAuthenticated|isLoggedIn|authenticated|loggedIn|verified|isAdmin)\b/i,
      desc: 'request body/query carrying authentication state flag',
    },
  ];

  const SIGNED_RE = /\b(hmac|signature|sign|verify|jwt|jws|encrypt|hash|sha256|sha1|md5|crypto\.create|createHmac|createSign|verifySignature|validateToken)\b/i;

  const authAndControl302 = map.nodes.filter(n =>
    n.node_type === 'AUTH' || n.node_type === 'CONTROL'
  );

  for (const node of authAndControl302) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const { pattern, desc } of ASSUMED_IMMUTABLE_PATTERNS) {
      if (pattern.test(code)) {
        if (!SIGNED_RE.test(code)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (server-side verification — do not trust client-supplied auth state)',
            severity: 'critical',
            description: `Authentication at ${node.label} trusts ${desc}. ` +
              `This data appears immutable but is fully controlled by the client. ` +
              `An attacker can modify hidden fields, cookies, headers, and localStorage to bypass auth.`,
            fix: 'Never trust client-supplied authentication/authorization state. ' +
              'Maintain auth state server-side (sessions, signed JWTs). ' +
              'If auth data must be in cookies, sign them with HMAC and verify server-side.',
            via: 'structural',
          });
          break;
        }
      }
    }
  }

  const ingress302 = nodesOfType(map, 'INGRESS');
  for (const src of ingress302) {
    const code = stripComments(src.analysis_snapshot || src.code_snapshot);
    for (const { pattern, desc } of ASSUMED_IMMUTABLE_PATTERNS) {
      if (pattern.test(code) && !SIGNED_RE.test(code)) {
        for (const auth of authAndControl302) {
          if (hasTaintedPathWithoutControl(map, src.id, auth.id)) {
            if (!findings.some(f => f.source.id === src.id && f.sink.id === auth.id)) {
              findings.push({
                source: nodeRef(src), sink: nodeRef(auth),
                missing: 'CONTROL (cryptographic verification of client-supplied auth data)',
                severity: 'high',
                description: `Client-controlled ${desc} from ${src.label} flows to auth decision at ${auth.label} without signature verification.`,
                fix: 'Sign auth data with server-side secret (HMAC, JWT). Verify the signature before trusting the data.',
                via: 'bfs',
              });
            }
            break;
          }
        }
        break;
      }
    }
  }

  return { cwe: 'CWE-302', name: 'Authentication Bypass by Assumed-Immutable Data', holds: findings.length === 0, findings };
}

/**
 * CWE-304: Missing Critical Step in Authentication
 * Pattern: Authentication that skips a critical step — verifies username but not password,
 *          checks token format but not signature, validates but never checks expiration.
 */
function verifyCWE304(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const USERNAME_CHECK_RE = /\b(username|user[_-]?name|email|login|userId|user_id|user)\b\s*(?:===?|!==?|==|\.equals|\.match)/i;
  const PASSWORD_CHECK_RE = /\b(password|passwd|pwd|passphrase|pass[_-]?word|secret)\b\s*(?:===?|!==?|==|\.equals|bcrypt|argon|scrypt|compare|verify|hash|pbkdf)/i;
  const TOKEN_FORMAT_RE = /\b(token|jwt|bearer)\b\s*(?:\.split|\.length|\.startsWith|typeof|!==?\s*['"]?(?:undefined|null)['"]?)/i;
  const TOKEN_VERIFY_RE = /\b(jwt\.verify|verifyToken|validateToken|verify[_-]?signature|jws\.verify|crypto\.verify|checkSignature|decodeToken.*verify)\b/i;
  const EXPIRY_CHECK_RE = /\b(exp|expir|expiration|expiresAt|expires_at|token_expiry|isExpired|notExpired|Date\.now|ttl|max[_-]?age)\b/i;
  const SESSION_INVALIDATE_RE = /\b(destroy|invalidate|revoke|delete|clear|remove|expire|logout|logOut|signOut|sign_out)\b.*\b(session|token|cookie)\b|\b(session|token|cookie)\b.*\b(destroy|invalidate|revoke|delete|clear|remove|expire)\b/i;

  const authNodes304 = nodesOfType(map, 'AUTH');

  for (const authNode of authNodes304) {
    const code = stripComments(authNode.analysis_snapshot || authNode.code_snapshot);
    const hasUsername = USERNAME_CHECK_RE.test(code);
    const hasPassword = PASSWORD_CHECK_RE.test(code);
    const hasTokenFormat = TOKEN_FORMAT_RE.test(code);
    const hasTokenVerify = TOKEN_VERIFY_RE.test(code);
    const hasExpiryCheck = EXPIRY_CHECK_RE.test(code);

    if (hasUsername && !hasPassword && !hasTokenVerify) {
      if (/\b(login|authenticate|auth|signIn|sign_in|verify|check)\b/i.test(code)) {
        findings.push({
          source: nodeRef(authNode), sink: nodeRef(authNode),
          missing: 'AUTH (password/credential verification — only username is checked)',
          severity: 'critical',
          description: `Authentication at ${authNode.label} checks the username/identity but does not verify the password or credential. ` +
            `Any user who knows a valid username can authenticate without the correct password.`,
          fix: 'Always verify both the identity (username/email) AND the credential (password, token, certificate). ' +
            'Use bcrypt.compare or equivalent for password verification.',
          via: 'structural',
        });
      }
    }

    if (hasTokenFormat && !hasTokenVerify) {
      findings.push({
        source: nodeRef(authNode), sink: nodeRef(authNode),
        missing: 'AUTH (token signature verification — only format is checked, not authenticity)',
        severity: 'critical',
        description: `Authentication at ${authNode.label} checks token format/presence but does not verify the cryptographic signature. ` +
          `An attacker can forge tokens that pass the format check but contain arbitrary claims.`,
        fix: 'Always verify token signatures using jwt.verify() or equivalent with the server-side secret/public key. ' +
          'Checking token format, length, or presence is NOT authentication.',
        via: 'structural',
      });
    }

    if (hasTokenVerify && !hasExpiryCheck) {
      const autoExpiry = /jwt\.verify|jose\.jwtVerify|jsonwebtoken/i.test(code);
      if (!autoExpiry) {
        findings.push({
          source: nodeRef(authNode), sink: nodeRef(authNode),
          missing: 'AUTH (token expiration check — tokens are verified but never expire)',
          severity: 'high',
          description: `Authentication at ${authNode.label} verifies the token but does not check expiration. ` +
            `Stolen or leaked tokens remain valid indefinitely.`,
          fix: 'Include an "exp" claim in tokens and verify it. Use libraries that check expiration automatically. ' +
            'Implement token rotation and short-lived access tokens with refresh tokens.',
          via: 'structural',
        });
      }
    }
  }

  const loginHandlers304 = map.nodes.filter(n =>
    (n.node_type === 'AUTH' || n.node_type === 'INGRESS') &&
    /\b(login|signIn|sign_in|authenticate)\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const handler of loginHandlers304) {
    const code = stripComments(handler.analysis_snapshot || handler.code_snapshot);
    if (/\b(session|req\.session|request\.session)\b/i.test(code) && !SESSION_INVALIDATE_RE.test(code)) {
      const sessionRegen = /\b(regenerate|regenerateId|rotate|newSession|create.*session|session\.id\s*=)\b/i;
      if (!sessionRegen.test(code)) {
        findings.push({
          source: nodeRef(handler), sink: nodeRef(handler),
          missing: 'AUTH (session regeneration on login — old session ID remains valid)',
          severity: 'medium',
          description: `Login handler at ${handler.label} creates/uses a session but does not invalidate or regenerate the old session ID. ` +
            `This allows session fixation attacks.`,
          fix: 'Regenerate the session ID on successful login (req.session.regenerate()). ' +
            'Invalidate old sessions before creating new ones.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-304', name: 'Missing Critical Step in Authentication', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Privilege & Permission Management
// ---------------------------------------------------------------------------

/**
 * CWE-266: Incorrect Privilege Assignment
 * Pattern: Code assigns privileges incorrectly — granting too much, assigning to the
 * wrong principal, or using default-allow.
 * Property: Privilege assignments follow least privilege and are validated against policy.
 */
function verifyCWE266(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const OVERPRIVILEGED = /\b(chmod\s*\(\s*[^,]*,?\s*(?:0?777|0?776|0?766|0o777|0o776)|permissions?\s*[:=]\s*['"]?\*['"]?|role\s*[:=]\s*['"]admin['"]|isAdmin\s*[:=]\s*true|GRANT\s+ALL|ALL\s+PRIVILEGES|capabilities\s*[:=]\s*\[\s*['"]?\*|sudo\s+ALL|NOPASSWD:\s*ALL|S_IRWXO|world.*(?:read|writ)|other.*(?:read|writ)|everyone.*full|--privileged|securityContext.*privileged:\s*true|CAP_SYS_ADMIN|cap_add.*ALL)\b/i;
  const DEFAULT_ADMIN = /\b(default.*role\s*[:=]\s*['"]admin|default.*permission\s*[:=]\s*['"]?\*|new.*User\s*\([^)]*admin|createUser\s*\([^)]*role\s*[:=]\s*['"]admin|register.*admin.*default)\b/i;
  const PROPER_ASSIGNMENT = /\b(least.*privilege|minimal.*permission|restrict|rbac|abac|role.*assign.*validate|policy\.check|principal\.can|hasPermission|authorize|if\s*\(\s*isAdmin|requireRole|@RolesAllowed|@Secured|@PreAuthorize)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (OVERPRIVILEGED.test(code) && !PROPER_ASSIGNMENT.test(code)) {
      const match = code.match(OVERPRIVILEGED)?.[0] || 'overprivileged assignment';
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (least-privilege assignment — restrict permissions to minimum needed)',
        severity: 'high',
        description: `Overprivileged assignment at ${node.label}: "${match}". ` +
          `Assigning maximum privileges violates least privilege — if the principal is compromised, ` +
          `the attacker inherits all granted privileges.`,
        fix: 'Apply least privilege: grant only the specific permissions needed. ' +
          'chmod 750 instead of 777. Assign specific roles, not "admin" by default. ' +
          'Use GRANT SELECT ON specific_table instead of GRANT ALL. ' +
          'In containers, drop ALL capabilities and add back only what is needed.',
        via: 'structural',
      });
    }

    if (DEFAULT_ADMIN.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (default to minimum privileges — never default to admin)',
        severity: 'critical',
        description: `Default admin privilege assignment at ${node.label}. New users or resources ` +
          `are assigned admin/full privileges by default. This means any newly created account ` +
          `has full system access until explicitly restricted.`,
        fix: 'Default to the minimum privilege level (e.g., "viewer" or "user" role). ' +
          'Require explicit, authenticated, authorized action to elevate privileges. ' +
          'Follow principle of fail-safe defaults: absence of access should mean denial.',
        via: 'structural',
      });
    }
  }

  // Check INGRESS->AUTH/STORAGE paths where user input sets privilege levels
  const ingress = nodesOfType(map, 'INGRESS');
  const authNodes = nodesOfType(map, 'AUTH');
  const PRIV_FIELD = /\b(role|permission|privilege|admin|isAdmin|access_level|accessLevel|group|authority)\b/i;

  for (const src of ingress) {
    for (const auth of authNodes) {
      if (src.id === auth.id) continue;
      if (PRIV_FIELD.test(auth.analysis_snapshot || auth.code_snapshot) && hasTaintedPathWithoutControl(map, src.id, auth.id)) {
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
        if (!PROPER_ASSIGNMENT.test(srcCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(auth),
            missing: 'CONTROL (validate privilege assignment — user input should not directly set roles)',
            severity: 'critical',
            description: `User input from ${src.label} directly influences privilege assignment at ${auth.label}. ` +
              `An attacker can set their own role to "admin" or grant themselves arbitrary permissions.`,
            fix: 'Never accept privilege/role values directly from user input. Use server-side lookup to map user actions ' +
              'to privilege levels. Validate against an allowlist of assignable roles. ' +
              'Require existing admin authorization to assign elevated roles.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-266', name: 'Incorrect Privilege Assignment', holds: findings.length === 0, findings };
}

/**
 * CWE-268: Privilege Chaining
 * Pattern: One privilege is used to acquire another, creating a chain where compromising
 * the first automatically grants the second. Privileges should be independently validated.
 * Property: Each privilege level requires independent authentication/authorization.
 */
function verifyCWE268(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const PRIV_CHAIN = /\b(if\s*\(\s*(?:is|has)(?:Auth|Logged|User)\w*\s*(?:\(\)|)\s*\)\s*\{[^}]*(?:admin|moderator|superuser|elevated|root|manager|operator)|role\s*===?\s*['"]user['"]\s*(?:\|\||&&)\s*.*(?:admin|moderator|elevat)|canRead.*canWrite.*canDelete|hasAny.*Permission|user\.roles\.includes\s*\(\s*['"]user['"]\s*\)\s*(?:\|\||&&)\s*.*(?:admin|manager)|req\.session\s*&&[^;]*admin|isAuthenticated\s*(?:\(\)|)\s*(?:\?\s*true|&&\s*true|\|\|\s*isAdmin))\b/i;
  const DERIVED_PRIV = /\b(token\.includes\s*\(\s*['"]admin|token.*split.*role|jwt\..*role\s*===?\s*['"]user['"].*admin|bearer.*admin|session\[['"]role['"]\]\s*=\s*['"]admin|cookie.*admin|localStorage.*role.*admin|req\.(?:query|params|body)\..*(?:role|admin|permission))\b/i;
  const INDEPENDENT_AUTH = /\b(require\w*Auth\s*\(\s*['"]admin|checkRole\s*\(\s*['"]admin|@RequiresRole\s*\(\s*['"]admin|authorize\s*\(\s*['"]admin|requirePermission\s*\(\s*['"]|rbac\.check|abac\.evaluate|policy\.enforce|step_up_auth|mfa|two_factor|2fa|reauth|re-auth|re.?authenticate|verify.*password.*before|confirmPassword|currentPassword)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (PRIV_CHAIN.test(code) && !INDEPENDENT_AUTH.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (independent privilege validation — do not chain privileges)',
        severity: 'high',
        description: `Privilege chaining detected at ${node.label}: a lower privilege level appears to ` +
          `automatically grant a higher one. Authentication (is the user logged in?) is being conflated ` +
          `with authorization (does this user have admin rights?). An attacker who gains basic access ` +
          `may automatically inherit elevated privileges.`,
        fix: 'Validate each privilege level independently. Admin operations should require admin-specific authorization, ' +
          'not just "is authenticated." Implement step-up authentication for sensitive operations. ' +
          'Use RBAC/ABAC with explicit role checks at each privilege boundary. ' +
          'Never derive higher privileges from lower ones.',
        via: 'structural',
      });
    }

    if (DERIVED_PRIV.test(code) && !INDEPENDENT_AUTH.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (independent authorization — do not derive privileges from tokens/sessions)',
        severity: 'high',
        description: `Code at ${node.label} derives privilege levels from client-controlled data (tokens, sessions, ` +
          `cookies) without independent server-side validation. If the token/session is compromised or ` +
          `manipulated, the derived privilege level is also compromised.`,
        fix: 'Validate privileges on every request against a server-side authority (database, LDAP, IAM). ' +
          'Do not trust client-side role claims. Use signed, server-verified tokens (JWT with server-side validation). ' +
          'Implement privilege separation: each privilege domain should have its own verification.',
        via: 'structural',
      });
    }
  }

  // Check AUTH->AUTH paths where one auth check enables bypassing another
  const authNodes = nodesOfType(map, 'AUTH');
  for (let i = 0; i < authNodes.length; i++) {
    for (let j = 0; j < authNodes.length; j++) {
      if (i === j) continue;
      const src = authNodes[i];
      const sink = authNodes[j];
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const srcLevel = /\b(user|read|basic|view)\b/i.test(srcCode);
        const sinkLevel = /\b(admin|write|delete|execute|manage|super)\b/i.test(sinkCode);
        if (srcLevel && sinkLevel && !INDEPENDENT_AUTH.test(sinkCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (independent validation — higher privilege must not chain from lower)',
            severity: 'high',
            description: `Lower-privilege auth at ${src.label} flows to higher-privilege auth at ${sink.label} ` +
              `without independent validation. Gaining the lower privilege may automatically bypass the higher check.`,
            fix: 'Each authorization level must independently verify the principal has the required privilege. ' +
              'Use separate auth middleware for each privilege tier. Require step-up authentication (MFA, password re-entry) ' +
              'for privilege-escalating operations.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-268', name: 'Privilege Chaining', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Data Authenticity & Integrity Verification
// ---------------------------------------------------------------------------

/**
 * CWE-351: Insufficient Type Distinction
 * Detects security decisions based on values that don't carry type information,
 * e.g., treating file extensions as authoritative content types, using string
 * comparisons for typed enums, or conflating user roles by string matching
 * instead of typed role objects.
 */
function verifyCWE351(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // File extension as content type (classic: upload filter by extension only)
  const EXT_AS_TYPE_RE = /\.endsWith\s*\(\s*['"]\.(?:jpg|jpeg|png|gif|pdf|doc|exe|php|jsp|asp|sh|bat)['"]\s*\)|\.split\s*\(\s*['"]\.['"].*(?:pop|slice|-1)|\.match\s*\(\s*\/\\\.(?:jpg|png|gif|pdf)/i;
  const MIME_CHECK_RE = /\.(?:mimetype|content[_-]?type|type)\s*(?:===?|!==?|\.includes|\.startsWith)/i;
  const CONTENT_INSPECT_RE = /\bfile[_-]?type\b.*\bmagic\b|\bfileType\s*\(|\bfile-type\b|\bmimeMagic\b|\bmagicBytes\b|\bfile\s+--mime/i;

  // String role comparison without type safety
  const STRING_ROLE_RE = /\b(?:role|permission|privilege|access[_-]?level)\s*(?:===?\s*['"]|\.includes\s*\(\s*['"]).*(admin|user|moderator|editor|viewer|owner|manager|superuser)/i;
  const ENUM_ROLE_RE = /\bRole\.\w+|\bPermission\.\w+|\bAccessLevel\.\w+|\benum\s+Role\b|\benum\s+Permission\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check 1: File extension used as content type for security decisions
    if (EXT_AS_TYPE_RE.test(code) && !MIME_CHECK_RE.test(code) && !CONTENT_INSPECT_RE.test(code)) {
      const isUpload = /upload|file|attachment|import|media/i.test(node.label) || /upload|file/i.test(node.node_subtype);
      if (isUpload || node.node_type === 'CONTROL') {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (content-based type detection — magic bytes, MIME sniffing)',
          severity: 'high',
          description: `File type determined by extension alone at ${node.label}. ` +
            `An attacker can rename malicious.php to malicious.jpg to bypass upload filters.`,
          fix: 'Validate content type by inspecting magic bytes (file-type library, libmagic). ' +
            'Never trust file extensions for security decisions. Check both extension AND content.',
          via: 'structural',
        });
      }
    }

    // Check 2: String-based role comparison without typed enum
    if (STRING_ROLE_RE.test(code) && !ENUM_ROLE_RE.test(code) && node.node_type === 'CONTROL') {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (typed role/permission enum instead of string comparison)',
        severity: 'medium',
        description: `Authorization at ${node.label} compares roles as plain strings. ` +
          `String comparisons are fragile — typos ("adimn" vs "admin"), case differences, or unicode ` +
          `homoglyphs can bypass checks without compiler/type-system detection.`,
        fix: 'Use typed enums or constant objects for roles/permissions. ' +
          'This ensures the type system catches invalid values at compile time.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-351', name: 'Insufficient Type Distinction', holds: findings.length === 0, findings };
}

/**
 * CWE-355: User Interface Security Issues
 * Detects UI patterns that create security vulnerabilities: sensitive data
 * displayed without masking, autocomplete on password fields, form actions
 * to HTTP (not HTTPS), and sensitive inputs without input masking.
 */
function verifyCWE355(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Sensitive data displayed in UI without masking
  const DISPLAY_SENSITIVE_RE = /\b(?:innerHTML|textContent|innerText|\.text\s*=|\.value\s*=|\.html\s*\(|\.text\s*\(|render|display|show)\b.*\b(?:password|secret|token|ssn|credit[_-]?card|cvv|pin|api[_-]?key)\b/i;
  const MASK_RE = /\bmask\s*\(|\b\*{3,}\b|\bpassword[_-]?mask\b|\bhidden\b|\bobscure\b|\bredact\s*\(|\btype\s*[:=]\s*['"]password['"]/i;
  // Autocomplete on sensitive fields not disabled
  const AUTOCOMPLETE_ON_RE = /autocomplete\s*[:=]\s*['"](?:on|name|email|cc-number|cc-exp)['"]/i;
  const SENSITIVE_FIELD_RE = /\b(?:password|credit[_-]?card|ccn|cvv|ssn|secret|token|pin)\b/i;
  // HTTP form actions
  const HTTP_FORM_RE = /action\s*[:=]\s*['"]http:\/\//i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Sensitive data display without masking
    if (DISPLAY_SENSITIVE_RE.test(code) && !MASK_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (data masking before UI display)',
        severity: 'medium',
        description: `Sensitive data displayed without masking at ${node.label}. ` +
          `Shoulder surfing, screen recording, or screenshots can capture secrets.`,
        fix: 'Mask sensitive values in the UI: show only last 4 chars of tokens, use type="password" for secrets, ' +
          'implement copy-to-clipboard instead of displaying.',
        via: 'structural',
      });
    }

    // HTTP form action for sensitive data
    if (HTTP_FORM_RE.test(code) && SENSITIVE_FIELD_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (HTTPS for sensitive form submission)',
        severity: 'high',
        description: `Form at ${node.label} submits sensitive data over plain HTTP. ` +
          `Credentials and personal data are visible to network observers.`,
        fix: 'Use HTTPS for all form submissions containing sensitive data. ' +
          'Set form action to relative URLs or HTTPS absolute URLs.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-355', name: 'User Interface Security Issues', holds: findings.length === 0, findings };
}

/**
 * CWE-357: Insufficient UI Warning of Dangerous Operations
 * Detects dangerous operations (account deletion, data purge, permission grants,
 * financial transfers) executed without confirmation UI. Extends CWE-356 but
 * focuses on MISSING WARNING rather than missing confirmation — the distinction
 * is that CWE-357 covers cases where a warning SHOULD be shown but the code
 * proceeds silently.
 */
function verifyCWE357(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Irreversible/dangerous operations
  const DANGER_OPS_RE = /\b(deleteAccount|removeUser|dropDatabase|dropTable|truncateTable|purgeData|revokeAll|resetPassword|transferFunds|withdrawAll|formatDisk|factoryReset|deactivateAccount|disableMFA|removeAllPermissions|deleteAll|clearAllData)\s*\(/i;
  // Alternate: dangerous ops in EXTERNAL/STORAGE nodes with specific patterns
  const DANGER_PATTERN_RE = /\bDELETE\s+FROM\b.*\bWHERE\b.*\b(?:1\s*=\s*1|true)\b|\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\b|\bdelete\s*\(\s*\)\s*\.(?:many|all)\b/i;
  const WARNING_RE = /\bconfirm\s*\(|\bwindow\.confirm\b|\bconfirmation\b|\bconfirmDialog\b|\bshowConfirm\b|\bare[_-]?you[_-]?sure\b|\bwarning[_-]?dialog\b|\bwarnUser\b|\bdangerousAction\b|\brequireConfirmation\b|\bconfirmDangerous\b|\bshowWarning\b|\balert\s*\(\s*['"].*(?:danger|warning|irreversible|cannot be undone)/i;
  const REAUTH_RE = /\bre[_-]?authenticate\b|\bpassword[_-]?confirm\b|\bverify[_-]?identity\b|\b2fa\b|\btwo[_-]?factor\b|\bstep[_-]?up[_-]?auth\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const isDangerous = DANGER_OPS_RE.test(code) || DANGER_PATTERN_RE.test(code);
    if (!isDangerous) continue;

    // Check the node itself and siblings in scope for warnings
    const hasWarning = WARNING_RE.test(code) || REAUTH_RE.test(code);
    if (hasWarning) continue;

    const scopeNodes = map.nodes.filter(n => n.id !== node.id && sharesFunctionScope(map, node.id, n.id));
    const scopeHasWarning = scopeNodes.some(n => {
      const c = stripComments(n.analysis_snapshot || n.code_snapshot);
      return WARNING_RE.test(c) || REAUTH_RE.test(c);
    });
    if (scopeHasWarning) continue;

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'CONTROL (user warning/confirmation before irreversible operation)',
      severity: 'medium',
      description: `Dangerous operation at ${node.label} executes without user warning. ` +
        `Accidental invocation, CSRF, or XSS-triggered calls could cause irreversible damage ` +
        `(data loss, account deletion, privilege changes) with no user awareness.`,
      fix: 'Show an explicit warning dialog explaining the consequences before executing. ' +
        'For high-impact operations, require re-authentication or a typed confirmation phrase ' +
        '(e.g., "type DELETE to confirm").',
      via: 'scope_taint',
    });
  }
  return { cwe: 'CWE-357', name: 'Insufficient UI Warning of Dangerous Operations', holds: findings.length === 0, findings };
}

/**
 * CWE-358: Improperly Implemented Security Check for Standard
 * Detects ad-hoc reimplementations of standard security checks instead of
 * using established libraries: hand-rolled JWT parsing, custom bcrypt,
 * manual certificate validation, DIY OAuth, custom SAML parsing.
 */
function verifyCWE358(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Hand-rolled JWT parsing (splitting on dots, base64 decoding, but no library verify)
  const DIY_JWT_RE = /\.split\s*\(\s*['"]\.['"].*(?:base64|atob|Buffer\.from)|(?:base64|atob|Buffer\.from).*\.split\s*\(\s*['"]\.['"]/i;
  const JWT_LIB_RE = /\bjwt\.verify\b|\bjose\.jwtVerify\b|\bjwtVerify\b|\bjsonwebtoken\b|\bjose\b|\bPassportStrategy\b/i;

  // Hand-rolled password hashing (instead of bcrypt/scrypt/argon2)
  const DIY_HASH_RE = /\b(?:createHash|hashlib|MessageDigest|sha256|sha512|md5)\b.*\b(?:password|passwd|pwd|credential)\b/i;
  const HASH_LIB_RE = /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bpbkdf2\b|\bpasslib\b|\bpassword[_-]?hash\b/i;

  // DIY certificate/TLS validation
  const DIY_CERT_RE = /\brejectUnauthorized\s*:\s*false|\bverify[_-]?ssl\s*[:=]\s*(?:false|False|0)|\bINSECURE\b|\bcert[_-]?verify\s*[:=]\s*(?:false|False)|\bssl\s*[:=]\s*\{\s*rejectUnauthorized\s*:\s*false/i;

  // DIY OAuth (manual token exchange without library)
  const DIY_OAUTH_RE = /\bfetch\s*\(\s*['"].*\/token['"]|\.post\s*\(\s*['"].*\/oauth\/token['"]|client_secret.*grant_type|grant_type.*client_secret/i;
  const OAUTH_LIB_RE = /\bpassport\b|\boauth2[_-]?client\b|\boauthlib\b|\bgolang\.org\/x\/oauth2\b|\bSpring[_-]?Security\b|\bauth0\b|\boidc[_-]?client\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Hand-rolled JWT parsing
    if (DIY_JWT_RE.test(code) && !JWT_LIB_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EXTERNAL (standard JWT library — jsonwebtoken, jose)',
        severity: 'high',
        description: `Hand-rolled JWT parsing at ${node.label}. Splitting on "." and base64-decoding ` +
          `skips signature verification, algorithm validation, expiry checks, and claim validation.`,
        fix: 'Use a standard JWT library (jsonwebtoken, jose, PyJWT) that handles signature verification, ' +
          'algorithm whitelisting, and claim validation correctly.',
        via: 'structural',
      });
    }

    // Hand-rolled password hashing
    if (DIY_HASH_RE.test(code) && !HASH_LIB_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'EXTERNAL (password hashing library — bcrypt, argon2, scrypt)',
        severity: 'critical',
        description: `Ad-hoc password hashing at ${node.label} using raw SHA/MD5 instead of a password-specific KDF. ` +
          `Fast hashes are trivially brute-forced — GPU rigs crack billions of SHA-256 hashes per second.`,
        fix: 'Use bcrypt, argon2id, or scrypt for password storage. These algorithms are deliberately slow ' +
          'and include built-in salting.',
        via: 'structural',
      });
    }

    // Disabled certificate verification
    if (DIY_CERT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (proper TLS certificate verification)',
        severity: 'critical',
        description: `TLS certificate verification disabled at ${node.label}. ` +
          `This allows man-in-the-middle attacks — any certificate, including self-signed attacker certs, is accepted.`,
        fix: 'Enable certificate verification. Use proper CA bundles. If using self-signed certs in development, ' +
          'use environment-conditional configuration, not blanket disabling.',
        via: 'structural',
      });
    }

    // DIY OAuth without library
    if (DIY_OAUTH_RE.test(code) && !OAUTH_LIB_RE.test(code)) {
      const hasStateParam = /\bstate\s*[:=]|\bstate\b.*\brandom\b/i.test(code);
      if (!hasStateParam) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'EXTERNAL (OAuth2 library with CSRF state parameter)',
          severity: 'high',
          description: `Manual OAuth token exchange at ${node.label} without state parameter verification. ` +
            `Missing CSRF protection in OAuth flow allows login CSRF attacks.`,
          fix: 'Use an established OAuth2 library (passport, oauthlib, Spring Security OAuth2) that handles ' +
            'state parameter generation, PKCE, token validation, and CSRF protection.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-358', name: 'Improperly Implemented Security Check for Standard', holds: findings.length === 0, findings };
}

/**
 * CWE-360: Trust of System Event Data
 * Detects code that trusts system event data (environment variables, HTTP headers,
 * DNS responses, OS signals, webhook payloads) without validation. Attackers
 * can spoof these in many contexts.
 */
function verifyCWE360(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Trusting spoofable headers for security decisions
  const SPOOFABLE_HEADER_RE = /\b(?:x[_-]?forwarded[_-]?for|x[_-]?real[_-]?ip|x[_-]?forwarded[_-]?host|x[_-]?forwarded[_-]?proto|referer|origin|x[_-]?request[_-]?id|x[_-]?correlation[_-]?id|x[_-]?client[_-]?ip)\b/i;
  const SEC_DECISION_RE = /\b(?:if|switch|case|===?|!==?|\.includes|\.startsWith)\b/i;
  const AUTH_CONTEXT_RE = /\b(auth|permission|access|allow|deny|block|rate[_-]?limit|throttle|whitelist|blacklist|ban|trust|isAdmin|isInternal)\b/i;

  // Trusting webhook payloads without signature verification
  const WEBHOOK_RE = /\bwebhook\b|\bcallback[_-]?url\b|\bnotification[_-]?endpoint\b|\bevent[_-]?handler\b.*\b(?:req|request)\b/i;
  const WEBHOOK_VERIFY_RE = /\bverifySignature\b|\bhmac\b|\bcrypto\.createHmac\b|\bverify[_-]?webhook\b|\bsignature[_-]?valid\b|\btimingSafeEqual\b|\bstripe\.webhooks\.constructEvent\b/i;

  // Trusting environment variables for security in production
  const ENV_TRUST_RE = /\bprocess\.env\.\w*(?:ADMIN|DEBUG|DISABLE[_-]?AUTH|BYPASS|SKIP[_-]?VERIFY|TRUST|ALLOW[_-]?ALL)\b|\bos\.environ.*(?:ADMIN|DEBUG|DISABLE[_-]?AUTH|BYPASS)\b|\bgetenv\s*\(\s*['"](?:ADMIN|DEBUG|DISABLE_AUTH|BYPASS)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Spoofable headers used in security decisions
    if (SPOOFABLE_HEADER_RE.test(code) && SEC_DECISION_RE.test(code) && AUTH_CONTEXT_RE.test(code)) {
      // Check if there's validation of the header against known proxies
      const PROXY_VALIDATE_RE = /\btrustedProxies\b|\btrust[_-]?proxy\b|\ballowedIps\b|\bproxy[_-]?whitelist\b/i;
      if (!PROXY_VALIDATE_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (validation of spoofable system event data — trusted proxy list)',
          severity: 'high',
          description: `Security decision at ${node.label} trusts spoofable header (X-Forwarded-For, Referer, etc.). ` +
            `Attackers can set arbitrary HTTP headers to bypass IP-based access controls, rate limiting, or auth.`,
          fix: 'Never use spoofable headers for security decisions without a trusted proxy configuration. ' +
            'Use the direct connection IP (req.socket.remoteAddress) and configure trust proxy settings. ' +
            'Validate X-Forwarded-For only from known proxy IPs.',
          via: 'structural',
        });
      }
    }

    // Webhook payloads without signature verification
    if (WEBHOOK_RE.test(code) && node.node_type === 'INGRESS') {
      const scopeNodes = map.nodes.filter(n => sharesFunctionScope(map, node.id, n.id));
      const hasVerify = scopeNodes.some(n => WEBHOOK_VERIFY_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
      if (!hasVerify && !WEBHOOK_VERIFY_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (webhook signature verification — HMAC, crypto.timingSafeEqual)',
          severity: 'high',
          description: `Webhook endpoint at ${node.label} processes payloads without signature verification. ` +
            `An attacker can forge webhook events to trigger actions (payments, account changes, deployments).`,
          fix: 'Verify webhook signatures using HMAC-SHA256 with a shared secret. ' +
            'Use timing-safe comparison (crypto.timingSafeEqual). Most providers (Stripe, GitHub, Slack) send signatures.',
          via: 'scope_taint',
        });
      }
    }

    // Environment variables controlling security in non-debug code
    if (ENV_TRUST_RE.test(code)) {
      const isDebugGuarded = /\bNODE_ENV\s*(?:===?\s*['"](?:development|test)['"]|!==?\s*['"]production['"])\b/i.test(code);
      if (!isDebugGuarded) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (environment variable security bypass must be development-only)',
          severity: 'high',
          description: `Security bypass via environment variable at ${node.label} without dev/test guard. ` +
            `If an attacker can control environment variables (container escape, CI poisoning, .env leak), ` +
            `they can disable authentication or enable debug mode in production.`,
          fix: 'Guard security-sensitive environment checks with NODE_ENV/ENVIRONMENT checks. ' +
            'Better: remove bypass flags entirely in production builds. Use feature flags with proper auth instead.',
          via: 'scope_taint',
        });
      }
    }
  }
  return { cwe: 'CWE-360', name: 'Trust of System Event Data', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Channel Security & Deployment
// ---------------------------------------------------------------------------

/**
 * CWE-419: Unprotected Primary Channel
 * The app transmits sensitive data over its primary communication channel
 * (e.g., HTTP) without encryption. Detects INGRESS/EGRESS nodes handling
 * sensitive data without TLS/HTTPS enforcement.
 */
function verifyCWE419(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const channelNodes = map.nodes.filter(n =>
    (n.node_type === 'INGRESS' || n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('http') || n.node_subtype.includes('socket') ||
     n.node_subtype.includes('api') || n.node_subtype.includes('server') ||
     n.node_subtype.includes('endpoint') || n.node_subtype.includes('listener') ||
     /\b(createServer|http\.listen|app\.listen|express\(\)|new\s+Server|net\.createServer|WebSocket\b|ws:\/\/)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  const TLS_SAFE = /\b(https|tls|ssl|createSecureServer|secure:\s*true|forceSSL|requireHTTPS|redirect.*https|hsts|helmet|strictTransportSecurity|wss:\/\/|sslOptions|cert:|key:|pfx:)\b/i;
  const SENSITIVE_DATA = /\b(password|token|secret|credit.?card|ssn|auth|session|cookie|jwt|bearer|api.?key|private.?key)\b/i;

  for (const node of channelNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    // Only flag if (a) the channel handles sensitive data and (b) no TLS enforcement
    const handlesSensitive = SENSITIVE_DATA.test(code) ||
      node.data_in.some(d => d.sensitivity !== 'NONE') ||
      node.data_out.some(d => d.sensitivity !== 'NONE') ||
      node.attack_surface.includes('sensitive_data');
    if (handlesSensitive && !TLS_SAFE.test(code)) {
      // Check if ANY node in the map enforces TLS globally
      const globalTLS = map.nodes.some(n =>
        TLS_SAFE.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
        (n.node_type === 'CONTROL' || n.node_type === 'STRUCTURAL' || n.node_type === 'META'));
      if (!globalTLS) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (TLS/HTTPS enforcement on primary channel)',
          severity: 'high',
          description: `${node.label} handles sensitive data over an unprotected primary channel. ` +
            `No TLS/HTTPS enforcement detected — data transmitted in cleartext is interceptable.`,
          fix: 'Enforce HTTPS on all channels handling sensitive data. Use HSTS headers. ' +
            'Redirect HTTP to HTTPS. Node: https.createServer({key, cert}). ' +
            'Express: app.use(helmet.hsts()). Set Secure flag on cookies.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-419', name: 'Unprotected Primary Channel', holds: findings.length === 0, findings };
}

/**
 * CWE-420: Unprotected Alternate Channel
 * The app has a secondary channel (debug endpoint, admin API, monitoring port,
 * WebSocket, MQTT, etc.) that lacks the security controls of the primary channel.
 * Detects alternate communication interfaces without auth/encryption.
 */
function verifyCWE420(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ALT_CHANNEL = /\b(debug|admin|internal|monitor|health|metrics|status|diag|test|staging|dev|backdoor|management|actuator|console|profil|graphql|grpc|mqtt|amqp|redis\.subscribe|socket\.io|ws:\/\/|websocket|alternative.?port|secondary.?server)\b/i;
  const altChannelNodes = map.nodes.filter(n =>
    (n.node_type === 'INGRESS' || n.node_type === 'EXTERNAL') &&
    (ALT_CHANNEL.test(n.analysis_snapshot || n.code_snapshot) || ALT_CHANNEL.test(n.node_subtype) ||
     ALT_CHANNEL.test(n.label) || n.attack_surface.includes('debug') ||
     n.attack_surface.includes('internal') || n.attack_surface.includes('admin'))
  );
  const AUTH_SAFE = /\b(authenticate|authorize|requireAuth|isAuthenticated|passport|jwt\.verify|verifyToken|checkAuth|authMiddleware|basicAuth|session\.user|req\.user|isAdmin|requireRole|guard|middleware.*auth|auth.*middleware)\b/i;
  const TLS_SAFE = /\b(https|tls|ssl|wss:\/\/|secure:\s*true)\b/i;

  for (const alt of altChannelNodes) {
    const code = stripComments(alt.analysis_snapshot || alt.code_snapshot);
    const hasAuth = AUTH_SAFE.test(code);
    const hasTLS = TLS_SAFE.test(code);
    // Also check if any CONTROL/AUTH node directly protects this endpoint
    const isProtected = hasAuth || hasTLS || map.nodes.some(n =>
      (n.node_type === 'AUTH' || n.node_type === 'CONTROL') &&
      n.edges.some(e => e.target === alt.id) &&
      AUTH_SAFE.test(stripComments(n.analysis_snapshot || n.code_snapshot)));
    if (!isProtected) {
      findings.push({
        source: nodeRef(alt), sink: nodeRef(alt),
        missing: 'AUTH + CONTROL (authentication and encryption on alternate channel)',
        severity: 'high',
        description: `Alternate channel at ${alt.label} (${alt.node_subtype}) lacks security controls. ` +
          `If the primary channel enforces auth/TLS but this alternate channel does not, ` +
          `attackers can bypass protections by using this unguarded entry point.`,
        fix: 'Apply the same authentication and encryption to ALL channels. ' +
          'Disable debug/admin endpoints in production. Bind internal services to localhost. ' +
          'Apply auth middleware: app.use("/admin", requireAuth, adminRouter).',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-420', name: 'Unprotected Alternate Channel', holds: findings.length === 0, findings };
}

/**
 * CWE-421: Race Condition During Access to Alternate Channel
 * A timing window exists where the alternate channel is accessible before
 * security controls are fully initialized. Detects server startup patterns
 * where listen() happens before auth middleware is applied.
 */
function verifyCWE421(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Look for server startup nodes and auth setup nodes
  const LISTEN_PATTERN = /\b(\.listen\s*\(|createServer|server\.start|app\.start|http\.createServer|net\.createServer|bind\s*\(\s*\d+)\b/i;
  const AUTH_SETUP = /\b(app\.use.*auth|passport\.initialize|session\s*\(|jwt.*middleware|app\.use.*helmet|csrf|cors\(\))\b/i;
  const startupNodes = map.nodes.filter(n =>
    LISTEN_PATTERN.test(n.analysis_snapshot || n.code_snapshot) &&
    (n.node_type === 'EXTERNAL' || n.node_type === 'STRUCTURAL' || n.node_type === 'INGRESS'));
  const authSetupNodes = map.nodes.filter(n =>
    AUTH_SETUP.test(n.analysis_snapshot || n.code_snapshot) &&
    (n.node_type === 'CONTROL' || n.node_type === 'AUTH' || n.node_type === 'STRUCTURAL'));

  for (const startup of startupNodes) {
    const code = stripComments(startup.analysis_snapshot || startup.code_snapshot);
    // Check if auth setup appears after listen (ordering vulnerability)
    for (const auth of authSetupNodes) {
      if (auth.sequence > startup.sequence) {
        // Auth middleware registered AFTER server starts listening — race window
        findings.push({
          source: nodeRef(startup), sink: nodeRef(auth),
          missing: 'CONTROL (ensure security controls initialize BEFORE server accepts connections)',
          severity: 'medium',
          description: `Server at ${startup.label} starts listening (seq ${startup.sequence}) before ` +
            `auth setup at ${auth.label} (seq ${auth.sequence}). During this window, requests ` +
            `reach handlers without authentication — a race condition on the alternate channel.`,
          fix: 'Initialize all security middleware BEFORE calling listen(). ' +
            'Use app.use(authMiddleware) before app.listen(). ' +
            'In frameworks with lifecycle hooks, register guards in the setup phase.',
          via: 'structural',
        });
      }
    }
    // Also flag if listen() has no preceding auth setup at all
    if (authSetupNodes.length === 0 && startupNodes.length > 0) {
      // Check if the startup node itself mentions multiple ports/channels
      const multiChannel = /\b(port.*\|\||process\.env\.\w+PORT|alternate|secondary|:\s*\d{4,5}\b.*:\s*\d{4,5})\b/i;
      if (multiChannel.test(code)) {
        findings.push({
          source: nodeRef(startup), sink: nodeRef(startup),
          missing: 'CONTROL (auth initialization before multi-channel server startup)',
          severity: 'medium',
          description: `Multi-channel server at ${startup.label} starts without any auth setup. ` +
            `All channels are unprotected from the moment they begin accepting connections.`,
          fix: 'Register auth middleware before listen(). Apply to all server instances.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-421', name: 'Race Condition During Access to Alternate Channel', holds: findings.length === 0, findings };
}

/**
 * CWE-424: Improper Protection of Alternate Path
 * An alternative code path (fallback, error handler, default case, else branch)
 * bypasses the security controls applied to the main path.
 * Detects catch/error handlers, default routes, and fallback logic that skip auth.
 */
function verifyCWE424(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ALT_PATH = /\b(catch\s*\(|\.catch\s*\(|default\s*:|else\s*\{|fallback|onError|errorHandler|on\s*\(\s*['"]error|\.on\s*\(\s*['"]unhandledRejection|process\.on\s*\(\s*['"]uncaughtException|notFound|404|wildcard|\*\))/i;
  const AUTH_CHECK = /\b(authenticate|authorize|requireAuth|isAuthenticated|verifyToken|checkAuth|session\.user|req\.user|passport|jwt\.verify|guard|middleware.*auth)\b/i;
  const SENSITIVE_OP = /\b(delete|update|insert|exec|eval|write|send|redirect|render|res\.|response\.)\b/i;

  const altPathNodes = map.nodes.filter(n =>
    ALT_PATH.test(n.analysis_snapshot || n.code_snapshot) &&
    (n.node_type === 'CONTROL' || n.node_type === 'STRUCTURAL' || n.node_type === 'INGRESS'));

  for (const alt of altPathNodes) {
    const code = stripComments(alt.analysis_snapshot || alt.code_snapshot);
    // Check if the alternate path performs sensitive operations without auth
    if (SENSITIVE_OP.test(code) && !AUTH_CHECK.test(code)) {
      // Verify the main path (same scope) HAS auth — otherwise this is just CWE-306
      const parent = findContainingFunction(map, alt.id);
      if (parent) {
        const siblings = map.nodes.filter(n => {
          const np = findContainingFunction(map, n.id);
          return np === parent && n.id !== alt.id;
        });
        const mainPathHasAuth = siblings.some(s => AUTH_CHECK.test(stripComments(s.analysis_snapshot || s.code_snapshot)));
        if (mainPathHasAuth) {
          findings.push({
            source: nodeRef(alt), sink: nodeRef(alt),
            missing: 'AUTH (security controls on alternate code path)',
            severity: 'high',
            description: `Alternate path at ${alt.label} performs sensitive operations without the auth checks ` +
              `present on the main path. Attackers can trigger the fallback/error/default path to bypass security.`,
            fix: 'Apply authentication and authorization on ALL code paths, including error handlers, ' +
              'catch blocks, default cases, and fallback routes. Never assume only the happy path is reachable.',
            via: 'structural',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-424', name: 'Improper Protection of Alternate Path', holds: findings.length === 0, findings };
}

/**
 * CWE-425: Direct Request (Forced Browsing)
 * The app does not enforce access control consistently — some resources are
 * accessible via direct URL without going through the expected navigation flow.
 * Detects routes/static files serving sensitive content without auth middleware.
 */
function verifyCWE425(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SENSITIVE_ROUTE = /\b(admin|config|backup|\.env|internal|private|secret|upload|export|download|report|database|dump|log|debug|api\/v\d+\/users|manage|dashboard|settings|profile|account)\b/i;
  const STATIC_SERVE = /\b(express\.static|serveStatic|sendFile|res\.download|staticFiles|public\/|assets\/|uploads\/|files\/|media\/)\b/i;
  const AUTH_MIDDLEWARE = /\b(authenticate|authorize|requireAuth|isAuthenticated|authMiddleware|passport|guard|checkPermission|requireLogin|requireRole|ensureLoggedIn|isLoggedIn|jwt\.verify)\b/i;

  const routeNodes = map.nodes.filter(n =>
    n.node_type === 'INGRESS' &&
    (SENSITIVE_ROUTE.test(n.analysis_snapshot || n.code_snapshot) || SENSITIVE_ROUTE.test(n.label) ||
     SENSITIVE_ROUTE.test(n.node_subtype)));

  for (const route of routeNodes) {
    const code = stripComments(route.analysis_snapshot || route.code_snapshot);
    const hasAuth = AUTH_MIDDLEWARE.test(code);
    // Also check AUTH nodes with edges to this route
    const protectedByAuth = hasAuth || map.nodes.some(n =>
      (n.node_type === 'AUTH' || n.node_type === 'CONTROL') &&
      AUTH_MIDDLEWARE.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
      (n.edges.some(e => e.target === route.id) ||
       hasTaintedPathWithoutControl(map, n.id, route.id) === false));
    // Check if the route is behind auth middleware by examining whether
    // any auth node exists on paths from INGRESS to sensitive operations
    if (!protectedByAuth) {
      const sensitive = map.nodes.filter(n =>
        n.id !== route.id &&
        (n.node_type === 'STORAGE' || n.node_type === 'EGRESS') &&
        sharesFunctionScope(map, route.id, n.id));
      for (const sink of sensitive) {
        if (hasTaintedPathWithoutAuth(map, route.id, sink.id)) {
          findings.push({
            source: nodeRef(route), sink: nodeRef(sink),
            missing: 'AUTH (access control on directly requestable resource)',
            severity: 'high',
            description: `Sensitive route ${route.label} is accessible via direct request without authentication. ` +
              `Attacker can bypass intended navigation flow by requesting the URL directly (forced browsing).`,
            fix: 'Apply auth middleware to ALL sensitive routes, not just the navigation paths. ' +
              'Use router-level middleware: router.use(requireAuth). ' +
              'Never rely on client-side navigation as an access control mechanism.',
            via: 'bfs',
          });
          break; // one finding per route
        }
      }
    }
  }

  // Also check for static file serving of sensitive directories without auth
  const staticNodes = map.nodes.filter(n =>
    STATIC_SERVE.test(n.analysis_snapshot || n.code_snapshot) &&
    (n.node_type === 'STRUCTURAL' || n.node_type === 'INGRESS' || n.node_type === 'EXTERNAL'));
  for (const stat of staticNodes) {
    const code = stripComments(stat.analysis_snapshot || stat.code_snapshot);
    const servesUploads = /\b(uploads?|private|internal|backup|config|\.env)\b/i.test(code);
    if (servesUploads && !AUTH_MIDDLEWARE.test(code)) {
      findings.push({
        source: nodeRef(stat), sink: nodeRef(stat),
        missing: 'AUTH (access control on static file serving of sensitive directories)',
        severity: 'high',
        description: `Static file serving at ${stat.label} exposes sensitive directories (uploads/private/config) ` +
          `without authentication. Any user can directly browse to these files.`,
        fix: 'Do not serve sensitive directories as static files. Move them outside the web root. ' +
          'Serve files through authenticated route handlers with access checks.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-425', name: 'Direct Request (Forced Browsing)', holds: findings.length === 0, findings };
}

/**
 * CWE-430: Deployment of Wrong Handler
 * A handler/module is deployed for a purpose it was not designed for, or
 * a misconfigured route maps to the wrong handler. Detects handler mismatches
 * where the handler's logic doesn't match the route's expected behavior.
 */
function verifyCWE430(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Look for route definitions that map to handlers with mismatched intent
  const routeNodes = map.nodes.filter(n =>
    n.node_type === 'INGRESS' &&
    (n.node_subtype.includes('http') || n.node_subtype.includes('route') ||
     n.node_subtype.includes('handler') || n.node_subtype.includes('endpoint') ||
     /\b(app\.(get|post|put|delete|patch|all|use)|router\.(get|post|put|delete|patch|all)|@(Get|Post|Put|Delete|Patch|RequestMapping))\b/i.test(n.analysis_snapshot || n.code_snapshot)));
  // Detect method mismatches (e.g., GET route doing writes, DELETE route without delete logic)
  const WRITE_OPS = /\b(INSERT|UPDATE|DELETE|DROP|CREATE|save|write|put|remove|destroy|create|modify|append|truncate)\b/i;
  const READ_OPS = /\b(SELECT|find|read|get|fetch|query|list|search|lookup|load)\b/i;
  const GET_ROUTE = /\b(app\.get|router\.get|@Get|method:\s*['"]GET)/i;
  const DELETE_ROUTE = /\b(app\.delete|router\.delete|@Delete|method:\s*['"]DELETE)/i;

  for (const route of routeNodes) {
    const code = stripComments(route.analysis_snapshot || route.code_snapshot);
    // Find handler body — nodes connected via CALLS/CONTAINS
    const handlerNodes = map.nodes.filter(n =>
      n.id !== route.id && sharesFunctionScope(map, route.id, n.id));
    const handlerCode = stripComments(handlerNodes.map(n => n.analysis_snapshot || n.code_snapshot).join(' '));

    // GET route performing state-changing writes
    if (GET_ROUTE.test(code) && WRITE_OPS.test(handlerCode) && !READ_OPS.test(handlerCode)) {
      findings.push({
        source: nodeRef(route), sink: nodeRef(route),
        missing: 'STRUCTURAL (correct handler deployment — GET route should not perform writes)',
        severity: 'medium',
        description: `GET route at ${route.label} delegates to a handler that performs write operations. ` +
          `GET handlers should be idempotent and read-only. Wrong handler may be deployed.`,
        fix: 'Ensure the handler matches the HTTP method semantics. ' +
          'GET = read-only. POST/PUT = create/update. DELETE = removal. ' +
          'Review route-handler mappings for accidental misassignment.',
        via: 'scope_taint',
      });
    }

    // DELETE route with no delete logic (handler doesn't actually delete)
    if (DELETE_ROUTE.test(code) && !WRITE_OPS.test(handlerCode) && handlerNodes.length > 0) {
      findings.push({
        source: nodeRef(route), sink: nodeRef(route),
        missing: 'STRUCTURAL (correct handler deployment — DELETE route handler performs no deletion)',
        severity: 'medium',
        description: `DELETE route at ${route.label} maps to a handler with no delete/write operations. ` +
          `The wrong handler may be deployed, or the route definition is incorrect.`,
        fix: 'Verify the handler function matches the route intent. ' +
          'Check for copy-paste errors in route definitions.',
        via: 'scope_taint',
      });
    }
  }
  return { cwe: 'CWE-430', name: 'Deployment of Wrong Handler', holds: findings.length === 0, findings };
}

/**
 * CWE-431: Missing Handler
 * A required handler/error handler is not registered, leaving certain
 * conditions (errors, specific routes, signals) unhandled. Results in
 * default behavior that may expose information or crash the app.
 */
function verifyCWE431(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code defines the error handling mechanisms themselves
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-431', name: 'Missing Handler', holds: true, findings };
  }

  const allCode = map.nodes.map(n => stripComments(n.analysis_snapshot || n.code_snapshot)).join('\n');

  // Check 1: Express/Koa/Fastify without error handler (4-arg middleware or .setErrorHandler)
  const hasExpressLike = /\b(express\(\)|new\s+Koa|fastify\(\)|createApp|new\s+Hono)\b/i.test(allCode);
  const hasErrorHandler = /\b(err\s*,\s*req\s*,\s*res\s*,\s*next|error.*middleware|\.setErrorHandler|app\.onError|\.use\s*\(\s*(?:function\s*)?\(\s*(?:err|error)\s*,|@Catch|ExceptionFilter|exception_handler)\b/i.test(allCode);
  if (hasExpressLike && !hasErrorHandler) {
    const serverNode = map.nodes.find(n =>
      /\b(express\(\)|new\s+Koa|fastify\(\)|createApp)\b/i.test(n.analysis_snapshot || n.code_snapshot));
    if (serverNode) {
      findings.push({
        source: nodeRef(serverNode), sink: nodeRef(serverNode),
        missing: 'CONTROL (error handler middleware)',
        severity: 'medium',
        description: `Server at ${serverNode.label} has no error handler. Unhandled errors will trigger ` +
          `default framework behavior — typically exposing stack traces, crashing the process, or returning 500 with debug info.`,
        fix: 'Register an error-handling middleware: app.use((err, req, res, next) => { ... }). ' +
          'Log the error server-side; return a generic message to clients. ' +
          'In Express, this must be a 4-argument middleware registered LAST.',
        via: 'structural',
      });
    }
  }

  // Check 2: Promises/async without rejection handlers
  const hasPromises = /\b(new\s+Promise|async\s+function|async\s*\(|\.then\s*\()\b/i.test(allCode);
  const hasRejectionHandler = /\b(\.catch\s*\(|try\s*\{|process\.on\s*\(\s*['"]unhandledRejection|addEventListener.*unhandledrejection|window\.onerror)\b/i.test(allCode);
  if (hasPromises && !hasRejectionHandler) {
    const asyncNode = map.nodes.find(n =>
      /\b(new\s+Promise|\.then\s*\()\b/i.test(n.analysis_snapshot || n.code_snapshot) &&
      !/\.catch\s*\(/i.test(n.analysis_snapshot || n.code_snapshot));
    if (asyncNode) {
      findings.push({
        source: nodeRef(asyncNode), sink: nodeRef(asyncNode),
        missing: 'CONTROL (promise rejection / async error handler)',
        severity: 'medium',
        description: `Async code at ${asyncNode.label} has no rejection handler. ` +
          `Unhandled rejections crash Node.js (v15+) or silently swallow errors.`,
        fix: 'Add .catch() to all promise chains. Use try/catch with async/await. ' +
          'Register process.on("unhandledRejection") as a safety net.',
        via: 'structural',
      });
    }
  }

  // Check 3: Signal handlers missing (SIGTERM/SIGINT for graceful shutdown)
  const hasServer = /\b(\.listen\s*\(|createServer|server\.start)\b/i.test(allCode);
  const hasSignalHandler = /\b(process\.on\s*\(\s*['"]SIG(TERM|INT)|signal\.signal\s*\(|Runtime\.getRuntime\(\)\.addShutdownHook|atexit)\b/i.test(allCode);
  if (hasServer && !hasSignalHandler) {
    const listenNode = map.nodes.find(n =>
      /\b(\.listen\s*\(|createServer)\b/i.test(n.analysis_snapshot || n.code_snapshot));
    if (listenNode) {
      findings.push({
        source: nodeRef(listenNode), sink: nodeRef(listenNode),
        missing: 'CONTROL (signal handler for graceful shutdown)',
        severity: 'low',
        description: `Server at ${listenNode.label} has no SIGTERM/SIGINT handler. ` +
          `Abrupt termination can leave connections dangling, data uncommitted, or resources leaked.`,
        fix: 'Register signal handlers: process.on("SIGTERM", () => server.close(...)). ' +
          'Drain connections, flush logs, and close DB connections before exit.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-431', name: 'Missing Handler', holds: findings.length === 0, findings };
}

/**
 * CWE-432: Dangerous Signal Handler not Disabled During Sensitive Operations
 * Signal handlers that perform non-reentrant operations (malloc, logging, DB writes)
 * remain active during sensitive critical sections. In JS/Python this manifests as
 * process event handlers that mutate shared state during async operations.
 */
function verifyCWE432(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SIGNAL_HANDLER = /\b(process\.on\s*\(\s*['"]SIG|signal\.signal\s*\(|sigaction|signal\s*\(\s*SIG|Runtime\..*ShutdownHook|atexit\.register)\b/i;
  const DANGEROUS_IN_HANDLER = /\b(write|log|console\.|printf|fprintf|malloc|realloc|free|fopen|fclose|exit|abort|throw|reject|db\.|query\(|save\(|insert\(|update\(|delete\(|fs\.|readFile|writeFile|lock|mutex|acquire|release)\b/i;

  const signalNodes = map.nodes.filter(n =>
    SIGNAL_HANDLER.test(n.analysis_snapshot || n.code_snapshot));

  for (const sig of signalNodes) {
    const code = stripComments(sig.analysis_snapshot || sig.code_snapshot);
    if (DANGEROUS_IN_HANDLER.test(code)) {
      // Check if the signal handler is disabled during critical sections
      const hasGuard = /\b(signal\.signal\s*\(\s*SIG\w+\s*,\s*SIG_IGN|blocked_signals|sigprocmask|process\.removeListener|process\.off|mutex|lock|critical_section|semaphore)\b/i.test(
        map.nodes.map(n => n.analysis_snapshot || n.code_snapshot).join(' '));
      if (!hasGuard) {
        findings.push({
          source: nodeRef(sig), sink: nodeRef(sig),
          missing: 'CONTROL (disable or guard signal handler during sensitive operations)',
          severity: 'medium',
          description: `Signal handler at ${sig.label} performs non-reentrant operations (I/O, memory allocation, DB). ` +
            `If a signal fires during a critical section, reentrancy can corrupt data, deadlock, or crash.`,
          fix: 'Use only async-signal-safe functions in signal handlers (set a flag, then handle in main loop). ' +
            'Block signals during critical sections. In Node.js, keep signal handlers minimal — ' +
            'set a flag and let the event loop handle cleanup.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-432', name: 'Dangerous Signal Handler not Disabled During Sensitive Operations', holds: findings.length === 0, findings };
}

/**
 * CWE-433: Unparsed Raw Web Content Delivery
 * The application delivers raw web content (HTML, XML, JSON) without proper
 * content-type headers or parsing, allowing browser misinterpretation.
 * Detects responses that send user-influenced content without Content-Type
 * and X-Content-Type-Options: nosniff.
 */
function verifyCWE433(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress433 = nodesOfType(map, 'INGRESS');
  const egressNodes = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('response') || n.node_subtype.includes('http') ||
     n.node_subtype.includes('render') || n.node_subtype.includes('send') ||
     /\b(res\.send|res\.write|res\.end|response\.write|response\.send|HttpResponse|send_response|echo|print|write\s*\()\b/i.test(n.analysis_snapshot || n.code_snapshot)));
  const CONTENT_TYPE_SET = /\b(content-?type|setHeader.*content|res\.type|response\.headers|Content-Type|application\/json|text\/html|text\/plain)\b/i;
  const NOSNIFF = /\b(nosniff|X-Content-Type-Options|helmet|contentTypeOptions)\b/i;

  for (const src of ingress433) {
    for (const sink of egressNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const hasCT = CONTENT_TYPE_SET.test(sinkCode);
        const hasNoSniff = NOSNIFF.test(sinkCode) || map.nodes.some(n =>
          NOSNIFF.test(stripComments(n.analysis_snapshot || n.code_snapshot)) &&
          (n.node_type === 'CONTROL' || n.node_type === 'STRUCTURAL'));
        if (!hasCT || !hasNoSniff) {
          const mp: string[] = [];
          if (!hasCT) mp.push('Content-Type header');
          if (!hasNoSniff) mp.push('X-Content-Type-Options: nosniff');
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: `CONTROL (${mp.join(' + ')})`,
            severity: 'medium',
            description: `User input from ${src.label} reaches response at ${sink.label} without ${mp.join(' or ')}. ` +
              `Browsers may MIME-sniff the content and interpret it as HTML/script, enabling XSS.`,
            fix: 'Always set an explicit Content-Type header. Add X-Content-Type-Options: nosniff. ' +
              'Use res.json() for JSON, res.type("text/plain") for text. ' +
              'Use helmet middleware: app.use(helmet.noSniff()).',
            via: 'bfs',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-433', name: 'Unparsed Raw Web Content Delivery', holds: findings.length === 0, findings };
}

/**
 * CWE-439: Behavioral Change in New Version or Environment
 * The application relies on behavior that differs between environments, versions,
 * or configurations without explicit checks. Detects environment-dependent code
 * that lacks explicit version/environment guards.
 */
function verifyCWE439(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // Detect environment-dependent code patterns
  const ENV_DEPENDENT = /\b(process\.env\.NODE_ENV|NODE_ENV|RAILS_ENV|FLASK_ENV|DJANGO_SETTINGS_MODULE|__DEV__|process\.env\.DEBUG|DEBUG\s*=|development|production|staging)\b/i;
  const SECURITY_DISABLED_IN_DEV = /\b(if\s*\(\s*(?:process\.env\.)?(?:NODE_ENV|env)\s*[!=]==?\s*['"](?:development|dev|test)['"]|disable.*(?:csrf|cors|auth|ssl|tls|security|validation)|skip.*(?:auth|validation|csrf)|(?:csrf|cors|auth|ssl|security|validation).*(?:false|disable|skip|off))\b/i;
  const VERSION_DEPENDENT = /\b(parseInt\s*\(\s*process\.version|node.*version|semver|engines|>=?\s*\d+\.\d+|require\s*\(\s*['"](?:child_process|cluster|worker_threads)['"])\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Pattern 1: Security controls conditionally disabled based on environment
    if (SECURITY_DISABLED_IN_DEV.test(code)) {
      const envGuarded = /\b(if\s*\(\s*(?:process\.env\.)?NODE_ENV\s*===?\s*['"]production['"]\s*\))\b/i.test(code);
      if (!envGuarded) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (environment-independent security — do not disable controls in dev/test)',
          severity: 'medium',
          description: `Security control at ${node.label} is conditionally disabled based on environment. ` +
            `If NODE_ENV is misconfigured or unset in production, security controls may be skipped.`,
          fix: 'Never disable security controls based on environment variables. ' +
            'If dev convenience is needed, use explicit feature flags with safe defaults. ' +
            'Default to production security: if (env !== "production") warn, but still enforce.',
          via: 'structural',
        });
      }
    }

    // Pattern 2: Reliance on API/behavior that differs across versions without checks
    if (VERSION_DEPENDENT.test(code) && ENV_DEPENDENT.test(code)) {
      const hasExplicitCheck = /\b(semver\.satisfies|parseInt\s*\(.*version.*\)\s*>=|process\.version\s*[><=]|engines.*node)\b/i.test(code);
      if (!hasExplicitCheck) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (explicit version/environment check)',
          severity: 'low',
          description: `Code at ${node.label} depends on environment and version-specific behavior ` +
            `without explicit compatibility checks. Behavioral changes across versions may introduce vulnerabilities.`,
          fix: 'Add explicit version checks for version-dependent features. ' +
            'Use engines field in package.json. Test across supported versions in CI. ' +
            'Document minimum version requirements.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-439', name: 'Behavioral Change in New Version or Environment', holds: findings.length === 0, findings };
}

/**
 * CWE-440: Expected Behavior Violation
 * A feature/API does not perform according to its specification. Detects: validator
 * functions that never reject, delete functions that don't delete, and security-
 * critical operations that swallow errors silently.
 */
function verifyCWE440(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library code defines validation primitives — they may delegate rejection to callers
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-440', name: 'Expected Behavior Violation', holds: true, findings };
  }

  const VALIDATOR_NAME_RE440 = /\b(validate|verify|check|assert|ensure|require|must|guard)\w*/i;
  const REJECTS_RE440 = /\bthrow\b|\breject\b|\breturn\s+false\b|\breturn\s+null\b|\bres\.status\s*\(\s*4\d{2}\b|\bnew\s+Error\b|\bfail\b|\babort\b/;
  const DELETE_NAME_RE440 = /\b(delete|remove|destroy|purge|erase|drop)\w*/i;
  const DELETE_ACTION_RE440 = /\b(DELETE\b|\.delete\s*\(|\.remove\s*\(|\.destroy\s*\(|\.drop\s*\(|unlink\s*\(|rm\s*\(|\.splice\s*\(|\.pop\s*\()/i;
  const CATCH_SWALLOW_RE440 = /\.catch\s*\(\s*(?:\(\s*\w*\s*\))?\s*=>\s*\{?\s*\}?\s*\)|catch\s*\(\s*\w*\s*\)\s*\{\s*\}/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const label = node.label.toLowerCase();

    if ((VALIDATOR_NAME_RE440.test(label) || VALIDATOR_NAME_RE440.test(code.slice(0, 80))) &&
        !REJECTS_RE440.test(code) && code.length > 30 &&
        /\bfunction\b|\b=>\b|\basync\b/.test(code.slice(0, 100))) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validation function must have a rejection path)',
        severity: 'medium',
        description: `Function at ${node.label} has a validation-indicating name but no rejection path. ` +
          `Callers expect it to reject bad input, but it silently accepts everything.`,
        fix: 'Ensure validation functions throw, return false, or set an error status for invalid input. ' +
          'A validator that always succeeds is worse than no validator — it creates false confidence.',
        via: 'structural',
      });
    }

    if ((DELETE_NAME_RE440.test(label) || DELETE_NAME_RE440.test(code.slice(0, 80))) &&
        !DELETE_ACTION_RE440.test(code) && code.length > 30 &&
        /\bfunction\b|\b=>\b|\basync\b/.test(code.slice(0, 100))) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STORAGE (delete function must actually perform deletion)',
        severity: 'medium',
        description: `Function at ${node.label} is named as a deletion operation but performs no delete action. ` +
          `Data the caller expects to be destroyed may persist, violating data retention policies.`,
        fix: 'Ensure delete/remove functions perform the actual deletion or name soft-delete clearly (archiveX).',
        via: 'structural',
      });
    }

    if (CATCH_SWALLOW_RE440.test(code) &&
        /\b(auth|login|password|token|session|permission|encrypt|decrypt|sign|verify|validate)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (error handling for security-critical operations)',
        severity: 'high',
        description: `Security-critical operation at ${node.label} swallows errors silently. ` +
          `A failed auth/encryption/validation is indistinguishable from success.`,
        fix: 'Never swallow errors in security-critical code. Log and propagate failure. ' +
          'For auth/crypto operations, a swallowed error means the security check is bypassed.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-440', name: 'Expected Behavior Violation', holds: findings.length === 0, findings };
}

/**
 * CWE-441: Unintended Proxy or Intermediary (Confused Deputy)
 * A server-side component is tricked into making requests on behalf of an attacker.
 * The generalization of SSRF -- a trusted intermediary performs actions using
 * attacker-supplied parameters, leveraging the server's trust relationships.
 */
function verifyCWE441(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PROXY_RE441 = /\b(proxy|forward|relay|redirect|pipe|fetch|axios|request|http\.get|http\.request|got|node-fetch|urllib|httpClient|RestTemplate|WebClient)\b/i;
  const HEADER_FORWARD_RE441 = /req\.headers|request\.headers|ctx\.headers|getHeader|getAllHeaders/i;
  const AUTH_HEADER_RE441 = /\b(authorization|cookie|x-api-key|x-auth-token|bearer|session[_-]?id)\b/i;
  const SAFE_DEPUTY_RE441 = /\ballowlist\b|\bwhitelist\b|\ballowed[_-]?hosts\b|\ballowed[_-]?urls\b|\bvalidate[_-]?(?:url|host|target)\b|\bURL\.parse\b.*\bhostname\b/i;

  const ingress441 = nodesOfType(map, 'INGRESS');
  const externalSinks441 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS') &&
    (PROXY_RE441.test(n.analysis_snapshot || n.code_snapshot) || n.node_subtype.includes('http') ||
     n.node_subtype.includes('api') || n.node_subtype.includes('proxy'))
  );

  for (const src of ingress441) {
    for (const sink of externalSinks441) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const combined = stripComments(src.analysis_snapshot || src.code_snapshot + ' ' + sink.code_snapshot);
        if (!SAFE_DEPUTY_RE441.test(combined)) {
          const controlsDest = /\b(url|host|target|endpoint|destination|path|href)\b/i.test(src.analysis_snapshot || src.code_snapshot);
          const forwardsHeaders = HEADER_FORWARD_RE441.test(combined) && AUTH_HEADER_RE441.test(combined);
          if (controlsDest || forwardsHeaders || PROXY_RE441.test(combined)) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(sink),
              missing: 'CONTROL (request validation -- allowlist targets, strip forwarded auth)',
              severity: 'high',
              description: `User input at ${src.label} influences server-side request at ${sink.label}. ` +
                (forwardsHeaders ? 'Auth headers forwarded to internal service -- attacker uses server as confused deputy. ' :
                'Server acts as confused deputy, making requests the attacker cannot make directly. ') +
                'Attacker leverages the server\'s trust relationships and network position.',
              fix: 'Validate and allowlist target URLs/hosts. Strip auth headers when forwarding. ' +
                'Use separate credentials for internal service calls -- never forward user-supplied auth tokens.',
              via: 'bfs',
            });
          }
        }
      }
    }
  }
  return { cwe: 'CWE-441', name: 'Unintended Proxy or Intermediary (Confused Deputy)', holds: findings.length === 0, findings };
}

/**
 * CWE-444: Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)
 * When a proxy and backend disagree on where one HTTP request ends and the next begins,
 * an attacker can smuggle a second request inside the first. Bypasses ALL frontend
 * security (WAF, auth, rate limiting). Root causes: Transfer-Encoding vs Content-Length
 * disagreement, malformed TE headers, HTTP/1.1 connection reuse through proxies.
 */
function verifyCWE444(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const RAW_HTTP_RE444 = /\b(writeHead|setHeader|write|end)\b.*\b(Transfer-Encoding|Content-Length)\b|\b(Transfer-Encoding|Content-Length)\b.*\b(writeHead|setHeader|write|end)\b/i;
  const BOTH_HEADERS_RE444 = /Transfer-Encoding[\s\S]{0,200}Content-Length|Content-Length[\s\S]{0,200}Transfer-Encoding/i;
  const PROXY_PATTERN_RE444 = /\b(createProxyServer|httpProxy|http-proxy|http-proxy-middleware|proxy_pass|ProxyPass|createProxy|setupProxy)\b/i;
  const RAW_SOCKET_RE444 = /\b(net\.connect|net\.createConnection|tls\.connect|socket\.write|new\s+Socket|raw.*socket)\b/i;
  const HTTP_STRING_RE444 = /['"`](?:HTTP\/1\.[01]|GET |POST |PUT |DELETE |HEAD |OPTIONS |PATCH ).*\\r\\n/i;
  const NORMALIZE_RE444 = /\b(normalize|sanitize|strip).*(?:header|transfer.encoding|content.length)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (BOTH_HEADERS_RE444.test(code)) {
      // Don't flag code that is REMOVING headers (removeHeader, delete, unset) —
      // this is protective code (e.g., Express stripping TE for 204/304 responses)
      const isRemovingHeaders = /\b(removeHeader|deleteHeader|unset|remove)\s*\(\s*['"](?:Transfer-Encoding|Content-Length)['"]/i.test(code);
      // Don't flag library/framework code that defines HTTP handling primitives
      if (!isRemovingHeaders && !isLibraryCode(map)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (consistent HTTP framing -- use only one of Transfer-Encoding or Content-Length)',
          severity: 'critical',
          description: `Both Transfer-Encoding and Content-Length headers present at ${node.label}. ` +
            `This is the exact condition for HTTP request smuggling (CL.TE or TE.CL). ` +
            `A frontend proxy uses one while the backend uses the other, allowing request smuggling.`,
          fix: 'Never set both Transfer-Encoding and Content-Length. Use a well-tested HTTP library. ' +
            'If proxying, normalize these headers. Prefer HTTP/2 end-to-end.',
          via: 'structural',
        });
      }
    }

    if (RAW_SOCKET_RE444.test(code) && HTTP_STRING_RE444.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use HTTP library instead of raw socket for HTTP framing)',
        severity: 'high',
        description: `Raw socket HTTP construction at ${node.label}. Manual HTTP framing is extremely ` +
          `prone to smuggling -- any RFC 7230 deviation creates a proxy/backend interpretation gap.`,
        fix: 'Use a proper HTTP client library (axios, node-fetch, urllib3) instead of raw sockets.',
        via: 'structural',
      });
    }

    if (PROXY_PATTERN_RE444.test(code) && !NORMALIZE_RE444.test(code)) {
      const userControlled = /\b(req\.|request\.|params\.|query\.|body\.)\b/i.test(code);
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (HTTP request normalization in proxy layer)',
        severity: userControlled ? 'critical' : 'high',
        description: `Proxy at ${node.label} does not normalize HTTP requests. ` +
          `Malformed Transfer-Encoding headers pass through to the backend, which may ` +
          `interpret them differently than the proxy.` +
          (userControlled ? ' User input influences proxy routing, increasing exploitability.' : ''),
        fix: 'Normalize requests in proxy: reject ambiguous Transfer-Encoding, strip duplicate Content-Length. ' +
          'Use HTTP/2 between proxy and backend. Consider disabling keep-alive as defense-in-depth.',
        via: 'structural',
      });
    }

    if (RAW_HTTP_RE444.test(code) && /\b(req\.|request\.|params\.|query\.|body\.|headers\[)/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (reject user-influenced Transfer-Encoding/Content-Length)',
        severity: 'critical',
        description: `User input influences HTTP framing headers at ${node.label}. ` +
          `Attacker-controlled TE/CL values enable smuggling that bypasses all frontend security.`,
        fix: 'Never allow user input to influence Transfer-Encoding or Content-Length. ' +
          'Let the HTTP framework calculate Content-Length automatically. Rewrite headers when proxying.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-444', name: 'Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)', holds: findings.length === 0, findings };
}

/**
 * CWE-446: UI Discrepancy for Security Feature
 * The UI indicates a security feature is active but the implementation doesn't match.
 * Lock icon on HTTP, "encrypted" label on unencrypted storage, "verified" badge
 * on unchecked identity.
 */
function verifyCWE446(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SEC_IND_RE446 = /\b(lock|secure|encrypted|verified|authenticated|protected|trusted|safe|signed)\b/i;
  const UI_DISP_RE446 = /\b(innerHTML|textContent|innerText|\.text\s*=|\.html\s*\(|render|display|badge|icon|label|tooltip|status[_-]?text|indicator)\b/i;
  const BACKING_RE446 = /\bhttps\b|\bssl\b|\btls\b|\bprotocol\s*===?\s*['"]https['"]|\b(encrypt|aes|rsa|cipher|createCipher|crypto\.subtle)\b|\b(verify|jwt\.verify|crypto\.verify|validateSignature)\b|\b(isAuthenticated|isLoggedIn|session\.user|req\.user|auth\.check)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (SEC_IND_RE446.test(code) && UI_DISP_RE446.test(code)) {
      const hasBackingCheck = BACKING_RE446.test(code);
      const isHardcoded = /['"`].*(?:secure|verified|encrypted|protected).*['"`]/i.test(code) &&
        !(/\bif\b.*\?\s*['"].*(?:secure|lock)/i.test(code));
      if (!hasBackingCheck || isHardcoded) {
        const indicator = code.match(SEC_IND_RE446)?.[0] || 'security';
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (verify security state before displaying security indicator)',
          severity: 'medium',
          description: `UI at ${node.label} displays "${indicator}" indicator without verifying actual security state. ` +
            (isHardcoded ? 'The indicator appears hardcoded. ' : '') +
            'Users rely on security indicators to make trust decisions; a false indicator is actively dangerous.',
          fix: 'Derive security indicators from actual state checks. Never hardcode security indicators.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-446', name: 'UI Discrepancy for Security Feature', holds: findings.length === 0, findings };
}

/**
 * CWE-449: The UI Performs the Wrong Action
 * The UI action does not correspond to what the user intended. Forms with dynamic
 * action attributes, onclick handlers navigating to unexpected targets, and buttons
 * wired to different actions than their labels suggest.
 */
function verifyCWE449(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const DYN_ACTION_RE449 = /\baction\s*[:=]\s*(?:\$\{|`.*\$|req\.|request\.|params\.|query\.|body\.|location\.|document\.)/i;
  const REDIR_HANDLER_RE449 = /\b(onclick|onsubmit|addEventListener)\b.*\b(window\.location|location\.href|window\.open|document\.location|navigate)\b/i;
  const DANGER_ACT_RE449 = /\b(delete|remove|destroy|purge|drop|transfer|send|pay|submit|authorize|approve|grant)\b/i;
  const SAFE_LBL_RE449 = /\b(cancel|close|dismiss|back|view|preview|details|info)\b/i;
  const CSRF_RE449 = /\bcsrf\b|\b_token\b|\bcsrfmiddlewaretoken\b|\bx-csrf-token\b|\banti-forgery\b/i;
  const CONFIRM_RE449 = /\bconfirm\s*\(|\bwindow\.confirm\b|\bprompt\s*\(|\bconfirmation\b|\bare\s*you\s*sure\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (DYN_ACTION_RE449.test(code) && !CSRF_RE449.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (static or validated form action + CSRF token)',
        severity: 'high',
        description: `Form at ${node.label} has a dynamically constructed action URL. ` +
          `An attacker who controls the action attribute redirects form submission to their server.`,
        fix: 'Use static form action URLs. Validate dynamic actions against an allowlist. ' +
          'Include CSRF tokens. Use CSP form-action directive to restrict submission targets.',
        via: 'structural',
      });
    }

    if (REDIR_HANDLER_RE449.test(code) &&
        /\b(query|param|hash|search|location\.search|location\.hash|document\.referrer)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate redirect target in UI event handler)',
        severity: 'high',
        description: `UI event handler at ${node.label} redirects to a user-influenced URL. ` +
          `A button or link can be manipulated to navigate the user to a malicious page.`,
        fix: 'Validate redirect targets against an allowlist. Use relative URLs where possible.',
        via: 'structural',
      });
    }

    if (SAFE_LBL_RE449.test(code) && DANGER_ACT_RE449.test(code) && !CONFIRM_RE449.test(code) &&
        /\b(button|btn|link|anchor|<a|<button|onClick|click)\b/i.test(code)) {
      const safeLabel = code.match(SAFE_LBL_RE449)?.[0];
      const dangerAction = code.match(DANGER_ACT_RE449)?.[0];
      if (safeLabel && dangerAction) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (UI label must match action + confirmation for destructive ops)',
          severity: 'medium',
          description: `UI element at ${node.label} labeled "${safeLabel}" but performs "${dangerAction}" action.`,
          fix: 'Ensure labels match actions. Add confirmation dialogs for destructive operations.',
          via: 'structural',
        });
      }
    }
  }
  return { cwe: 'CWE-449', name: 'The UI Performs the Wrong Action', holds: findings.length === 0, findings };
}

/**
 * CWE-450: Multiple Interpretations of UI Input
 * Same user input interpreted differently by different components. Locale-dependent
 * parsing ("1.000" = 1 in US, 1000 in Germany) and Unicode normalization differences.
 */
function verifyCWE450(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PARSE_NUM_RE450 = /\b(parseFloat|parseInt|Number\(|\.toFixed|new\s+Intl\.NumberFormat)\b/;
  const LOCALE_RE450 = /\blocale\b|\bIntl\.\w+\s*\(\s*['"][a-z]{2}(-[A-Z]{2})?['"]/i;
  const UNICODE_NORM_RE450 = /\b(normalize|NFC|NFD|NFKC|NFKD|\.normalize\s*\()\b/;
  const UNICODE_CMP_RE450 = /===?\s*['"][^'"]*[^\x00-\x7F]|['"][^'"]*[^\x00-\x7F].*===?/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (PARSE_NUM_RE450.test(code) && !LOCALE_RE450.test(code)) {
      const isFinancial = /\b(price|amount|total|balance|credit|debit|cost|fee|payment|rate|tax|currency)\b/i.test(code);
      const isPermission = /\b(permission|mask|mode|flag|level|priority|weight|score|threshold|limit)\b/i.test(code);
      if (isFinancial || isPermission) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (explicit locale for numeric parsing in security/financial context)',
          severity: isFinancial ? 'high' : 'medium',
          description: `Locale-dependent number parsing at ${node.label} in a ${isFinancial ? 'financial' : 'security'} context. ` +
            '"1,000.50" means 1000.50 in en-US but approximately 1.0005 in de-DE. ' +
            (isFinancial ? 'Financial calculations can be off by orders of magnitude.' :
            'Permission thresholds can be misinterpreted, granting unintended access.'),
          fix: 'Specify locale explicitly. Use canonical numeric format at the API boundary. Validate ranges.',
          via: 'structural',
        });
      }
    }

    if (UNICODE_CMP_RE450.test(code) && !UNICODE_NORM_RE450.test(code) &&
        /\b(user|name|email|role|permission|identity|credential)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (Unicode normalization before security-relevant string comparison)',
        severity: 'medium',
        description: `Unicode string comparison at ${node.label} without normalization. ` +
          'Same visual character can have multiple representations -- attacker registers visually identical username.',
        fix: 'Apply String.prototype.normalize("NFC") before comparing. Use NFKC for identifiers.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-450', name: 'Multiple Interpretations of UI Input', holds: findings.length === 0, findings };
}

/**
 * CWE-451: UI Misrepresentation of Critical Information
 * UI displays information that misleads the user. URL bar spoofing, truncated
 * filenames hiding extensions, user-controlled content rendered as system UI.
 */
function verifyCWE451(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const RENDER_TR_RE451 = /\b(innerHTML|dangerouslySetInnerHTML|v-html|ng-bind-html|\[innerHTML\]|\.html\s*\()\b/i;
  const SYS_UI_RE451 = /\b(dialog|modal|alert|notification|toast|banner|header|toolbar|navigation|status[_-]?bar|title[_-]?bar|breadcrumb)\b/i;
  const URL_DISP_RE451 = /\b(href|src|url|link|location)\b.*\b(textContent|innerText|innerHTML|\.text\s*=|title|alt|tooltip)\b/i;
  const URL_TRUNC_RE451 = /\.slice\s*\(|\.substring\s*\(|\.substr\s*\(|\.truncate\s*\(|\.ellipsis\b|text-overflow:\s*ellipsis|overflow:\s*hidden/i;
  const FN_RE451 = /\b(filename|file[_-]?name|name|basename|originalname|original[_-]?name)\b/i;
  const HIDE_EXT_RE451 = /\.replace\s*\(\s*\/\\.\w+\$\/|\.split\s*\(\s*['"]\.['"].*\[0\]|path\.parse.*\.name\b|\.slice\s*\(\s*0\s*,\s*[^)]*\.lastIndexOf\s*\(\s*['"]\.['"].*\)/i;
  const SANITIZE_RE451 = /\bDOMPurify\b|\bsanitize\s*\(|\bsanitizeHtml\b|\bxss\s*\(|\bescape[_-]?html\b|\btextContent\s*=/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (RENDER_TR_RE451.test(code) && SYS_UI_RE451.test(code) && !SANITIZE_RE451.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (sanitize user content before rendering in trusted UI context)',
        severity: 'high',
        description: `User-controlled HTML in system UI context at ${node.label}. ` +
          'Attacker injects content impersonating system dialogs, tricking users into entering credentials.',
        fix: 'Use textContent instead of innerHTML. If HTML needed, sanitize with DOMPurify.',
        via: 'structural',
      });
    }

    if (URL_DISP_RE451.test(code) && URL_TRUNC_RE451.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (display full URL or at minimum the full domain)',
        severity: 'medium',
        description: `URL display truncated at ${node.label}. ` +
          'Subdomain spoofing: "https://legitimate-bank.com.evil.com/..." truncated to "https://legitimate-bank.com..."',
        fix: 'Always display the full domain. If truncating, truncate the path, never the domain.',
        via: 'structural',
      });
    }

    if (FN_RE451.test(code) && HIDE_EXT_RE451.test(code) &&
        /\b(download|attachment|save|open|execute|run)\b/i.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (display full filename including extension)',
        severity: 'high',
        description: `Filename without extension at ${node.label} in download context. ` +
          '"report.pdf.exe" displayed as "report.pdf" tricks users into executing malware.',
        fix: 'Always display full filename with all extensions. Warn on multiple extensions.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-451', name: 'UI Misrepresentation of Critical Information', holds: findings.length === 0, findings };
}

/**
 * CWE-453: Insecure Default Variable Initialization
 * Variables initialized to insecure defaults that grant access or disable protections.
 * Different from CWE-456 (missing init) -- here the variable IS initialized, but to
 * a dangerous value (isAdmin=true, secure=false, permissions=0777).
 */
function verifyCWE453(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PERM_BOOL_RE453 = /\b(isAdmin|is[_-]?admin|isAuthenticated|is[_-]?authenticated|isAuthorized|is[_-]?authorized|isValid|is[_-]?valid|isVerified|is[_-]?verified|hasPermission|has[_-]?permission|isEnabled|isTrusted|is[_-]?trusted|canAccess|allowAll)\s*(?:[:=])\s*true\b/;
  const PERM_FILE_RE453 = /\b(?:0o?)?(?:777|776|766|666|775|755)\b|\bchmod\s*\(\s*[^,]+,\s*(?:0o?)?(?:777|776|766|666)\b/;
  const INSEC_DEF_RE453 = /\b(secure|httpOnly|sameSite|csrf|xss[_-]?protection|frameguard|hsts|cors[_-]?enabled|ssl[_-]?verify|tls[_-]?verify|verify[_-]?ssl|check[_-]?certificate)\s*(?:[:=])\s*(?:false|0|null|undefined|['"]none['"]|['"]off['"]|['"]disabled['"])\b/i;
  const RATE_LIM_RE453 = /\b(rate[_-]?limit|max[_-]?requests|max[_-]?attempts|throttle|limit)\s*(?:[:=])\s*(?:(?:Infinity|Number\.MAX|9{4,})|0|false|null)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    const boolMatch = code.match(PERM_BOOL_RE453);
    if (boolMatch) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (default security booleans to restrictive -- false)',
        severity: 'high',
        description: `Security flag "${boolMatch[1]}" defaults to true at ${node.label}. ` +
          'If check fails silently, the default grants access. Flags must default to deny.',
        fix: 'Default all security booleans to false/deny. Only set true after explicit verification.',
        via: 'structural',
      });
    }

    const configMatch = code.match(INSEC_DEF_RE453);
    if (configMatch) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (default security configurations to restrictive values)',
        severity: 'high',
        description: `Security config "${configMatch[1]}" defaults to insecure at ${node.label}. ` +
          'Production deployments inheriting defaults will be silently vulnerable.',
        fix: 'Default to most restrictive. Require explicit opt-out for insecure settings with logging.',
        via: 'structural',
      });
    }

    if (PERM_FILE_RE453.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (restrictive default file permissions -- 0600/0640)',
        severity: 'medium',
        description: `Permissive file permissions at ${node.label}. ` +
          'World-readable/writable permissions allow any local user to read or modify files.',
        fix: 'Use 0600 for secrets, 0640 for config, 0750 for directories.',
        via: 'structural',
      });
    }

    const rateMatch = code.match(RATE_LIM_RE453);
    if (rateMatch) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (sensible default rate limits)',
        severity: 'medium',
        description: `Rate limiting "${rateMatch[1]}" defaults to unlimited at ${node.label}.`,
        fix: 'Set reasonable defaults: 5-10 auth attempts/min, 100-1000 API requests/min.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-453', name: 'Insecure Default Variable Initialization', holds: findings.length === 0, findings };
}

/**
 * CWE-454: External Initialization of Trusted Variables or Data Stores
 * Security-critical variables initialized from external/untrusted sources (env vars,
 * URL params, HTTP headers) without validation, then used in trust decisions.
 */
function verifyCWE454(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ENV_RE454 = /\bprocess\.env\.\w+|\bos\.environ\b|\bSystem\.getenv\b|\bENV\[|\b\$_ENV\[|\bgetenv\s*\(/i;
  const URL_RE454 = /\b(query\.|params\.|searchParams|location\.search|location\.hash|req\.query|request\.query|URLSearchParams)\b/i;
  const HDR_RE454 = /\b(req\.headers|request\.headers|getHeader)\b.*\b(x-[a-z]|X-[A-Z])/i;
  const TRUST_RE454 = /\b(isAdmin|is[_-]?admin|role|permission|access[_-]?level|trust[_-]?level|debug|isDebug|is[_-]?debug|NODE_ENV|admin|superuser|bypass|skip[_-]?auth|disable[_-]?security|maintenance[_-]?mode)\b/i;
  const VALID_RE454 = /\b(validate|sanitize|check|verify|assert|allow|whitelist|allowlist|enum|includes|indexOf|===)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    const isConfigGate = (map.story ?? []).some(s =>
      s.templateKey === 'gate-conditional' &&
      s.nodeId === node.id &&
      s.slots?.subject === 'NODE_ENV' &&
      /['"](?:development|production|test|staging)['"]/.test(s.slots?.condition ?? '')
    );

    if (ENV_RE454.test(code) && TRUST_RE454.test(code) && !VALID_RE454.test(code) && !isConfigGate) {
      const trustVar = code.match(TRUST_RE454)?.[0];
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate environment-sourced security variables)',
        severity: 'high',
        description: `Security variable "${trustVar}" from environment at ${node.label} without validation. ` +
          'Misconfigured deployment can set ADMIN=true. Note: "false" is truthy in JS.',
        fix: 'Validate against allowlist. Use typed config libraries. Never use string truthiness for env vars.',
        via: 'structural',
      });
    }

    if (URL_RE454.test(code) && TRUST_RE454.test(code) && !VALID_RE454.test(code)) {
      const trustVar = code.match(TRUST_RE454)?.[0];
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (never derive security flags from URL parameters)',
        severity: 'critical',
        description: `Security variable "${trustVar}" from URL parameter at ${node.label}. ` +
          'Anyone can add "?admin=true" -- this is a direct privilege escalation vector.',
        fix: 'Never derive security flags from user input. Use server-side sources (session, JWT, database).',
        via: 'structural',
      });
    }

    if (HDR_RE454.test(code) && TRUST_RE454.test(code) && !VALID_RE454.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate header-sourced trust values)',
        severity: 'high',
        description: `Security decision at ${node.label} based on custom HTTP header. ` +
          'Headers are user-controlled unless stripped by a trusted reverse proxy.',
        fix: 'Only trust headers set by your proxy that strips them from incoming requests.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-454', name: 'External Initialization of Trusted Variables or Data Stores', holds: findings.length === 0, findings };
}

/**
 * CWE-455: Non-exit on Failed Initialization
 * Security-critical initialization fails but system continues in degraded/insecure
 * state. The "fail open" anti-pattern at startup time.
 */
function verifyCWE455(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SEC_INIT_RE455 = /\b(loadKey|loadCert|initAuth|initSecurity|connectAuth|loadConfig|initEncryption|setupTLS|initSSL|loadCredentials|initFirewall|setupCORS|initSession|loadSecret|initOAuth|initSAML|initLDAP)\b/i;
  const CRYPTO_INIT_RE455 = /\b(createCipher|generateKey|createSign|createVerify|createHmac|randomBytes|generateKeyPair)\b.*\b(catch|try)\b|\b(catch|try)\b.*\b(createCipher|generateKey|createSign|createVerify)\b/i;
  const AUTH_CONN_RE455 = /\b(connect|createConnection|createPool|createClient)\b.*\b(auth|session|user|permission|role|ldap|oauth)\b/i;
  const CONT_FAIL_RE455 = /\bcatch\s*\([^)]*\)\s*\{[^}]*(?:console\.\w+|logger\.\w+|log\.\w+)[^}]*\}/;
  const FALL_PERM_RE455 = /\bcatch\b[\s\S]{0,200}\b(allow|permit|grant|true|enabled|open|skip|bypass|default|fallback)\b/i;
  const EXIT_RE455 = /\b(process\.exit|System\.exit|os\.exit|sys\.exit|throw\b|reject\b|fatal\b|panic\b|die\b|abort\b)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if ((SEC_INIT_RE455.test(code) || CRYPTO_INIT_RE455.test(code)) &&
        CONT_FAIL_RE455.test(code) && !EXIT_RE455.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (exit or throw on failed security initialization)',
        severity: 'critical',
        description: `Security initialization at ${node.label} continues after failure. ` +
          'Failed crypto key = no protection. Failed auth connection = bypassed authentication.',
        fix: 'Call process.exit(1) or throw fatal error on security init failure. Use health checks.',
        via: 'structural',
      });
    }

    if (FALL_PERM_RE455.test(code)) {
      const isSecCtx = SEC_INIT_RE455.test(code) || AUTH_CONN_RE455.test(code) ||
        /\b(auth|security|crypto|encrypt|permission|session|token|certificate|ssl|tls)\b/i.test(code);
      if (isSecCtx && !EXIT_RE455.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (fail closed -- deny access when security systems unavailable)',
          severity: 'critical',
          description: `Security at ${node.label} falls back to permissive on init failure. ` +
            'Fail-open: attacker can DoS the auth service to bypass all security.',
          fix: 'Fail closed. Return 503 when security systems unavailable. Alert operations.',
          via: 'structural',
        });
      }
    }

    if (AUTH_CONN_RE455.test(code) && CONT_FAIL_RE455.test(code) && !EXIT_RE455.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (fail closed on auth service connection failure)',
        severity: 'high',
        description: `Auth service connection at ${node.label} logs error but continues. ` +
          'Application may run without authentication, silently admitting all users.',
        fix: 'Exit process or enter safe no-service mode. Use readiness probes and circuit breakers.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-455', name: 'Non-exit on Failed Initialization', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// Credential & Cookie Security
// ---------------------------------------------------------------------------

function verifyCWE551(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Look for CONTROL nodes that do auth/authz checks
  const AUTH_RE = /\b(authorize|isAuthorized|checkPermission|hasRole|hasPermission|isAllowed|canAccess|requireAuth|authenticate|checkAuth|isAdmin|verifyRole|rbac|acl)\b/i;
  // Look for TRANSFORM nodes that do parsing/canonicalization/decoding
  const CANON_RE = /\b(decodeURI|decodeURIComponent|unescape|url\.parse|path\.normalize|path\.resolve|canonicalize|realpath|URL\s*\(|new\s+URL|encodeURI|decodeURIComponent|querystring\.parse|urlDecode|htmlDecode|base64Decode|atob|Buffer\.from.*(?:base64|hex)|uridecode|rawurldecode|urldecode)\b/i;
  const PATH_NORMALIZE_RE = /\b(normalize|resolve|realpath|canonicalize|toAbsolutePath|getCanonicalPath|getAbsolutePath)\b/i;

  // Strategy: find nodes where auth happens, then check if any parsing/decoding
  // happens AFTER auth in the data flow graph
  const controlNodes = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'TRANSFORM') &&
    AUTH_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );

  const parseNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'INGRESS') &&
    (CANON_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)) || PATH_NORMALIZE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot)))
  );

  for (const authNode of controlNodes) {
    for (const parseNode of parseNodes) {
      if (authNode.id === parseNode.id) continue;
      const code = stripComments(authNode.analysis_snapshot || authNode.code_snapshot);
      // Check if auth node references path/URL that will later be decoded
      if (/\b(path|url|uri|resource|file|route|endpoint)\b/i.test(code)) {
        // Check if there's a flow from auth to parse (auth happens first, parse second)
        if (hasTaintedPathWithoutControl(map, authNode.id, parseNode.id)) {
          findings.push({
            source: nodeRef(authNode),
            sink: nodeRef(parseNode),
            missing: 'ORDERING (canonicalize/parse BEFORE authorization, not after)',
            severity: 'high',
            description: `Authorization at ${authNode.label} occurs before parsing/canonicalization at ${parseNode.label}. ` +
              `An attacker can use encoded characters (e.g., %2e%2e/, %00, double-encoding) to bypass the auth check. ` +
              `The request is authorized against the encoded form, then decoded into a different resource path.`,
            fix: 'Canonicalize and fully parse/decode the input BEFORE performing authorization checks. ' +
              'Apply path.normalize(), decodeURIComponent(), and URL resolution before any access control decision. ' +
              'Reject requests containing encoded path separators or null bytes.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-551', name: 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization', holds: findings.length === 0, findings };
}

/**
 * CWE-523: Unprotected Transport of Credentials
 * Credentials transmitted over unencrypted channels (HTTP instead of HTTPS,
 * plain TCP instead of TLS, FTP instead of SFTP).
 */
function verifyCWE523(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CRED_RE523 = /\b(password|passwd|secret|api.?key|token|auth|credential|private.?key|client.?secret|bearer|jwt|session.?id|cookie)\b/i;
  const HTTP_URL_RE523 = /['"`]http:\/\/[^'"` ]+/i;
  const INSECURE_PROTO_RE523 = /\b(ftp:\/\/|telnet:\/\/|smtp(?!s)|pop3(?!s)|imap(?!s)|ldap(?!s)|ws:\/\/(?!s)|mqtt(?!s):\/\/|amqp(?!s):\/\/)\b/i;
  const FORM_HTTP_RE523 = /action\s*[:=]\s*['"]http:\/\//i;
  const FETCH_HTTP_RE523 = /\b(fetch|axios|request|http\.request|urllib|requests\.)\s*\(\s*['"`]http:\/\//i;
  const SAFE523 = /\b(https|ssl|tls|wss|sftp|smtps|ldaps|imaps|pop3s|amqps|mqtts)\b/i;
  const LOCAL_RE523 = /\b(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (CRED_RE523.test(code) && (HTTP_URL_RE523.test(code) || INSECURE_PROTO_RE523.test(code) || FETCH_HTTP_RE523.test(code))) {
      if (!SAFE523.test(code) && !LOCAL_RE523.test(code)) {
        const proto = INSECURE_PROTO_RE523.test(code) ? (code.match(INSECURE_PROTO_RE523)?.[0] || 'insecure protocol') : 'HTTP';
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (encrypt transport channel for credentials)',
          severity: 'critical',
          description: `Credentials at ${node.label} transmitted over ${proto}. ` +
            'Passwords/tokens sent in cleartext can be intercepted by any network observer (WiFi sniffing, ISP, middlebox).',
          fix: 'Use HTTPS (TLS) for all credential transmission. Set HSTS headers. ' +
            'Redirect HTTP to HTTPS at the server/load-balancer level. Use Secure flag on cookies.',
          via: 'structural',
        });
      }
    }

    if (FORM_HTTP_RE523.test(code) && CRED_RE523.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (HTTPS for login form submission)',
        severity: 'critical',
        description: `Login form at ${node.label} submits credentials over HTTP. ` +
          'The username and password are visible to anyone on the network path.',
        fix: 'Change form action to HTTPS. Better: use relative URLs and enforce HTTPS site-wide via HSTS.',
        via: 'structural',
      });
    }
  }

  const ingressCred523 = nodesOfType(map, 'INGRESS').filter(n => CRED_RE523.test(n.label) || CRED_RE523.test(n.analysis_snapshot || n.code_snapshot));
  const egressUnenc523 = nodesOfType(map, 'EGRESS').filter(n =>
    (HTTP_URL_RE523.test(n.analysis_snapshot || n.code_snapshot) || INSECURE_PROTO_RE523.test(n.analysis_snapshot || n.code_snapshot)) &&
    !SAFE523.test(n.analysis_snapshot || n.code_snapshot) && !LOCAL_RE523.test(n.analysis_snapshot || n.code_snapshot)
  );
  for (const src of ingressCred523) {
    for (const sink of egressUnenc523) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(sink),
          missing: 'CONTROL (TLS/HTTPS transport for credential data)',
          severity: 'critical',
          description: `Credential from ${src.label} flows to unencrypted egress at ${sink.label}. ` +
            'Credentials transmitted in cleartext are trivially interceptable.',
          fix: 'Ensure all credential egress uses TLS. Configure the HTTP client for HTTPS only.',
          via: 'bfs',
        });
      }
    }
  }

  return { cwe: 'CWE-523', name: 'Unprotected Transport of Credentials', holds: findings.length === 0, findings };
}


// ---------------------------------------------------------------------------
// AUTH_REGISTRY -- maps CWE IDs to verification functions
// ---------------------------------------------------------------------------

export const AUTH_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-306': verifyCWE306,
  'CWE-352': verifyCWE352,
  'CWE-384': verifyCWE384,
  'CWE-287': verifyCWE287,
  'CWE-288': verifyCWE288,
  'CWE-290': verifyCWE290,
  'CWE-294': verifyCWE294,
  'CWE-295': verifyCWE295,
  'CWE-296': verifyCWE296,
  'CWE-297': verifyCWE297,
  'CWE-521': verifyCWE521,
  'CWE-522': verifyCWE522,
  'CWE-620': verifyCWE620,
  'CWE-434': verifyCWE434,
  'CWE-436': verifyCWE436,
  'CWE-470': verifyCWE470,
  'CWE-501': verifyCWE501,
  'CWE-862': verifyCWE862,
  'CWE-863': verifyCWE863,
  'CWE-250': verifyCWE250,
  'CWE-269': verifyCWE269,
  'CWE-270': verifyCWE270,
  'CWE-271': verifyCWE271,
  'CWE-272': verifyCWE272,
  'CWE-273': verifyCWE273,
  'CWE-274': verifyCWE274,
  'CWE-276': verifyCWE276,
  'CWE-277': verifyCWE277,
  'CWE-279': verifyCWE279,
  'CWE-345': verifyCWE345,
  'CWE-346': verifyCWE346,
  'CWE-348': verifyCWE348,
  'CWE-349': verifyCWE349,
  'CWE-350': verifyCWE350,
  'CWE-353': verifyCWE353,
  'CWE-356': verifyCWE356,
  'CWE-565': verifyCWE565,
  'CWE-566': verifyCWE566,
  'CWE-614': verifyCWE614,
  'CWE-602': verifyCWE602,
  'CWE-603': verifyCWE603,
  'CWE-639': verifyCWE639,
  'CWE-640': verifyCWE640,
  'CWE-645': verifyCWE645,
  'CWE-646': verifyCWE646,
  'CWE-649': verifyCWE649,
  'CWE-650': verifyCWE650,
  'CWE-653': verifyCWE653,
  'CWE-654': verifyCWE654,
  'CWE-913': verifyCWE913,
  'CWE-915': verifyCWE915,
  'CWE-1022': verifyCWE1022,
  'CWE-1023': verifyCWE1023,
  'CWE-1024': verifyCWE1024,
  'CWE-1025': verifyCWE1025,
  'CWE-1036': verifyCWE1036,
  'CWE-939': verifyCWE939,
  'CWE-940': verifyCWE940,
  'CWE-941': verifyCWE941,
  'CWE-942': verifyCWE942,
  'CWE-943': verifyCWE943,
  'CWE-1004': verifyCWE1004,
  'CWE-1007': verifyCWE1007,
  'CWE-1021': verifyCWE1021,
  'CWE-305': verifyCWE305,
  'CWE-307': verifyCWE307,
  'CWE-308': verifyCWE308,
  'CWE-309': verifyCWE309,
  'CWE-280': verifyCWE280,
  'CWE-282': verifyCWE282,
  'CWE-283': verifyCWE283,
  'CWE-284': verifyCWE284,
  'CWE-285': verifyCWE285,
  'CWE-286': verifyCWE286,
  'CWE-289': verifyCWE289,
  'CWE-291': verifyCWE291,
  'CWE-302': verifyCWE302,
  'CWE-304': verifyCWE304,
  'CWE-266': verifyCWE266,
  'CWE-268': verifyCWE268,
  'CWE-351': verifyCWE351,
  'CWE-355': verifyCWE355,
  'CWE-357': verifyCWE357,
  'CWE-358': verifyCWE358,
  'CWE-360': verifyCWE360,
  'CWE-419': verifyCWE419,
  'CWE-420': verifyCWE420,
  'CWE-421': verifyCWE421,
  'CWE-424': verifyCWE424,
  'CWE-425': verifyCWE425,
  'CWE-430': verifyCWE430,
  'CWE-431': verifyCWE431,
  'CWE-432': verifyCWE432,
  'CWE-433': verifyCWE433,
  'CWE-439': verifyCWE439,
  'CWE-440': verifyCWE440,
  'CWE-441': verifyCWE441,
  'CWE-444': verifyCWE444,
  'CWE-446': verifyCWE446,
  'CWE-449': verifyCWE449,
  'CWE-450': verifyCWE450,
  'CWE-451': verifyCWE451,
  'CWE-453': verifyCWE453,
  'CWE-454': verifyCWE454,
  'CWE-455': verifyCWE455,
  'CWE-551': verifyCWE551,
  'CWE-523': verifyCWE523,
};
