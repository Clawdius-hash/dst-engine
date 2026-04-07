/**
 * Resource Management & Concurrency CWE Verifiers
 *
 * Race conditions, temp file races, signal/thread safety, resource exhaustion,
 * search path issues, cleanup/init, synchronization, lock management,
 * resource limits, deadlock detection, and ReDoS.
 *
 * Extracted from verifier/index.ts -- Phase 6 of the monolith split.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import type { VerificationResult, Finding } from './types.ts';
import { stripComments } from './source-analysis.ts';
import { nodeRef, nodesOfType, inferMapLanguage, isLibraryCode, hasTaintedPathWithoutControl, findContainingFunction, sharesFunctionScope } from './graph-helpers.ts';
import { getContainingScopeSnapshots, findNearestNode } from '../generated/_helpers.js';

// ---------------------------------------------------------------------------
// Resource Exhaustion & DoS
// ---------------------------------------------------------------------------

/* REMOVED: verifyCWE384 -- now in auth.ts */

// ---------------------------------------------------------------------------
// RESOURCE CWE Verification Paths
// ---------------------------------------------------------------------------

/**
 * CWE-400: Uncontrolled Resource Consumption
 * Pattern: INGRESS → RESOURCE[any] without CONTROL[limit_check]
 * Property: All resource allocations driven by user input have bounded limits
 *
 * R1: Unbounded resource consumption from user input.
 * Detects when tainted data flows to a RESOURCE node without a CONTROL
 * (validation, size limit, rate limiter) in between.
 */
function verifyCWE400(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const resources = nodesOfType(map, 'RESOURCE');

  for (const src of ingress) {
    for (const sink of resources) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if the resource call or its scope has bounds (V4-D: check scope for limits on prior lines)
        const scopeSnapshots400 = getContainingScopeSnapshots(map, sink.id);
        const combinedScope400 = stripComments(scopeSnapshots400.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isBounded = combinedScope400.match(
          /\bmax\b|\blimit\b|\bcap\b|\bMAX_|\bLIMIT_|\bmaxSize|\bmaxLength|\bslice\s*\(\s*\d|\bsubstring\s*\(\s*\d/i
        ) !== null;

        if (!isBounded) {
          const subtypeLabel = sink.node_subtype || 'unknown';
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input size validation or resource limit)',
            severity: subtypeLabel === 'cpu' ? 'high' : 'medium',
            description: `User input from ${src.label} controls ${subtypeLabel} resource allocation at ${sink.label} without bounds. ` +
              `An attacker can exhaust server ${subtypeLabel} resources causing denial of service.`,
            fix: `Validate and limit user input before passing to resource allocation. ` +
              `Add size/count limits: check input length, cap allocation size, use timeouts. ` +
              (subtypeLabel === 'cpu'
                ? 'For regex: use a safe regex library (re2) or limit input length. For crypto: cap iteration counts.'
                : subtypeLabel === 'memory'
                ? 'Cap buffer sizes. Limit request body size. Stream large inputs instead of buffering.'
                : subtypeLabel === 'connections'
                ? 'Use connection pooling with max limits. Set request timeouts. Add rate limiting.'
                : subtypeLabel === 'file_descriptors'
                ? 'Limit concurrent file operations. Close files in finally blocks.'
                : 'Add appropriate resource limits and rate limiting.'),
            via: 'bfs',
          });
        }
      }
    }
  }

  // Secondary check: INGRESS → RESOURCE via shared function scope (for patterns where
  // taint flows through local variables without explicit DATA_FLOW edges)
  if (findings.length === 0 && ingress.length > 0 && resources.length > 0) {
    for (const res of resources) {
      for (const src of ingress) {
        if (sharesFunctionScope(map, src.id, res.id)) {
          // Check if there's a CONTROL node in the same scope
          const controlInScope = map.nodes.some(n =>
            n.node_type === 'CONTROL' && sharesFunctionScope(map, n.id, res.id)
          );
          if (!controlInScope) {
            const isBounded = stripComments(res.analysis_snapshot || res.code_snapshot).match(
              /\bmax\b|\blimit\b|\bcap\b|\bMAX_|\bLIMIT_/i
            ) !== null;
            if (!isBounded) {
              const subtypeLabel = res.node_subtype || 'unknown';
              findings.push({
                source: nodeRef(src),
                sink: nodeRef(res),
                missing: 'CONTROL (input size validation or resource limit)',
                severity: 'medium',
                description: `User input from ${src.label} is accessible in the same scope as ${subtypeLabel} resource allocation at ${res.label} without bounds checking.`,
                fix: 'Add input validation or resource limits between user input and resource allocation.',
                via: 'scope_taint',
              });
            }
          }
        }
      }
    }
  }

  // Tertiary check: INGRESS → CONTROL/loop with tainted loop bounds.
  // A for/while/do loop whose bound is user-controlled IS resource exhaustion (CPU).
  // The mapper tags such loops with 'tainted_loop_bound' and creates DATA_FLOW edges.
  if (findings.length === 0) {
    const taintedLoops = map.nodes.filter(n =>
      n.node_type === 'CONTROL' && n.node_subtype === 'loop' &&
      (n.tags?.includes('tainted_loop_bound') || n.data_in.some((d: any) => d.tainted))
    );
    for (const loop of taintedLoops) {
      // Check that the loop doesn't already have bounds validation
      const scopeSnapshots = getContainingScopeSnapshots(map, loop.id);
      const combined = stripComments(scopeSnapshots.join('\n') || loop.analysis_snapshot || loop.code_snapshot);
      const isBounded = combined.match(
        /\bmax\b|\blimit\b|\bcap\b|\bMAX_|\bLIMIT_|\bmaxSize|\bmaxLength|\bMath\.min\b/i
      ) !== null;
      if (isBounded) continue;
      // Also check if the loop is wrapped by an if-statement that bounds the tainted variable.
      // Pattern: if (var > 0 && var <= N) { for(...) } — Juliet goodB2G pattern.
      const containingBranch400 = map.nodes.find(n =>
        n.node_type === 'CONTROL' && n.node_subtype === 'branch' &&
        n.line_start < loop.line_start && n.line_end >= loop.line_end &&
        /\b\w+\s*(?:<=?|>=?)\s*\d+/.test(n.analysis_snapshot || n.code_snapshot)
      );
      if (containingBranch400) continue;

      // Find the INGRESS source that taints this loop
      const taintedIn = loop.data_in.find((d: any) => d.tainted);
      const srcNodeId = taintedIn?.source;
      let srcNode = srcNodeId ? map.nodes.find(n => n.id === srcNodeId) : null;
      // Walk back to find an INGRESS node in the taint chain
      if (srcNode && srcNode.node_type !== 'INGRESS') {
        for (const ing of ingress) {
          if (sharesFunctionScope(map, ing.id, loop.id)) {
            srcNode = ing;
            break;
          }
        }
      }
      if (!srcNode) {
        // Fallback: use any INGRESS in the same function scope
        for (const ing of ingress) {
          if (sharesFunctionScope(map, ing.id, loop.id)) {
            srcNode = ing;
            break;
          }
        }
      }
      if (srcNode) {
        findings.push({
          source: nodeRef(srcNode),
          sink: nodeRef(loop),
          missing: 'CONTROL (input size validation or resource limit)',
          severity: 'high',
          description: `User input from ${srcNode.label} controls loop iteration count at ${loop.label} without bounds. ` +
            `An attacker can exhaust server CPU resources causing denial of service.`,
          fix: 'Validate and limit user input before using in loop condition. ' +
            'Add upper bound: if (count > MAX_ALLOWED) count = MAX_ALLOWED. Always enforce maximum iteration limits.',
          via: 'scope_taint',
        });
      }
    }
  }

  return {
    cwe: 'CWE-400',
    name: 'Uncontrolled Resource Consumption',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-770: Allocation of Resources Without Limits or Throttling
 * Pattern: Multiple INGRESS paths → same RESOURCE without CONTROL[rate_limit]
 * Property: Resource-consuming endpoints have rate limiting
 *
 * R3: DoS via multiple unthrottled paths to the same resource.
 * Checks if RESOURCE nodes reachable from INGRESS have rate limiting applied.
 */

/**
 * CWE-770: Allocation of Resources Without Limits or Throttling
 * Pattern: Multiple INGRESS paths → same RESOURCE without CONTROL[rate_limit]
 * Property: Resource-consuming endpoints have rate limiting
 *
 * R3: DoS via multiple unthrottled paths to the same resource.
 * Checks if RESOURCE nodes reachable from INGRESS have rate limiting applied.
 */
function verifyCWE770(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const resources = nodesOfType(map, 'RESOURCE');

  // Check for rate limiting: CONTROL nodes with rate_limit or rate_limiter subtypes
  const hasRateLimiter = map.nodes.some(n =>
    n.node_type === 'CONTROL' &&
    (n.node_subtype.includes('rate_limit') || n.node_subtype.includes('throttle') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\brate.?limit\b|\bthrottle\b|\brateLimit\b/i) !== null)
  );

  if (hasRateLimiter) {
    return {
      cwe: 'CWE-770',
      name: 'Allocation of Resources Without Limits or Throttling',
      holds: true,
      findings: [],
    };
  }

  // Count how many INGRESS paths reach each RESOURCE
  for (const res of resources) {
    const reachingIngress: NeuralMapNode[] = [];
    let reachedViaBfs770 = false;
    for (const src of ingress) {
      // Check if there's any path (tainted or not) from ingress to resource
      const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
      const visited = new Set<string>();
      const queue = [src.id];
      let found = false;

      while (queue.length > 0 && !found) {
        const nodeId = queue.shift()!;
        if (visited.has(nodeId)) continue;
        visited.add(nodeId);

        if (nodeId === res.id) { found = true; break; }

        const node = nodeMap.get(nodeId);
        if (!node) continue;
        for (const edge of node.edges) {
          if (!visited.has(edge.target)) queue.push(edge.target);
        }
      }
      if (found) { reachingIngress.push(src); reachedViaBfs770 = true; }
    }

    // Also check via function scope proximity
    if (reachingIngress.length === 0) {
      for (const src of ingress) {
        if (sharesFunctionScope(map, src.id, res.id)) {
          reachingIngress.push(src);
        }
      }
    }

    if (reachingIngress.length > 0) {
      const subtypeLabel = res.node_subtype || 'unknown';
      findings.push({
        source: nodeRef(reachingIngress[0]),
        sink: nodeRef(res),
        missing: 'CONTROL (rate limiting or request throttling)',
        severity: 'medium',
        description: `${reachingIngress.length} ingress path(s) reach ${subtypeLabel} resource at ${res.label} without rate limiting. ` +
          `An attacker can send many requests to exhaust the resource pool.`,
        fix: 'Add rate limiting middleware (e.g., express-rate-limit) to endpoints that consume shared resources. ' +
          'Set per-IP and global request limits. Use connection pool limits.',
        via: reachedViaBfs770 ? 'bfs' : 'scope_taint',
      });
    }
  }

  return {
    cwe: 'CWE-770',
    name: 'Allocation of Resources Without Limits or Throttling',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-1333: Inefficient Regular Expression Complexity (ReDoS)
 *
 * PRIMARY verifier — scans ALL nodes for dangerous regex patterns regardless of node type.
 * The old implementation only caught INGRESS→RESOURCE[cpu] (user-controlled regex construction).
 * This replacement adds a primary pass that detects catastrophic backtracking in hardcoded
 * regex literals anywhere in the graph, then elevates severity when INGRESS taint reaches
 * the regex node.
 *
 * Detection strategies (in order):
 *   1. PRIMARY: Any node whose code_snapshot contains a regex literal with catastrophic
 *      backtracking structure — (a+)+, (a*)*, (\s+)+, overlapping alternation with quantifiers,
 *      .* repeated, nested quantifiers (a+b+)* etc.
 *      Safe exits: atomic groups (?>...), possessive quantifiers (\w++), RE2/re2 library.
 *      Severity is elevated to 'critical' when an INGRESS node has a direct taint flow
 *      to the regex node (attacker controls the regex input, compounding the risk).
 *   2. SECONDARY: RESOURCE[cpu] nodes fed by INGRESS taint without a CONTROL gate
 *      (user-controlled regex construction via new RegExp(userInput)).
 *   3. TERTIARY: Code-snapshot scan for new RegExp(tainted) in non-STRUCTURAL nodes
 *      sharing function scope with an INGRESS node.
 */

// Catastrophic backtracking detector patterns (applied to the regex body, not the surrounding code)

// ReDoS helper functions and constants
const CATASTROPHIC_BACKTRACK_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  // (a+)+ or (a*)* — quantifier on a group that already has a quantifier inside
  { pattern: /\([^)]*[+*][^)]*\)[+*{]/, label: 'nested quantifier group (a+)+ or (a*)*' },
  // (\s+)+ or (\w+)+ etc.
  { pattern: /\(\\[swdStWD][+*][^)]*\)[+*{]/, label: 'repeated character-class group (\\s+)+' },
  // (a|b)+ with overlapping alternatives — ambiguous match
  { pattern: /\([^)]*\|[^)]*\)[+*{]/, label: 'overlapping alternation with quantifier (a|b)+' },
  // .*.* or .*.*$ — repeated .* patterns
  { pattern: /\.\*[^|)]*\.\*/, label: 'repeated .* wildcard' },
  // Nested quantifiers: (a+b+)* or (a{2,}b+)+ etc.
  { pattern: /\([^)]*[+*]\s*[^)]*[+*]\)[+*{]/, label: 'compound nested quantifiers (a+b+)*' },
  // ([a-z]+)+ or ([A-Z0-9]+)* — character class group with outer quantifier
  { pattern: /\(\[[^\]]+\][+*]\)[+*{]/, label: 'character class group with outer quantifier ([a-z]+)+' },
  // (?:a+)+ — even non-capturing groups are vulnerable
  { pattern: /\(\?:[^)]*[+*][^)]*\)[+*{]/, label: 'non-capturing group nested quantifier (?:a+)+' },
];

// Safe patterns that exempt a regex from ReDoS flagging
const REDOS_SAFE_PATTERNS = /\(\?>|[+*?]\+|\bre2\b|\bRE2\b|\bre2\.compile\b|\bnew\s+RE2\b|\bsafe[-_]regex\b/i;

/**
 * Extract all regex literals from a code string.
 * Returns an array of regex body strings (the part between the slashes).
 * Handles: /pattern/flags, new RegExp("pattern"), re.compile("pattern").
 */
function extractRegexBodies(code: string): string[] {
  const bodies: string[] = [];
  const stripped = stripComments(code);

  // Regex literals: /pattern/flags — exclude division operators by requiring non-alpha/non-digit before
  const literalRe = /(?:^|[^a-zA-Z0-9_$\])])\s*\/([^/\n]{2,})\/[gimsuy]*/g;
  let m: RegExpExecArray | null;
  while ((m = literalRe.exec(stripped)) !== null) {
    bodies.push(m[1]);
  }

  // new RegExp("pattern") or new RegExp('pattern') or new RegExp(`pattern`)
  const newRegexpRe = /new\s+RegExp\s*\(\s*(['"`])([^'"`,)]{2,})\1/g;
  while ((m = newRegexpRe.exec(stripped)) !== null) {
    bodies.push(m[2]);
  }

  // Python/Ruby re.compile("pattern") or re.match("pattern") etc.
  const reCompileRe = /re\.(?:compile|match|search|fullmatch|findall|finditer|sub|subn)\s*\(\s*r?(['"`])([^'"`,)]{2,})\1/g;
  while ((m = reCompileRe.exec(stripped)) !== null) {
    bodies.push(m[2]);
  }

  // Java Pattern.compile("pattern")
  const patternCompileRe = /Pattern\.compile\s*\(\s*"([^"]{2,})"/g;
  while ((m = patternCompileRe.exec(stripped)) !== null) {
    bodies.push(m[1]);
  }

  return bodies;
}

/**
 * Returns true if the regex body contains a catastrophic backtracking pattern
 * AND is not protected by an atomic group, possessive quantifier, or RE2 library.
 * Returns the matched label or null if safe.
 */
function detectCatastrophicBacktracking(regexBody: string): string | null {
  // If it uses safe constructs, skip
  if (REDOS_SAFE_PATTERNS.test(regexBody)) return null;
  for (const { pattern, label } of CATASTROPHIC_BACKTRACK_PATTERNS) {
    if (pattern.test(regexBody)) return label;
  }
  return null;
}

function verifyCWE1333(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const seenNodeIds = new Set<string>();

  // Build a quick lookup: which node IDs are reachable (with taint) from any INGRESS?
  // Used to elevate severity from 'high' to 'critical' when user data reaches a bad regex.
  const taintReachable = new Set<string>();
  for (const src of ingress) {
    // BFS following flow edges — collect all reachable nodes
    const visited = new Set<string>();
    const queue = [src.id];
    let head = 0;
    const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
    while (head < queue.length) {
      const nodeId = queue[head++];
      if (visited.has(nodeId)) continue;
      visited.add(nodeId);
      taintReachable.add(nodeId);
      const node = nodeMap.get(nodeId);
      if (!node) continue;
      for (const edge of node.edges) {
        if (['DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS'].includes(edge.edge_type)) {
          if (!visited.has(edge.target)) queue.push(edge.target);
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // STRATEGY 1 (PRIMARY): Scan ALL non-META nodes for catastrophic regex patterns
  // -------------------------------------------------------------------------
  for (const node of map.nodes) {
    if (node.node_type === 'META') continue;
    if (seenNodeIds.has(node.id)) continue;

    const code = node.analysis_snapshot || node.code_snapshot;
    if (!code || code.length < 5) continue;

    // Check if the node itself mentions a safe regex library — skip the whole node
    if (/\bre2\b|\bRE2\b|\bnew\s+RE2\b/i.test(stripComments(code))) continue;

    const bodies = extractRegexBodies(code);
    for (const body of bodies) {
      const dangerLabel = detectCatastrophicBacktracking(body);
      if (!dangerLabel) continue;

      // Is this node reachable from INGRESS taint? Elevate severity.
      const ingressTainted = taintReachable.has(node.id) ||
        node.data_in.some(d => d.tainted);

      // Use a synthetic "source" from the first INGRESS if tainted, else self-reference
      const firstIngress = ingress[0];
      const sourceRef = ingressTainted && firstIngress
        ? nodeRef(firstIngress)
        : nodeRef(node);

      seenNodeIds.add(node.id);
      findings.push({
        source: sourceRef,
        sink: nodeRef(node),
        missing: ingressTainted
          ? 'CONTROL (regex timeout, possessive quantifiers, or RE2 library) — user input reaches vulnerable regex'
          : 'CONTROL (rewrite regex with possessive quantifiers/atomic groups, or use RE2 library)',
        severity: ingressTainted ? 'critical' : 'high',
        description: `Node ${node.label} contains a regex with catastrophic backtracking potential (${dangerLabel}): ` +
          `/${body}/. ` +
          (ingressTainted
            ? `User-controlled data flows into this regex, giving an attacker direct control over backtracking depth. `
            : `Even without direct user input, this pattern can cause exponential backtracking on adversarial strings. `) +
          `ReDoS can freeze or crash the server.`,
        fix: 'Rewrite the regex to eliminate ambiguous quantifiers. Options: ' +
          '(1) Use possessive quantifiers or atomic groups: (?>a+)+ never backtracks. ' +
          '(2) Use the RE2 library (Node: "re2" package, Python: "google-re2") which guarantees O(n) matching. ' +
          '(3) Set a hard timeout on regex execution. ' +
          '(4) Validate and limit input length before applying the regex.',
        via: 'structural',
      });
      break; // One finding per node — most dangerous pattern is enough
    }
  }

  // -------------------------------------------------------------------------
  // STRATEGY 2 (SECONDARY): INGRESS → RESOURCE[cpu] via tainted path (user-controlled pattern)
  // -------------------------------------------------------------------------
  const regexResources = map.nodes.filter(n =>
    n.node_type === 'RESOURCE' && n.node_subtype === 'cpu' &&
    /\bRegExp\b|\bregex\b|\bnew\s+RegExp\b/i.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const src of ingress) {
    for (const sink of regexResources) {
      if (seenNodeIds.has(sink.id)) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        seenNodeIds.add(sink.id);
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'CONTROL (regex input validation or safe regex library)',
          severity: 'high',
          description: `User input from ${src.label} is used to construct a regular expression at ${sink.label}. ` +
            `A crafted input like (a+)+$ can cause catastrophic backtracking (ReDoS), freezing the server.`,
          fix: 'Never pass user input directly to new RegExp(). Options: ' +
            '(1) Use a safe regex library like re2. ' +
            '(2) Escape user input with escapeRegExp() before constructing. ' +
            '(3) Set a timeout on regex execution. ' +
            '(4) Limit input length before regex construction.',
          via: 'bfs',
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // STRATEGY 3 (TERTIARY): Code-snapshot scan for new RegExp(tainted) in any node
  // -------------------------------------------------------------------------
  if (ingress.length > 0) {
    const regexNodes = map.nodes.filter(n =>
      n.node_type !== 'STRUCTURAL' && n.node_type !== 'META' &&
      !seenNodeIds.has(n.id) &&
      /\bnew\s+RegExp\s*\(/.test(n.analysis_snapshot || n.code_snapshot)
    );

    for (const regNode of regexNodes) {
      for (const src of ingress) {
        const bfsHit1333 = hasTaintedPathWithoutControl(map, src.id, regNode.id);
        const scopeHit1333 = !bfsHit1333 && sharesFunctionScope(map, src.id, regNode.id);
        if (bfsHit1333 || scopeHit1333) {
          // Check scope snapshots so sanitization on prior lines is visible
          const scopeSnapshots1333 = getContainingScopeSnapshots(map, regNode.id);
          const combinedScope1333 = stripComments(scopeSnapshots1333.join('\n') || regNode.analysis_snapshot || regNode.code_snapshot);
          const isEscaped = combinedScope1333.match(
            /\bescapeRegExp\s*\(|\bescape\s*\(|\bsanitize\s*\(|\bre2\b|\bsafe.*regex/i
          ) !== null;

          if (!isEscaped) {
            seenNodeIds.add(regNode.id);
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(regNode),
              missing: 'CONTROL (regex input escaping or safe regex library)',
              severity: 'high',
              description: `User input from ${src.label} may reach regex construction at ${regNode.label}. ` +
                `Crafted patterns can cause catastrophic backtracking (ReDoS).`,
              fix: 'Escape user input before passing to new RegExp(), or use the re2 library for safe regex.',
              via: bfsHit1333 ? 'bfs' : 'scope_taint',
            });
            break;
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-1333',
    name: 'Inefficient Regular Expression Complexity (ReDoS)',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-404: Improper Resource Shutdown or Release
 * Pattern: RESOURCE[acquire] on error path without RESOURCE[release]
 * Property: All resource acquisitions have corresponding releases on all paths
 *
 * R2: Resource leak detection.
 * Checks if RESOURCE nodes (connections, file descriptors) are properly released
 * by looking for matching release patterns in the same function scope.
 */

/**
 * CWE-404: Improper Resource Shutdown or Release
 * Pattern: RESOURCE[acquire] on error path without RESOURCE[release]
 * Property: All resource acquisitions have corresponding releases on all paths
 *
 * R2: Resource leak detection.
 * Checks if RESOURCE nodes (connections, file descriptors) are properly released
 * by looking for matching release patterns in the same function scope.
 */
function verifyCWE404(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Resource acquire patterns — node_subtype + code_snapshot checks
  const acquirePatterns = /\b(open|createReadStream|createWriteStream|getConnection|acquire|connect|createServer|createConnection)\b/i;
  const releasePatterns = /\b(close|end|release|destroy|releaseConnection|disconnect|shutdown|unref)\b/i;

  const resourceNodes = nodesOfType(map, 'RESOURCE');

  for (const res of resourceNodes) {
    // Only check acquirable resources (connections, file descriptors)
    if (res.node_subtype !== 'connections' && res.node_subtype !== 'file_descriptors') continue;

    // Check if this is an acquire operation
    if (!acquirePatterns.test(res.analysis_snapshot || res.code_snapshot)) continue;

    // Find the containing function
    const containingFunc = findContainingFunction(map, res.id);
    if (!containingFunc) continue;

    // Look for a matching release in the same function
    const funcNode = map.nodes.find(n => n.id === containingFunc);
    if (!funcNode) continue;

    // Gather all nodes contained in the same function
    const containedNodeIds = new Set<string>();
    const queue = [containingFunc];
    while (queue.length > 0) {
      const id = queue.shift()!;
      const node = map.nodes.find(n => n.id === id);
      if (!node) continue;
      for (const edge of node.edges) {
        if (edge.edge_type === 'CONTAINS' && !containedNodeIds.has(edge.target)) {
          containedNodeIds.add(edge.target);
          queue.push(edge.target);
        }
      }
    }

    // Check if any contained node has a release pattern
    const hasRelease = map.nodes.some(n =>
      containedNodeIds.has(n.id) && releasePatterns.test(n.analysis_snapshot || n.code_snapshot)
    );

    // Also check code_snapshot of the containing function itself for finally/release
    const funcHasRelease = releasePatterns.test(funcNode.analysis_snapshot || funcNode.code_snapshot) ||
      /\bfinally\b/.test(funcNode.analysis_snapshot || funcNode.code_snapshot);

    if (!hasRelease && !funcHasRelease) {
      findings.push({
        source: nodeRef(res),
        sink: nodeRef(res),
        missing: 'RESOURCE (release/close/end on all code paths including error paths)',
        severity: 'medium',
        description: `${res.node_subtype} resource acquired at ${res.label} may not be released on all code paths. ` +
          `This can lead to resource leaks (${res.node_subtype === 'connections' ? 'connection pool exhaustion' : 'file descriptor exhaustion'}).`,
        fix: `Ensure resources are released in a finally block or using a try-with-resources pattern. ` +
          `For connections: always call release() or end() in a finally block. ` +
          `For files: use fs.promises with try/finally, or streams that auto-close.`,
        via: 'structural',
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Java-specific: detect resource close in try block instead of finally (Juliet CWE-404)
  // Juliet pattern: FileReader/Connection opened in try, close() inside try (not finally)
  // Good pattern: close() inside finally block
  // ---------------------------------------------------------------------------
  if (inferMapLanguage(map) === 'java') {
    const JAVA_RESOURCE_OPEN_RE = /\bnew\s+(FileReader|BufferedReader|FileInputStream|FileOutputStream|FileWriter|BufferedWriter|InputStreamReader|OutputStreamWriter|PrintWriter|Socket|ServerSocket|ZipFile|Connection|PreparedStatement|Statement|ResultSet)\b|\b(getConnection|getDBConnection|openConnection)\s*\(/;
    const JAVA_RESOURCE_CLOSE_RE = /\.\s*close\s*\(/;
    const JAVA_FINALLY_CLOSE_RE = /\bfinally\b[\s\S]*?\.\s*close\s*\(/;
    const JAVA_TRY_WITH_RESOURCES_RE = /\btry\s*\(/;

    for (const node of map.nodes) {
      if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
      const rawCode = node.analysis_snapshot || node.code_snapshot;
      if (!rawCode) continue;
      // Strip comments to avoid false matches on words like "finally" in comments
      const code = stripComments(rawCode);
      // Skip if using try-with-resources (auto-close)
      if (JAVA_TRY_WITH_RESOURCES_RE.test(code)) continue;
      // Must have resource creation
      if (!JAVA_RESOURCE_OPEN_RE.test(code)) continue;

      // Check: does it have close() but NOT in a finally block?
      const hasClose = JAVA_RESOURCE_CLOSE_RE.test(code);
      const hasFinally = /\bfinally\b/.test(code);
      const hasCloseInFinally = JAVA_FINALLY_CLOSE_RE.test(code);

      // Vulnerable: resource opened + (no close at all, or close only in try not finally)
      if (!hasCloseInFinally) {
        // Has close but not in finally = improper shutdown (Juliet bad pattern)
        // Has no close at all = also improper
        const resourceMatch = code.match(JAVA_RESOURCE_OPEN_RE);
        const resourceType = resourceMatch ? (resourceMatch[1] || 'resource') : 'resource';
        if (!findings.some(f => f.source.id === node.id)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'RESOURCE (release/close in finally block or try-with-resources)',
            severity: 'medium',
            description: `Method ${node.label} opens ${resourceType} but does not close it in a finally block. If an exception occurs, the resource will leak.`,
            fix: 'Move resource close() calls to a finally block, or use try-with-resources (Java 7+) for automatic cleanup.',
            via: 'structural',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-404',
    name: 'Improper Resource Shutdown or Release',
    holds: findings.length === 0,
    findings,
  };
}

// ---------------------------------------------------------------------------
// CWE-405: Asymmetric Resource Consumption (Amplification)
// ---------------------------------------------------------------------------

/**
 * CWE-405: Asymmetric Resource Consumption (Amplification)
 * Detects when a small user input triggers disproportionately large server-side
 * resource consumption — the classic amplification attack. A tiny request causes
 * the server to do massive work (fan-out queries, recursive expansion, broadcast).
 *
 * Detection: INGRESS -> RESOURCE paths where the resource node shows amplification
 * patterns (loops over input, fan-out calls, recursive expansion) without bounds.
 */
function verifyCWE405(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const resources = nodesOfType(map, 'RESOURCE');

  // Patterns that indicate amplification — small input causes large work
  const AMPLIFICATION_PATTERN = /\b(broadcast|fanout|fan.?out|multicast|Promise\.all|Promise\.allSettled|allSettled|forEach\s*\(\s*async|\.map\s*\(\s*async|for\s*\(\s*(let|const|var)\s+\w+\s+(of|in)\b|while\s*\(|do\s*\{|recursive|recurse|expand|inflate|replicate|spawn|fork|cluster\.fork|worker_threads|child_process|exec\s*\(|notify.?all|send.?all|email.?all|sms.?all|push.?all)\b/i;
  // Patterns that indicate input directly controls iteration/fan-out count
  const INPUT_CONTROLS_SCALE = /\b(\.length|\.size|\.count|Object\.keys|Array\.from|Array\(|new\s+Array|repeat\s*\(|times\s*\(|range\s*\(|\.split\s*\(|parseInt|Number\s*\()\b/i;
  // Safe patterns — bounded amplification
  const BOUNDED_SAFE = /\b(Math\.min|Math\.max|\.slice\s*\(\s*\d|\.substring\s*\(\s*\d|limit|LIMIT|maxItems|maxCount|maxRecipients|maxFanout|batchSize|BATCH_SIZE|chunk|paginate|pageSize|PAGE_SIZE|throttle|rateLimit|rate.?limit|bulkhead)\b/i;

  for (const src of ingress) {
    for (const res of resources) {
      if (hasTaintedPathWithoutControl(map, src.id, res.id)) {
        const code = stripComments(res.analysis_snapshot || res.code_snapshot);
        const containingFunc = findContainingFunction(map, res.id);
        const funcCode = containingFunc
          ? stripComments(map.nodes.find(n => n.id === containingFunc)?.analysis_snapshot || map.nodes.find(n => n.id === containingFunc)?.code_snapshot || '')
          : '';
        const allCode = code + ' ' + funcCode;

        const hasAmplification = AMPLIFICATION_PATTERN.test(allCode) || INPUT_CONTROLS_SCALE.test(code);
        const isBounded = BOUNDED_SAFE.test(allCode);

        if (hasAmplification && !isBounded) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(res),
            missing: 'CONTROL (amplification bound — limit fan-out factor)',
            severity: 'high',
            description: `User input from ${src.label} triggers amplified resource consumption at ${res.label}. ` +
              `A small request can cause disproportionately large server-side work (fan-out, broadcast, recursive expansion), ` +
              `enabling denial-of-service with minimal attacker bandwidth.`,
            fix: 'Cap the amplification factor: limit array/list sizes before iteration, ' +
              'bound fan-out counts (e.g., max 100 recipients for broadcast), ' +
              'use pagination/chunking for bulk operations, and add rate limiting on amplifiable endpoints. ' +
              'For recursive expansion: set a max depth. For Promise.all: limit concurrency with p-limit or similar.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-405', name: 'Asymmetric Resource Consumption (Amplification)', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-406: Insufficient Control of Network Message Volume
// ---------------------------------------------------------------------------

/**
 * CWE-406: Insufficient Control of Network Message Volume
 * Detects endpoints that generate or relay network messages without volume controls.
 * Unlike CWE-405 (general amplification), this specifically targets network traffic:
 * email sending, push notifications, webhook dispatch, API call fan-out, etc.
 *
 * Detection: INGRESS nodes that reach EGRESS or network-sending nodes without
 * rate limiting or volume caps.
 */

// ---------------------------------------------------------------------------
// CWE-406: Insufficient Control of Network Message Volume
// ---------------------------------------------------------------------------

/**
 * CWE-406: Insufficient Control of Network Message Volume
 * Detects endpoints that generate or relay network messages without volume controls.
 * Unlike CWE-405 (general amplification), this specifically targets network traffic:
 * email sending, push notifications, webhook dispatch, API call fan-out, etc.
 *
 * Detection: INGRESS nodes that reach EGRESS or network-sending nodes without
 * rate limiting or volume caps.
 */
function verifyCWE406(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const egress = nodesOfType(map, 'EGRESS');

  // Network message sending patterns
  const NETWORK_SEND = /\b(sendMail|send_mail|sendEmail|send_email|smtp|transporter\.send|nodemailer|sgMail|ses\.send|postmark|mailgun|sendGrid|fetch\s*\(|axios\s*\.|http\.request|https\.request|request\s*\(|got\s*\(|needle|superagent|webhook|notify|push\.send|pushNotification|fcm\.send|apns|sns\.publish|sqs\.send|kafka\.send|producer\.send|publish\s*\(|emit\s*\(|broadcast|socket\.send|ws\.send|io\.emit|io\.to\()\b/i;
  // Volume control patterns
  const VOLUME_SAFE = /\b(rateLimit|rate.?limit|throttle|Throttle|debounce|maxMessages|maxEmails|maxNotifications|maxRequests|dailyLimit|hourlyLimit|quota|QUOTA|cooldown|backoff|exponentialBackoff|retry.?limit|maxRetries|circuit.?breaker|bulkhead|semaphore|token.?bucket|leaky.?bucket|sliding.?window)\b/i;

  for (const src of ingress) {
    for (const sink of egress) {
      const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      if (!NETWORK_SEND.test(code)) continue;

      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const containingFunc = findContainingFunction(map, sink.id);
        const funcCode = containingFunc
          ? stripComments(map.nodes.find(n => n.id === containingFunc)?.analysis_snapshot || map.nodes.find(n => n.id === containingFunc)?.code_snapshot || '')
          : '';
        const allCode = code + ' ' + funcCode;

        if (!VOLUME_SAFE.test(allCode)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (network message volume limit — rate limiting or quota)',
            severity: 'medium',
            description: `User input from ${src.label} triggers network message sending at ${sink.label} without volume controls. ` +
              `An attacker can abuse this to flood recipients (email bombing), exhaust API quotas, ` +
              `or amplify traffic through the server as a relay.`,
            fix: 'Add rate limiting per user/IP on message-sending endpoints. ' +
              'Implement daily/hourly quotas for outbound messages. ' +
              'Use a message queue with bounded throughput rather than synchronous send-all. ' +
              'For webhooks: add circuit breakers and exponential backoff. ' +
              'For notifications: deduplicate and batch.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Also check TRANSFORM and RESOURCE nodes that do network sends
  const allNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'RESOURCE') &&
    NETWORK_SEND.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );
  for (const src of ingress) {
    for (const sink of allNodes) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const containingFunc = findContainingFunction(map, sink.id);
        const funcCode = containingFunc
          ? stripComments(map.nodes.find(n => n.id === containingFunc)?.analysis_snapshot || map.nodes.find(n => n.id === containingFunc)?.code_snapshot || '')
          : '';
        if (!VOLUME_SAFE.test(code + ' ' + funcCode)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (network message volume limit)',
            severity: 'medium',
            description: `User input from ${src.label} triggers network message sending at ${sink.label} without volume controls.`,
            fix: 'Add rate limiting, quotas, or message queue with bounded throughput for outbound network messages.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-406', name: 'Insufficient Control of Network Message Volume', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-407: Inefficient Algorithmic Complexity
// ---------------------------------------------------------------------------

/**
 * CWE-407: Inefficient Algorithmic Complexity
 * Detects use of algorithms with poor worst-case complexity on user-controlled input.
 * Related to CWE-1333 (ReDoS) but broader: covers sorting, searching, parsing,
 * and any operation where attacker-crafted input triggers worst-case O(n^2+) behavior.
 *
 * Detection: INGRESS data flows to nodes using known-bad-complexity operations
 * without input size limits or algorithm guards.
 */

// ---------------------------------------------------------------------------
// CWE-407: Inefficient Algorithmic Complexity
// ---------------------------------------------------------------------------

/**
 * CWE-407: Inefficient Algorithmic Complexity
 * Detects use of algorithms with poor worst-case complexity on user-controlled input.
 * Related to CWE-1333 (ReDoS) but broader: covers sorting, searching, parsing,
 * and any operation where attacker-crafted input triggers worst-case O(n^2+) behavior.
 *
 * Detection: INGRESS data flows to nodes using known-bad-complexity operations
 * without input size limits or algorithm guards.
 */
function verifyCWE407(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const transforms = nodesOfType(map, 'TRANSFORM');
  const allProcessing = [...transforms, ...nodesOfType(map, 'RESOURCE')];

  // Patterns with known worst-case complexity issues on adversarial input
  const BAD_COMPLEXITY = /\b(\.sort\s*\(|Array\.prototype\.sort|qsort|quicksort|bubble.?sort|insertion.?sort|\.indexOf\s*\([^)]*\bfor\b|nested.*loop|\.includes\s*\(\s*[^)]+\.includes|JSON\.parse|xml\.parse|yaml\.load|yaml\.safe_load|parseFloat|parseInt|DOMParser|\.match\s*\(|\.replace\s*\(|\.split\s*\(|\.search\s*\(|RegExp|new\s+RegExp|eval\s*\(|Function\s*\(|template.*compile|handlebars\.compile|ejs\.render|pug\.compile|markdown|marked|showdown|textile|restructuredtext|difflib|diff\.createPatch|levenshtein|edit.?distance|similarity|fuzzy.?match|glob.?match|minimatch|micromatch|picomatch)\b/i;
  // Quadratic or worse patterns — nested iteration over same input
  const NESTED_ITERATION = /for\s*\([^)]*\)\s*\{[^}]*for\s*\([^)]*\)|\.forEach\s*\([^)]*\.forEach|\.map\s*\([^)]*\.filter|\.filter\s*\([^)]*\.find|while\s*\([^)]*while\s*\(/i;
  // Safe — input bounded or safe algorithm used
  const COMPLEXITY_SAFE = /\b(Math\.min|\.slice\s*\(\s*0\s*,\s*\d|\.substring\s*\(\s*0\s*,\s*\d|maxLength|MAX_LENGTH|maxSize|MAX_SIZE|MAX_INPUT|limit|LIMIT|truncate|TimSort|mergesort|merge.?sort|radix.?sort|Map\s*\(|Set\s*\(|HashMap|HashSet|\.has\s*\(|binary.?search|bisect|re2|RE2|safe.?regex|safe.?regexp|timeout|TIMEOUT|AbortController|signal|deadline)\b/i;

  for (const src of ingress) {
    for (const sink of allProcessing) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const containingFunc = findContainingFunction(map, sink.id);
        const funcCode = containingFunc
          ? stripComments(map.nodes.find(n => n.id === containingFunc)?.analysis_snapshot || map.nodes.find(n => n.id === containingFunc)?.code_snapshot || '')
          : '';
        const allCode = code + ' ' + funcCode;

        const hasBadComplexity = BAD_COMPLEXITY.test(code) || NESTED_ITERATION.test(allCode);
        const isSafe = COMPLEXITY_SAFE.test(allCode);

        if (hasBadComplexity && !isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input size limit or algorithm with guaranteed O(n log n) or better)',
            severity: 'medium',
            description: `User input from ${src.label} is processed by an algorithm at ${sink.label} that may have ` +
              `super-linear worst-case complexity. An attacker can craft input that triggers worst-case behavior, ` +
              `causing CPU exhaustion (algorithmic complexity attack / hash-flooding / quadratic blowup).`,
            fix: 'Limit input size before processing (truncate to safe maximum). ' +
              'Use algorithms with guaranteed O(n log n) or better worst-case (e.g., mergesort instead of quicksort). ' +
              'For regex: use RE2 or validate patterns with safe-regex. ' +
              'For string matching: use hash-based lookups (Set/Map) instead of nested iteration. ' +
              'For JSON/XML parsing: limit depth and size. Add timeouts as a safety net.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-407', name: 'Inefficient Algorithmic Complexity', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-409: Improper Handling of Highly Compressed Data (Decompression Bomb)
// ---------------------------------------------------------------------------

/**
 * CWE-409: Improper Handling of Highly Compressed Data
 * Detects decompression of user-supplied data without output size limits.
 * A "zip bomb" or "gzip bomb" — a small compressed payload expands to gigabytes,
 * exhausting memory or disk.
 *
 * Detection: INGRESS data flows to decompression/inflate operations without
 * output size checks.
 */

// ---------------------------------------------------------------------------
// CWE-409: Improper Handling of Highly Compressed Data (Decompression Bomb)
// ---------------------------------------------------------------------------

/**
 * CWE-409: Improper Handling of Highly Compressed Data
 * Detects decompression of user-supplied data without output size limits.
 * A "zip bomb" or "gzip bomb" — a small compressed payload expands to gigabytes,
 * exhausting memory or disk.
 *
 * Detection: INGRESS data flows to decompression/inflate operations without
 * output size checks.
 */
function verifyCWE409(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Decompression patterns across languages
  const DECOMPRESS_PATTERN = /\b(zlib\.inflate|zlib\.gunzip|zlib\.unzip|zlib\.brotliDecompress|zlib\.createGunzip|zlib\.createInflate|zlib\.createUnzip|createBrotliDecompress|decompress|decompressSync|gunzip|ungzip|inflate|inflateRaw|unzip|extract|tar\.extract|tar\.x|untar|archiver|adm.?zip|yauzl|yazl|node.?unzip|unzipper|pako\.inflate|pako\.ungzip|lz4\.decode|snappy\.uncompress|brotli\.decompress|ZipFile|ZipInputStream|GZIPInputStream|Inflater|DeflaterInputStream|zipfile\.ZipFile|gzip\.open|gzip\.decompress|bz2\.decompress|lzma\.decompress|zstandard|zstd\.decompress|7z|unrar|libarchive)\b/i;
  // Safe patterns — output size bounded
  const DECOMPRESS_SAFE = /\b(maxSize|MAX_SIZE|maxOutputSize|maxDecompressedSize|maxLength|MAX_LENGTH|sizeLimit|SIZE_LIMIT|outputLimit|maxBytes|MAX_BYTES|ratio|compressionRatio|COMPRESSION_RATIO|maxRatio|MAX_RATIO|bytesWritten|totalSize|totalBytes|AbortController|highWaterMark|limit|LIMIT|quota|QUOTA)\b/i;

  // Check all nodes for decompression operations
  const decompressNodes = map.nodes.filter(n =>
    DECOMPRESS_PATTERN.test(stripComments(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const sink of decompressNodes) {
      const bfsHit409 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const scopeHit409 = !bfsHit409 && sharesFunctionScope(map, src.id, sink.id);
      if (!bfsHit409 && !scopeHit409) continue;

      const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      const containingFunc = findContainingFunction(map, sink.id);
      const funcCode = containingFunc
        ? stripComments(map.nodes.find(n => n.id === containingFunc)?.analysis_snapshot || map.nodes.find(n => n.id === containingFunc)?.code_snapshot || '')
        : '';
      const allCode = code + ' ' + funcCode;

      if (!DECOMPRESS_SAFE.test(allCode)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'CONTROL (decompressed output size limit)',
          severity: 'high',
          description: `User-supplied compressed data from ${src.label} is decompressed at ${sink.label} without output size limits. ` +
            `A decompression bomb (zip bomb) — a few kilobytes of compressed data expanding to gigabytes — ` +
            `can exhaust server memory or disk, causing denial of service.`,
          fix: 'Set a maximum decompressed output size and abort if exceeded. ' +
            'Stream decompression with a byte counter that aborts on threshold. ' +
            'Check the compression ratio — legitimate data rarely exceeds 100:1. ' +
            'For zip archives: limit total extracted size AND number of entries. ' +
            'Use streaming decompression with highWaterMark/backpressure rather than buffering entire output.',
          via: bfsHit409 ? 'bfs' : 'scope_taint',
        });
      }
    }
  }

  return { cwe: 'CWE-409', name: 'Improper Handling of Highly Compressed Data', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-459: Incomplete Cleanup
// ---------------------------------------------------------------------------

/**
 * CWE-459: Incomplete Cleanup
 * Detects resources, sensitive data, or temporary state that is not fully cleaned up.
 * Broader than CWE-404 (which focuses on release/close): this covers sensitive data
 * left in memory, temp files not deleted, session state not cleared, caches not
 * invalidated, and partial cleanup that misses some resources.
 *
 * Detection: Scans for sensitive data handling, temp file creation, and session/cache
 * operations without corresponding cleanup in the same scope.
 */

// ---------------------------------------------------------------------------
// CWE-410: Insufficient Resource Pool
// ---------------------------------------------------------------------------

/**
 * CWE-410: Insufficient Resource Pool
 * Detects resource pools (connection pools, thread pools, worker pools) that
 * are accessed from INGRESS paths without adequate pool sizing or overflow
 * handling. A small fixed pool under high concurrency leads to blocking/DoS.
 *
 * Detection: RESOURCE nodes with pool-related subtypes/code reachable from
 * INGRESS without evidence of pool sizing, queue limits, or timeout on acquire.
 */
function verifyCWE410(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const resources = nodesOfType(map, 'RESOURCE');

  const POOL_PATTERN = /\b(pool|Pool|createPool|ConnectionPool|ThreadPool|WorkerPool|FixedThreadPool|Executor|GenericObjectPool|jedisPool|hikari|c3p0|dbcp|pgPool|knex|sequelize\.pool|typeorm.*pool|drizzle.*pool)\b/i;
  const POOL_CONFIG_SAFE = /\b(max|maxSize|maximumPoolSize|maxTotal|maxWaitMillis|maxIdleTime|connectionLimit|pool\s*[:=]\s*\{[^}]*max|queueLimit|waitForConnections|acquireTimeout|idleTimeout|maxWait|overflow|grow|elastic|dynamic|auto.?scale)\b/i;
  const TIMEOUT_SAFE = /\b(timeout|Timeout|waitTimeout|acquireTimeoutMillis|connectionTimeout|getConnectionTimeout|borrowMaxWait)\b/i;

  for (const src of ingress) {
    for (const res of resources) {
      if (!POOL_PATTERN.test(res.analysis_snapshot || res.code_snapshot) && !res.node_subtype.includes('pool') && !res.node_subtype.includes('connections')) continue;

      const bfsHit410 = hasTaintedPathWithoutControl(map, src.id, res.id);
      const scopeHit410 = !bfsHit410 && sharesFunctionScope(map, src.id, res.id);
      if (!bfsHit410 && !scopeHit410) continue;

      const code = stripComments(res.analysis_snapshot || res.code_snapshot);
      const containingFunc = findContainingFunction(map, res.id);
      const funcCode = containingFunc
        ? stripComments(map.nodes.find(n => n.id === containingFunc)?.analysis_snapshot || map.nodes.find(n => n.id === containingFunc)?.code_snapshot || '')
        : '';
      const allCode = code + ' ' + funcCode;

      const hasPoolConfig = POOL_CONFIG_SAFE.test(allCode);
      const hasTimeout = TIMEOUT_SAFE.test(allCode);

      if (!hasPoolConfig && !hasTimeout) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(res),
          missing: 'CONTROL (pool sizing configuration and acquire timeout)',
          severity: 'medium',
          description: `Resource pool at ${res.label} is reachable from ${src.label} without pool size limits or acquire timeouts. ` +
            `Under load, all pool slots fill and subsequent requests block indefinitely, causing denial of service.`,
          fix: 'Configure pool with explicit max size, acquire timeout, and queue/overflow limits. ' +
            'For DB pools: set max connections, connectionTimeout, idleTimeout. ' +
            'For thread pools: use bounded pools with rejection policies. ' +
            'Always set an acquire timeout to fail fast when pool is exhausted.',
          via: bfsHit410 ? 'bfs' : 'scope_taint',
        });
      }
    }
  }

  return { cwe: 'CWE-410', name: 'Insufficient Resource Pool', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-662: Improper Synchronization
// ---------------------------------------------------------------------------

/**
 * CWE-662: Improper Synchronization
 * Detects shared state accessed from concurrent contexts (async handlers,
 * threads, goroutines) without proper synchronization primitives.
 *
 * Broader than CWE-362 (race condition on files) — this covers ANY shared
 * mutable state: module-level variables, class fields, global caches, etc.
 * Specifically looks for WRITE operations to shared state from multiple
 * concurrent entry points without locks/atomics.
 */

// ---------------------------------------------------------------------------
// Race Conditions
// ---------------------------------------------------------------------------

/* REMOVED: verifyCWE862 -- now in auth.ts */

/* REMOVED: verifyCWE863 -- now in auth.ts */

// ---------------------------------------------------------------------------
// Concurrency, Temp File, and Search Path CWEs
// ---------------------------------------------------------------------------

/**
 * CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization ('Race Condition')
 *
 * Covers two major patterns:
 * 1. TOCTOU: check-then-act on filesystem/resources (existsSync → writeFileSync)
 * 2. Shared-state races: shared/global mutable state accessed without synchronization
 *
 * True race conditions are hard to detect statically, but we flag the most
 * common code-level indicators.
 */
function verifyCWE362(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // --- Pattern 1: TOCTOU (check-then-act on external resources) ---
  const CHECK_PATTERN = /\b(exists|access|stat|lstat|fstat|isFile|isDirectory|os\.path\.exists|os\.path\.isfile|os\.access|File\.exists|Files\.exists|fs\.existsSync|fs\.accessSync|fs\.statSync|Path\.exists|test\s+-[efdrwx])\b/i;
  const USE_PATTERN = /\b(open|read|write|readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|unlink|rename|chmod|chown|mkdir|rmdir|fopen|fread|fwrite|file_get_contents|file_put_contents|File\.open|File\.read|Files\.read|Files\.write|os\.open|os\.remove|os\.rename|shutil)\b/i;
  const TOCTOU_SAFE = /\b(O_CREAT|O_EXCL|LOCK_EX|flock|lockf|fcntl|FileLock|atomic|rename.*tmp|mkstemp|tmpfile|NamedTemporaryFile|openat|AT_FDCWD)\b/i;

  const checkNodes = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'TRANSFORM') &&
    CHECK_PATTERN.test(n.analysis_snapshot || n.code_snapshot)
  );
  const useNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    USE_PATTERN.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const check of checkNodes) {
    for (const use of useNodes) {
      if (check.id === use.id) continue;
      // Check must flow to use, or share scope with check before use
      const edgeHit362 = check.edges.some(e => e.target === use.id);
      const scopeHit362 = !edgeHit362 && sharesFunctionScope(map, check.id, use.id);
      if (edgeHit362 || scopeHit362) {
        const allCode = stripComments(check.analysis_snapshot || check.code_snapshot + ' ' + use.code_snapshot);
        if (!TOCTOU_SAFE.test(allCode)) {
          findings.push({
            source: nodeRef(check), sink: nodeRef(use),
            missing: 'CONTROL (atomic check-and-use — O_CREAT|O_EXCL, flock, or lock)',
            severity: 'medium',
            description: `TOCTOU: check at ${check.label} then use at ${use.label}. Resource state can change between check and use, creating a race window.`,
            fix: 'Use atomic operations: open() with O_CREAT|O_EXCL, flock() for locking, or try/catch with specific error codes instead of check-then-act.',
            via: edgeHit362 ? 'bfs' : 'scope_taint',
          });
        }
      }
    }
  }

  // --- Pattern 2: Shared mutable state without synchronization ---
  const sharedState = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('global') || n.node_subtype.includes('shared') ||
     n.node_subtype.includes('module') || n.node_subtype.includes('static') ||
     n.node_subtype.includes('class_field') ||
     n.attack_surface.includes('shared_state') || n.attack_surface.includes('shared_resource') ||
     /\b(global\.|module\.\w+\s*=|self\.\w+\s*=|cls\.\w+\s*=|static\s+\w+|volatile\b|shared_?state|instance\.\w+\s*[+\-*/]?=)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  const concurrentSources = map.nodes.filter(n =>
    n.id !== '' &&
    (n.node_type === 'INGRESS' || n.node_type === 'STRUCTURAL' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('handler') || n.node_subtype.includes('endpoint') ||
     n.node_subtype.includes('async') || n.node_subtype.includes('thread') ||
     n.node_subtype.includes('worker') || n.node_subtype.includes('task') ||
     n.node_subtype.includes('shared') || n.node_subtype.includes('concurrent') ||
     n.attack_surface.includes('shared_resource') ||
     /\b(async\s+def|async\s+function|@app\.(get|post|put|delete|route)|router\.(get|post|put|delete)|Thread|threading|goroutine|go\s+func|spawn|tokio::spawn|Promise\.all|Worker)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  const SYNC_SAFE = /\b(mutex|lock|synchronized|atomic|Atomic|semaphore|RwLock|Mutex|Lock|acquire|threading\.Lock|asyncio\.Lock|sync\.Mutex|sync\.RWMutex|ConcurrentHashMap|AtomicInteger|AtomicReference|compareAndSet|channel|Chan|select\s*\{|transaction|BEGIN|COMMIT|\.transaction\(|trx\.|knex\.transaction)\b/i;

  for (const src of concurrentSources) {
    for (const shared of sharedState) {
      if (src.id === shared.id) continue;
      const edgeHit362b = src.edges.some(e => e.target === shared.id);
      const bfsHit362b = !edgeHit362b && hasTaintedPathWithoutControl(map, src.id, shared.id);
      const scopeHit362b = !edgeHit362b && !bfsHit362b && sharesFunctionScope(map, src.id, shared.id);
      if (edgeHit362b || bfsHit362b || scopeHit362b) {
        const allCode = stripComments(
          (src.analysis_snapshot || src.code_snapshot) + ' ' + (shared.analysis_snapshot || shared.code_snapshot) + ' ' +
          nodesOfType(map, 'CONTROL').filter(c => sharesFunctionScope(map, c.id, shared.id)).map(c => c.analysis_snapshot || c.code_snapshot).join(' ')
        );
        if (!SYNC_SAFE.test(allCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(shared),
            missing: 'CONTROL (synchronization primitive — mutex, lock, or atomic operation)',
            severity: 'medium',
            description: `Shared state ${shared.label} accessed from ${src.label} without synchronization. Concurrent access can corrupt data.`,
            fix: 'Protect shared state with a mutex/lock, use atomic operations, or move state to request-scoped storage (DB transaction, local variable).',
            via: edgeHit362b || bfsHit362b ? 'bfs' : 'scope_taint',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-362', name: 'Race Condition', holds: findings.length === 0, findings };
}

/**
 * CWE-366: Race Condition Within a Thread
 *
 * Variant of CWE-362 focused on intra-thread races: multiple non-atomic
 * read-modify-write sequences on the same variable in async code (e.g.,
 * `count = count + 1` across await boundaries).
 */

/**
 * CWE-366: Race Condition Within a Thread
 *
 * Variant of CWE-362 focused on intra-thread races: multiple non-atomic
 * read-modify-write sequences on the same variable in async code (e.g.,
 * `count = count + 1` across await boundaries).
 */
function verifyCWE366(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const RMW_PATTERN = /(\w+)\s*=\s*\1\s*[+\-*/]|(\w+)\s*[+\-*/]=|\+\+\w|\w\+\+|--\w|\w--/i;
  const ASYNC_CONTEXT = /\b(async\s|await\s|yield\s|\.then\(|Promise|goroutine|go\s+func|spawn|tokio|CompletableFuture|Task\.Run)\b/i;
  const ATOMIC_SAFE = /\b(atomic|Atomic|Interlocked|compareAndSet|compareAndSwap|synchronized|lock|mutex|Mutex)\b/i;

  const asyncNodes = map.nodes.filter(n =>
    ASYNC_CONTEXT.test(n.analysis_snapshot || n.code_snapshot) &&
    (n.node_type === 'STRUCTURAL' || n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE')
  );
  const storageNodes = map.nodes.filter(n =>
    n.node_type === 'STORAGE' && RMW_PATTERN.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const async of asyncNodes) {
    for (const store of storageNodes) {
      if (async.id === store.id) continue;
      if (sharesFunctionScope(map, async.id, store.id)) {
        const code = stripComments(async.analysis_snapshot || async.code_snapshot + ' ' + store.code_snapshot);
        if (RMW_PATTERN.test(code) && !ATOMIC_SAFE.test(code)) {
          findings.push({
            source: nodeRef(async), sink: nodeRef(store),
            missing: 'CONTROL (atomic read-modify-write or lock around async boundary)',
            severity: 'medium',
            description: `Non-atomic read-modify-write on ${store.label} inside async context ${async.label}. Interleaving across await points can cause lost updates.`,
            fix: 'Use atomic operations (AtomicInteger, Interlocked.Increment), or hold a lock across the entire read-modify-write sequence. Avoid splitting read and write across await.',
            via: 'scope_taint',
          });
          break;
        }
      }
    }
  }
  return { cwe: 'CWE-366', name: 'Race Condition Within a Thread', holds: findings.length === 0, findings };
}

/**
 * CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
 *
 * Detects check-then-act patterns on external resources (files, DB rows)
 * where the resource state can change between the check and the use.
 * Classic pattern: if (file.exists()) { read(file) }.
 */

/**
 * CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
 *
 * Detects check-then-act patterns on external resources (files, DB rows)
 * where the resource state can change between the check and the use.
 * Classic pattern: if (file.exists()) { read(file) }.
 */
function verifyCWE367(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CHECK_PATTERN = /\b(exists|access|stat|lstat|fstat|isFile|isDirectory|os\.path\.exists|os\.path\.isfile|os\.access|File\.exists|Files\.exists|File\.readable|File\.writable|fs\.existsSync|fs\.accessSync|fs\.statSync|Path\.exists|test\s+-[efdrwx])\b/i;
  const USE_PATTERN = /\b(open|read|write|readFile|writeFile|createReadStream|createWriteStream|unlink|rename|chmod|chown|mkdir|rmdir|fopen|fread|fwrite|file_get_contents|file_put_contents|File\.open|File\.read|Files\.read|Files\.write|os\.open|os\.remove|os\.rename|shutil)\b/i;
  const TOCTOU_SAFE = /\b(O_CREAT|O_EXCL|LOCK_EX|flock|lockf|fcntl|FileLock|atomic|rename.*tmp|mkstemp|tmpfile|NamedTemporaryFile|openat|AT_FDCWD|try.*catch|ENOENT|EEXIST)\b/i;

  const checkNodes = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'TRANSFORM') &&
    CHECK_PATTERN.test(n.analysis_snapshot || n.code_snapshot)
  );
  const useNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    USE_PATTERN.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const check of checkNodes) {
    for (const use of useNodes) {
      if (check.id === use.id) continue;
      // Check must come before use in the same scope
      if (sharesFunctionScope(map, check.id, use.id) && check.line_start < use.line_start) {
        const allCode = stripComments(check.analysis_snapshot || check.code_snapshot + ' ' + use.code_snapshot);
        // Both must reference filesystem operations
        if (CHECK_PATTERN.test(check.analysis_snapshot || check.code_snapshot) && USE_PATTERN.test(use.analysis_snapshot || use.code_snapshot) && !TOCTOU_SAFE.test(allCode)) {
          findings.push({
            source: nodeRef(check), sink: nodeRef(use),
            missing: 'CONTROL (atomic check-and-use — O_CREAT|O_EXCL, flock, or try/catch on ENOENT)',
            severity: 'medium',
            description: `Check at ${check.label} (line ${check.line_start}) followed by use at ${use.label} (line ${use.line_start}). File state can change between check and use.`,
            fix: 'Use atomic operations: open() with O_CREAT|O_EXCL, flock() for locking, or try/catch with specific error codes (ENOENT/EEXIST) instead of check-then-act.',
            via: 'scope_taint',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-367', name: 'TOCTOU Race Condition', holds: findings.length === 0, findings };
}

/**
 * CWE-377: Insecure Temporary File
 *
 * Detects creation of temporary files using predictable names or insecure methods.
 * Attackers can predict the filename and pre-create symlinks to hijack writes.
 */

/* REMOVED: verifyCWE351 -- now in auth.ts */

/* REMOVED: verifyCWE355 -- now in auth.ts */

/* REMOVED: verifyCWE357 -- now in auth.ts */

/* REMOVED: verifyCWE358 -- now in auth.ts */

/* REMOVED: verifyCWE360 -- now in auth.ts */

// ---------------------------------------------------------------------------
// Race conditions & object mutability CWEs (363, 364, 365, 368, 370, 372, 374, 375, 385, 386)
// ---------------------------------------------------------------------------

/**
 * CWE-363: Race Condition Enabling Link Following
 *
 * A race between checking a file path and using it allows an attacker to replace
 * the target with a symlink between the check and use (symlink TOCTOU).
 * Classic: stat(path) -> open(path), attacker replaces path with symlink in the gap.
 */
function verifyCWE363(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const LINK_CHECK_RE = /\b(lstat|readlink|isSymbolicLink|is_symlink|islink|os\.path\.islink|Files\.isSymbolicLink|File\.symlink\?|Path\.is_symlink|realpath|os\.path\.realpath|fs\.realpathSync|fs\.realpath|Path\.toRealPath|File\.getCanonicalPath)\b/i;
  const FILE_USE_RE = /\b(open|read|write|readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|unlink|rename|chmod|chown|fopen|fread|fwrite|file_get_contents|file_put_contents|File\.open|File\.read|Files\.read|Files\.write|os\.open|os\.remove|os\.rename|shutil|exec|execSync|spawn|child_process)\b/i;
  const SAFE_LINK_RE = /\b(O_NOFOLLOW|AT_SYMLINK_NOFOLLOW|openat|AT_FDCWD|LOCK_EX|flock|O_CREAT\s*\|\s*O_EXCL|lchmod|lchown|File\.open.*nofollow|no_follow|NOFOLLOW|chroot|securedir|safepath)\b/i;

  const checkNodes = map.nodes.filter(n =>
    (n.node_type === 'CONTROL' || n.node_type === 'TRANSFORM') &&
    LINK_CHECK_RE.test(n.analysis_snapshot || n.code_snapshot)
  );
  const useNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    FILE_USE_RE.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const check of checkNodes) {
    for (const use of useNodes) {
      if (check.id === use.id) continue;
      if (sharesFunctionScope(map, check.id, use.id) && check.line_start < use.line_start) {
        const allCode = stripComments(check.analysis_snapshot || check.code_snapshot + ' ' + use.code_snapshot);
        if (!SAFE_LINK_RE.test(allCode)) {
          findings.push({
            source: nodeRef(check), sink: nodeRef(use),
            missing: 'CONTROL (O_NOFOLLOW, openat, or atomic link-safe file access)',
            severity: 'medium',
            description: `Symlink check at ${check.label} (line ${check.line_start}) followed by file use at ${use.label} (line ${use.line_start}). ` +
              `An attacker can replace the target with a symlink between the check and use, redirecting the operation to an arbitrary file.`,
            fix: 'Use O_NOFOLLOW flag with open(), openat() with AT_FDCWD for directory-relative access, or operate on file descriptors ' +
              'obtained during the check rather than re-resolving the path. Avoid separate check-then-use on symlink status.',
            via: 'scope_taint',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-363', name: 'Race Condition Enabling Link Following', holds: findings.length === 0, findings };
}

/**
 * CWE-364: Signal Handler Race Condition
 *
 * Signal handlers that access shared state or call non-async-signal-safe functions
 * create races because signals can interrupt any instruction. If a signal handler
 * modifies a global that the main code also uses, the result is undefined.
 */

/**
 * CWE-364: Signal Handler Race Condition
 *
 * Signal handlers that access shared state or call non-async-signal-safe functions
 * create races because signals can interrupt any instruction. If a signal handler
 * modifies a global that the main code also uses, the result is undefined.
 */
function verifyCWE364(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SIGNAL_HANDLER_RE = /\b(signal\s*\(|sigaction\s*\(|SignalHandler|SIG[A-Z]+|SIGINT|SIGTERM|SIGHUP|SIGALRM|SIGUSR[12]|process\.on\s*\(\s*['"]SIG|trap\s+['"]?[A-Z]+|Signal\.trap|atexit|on_exit|register_shutdown_function)\b/;
  const UNSAFE_IN_HANDLER_RE = /\b(printf|fprintf|sprintf|snprintf|malloc|free|calloc|realloc|new\s|delete\s|exit\s*\(|_exit|abort|fopen|fclose|fread|fwrite|fflush|puts|fputs|gets|fgets|syslog|openlog|strtok|localtime|gmtime|ctime|asctime|setlocale|longjmp|throw\s|raise\s*\(|pthread_|mutex_|lock|errno\s*=|strerror)\b/;
  const SHARED_STATE_RE = /\b(global|static\s+\w+\s*[=;]|volatile|extern\s|module\.\w+\s*=|self\.\w+\s*=|@@\w+|shared_state|g_\w+)\b/i;
  const SAFE_SIGNAL_RE = /\b(sig_atomic_t|volatile\s+sig_atomic_t|signalfd|sigwaitinfo|sigtimedwait|sigwait|eventfd|pipe\s*\(|self_pipe|write\s*\(\s*\w+_fd|SA_RESTART|SA_SIGINFO|sigprocmask|pthread_sigmask|blocked_signals|sigfillset|sigemptyset)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!SIGNAL_HANDLER_RE.test(code)) continue;

    if (UNSAFE_IN_HANDLER_RE.test(code) && !SAFE_SIGNAL_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (async-signal-safe functions only in signal handler)',
        severity: 'high',
        description: `Signal handler at ${node.label} calls non-async-signal-safe functions (malloc, printf, etc.). ` +
          `Signals can interrupt at any point; calling non-reentrant functions from a handler causes undefined behavior, ` +
          `including deadlocks (e.g., malloc holds a lock, signal fires, handler calls malloc again).`,
        fix: 'In signal handlers, only call async-signal-safe functions (write(), _exit(), sig_atomic_t flag set). ' +
          'Use the self-pipe trick or signalfd() to defer processing to the main loop. ' +
          'Set a volatile sig_atomic_t flag in the handler and check it in the main code.',
        via: 'structural',
      });
    }

    if (SHARED_STATE_RE.test(code) && !SAFE_SIGNAL_RE.test(code)) {
      if (!/\bsig_atomic_t\b/.test(code) && !/\bvolatile\b/.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (volatile sig_atomic_t for signal handler shared state)',
          severity: 'high',
          description: `Signal handler at ${node.label} accesses shared state without volatile sig_atomic_t. ` +
            `The compiler may optimize away reads/writes, and the signal can corrupt multi-word variables ` +
            `by interrupting a partial write.`,
          fix: 'Use volatile sig_atomic_t for any state shared between signal handlers and main code. ' +
            'For complex shared data, block signals with sigprocmask() during critical sections, or ' +
            'use signalfd()/self-pipe to convert signals into I/O events handled synchronously.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-364', name: 'Signal Handler Race Condition', holds: findings.length === 0, findings };
}

/**
 * CWE-365: TOCTOU Race Condition in Switch
 *
 * A value read from a volatile source (user input, shared memory, file) is used in a
 * switch statement, but the source can change between the read and the switch dispatch.
 * The switch may enter one case but execute with data from a different state.
 */

/**
 * CWE-365: TOCTOU Race Condition in Switch
 *
 * A value read from a volatile source (user input, shared memory, file) is used in a
 * switch statement, but the source can change between the read and the switch dispatch.
 * The switch may enter one case but execute with data from a different state.
 */
function verifyCWE365(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const VOLATILE_SOURCE_RE = /\b(req\.\w+|request\.\w+|params\.\w+|query\.\w+|body\.\w+|args\.\w+|getParameter|getAttribute|getHeader|environ\.\w+|os\.environ|System\.getenv|getenv|shared_\w+|volatile\s+\w+|global\.\w+|process\.env)\b/i;
  const SWITCH_RE = /\b(switch\s*\(|match\s+|case\s+.*when\s|if\s*\(.*===?\s*['"]\w+['"]\s*\)\s*\{[\s\S]*?else\s+if\s*\(.*===?\s*['"]\w+['"]\s*\))/i;
  const CACHED_LOCAL_RE = /\b(const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=|final\s+\w+\s+\w+\s*=|val\s+\w+\s*=)\s*(?:req\.|request\.|params\.|query\.|body\.|getParameter|getAttribute|getHeader|environ|getenv)/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!SWITCH_RE.test(code)) continue;
    if (!VOLATILE_SOURCE_RE.test(code)) continue;

    if (!CACHED_LOCAL_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (snapshot volatile value into local before switch dispatch)',
        severity: 'low',
        description: `Switch/match at ${node.label} reads directly from a volatile source (request params, env, shared state). ` +
          `If the source changes between case evaluation and case body execution, the program can enter ` +
          `an inconsistent state — dispatching on one value but operating on another.`,
        fix: 'Cache the value in a local const/final variable before the switch: ' +
          'const action = req.body.action; switch(action) { ... }. This ensures the dispatched value ' +
          'matches the value used inside the case body.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-365', name: 'TOCTOU Race Condition in Switch', holds: findings.length === 0, findings };
}

/**
 * CWE-368: Context Switching Race Condition
 *
 * Critical sections that assume atomic execution but can be preempted by context
 * switches. Typically: non-atomic check-then-act on shared resources in multi-threaded
 * or multi-process environments without proper locking.
 */

/**
 * CWE-368: Context Switching Race Condition
 *
 * Critical sections that assume atomic execution but can be preempted by context
 * switches. Typically: non-atomic check-then-act on shared resources in multi-threaded
 * or multi-process environments without proper locking.
 */
function verifyCWE368(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const SHARED_RESOURCE_RE = /\b(shared_\w+|global_\w+|static\s+\w+|volatile\s+\w+|class_?\w*\s*\.\s*\w+|module\.\w+\s*=|self\.\w+\s*=|@@\w+|g_\w+|instance\.\w+)\b/i;
  const CHECK_ACT_RE = /\bif\s*\([^)]*(?:shared|global|static|volatile|count|size|len|length|balance|stock|available|remaining|capacity|quota|limit)\b[^)]*\)\s*\{[^}]*(?:shared|global|static|volatile|count|size|len|length|balance|stock|available|remaining|capacity|quota|limit)\b[^}]*(?:\+=|-=|=\s*\w+|--|\+\+)/i;
  const RMW_SHARED_RE = /(?:shared|global|static|volatile|g_)\w*\s*=\s*(?:shared|global|static|volatile|g_)\w*\s*[+\-*/]|(?:count|balance|stock|available)\s*=\s*(?:count|balance|stock|available)\s*[+\-]/i;
  const SYNC_SAFE = /\b(mutex|lock|synchronized|atomic|Atomic|semaphore|RwLock|Mutex|Lock|acquire|threading\.Lock|asyncio\.Lock|sync\.Mutex|sync\.RWMutex|ConcurrentHashMap|AtomicInteger|AtomicReference|compareAndSet|compareAndSwap|Interlocked|transaction|SERIALIZABLE|BEGIN|COMMIT|\.transaction\(|flock|LOCK_EX|critical_section|EnterCriticalSection|monitor\.enter)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if ((CHECK_ACT_RE.test(code) || RMW_SHARED_RE.test(code)) && SHARED_RESOURCE_RE.test(code)) {
      if (!SYNC_SAFE.test(code)) {
        const scopeNodes = map.nodes.filter(n =>
          n.node_type === 'CONTROL' &&
          sharesFunctionScope(map, n.id, node.id) &&
          SYNC_SAFE.test(n.analysis_snapshot || n.code_snapshot)
        );
        if (scopeNodes.length === 0) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (mutex/lock/atomic around check-then-act on shared state)',
            severity: 'medium',
            description: `Check-then-act on shared resource at ${node.label} without synchronization. ` +
              `A context switch between the check and the modification can cause lost updates, ` +
              `double-spend, or negative-balance bugs (e.g., two threads both see balance=100, both deduct).`,
            fix: 'Wrap the entire check-then-act in a mutex/lock, use atomic compare-and-swap (CAS), ' +
              'or use database-level SERIALIZABLE transactions. The check and the modification must be indivisible.',
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-368', name: 'Context Switching Race Condition', holds: findings.length === 0, findings };
}

/**
 * CWE-370: Missing Check for Certificate Revocation After Initial Check
 *
 * TLS/certificate validation that checks validity at connection time but never
 * rechecks revocation status for long-lived connections. OCSP stapling or CRL
 * checks must be periodic, not just at handshake.
 */

// ---------------------------------------------------------------------------
// Temp File Races
// ---------------------------------------------------------------------------

/**
 * CWE-377: Insecure Temporary File
 *
 * Detects creation of temporary files using predictable names or insecure methods.
 * Attackers can predict the filename and pre-create symlinks to hijack writes.
 */
function verifyCWE377(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const INSECURE_TEMP = /\b(tmpnam|tempnam|mktemp[^s]|tmpfile\(\)|tempfile\.mktemp|File\.createTempFile|System\.IO\.Path\.GetTempFileName)\b|\/tmp\/[a-zA-Z_]+[^/\s]*|\\temp\\[a-zA-Z_]+[^/\\\s]*/i;
  const PREDICTABLE_NAME = /["'`](\/tmp\/|\\temp\\|\/var\/tmp\/|C:\\Temp\\)[a-zA-Z0-9_.\-]+["'`]/i;
  const SAFE_TEMP = /\b(mkstemp|mkdtemp|NamedTemporaryFile|TemporaryDirectory|tempfile\.(mkstemp|mkdtemp|NamedTemporaryFile|TemporaryDirectory|SpooledTemporaryFile)|tmpdir|fs\.mkdtemp|os\.tmpdir|SecureRandom|UUID\.randomUUID|crypto\.randomUUID|crypto\.randomBytes)\b/i;

  const allNodes = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM'
  );
  for (const node of allNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if ((INSECURE_TEMP.test(code) || PREDICTABLE_NAME.test(code)) && !SAFE_TEMP.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (secure temp file creation — mkstemp, NamedTemporaryFile, or crypto-random name)',
        severity: 'medium',
        description: `Insecure temporary file usage at ${node.label}. Predictable temp filenames enable symlink attacks and file hijacking.`,
        fix: 'Use mkstemp() (C), tempfile.NamedTemporaryFile (Python), fs.mkdtemp (Node.js), or Files.createTempFile (Java) which create files with random names and secure permissions.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-377', name: 'Insecure Temporary File', holds: findings.length === 0, findings };
}

/**
 * CWE-378: Creation of Temporary File With Insecure Permissions
 *
 * Temp files created with overly permissive modes (world-readable/writable),
 * OR temp files created without ANY permission-setting calls afterward.
 * The Juliet pattern: File.createTempFile() without setReadable/setWritable.
 */

/**
 * CWE-378: Creation of Temporary File With Insecure Permissions
 *
 * Temp files created with overly permissive modes (world-readable/writable),
 * OR temp files created without ANY permission-setting calls afterward.
 * The Juliet pattern: File.createTempFile() without setReadable/setWritable.
 */
function verifyCWE378(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const TEMP_CREATE = /\b(mkstemp|mkdtemp|tempfile|tmpfile|createTempFile|GetTempFileName|NamedTemporaryFile|TemporaryFile|fs\.mkdtemp|os\.tmpdir|tmp\.file|tmp\.dir)\b/i;
  const INSECURE_PERMS = /\b(0o?777|0o?766|0o?755|0o?666|0o?664|0o?644|chmod\s*\(\s*[^,]+,\s*0o?7|umask\s*\(\s*0+\s*\)|world.?read|world.?writ|S_IROTH|S_IWOTH|FileMode\s*\(\s*0o?[67])/i;
  const SAFE_PERMS = /\b(0o?600|0o?700|0o?400|0o?500|S_IRUSR|S_IWUSR|owner.?only|FileAttribute|PosixFilePermission.*OWNER|mode\s*=\s*0o?[0-6]00)\b/i;
  // Java/general: setReadable/setWritable/setExecutable calls = permission management
  const PERM_SETTER = /\bset(?:Readable|Writable|Executable)\s*\(/i;

  const allNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    TEMP_CREATE.test(n.analysis_snapshot || n.code_snapshot)
  );
  for (const node of allNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Strategy 1: Explicit insecure permissions set on temp file
    if (INSECURE_PERMS.test(code) && !SAFE_PERMS.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (restrictive file permissions — 0600 or 0700)',
        severity: 'medium',
        description: `Temporary file at ${node.label} created with overly permissive permissions. Other users on the system can read or modify it.`,
        fix: 'Set permissions to 0600 (owner read/write only) or 0700 (owner only). Use umask(0077) before creation. In Python, use NamedTemporaryFile which defaults to 0600.',
        via: 'structural',
      });
      continue;
    }

    // Strategy 2: createTempFile with NO permission-setting calls in same function scope
    // (Juliet CWE-378 pattern: File.createTempFile() without setReadable/setWritable)
    if (SAFE_PERMS.test(code) || PERM_SETTER.test(code)) continue;

    // Check sibling nodes in the same function scope for permission-setting calls
    const siblingNodes = map.nodes.filter(sib =>
      sib.id !== node.id && sharesFunctionScope(map, node.id, sib.id)
    );
    const siblingCode = siblingNodes.map(sib =>
      stripComments(sib.analysis_snapshot || sib.code_snapshot)
    ).join('\n');
    const hasScopePerms = SAFE_PERMS.test(siblingCode) || PERM_SETTER.test(siblingCode);

    if (!hasScopePerms) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (file permissions never set after temp file creation)',
        severity: 'medium',
        description: `Temporary file at ${node.label} created without any permission-setting calls. ` +
          `Default permissions may allow other users on the system to read or modify it.`,
        fix: 'After creating the temp file, call setReadable(true, true), setWritable(true, true), and setExecutable(false) ' +
          'to restrict to owner-only. Or use Files.createTempFile with PosixFilePermissions, or set umask(0077) before creation.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-378', name: 'Temp File With Insecure Permissions', holds: findings.length === 0, findings };
}

/**
 * CWE-379: Creation of Temporary File in Directory with Insecure Permissions
 *
 * Even a securely-created temp file is vulnerable if it lives in a directory
 * where other users can create/delete files (enabling rename/symlink attacks).
 */

/**
 * CWE-379: Creation of Temporary File in Directory with Insecure Permissions
 *
 * Even a securely-created temp file is vulnerable if it lives in a directory
 * where other users can create/delete files (enabling rename/symlink attacks).
 */
function verifyCWE379(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const INSECURE_DIR = /["'`](\/tmp\/|\/var\/tmp\/|\\temp\\|C:\\Windows\\Temp|\/dev\/shm\/|System\.IO\.Path\.GetTempPath)\b/i;
  const HARDCODED_DIR = /["'`](\/tmp|\/var\/tmp|\\temp|C:\\Temp|C:\\Windows\\Temp)["'`]/i;
  const SAFE_DIR = /\b(mkdtemp|TemporaryDirectory|tempDir.*mode.*0o?700|private.*tmp|app.?data|XDG_RUNTIME_DIR|user.?specific|per.?user)\b/i;
  // Java: 2-arg createTempFile uses default (insecure) temp dir; 3-arg passes explicit dir
  const TWO_ARG_CREATE_TEMP = /\bcreate[Tt]emp[Ff]ile\s*\(\s*(?:"[^"]*"|'[^']*'|\w+)\s*,\s*(?:"[^"]*"|'[^']*'|\w+)\s*\)/;
  const DIR_PERM_SETTER = /\bset(?:Readable|Writable|Executable)\s*\(/i;

  const allNodes = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM')
  );
  for (const node of allNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Strategy 1: Hardcoded insecure directories
    if ((INSECURE_DIR.test(code) || HARDCODED_DIR.test(code)) && !SAFE_DIR.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use per-user temp directory or mkdtemp with restrictive permissions)',
        severity: 'low',
        description: `File operation at ${node.label} uses a shared temp directory. Other users can manipulate files via symlink or race attacks.`,
        fix: 'Use mkdtemp() to create a private subdirectory, or use XDG_RUNTIME_DIR / app-specific directories. Set sticky bit is not sufficient — use per-user dirs.',
        via: 'structural',
      });
      continue;
    }

    // Strategy 2: Java 2-arg createTempFile (uses system default temp dir)
    if (TWO_ARG_CREATE_TEMP.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (secure directory argument for temp file creation)',
        severity: 'medium',
        description: `Temporary file at ${node.label} created with 2-arg createTempFile, which uses the system ` +
          `default temp directory. This directory is shared and other users may manipulate files via symlink or race attacks.`,
        fix: 'Use the 3-arg form File.createTempFile(prefix, suffix, secureDir) with a directory that has owner-only permissions, ' +
          'or use Files.createTempFile(dir, prefix, suffix, attrs) with PosixFilePermissions.',
        via: 'structural',
      });
      continue;
    }
  }

  // Strategy 3: mkdir()/mkdirs() without permission-setting on directory, before createTempFile
  const mkdirNodes = map.nodes.filter(n => {
    const c = n.analysis_snapshot || n.code_snapshot;
    return /\b(?:mkdir|mkdirs)\s*\(\s*\)/.test(c);
  });
  for (const dirNode of mkdirNodes) {
    // Check if there's a createTempFile in the same function scope
    const siblingNodes = map.nodes.filter(sib =>
      sib.id !== dirNode.id && sharesFunctionScope(map, dirNode.id, sib.id)
    );
    const hasCreateTemp = siblingNodes.some(sib =>
      /\bcreateTemp[Ff]ile\b/.test(sib.analysis_snapshot || sib.code_snapshot)
    );
    if (!hasCreateTemp) continue;

    // Check if directory permissions are set BEFORE the mkdir call
    const dirLine = dirNode.line_start;
    const preNodes = siblingNodes.filter(sib =>
      sib.line_start < dirLine &&
      DIR_PERM_SETTER.test(stripComments(sib.analysis_snapshot || sib.code_snapshot))
    );
    if (preNodes.length === 0) {
      findings.push({
        source: nodeRef(dirNode), sink: nodeRef(dirNode),
        missing: 'CONTROL (set directory permissions before creating temp files in it)',
        severity: 'medium',
        description: `Directory at ${dirNode.label} created without permission-setting before temp file creation. ` +
          `Other users can manipulate the directory contents via symlink or race attacks.`,
        fix: 'Set directory permissions (setWritable(true, true), setReadable(true, true)) before mkdir, ' +
          'or use a per-user private directory.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-379', name: 'Temp File in Insecure Directory', holds: findings.length === 0, findings };
}

/**
 * CWE-426: Untrusted Search Path
 *
 * Program uses PATH or similar search mechanism to locate executables
 * without verifying the result is from a trusted location. Attacker can
 * plant a malicious binary earlier in the search path.
 */

// ---------------------------------------------------------------------------
// Search Path
// ---------------------------------------------------------------------------

/**
 * CWE-426: Untrusted Search Path
 *
 * Program uses PATH or similar search mechanism to locate executables
 * without verifying the result is from a trusted location. Attacker can
 * plant a malicious binary earlier in the search path.
 */
function verifyCWE426(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const EXEC_SEARCH = /\b(exec|execFile|spawn|system|popen|subprocess\.(call|run|Popen|check_output|check_call)|child_process\.(exec|execSync|spawn|spawnSync)|os\.system|os\.popen|os\.exec|Runtime\.exec|ProcessBuilder|ShellExecute|CreateProcess|Process\.Start)\b/i;
  const BARE_CMD = /\b(exec|system|popen|spawn|subprocess)\s*\(\s*["'`](?!\/|[A-Z]:\\|\.\/|\.\.\/)([a-zA-Z][\w\-]*)\b/i;
  const SAFE_PATH = /\b(\/usr\/bin\/|\/bin\/|\/usr\/sbin\/|C:\\Windows\\System32\\|\.\/|__dirname|__filename|path\.join|path\.resolve|require\.resolve|which\.sync|lookpath|abs.*path|full.*path)\b/i;

  const execNodes = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
    EXEC_SEARCH.test(n.analysis_snapshot || n.code_snapshot)
  );
  for (const node of execNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (BARE_CMD.test(code) && !SAFE_PATH.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (absolute path to executable or PATH validation)',
        severity: 'high',
        description: `Command execution at ${node.label} uses a bare command name without an absolute path. Attacker can plant a malicious binary in the search path.`,
        fix: 'Use absolute paths to executables (e.g., /usr/bin/git). If PATH must be used, validate PATH entries, or use which/lookpath and verify the result is in a trusted directory.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-426', name: 'Untrusted Search Path', holds: findings.length === 0, findings };
}

/**
 * CWE-427: Uncontrolled Search Path Element
 *
 * Application modifies or relies on environment variables (PATH, LD_LIBRARY_PATH,
 * PYTHONPATH, NODE_PATH) that can be influenced by an attacker.
 */

/**
 * CWE-427: Uncontrolled Search Path Element
 *
 * Application modifies or relies on environment variables (PATH, LD_LIBRARY_PATH,
 * PYTHONPATH, NODE_PATH) that can be influenced by an attacker.
 */
function verifyCWE427(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const PATH_MODIFY = /\b(process\.env\.PATH|os\.environ\[.PATH.\]|putenv.*PATH|setenv.*PATH|System\.setProperty.*path|Environment\.SetEnvironmentVariable.*Path|LD_LIBRARY_PATH|LD_PRELOAD|DYLD_LIBRARY_PATH|PYTHONPATH|NODE_PATH|CLASSPATH|GEM_PATH|RUBYLIB|PERL5LIB)\b/i;
  const PATH_INJECT = /\b(process\.env|os\.environ|getenv|System\.getenv|Environment\.GetEnvironmentVariable)\b.*\b(PATH|LD_LIBRARY_PATH|LD_PRELOAD|DYLD_LIBRARY_PATH|PYTHONPATH|NODE_PATH|CLASSPATH)\b/i;
  const SAFE_CONTROL = /\b(sanitize.*path|validate.*path|whitelist|allowlist|trusted.*dir|safe.*path|known.*path|hardcoded.*path)\b/i;

  // Check all nodes for PATH manipulation
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (PATH_MODIFY.test(code) || PATH_INJECT.test(code)) {
      if (!SAFE_CONTROL.test(code)) {
        // Check if there's an INGRESS feeding into this
        const ingresses = nodesOfType(map, 'INGRESS');
        let fromUser = false;
        for (const src of ingresses) {
          if (hasTaintedPathWithoutControl(map, src.id, node.id)) {
            fromUser = true;
            findings.push({
              source: nodeRef(src), sink: nodeRef(node),
              missing: 'CONTROL (search path validation — restrict to trusted directories)',
              severity: 'high',
              description: `User input from ${src.label} influences search path at ${node.label}. Attacker can inject malicious libraries or executables.`,
              fix: 'Never let user input modify PATH/LD_LIBRARY_PATH/NODE_PATH. Hardcode trusted paths. If dynamic paths are needed, validate against an allowlist of trusted directories.',
              via: 'bfs',
            });
          }
        }
        if (!fromUser) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (search path hardening — use explicit paths)',
            severity: 'medium',
            description: `Search path variable modified at ${node.label} without validation. Environment manipulation could redirect execution.`,
            fix: 'Use absolute paths instead of relying on PATH. If PATH must be modified, prepend trusted dirs and validate entries.',
            via: 'structural',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-427', name: 'Uncontrolled Search Path Element', holds: findings.length === 0, findings };
}

/**
 * CWE-428: Unquoted Search Path or Element
 *
 * Windows-specific: service paths or exec calls with spaces that aren't quoted,
 * allowing "C:\Program Files\App\bin.exe" to be hijacked by "C:\Program.exe".
 * Also applies to shell commands with unquoted variables.
 */

/**
 * CWE-428: Unquoted Search Path or Element
 *
 * Windows-specific: service paths or exec calls with spaces that aren't quoted,
 * allowing "C:\Program Files\App\bin.exe" to be hijacked by "C:\Program.exe".
 * Also applies to shell commands with unquoted variables.
 */
function verifyCWE428(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const UNQUOTED_PATH_WIN = /\b(CreateProcess|ShellExecute|WinExec|system|exec|spawn|Start-Process|sc\s+create|New-Service|ServiceInstall)\b[^"']*\b([A-Z]:\\[Pp]rogram [Ff]iles|[A-Z]:\\[Pp]rogram [Ff]iles \(x86\))[^"']*\b/i;
  const UNQUOTED_VAR = /\$\{?\w+\}?(?!\s*["'])/i;
  const SHELL_UNQUOTED = /\b(system|exec|popen|spawn|subprocess)\s*\([^)]*\$\w+[^)]*\)/i;
  const SAFE_QUOTE = /["'][A-Z]:\\[^"']+["']|"\$\{?\w+\}?"|'\$\{?\w+\}?'/i;

  const execNodes = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
    (/\b(CreateProcess|ShellExecute|system|exec|spawn|popen|subprocess|child_process|Process\.Start|sc\s+create)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );
  for (const node of execNodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if ((UNQUOTED_PATH_WIN.test(code) || SHELL_UNQUOTED.test(code)) && !SAFE_QUOTE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (quoted path — wrap file paths and variables in quotes)',
        severity: 'high',
        description: `Unquoted path in command execution at ${node.label}. On Windows, spaces in paths cause incorrect binary resolution. In shells, unquoted variables enable injection.`,
        fix: 'Always quote paths containing spaces: "C:\\Program Files\\...". Quote shell variables: "$var". Use arrays for subprocess args instead of string concatenation.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-428', name: 'Unquoted Search Path or Element', holds: findings.length === 0, findings };
}

/**
 * CWE-668: Exposure of Resource to Wrong Sphere
 *
 * A resource (file, socket, memory, service) is accessible to actors outside
 * the intended security sphere. Covers: binding to 0.0.0.0, world-readable
 * files, CORS *, exposing internal services, debug endpoints in production.
 */

// ---------------------------------------------------------------------------
// Resource Exposure & Sphere
// ---------------------------------------------------------------------------

/**
 * CWE-668: Exposure of Resource to Wrong Sphere
 *
 * A resource (file, socket, memory, service) is accessible to actors outside
 * the intended security sphere. Covers: binding to 0.0.0.0, world-readable
 * files, CORS *, exposing internal services, debug endpoints in production.
 */
function verifyCWE668(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const EXPOSED_RESOURCE = /\b(0\.0\.0\.0|INADDR_ANY|listen\s*\(\s*["']0\.0\.0\.0|bind\s*\(\s*["']0\.0\.0\.0|host\s*[:=]\s*["']0\.0\.0\.0|Access-Control-Allow-Origin.*\*|cors\(\s*\)|cors\(\s*\{[^}]*origin\s*:\s*(?:true|\*|["']\*["']))\b/i;
  const DEBUG_EXPOSED = /\b(debug\s*[:=]\s*[Tt]rue|DEBUG\s*=\s*1|app\.debug\s*=\s*True|FLASK_DEBUG|NODE_ENV.*development.*listen|verbose.*error|stack.*trace.*response|exposeStack|showErrors)\b/i;
  const INSECURE_BIND = /\b(listen|bind|serve|createServer)\s*\([^)]*\b(3000|8080|8000|5000|9090|80)\b/i;
  const SAFE_SPHERE = /\b(127\.0\.0\.1|localhost|::1|CORS_ORIGIN|allowedOrigins|whitelist|origin\s*:\s*["'][^*]|helmet|X-Frame-Options|Content-Security-Policy|internal|private|firewall|vpc|127\.0\.0\.1)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if ((EXPOSED_RESOURCE.test(code) || DEBUG_EXPOSED.test(code)) && !SAFE_SPHERE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (restrict resource exposure — bind to localhost, restrict CORS, disable debug)',
        severity: 'medium',
        description: `Resource at ${node.label} exposed to a wider sphere than intended. Binding to 0.0.0.0, CORS *, or debug mode in production exposes internal functionality.`,
        fix: 'Bind to 127.0.0.1 or specific interfaces. Use explicit CORS origins, not *. Disable debug/verbose errors in production. Use network segmentation for internal services.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-668', name: 'Exposure of Resource to Wrong Sphere', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Input Validation & Injection Variant CWEs
// ---------------------------------------------------------------------------

/**
 * CWE-20: Improper Input Validation
 * Pattern: INGRESS → STORAGE/EXTERNAL without CONTROL, where no validation detected
 * Property: All user input is validated before reaching processing nodes.
 *
 * CWE-20 is the broadest input validation CWE — covers ANY case where user input
 * reaches a processing sink without validation. Unlike specific injection CWEs,
 * this catches missing validation even when the sink isn't a classic injection
 * point (business logic params, numeric IDs, enum values, date strings).
 */

// ---------------------------------------------------------------------------
// Synchronization & Locking
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-662: Improper Synchronization
// ---------------------------------------------------------------------------

/**
 * CWE-662: Improper Synchronization
 * Detects shared state accessed from concurrent contexts (async handlers,
 * threads, goroutines) without proper synchronization primitives.
 *
 * Broader than CWE-362 (race condition on files) — this covers ANY shared
 * mutable state: module-level variables, class fields, global caches, etc.
 * Specifically looks for WRITE operations to shared state from multiple
 * concurrent entry points without locks/atomics.
 */
function verifyCWE662(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const WRITE_PATTERN = /(\w+)\s*=\s*[^=]|\w+\s*\+=|\w+\s*-=|\w+\s*\*=|\w+\.\s*(push|pop|shift|unshift|splice|set|delete|add|remove|put|insert|append|extend|update|clear)\s*\(|\+\+\w|\w\+\+|--\w|\w--/i;
  const CONCURRENT_CONTEXT = /\b(async\s|await\s|\.then\(|Promise|goroutine|go\s+func|spawn|tokio|Thread|threading|CompletableFuture|Task\.Run|@app\.(get|post|put|delete)|router\.(get|post|put|delete)|handle|Handler|endpoint|worker|Worker|setInterval|setTimeout|EventEmitter|on\s*\(\s*['"])/i;
  const SYNC_SAFE = /\b(mutex|Mutex|lock|Lock|synchronized|atomic|Atomic|Interlocked|RwLock|ReentrantLock|semaphore|Semaphore|monitor|Monitor|ConcurrentHashMap|ConcurrentLinkedQueue|CopyOnWriteArray|channel|Chan|select\s*\{|\.transaction\(|BEGIN\s+TRANSACTION|serial|serialize|enqueue|single.?thread)\b/i;

  // Find shared mutable state: STORAGE nodes at module/global/static/class scope
  const sharedStorage = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('global') || n.node_subtype.includes('shared') ||
     n.node_subtype.includes('module') || n.node_subtype.includes('static') ||
     n.node_subtype.includes('class_field') || n.node_subtype.includes('cache') ||
     n.node_subtype.includes('singleton') ||
     n.attack_surface.includes('shared_state') || n.attack_surface.includes('shared_resource') ||
     /\b(global\.|module\.exports\.|self\.\w+|cls\.\w+|static\s+\w+|volatile\b|_instance|singleton|cache)\b/i.test(n.analysis_snapshot || n.code_snapshot))
  );

  // Find concurrent entry points
  const concurrentEntries = map.nodes.filter(n =>
    (n.node_type === 'INGRESS' || n.node_type === 'STRUCTURAL' || n.node_type === 'TRANSFORM') &&
    CONCURRENT_CONTEXT.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const entry of concurrentEntries) {
    for (const shared of sharedStorage) {
      if (entry.id === shared.id) continue;
      if (!WRITE_PATTERN.test(shared.analysis_snapshot || shared.code_snapshot)) continue;

      const bfsHit662 = hasTaintedPathWithoutControl(map, entry.id, shared.id);
      const scopeHit662 = !bfsHit662 && sharesFunctionScope(map, entry.id, shared.id);
      if (!bfsHit662 && !scopeHit662) continue;

      const allCode = stripComments(entry.analysis_snapshot || entry.code_snapshot + ' ' + shared.code_snapshot);
      // Also check CONTROL nodes in the same scope
      const controlsInScope = map.nodes.filter(c =>
        c.node_type === 'CONTROL' && sharesFunctionScope(map, c.id, shared.id)
      );
      const controlCode = controlsInScope.map(c => stripComments(c.analysis_snapshot || c.code_snapshot)).join(' ');

      if (!SYNC_SAFE.test(allCode) && !SYNC_SAFE.test(controlCode)) {
        findings.push({
          source: nodeRef(entry),
          sink: nodeRef(shared),
          missing: 'CONTROL (synchronization primitive — mutex, lock, atomic, or channel)',
          severity: 'medium',
          description: `Shared mutable state ${shared.label} is written from concurrent context ${entry.label} without synchronization. ` +
            `Concurrent writes can cause data corruption, lost updates, or inconsistent reads.`,
          fix: 'Protect shared state with a mutex/lock, use atomic operations, or restructure to use message-passing (channels). ' +
            'In Node.js, use atomic operations or serialize access through a queue. ' +
            'In Go, use sync.Mutex or channels. In Java, use synchronized blocks or java.util.concurrent.',
          via: bfsHit662 ? 'bfs' : 'scope_taint',
        });
      }
    }
  }

  return { cwe: 'CWE-662', name: 'Improper Synchronization', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-667: Improper Locking
// ---------------------------------------------------------------------------

/**
 * CWE-667: Improper Locking
 * Detects lock usage patterns that are incorrect: acquiring locks without
 * releasing them, releasing locks that aren't held, nested locks that can
 * deadlock, and locks not released in error/exception paths.
 *
 * Key patterns:
 * - Lock acquired without corresponding release in finally/defer/ensure
 * - Multiple locks acquired in inconsistent order (deadlock risk)
 * - Lock held across await/yield points (async deadlock)
 */

// ---------------------------------------------------------------------------
// CWE-667: Improper Locking
// ---------------------------------------------------------------------------

/**
 * CWE-667: Improper Locking
 * Detects lock usage patterns that are incorrect: acquiring locks without
 * releasing them, releasing locks that aren't held, nested locks that can
 * deadlock, and locks not released in error/exception paths.
 *
 * Key patterns:
 * - Lock acquired without corresponding release in finally/defer/ensure
 * - Multiple locks acquired in inconsistent order (deadlock risk)
 * - Lock held across await/yield points (async deadlock)
 */
function verifyCWE667(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const LOCK_ACQUIRE = /\b(lock|Lock|acquire|synchronized|mutex\.lock|\.lock\(\)|RLock|tryLock|EnterCriticalSection|pthread_mutex_lock|sync\.Mutex|\.Lock\(\)|flock\(.*LOCK_EX|Semaphore\.acquire|sem\.acquire|ReentrantLock\.lock)\b/i;
  const LOCK_RELEASE = /\b(unlock|Unlock|release|\.unlock\(\)|LeaveCriticalSection|pthread_mutex_unlock|\.Unlock\(\)|flock\(.*LOCK_UN|Semaphore\.release|sem\.release|ReentrantLock\.unlock)\b/i;
  const FINALLY_DEFER = /\b(finally|defer|ensure|__exit__|@contextmanager|with\s+\w+.*:|using\s*\(|try\s*\(.*\)\s*\{)\b/i;
  const ASYNC_YIELD = /\b(await\s|yield\s|\.then\(|async\s+with|aiohttp|asyncio\.sleep)\b/i;

  // Find all nodes that acquire locks
  const lockNodes = map.nodes.filter(n =>
    LOCK_ACQUIRE.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const lockNode of lockNodes) {
    const containingFunc = findContainingFunction(map, lockNode.id);
    if (!containingFunc) continue;

    // Gather all nodes in the same function
    const funcNode = map.nodes.find(n => n.id === containingFunc);
    if (!funcNode) continue;

    const containedIds = new Set<string>();
    const queue = [containingFunc];
    while (queue.length > 0) {
      const id = queue.shift()!;
      const node = map.nodes.find(n => n.id === id);
      if (!node) continue;
      for (const edge of node.edges) {
        if (edge.edge_type === 'CONTAINS' && !containedIds.has(edge.target)) {
          containedIds.add(edge.target);
          queue.push(edge.target);
        }
      }
    }

    const containedNodes = map.nodes.filter(n => containedIds.has(n.id));
    const allFuncCode = stripComments(funcNode.analysis_snapshot || funcNode.code_snapshot);
    const hasRelease = containedNodes.some(n => LOCK_RELEASE.test(n.analysis_snapshot || n.code_snapshot)) ||
                       LOCK_RELEASE.test(allFuncCode);
    const hasFinally = FINALLY_DEFER.test(allFuncCode);

    // Pattern 1: Lock acquired without release in finally/defer
    if (hasRelease && !hasFinally) {
      findings.push({
        source: nodeRef(lockNode),
        sink: nodeRef(lockNode),
        missing: 'CONTROL (lock release in finally/defer/ensure block)',
        severity: 'high',
        description: `Lock acquired at ${lockNode.label} is released but not in a finally/defer block. ` +
          `If an exception occurs between acquire and release, the lock is never released, causing deadlock.`,
        fix: 'Always release locks in a finally block (try/finally), defer statement (Go), or use a context manager (Python with statement). ' +
          'In Java, use try-with-resources with AutoCloseable locks.',
        via: 'structural',
      });
    }

    if (!hasRelease) {
      findings.push({
        source: nodeRef(lockNode),
        sink: nodeRef(lockNode),
        missing: 'CONTROL (corresponding lock release)',
        severity: 'high',
        description: `Lock acquired at ${lockNode.label} has no corresponding release in the same function. ` +
          `The lock will be held indefinitely, blocking all other threads/goroutines.`,
        fix: 'Add a matching unlock/release call. Always pair lock() with unlock() in a finally/defer block.',
        via: 'structural',
      });
    }

    // Pattern 2: Lock held across await/yield (async deadlock)
    if (hasRelease) {
      const codeAfterLock = containedNodes.filter(n =>
        n.line_start >= lockNode.line_start && ASYNC_YIELD.test(n.analysis_snapshot || n.code_snapshot)
      );
      if (codeAfterLock.length > 0) {
        findings.push({
          source: nodeRef(lockNode),
          sink: nodeRef(codeAfterLock[0]),
          missing: 'CONTROL (lock must not span await/yield points)',
          severity: 'medium',
          description: `Lock acquired at ${lockNode.label} is held across an await/yield at ${codeAfterLock[0].label}. ` +
            `In async runtimes, holding a lock across yield points can cause deadlocks when the resumed coroutine ` +
            `tries to re-acquire or when another coroutine on the same thread needs the lock.`,
          fix: 'Restructure to release the lock before await/yield, or use async-aware locks (asyncio.Lock, tokio::sync::Mutex). ' +
            'Alternatively, gather all data needed under the lock, release it, then await.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-667', name: 'Improper Locking', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-382: J2EE Bad Practices: Use of System.exit()
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-764: Multiple Locks of a Critical Resource
// ---------------------------------------------------------------------------
function verifyCWE764(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const LOCK_RE = /\.lock\s*\(\s*\)/g;
  const UNLOCK_RE = /\.unlock\s*\(\s*\)/g;
  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
    const code = node.analysis_snapshot || node.code_snapshot;
    const lockCount = (code.match(LOCK_RE) || []).length;
    const unlockCount = (code.match(UNLOCK_RE) || []).length;
    if (lockCount > 1 && lockCount > unlockCount) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (balanced lock/unlock — each lock() needs matching unlock())',
        severity: 'medium',
        description: `Function ${node.label} calls lock() ${lockCount} times but unlock() only ${unlockCount} times. ` +
          `The lock is never fully released, blocking other threads permanently.`,
        fix: 'Ensure each lock() call has a matching unlock() in a finally block.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-764', name: 'Multiple Locks of a Critical Resource', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-765: Multiple Unlocks of a Critical Resource
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-765: Multiple Unlocks of a Critical Resource
// ---------------------------------------------------------------------------
function verifyCWE765(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const LOCK_RE = /\.lock\s*\(\s*\)/g;
  const UNLOCK_RE = /\.unlock\s*\(\s*\)/g;
  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
    const code = node.analysis_snapshot || node.code_snapshot;
    const lockCount = (code.match(LOCK_RE) || []).length;
    const unlockCount = (code.match(UNLOCK_RE) || []).length;
    if (unlockCount > 1 && unlockCount > lockCount) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (balanced lock/unlock — only unlock once per lock)',
        severity: 'medium',
        description: `Function ${node.label} calls unlock() ${unlockCount} times but lock() only ${lockCount} times. ` +
          `The extra unlock() will throw IllegalMonitorStateException at runtime.`,
        fix: 'Ensure each lock() has exactly one matching unlock() in a finally block.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-765', name: 'Multiple Unlocks of a Critical Resource', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-832: Unlock of a Resource that is not Locked
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-832: Unlock of a Resource that is not Locked
// ---------------------------------------------------------------------------
function verifyCWE832(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const LOCK_RE = /\.lock\s*\(\s*\)/g;
  const UNLOCK_RE = /\.unlock\s*\(\s*\)/g;
  for (const node of map.nodes) {
    if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
    const code = node.analysis_snapshot || node.code_snapshot;
    const lockCount = (code.match(LOCK_RE) || []).length;
    const unlockCount = (code.match(UNLOCK_RE) || []).length;
    if (unlockCount > 0 && lockCount === 0) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (lock before unlock — must hold lock to release it)',
        severity: 'medium',
        description: `Function ${node.label} calls unlock() ${unlockCount} times but never calls lock(). ` +
          `Unlocking a resource you don't hold throws IllegalMonitorStateException.`,
        fix: 'Only call unlock() on locks you currently hold. Use lock(); try { ... } finally { unlock(); }.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-832', name: 'Unlock of a Resource that is not Locked', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-833: Deadlock — Lock Ordering Inversion Detection
// ---------------------------------------------------------------------------

/**
 * CWE-833: Deadlock
 *
 * Detects deadlock potential by finding methods that acquire two or more
 * locks in different orders. The classic pattern:
 *   Method A: lock1 -> lock2
 *   Method B: lock2 -> lock1
 *
 * Covers three Java patterns from Juliet:
 * 1. ReentrantLock: X.lock() then Y.lock() vs Y.lock() then X.lock()
 * 2. synchronized(object): synchronized(X) { synchronized(Y) } vs synchronized(Y) { synchronized(X) }
 * 3. synchronized methods: synchronized method on obj1 calls synchronized method on obj2 (and vice versa)
 *
 * Source-level scan — no graph traversal needed. The deadlock pattern is
 * entirely visible in the source text within a single file.
 *
 * Limitations:
 * - Only detects intra-file deadlock patterns (cross-file would require call graph)
 * - Pattern 3 (synchronized methods calling each other) requires understanding
 *   that `synchronized` on a method means locking `this` — harder to detect
 *   with source scanning alone, so we use a heuristic approach
 * - Does not track lock aliases (e.g., Lock ref = lock1; ref.lock())
 */

// ---------------------------------------------------------------------------
// CWE-833: Deadlock — Lock Ordering Inversion Detection
// ---------------------------------------------------------------------------

/**
 * CWE-833: Deadlock
 *
 * Detects deadlock potential by finding methods that acquire two or more
 * locks in different orders. The classic pattern:
 *   Method A: lock1 -> lock2
 *   Method B: lock2 -> lock1
 *
 * Covers three Java patterns from Juliet:
 * 1. ReentrantLock: X.lock() then Y.lock() vs Y.lock() then X.lock()
 * 2. synchronized(object): synchronized(X) { synchronized(Y) } vs synchronized(Y) { synchronized(X) }
 * 3. synchronized methods: synchronized method on obj1 calls synchronized method on obj2 (and vice versa)
 *
 * Source-level scan — no graph traversal needed. The deadlock pattern is
 * entirely visible in the source text within a single file.
 *
 * Limitations:
 * - Only detects intra-file deadlock patterns (cross-file would require call graph)
 * - Pattern 3 (synchronized methods calling each other) requires understanding
 *   that `synchronized` on a method means locking `this` — harder to detect
 *   with source scanning alone, so we use a heuristic approach
 * - Does not track lock aliases (e.g., Lock ref = lock1; ref.lock())
 */
function verifyCWE833(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const src = map.source_code || '';
  if (!src) return { cwe: 'CWE-833', name: 'Deadlock', holds: true, findings };

  const lines = src.split('\n').map((line, i) => ({
    line,
    lineNum: i + 1,
    isComment: /^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*\/\*/.test(line),
  }));

  // -------------------------------------------------------------------------
  // Step 1: Extract method boundaries from source
  // -------------------------------------------------------------------------
  interface MethodInfo {
    name: string;
    startLine: number;
    endLine: number;
    body: string;
    isSynchronized: boolean;
  }

  const methods: MethodInfo[] = [];
  // Match Java method declarations — { may be on same line or next line
  // Return type must NOT consume spaces (so we exclude \s from its char class)
  const METHOD_DECL_RE = /^\s*(?:(?:public|private|protected|static|final|synchronized|override|virtual|abstract)\s+)*(\w[\w<>\[\],?]*)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{?\s*$/;

  for (let i = 0; i < lines.length; i++) {
    if (lines[i].isComment) continue;
    const line = lines[i].line.replace(/\r$/, '');
    const match = METHOD_DECL_RE.exec(line);
    if (!match) continue;

    // Ensure this is a method, not a class/interface declaration
    const retType = match[1];
    if (retType === 'class' || retType === 'interface' || retType === 'enum') continue;

    const methodName = match[2];
    const startLine = lines[i].lineNum;
    const isSynchronized = /\bsynchronized\b/.test(line);

    // Find matching closing brace by counting braces
    let braceDepth = 0;
    let foundOpen = false;
    let endLine = startLine;
    const bodyLines: string[] = [];

    for (let j = i; j < lines.length; j++) {
      const line = lines[j].line;
      for (const ch of line) {
        if (ch === '{') { braceDepth++; foundOpen = true; }
        if (ch === '}') { braceDepth--; }
      }
      bodyLines.push(line);
      if (foundOpen && braceDepth === 0) {
        endLine = lines[j].lineNum;
        break;
      }
    }

    methods.push({
      name: methodName,
      startLine,
      endLine,
      body: bodyLines.join('\n'),
      isSynchronized,
    });
  }

  // -------------------------------------------------------------------------
  // Step 2: For each method, extract lock acquisition order
  // -------------------------------------------------------------------------
  interface LockAcquisition {
    lockName: string;
    line: number;
  }

  function extractLockOrder(method: MethodInfo): LockAcquisition[] {
    const acquisitions: LockAcquisition[] = [];
    const methodLines = method.body.split('\n').map((line, idx) => ({
      line,
      lineNum: idx + 1,
      isComment: /^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*\/\*/.test(line),
    }));

    for (const ml of methodLines) {
      if (ml.isComment) continue;
      const line = ml.line;
      const lineNum = method.startLine + ml.lineNum - 1;

      // Pattern 1: ReentrantLock — VARNAME.lock()
      const lockCallRe = /(\w+)\.lock\s*\(\s*\)/g;
      let m;
      while ((m = lockCallRe.exec(line)) !== null) {
        acquisitions.push({ lockName: m[1], line: lineNum });
      }

      // Pattern 2: synchronized(EXPRESSION) — extract the object being synchronized on
      const syncRe = /\bsynchronized\s*\(\s*(\w+)\s*\)/g;
      while ((m = syncRe.exec(line)) !== null) {
        acquisitions.push({ lockName: `sync:${m[1]}`, line: lineNum });
      }
    }

    return acquisitions;
  }

  // -------------------------------------------------------------------------
  // Step 3: Compare lock ordering across method pairs
  // -------------------------------------------------------------------------
  const methodLockOrders = methods.map(m => ({
    method: m,
    locks: extractLockOrder(m),
  }));

  for (let i = 0; i < methodLockOrders.length; i++) {
    for (let j = i + 1; j < methodLockOrders.length; j++) {
      const a = methodLockOrders[i];
      const b = methodLockOrders[j];

      if (a.locks.length < 2 || b.locks.length < 2) continue;

      // Find locks that appear in both methods
      const aLockNames = a.locks.map(l => l.lockName);
      const bLockNames = b.locks.map(l => l.lockName);
      const sharedLocks = [...new Set(aLockNames.filter(l => bLockNames.includes(l)))];

      if (sharedLocks.length < 2) continue;

      // For each pair of shared locks, check if the order is inverted
      for (let p = 0; p < sharedLocks.length; p++) {
        for (let q = p + 1; q < sharedLocks.length; q++) {
          const lock1 = sharedLocks[p];
          const lock2 = sharedLocks[q];

          // Find first occurrence index in each method
          const aIdx1 = aLockNames.indexOf(lock1);
          const aIdx2 = aLockNames.indexOf(lock2);
          const bIdx1 = bLockNames.indexOf(lock1);
          const bIdx2 = bLockNames.indexOf(lock2);

          // Check for ordering inversion: A acquires lock1 before lock2,
          // but B acquires lock2 before lock1 (or vice versa)
          const aOrder = aIdx1 < aIdx2; // true = lock1 first in A
          const bOrder = bIdx1 < bIdx2; // true = lock1 first in B

          if (aOrder !== bOrder) {
            // Deadlock detected!
            const firstInA = aOrder ? lock1 : lock2;
            const secondInA = aOrder ? lock2 : lock1;
            const firstAcqA = a.locks[aOrder ? aIdx1 : aIdx2];
            const firstAcqB = b.locks[bOrder ? bIdx2 : bIdx1];

            const sourceNode = findNearestNode(map, firstAcqA.line) || map.nodes[0];
            const sinkNode = findNearestNode(map, firstAcqB.line) || map.nodes[0];

            if (sourceNode && sinkNode) {
              const displayLock1 = firstInA.replace('sync:', '');
              const displayLock2 = secondInA.replace('sync:', '');
              findings.push({
                source: nodeRef(sourceNode),
                sink: nodeRef(sinkNode),
                missing: 'CONTROL (consistent lock ordering — all methods must acquire locks in the same order)',
                severity: 'high',
                description: `Deadlock: ${a.method.name}() acquires ${displayLock1} then ${displayLock2}, ` +
                  `but ${b.method.name}() acquires ${displayLock2} then ${displayLock1}. ` +
                  `If these methods run concurrently, each thread can hold one lock while waiting for the other, causing deadlock.`,
                fix: `Enforce a global lock ordering: always acquire ${displayLock1} before ${displayLock2} (or vice versa, but consistently). ` +
                  `Alternatively, use tryLock() with timeouts to break potential deadlocks.`,
                via: 'source_line_fallback',
              });
            }
          }
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Step 4: Pattern 3 — synchronized methods calling synchronized methods
  // on other objects (the "bow" pattern from Juliet).
  // -------------------------------------------------------------------------
  const syncMethods = methods.filter(m => m.isSynchronized);
  if (syncMethods.length >= 2) {
    for (const sm of syncMethods) {
      const bodyLines = sm.body.split('\n').map((line, idx) => ({
        line,
        lineNum: idx + 1,
        isComment: /^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*\/\*/.test(line),
      }));

      for (const bl of bodyLines) {
        if (bl.isComment) continue;
        // Look for calls like: bower.someMethod(this) or param.someMethod(...)
        const callRe = /(\w+)\.(\w+)\s*\(/g;
        let m;
        while ((m = callRe.exec(bl.line)) !== null) {
          const calledObj = m[1];
          const calledMethod = m[2];

          // Is calledMethod a synchronized method in this file?
          const target = syncMethods.find(t => t.name === calledMethod && t !== sm);
          if (!target) continue;

          // Calling on 'this' or 'super' is not cross-object
          if (calledObj === 'this' || calledObj === 'super') continue;

          // This synchronized method calls another synchronized method on a different object
          // while holding its own lock — potential deadlock if the other object does the same.
          const lineNum = sm.startLine + bl.lineNum - 1;
          const sourceNode = findNearestNode(map, sm.startLine) || map.nodes[0];
          const sinkNode = findNearestNode(map, lineNum) || map.nodes[0];

          if (sourceNode && sinkNode) {
            findings.push({
              source: nodeRef(sourceNode),
              sink: nodeRef(sinkNode),
              missing: 'CONTROL (avoid calling synchronized method on another object while holding own lock)',
              severity: 'high',
              description: `Deadlock risk: synchronized method ${sm.name}() holds lock on 'this' ` +
                `while calling synchronized method ${calledMethod}() on '${calledObj}'. ` +
                `If ${calledObj} simultaneously calls a synchronized method on this object, deadlock occurs.`,
              fix: `Release your own lock before calling synchronized methods on other objects. ` +
                `Use a synchronized block instead of synchronized method, and release before the cross-object call. ` +
                `Or use a global lock ordering strategy.`,
              via: 'source_line_fallback',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-833', name: 'Deadlock', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-672: Operation on Resource After Expiration or Release
// ---------------------------------------------------------------------------

/**
 * CWE-672: Operation on Resource After Expiration or Release
 * Detects use of resources (connections, file handles, sessions, tokens)
 * after they have been closed/released/expired. Covers:
 * - Using a connection after close/release/end
 * - Using a file descriptor after close
 * - Using an expired token/session without re-validation
 * - Using an object after dispose/destroy
 */

// ---------------------------------------------------------------------------
// Signal & Thread Safety
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-382: J2EE Bad Practices: Use of System.exit()
// ---------------------------------------------------------------------------
function verifyCWE382(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const allSnapshots = map.nodes.map(n => n.analysis_snapshot || n.code_snapshot).join('\n');
  const isServletContext = /\b(extends\s+(?:HttpServlet|AbstractTestCaseServlet\w*|GenericServlet)|import\s+javax\.servlet|import\s+jakarta\.servlet|@WebServlet|@Stateless|@Stateful|@MessageDriven|SessionBean|EntityBean)\b/.test(allSnapshots);
  if (!isServletContext) {
    return { cwe: 'CWE-382', name: 'J2EE Bad Practices: Use of System.exit()', holds: true, findings };
  }
  const EXIT_RE = /\b(System\s*\.\s*exit\s*\(|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exit\s*\(|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*halt\s*\(|Runtime\s*\.\s*halt\s*\()/;
  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (EXIT_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (no System.exit/Runtime.halt in servlet/J2EE container)',
        severity: 'high',
        description: `System.exit() or Runtime.halt() called at ${node.label} in a servlet/J2EE context. ` +
          `This terminates the entire JVM, killing all active sessions and servlets in the container.`,
        fix: 'Never call System.exit() or Runtime.halt() in servlet/EJB code. Use proper exception handling ' +
          'and return appropriate HTTP error codes.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-382', name: 'J2EE Bad Practices: Use of System.exit()', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-383: J2EE Bad Practices: Direct Use of Threads
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-383: J2EE Bad Practices: Direct Use of Threads
// ---------------------------------------------------------------------------
function verifyCWE383(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const allSnapshots = map.nodes.map(n => n.analysis_snapshot || n.code_snapshot).join('\n');
  const isServletContext = /\b(extends\s+(?:HttpServlet|AbstractTestCaseServlet\w*|GenericServlet)|import\s+javax\.servlet|import\s+jakarta\.servlet|@WebServlet|@Stateless|@Stateful|@MessageDriven|SessionBean|EntityBean)\b/.test(allSnapshots);
  if (!isServletContext) {
    return { cwe: 'CWE-383', name: 'J2EE Bad Practices: Direct Use of Threads', holds: true, findings };
  }
  const DIRECT_THREAD_RE = /\b(new\s+Thread\s*\(|\.start\s*\(\s*\)|Thread\s*\.\s*sleep\s*\(|extends\s+Thread\b|implements\s+Runnable\b)/;
  const SAFE_THREAD_RE = /\b(ExecutorService|ManagedExecutorService|ScheduledExecutorService|CompletableFuture|ForkJoinPool|@Asynchronous)\b/;
  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    if (DIRECT_THREAD_RE.test(code) && !SAFE_THREAD_RE.test(code)) {
      if (/^\s*(public\s+)?(interface|abstract\s+class)\s/.test(code)) continue;
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'STRUCTURAL (container-managed concurrency — use ExecutorService)',
        severity: 'medium',
        description: `Direct thread management at ${node.label} in a servlet/J2EE context. ` +
          `Creating threads directly bypasses the container thread management and security context propagation.`,
        fix: 'Use container-managed thread pools: ExecutorService, ManagedExecutorService, or @Asynchronous EJB methods.',
        via: 'structural',
      });
    }
  }
  return { cwe: 'CWE-383', name: 'J2EE Bad Practices: Direct Use of Threads', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-764: Multiple Locks of a Critical Resource
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Resource Lifecycle
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-672: Operation on Resource After Expiration or Release
// ---------------------------------------------------------------------------

/**
 * CWE-672: Operation on Resource After Expiration or Release
 * Detects use of resources (connections, file handles, sessions, tokens)
 * after they have been closed/released/expired. Covers:
 * - Using a connection after close/release/end
 * - Using a file descriptor after close
 * - Using an expired token/session without re-validation
 * - Using an object after dispose/destroy
 */
function verifyCWE672(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const RELEASE_PATTERN = /\b(close|end|release|destroy|dispose|free|fclose|shutdown|disconnect|invalidate|expire|revoke|unsubscribe|abort|cancel|terminate|pool\.release|connection\.end|connection\.close|conn\.close|fd\.close|handle\.close|stream\.destroy|session\.destroy|\.dispose\(\))\b/i;
  const USE_AFTER_PATTERN = /\b(query|execute|read|write|send|recv|fetch|get|put|post|request|emit|push|pipe|on\(|addListener|setTimeout|setInterval|resume|pause)\b/i;

  const resourceNodes = nodesOfType(map, 'RESOURCE');
  const storageNodes = nodesOfType(map, 'STORAGE');
  const allResourceish = [...resourceNodes, ...storageNodes.filter(s =>
    s.node_subtype.includes('connection') || s.node_subtype.includes('file') ||
    s.node_subtype.includes('handle') || s.node_subtype.includes('session') ||
    s.node_subtype.includes('token') || s.node_subtype.includes('stream')
  )];

  for (const res of allResourceish) {
    const containingFunc = findContainingFunction(map, res.id);
    if (!containingFunc) continue;

    const containedIds = new Set<string>();
    const queue = [containingFunc];
    while (queue.length > 0) {
      const id = queue.shift()!;
      const node = map.nodes.find(n => n.id === id);
      if (!node) continue;
      for (const edge of node.edges) {
        if (edge.edge_type === 'CONTAINS' && !containedIds.has(edge.target)) {
          containedIds.add(edge.target);
          queue.push(edge.target);
        }
      }
    }

    const containedNodes = map.nodes.filter(n => containedIds.has(n.id));

    // Find release nodes for this resource
    const releaseNodes = containedNodes.filter(n =>
      RELEASE_PATTERN.test(n.analysis_snapshot || n.code_snapshot) && n.line_start > 0
    );

    for (const rel of releaseNodes) {
      // Find use-after-release: nodes that use the resource AFTER the release line
      const useAfter = containedNodes.filter(n =>
        n.id !== rel.id && n.line_start > rel.line_start &&
        USE_AFTER_PATTERN.test(n.analysis_snapshot || n.code_snapshot) &&
        // Must reference the same resource (rough heuristic: same variable name)
        res.label && (n.analysis_snapshot || n.code_snapshot).includes(res.label.split('.').pop() || '')
      );

      for (const use of useAfter) {
        // Check for re-acquire/re-open pattern
        const reacquire = containedNodes.some(n =>
          n.line_start > rel.line_start && n.line_start < use.line_start &&
          /\b(open|connect|acquire|create|new|getConnection|reopen|reconnect)\b/i.test(n.analysis_snapshot || n.code_snapshot)
        );
        if (!reacquire) {
          findings.push({
            source: nodeRef(rel),
            sink: nodeRef(use),
            missing: 'CONTROL (resource validity check or re-acquisition before use)',
            severity: 'high',
            description: `Resource released at ${rel.label} (line ${rel.line_start}) is used again at ${use.label} (line ${use.line_start}). ` +
              `Operating on a closed/expired resource causes errors, data corruption, or undefined behavior.`,
            fix: 'Either restructure code to not use the resource after release, re-acquire it before use, ' +
              'or add a validity check (isOpen, isConnected, isValid) before each use. ' +
              'Consider using RAII/try-with-resources patterns to scope resource lifetime.',
            via: 'structural',
          });
          break; // One finding per release is enough
        }
      }
    }
  }

  return { cwe: 'CWE-672', name: 'Operation on Resource After Expiration or Release', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-674: Uncontrolled Recursion
// ---------------------------------------------------------------------------

/**
 * CWE-674: Uncontrolled Recursion
 * Detects recursive function calls (direct or via mutual recursion) where
 * the recursion depth is not bounded, leading to stack overflow / DoS.
 *
 * Detection strategies:
 * 1. STRUCTURAL nodes whose code_snapshot contains a call to themselves
 *    without a depth/limit check
 * 2. TRANSFORM/EXTERNAL nodes with recursive patterns (self-call) reachable
 *    from INGRESS without depth guards
 */

// ---------------------------------------------------------------------------
// CWE-674: Uncontrolled Recursion
// ---------------------------------------------------------------------------

/**
 * CWE-674: Uncontrolled Recursion
 * Detects recursive function calls (direct or via mutual recursion) where
 * the recursion depth is not bounded, leading to stack overflow / DoS.
 *
 * Detection strategies:
 * 1. STRUCTURAL nodes whose code_snapshot contains a call to themselves
 *    without a depth/limit check
 * 2. TRANSFORM/EXTERNAL nodes with recursive patterns (self-call) reachable
 *    from INGRESS without depth guards
 */
function verifyCWE674(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  /**
   * Detect self-referencing function calls by extracting the function name from
   * the declaration and checking if it appears as a call INSIDE the function body
   * (not in the declaration header itself). This avoids false positives from
   * named function expressions like `res.sendStatus = function sendStatus(...)`.
   */
  function hasSelfCall(code: string): boolean {
    // Extract function name from declaration patterns across languages
    const DECL_PATTERNS = [
      /\bfunction\s+(\w+)\s*\([^)]*\)\s*\{/,           // JS/TS: function name(...) {
      /\bdef\s+(\w+)\s*\(/,                              // Python: def name(
      /\bfn\s+(\w+)\s*\(/,                               // Rust: fn name(
      /\bfunc\s+(\w+)\s*\(/,                             // Go: func name(
      /(\w+)\s*=\s*function\s+\w*\s*\([^)]*\)\s*\{/,    // JS: name = function [...](...)  {
      /(\w+)\s*=\s*\([^)]*\)\s*=>/,                      // JS: name = (...) =>
      // Java/C#/Kotlin: [modifiers] returnType methodName(params) {
      /(?:(?:public|private|protected|static|final|abstract|synchronized|native)\s+)*\w+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w[\w.,\s]*\s*)?\{/,
    ];
    for (const pat of DECL_PATTERNS) {
      const m = code.match(pat);
      if (m) {
        const fnName = m[1];
        // Find the function body — everything after the first `{` or `:` after params
        const declEnd = code.indexOf('{', (m.index ?? 0) + m[0].length - 1);
        if (declEnd === -1) continue;
        const body = code.slice(declEnd + 1);
        // Check if the function name appears as a DIRECT call in the body (not as a method
        // on another object like `obj.name()`). Uses negative lookbehind for `.` to exclude
        // `mime.contentType()` from matching when the function is `contentType`.
        const callPattern = new RegExp(`(?<!\\.)\\b${fnName}\\s*\\(`);
        if (callPattern.test(body)) return true;
      }
    }
    return false;
  }

  // Explicit recursion keywords/patterns — but NOT `this.method()` alone, which is
  // typically calling a DIFFERENT method on the same object, not recursion.
  const RECURSION_INDICATOR = /\brecursi|self\.\w+\s*\(.*?\/\/.*recursi|this\.\w+\s*\(.*?\/\/.*recursi|\brecur\b|\barguments\.callee/i;
  // Depth guard must compare against a named limit or non-zero value.
  // `level == 0` alone is NOT a sufficient guard (Juliet: Long.MAX_VALUE recursion depth).
  // A real guard: `level > MAX_DEPTH`, `depth >= LIMIT`, `count > maxRecursion`, etc.
  const DEPTH_GUARD = /\b(maxDepth|max_depth|MAX_DEPTH|MAX_RECURSION|RECURSION_LIMIT|RECURSION_\w*MAX|sys\.setrecursionlimit|stack.?size|base.?case)\b|(?:depth|level|count)\s*(?:>|>=|<|<=)\s*(?:[A-Z_]{2,}|\w*[Mm]ax\w*|\w*[Ll]imit\w*|\w*[Dd]epth\w*|[1-9]\d*)|\blimit\b/i;

  const structuralNodes = nodesOfType(map, 'STRUCTURAL');
  const allCallable = [...structuralNodes, ...nodesOfType(map, 'TRANSFORM')];
  const ingress = nodesOfType(map, 'INGRESS');

  for (const node of allCallable) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check for self-calling pattern or explicit recursion indicator
    const isSelfCall = hasSelfCall(code);
    const isRecursive = RECURSION_INDICATOR.test(code);

    if (!isSelfCall && !isRecursive) continue;

    // Check if depth is bounded
    if (DEPTH_GUARD.test(code)) continue;

    // Is this reachable from user input? (higher severity if so)
    const reachableFromIngress = ingress.some(src =>
      hasTaintedPathWithoutControl(map, src.id, node.id) ||
      sharesFunctionScope(map, src.id, node.id)
    );

    findings.push({
      source: nodeRef(node),
      sink: nodeRef(node),
      missing: 'CONTROL (recursion depth limit or base case guard)',
      severity: reachableFromIngress ? 'high' : 'medium',
      description: `Recursive function at ${node.label} has no explicit depth limit. ` +
        (reachableFromIngress
          ? 'User input can control recursion depth, enabling stack overflow DoS attacks.'
          : 'Malformed or deeply nested data can cause stack overflow.'),
      fix: 'Add an explicit depth parameter with a maximum limit, or convert to iterative approach. ' +
        'Example: function process(data, depth = 0) { if (depth > MAX_DEPTH) throw new Error("too deep"); ... process(child, depth + 1); }. ' +
        'For user-controlled input: always validate nesting depth before processing.',
      via: 'structural',
    });
  }

  return { cwe: 'CWE-674', name: 'Uncontrolled Recursion', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-676: Use of Potentially Dangerous Function
// ---------------------------------------------------------------------------

/**
 * CWE-676: Use of Potentially Dangerous Function
 * Detects usage of functions that are inherently unsafe and have safer
 * alternatives. These are well-known dangerous functions across languages:
 *
 * C/C++: strcpy, strcat, sprintf, gets, scanf (→ strncpy, strncat, snprintf, fgets)
 * JS:    eval, Function(), setTimeout(string), innerHTML, document.write
 * Python: eval, exec, pickle.loads, yaml.load (unsafe), os.system, subprocess with shell=True
 * PHP:   eval, system, exec, passthru, shell_exec, assert, preg_replace with /e
 * Ruby:  eval, system, send, __send__, instance_eval, class_eval
 */

// ---------------------------------------------------------------------------
// CWE-676: Use of Potentially Dangerous Function
// ---------------------------------------------------------------------------

/**
 * CWE-676: Use of Potentially Dangerous Function
 * Detects usage of functions that are inherently unsafe and have safer
 * alternatives. These are well-known dangerous functions across languages:
 *
 * C/C++: strcpy, strcat, sprintf, gets, scanf (→ strncpy, strncat, snprintf, fgets)
 * JS:    eval, Function(), setTimeout(string), innerHTML, document.write
 * Python: eval, exec, pickle.loads, yaml.load (unsafe), os.system, subprocess with shell=True
 * PHP:   eval, system, exec, passthru, shell_exec, assert, preg_replace with /e
 * Ruby:  eval, system, send, __send__, instance_eval, class_eval
 */
function verifyCWE676(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DANGEROUS_FUNCTIONS: Array<{ pattern: RegExp; name: string; fix: string; severity: 'critical' | 'high' | 'medium' }> = [
    // C/C++ memory-unsafe functions
    { pattern: /\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf|fscanf|realpath)\s*\(/i, name: 'C unsafe string function', fix: 'Use bounded alternatives: strncpy, strncat, snprintf, fgets. Or use std::string in C++.', severity: 'high' },
    // C/C++ dangerous memory
    { pattern: /\b(alloca|setjmp|longjmp)\s*\(/i, name: 'C dangerous control/memory function', fix: 'Avoid alloca (use malloc with size check). Avoid setjmp/longjmp (use structured error handling).', severity: 'medium' },
    // JS/TS eval family
    { pattern: /\beval\s*\(|(?<![a-z])Function\s*\(|new\s+Function\s*\(/, name: 'Dynamic code evaluation', fix: 'Replace eval/Function constructor with safe alternatives: JSON.parse for data, a sandboxed interpreter, or refactor to avoid dynamic code execution.', severity: 'critical' },
    // JS DOM injection
    { pattern: /\.(innerHTML|outerHTML)\s*=|\bdocument\.(write|writeln)\s*\(/i, name: 'Unsafe DOM manipulation', fix: 'Use textContent, createElement + appendChild, or a sanitizer library (DOMPurify) instead of innerHTML/document.write.', severity: 'high' },
    // Python dangerous
    { pattern: /\b(pickle\.loads?|cPickle\.loads?|shelve\.open|marshal\.loads?|yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)|yaml\.unsafe_load)\b/i, name: 'Unsafe deserialization function', fix: 'Use yaml.safe_load instead of yaml.load. Avoid pickle for untrusted data — use JSON or a schema-validated format.', severity: 'critical' },
    { pattern: /\bos\.system\s*\(|subprocess\.\w+\(.*shell\s*=\s*True/i, name: 'Shell command execution', fix: 'Use subprocess.run with shell=False and pass arguments as a list. Avoid os.system entirely.', severity: 'high' },
    // PHP dangerous
    { pattern: /\b(assert|create_function|preg_replace\s*\(.*['"]\/[^'"]*e['"]\s*,)\b/i, name: 'PHP dangerous function', fix: 'Remove assert() in production code. Replace create_function with closures. Remove /e modifier from preg_replace (use preg_replace_callback).', severity: 'high' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    for (const df of DANGEROUS_FUNCTIONS) {
      if (df.pattern.test(code)) {
        // Skip if this is inside a comment-only or test/mock context
        if (/\b(test|spec|mock|stub|fake|__test__|describe\s*\(|it\s*\()\b/i.test(node.label)) continue;

        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: `TRANSFORM (replacement of dangerous function: ${df.name})`,
          severity: df.severity,
          description: `${df.name} used at ${node.label}. This function is inherently unsafe and has known safer alternatives.`,
          fix: df.fix,
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-676', name: 'Use of Potentially Dangerous Function', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-694: Use of Multiple Resources with Duplicate Identifier
// ---------------------------------------------------------------------------

/**
 * CWE-694: Use of Multiple Resources with Duplicate Identifier
 * Detects when multiple resources (DB connections, file handles, service
 * bindings, configuration keys) are registered/opened with the same
 * identifier, leading to confusion about which resource is actually used.
 *
 * Detection: look for RESOURCE/STORAGE/EXTERNAL nodes with the same label
 * or matching identifier patterns in their code_snapshot.
 */

// ---------------------------------------------------------------------------
// CWE-694: Use of Multiple Resources with Duplicate Identifier
// ---------------------------------------------------------------------------

/**
 * CWE-694: Use of Multiple Resources with Duplicate Identifier
 * Detects when multiple resources (DB connections, file handles, service
 * bindings, configuration keys) are registered/opened with the same
 * identifier, leading to confusion about which resource is actually used.
 *
 * Detection: look for RESOURCE/STORAGE/EXTERNAL nodes with the same label
 * or matching identifier patterns in their code_snapshot.
 */
function verifyCWE694(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const IDENTIFIER_PATTERN = /(?:name|key|id|identifier|alias|binding|register|bind)\s*[:=]\s*['"]([^'"]+)['"]/gi;
  const PORT_PATTERN = /(?:port|listen)\s*[:=(\s]+(\d+)/gi;
  const ROUTE_PATTERN = /(?:route|path|endpoint|url)\s*[:=]\s*['"]([^'"]+)['"]/gi;

  // Collect identifiers from resource-like nodes
  const resourceLike = map.nodes.filter(n =>
    n.node_type === 'RESOURCE' || n.node_type === 'EXTERNAL' ||
    (n.node_type === 'STORAGE' && (n.node_subtype.includes('config') || n.node_subtype.includes('registry') || n.node_subtype.includes('binding')))
  );

  const identifierMap = new Map<string, NeuralMapNode[]>();

  for (const node of resourceLike) {
    const code = node.analysis_snapshot || node.code_snapshot;
    const patterns = [IDENTIFIER_PATTERN, PORT_PATTERN, ROUTE_PATTERN];
    for (const pat of patterns) {
      pat.lastIndex = 0;
      let match;
      while ((match = pat.exec(code)) !== null) {
        const key = match[1].toLowerCase().trim();
        if (key.length < 2) continue; // Skip trivially short identifiers
        const existing = identifierMap.get(key) || [];
        existing.push(node);
        identifierMap.set(key, existing);
      }
    }

    // Also check for duplicate labels among same-type nodes
    const labelKey = `label:${node.node_type}:${node.label.toLowerCase()}`;
    const existing = identifierMap.get(labelKey) || [];
    existing.push(node);
    identifierMap.set(labelKey, existing);
  }

  for (const [identifier, nodes] of identifierMap) {
    if (nodes.length < 2) continue;
    // Deduplicate by node id
    const unique = [...new Map(nodes.map(n => [n.id, n])).values()];
    if (unique.length < 2) continue;

    findings.push({
      source: nodeRef(unique[0]),
      sink: nodeRef(unique[1]),
      missing: 'CONTROL (unique resource identifiers)',
      severity: 'medium',
      description: `Multiple resources share identifier "${identifier.replace('label:', '')}": ${unique.map(n => n.label).join(', ')}. ` +
        `Duplicate identifiers cause ambiguity — the wrong resource may be used, leading to data leaks or logic errors.`,
      fix: 'Ensure each resource has a unique identifier. Use namespacing (e.g., "db.primary" vs "db.replica") ' +
        'or explicit aliasing. Review resource registries for accidental overwrites.',
      via: 'structural',
    });
  }

  return { cwe: 'CWE-694', name: 'Use of Multiple Resources with Duplicate Identifier', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-771: Missing Reference to Active Allocated Resource
// ---------------------------------------------------------------------------

/**
 * CWE-771: Missing Reference to Active Allocated Resource
 * Detects when a resource is allocated but no reference is stored, making
 * it impossible to release later. Classic pattern: fire-and-forget resource
 * allocation where the handle is discarded.
 *
 * Examples:
 * - `new DatabaseConnection(...)` without assignment
 * - `open(file)` return value not captured
 * - `createServer().listen()` without storing the server reference
 * - Promise/async resource allocation without error handling
 */

// ---------------------------------------------------------------------------
// CWE-771: Missing Reference to Active Allocated Resource
// ---------------------------------------------------------------------------

/**
 * CWE-771: Missing Reference to Active Allocated Resource
 * Detects when a resource is allocated but no reference is stored, making
 * it impossible to release later. Classic pattern: fire-and-forget resource
 * allocation where the handle is discarded.
 *
 * Examples:
 * - `new DatabaseConnection(...)` without assignment
 * - `open(file)` return value not captured
 * - `createServer().listen()` without storing the server reference
 * - Promise/async resource allocation without error handling
 */
function verifyCWE771(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const ALLOC_NO_ASSIGN = /^(?!\s*(const|let|var|val|auto|final|\w+\s+\w+)\s*=).*\b(new\s+\w*(Connection|Pool|Client|Server|Socket|Stream|Handle|Resource|Session|Worker|Thread))\s*\(/i;
  const FIRE_AND_FORGET_ALLOC = /^\s*(open|fopen|connect|createConnection|createServer|createClient|spawn|fork|acquire)\s*\([^)]*\)\s*[;]?\s*$/im;
  const RESOURCE_CREATE_UNASSIGNED = /\b(create|open|allocate|acquire|spawn|fork|new)\b.*\b(connection|pool|handle|socket|stream|file|resource|session|worker|thread)\b/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'RESOURCE' && node.node_type !== 'EXTERNAL') continue;
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    // Check if this looks like an allocation without reference capture
    const isUnassigned = ALLOC_NO_ASSIGN.test(code) || FIRE_AND_FORGET_ALLOC.test(code);
    if (!isUnassigned) continue;

    // Verify there's no assignment in the surrounding context
    const containingFunc = findContainingFunction(map, node.id);
    if (containingFunc) {
      const funcNode = map.nodes.find(n => n.id === containingFunc);
      if (funcNode) {
        const funcCode = stripComments(funcNode.analysis_snapshot || funcNode.code_snapshot);
        // If the function properly captures the result, skip
        const capturePattern = new RegExp(`\\b(const|let|var|\\w+)\\s*=\\s*.*${node.label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'i');
        if (capturePattern.test(funcCode)) continue;
      }
    }

    findings.push({
      source: nodeRef(node),
      sink: nodeRef(node),
      missing: 'STORAGE (reference to allocated resource for later cleanup)',
      severity: 'medium',
      description: `Resource allocated at ${node.label} without storing a reference. ` +
        `Without a reference, the resource cannot be explicitly released, leading to resource leaks.`,
      fix: 'Always capture the return value of resource allocation into a variable. ' +
        'Store references in a scope where cleanup can happen (try/finally, RAII, context manager). ' +
        'For servers/connections: const server = createServer(...); process.on("SIGTERM", () => server.close());',
      via: 'structural',
    });
  }

  return { cwe: 'CWE-771', name: 'Missing Reference to Active Allocated Resource', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-772: Missing Release of Resource After Effective Lifetime
// ---------------------------------------------------------------------------

/**
 * CWE-772: Missing Release of Resource After Effective Lifetime
 * Closely related to CWE-404 but focuses specifically on resources that
 * outlive their useful scope — the resource IS referenced, but never
 * released. Covers:
 * - DB connections opened but never closed
 * - File handles opened but never closed
 * - Event listeners added but never removed (memory leak)
 * - Timers/intervals set but never cleared
 * - Subscriptions created but never unsubscribed
 */

// ---------------------------------------------------------------------------
// CWE-772: Missing Release of Resource After Effective Lifetime
// ---------------------------------------------------------------------------

/**
 * CWE-772: Missing Release of Resource After Effective Lifetime
 * Closely related to CWE-404 but focuses specifically on resources that
 * outlive their useful scope — the resource IS referenced, but never
 * released. Covers:
 * - DB connections opened but never closed
 * - File handles opened but never closed
 * - Event listeners added but never removed (memory leak)
 * - Timers/intervals set but never cleared
 * - Subscriptions created but never unsubscribed
 */
function verifyCWE772(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const ACQUIRE_PATTERNS: Array<{ acquire: RegExp; release: RegExp; resourceType: string }> = [
    { acquire: /\b(createConnection|getConnection|connect|createPool|open|createClient)\s*\(/i, release: /\b(close|end|release|destroy|disconnect|terminate|pool\.end)\b/i, resourceType: 'connection/handle' },
    { acquire: /\b(createReadStream|createWriteStream|openSync|fs\.open|fopen|File\.open|open\s*\()\b/i, release: /\b(close|end|destroy|fclose|\.close\(\))\b/i, resourceType: 'file handle' },
    { acquire: /\b(addEventListener|\.on\s*\(|addListener|subscribe|observe)\s*\(/i, release: /\b(removeEventListener|\.off\s*\(|removeListener|removeAllListeners|unsubscribe|disconnect|dispose)\b/i, resourceType: 'event listener/subscription' },
    { acquire: /\b(setInterval|setTimeout|setImmediate|requestAnimationFrame)\s*\(/i, release: /\b(clearInterval|clearTimeout|clearImmediate|cancelAnimationFrame)\b/i, resourceType: 'timer' },
    { acquire: /\b(Worker|spawn|fork|child_process|new\s+Thread|threading\.Thread)\s*\(/i, release: /\b(terminate|kill|join|close|destroy|exit)\b/i, resourceType: 'worker/thread' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    for (const ap of ACQUIRE_PATTERNS) {
      if (!ap.acquire.test(code)) continue;

      // Check the containing function for matching release
      const containingFunc = findContainingFunction(map, node.id);
      let hasRelease = false;

      if (containingFunc) {
        const funcNode = map.nodes.find(n => n.id === containingFunc);
        if (funcNode) {
          const funcCode = stripComments(funcNode.analysis_snapshot || funcNode.code_snapshot);
          hasRelease = ap.release.test(funcCode);
        }

        // Also check sibling nodes in the same function
        if (!hasRelease) {
          const containedIds = new Set<string>();
          const queue = [containingFunc];
          while (queue.length > 0) {
            const id = queue.shift()!;
            const n = map.nodes.find(nd => nd.id === id);
            if (!n) continue;
            for (const edge of n.edges) {
              if (edge.edge_type === 'CONTAINS' && !containedIds.has(edge.target)) {
                containedIds.add(edge.target);
                queue.push(edge.target);
              }
            }
          }
          hasRelease = map.nodes.some(n =>
            containedIds.has(n.id) && ap.release.test(stripComments(n.analysis_snapshot || n.code_snapshot))
          );
        }
      }

      // Also check if the node itself contains the release (e.g., inline cleanup)
      if (!hasRelease) {
        hasRelease = ap.release.test(code);
      }

      // Check module-level cleanup handlers
      if (!hasRelease) {
        hasRelease = map.nodes.some(n =>
          /\b(process\.on\s*\(\s*['"](SIGTERM|SIGINT|exit|beforeExit)['"]|atexit|Runtime\.addShutdownHook|defer|finally)\b/i.test(n.analysis_snapshot || n.code_snapshot) &&
          ap.release.test(stripComments(n.analysis_snapshot || n.code_snapshot))
        );
      }

      if (!hasRelease) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: `CONTROL (${ap.resourceType} release/cleanup)`,
          severity: ap.resourceType === 'event listener/subscription' || ap.resourceType === 'timer' ? 'medium' : 'high',
          description: `${ap.resourceType} acquired at ${node.label} is never released. ` +
            `Over time, unreleased ${ap.resourceType}s accumulate, causing ${
              ap.resourceType.includes('connection') ? 'connection pool exhaustion' :
              ap.resourceType.includes('file') ? 'file descriptor exhaustion' :
              ap.resourceType.includes('listener') ? 'memory leaks from retained closures' :
              ap.resourceType.includes('timer') ? 'memory leaks and unexpected callback execution' :
              'resource exhaustion'
            }.`,
          fix: `Add cleanup: ${
            ap.resourceType.includes('connection') ? 'call close()/end()/release() in a finally block or on process shutdown.' :
            ap.resourceType.includes('file') ? 'call close() in a finally block, or use try-with-resources / context managers.' :
            ap.resourceType.includes('listener') ? 'call removeEventListener/off/unsubscribe in cleanup (componentWillUnmount, useEffect return, ngOnDestroy).' :
            ap.resourceType.includes('timer') ? 'store the timer ID and call clearInterval/clearTimeout in cleanup.' :
            'ensure the resource is released when no longer needed.'
          }`,
          via: 'structural',
        });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Java-specific: detect resources opened but never closed (Juliet CWE-772)
  // Juliet pattern: DB Connection/PreparedStatement/ResultSet opened, never .close()
  // Also: InputStreamReader, console readers never closed
  // ---------------------------------------------------------------------------
  if (inferMapLanguage(map) === 'java') {
    const JAVA_RESOURCE_OPEN_RE = /\bnew\s+(InputStreamReader|BufferedReader|FileReader|FileWriter|FileInputStream|FileOutputStream|Socket|ServerSocket)\b|\b(getConnection|getDBConnection|openConnection|prepareStatement|createStatement|executeQuery)\s*\(/;
    const JAVA_RESOURCE_CLOSE_RE = /\.\s*close\s*\(/;
    const JAVA_TRY_WITH_RESOURCES_RE = /\btry\s*\(/;

    for (const node of map.nodes) {
      if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
      const code = node.analysis_snapshot || node.code_snapshot;
      if (!code) continue;
      if (JAVA_TRY_WITH_RESOURCES_RE.test(code)) continue;
      if (!JAVA_RESOURCE_OPEN_RE.test(code)) continue;

      // If no close at all — resource leak
      if (!JAVA_RESOURCE_CLOSE_RE.test(code)) {
        const resourceMatch = code.match(JAVA_RESOURCE_OPEN_RE);
        const resourceType = resourceMatch ? (resourceMatch[1] || resourceMatch[2] || 'resource') : 'resource';
        if (!findings.some(f => f.source.id === node.id)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: `CONTROL (${resourceType} release/cleanup — close after use)`,
            severity: 'high',
            description: `Method ${node.label} creates ${resourceType} but never calls close(). Unreleased resources accumulate over time, causing exhaustion.`,
            fix: 'Close resources in a finally block or use try-with-resources. For DB connections, always close Connection, PreparedStatement, and ResultSet.',
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-772', name: 'Missing Release of Resource After Effective Lifetime', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Information Disclosure CWEs (CWE-209, 215, 497, 532, 538, 540, 548, 550, 598, 615)
// ---------------------------------------------------------------------------

/* REMOVED: verifyCWE472 — now in sensitive-data.ts */

/* REMOVED: verifyCWE473 — now in sensitive-data.ts */

/* REMOVED: verifyCWE474 — now in sensitive-data.ts */

/* REMOVED: verifyCWE488 — now in sensitive-data.ts */

/* REMOVED: verifyCWE523 -- now in auth.ts */

/* REMOVED: verifyCWE527 — now in sensitive-data.ts */

/* REMOVED: verifyCWE529 — now in sensitive-data.ts */

/* REMOVED: verifyCWE531 — now in sensitive-data.ts */

/* REMOVED: verifyCWE535 — now in sensitive-data.ts */

// ---------------------------------------------------------------------------
// CWE-533, CWE-534, CWE-775: New verifiers for Juliet Java benchmark
// ---------------------------------------------------------------------------

/* REMOVED: verifyCWE533 — now in sensitive-data.ts */

/* REMOVED: verifyCWE534 — now in sensitive-data.ts */

/**
 * CWE-775: Missing Release of File Descriptor or Handle after Effective Lifetime
 * Juliet pattern: FileReader/BufferedReader opened in try, never closed
 */
function verifyCWE775(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const FD_ACQUIRE_RE = /\b(createReadStream|createWriteStream|openSync|fs\.open|fopen|new\s+FileReader|new\s+BufferedReader|new\s+FileWriter|new\s+BufferedWriter|new\s+FileInputStream|new\s+FileOutputStream|new\s+RandomAccessFile|new\s+ZipFile)\b/i;
  const FD_RELEASE_RE = /\.\s*close\s*\(/;
  const TRY_WITH_RE = /\btry\s*\(/;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (!code) continue;
    if (!FD_ACQUIRE_RE.test(code)) continue;
    if (node.node_type === 'STRUCTURAL' && node.node_subtype === 'function') {
      if (TRY_WITH_RE.test(code)) continue;
      if (!FD_RELEASE_RE.test(code)) {
        const match = code.match(FD_ACQUIRE_RE);
        const handleType = match ? match[1] : 'file handle';
        findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (file descriptor release)', severity: 'high',
          description: `Method ${node.label} opens ${handleType} but never closes it.`,
          fix: 'Close file handles in a finally block or use try-with-resources.',
          via: 'structural' });
      }
    }
  }
  if (inferMapLanguage(map) === 'java') {
    const JAVA_FILE_OPEN_RE = /\bnew\s+(FileReader|BufferedReader|FileInputStream|FileOutputStream|FileWriter|BufferedWriter|RandomAccessFile|ZipFile|PrintWriter|InputStreamReader|OutputStreamWriter)\b/;
    for (const node of map.nodes) {
      if (node.node_type !== 'STRUCTURAL' || node.node_subtype !== 'function') continue;
      const code = node.analysis_snapshot || node.code_snapshot;
      if (!code) continue;
      if (TRY_WITH_RE.test(code)) continue;
      if (!JAVA_FILE_OPEN_RE.test(code)) continue;
      if (!FD_RELEASE_RE.test(code)) {
        const match = code.match(JAVA_FILE_OPEN_RE);
        const handleType = match ? match[1] : 'file handle';
        if (!findings.some(f => f.source.id === node.id)) {
          findings.push({ source: nodeRef(node), sink: nodeRef(node), missing: 'CONTROL (file descriptor release)', severity: 'high',
            description: `Method ${node.label} opens ${handleType} but never closes it.`,
            fix: 'Close file handles in a finally block. Use try-with-resources for automatic cleanup.',
            via: 'structural' });
        }
      }
    }
  }
  return { cwe: 'CWE-775', name: 'Missing Release of File Descriptor or Handle after Effective Lifetime', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-401: Missing Release of Memory after Effective Lifetime
// ---------------------------------------------------------------------------
function verifyCWE401(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library/framework code manages listeners and caches as part of its architecture
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-401', name: 'Missing Release of Memory after Effective Lifetime', holds: true, findings };
  }

  const C_ALLOC = /\b(malloc|calloc|realloc|strdup|strndup|asprintf|vasprintf|aligned_alloc|memalign|valloc|pvalloc|new\s+\w+(?:\[|\())\b/i;
  const C_FREE = /\b(free|delete|delete\s*\[|cfree|munmap|g_free|av_free|xmlFree)\b/i;
  const EARLY_RETURN_PATTERN = /(?:if\s*\([^)]*(?:err|fail|null|NULL|nullptr|<\s*0|!\s*\w+)[^)]*\)\s*\{[^}]*return\b)/i;
  const EVENT_LISTENER_ADD = /\b(addEventListener|addListener|on\s*\(\s*['"]|subscribe|observe|attachEvent|\.on\s*\(\s*['"]|emitter\.on)\b/i;
  const EVENT_LISTENER_REMOVE = /\b(removeEventListener|removeListener|removeAllListeners|off\s*\(\s*['"]|unsubscribe|unobserve|detachEvent|\.off\s*\(\s*['"])\b/i;
  const CACHE_GROW = /\b(\.set\s*\(|\.push\s*\(|\.add\s*\(|\.put\s*\(|cache\[|memo\[|store\[|registry\[)\b/i;
  const CACHE_EVICT = /\b(\.delete\s*\(|\.remove\s*\(|\.evict\s*\(|\.clear\s*\(|\.expire|maxSize|maxAge|ttl|lru|WeakMap|WeakSet|WeakRef|FinalizationRegistry)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (C_ALLOC.test(code)) {
      const containerId = findContainingFunction(map, node.id);
      if (containerId) {
        const container = map.nodes.find(n => n.id === containerId);
        if (container) {
          const containerCode = stripComments(container.analysis_snapshot || container.code_snapshot);
          if (!C_FREE.test(containerCode) && EARLY_RETURN_PATTERN.test(containerCode)) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(node),
              missing: 'RESOURCE (free/delete on all exit paths including error paths)',
              severity: 'high',
              description: `Memory allocated at ${node.label} may leak on error paths. The containing function ` +
                `has early returns (error paths) but no corresponding free/delete call. Each invocation ` +
                `on the error path permanently leaks memory, leading to eventual OOM.`,
              fix: 'Free allocated memory on ALL exit paths — use goto cleanup pattern in C, ' +
                'RAII/smart pointers in C++ (std::unique_ptr, std::shared_ptr), or ' +
                'try/finally in languages that support it.',
              via: 'structural',
            });
          }
        }
      }
    }

    if (EVENT_LISTENER_ADD.test(code) && node.node_type === 'STRUCTURAL') {
      const containerId = findContainingFunction(map, node.id);
      const container = containerId ? map.nodes.find(n => n.id === containerId) : null;
      const containerCode = container ? stripComments(container.analysis_snapshot || container.code_snapshot) : code;
      if (!EVENT_LISTENER_REMOVE.test(containerCode) &&
          !/\b(componentWillUnmount|useEffect\s*\(\s*\(\)\s*=>\s*\{[^}]*return|ngOnDestroy|dispose|cleanup|teardown)\b/i.test(containerCode)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'RESOURCE (remove event listener when no longer needed)',
          severity: 'medium',
          description: `Event listener added at ${node.label} without a corresponding removal. In long-running ` +
            `applications (servers, SPAs), this accumulates listeners that keep their closure scope ` +
            `alive, preventing garbage collection of potentially large object graphs.`,
          fix: 'Remove event listeners in cleanup: componentWillUnmount, useEffect return function, ' +
            'ngOnDestroy, or explicit removeEventListener. Store listener references for later removal.',
          via: 'structural',
        });
      }
    }

    if (CACHE_GROW.test(code) && /\b(cache|memo|store|registry|pool|bucket)\b/i.test(code)) {
      if (!CACHE_EVICT.test(code)) {
        const containerId = findContainingFunction(map, node.id);
        const container = containerId ? map.nodes.find(n => n.id === containerId) : null;
        const containerCode = container ? stripComments(container.analysis_snapshot || container.code_snapshot) : '';
        if (!CACHE_EVICT.test(containerCode)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'RESOURCE (cache eviction policy — maxSize, TTL, or WeakMap)',
            severity: 'medium',
            description: `Cache/store at ${node.label} grows without bounds. Items are added but never evicted. ` +
              `Over time this will consume all available memory, especially if keys are derived from ` +
              `user input (an attacker can intentionally exhaust memory by requesting unique keys).`,
            fix: 'Use a bounded cache with eviction: LRU cache with maxSize, TTL-based expiry, ' +
              'WeakMap/WeakRef for object caches. For Node.js: lru-cache package. ' +
              'For Java: Caffeine or Guava Cache. Monitor cache size in production.',
            via: 'structural',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-401', name: 'Missing Release of Memory after Effective Lifetime', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-403: Exposure of File Descriptor to Unintended Control Sphere
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-403: Exposure of File Descriptor to Unintended Control Sphere
// ---------------------------------------------------------------------------
function verifyCWE403(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const FD_CREATE = /\b(open\s*\(|socket\s*\(|pipe\s*\(|dup\s*\(|dup2\s*\(|accept\s*\(|shm_open\s*\(|eventfd\s*\(|timerfd_create\s*\(|signalfd\s*\(|epoll_create\s*\(|inotify_init\s*\(|memfd_create\s*\(|openat\s*\(|mkstemp\s*\()\b/;
  const CHILD_SPAWN = /\b(fork\s*\(|exec[lv]p?e?\s*\(|system\s*\(|popen\s*\(|posix_spawn|CreateProcess|spawn\s*\(|child_process\.(?:exec|spawn|fork|execFile)|subprocess\.(?:Popen|call|run|check_output)|os\.(?:system|popen|exec[lv]p?e?)|Process\.Start|Runtime\.(?:exec|getRuntime))\b/i;
  const FD_PROTECTED = /\b(O_CLOEXEC|FD_CLOEXEC|SOCK_CLOEXEC|fcntl\s*\([^)]*F_SETFD|closeOnExec|close_fds\s*[=:]\s*(?:true|True)|CloseHandle|inherit\s*[=:]\s*false|stdio\s*:\s*['"](?:ignore|pipe)|STARTF_USESTDHANDLES)\b/i;
  const INTENTIONAL_PASS = /\b(dup2\s*\([^,]+,\s*(?:STDIN_FILENO|STDOUT_FILENO|STDERR_FILENO|0|1|2)\s*\)|stdio\s*:\s*\[|inherit\s*[=:]\s*true|pass_fds\s*=)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (FD_CREATE.test(code) && CHILD_SPAWN.test(code) &&
        !FD_PROTECTED.test(code) && !INTENTIONAL_PASS.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (O_CLOEXEC or FD_CLOEXEC on file descriptors before spawning child)',
        severity: 'high',
        description: `File descriptor created and child process spawned at ${node.label} without close-on-exec ` +
          `protection. The child process inherits the parent's file descriptors, potentially gaining ` +
          `access to open files, sockets, database connections, or crypto key material that should ` +
          `be confined to the parent process.`,
        fix: 'Set O_CLOEXEC when creating FDs: open("file", O_RDONLY | O_CLOEXEC). ' +
          'For existing FDs: fcntl(fd, F_SETFD, FD_CLOEXEC). For sockets: SOCK_CLOEXEC flag. ' +
          'In Python: subprocess with close_fds=True (default in 3.x). ' +
          'In Node.js: child_process.spawn with stdio: "pipe" (not "inherit").',
        via: 'structural',
      });
    }
    if (CHILD_SPAWN.test(code) && !FD_PROTECTED.test(code) && !INTENTIONAL_PASS.test(code) &&
        !FD_CREATE.test(code)) {
      const hasResourceNodes = map.nodes.some(n =>
        n.node_type === 'RESOURCE' && (n.node_subtype === 'file_descriptors' || n.node_subtype === 'connections')
      );
      if (hasResourceNodes) {
        const containerId = findContainingFunction(map, node.id);
        const container = containerId ? map.nodes.find(n => n.id === containerId) : null;
        if (!container || !FD_PROTECTED.test(stripComments(container.analysis_snapshot || container.code_snapshot))) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (close_fds=True or O_CLOEXEC before child process creation)',
            severity: 'medium',
            description: `Child process spawned at ${node.label} without explicit close-on-exec. The codebase ` +
              `manages file descriptors/connections that could be inherited by the child process, ` +
              `exposing them to an unintended control sphere.`,
            fix: 'Use close_fds=True in subprocess calls (Python), set O_CLOEXEC on all FDs (C/C++), ' +
              'or use stdio: "pipe" in Node.js child_process.',
            via: 'structural',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-403', name: 'Exposure of File Descriptor to Unintended Control Sphere', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// HTTP smuggling, confused deputy, UI security, initialization CWEs (440-455)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Cleanup & Init
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-459: Incomplete Cleanup
// ---------------------------------------------------------------------------

/**
 * CWE-459: Incomplete Cleanup
 * Detects resources, sensitive data, or temporary state that is not fully cleaned up.
 * Broader than CWE-404 (which focuses on release/close): this covers sensitive data
 * left in memory, temp files not deleted, session state not cleared, caches not
 * invalidated, and partial cleanup that misses some resources.
 *
 * Detection: Scans for sensitive data handling, temp file creation, and session/cache
 * operations without corresponding cleanup in the same scope.
 */
function verifyCWE459(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Sensitive data in memory patterns
  const SENSITIVE_BUFFER = /\b(password|passwd|secret|token|apiKey|api_key|privateKey|private_key|credentials|creditCard|credit_card|ssn|socialSecurity|encryptionKey|encryption_key|masterKey|master_key|sessionToken|session_token|accessToken|access_token|refreshToken|refresh_token)\b/i;
  // Memory clearing patterns
  const MEMORY_CLEAR = /\b(\.fill\s*\(\s*0|crypto\.timingSafeEqual|Buffer\.alloc|memset|SecureString|overwrite|wipe|zeroize|zero.?fill|clear.?sensitive|secureClear|dispose|GC\.Collect|WeakRef|FinalizationRegistry|null\s*;|=\s*null|=\s*undefined|=\s*''|=\s*""|delete\s+\w+\.)\b/i;

  // Temp file patterns
  const TEMP_FILE = /\b(tmp|temp|\.tmp|tempFile|tmpFile|tempDir|tmpDir|mktemp|mkdtemp|tmpdir|os\.tmpdir|tempfile|NamedTemporaryFile|TemporaryDirectory|createTempFile|getTempPath)\b/i;
  const TEMP_CLEANUP = /\b(unlink|unlinkSync|rmSync|rm\s*\(|rimraf|del|remove|removeSync|cleanup|cleanupSync|fs\.unlink|os\.unlink|os\.remove|shutil\.rmtree|Files\.delete|afterAll|afterEach|finally)\b/i;
  // deleteOnExit is NOT proper cleanup — it defers deletion to JVM shutdown which may never happen in servlets
  const DELETE_ON_EXIT_RE = /\bdeleteOnExit\s*\(/;

  // Session/cache cleanup patterns
  const SESSION_CREATE = /\b(session\.create|session\.save|session\.set|req\.session|createSession|setSession|cache\.set|cache\.put|redis\.set|redis\.hset|memcached\.set|store\.set)\b/i;
  const SESSION_CLEANUP = /\b(session\.destroy|session\.invalidate|session\.delete|session\.clear|logout|signout|sign.?out|cache\.del|cache\.delete|cache\.invalidate|cache\.flush|cache\.clear|redis\.del|redis\.expire|TTL|ttl|maxAge|max_age|expires|expiry)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const containingFunc = findContainingFunction(map, node.id);
    const funcCode = containingFunc
      ? stripComments(map.nodes.find(n => n.id === containingFunc)?.analysis_snapshot || map.nodes.find(n => n.id === containingFunc)?.code_snapshot || '')
      : '';
    const allCode = code + ' ' + funcCode;

    // Check 1: Sensitive data in buffers without zeroing
    if (SENSITIVE_BUFFER.test(code) && /\b(Buffer|Uint8Array|ArrayBuffer|byte\[\]|char\[\])\b/i.test(code)) {
      if (!MEMORY_CLEAR.test(allCode)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CLEANUP (sensitive data buffer zeroing)',
          severity: 'medium',
          description: `Sensitive data (${code.match(SENSITIVE_BUFFER)?.[0] || 'credentials'}) stored in a buffer at ${node.label} ` +
            `may not be zeroed after use. Residual sensitive data in memory can be extracted via core dumps, ` +
            `heap inspection, or memory disclosure vulnerabilities.`,
          fix: 'Zero/overwrite buffers containing sensitive data immediately after use: buffer.fill(0). ' +
            'Use SecureString equivalents where available. Consider crypto.timingSafeEqual for comparisons. ' +
            'Set variables to null after use to help GC. Avoid string types for secrets (strings are immutable and interned).',
          via: 'structural',
        });
      }
    }

    // Check 2: Temp files without cleanup
    if (TEMP_FILE.test(code) && /\b(write|create|open|mktemp|mkdtemp)\b/i.test(code)) {
      if (!TEMP_CLEANUP.test(allCode)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CLEANUP (temporary file deletion)',
          severity: 'low',
          description: `Temporary file created at ${node.label} without visible cleanup. ` +
            `Leftover temp files waste disk space and may contain sensitive data accessible to other users.`,
          fix: 'Delete temp files in a finally block. Use os.tmpdir() with unique names and register cleanup via ' +
            'process exit handlers. In tests: use afterAll/afterEach hooks. ' +
            'Consider using streams instead of temp files where possible.',
          via: 'structural',
        });
      }
    }

    // Check 2b: deleteOnExit used instead of proper finally { delete() } — incomplete cleanup in servlets
    if (DELETE_ON_EXIT_RE.test(code) && !TEMP_CLEANUP.test(allCode)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CLEANUP (use explicit delete() in finally block, not deleteOnExit())',
        severity: 'medium',
        description: `Temp file at ${node.label} uses deleteOnExit() instead of explicit deletion. ` +
          `In servlet containers, the JVM may run indefinitely, so deleteOnExit() effectively never cleans up. ` +
          `Temp files accumulate, wasting disk space and potentially exposing sensitive data.`,
        fix: 'Delete temporary files explicitly in a finally block using file.delete(). ' +
          'Do not rely on deleteOnExit() in long-running applications like servlets.',
        via: 'structural',
      });
    }

    // Check 3: Session/cache creation without expiry or cleanup
    if (SESSION_CREATE.test(code)) {
      if (!SESSION_CLEANUP.test(allCode)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CLEANUP (session/cache expiry or invalidation)',
          severity: 'medium',
          description: `Session or cache entry created at ${node.label} without visible expiry or cleanup. ` +
            `Stale sessions accumulate, consuming memory, and never-expiring sessions are a session fixation risk.`,
          fix: 'Always set TTL/maxAge on session and cache entries. Implement explicit logout/invalidation. ' +
            'For Redis: use EXPIRE or SETEX. For in-memory caches: use LRU with max size. ' +
            'For sessions: set cookie maxAge and server-side session timeout.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-459', name: 'Incomplete Cleanup', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-460: Improper Cleanup on Thrown Exception
// ---------------------------------------------------------------------------

/**
 * CWE-460: Improper Cleanup on Thrown Exception
 * Detects resource acquisition in try blocks without proper cleanup in
 * catch/finally. Distinct from CWE-404 (which checks for release existence) —
 * this specifically checks that cleanup happens on the ERROR PATH.
 *
 * Detection: Resource acquisition inside try blocks where the catch/finally
 * block doesn't include corresponding release operations.
 */

// ---------------------------------------------------------------------------
// CWE-460: Improper Cleanup on Thrown Exception
// ---------------------------------------------------------------------------

/**
 * CWE-460: Improper Cleanup on Thrown Exception
 * Detects resource acquisition in try blocks without proper cleanup in
 * catch/finally. Distinct from CWE-404 (which checks for release existence) —
 * this specifically checks that cleanup happens on the ERROR PATH.
 *
 * Detection: Resource acquisition inside try blocks where the catch/finally
 * block doesn't include corresponding release operations.
 */
function verifyCWE460(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const ACQUIRE_PATTERN = /\b(open|createReadStream|createWriteStream|getConnection|acquire|connect|createServer|createConnection|createPool|fopen|socket|createSocket|listen|bind|lock|Lock|acquire|beginTransaction|BEGIN)\b/i;
  const RELEASE_PATTERN = /\b(close|end|release|destroy|dispose|free|fclose|shutdown|disconnect|unlock|Unlock|rollback|ROLLBACK|abort|cancel)\b/i;
  const TRY_BLOCK = /\btry\s*\{/;
  const CATCH_BLOCK = /\bcatch\s*\(/;
  const FINALLY_BLOCK = /\bfinally\s*\{/;

  for (const node of map.nodes) {
    const code = node.analysis_snapshot || node.code_snapshot;
    const stripped = stripComments(code);

    // Only interested in code with try blocks that acquire resources
    if (!TRY_BLOCK.test(stripped)) continue;
    if (!ACQUIRE_PATTERN.test(stripped)) continue;

    const hasCatch = CATCH_BLOCK.test(stripped);
    const hasFinally = FINALLY_BLOCK.test(stripped);

    if (!hasCatch && !hasFinally) {
      // No error handling at all — definite issue
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CLEANUP (catch/finally block for resource release on error)',
        severity: 'high',
        description: `Resource acquired in try block at ${node.label} without catch or finally. ` +
          `If an exception occurs after acquisition but before release, the resource leaks.`,
        fix: 'Add a finally block that releases the resource, or use try-with-resources (Java), ' +
          'context managers (Python with statement), or RAII (C++/Rust) to guarantee cleanup.',
        via: 'structural',
      });
      continue;
    }

    // Has catch or finally — check if release happens on the error path
    if (hasFinally) {
      // Extract the finally block content (rough heuristic)
      const finallyMatch = stripped.match(/finally\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/);
      if (finallyMatch && !RELEASE_PATTERN.test(finallyMatch[1])) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CLEANUP (resource release inside finally block)',
          severity: 'medium',
          description: `Resource acquired at ${node.label} has a finally block but it doesn't release the resource. ` +
            `The resource will leak if an exception is thrown between acquire and release.`,
          fix: 'Move the resource release (close/end/release/destroy) into the finally block ' +
            'to ensure it runs on both success and error paths.',
          via: 'structural',
        });
      }
    } else if (hasCatch) {
      // Has catch but no finally — check if catch releases
      const catchMatch = stripped.match(/catch\s*\([^)]*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/);
      if (catchMatch && !RELEASE_PATTERN.test(catchMatch[1])) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CLEANUP (resource release in catch block, or add finally block)',
          severity: 'medium',
          description: `Resource acquired at ${node.label} has a catch block that doesn't release the resource. ` +
            `On exception, the acquired resource leaks. Using finally is preferred over catch for cleanup.`,
          fix: 'Add a finally block for resource cleanup (preferred), or add release calls to the catch block. ' +
            'The finally block runs on both success and error paths, making it more reliable than catch-only cleanup.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-460', name: 'Improper Cleanup on Thrown Exception', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-462: Duplicate Key in Associative List (Map/Dict)
// ---------------------------------------------------------------------------

/**
 * CWE-462: Duplicate Key in Associative List
 * Detects duplicate keys in object literals, Maps, config files, or dictionaries
 * where the second value silently overwrites the first. This can cause security
 * policy bypasses (e.g., duplicate CORS headers, duplicate permission entries).
 *
 * Detection: Scans code snapshots for object literals or map constructions
 * with duplicate keys, and for patterns where user input is used as map keys
 * without deduplication.
 */

// ---------------------------------------------------------------------------
// CWE-462: Duplicate Key in Associative List (Map/Dict)
// ---------------------------------------------------------------------------

/**
 * CWE-462: Duplicate Key in Associative List
 * Detects duplicate keys in object literals, Maps, config files, or dictionaries
 * where the second value silently overwrites the first. This can cause security
 * policy bypasses (e.g., duplicate CORS headers, duplicate permission entries).
 *
 * Detection: Scans code snapshots for object literals or map constructions
 * with duplicate keys, and for patterns where user input is used as map keys
 * without deduplication.
 */
function verifyCWE462(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns where user input becomes a map/object key
  const INPUT_AS_KEY = /\b(\w+)\s*\[\s*(req\.|request\.|params\.|query\.|body\.|input\.|data\.|user\.|args\.|argv\.)|\bMap\s*\(\s*\[.*?(req\.|request\.|params\.|query\.|body\.)|Object\.fromEntries|\.reduce\s*\(\s*\([^)]*\)\s*=>\s*\{[^}]*\[[^\]]*\]\s*=/i;
  // Config/policy objects where duplicate keys cause silent override
  const POLICY_OBJECT = /\b(cors|CORS|helmet|csp|CSP|permissions|Permissions|roles|Roles|access|Access|whitelist|allowlist|blacklist|denylist|headers|Headers|rules|Rules|config|Config|policy|Policy|acl|ACL)\b/i;
  // Duplicate key detection — object literal with same key repeated (static analysis)
  const DUPLICATE_KEY_RISK = /\{[^}]*(\w+)\s*:.*\1\s*:/;
  // Safe — explicit dedup
  const DEDUP_SAFE = /\b(new\s+Set|new\s+Map|\.has\s*\(|hasOwnProperty|Object\.keys\s*\([^)]*\)\.includes|dedup|deduplicate|unique|distinct|\.filter\s*\(\s*\([^)]*,\s*\w+\s*,\s*\w+\)\s*=>|Set\.from|uniqueBy|groupBy)\b/i;

  const ingress = nodesOfType(map, 'INGRESS');
  const storage = nodesOfType(map, 'STORAGE');

  // Check 1: User input used as dictionary/map keys without dedup
  for (const src of ingress) {
    for (const sink of storage) {
      const bfsHit462 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const scopeHit462 = !bfsHit462 && sharesFunctionScope(map, src.id, sink.id);
      if (bfsHit462 || scopeHit462) {
        const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (INPUT_AS_KEY.test(code) && !DEDUP_SAFE.test(code)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (duplicate key check before associative list insertion)',
            severity: 'medium',
            description: `User input from ${src.label} is used as a key in an associative structure at ${sink.label} without duplicate checking. ` +
              `Duplicate keys cause silent value overwrites — an attacker can override earlier entries (e.g., security policies) ` +
              `by submitting duplicate keys where the last one wins.`,
            fix: 'Check for existing keys before insertion: use Map.has() or hasOwnProperty(). ' +
              'For user-provided key-value pairs: validate uniqueness, reject or merge duplicates explicitly. ' +
              'For HTTP headers: be aware that duplicate headers have framework-specific behavior (first-wins vs last-wins). ' +
              'For config: use a schema validator that rejects duplicate keys.',
            via: bfsHit462 ? 'bfs' : 'scope_taint',
          });
        }
      }
    }
  }

  // Check 2: Policy/config objects with duplicate key risk
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (POLICY_OBJECT.test(code) && DUPLICATE_KEY_RISK.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CODE QUALITY (duplicate key in security-relevant object literal)',
        severity: 'low',
        description: `Potential duplicate key in security-relevant object at ${node.label}. ` +
          `In JavaScript, duplicate keys in object literals silently use the last value. ` +
          `In security contexts (CORS, CSP, permissions), this can inadvertently weaken policies.`,
        fix: 'Enable the no-dupe-keys ESLint rule. Review object literals for duplicate keys. ' +
          'For generated configs: add a post-generation duplicate-key check.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-462', name: 'Duplicate Key in Associative List', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-463: Deletion of Data Structure Sentinel
// ---------------------------------------------------------------------------

/**
 * CWE-463: Deletion of Data Structure Sentinel
 * Detects deletion or overwriting of sentinel/terminator values in data structures
 * (null terminators in C strings, end-of-list markers, delimiter values).
 * In higher-level languages, this manifests as removing boundary markers from
 * arrays/strings that downstream code depends on (e.g., removing trailing newline
 * from protocol data, deleting end-of-record markers, null-byte injection).
 *
 * Detection: Looks for patterns that strip/delete sentinel characters from
 * protocol or binary data, or that allow user input to overwrite sentinel positions.
 */

// ---------------------------------------------------------------------------
// CWE-463: Deletion of Data Structure Sentinel
// ---------------------------------------------------------------------------

/**
 * CWE-463: Deletion of Data Structure Sentinel
 * Detects deletion or overwriting of sentinel/terminator values in data structures
 * (null terminators in C strings, end-of-list markers, delimiter values).
 * In higher-level languages, this manifests as removing boundary markers from
 * arrays/strings that downstream code depends on (e.g., removing trailing newline
 * from protocol data, deleting end-of-record markers, null-byte injection).
 *
 * Detection: Looks for patterns that strip/delete sentinel characters from
 * protocol or binary data, or that allow user input to overwrite sentinel positions.
 */
function verifyCWE463(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Sentinel deletion patterns — removing boundary/terminator characters
  const SENTINEL_DELETE = /\b(\.replace\s*\(\s*\/\\0|\.replace\s*\(\s*\/\\n\s*\/\s*[gim]*\s*,\s*['"]|\.replace\s*\(\s*['"]\\0|\.replace\s*\(\s*\/\\r\\n|\.trimEnd\s*\(\)|\.trimRight\s*\(\)|\.slice\s*\(\s*0\s*,\s*-1\s*\)|\.pop\s*\(\)|\.splice\s*\(\s*-1|null.?byte|NUL|sentinel|terminator|delimiter|boundary)\b/i;
  // Binary/protocol data context where sentinels matter
  const BINARY_PROTOCOL = /\b(Buffer|ArrayBuffer|Uint8Array|DataView|protocol|packet|frame|header|payload|binary|serialize|deserialize|marshal|unmarshal|encode|decode|wire|socket|tcp|udp|stream|pipe|\.write\s*\(|\.read\s*\(|readUInt|writeUInt|readInt|writeInt|readFloat|writeFloat)\b/i;
  // Safe — proper boundary handling
  const BOUNDARY_SAFE = /\b(assert|invariant|check.?boundary|check.?length|validate.?length|\.length\s*[><=!]+|\.byteLength|bounds.?check|sentinel.?check|terminator.?check|null.?terminated|ensure.?terminated|append.?null|add.?sentinel)\b/i;

  const ingress = nodesOfType(map, 'INGRESS');
  const transforms = nodesOfType(map, 'TRANSFORM');

  for (const src of ingress) {
    for (const sink of transforms) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if ((SENTINEL_DELETE.test(code) && BINARY_PROTOCOL.test(code)) ||
            // Null-byte injection — user input with \0 reaching string operations
            (/\\0|%00|null.?byte/i.test(code) && !BOUNDARY_SAFE.test(code))) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (sentinel preservation or boundary re-validation)',
            severity: 'medium',
            description: `Data from ${src.label} may have sentinel/terminator values removed at ${sink.label}. ` +
              `Deleting sentinels (null terminators, record delimiters, boundary markers) from data structures ` +
              `causes downstream code to read past boundaries, merge records, or misparse protocol data.`,
            fix: 'Preserve sentinel values in binary/protocol data. If stripping is necessary, ' +
              're-validate boundaries after transformation. For null bytes: reject input containing \\0 ' +
              'unless the protocol explicitly allows it. For protocol delimiters: use length-prefixed ' +
              'framing instead of delimiter-based parsing.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Also scan for direct sentinel manipulation in any node
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    // C-style null terminator overwrite
    if (/\[\s*\w+\s*\]\s*=\s*[^;]*[^'"]\\0|str\s*\[\s*len\s*\]\s*=\s*[^'"](?!\\0)/i.test(code) &&
        BINARY_PROTOCOL.test(code) && !BOUNDARY_SAFE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (sentinel value preservation)',
        severity: 'high',
        description: `Potential sentinel value overwrite at ${node.label} in binary/protocol context. ` +
          `Overwriting the null terminator or boundary marker causes buffer over-reads or protocol confusion.`,
        fix: 'Never write past the allocated buffer length. Use safe string functions that guarantee null termination. ' +
          'In C: use strlcpy/snprintf instead of strcpy/sprintf. In binary protocols: validate offset before write.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-463', name: 'Deletion of Data Structure Sentinel', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-464: Addition of Data Structure Sentinel
// ---------------------------------------------------------------------------

/**
 * CWE-464: Addition of Data Structure Sentinel
 * Detects when user input can inject sentinel/terminator values into data structures,
 * causing premature termination or record splitting. The classic example is null-byte
 * injection (%00) that truncates strings in C-backed functions, but also covers
 * CRLF injection, record separator injection, and path separator injection.
 *
 * Detection: INGRESS data containing potential sentinel characters flows to
 * sensitive operations without stripping/rejecting those characters.
 */

// ---------------------------------------------------------------------------
// CWE-464: Addition of Data Structure Sentinel
// ---------------------------------------------------------------------------

/**
 * CWE-464: Addition of Data Structure Sentinel
 * Detects when user input can inject sentinel/terminator values into data structures,
 * causing premature termination or record splitting. The classic example is null-byte
 * injection (%00) that truncates strings in C-backed functions, but also covers
 * CRLF injection, record separator injection, and path separator injection.
 *
 * Detection: INGRESS data containing potential sentinel characters flows to
 * sensitive operations without stripping/rejecting those characters.
 */
function verifyCWE464(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Sentinel-sensitive operations
  const SENTINEL_SINK = /\b(exec|execSync|spawn|spawnSync|execFile|system|popen|open|fopen|readFile|writeFile|path\.join|path\.resolve|require\s*\(|import\s*\(|include|include_once|require_once|eval|setHeader|writeHead|createReadStream|createWriteStream|sql|query|prepare|execute|\.write\s*\(|send|sendFile|download|redirect)\b/i;
  // Null-byte, CRLF, path separator patterns that could be injected
  const SENTINEL_CHARS_UNSAFE = /\b(\.replace|\.split|\.indexOf|\.includes|\.match|\.test|\.search)\b/i;
  // Safe — sanitization that removes/rejects sentinel characters
  const SENTINEL_SANITIZE = /\b(\.replace\s*\(\s*\/[\[\\]*(\\0|%00|\x00|\\n|\\r|\\r\\n|[\\/]|\\\\)[\]]*\/|encodeURIComponent|encodeURI|sanitize|escape|strip.?null|reject.?null|no.?null|path\.normalize|\.normalize\s*\(|validator\.escape|xss|DOMPurify|\.replace\s*\(\s*\/[\\]0\/g|\.replace\s*\(\s*\/\\x00\/g)\b/i;

  // Scan for paths where null/CRLF bytes could survive into sensitive sinks
  const sinkNodes = map.nodes.filter(n => SENTINEL_SINK.test(stripComments(n.analysis_snapshot || n.code_snapshot)));

  for (const src of ingress) {
    for (const sink of sinkNodes) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const containingFunc = findContainingFunction(map, sink.id);
        const funcCode = containingFunc
          ? stripComments(map.nodes.find(n => n.id === containingFunc)?.analysis_snapshot || map.nodes.find(n => n.id === containingFunc)?.code_snapshot || '')
          : '';
        const allCode = sinkCode + ' ' + funcCode;

        // Check if there's no sentinel stripping in the path
        if (!SENTINEL_SANITIZE.test(allCode)) {
          // Determine what kind of sentinel injection is likely
          const isPathOp = /\b(path\.|readFile|writeFile|open|fopen|include|require|createReadStream|createWriteStream|sendFile|download)\b/i.test(sinkCode);
          const isHeaderOp = /\b(setHeader|writeHead|header\s*\(|response\.header|res\.set)\b/i.test(sinkCode);
          const isExecOp = /\b(exec|spawn|system|popen|execFile)\b/i.test(sinkCode);

          const context = isPathOp ? 'path operation (null-byte truncation can bypass extension checks)'
            : isHeaderOp ? 'HTTP header (CRLF injection enables header splitting / response splitting)'
            : isExecOp ? 'command execution (null-byte or shell metacharacter injection)'
            : 'sensitive operation';

          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (sentinel character rejection or stripping)',
            severity: isHeaderOp || isExecOp ? 'high' : 'medium',
            description: `User input from ${src.label} reaches ${context} at ${sink.label} without sentinel character filtering. ` +
              `An attacker can inject null bytes (\\0/%00), CRLF (\\r\\n), or path separators to ` +
              `truncate strings, split records, or escape intended boundaries.`,
            fix: isPathOp
              ? 'Reject or strip null bytes from file paths: input.replace(/\\0/g, ""). ' +
                'Use path.normalize() and verify the result is still within the expected directory. ' +
                'Validate file extensions AFTER null-byte stripping.'
              : isHeaderOp
              ? 'Strip \\r and \\n from header values: value.replace(/[\\r\\n]/g, ""). ' +
                'Modern frameworks (Express 4.x+, etc.) reject CRLF in headers automatically — ensure you\'re on a current version.'
              : 'Reject input containing null bytes (\\0), carriage returns (\\r), and line feeds (\\n) ' +
                'before passing to sensitive operations. Use allowlist validation where possible.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-464', name: 'Addition of Data Structure Sentinel', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Malicious code & covert channel CWEs
// ---------------------------------------------------------------------------

/**
 * CWE-494: Download of Code Without Integrity Check
 * Pattern: Fetching remote code (scripts, modules, updates) and executing it
 * without verifying a hash, signature, or checksum first.
 * Sources: fetch/http.get/curl/wget/import() of remote URLs
 * Sinks: eval/exec/Function()/spawn/require()/import() or file writes
 * Missing: Integrity verification (hash comparison, signature check, SRI)
 */

// ---------------------------------------------------------------------------
// Timing & State
// ---------------------------------------------------------------------------

/**
 * CWE-370: Missing Check for Certificate Revocation After Initial Check
 *
 * TLS/certificate validation that checks validity at connection time but never
 * rechecks revocation status for long-lived connections. OCSP stapling or CRL
 * checks must be periodic, not just at handshake.
 */
function verifyCWE370(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const CERT_VALIDATION_RE = /\b(X509|certificate|cert|ssl|tls|TLSSocket|https\.createServer|SSLContext|ssl\.create_default_context|X509TrustManager|CertificateFactory|PKIXParameters|checkValidity|verify\s*\(\s*cert|TrustManagerFactory|ssl_context|Net::SSL|OpenSSL::SSL|rustls|reqwest.*danger_accept_invalid_certs)\b/i;
  const REVOCATION_CHECK_RE = /\b(OCSP|ocsp|CRL|crl|checkRevocation|revocation|X509Revoked|setRevocationEnabled|PKIXRevocationChecker|CertPathValidator|OCSPReq|OCSPResp|isRevoked|RevocationList|crl_distribution_points|OCSP_basic_verify|must_staple|ocsp_stapling|setEnableCRLDP|setEnableOCSP|check_revocation|certificate_revocation|RevocationMode|X509RevocationMode|X509RevocationFlag)\b/i;
  const LONG_LIVED_RE = /\b(keep.?alive|persistent|pool|connection.?pool|reuse|long.?lived|setKeepAlive|keepAliveTimeout|maxSockets|Agent|http\.Agent|ConnectionPool|PoolingHttpClient|session|Session|createPool|getConnection)\b/i;
  const SAFE_REVOCATION_RE = /\b(OCSP.*stapl|stapl.*OCSP|setRevocationEnabled\s*\(\s*true|PKIXRevocationChecker|check_revocation\s*=\s*True|RevocationMode\.Online|X509RevocationMode\.Online|must_staple|ssl_check_revocation|enable.*revocation|crl_check|VERIFY_CRL_CHECK|X509_V_FLAG_CRL_CHECK)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!CERT_VALIDATION_RE.test(code)) continue;

    if (!REVOCATION_CHECK_RE.test(code) && !SAFE_REVOCATION_RE.test(code)) {
      if (/\b(createServer|SSLContext|ssl_context|TrustManager|X509Certificate|verify|handshake|connect)\b/i.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (OCSP stapling or CRL revocation check)',
          severity: 'medium',
          description: `TLS/certificate setup at ${node.label} validates certificates but has no revocation checking (OCSP/CRL). ` +
            `A compromised certificate that has been revoked by the CA will still be accepted.`,
          fix: 'Enable OCSP stapling on the server, or configure CRL checking on the client. ' +
            'In Java: use PKIXRevocationChecker with PKIXParameters. ' +
            'In Python: set ssl_context.check_revocation = True. ' +
            'In Node.js: use a custom agent with OCSP verification.',
          via: 'structural',
        });
      }
    }

    if (LONG_LIVED_RE.test(code) && CERT_VALIDATION_RE.test(code) && !SAFE_REVOCATION_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (periodic certificate revocation recheck for pooled connections)',
        severity: 'medium',
        description: `Connection pool at ${node.label} uses TLS but does not periodically recheck certificate revocation. ` +
          `Long-lived connections may continue using a certificate that has been revoked since the initial handshake.`,
        fix: 'Set a maximum connection lifetime in the pool (e.g., maxLifetimeMillis). ' +
          'Enable OCSP stapling on the server side. Periodically rotate pool connections to force re-handshake and revocation recheck.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-370', name: 'Missing Check for Certificate Revocation After Initial Check', holds: findings.length === 0, findings };
}

/**
 * CWE-372: Incomplete Internal State Distinction
 *
 * A system fails to properly distinguish between different internal states,
 * using the same variable/flag to represent multiple distinct conditions.
 * An attacker who can influence one state transition affects the other.
 */

/**
 * CWE-372: Incomplete Internal State Distinction
 *
 * A system fails to properly distinguish between different internal states,
 * using the same variable/flag to represent multiple distinct conditions.
 * An attacker who can influence one state transition affects the other.
 */
function verifyCWE372(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const MULTI_SET_RE = /(\bisAuthenticated|\bisValid|\bisReady|\bisActive|\bisEnabled|\bisAllowed|\bhasAccess|\bisVerified|\bisApproved|\bloggedIn|\bauthorized|\bauthenticated|\bverified|\bapproved)\s*=\s*true/gi;
  const ENUM_STATE_RE = /\b(enum\s+\w*State|enum\s+\w*Status|State\.\w+|Status\.\w+|STATE_\w+|status\s*===?\s*['"][A-Z_]+['"])\b/i;
  const STATE_MACHINE_RE = /\b(StateMachine|state_machine|FSM|transition|setState|nextState|currentState)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    const matches = code.match(MULTI_SET_RE);
    if (matches && matches.length >= 2) {
      const uniqueFlags = new Set(matches.map(m => m.split(/\s*=/)[0].trim().toLowerCase()));
      for (const flag of uniqueFlags) {
        const flagRe = new RegExp(`\\b${flag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*true`, 'gi');
        const flagMatches = code.match(flagRe);
        if (flagMatches && flagMatches.length >= 2 && !ENUM_STATE_RE.test(code) && !STATE_MACHINE_RE.test(code)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (distinct state representation — enum or state machine instead of boolean)',
            severity: 'low',
            description: `Boolean flag "${flag}" at ${node.label} is set to true in multiple distinct contexts. ` +
              `A single boolean cannot distinguish HOW the state was reached — email-verified and OAuth-verified ` +
              `both set isVerified=true, but they have different trust implications.`,
            fix: 'Replace boolean state flags with an enum or state machine that encodes the specific transition path. ' +
              'Example: instead of isAuthenticated=true, use authState = AuthState.PASSWORD_VERIFIED or AuthState.OAUTH_VERIFIED. ' +
              'This prevents state confusion attacks where achieving one state grants access intended for another.',
            via: 'structural',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-372', name: 'Incomplete Internal State Distinction', holds: findings.length === 0, findings };
}

/**
 * CWE-374: Passing Mutable Objects to an Untrusted Method
 *
 * Passing mutable internal state (arrays, collections, objects) to external or
 * untrusted methods. The callee can modify the caller's internal state through
 * the shared reference.
 */

/**
 * CWE-374: Passing Mutable Objects to an Untrusted Method
 *
 * Passing mutable internal state (arrays, collections, objects) to external or
 * untrusted methods. The callee can modify the caller's internal state through
 * the shared reference.
 */
function verifyCWE374(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const INTERNAL_STATE_RE = /\b(?:this\.|self\.|@|_)\w+(?:List|Array|Map|Set|Items|Collection|Data|Records|Buffer|Config|Settings|Options|State|Cache|Store|Queue|Stack)\b/i;
  const EXTERNAL_CALL_RE = /\b(?:callback|handler|listener|plugin|middleware|hook|delegate|observer|visitor|interceptor|fn|func|onSuccess|onError|onComplete|emit|dispatch|publish|notify|trigger|fire|broadcast)\s*\(/i;
  const UNTRUSTED_CALL_RE = /\b(?:eval|Function\s*\(|require\s*\(|import\s*\(|load|exec|execute|invoke|apply|call|send|post|fetch|request|api\.\w+|client\.\w+|service\.\w+|remote\.\w+|thirdParty|external|plugin|module)\s*\(/i;

  const SAFE_PASS_RE = /\b(Object\.freeze|Object\.assign\s*\(\s*\{\}|structuredClone|\[\.\.\.this\.|\.slice\(\)|\.concat\(\)|Array\.from|new\s+(?:Array|Set|Map|List|ArrayList|HashMap)\s*\(|Collections\.unmodifiable|List\.copyOf|Map\.copyOf|Set\.copyOf|copy\.deepcopy|list\(|dict\(|tuple\(|\.dup\b|\.clone\(\)|\.freeze\b|readonly|Immutable|deepClone|defensiveCopy|toImmutable|asUnmodifiable|\.toList\(\)|\.toMap\(\))\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!INTERNAL_STATE_RE.test(code)) continue;
    if (!(EXTERNAL_CALL_RE.test(code) || UNTRUSTED_CALL_RE.test(code))) continue;
    if (SAFE_PASS_RE.test(code)) continue;

    const internalMatch = code.match(/(?:this\.|self\.|@|_)\w+(?:List|Array|Map|Set|Items|Collection|Data|Records|Buffer|Config|Settings|Options|State|Cache|Store|Queue|Stack)/i);
    const callMatch = code.match(/(?:callback|handler|listener|plugin|middleware|hook|delegate|observer|fn|func|emit|dispatch|publish|notify|trigger|eval|Function|exec|execute|invoke|apply|call)\s*\(/i);

    if (internalMatch && callMatch) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (defensive copy before passing internal state to external method)',
        severity: 'medium',
        description: `${node.label} passes internal mutable state (${internalMatch[0]}) to an external or callback method. ` +
          `The callee receives a reference to the same object and can modify the caller's internal state, ` +
          `bypassing encapsulation, invariant checks, and access controls.`,
        fix: 'Pass a defensive copy: callback([...this._items]) (JS), callback(list(self._data)) (Python), ' +
          'callback(Collections.unmodifiableList(this.items)) (Java). For deep structures, use structuredClone() ' +
          'or Object.freeze() to prevent nested mutations.',
        via: 'structural',
      });
    }
  }

  return { cwe: 'CWE-374', name: 'Passing Mutable Objects to an Untrusted Method', holds: findings.length === 0, findings };
}

/**
 * CWE-375: Returning a Mutable Object to an Untrusted Caller
 *
 * A method returns a direct reference to an internal mutable object. The caller
 * (potentially untrusted) can modify the object and corrupt the internal state.
 * Stronger variant of CWE-495 — focuses on trust boundary crossing.
 */

/**
 * CWE-375: Returning a Mutable Object to an Untrusted Caller
 *
 * A method returns a direct reference to an internal mutable object. The caller
 * (potentially untrusted) can modify the object and corrupt the internal state.
 * Stronger variant of CWE-495 — focuses on trust boundary crossing.
 */
function verifyCWE375(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const RETURN_MUTABLE_RE = /\breturn\s+(?:this\.|self\.|@)\s*_?\w+(?:List|Array|Map|Set|Items|Collection|Data|Records|Buffer|Config|Settings|Options|State|Cache|Store|Queue|Stack|Entries|credentials|secrets|keys|tokens)\s*;?$/im;
  const GETTER_RE = /\b(?:get\s+\w+\s*\(|get\w+\s*\(\s*\)|@property|@\w+\.getter|def\s+\w+\s*\(\s*self\s*\)|public\s+\w+(?:\[\]|<\w+>|List|Map|Set|Collection|Array)\s+get\w+\s*\()\b/i;
  const API_BOUNDARY_RE = /\b(?:public|export|@api|@route|@app\.|@controller|@RequestMapping|@GetMapping|@PostMapping|@Expose|module\.exports|router\.\w+)\b/i;

  const SAFE_RETURN_RE = /\b(\.slice\(\)|\.concat\(\)|Array\.from|Object\.assign\s*\(\s*\{\}|structuredClone|\[\.\.\.this\.|\{\.\.\.this\.|new\s+(?:Array|Set|Map|List|ArrayList|HashMap|HashSet)\s*\(|Collections\.unmodifiable|List\.copyOf|Map\.copyOf|Set\.copyOf|Object\.freeze|\.freeze\(|readonly|Immutable|unmodifiable|deepCopy|defensiveCopy|\.copy\(\)|copy\.copy|copy\.deepcopy|\.dup\b|\.clone\(\)|\.toList\(\)|\.toArray\(\)|\.toMap\(\)|ImmutableList|ImmutableMap|ImmutableSet|\.frozen\?|\.freeze\b|as\s+const)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (!RETURN_MUTABLE_RE.test(code)) continue;
    if (!API_BOUNDARY_RE.test(code) && !GETTER_RE.test(code)) continue;
    if (SAFE_RETURN_RE.test(code)) continue;

    const returnMatch = code.match(/return\s+((?:this\.|self\.|@)\s*_?\w+)/i);
    const fieldName = returnMatch ? returnMatch[1] : 'internal mutable field';

    findings.push({
      source: nodeRef(node), sink: nodeRef(node),
      missing: 'TRANSFORM (defensive copy or immutable wrapper before returning to untrusted caller)',
      severity: 'medium',
      description: `Public method at ${node.label} returns a direct reference to internal mutable state (${fieldName}). ` +
        `Any caller — including untrusted code — can modify the returned object and corrupt ` +
        `the enclosing object's invariants, cache consistency, or security state.`,
      fix: 'Return a defensive copy or immutable view: return [...this._items] (JS), ' +
        'return Collections.unmodifiableList(this.items) (Java), return list(self._data) (Python). ' +
        'For security-sensitive state (credentials, tokens), never expose the backing store directly.',
      via: 'structural',
    });
  }

  return { cwe: 'CWE-375', name: 'Returning a Mutable Object to an Untrusted Caller', holds: findings.length === 0, findings };
}

/**
 * CWE-385: Covert Timing Channel
 *
 * Operations whose execution time depends on secret data, allowing an attacker
 * to extract secrets by measuring response times. Classic examples: non-constant-time
 * string comparison for passwords/tokens, early-return on first mismatch.
 */

/**
 * CWE-385: Covert Timing Channel
 *
 * Operations whose execution time depends on secret data, allowing an attacker
 * to extract secrets by measuring response times. Classic examples: non-constant-time
 * string comparison for passwords/tokens, early-return on first mismatch.
 */
function verifyCWE385(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Library/framework code does not perform application-level secret comparison
  if (isLibraryCode(map)) {
    return { cwe: 'CWE-385', name: 'Covert Timing Channel', holds: true, findings };
  }

  const SECRET_COMPARE_RE = /\b(password|passwd|secret|token|apiKey|api_key|hmac|digest|hash|signature|mac|key|pin|otp|nonce|csrf|session_id|sessionId|auth_token|authToken|access_token|accessToken)\b.*(?:===?|!==?|\.equals\(|strcmp|==|!=|\.compareTo\(|\.match\(|\.startsWith\(|\.endsWith\()/i;
  const COMPARE_SECRET_RE = /(?:===?|!==?|\.equals\(|strcmp|==|!=|\.compareTo\(|\.match\(|\.startsWith\(|\.endsWith\().*\b(password|passwd|secret|token|apiKey|api_key|hmac|digest|hash|signature|mac|key|pin|otp|nonce|csrf|session_id|sessionId|auth_token|authToken|access_token|accessToken)\b/i;
  const EARLY_RETURN_RE = /\bif\s*\([^)]*(?:password|token|secret|key|hmac|signature|hash|digest)\b[^)]*(?:!==?|===?)[^)]*\)\s*(?:return|throw|break|continue|res\.status\(4)/i;

  const SAFE_COMPARE_RE = /\b(timingSafeEqual|crypto\.timingSafeEqual|hmac\.compare_digest|constantTimeCompare|ConstantTimeCompare|constant_time_compare|secure_compare|secureCompare|MessageDigest\.isEqual|SecureComparator|timing_safe_equal|OpenSSL\.secure_compare|rack\.utils\.secure_compare|Devise\.secure_compare|ActiveSupport::SecurityUtils|constantTimeEquals|safeEqual|SlowEquals|CryptographicOperations\.FixedTimeEquals)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    const isSecretCompare = SECRET_COMPARE_RE.test(code) || COMPARE_SECRET_RE.test(code);
    const isEarlyReturn = EARLY_RETURN_RE.test(code);

    if ((isSecretCompare || isEarlyReturn) && !SAFE_COMPARE_RE.test(code)) {
      const isAuthContext = node.node_type === 'CONTROL' || node.node_type === 'AUTH' ||
        /\b(auth|login|verify|validate|check|compare|match|authenticate)\b/i.test(node.label) ||
        /\b(auth|login|verify|validate|check|compare|match|authenticate)\b/i.test(node.node_subtype);

      if (isAuthContext || isEarlyReturn) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (constant-time comparison for secret values)',
          severity: 'high',
          description: `${node.label} compares secret values (passwords, tokens, HMACs) using non-constant-time operations. ` +
            `Standard string comparison returns on first mismatch, leaking how many bytes match. ` +
            `With enough measurements, an attacker can extract the secret byte-by-byte.`,
          fix: 'Use crypto.timingSafeEqual() (Node.js), hmac.compare_digest() (Python), ' +
            'MessageDigest.isEqual() (Java), ConstantTimeCompare() (Go), or rack.utils.secure_compare (Ruby). ' +
            'Never use == or === for comparing secrets, tokens, or HMAC digests.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-385', name: 'Covert Timing Channel', holds: findings.length === 0, findings };
}

/**
 * CWE-386: Symbolic Name Not Mapping to Correct Object
 *
 * A symbolic name (filename, hostname, variable name, registry key) resolves to
 * a different object than intended because the resolution depends on mutable
 * external state (DNS, filesystem, PATH, classpath, etc).
 */

/**
 * CWE-386: Symbolic Name Not Mapping to Correct Object
 *
 * A symbolic name (filename, hostname, variable name, registry key) resolves to
 * a different object than intended because the resolution depends on mutable
 * external state (DNS, filesystem, PATH, classpath, etc).
 */
function verifyCWE386(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const DNS_USED_FOR_AUTH_RE = /\b(?:if|switch|match|case|allow|deny|trust|verify|authenticate|authorize)\s*\([^)]*(?:hostname|host|domain|ip|addr|address|remote_addr|peer|client_ip|source_ip|remoteHost)\b/i;
  const SAFE_DNS_RE = /\b(certificate.?pin|pin.?certificate|HPKP|pinning|ssl.?pin|cert.?pin|TLSA|DANE|DNSSEC|verif.*certificate|mutual.?TLS|mTLS|client.?cert|IP\.parse|inet_aton|inet_pton|IPAddress\.parse|ipaddress\.ip_address)\b/i;

  const RELATIVE_PATH_RE = /\b(require\s*\(\s*['"][^./]|import\s+['"][^./]|dlopen\s*\(\s*['"][^/]|LoadLibrary\s*\(\s*['"][^/\\]|System\.loadLibrary\s*\(\s*['"][^/])\b/;
  const SAFE_RESOLVE_RE = /\b(absolute.?path|full.?path|realpath|canonicalize|resolve|Path\.resolve|path\.resolve|os\.path\.abspath|Path\.of|Paths\.get|__dirname|__filename|import\.meta\.url|require\.resolve|pin|whitelist|allowlist|verify.?path)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    if (DNS_USED_FOR_AUTH_RE.test(code) && !SAFE_DNS_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (cryptographic identity verification instead of DNS-based trust)',
        severity: 'high',
        description: `${node.label} makes trust/authorization decisions based on DNS-resolved hostnames. ` +
          `DNS is not authenticated by default — an attacker with DNS cache poisoning or MITM can ` +
          `make their malicious host resolve to a trusted name.`,
        fix: 'Never trust hostnames for authorization. Use mutual TLS (mTLS) with certificate pinning, ' +
          'DNSSEC for verified resolution, or authenticate the peer via cryptographic tokens/signatures. ' +
          'For IP-based filtering, resolve once and verify the certificate matches the expected identity.',
        via: 'structural',
      });
    }

    if (RELATIVE_PATH_RE.test(code) && !SAFE_RESOLVE_RE.test(code)) {
      const isSecurityContext = /\b(auth|security|crypto|secret|credential|admin|privilege|permission|trust)\b/i.test(code) ||
        node.node_subtype.includes('security') || node.node_subtype.includes('auth');

      if (isSecurityContext) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (absolute path or verified module resolution)',
          severity: 'medium',
          description: `${node.label} loads a module/library via relative path in a security-sensitive context. ` +
            `Relative paths resolve through PATH/NODE_PATH/CLASSPATH which can be manipulated. ` +
            `An attacker who controls the resolution order can substitute a malicious module.`,
          fix: 'Use absolute paths for security-critical modules. In Node.js: require(path.resolve(__dirname, "module")). ' +
            'In Python: use importlib with explicit paths. In C: use absolute paths for dlopen(). ' +
            'Verify loaded module integrity with checksums or signatures.',
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-386', name: 'Symbolic Name Not Mapping to Correct Object', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const RESOURCE_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Resource Exhaustion & DoS
  'CWE-400': verifyCWE400,
  'CWE-770': verifyCWE770,
  'CWE-1333': verifyCWE1333,
  'CWE-404': verifyCWE404,
  'CWE-405': verifyCWE405,
  'CWE-406': verifyCWE406,
  'CWE-407': verifyCWE407,
  'CWE-409': verifyCWE409,
  'CWE-410': verifyCWE410,
  // Race Conditions
  'CWE-362': verifyCWE362,
  'CWE-366': verifyCWE366,
  'CWE-367': verifyCWE367,
  'CWE-363': verifyCWE363,
  'CWE-364': verifyCWE364,
  'CWE-365': verifyCWE365,
  'CWE-368': verifyCWE368,
  // Temp File Races
  'CWE-377': verifyCWE377,
  'CWE-378': verifyCWE378,
  'CWE-379': verifyCWE379,
  // Search Path
  'CWE-426': verifyCWE426,
  'CWE-427': verifyCWE427,
  'CWE-428': verifyCWE428,
  // Resource Exposure & Sphere
  'CWE-668': verifyCWE668,
  // Synchronization & Locking
  'CWE-662': verifyCWE662,
  'CWE-667': verifyCWE667,
  'CWE-764': verifyCWE764,
  'CWE-765': verifyCWE765,
  'CWE-832': verifyCWE832,
  'CWE-833': verifyCWE833,
  // Signal & Thread Safety
  'CWE-382': verifyCWE382,
  'CWE-383': verifyCWE383,
  // Resource Lifecycle
  'CWE-672': verifyCWE672,
  'CWE-674': verifyCWE674,
  'CWE-676': verifyCWE676,
  'CWE-694': verifyCWE694,
  'CWE-771': verifyCWE771,
  'CWE-772': verifyCWE772,
  'CWE-775': verifyCWE775,
  'CWE-401': verifyCWE401,
  'CWE-403': verifyCWE403,
  // Cleanup & Init
  'CWE-459': verifyCWE459,
  'CWE-460': verifyCWE460,
  'CWE-462': verifyCWE462,
  'CWE-463': verifyCWE463,
  'CWE-464': verifyCWE464,
  // Timing & State
  'CWE-370': verifyCWE370,
  'CWE-372': verifyCWE372,
  'CWE-374': verifyCWE374,
  'CWE-375': verifyCWE375,
  'CWE-385': verifyCWE385,
  'CWE-386': verifyCWE386,
};
