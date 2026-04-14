/**
 * DST Generated Verifiers — Shared Helpers
 * Graph traversal, node filtering, result types, shared safe-pattern regexes,
 * compact factory, BFS shortcuts, source scanning utilities, and language
 * detection used by all batches.
 */

import type { NeuralMap, NeuralMapNode, NodeType, EdgeType, RangeInfo } from '../types';
import { rangeExcludesZero, isRangeSafe } from '../types';

// ---------------------------------------------------------------------------
// Result types (same shape as verifier.ts exports)
// ---------------------------------------------------------------------------

export interface VerificationResult {
  cwe: string;
  name: string;
  holds: boolean;
  findings: Finding[];
}

export interface Finding {
  source: NodeRef;
  sink: NodeRef;
  missing: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fix: string;
  via?: 'bfs' | 'sink_tainted' | 'scope_taint' | 'source_line_fallback' | 'structural';
}

export interface NodeRef {
  id: string;
  label: string;
  line: number;
  code: string;
  file?: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low';

// ---------------------------------------------------------------------------
// Graph helpers
// ---------------------------------------------------------------------------

/**
 * Edge types that represent actual data flow between nodes.
 * CONTAINS is structural containment (function contains statement) and
 * DEPENDS is a dependency relationship — neither represents data movement.
 * BFS for vulnerability path detection should only follow flow edges.
 */
const FLOW_EDGE_TYPES: ReadonlySet<EdgeType> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);

export function nodeRef(node: NeuralMapNode): NodeRef {
  return { id: node.id, label: node.label, line: node.line_start, code: node.code_snapshot.slice(0, 200), file: node.file };
}

export function nodesOfType(map: NeuralMap, type: NodeType): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === type);
}

/**
 * Unified BFS: is there a path from source to sink that never passes through a
 * "gate" node (a node whose type matches gateType)?
 *
 * @param map         - The neural map to traverse
 * @param sourceId    - Start node ID
 * @param sinkId      - Target node ID
 * @param gateType    - NodeType (or array of NodeTypes) that counts as the gate
 * @param requireTaint - When true, only nodes with tainted data_in count as sources;
 *                       currently unused at the BFS level (callers pre-filter sources)
 *                       but included for API completeness and future use.
 *
 * Uses composite visited keys (nodeId:passedGate) to prevent safe-path pruning —
 * a safe path through the gate must not block exploration of unsafe paths.
 * Uses index-based queue iteration (O(n)) instead of shift() (O(n²)).
 * Only follows data-flow edges — CONTAINS/DEPENDS are excluded.
 */
export function hasPathWithoutGate(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
  gateType: NodeType | NodeType[],
  _requireTaint?: boolean,
): boolean {
  const gateSet: ReadonlySet<NodeType> = Array.isArray(gateType)
    ? new Set(gateType)
    : new Set([gateType]);
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedGate: boolean }> = [
    { nodeId: sourceId, passedGate: false },
  ];
  let head = 0; // index-based dequeue — O(1) instead of shift() O(n)

  while (head < queue.length) {
    const { nodeId, passedGate } = queue[head++];
    const visitKey = `${nodeId}:${passedGate}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    const isGateType = gateSet.has(node.node_type);

    // A gate only counts if it actually processes data from the tracked path.
    // A CONTROL named "sanitize" that doesn't touch the tainted variable is NOT a real gate.
    const isEffectiveGate = isGateType &&
      (node.data_in?.some(d => d.tainted || d.sensitivity !== 'NONE') ?? false);

    const gateNow = passedGate || isEffectiveGate;

    if (nodeId === sinkId) {
      if (!gateNow) return true;
      continue;
    }

    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      const edgeKey = `${edge.target}:${gateNow}`;
      if (!visited.has(edgeKey)) {
        queue.push({ nodeId: edge.target, passedGate: gateNow });
      }
    }
  }

  return false;
}

/**
 * BFS: is there a path from source to sink that never passes through a CONTROL node?
 * Delegates to hasPathWithoutGate.
 */
export function hasTaintedPathWithoutControl(map: NeuralMap, sourceId: string, sinkId: string): boolean {
  return hasPathWithoutGate(map, sourceId, sinkId, 'CONTROL');
}

/**
 * Fallback taint check: does the sink node's data_in contain a tainted entry
 * whose source is reachable from sourceId via BFS?
 *
 * This covers cases where the mapper captured taint in data_in entries but
 * did not emit explicit DATA_FLOW edges between the source and the sink.
 * Used as a belt-and-suspenders fallback after hasTaintedPathWithoutControl.
 *
 * Multi-hop: any tainted data_in entry on the sink counts, regardless of
 * which specific source node it names — the fact that `d.tainted === true`
 * means the mapper already decided taint reaches this sink.
 */
export function sinkHasTaintedDataIn(map: NeuralMap, sinkId: string): boolean {
  const sink = map.nodes.find(n => n.id === sinkId);
  if (!sink) return false;
  return sink.data_in.some(d => d.tainted);
}

// ---------------------------------------------------------------------------
// Range-aware helpers (Step 7) — used by CWE-190, 191, 369, 131
// ---------------------------------------------------------------------------

/**
 * Check if a sink node has any data_in with a bounded range.
 * Used by integer/arithmetic verifiers to suppress findings when
 * the incoming data is provably bounded by a CONTROL gate.
 */
export function sinkHasBoundedRange(map: NeuralMap, sinkId: string): boolean {
  const sink = map.nodes.find(n => n.id === sinkId);
  if (!sink) return false;
  return sink.data_in.some(d => d.range?.bounded === true);
}

/**
 * Check if a sink node has data_in with a range that provably excludes zero.
 * Used by CWE-369 (divide by zero) to suppress findings when the divisor
 * is known to be non-zero from a CONTROL gate.
 */
export function sinkHasNonZeroRange(map: NeuralMap, sinkId: string): boolean {
  const sink = map.nodes.find(n => n.id === sinkId);
  if (!sink) return false;
  return sink.data_in.some(d => d.range != null && rangeExcludesZero(d.range));
}

/**
 * Check if a sink node has data_in with a range that fits within [0, maxSafe].
 * Used by CWE-190 (integer overflow) to suppress findings when the value
 * is known to be within safe bounds from a CONTROL gate.
 */
export function sinkHasSafeRange(map: NeuralMap, sinkId: string, maxSafe: number): boolean {
  const sink = map.nodes.find(n => n.id === sinkId);
  if (!sink) return false;
  return sink.data_in.some(d => d.range != null && isRangeSafe(d.range, maxSafe));
}

/**
 * Get all ranges from a sink's data_in.
 * Returns an empty array if no ranges are present.
 */
export function getSinkRanges(map: NeuralMap, sinkId: string): RangeInfo[] {
  const sink = map.nodes.find(n => n.id === sinkId);
  if (!sink) return [];
  return sink.data_in
    .filter(d => d.range != null)
    .map(d => d.range!);
}

/**
 * SECOND PASS: Evaluate whether CONTROL nodes on a mediated path are actually
 * effective. Returns an array of "weak control" findings.
 *
 * This is the anti-inversion engine. When a path from INGRESS to SINK passes
 * through a CONTROL node, the first pass says "safe." This function asks:
 * "but IS that control actually safe?"
 *
 * Checks for:
 *   - ReDoS: regex in CONTROL has catastrophic backtracking patterns (CWE-1333)
 *   - Sanitizer collapse: CONTROL strips chars that create new dangerous values (CWE-182)
 *   - User-controlled both sides: auth compares two user-supplied values (CWE-639)
 *   - Dead control: CONTROL is in unreachable code or always-true condition
 *   - Incomplete validation: CONTROL validates one field but not the dangerous one
 */
export interface WeakControlFinding {
  controlNode: NeuralMapNode;
  weakness: string;
  cwe: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
}

// ReDoS-prone regex patterns — exponential backtracking
const REDOS_PATTERNS = [
  /\([^)]*[+*][^)]*\)[+*]/,      // (a+)+ or (a*)*
  /\([^)]*\|[^)]*\)[+*]/,         // (a|b)+ with overlapping
  /\([^)]*[+*][^)]*[+*]\)/,       // nested quantifiers (a+b+)
  /\.[\*\+]\.\*$/,                  // .*.*
  /\([^)]*\\s[+*][^)]*\)[+*]/,    // (\s+)+
];

// Patterns that indicate a control compares user-controlled values on both sides
const BOTH_SIDES_USER_RE = /(?:req\.|params\.|query\.|body\.|input\.|user\.).*(?:===?|!==?).*(?:req\.|params\.|query\.|body\.|input\.|user\.)/;

// Sanitizers that strip/remove characters (could collapse into dangerous values)
const STRIP_SANITIZER_RE = /\.replace\s*\([^,]+,\s*['"`]{2}\s*\)|\.replace\s*\([^,]+,\s*['"`]['"`]\s*\)|stripTags|strip_tags|htmlspecialchars.*ENT_QUOTES/;

export function evaluateControlEffectiveness(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): WeakControlFinding[] {
  const findings: WeakControlFinding[] = [];
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  // Collect CONTROL nodes on paths between source and sink
  const controlsOnPath: NeuralMapNode[] = [];
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; path: string[] }> = [
    { nodeId: sourceId, path: [] },
  ];

  while (queue.length > 0) {
    const { nodeId, path } = queue.shift()!;
    if (visited.has(nodeId)) continue;
    visited.add(nodeId);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    if (node.node_type === 'CONTROL' && nodeId !== sourceId && nodeId !== sinkId) {
      controlsOnPath.push(node);
    }

    if (nodeId === sinkId) continue;

    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      if (!visited.has(edge.target)) {
        queue.push({ nodeId: edge.target, path: [...path, nodeId] });
      }
    }
  }

  // Evaluate each CONTROL node
  for (const ctrl of controlsOnPath) {
    const code = ctrl.code_snapshot;

    // Check 1: ReDoS — regex in this control has catastrophic backtracking
    const regexMatch = code.match(/\/([^/]+)\/[gimsuy]*/);
    if (regexMatch) {
      const regexBody = regexMatch[1];
      for (const pattern of REDOS_PATTERNS) {
        if (pattern.test(regexBody)) {
          findings.push({
            controlNode: ctrl,
            weakness: 'ReDoS: this validation regex has catastrophic backtracking',
            cwe: 'CWE-1333',
            severity: 'high',
            description: `CONTROL at ${ctrl.label} uses regex /${regexBody}/ which is vulnerable to ReDoS. ` +
              `The regex itself IS the denial-of-service vector — an attacker can craft input that causes exponential backtracking.`,
          });
          break;
        }
      }
    }

    // Check 2: Both sides user-controlled — auth comparing user values
    if (BOTH_SIDES_USER_RE.test(code)) {
      findings.push({
        controlNode: ctrl,
        weakness: 'Authorization compares two user-controlled values',
        cwe: 'CWE-639',
        severity: 'critical',
        description: `CONTROL at ${ctrl.label} compares user-supplied values against each other. ` +
          `The attacker controls both sides of the check, making it bypassable.`,
      });
    }

    // Check 3: Sanitizer that strips/removes (could collapse)
    if (STRIP_SANITIZER_RE.test(code)) {
      // Check if the stripped result could be dangerous
      const postStripDanger = /\.replace.*(?:script|on\w+=|javascript:|eval|exec|system)/i;
      if (postStripDanger.test(code) || ctrl.node_subtype.includes('sanitize')) {
        findings.push({
          controlNode: ctrl,
          weakness: 'Sanitizer removes characters — could collapse into dangerous values',
          cwe: 'CWE-182',
          severity: 'medium',
          description: `CONTROL at ${ctrl.label} strips characters from input. ` +
            `If the stripped characters interleave with dangerous patterns (e.g., stripping 'x' from 'sxcxrxixpxt'), ` +
            `the result becomes dangerous after removal.`,
        });
      }
    }

    // Check 4: Always-true condition (dead control)
    const alwaysTrue = /if\s*\(\s*(?:true|1|!0|!!1)\s*\)|if\s*\(\s*['"][^'"]+['"]\s*\)/;
    if (alwaysTrue.test(code)) {
      findings.push({
        controlNode: ctrl,
        weakness: 'Control condition is always true — validation never rejects',
        cwe: 'CWE-561',
        severity: 'critical',
        description: `CONTROL at ${ctrl.label} has a condition that is always true. ` +
          `This validation never actually rejects any input — it provides false safety.`,
      });
    }

    // Check 5: Wrong comparison operator in authorization control
    // Java: == on objects (reference comparison instead of .equals())
    // JS: == instead of === (type coercion bypass)
    const wrongCompare = /(?:==\s*(?:req\.|params\.|query\.|body\.|user\.|role|admin|token|session))|(?:(?:role|admin|token|permission|auth)\s*==\s*[^=])/;
    const hasLooseEquality = wrongCompare.test(code) && !code.includes('===') && !code.includes('.equals(');
    if (hasLooseEquality && (ctrl.node_subtype.includes('auth') || ctrl.node_subtype.includes('validate') ||
        code.match(/\b(role|admin|permission|auth|token|session|user)\b/i))) {
      findings.push({
        controlNode: ctrl,
        weakness: 'Authorization uses loose equality — type coercion bypass possible',
        cwe: 'CWE-597',
        severity: 'high',
        description: `CONTROL at ${ctrl.label} uses loose equality (==) in a security comparison. ` +
          `Type coercion can bypass the check (e.g., 0 == "" == false == null in JS, reference vs value in Java).`,
      });
    }

    // Check 6: Permissive regex in validation control — missing anchors
    if (regexMatch) {
      const regexBody = regexMatch[1];
      const hasStartAnchor = regexBody.startsWith('^');
      const hasEndAnchor = regexBody.endsWith('$');
      const isSecurityContext = code.match(/\b(valid|check|sanitiz|filter|allow|deny|block|reject|match)\b/i);
      if (isSecurityContext && (!hasStartAnchor || !hasEndAnchor)) {
        // Only flag if the regex has meaningful content (not just .* or empty)
        if (regexBody.length > 3 && !regexBody.match(/^\.\*$|^\.\+$/)) {
          findings.push({
            controlNode: ctrl,
            weakness: 'Validation regex missing anchors — partial match allows bypass',
            cwe: 'CWE-625',
            severity: 'medium',
            description: `CONTROL at ${ctrl.label} uses regex /${regexBody}/ for validation but is missing ` +
              `${!hasStartAnchor && !hasEndAnchor ? 'both ^ and $' : !hasStartAnchor ? 'start anchor ^' : 'end anchor $'} anchors. ` +
              `An attacker can prepend or append malicious content that passes the partial match.`,
          });
        }
      }
    }

    // Check 7: Control-threat mismatch — control addresses the wrong threat class
    // A parameterized query prevents INJECTION but says nothing about AUTHORIZATION.
    // A lock prevents RACE CONDITIONS but says nothing about INPUT VALIDATION.
    const mismatchFindings = controlThreatMismatch(map, ctrl, sourceId, sinkId);
    findings.push(...mismatchFindings);
  }

  return findings;
}

// ---------------------------------------------------------------------------
// THREAT-CONTROL MISMATCH DETECTOR (Check #7)
// ---------------------------------------------------------------------------

/**
 * Threat classes that controls can address.
 * Each control technique has a primary threat class it mitigates.
 */
type ThreatClass =
  | 'injection'        // SQL injection, command injection, XSS
  | 'authorization'    // ownership checks, RBAC, ABAC, row-level access
  | 'authentication'   // identity verification, session management
  | 'cryptography'     // encryption, hashing, key management
  | 'input_validation' // format checks, range checks, type checks
  | 'resource_mgmt'    // locks, transactions, resource limits
  | 'path_traversal'   // path canonicalization, chroot
  | 'unknown';

/**
 * Patterns that identify what threat class a CONTROL node addresses.
 * Ordered by specificity — first match wins.
 */
const CONTROL_THREAT_PATTERNS: Array<{ threat: ThreatClass; pattern: RegExp; label: string }> = [
  // Injection controls
  { threat: 'injection', label: 'parameterized query',
    pattern: /\b(preparedStatement|PreparedStatement|prepared_statement|parameteriz|\.setInt|\.setString|\.setLong|\.setDouble|\.setFloat|\.setBoolean|\.setDate|\.setTimestamp|\.setObject|placeholder|\$\d+|:\w+)\b/i },
  { threat: 'injection', label: 'SQL escaping',
    pattern: /\b(mysql_real_escape|pg_escape|escape_string|quote_ident|quote_literal|sanitize_sql|sql_escape)\b/i },
  { threat: 'injection', label: 'HTML encoding',
    pattern: /\b(htmlspecialchars|htmlentities|escapeHtml|encodeURIComponent|DOMPurify|sanitizeHtml|bleach\.clean|xss_clean|strip_tags)\b/i },
  { threat: 'injection', label: 'command escaping',
    pattern: /\b(escapeshellarg|escapeshellcmd|shlex\.quote|ProcessBuilder)\b/i },

  // Authorization controls
  { threat: 'authorization', label: 'ownership check',
    pattern: /\b(session\.user[_.]?id|session\.getAttribute.*user|request\.getUserPrincipal|SecurityContext|currentUser|req\.user\.id|user_id\s*===?\s*|owned_by|belongs_to|checkOwnership|isOwner|verifyOwner|authorize[!]?|hasPermission|can\?\s*:|ability\.can|@PreAuthorize|@Secured|@RolesAllowed|\.where\s*\(.*(?:user_id|owner_id|created_by)|\.filter\s*\(.*(?:owner|user))\b/i },
  { threat: 'authorization', label: 'RBAC/role check',
    pattern: /\b(hasRole|isAdmin|checkRole|requireRole|role\s*===?\s*|isAuthorized|policy\.\w+|permit\?|authorize_resource)\b/i },

  // Authentication controls
  { threat: 'authentication', label: 'auth verification',
    pattern: /\b(isAuthenticated|requireAuth|verifyToken|jwt\.verify|passport\.authenticate|checkAuth|session\.isValid|validateSession)\b/i },
  { threat: 'authentication', label: 'password/credential check',
    pattern: /\b(bcrypt\.compare|password_verify|checkPassword|validateCredentials|authenticate)\b/i },

  // Cryptography controls
  { threat: 'cryptography', label: 'encryption',
    pattern: /\b(encrypt|decrypt|createCipher|AES|RSA|createHash|HMAC)\b/i },

  // Input validation controls (general)
  { threat: 'input_validation', label: 'type/format validation',
    pattern: /\b(parseInt|parseFloat|Number\(|Integer\.parseInt|Double\.parseDouble|NumberFormatException|isNaN|isFinite|validate|validator)\b/i },

  // Resource management controls
  { threat: 'resource_mgmt', label: 'synchronization',
    pattern: /\b(synchronized|lock|mutex|semaphore|ReentrantLock|atomic)\b/i },

  // Path traversal controls
  { threat: 'path_traversal', label: 'path sanitization',
    pattern: /\b(realpath|canonicalize|normalize.*path|path\.resolve|chroot|jail)\b/i },
];

/**
 * Patterns that identify what threat class a SINK node represents (what the
 * sink is vulnerable TO if unprotected).
 */
const SINK_THREAT_PATTERNS: Array<{ threat: ThreatClass; pattern: RegExp }> = [
  // SQL sinks → vulnerable to both injection AND authorization bypass
  { threat: 'injection',
    pattern: /\b(query|execute|prepareStatement|createStatement|exec|raw\s*\(|sql\(|\.run\s*\()\b/i },
  // File sinks → vulnerable to path traversal
  { threat: 'path_traversal',
    pattern: /\b(readFile|writeFile|openFile|createReadStream|fs\.\w+|File\(|FileInputStream|FileOutputStream)\b/i },
  // Command sinks → vulnerable to injection
  { threat: 'injection',
    pattern: /\b(exec|spawn|system|popen|Runtime\.getRuntime|ProcessBuilder|child_process)\b/i },
  // Network/egress sinks → vulnerable to data exposure
  { threat: 'authorization',
    pattern: /\b(response\.write|res\.json|res\.send|println|writeString|getWriter)\b/i },
];

/**
 * CWEs that test for a specific threat class different from injection.
 * When we know the CWE being tested, we can check if the control addresses
 * the right threat.
 */
const CWE_THREAT_MAP: Record<string, ThreatClass> = {
  // Authorization bypass CWEs
  'CWE-566': 'authorization',  // Auth bypass through SQL primary key
  'CWE-639': 'authorization',  // Auth bypass through user-controlled key
  'CWE-284': 'authorization',  // Improper access control
  'CWE-285': 'authorization',  // Improper authorization
  'CWE-862': 'authorization',  // Missing authorization
  'CWE-863': 'authorization',  // Incorrect authorization
  'CWE-352': 'authentication', // CSRF
  'CWE-306': 'authentication', // Missing authentication
  'CWE-287': 'authentication', // Improper authentication
  'CWE-384': 'authentication', // Session fixation
  // Injection CWEs
  'CWE-89': 'injection',       // SQL injection
  'CWE-78': 'injection',       // OS command injection
  'CWE-79': 'injection',       // XSS
  // Overflow CWEs
  'CWE-190': 'input_validation', // Integer overflow
  'CWE-191': 'input_validation', // Integer underflow
  // Race condition CWEs
  'CWE-362': 'resource_mgmt',   // Race condition
  'CWE-367': 'resource_mgmt',   // TOCTOU
};

/**
 * Identify what threat class a CONTROL node's code addresses.
 * Returns the threat class and a human-readable label for the finding.
 */
function classifyControlThreat(code: string): { threat: ThreatClass; label: string } {
  for (const { threat, pattern, label } of CONTROL_THREAT_PATTERNS) {
    if (pattern.test(code)) {
      return { threat, label };
    }
  }
  return { threat: 'unknown', label: 'unknown control type' };
}

/**
 * Identify what threat class a SINK node is vulnerable to.
 */
function classifySinkThreat(code: string): ThreatClass {
  for (const { threat, pattern } of SINK_THREAT_PATTERNS) {
    if (pattern.test(code)) {
      return threat;
    }
  }
  return 'unknown';
}

/**
 * AUTH ownership patterns — indicates a node checks that the authenticated
 * user owns the resource being accessed. These are the AUTHORIZATION controls
 * that CWE-566 (and similar) require.
 */
const AUTH_OWNERSHIP_RE = /\b(session\.getAttribute|getSession\s*\(\s*\)\s*\.\s*getAttribute|session\.user[_.]?id|request\.getUserPrincipal|SecurityContext|getRemoteUser|getUserName|currentUser|req\.user\.id|req\.user\b|user_id\s*===?\s*|AND\s+(?:user_id|owner_id|created_by)\s*=|owned_by|belongs_to|checkOwnership|isOwner|verifyOwner|authorize[!]?|hasPermission|can\?\s*:|ability\.can|@PreAuthorize|@Secured|@RolesAllowed|\.where\s*\(.*(?:user_id|owner_id|created_by))/i;

/**
 * SQL query with user-controlled WHERE clause — the pattern that CWE-566
 * targets specifically: a SQL query uses a user-supplied ID as the primary
 * key lookup, but nobody checks if the session user owns that record.
 */
const SQL_PK_LOOKUP_RE = /(?:WHERE\s+(?:uid|id|user_id|pk|primary_key)\s*=\s*\?|\bfindById\b|\bfindByPk\b|\bget_object_or_404\b|\.get\s*\(\s*pk\b|\.find\s*\(\s*(?:req\.|params\.|request\.))/i;

/**
 * Check #7: Control-Threat Mismatch
 *
 * Given a CONTROL node on a mediated path, determine:
 * 1. What threat does this control address? (e.g., injection)
 * 2. What threat is the sink vulnerable to? (e.g., authorization bypass)
 * 3. Are there OTHER nodes on the path that address the sink's threat?
 * 4. If the control's threat != the sink's required threat, and no other
 *    node covers the gap, flag it as a mismatch.
 *
 * The canonical example: CWE-566
 *   - INGRESS: request.getParameter("id")
 *   - CONTROL: PreparedStatement (addresses INJECTION)
 *   - STORAGE: SQL query WHERE uid=? (vulnerable to AUTHORIZATION BYPASS)
 *   - No AUTH node checking session user == queried uid
 *   → MISMATCH: control addresses injection, threat is authorization
 */
export function controlThreatMismatch(
  map: NeuralMap,
  ctrl: NeuralMapNode,
  sourceId: string,
  sinkId: string,
): WeakControlFinding[] {
  const findings: WeakControlFinding[] = [];
  const code = ctrl.code_snapshot + ' ' + (ctrl.analysis_snapshot || '');
  const sinkNode = map.nodes.find(n => n.id === sinkId);
  const sourceNode = map.nodes.find(n => n.id === sourceId);
  if (!sinkNode || !sourceNode) return findings;

  const sinkCode = sinkNode.code_snapshot + ' ' + (sinkNode.analysis_snapshot || '');

  // Classify the control's threat and the sink's threat
  const controlClass = classifyControlThreat(code);
  const sinkThreat = classifySinkThreat(sinkCode);

  // Only fire on clear mismatches we understand
  if (controlClass.threat === 'unknown' || sinkThreat === 'unknown') return findings;

  // --- CWE-566 SPECIFIC: SQL query with user-controlled PK but only injection control ---
  // This is the high-value case: parameterized query protects against injection,
  // but nobody checks ownership (session user == queried user).
  if (controlClass.threat === 'injection' && sinkNode.node_type === 'STORAGE') {
    const fullSinkCode = sinkCode + ' ' + getContainingScopeSnapshots(map, sinkId).join(' ');
    const hasSqlPkLookup = SQL_PK_LOOKUP_RE.test(fullSinkCode);

    if (hasSqlPkLookup) {
      // Check: is there ANY auth/ownership node in scope that checks the session user?
      const hasOwnershipCheck = map.nodes.some(n => {
        // Must be in the same function scope
        if (!sharesFunctionScope(map, n.id, sinkId)) return false;
        // Must contain an ownership check pattern
        const nodeCode = n.code_snapshot + ' ' + (n.analysis_snapshot || '');
        return AUTH_OWNERSHIP_RE.test(nodeCode);
      });

      if (!hasOwnershipCheck) {
        findings.push({
          controlNode: ctrl,
          weakness: 'Control addresses injection, not authorization — missing ownership check',
          cwe: 'CWE-566',
          severity: 'high',
          description: `CONTROL at ${ctrl.label} uses ${controlClass.label} which prevents SQL injection, ` +
            `but the query at ${sinkNode.label} uses a user-supplied primary key without verifying ` +
            `that the authenticated user owns that record. An attacker can change the ID to access ` +
            `other users' data (IDOR/authorization bypass). The control addresses the wrong threat class.`,
        });
      }
    }
  }

  // --- GENERAL MISMATCH: control threat != required threat for this sink ---
  // Only flag when we have high confidence both classifications are correct.
  // The injection-vs-authorization case is handled above (CWE-566 specific).
  // Add more specific cases here as needed (CWE-190, CWE-362, etc.)

  return findings;
}

/**
 * BFS: is there a path from source to sink that doesn't pass through any
 * intermediate node of the given type? Source and sink themselves are excluded
 * from the check — only nodes BETWEEN them count as mediators.
 *
 * Use this when the sink (or source) is the SAME node type as the missing mediator,
 * e.g., "INGRESS→TRANSFORM without TRANSFORM" where the sink IS a TRANSFORM.
 * Only follows data-flow edges — CONTAINS/DEPENDS are excluded.
 */
export function hasPathWithoutIntermediateType(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
  intermediateType: NodeType,
): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedType: boolean }> = [
    { nodeId: sourceId, passedType: false },
  ];
  let head = 0;

  while (head < queue.length) {
    const { nodeId, passedType } = queue[head++];
    const visitKey = `${nodeId}:${passedType}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    if (nodeId === sinkId) {
      if (!passedType) return true;
      continue;
    }

    // Only intermediate nodes (not source, not sink) count as mediators
    const isIntermediate = nodeId !== sourceId && node.node_type === intermediateType;
    const typeNow = passedType || isIntermediate;

    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      const edgeKey = `${edge.target}:${typeNow}`;
      if (!visited.has(edgeKey)) {
        queue.push({ nodeId: edge.target, passedType: typeNow });
      }
    }
  }

  return false;
}

/**
 * BFS: is there a path from source to sink that never passes through a TRANSFORM node?
 * Delegates to hasPathWithoutGate.
 */
export function hasPathWithoutTransform(map: NeuralMap, sourceId: string, sinkId: string): boolean {
  return hasPathWithoutGate(map, sourceId, sinkId, 'TRANSFORM');
}

// ---------------------------------------------------------------------------
// Comment stripping — prevents comments from defeating safe-pattern detection
// ---------------------------------------------------------------------------

/**
 * Strip comments from a code snapshot so that safe-pattern regexes only match
 * actual code, not comments. Handles:
 *   - Single-line comments (// ...) and (# ...) for Python/Ruby/PHP
 *   - Multi-line comments (/* ... *​/)
 *   - Preserves string literals — won't strip // inside "strings" or 'strings'
 *   - Preserves template literals — won't strip // inside `backtick strings`
 */
const HASH_COMMENT_LANGS = new Set(['python', 'ruby', 'php', 'perl', 'shell', 'bash', 'r']);

export function stripComments(code: string, language?: string): string {
  const stripHash = !language || HASH_COMMENT_LANGS.has(language.toLowerCase());
  let result = '';
  let i = 0;
  const len = code.length;

  while (i < len) {
    const ch = code[i];
    const next = i + 1 < len ? code[i + 1] : '';

    // String literals — skip through without stripping
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      result += ch;
      i++;
      while (i < len) {
        if (code[i] === '\\') {
          // Escaped character — consume both
          result += code[i] + (i + 1 < len ? code[i + 1] : '');
          i += 2;
          continue;
        }
        if (code[i] === quote) {
          result += code[i];
          i++;
          break;
        }
        result += code[i];
        i++;
      }
      continue;
    }

    // Multi-line comment: /* ... */
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < len) {
        if (code[i] === '*' && i + 1 < len && code[i + 1] === '/') {
          i += 2;
          break;
        }
        i++;
      }
      result += ' '; // Replace comment with space to avoid token merging
      continue;
    }

    // Single-line comment: // ...
    if (ch === '/' && next === '/') {
      // Skip to end of line
      i += 2;
      while (i < len && code[i] !== '\n') {
        i++;
      }
      continue;
    }

    // Hash comment: # ... (only for Python, Ruby, PHP, etc.)
    if (ch === '#' && stripHash) {
      // Skip to end of line
      i++;
      while (i < len && code[i] !== '\n') {
        i++;
      }
      continue;
    }

    result += ch;
    i++;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Scope-aware safe-pattern helper
// ---------------------------------------------------------------------------

/**
 * Returns the analysis_snapshot of the STRUCTURAL function/method that contains nodeId.
 * This gives safe-pattern checks visibility into the containing function's code without
 * leaking code from unrelated functions (scope poisoning).
 *
 * Walk: target node → CONTAINS parent → ... → nearest function/route STRUCTURAL node.
 * Returns that node's analysis_snapshot (full function body, up to 2000 chars).
 * Falls back to the target node's own snapshot if no containing function is found.
 */
export function getContainingScopeSnapshots(map: NeuralMap, nodeId: string): string[] {
  const targetNode = map.nodes.find(n => n.id === nodeId);
  if (!targetNode) return [];

  // Build a lookup for CONTAINS edges: child -> parent source ID
  const childToParent = new Map<string, string>();
  for (const e of map.edges) {
    if (e.edge_type === 'CONTAINS') {
      childToParent.set(e.target, e.source!);
    }
  }

  // Build a node lookup
  const nodeById = new Map(map.nodes.map(n => [n.id, n]));

  // Walk up the CONTAINS chain to find the nearest function-level STRUCTURAL node
  const functionSubtypes = new Set(['function', 'route', 'method', 'lambda']);
  let currentId: string | undefined = nodeId;
  const visited = new Set<string>();

  while (currentId) {
    if (visited.has(currentId)) break; // cycle guard
    visited.add(currentId);

    const parentId = childToParent.get(currentId);
    if (!parentId) break;

    const parentNode = nodeById.get(parentId);
    if (!parentNode) break;

    if (parentNode.node_type === 'STRUCTURAL' && functionSubtypes.has(parentNode.node_subtype)) {
      // Found the containing function — return its analysis_snapshot
      return [parentNode.analysis_snapshot || parentNode.code_snapshot];
    }

    currentId = parentId;
  }

  // No containing function found — fall back to the target node's own snapshot
  return [targetNode.analysis_snapshot || targetNode.code_snapshot];
}

// ---------------------------------------------------------------------------
// Scope-based taint fallback — for Java Juliet patterns where BFS path
// doesn't exist but tainted data clearly flows through assignments
// ---------------------------------------------------------------------------

/**
 * STRUCTURAL node subtypes that represent function-level scopes.
 * 'function' covers: function/method declarations, constructors, arrow functions, lambdas, closures, generators
 * 'route' covers: route-annotated methods (@GetMapping, [HttpGet], etc.)
 */
export const FUNCTION_SCOPE_SUBTYPES = new Set(['function', 'route']);

/**
 * Check whether two nodes share a function scope.
 * "Shares scope" = both nodes are contained by the same function-body STRUCTURAL node.
 * Two methods in the same class do NOT share function scope.
 */
export function sharesFunctionScope(map: NeuralMap, nodeIdA: string, nodeIdB: string): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const nodeA = nodeMap.get(nodeIdA);
  const nodeB = nodeMap.get(nodeIdB);
  if (!nodeA || !nodeB) return false;

  // Strategy 1: Common CONTAINS ancestor that is a function-scope STRUCTURAL node
  const getAncestors = (nodeId: string): Set<string> => {
    const ancestors = new Set<string>();
    for (const n of map.nodes) {
      if (n.node_type === 'STRUCTURAL' && FUNCTION_SCOPE_SUBTYPES.has(n.node_subtype)) {
        for (const edge of n.edges) {
          if (edge.target === nodeId && edge.edge_type === 'CONTAINS') {
            ancestors.add(n.id);
          }
        }
      }
    }
    return ancestors;
  };

  const ancestorsA = getAncestors(nodeIdA);
  const ancestorsB = getAncestors(nodeIdB);
  for (const a of ancestorsA) {
    if (ancestorsB.has(a)) return true;
  }

  // Strategy 2: Line-range fallback — both nodes within same function-scope node's span
  const funcNodes = map.nodes.filter(n =>
    n.node_type === 'STRUCTURAL' && FUNCTION_SCOPE_SUBTYPES.has(n.node_subtype)
  );

  for (const func of funcNodes) {
    if (nodeA.line_start >= func.line_start && nodeA.line_start <= func.line_end &&
        nodeB.line_start >= func.line_start && nodeB.line_start <= func.line_end) {
      return true;
    }
  }

  return false;
}

/**
 * Scope-based taint fallback: checks whether an INGRESS source and an EGRESS/sink
 * share a function scope AND there exists a tainted TRANSFORM node (variable assignment
 * carrying tainted data) in the same scope. This catches patterns where:
 *   data = request.getParameter("x");   // INGRESS -> TRANSFORM (tainted)
 *   response.getWriter().println(data);  // EGRESS  (no direct DATA_FLOW edge)
 *
 * The BFS path fails because the mapper doesn't create DATA_FLOW edges through
 * chained method calls like response.getWriter().println(data). But the taint
 * IS captured in the TRANSFORM node's data_in.
 */
export function scopeBasedTaintReaches(
  map: NeuralMap, sourceId: string, sinkId: string
): boolean {
  if (!sharesFunctionScope(map, sourceId, sinkId)) return false;

  // Per-function check: did collection per-index tracking neutralize taint in this sink's function?
  const _sinkFuncNodes = map.nodes.filter(n =>
    n.node_type === 'STRUCTURAL' && n.edges.some(e => e.target === sinkId && e.edge_type === 'CONTAINS')
  );
  if (_sinkFuncNodes.some(fn => fn.metadata?.collectionTaintNeutralized === true)) return false;
  // Fallback: global flag (transitional)
  if ((map as any).collectionTaintNeutralized) return false;

  // Check if any TRANSFORM node in the same scope has tainted data_in
  // (meaning the INGRESS data was assigned to a variable in scope)
  const hasTaintedTransform = map.nodes.some(n =>
    n.node_type === 'TRANSFORM' &&
    n.data_in.some(d => d.tainted) &&
    sharesFunctionScope(map, n.id, sinkId)
  );

  return hasTaintedTransform;
}

// ---------------------------------------------------------------------------
// Sink domain classification — prevents cross-domain false positives
// ---------------------------------------------------------------------------
// When a factory CWE targets a broad node type (e.g. EXTERNAL), we need to
// know whether the actual sink is a shell command, SQL query, URL request,
// LDAP query, etc.  A shell-injection CWE should not fire on a URL sink.
//
// Backported from ZeroDay ZDAY-002 domain mismatch detection.

export type SinkDomain = 'SQL' | 'HTML' | 'SHELL' | 'FILE' | 'LDAP' | 'URL' | 'XML' | 'CRYPTO' | 'LOG' | 'UNKNOWN';

const DOMAIN_SQL_RE   = /\b(query|execute|prepare|sql|SELECT\s|INSERT\s|UPDATE\s|DELETE\s|\.run\s*\(|\.exec\s*\(|Statement|ResultSet|hibernate|HQL|JPQL|criteria|createQuery|createNativeQuery|preparedStatement)\b/i;
const DOMAIN_HTML_RE  = /\b(render|\.send\s*\(|\.write\s*\(|\.html\s*\(|innerHTML|document\.write|\.append\(|response\.getWriter|HttpServletResponse|\.setContentType.*text\/html)\b/i;
const DOMAIN_SHELL_RE = /\b(exec\s*\(|spawn\s*\(|system\s*\(|popen|child_process|Runtime\.exec|Runtime\.getRuntime|ProcessBuilder|shell_exec|os\.system|subprocess|execSync|execFile|ShellExecute)\b/i;
const DOMAIN_FILE_RE  = /\b(readFile|writeFile|open\s*\(|createStream|FileInputStream|FileOutputStream|fopen|fwrite|fread|createReadStream|createWriteStream|path\.join|path\.resolve|File\s*\(|RandomAccessFile|BufferedReader.*FileReader)\b/i;
const DOMAIN_LDAP_RE  = /\b(ldap|LDAP|ldap_search|ldap_bind|ldap_connect|DirContext|InitialDirContext|LdapContext|searchFilter)\b/i;
const DOMAIN_URL_RE   = /\b(URL|openStream|openConnection|HttpClient|HttpURLConnection|fetch\s*\(|axios|request\s*\(|http\.get|https\.get|curl|wget|URLConnection|HttpGet|HttpPost|RestTemplate|WebClient|\.getInputStream\s*\(\s*\))\b/i;
const DOMAIN_XML_RE   = /\b(XQuery|xquery|xmldb|XPath|xpath|SAXParser|DocumentBuilder|XMLReader|XMLParser|parseXML|etree\.parse|xml\.parse|DTD|DOCTYPE)\b/i;

/**
 * Classify what security domain a sink node operates in.
 * Uses code_snapshot + node_subtype for classification.
 * Returns UNKNOWN if no confident match — UNKNOWN sinks are never filtered out.
 */
export function classifySinkDomain(node: NeuralMapNode): SinkDomain {
  // Prefer structured node_subtype over regex on code snapshots.
  // The mapper already classified this node — use that classification first.
  if (node.node_subtype === 'log_write' || node.node_subtype === 'display') return 'LOG';
  if (node.node_subtype === 'http_response' || node.node_subtype === 'redirect') return 'HTML';
  if (node.node_subtype === 'system_exec') return 'SHELL';
  if (node.node_subtype === 'sql_query' || node.node_subtype === 'db_read' || node.node_subtype === 'db_write') return 'SQL';
  if (node.node_subtype === 'file_read' || node.node_subtype === 'file_write' || node.node_subtype === 'file_access') return 'FILE';
  if (node.node_subtype === 'api_call' || node.node_subtype === 'url_fetch') return 'URL';
  if (node.node_subtype === 'xml_parse') return 'XML';
  if (node.node_subtype === 'ldap_query') return 'LDAP';

  // Fallback: regex on code snapshot for nodes without precise subtypes
  const code = node.code_snapshot + ' ' + (node.analysis_snapshot || '') + ' ' + node.node_subtype;

  // Order matters: more specific before less specific.
  if (DOMAIN_LDAP_RE.test(code))  return 'LDAP';
  if (DOMAIN_SHELL_RE.test(code)) return 'SHELL';
  if (DOMAIN_SQL_RE.test(code))   return 'SQL';
  if (DOMAIN_XML_RE.test(code))   return 'XML';
  if (DOMAIN_URL_RE.test(code))   return 'URL';
  if (DOMAIN_HTML_RE.test(code))  return 'HTML';
  if (DOMAIN_FILE_RE.test(code))  return 'FILE';
  return 'UNKNOWN';
}

/**
 * Map of CWE IDs to the sink domain(s) they apply to.
 * CWEs NOT listed here are domain-agnostic and fire on any sink.
 *
 * This is the core of the cross-domain false-positive suppression:
 * if a CWE is listed here, the factory verifier will only create a finding
 * when the sink's classified domain is in the CWE's allowed set.
 *
 * UNKNOWN-domain sinks are NEVER filtered out (conservative: if we can't
 * classify the sink, we let the CWE fire to avoid false negatives).
 */
const CWE_DOMAIN_MAP: Record<string, ReadonlySet<SinkDomain>> = {
  // Shell / command injection
  'CWE-77':  new Set(['SHELL']),
  'CWE-78':  new Set(['SHELL']),
  'CWE-88':  new Set(['SHELL']),
  'CWE-214': new Set(['SHELL']),        // visible sensitive info in process args

  // SQL injection
  'CWE-89':  new Set(['SQL']),
  'CWE-564': new Set(['SQL']),           // Hibernate SQL injection

  // XSS / HTML injection — all XSS variants require HTML output context
  'CWE-79':  new Set(['HTML']),
  'CWE-80':  new Set(['HTML']),
  'CWE-81':  new Set(['HTML']),           // XSS in error messages
  'CWE-82':  new Set(['HTML']),           // XSS in IMG tag attributes
  'CWE-83':  new Set(['HTML']),           // XSS in attributes
  'CWE-84':  new Set(['HTML']),           // XSS in URI
  'CWE-85':  new Set(['HTML']),           // doubled character XSS
  'CWE-86':  new Set(['HTML']),           // XSS via HTTP headers
  'CWE-87':  new Set(['HTML']),           // XSS via alternate syntax

  // Output neutralization — these are XSS-adjacent, require HTML/output context
  'CWE-75':  new Set(['HTML']),           // sanitize special elements
  'CWE-138': new Set(['HTML']),           // neutralize special elements
  'CWE-150': new Set(['HTML']),           // neutralize escape sequences
  'CWE-692': new Set(['HTML']),           // incomplete XSS denylist
  'CWE-790': new Set(['HTML']),           // improper filtering of special elements
  'CWE-791': new Set(['HTML']),           // incomplete filtering

  // Log injection — requires LOG output context
  'CWE-117': new Set(['LOG']),

  // LDAP injection
  'CWE-90':  new Set(['LDAP']),

  // XML/XQuery injection
  'CWE-91':  new Set(['XML']),
  'CWE-643': new Set(['XML']),           // XPath injection
  'CWE-652': new Set(['XML']),           // XQuery injection
  'CWE-827': new Set(['XML']),           // DTD control

  // SSRF / URL
  'CWE-918': new Set(['URL']),

  // Path traversal / file
  'CWE-22':  new Set(['FILE']),
  'CWE-23':  new Set(['FILE']),
  'CWE-36':  new Set(['FILE']),
  'CWE-73':  new Set(['FILE']),
};

/**
 * Check whether a CWE should fire on a given sink node.
 * Returns true if the CWE should fire (domain matches or CWE is domain-agnostic).
 * Returns false only when the CWE is domain-specific AND the sink's domain
 * is confidently classified as a DIFFERENT domain.
 */
export function cweDomainMatchesSink(cweId: string, sink: NeuralMapNode): boolean {
  const allowedDomains = CWE_DOMAIN_MAP[cweId];
  if (!allowedDomains) return true;                     // domain-agnostic CWE: always fires
  const sinkDomain = classifySinkDomain(sink);
  if (sinkDomain === 'UNKNOWN') return true;            // can't classify sink: let it fire (conservative)
  return allowedDomains.has(sinkDomain);
}

// ---------------------------------------------------------------------------
// Generic factory — configurable source, sink, safe pattern
// ---------------------------------------------------------------------------

export function createGenericVerifier(
  cweId: string, cweName: string, severity: Severity,
  sinkFilter: (map: NeuralMap) => NeuralMapNode[],
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
  sourceType: NodeType = 'INGRESS',
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const sources = nodesOfType(map, sourceType);
    const sinks = sinkFilter(map);

    for (const src of sources) {
      for (const sink of sinks) {
        // Domain filter: skip sinks whose domain doesn't match this CWE
        if (!cweDomainMatchesSink(cweId, sink)) continue;
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          // V4-D: check scope snapshots (analysis_snapshot) so safe patterns on prior lines are visible
          const scopeSnaps = getContainingScopeSnapshots(map, sink.id);
          const combinedScope = stripComments(scopeSnaps.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
          if (!safePattern.test(combinedScope)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `User input from ${src.label} reaches ${sink.label} without proper controls. ` +
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

// ---------------------------------------------------------------------------
// Safe-pattern regex constants — shared across batch_015, 016, 017, 018
// ---------------------------------------------------------------------------

/** Validation functions */
export const SP_V = /\bvalidate\s*\(|\bcheck\s*\(|\bverif\w*\s*\(|\bassert\s*\(|\bguard\s*\(|\bensure\s*\(/i;
/** Sanitization functions */
export const SP_S = /\bsanitize\s*\(|\bescape\s*\(|\bencode\s*\(|\b\.filter\s*\(|\bstrip\s*\(|\bneutralize\s*\(/i;
/** Authorization functions */
export const SP_A = /\bauthorize\s*\(|\bhasPermission\s*\(|\bcheckAccess\s*\(|\brole\b|\btoken\b.*\bverif\w*\s*\(|\bauth\s*\(/i;
/** Encryption/hashing functions */
export const SP_E = /\bencrypt\s*\(|\bhash\s*\(|\bcreateHash\b|\bcipher\s*\(|\bcreateCipher\w*\b|\bprotect\s*\(|\bsecure\s*\(/i;
/** Lock/synchronization primitives */
export const SP_L = /\block\s*\(|\bmutex\b|\bsynchronized\b|\batomic\b|\btransaction\b/i;
/** Resource release functions */
export const SP_R = /\brelease\s*\(|\bclose\s*\(|\bdispose\s*\(|\bfinally\b|\bcleanup\s*\(/i;
/** Immutability patterns */
export const SP_I = /\bimmutable\b|\b\.freeze\s*\(|\breadonly\b|\bconst\b|\b\.seal\s*\(/i;
/** Debug/production mode checks */
export const SP_D = /\bdebug.*off\b|\bproduction\b|\bNODE_ENV\b/i;
/** Cryptographic random functions */
export const SP_CR = /\bcrypto\.random\b|\brandomBytes\b|\bCSPRNG\b|\bgetRandomValues\b/i;

// ---------------------------------------------------------------------------
// BFS shortcut type + shared shortcuts
// ---------------------------------------------------------------------------

export type BfsCheck = (map: NeuralMap, srcId: string, sinkId: string) => boolean;

/** No path without CONTROL (taint-aware) */
export const bfs_nC: BfsCheck = hasTaintedPathWithoutControl;
/** No path without TRANSFORM */
export const bfs_nT: BfsCheck = hasPathWithoutTransform;
/** No path without intermediate CONTROL */
export const bfs_nCi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'CONTROL');
/** No path without intermediate TRANSFORM */
export const bfs_nTi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'TRANSFORM');
/** No path without intermediate AUTH */
export const bfs_nA: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'AUTH');
/** No path without intermediate META */
export const bfs_nM: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'META');
/** No path without intermediate STRUCTURAL */
export const bfs_nS: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'STRUCTURAL');
/** No path without intermediate EXTERNAL */
export const bfs_nE: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'EXTERNAL');
/** No path without intermediate EGRESS */
export const bfs_nEg: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'EGRESS');
/** No path without intermediate STORAGE */
export const bfs_nSt: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'STORAGE');

// ---------------------------------------------------------------------------
// Compact verifier factory — shared across batch_015, 016, 017, 018
// ---------------------------------------------------------------------------

/**
 * Factory for simple BFS-based verifiers: iterates all (source, sink) pairs,
 * runs bfsCheck, tests safePattern on both code_snapshots.
 */
export function makeVerifier(
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
        // Domain filter: skip sinks whose domain doesn't match this CWE
        if (!cweDomainMatchesSink(cweId, sink)) continue;
        if (bfsCheck(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(sink),
              missing: missingDesc, severity,
              description: `${sourceType} at ${src.label} → ${sinkType} at ${sink.label} without controls. Vulnerable to ${cweName}.`,
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

// ---------------------------------------------------------------------------
// Source scanning helpers
// ---------------------------------------------------------------------------

/**
 * Split source code into lines, returning an array of { line, lineNum }
 * with comment-only lines marked. Strips single-line comment lines
 * (// and block-comment continuation lines starting with *).
 *
 * Returns cleaned lines ready for regex scanning.
 */
export function scanSourceLines(source: string): Array<{ line: string; lineNum: number; isComment: boolean }> {
  const lines = source.split('\n');
  return lines.map((line, i) => ({
    line,
    lineNum: i + 1,
    isComment: /^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*\/\*/.test(line),
  }));
}

/**
 * Find the nearest NeuralMapNode to a given source line number.
 * Tries exact match first, then within a tolerance window, then falls back to nodes[0].
 */
export function findNearestNode(map: NeuralMap, lineNum: number, tolerance: number = 2): NeuralMapNode | undefined {
  return map.nodes.find(n => n.line_start === lineNum) ||
    map.nodes.find(n => Math.abs(n.line_start - lineNum) <= tolerance) ||
    map.nodes[0];
}

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

/** Extension-to-language mapping — canonical, used across all batches */
const EXT_LANG_MAP: Record<string, string> = {
  js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
  ts: 'typescript', tsx: 'typescript', py: 'python', rb: 'ruby', php: 'php',
  java: 'java', kt: 'kotlin', go: 'go', rs: 'rust', cs: 'csharp',
  c: 'c', cpp: 'cpp', cc: 'cpp', swift: 'swift', scala: 'scala',
};

/**
 * Infer the effective programming language from a NeuralMap.
 * Checks node.language first, then falls back to source_file extension.
 * Returns lowercase language name or empty string if unknown.
 */
export function detectLanguage(map: NeuralMap): string {
  const lang = (map.nodes.find(n => n.language)?.language ?? '').toLowerCase();
  if (lang) return lang;
  const ext = map.source_file?.split('.').pop()?.toLowerCase() ?? '';
  return EXT_LANG_MAP[ext] || '';
}
