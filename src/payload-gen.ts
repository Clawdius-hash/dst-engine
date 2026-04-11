
import type { NeuralMap, NeuralMapNode } from './types';
import type {
  Finding,
  NodeRef,
  ProofCertificate,
  ProofPayload,
  DeliverySpec,
  OracleDefinition,
  PathAnalysis,
} from './verifier/types.ts';
import type { TransformEffect, PayloadClass, ProofPayloadTemplate } from './payload-dictionary.ts';
import {
  SINK_CLASS_MAP,
  resolveSinkClass,
  inferPayloadClassFromCWE,
  SQL_INJECTION_PAYLOADS,
  TRANSFORM_EFFECTS,
  classifyTransform,
  SAFE_COMMANDS,
  SQL_DESTRUCTIVE,
  SQL_READ_ONLY,
} from './payload-dictionary.js';


const FLOW_EDGES: ReadonlySet<string> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);


/**
 * Find a NeuralMapNode in the map matching a Finding's NodeRef.
 *
 * Three cases:
 * 1. Direct ID match (normal BFS findings)
 * 2. Prefixed IDs from cross-file merged maps (prefix::node_id)
 * 3. Synthetic srcline-N IDs from source-line fallback
 *
 * FIX #4: When line_end === 0 (createNode default), use line_start === ref.line
 */
export function lookupNode(map: NeuralMap, ref: NodeRef): NeuralMapNode | null {
  const direct = map.nodes.find(n => n.id === ref.id);
  if (direct) return direct;

  if (ref.id.startsWith('srcline-')) {
    const candidates = map.nodes.filter(n => {
      if (n.line_end === 0) {
        return n.line_start === ref.line;
      }
      return n.line_start <= ref.line && n.line_end >= ref.line;
    });
    if (candidates.length > 0) {
      return candidates.sort((a, b) => {
        const spanA = a.line_end === 0 ? 0 : (a.line_end - a.line_start);
        const spanB = b.line_end === 0 ? 0 : (b.line_end - b.line_start);
        return spanA - spanB;
      })[0];
    }
  }

  return null;
}


/**
 * BFS from sourceId to sinkId, returning the path as an ordered array of node IDs.
 * Only follows FLOW_EDGE_TYPES (DATA_FLOW, CALLS, READS, WRITES, RETURNS).
 * Returns null if no path exists.
 */
export function tracePath(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): string[] | null {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; path: string[] }> = [
    { nodeId: sourceId, path: [sourceId] },
  ];
  let head = 0;

  while (head < queue.length) {
    const { nodeId, path } = queue[head++];
    if (visited.has(nodeId)) continue;
    visited.add(nodeId);

    if (nodeId === sinkId) return path;

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    for (const edge of node.edges) {
      if (!FLOW_EDGES.has(edge.edge_type)) continue;
      if (!visited.has(edge.target)) {
        queue.push({ nodeId: edge.target, path: [...path, edge.target] });
      }
    }
  }

  return null;
}


/**
 * Determine if the SQL injection point is in a string or numeric context.
 * Examines the sink's code snapshot for quote patterns around concatenation.
 *
 * String context: the injected variable is wrapped in SQL quotes
 *   e.g., "SELECT * FROM users WHERE name='" + input + "'"
 * Numeric context: the injected variable is NOT wrapped in SQL quotes
 *   e.g., "SELECT * FROM users WHERE id=" + input
 */
export function extractSQLContext(sinkNode: NeuralMapNode): 'sql_string' | 'sql_numeric' {
  const snap = sinkNode.analysis_snapshot || sinkNode.code_snapshot;

  const stringConcat = /'\s*["']\s*\+\s*\w+\s*\+\s*["']\s*'/;
  if (stringConcat.test(snap)) return 'sql_string';

  const stringOpen = /'\s*["']\s*\+\s*\w+/;
  if (stringOpen.test(snap)) return 'sql_string';

  const numericConcat = /[=<>!]\s*["']\s*\+\s*\w+/;
  if (numericConcat.test(snap)) return 'sql_numeric';

  return 'sql_string';
}


const CANARY_MAP: Record<string, string> = {
  sql_injection: 'DST_CANARY_SQLI',
  command_injection: 'DST_CMDI_PROOF',
  xss: 'DST_XSS_PROOF',
  path_traversal: 'DST_PATH_PROOF',
  ldap_injection: 'DST_LDAP_PROOF',
  xpath_injection: 'DST_XPATH_PROOF',
  xxe: 'DST_XXE_PROOF',
  deserialization: 'DST_DESER_PROOF',
  open_redirect: 'DST_REDIR_PROOF',
  log_injection: 'DST_LOG_PROOF',
  ssti: 'DST_SSTI_PROOF',
};

export function generateCanary(payloadClass: PayloadClass): string {
  return CANARY_MAP[payloadClass] ?? `DST_PROOF_${payloadClass.toUpperCase()}`;
}


/**
 * Select the best payload for a given class and sink context.
 * Returns primary + variants.
 */
export function selectPayload(
  payloadClass: PayloadClass,
  sinkNode: NeuralMapNode | null,
  sinkRef: NodeRef,
  pathAnalysis: PathAnalysis | null,
): { primary: ProofPayload; variants: ProofPayload[] } {
  if (payloadClass === 'sql_injection') {
    return selectSQLPayload(sinkNode, sinkRef, pathAnalysis);
  }

  const canary = generateCanary(payloadClass);
  const primary: ProofPayload = {
    value: canary,
    canary,
    context: 'generic',
    execution_safe: true,
  };
  return { primary, variants: [] };
}

function selectSQLPayload(
  sinkNode: NeuralMapNode | null,
  sinkRef: NodeRef,
  pathAnalysis: PathAnalysis | null,
): { primary: ProofPayload; variants: ProofPayload[] } {
  let context: 'sql_string' | 'sql_numeric' = 'sql_string';
  if (sinkNode) {
    context = extractSQLContext(sinkNode);
  } else {
    const stringConcat = /["']\s*\+\s*\w+\s*\+\s*["']|["'][^"']*'\s*\+\s*\w+/;
    context = stringConcat.test(sinkRef.code) ? 'sql_string' : 'sql_string';
  }

  if (pathAnalysis?.transforms.some(t => t.effect.effect === 'type_coercion')) {
    context = 'sql_numeric';
  }

  const prefix = context === 'sql_numeric' ? 'sql_numeric' : 'sql_string';

  const primaryTemplate = SQL_INJECTION_PAYLOADS[`${prefix}_union_canary`]
    ?? SQL_INJECTION_PAYLOADS[`${prefix}_tautology`]!;

  const primary: ProofPayload = {
    value: primaryTemplate.value,
    canary: primaryTemplate.canary,
    context: primaryTemplate.context as ProofPayload['context'],
    execution_safe: primaryTemplate.execution_safe,
  };

  const variants: ProofPayload[] = [];

  const tautology = SQL_INJECTION_PAYLOADS[`${prefix}_tautology`];
  if (tautology && tautology.value !== primary.value) {
    variants.push({
      value: tautology.value,
      canary: tautology.canary,
      context: tautology.context as ProofPayload['context'],
      execution_safe: tautology.execution_safe,
    });
  }

  for (const key of ['sql_time_mysql', 'sql_time_postgres', 'sql_time_mssql']) {
    const tmpl = SQL_INJECTION_PAYLOADS[key];
    if (tmpl) {
      variants.push({
        value: tmpl.value,
        canary: tmpl.canary,
        context: tmpl.context as ProofPayload['context'],
        execution_safe: tmpl.execution_safe,
      });
    }
  }

  return { primary, variants };
}


export function analyzeTransforms(
  map: NeuralMap,
  pathIds: string[],
): Array<{ node_id: string; subtype: string; effect: TransformEffect }> {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const result: Array<{ node_id: string; subtype: string; effect: TransformEffect }> = [];

  for (const id of pathIds) {
    const node = nodeMap.get(id);
    if (!node || node.node_type !== 'TRANSFORM') continue;

    result.push({
      node_id: id,
      subtype: node.node_subtype,
      effect: classifyTransform(node),
    });
  }

  return result;
}


function resolveRoutePath(map: NeuralMap, sourceNode: NeuralMapNode): string {
  let bestPath: string | null = null;
  let bestSpan = Infinity;

  for (const n of map.nodes) {
    if (n.node_type !== 'STRUCTURAL') continue;
    if (!n.metadata.route_path) continue;

    const routePath = n.metadata.route_path as string;
    const containsSource =
      n.line_start <= sourceNode.line_start &&
      (n.line_end === 0 ? n.line_start === sourceNode.line_start : n.line_end >= sourceNode.line_start);

    if (containsSource) {
      const span = n.line_end === 0 ? 0 : (n.line_end - n.line_start);
      if (span < bestSpan) {
        bestSpan = span;
        bestPath = routePath;
      }
    }
  }

  return bestPath ?? '/';
}

function extractHTTPDelivery(sourceNode: NeuralMapNode, map: NeuralMap): DeliverySpec['http'] {
  const snap = sourceNode.analysis_snapshot || sourceNode.code_snapshot;
  const paramName = sourceNode.param_names?.[0];
  const method = /\b(doPost|POST|post|body)\b/i.test(snap) ? 'POST' : 'GET';
  const path = resolveRoutePath(map, sourceNode);

  if (/\bgetHeader\b|\bheader\b/i.test(snap)) {
    return { method, path, header: paramName || 'X-Custom' };
  }
  if (/\bgetCookies\b|\bcookie\b/i.test(snap)) {
    return { method, path, cookie: paramName || 'session' };
  }

  return { method, path, param: paramName || 'input' };
}

export function buildDeliverySpec(
  map: NeuralMap,
  sourceNode: NeuralMapNode | null,
  sourceRef: NodeRef,
  rawPayload: string,
  transforms: TransformEffect[],
): DeliverySpec {
  let channel: DeliverySpec['channel'] = 'unknown';
  let http: DeliverySpec['http'] | undefined;

  if (sourceNode) {
    switch (sourceNode.node_subtype) {
      case 'http_request':
      case 'http_handler':
      case 'route_handler':
        channel = 'http';
        http = extractHTTPDelivery(sourceNode, map);
        break;
      case 'user_input':
        channel = 'stdin';
        break;
      case 'env_read':
        channel = 'env';
        break;
      case 'file_read':
        channel = 'file';
        break;
      case 'network_input':
        channel = 'socket';
        break;
      default:
        if (/\b(req\.|request\.|getParameter|getHeader|express|app\.(get|post|put|delete))\b/i.test(
          sourceNode.analysis_snapshot || sourceNode.code_snapshot
        )) {
          channel = 'http';
          http = extractHTTPDelivery(sourceNode, map);
        } else {
          channel = 'unknown';
        }
    }
  }

  let encodedPayload = rawPayload;
  for (const t of transforms) {
    if (t.payload_action === 'encode_before_delivery') {
      encodedPayload = encodeURIComponent(encodedPayload);
    }
  }

  return {
    channel,
    http,
    raw_payload: rawPayload,
    encoded_payload: encodedPayload,
  };
}


export function buildOracle(
  payloadClass: PayloadClass,
  primary: ProofPayload,
  pathAnalysis: PathAnalysis | null,
): OracleDefinition {
  let staticProof: string;
  if (pathAnalysis) {
    const transformCount = pathAnalysis.transforms.length;
    const blockingTransforms = pathAnalysis.transforms.filter(
      t => t.effect.payload_action === 'payload_blocked'
    );
    if (blockingTransforms.length > 0) {
      staticProof = `Path contains ${transformCount} transform(s), including ${blockingTransforms.length} blocking transform(s). ` +
        `Payload may not reach sink in exploitable form.`;
    } else if (transformCount > 0) {
      staticProof = `Path contains ${transformCount} transform(s), none blocking. ` +
        `Payload survives transit from source to sink across ${pathAnalysis.path_node_ids.length} nodes.`;
    } else {
      staticProof = `Direct path from source to sink (${pathAnalysis.path_node_ids.length} nodes), no transforms. ` +
        `Payload reaches sink unmodified.`;
    }
  } else {
    staticProof = `Source-sink relationship established by static analysis. ` +
      `Path details unavailable (source-line fallback or data_in taint).`;
  }

  let dynamicSignal: OracleDefinition['dynamic_signal'] | undefined;

  if (primary.canary) {
    dynamicSignal = {
      type: 'content_match',
      pattern: primary.canary,
      positive: true,
    };
  } else if (payloadClass === 'sql_injection' && /SLEEP|pg_sleep|WAITFOR/i.test(primary.value)) {
    dynamicSignal = {
      type: 'timing',
      pattern: 'response_time > 2000ms',
      positive: true,
    };
  }

  return {
    type: dynamicSignal ? 'hybrid' : 'static',
    static_proof: staticProof,
    dynamic_signal: dynamicSignal,
  };
}


/**
 * Validate that a payload is safe for automated use.
 * Returns true if the payload passes the safety gate.
 *
 * SQL: must not contain destructive keywords (DROP, DELETE, etc.)
 * Command: must be from the SAFE_COMMANDS allowlist
 * Others: pass through for now (MVP)
 */
export function validatePayloadSafety(payload: string, payloadClass: PayloadClass): boolean {
  if (payloadClass === 'sql_injection') {
    if (SQL_DESTRUCTIVE.test(payload)) return false;
    return true;
  }

  if (payloadClass === 'command_injection') {
    const commandPart = payload.replace(/^[;&|]+\s*/, '').trim();
    return SAFE_COMMANDS.some(safe => commandPart === safe || commandPart.startsWith(safe));
  }

  return true;
}


/**
 * Content-aware payload class inference — permanent last-resort fallback.
 *
 * Examines the code snapshot of a node for patterns that indicate a specific
 * vulnerability class. Used when sink-class, CWE-class, AND sink-context all fail.
 *
 * SQL detection requires 2+ structural keywords to avoid false positives on
 * English text that happens to contain words like "SELECT".
 */
export function inferPayloadClassFromContent(node: NeuralMapNode): PayloadClass | null {
  const snap = node.analysis_snapshot || node.code_snapshot;
  if (!snap) return null;

  // SQL detection: require 2+ structural keywords
  const sqlKeywords = [
    /\bSELECT\b/i, /\bINSERT\b/i, /\bUPDATE\b/i, /\bDELETE\b/i,
    /\bFROM\b/i, /\bWHERE\b/i, /\bUNION\b/i, /\bJOIN\b/i,
    /\bORDER\s+BY\b/i, /\bGROUP\s+BY\b/i, /\bHAVING\b/i,
    /\bCASE\s+WHEN\b/i, /\bVALUES\b/i, /\bINTO\b/i,
  ];
  const sqlHits = sqlKeywords.filter(re => re.test(snap)).length;
  if (sqlHits >= 2) return 'sql_injection';

  // Command injection: shell interpreters and child_process calls
  if (/(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)\b/.test(snap)) return 'command_injection';
  if (/\b(child_process|exec|execSync|spawn|spawnSync)\s*\(/.test(snap)) return 'command_injection';

  // XSS: DOM manipulation
  if (/\.(innerHTML|outerHTML)\s*=/.test(snap)) return 'xss';
  if (/document\.(write|writeln)\s*\(/.test(snap)) return 'xss';

  // Path traversal: file operations with interpolation
  if (/\b(readFileSync|readFile|writeFileSync|writeFile|createReadStream)\s*\(/.test(snap) &&
      /\$\{|` *\+/.test(snap)) return 'path_traversal';

  return null;
}


/**
 * Generate a proof certificate for a finding.
 *
 * This is the entry point. Given a NeuralMap, a Finding, and the CWE that
 * triggered it, produce a ProofCertificate with:
 * - A primary payload demonstrating the vulnerability
 * - Variant payloads for different contexts
 * - A delivery spec (how to get the payload to the source)
 * - An oracle (how to verify it worked)
 * - Path analysis (what transforms the payload traverses)
 *
 * Returns null for CWEs that are not payload-generatable (crypto, hardcoded creds, etc.)
 */
export function generateProof(
  map: NeuralMap,
  finding: Finding,
  cwe: string,
  sinkContext?: Map<string, Set<string>>,
): ProofCertificate | null {
  const sinkNode = lookupNode(map, finding.sink);
  const sourceNode = lookupNode(map, finding.source);
  const isSyntheticFinding = finding.source.id.startsWith('srcline-')
                           || finding.sink.id.startsWith('srcline-');

  let payloadClass: PayloadClass | null = null;

  if (sinkNode) {
    payloadClass = resolveSinkClass(sinkNode.node_subtype);
  }

  if (!payloadClass) {
    payloadClass = inferPayloadClassFromCWE(cwe);
  }

  // Sink-context fallback: check if the finding's taint came through a function
  // that feeds a known sink type. The cross_file_param_taint_via_* data_in entries
  // tell us which function carried the taint.
  if (!payloadClass && sinkContext && sinkNode) {
    for (const d of sinkNode.data_in) {
      const match = d.name.match(/^cross_file_param_taint_via_(.+)$/);
      if (match) {
        const funcName = match[1];
        const sinkSubtypes = sinkContext.get(funcName);
        if (sinkSubtypes && sinkSubtypes.size > 0) {
          payloadClass = resolveSinkClass([...sinkSubtypes][0]);
          if (payloadClass) break;
        }
      }
    }
  }

  // ALSO check by nodeId keys (direct cataloging uses nodeId, not funcName)
  if (!payloadClass && sinkContext) {
    for (const [key, subtypes] of sinkContext) {
      if (subtypes.size > 0) {
        const candidate = resolveSinkClass([...subtypes][0]);
        if (candidate) {
          // Only use this if the finding's source or sink is related to this function
          // (V1: accept any sink context — over-approximation matching PASS 2/3 philosophy)
          payloadClass = candidate;
          break;
        }
      }
    }
  }

  if (!payloadClass && sinkNode) {
    payloadClass = inferPayloadClassFromContent(sinkNode);
  }

  if (!payloadClass) return null;

  let pathAnalysis: PathAnalysis | null = null;
  if (!isSyntheticFinding && sinkNode && sourceNode) {
    const pathIds = tracePath(map, finding.source.id, finding.sink.id);
    if (pathIds) {
      const transforms = analyzeTransforms(map, pathIds);
      const blocked = transforms.find(t => t.effect.payload_action === 'payload_blocked');
      pathAnalysis = {
        path_node_ids: pathIds,
        transforms,
        payload_reaches_sink: !blocked,
        blocked_by: blocked?.node_id,
      };
    }
  }

  const { primary, variants } = selectPayload(
    payloadClass,
    sinkNode,
    finding.sink,
    pathAnalysis,
  );

  const delivery = buildDeliverySpec(
    map,
    sourceNode,
    finding.source,
    primary.value,
    pathAnalysis?.transforms.map(t => t.effect) ?? [],
  );

  const oracle = buildOracle(payloadClass, primary, pathAnalysis);

  let strength: ProofCertificate['proof_strength'] = 'conclusive';
  if (isSyntheticFinding) {
    strength = 'indicative';
  } else if (pathAnalysis?.transforms.some(t => t.effect.effect === 'unknown')) {
    strength = 'strong';
  } else if (!pathAnalysis) {
    strength = 'strong';
  }

  if (!validatePayloadSafety(primary.value, payloadClass)) {
    return null;
  }

  return {
    primary_payload: primary,
    variants,
    delivery,
    oracle,
    proof_strength: strength,
    path_analysis: pathAnalysis,
  };
}
