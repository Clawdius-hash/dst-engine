/**
 * Property Engine — Taint Reachability Property
 *
 * Assertion: "No tainted data reaches a dangerous sink without neutralization."
 *
 * Two detection strategies:
 * 1. Story-based (V2): Walk map.story sentences, track taint through variables,
 *    detect SINK sentences with tainted variables. Respect parameter-binding as neutralization.
 * 2. Graph BFS: For each INGRESS node, check if any unsanitized path reaches a dangerous
 *    STORAGE/EXTERNAL/EGRESS node. TRANSFORM/sanitize, TRANSFORM/encrypt, TRANSFORM/hash,
 *    or effective CONTROL nodes neutralize taint.
 */

import type { NeuralMap, NeuralMapNode, NodeType, SemanticSentence, EdgeType } from '../types.js';
import type { NodeRef } from '../verifier/types.js';
import type { SecurityProperty, CWEMapping, PropertyContext, PropertyResult, PropertyViolation } from './types.js';
import { isNeutralizingSubtype } from './neutralizers.js';

// ---------------------------------------------------------------------------
// Dangerous sink types — node types that can be exploited with tainted data
// ---------------------------------------------------------------------------

const DANGEROUS_SINK_TYPES: ReadonlySet<NodeType> = new Set([
  'STORAGE', 'EXTERNAL', 'EGRESS',
]);

/**
 * Subtypes of TRANSFORM that neutralize taint.
 * If a path passes through one of these, taint is considered neutralized.
 */
const NEUTRALIZING_SUBTYPES: ReadonlySet<string> = new Set([
  'sanitize', 'encrypt', 'hash', 'encode', 'escape', 'validate',
  'parameterize', 'prepared_statement',
]);

/**
 * Edge types that represent actual data flow.
 */
const FLOW_EDGE_TYPES: ReadonlySet<EdgeType> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);

// ---------------------------------------------------------------------------
// CWE Mappings — covers all required injection types
// ---------------------------------------------------------------------------

const TAINT_CWE_MAPPINGS: CWEMapping[] = [
  // SQL Injection
  {
    cwe: 'CWE-89',
    name: 'SQL Injection',
    when: { sinkType: 'STORAGE', sinkSubtype: ['sql_query', 'sql_write', 'sql_read'], missing: 'sanitization' },
    severity: 'critical',
  },
  // NoSQL Injection
  {
    cwe: 'CWE-943',
    name: 'NoSQL Injection',
    when: { sinkType: 'STORAGE', sinkSubtype: ['nosql_query', 'nosql_write', 'nosql_read'], missing: 'sanitization' },
    severity: 'critical',
  },
  // XSS
  {
    cwe: 'CWE-79',
    name: 'Cross-site Scripting (XSS)',
    when: { sinkType: 'EGRESS', sinkSubtype: ['http_response', 'html_render', 'template_render'], missing: 'encoding' },
    severity: 'high',
  },
  // OS Command Injection
  {
    cwe: 'CWE-78',
    name: 'OS Command Injection',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['system_exec', 'shell_exec', 'process_spawn'], missing: 'sanitization' },
    severity: 'critical',
  },
  // Command Injection (generic)
  {
    cwe: 'CWE-77',
    name: 'Command Injection',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['command_exec', 'eval'], missing: 'sanitization' },
    severity: 'critical',
  },
  // Path Traversal
  {
    cwe: 'CWE-22',
    name: 'Path Traversal',
    when: { sinkType: 'STORAGE', sinkSubtype: ['file_read', 'file_write', 'file_access'], missing: 'validation' },
    severity: 'high',
  },
  // LDAP Injection
  {
    cwe: 'CWE-90',
    name: 'LDAP Injection',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['ldap_query', 'ldap_search'], missing: 'sanitization' },
    severity: 'high',
  },
  // XPath Injection
  {
    cwe: 'CWE-643',
    name: 'XPath Injection',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['xpath_query', 'xpath_evaluate'], missing: 'sanitization' },
    severity: 'high',
  },
  // SSRF
  {
    cwe: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['http_request', 'url_fetch', 'network_connect'], missing: 'validation' },
    severity: 'high',
  },
  // XXE
  {
    cwe: 'CWE-611',
    name: 'XML External Entity (XXE)',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['xml_parse', 'xml_process'], missing: 'validation' },
    severity: 'high',
  },
  // Code Injection
  {
    cwe: 'CWE-94',
    name: 'Code Injection',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['code_eval', 'dynamic_import', 'script_exec'], missing: 'sanitization' },
    severity: 'critical',
  },
  // Open Redirect
  {
    cwe: 'CWE-601',
    name: 'Open Redirect',
    when: { sinkType: 'EGRESS', sinkSubtype: ['redirect', 'url_redirect', 'http_redirect'], missing: 'validation' },
    severity: 'medium',
  },
  // Deserialization of Untrusted Data
  {
    cwe: 'CWE-502',
    name: 'Deserialization of Untrusted Data',
    when: { sinkType: 'EXTERNAL', sinkSubtype: ['deserialize', 'unserialize', 'unpickle'], missing: 'validation' },
    severity: 'critical',
  },
];

// ---------------------------------------------------------------------------
// Fix suggestions indexed by CWE
// ---------------------------------------------------------------------------

const FIX_SUGGESTIONS: Record<string, string> = {
  'CWE-89': 'Use parameterized queries or prepared statements instead of string concatenation.',
  'CWE-943': 'Use parameterized queries or ORM methods with proper input validation.',
  'CWE-79': 'Apply context-aware output encoding (HTML entity encode, JS escape, URL encode).',
  'CWE-78': 'Avoid shell commands with user input. Use parameterized APIs or allowlists.',
  'CWE-77': 'Avoid dynamic command construction. Use parameterized APIs or allowlists.',
  'CWE-22': 'Validate and canonicalize file paths. Use allowlists for permitted directories.',
  'CWE-90': 'Escape special LDAP characters in user input before constructing queries.',
  'CWE-643': 'Use parameterized XPath APIs or escape special characters in user input.',
  'CWE-918': 'Validate and allowlist destination URLs. Block internal/private IP ranges.',
  'CWE-611': 'Disable external entity processing in XML parser configuration.',
  'CWE-94': 'Avoid dynamic code evaluation. Use sandboxed interpreters if unavoidable.',
  'CWE-601': 'Validate redirect URLs against an allowlist of permitted destinations.',
  'CWE-502': 'Avoid deserializing untrusted data. Use safe serialization formats (JSON).',
};

// ---------------------------------------------------------------------------
// Strategy 1: Story-based detection (V2)
// ---------------------------------------------------------------------------

/**
 * Walk the semantic story, track variable taint, detect when tainted variables
 * reach sinks without neutralization. Respects parameter-binding as neutralization.
 */
function verifyViaStory(map: NeuralMap, _ctx: PropertyContext): PropertyViolation[] {
  const story = map.story;
  if (!story || story.length === 0) return [];

  const violations: PropertyViolation[] = [];

  // Track variable taint: variable name -> { tainted, sourceNodeId, sourceLine }
  const taintMap = new Map<string, { tainted: boolean; sourceNodeId: string; sourceLine: number }>();

  // Track parameterized objects — parameter-binding neutralizes taint
  const parameterizedObjects = new Set<string>();

  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  for (const sentence of story) {
    const node = nodeMap.get(sentence.nodeId);
    if (!node) continue;

    const variable = sentence.slots?.variable ?? sentence.slots?.name ?? '';

    // TAINTED sentences: mark variables as tainted
    if (sentence.taintClass === 'TAINTED' && variable) {
      taintMap.set(variable, {
        tainted: true,
        sourceNodeId: sentence.nodeId,
        sourceLine: sentence.lineNumber,
      });
    }

    // TRANSFORM sentences: mark variables as clean
    if (sentence.taintClass === 'TRANSFORM' && variable) {
      taintMap.set(variable, {
        tainted: false,
        sourceNodeId: sentence.nodeId,
        sourceLine: sentence.lineNumber,
      });
    }

    // SAFE sentences: mark variables as clean (e.g., constants, config values)
    if (sentence.taintClass === 'SAFE' && variable) {
      taintMap.set(variable, {
        tainted: false,
        sourceNodeId: sentence.nodeId,
        sourceLine: sentence.lineNumber,
      });
    }

    // Parameter-binding detection
    if (sentence.templateKey?.includes('parameterized') ||
        sentence.templateKey?.includes('parameter_binding') ||
        sentence.templateKey?.includes('prepared_statement') ||
        sentence.text?.includes('parameter-binding')) {
      const obj = sentence.slots?.object ?? '';
      if (obj) parameterizedObjects.add(obj);
      // The variable used in parameter binding is safe
      if (variable) {
        taintMap.set(variable, {
          tainted: false,
          sourceNodeId: sentence.nodeId,
          sourceLine: sentence.lineNumber,
        });
      }
    }

    // SINK sentences: check if any tainted variable reaches sink
    if (sentence.taintClass === 'SINK' && node && DANGEROUS_SINK_TYPES.has(node.node_type)) {
      // Check if the object was parameterized
      const obj = sentence.slots?.object ?? '';
      if (obj && parameterizedObjects.has(obj)) continue;

      // Check if the variable is tainted
      if (variable) {
        const info = taintMap.get(variable);
        if (info?.tainted) {
          const sourceNode = nodeMap.get(info.sourceNodeId);
          violations.push({
            source: nodeRefFrom(sourceNode, info.sourceNodeId, info.sourceLine),
            sink: nodeRefFrom(node, node.id, sentence.lineNumber),
            sinkType: node.node_type,
            sinkSubtype: node.node_subtype,
            missing: inferMissing(node.node_type, node.node_subtype),
            via: 'property_sentence',
            description: `Tainted variable "${variable}" reaches ${node.node_type}/${node.node_subtype} without neutralization`,
          });
        }
      }
    }
  }

  return violations;
}

// ---------------------------------------------------------------------------
// Strategy 2: Graph BFS detection
// ---------------------------------------------------------------------------

/**
 * For each INGRESS node, BFS to find unsanitized paths to dangerous sinks.
 * A TRANSFORM with a neutralizing subtype or an effective CONTROL node blocks the path.
 */
function verifyViaBFS(map: NeuralMap, _ctx: PropertyContext): PropertyViolation[] {
  const violations: PropertyViolation[] = [];
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  // Collect INGRESS nodes as potential taint sources
  const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');

  // Collect dangerous sink nodes
  const sinkNodes = map.nodes.filter(n =>
    DANGEROUS_SINK_TYPES.has(n.node_type) &&
    n.node_subtype !== '' // Must have a meaningful subtype
  );

  for (const source of ingressNodes) {
    // Only consider sources that emit tainted data
    const hasTaintedOutput = source.data_out?.some(d => d.tainted) ?? false;
    if (!hasTaintedOutput && source.data_out?.length > 0) continue;

    for (const sink of sinkNodes) {
      // Check if there's an unsanitized path from source to sink
      if (hasUnsanitizedPath(map, nodeMap, source.id, sink.id)) {
        violations.push({
          source: nodeRefFrom(source, source.id, source.line_start),
          sink: nodeRefFrom(sink, sink.id, sink.line_start),
          sinkType: sink.node_type,
          sinkSubtype: sink.node_subtype,
          missing: inferMissing(sink.node_type, sink.node_subtype),
          via: 'property_bfs',
          description: `Tainted data from ${source.label || source.node_subtype} reaches ${sink.node_type}/${sink.node_subtype} without neutralization`,
        });
      }
    }
  }

  return violations;
}

/**
 * BFS: check if there is a path from source to sink that does not pass through
 * any neutralizing node (TRANSFORM with sanitize/encrypt/hash/encode/escape/validate
 * subtypes, or effective CONTROL nodes).
 *
 * Uses composite visited keys (nodeId:passedGate) to avoid safe-path pruning.
 */
function hasUnsanitizedPath(
  map: NeuralMap,
  nodeMap: Map<string, NeuralMapNode>,
  sourceId: string,
  sinkId: string,
): boolean {
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; neutralized: boolean }> = [
    { nodeId: sourceId, neutralized: false },
  ];
  let head = 0;

  while (head < queue.length) {
    const { nodeId, neutralized } = queue[head++];
    const visitKey = `${nodeId}:${neutralized}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    // Check if this node neutralizes taint
    let isNeutralizer = false;
    if (node.node_type === 'TRANSFORM' && isNeutralizingSubtype(node.node_subtype)) {
      isNeutralizer = true;
    }
    if (node.node_type === 'CONTROL' &&
        (node.node_subtype === 'validation' || node.node_subtype === 'guard' || node.node_subtype === 'bounds_check')) {
      // Only CONTROL nodes with validation/guard/bounds_check subtypes neutralize taint.
      // Generic CONTROL nodes (e.g., `if (user.isAdmin)`) do NOT sanitize.
      const processesData = node.data_in?.some(d => d.tainted || d.sensitivity !== 'NONE') ?? false;
      if (processesData) isNeutralizer = true;
    }

    const neutralizedNow = neutralized || isNeutralizer;

    // Reached sink — vulnerable only if not neutralized
    if (nodeId === sinkId) {
      if (!neutralizedNow) return true;
      continue;
    }

    // Follow data-flow edges
    for (const edge of node.edges) {
      if (!FLOW_EDGE_TYPES.has(edge.edge_type)) continue;
      const edgeKey = `${edge.target}:${neutralizedNow}`;
      if (!visited.has(edgeKey)) {
        queue.push({ nodeId: edge.target, neutralized: neutralizedNow });
      }
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nodeRefFrom(node: NeuralMapNode | undefined, id: string, line: number): NodeRef {
  if (!node) {
    return { id, label: '', line, code: '' };
  }
  return {
    id: node.id,
    label: node.label,
    line: node.line_start || line,
    code: node.code_snapshot?.slice(0, 200) ?? '',
  };
}

/**
 * Infer what neutralization is missing based on sink type and subtype.
 */
function inferMissing(sinkType: NodeType, sinkSubtype: string): PropertyViolation['missing'] {
  // File operations need validation (path traversal)
  if (sinkSubtype.startsWith('file_')) return 'validation';
  // HTTP responses need encoding (XSS)
  if (sinkSubtype.includes('response') || sinkSubtype.includes('render')) return 'encoding';
  // Redirects need validation
  if (sinkSubtype.includes('redirect')) return 'validation';
  // Network/URL operations need validation (SSRF)
  if (sinkSubtype.includes('http_request') || sinkSubtype.includes('url_fetch') || sinkSubtype.includes('network')) return 'validation';
  // XML parsing needs validation (XXE)
  if (sinkSubtype.includes('xml_')) return 'validation';
  // Deserialization needs validation
  if (sinkSubtype.includes('deserialize') || sinkSubtype.includes('unserialize') || sinkSubtype.includes('unpickle')) return 'validation';
  // Default: sanitization (SQL injection, command injection, LDAP, XPath, etc.)
  return 'sanitization';
}

// ---------------------------------------------------------------------------
// The Property
// ---------------------------------------------------------------------------

/**
 * Taint Reachability Property
 *
 * Asserts: "No tainted data reaches a dangerous sink without neutralization."
 */
export const taintReachability: SecurityProperty = {
  id: 'taint-reachability',
  name: 'Taint Reachability',
  assertion: 'No tainted data reaches a dangerous sink without neutralization.',
  cweMapping: TAINT_CWE_MAPPINGS,

  verify(map: NeuralMap, ctx: PropertyContext): PropertyResult {
    let violations: PropertyViolation[] = [];
    let storyRan = false;

    // Strategy 1: Story-based detection (preferred when story is available)
    // Story is the higher-fidelity signal — it understands parameter-binding,
    // variable reassignment, and other neutralizations the BFS cannot see.
    if (ctx.hasStory && map.story && map.story.length > 0) {
      violations = verifyViaStory(map, ctx);
      storyRan = true;
    }

    // Strategy 2: Graph BFS (primary when no story, complement when story found nothing)
    // Skip BFS when story ran — story understands neutralizations BFS cannot.
    if (!storyRan) {
      violations = verifyViaBFS(map, ctx);
    }

    // Deduplicate by source-sink pair
    const seen = new Set<string>();
    const deduped: PropertyViolation[] = [];
    for (const v of violations) {
      const key = `${v.source.id}:${v.sink.id}:${v.sinkSubtype}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(v);
      }
    }

    return {
      propertyId: 'taint-reachability',
      holds: deduped.length === 0,
      violations: deduped,
    };
  },
};

export { TAINT_CWE_MAPPINGS, FIX_SUGGESTIONS };
