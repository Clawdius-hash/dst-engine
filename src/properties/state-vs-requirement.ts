/**
 * Property Engine — State vs Requirement
 *
 * Assertion: "Data flowing to a sink must have the security state
 * the sink requires."
 *
 * Unlike taint-reachability (boolean: tainted or not), this property
 * tracks PER-DOMAIN security state. Data that passes through htmlEscape
 * is xss_safe but NOT sql_safe. If it reaches a SQL sink, the mismatch
 * is the finding.
 *
 * Story-based detection only (no BFS) — avoids 2^11 state explosion.
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types.js';
import type { NodeRef } from '../verifier/types.js';
import type { SecurityProperty, PropertyContext, PropertyResult, PropertyViolation } from './types.js';
import { TAINT_CWE_MAPPINGS } from './taint-reachability.js';
import {
  createUntrustedState,
  createTrustedState,
  applyNeutralizer,
  sinkSubtypeToDomain,
} from './security-state.js';

const DANGEROUS_SINK_TYPES: ReadonlySet<NodeType> = new Set([
  'STORAGE', 'EXTERNAL', 'EGRESS',
]);

interface VarStateInfo {
  state: import('./security-state.js').SecurityState;
  sourceNodeId: string;
  sourceLine: number;
}

function nodeRefFrom(node: NeuralMapNode | undefined, id: string, line: number): NodeRef {
  if (!node) return { id, label: '', line, code: '' };
  return { id: node.id, label: node.label, line: node.line_start || line, code: node.code_snapshot?.slice(0, 200) ?? '' };
}

function inferMissing(sinkSubtype: string): PropertyViolation['missing'] {
  if (sinkSubtype.startsWith('file_')) return 'validation';
  if (sinkSubtype.includes('response') || sinkSubtype.includes('render') || sinkSubtype === 'xss_sink') return 'encoding';
  if (sinkSubtype.includes('redirect')) return 'validation';
  if (sinkSubtype.includes('http_request') || sinkSubtype.includes('url_fetch')) return 'validation';
  if (sinkSubtype.includes('xml_')) return 'validation';
  if (sinkSubtype.includes('deserialize') || sinkSubtype.includes('unserialize')) return 'validation';
  return 'sanitization';
}

function verifyViaStory(map: NeuralMap, _ctx: PropertyContext): PropertyViolation[] {
  const story = map.story;
  if (!story || story.length === 0) return [];

  const violations: PropertyViolation[] = [];
  const stateMap = new Map<string, VarStateInfo>();
  const parameterizedObjects = new Set<string>();
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));

  for (const sentence of story) {
    const node = nodeMap.get(sentence.nodeId);
    if (!node) continue;

    const variable = sentence.slots?.subject ?? sentence.slots?.variable ?? sentence.slots?.name ?? '';

    // TAINTED: initialize as all-unsafe
    if (sentence.taintClass === 'TAINTED' && variable) {
      stateMap.set(variable, {
        state: createUntrustedState(),
        sourceNodeId: sentence.nodeId,
        sourceLine: sentence.lineNumber,
      });
    }

    // TRANSFORM: apply neutralizer based on node subtype
    if (sentence.taintClass === 'TRANSFORM' && variable) {
      const existing = stateMap.get(variable);
      if (existing) {
        const newState = applyNeutralizer(existing.state, node.node_subtype);
        stateMap.set(variable, { ...existing, state: newState });
      }
    }

    // SAFE: constants, configs — mark all-safe
    if (sentence.taintClass === 'SAFE' && variable) {
      stateMap.set(variable, {
        state: createTrustedState(),
        sourceNodeId: sentence.nodeId,
        sourceLine: sentence.lineNumber,
      });
    }

    // Parameter-binding: mark parameterized objects
    if (sentence.templateKey?.includes('parameter') ||
        sentence.templateKey?.includes('prepared_statement') ||
        sentence.text?.includes('parameter-binding')) {
      const obj = sentence.slots?.object ?? '';
      if (obj) parameterizedObjects.add(obj);
      if (variable) {
        const existing = stateMap.get(variable);
        const base = existing?.state ?? createUntrustedState();
        stateMap.set(variable, {
          state: applyNeutralizer(base, 'parameterize'),
          sourceNodeId: sentence.nodeId,
          sourceLine: sentence.lineNumber,
        });
      }
    }

    // SINK: check if variable state satisfies sink requirement
    if (sentence.taintClass === 'SINK' && node && DANGEROUS_SINK_TYPES.has(node.node_type)) {
      const obj = sentence.slots?.object ?? '';
      if (obj && parameterizedObjects.has(obj)) continue;

      const sinkVar = sentence.slots?.variables ?? variable;
      if (!sinkVar) continue;

      const info = stateMap.get(sinkVar);
      if (!info) continue;

      const domain = sinkSubtypeToDomain(node.node_subtype);
      if (!domain) continue;

      if (!info.state[domain]) {
        const sourceNode = nodeMap.get(info.sourceNodeId);
        violations.push({
          source: nodeRefFrom(sourceNode, info.sourceNodeId, info.sourceLine),
          sink: nodeRefFrom(node, node.id, sentence.lineNumber),
          sinkType: node.node_type,
          sinkSubtype: node.node_subtype,
          missing: inferMissing(node.node_subtype),
          via: 'property_sentence',
          description: `Variable "${sinkVar}" reaches ${node.node_type}/${node.node_subtype} without required ${domain} neutralization`,
          context: {
            actual_state: Object.entries(info.state).filter(([, v]) => v).map(([k]) => k).join(',') || 'UNTRUSTED',
            required_domain: domain,
          },
        });
      }
    }
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

  return deduped;
}

export const stateVsRequirement: SecurityProperty = {
  id: 'state-vs-requirement',
  name: 'Security State Mismatch',
  assertion: 'Data flowing to a sink must have the security state the sink requires.',
  cweMapping: TAINT_CWE_MAPPINGS,

  verify(map: NeuralMap, ctx: PropertyContext): PropertyResult {
    let violations: PropertyViolation[] = [];

    if (ctx.hasStory && map.story && map.story.length > 0) {
      violations = verifyViaStory(map, ctx);
    }

    return {
      propertyId: 'state-vs-requirement',
      holds: violations.length === 0,
      violations,
    };
  },
};
