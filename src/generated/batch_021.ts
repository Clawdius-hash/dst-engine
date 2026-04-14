/**
 * DST Generated Verifiers — Batch 021
 * Real verifiers only (2 CWEs).
 *   CWE-862  Missing Authorization
 *   CWE-915  Improperly Controlled Modification of Dynamically-Determined Object Attributes
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutTransform,
  hasPathWithoutIntermediateType, cweDomainMatchesSink,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Compact factory (matches batch_015-017 pattern)
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
              description: `${sourceType} at ${src.label} \u2192 ${sinkType} at ${sink.label} without controls. Vulnerable to ${cweName}.`,
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
const nCi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'CONTROL');

// Safe patterns
const A = /\bauthorize\s*\(|\bhasPermission\s*\(|\bcheckAccess\s*\(|\brole\b|\bacl\b|\brbac\b|\bcan\b.*\bdo\b/i;
const MA = /\ballowedFields\b|\bpermit\b|\bwhitelist\b|\ballowlist\b|\b\.pick\s*\(|\bschema\b|\bvalidate\s*\(/i;

// ---------------------------------------------------------------------------
// A. Real verifiers — graph-pattern-based
// ---------------------------------------------------------------------------

// CWE-862: Authenticated request reaches privileged storage/external without authorization check
export const verifyCWE862 = (function () {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];

    // Sources: AUTH nodes (post-authentication) or INGRESS nodes
    const authNodes = nodesOfType(map, 'AUTH');
    const sources = authNodes.length > 0 ? authNodes : nodesOfType(map, 'INGRESS');

    // Sinks: STORAGE and EXTERNAL nodes performing privileged operations
    const sinks = map.nodes.filter(n =>
      (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
      (n.node_subtype.includes('database') || n.node_subtype.includes('admin') ||
       n.node_subtype.includes('config') || n.node_subtype.includes('user') ||
       n.attack_surface.includes('data_access') || n.attack_surface.includes('state_modification') ||
       n.code_snapshot.match(
         /\b(delete|update|insert|drop|alter|grant|revoke|admin|destroy|remove|purge|modify|write)\b/i
       ) !== null)
    );

    // Authorization controls: CONTROL nodes that check permissions
    const authzControls = nodesOfType(map, 'CONTROL').filter(c =>
      A.test(c.code_snapshot) ||
      c.node_subtype.includes('authorization') || c.node_subtype.includes('permission') ||
      c.node_subtype.includes('access_control')
    );
    const authzIds = new Set(authzControls.map(c => c.id));

    for (const src of sources) {
      for (const sink of sinks) {
        if (src.id === sink.id) continue;
        // Check if path exists without passing through an authorization control
        if (nA(map, src.id, sink.id)) {
          // Double-check: no inline authorization in source or sink code
          if (!A.test(sink.code_snapshot) && !A.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (authorization — verify actor has permission for specific resource/action)',
              severity: 'critical',
              description: `Authenticated request at ${src.label} reaches privileged operation at ${sink.label} without authorization check. Any authenticated user could access or modify protected resources.`,
              fix: 'Add authorization checks (RBAC, ABAC, or ACL) before all privileged operations. Verify the requesting user has specific permission for the target resource and action.',
            });
          }
        }
      }
    }

    return { cwe: 'CWE-862', name: 'Missing Authorization', holds: findings.length === 0, findings };
  };
})();

// CWE-915: User input mass-assigns object attributes without field allowlisting
export const verifyCWE915 = (function () {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');

    // Sinks: TRANSFORM nodes that do mass assignment / object binding
    const massAssignSinks = map.nodes.filter(n =>
      (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
      (n.node_subtype.includes('object_binding') || n.node_subtype.includes('mass_assignment') ||
       n.node_subtype.includes('autobind') || n.node_subtype.includes('merge') ||
       n.code_snapshot.match(
         /\bObject\.assign\b|\bspread\b|\b\.\.\.\w+\b|\b_\.merge\b|\b_\.assign\b|\bdeepMerge\b|\bextend\b|\bcreate\(.*req\.body\b|\bupdate\(.*req\.body\b|\bnew\s+\w+\(req\.body\)/i
       ) !== null)
    );

    for (const src of ingress) {
      for (const sink of massAssignSinks) {
        if (src.id === sink.id) continue;
        if (nCi(map, src.id, sink.id)) {
          if (!MA.test(sink.code_snapshot) && !MA.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (attribute allowlist — restrict which fields can be set from user input)',
              severity: 'high',
              description: `User input from ${src.label} mass-assigns object attributes at ${sink.label} without field filtering. Attackers could set internal fields like isAdmin, role, or price.`,
              fix: 'Implement attribute allowlisting: explicitly pick permitted fields from user input before object creation/update. Never pass raw request body to ORM create/update methods.',
            });
          }
        }
      }
    }

    return { cwe: 'CWE-915', name: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes', holds: findings.length === 0, findings };
  };
})();


// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_021_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-862': verifyCWE862,
  'CWE-915': verifyCWE915,
};
