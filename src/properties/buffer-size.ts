/**
 * Property Engine — Buffer Size Mismatch Property
 *
 * Assertion: "No write operation exceeds the allocation size of its target buffer."
 *
 * For each node that has `buffer_size` defined (meaning its allocation size is known):
 * - Check all `data_in` entries for `write_size`
 * - If any `write_size.max > buffer_size.min` -> violation (maximum write can exceed minimum buffer)
 *
 * This detects the class of bugs exemplified by:
 * - FreeBSD NFS CVE-2026-4747: 128-byte stack buffer receives up to 400 bytes via memcpy
 * - Linux kernel NFS: 112-byte buffer receives 1056 bytes
 */

import type { NeuralMap, NeuralMapNode } from '../types.js';
import type { SecurityProperty, PropertyViolation, PropertyContext, CWEMapping, PropertyResult } from './types.js';
import type { NodeRef } from '../verifier/types.js';

function nodeRef(n: NeuralMapNode): NodeRef {
  return { id: n.id, label: n.label, line: n.line_start, code: n.code_snapshot.slice(0, 200) };
}

const CWE_MAPPINGS: CWEMapping[] = [
  { cwe: 'CWE-119', name: 'Improper Restriction of Operations within Bounds of Memory Buffer', severity: 'critical',
    when: {} },
  { cwe: 'CWE-120', name: 'Buffer Copy without Checking Size of Input', severity: 'critical',
    when: { sinkSubtype: ['buffer', 'memory'] } },
  { cwe: 'CWE-787', name: 'Out-of-bounds Write', severity: 'critical',
    when: {} },
];

export const bufferSize: SecurityProperty = {
  id: 'buffer-size',
  name: 'Buffer Size Mismatch',
  assertion: 'No write operation exceeds the allocation size of its target buffer',
  cweMapping: CWE_MAPPINGS,

  verify(map: NeuralMap, _ctx: PropertyContext): PropertyResult {
    const violations: PropertyViolation[] = [];

    for (const node of map.nodes) {
      if (!node.buffer_size || !node.buffer_size.bounded) continue;

      for (const flow of node.data_in) {
        if (!flow.write_size || !flow.write_size.bounded) continue;

        if (flow.write_size.max > node.buffer_size.min) {
          const writer = map.nodes.find(n => n.id === flow.source);
          violations.push({
            source: writer ? nodeRef(writer) : { id: flow.source, label: flow.name, line: 0, code: '' },
            sink: nodeRef(node),
            sinkType: node.node_type,
            sinkSubtype: node.node_subtype,
            missing: 'bounds_check',
            via: 'property_structural',
            description: `Write of up to ${flow.write_size.max} bytes into buffer of ${node.buffer_size.min} bytes — overflow of ${flow.write_size.max - node.buffer_size.min} bytes`,
            context: {
              buffer_size: String(node.buffer_size.min),
              write_size: String(flow.write_size.max),
              overflow: String(flow.write_size.max - node.buffer_size.min),
            },
          });
        }
      }
    }

    return { propertyId: 'buffer-size', holds: violations.length === 0, violations };
  },
};
