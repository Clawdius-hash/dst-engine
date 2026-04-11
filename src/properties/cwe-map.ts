/**
 * Property Engine — CWE Mapping
 *
 * Converts CWE-free PropertyViolations into CWE-labeled Findings
 * compatible with the existing DST verification pipeline.
 *
 * This is the bridge between the semantic property layer and CWE reporting.
 */

import type { Finding } from '../verifier/types.js';
import type { CWEMapping, PropertyViolation } from './types.js';

/**
 * Match a violation against a set of CWE mappings.
 * Returns the first matching CWEMapping, or null if none match.
 *
 * Matching rules:
 * - sinkType must match (if specified in the mapping)
 * - sinkSubtype must match (string or one of string[], if specified)
 * - missing must match (if specified in the mapping)
 * - sourceType must match the source node type (if specified — not used in violations directly)
 */
export function mapViolationToCWE(
  violation: PropertyViolation,
  mappings: CWEMapping[],
): CWEMapping | null {
  for (const mapping of mappings) {
    const w = mapping.when;

    // Check sinkType
    if (w.sinkType !== undefined && w.sinkType !== violation.sinkType) {
      continue;
    }

    // Check sinkSubtype (string or array)
    if (w.sinkSubtype !== undefined) {
      if (Array.isArray(w.sinkSubtype)) {
        if (!w.sinkSubtype.includes(violation.sinkSubtype)) continue;
      } else {
        if (w.sinkSubtype !== violation.sinkSubtype) continue;
      }
    }

    // Check missing neutralization type
    if (w.missing !== undefined && w.missing !== violation.missing) {
      continue;
    }

    // All specified criteria matched
    return mapping;
  }

  return null;
}

/**
 * Convert a PropertyViolation + matched CWE into a Finding
 * compatible with the existing DST verification pipeline.
 */
export function violationToFinding(
  violation: PropertyViolation,
  cwe: CWEMapping,
  fix: string,
): Finding {
  return {
    source: violation.source,
    sink: violation.sink,
    missing: violation.missing,
    severity: cwe.severity,
    description: violation.description,
    fix,
    via: violation.via === 'property_bfs' ? 'bfs'
       : violation.via === 'property_sentence' ? 'scope_taint'
       : 'structural',
  };
}
