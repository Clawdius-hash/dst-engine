/**
 * Property Engine — Execution Engine
 *
 * Runs all registered security properties against a NeuralMap and
 * converts CWE-free results into CWE-labeled VerificationResults
 * compatible with the existing DST pipeline.
 */

import type { NeuralMap } from '../types.js';
import type { VerificationResult } from '../verifier/types.js';
import type { SecurityProperty, PropertyContext, PropertyResult } from './types.js';
import { mapViolationToCWE, violationToFinding } from './cwe-map.js';
import { PROPERTY_REGISTRY } from './registry.js';

// ---------------------------------------------------------------------------
// Run all properties
// ---------------------------------------------------------------------------

/**
 * Run all registered security properties against a NeuralMap.
 * Returns an array of PropertyResult (CWE-free).
 */
export function runProperties(map: NeuralMap, ctx: PropertyContext): PropertyResult[] {
  const results: PropertyResult[] = [];

  for (const property of PROPERTY_REGISTRY) {
    const result = property.verify(map, ctx);
    results.push(result);
  }

  return results;
}

// ---------------------------------------------------------------------------
// Convert to CWE-labeled findings
// ---------------------------------------------------------------------------

/**
 * Fix suggestions indexed by CWE — imported from taint-reachability
 * but also augmented here for any additional properties.
 */
const DEFAULT_FIX = 'Apply appropriate input validation and output encoding.';

/**
 * Convert PropertyResults into VerificationResults (CWE-labeled).
 * Each violation is mapped to zero or more CWEs via the property's cweMapping.
 *
 * Returns one VerificationResult per CWE found, grouped by CWE.
 */
export function propertyResultsToFindings(results: PropertyResult[]): VerificationResult[] {
  // Group findings by CWE
  const cweGroups = new Map<string, { name: string; findings: ReturnType<typeof violationToFinding>[] }>();

  for (const result of results) {
    if (result.holds) continue;

    // Find the property to get its CWE mappings
    const property = PROPERTY_REGISTRY.find(p => p.id === result.propertyId);
    if (!property) continue;

    for (const violation of result.violations) {
      const matched = mapViolationToCWE(violation, property.cweMapping);
      if (!matched) continue;

      const fixSuggestion = getFix(matched.cwe, property);
      const finding = violationToFinding(violation, matched, fixSuggestion);

      if (!cweGroups.has(matched.cwe)) {
        cweGroups.set(matched.cwe, { name: matched.name, findings: [] });
      }
      cweGroups.get(matched.cwe)!.findings.push(finding);
    }
  }

  // Convert groups to VerificationResults
  const verResults: VerificationResult[] = [];
  for (const [cwe, group] of cweGroups) {
    verResults.push({
      cwe,
      name: group.name,
      holds: false,
      findings: group.findings,
    });
  }

  return verResults;
}

/**
 * Get fix suggestion for a CWE from the property's data.
 */
function getFix(cwe: string, property: SecurityProperty): string {
  // Try importing fix suggestions from taint-reachability
  try {
    // Dynamic import is not ideal here, so we use a static lookup
    const FIX_MAP: Record<string, string> = {
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
    return FIX_MAP[cwe] ?? DEFAULT_FIX;
  } catch {
    return DEFAULT_FIX;
  }
}
