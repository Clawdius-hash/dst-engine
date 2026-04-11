/**
 * Property Engine — Public API
 *
 * Exports the property registry and engine functions.
 */

// ---------------------------------------------------------------------------
// Property Registry (from registry.ts to avoid circular import with engine.ts)
// ---------------------------------------------------------------------------

export { PROPERTY_REGISTRY } from './registry.js';

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

export { runProperties, propertyResultsToFindings } from './engine.js';
export { taintReachability } from './taint-reachability.js';
export type {
  SecurityProperty,
  CWEMapping,
  PropertyContext,
  PropertyResult,
  PropertyViolation,
} from './types.js';
export { mapViolationToCWE, violationToFinding } from './cwe-map.js';
