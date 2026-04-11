/**
 * Property Engine — Property Registry
 *
 * Defines and exports the PROPERTY_REGISTRY array.
 * Extracted from index.ts to break the circular dependency
 * between engine.ts and index.ts.
 */

import type { SecurityProperty } from './types.js';
import { taintReachability } from './taint-reachability.js';

// ---------------------------------------------------------------------------
// Property Registry
// ---------------------------------------------------------------------------

/**
 * All registered security properties.
 * New properties are added here as they are implemented.
 */
export const PROPERTY_REGISTRY: SecurityProperty[] = [
  taintReachability,
];
