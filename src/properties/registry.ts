/**
 * Property Engine — Property Registry
 *
 * Defines and exports the PROPERTY_REGISTRY array.
 * Extracted from index.ts to break the circular dependency
 * between engine.ts and index.ts.
 */

import type { SecurityProperty } from './types.js';
import { taintReachability } from './taint-reachability.js';
import { missingAuth } from './missing-auth.js';
import { sensitiveExposure } from './sensitive-exposure.js';
import { weakCrypto } from './weak-crypto.js';
import { resourceLifecycle } from './resource-lifecycle.js';
import { integerOverflow } from './integer-overflow.js';
import { bufferSize } from './buffer-size.js';
import { sentinelCollision } from './sentinel-collision.js';

// ---------------------------------------------------------------------------
// Property Registry
// ---------------------------------------------------------------------------

/**
 * All registered security properties.
 * New properties are added here as they are implemented.
 */
export const PROPERTY_REGISTRY: SecurityProperty[] = [
  taintReachability,
  missingAuth,
  sensitiveExposure,
  weakCrypto,
  resourceLifecycle,
  integerOverflow,
  bufferSize,
  sentinelCollision,
];
