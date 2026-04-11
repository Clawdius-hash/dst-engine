/**
 * Property Engine — Type Definitions
 *
 * Security properties are CWE-free semantic assertions about code behavior.
 * Violations carry only structural information (source, sink, what's missing).
 * CWE labeling is a separate mapping step, not embedded in the property.
 */

import type { NeuralMap, NodeType } from '../types.js';
import type { NodeRef } from '../verifier/types.js';

// ---------------------------------------------------------------------------
// Core Property Interfaces
// ---------------------------------------------------------------------------

/**
 * A security property: a named assertion that can be verified against a NeuralMap.
 * Properties detect vulnerabilities semantically, without coupling to CWE identifiers.
 * The cweMapping array enables post-hoc CWE labeling for reporting compatibility.
 */
export interface SecurityProperty {
  /** Unique property identifier (e.g., 'taint-reachability') */
  id: string;
  /** Human-readable name */
  name: string;
  /** The assertion this property checks (plain English) */
  assertion: string;
  /** CWE mappings for converting violations to CWE-labeled findings */
  cweMapping: CWEMapping[];
  /** Verify the property against a NeuralMap */
  verify: (map: NeuralMap, ctx: PropertyContext) => PropertyResult;
}

/**
 * Maps a property violation pattern to a specific CWE.
 * The `when` clause matches on violation characteristics.
 */
export interface CWEMapping {
  /** CWE identifier (e.g., 'CWE-89') */
  cwe: string;
  /** CWE name (e.g., 'SQL Injection') */
  name: string;
  /** Matching criteria — when does this CWE apply? */
  when: {
    sinkType?: NodeType;
    sinkSubtype?: string | string[];
    sourceType?: NodeType;
    missing?: string;
  };
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low';
}

// ---------------------------------------------------------------------------
// Execution Context
// ---------------------------------------------------------------------------

/**
 * Context passed to property verification — controls detection strategy and strictness.
 */
export interface PropertyContext {
  /** Source language (lowercase) */
  language: string;
  /** Whether the NeuralMap has a semantic story (enables V2 sentence-based detection) */
  hasStory: boolean;
  /** Whether the code is library/framework code (suppresses certain findings) */
  isLibrary: boolean;
  /** Strict mode — report even low-confidence findings */
  pedantic: boolean;
}

// ---------------------------------------------------------------------------
// Results (CWE-free)
// ---------------------------------------------------------------------------

/**
 * Result of verifying a single property against a NeuralMap.
 * Contains NO CWE field — CWE mapping is a separate downstream step.
 */
export interface PropertyResult {
  /** Which property produced this result */
  propertyId: string;
  /** Whether the property holds (true = no violations found) */
  holds: boolean;
  /** Specific violations found (empty if holds is true) */
  violations: PropertyViolation[];
}

/**
 * A single property violation — tainted data reaching a dangerous sink
 * without the required neutralization.
 *
 * Deliberately CWE-free. The violation describes WHAT happened structurally,
 * not which CWE it maps to. CWE labeling is done by cwe-map.ts.
 */
export interface PropertyViolation {
  /** The source node (where tainted data originates) */
  source: NodeRef;
  /** The sink node (where tainted data arrives) */
  sink: NodeRef;
  /** Sink node type */
  sinkType: NodeType;
  /** Sink node subtype (e.g., 'sql_query', 'system_exec') */
  sinkSubtype: string;
  /** What neutralization is missing */
  missing: 'sanitization' | 'validation' | 'authentication' | 'authorization'
         | 'encryption' | 'bounds_check' | 'null_check' | 'lifecycle'
         | 'synchronization' | 'encoding';
  /** How the violation was detected */
  via: 'property_bfs' | 'property_sentence' | 'property_structural';
  /** Plain-language description of the violation */
  description: string;
  /** Optional extra context */
  context?: Record<string, string>;
}
