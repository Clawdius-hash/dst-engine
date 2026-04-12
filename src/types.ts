import type { SecurityState } from './properties/security-state.js';

export type NodeType =
  | 'INGRESS'
  | 'EGRESS'
  | 'TRANSFORM'
  | 'CONTROL'
  | 'AUTH'
  | 'STORAGE'
  | 'EXTERNAL'
  | 'STRUCTURAL'
  | 'META'
  | 'RESOURCE';

export const NODE_TYPES: readonly NodeType[] = [
  'INGRESS', 'EGRESS', 'TRANSFORM', 'CONTROL', 'AUTH',
  'STORAGE', 'EXTERNAL', 'STRUCTURAL', 'META',
] as const;

/** Extended node types including RESOURCE — the 10th type for finite capacity tracking */
export const NODE_TYPES_EXTENDED: readonly NodeType[] = [
  ...NODE_TYPES, 'RESOURCE',
] as const;

export type EdgeType =
  | 'CALLS'
  | 'RETURNS'
  | 'READS'
  | 'WRITES'
  | 'DEPENDS'
  | 'CONTAINS'
  | 'DATA_FLOW';

export const EDGE_TYPES: readonly EdgeType[] = [
  'CALLS', 'RETURNS', 'READS', 'WRITES', 'DEPENDS', 'CONTAINS', 'DATA_FLOW',
] as const;

export type Sensitivity = 'NONE' | 'PII' | 'SECRET' | 'AUTH' | 'FINANCIAL';

/**
 * Tracks the known numeric range of a variable after it passes through
 * a CONTROL node with comparison operators (e.g., if (x > 0 && x < 1000)).
 *
 * Used by integer/arithmetic verifiers (CWE-190, 191, 369, 131) to
 * suppress findings when a variable is provably bounded.
 */
export interface RangeInfo {
  min: number;
  max: number;
  bounded: boolean;
  sourceNodeId?: string;
}

/**
 * Create a RangeInfo with sensible defaults (unbounded).
 */
export function createUnboundedRange(): RangeInfo {
  return { min: -Infinity, max: Infinity, bounded: false };
}

/**
 * Create a RangeInfo from known bounds. Sets `bounded` automatically.
 */
export function createRange(min: number, max: number, sourceNodeId?: string): RangeInfo {
  return {
    min,
    max,
    bounded: Number.isFinite(min) && Number.isFinite(max),
    sourceNodeId,
  };
}

/**
 * Narrow an existing range by intersecting with new bounds.
 * Used when a variable passes through multiple CONTROL gates.
 * e.g., first `if (x > 0)` then later `if (x < 1000)` → range is (0, 1000].
 */
export function narrowRange(existing: RangeInfo, additional: RangeInfo): RangeInfo {
  const min = Math.max(existing.min, additional.min);
  const max = Math.min(existing.max, additional.max);
  return {
    min,
    max,
    bounded: Number.isFinite(min) && Number.isFinite(max),
    sourceNodeId: additional.sourceNodeId ?? existing.sourceNodeId,
  };
}

/**
 * Check if a range is provably safe for a given maximum value.
 * Returns true if the entire range fits within [0, maxSafe].
 */
export function isRangeSafe(range: RangeInfo, maxSafe: number): boolean {
  return range.bounded && range.min >= 0 && range.max <= maxSafe;
}

/**
 * Check if a range provably excludes zero (safe for division).
 */
export function rangeExcludesZero(range: RangeInfo): boolean {
  return range.min > 0 || range.max < 0;
}

/** A deterministic semantic sentence describing what one piece of code does */
export interface SemanticSentence {
  text: string;
  templateKey: string;
  slots: Record<string, string>;
  lineNumber: number;
  nodeId: string;
  taintClass: 'TAINTED' | 'SAFE' | 'SINK' | 'TRANSFORM' | 'STRUCTURAL' | 'NEUTRAL';
  taintBasis?: 'SCOPE_LOOKUP' | 'PHONEME_RESOLUTION' | 'PENDING';
  reconciled?: boolean;
  originalTaintClass?: SemanticSentence['taintClass'];
  reconciliationReason?: string;
}

export interface TaintEvent {
  variable: string;
  tainted: boolean;
  reason: string;
  sentenceIndex: number;
  nodeId: string;
}

export interface DataFlow {
  name: string;
  source: string;
  target?: string;
  data_type: string;
  tainted: boolean;
  sensitivity: Sensitivity;
  range?: RangeInfo;
  /** Size of data being written — used by buffer overflow detection */
  write_size?: RangeInfo;
  /**
   * Security domain derived from the sink this data feeds — e.g.,
   * 'sql_query', 'system_exec'. Set by backward traversal from sinks.
   */
  security_domain?: string;
  /** Per-domain security state — Phase B type-state tracking.
   *  When present, consumers check this instead of boolean tainted. */
  security_state?: SecurityState;
}

export interface Edge {
  source?: string;
  target: string;
  edge_type: EdgeType;
  conditional: boolean;
  async: boolean;
}

export interface NeuralMapNode {
  id: string;
  label: string;
  sequence: number;
  node_type: NodeType;
  node_subtype: string;
  language: string;
  file: string;
  line_start: number;
  line_end: number;
  code_snapshot: string;
  analysis_snapshot: string;
  param_names?: string[];
  callee_chain?: string[];
  algorithm_name?: string;
  /** Buffer/allocation size interval — used by buffer overflow detection */
  buffer_size?: RangeInfo;
  data_in: DataFlow[];
  data_out: DataFlow[];
  edges: Edge[];
  attack_surface: string[];
  trust_boundary: string;
  tags: string[];
  metadata: Record<string, unknown>;
  sentences?: SemanticSentence[];
}

export interface NeuralMap {
  nodes: NeuralMapNode[];
  edges: Edge[];
  source_file: string;
  source_code: string;
  created_at: string;
  parser_version: string;
  story?: SemanticSentence[];
  /**
   * Reverse edge index: target nodeId -> sources.
   * Built post-processing for backward BFS.
   */
  reverseEdgeIndex?: Map<string, Array<{source: string, edge_type: string}>>;
}

let _sequenceCounter = 0;
let _sequenceGeneration = 0;

/**
 * Reset the sequence counter (for node ordering within a map).
 * Call between tests or between files. Increments the generation prefix
 * so IDs from previous builds never collide with new ones.
 */
export function resetSequence(): void {
  _sequenceCounter = 0;
  _sequenceGeneration++;
}

/**
 * Advance to the next ID generation. Call this before concurrent builds
 * to ensure auto-generated node IDs don't collide across maps.
 */
export function nextGeneration(): void {
  _sequenceGeneration++;
}

/**
 * Hard reset both counters to zero. Use in determinism tests where
 * you need two builds to produce identical IDs.
 */
export function resetSequenceHard(): void {
  _sequenceCounter = 0;
  _sequenceGeneration = 0;
}

/**
 * Create a NeuralMapNode with sensible defaults. Only `id` and `node_type`
 * are truly required; everything else gets safe empty values.
 *
 * Usage:
 *   const node = createNode({ node_type: 'INGRESS', label: 'POST /login' });
 */
export function createNode(partial: Partial<NeuralMapNode> & { node_type: NodeType }): NeuralMapNode {
  _sequenceCounter += 1;
  return {
    id: partial.id ?? `node_${_sequenceGeneration}_${_sequenceCounter}`,
    label: partial.label ?? '',
    sequence: partial.sequence ?? _sequenceCounter,
    node_type: partial.node_type,
    node_subtype: partial.node_subtype ?? '',
    language: partial.language ?? 'javascript',
    file: partial.file ?? '',
    line_start: partial.line_start ?? 0,
    line_end: partial.line_end ?? 0,
    code_snapshot: partial.code_snapshot ?? '',
    analysis_snapshot: partial.analysis_snapshot ?? partial.code_snapshot ?? '',
    param_names: partial.param_names,
    callee_chain: partial.callee_chain,
    algorithm_name: partial.algorithm_name,
    buffer_size: partial.buffer_size,
    data_in: partial.data_in ?? [],
    data_out: partial.data_out ?? [],
    edges: partial.edges ?? [],
    attack_surface: partial.attack_surface ?? [],
    trust_boundary: partial.trust_boundary ?? '',
    tags: partial.tags ?? [],
    metadata: partial.metadata ?? {},
  };
}

/**
 * Create an empty NeuralMap shell for a given file.
 */
export function createNeuralMap(sourceFile: string, sourceCode: string): NeuralMap {
  return {
    nodes: [],
    edges: [],
    source_file: sourceFile,
    source_code: sourceCode,
    created_at: new Date().toISOString(),
    parser_version: '0.1.0',
  };
}
