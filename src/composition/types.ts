import type { Finding } from '../verifier/types.js';

export interface ComposableFinding {
  cwe: string;
  file: string;
  finding: Finding;
  /** AST-derived storage target for the sink node (preferred over regex extraction) */
  sinkStorageTarget?: { kind: string; name: string } | null;
  /** AST-derived storage target for the source node (preferred over regex extraction) */
  sourceStorageTarget?: { kind: string; name: string } | null;
  /** Trust boundary of the sink node (e.g. 'network_external', 'storage', 'subprocess') */
  sinkTrustBoundary?: string;
  /** Trust boundary of the source node */
  sourceTrustBoundary?: string;
  /** Node type of the sink (INGRESS, EGRESS, STORAGE, TRANSFORM, etc.) */
  sinkNodeType?: string;
  /** Node subtype of the sink (db_write, file_read, env_read, http_response, etc.) */
  sinkNodeSubtype?: string;
  /** Node type of the source */
  sourceNodeType?: string;
  /** Node subtype of the source */
  sourceNodeSubtype?: string;
}

export interface ChainLink {
  finding: ComposableFinding;
  bridgeType: 'same_node' | 'storage' | 'file_io' | 'env_var' | 'config' | 'network';
  bridgeDetail: string;
}

export interface FindingChain {
  links: ChainLink[];
  chainType: string;
  boundariesCrossed: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}
