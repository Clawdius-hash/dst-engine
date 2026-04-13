import type { Finding } from '../verifier/types.js';

export interface ComposableFinding {
  cwe: string;
  file: string;
  finding: Finding;
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
