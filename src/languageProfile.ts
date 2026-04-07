import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { NodeType, SemanticSentence } from './types.js';
import type { CalleePattern } from './calleePatterns.js';
import type { ScopeType, VariableInfo } from './mapper.js';

export interface ResolvedCalleeResult {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
  chain: string[];
}

export interface ResolvedPropertyResult {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export interface StructuralAnalysisResult {
  middlewareNames: string[];
  hasAuthGate: boolean;
  hasRateLimiter: boolean;
  hasCsrfProtection: boolean;
  hasValidation: boolean;
  routePath: string | null;
  httpMethod: string | null;
}

export interface LanguageProfile {
  id: string;

  extensions: string[];

  functionScopeTypes: ReadonlySet<string>;

  blockScopeTypes: ReadonlySet<string>;

  classScopeTypes: ReadonlySet<string>;

  getScopeType: (node: SyntaxNode) => ScopeType | null;

  variableDeclarationTypes: ReadonlySet<string>;

  functionDeclarationTypes: ReadonlySet<string>;

  processVariableDeclaration: (node: SyntaxNode, ctx: MapperContextLike) => void;

  processFunctionParams: (funcNode: SyntaxNode, ctx: MapperContextLike) => void;

  extractPatternNames: (pattern: SyntaxNode) => string[];

  resolveCallee: (node: SyntaxNode) => ResolvedCalleeResult | null;

  resolvePropertyAccess: (node: SyntaxNode) => ResolvedPropertyResult | null;

  lookupCallee: (chain: string[]) => CalleePattern | null;

  analyzeStructure: (node: SyntaxNode) => StructuralAnalysisResult | null;

  ingressPattern: RegExp;

  taintedPaths: ReadonlySet<string>;

  classifyNode: (node: SyntaxNode, ctx: MapperContextLike) => void;

  extractTaintSources: (expr: SyntaxNode, ctx: MapperContextLike) => TaintSourceResult[];

  postVisitFunction?: (node: SyntaxNode, ctx: MapperContextLike) => void;

  preVisitIteration?: (node: SyntaxNode, ctx: MapperContextLike) => void;

  postVisitIteration?: (node: SyntaxNode, ctx: MapperContextLike) => void;

  isValueFirstDeclaration: (nodeType: string) => boolean;

  isStatementContainer: (nodeType: string) => boolean;

  functionParamPattern?: RegExp;

  tryEvalCondition?: (condNode: SyntaxNode, ctx: MapperContextLike) => boolean | null;

  tryEvalSwitchTarget?: (condNode: SyntaxNode, ctx: MapperContextLike) => string | null;
}

export interface MapperContextLike {
  readonly neuralMap: { nodes: any[]; edges: any[]; source_file: string };
  readonly scopeStack: any[];
  readonly functionRegistry: Map<string, string>;
  readonly pendingCalls: Array<{ callerContainerId: string; calleeName: string; isAsync: boolean }>;
  readonly pendingCallbackTaint: Map<string, string>;
  readonly functionReturnTaint: Map<string, boolean>;
  lastCreatedNodeId: string | null;
  nodeSequence: number;
  currentScope: any | null;
  pushScope: (type: ScopeType, node: SyntaxNode, containerNodeId?: string | null) => any;
  popScope: () => any;
  declareVariable: (name: string, kind: VariableInfo['kind'], declaringNodeId?: string | null, tainted?: boolean, producingNodeId?: string | null) => void;
  resolveVariable: (name: string) => VariableInfo | null;
  addDataFlow: (fromNodeId: string, toNodeId: string, name: string, dataType?: string, tainted?: boolean) => void;
  getCurrentContainerId: () => string | null;
  addContainsEdge: (containerNodeId: string, childNodeId: string) => void;
  emitContainsIfNeeded: (childNodeId: string) => void;
  sentences: SemanticSentence[];
  addSentence(s: SemanticSentence): void;
}

export interface TaintSourceResult {
  nodeId: string;
  name: string;
}
