import type { Node as SyntaxNode } from 'web-tree-sitter';
import type Parser from 'web-tree-sitter';
import type { NeuralMap, NeuralMapNode, Edge, Sensitivity, RangeInfo, SemanticSentence, TaintEvent } from './types.js';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { LanguageProfile } from './languageProfile.js';
import { javascriptProfile } from './profiles/javascript.js';
import { resolveSentences } from './sentence-resolver.js';
import { getTemplateKey, generateSentence } from './sentence-generator.js';

const CALL_NODE_TYPES = new Set([
  'call_expression',
  'call',
  'method_invocation',
  'invocation_expression',
  'function_call_expression',
  'member_call_expression',
  'scoped_call_expression',
]);

export interface VariableInfo {
  name: string;
  declaringNodeId: string | null;
  producingNodeId: string | null;
  kind: 'let' | 'const' | 'var' | 'param' | 'import';
  tainted: boolean;
  aliasChain?: string[];
  constantValue?: string;
  genericTypeArgs?: string[];
  numericValue?: number;
  collectionTaint?: Array<{ tainted: boolean; producingNodeId: string | null }>;
  keyedTaint?: Map<string, { tainted: boolean; producingNodeId: string | null }>;
  range?: RangeInfo;
}

export type ScopeType = 'module' | 'function' | 'block' | 'class';

export interface Scope {
  id: string;
  parentId: string | null;
  type: ScopeType;
  variables: Map<string, VariableInfo>;
  node: SyntaxNode;
  containerNodeId: string | null;
}

export class MapperContext {
  readonly scopeStack: Scope[] = [];
  readonly neuralMap: NeuralMap;
  private scopeCounter = 0;
  nodeSequence = 0;
  lastCreatedNodeId: string | null = null;
  readonly functionRegistry = new Map<string, string>();
  readonly pendingCalls: Array<{
    callerContainerId: string;
    calleeName: string;
    isAsync: boolean;
  }> = [];
  readonly pendingCallbackTaint = new Map<string, string>();
  readonly functionReturnTaint = new Map<string, boolean>();
  readonly nodeById = new Map<string, NeuralMapNode>();
  readonly edgeSet = new Set<string>();
  diagnostics = {
    unmappedCalls: 0,
    droppedFlows: 0,
    droppedEdges: 0,
    totalCalls: 0,
    sourceLineFallbacks: 0,
    timing: {
      walkMs: 0,
      postProcessMs: 0,
      totalMs: 0,
    },
  };

  readonly profile: LanguageProfile;
  readonly sentences: SemanticSentence[] = [];
  readonly taintLog: TaintEvent[] = [];

  addSentence(s: SemanticSentence): void {
    this.sentences.push(s);
  }

  constructor(sourceFile: string, sourceCode: string, profile: LanguageProfile = javascriptProfile) {
    resetSequence();
    this.neuralMap = createNeuralMap(sourceFile, sourceCode);
    this.profile = profile;
  }

  buildNodeIndex(): void {
    this.nodeById.clear();
    this.edgeSet.clear();
    for (const node of this.neuralMap.nodes) {
      this.nodeById.set(node.id, node);
      for (const edge of node.edges) {
        this.edgeSet.add(`${node.id}:${edge.target}:${edge.edge_type}`);
      }
    }
  }

  get currentScope(): Scope | null {
    return this.scopeStack.length > 0
      ? this.scopeStack[this.scopeStack.length - 1]
      : null;
  }

  pushScope(type: ScopeType, node: SyntaxNode, containerNodeId: string | null = null): Scope {
    this.scopeCounter += 1;
    const parentId = this.currentScope?.id ?? null;
    const scope: Scope = {
      id: `scope_${this.scopeCounter}`,
      parentId,
      type,
      variables: new Map(),
      node,
      containerNodeId,
    };
    this.scopeStack.push(scope);
    return scope;
  }

  popScope(): Scope | undefined {
    return this.scopeStack.pop();
  }

  declareVariable(
    name: string,
    kind: VariableInfo['kind'],
    declaringNodeId: string | null = null,
    tainted: boolean = false,
    producingNodeId: string | null = null,
  ): void {
    const targetScope = kind === 'var'
      ? this.findVarScope()
      : this.currentScope;

    if (!targetScope) return;

    targetScope.variables.set(name, {
      name,
      declaringNodeId,
      producingNodeId,
      kind,
      tainted,
    });
  }

  resolveVariable(name: string): VariableInfo | null {
    for (let i = this.scopeStack.length - 1; i >= 0; i--) {
      const variable = this.scopeStack[i].variables.get(name);
      if (variable) return variable;
    }
    return null;
  }

  addDataFlow(
    fromNodeId: string,
    toNodeId: string,
    name: string,
    dataType: string = 'unknown',
    tainted: boolean = false,
    range?: RangeInfo,
  ): void {
    const fromNode = this.nodeById.get(fromNodeId) ?? this.neuralMap.nodes.find(n => n.id === fromNodeId);
    const toNode = this.nodeById.get(toNodeId) ?? this.neuralMap.nodes.find(n => n.id === toNodeId);
    if (!fromNode || !toNode) {
      this.diagnostics.droppedFlows++;
      return;
    }
    if (!this.nodeById.has(fromNodeId)) this.nodeById.set(fromNodeId, fromNode);
    if (!this.nodeById.has(toNodeId)) this.nodeById.set(toNodeId, toNode);

    const flow: {
      name: string; source: string; target: string;
      data_type: string; tainted: boolean; sensitivity: 'NONE';
      range?: RangeInfo;
    } = {
      name,
      source: fromNodeId,
      target: toNodeId,
      data_type: dataType,
      tainted,
      sensitivity: 'NONE' as const,
      ...(range !== undefined ? { range } : {}),
    };

    const existingOut = fromNode.data_out.find(
      d => d.name === name && d.source === fromNodeId && d.target === toNodeId
    );
    if (existingOut) {
      if (tainted && !existingOut.tainted) existingOut.tainted = true;
      if (range !== undefined && !existingOut.range) existingOut.range = range;
    } else {
      fromNode.data_out.push({ ...flow });
    }

    const existingIn = toNode.data_in.find(
      d => d.name === name && d.source === fromNodeId && d.target === toNodeId
    );
    if (existingIn) {
      if (tainted && !existingIn.tainted) existingIn.tainted = true;
      if (range !== undefined && !existingIn.range) existingIn.range = range;
    } else {
      toNode.data_in.push({ ...flow });
    }
  }

  getCurrentContainerId(): string | null {
    for (let i = this.scopeStack.length - 1; i >= 0; i--) {
      if (this.scopeStack[i]!.containerNodeId) return this.scopeStack[i]!.containerNodeId;
    }
    return null;
  }

  addEdge(
    sourceNodeId: string,
    targetNodeId: string,
    edgeType: Edge['edge_type'],
    opts?: { conditional?: boolean; async?: boolean },
    sourceNode?: NeuralMapNode,
  ): boolean {
    const src = sourceNode ?? this.nodeById.get(sourceNodeId)
              ?? this.neuralMap.nodes.find(n => n.id === sourceNodeId);
    if (!src) {
      this.diagnostics.droppedEdges++;
      return false;
    }

    const edgeKey = `${sourceNodeId}:${targetNodeId}:${edgeType}`;
    if (this.edgeSet.has(edgeKey)) return false;
    this.edgeSet.add(edgeKey);

    const edge: Edge = {
      target: targetNodeId,
      edge_type: edgeType,
      conditional: opts?.conditional ?? false,
      async: opts?.async ?? false,
    };

    src.edges.push(edge);
    this.neuralMap.edges.push({ ...edge, source: sourceNodeId });
    return true;
  }

  addContainsEdge(containerNodeId: string, childNodeId: string): void {
    this.addEdge(containerNodeId, childNodeId, 'CONTAINS');
  }

  emitContainsIfNeeded(childNodeId: string): void {
    const containerId = this.getCurrentContainerId();
    if (containerId && containerId !== childNodeId) {
      this.addContainsEdge(containerId, childNodeId);
    }
  }

  buildDataFlowEdges(): void {
    for (const node of this.neuralMap.nodes) {
      for (const flow of node.data_in) {
        if (!flow.source || flow.source === 'EXTERNAL') continue;
        const sourceNode = this.nodeById.get(flow.source);
        if (!sourceNode) continue;
        this.addEdge(flow.source, node.id, 'DATA_FLOW', undefined, sourceNode);
      }
    }
  }

  buildReadsEdges(): void {
    const readSubtypes = new Set(['db_read', 'cache_read', 'state_read']);

    const consumersBySource = new Map<string, NeuralMapNode[]>();
    for (const consumer of this.neuralMap.nodes) {
      for (const flow of consumer.data_in) {
        if (!flow.source || flow.source === 'EXTERNAL') continue;
        let arr = consumersBySource.get(flow.source);
        if (!arr) {
          arr = [];
          consumersBySource.set(flow.source, arr);
        }
        arr.push(consumer);
      }
    }

    for (const node of this.neuralMap.nodes) {
      if (node.node_type !== 'STORAGE') continue;
      if (!readSubtypes.has(node.node_subtype)) continue;

      const consumers = consumersBySource.get(node.id);
      if (!consumers) continue;
      for (const consumer of consumers) {
        if (consumer.id === node.id) continue;
        this.addEdge(node.id, consumer.id, 'READS', undefined, node);
      }
    }
  }

  buildWritesEdges(): void {
    const writeSubtypes = new Set(['db_write', 'cache_write', 'state_write']);

    for (const node of this.neuralMap.nodes) {
      if (node.node_type !== 'STORAGE') continue;
      if (!writeSubtypes.has(node.node_subtype)) continue;

      for (const flow of node.data_in) {
        if (!flow.source || flow.source === 'EXTERNAL') continue;
        this.addEdge(flow.source, node.id, 'WRITES');
      }
    }
  }

  buildDependsEdges(): void {
    const dependencyNodes = this.neuralMap.nodes.filter(
      n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'dependency'
    );

    if (dependencyNodes.length === 0) return;

    let moduleNode = this.neuralMap.nodes.find(
      n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'module'
    );

    if (!moduleNode) {
      moduleNode = createNode({
        label: this.neuralMap.source_file,
        node_type: 'STRUCTURAL',
        node_subtype: 'module',
        language: this.profile.id,
        file: this.neuralMap.source_file,
        line_start: 1,
        line_end: 1,
        code_snapshot: `// module: ${this.neuralMap.source_file}`,
        analysis_snapshot: `// module: ${this.neuralMap.source_file}`,
      });
      this.neuralMap.nodes.push(moduleNode);
      this.nodeById.set(moduleNode.id, moduleNode);
    }

    for (const dep of dependencyNodes) {
      this.addEdge(moduleNode.id, dep.id, 'DEPENDS', undefined, moduleNode);
    }
  }

  propagateInterproceduralTaint(): void {
    const containedMap = this.buildFunctionContainedNodes();
    const summaries = this.buildFunctionTaintSummaries(containedMap);
    this.connectCallSitesToSinks(summaries);
    const allLocalCalls = this.neuralMap.nodes.filter(n => n.node_subtype === 'local_call');
    this.markLocalCallsTainted(allLocalCalls, summaries);
    this.markLocalCallsReturnTainted(allLocalCalls, containedMap);
    this.connectTaintedLocalCallsToSinks(summaries);
    this.propagateEventEmitterTaint();
  }

  private correctPassthroughReturnTaint(allLocalCalls: NeuralMapNode[]): void {
    const nodeById = this.nodeById;
    const REQUEST_TYPES = /\b(HttpServletRequest|ServletRequest|WebRequest|HttpRequest|HttpServletResponse|ServletResponse)\b/;

    for (const [funcName, funcNodeId] of this.functionRegistry) {
      if (funcName.includes(':')) continue;
      if (this.functionReturnTaint.get(funcNodeId) !== true) continue;

      const funcNode = nodeById.get(funcNodeId);
      if (!funcNode?.param_names || funcNode.param_names.length === 0) continue;

      const snap = funcNode.analysis_snapshot || funcNode.code_snapshot || '';
      const escaped = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      const sigMatch = snap.match(new RegExp(escaped + '\\s*\\(([^)]*)\\)'));
      const sigText = sigMatch?.[1] ?? '';
      const nonRequestParams: string[] = [];
      for (const pn of funcNode.param_names) {
        const paramTypeRe = new RegExp('(\\w+(?:\\.\\w+)*)\\s+' + pn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
        const ptMatch = sigText.match(paramTypeRe);
        if (!ptMatch || !REQUEST_TYPES.test(ptMatch[1]!)) {
          nonRequestParams.push(pn);
        }
      }
      if (nonRequestParams.length === 0) continue;

      const bodyMatch = snap.match(/\{([\s\S]*)\}/);
      const body = bodyMatch ? bodyMatch[1]! : snap;
      const lines = body.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('//') && !l.startsWith('*'));
      const aliases = new Set(nonRequestParams);
      for (const ln of lines) {
        const assignMatch = ln.match(/^(?:(?:final\s+)?[\w.<>\[\]]+\s+)?(\w+)\s*=\s*(.*)/);
        if (assignMatch) {
          const lhs = assignMatch[1]!;
          let rhs = assignMatch[2]!;
          for (const a of aliases) {
            if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(rhs)) {
              aliases.add(lhs);
              break;
            }
          }
        }
        if (ln.startsWith('case ') || ln.startsWith('default:')) {
          const caseAssign = ln.match(/\b(\w+)\s*=\s*(\w+)\s*;/);
          if (caseAssign) {
            for (const a of aliases) {
              if (caseAssign[2] === a) { aliases.add(caseAssign[1]!); break; }
            }
          }
        }
        if (ln.startsWith('if ') || ln.startsWith('if(') || ln.startsWith('else ')) {
          const ifAssign = ln.match(/\b(\w+)\s*=\s*([^;]+);/);
          if (ifAssign) {
            for (const a of aliases) {
              if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(ifAssign[2]!)) {
                aliases.add(ifAssign[1]!); break;
              }
            }
          }
        }
      }

      const returnMatch = body.match(/return\s+(\w+)\s*;/);
      if (!returnMatch || !aliases.has(returnMatch[1]!)) continue;

      for (const lc of allLocalCalls) {
        const lcSnap = lc.analysis_snapshot || lc.code_snapshot || '';
        if (!lcSnap.match(new RegExp('\\b' + escaped + '\\s*\\('))) continue;

        const callArgMatch = lcSnap.match(new RegExp(escaped + '\\s*\\(([^)]*)\\)'));
        if (!callArgMatch) continue;
        const callArgs = callArgMatch[1]!.split(',').map(a => a.trim());

        let allPassthroughArgsClean = true;
        for (let pi = 0; pi < funcNode.param_names.length; pi++) {
          const pn = funcNode.param_names[pi]!;
          if (!nonRequestParams.includes(pn)) continue;
          if (!aliases.has(pn)) continue;
          const argName = callArgs[pi];
          if (!argName) continue;
          const argIsTainted = lc.data_in.some(d =>
            d.tainted && d.name && new RegExp('\\b' + argName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(d.name)
          );
          if (argIsTainted) {
            allPassthroughArgsClean = false;
            break;
          }
        }

        if (allPassthroughArgsClean) {
          this.functionReturnTaint.set(funcNodeId, false);
        }
      }
    }
  }

  private buildFunctionContainedNodes(): Map<string, NeuralMapNode[]> {
    const result = new Map<string, NeuralMapNode[]>();
    const nodeById = this.nodeById;

    for (const [, funcNodeId] of this.functionRegistry) {
      if (!nodeById.get(funcNodeId)) continue;
      const contained: NeuralMapNode[] = [];
      const visited = new Set<string>();
      const queue = [funcNodeId];
      while (queue.length > 0) {
        const currentId = queue.shift()!;
        if (visited.has(currentId)) continue;
        visited.add(currentId);
        const current = nodeById.get(currentId);
        if (!current) continue;
        contained.push(current);
        for (const edge of current.edges) {
          if (edge.edge_type === 'CONTAINS' && !visited.has(edge.target)) {
            queue.push(edge.target);
          }
        }
      }
      result.set(funcNodeId, contained);
    }
    return result;
  }

  private buildFunctionTaintSummaries(
    containedMap: Map<string, NeuralMapNode[]>,
  ): Map<string, { funcName: string; funcNodeId: string; sinks: NeuralMapNode[]; paramNames: string[] }> {
    const sinkTypes = new Set(['STORAGE', 'EXTERNAL']);
    const summaries = new Map<string, { funcName: string; funcNodeId: string; sinks: NeuralMapNode[]; paramNames: string[] }>();
    const nodeById = this.nodeById;

    for (const [funcName, funcNodeId] of this.functionRegistry) {
      const contained = containedMap.get(funcNodeId) || [];
      const sinks = contained.filter(n => sinkTypes.has(n.node_type));
      if (sinks.length === 0) continue;

      const funcNode = nodeById.get(funcNodeId);
      if (!funcNode) continue;

      let paramNames: string[] = [];
      if (funcNode.param_names && funcNode.param_names.length > 0) {
        paramNames = funcNode.param_names;
      } else {
        const jsPattern = /(?:function\s+\w+\s*|(?:async\s+)?)\(([^)]*)\)|(\w+)\s*=>|\w+\s*\(([^)]*)\)\s*\{/;
        const funcAnalysis = funcNode.analysis_snapshot || funcNode.code_snapshot;
        const paramMatch = (this.profile.functionParamPattern
          ? funcAnalysis.match(this.profile.functionParamPattern)
          : null
        ) || funcAnalysis.match(jsPattern);
        if (paramMatch) {
          const paramStr = paramMatch[1] || paramMatch[2] || paramMatch[3] || '';
          paramNames = paramStr.split(',').map(p => {
            let token = p.trim()
              .replace(/\s*=.*$/, '')
              .replace(/\s*:.*$/, '')
              .replace(/\.{3}/, '')
              .replace(/^\*{1,2}/, '');
            if (this.profile.id === 'java' && /\s/.test(token)) {
              const parts = token.trim().split(/\s+/);
              token = parts[parts.length - 1];
            }
            return token;
          }).filter(Boolean);
        }
      }

      const sinksReferencingParams = sinks.filter(sink =>
        paramNames.some(p => (sink.analysis_snapshot || sink.code_snapshot).includes(p))
      );

      if (sinksReferencingParams.length > 0) {
        summaries.set(funcName, { funcName, funcNodeId, sinks: sinksReferencingParams, paramNames });
      }
    }
    return summaries;
  }

  private connectCallSitesToSinks(
    summaries: Map<string, { funcName: string; sinks: NeuralMapNode[] }>,
  ): void {
    for (const node of this.neuralMap.nodes) {
      for (const [funcName, summary] of summaries) {
        if ((node.analysis_snapshot || node.code_snapshot).match(new RegExp('\\b' + funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(')) !== null) {
          if (node.data_in.some(d => d.tainted)) {
            for (const sink of summary.sinks) {
              this.addEdge(node.id, sink.id, 'DATA_FLOW', undefined, node);
            }
          }
          if (this.profile.ingressPattern.test(node.analysis_snapshot || node.code_snapshot)) {
            const ingressNodes = this.neuralMap.nodes.filter(n =>
              n.node_type === 'INGRESS' && n.attack_surface.includes('user_input')
            );
            for (const ingress of ingressNodes) {
              for (const sink of summary.sinks) {
                this.addEdge(ingress.id, sink.id, 'DATA_FLOW', undefined, ingress);
              }
            }
          }
        }
      }
    }
  }

  private markLocalCallsTainted(
    allLocalCalls: NeuralMapNode[],
    summaries: Map<string, { funcName: string; sinks: NeuralMapNode[] }>,
  ): void {
    for (const lc of allLocalCalls) {
      if (lc.data_out.some(d => d.tainted)) continue;
      for (const [funcName] of summaries) {
        if ((lc.analysis_snapshot || lc.code_snapshot).match(new RegExp('\\b' + funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(')) !== null) {
          lc.data_out.push({
            name: 'result', source: lc.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE',
          });
          break;
        }
      }
    }
  }

  private markLocalCallsReturnTainted(
    allLocalCalls: NeuralMapNode[],
    containedMap: Map<string, NeuralMapNode[]>,
  ): void {
    const nodeById = this.nodeById;

    const untaintedCallIds = new Set<string>();
    const taintedCallsAndPassthroughs = this.neuralMap.nodes.filter(n =>
      (n.node_subtype === 'local_call' || n.node_subtype === 'passthrough') &&
      n.data_out.some(d => d.tainted)
    );
    for (const lc of taintedCallsAndPassthroughs) {
      for (const [funcName, funcNodeId] of this.functionRegistry) {
        if (funcName.includes(':')) continue;
        const escaped = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if ((lc.analysis_snapshot || lc.code_snapshot).match(
          new RegExp('\\b' + escaped + '\\s*\\(')
        ) !== null) {
          if (this.functionReturnTaint.get(funcNodeId) === false) {
            const funcNode = nodeById.get(funcNodeId);
            const paramNames = funcNode?.param_names;
            let isPassthrough = false;
            if (funcNode && paramNames && paramNames.length > 0) {
              const snap = funcNode.analysis_snapshot || funcNode.code_snapshot || '';
              const REQUEST_TYPES = /\b(HttpServletRequest|ServletRequest|WebRequest|HttpRequest|HttpServletResponse|ServletResponse)\b/;
              const sigMatch = snap.match(new RegExp(escaped.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(([^)]*)\\)'));
              const sigText = sigMatch?.[1] ?? '';
              const nonRequestParams: string[] = [];
              for (const pn of paramNames) {
                const paramTypeRe = new RegExp('(\\w+(?:\\.\\w+)*)\\s+' + pn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
                const ptMatch = sigText.match(paramTypeRe);
                if (!ptMatch || !REQUEST_TYPES.test(ptMatch[1]!)) {
                  nonRequestParams.push(pn);
                }
              }
              if (nonRequestParams.length > 0) {
                const bodyMatch = snap.match(/\{([\s\S]*)\}/);
                const body = bodyMatch ? bodyMatch[1]! : snap;
                const lines = body.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('//') && !l.startsWith('*'));
                const aliases = new Set(nonRequestParams);
                for (let li = 0; li < lines.length; li++) {
                  const ln = lines[li]!;
                  const assignMatch = ln.match(/^(?:(?:final\s+)?[\w.<>\[\]]+\s+)?(\w+)\s*=\s*(.*)/);
                  if (assignMatch) {
                    const lhs = assignMatch[1]!;
                    let rhs = assignMatch[2]!;
                    if (!rhs.includes(';') && li + 1 < lines.length) {
                      for (let ci = li + 1; ci < lines.length; ci++) {
                        rhs += ' ' + lines[ci]!;
                        if (lines[ci]!.includes(';')) break;
                      }
                    }
                    for (const a of aliases) {
                      if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(rhs)) {
                        aliases.add(lhs);
                        break;
                      }
                    }
                  }
                  if (!assignMatch && (ln.startsWith('if ') || ln.startsWith('if(') || ln.startsWith('else '))) {
                    const ifAssignMatch = ln.match(/\b(\w+)\s*=\s*([^;]+);/);
                    if (ifAssignMatch) {
                      const lhs = ifAssignMatch[1]!;
                      const rhs = ifAssignMatch[2]!;
                      for (const a of aliases) {
                        if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(rhs)) {
                          aliases.add(lhs);
                          break;
                        }
                      }
                    }
                  }
                  const ternMatch = ln.match(/^(?:[\w.<>\[\]]+\s+)?(\w+)\s*=.*\?.*:(.*)/);
                  if (ternMatch) {
                    const lhs = ternMatch[1]!;
                    const rhs = ternMatch[2]!;
                    for (const a of aliases) {
                      if (new RegExp('\\b' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(rhs)) {
                        aliases.add(lhs);
                        break;
                      }
                    }
                  }
                  const putMatch = ln.match(/(\w+)\.put\s*\(\s*"([^"]*)"\s*,\s*(\w+)\s*\)/);
                  if (putMatch) {
                    for (const a of aliases) {
                      if (putMatch[3] === a) {
                        aliases.add(`__map_${putMatch[1]}_${putMatch[2]}`);
                        break;
                      }
                    }
                  }
                  const getMatch = ln.match(/(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
                  if (getMatch && aliases.has(`__map_${getMatch[2]}_${getMatch[3]}`)) {
                    aliases.add(getMatch[1]!);
                  }
                }
                const returnMatch = body.match(/return\s+(\w+)\s*;/);
                if (returnMatch && aliases.has(returnMatch[1]!)) {
                  const callSnap = lc.analysis_snapshot || lc.code_snapshot || '';
                  const callArgMatch = callSnap.match(new RegExp(escaped + '\\s*\\(([^)]*)\\)'));
                  if (callArgMatch) {
                    const callArgs = callArgMatch[1]!.split(',').map(a => a.trim());
                    let hasAnyTaintedPassthroughArg = false;
                    for (let pi = 0; pi < paramNames.length; pi++) {
                      const pn = paramNames[pi]!;
                      if (!nonRequestParams.includes(pn)) continue;
                      if (!aliases.has(pn)) continue;
                      const argName = callArgs[pi];
                      if (!argName) continue;
                      const argIsTainted = lc.data_in.some(d =>
                        d.tainted && d.name && new RegExp('\\b' + argName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(d.name)
                      );
                      if (argIsTainted) {
                        hasAnyTaintedPassthroughArg = true;
                        break;
                      }
                    }
                    isPassthrough = hasAnyTaintedPassthroughArg;
                  } else {
                    isPassthrough = true;
                  }
                }
              }
            }
            if (!isPassthrough) {
              lc.data_out = lc.data_out.filter(d => !d.tainted);
              untaintedCallIds.add(lc.id);
            }
          }
          break;
        }
      }
    }

    if (untaintedCallIds.size > 0) {
      for (const node of this.neuralMap.nodes) {
        node.data_in = node.data_in.map(d => {
          if (d.tainted && d.source && untaintedCallIds.has(d.source)) {
            return { ...d, tainted: false };
          }
          return d;
        });
        node.data_out = node.data_out.map(d => {
          if (d.tainted && d.source && untaintedCallIds.has(d.source)) {
            return { ...d, tainted: false };
          }
          return d;
        });
        if (untaintedCallIds.has(node.id)) {
          for (const e of node.edges) {
            if (e.edge_type === 'DATA_FLOW') {
              this.edgeSet.delete(`${node.id}:${e.target}:DATA_FLOW`);
            }
          }
          node.edges = node.edges.filter(e => e.edge_type !== 'DATA_FLOW');
        }
      }
      this.neuralMap.edges = this.neuralMap.edges.filter(e =>
        !(e.edge_type === 'DATA_FLOW' && e.source && untaintedCallIds.has(e.source))
      );
    }

    for (const lc of allLocalCalls) {
      if (lc.data_out.some(d => d.tainted)) continue;
      for (const [funcName, funcNodeId] of this.functionRegistry) {
        const escaped = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if ((lc.analysis_snapshot || lc.code_snapshot).match(
          new RegExp('\\b' + escaped + '\\s*\\(')
        ) !== null) {
          if (this.functionReturnTaint.get(funcNodeId) !== true) break;

          const funcNode = nodeById.get(funcNodeId);
          const contained = containedMap.get(funcNodeId) || [];
          const taintedNames = contained
            .filter(n => n.data_out.some(d => d.tainted) && n.node_type !== 'STRUCTURAL')
            .map(n => n.label.replace(/\s*=\s*$/, '').trim())
            .filter(name => name.length > 0 && name.length < 40);
          const snap = funcNode?.analysis_snapshot || funcNode?.code_snapshot || '';
          const hasReturnWithTaint = taintedNames.length === 0 ||
            taintedNames.some(name => {
              const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
              return new RegExp(`return\\s+[^;]*\\b${esc}\\b`).test(snap);
            });
          if (!hasReturnWithTaint) break;

          lc.data_out.push({
            name: 'return', source: lc.id, data_type: 'unknown',
            tainted: true, sensitivity: 'NONE' as const,
          });
          const ingressInFunc = contained.find(n => n.node_type === 'INGRESS');
          if (ingressInFunc) {
            this.addEdge(ingressInFunc.id, lc.id, 'DATA_FLOW', undefined, ingressInFunc);
          }
          break;
        }
      }
    }
  }

  private connectTaintedLocalCallsToSinks(
    summaries: Map<string, { funcName: string; sinks: NeuralMapNode[] }>,
  ): void {
    const taintedLocalCalls = this.neuralMap.nodes.filter(n =>
      n.node_subtype === 'local_call' && n.data_out.some(d => d.tainted)
    );
    const sinkNodes = this.neuralMap.nodes.filter(n =>
      n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL'
    );
    for (const lc of taintedLocalCalls) {
      for (const sink of sinkNodes) {
        if ((sink.analysis_snapshot || sink.code_snapshot).includes(lc.label.slice(0, 30)) && sink.id !== lc.id) {
          this.addEdge(lc.id, sink.id, 'DATA_FLOW', undefined, lc);
        }
      }
      for (const summary of summaries.values()) {
        if ((lc.analysis_snapshot || lc.code_snapshot).includes(summary.funcName + '(')) {
          for (const sink of summary.sinks) {
            this.addEdge(lc.id, sink.id, 'DATA_FLOW', undefined, lc);
          }
        }
      }
    }
  }

  private propagateEventEmitterTaint(): void {
    const emitPattern = /\.emit\s*\(\s*['"](\w+)['"]/;
    const onPattern = /\.on\s*\(\s*['"](\w+)['"]/;

    const emitNodes: Array<{ node: NeuralMapNode; eventName: string }> = [];
    const onNodes: Array<{ node: NeuralMapNode; eventName: string }> = [];

    for (const node of this.neuralMap.nodes) {
      const emitMatch = (node.analysis_snapshot || node.code_snapshot).match(emitPattern);
      if (emitMatch) emitNodes.push({ node, eventName: emitMatch[1] });
      const onMatch = (node.analysis_snapshot || node.code_snapshot).match(onPattern);
      if (onMatch) onNodes.push({ node, eventName: onMatch[1] });
    }

    for (const emit of emitNodes) {
      const hasTaint = emit.node.data_in.some(d => d.tainted) ||
        this.profile.ingressPattern.test(emit.node.analysis_snapshot || emit.node.code_snapshot);
      if (!hasTaint) continue;

      const matchingHandlers = onNodes.filter(on => on.eventName === emit.eventName);
      for (const handler of matchingHandlers) {
        const handlerLine = handler.node.line_start;
        const nearbySinks = this.neuralMap.nodes.filter(n =>
          (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
          n.line_start >= handlerLine && n.line_start <= handlerLine + 20
        );
        const ingressNodes = this.neuralMap.nodes.filter(n =>
          n.node_type === 'INGRESS' && n.attack_surface.includes('user_input')
        );
        for (const sink of nearbySinks) {
          for (const ingress of ingressNodes) {
            this.addEdge(ingress.id, sink.id, 'DATA_FLOW', undefined, ingress);
          }
        }
      }
    }
  }

  buildCallsEdges(): void {
    for (const pending of this.pendingCalls) {
      const calleeNodeId = this.functionRegistry.get(pending.calleeName);
      if (!calleeNodeId) continue;
      if (calleeNodeId === pending.callerContainerId) continue;
      this.addEdge(pending.callerContainerId, calleeNodeId, 'CALLS',
        { async: pending.isAsync });
    }
  }

  private findVarScope(): Scope | null {
    for (let i = this.scopeStack.length - 1; i >= 0; i--) {
      const scope = this.scopeStack[i];
      if (scope.type === 'function' || scope.type === 'module') {
        return scope;
      }
    }
    return null;
  }
}


function detectSensitivity(name: string): Sensitivity {
  const lower = name.toLowerCase();

  const secretPatterns = [
    'password', 'passwd', 'pwd', 'secret', 'token',
    'api_key', 'apikey', 'api-key', 'private_key', 'privatekey',
    'access_key', 'accesskey', 'secret_key', 'secretkey',
  ];
  if (secretPatterns.some(p => lower.includes(p))) {
    return 'SECRET';
  }

  const piiPatterns = [
    'email', 'phone', 'address', 'ssn', 'social_security',
    'dob', 'date_of_birth', 'birthdate', 'firstname', 'first_name',
    'lastname', 'last_name', 'fullname', 'full_name',
    'zipcode', 'zip_code', 'postal',
  ];
  if (piiPatterns.some(p => lower.includes(p))) {
    return 'PII';
  }

  const authPatterns = [
    'session', 'auth', 'jwt', 'cookie', 'bearer',
    'credential', 'oauth', 'refresh_token', 'id_token',
  ];
  if (authPatterns.some(p => lower.includes(p))) {
    return 'AUTH';
  }

  const financialPatterns = [
    'amount', 'price', 'balance', 'credit', 'payment',
    'card_number', 'cardnumber', 'cvv', 'expiry',
    'account_number', 'routing', 'iban', 'swift',
  ];
  if (financialPatterns.some(p => lower.includes(p))) {
    return 'FINANCIAL';
  }

  return 'NONE';
}

function initializeTaint(map: NeuralMap): void {
  for (const node of map.nodes) {
    if (node.node_type === 'INGRESS') {
      for (const flow of node.data_out) {
        flow.tainted = true;
      }
    }

    if (node.node_type === 'EXTERNAL') {
      for (const flow of node.data_out) {
        flow.tainted = true;
      }
    }

    if (node.node_type === 'TRANSFORM' && node.node_subtype === 'sanitize') {
      for (const flow of node.data_out) {
        flow.tainted = false;
      }
    }

    if (node.node_type === 'TRANSFORM' && node.node_subtype === 'encrypt') {
      for (const flow of node.data_out) {
        flow.tainted = false;
      }
    }

    for (const flow of node.data_out) {
      const sensitivity = detectSensitivity(flow.name);
      if (sensitivity !== 'NONE') {
        flow.sensitivity = sensitivity;
      }
    }
    for (const flow of node.data_in) {
      const sensitivity = detectSensitivity(flow.name);
      if (sensitivity !== 'NONE') {
        flow.sensitivity = sensitivity;
      }
    }
  }
}


/**
 * Build a NeuralMap from a parsed tree-sitter tree.
 *
 * This skeleton version:
 * - Creates the root module scope
 * - Walks the tree depth-first
 * - Pushes/pops scopes at function, class, and block boundaries
 * - Declares variables at variable_declaration/lexical_declaration nodes
 * - Declares function parameters when entering function scopes
 * - Returns a NeuralMap with 0 classified nodes (classification comes in Goal 3)
 *
 * The MapperContext is returned alongside the NeuralMap for testing purposes.
 */
export function buildNeuralMap(
  tree: Parser.Tree,
  sourceCode: string,
  fileName: string,
  profile: LanguageProfile = javascriptProfile,
): { map: NeuralMap; ctx: MapperContext } {
  const t0 = performance.now();
  const ctx = new MapperContext(fileName, sourceCode, profile);
  const root = tree.rootNode;

  ctx.pushScope('module', root);

  walkWithScopes(root, ctx, profile);

  const tWalkDone = performance.now();


  ctx.buildNodeIndex();

  initializeTaint(ctx.neuralMap);

  ctx.buildCallsEdges();

  ctx.buildDataFlowEdges();

  ctx.propagateInterproceduralTaint();

  ctx.buildReadsEdges();
  ctx.buildWritesEdges();
  ctx.buildDependsEdges();

  resolveSentences(ctx);

  if (ctx.sentences.length > 0) {
    ctx.neuralMap.story = [...ctx.sentences].sort((a, b) => a.lineNumber - b.lineNumber);
  }

  const tDone = performance.now();
  ctx.diagnostics.timing.walkMs = Math.round(tWalkDone - t0);
  ctx.diagnostics.timing.postProcessMs = Math.round(tDone - tWalkDone);
  ctx.diagnostics.timing.totalMs = Math.round(tDone - t0);

  return { map: ctx.neuralMap, ctx };
}

function tryFoldCaseLabel(expr: SyntaxNode): string | null {
  if (expr.type === 'character_literal') return expr.text.replace(/^'|'$/g, '');
  if (expr.type === 'string_literal') return expr.text.replace(/^"|"$/g, '');
  if (expr.type === 'decimal_integer_literal') return expr.text;
  return null;
}

function groupEndsWithBreak(group: SyntaxNode): boolean {
  for (let i = group.namedChildCount - 1; i >= 0; i--) {
    const child = group.namedChild(i);
    if (!child || child.type === 'switch_label') continue;
    return child.type === 'break_statement' || child.type === 'return_statement'
        || child.type === 'throw_statement' || child.type === 'continue_statement';
  }
  return false;
}

function walkWithScopes(node: SyntaxNode, ctx: MapperContext, profile: LanguageProfile): void {
  const scopeType = profile.getScopeType(node);
  let pushedScope = false;

  if (scopeType && node !== ctx.scopeStack[0]?.node) {
    ctx.pushScope(scopeType, node);
    pushedScope = true;

    if (scopeType === 'function') {
      profile.processFunctionParams(node, ctx);
    }

    if (scopeType === 'class') {
      const className = node.childForFieldName('name');
      if (className && ctx.scopeStack.length >= 2) {
        const parentScope = ctx.scopeStack[ctx.scopeStack.length - 2];
        parentScope.variables.set(className.text, {
          name: className.text,
          declaringNodeId: null,
          producingNodeId: null,
          kind: 'const',
          tainted: false,
        });
      }
    }
  }

  if (profile.preVisitIteration) {
    profile.preVisitIteration(node, ctx);
  }

  if (profile.isValueFirstDeclaration(node.type)) {
    ctx.lastCreatedNodeId = null;
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) walkWithScopes(child, ctx, profile);
    }
    profile.processVariableDeclaration(node, ctx);
    if (pushedScope) ctx.popScope();
    return;
  }

  const isCallNode = CALL_NODE_TYPES.has(node.type);
  const prevNodeId = isCallNode ? ctx.lastCreatedNodeId : null;
  if (isCallNode) ctx.diagnostics.totalCalls++;

  const nodeCountBefore = ctx.neuralMap.nodes.length;
  profile.classifyNode(node, ctx);

  if (isCallNode && ctx.lastCreatedNodeId === prevNodeId) {
    ctx.diagnostics.unmappedCalls++;
  }

  // ── Generic sentence emission ─────────────────────────────────
  // For nodes created by classifyNode that DON'T already have profile-emitted
  // sentences, emit a default sentence based on nodeType/subtype.
  // This gives every language V2 sentences without per-profile changes.
  // Java's 14 specialized emission sites still take priority (they attach
  // sentences to nodes before this runs).
  if (ctx.addSentence) {
    const newNodes = ctx.neuralMap.nodes.slice(nodeCountBefore);
    for (const n of newNodes) {
      if (n.sentences && n.sentences.length > 0) continue;
      const templateKey = getTemplateKey(n.node_type, n.node_subtype);
      if (templateKey === 'gate-conditional' || templateKey === 'iterates-over') continue;
      // Don't emit sink templates generically — they trigger V2 authority.
      // V2 verifiers need profile-quality sentences with proper variables slots.
      // Generic sentences are for informational/taint-tracking purposes only.
      // Sink detection stays with V1 until the profile emits proper sentences.
      if (templateKey === 'executes-query' || templateKey === 'writes-response' || templateKey === 'accesses-path') continue;
      const isTainted = n.data_out.some((d: any) => d.tainted) || n.node_type === 'INGRESS';
      const taintClass: SemanticSentence['taintClass'] =
        n.node_type === 'INGRESS' ? 'TAINTED' :
        n.node_type === 'STORAGE' && (n.node_subtype === 'sql_query' || n.node_subtype === 'db_read' || n.node_subtype === 'db_write') ? 'SINK' :
        isTainted ? 'TAINTED' : 'NEUTRAL';
      const snap = n.code_snapshot || n.label || '';
      const methodMatch = snap.match(/\.(\w+)\s*\(/);
      const method = methodMatch?.[1] ?? n.node_subtype;
      const objMatch = snap.match(/^(\w+(?:\.\w+)*)\.\w+\s*\(/);
      const obj = objMatch?.[1] ?? '';
      const argsMatch = snap.match(/\(([^)]*)\)/);
      const args = argsMatch?.[1]?.slice(0, 60) ?? '';
      let slots: Record<string, string>;
      if (templateKey === 'retrieves-from-source') {
        slots = { subject: n.label, data_type: 'user input', source: snap.slice(0, 60), context: `line ${n.line_start}` };
      } else if (templateKey === 'executes-query') {
        const varNames = args.replace(/"[^"]*"|'[^']*'/g, '').match(/\b[a-z_]\w*\b/gi) || [];
        slots = { subject: obj || method, query_type: 'SQL', variables: varNames.join(', '), context: `line ${n.line_start}` };
      } else if (templateKey === 'writes-response') {
        const varNames = args.replace(/"[^"]*"|'[^']*'/g, '').match(/\b[a-z_]\w*\b/gi) || [];
        slots = { subject: obj || n.label, method, object: obj, args, variables: varNames.filter(v => !v.match(/^[A-Z][A-Z_0-9]*$/)).join(', '), context: `line ${n.line_start}` };
      } else if (templateKey === 'accesses-path') {
        const varNames = args.replace(/"[^"]*"|'[^']*'/g, '').match(/\b[a-z_]\w*\b/gi) || [];
        slots = { subject: n.label, variables: varNames.join(', '), context: `line ${n.line_start}` };
      } else {
        slots = { subject: obj || n.label, method, object: obj, args, context: `line ${n.line_start}` };
      }
      const sentence = generateSentence(templateKey, slots, n.line_start, n.id, taintClass);
      sentence.taintBasis = 'PHONEME_RESOLUTION';
      if (!n.sentences) n.sentences = [];
      n.sentences.push(sentence);
      ctx.addSentence(sentence);
    }
  }

  const isIfNode = node.type === 'if_statement' || node.type === 'if_expression';
  let skipConsequence = false;
  let skipAlternative = false;
  if (isIfNode && profile.tryEvalCondition) {
    const condNode = node.childForFieldName('condition');
    if (condNode) {
      const condResult = profile.tryEvalCondition(condNode, ctx);
      if (condResult === true) skipAlternative = true;
      if (condResult === false) skipConsequence = true;
      if (condResult === true || condResult === false) {
        const _dbContainerId = ctx.getCurrentContainerId();
        if (_dbContainerId) {
          const _dbContainer = ctx.nodeById.get(_dbContainerId);
          if (_dbContainer && !_dbContainer.metadata.dead_branch_eliminated) {
            _dbContainer.metadata.dead_branch_eliminated = true;
          }
        }
      }
    }
  }

  const isStatementContainer = profile.isStatementContainer(node.type);

  const isSwitchBlock = node.type === 'switch_block';
  const deadSwitchChildIds = new Set<number>();
  if (isSwitchBlock && profile.tryEvalSwitchTarget && node.parent?.type === 'switch_expression') {
    const condNode = node.parent.childForFieldName('condition');
    if (condNode) {
      const targetValue = profile.tryEvalSwitchTarget(condNode, ctx);
      if (targetValue !== null) {
        const allGroups: SyntaxNode[] = [];
        for (let i = 0; i < node.namedChildCount; i++) {
          const g = node.namedChild(i);
          if (g && (g.type === 'switch_block_statement_group' || g.type === 'switch_rule')) {
            allGroups.push(g);
          }
        }

        let matchedIdx = -1;
        let defaultIdx = -1;
        for (let i = 0; i < allGroups.length; i++) {
          const group = allGroups[i];
          let isDefault = false;
          let matches = false;
          for (let j = 0; j < group.namedChildCount; j++) {
            const child = group.namedChild(j);
            if (child?.type !== 'switch_label') continue;
            const labelExpr = child.namedChild(0);
            if (!labelExpr) { isDefault = true; }
            else {
              const labelValue = tryFoldCaseLabel(labelExpr);
              if (labelValue === targetValue) matches = true;
            }
          }
          if (matches && matchedIdx === -1) matchedIdx = i;
          if (isDefault) defaultIdx = i;
        }

        const liveIdx = matchedIdx !== -1 ? matchedIdx : defaultIdx;
        if (liveIdx !== -1) {
          const liveGroupIds = new Set<number>();
          liveGroupIds.add(allGroups[liveIdx].id);
          if (allGroups[liveIdx].type !== 'switch_rule' && !groupEndsWithBreak(allGroups[liveIdx])) {
            for (let k = liveIdx + 1; k < allGroups.length; k++) {
              liveGroupIds.add(allGroups[k].id);
              if (allGroups[k].type === 'switch_rule' || groupEndsWithBreak(allGroups[k])) break;
            }
          }
          for (const g of allGroups) {
            if (!liveGroupIds.has(g.id)) deadSwitchChildIds.add(g.id);
          }
          const _dbContainerId = ctx.getCurrentContainerId();
          if (_dbContainerId) {
            const _dbContainer = ctx.nodeById.get(_dbContainerId);
            if (_dbContainer && !_dbContainer.metadata.dead_branch_eliminated) {
              _dbContainer.metadata.dead_branch_eliminated = true;
            }
          }
        }
      }
    }
  }

  if (node.type === 'class_body') {
    const savedLastNodeId = ctx.lastCreatedNodeId;
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type === 'class_declaration') {
        walkWithScopes(child, ctx, profile);
      }
    }
    ctx.lastCreatedNodeId = savedLastNodeId;

    for (let i = 0; i < node.childCount; i++) {
      if (isStatementContainer) ctx.lastCreatedNodeId = null;
      const child = node.child(i);
      if (!child) continue;
      if (child.type === 'class_declaration') continue;
      walkWithScopes(child, ctx, profile);
    }

    if (profile.postVisitIteration) {
      profile.postVisitIteration(node, ctx);
    }
    if (profile.postVisitFunction) {
      profile.postVisitFunction(node, ctx);
    }

    if (pushedScope) ctx.popScope();
    return;
  }

  for (let i = 0; i < node.childCount; i++) {
    if (isStatementContainer) {
      ctx.lastCreatedNodeId = null;
    }
    const child = node.child(i);
    if (child) {
      if (isIfNode) {
        const fieldName = node.fieldNameForChild(i);
        if (skipConsequence && fieldName === 'consequence') continue;
        if (skipAlternative && fieldName === 'alternative') continue;
      }
      if (deadSwitchChildIds.size > 0 && deadSwitchChildIds.has(child.id)) continue;
      walkWithScopes(child, ctx, profile);
    }
  }

  if (profile.postVisitIteration) {
    profile.postVisitIteration(node, ctx);
  }
  if (profile.postVisitFunction) {
    profile.postVisitFunction(node, ctx);
  }

  if (pushedScope) {
    ctx.popScope();
  }
}
