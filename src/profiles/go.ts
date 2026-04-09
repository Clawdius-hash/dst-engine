/**
 * GoProfile — the third LanguageProfile implementation.
 *
 * Every piece of Go-specific logic lives here: AST node type names (from
 * tree-sitter-go grammar), field access patterns, scope rules, callee
 * resolution via the Go phoneme dictionary, taint extraction, and node
 * classification.
 *
 * Key differences from JavaScript:
 *   - `call_expression` same as JS, but `function` field is named `function`
 *   - `selector_expression` not `member_expression` (fields: `operand` + `field`)
 *   - `function_declaration` + `method_declaration` (methods have `receiver`)
 *   - `short_var_declaration` (:=) and `var_declaration` (var x = ...)
 *   - `source_file` not `program`, `block` creates block scope
 *   - NO classes — Go uses `type_declaration` for structs/interfaces
 *   - `defer_statement`, `go_statement` (goroutines), `select_statement` (channels)
 *   - Error handling via multiple return values, not exceptions
 *   - `for_statement` is the only loop (no while, do)
 *   - `import_declaration` not `import_statement`
 *   - `composite_literal` for struct/slice/map literals
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type {
  LanguageProfile,
  MapperContextLike,
  TaintSourceResult,
  ResolvedCalleeResult,
  ResolvedPropertyResult,
  StructuralAnalysisResult,
} from '../languageProfile.js';
import type { ScopeType, VariableInfo } from '../mapper.js';
import type { CalleePattern } from '../calleePatterns.js';
import { createNode } from '../types.js';
import { lookupCallee as _lookupCallee } from '../languages/go.js';

// ---------------------------------------------------------------------------
// AST Node Type Sets
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'function_declaration',
  'method_declaration',
  'func_literal',        // anonymous function: func() { ... }
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'for_statement',
  'if_statement',
  'switch_statement',
  'type_switch_statement',
  'select_statement',
  'block',               // bare { } blocks
  'communication_case',
  'expression_case',
  'default_case',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  // Go has no classes — type declarations don't create scopes.
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'short_var_declaration',    // x := expr
  'var_declaration',          // var x = expr
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'function_declaration',
  'method_declaration',
]);

const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // net/http (r is conventional name for *http.Request)
  'r.Body', 'r.Form', 'r.PostForm', 'r.MultipartForm',
  'r.Header', 'r.Host', 'r.RemoteAddr', 'r.URL', 'r.URL.Path',
  'r.URL.RawQuery', 'r.RequestURI', 'r.Trailer', 'r.TransferEncoding',
  'req.Body', 'req.Form', 'req.Header', 'req.URL',
  // Gin (c *gin.Context)
  'c.Request', 'c.Params',
  // os
  'os.Args', 'os.Stdin',
]);

// Request parameter names: when a function parameter has one of these types,
// it should be considered a taint source.
const GO_HTTP_REQUEST_TYPES: ReadonlySet<string> = new Set([
  'http.Request',
  '*http.Request',
  'Request',
]);

// Conventional request parameter names in Go handlers
const GO_REQUEST_PARAM_NAMES: ReadonlySet<string> = new Set([
  'r', 'req', 'request',
]);

// Response writer parameter names
const GO_RESPONSE_PARAM_NAMES: ReadonlySet<string> = new Set([
  'w', 'rw', 'resp', 'writer',
]);

// Gin/Echo/Fiber context parameter names
const GO_FRAMEWORK_CONTEXT_NAMES: ReadonlySet<string> = new Set([
  'c', 'ctx',
]);

// ---------------------------------------------------------------------------
// Helper: extract callee chain from a `selector_expression` node tree
// ---------------------------------------------------------------------------

function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier') {
    return [node.text];
  }
  if (node.type === 'selector_expression') {
    const operand = node.childForFieldName('operand');
    const field = node.childForFieldName('field');
    if (operand && field) {
      const chain = extractCalleeChain(operand);
      chain.push(field.text);
      return chain;
    }
  }
  return [];
}

// ---------------------------------------------------------------------------
// Helper: find INGRESS node inside a function (for cross-function taint)
// ---------------------------------------------------------------------------

function findIngressInFunction(funcNodeId: string, ctx: MapperContextLike): string | null {
  const contained = new Set<string>();
  const queue = [funcNodeId];

  while (queue.length > 0) {
    const id = queue.shift()!;
    const node = ctx.neuralMap.nodes.find((n: any) => n.id === id);
    if (!node) continue;

    for (const edge of node.edges) {
      if (edge.edge_type === 'CONTAINS' && !contained.has(edge.target)) {
        contained.add(edge.target);
        queue.push(edge.target);
      }
    }
  }

  const ingress = ctx.neuralMap.nodes.find(
    (n: any) => contained.has(n.id) && n.node_type === 'INGRESS'
  );
  return ingress?.id ?? null;
}

// ---------------------------------------------------------------------------
// resolveCallee — resolve a Go `call_expression` to a NeuralMap node type
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  if (node.type !== 'call_expression') return null;

  const callee = node.childForFieldName('function');
  if (!callee) return null;

  // Direct call: make(), len(), panic(), etc.
  if (callee.type === 'identifier') {
    const chain = [callee.text];
    const pattern = _lookupCallee(chain);
    if (pattern) {
      return {
        nodeType: pattern.nodeType,
        subtype: pattern.subtype,
        tainted: pattern.tainted,
        chain,
      };
    }
    return null;
  }

  // Selector expression: pkg.Func() or obj.Method()
  if (callee.type === 'selector_expression') {
    const chain = extractCalleeChain(callee);
    if (chain.length > 0) {
      const pattern = _lookupCallee(chain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain,
        };
      }
    }
    return null;
  }

  return null;
}

// ---------------------------------------------------------------------------
// resolvePropertyAccess — resolve a Go `selector_expression` (non-call)
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  if (node.type !== 'selector_expression') return null;

  const chain = extractCalleeChain(node);
  if (chain.length < 2) return null;

  const fullPath = chain.join('.');

  // Check tainted paths (r.Body, r.URL, c.Request, etc.)
  if (TAINTED_PATHS.has(fullPath)) {
    return {
      nodeType: 'INGRESS',
      subtype: 'http_request',
      tainted: true,
    };
  }

  // Check phoneme dictionary for property access
  const pattern = _lookupCallee(chain);
  if (pattern) {
    return {
      nodeType: pattern.nodeType,
      subtype: pattern.subtype,
      tainted: pattern.tainted,
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// extractPatternNames — Go has no destructuring, but var blocks exist
// ---------------------------------------------------------------------------

function extractPatternNames(pattern: SyntaxNode): string[] {
  const names: string[] = [];

  // Go doesn't have destructuring patterns like JS/Python.
  // This handles identifier lists in var declarations and short var decls.
  if (pattern.type === 'identifier') {
    // Skip the blank identifier
    if (pattern.text !== '_') {
      names.push(pattern.text);
    }
  }

  // expression_list on the left side of :=
  if (pattern.type === 'expression_list') {
    for (let i = 0; i < pattern.namedChildCount; i++) {
      const child = pattern.namedChild(i);
      if (child?.type === 'identifier' && child.text !== '_') {
        names.push(child.text);
      }
    }
  }

  return names;
}

// ---------------------------------------------------------------------------
// extractTaintSources
// ---------------------------------------------------------------------------

function extractTaintSources(expr: SyntaxNode, ctx: MapperContextLike): TaintSourceResult[] {
  if (!expr) return [];

  switch (expr.type) {
    // -- Leaf: identifier --
    case 'identifier': {
      const varInfo = ctx.resolveVariable(expr.text);
      if (varInfo?.tainted && varInfo.producingNodeId) {
        return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
      }
      return [];
    }

    // -- Leaf: selector_expression (r.Body, r.URL.Query, etc.) --
    case 'selector_expression': {
      const resolution = resolvePropertyAccess(expr);
      if (resolution?.tainted) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'go',
          file: ctx.neuralMap.source_file,
          line_start: expr.startPosition.row + 1,
          line_end: expr.endPosition.row + 1,
          code_snapshot: expr.text.slice(0, 200), analysis_snapshot: expr.text.slice(0, 2000),
          data_out: [{
            name: 'result',
            source: 'SELF',
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          }],
          attack_surface: ['user_input'],
        });
        ingressNode.data_out[0].source = ingressNode.id;

        ctx.neuralMap.nodes.push(ingressNode);
        ctx.emitContainsIfNeeded(ingressNode.id);

        return [{ nodeId: ingressNode.id, name: expr.text }];
      }
      // Check if the operand is a tainted variable
      const operand = expr.childForFieldName('operand');
      if (operand?.type === 'identifier') {
        const varInfo = ctx.resolveVariable(operand.text);
        if (varInfo?.tainted && varInfo.producingNodeId) {
          return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
        }
      }
      // Recurse into deeper selector chains
      if (operand?.type === 'selector_expression') {
        return extractTaintSources(operand, ctx);
      }
      return [];
    }

    // -- Binary expression: string concatenation, arithmetic --
    case 'binary_expression': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const sources: TaintSourceResult[] = [];
      if (left) sources.push(...extractTaintSources(left, ctx));
      if (right) sources.push(...extractTaintSources(right, ctx));
      return sources;
    }

    // -- Call expression: check if sanitizer, then check args --
    case 'call_expression': {
      const callResolution = resolveCallee(expr);
      // Sanitizer or encoder call stops taint
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          (callResolution.subtype === 'sanitize' || callResolution.subtype === 'encode')) {
        return [];
      }
      // For any other call, check arguments AND receiver for taint
      const sources: TaintSourceResult[] = [];
      const args = expr.childForFieldName('arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (arg) sources.push(...extractTaintSources(arg, ctx));
        }
      }
      // Check receiver
      const calleeExpr = expr.childForFieldName('function');
      if (calleeExpr?.type === 'selector_expression') {
        const receiver = calleeExpr.childForFieldName('operand');
        if (receiver) sources.push(...extractTaintSources(receiver, ctx));
      }
      // Check: existing node with tainted data_out
      if (sources.length === 0) {
        const callLine = expr.startPosition.row + 1;
        const callSnap = expr.text.slice(0, 30);
        const existing = ctx.neuralMap.nodes.find((n: any) =>
          n.line_start === callLine && n.code_snapshot.startsWith(callSnap)
        );
        if (existing?.data_out.some((d: any) => d.tainted)) {
          sources.push({ nodeId: existing.id, name: existing.label });
        }
      }
      return sources;
    }

    // -- Parenthesized expression --
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Composite literal: struct{...}, []T{...}, map[K]V{...} --
    case 'composite_literal': {
      const sources: TaintSourceResult[] = [];
      const body = expr.childForFieldName('body');
      if (body) {
        for (let i = 0; i < body.namedChildCount; i++) {
          const elem = body.namedChild(i);
          if (!elem) continue;
          // keyed_element: field: value
          if (elem.type === 'keyed_element') {
            const val = elem.namedChildCount >= 2 ? elem.namedChild(1) : null;
            if (val) sources.push(...extractTaintSources(val, ctx));
          } else {
            sources.push(...extractTaintSources(elem, ctx));
          }
        }
      }
      return sources;
    }

    // -- Index expression: arr[i] --
    case 'index_expression': {
      const operand = expr.childForFieldName('operand');
      if (operand) return extractTaintSources(operand, ctx);
      return [];
    }

    // -- Slice expression: arr[a:b] --
    case 'slice_expression': {
      const operand = expr.childForFieldName('operand');
      if (operand) return extractTaintSources(operand, ctx);
      return [];
    }

    // -- Unary expression: &x, *x, !x --
    case 'unary_expression': {
      const operand = expr.childForFieldName('operand');
      return operand ? extractTaintSources(operand, ctx) : [];
    }

    // -- Type assertion: x.(Type) --
    case 'type_assertion_expression': {
      const operand = expr.childForFieldName('operand');
      return operand ? extractTaintSources(operand, ctx) : [];
    }

    // -- Type conversion: string(x), int(x) --
    case 'type_conversion_expression': {
      const operand = expr.childForFieldName('operand');
      return operand ? extractTaintSources(operand, ctx) : [];
    }

    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type === 'short_var_declaration') {
    // x, y := expr1, expr2
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');

    if (!left) return;

    const names = extractPatternNames(left);

    // Check taint from producing node
    let producingNodeId = ctx.lastCreatedNodeId;
    let tainted = false;

    if (producingNodeId) {
      const producer = ctx.neuralMap.nodes.find((n: any) => n.id === producingNodeId);
      if (producer && (
        producer.node_type === 'INGRESS' ||
        producer.data_out.some((d: any) => d.tainted)
      )) {
        tainted = true;
      }
    }

    // Multi-hop taint: if right side is a plain identifier, inherit taint
    if (!producingNodeId && right) {
      // For expression_list, check all expressions
      if (right.type === 'expression_list') {
        for (let i = 0; i < right.namedChildCount; i++) {
          const rExpr = right.namedChild(i);
          if (rExpr?.type === 'identifier') {
            const sourceVar = ctx.resolveVariable(rExpr.text);
            if (sourceVar) {
              tainted = tainted || sourceVar.tainted;
              if (sourceVar.producingNodeId) producingNodeId = sourceVar.producingNodeId;
            }
          }
        }
      } else if (right.type === 'identifier') {
        const sourceVar = ctx.resolveVariable(right.text);
        if (sourceVar) {
          tainted = sourceVar.tainted;
          producingNodeId = sourceVar.producingNodeId;
        }
      }
    }

    // Direct taint extraction from the value expression
    if (!tainted && right) {
      const rightExpr = right.type === 'expression_list' ? right : right;
      const directTaint = extractTaintSources(rightExpr, ctx);
      if (directTaint.length > 0) {
        tainted = true;
        producingNodeId = directTaint[0].nodeId;
      }
    }

    // Cross-function taint: x := getInput(r)
    if (!producingNodeId && right) {
      const checkCallTaint = (expr: SyntaxNode) => {
        if (expr.type === 'call_expression') {
          const callee = expr.childForFieldName('function');
          if (callee?.type === 'identifier') {
            const funcNodeId = ctx.functionRegistry.get(callee.text);
            if (funcNodeId) {
              const ingressInFunc = findIngressInFunction(funcNodeId, ctx);
              if (ingressInFunc) {
                tainted = true;
                producingNodeId = ingressInFunc;
              }
            }
          }
        }
      };
      if (right.type === 'expression_list') {
        for (let i = 0; i < right.namedChildCount; i++) {
          const rExpr = right.namedChild(i);
          if (rExpr) checkCallTaint(rExpr);
        }
      } else {
        checkCallTaint(right);
      }
    }

    // Alias chain detection: db := sql.Open(...) -> store ['sql', 'Open'] on the variable
    let aliasChain: string[] | undefined;
    if (right) {
      const checkAlias = (expr: SyntaxNode): string[] | undefined => {
        if (expr.type === 'selector_expression') {
          const chain: string[] = [];
          let cur: SyntaxNode | null = expr;
          while (cur?.type === 'selector_expression') {
            const field = cur.childForFieldName('field');
            if (field) chain.unshift(field.text);
            cur = cur.childForFieldName('operand');
          }
          if (cur?.type === 'identifier') {
            const curVar = ctx.resolveVariable(cur.text);
            if (curVar?.aliasChain) {
              chain.unshift(...curVar.aliasChain);
            } else {
              chain.unshift(cur.text);
            }
            return chain;
          }
        }
        return undefined;
      };

      if (right.type === 'expression_list') {
        const first = right.namedChild(0);
        if (first) aliasChain = checkAlias(first);
      } else {
        aliasChain = checkAlias(right);
      }
    }

    for (const name of names) {
      ctx.declareVariable(name, 'const', null, tainted, producingNodeId);
      if (aliasChain) {
        const v = ctx.resolveVariable(name);
        if (v) v.aliasChain = aliasChain;
      }
    }

    return;
  }

  if (node.type === 'var_declaration') {
    // var x = expr  OR  var (x = expr; y = expr)
    // Walk var_spec children
    for (let i = 0; i < node.namedChildCount; i++) {
      const spec = node.namedChild(i);
      if (!spec || spec.type !== 'var_spec') continue;

      const nameNode = spec.childForFieldName('name');
      const valueNode = spec.childForFieldName('value');

      if (!nameNode) continue;

      const names: string[] = [];
      if (nameNode.type === 'identifier' && nameNode.text !== '_') {
        names.push(nameNode.text);
      }
      // Multiple names: var a, b = expr1, expr2
      // tree-sitter-go puts each name as a separate named child before the type/value
      for (let j = 0; j < spec.namedChildCount; j++) {
        const child = spec.namedChild(j);
        if (child?.type === 'identifier' && child.text !== '_' && !names.includes(child.text)) {
          names.push(child.text);
        }
      }

      let producingNodeId = ctx.lastCreatedNodeId;
      let tainted = false;

      if (producingNodeId) {
        const producer = ctx.neuralMap.nodes.find((n: any) => n.id === producingNodeId);
        if (producer && (
          producer.node_type === 'INGRESS' ||
          producer.data_out.some((d: any) => d.tainted)
        )) {
          tainted = true;
        }
      }

      if (!tainted && valueNode) {
        const directTaint = extractTaintSources(valueNode, ctx);
        if (directTaint.length > 0) {
          tainted = true;
          producingNodeId = directTaint[0].nodeId;
        }
      }

      for (const name of names) {
        ctx.declareVariable(name, 'var', null, tainted, producingNodeId);
      }
    }
    return;
  }
}

// ---------------------------------------------------------------------------
// processFunctionParams
// ---------------------------------------------------------------------------

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) return;

  // In Go, parameters are in `parameter_list` containing `parameter_declaration` nodes.
  // Each parameter_declaration has name(s) and a type.
  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    if (param.type === 'parameter_declaration') {
      const typeNode = param.childForFieldName('type');
      const typeText = typeNode?.text ?? '';

      // Collect all identifier children (parameter names)
      const paramNames: string[] = [];
      for (let j = 0; j < param.namedChildCount; j++) {
        const child = param.namedChild(j);
        if (child?.type === 'identifier') {
          paramNames.push(child.text);
        }
      }

      for (const name of paramNames) {
        // Check if this is an HTTP request parameter
        const isRequestParam =
          GO_HTTP_REQUEST_TYPES.has(typeText) ||
          GO_REQUEST_PARAM_NAMES.has(name) ||
          GO_FRAMEWORK_CONTEXT_NAMES.has(name);

        if (isRequestParam) {
          // Create an INGRESS node for the request parameter
          const ingressNode = createNode({
            label: name,
            node_type: 'INGRESS',
            node_subtype: 'http_request',
            language: 'go',
            file: ctx.neuralMap.source_file,
            line_start: param.startPosition.row + 1,
            line_end: param.endPosition.row + 1,
            code_snapshot: param.text.slice(0, 200), analysis_snapshot: param.text.slice(0, 2000),
          });
          ingressNode.data_out.push({
            name: 'result',
            source: ingressNode.id,
            data_type: typeText || 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
          ingressNode.attack_surface.push('user_input');
          ctx.neuralMap.nodes.push(ingressNode);
          ctx.emitContainsIfNeeded(ingressNode.id);

          ctx.declareVariable(name, 'param', null, true, ingressNode.id);
        } else if (GO_RESPONSE_PARAM_NAMES.has(name)) {
          // Response writer — not tainted but declare it
          ctx.declareVariable(name, 'param', null, false, null);
        } else {
          // Check pendingCallbackTaint
          const producingId = ctx.pendingCallbackTaint.get(name) ?? null;
          const isTainted = producingId !== null;
          if (isTainted) ctx.pendingCallbackTaint.delete(name);
          ctx.declareVariable(name, 'param', null, isTainted, producingId);
        }
      }
    }

    // Variadic parameter: names ...type
    if (param.type === 'variadic_parameter_declaration') {
      const nameChild = param.childForFieldName('name');
      if (nameChild?.type === 'identifier') {
        const producingId = ctx.pendingCallbackTaint.get(nameChild.text) ?? null;
        const isTainted = producingId !== null;
        if (isTainted) ctx.pendingCallbackTaint.delete(nameChild.text);
        ctx.declareVariable(nameChild.text, 'param', null, isTainted, producingId);
      }
    }
  }

  // Handle method receiver: func (s *Server) Handler(w, r) { ... }
  const receiver = funcNode.childForFieldName('receiver');
  if (receiver) {
    for (let i = 0; i < receiver.namedChildCount; i++) {
      const param = receiver.namedChild(i);
      if (param?.type === 'parameter_declaration') {
        for (let j = 0; j < param.namedChildCount; j++) {
          const child = param.namedChild(j);
          if (child?.type === 'identifier') {
            ctx.declareVariable(child.text, 'param', null, false, null);
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of the switch statement
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  // Process function declarations (hoist the function name)
  if (node.type === 'function_declaration') {
    const funcName = node.childForFieldName('name');
    if (funcName && ctx.scopeStack.length >= 2) {
      const outerScope = ctx.scopeStack[ctx.scopeStack.length - 2];
      outerScope.variables.set(funcName.text, {
        name: funcName.text,
        declaringNodeId: null,
        producingNodeId: null,
        kind: 'var',
        tainted: false,
      });
    }
  }

  switch (node.type) {
    // -- FUNCTION DECLARATIONS --
    case 'function_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const fnNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'go',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(fnNode);
      ctx.lastCreatedNodeId = fnNode.id;
      ctx.emitContainsIfNeeded(fnNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = fnNode.id;
      if (name !== 'anonymous') ctx.functionRegistry.set(name, fnNode.id);
      break;
    }

    case 'method_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      // Extract receiver type for fully qualified name
      const receiver = node.childForFieldName('receiver');
      let receiverType = '';
      if (receiver) {
        const typeNode = receiver.descendantsOfType('type_identifier');
        if (typeNode.length > 0) {
          receiverType = typeNode[0].text;
        }
      }
      const fullName = receiverType ? `${receiverType}.${name}` : name;
      const methodNode = createNode({
        label: fullName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'go',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(methodNode);
      ctx.lastCreatedNodeId = methodNode.id;
      ctx.emitContainsIfNeeded(methodNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = methodNode.id;
      ctx.functionRegistry.set(name, methodNode.id);
      if (fullName !== name) ctx.functionRegistry.set(fullName, methodNode.id);
      break;
    }

    case 'func_literal': {
      // Anonymous function literal: func() { ... }
      let funcLitName = 'anonymous';
      if (
        node.parent?.type === 'short_var_declaration' ||
        node.parent?.type === 'var_spec'
      ) {
        const left = node.parent.childForFieldName('left') ?? node.parent.childForFieldName('name');
        if (left?.type === 'identifier') {
          funcLitName = left.text;
        }
      }
      const funcLitNode = createNode({
        label: funcLitName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'go',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(funcLitNode);
      ctx.lastCreatedNodeId = funcLitNode.id;
      ctx.emitContainsIfNeeded(funcLitNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = funcLitNode.id;
      if (funcLitName !== 'anonymous') ctx.functionRegistry.set(funcLitName, funcLitNode.id);
      break;
    }

    // -- IMPORT DECLARATIONS --
    case 'import_declaration': {
      // import "pkg" or import ( "pkg1"; "pkg2" )
      const specs = node.descendantsOfType('import_spec');
      for (const spec of specs) {
        const pathNode = spec.childForFieldName('path');
        const moduleName = pathNode
          ? pathNode.text.replace(/"/g, '')
          : 'unknown';
        const importNode = createNode({
          label: moduleName,
          node_type: 'STRUCTURAL',
          node_subtype: 'dependency',
          language: 'go',
          file: ctx.neuralMap.source_file,
          line_start: spec.startPosition.row + 1,
          line_end: spec.endPosition.row + 1,
          code_snapshot: spec.text.slice(0, 200), analysis_snapshot: spec.text.slice(0, 2000),
        });
        ctx.neuralMap.nodes.push(importNode);
        ctx.lastCreatedNodeId = importNode.id;
        ctx.emitContainsIfNeeded(importNode.id);
      }
      break;
    }

    // -- TYPE DECLARATIONS --
    case 'type_declaration': {
      const specs = node.descendantsOfType('type_spec');
      for (const spec of specs) {
        const name = spec.childForFieldName('name')?.text ?? 'unknown';
        const typeBody = spec.childForFieldName('type');
        const subtype = typeBody?.type === 'interface_type' ? 'interface' : 'struct';
        const typeNode = createNode({
          label: name,
          node_type: 'STRUCTURAL',
          node_subtype: subtype,
          language: 'go',
          file: ctx.neuralMap.source_file,
          line_start: spec.startPosition.row + 1,
          line_end: spec.endPosition.row + 1,
          code_snapshot: spec.text.slice(0, 200), analysis_snapshot: spec.text.slice(0, 2000),
        });
        ctx.neuralMap.nodes.push(typeNode);
        ctx.lastCreatedNodeId = typeNode.id;
        ctx.emitContainsIfNeeded(typeNode.id);
      }
      break;
    }

    // -- CALL EXPRESSION: classify by callee --
    case 'call_expression': {
      const resolution = resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'go',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        if (resolution.tainted) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }
        if (resolution.nodeType === 'INGRESS') {
          n.attack_surface.push('user_input');
        }
        if (resolution.nodeType === 'EXTERNAL' && resolution.subtype === 'system_exec') {
          n.attack_surface.push('command_injection');
        }
        ctx.neuralMap.nodes.push(n);
        ctx.lastCreatedNodeId = n.id;
        ctx.emitContainsIfNeeded(n.id);

        // Data flow: resolve arguments via recursive taint extraction
        const argsNode = node.childForFieldName('arguments');
        let callHasTaintedArgs = false;
        if (argsNode) {
          for (let a = 0; a < argsNode.namedChildCount; a++) {
            const arg = argsNode.namedChild(a);
            if (!arg) continue;

            const taintSources = extractTaintSources(arg, ctx);
            if (taintSources.length > 0) callHasTaintedArgs = true;
            for (const source of taintSources) {
              ctx.addDataFlow(
                source.nodeId,
                n.id,
                source.name,
                'unknown',
                true,
              );
            }
          }
        }

        // Receiver taint: method calls on tainted objects
        const calleeExprForReceiver = node.childForFieldName('function');
        if (calleeExprForReceiver?.type === 'selector_expression') {
          const receiverForTaint = calleeExprForReceiver.childForFieldName('operand');
          if (receiverForTaint) {
            const receiverTaint = extractTaintSources(receiverForTaint, ctx);
            for (const source of receiverTaint) {
              if (!callHasTaintedArgs) callHasTaintedArgs = true;
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
            }
          }
        }

        // Taint-through: if ANY tainted data flows in, mark output tainted
        if (callHasTaintedArgs && !n.data_out.some((d: any) => d.tainted)) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }

        // Callback parameter taint (for func literals passed as args)
        if (callHasTaintedArgs) {
          const callArgs = node.childForFieldName('arguments');
          if (callArgs) {
            for (let ai = 0; ai < callArgs.namedChildCount; ai++) {
              const arg = callArgs.namedChild(ai);
              if (arg?.type === 'func_literal') {
                const params = arg.childForFieldName('parameters');
                if (params) {
                  for (let pi = 0; pi < params.namedChildCount; pi++) {
                    const p = params.namedChild(pi);
                    if (p?.type === 'parameter_declaration') {
                      for (let ni = 0; ni < p.namedChildCount; ni++) {
                        const pName = p.namedChild(ni);
                        if (pName?.type === 'identifier') {
                          ctx.pendingCallbackTaint.set(pName.text, n.id);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      } else {
        // -- Variable alias resolution --
        const aliasCalleeNode = node.childForFieldName('function');
        if (aliasCalleeNode?.type === 'identifier') {
          const aliasVar = ctx.resolveVariable(aliasCalleeNode.text);
          if (aliasVar?.aliasChain) {
            const aliasPattern = _lookupCallee(aliasVar.aliasChain);
            if (aliasPattern) {
              const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const aliasN = createNode({
                label,
                node_type: aliasPattern.nodeType,
                node_subtype: aliasPattern.subtype,
                language: 'go',
                file: ctx.neuralMap.source_file,
                line_start: node.startPosition.row + 1,
                line_end: node.endPosition.row + 1,
                code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
              });
              if (aliasPattern.nodeType === 'EXTERNAL' && aliasPattern.subtype === 'system_exec') {
                aliasN.attack_surface.push('command_injection');
              }
              ctx.neuralMap.nodes.push(aliasN);
              ctx.lastCreatedNodeId = aliasN.id;
              ctx.emitContainsIfNeeded(aliasN.id);
              const aliasArgs = node.childForFieldName('arguments');
              if (aliasArgs) {
                for (let a = 0; a < aliasArgs.namedChildCount; a++) {
                  const arg = aliasArgs.namedChild(a);
                  if (!arg) continue;
                  const taintSources = extractTaintSources(arg, ctx);
                  for (const source of taintSources) {
                    ctx.addDataFlow(source.nodeId, aliasN.id, source.name, 'unknown', true);
                  }
                }
              }
              break;
            }
          }
        }

        // -- Unresolved call -- check if it's a locally-defined function --
        const calleeNode = node.childForFieldName('function');
        let calleeName: string | null = null;
        if (calleeNode?.type === 'identifier') {
          calleeName = calleeNode.text;
        } else if (calleeNode?.type === 'selector_expression') {
          calleeName = calleeNode.childForFieldName('field')?.text ?? null;
        }

        if (calleeName && ctx.functionRegistry.has(calleeName)) {
          const argsNode = node.childForFieldName('arguments');
          const taintSources: TaintSourceResult[] = [];
          if (argsNode) {
            for (let a = 0; a < argsNode.namedChildCount; a++) {
              const arg = argsNode.namedChild(a);
              if (arg) taintSources.push(...extractTaintSources(arg, ctx));
            }
          }

          const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
          const callNode = createNode({
            label,
            node_type: 'TRANSFORM',
            node_subtype: 'local_call',
            language: 'go',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
          });
          const funcNodeId = ctx.functionRegistry.get(calleeName);
          const funcStructNode = funcNodeId ? ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId) : null;
          const funcReturnsTaint = funcStructNode?.data_out.some((d: any) => d.tainted) ?? false;

          if (taintSources.length > 0 || funcReturnsTaint) {
            callNode.data_out.push({
              name: 'result',
              source: callNode.id,
              data_type: 'unknown',
              tainted: true,
              sensitivity: 'NONE',
            });
          }
          ctx.neuralMap.nodes.push(callNode);
          ctx.lastCreatedNodeId = callNode.id;
          ctx.emitContainsIfNeeded(callNode.id);

          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, callNode.id, source.name, 'unknown', true);
          }
        }
      }

      // CALLS edge: capture simple identifier calls
      const callFuncNode = node.childForFieldName('function');
      if (callFuncNode?.type === 'identifier') {
        const containerId = ctx.getCurrentContainerId();
        if (containerId) {
          ctx.pendingCalls.push({
            callerContainerId: containerId,
            calleeName: callFuncNode.text,
            isAsync: false,
          });
        }
      }
      break;
    }

    // -- SELECTOR EXPRESSION: standalone property access --
    case 'selector_expression': {
      // Skip if this is part of a call_expression callee
      const funcNode = node.parent?.childForFieldName('function');
      const parentIsCall = node.parent?.type === 'call_expression' &&
        funcNode != null &&
        funcNode.startIndex === node.startIndex;
      if (!parentIsCall) {
        const lineNum = node.startPosition.row + 1;
        const codeText = node.text.slice(0, 200);
        const alreadyCreated = ctx.neuralMap.nodes.find(
          (n: any) => n.line_start === lineNum &&
               n.code_snapshot === codeText
        );
        if (alreadyCreated) {
          ctx.lastCreatedNodeId = alreadyCreated.id;
          break;
        }

        const resolution = resolvePropertyAccess(node);
        if (resolution) {
          const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
          const n = createNode({
            label,
            node_type: resolution.nodeType,
            node_subtype: resolution.subtype,
            language: 'go',
            file: ctx.neuralMap.source_file,
            line_start: lineNum,
            line_end: node.endPosition.row + 1,
            code_snapshot: codeText,
          });
          if (resolution.tainted) {
            n.data_out.push({
              name: 'result',
              source: n.id,
              data_type: 'unknown',
              tainted: true,
              sensitivity: 'NONE',
            });
            n.attack_surface.push('user_input');
          }
          ctx.neuralMap.nodes.push(n);
          ctx.lastCreatedNodeId = n.id;
          ctx.emitContainsIfNeeded(n.id);
        }
      }
      break;
    }

    // -- CONTROL FLOW --
    case 'if_statement': {
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      break;
    }
    case 'for_statement': {
      const forN = createNode({ label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      break;
    }
    case 'switch_statement': {
      const switchN = createNode({ label: 'switch', node_type: 'CONTROL', node_subtype: 'branch', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(switchN); ctx.lastCreatedNodeId = switchN.id; ctx.emitContainsIfNeeded(switchN.id);
      break;
    }
    case 'type_switch_statement': {
      const typeSwitchN = createNode({ label: 'type switch', node_type: 'CONTROL', node_subtype: 'branch', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(typeSwitchN); ctx.lastCreatedNodeId = typeSwitchN.id; ctx.emitContainsIfNeeded(typeSwitchN.id);
      break;
    }
    case 'select_statement': {
      const selectN = createNode({ label: 'select', node_type: 'CONTROL', node_subtype: 'channel_select', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      selectN.tags.push('concurrency');
      ctx.neuralMap.nodes.push(selectN); ctx.lastCreatedNodeId = selectN.id; ctx.emitContainsIfNeeded(selectN.id);
      break;
    }
    case 'return_statement': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }
    case 'break_statement': {
      const breakN = createNode({ label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(breakN); ctx.lastCreatedNodeId = breakN.id; ctx.emitContainsIfNeeded(breakN.id);
      break;
    }
    case 'continue_statement': {
      const contN = createNode({ label: 'continue', node_type: 'CONTROL', node_subtype: 'continue', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(contN); ctx.lastCreatedNodeId = contN.id; ctx.emitContainsIfNeeded(contN.id);
      break;
    }
    case 'labeled_statement': {
      const labelN = createNode({ label: `label:${node.childForFieldName('label')?.text ?? '?'}`, node_type: 'CONTROL', node_subtype: 'label', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(labelN); ctx.lastCreatedNodeId = labelN.id; ctx.emitContainsIfNeeded(labelN.id);
      break;
    }
    case 'expression_case': {
      const caseN = createNode({ label: 'case', node_type: 'CONTROL', node_subtype: 'case', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(caseN); ctx.lastCreatedNodeId = caseN.id; ctx.emitContainsIfNeeded(caseN.id);
      break;
    }
    case 'default_case': {
      const defN = createNode({ label: 'default', node_type: 'CONTROL', node_subtype: 'case', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(defN); ctx.lastCreatedNodeId = defN.id; ctx.emitContainsIfNeeded(defN.id);
      break;
    }

    // -- GO-SPECIFIC: defer, goroutines, channels --
    case 'defer_statement': {
      const deferN = createNode({ label: 'defer', node_type: 'CONTROL', node_subtype: 'defer', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      deferN.tags.push('cleanup', 'defer');
      ctx.neuralMap.nodes.push(deferN); ctx.lastCreatedNodeId = deferN.id; ctx.emitContainsIfNeeded(deferN.id);
      break;
    }
    case 'go_statement': {
      const goN = createNode({ label: 'go', node_type: 'CONTROL', node_subtype: 'goroutine', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      goN.tags.push('concurrency', 'goroutine');
      ctx.neuralMap.nodes.push(goN); ctx.lastCreatedNodeId = goN.id; ctx.emitContainsIfNeeded(goN.id);
      break;
    }
    case 'send_statement': {
      // ch <- value
      const sendN = createNode({ label: 'chan<-', node_type: 'CONTROL', node_subtype: 'channel_send', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      sendN.tags.push('concurrency', 'channel');
      ctx.neuralMap.nodes.push(sendN); ctx.lastCreatedNodeId = sendN.id; ctx.emitContainsIfNeeded(sendN.id);
      break;
    }
    case 'receive_statement': {
      // <- ch  or  x := <- ch
      const recvN = createNode({ label: '<-chan', node_type: 'CONTROL', node_subtype: 'channel_receive', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      recvN.tags.push('concurrency', 'channel');
      ctx.neuralMap.nodes.push(recvN); ctx.lastCreatedNodeId = recvN.id; ctx.emitContainsIfNeeded(recvN.id);
      break;
    }

    // -- ASSIGNMENT (non-declaration) --
    case 'assignment_statement': {
      const assignLeft = node.childForFieldName('left');
      const leftText = assignLeft?.text?.slice(0, 40) ?? '?';
      const assignN = createNode({ label: `${leftText} =`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(assignN); ctx.lastCreatedNodeId = assignN.id; ctx.emitContainsIfNeeded(assignN.id);

      const assignRight = node.childForFieldName('right');
      if (assignRight) {
        const taintSources = extractTaintSources(assignRight, ctx);
        if (taintSources.length > 0) {
          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, assignN.id, source.name, 'unknown', true);
          }
          // Propagate taint to the variable being assigned
          if (assignLeft?.type === 'identifier') {
            const varInfo = ctx.resolveVariable(assignLeft.text);
            if (varInfo) {
              varInfo.tainted = true;
              varInfo.producingNodeId = assignN.id;
            }
          }
          if (assignLeft?.type === 'expression_list') {
            for (let i = 0; i < assignLeft.namedChildCount; i++) {
              const lhs = assignLeft.namedChild(i);
              if (lhs?.type === 'identifier' && lhs.text !== '_') {
                const varInfo = ctx.resolveVariable(lhs.text);
                if (varInfo) {
                  varInfo.tainted = true;
                  varInfo.producingNodeId = assignN.id;
                }
              }
            }
          }
          assignN.data_out.push({
            name: 'result',
            source: assignN.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }
      }
      break;
    }

    // -- INC/DEC STATEMENTS --
    case 'inc_statement':
    case 'dec_statement': {
      const incDecN = createNode({ label: node.text.slice(0, 20), node_type: 'TRANSFORM', node_subtype: 'update', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      incDecN.tags.push('mutation');
      ctx.neuralMap.nodes.push(incDecN); ctx.lastCreatedNodeId = incDecN.id; ctx.emitContainsIfNeeded(incDecN.id);
      break;
    }

    // -- PACKAGE CLAUSE --
    case 'package_clause': {
      const pkgName = node.childForFieldName('name')?.text ?? 'main';
      const pkgN = createNode({ label: `package ${pkgName}`, node_type: 'STRUCTURAL', node_subtype: 'module', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(pkgN); ctx.lastCreatedNodeId = pkgN.id; ctx.emitContainsIfNeeded(pkgN.id);
      break;
    }

    // -- COMPOSITE LITERAL (struct/slice/map init) --
    case 'composite_literal': {
      if (node.namedChildCount >= 2) {
        const compType = node.childForFieldName('type')?.text ?? '{...}';
        const compN = createNode({ label: compType, node_type: 'TRANSFORM', node_subtype: 'composite_literal', language: 'go', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(compN); ctx.lastCreatedNodeId = compN.id; ctx.emitContainsIfNeeded(compN.id);
      }
      break;
    }

    // -- Silent pass-throughs --
    case 'expression_statement':
    case 'empty_statement':
    case 'parenthesized_expression':
    case 'comment':
      break;
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'function_declaration' && node.type !== 'method_declaration' && node.type !== 'func_literal') {
    return;
  }

  const body = node.childForFieldName('body');
  if (!body) return;

  // Check for return statements with tainted expressions
  for (let i = 0; i < body.namedChildCount; i++) {
    const stmt = body.namedChild(i);
    if (stmt?.type === 'return_statement') {
      // Go returns can have expression_list: return a, err
      for (let j = 0; j < stmt.namedChildCount; j++) {
        const retExpr = stmt.namedChild(j);
        if (retExpr) {
          const taintSources = extractTaintSources(retExpr, ctx);
          if (taintSources.length > 0) {
            const funcNodeId = ctx.currentScope?.containerNodeId;
            if (funcNodeId) {
              const funcNode = ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId);
              if (funcNode && !funcNode.data_out.some((d: any) => d.tainted)) {
                funcNode.data_out.push({
                  name: 'return', source: funcNode.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE',
                });
              }
            }
            break; // one tainted return is enough
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// preVisitIteration — set up range variable taint
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_statement') return;

  // Go for-range: for k, v := range iterable { ... }
  // tree-sitter-go: for_statement with range_clause child
  const rangeClause = node.descendantsOfType('range_clause')[0];
  if (!rangeClause) return;

  const right = rangeClause.childForFieldName('right');
  if (right) {
    const iterTaint = extractTaintSources(right, ctx);
    if (iterTaint.length > 0) {
      const left = rangeClause.childForFieldName('left');
      if (left) {
        const names = extractPatternNames(left);
        for (const varName of names) {
          ctx.declareVariable(varName, 'const', null, true, iterTaint[0].nodeId);
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration — re-mark range variable taint after body walk
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_statement') return;

  const rangeClause = node.descendantsOfType('range_clause')[0];
  if (!rangeClause) return;

  const right = rangeClause.childForFieldName('right');
  if (right) {
    const iterTaint = extractTaintSources(right, ctx);
    if (iterTaint.length > 0) {
      const left = rangeClause.childForFieldName('left');
      if (left) {
        const names = extractPatternNames(left);
        for (const varName of names) {
          const v = ctx.resolveVariable(varName);
          if (v) {
            v.tainted = true;
            v.producingNodeId = iterTaint[0].nodeId;
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// The Profile
// ---------------------------------------------------------------------------

export const goProfile: LanguageProfile = {
  id: 'go',
  extensions: ['.go'],

  // Layer 1: AST Node Type Recognition
  functionScopeTypes: FUNCTION_SCOPE_TYPES,
  blockScopeTypes: BLOCK_SCOPE_TYPES,
  classScopeTypes: CLASS_SCOPE_TYPES,

  getScopeType(node: SyntaxNode): ScopeType | null {
    if (FUNCTION_SCOPE_TYPES.has(node.type)) return 'function';
    if (BLOCK_SCOPE_TYPES.has(node.type)) return 'block';
    // Go has no class scopes
    return null;
  },

  variableDeclarationTypes: VARIABLE_DECLARATION_TYPES,
  functionDeclarationTypes: FUNCTION_DECLARATION_TYPES,

  // Layer 2: AST Child Access
  processVariableDeclaration,
  processFunctionParams,
  extractPatternNames,

  // Layer 3: Callee Resolution (Phoneme Dictionary)
  resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
    return resolveCallee(node);
  },

  resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
    return resolvePropertyAccess(node);
  },

  lookupCallee(chain: string[]): CalleePattern | null {
    return _lookupCallee(chain);
  },

  analyzeStructure(_node: SyntaxNode): StructuralAnalysisResult | null {
    // Go middleware patterns (Gin router.Use, Chi r.Use, etc.) are handled
    // through the phoneme dictionary in classifyNode. Structural analysis
    // for Go is a future enhancement.
    return null;
  },

  // Layer 4: Taint Source Detection
  ingressPattern: /(?:r\.(?:FormValue|FormFile|PostFormValue|ParseForm|Body|URL|Header|Host|RemoteAddr|Cookies?|URL\.Query|URL\.Path)|req\.(?:FormValue|Body|Header|URL)|c\.(?:Query|Param|PostForm|DefaultQuery|GetRawData|ShouldBindJSON|ShouldBind|BindJSON|Bind|GetHeader|FormFile|Request|ClientIP|Cookie|FullPath|QueryParam|QueryParams|FormValue|PathParam|Params|Body|BodyParser|Get|Cookies)|os\.(?:Args|Stdin)|flag\.(?:Parse|String|Int|Bool|Arg|Args)|bufio\.(?:NewReader|NewScanner))/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) => nodeType === 'short_var_declaration' || nodeType === 'var_declaration',
  getDeclarationValueNode: (node) => {
    // short_var_declaration: x, err := expr → 'right' field
    if (node.type === 'short_var_declaration') return node.childForFieldName('right');
    // var_declaration: var x = expr → var_spec children → 'value' field
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child?.type === 'var_spec') return child.childForFieldName('value');
    }
    return null;
  },
  isStatementContainer: (nodeType: string) => nodeType === 'source_file' || nodeType === 'block',

  // Inter-procedural taint: Go func syntax
  // Matches: func name(params) { | func (r *T) name(params) { | func(params) {
  // Group 1 captures the full parameter list between parentheses.
  functionParamPattern: /func\s+(?:\([^)]*\)\s*)?\w*\s*\(([^)]*)\)/,
};

export default goProfile;
