/**
 * SwiftProfile — LanguageProfile for the Swift programming language.
 *
 * Every piece of Swift-specific logic lives here: AST node type names,
 * field access patterns, scope rules, callee resolution, taint extraction,
 * and node classification.
 *
 * Key differences from Rust/JavaScript:
 *   - `function_declaration` same name as JS but different children
 *   - `property_declaration` for let/var (replaces lexical_declaration)
 *   - `call_expression` with `call_suffix` -> `value_arguments`
 *   - `navigation_expression` with `navigation_suffix` for member access (not member_expression)
 *   - `class_declaration` for class, struct, enum, AND extension (all share the AST node type)
 *   - `protocol_declaration` for protocols
 *   - `if_statement`, `switch_statement`, `guard_statement`
 *   - `lambda_literal` for closures (not closure_expression or arrow_function)
 *   - `control_transfer_statement` for return/break/continue/throw (single node type)
 *   - `interpolated_expression` inside `line_string_literal` (taint vectors!)
 *   - `try_expression` / `await_expression` for Swift concurrency
 *   - `do_statement` with `catch_block` for error handling
 *   - `for_statement`, `while_statement` for loops
 *   - `value_binding_pattern` for let/var keyword in declarations
 *   - `simple_identifier` is the leaf identifier node (not plain `identifier`)
 *   - Parameters use `parameter` nodes with `name` field and `type` field
 *
 * tree-sitter-swift AST reference: https://github.com/alex-pinkus/tree-sitter-swift
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
import { lookupCallee as _lookupSwiftCallee } from '../languages/swift.js';

// ---------------------------------------------------------------------------
// AST Node Type Sets (tree-sitter-swift)
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'function_declaration',
  'lambda_literal',
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'statements',          // { ... } block bodies
  'if_statement',
  'guard_statement',
  'switch_statement',
  'switch_entry',
  'for_statement',
  'while_statement',
  'do_statement',
  'catch_block',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'class_declaration',       // class, struct, enum, extension all use this
  'protocol_declaration',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'property_declaration',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'function_declaration',
]);

// Tainted paths for Swift web frameworks (Vapor)
const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // Vapor request
  'req.content', 'req.query', 'req.parameters', 'req.headers',
  'req.body', 'req.cookies', 'req.session',
  'request.content', 'request.query', 'request.parameters',
  'request.headers', 'request.body', 'request.cookies',
  // UIKit user input
  'textField.text', 'textView.text', 'searchBar.text',
  // Pasteboard
  'UIPasteboard.general.string', 'UIPasteboard.general.strings',
  'UIPasteboard.general.url', 'UIPasteboard.general.image',
  // Environment
  'ProcessInfo.processInfo.environment',
  'CommandLine.arguments',
]);

// Vapor extractor type names that indicate tainted function params
const SWIFT_WEB_EXTRACTORS: ReadonlySet<string> = new Set([
  'Request', 'Content', 'Parameters',
]);

// Common parameter names that represent user-controlled input.
// When a function takes a `String` parameter with one of these names,
// it's almost certainly receiving external data.
const TAINTED_PARAM_NAMES: ReadonlySet<string> = new Set([
  // Identity / auth
  'username', 'password', 'user', 'email', 'token', 'apiKey',
  // Generic input
  'input', 'data', 'payload', 'body', 'content', 'text', 'value', 'rawValue',
  // Path / file
  'path', 'filePath', 'filename', 'fileName', 'file', 'directory', 'dir',
  // URL / network
  'url', 'urlString', 'targetUrl', 'redirectUrl', 'returnUrl', 'endpoint', 'uri', 'href',
  // Query / search
  'query', 'search', 'term', 'filter', 'param', 'key',
  // Identifiers
  'id', 'userId', 'itemId', 'recordId', 'resourceId',
  // Names
  'name', 'title', 'label', 'description', 'message', 'comment', 'html', 'template',
  // Command / code
  'command', 'cmd', 'script', 'code', 'expression', 'sql',
  // Headers / cookies
  'header', 'cookie', 'referer', 'origin', 'host',
]);

// Types that indicate user-controlled data when used as function params
const TAINTED_PARAM_TYPES: ReadonlySet<string> = new Set([
  'String', 'String?', 'Substring', 'Data', 'Data?',
]);

// ---------------------------------------------------------------------------
// Helper: extract callee chain from Swift AST nodes
// ---------------------------------------------------------------------------

/**
 * Extract the callee chain from a Swift expression.
 * Handles:
 *   - simple_identifier: `print` -> ['print']
 *   - navigation_expression: `URLSession.shared.data` -> ['URLSession', 'shared', 'data']
 *   - call_expression chains: `req.content.decode(...)` -> ['req', 'content', 'decode']
 */
function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'simple_identifier') {
    return [node.text];
  }

  if (node.type === 'navigation_expression') {
    const parts: string[] = [];
    // Recursively collect the chain
    collectNavigationChain(node, parts);
    return parts;
  }

  if (node.type === 'call_expression') {
    // The first child is the function being called
    const funcChild = node.child(0);
    if (funcChild) return extractCalleeChain(funcChild);
  }

  if (node.type === 'try_expression') {
    // try expr — unwrap
    const inner = node.namedChild(node.namedChildCount - 1);
    if (inner) return extractCalleeChain(inner);
  }

  if (node.type === 'await_expression') {
    // await expr — unwrap
    const inner = node.namedChild(node.namedChildCount - 1);
    if (inner) return extractCalleeChain(inner);
  }

  return [node.text.slice(0, 50)];
}

/**
 * Collect parts of a navigation_expression chain into an array.
 * navigation_expression has children: [expr, navigation_suffix]
 * where navigation_suffix contains ['.', simple_identifier]
 */
function collectNavigationChain(node: SyntaxNode, parts: string[]): void {
  if (node.type === 'simple_identifier') {
    parts.push(node.text);
    return;
  }

  if (node.type === 'navigation_expression') {
    // First child is the base expression, second is navigation_suffix
    const base = node.child(0);
    const suffix = node.children.find((c: SyntaxNode) => c.type === 'navigation_suffix');

    if (base) collectNavigationChain(base, parts);
    if (suffix) {
      // navigation_suffix contains ['.', simple_identifier]
      const ident = suffix.children.find((c: SyntaxNode) => c.type === 'simple_identifier');
      if (ident) parts.push(ident.text);
    }
    return;
  }

  if (node.type === 'call_expression') {
    // Chained call: a.b().c — the base of c is the call a.b()
    const funcChild = node.child(0);
    if (funcChild) collectNavigationChain(funcChild, parts);
    return;
  }

  // Fallback for other node types
  parts.push(node.text.slice(0, 50));
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
// Helper: get the kind of a class_declaration (class, struct, enum, extension)
// ---------------------------------------------------------------------------

function getClassKind(node: SyntaxNode): 'class' | 'struct' | 'enum' | 'extension' {
  const firstChild = node.child(0);
  if (firstChild) {
    const text = firstChild.text;
    if (text === 'struct') return 'struct';
    if (text === 'enum') return 'enum';
    if (text === 'extension') return 'extension';
  }
  return 'class';
}

// ---------------------------------------------------------------------------
// Helper: get control_transfer_statement kind
// ---------------------------------------------------------------------------

function getTransferKind(node: SyntaxNode): 'return' | 'break' | 'continue' | 'throw' | null {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === 'return' || child.text === 'return') return 'return';
    if (child.text === 'break') return 'break';
    if (child.text === 'continue') return 'continue';
    if (child.type === 'throw_keyword' || child.text === 'throw') return 'throw';
  }
  return null;
}

// ---------------------------------------------------------------------------
// extractPatternNames — extract variable names from Swift patterns
// ---------------------------------------------------------------------------

function extractPatternNames(pattern: SyntaxNode): string[] {
  const names: string[] = [];

  switch (pattern.type) {
    case 'simple_identifier':
      if (pattern.text !== '_') names.push(pattern.text);
      break;

    case 'pattern':
      // pattern wraps a simple_identifier
      for (let i = 0; i < pattern.namedChildCount; i++) {
        const child = pattern.namedChild(i);
        if (child) names.push(...extractPatternNames(child));
      }
      break;

    case 'tuple_pattern':
      for (let i = 0; i < pattern.namedChildCount; i++) {
        const child = pattern.namedChild(i);
        if (child) names.push(...extractPatternNames(child));
      }
      break;

    case 'value_binding_pattern':
      // let/var in pattern context — skip the keyword, get the identifiers
      for (let i = 0; i < pattern.namedChildCount; i++) {
        const child = pattern.namedChild(i);
        if (child && child.type !== 'let' && child.type !== 'var') {
          names.push(...extractPatternNames(child));
        }
      }
      break;

    case 'identifier':
      if (pattern.text !== '_') names.push(pattern.text);
      break;

    default:
      // Try to find identifiers in unknown patterns
      for (let i = 0; i < pattern.namedChildCount; i++) {
        const child = pattern.namedChild(i);
        if (child?.type === 'simple_identifier' && child.text !== '_') {
          names.push(child.text);
        } else if (child) {
          names.push(...extractPatternNames(child));
        }
      }
      break;
  }

  return names;
}

// ---------------------------------------------------------------------------
// extractTaintSources — recursive expression X-ray for Swift
// ---------------------------------------------------------------------------

function extractTaintSources(expr: SyntaxNode, ctx: MapperContextLike): TaintSourceResult[] {
  if (!expr) return [];

  switch (expr.type) {
    // -- Leaf: identifier -- check if tainted variable
    case 'simple_identifier': {
      const varInfo = ctx.resolveVariable(expr.text);
      if (varInfo?.tainted && varInfo.producingNodeId) {
        return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
      }
      return [];
    }

    // -- navigation_expression: req.body, data.field --
    case 'navigation_expression': {
      const chain = extractCalleeChain(expr);
      const key = chain.join('.');
      if (TAINTED_PATHS.has(key)) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: 'INGRESS',
          node_subtype: 'http_request',
          language: 'swift',
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
      // Check if first element is a tainted variable
      const baseNode = expr.child(0);
      if (baseNode?.type === 'simple_identifier') {
        const varInfo = ctx.resolveVariable(baseNode.text);
        if (varInfo?.tainted && varInfo.producingNodeId) {
          return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
        }
      }
      // Recurse into deeper chains
      if (baseNode?.type === 'navigation_expression') {
        return extractTaintSources(baseNode, ctx);
      }
      return [];
    }

    // -- Binary / infix expression --
    case 'infix_expression':
    case 'additive_expression':
    case 'multiplicative_expression':
    case 'comparison_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Nil coalescing: x ?? default --
    case 'nil_coalescing_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Call expression: function(tainted_data) --
    case 'call_expression': {
      const callChain = extractCalleeChain(expr);
      const callResolution = _lookupSwiftCallee(callChain);
      // Sanitizer calls break taint
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          (callResolution.subtype === 'sanitize' || callResolution.subtype === 'encode')) {
        return [];
      }
      // Check arguments for taint
      const sources: TaintSourceResult[] = [];
      const callSuffix = expr.children.find((c: SyntaxNode) => c.type === 'call_suffix');
      const args = callSuffix?.children.find((c: SyntaxNode) => c.type === 'value_arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (!arg) continue;
          if (arg.type === 'value_argument') {
            // value_argument can have a label and a value
            for (let j = 0; j < arg.namedChildCount; j++) {
              const argChild = arg.namedChild(j);
              if (argChild && argChild.type !== 'value_argument_label') {
                sources.push(...extractTaintSources(argChild, ctx));
              }
            }
          } else {
            sources.push(...extractTaintSources(arg, ctx));
          }
        }
      }
      // Check receiver for taint
      const funcExpr = expr.child(0);
      if (funcExpr?.type === 'navigation_expression') {
        const receiver = funcExpr.child(0);
        if (receiver) sources.push(...extractTaintSources(receiver, ctx));
      }
      // Check existing node with tainted data_out
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

    // -- String interpolation: "Hello, \(name)" --
    case 'line_string_literal':
    case 'multi_line_string_literal': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.childCount; i++) {
        const child = expr.child(i);
        if (child?.type === 'interpolated_expression') {
          for (let j = 0; j < child.namedChildCount; j++) {
            const inner = child.namedChild(j);
            if (inner) sources.push(...extractTaintSources(inner, ctx));
          }
        }
      }
      return sources;
    }

    case 'interpolated_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Try expression: try expr --
    case 'try_expression': {
      const inner = expr.namedChild(expr.namedChildCount - 1);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Await expression: await expr --
    case 'await_expression': {
      const inner = expr.namedChild(expr.namedChildCount - 1);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Parenthesized: (expr) --
    case 'tuple_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Array literal: [a, b, c] --
    case 'array_literal': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Dictionary literal: [k: v, ...] --
    case 'dictionary_literal': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Closure: { expr } --
    case 'lambda_literal': {
      // Check last expression in the closure body
      const stmts = expr.children.find((c: SyntaxNode) => c.type === 'statements');
      if (stmts) {
        const last = stmts.namedChild(stmts.namedChildCount - 1);
        if (last) return extractTaintSources(last, ctx);
      }
      return [];
    }

    // -- Ternary: cond ? a : b --
    case 'ternary_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Prefix expression: !expr, -expr --
    case 'prefix_expression': {
      const inner = expr.namedChild(expr.namedChildCount - 1);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Force unwrap: expr! --
    case 'force_unwrap_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Optional chaining: expr? --
    case 'optional_chaining_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- As/is cast: expr as Type --
    case 'as_expression':
    case 'is_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Subscript: arr[i] --
    case 'subscript_expression': {
      const obj = expr.namedChild(0);
      return obj ? extractTaintSources(obj, ctx) : [];
    }

    // -- Statements (last expression is the value) --
    case 'statements': {
      const lastChild = expr.namedChild(expr.namedChildCount - 1);
      return lastChild ? extractTaintSources(lastChild, ctx) : [];
    }

    // -- Control transfer (return value) --
    case 'control_transfer_statement': {
      const kind = getTransferKind(expr);
      if (kind === 'return') {
        // Return value is the last named child (after the `return` keyword)
        const retVal = expr.namedChild(expr.namedChildCount - 1);
        if (retVal && retVal.type !== 'return') {
          return extractTaintSources(retVal, ctx);
        }
      }
      return [];
    }

    // -- Property declaration value --
    case 'property_declaration': {
      const valueNode = expr.childForFieldName('value');
      return valueNode ? extractTaintSources(valueNode, ctx) : [];
    }

    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration — handle let/var property declarations
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'property_declaration') return;

  // Determine let vs var from value_binding_pattern
  const bindingPattern = node.children.find((c: SyntaxNode) => c.type === 'value_binding_pattern');
  const isLet = bindingPattern?.text?.startsWith('let') ?? false;
  const kind: VariableInfo['kind'] = isLet ? 'const' : 'let';

  // Get the name from the 'name' field (which is a pattern node)
  const nameNode = node.childForFieldName('name');
  if (!nameNode) return;

  // Get the value expression
  const valueNode = node.childForFieldName('value');

  // lastCreatedNodeId was set by walking the value expression (children-first)
  let producingNodeId = ctx.lastCreatedNodeId;

  // Check if the producing node is tainted
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

  // Multi-hop taint: if value is a plain identifier, inherit taint
  if (!producingNodeId && valueNode) {
    if (valueNode.type === 'simple_identifier') {
      const sourceVar = ctx.resolveVariable(valueNode.text);
      if (sourceVar) {
        tainted = sourceVar.tainted;
        producingNodeId = sourceVar.producingNodeId;
      }
    }
  }

  // Direct taint extraction on the value expression
  if (!tainted && valueNode) {
    const directTaint = extractTaintSources(valueNode, ctx);
    if (directTaint.length > 0) {
      tainted = true;
      producingNodeId = directTaint[0].nodeId;
    }
  }

  // Cross-function taint: let val = getInput(req)
  if (!producingNodeId && valueNode?.type === 'call_expression') {
    const funcChild = valueNode.child(0);
    if (funcChild?.type === 'simple_identifier') {
      const funcNodeId = ctx.functionRegistry.get(funcChild.text);
      if (funcNodeId) {
        const ingressInFunc = findIngressInFunction(funcNodeId, ctx);
        if (ingressInFunc) {
          tainted = true;
          producingNodeId = ingressInFunc;
        }
      }
    }
  }

  // Alias chain detection: let query = db.query
  let aliasChain: string[] | undefined;
  if (valueNode?.type === 'navigation_expression') {
    aliasChain = extractCalleeChain(valueNode);
  }

  // Preserve existing taint from loop variables etc.
  const preserveTaint = (varName: string, newTainted: boolean, newProducing: string | null) => {
    if (!newTainted) {
      const existing = ctx.resolveVariable(varName);
      if (existing?.tainted) return;
    }
    ctx.declareVariable(varName, kind, null, newTainted, newProducing);
    const v = ctx.resolveVariable(varName);
    if (v && aliasChain) v.aliasChain = aliasChain;
  };

  // Extract variable names from the pattern
  const names = extractPatternNames(nameNode);
  for (const n of names) {
    preserveTaint(n, tainted, producingNodeId);
  }
}

// ---------------------------------------------------------------------------
// processFunctionParams — declare params in the current scope
// ---------------------------------------------------------------------------

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  const declareParam = (name: string) => {
    const producingId = ctx.pendingCallbackTaint.get(name) ?? null;
    const isTainted = producingId !== null;
    if (isTainted) ctx.pendingCallbackTaint.delete(name);
    ctx.declareVariable(name, 'param', null, isTainted, producingId);
  };

  /**
   * Declare a web extractor parameter as a tainted INGRESS source.
   * In Swift/Vapor, Request parameters are function params.
   */
  const declareTaintedExtractorParam = (name: string, paramNode: SyntaxNode) => {
    const producingId = ctx.pendingCallbackTaint.get(name) ?? null;
    if (producingId !== null) {
      ctx.pendingCallbackTaint.delete(name);
      ctx.declareVariable(name, 'param', null, true, producingId);
      return;
    }

    const ingressNode = createNode({
      label: name,
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      language: 'swift',
      file: ctx.neuralMap.source_file,
      line_start: paramNode.startPosition.row + 1,
      line_end: paramNode.endPosition.row + 1,
      code_snapshot: paramNode.text.slice(0, 200), analysis_snapshot: paramNode.text.slice(0, 2000),
    });
    ingressNode.data_out.push({
      name: 'result',
      source: ingressNode.id,
      data_type: 'unknown',
      tainted: true,
      sensitivity: 'NONE',
    });
    ingressNode.attack_surface.push('user_input');
    ctx.neuralMap.nodes.push(ingressNode);
    ctx.emitContainsIfNeeded(ingressNode.id);

    ctx.declareVariable(name, 'param', null, true, ingressNode.id);
  };

  if (funcNode.type === 'function_declaration') {
    // Parameters are direct children of function_declaration between ( and )
    for (let i = 0; i < funcNode.namedChildCount; i++) {
      const param = funcNode.namedChild(i);
      if (!param || param.type !== 'parameter') continue;

      const paramName = param.childForFieldName('name')?.text;
      if (!paramName) continue;

      // Check if the type is a known web extractor
      const typeField = param.childForFieldName('type');
      const typeText = typeField?.text ?? '';
      const baseType = typeText.split('<')[0].split('?')[0].trim();

      if (SWIFT_WEB_EXTRACTORS.has(baseType)) {
        declareTaintedExtractorParam(paramName, param);
      } else if (TAINTED_PARAM_NAMES.has(paramName) && TAINTED_PARAM_TYPES.has(typeText.trim())) {
        // Common user-input parameter name with a String-like type — treat as tainted
        declareTaintedExtractorParam(paramName, param);
      } else {
        declareParam(paramName);
      }
    }
  } else if (funcNode.type === 'lambda_literal') {
    // Lambda parameters are in lambda_function_type -> lambda_function_type_parameters
    const funcType = funcNode.children.find((c: SyntaxNode) => c.type === 'lambda_function_type');
    if (funcType) {
      const paramsNode = funcType.children.find(
        (c: SyntaxNode) => c.type === 'lambda_function_type_parameters'
      );
      if (paramsNode) {
        for (let i = 0; i < paramsNode.namedChildCount; i++) {
          const param = paramsNode.namedChild(i);
          if (!param) continue;

          if (param.type === 'lambda_parameter') {
            // lambda_parameter contains the parameter name and optional type
            const name = param.text.split(':')[0].trim();
            if (name && name !== '_') {
              // Check type
              const typeText = param.text.includes(':') ? param.text.split(':')[1].trim() : '';
              const baseType = typeText.split('<')[0].split('?')[0].trim();
              if (SWIFT_WEB_EXTRACTORS.has(baseType)) {
                declareTaintedExtractorParam(name, param);
              } else {
                declareParam(name);
              }
            }
          } else if (param.type === 'simple_identifier') {
            declareParam(param.text);
          }
        }
      }
    }

    // Also check for short closure syntax: { name in ... }
    // Look for capture_list or identifiers before 'in'
    let foundIn = false;
    for (let i = 0; i < funcNode.childCount; i++) {
      const child = funcNode.child(i);
      if (!child) continue;
      if (child.type === 'in') { foundIn = true; break; }
      if (child.text === 'in') { foundIn = true; break; }
    }
    if (foundIn && !funcType) {
      // Simple closure: { x in ... } or { x, y in ... }
      for (let i = 0; i < funcNode.childCount; i++) {
        const child = funcNode.child(i);
        if (!child) continue;
        if (child.type === 'in' || child.text === 'in') break;
        if (child.type === '{') continue;
        if (child.type === 'simple_identifier' && child.text !== '_') {
          declareParam(child.text);
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of the walk switch statement
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  // Hoist function declarations to outer scope
  if (node.type === 'function_declaration') {
    const funcName = node.childForFieldName('name');
    if (funcName && ctx.scopeStack.length >= 2) {
      const outerScope = ctx.scopeStack[ctx.scopeStack.length - 2];
      outerScope.variables.set(funcName.text, {
        name: funcName.text,
        declaringNodeId: null,
        producingNodeId: null,
        kind: 'const',
        tainted: false,
      });
    }
  }

  switch (node.type) {
    // ── Functions ──────────────────────────────────────────────────────

    case 'function_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const isAsync = node.text.includes(' async ') || node.text.includes(' async\n');
      const fnNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      if (isAsync) fnNode.tags.push('async');
      ctx.neuralMap.nodes.push(fnNode);
      ctx.lastCreatedNodeId = fnNode.id;
      ctx.emitContainsIfNeeded(fnNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = fnNode.id;
      if (name !== 'anonymous') ctx.functionRegistry.set(name, fnNode.id);
      break;
    }

    case 'lambda_literal': {
      let closureName = 'anonymous';
      // Check if assigned to a variable: let handler = { ... }
      if (
        node.parent?.type === 'property_declaration' &&
        node.parent.childForFieldName('name')
      ) {
        const nameNode = node.parent.childForFieldName('name');
        const names = extractPatternNames(nameNode!);
        if (names.length > 0) closureName = names[0];
      }
      const closureNode = createNode({
        label: closureName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      closureNode.tags.push('closure');
      ctx.neuralMap.nodes.push(closureNode);
      ctx.lastCreatedNodeId = closureNode.id;
      ctx.emitContainsIfNeeded(closureNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = closureNode.id;
      if (closureName !== 'anonymous') ctx.functionRegistry.set(closureName, closureNode.id);
      break;
    }

    // ── Classes, Structs, Enums, Extensions, Protocols ────────────────

    case 'class_declaration': {
      const classKind = getClassKind(node);
      const nameNode = node.childForFieldName('name');
      const name = nameNode?.text ?? `Anonymous${classKind.charAt(0).toUpperCase() + classKind.slice(1)}`;

      const subtype = classKind === 'extension' ? 'class' : 'class';
      const label = classKind === 'extension' ? `extension ${name}` : name;

      const classNode = createNode({
        label,
        node_type: 'STRUCTURAL',
        node_subtype: subtype,
        language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      classNode.tags.push(classKind);

      // Check for inheritance
      const hasInheritance = node.children.some(
        (c: SyntaxNode) => c.type === 'inheritance_specifier' || c.type === ':'
      );
      if (hasInheritance && classKind !== 'extension') {
        classNode.tags.push('inherits');
      }

      ctx.neuralMap.nodes.push(classNode);
      ctx.lastCreatedNodeId = classNode.id;
      ctx.emitContainsIfNeeded(classNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = classNode.id;
      break;
    }

    case 'protocol_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousProtocol';
      const protoNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      protoNode.tags.push('protocol');
      ctx.neuralMap.nodes.push(protoNode);
      ctx.lastCreatedNodeId = protoNode.id;
      ctx.emitContainsIfNeeded(protoNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = protoNode.id;
      break;
    }

    // ── Imports ─────────────────────────────────────────────────────────

    case 'import_declaration': {
      const moduleName = node.children
        .filter((c: SyntaxNode) => c.type === 'identifier')
        .map((c: SyntaxNode) => c.text)
        .join('.') || 'unknown';
      const importNode = createNode({
        label: moduleName,
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(importNode);
      ctx.lastCreatedNodeId = importNode.id;
      ctx.emitContainsIfNeeded(importNode.id);
      break;
    }

    // ── Call Expressions ────────────────────────────────────────────────

    case 'call_expression': {
      const chain = extractCalleeChain(node);
      const resolution = _lookupSwiftCallee(chain);

      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'swift',
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

        // Data flow: extract tainted arguments
        const callSuffix = node.children.find((c: SyntaxNode) => c.type === 'call_suffix');
        const argsNode = callSuffix?.children.find((c: SyntaxNode) => c.type === 'value_arguments');
        let callHasTaintedArgs = false;
        if (argsNode) {
          for (let a = 0; a < argsNode.namedChildCount; a++) {
            const arg = argsNode.namedChild(a);
            if (!arg) continue;
            let taintSources: TaintSourceResult[];
            if (arg.type === 'value_argument') {
              taintSources = [];
              for (let j = 0; j < arg.namedChildCount; j++) {
                const argChild = arg.namedChild(j);
                if (argChild && argChild.type !== 'value_argument_label') {
                  taintSources.push(...extractTaintSources(argChild, ctx));
                }
              }
            } else {
              taintSources = extractTaintSources(arg, ctx);
            }
            if (taintSources.length > 0) callHasTaintedArgs = true;
            for (const source of taintSources) {
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
            }
          }
        }

        // Also check for trailing closure taint
        const trailingLambda = callSuffix?.children.find(
          (c: SyntaxNode) => c.type === 'lambda_literal'
        );
        if (trailingLambda) {
          const lambdaTaint = extractTaintSources(trailingLambda, ctx);
          if (lambdaTaint.length > 0) callHasTaintedArgs = true;
          for (const source of lambdaTaint) {
            ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
          }
        }

        // Receiver taint: for method calls on tainted objects
        const calleeExpr = node.child(0);
        if (calleeExpr?.type === 'navigation_expression') {
          const receiver = calleeExpr.child(0);
          if (receiver) {
            const receiverTaint = extractTaintSources(receiver, ctx);
            for (const source of receiverTaint) {
              if (!callHasTaintedArgs) callHasTaintedArgs = true;
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
            }
          }
        }

        // Taint-through: tainted input -> tainted output
        if (callHasTaintedArgs && !n.data_out.some((d: any) => d.tainted)) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }

        // Callback parameter taint (closures passed as args)
        if (callHasTaintedArgs) {
          if (trailingLambda) {
            const funcType = trailingLambda.children.find(
              (c: SyntaxNode) => c.type === 'lambda_function_type'
            );
            const paramsNode = funcType?.children.find(
              (c: SyntaxNode) => c.type === 'lambda_function_type_parameters'
            );
            if (paramsNode) {
              for (let pi = 0; pi < paramsNode.namedChildCount; pi++) {
                const p = paramsNode.namedChild(pi);
                if (p?.type === 'lambda_parameter' || p?.type === 'simple_identifier') {
                  const pName = p.text.split(':')[0].trim();
                  if (pName) ctx.pendingCallbackTaint.set(pName, n.id);
                }
              }
            }
          }
        }
      } else {
        // Unresolved call — check if locally defined function
        let calleeName: string | null = null;
        const calleeNode = node.child(0);
        if (calleeNode?.type === 'simple_identifier') {
          calleeName = calleeNode.text;
        } else if (calleeNode?.type === 'navigation_expression') {
          // Take the last segment
          const chain = extractCalleeChain(calleeNode);
          calleeName = chain[chain.length - 1] ?? null;
        }

        if (calleeName && ctx.functionRegistry.has(calleeName)) {
          const callSuffix = node.children.find((c: SyntaxNode) => c.type === 'call_suffix');
          const argsNode = callSuffix?.children.find(
            (c: SyntaxNode) => c.type === 'value_arguments'
          );
          const taintSources: TaintSourceResult[] = [];
          if (argsNode) {
            for (let a = 0; a < argsNode.namedChildCount; a++) {
              const arg = argsNode.namedChild(a);
              if (!arg) continue;
              if (arg.type === 'value_argument') {
                for (let j = 0; j < arg.namedChildCount; j++) {
                  const argChild = arg.namedChild(j);
                  if (argChild && argChild.type !== 'value_argument_label') {
                    taintSources.push(...extractTaintSources(argChild, ctx));
                  }
                }
              } else {
                taintSources.push(...extractTaintSources(arg, ctx));
              }
            }
          }

          const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
          const callNode = createNode({
            label,
            node_type: 'TRANSFORM',
            node_subtype: 'local_call',
            language: 'swift',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
          });
          const funcNodeId = ctx.functionRegistry.get(calleeName);
          const funcStructNode = funcNodeId
            ? ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId)
            : null;
          const funcReturnsTaint =
            funcStructNode?.data_out.some((d: any) => d.tainted) ?? false;

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

        // Variable alias resolution: let q = db.query -> q() resolves as db.query
        if (calleeNode?.type === 'simple_identifier') {
          const aliasVar = ctx.resolveVariable(calleeNode.text);
          if (aliasVar?.aliasChain) {
            const aliasPattern = _lookupSwiftCallee(aliasVar.aliasChain);
            if (aliasPattern) {
              const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const aliasN = createNode({
                label,
                node_type: aliasPattern.nodeType,
                node_subtype: aliasPattern.subtype,
                language: 'swift',
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
            }
          }
        }
      }

      // CALLS edge: capture simple identifier calls
      const callFuncNode = node.child(0);
      if (callFuncNode?.type === 'simple_identifier') {
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

    // ── Navigation Expression (standalone property access) ──────────────

    case 'navigation_expression': {
      // Only classify if NOT the callee of a call_expression
      const parentIsCall = node.parent?.type === 'call_expression' &&
        node.parent.child(0)?.startIndex === node.startIndex;
      if (!parentIsCall) {
        const chain = extractCalleeChain(node);
        const key = chain.join('.');
        if (TAINTED_PATHS.has(key)) {
          const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
          const n = createNode({
            label,
            node_type: 'INGRESS',
            node_subtype: 'http_request',
            language: 'swift',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
          });
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
          n.attack_surface.push('user_input');
          ctx.neuralMap.nodes.push(n);
          ctx.lastCreatedNodeId = n.id;
          ctx.emitContainsIfNeeded(n.id);
        }
      }
      break;
    }

    // ── String Interpolation ──────────────────────────────────────────

    case 'line_string_literal':
    case 'multi_line_string_literal': {
      // Check if there's interpolation with tainted data
      let hasInterpolation = false;
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child?.type === 'interpolated_expression') {
          hasInterpolation = true;
          break;
        }
      }
      if (hasInterpolation) {
        const strNode = createNode({
          label: node.text.length > 50 ? node.text.slice(0, 47) + '...' : node.text,
          node_type: 'TRANSFORM',
          node_subtype: 'template_string',
          language: 'swift',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        ctx.neuralMap.nodes.push(strNode);
        ctx.lastCreatedNodeId = strNode.id;
        ctx.emitContainsIfNeeded(strNode.id);

        // Check if interpolated values are tainted
        for (let i = 0; i < node.childCount; i++) {
          const child = node.child(i);
          if (child?.type === 'interpolated_expression') {
            for (let j = 0; j < child.namedChildCount; j++) {
              const inner = child.namedChild(j);
              if (inner) {
                const taintSources = extractTaintSources(inner, ctx);
                for (const source of taintSources) {
                  ctx.addDataFlow(source.nodeId, strNode.id, source.name, 'unknown', true);
                  if (!strNode.data_out.some((d: any) => d.tainted)) {
                    strNode.data_out.push({
                      name: 'result',
                      source: strNode.id,
                      data_type: 'string',
                      tainted: true,
                      sensitivity: 'NONE',
                    });
                  }
                }
              }
            }
          }
        }
      }
      break;
    }

    // ── Control Flow ────────────────────────────────────────────────────

    case 'if_statement': {
      const ifN = createNode({
        label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(ifN);
      ctx.lastCreatedNodeId = ifN.id;
      ctx.emitContainsIfNeeded(ifN.id);
      break;
    }

    case 'guard_statement': {
      const guardN = createNode({
        label: 'guard', node_type: 'CONTROL', node_subtype: 'guard', language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      guardN.tags.push('guard');
      ctx.neuralMap.nodes.push(guardN);
      ctx.lastCreatedNodeId = guardN.id;
      ctx.emitContainsIfNeeded(guardN.id);
      break;
    }

    case 'switch_statement': {
      const switchN = createNode({
        label: 'switch', node_type: 'CONTROL', node_subtype: 'branch', language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(switchN);
      ctx.lastCreatedNodeId = switchN.id;
      ctx.emitContainsIfNeeded(switchN.id);
      break;
    }

    case 'for_statement': {
      const forN = createNode({
        label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(forN);
      ctx.lastCreatedNodeId = forN.id;
      ctx.emitContainsIfNeeded(forN.id);
      break;
    }

    case 'while_statement': {
      const whileN = createNode({
        label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(whileN);
      ctx.lastCreatedNodeId = whileN.id;
      ctx.emitContainsIfNeeded(whileN.id);
      break;
    }

    case 'do_statement': {
      const doN = createNode({
        label: 'do-catch', node_type: 'CONTROL', node_subtype: 'error_handler', language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(doN);
      ctx.lastCreatedNodeId = doN.id;
      ctx.emitContainsIfNeeded(doN.id);
      break;
    }

    // ── Control Transfer (return/break/continue/throw) ─────────────────

    case 'control_transfer_statement': {
      const kind = getTransferKind(node);
      if (kind === 'return') {
        const retN = createNode({
          label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'swift',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        ctx.neuralMap.nodes.push(retN);
        ctx.lastCreatedNodeId = retN.id;
        ctx.emitContainsIfNeeded(retN.id);
      } else if (kind === 'break') {
        const breakN = createNode({
          label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'swift',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        ctx.neuralMap.nodes.push(breakN);
        ctx.lastCreatedNodeId = breakN.id;
        ctx.emitContainsIfNeeded(breakN.id);
      } else if (kind === 'continue') {
        const contN = createNode({
          label: 'continue', node_type: 'CONTROL', node_subtype: 'continue', language: 'swift',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        ctx.neuralMap.nodes.push(contN);
        ctx.lastCreatedNodeId = contN.id;
        ctx.emitContainsIfNeeded(contN.id);
      } else if (kind === 'throw') {
        const throwN = createNode({
          label: 'throw', node_type: 'CONTROL', node_subtype: 'error_handler', language: 'swift',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        ctx.neuralMap.nodes.push(throwN);
        ctx.lastCreatedNodeId = throwN.id;
        ctx.emitContainsIfNeeded(throwN.id);
      }
      break;
    }

    // ── Try Expression ─────────────────────────────────────────────────

    case 'try_expression': {
      const tryN = createNode({
        label: 'try', node_type: 'CONTROL', node_subtype: 'error_handler', language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(tryN);
      ctx.lastCreatedNodeId = tryN.id;
      ctx.emitContainsIfNeeded(tryN.id);
      break;
    }

    // ── Await Expression ───────────────────────────────────────────────

    case 'await_expression': {
      const awaitN = createNode({
        label: 'await', node_type: 'CONTROL', node_subtype: 'await', language: 'swift',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      awaitN.tags.push('async');
      ctx.neuralMap.nodes.push(awaitN);
      ctx.lastCreatedNodeId = awaitN.id;
      ctx.emitContainsIfNeeded(awaitN.id);
      break;
    }

    // ── Assignment (Swift uses property_declaration for let/var,
    //    but direct assignment x = y uses assignment node) ─────────────

    case 'directly_assignable_expression': {
      // This is the left side of an assignment — handled by the parent
      break;
    }

    // ── Silent pass-throughs ────────────────────────────────────────────

    case 'source_file':
    case 'statements':
    case 'comment':
    case 'multiline_comment':
      break;
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'function_declaration' && node.type !== 'lambda_literal') return;

  const body = node.childForFieldName('body') ??
    node.children.find((c: SyntaxNode) => c.type === 'function_body');

  if (!body) return;

  // Find the statements node inside the function_body
  const stmts = body.children.find((c: SyntaxNode) => c.type === 'statements') ?? body;

  if (stmts) {
    // Check explicit return statements
    for (let i = 0; i < stmts.namedChildCount; i++) {
      const stmt = stmts.namedChild(i);
      if (stmt?.type === 'control_transfer_statement') {
        const kind = getTransferKind(stmt);
        if (kind === 'return') {
          const retExpr = stmt.namedChild(stmt.namedChildCount - 1);
          if (retExpr && retExpr.type !== 'return') {
            const taintSources = extractTaintSources(retExpr, ctx);
            if (taintSources.length > 0) {
              const funcNodeId = ctx.currentScope?.containerNodeId;
              if (funcNodeId) {
                const funcNode = ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId);
                if (funcNode && !funcNode.data_out.some((d: any) => d.tainted)) {
                  funcNode.data_out.push({
                    name: 'return', source: funcNode.id, data_type: 'unknown',
                    tainted: true, sensitivity: 'NONE',
                  });
                }
              }
            }
          }
        }
      }
    }

    // Check last expression as implicit return (single-expression functions)
    const lastChild = stmts.namedChild(stmts.namedChildCount - 1);
    if (lastChild && lastChild.type !== 'control_transfer_statement' &&
        lastChild.type !== 'property_declaration') {
      const taintSources = extractTaintSources(lastChild, ctx);
      if (taintSources.length > 0) {
        const funcNodeId = ctx.currentScope?.containerNodeId;
        if (funcNodeId) {
          const funcNode = ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId);
          if (funcNode && !funcNode.data_out.some((d: any) => d.tainted)) {
            funcNode.data_out.push({
              name: 'return', source: funcNode.id, data_type: 'unknown',
              tainted: true, sensitivity: 'NONE',
            });
          }
        }
      }
    }
  }

  // For closures with expression body: { expr }
  if (node.type === 'lambda_literal' && !body) {
    const statementsNode = node.children.find((c: SyntaxNode) => c.type === 'statements');
    if (statementsNode) {
      const lastChild = statementsNode.namedChild(statementsNode.namedChildCount - 1);
      if (lastChild) {
        const taintSources = extractTaintSources(lastChild, ctx);
        if (taintSources.length > 0) {
          const funcNodeId = ctx.currentScope?.containerNodeId;
          if (funcNodeId) {
            const funcNode = ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId);
            if (funcNode && !funcNode.data_out.some((d: any) => d.tainted)) {
              funcNode.data_out.push({
                name: 'return', source: funcNode.id, data_type: 'unknown',
                tainted: true, sensitivity: 'NONE',
              });
            }
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// preVisitIteration — set up loop variable taint before walking body
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_statement') return;

  // for_statement children: 'for', pattern, 'in', expression, '{', statements, '}'
  let patternNode: SyntaxNode | null = null;
  let valueNode: SyntaxNode | null = null;
  let foundIn = false;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === 'in' || child.text === 'in') {
      foundIn = true;
      continue;
    }
    if (!foundIn && child.type === 'pattern') {
      patternNode = child;
    }
    if (foundIn && child.type !== '{' && child.type !== 'statements' && child.type !== '}') {
      if (!valueNode) valueNode = child;
    }
  }

  if (!patternNode || !valueNode) return;

  const iterTaint = extractTaintSources(valueNode, ctx);
  if (iterTaint.length > 0) {
    const names = extractPatternNames(patternNode);
    for (const varName of names) {
      ctx.declareVariable(varName, 'let', null, true, iterTaint[0].nodeId);
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration — re-mark loop variable taint after body walk
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_statement') return;

  let patternNode: SyntaxNode | null = null;
  let valueNode: SyntaxNode | null = null;
  let foundIn = false;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === 'in' || child.text === 'in') {
      foundIn = true;
      continue;
    }
    if (!foundIn && child.type === 'pattern') {
      patternNode = child;
    }
    if (foundIn && child.type !== '{' && child.type !== 'statements' && child.type !== '}') {
      if (!valueNode) valueNode = child;
    }
  }

  if (!patternNode || !valueNode) return;

  const iterTaint = extractTaintSources(valueNode, ctx);
  if (iterTaint.length > 0) {
    const names = extractPatternNames(patternNode);
    for (const varName of names) {
      const v = ctx.resolveVariable(varName);
      if (v) {
        v.tainted = true;
        v.producingNodeId = iterTaint[0].nodeId;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// resolveCallee — wrapper that uses Swift callee chain extraction + lookup
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  if (node.type !== 'call_expression') return null;

  const chain = extractCalleeChain(node);
  const pattern = _lookupSwiftCallee(chain);
  if (!pattern) return null;

  return {
    nodeType: pattern.nodeType,
    subtype: pattern.subtype,
    tainted: pattern.tainted,
    chain,
  };
}

// ---------------------------------------------------------------------------
// resolvePropertyAccess — for standalone navigation_expression
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  if (node.type !== 'navigation_expression') return null;

  const chain = extractCalleeChain(node);
  const key = chain.join('.');

  if (TAINTED_PATHS.has(key)) {
    return {
      nodeType: 'INGRESS',
      subtype: 'http_request',
      tainted: true,
    };
  }

  // Check callee DB for non-tainted property access patterns
  const pattern = _lookupSwiftCallee(chain);
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
// analyzeStructure — Swift structural patterns (Vapor routes, middleware)
// ---------------------------------------------------------------------------

function analyzeStructure(node: SyntaxNode): StructuralAnalysisResult | null {
  if (node.type !== 'call_expression') return null;

  const chain = extractCalleeChain(node);
  const methodName = chain[chain.length - 1];
  const receiverName = chain.length > 1 ? chain[0] : '';

  // Detect Vapor route definitions: app.get, app.post, etc.
  const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch'];
  if (receiverName === 'app' && HTTP_METHODS.includes(methodName ?? '')) {
    const callSuffix = node.children.find((c: SyntaxNode) => c.type === 'call_suffix');
    const argsNode = callSuffix?.children.find((c: SyntaxNode) => c.type === 'value_arguments');
    const firstArg = argsNode?.namedChild(0);
    let routePath: string | null = null;
    if (firstArg) {
      routePath = firstArg.text.replace(/["']/g, '') ?? null;
    }

    return {
      middlewareNames: [],
      hasAuthGate: false,
      hasRateLimiter: false,
      hasCsrfProtection: false,
      hasValidation: false,
      routePath,
      httpMethod: methodName?.toUpperCase() ?? null,
    };
  }

  // Detect middleware: app.middleware.use(...)
  if (methodName === 'use' && chain.includes('middleware')) {
    const callSuffix = node.children.find((c: SyntaxNode) => c.type === 'call_suffix');
    const argsNode = callSuffix?.children.find((c: SyntaxNode) => c.type === 'value_arguments');
    const middlewareNames: string[] = [];
    let hasAuthGate = false;
    let hasRateLimiter = false;
    let hasCsrfProtection = false;
    let hasValidation = false;

    if (argsNode) {
      const argText = argsNode.text.toLowerCase();
      middlewareNames.push(argText.slice(1, -1).trim().slice(0, 50));

      if (argText.includes('auth') || argText.includes('jwt') || argText.includes('bearer')) {
        hasAuthGate = true;
      }
      if (argText.includes('rate') || argText.includes('throttle')) {
        hasRateLimiter = true;
      }
      if (argText.includes('csrf') || argText.includes('xsrf')) {
        hasCsrfProtection = true;
      }
      if (argText.includes('valid')) {
        hasValidation = true;
      }
    }

    return {
      middlewareNames,
      hasAuthGate,
      hasRateLimiter,
      hasCsrfProtection,
      hasValidation,
      routePath: null,
      httpMethod: null,
    };
  }

  // Detect route grouping: app.grouped(...)
  if (methodName === 'grouped' && receiverName === 'app') {
    const callSuffix = node.children.find((c: SyntaxNode) => c.type === 'call_suffix');
    const argsNode = callSuffix?.children.find((c: SyntaxNode) => c.type === 'value_arguments');
    const firstArg = argsNode?.namedChild(0);
    const routePath = firstArg?.text?.replace(/["']/g, '') ?? null;

    return {
      middlewareNames: [],
      hasAuthGate: false,
      hasRateLimiter: false,
      hasCsrfProtection: false,
      hasValidation: false,
      routePath,
      httpMethod: null,
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// The Profile
// ---------------------------------------------------------------------------

export const swiftProfile: LanguageProfile = {
  id: 'swift',
  extensions: ['.swift'],

  // Layer 1: AST Node Type Recognition
  functionScopeTypes: FUNCTION_SCOPE_TYPES,
  blockScopeTypes: BLOCK_SCOPE_TYPES,
  classScopeTypes: CLASS_SCOPE_TYPES,

  getScopeType(node: SyntaxNode): ScopeType | null {
    if (FUNCTION_SCOPE_TYPES.has(node.type)) return 'function';
    if (CLASS_SCOPE_TYPES.has(node.type)) return 'class';
    if (BLOCK_SCOPE_TYPES.has(node.type)) return 'block';
    return null;
  },

  variableDeclarationTypes: VARIABLE_DECLARATION_TYPES,
  functionDeclarationTypes: FUNCTION_DECLARATION_TYPES,

  // Layer 2: AST Child Access
  processVariableDeclaration,
  processFunctionParams,
  extractPatternNames,

  // Layer 3: Callee Resolution (Phoneme Dictionary)
  resolveCallee,
  resolvePropertyAccess,

  lookupCallee(chain: string[]): CalleePattern | null {
    return _lookupSwiftCallee(chain);
  },

  analyzeStructure,

  // Layer 4: Taint Source Detection
  ingressPattern: /(?:readLine\s*\(|req\.content\.decode|req\.query\.decode|req\.parameters\.get|req\.body|req\.headers|req\.cookies|req\.session|request\.content|request\.query|request\.parameters|request\.headers|request\.body|URLSession\.shared\.data|URLSession\.shared\.dataTask|CommandLine\.arguments|UIPasteboard\.general\.string|UIPasteboard\.general\.url|textField\.text|textView\.text|searchBar\.text|ProcessInfo\.processInfo\.environment)/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) => nodeType === 'property_declaration',
  getDeclarationValueNode: (node) => node.childForFieldName('value'),
  isStatementContainer: (nodeType: string) => nodeType === 'source_file' || nodeType === 'statements',

  // Swift function parameter pattern for inter-procedural taint
  functionParamPattern: /func\s+\w+\s*(?:<[^>]*>)?\s*\(([^)]*)\)/,
};

export default swiftProfile;
