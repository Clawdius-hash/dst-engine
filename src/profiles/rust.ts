/**
 * RustProfile — the third LanguageProfile implementation.
 *
 * Every piece of Rust-specific logic lives here: AST node type names,
 * field access patterns, scope rules, callee resolution, taint extraction,
 * and node classification.
 *
 * Key differences from JavaScript:
 *   - `function_item` not `function_declaration`
 *   - `let_declaration` not `lexical_declaration`
 *   - `call_expression` same name, but `macro_invocation` is separate
 *   - `field_expression` not `member_expression` (receiver.method)
 *   - `scoped_identifier` for `module::function` paths (e.g., `std::io::stdin`)
 *   - `impl_item` creates method scopes
 *   - `match_expression` not `switch_statement`
 *   - `if_expression` (Rust ifs are expressions)
 *   - Rust has `unsafe_block` as a distinct AST node
 *   - `closure_expression` not `arrow_function`
 *   - No `var` keyword — only `let` and `const` (statics)
 *   - Ownership/borrowing does NOT affect taint tracking (taint follows data)
 *   - Macros (println!, format!, sql!) appear as `macro_invocation` nodes
 *   - Error handling via Result/Option — `.unwrap()` paths
 *
 * tree-sitter-rust AST reference: https://github.com/tree-sitter/tree-sitter-rust
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
import { lookupCallee as _lookupRustCallee } from '../languages/rust.js';
import { isNeutralizingSubtype } from '../properties/neutralizers.js';
import { extractStorageMetadata } from '../extractStorageMetadata.js';
import { classifyTrustBoundary } from '../trustBoundary.js';

// ---------------------------------------------------------------------------
// AST Node Type Sets (tree-sitter-rust)
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'function_item',
  'closure_expression',
  'impl_item',        // impl blocks create a scope for methods
  'trait_item',       // trait blocks create a scope for default methods
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'block',               // { ... }
  'if_expression',
  'else_clause',
  'for_expression',
  'while_expression',
  'loop_expression',
  'match_expression',
  'match_arm',
  'unsafe_block',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'struct_item',
  'enum_item',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'let_declaration',
  'const_item',
  'static_item',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'function_item',
]);

// Tainted paths for Rust web frameworks
const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // actix-web
  'req.headers', 'req.uri', 'req.cookie', 'req.peer_addr',
  'req.match_info', 'req.head', 'req.path', 'req.query_string',
  'req.content_type',
  'HttpRequest.headers', 'HttpRequest.uri', 'HttpRequest.cookie',
  'HttpRequest.peer_addr', 'HttpRequest.match_info', 'HttpRequest.path',
  'HttpRequest.query_string', 'HttpRequest.content_type',
]);

// Actix-web / Axum / Rocket extractor type names that indicate tainted function params
const RUST_WEB_EXTRACTORS: ReadonlySet<string> = new Set([
  'Json', 'Path', 'Query', 'Form', 'Bytes', 'Payload',
  'Multipart', 'BodyStream', 'RawBody',
  'web::Json', 'web::Path', 'web::Query', 'web::Form',
  'web::Bytes', 'web::Payload',
  'extract::Json', 'extract::Path', 'extract::Query',
  'extract::Form', 'extract::Multipart',
  'extract::ConnectInfo', 'extract::Host', 'extract::OriginalUri',
  'TypedHeader',
]);

// Non-tainted extractors (state, data, etc.)
const RUST_SAFE_EXTRACTORS: ReadonlySet<string> = new Set([
  'Data', 'State', 'web::Data', 'extract::State',
]);

// ---------------------------------------------------------------------------
// Helper: extract callee chain from Rust AST nodes
// ---------------------------------------------------------------------------

/**
 * Extract the callee chain from a Rust expression.
 * Handles:
 *   - identifier: `stdin` -> ['stdin']
 *   - field_expression: `stdin.read_line` -> ['stdin', 'read_line']
 *   - scoped_identifier: `std::io::stdin` -> ['std', 'io', 'stdin'] or joined as key
 *   - call_expression chains: `client.get(url).send()` -> resolves terminal method
 */
function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier') {
    return [node.text];
  }

  if (node.type === 'field_expression') {
    const value = node.childForFieldName('value');
    const field = node.childForFieldName('field');
    if (value && field) {
      const chain = extractCalleeChain(value);
      chain.push(field.text);
      return chain;
    }
  }

  if (node.type === 'scoped_identifier') {
    // e.g., std::io::stdin, serde_json::from_str
    const parts: string[] = [];
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type !== '::') {
        if (child.type === 'scoped_identifier') {
          parts.push(...extractCalleeChain(child));
        } else {
          parts.push(child.text);
        }
      }
    }
    return parts;
  }

  // For generic_function (turbofish): path::<Type> -> extract the path
  if (node.type === 'generic_function') {
    const fn = node.childForFieldName('function');
    if (fn) return extractCalleeChain(fn);
  }

  // Chained call: a.b().c() - the 'function' child of the outer call is a field_expression
  // whose 'value' is the inner call_expression
  if (node.type === 'call_expression') {
    const fn = node.childForFieldName('function');
    if (fn) return extractCalleeChain(fn);
  }

  return [node.text.slice(0, 50)];
}

// ---------------------------------------------------------------------------
// Helper: resolve a macro invocation name
// ---------------------------------------------------------------------------

function extractMacroName(node: SyntaxNode): string {
  // macro_invocation has a 'macro' field which is the macro name (e.g., println, format)
  const macroField = node.childForFieldName('macro');
  if (macroField) {
    // Strip trailing '!' from the macro name
    const name = macroField.text.replace(/!$/, '');
    return name;
  }
  // Fallback: first child is usually the macro name
  const firstChild = node.child(0);
  if (firstChild) {
    return firstChild.text.replace(/!$/, '');
  }
  return 'unknown_macro';
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
// extractPatternNames — extract variable names from Rust patterns
// ---------------------------------------------------------------------------

/**
 * Rust patterns include:
 *   - identifier: `x`
 *   - tuple_pattern: `(a, b)`
 *   - struct_pattern: `Point { x, y }`
 *   - tuple_struct_pattern: `Some(val)`
 *   - slice_pattern: `[first, .., last]`
 *   - ref_pattern: `ref x` or `&x`
 *   - mut_pattern: `mut x`
 *   - or_pattern: `A | B`
 *   - _pattern: `_`
 */
function extractPatternNames(pattern: SyntaxNode): string[] {
  const names: string[] = [];

  switch (pattern.type) {
    case 'identifier':
      if (pattern.text !== '_') names.push(pattern.text);
      break;

    case 'tuple_pattern':
    case 'slice_pattern':
    case 'or_pattern':
      for (let i = 0; i < pattern.namedChildCount; i++) {
        const child = pattern.namedChild(i);
        if (child) names.push(...extractPatternNames(child));
      }
      break;

    case 'struct_pattern':
      // struct_pattern -> field_pattern children
      for (let i = 0; i < pattern.namedChildCount; i++) {
        const child = pattern.namedChild(i);
        if (!child) continue;
        if (child.type === 'field_pattern') {
          const name = child.childForFieldName('name');
          const pat = child.childForFieldName('pattern');
          if (pat) {
            names.push(...extractPatternNames(pat));
          } else if (name && name.type === 'identifier') {
            names.push(name.text);
          }
        } else if (child.type === 'shorthand_field_identifier') {
          names.push(child.text);
        } else {
          names.push(...extractPatternNames(child));
        }
      }
      break;

    case 'tuple_struct_pattern':
      // e.g., Some(val), Ok(data)
      for (let i = 0; i < pattern.namedChildCount; i++) {
        const child = pattern.namedChild(i);
        if (child && child.type !== 'identifier') {
          // Skip the struct/enum name, extract inner patterns
          names.push(...extractPatternNames(child));
        } else if (child && child.type === 'identifier') {
          // Could be the name (e.g., Some) or a binding — check position
          // First identifier is usually the constructor name
          if (i > 0) names.push(child.text);
        }
      }
      break;

    case 'ref_pattern':
    case 'mut_pattern':
    case 'reference_pattern': {
      // ref x, mut x, &x — the inner identifier is the binding
      const inner = pattern.namedChild(0);
      if (inner) names.push(...extractPatternNames(inner));
      break;
    }

    case 'captured_pattern': {
      // `name @ pattern`
      const binding = pattern.childForFieldName('pattern');
      if (binding) names.push(...extractPatternNames(binding));
      // Also the identifier before @
      for (let i = 0; i < pattern.namedChildCount; i++) {
        const child = pattern.namedChild(i);
        if (child?.type === 'identifier') {
          names.push(child.text);
          break;
        }
      }
      break;
    }

    case '_':
    case 'rest_pattern':
    case 'range_pattern':
      // No bindings
      break;

    default:
      // Try to find identifiers in unknown patterns
      for (let i = 0; i < pattern.namedChildCount; i++) {
        const child = pattern.namedChild(i);
        if (child?.type === 'identifier' && child.text !== '_') {
          names.push(child.text);
        }
      }
      break;
  }

  return names;
}

// ---------------------------------------------------------------------------
// extractTaintSources — recursive expression X-ray for Rust
// ---------------------------------------------------------------------------

function extractTaintSources(expr: SyntaxNode, ctx: MapperContextLike): TaintSourceResult[] {
  if (!expr) return [];

  switch (expr.type) {
    // -- Leaf: identifier -- check if tainted variable
    case 'identifier': {
      const varInfo = ctx.resolveVariable(expr.text);
      if (varInfo?.tainted && varInfo.producingNodeId) {
        return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
      }
      return [];
    }

    // -- field_expression: req.body, data.field --
    case 'field_expression': {
      const chain = extractCalleeChain(expr);
      const key = chain.join('.');
      if (TAINTED_PATHS.has(key)) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: 'INGRESS',
          node_subtype: 'http_request',
          trust_boundary: classifyTrustBoundary('INGRESS', 'http_request'),
          language: 'rust',
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
      // Check if receiver object is a tainted variable
      const valueNode = expr.childForFieldName('value');
      if (valueNode?.type === 'identifier') {
        const varInfo = ctx.resolveVariable(valueNode.text);
        if (varInfo?.tainted && varInfo.producingNodeId) {
          return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
        }
      }
      // Recurse into deeper chains
      if (valueNode?.type === 'field_expression') {
        return extractTaintSources(valueNode, ctx);
      }
      return [];
    }

    // -- Binary expression: string + string, arithmetic --
    case 'binary_expression': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const sources: TaintSourceResult[] = [];
      if (left) sources.push(...extractTaintSources(left, ctx));
      if (right) sources.push(...extractTaintSources(right, ctx));
      return sources;
    }

    // -- Call expression: function(tainted_data) --
    case 'call_expression': {
      const callChain = extractCalleeChain(expr);
      const callResolution = _lookupRustCallee(callChain);
      // Neutralizing calls (sanitize, encode, etc.) break taint
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          isNeutralizingSubtype(callResolution.subtype)) {
        return [];
      }
      // Check arguments for taint
      const sources: TaintSourceResult[] = [];
      const args = expr.childForFieldName('arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (arg) sources.push(...extractTaintSources(arg, ctx));
        }
      }
      // Check receiver for taint
      const fn = expr.childForFieldName('function');
      if (fn?.type === 'field_expression') {
        const receiver = fn.childForFieldName('value');
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

    // -- Macro invocation: format!(tainted), sql!(tainted) --
    case 'macro_invocation': {
      const sources: TaintSourceResult[] = [];
      // Check all children of the token_tree for taint
      const tokenTree = expr.children.find((c: SyntaxNode) => c.type === 'token_tree');
      if (tokenTree) {
        for (let i = 0; i < tokenTree.namedChildCount; i++) {
          const child = tokenTree.namedChild(i);
          if (child) sources.push(...extractTaintSources(child, ctx));
        }
      }
      return sources;
    }

    // -- Reference: &expr or &mut expr --
    case 'reference_expression': {
      const inner = expr.childForFieldName('value') ?? expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Dereference: *expr --
    case 'unary_expression': {
      const op = expr.childForFieldName('operator')?.text ?? '';
      if (op === '*' || op === '!' || op === '-') {
        const arg = expr.namedChild(expr.namedChildCount - 1);
        return arg ? extractTaintSources(arg, ctx) : [];
      }
      return [];
    }

    // -- Borrow: &x, &mut x --
    case 'borrow_expression': {
      const inner = expr.namedChild(expr.namedChildCount - 1);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Parenthesized: (expr) --
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Await: expr.await --
    case 'await_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Try: expr? --
    case 'try_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Block expression: { ...; expr } -- last expression is the value
    case 'block': {
      const lastChild = expr.namedChild(expr.namedChildCount - 1);
      return lastChild ? extractTaintSources(lastChild, ctx) : [];
    }

    // -- If expression: if cond { tainted } else { safe } --
    case 'if_expression': {
      const sources: TaintSourceResult[] = [];
      const consequence = expr.childForFieldName('consequence');
      const alternative = expr.childForFieldName('alternative');
      if (consequence) sources.push(...extractTaintSources(consequence, ctx));
      if (alternative) sources.push(...extractTaintSources(alternative, ctx));
      return sources;
    }

    // -- Match expression: match x { Pat => tainted, ... } --
    case 'match_expression': {
      const sources: TaintSourceResult[] = [];
      const body = expr.childForFieldName('body');
      if (body) {
        for (let i = 0; i < body.namedChildCount; i++) {
          const arm = body.namedChild(i);
          if (arm?.type === 'match_arm') {
            const value = arm.childForFieldName('value');
            if (value) sources.push(...extractTaintSources(value, ctx));
          }
        }
      }
      return sources;
    }

    // -- Closure: |x| expr --
    case 'closure_expression': {
      const body = expr.childForFieldName('body');
      return body ? extractTaintSources(body, ctx) : [];
    }

    // -- Tuple expression: (a, b, c) --
    case 'tuple_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Array expression: [a, b, c] --
    case 'array_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Struct expression: MyStruct { field: tainted } --
    case 'struct_expression': {
      const sources: TaintSourceResult[] = [];
      const body = expr.childForFieldName('body');
      if (body) {
        for (let i = 0; i < body.namedChildCount; i++) {
          const field = body.namedChild(i);
          if (field?.type === 'field_initializer') {
            const value = field.childForFieldName('value');
            if (value) sources.push(...extractTaintSources(value, ctx));
          } else if (field?.type === 'shorthand_field_initializer') {
            // { field } shorthand — the field name IS the variable name
            const varInfo = ctx.resolveVariable(field.text);
            if (varInfo?.tainted && varInfo.producingNodeId) {
              sources.push({ nodeId: varInfo.producingNodeId, name: field.text });
            }
          }
        }
      }
      return sources;
    }

    // -- Type cast: expr as Type --
    case 'type_cast_expression': {
      const inner = expr.childForFieldName('value');
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Index expression: arr[i] --
    case 'index_expression': {
      const obj = expr.namedChild(0);
      return obj ? extractTaintSources(obj, ctx) : [];
    }

    // -- Range expression: a..b --
    case 'range_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Scoped identifier: module::item (could be a tainted path) --
    case 'scoped_identifier': {
      const chain = extractCalleeChain(expr);
      const key = chain.join('::');
      // Check for tainted paths in scoped form
      const pattern = _lookupRustCallee(chain);
      if (pattern?.tainted) {
        return [{ nodeId: '', name: key }]; // nodeId will be set by caller
      }
      return [];
    }

    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration — handle let, const, static
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'let_declaration' && node.type !== 'const_item' && node.type !== 'static_item') {
    return;
  }

  const kind: VariableInfo['kind'] =
    node.type === 'const_item' ? 'const' :
    node.type === 'static_item' ? 'const' :
    'let';

  // For let_declaration: `let [mut] pattern [: type] = value;`
  // For const_item: `const NAME: Type = value;`
  // For static_item: `static [mut] NAME: Type = value;`

  const patternNode = node.childForFieldName('pattern') ?? node.childForFieldName('name');
  if (!patternNode) return;

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
    if (valueNode.type === 'identifier') {
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

  // Cross-function taint: let val = get_input(&req)
  if (!producingNodeId && valueNode?.type === 'call_expression') {
    const fn = valueNode.childForFieldName('function');
    if (fn?.type === 'identifier') {
      const funcNodeId = ctx.functionRegistry.get(fn.text);
      if (funcNodeId) {
        const ingressInFunc = findIngressInFunction(funcNodeId, ctx);
        if (ingressInFunc) {
          tainted = true;
          producingNodeId = ingressInFunc;
        }
      }
    }
  }

  // Alias chain detection: let q = db.query
  let aliasChain: string[] | undefined;
  if (valueNode?.type === 'field_expression') {
    aliasChain = extractCalleeChain(valueNode);
  } else if (valueNode?.type === 'scoped_identifier') {
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

  if (patternNode.type === 'identifier') {
    preserveTaint(patternNode.text, tainted, producingNodeId);
  } else if (patternNode.type === 'mut_pattern') {
    // `let mut x = ...`
    const inner = patternNode.namedChild(0);
    if (inner?.type === 'identifier') {
      preserveTaint(inner.text, tainted, producingNodeId);
    }
  } else {
    // Destructuring patterns
    const names = extractPatternNames(patternNode);
    for (const n of names) {
      preserveTaint(n, tainted, producingNodeId);
    }
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
   * In Rust, extractors like Json<T>, Path<T>, Query<T> are function params.
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
      trust_boundary: classifyTrustBoundary('INGRESS', 'http_request'),
      language: 'rust',
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

  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) return;

  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    // Skip self parameters
    if (param.type === 'self_parameter') continue;

    if (param.type === 'parameter') {
      const patternField = param.childForFieldName('pattern');
      const typeField = param.childForFieldName('type');

      const paramName = patternField?.type === 'identifier'
        ? patternField.text
        : patternField?.type === 'mut_pattern'
          ? patternField.namedChild(0)?.text
          : null;

      if (!paramName) {
        // Destructuring param - extract all names
        if (patternField) {
          const names = extractPatternNames(patternField);
          for (const n of names) declareParam(n);
        }
        continue;
      }

      // Check if the type is a known web extractor
      const typeText = typeField?.text ?? '';
      const isExtractor = RUST_WEB_EXTRACTORS.has(typeText.split('<')[0].trim()) ||
        RUST_WEB_EXTRACTORS.has(typeText.split('(')[0].trim());
      const isSafeExtractor = RUST_SAFE_EXTRACTORS.has(typeText.split('<')[0].trim());

      if (isExtractor && !isSafeExtractor) {
        declareTaintedExtractorParam(paramName, param);
      } else {
        declareParam(paramName);
      }
    } else if (param.type === 'identifier') {
      // Closure parameter without type annotation
      declareParam(param.text);
    }
  }
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of the walk switch statement
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  // Hoist function declarations to outer scope
  if (node.type === 'function_item') {
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

    case 'function_item': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const isAsync = node.text.trimStart().startsWith('async');
      const fnNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'rust',
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

    case 'closure_expression': {
      let closureName = 'anonymous';
      // Check if assigned to a variable: let handler = |req| { ... }
      if (
        node.parent?.type === 'let_declaration' &&
        node.parent.childForFieldName('pattern')?.type === 'identifier'
      ) {
        closureName = node.parent.childForFieldName('pattern')!.text;
      }
      const closureNode = createNode({
        label: closureName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'rust',
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

    // ── Structs, Enums, Impls, Traits ──────────────────────────────────

    case 'struct_item': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousStruct';
      const structNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'rust',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(structNode);
      ctx.lastCreatedNodeId = structNode.id;
      ctx.emitContainsIfNeeded(structNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = structNode.id;
      break;
    }

    case 'enum_item': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousEnum';
      const enumNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'rust',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      enumNode.tags.push('enum');
      ctx.neuralMap.nodes.push(enumNode);
      ctx.lastCreatedNodeId = enumNode.id;
      ctx.emitContainsIfNeeded(enumNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = enumNode.id;
      break;
    }

    case 'impl_item': {
      const typeName = node.childForFieldName('type')?.text ?? 'impl';
      const traitName = node.childForFieldName('trait')?.text;
      const label = traitName ? `impl ${traitName} for ${typeName}` : `impl ${typeName}`;
      const implNode = createNode({
        label,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'rust',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      implNode.tags.push('impl');
      ctx.neuralMap.nodes.push(implNode);
      ctx.lastCreatedNodeId = implNode.id;
      ctx.emitContainsIfNeeded(implNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = implNode.id;
      break;
    }

    case 'trait_item': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousTrait';
      const traitNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'rust',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      traitNode.tags.push('trait');
      ctx.neuralMap.nodes.push(traitNode);
      ctx.lastCreatedNodeId = traitNode.id;
      ctx.emitContainsIfNeeded(traitNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = traitNode.id;
      break;
    }

    // ── Imports ─────────────────────────────────────────────────────────

    case 'use_declaration': {
      // use std::io::stdin;
      const argNode = node.childForFieldName('argument');
      const moduleName = argNode?.text ?? 'unknown';
      const importNode = createNode({
        label: moduleName,
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'rust',
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

    case 'mod_item': {
      const name = node.childForFieldName('name')?.text ?? 'mod';
      const modNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'module',
        language: 'rust',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(modNode);
      ctx.lastCreatedNodeId = modNode.id;
      ctx.emitContainsIfNeeded(modNode.id);
      break;
    }

    // ── Call Expressions ────────────────────────────────────────────────

    case 'call_expression': {
      const chain = extractCalleeChain(node);
      const resolution = _lookupRustCallee(chain);

      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'rust',
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
          n.attack_surface.push(resolution.subtype === 'env_read' ? 'environment' : 'user_input');
        }
        if (resolution.nodeType === 'EXTERNAL' && resolution.subtype === 'exec') {
          n.attack_surface.push('command_injection');
        }
        ctx.neuralMap.nodes.push(n);
        ctx.lastCreatedNodeId = n.id;
        ctx.emitContainsIfNeeded(n.id);
        n.callee_chain = chain;
        const _storageTarget = extractStorageMetadata(node, { ...resolution, chain });
        if (_storageTarget) n.metadata.storage_target = _storageTarget;
        n.trust_boundary = classifyTrustBoundary(n.node_type, n.node_subtype);

        // Data flow: extract tainted arguments
        const argsNode = node.childForFieldName('arguments');
        let callHasTaintedArgs = false;
        if (argsNode) {
          for (let a = 0; a < argsNode.namedChildCount; a++) {
            const arg = argsNode.namedChild(a);
            if (!arg) continue;
            const taintSources = extractTaintSources(arg, ctx);
            if (taintSources.length > 0) callHasTaintedArgs = true;
            for (const source of taintSources) {
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
            }
          }
        }

        // Receiver taint: for method calls on tainted objects
        const calleeExpr = node.childForFieldName('function');
        if (calleeExpr?.type === 'field_expression') {
          const receiver = calleeExpr.childForFieldName('value');
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
          const callArgs = node.childForFieldName('arguments');
          if (callArgs) {
            for (let ai = 0; ai < callArgs.namedChildCount; ai++) {
              const arg = callArgs.namedChild(ai);
              if (arg?.type === 'closure_expression') {
                const params = arg.childForFieldName('parameters');
                if (params) {
                  for (let pi = 0; pi < params.namedChildCount; pi++) {
                    const p = params.namedChild(pi);
                    if (p?.type === 'identifier') ctx.pendingCallbackTaint.set(p.text, n.id);
                  }
                }
              }
            }
          }
        }
      } else {
        // Unresolved call — check if locally defined function
        const calleeNode = node.childForFieldName('function');
        let calleeName: string | null = null;
        if (calleeNode?.type === 'identifier') {
          calleeName = calleeNode.text;
        } else if (calleeNode?.type === 'field_expression') {
          calleeName = calleeNode.childForFieldName('field')?.text ?? null;
        } else if (calleeNode?.type === 'scoped_identifier') {
          // Take the last segment
          calleeName = calleeNode.namedChild(calleeNode.namedChildCount - 1)?.text ?? null;
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
            language: 'rust',
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

        // Variable alias resolution: let q = db.query -> q() resolves as db.query
        if (calleeNode?.type === 'identifier') {
          const aliasVar = ctx.resolveVariable(calleeNode.text);
          if (aliasVar?.aliasChain) {
            const aliasPattern = _lookupRustCallee(aliasVar.aliasChain);
            if (aliasPattern) {
              const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const aliasN = createNode({
                label,
                node_type: aliasPattern.nodeType,
                node_subtype: aliasPattern.subtype,
                language: 'rust',
                file: ctx.neuralMap.source_file,
                line_start: node.startPosition.row + 1,
                line_end: node.endPosition.row + 1,
                code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
              });
              if (aliasPattern.nodeType === 'EXTERNAL' && aliasPattern.subtype === 'exec') {
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

    // ── Macro Invocations ───────────────────────────────────────────────

    case 'macro_invocation': {
      const macroName = extractMacroName(node);
      const directPattern = _lookupRustCallee([macroName]);

      if (directPattern) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: directPattern.nodeType,
          node_subtype: directPattern.subtype,
          language: 'rust',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        n.tags.push('macro');
        ctx.neuralMap.nodes.push(n);
        ctx.lastCreatedNodeId = n.id;
        ctx.emitContainsIfNeeded(n.id);

        // Check token_tree for tainted data
        const tokenTree = node.children.find((c: SyntaxNode) => c.type === 'token_tree');
        if (tokenTree) {
          for (let i = 0; i < tokenTree.namedChildCount; i++) {
            const arg = tokenTree.namedChild(i);
            if (!arg) continue;
            const taintSources = extractTaintSources(arg, ctx);
            for (const source of taintSources) {
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
              // Taint-through for macros that produce output
              if (!n.data_out.some((d: any) => d.tainted)) {
                n.data_out.push({
                  name: 'result',
                  source: n.id,
                  data_type: 'unknown',
                  tainted: true,
                  sensitivity: 'NONE',
                });
              }
            }
          }
        }
      } else {
        // Unknown macro — still emit a node for it
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const macroNode = createNode({
          label,
          node_type: 'TRANSFORM',
          node_subtype: 'macro',
          language: 'rust',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        macroNode.tags.push('macro');
        ctx.neuralMap.nodes.push(macroNode);
        ctx.lastCreatedNodeId = macroNode.id;
        ctx.emitContainsIfNeeded(macroNode.id);
      }
      break;
    }

    // ── Field Expression (standalone property access) ────────────────────

    case 'field_expression': {
      // Only classify if NOT the callee of a call_expression
      const funcNode = node.parent?.childForFieldName('function');
      const parentIsCall = node.parent?.type === 'call_expression' &&
        funcNode != null &&
        funcNode.startIndex === node.startIndex;
      if (!parentIsCall) {
        const chain = extractCalleeChain(node);
        const key = chain.join('.');
        if (TAINTED_PATHS.has(key)) {
          const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
          const n = createNode({
            label,
            node_type: 'INGRESS',
            node_subtype: 'http_request',
            trust_boundary: classifyTrustBoundary('INGRESS', 'http_request'),
            language: 'rust',
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

    // ── Unsafe Block ────────────────────────────────────────────────────

    case 'unsafe_block': {
      const unsafeNode = createNode({
        label: 'unsafe',
        node_type: 'EXTERNAL',
        node_subtype: 'unsafe',
        language: 'rust',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      unsafeNode.tags.push('unsafe');
      unsafeNode.attack_surface.push('memory_safety');
      ctx.neuralMap.nodes.push(unsafeNode);
      ctx.lastCreatedNodeId = unsafeNode.id;
      ctx.emitContainsIfNeeded(unsafeNode.id);
      break;
    }

    // ── Control Flow ────────────────────────────────────────────────────

    case 'if_expression': {
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      break;
    }

    case 'match_expression': {
      const matchN = createNode({ label: 'match', node_type: 'CONTROL', node_subtype: 'branch', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(matchN); ctx.lastCreatedNodeId = matchN.id; ctx.emitContainsIfNeeded(matchN.id);
      break;
    }

    case 'for_expression': {
      const forN = createNode({ label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      break;
    }

    case 'while_expression': {
      const whileN = createNode({ label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whileN); ctx.lastCreatedNodeId = whileN.id; ctx.emitContainsIfNeeded(whileN.id);
      break;
    }

    case 'loop_expression': {
      const loopN = createNode({ label: 'loop', node_type: 'CONTROL', node_subtype: 'loop', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(loopN); ctx.lastCreatedNodeId = loopN.id; ctx.emitContainsIfNeeded(loopN.id);
      break;
    }

    // ── Return/Break/Continue ───────────────────────────────────────────

    case 'return_expression': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }

    case 'break_expression': {
      const breakN = createNode({ label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(breakN); ctx.lastCreatedNodeId = breakN.id; ctx.emitContainsIfNeeded(breakN.id);
      break;
    }

    case 'continue_expression': {
      const contN = createNode({ label: 'continue', node_type: 'CONTROL', node_subtype: 'continue', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(contN); ctx.lastCreatedNodeId = contN.id; ctx.emitContainsIfNeeded(contN.id);
      break;
    }

    // ── Await ───────────────────────────────────────────────────────────

    case 'await_expression': {
      const awaitN = createNode({ label: 'await', node_type: 'CONTROL', node_subtype: 'await', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      awaitN.tags.push('async');
      ctx.neuralMap.nodes.push(awaitN); ctx.lastCreatedNodeId = awaitN.id; ctx.emitContainsIfNeeded(awaitN.id);
      break;
    }

    // ── Try expression (?) ──────────────────────────────────────────────

    case 'try_expression': {
      const tryN = createNode({ label: '?', node_type: 'CONTROL', node_subtype: 'error_handler', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      tryN.tags.push('result-propagation');
      ctx.neuralMap.nodes.push(tryN); ctx.lastCreatedNodeId = tryN.id; ctx.emitContainsIfNeeded(tryN.id);
      break;
    }

    // ── Assignment ──────────────────────────────────────────────────────

    case 'assignment_expression': {
      const assignLeft = node.childForFieldName('left');
      const leftText = assignLeft?.text?.slice(0, 40) ?? '?';
      const assignN = createNode({ label: `${leftText} =`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(assignN); ctx.lastCreatedNodeId = assignN.id; ctx.emitContainsIfNeeded(assignN.id);

      const assignRight = node.childForFieldName('right');
      if (assignRight) {
        const taintSources = extractTaintSources(assignRight, ctx);
        if (taintSources.length > 0) {
          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, assignN.id, source.name, 'unknown', true);
          }
          if (assignLeft?.type === 'identifier') {
            const varInfo = ctx.resolveVariable(assignLeft.text);
            if (varInfo) {
              varInfo.tainted = true;
              varInfo.producingNodeId = assignN.id;
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

    case 'compound_assignment_expr': {
      const augLeft = node.childForFieldName('left');
      const augOp = node.children.find((c: SyntaxNode) => c.type.endsWith('=') && c.type !== 'identifier')?.text ?? '+=';
      const augLeftText = augLeft?.text?.slice(0, 40) ?? '?';
      const augN = createNode({ label: `${augLeftText} ${augOp}`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(augN); ctx.lastCreatedNodeId = augN.id; ctx.emitContainsIfNeeded(augN.id);

      const augRight = node.childForFieldName('right');
      if (augRight) {
        const taintSources = extractTaintSources(augRight, ctx);
        if (taintSources.length > 0) {
          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, augN.id, source.name, 'unknown', true);
          }
          if (augLeft?.type === 'identifier') {
            const varInfo = ctx.resolveVariable(augLeft.text);
            if (varInfo) {
              varInfo.tainted = true;
              varInfo.producingNodeId = augN.id;
            }
          }
        }
      }
      break;
    }

    // ── Attribute (derives and macros) ──────────────────────────────────

    case 'attribute_item': {
      const attrText = node.text.slice(0, 100);
      const attrN = createNode({ label: attrText, node_type: 'META', node_subtype: 'decorator', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      attrN.tags.push('attribute');

      // Detect route attributes: #[get("/path")], #[post("/path")], #[route(GET, path="/path")]
      const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];
      const attrLower = attrText.toLowerCase();
      for (const method of HTTP_METHODS) {
        if (attrLower.includes(`#[${method}(`) || attrLower.includes(`#[${method}("`) ||
            attrLower.includes(`method = ${method}`)) {
          attrN.node_type = 'STRUCTURAL';
          attrN.node_subtype = 'route';
          attrN.tags.push('http-route');
          break;
        }
      }

      ctx.neuralMap.nodes.push(attrN); ctx.lastCreatedNodeId = attrN.id; ctx.emitContainsIfNeeded(attrN.id);
      break;
    }

    // ── Type cast expression --
    case 'type_cast_expression': {
      const castN = createNode({ label: node.text.slice(0, 40), node_type: 'TRANSFORM', node_subtype: 'type_cast', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(castN); ctx.lastCreatedNodeId = castN.id; ctx.emitContainsIfNeeded(castN.id);
      break;
    }

    // ── Index expression --
    case 'index_expression': {
      const idxN = createNode({ label: node.text.slice(0, 40), node_type: 'TRANSFORM', node_subtype: 'subscript', language: 'rust', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(idxN); ctx.lastCreatedNodeId = idxN.id; ctx.emitContainsIfNeeded(idxN.id);
      break;
    }

    // ── Const / Static items — emit META config_value so verifiers can
    //    scan for hardcoded credentials (CWE-798) and other config issues.
    case 'const_item':
    case 'static_item': {
      const nameNode = node.childForFieldName('name');
      const constLabel = nameNode ? nameNode.text : node.text.slice(0, 40);
      const constN = createNode({
        label: constLabel,
        node_type: 'META',
        node_subtype: 'config_value',
        language: 'rust',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 300),
      });
      ctx.neuralMap.nodes.push(constN);
      ctx.lastCreatedNodeId = constN.id;
      ctx.emitContainsIfNeeded(constN.id);
      break;
    }

    // ── Silent pass-throughs ────────────────────────────────────────────

    case 'empty_statement':
    case 'expression_statement':
    case 'parenthesized_expression':
    case 'block':
    case 'source_file':
      break;
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'function_item' && node.type !== 'closure_expression') return;

  const body = node.childForFieldName('body');
  if (!body) return;

  // Rust functions: last expression in block (no semicolon) is the return value
  if (body.type === 'block') {
    const lastChild = body.namedChild(body.namedChildCount - 1);
    if (lastChild && lastChild.type !== 'let_declaration' &&
        lastChild.type !== 'expression_statement') {
      // It's a tail expression — check for taint
      const taintSources = extractTaintSources(lastChild, ctx);
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
      }
    }

    // Also check explicit return statements
    for (let i = 0; i < body.namedChildCount; i++) {
      const stmt = body.namedChild(i);
      if (stmt?.type === 'return_expression') {
        const retExpr = stmt.namedChild(0);
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
          }
        }
      }
    }
  }

  // For closures with expression body: |x| expr
  if (body.type !== 'block') {
    const taintSources = extractTaintSources(body, ctx);
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
    }
  }
}

// ---------------------------------------------------------------------------
// preVisitIteration — set up loop variable taint before walking body
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_expression') return;

  const pattern = node.childForFieldName('pattern');
  const value = node.childForFieldName('value');
  if (!pattern || !value) return;

  const iterTaint = extractTaintSources(value, ctx);
  if (iterTaint.length > 0) {
    const names = extractPatternNames(pattern);
    for (const varName of names) {
      ctx.declareVariable(varName, 'let', null, true, iterTaint[0].nodeId);
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration — re-mark loop variable taint after body walk
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_expression') return;

  const pattern = node.childForFieldName('pattern');
  const value = node.childForFieldName('value');
  if (!pattern || !value) return;

  const iterTaint = extractTaintSources(value, ctx);
  if (iterTaint.length > 0) {
    const names = extractPatternNames(pattern);
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
// resolveCallee — wrapper that uses Rust callee chain extraction + lookup
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  if (node.type !== 'call_expression') return null;

  const chain = extractCalleeChain(node);
  const pattern = _lookupRustCallee(chain);
  if (!pattern) return null;

  return {
    nodeType: pattern.nodeType,
    subtype: pattern.subtype,
    tainted: pattern.tainted,
    chain,
  };
}

// ---------------------------------------------------------------------------
// resolvePropertyAccess — for standalone field_expression
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  if (node.type !== 'field_expression') return null;

  const chain = extractCalleeChain(node);
  const key = chain.join('.');

  if (TAINTED_PATHS.has(key)) {
    return {
      nodeType: 'INGRESS',
      subtype: 'http_request',
      tainted: true,
    };
  }

  // Check callee DB for non-tainted field access patterns
  const pattern = _lookupRustCallee(chain);
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
// analyzeStructure — Rust structural patterns
// ---------------------------------------------------------------------------

function analyzeStructure(node: SyntaxNode): StructuralAnalysisResult | null {
  if (node.type !== 'call_expression') return null;

  const chain = extractCalleeChain(node);
  const methodName = chain[chain.length - 1];
  const receiverName = chain.length > 1 ? chain[chain.length - 2] : '';

  // Detect middleware/layer wrapping
  if (methodName === 'wrap' || methodName === 'layer') {
    const argsNode = node.childForFieldName('arguments');
    const middlewareNames: string[] = [];
    let hasAuthGate = false;
    let hasRateLimiter = false;
    let hasCsrfProtection = false;
    let hasValidation = false;

    if (argsNode) {
      const argText = argsNode.text.toLowerCase();
      middlewareNames.push(argText.slice(1, -1).trim().slice(0, 50)); // Remove parens

      if (argText.includes('auth') || argText.includes('identity') || argText.includes('jwt')) {
        hasAuthGate = true;
      }
      if (argText.includes('rate') || argText.includes('governor') || argText.includes('throttle')) {
        hasRateLimiter = true;
      }
      if (argText.includes('csrf') || argText.includes('xsrf')) {
        hasCsrfProtection = true;
      }
      if (argText.includes('valid') || argText.includes('guard')) {
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

  // Detect route definitions
  if (methodName === 'route' || methodName === 'service') {
    const argsNode = node.childForFieldName('arguments');
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

export const rustProfile: LanguageProfile = {
  id: 'rust',
  extensions: ['.rs'],

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
    return _lookupRustCallee(chain);
  },

  analyzeStructure,

  // Layer 4: Taint Source Detection
  ingressPattern: /\b(stdin\.read_line|env::args|env::var|env::vars|web::Json|web::Path|web::Query|web::Form|extract::Json|extract::Path|extract::Query|serde_json::from_str|req\.body|req\.query|req\.headers)\b/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) => nodeType === 'let_declaration',
  getDeclarationValueNode: (node) => node.childForFieldName('value'),
  isStatementContainer: (nodeType: string) => nodeType === 'source_file' || nodeType === 'block',

  // Rust function parameter pattern for inter-procedural taint
  functionParamPattern: /fn\s+\w+\s*(?:<[^>]*>)?\s*\(([^)]*)\)/,
};

export default rustProfile;
