/**
 * JavaScriptProfile — the first LanguageProfile implementation.
 *
 * Every piece of JavaScript-specific logic that was hardcoded in mapper.ts
 * now lives here. The mapper imports this profile and asks it questions
 * instead of assuming the answers.
 *
 * This file is large (~1200 lines). That's expected — it contains the entire
 * JS vocabulary that was previously scattered across the mapper's switch
 * statement, variable declaration handler, taint extraction, and scope logic.
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
import { createNode, createRange, narrowRange } from '../types.js';
import type { RangeInfo } from '../types.js';
import { resolveCallee as _resolveCallee, resolvePropertyAccess as _resolvePropertyAccess } from '../resolveCallee.js';
import { lookupCallee as _lookupCallee } from '../calleePatterns.js';
import { analyzeStructure as _analyzeStructure } from '../structuralPatterns.js';
import { isNeutralizingSubtype } from '../properties/neutralizers.js';

// ---------------------------------------------------------------------------
// Constant Folding — resolves string concatenation at parse time
// ---------------------------------------------------------------------------
// Handles evasion patterns like:
//   window['ev' + 'al'](x)       → window.eval(x)
//   require('child_' + 'process') → require('child_process')
//   globalThis['set' + 'Timeout'] → globalThis.setTimeout
//
// This is the anti-evasion core. Attackers split dangerous function names
// across string concatenation to dodge static analysis. We fold them back.

function tryFoldConstant(n: SyntaxNode): string | null {
  // Literal strings — also resolve hex/unicode escape sequences
  if (n.type === 'string' || n.type === 'string_fragment') {
    const raw = n.text.replace(/^['"`]|['"`]$/g, '');
    return resolveEscapes(raw);
  }
  // Template strings with no interpolation (just backtick-wrapped literals)
  if (n.type === 'template_string' && n.namedChildCount === 0) {
    return resolveEscapes(n.text.replace(/^`|`$/g, ''));
  }
  // Number literals — return as string for charcode operations
  if (n.type === 'number') {
    return n.text;
  }
  // Binary expression: "ev" + "al" → "eval"
  if (n.type === 'binary_expression') {
    const op = n.childForFieldName('operator')?.text;
    if (op === '+') {
      const left = n.childForFieldName('left');
      const right = n.childForFieldName('right');
      if (left && right) {
        const lv = tryFoldConstant(left);
        const rv = tryFoldConstant(right);
        if (lv !== null && rv !== null) return lv + rv;
      }
    }
  }
  // Parenthesized: ("ev" + "al") → "eval"
  if (n.type === 'parenthesized_expression') {
    const inner = n.namedChild(0);
    return inner ? tryFoldConstant(inner) : null;
  }
  // Ternary constant folding: cond ? 'a' : 'a' → 'a'
  if (n.type === 'ternary_expression') {
    const consequence = n.childForFieldName('consequence');
    const alternative = n.childForFieldName('alternative');
    if (consequence && alternative) {
      const cv = tryFoldConstant(consequence);
      const av = tryFoldConstant(alternative);
      if (cv !== null && av !== null && cv === av) return cv;
    }
  }
  // ── CHARCODE EVASION: String.fromCharCode(101, 118, 97, 108) → "eval" ──
  if (n.type === 'call_expression') {
    const func = n.childForFieldName('function');
    const args = n.childForFieldName('arguments');
    if (func && args) {
      // String.fromCharCode(...)
      if (func.type === 'member_expression') {
        const obj = func.childForFieldName('object');
        const prop = func.childForFieldName('property');
        if (obj?.text === 'String' && prop?.text === 'fromCharCode') {
          const codes: number[] = [];
          let allLiteral = true;
          for (let i = 0; i < args.namedChildCount; i++) {
            const arg = args.namedChild(i);
            if (arg?.type === 'number') {
              codes.push(parseInt(arg.text, 10));
            } else {
              allLiteral = false;
              break;
            }
          }
          if (allLiteral && codes.length > 0) {
            return String.fromCharCode(...codes);
          }
        }
      }
      // atob('ZXZhbA==') → "eval" (base64 decode)
      if (func.type === 'identifier' && func.text === 'atob') {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const b64 = tryFoldConstant(firstArg);
          if (b64 !== null) {
            try {
              return Buffer.from(b64, 'base64').toString('utf-8');
            } catch { /* not valid base64 */ }
          }
        }
      }
      // Buffer.from([...], 'hex').toString() or Buffer.from('...', 'base64').toString()
      // We handle the outer .toString() call — check if the inner is Buffer.from
      if (func.type === 'member_expression') {
        const innerObj = func.childForFieldName('object');
        const method = func.childForFieldName('property');
        if (method?.text === 'toString' && innerObj?.type === 'call_expression') {
          const innerFunc = innerObj.childForFieldName('function');
          const innerArgs = innerObj.childForFieldName('arguments');
          if (innerFunc?.type === 'member_expression') {
            const bufObj = innerFunc.childForFieldName('object');
            const bufMethod = innerFunc.childForFieldName('property');
            if (bufObj?.text === 'Buffer' && bufMethod?.text === 'from' && innerArgs) {
              const firstArg = innerArgs.namedChild(0);
              const secondArg = innerArgs.namedChild(1);
              const encoding = secondArg ? tryFoldConstant(secondArg) : null;
              if (firstArg && encoding) {
                const data = tryFoldConstant(firstArg);
                if (data !== null) {
                  try {
                    if (encoding === 'hex') return Buffer.from(data, 'hex').toString('utf-8');
                    if (encoding === 'base64') return Buffer.from(data, 'base64').toString('utf-8');
                  } catch { /* invalid encoding */ }
                }
              }
            }
          }
        }
      }
      // [101,118,97,108].map(c => String.fromCharCode(c)).join('')
      // Handle .join('') on the outer call — check for array.map(charcode).join pattern
      if (func.type === 'member_expression') {
        const joinObj = func.childForFieldName('object');
        const joinMethod = func.childForFieldName('property');
        if (joinMethod?.text === 'join' && joinObj?.type === 'call_expression') {
          // Check if separator is empty string
          const joinSep = args.namedChild(0);
          const sep = joinSep ? tryFoldConstant(joinSep) : '';
          if (sep !== null && sep === '') {
            // Look inside for .map(c => String.fromCharCode(c))
            const mapFunc = joinObj.childForFieldName('function');
            if (mapFunc?.type === 'member_expression') {
              const mapMethod = mapFunc.childForFieldName('property');
              const arrayNode = mapFunc.childForFieldName('object');
              if (mapMethod?.text === 'map' && arrayNode?.type === 'array') {
                // Try to extract all numbers from the array
                const codes: number[] = [];
                let allNums = true;
                for (let i = 0; i < arrayNode.namedChildCount; i++) {
                  const el = arrayNode.namedChild(i);
                  if (el?.type === 'number') {
                    codes.push(parseInt(el.text, 10));
                  } else {
                    allNums = false;
                    break;
                  }
                }
                if (allNums && codes.length > 0) {
                  // Check if the map callback is String.fromCharCode
                  const mapArgs = joinObj.childForFieldName('arguments');
                  const mapCallback = mapArgs?.namedChild(0);
                  if (mapCallback) {
                    const cbText = mapCallback.text;
                    if (cbText.includes('fromCharCode') || cbText.includes('String.fromCharCode')) {
                      return String.fromCharCode(...codes);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return null;
}

// Resolve \xHH and \uHHHH escape sequences in strings
function resolveEscapes(s: string): string {
  return s
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\\\/g, '\\');
}

// ---------------------------------------------------------------------------
// Range Extraction — parse comparison operators from CONTROL conditions
// ---------------------------------------------------------------------------

/**
 * Given a tree-sitter condition node (the `condition` field of an if_statement
 * or while_statement), extract variable-to-range mappings from comparison operators.
 *
 * Handles:
 *   x > 0          → { x: { min: 1, max: Infinity } }    (exclusive: min = val + 1)
 *   x >= 0         → { x: { min: 0, max: Infinity } }
 *   x < 1000       → { x: { min: -Infinity, max: 999 } } (exclusive: max = val - 1)
 *   x <= 1000      → { x: { min: -Infinity, max: 1000 } }
 *   x > 0 && x < 1000 → { x: { min: 1, max: 999 } }     (narrowed)
 *   x === 5        → { x: { min: 5, max: 5 } }
 *
 * Does NOT handle disjunctions (||), negation, or non-literal comparisons.
 */
function extractRangeFromCondition(
  conditionNode: SyntaxNode,
  ctx: MapperContextLike,
  controlNodeId: string,
): Map<string, RangeInfo> {
  const ranges = new Map<string, RangeInfo>();

  function processComparison(node: SyntaxNode): void {
    if (node.type !== 'binary_expression') return;

    const op = node.childForFieldName('operator')?.text;
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    if (!op || !left || !right) return;

    let varName: string | null = null;
    let numVal: number | null = null;
    let varIsLeft = true;

    // Try left = identifier/member, right = numeric literal
    if (left.type === 'identifier' || left.type === 'member_expression') {
      const folded = tryFoldConstant(right);
      if (folded !== null && !isNaN(Number(folded))) {
        varName = left.text;
        numVal = Number(folded);
        varIsLeft = true;
      }
    }
    // Try left = numeric literal, right = identifier/member
    if (varName === null && (right.type === 'identifier' || right.type === 'member_expression')) {
      const folded = tryFoldConstant(left);
      if (folded !== null && !isNaN(Number(folded))) {
        varName = right.text;
        numVal = Number(folded);
        varIsLeft = false;
      }
    }

    if (varName === null || numVal === null) return;

    // Normalize: express as "varName OP numVal"; flip operator if var was on right
    let normalizedOp = op;
    if (!varIsLeft) {
      switch (op) {
        case '<':  normalizedOp = '>'; break;
        case '<=': normalizedOp = '>='; break;
        case '>':  normalizedOp = '<'; break;
        case '>=': normalizedOp = '<='; break;
        // == and != are symmetric
      }
    }

    let newRange: RangeInfo;
    switch (normalizedOp) {
      case '>':
        newRange = createRange(numVal + 1, Infinity, controlNodeId);
        break;
      case '>=':
        newRange = createRange(numVal, Infinity, controlNodeId);
        break;
      case '<':
        newRange = createRange(-Infinity, numVal - 1, controlNodeId);
        break;
      case '<=':
        newRange = createRange(-Infinity, numVal, controlNodeId);
        break;
      case '==':
      case '===':
        newRange = createRange(numVal, numVal, controlNodeId);
        break;
      case '!=':
      case '!==':
        // Inequality doesn't yield a useful contiguous range
        return;
      default:
        return;
    }

    // Narrow with any existing range for this variable (handles && chains)
    const existing = ranges.get(varName);
    if (existing) {
      ranges.set(varName, narrowRange(existing, newRange));
    } else {
      ranges.set(varName, newRange);
    }
  }

  function walk(node: SyntaxNode): void {
    if (node.type === 'binary_expression') {
      const op = node.childForFieldName('operator')?.text;
      if (op === '&&') {
        // Conjunction: both sides contribute ranges
        const left = node.childForFieldName('left');
        const right = node.childForFieldName('right');
        if (left) walk(left);
        if (right) walk(right);
        return;
      }
      // Comparison — try to extract range
      processComparison(node);
      return;
    }
    // Parenthesized expression: unwrap
    if (node.type === 'parenthesized_expression') {
      const inner = node.namedChild(0);
      if (inner) walk(inner);
      return;
    }
    // Other node types: don't recurse (only handle explicit comparisons)
  }

  walk(conditionNode);

  // Attach inferred ranges to variables currently in scope
  for (const [varName, range] of ranges) {
    const varInfo = ctx.resolveVariable(varName);
    if (varInfo) {
      varInfo.range = varInfo.range
        ? narrowRange(varInfo.range, range)
        : range;
    }
  }

  return ranges;
}

// ---------------------------------------------------------------------------
// AST Node Type Sets
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'function_declaration',
  'function',
  'arrow_function',
  'method_definition',
  'generator_function_declaration',
  'generator_function',
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'for_statement',
  'for_in_statement',
  'for_of_statement',
  'while_statement',
  'do_statement',
  'if_statement',
  'switch_statement',
  'try_statement',
  'catch_clause',
  'class_static_block',
  'statement_block',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'class_declaration',
  'class',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'lexical_declaration',
  'variable_declaration',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'function_declaration',
]);

const TAINTED_PATHS: ReadonlySet<string> = new Set([
  'req.body',
  'req.query',
  'req.params',
  'req.headers',
  'req.cookies',
  'req.files',
  'req.file',
]);

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
// extractPatternNames — extract variable names from destructuring patterns
// ---------------------------------------------------------------------------

function extractPatternNames(pattern: SyntaxNode): string[] {
  const names: string[] = [];

  for (let i = 0; i < pattern.namedChildCount; i++) {
    const child = pattern.namedChild(i);
    if (!child) continue;

    switch (child.type) {
      case 'shorthand_property_identifier_pattern':
        names.push(child.text);
        break;
      case 'pair_pattern': {
        const value = child.childForFieldName('value');
        if (value && value.type === 'identifier') {
          names.push(value.text);
        } else if (value) {
          names.push(...extractPatternNames(value));
        }
        break;
      }
      case 'rest_pattern': {
        const ident = child.namedChildren.find(
          (c): c is NonNullable<typeof c> => c !== null && c.type === 'identifier'
        );
        if (ident) names.push(ident.text);
        break;
      }
      case 'identifier':
        names.push(child.text);
        break;
      case 'assignment_pattern': {
        const left = child.childForFieldName('left');
        if (left && left.type === 'identifier') {
          names.push(left.text);
        }
        break;
      }
      default:
        if (child.type === 'object_pattern' || child.type === 'array_pattern') {
          names.push(...extractPatternNames(child));
        }
    }
  }

  return names;
}

// ---------------------------------------------------------------------------
// extractTaintSources — the recursive expression X-ray
// ---------------------------------------------------------------------------

function extractTaintSources(expr: SyntaxNode, ctx: MapperContextLike): TaintSourceResult[] {
  if (!expr) return [];

  switch (expr.type) {
    // -- Leaf: identifier -- check if it's a tainted variable
    case 'identifier': {
      const varInfo = ctx.resolveVariable(expr.text);
      if (varInfo?.tainted && varInfo.producingNodeId) {
        return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
      }
      return [];
    }

    // -- Leaf: member_expression -- check callee DB for taint (e.g., req.body.name)
    case 'member_expression': {
      const resolution = _resolvePropertyAccess(expr);
      if (resolution?.tainted) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'javascript',
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
      // Even if callee DB says not tainted, the object might be a tainted variable
      const obj = expr.childForFieldName('object');
      if (obj?.type === 'identifier') {
        const varInfo = ctx.resolveVariable(obj.text);
        if (varInfo?.tainted && varInfo.producingNodeId) {
          return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
        }
      }
      // Recurse into the object for deeper chains
      if (obj?.type === 'member_expression') {
        return extractTaintSources(obj, ctx);
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

    // -- Template literal: `prefix ${TAINTED} suffix` --
    case 'template_string': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child?.type === 'template_substitution') {
          const inner = child.namedChild(0);
          if (inner) sources.push(...extractTaintSources(inner, ctx));
        }
      }
      return sources;
    }

    // -- Call expression: sanitize(TAINTED) breaks the chain --
    case 'call_expression': {
      const callResolution = _resolveCallee(expr);
      // If this is a neutralizing call (sanitize, encode, etc.), taint STOPS here
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          isNeutralizingSubtype(callResolution.subtype)) {
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
      // Check receiver: for arr.join(), str.split(), etc.
      const calleeExpr = expr.childForFieldName('function');
      if (calleeExpr?.type === 'member_expression') {
        const receiver = calleeExpr.childForFieldName('object');
        if (receiver) sources.push(...extractTaintSources(receiver, ctx));
      }
      // Also check: existing node with tainted data_out
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

    // -- Ternary: cond ? TAINTED : safe --
    case 'ternary_expression': {
      const consequence = expr.childForFieldName('consequence');
      const alternative = expr.childForFieldName('alternative');
      const sources: TaintSourceResult[] = [];
      if (consequence) sources.push(...extractTaintSources(consequence, ctx));
      if (alternative) sources.push(...extractTaintSources(alternative, ctx));
      return sources;
    }

    // -- Parenthesized: (TAINTED) --
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Assignment: x = TAINTED --
    case 'assignment_expression': {
      const right = expr.childForFieldName('right');
      return right ? extractTaintSources(right, ctx) : [];
    }

    // -- Await: await TAINTED --
    case 'await_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Spread: ...TAINTED --
    case 'spread_element': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Object literal: { key: TAINTED, ...TAINTED } --
    case 'object': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const prop = expr.namedChild(i);
        if (!prop) continue;
        if (prop.type === 'shorthand_property_identifier') {
          const varInfo = ctx.resolveVariable(prop.text);
          if (varInfo?.tainted && varInfo.producingNodeId) {
            sources.push({ nodeId: varInfo.producingNodeId, name: prop.text });
          }
        } else if (prop.type === 'pair') {
          const value = prop.childForFieldName('value');
          if (value) sources.push(...extractTaintSources(value, ctx));
        } else if (prop.type === 'spread_element') {
          sources.push(...extractTaintSources(prop, ctx));
        }
      }
      return sources;
    }

    // -- Array literal: [TAINTED, safe, TAINTED] --
    case 'array': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Unary: !TAINTED, typeof TAINTED --
    case 'unary_expression': {
      const arg = expr.childForFieldName('argument');
      return arg ? extractTaintSources(arg, ctx) : [];
    }

    // -- Default: unknown expression type --
    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'lexical_declaration' && node.type !== 'variable_declaration') {
    return;
  }

  const kindNode = node.child(0);
  const kindText = kindNode?.text;
  const kind: VariableInfo['kind'] =
    kindText === 'const' ? 'const' :
    kindText === 'let' ? 'let' :
    kindText === 'var' ? 'var' :
    'let';

  for (let i = 0; i < node.namedChildCount; i++) {
    const declarator = node.namedChild(i);
    if (!declarator || declarator.type !== 'variable_declarator') continue;

    const nameNode = declarator.childForFieldName('name');
    if (!nameNode) continue;

    // lastCreatedNodeId was set by walking the value expression (children-first)
    let producingNodeId = ctx.lastCreatedNodeId;

    // Check if the producing node is tainted (INGRESS or has tainted data_out)
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

    // Multi-hop taint propagation: if no producing node was found (the value
    // is a plain identifier like `const b = a`), look up the source variable
    // and inherit its taint status and producing node.
    if (!producingNodeId) {
      const valueNode = declarator.childForFieldName('value');
      if (valueNode?.type === 'identifier') {
        const sourceVar = ctx.resolveVariable(valueNode.text);
        if (sourceVar) {
          tainted = sourceVar.tainted;
          producingNodeId = sourceVar.producingNodeId;
        }
      }
    }

    // FIX 1: Direct taint extraction — if the producing node check missed taint,
    // use extractTaintSources on the value expression. This catches taint flowing
    // through object spreads, array literals, ternary expressions, and other
    // compound expressions where the lastCreatedNodeId may not be the tainted node.
    if (!tainted) {
      const valueNode = declarator.childForFieldName('value');
      if (valueNode) {
        const directTaint = extractTaintSources(valueNode, ctx);
        if (directTaint.length > 0) {
          tainted = true;
          producingNodeId = directTaint[0].nodeId;
        }
      }
    }

    // Cross-function taint: const val = getInput(req)
    if (!producingNodeId) {
      const valueNode = declarator.childForFieldName('value');
      if (valueNode?.type === 'call_expression') {
        const callee = valueNode.childForFieldName('function');
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
    }

    // Alias chain detection: const q = db.query -> store ['db', 'query'] on the variable
    let aliasChain: string[] | undefined;
    {
      const valueNode = declarator.childForFieldName('value');
      if (valueNode?.type === 'member_expression') {
        const chain: string[] = [];
        let cur: SyntaxNode | null = valueNode;
        while (cur?.type === 'member_expression') {
          const prop = cur.childForFieldName('property');
          if (prop) chain.unshift(prop.text);
          cur = cur.childForFieldName('object');
        }
        if (cur?.type === 'identifier') {
          // Check if the identifier itself has an alias chain (e.g., cp = require('child_process'))
          const curVar = ctx.resolveVariable(cur.text);
          if (curVar?.aliasChain) {
            chain.unshift(...curVar.aliasChain);
          } else {
            chain.unshift(cur.text);
          }
          aliasChain = chain;
        }
      }
      // FIX 3 (part 2): Bracket notation alias — const run = cp['exec'] -> ['child_process', 'exec']
      if (!aliasChain && valueNode?.type === 'subscript_expression') {
        const subObj = valueNode.childForFieldName('object');
        const subIdx = valueNode.childForFieldName('index');
        if (subObj?.type === 'identifier' && subIdx && (subIdx.type === 'string' || subIdx.type === 'template_string')) {
          const key = subIdx.text.replace(/^['"`]|['"`]$/g, '');
          if (key) {
            const subVar = ctx.resolveVariable(subObj.text);
            if (subVar?.aliasChain) {
              aliasChain = [...subVar.aliasChain, key];
            } else {
              aliasChain = [subObj.text, key];
            }
          }
        }
      }
      // Alias for require() calls: const cp = require('child_process') -> ['child_process']
      if (!aliasChain && valueNode?.type === 'call_expression') {
        const reqCallee = valueNode.childForFieldName('function');
        if (reqCallee?.type === 'identifier' && reqCallee.text === 'require') {
          const reqArgs = valueNode.childForFieldName('arguments');
          const firstArg = reqArgs?.namedChild(0);
          if (firstArg) {
            // Direct string: require('child_process')
            if (firstArg.type === 'string' || firstArg.type === 'template_string') {
              const moduleName = firstArg.text.replace(/^['"`]|['"`]$/g, '');
              if (moduleName) aliasChain = [moduleName];
            } else {
              // Concat folding: require('child_' + 'process') → 'child_process'
              const folded = tryFoldConstant(firstArg);
              if (folded) aliasChain = [folded];
            }
          }
        }
      }
    }

    // Constant folding: const action = "quer" + "y" -> constantValue = "query"
    let constantValue: string | undefined;
    {
      const valueNode = declarator.childForFieldName('value');
      if (valueNode) {
        const folded = tryFoldConstant(valueNode);
        if (folded !== null) constantValue = folded;
      }
    }

    // Preserve existing taint: if the variable was pre-declared as tainted
    // (e.g., for-of loop variable from tainted iterable), don't overwrite with false.
    const preserveTaint = (varName: string, newTainted: boolean, newProducing: string | null) => {
      if (!newTainted) {
        const existing = ctx.resolveVariable(varName);
        if (existing?.tainted) {
          return; // keep existing tainted state
        }
      }
      ctx.declareVariable(varName, kind, null, newTainted, newProducing);
      // Apply alias chain and constant value if detected
      const v = ctx.resolveVariable(varName);
      if (v) {
        if (aliasChain) v.aliasChain = aliasChain;
        if (constantValue) {
          v.constantValue = constantValue;
          // Step 6: constant folding → range
          // If the constant is numeric, set an exact range { min: N, max: N }
          const numVal = Number(constantValue);
          if (!isNaN(numVal) && Number.isFinite(numVal)) {
            v.range = createRange(numVal, numVal);
          }
        }
      }
    };

    if (nameNode.type === 'identifier') {
      preserveTaint(nameNode.text, tainted, producingNodeId);
    } else if (nameNode.type === 'object_pattern') {
      extractPatternNames(nameNode).forEach(n =>
        preserveTaint(n, tainted, producingNodeId)
      );
    } else if (nameNode.type === 'array_pattern') {
      extractPatternNames(nameNode).forEach(n =>
        preserveTaint(n, tainted, producingNodeId)
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Handler verb detection — Ghost/Strapi/Keystone pattern
// ---------------------------------------------------------------------------

// HTTP action verbs that indicate a method is a request handler when found
// inside module.exports. Excludes generic words (set, init, configure) to
// avoid false positives on utility methods.
const HANDLER_VERBS: ReadonlySet<string> = new Set([
  'query', 'read', 'browse', 'edit', 'destroy', 'add',
  'create', 'update', 'delete', 'list', 'find', 'search',
  'remove', 'get', 'post', 'put', 'patch', 'handle',
  'execute', 'run', 'process', 'fetch', 'save',
]);

/**
 * Detect whether a method_definition is a verb-named handler inside
 * module.exports (or export default). This covers the Ghost CMS pattern:
 *
 *   module.exports = {
 *     browse: {
 *       query(frame) { ... }  // ← verb-named method, frame is user input
 *     }
 *   };
 *
 * AST chain: method_definition → object → pair → object → assignment_expression
 * where left = "module.exports"
 */
function isExportedVerbMethod(funcNode: SyntaxNode): boolean {
  if (funcNode.type !== 'method_definition') return false;

  const name = funcNode.childForFieldName('name')?.text;
  if (!name || !HANDLER_VERBS.has(name)) return false;

  // Walk up parent chain looking for module.exports assignment or export default
  let node = funcNode.parent;
  while (node) {
    if (node.type === 'assignment_expression') {
      const left = node.childForFieldName('left');
      if (left?.text === 'module.exports') return true;
      if (left?.type === 'member_expression') {
        const obj = left.childForFieldName('object');
        if (obj?.text === 'module' || obj?.text === 'exports') return true;
      }
    }
    if (node.type === 'export_statement') return true;
    node = node.parent;
  }
  return false;
}

// ---------------------------------------------------------------------------
// processFunctionParams
// ---------------------------------------------------------------------------

// Known Express/HTTP request property names that carry user-controlled data.
// When these appear as destructured parameters from the first argument of an
// Express-style handler, they must be treated as tainted INGRESS sources.
const EXPRESS_REQUEST_PROPERTIES: ReadonlySet<string> = new Set([
  'body', 'query', 'params', 'headers', 'cookies', 'files', 'file',
]);

/**
 * Detect whether a function node looks like an Express-style HTTP handler.
 * Express handlers have 2-3 parameters: (req, res) or (req, res, next).
 * When the first parameter is a destructuring pattern (e.g., { body }: Request),
 * the destructured properties that match known request fields should be tainted.
 *
 * Returns true if the function signature matches the Express handler pattern.
 */
function isExpressHandlerSignature(paramsNode: SyntaxNode): boolean {
  // Count real parameters, skipping ERROR nodes (from stripped TS type annotations like `: Request`)
  let realParamCount = 0;
  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const child = paramsNode.namedChild(i);
    if (child && child.type !== 'ERROR') realParamCount++;
  }
  return realParamCount >= 2 && realParamCount <= 3;
}

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  const declareParam = (name: string) => {
    const producingId = ctx.pendingCallbackTaint.get(name) ?? null;
    const isTainted = producingId !== null;
    if (isTainted) ctx.pendingCallbackTaint.delete(name);
    ctx.declareVariable(name, 'param', null, isTainted, producingId);
  };

  /**
   * Declare a destructured Express request property as a tainted INGRESS source.
   * Creates an INGRESS node in the neural map and links the variable to it.
   */
  const declareTaintedRequestParam = (name: string, objectPattern: SyntaxNode) => {
    // Check if already handled by pendingCallbackTaint
    const producingId = ctx.pendingCallbackTaint.get(name) ?? null;
    if (producingId !== null) {
      ctx.pendingCallbackTaint.delete(name);
      ctx.declareVariable(name, 'param', null, true, producingId);
      return;
    }

    // Determine subtype based on the property name
    const subtype = (name === 'files' || name === 'file') ? 'file_upload' : 'http_request';

    // Create a synthetic INGRESS node for this destructured request property
    const ingressNode = createNode({
      label: `req.${name}`,
      node_type: 'INGRESS',
      node_subtype: subtype,
      language: 'javascript',
      file: ctx.neuralMap.source_file,
      line_start: objectPattern.startPosition.row + 1,
      line_end: objectPattern.endPosition.row + 1,
      code_snapshot: objectPattern.text.slice(0, 200), analysis_snapshot: objectPattern.text.slice(0, 2000),
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

    // Declare the variable as tainted, linked to the INGRESS node
    ctx.declareVariable(name, 'param', null, true, ingressNode.id);
  };

  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) {
    const singleParam = funcNode.childForFieldName('parameter');
    if (singleParam && singleParam.type === 'identifier') {
      declareParam(singleParam.text);
    }
    return;
  }

  // Detect Express handler with destructured first parameter.
  // Find the first non-ERROR param to check if it's a destructuring pattern.
  let firstRealParam: SyntaxNode | null = null;
  let firstRealParamIndex = -1;
  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const child = paramsNode.namedChild(i);
    if (child && child.type !== 'ERROR') {
      firstRealParam = child;
      firstRealParamIndex = i;
      break;
    }
  }

  const isExpressHandler = firstRealParam !== null &&
    (firstRealParam.type === 'object_pattern' || firstRealParam.type === 'array_pattern') &&
    isExpressHandlerSignature(paramsNode);

  // Ghost/Strapi/Keystone pattern: verb-named method in module.exports
  // Mark the first parameter as a tainted INGRESS source (e.g., `query(frame)`)
  const isVerbHandler = isExportedVerbMethod(funcNode);
  if (isVerbHandler && firstRealParam && firstRealParam.type === 'identifier') {
    const paramName = firstRealParam.text;

    // Create INGRESS node for the handler parameter
    const ingressNode = createNode({
      label: paramName,
      node_type: 'INGRESS',
      node_subtype: 'framework_handler',
      language: 'javascript',
      file: ctx.neuralMap.source_file,
      line_start: firstRealParam.startPosition.row + 1,
      line_end: firstRealParam.endPosition.row + 1,
      code_snapshot: funcNode.text.slice(0, 200),
      analysis_snapshot: funcNode.text.slice(0, 2000),
    });
    ingressNode.data_out.push({
      name: paramName,
      source: ingressNode.id,
      data_type: 'object',
      tainted: true,
      sensitivity: 'NONE',
    });
    ingressNode.attack_surface.push('user_input');
    ctx.neuralMap.nodes.push(ingressNode);
    ctx.emitContainsIfNeeded(ingressNode.id);

    // Declare the parameter as tainted, linked to the INGRESS node
    ctx.declareVariable(paramName, 'param', null, true, ingressNode.id);
  }

  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    // Skip ERROR nodes from stripped TypeScript annotations (e.g., `: Request`)
    if (param.type === 'ERROR') continue;

    // Skip first param if already declared as tainted by verb handler detection
    if (isVerbHandler && i === firstRealParamIndex && param.type === 'identifier') continue;

    switch (param.type) {
      case 'identifier':
        declareParam(param.text);
        break;
      case 'assignment_pattern': {
        const left = param.childForFieldName('left');
        if (left && left.type === 'identifier') {
          declareParam(left.text);
        }
        break;
      }
      case 'rest_pattern': {
        const ident = param.namedChildren.find(
          (c): c is NonNullable<typeof c> => c !== null && c.type === 'identifier'
        );
        if (ident) declareParam(ident.text);
        break;
      }
      case 'object_pattern':
      case 'array_pattern': {
        const names = extractPatternNames(param);

        // If this is the first param of an Express handler, taint known request properties
        if (isExpressHandler && i === firstRealParamIndex) {
          for (const n of names) {
            if (EXPRESS_REQUEST_PROPERTIES.has(n)) {
              declareTaintedRequestParam(n, param);
            } else {
              declareParam(n);
            }
          }
        } else {
          names.forEach(n => declareParam(n));
        }
        break;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of the switch statement
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  // Process function declarations (hoist the function name to current scope)
  if (node.type === 'function_declaration') {
    const funcName = node.childForFieldName('name');
    if (funcName && ctx.scopeStack.length >= 2) {
      // Declare in the scope OUTSIDE the function (the function creates its own scope)
      const outerScope = ctx.scopeStack[ctx.scopeStack.length - 2];
      outerScope.variables.set(funcName.text, {
        name: funcName.text,
        declaringNodeId: null,
        producingNodeId: null,
        kind: 'var', // function declarations are hoisted like var
        tainted: false,
      });
    }
  }

  switch (node.type) {
    case 'function_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const fnNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'javascript',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      // Populate param_names from AST
      const fnParams = node.childForFieldName('parameters');
      if (fnParams) {
        const pNames: string[] = [];
        for (let pi = 0; pi < fnParams.namedChildCount; pi++) {
          const p = fnParams.namedChild(pi);
          if (p?.type === 'identifier') pNames.push(p.text);
          else if (p?.type === 'assignment_pattern') {
            const left = p.childForFieldName('left');
            if (left?.type === 'identifier') pNames.push(left.text);
          } else if (p?.type === 'rest_pattern') {
            const inner = p.namedChildren[0];
            if (inner?.type === 'identifier') pNames.push(inner.text);
          }
        }
        if (pNames.length > 0) fnNode.param_names = pNames;
      }
      ctx.neuralMap.nodes.push(fnNode);
      ctx.lastCreatedNodeId = fnNode.id;
      ctx.emitContainsIfNeeded(fnNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = fnNode.id;
      if (name !== 'anonymous') ctx.functionRegistry.set(name, fnNode.id);
      break;
    }
    case 'arrow_function': {
      let arrowName = 'anonymous';
      if (
        node.parent?.type === 'variable_declarator' &&
        node.parent.childForFieldName('name')?.type === 'identifier'
      ) {
        arrowName = node.parent.childForFieldName('name')!.text;
      }
      const arrowNode = createNode({
        label: arrowName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'javascript',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(arrowNode);
      ctx.lastCreatedNodeId = arrowNode.id;
      ctx.emitContainsIfNeeded(arrowNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = arrowNode.id;
      if (arrowName !== 'anonymous') ctx.functionRegistry.set(arrowName, arrowNode.id);
      break;
    }
    case 'class_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousClass';
      const classNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'javascript',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(classNode);
      ctx.lastCreatedNodeId = classNode.id;
      ctx.emitContainsIfNeeded(classNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = classNode.id;
      break;
    }
    case 'method_definition': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const methodNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'javascript',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(methodNode);
      ctx.lastCreatedNodeId = methodNode.id;
      ctx.emitContainsIfNeeded(methodNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = methodNode.id;
      if (name !== 'anonymous') ctx.functionRegistry.set(name, methodNode.id);
      break;
    }
    case 'import_statement': {
      const sourceNode = node.childForFieldName('source');
      const moduleName = sourceNode
        ? sourceNode.text.replace(/['"]/g, '')
        : node.descendantsOfType('string').filter(s => s != null).map(s => s.text.replace(/['"]/g, ''))[0] ?? 'unknown';
      const importNode = createNode({
        label: moduleName,
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'javascript',
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
    // -- CALL EXPRESSION: classify by callee --
    case 'call_expression': {
      // Structural pattern analysis (middleware chains, route definitions)
      const structure = _analyzeStructure(node);
      if (structure) {
        if (structure.hasAuthGate) {
          const authNode = createNode({
            label: structure.middlewareNames.join(', '),
            node_type: 'AUTH',
            node_subtype: 'middleware',
            language: 'javascript',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: `// middleware: ${structure.middlewareNames.join(', ')}`,
            tags: ['structural-phoneme', 'express-middleware'],
          });
          ctx.neuralMap.nodes.push(authNode);
          ctx.emitContainsIfNeeded(authNode.id);
        }
        if (structure.hasRateLimiter) {
          const limitNode = createNode({
            label: 'rate-limiter',
            node_type: 'CONTROL',
            node_subtype: 'rate_limiter',
            language: 'javascript',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: `// rate limiter middleware`,
            tags: ['structural-phoneme'],
          });
          ctx.neuralMap.nodes.push(limitNode);
          ctx.emitContainsIfNeeded(limitNode.id);
        }
        if (structure.hasValidation) {
          const valNode = createNode({
            label: 'validator',
            node_type: 'CONTROL',
            node_subtype: 'validation',
            language: 'javascript',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: `// validation middleware`,
            tags: ['structural-phoneme'],
          });
          ctx.neuralMap.nodes.push(valNode);
          ctx.emitContainsIfNeeded(valNode.id);
        }
      }

      const resolution = _resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'javascript',
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

        // Receiver taint: for method calls on tainted objects
        const calleeExprForReceiver = node.childForFieldName('function');
        if (calleeExprForReceiver?.type === 'member_expression') {
          const receiverForTaint = calleeExprForReceiver.childForFieldName('object');
          if (receiverForTaint) {
            const receiverTaint = extractTaintSources(receiverForTaint, ctx);
            for (const source of receiverTaint) {
              if (!callHasTaintedArgs) callHasTaintedArgs = true;
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
            }
          }
        }

        // Taint-through: if ANY tainted data flows into this call, mark output tainted
        if (callHasTaintedArgs && !n.data_out.some((d: any) => d.tainted)) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }

        // Array/object taint propagation: mutating methods
        if (callHasTaintedArgs && resolution.subtype === 'calculate') {
          const calleeExpr = node.childForFieldName('function');
          if (calleeExpr?.type === 'member_expression') {
            const receiverObj = calleeExpr.childForFieldName('object');
            const methodProp = calleeExpr.childForFieldName('property');
            const MUTATING_METHODS = new Set(['push', 'unshift', 'splice', 'set', 'add', 'append']);
            if (receiverObj?.type === 'identifier' && methodProp && MUTATING_METHODS.has(methodProp.text)) {
              const arrVar = ctx.resolveVariable(receiverObj.text);
              if (arrVar) {
                arrVar.tainted = true;
                arrVar.producingNodeId = n.id;
              }
            }
          }
        }

        // Callback parameter taint
        if (callHasTaintedArgs) {
          const callArgs = node.childForFieldName('arguments');
          if (callArgs) {
            for (let ai = 0; ai < callArgs.namedChildCount; ai++) {
              const arg = callArgs.namedChild(ai);
              if (arg && (arg.type === 'arrow_function' || arg.type === 'function')) {
                const params = arg.childForFieldName('parameters');
                const singleParam = arg.childForFieldName('parameter');
                if (params) {
                  for (let pi = 0; pi < params.namedChildCount; pi++) {
                    const p = params.namedChild(pi);
                    if (p?.type === 'identifier') ctx.pendingCallbackTaint.set(p.text, n.id);
                  }
                } else if (singleParam?.type === 'identifier') {
                  ctx.pendingCallbackTaint.set(singleParam.text, n.id);
                }
              }
            }
          }
        }
      } else {
        // -- IIFE detection --
        const iifeCallee = node.childForFieldName('function');
        if (iifeCallee?.type === 'parenthesized_expression') {
          const inner = iifeCallee.namedChild(0);
          if (inner && (inner.type === 'arrow_function' || inner.type === 'function')) {
            const iifeArgs = node.childForFieldName('arguments');
            const iifeTaint: TaintSourceResult[] = [];
            if (iifeArgs) {
              for (let a = 0; a < iifeArgs.namedChildCount; a++) {
                const arg = iifeArgs.namedChild(a);
                if (arg) iifeTaint.push(...extractTaintSources(arg, ctx));
              }
            }
            if (iifeTaint.length > 0) {
              const params = inner.childForFieldName('parameters');
              const singleParam = inner.childForFieldName('parameter');
              if (params) {
                for (let pi = 0; pi < params.namedChildCount; pi++) {
                  const p = params.namedChild(pi);
                  if (p?.type === 'identifier' && iifeTaint.length > 0) {
                    ctx.pendingCallbackTaint.set(p.text, iifeTaint[0].nodeId);
                  }
                }
              } else if (singleParam?.type === 'identifier') {
                ctx.pendingCallbackTaint.set(singleParam.text, iifeTaint[0].nodeId);
              }
            }
          }
        }

        // -- Computed property resolution: db[action](...) where action = "query" --
        // Also handles inline concat: window['ev' + 'al'](...) → eval
        const computedCallee = node.childForFieldName('function');
        if (computedCallee?.type === 'subscript_expression') {
          const compObj = computedCallee.childForFieldName('object');
          const compIdx = computedCallee.childForFieldName('index');
          // Try inline constant folding first: obj['ev' + 'al']()
          let resolvedPropertyName: string | null = null;
          if (compIdx) {
            resolvedPropertyName = tryFoldConstant(compIdx);
          }
          // Fall back to variable lookup: const fn = 'eval'; obj[fn]()
          if (!resolvedPropertyName && compObj?.type === 'identifier' && compIdx?.type === 'identifier') {
            const idxVar = ctx.resolveVariable(compIdx.text);
            if (idxVar?.constantValue) resolvedPropertyName = idxVar.constantValue;
          }
          if (compObj && resolvedPropertyName) {
            // Also handle chained objects: extract chain from compObj
            const objChain = compObj.type === 'identifier' ? [compObj.text] :
              (compObj.type === 'member_expression' ? (() => {
                const parts: string[] = [];
                let cur: SyntaxNode | null = compObj;
                while (cur?.type === 'member_expression') {
                  const prop = cur.childForFieldName('property');
                  if (prop) parts.unshift(prop.text);
                  cur = cur.childForFieldName('object');
                }
                if (cur?.type === 'identifier') parts.unshift(cur.text);
                return parts;
              })() : [compObj.text]);
            const compChain = [...objChain, resolvedPropertyName];
            const compPattern = _lookupCallee(compChain);
            if (compPattern) {
              const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const compN = createNode({
                label,
                node_type: compPattern.nodeType,
                node_subtype: compPattern.subtype,
                language: 'javascript',
                file: ctx.neuralMap.source_file,
                line_start: node.startPosition.row + 1,
                line_end: node.endPosition.row + 1,
                code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
              });
              if (compPattern.nodeType === 'EXTERNAL' && compPattern.subtype === 'system_exec') {
                compN.attack_surface.push('command_injection');
              }
              ctx.neuralMap.nodes.push(compN);
              ctx.lastCreatedNodeId = compN.id;
              ctx.emitContainsIfNeeded(compN.id);
              const compArgs = node.childForFieldName('arguments');
              if (compArgs) {
                for (let a = 0; a < compArgs.namedChildCount; a++) {
                  const arg = compArgs.namedChild(a);
                  if (!arg) continue;
                  const taintSources = extractTaintSources(arg, ctx);
                  for (const source of taintSources) {
                    ctx.addDataFlow(source.nodeId, compN.id, source.name, 'unknown', true);
                  }
                }
              }
              break;
            }
          }
          // RUNTIME EVAL MARKER — constant folding failed, index is dynamic
          // This is the handoff point: DST can't resolve this statically.
          // If the index is tainted (user-controlled), flag it for runtime evaluation.
          if (!resolvedPropertyName && compObj && compIdx) {
            const idxTaint = extractTaintSources(compIdx, ctx);
            if (idxTaint.length > 0) {
              const dynNode = createNode({
                label: node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text,
                node_type: 'EXTERNAL',
                node_subtype: 'dynamic_dispatch',
                language: 'javascript',
                file: ctx.neuralMap.source_file,
                line_start: node.startPosition.row + 1,
                line_end: node.endPosition.row + 1,
                code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
              });
              dynNode.tags.push('needs_runtime_eval', 'unresolved_callee');
              dynNode.attack_surface.push('dynamic_dispatch');
              dynNode.data_out.push({
                name: 'result',
                source: dynNode.id,
                data_type: 'unknown',
                tainted: true,
                sensitivity: 'NONE',
              });
              ctx.neuralMap.nodes.push(dynNode);
              ctx.lastCreatedNodeId = dynNode.id;
              ctx.emitContainsIfNeeded(dynNode.id);
              for (const source of idxTaint) {
                ctx.addDataFlow(source.nodeId, dynNode.id, source.name, 'unknown', true);
              }
              // Also check arguments for taint
              const dynArgs = node.childForFieldName('arguments');
              if (dynArgs) {
                for (let a = 0; a < dynArgs.namedChildCount; a++) {
                  const arg = dynArgs.namedChild(a);
                  if (!arg) continue;
                  const argTaint = extractTaintSources(arg, ctx);
                  for (const source of argTaint) {
                    ctx.addDataFlow(source.nodeId, dynNode.id, source.name, 'unknown', true);
                  }
                }
              }
              break;
            }
          }
        }

        // -- Variable alias resolution: const q = db.query -> q(...) resolves as db.query --
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
                language: 'javascript',
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
        } else if (calleeNode?.type === 'member_expression') {
          calleeName = calleeNode.childForFieldName('property')?.text ?? null;
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

          {
            const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
            const callNode = createNode({
              label,
              node_type: 'TRANSFORM',
              node_subtype: 'local_call',
              language: 'javascript',
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

            if (funcReturnsTaint && taintSources.length === 0) {
              const ingressNodes = ctx.neuralMap.nodes.filter((n: any) =>
                n.node_type === 'INGRESS' && n.attack_surface.includes('user_input')
              );
              for (const ingress of ingressNodes) {
                ctx.addDataFlow(ingress.id, callNode.id, 'closure_capture', 'unknown', true);
              }
            }
            ctx.emitContainsIfNeeded(callNode.id);

            for (const source of taintSources) {
              ctx.addDataFlow(source.nodeId, callNode.id, source.name, 'unknown', true);
            }
          }
        }
      }

      // FIX 4: Promise.then/catch callback taint propagation
      // When tainted data flows through a promise chain (.then, .catch),
      // the callback parameters should inherit taint from the resolved value.
      {
        const promiseCallee = node.childForFieldName('function');
        if (promiseCallee?.type === 'member_expression') {
          const promiseMethod = promiseCallee.childForFieldName('property');
          const promiseReceiver = promiseCallee.childForFieldName('object');
          const PROMISE_METHODS = new Set(['then', 'catch', 'finally']);
          if (promiseMethod && PROMISE_METHODS.has(promiseMethod.text) && promiseReceiver) {
            // Check if the receiver carries tainted data (direct or via function return)
            let receiverTaint = extractTaintSources(promiseReceiver, ctx);

            // Also check: if receiver is a call_expression to a local function that
            // contains INGRESS nodes (cross-function taint through promise return)
            if (receiverTaint.length === 0 && promiseReceiver.type === 'call_expression') {
              const rcvCallee = promiseReceiver.childForFieldName('function');
              if (rcvCallee?.type === 'identifier') {
                const rcvFuncNodeId = ctx.functionRegistry.get(rcvCallee.text);
                if (rcvFuncNodeId) {
                  const rcvIngress = findIngressInFunction(rcvFuncNodeId, ctx);
                  if (rcvIngress) {
                    receiverTaint = [{ nodeId: rcvIngress, name: rcvCallee.text }];
                  }
                }
              }
              // Check arguments for taint too (e.g., fetchUserInput(req) where req.body is accessed inside)
              if (receiverTaint.length === 0) {
                const rcvArgs = promiseReceiver.childForFieldName('arguments');
                if (rcvArgs) {
                  for (let rai = 0; rai < rcvArgs.namedChildCount; rai++) {
                    const rarg = rcvArgs.namedChild(rai);
                    if (rarg) {
                      // Check if any argument's properties would be tainted
                      // (e.g., passing 'req' where req.body is tainted inside the function)
                      const argTaint = extractTaintSources(rarg, ctx);
                      receiverTaint.push(...argTaint);
                    }
                  }
                }
              }
            }

            if (receiverTaint.length > 0) {
              // Create a TRANSFORM node for the .then() call
              const thenLabel = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const thenNode = createNode({
                label: thenLabel,
                node_type: 'TRANSFORM',
                node_subtype: 'promise_chain',
                language: 'javascript',
                file: ctx.neuralMap.source_file,
                line_start: node.startPosition.row + 1,
                line_end: node.endPosition.row + 1,
                code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
              });
              thenNode.data_out.push({
                name: 'result',
                source: thenNode.id,
                data_type: 'unknown',
                tainted: true,
                sensitivity: 'NONE',
              });
              for (const source of receiverTaint) {
                ctx.addDataFlow(source.nodeId, thenNode.id, source.name, 'unknown', true);
              }
              ctx.neuralMap.nodes.push(thenNode);
              ctx.lastCreatedNodeId = thenNode.id;
              ctx.emitContainsIfNeeded(thenNode.id);

              // Mark callback parameters as tainted
              const thenArgs = node.childForFieldName('arguments');
              if (thenArgs) {
                for (let tai = 0; tai < thenArgs.namedChildCount; tai++) {
                  const thenArg = thenArgs.namedChild(tai);
                  if (thenArg && (thenArg.type === 'arrow_function' || thenArg.type === 'function')) {
                    const thenParams = thenArg.childForFieldName('parameters');
                    const thenSingleParam = thenArg.childForFieldName('parameter');
                    if (thenParams) {
                      for (let tpi = 0; tpi < thenParams.namedChildCount; tpi++) {
                        const tp = thenParams.namedChild(tpi);
                        if (tp?.type === 'identifier') ctx.pendingCallbackTaint.set(tp.text, thenNode.id);
                      }
                    } else if (thenSingleParam?.type === 'identifier') {
                      ctx.pendingCallbackTaint.set(thenSingleParam.text, thenNode.id);
                    }
                  }
                }
              }
            }
          }
        }
      }

      // FIX 2: Container taint propagation (Map/Set/Array)
      // When a method is called on a local variable (e.g., cache.set(k, taintedVal)),
      // propagate taint to the container. When reading from a tainted container
      // (e.g., cache.get(k)), propagate taint to the call's output.
      {
        const containerCallee = node.childForFieldName('function');
        if (containerCallee?.type === 'member_expression') {
          const containerObj = containerCallee.childForFieldName('object');
          const containerMethod = containerCallee.childForFieldName('property');
          if (containerObj?.type === 'identifier' && containerMethod) {
            const containerVar = ctx.resolveVariable(containerObj.text);
            const methodName = containerMethod.text;

            // Taint-write: mutating methods that store data into containers
            const TAINT_WRITE_METHODS = new Set(['set', 'add', 'push', 'unshift', 'splice', 'append', 'put']);
            if (containerVar && TAINT_WRITE_METHODS.has(methodName)) {
              const writeArgs = node.childForFieldName('arguments');
              if (writeArgs) {
                const writeTaint: TaintSourceResult[] = [];
                for (let wa = 0; wa < writeArgs.namedChildCount; wa++) {
                  const warg = writeArgs.namedChild(wa);
                  if (warg) writeTaint.push(...extractTaintSources(warg, ctx));
                }
                if (writeTaint.length > 0) {
                  containerVar.tainted = true;
                  containerVar.producingNodeId = writeTaint[0].nodeId;
                }
              }
            }

            // Taint-read: reading methods on tainted containers propagate taint
            const TAINT_READ_METHODS = new Set(['get', 'values', 'entries', 'keys', 'pop', 'shift', 'peek', 'first', 'last']);
            if (containerVar?.tainted && TAINT_READ_METHODS.has(methodName)) {
              const readLabel = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const readNode = createNode({
                label: readLabel,
                node_type: 'TRANSFORM',
                node_subtype: 'container_read',
                language: 'javascript',
                file: ctx.neuralMap.source_file,
                line_start: node.startPosition.row + 1,
                line_end: node.endPosition.row + 1,
                code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
              });
              readNode.data_out.push({
                name: 'result',
                source: readNode.id,
                data_type: 'unknown',
                tainted: true,
                sensitivity: 'NONE',
              });
              if (containerVar.producingNodeId) {
                ctx.addDataFlow(containerVar.producingNodeId, readNode.id, containerObj.text, 'unknown', true);
              }
              ctx.neuralMap.nodes.push(readNode);
              ctx.lastCreatedNodeId = readNode.id;
              ctx.emitContainsIfNeeded(readNode.id);
            }
          }
        }
      }

      // CALLS edge: capture simple identifier calls
      const callFuncNode = node.childForFieldName('function');
      if (callFuncNode && callFuncNode.type === 'identifier') {
        const containerId = ctx.getCurrentContainerId();
        if (containerId) {
          const isAsync = node.parent?.type === 'await_expression';
          ctx.pendingCalls.push({
            callerContainerId: containerId,
            calleeName: callFuncNode.text,
            isAsync,
          });
        }
      }

      // Also handle: arr.forEach(processItem) -- function ref passed as argument
      const argsNode2 = node.childForFieldName('arguments');
      if (argsNode2) {
        for (let ai = 0; ai < argsNode2.namedChildCount; ai++) {
          const arg = argsNode2.namedChild(ai);
          if (arg && arg.type === 'identifier') {
            const containerId = ctx.getCurrentContainerId();
            if (containerId) {
              ctx.pendingCalls.push({
                callerContainerId: containerId,
                calleeName: arg.text,
                isAsync: false,
              });
            }
          }
        }
      }

      break;
    }

    // -- MEMBER EXPRESSION: standalone property access --
    case 'member_expression': {
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

        const resolution = _resolvePropertyAccess(node);
        if (resolution) {
          const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
          const n = createNode({
            label,
            node_type: resolution.nodeType,
            node_subtype: resolution.subtype,
            language: 'javascript',
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

    // -- CONTROL nodes --
    case 'if_statement': {
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      // Range inference: extract bounds from condition and attach to variables in scope
      const ifCondition = node.childForFieldName('condition');
      if (ifCondition) extractRangeFromCondition(ifCondition, ctx, ifN.id);
      break;
    }
    case 'for_statement': {
      const forN = createNode({ label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      // Range inference: extract bounds from for-loop condition
      const forCondition = node.childForFieldName('condition');
      if (forCondition) extractRangeFromCondition(forCondition, ctx, forN.id);
      break;
    }
    case 'for_in_statement': {
      const forInN = createNode({ label: 'for...in', node_type: 'CONTROL', node_subtype: 'loop', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      const forInIterRight = node.childForFieldName('right');
      if (forInIterRight) {
        const iterTaint = extractTaintSources(forInIterRight, ctx);
        if (iterTaint.length > 0) {
          forInN.data_out.push({
            name: 'iteration', source: forInN.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE',
          });
        }
      }
      ctx.neuralMap.nodes.push(forInN); ctx.lastCreatedNodeId = forInN.id; ctx.emitContainsIfNeeded(forInN.id);
      break;
    }
    case 'while_statement': {
      const whileN = createNode({ label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whileN); ctx.lastCreatedNodeId = whileN.id; ctx.emitContainsIfNeeded(whileN.id);
      // Range inference: extract bounds from while-loop condition
      const whileCondition = node.childForFieldName('condition');
      if (whileCondition) extractRangeFromCondition(whileCondition, ctx, whileN.id);
      break;
    }
    case 'do_statement': {
      const doN = createNode({ label: 'do...while', node_type: 'CONTROL', node_subtype: 'loop', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(doN); ctx.lastCreatedNodeId = doN.id; ctx.emitContainsIfNeeded(doN.id);
      break;
    }
    case 'try_statement': {
      const tryN = createNode({ label: 'try/catch', node_type: 'CONTROL', node_subtype: 'error_handler', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(tryN); ctx.lastCreatedNodeId = tryN.id; ctx.emitContainsIfNeeded(tryN.id);
      break;
    }
    case 'switch_statement': {
      const switchN = createNode({ label: 'switch', node_type: 'CONTROL', node_subtype: 'branch', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(switchN); ctx.lastCreatedNodeId = switchN.id; ctx.emitContainsIfNeeded(switchN.id);
      break;
    }
    case 'ternary_expression': {
      const ternN = createNode({ label: 'ternary', node_type: 'CONTROL', node_subtype: 'branch', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ternN); ctx.lastCreatedNodeId = ternN.id; ctx.emitContainsIfNeeded(ternN.id);
      break;
    }

    case 'export_statement': {
      const exportN = createNode({ label: 'export', node_type: 'STRUCTURAL', node_subtype: 'module', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(exportN); ctx.lastCreatedNodeId = exportN.id; ctx.emitContainsIfNeeded(exportN.id);
      break;
    }

    // -- ES6+ Iteration --
    case 'for_of_statement': {
      const forOfN = createNode({ label: 'for...of', node_type: 'CONTROL', node_subtype: 'loop', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      if (node.text.startsWith('for await') || node.childCount > 0 && node.child(0)?.type === 'await') {
        forOfN.tags.push('async-iteration');
        forOfN.node_subtype = 'async_loop';
      }
      const forOfIterRight = node.childForFieldName('right');
      if (forOfIterRight) {
        const iterTaint = extractTaintSources(forOfIterRight, ctx);
        if (iterTaint.length > 0) {
          forOfN.data_out.push({
            name: 'iteration', source: forOfN.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE',
          });
        }
      }
      ctx.neuralMap.nodes.push(forOfN); ctx.lastCreatedNodeId = forOfN.id; ctx.emitContainsIfNeeded(forOfN.id);
      break;
    }

    // -- Generator functions --
    case 'generator_function_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const genN = createNode({ label: `${name}*`, node_type: 'STRUCTURAL', node_subtype: 'generator', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      genN.tags.push('generator');
      ctx.neuralMap.nodes.push(genN); ctx.lastCreatedNodeId = genN.id; ctx.emitContainsIfNeeded(genN.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = genN.id;
      if (name !== 'anonymous') ctx.functionRegistry.set(name, genN.id);
      break;
    }
    case 'generator_function': {
      const genExprN = createNode({ label: 'function*', node_type: 'STRUCTURAL', node_subtype: 'generator', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      genExprN.tags.push('generator');
      ctx.neuralMap.nodes.push(genExprN); ctx.lastCreatedNodeId = genExprN.id; ctx.emitContainsIfNeeded(genExprN.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = genExprN.id;
      break;
    }

    // -- Yield expressions --
    case 'yield_expression': {
      const yieldN = createNode({ label: 'yield', node_type: 'CONTROL', node_subtype: 'yield', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      if (node.text.includes('yield*')) yieldN.node_subtype = 'yield_delegate';
      ctx.neuralMap.nodes.push(yieldN); ctx.lastCreatedNodeId = yieldN.id; ctx.emitContainsIfNeeded(yieldN.id);
      break;
    }

    // -- Await expressions --
    case 'await_expression': {
      const awaitN = createNode({ label: 'await', node_type: 'CONTROL', node_subtype: 'await', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      awaitN.tags.push('async');
      ctx.neuralMap.nodes.push(awaitN); ctx.lastCreatedNodeId = awaitN.id; ctx.emitContainsIfNeeded(awaitN.id);
      break;
    }

    // -- Return/Throw/Break/Continue --
    case 'return_statement': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }
    case 'throw_statement': {
      const throwN = createNode({ label: 'throw', node_type: 'CONTROL', node_subtype: 'throw', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      throwN.tags.push('error-source');
      ctx.neuralMap.nodes.push(throwN); ctx.lastCreatedNodeId = throwN.id; ctx.emitContainsIfNeeded(throwN.id);
      break;
    }
    case 'break_statement': {
      const breakN = createNode({ label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(breakN); ctx.lastCreatedNodeId = breakN.id; ctx.emitContainsIfNeeded(breakN.id);
      break;
    }
    case 'continue_statement': {
      const contN = createNode({ label: 'continue', node_type: 'CONTROL', node_subtype: 'continue', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(contN); ctx.lastCreatedNodeId = contN.id; ctx.emitContainsIfNeeded(contN.id);
      break;
    }
    case 'labeled_statement': {
      const labelN = createNode({ label: `label:${node.childForFieldName('label')?.text ?? '?'}`, node_type: 'CONTROL', node_subtype: 'label', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(labelN); ctx.lastCreatedNodeId = labelN.id; ctx.emitContainsIfNeeded(labelN.id);
      break;
    }

    // -- New expression --
    case 'new_expression': {
      const ctorName = node.childForFieldName('constructor')?.text ?? 'unknown';
      const isDangerousCtor = /^Function$/.test(ctorName);
      // Check callee pattern database for constructor (e.g., RegExp → RESOURCE/cpu)
      const ctorPattern = _lookupCallee([ctorName]);
      let newNodeType: import('../types.js').NodeType = isDangerousCtor ? 'EXTERNAL' : 'TRANSFORM';
      let newSubtype = isDangerousCtor ? 'system_exec' : 'instantiation';
      if (ctorPattern && !isDangerousCtor) {
        newNodeType = ctorPattern.nodeType;
        newSubtype = ctorPattern.subtype;
      }
      const newN = createNode({ label: `new ${ctorName}`, node_type: newNodeType, node_subtype: newSubtype, language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      if (isDangerousCtor) {
        newN.attack_surface.push('command_injection', 'code_exec');
      }
      ctx.neuralMap.nodes.push(newN); ctx.lastCreatedNodeId = newN.id; ctx.emitContainsIfNeeded(newN.id);
      const newArgs = node.childForFieldName('arguments');
      if (newArgs) {
        for (let na = 0; na < newArgs.namedChildCount; na++) {
          const arg = newArgs.namedChild(na);
          if (!arg) continue;
          const taintSources = extractTaintSources(arg, ctx);
          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, newN.id, source.name, 'unknown', true);
          }
        }
      }
      const containerId = ctx.currentScope?.containerNodeId;
      if (containerId) {
        ctx.pendingCalls.push({ callerContainerId: containerId, calleeName: ctorName, isAsync: false });
      }
      break;
    }

    // -- Assignment expressions --
    case 'assignment_expression': {
      const op = node.childForFieldName('operator')?.text ?? '=';
      const assignLeftNode = node.childForFieldName('left');
      const leftText = assignLeftNode?.text?.slice(0, 40) ?? '?';
      const assignN = createNode({ label: `${leftText} ${op}`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      if (op === '&&=' || op === '||=' || op === '??=') {
        assignN.tags.push('logical-assignment');
      }
      ctx.neuralMap.nodes.push(assignN); ctx.lastCreatedNodeId = assignN.id; ctx.emitContainsIfNeeded(assignN.id);

      const assignRight = node.childForFieldName('right');
      if (assignRight) {
        const taintSources = extractTaintSources(assignRight, ctx);
        if (taintSources.length > 0) {
          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, assignN.id, source.name, 'unknown', true);
          }
          if (assignLeftNode?.type === 'identifier') {
            const varInfo = ctx.resolveVariable(assignLeftNode.text);
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
    case 'augmented_assignment_expression': {
      const augOp = node.childForFieldName('operator')?.text ?? '+=';
      const augLeftNode = node.childForFieldName('left');
      const augLeft = augLeftNode?.text?.slice(0, 40) ?? '?';
      const augN = createNode({ label: `${augLeft} ${augOp}`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(augN); ctx.lastCreatedNodeId = augN.id; ctx.emitContainsIfNeeded(augN.id);

      const augRight = node.childForFieldName('right');
      if (augRight) {
        const taintSources = extractTaintSources(augRight, ctx);
        if (taintSources.length > 0) {
          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, augN.id, source.name, 'unknown', true);
          }
          if (augLeftNode?.type === 'identifier') {
            const varInfo = ctx.resolveVariable(augLeftNode.text);
            if (varInfo) {
              varInfo.tainted = true;
              varInfo.producingNodeId = augN.id;
            }
          }
          augN.data_out.push({
            name: 'result',
            source: augN.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }
      }
      break;
    }

    // -- Binary/Unary/Update expressions --
    case 'binary_expression': {
      const binOp = node.childForFieldName('operator')?.text ?? '';
      if (binOp === 'instanceof' || binOp === 'in' || binOp === '??' || binOp === '**') {
        const binN = createNode({ label: binOp, node_type: 'TRANSFORM', node_subtype: 'binary_op', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        if (binOp === '??') binN.tags.push('nullish-coalescing');
        ctx.neuralMap.nodes.push(binN); ctx.lastCreatedNodeId = binN.id; ctx.emitContainsIfNeeded(binN.id);
      }
      break;
    }
    case 'unary_expression': {
      const unaryOp = node.childForFieldName('operator')?.text ?? '';
      if (unaryOp === 'typeof' || unaryOp === 'void' || unaryOp === 'delete') {
        const unaryN = createNode({ label: unaryOp, node_type: 'TRANSFORM', node_subtype: 'unary_op', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        if (unaryOp === 'delete') unaryN.tags.push('mutation');
        ctx.neuralMap.nodes.push(unaryN); ctx.lastCreatedNodeId = unaryN.id; ctx.emitContainsIfNeeded(unaryN.id);
      }
      break;
    }
    case 'update_expression': {
      const updateN = createNode({ label: node.text.slice(0, 20), node_type: 'TRANSFORM', node_subtype: 'update', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      updateN.tags.push('mutation');
      ctx.neuralMap.nodes.push(updateN); ctx.lastCreatedNodeId = updateN.id; ctx.emitContainsIfNeeded(updateN.id);
      break;
    }

    // -- Template literals --
    case 'template_string': {
      const hasSubs = node.namedChildren.some(c => c.type === 'template_substitution');
      if (hasSubs) {
        const tmplN = createNode({ label: 'template literal', node_type: 'TRANSFORM', node_subtype: 'template_string', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(tmplN); ctx.lastCreatedNodeId = tmplN.id; ctx.emitContainsIfNeeded(tmplN.id);
      }
      break;
    }
    case 'tagged_template_expression': {
      const tag = node.childForFieldName('function')?.text ?? 'tag';
      const tagN = createNode({ label: `tagged\`${tag}\``, node_type: 'TRANSFORM', node_subtype: 'tagged_template', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(tagN); ctx.lastCreatedNodeId = tagN.id; ctx.emitContainsIfNeeded(tagN.id);
      break;
    }

    // -- Spread / Rest --
    case 'spread_element': {
      const spreadN = createNode({ label: '...spread', node_type: 'TRANSFORM', node_subtype: 'spread', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(spreadN); ctx.lastCreatedNodeId = spreadN.id; ctx.emitContainsIfNeeded(spreadN.id);
      break;
    }

    // -- Optional chaining --
    case 'optional_chain_expression': {
      const optN = createNode({ label: '?.', node_type: 'TRANSFORM', node_subtype: 'optional_chain', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      optN.tags.push('optional-chaining');
      ctx.neuralMap.nodes.push(optN); ctx.lastCreatedNodeId = optN.id; ctx.emitContainsIfNeeded(optN.id);
      break;
    }

    // -- Class features --
    case 'field_definition':
    case 'property_definition': {
      const fieldName = node.childForFieldName('property')?.text ?? node.childForFieldName('name')?.text ?? '?';
      const isStatic = node.text.trimStart().startsWith('static');
      const isPrivate = fieldName.startsWith('#');
      const fieldN = createNode({ label: fieldName, node_type: 'STRUCTURAL', node_subtype: 'class_field', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      if (isStatic) fieldN.tags.push('static');
      if (isPrivate) fieldN.tags.push('private');
      ctx.neuralMap.nodes.push(fieldN); ctx.lastCreatedNodeId = fieldN.id; ctx.emitContainsIfNeeded(fieldN.id);
      break;
    }
    case 'class_static_block': {
      const staticBlockN = createNode({ label: 'static {}', node_type: 'STRUCTURAL', node_subtype: 'static_block', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(staticBlockN); ctx.lastCreatedNodeId = staticBlockN.id; ctx.emitContainsIfNeeded(staticBlockN.id);
      break;
    }

    // -- Computed property names --
    case 'computed_property_name': {
      const compN = createNode({ label: `[${node.text.slice(1, -1).slice(0, 30)}]`, node_type: 'TRANSFORM', node_subtype: 'computed_property', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(compN); ctx.lastCreatedNodeId = compN.id; ctx.emitContainsIfNeeded(compN.id);
      break;
    }

    // -- Destructuring assignment --
    case 'destructuring_assignment': {
      const destN = createNode({ label: 'destructure', node_type: 'TRANSFORM', node_subtype: 'destructuring', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(destN); ctx.lastCreatedNodeId = destN.id; ctx.emitContainsIfNeeded(destN.id);
      break;
    }

    // -- Dynamic import --
    case 'import': {
      if (node.parent?.type === 'call_expression') {
        const dynImportN = createNode({ label: 'import()', node_type: 'EXTERNAL', node_subtype: 'dynamic_import', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.parent.text.slice(0, 200), analysis_snapshot: node.parent.text.slice(0, 2000) });
        dynImportN.tags.push('async', 'dynamic-import');
        ctx.neuralMap.nodes.push(dynImportN); ctx.lastCreatedNodeId = dynImportN.id; ctx.emitContainsIfNeeded(dynImportN.id);
      }
      break;
    }

    // -- Sequence expression (comma operator) --
    case 'sequence_expression': {
      const seqN = createNode({ label: 'sequence', node_type: 'TRANSFORM', node_subtype: 'sequence', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(seqN); ctx.lastCreatedNodeId = seqN.id; ctx.emitContainsIfNeeded(seqN.id);
      break;
    }

    // -- Regex literals --
    case 'regex': {
      const regN = createNode({ label: node.text.slice(0, 40), node_type: 'TRANSFORM', node_subtype: 'regex', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(regN); ctx.lastCreatedNodeId = regN.id; ctx.emitContainsIfNeeded(regN.id);
      break;
    }

    // -- Debugger statement --
    case 'debugger_statement': {
      const dbgN = createNode({ label: 'debugger', node_type: 'META', node_subtype: 'debugger', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: 'debugger' });
      dbgN.tags.push('dev-only');
      ctx.neuralMap.nodes.push(dbgN); ctx.lastCreatedNodeId = dbgN.id; ctx.emitContainsIfNeeded(dbgN.id);
      break;
    }

    // -- With statement (deprecated but parseable) --
    case 'with_statement': {
      const withN = createNode({ label: 'with', node_type: 'CONTROL', node_subtype: 'with', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      withN.tags.push('deprecated');
      ctx.neuralMap.nodes.push(withN); ctx.lastCreatedNodeId = withN.id; ctx.emitContainsIfNeeded(withN.id);
      break;
    }

    // -- Silent pass-throughs --
    case 'empty_statement':
      break;
    case 'expression_statement':
      break;
    case 'parenthesized_expression':
      break;

    // -- Object/Array literals (when notable) --
    case 'object': {
      if (node.namedChildCount >= 3) {
        const objN = createNode({ label: '{...}', node_type: 'TRANSFORM', node_subtype: 'object_literal', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(objN); ctx.lastCreatedNodeId = objN.id; ctx.emitContainsIfNeeded(objN.id);
      }
      break;
    }
    case 'array': {
      if (node.namedChildCount >= 3) {
        const arrN = createNode({ label: '[...]', node_type: 'TRANSFORM', node_subtype: 'array_literal', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(arrN); ctx.lastCreatedNodeId = arrN.id; ctx.emitContainsIfNeeded(arrN.id);
      }
      break;
    }

    // -- Catch clause --
    case 'catch_clause': {
      const catchParam = node.childForFieldName('parameter');
      const catchN = createNode({ label: `catch(${catchParam?.text ?? ''})`, node_type: 'CONTROL', node_subtype: 'catch', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      catchN.tags.push('error-handler');
      ctx.neuralMap.nodes.push(catchN); ctx.lastCreatedNodeId = catchN.id; ctx.emitContainsIfNeeded(catchN.id);
      break;
    }
    case 'finally_clause': {
      const finallyN = createNode({ label: 'finally', node_type: 'CONTROL', node_subtype: 'finally', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(finallyN); ctx.lastCreatedNodeId = finallyN.id; ctx.emitContainsIfNeeded(finallyN.id);
      break;
    }

    // -- Switch case/default --
    case 'switch_case': {
      const caseVal = node.childForFieldName('value')?.text ?? 'default';
      const caseN = createNode({ label: `case ${caseVal}`, node_type: 'CONTROL', node_subtype: 'case', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(caseN); ctx.lastCreatedNodeId = caseN.id; ctx.emitContainsIfNeeded(caseN.id);
      break;
    }
    case 'switch_default': {
      const defN = createNode({ label: 'default', node_type: 'CONTROL', node_subtype: 'case', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(defN); ctx.lastCreatedNodeId = defN.id; ctx.emitContainsIfNeeded(defN.id);
      break;
    }

    // -- Subscript expression (bracket access a[b]) --
    case 'subscript_expression': {
      const subN = createNode({ label: node.text.slice(0, 40), node_type: 'TRANSFORM', node_subtype: 'subscript', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(subN); ctx.lastCreatedNodeId = subN.id; ctx.emitContainsIfNeeded(subN.id);
      break;
    }

    // -- Class heritage (extends) --
    case 'class_heritage': {
      const superClass = node.namedChildren[0]?.text ?? '?';
      const herN = createNode({ label: `extends ${superClass}`, node_type: 'STRUCTURAL', node_subtype: 'extends', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(herN); ctx.lastCreatedNodeId = herN.id; ctx.emitContainsIfNeeded(herN.id);
      break;
    }

    // -- Class expression (anonymous/inline class) --
    case 'class': {
      const classExprName = node.childForFieldName('name')?.text ?? 'anonymous';
      const classExprN = createNode({ label: classExprName, node_type: 'STRUCTURAL', node_subtype: 'class', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(classExprN); ctx.lastCreatedNodeId = classExprN.id; ctx.emitContainsIfNeeded(classExprN.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = classExprN.id;
      break;
    }

    // -- Function expression (anonymous/inline function) --
    case 'function_expression':
    case 'function': {
      const funcExprName = node.childForFieldName('name')?.text ?? 'anonymous';
      const funcExprN = createNode({ label: funcExprName, node_type: 'STRUCTURAL', node_subtype: 'function', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(funcExprN); ctx.lastCreatedNodeId = funcExprN.id; ctx.emitContainsIfNeeded(funcExprN.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = funcExprN.id;
      if (funcExprName !== 'anonymous') ctx.functionRegistry.set(funcExprName, funcExprN.id);
      break;
    }

    // -- Decorator (@decorator) --
    case 'decorator': {
      const decoratorExpr = node.namedChildren[0]?.text ?? '?';
      const decN = createNode({ label: `@${decoratorExpr}`, node_type: 'META', node_subtype: 'decorator', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      decN.tags.push('decorator');
      ctx.neuralMap.nodes.push(decN); ctx.lastCreatedNodeId = decN.id; ctx.emitContainsIfNeeded(decN.id);
      break;
    }

    // -- Optional chain (the ?. token) --
    case 'optional_chain':
      break;

    // -- Using declaration (ES2024 explicit resource management) --
    case 'using_declaration': {
      const usingN = createNode({ label: 'using', node_type: 'STRUCTURAL', node_subtype: 'using_declaration', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      usingN.tags.push('resource-management');
      ctx.neuralMap.nodes.push(usingN); ctx.lastCreatedNodeId = usingN.id; ctx.emitContainsIfNeeded(usingN.id);
      break;
    }

    // -- Meta property (new.target, import.meta) --
    case 'meta_property': {
      const metaN = createNode({ label: node.text, node_type: 'META', node_subtype: 'meta_property', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      if (node.text === 'import.meta') metaN.tags.push('module-meta');
      if (node.text === 'new.target') metaN.tags.push('constructor-meta');
      ctx.neuralMap.nodes.push(metaN); ctx.lastCreatedNodeId = metaN.id; ctx.emitContainsIfNeeded(metaN.id);
      break;
    }

    // -- JSX (React/Preact) --
    case 'jsx_element':
    case 'jsx_self_closing_element': {
      const tagNode = node.type === 'jsx_element'
        ? node.childForFieldName('open_tag')?.childForFieldName('name')
        : node.childForFieldName('name');
      const tagName = tagNode?.text ?? 'unknown';
      const isComponent = tagName[0] === tagName[0]?.toUpperCase();
      const jsxN = createNode({
        label: `<${tagName}>`,
        node_type: isComponent ? 'STRUCTURAL' : 'TRANSFORM',
        node_subtype: isComponent ? 'jsx_component' : 'jsx_element',
        language: 'javascript',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      jsxN.tags.push('jsx');
      if (isComponent) {
        const containerId = ctx.currentScope?.containerNodeId;
        if (containerId) {
          ctx.pendingCalls.push({ callerContainerId: containerId, calleeName: tagName, isAsync: false });
        }
      }
      ctx.neuralMap.nodes.push(jsxN); ctx.lastCreatedNodeId = jsxN.id; ctx.emitContainsIfNeeded(jsxN.id);
      break;
    }
    case 'jsx_expression':
      break;
    case 'jsx_attribute': {
      const attrName = node.childForFieldName('name')?.text ?? '?';
      if (attrName.startsWith('on') || attrName === 'ref' || attrName === 'key') {
        const jsxAttrN = createNode({ label: attrName, node_type: 'STRUCTURAL', node_subtype: 'jsx_prop', language: 'javascript', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        if (attrName.startsWith('on')) jsxAttrN.tags.push('event-handler');
        ctx.neuralMap.nodes.push(jsxAttrN); ctx.lastCreatedNodeId = jsxAttrN.id; ctx.emitContainsIfNeeded(jsxAttrN.id);
      }
      break;
    }
    case 'jsx_opening_element':
    case 'jsx_closing_element':
    case 'jsx_text':
    case 'jsx_namespace_name':
      break;
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'arrow_function' && node.type !== 'function_declaration' && node.type !== 'function') {
    return;
  }

  const body = node.childForFieldName('body');
  // Expression body (arrow function without braces): () => expr
  if (body && body.type !== 'statement_block') {
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
        // Set the functionReturnTaint flag for PASS 2 Step 4b
        ctx.functionReturnTaint.set(funcNodeId, true);
      }
    }
  }
  // Block body: check for return statements with tainted expressions
  if (body && body.type === 'statement_block') {
    for (let i = 0; i < body.namedChildCount; i++) {
      const stmt = body.namedChild(i);
      if (stmt?.type === 'return_statement') {
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
              // Set the functionReturnTaint flag for PASS 2 Step 4b
              ctx.functionReturnTaint.set(funcNodeId, true);
            }
          }
        }
      }
    }
  }
  // No tainted return found — explicitly mark as clean (false).
  // Distinguishes "analyzed, returns clean" from "never analyzed" (undefined).
  const cleanFuncNodeId = ctx.currentScope?.containerNodeId;
  if (cleanFuncNodeId && !ctx.functionReturnTaint.has(cleanFuncNodeId)) {
    ctx.functionReturnTaint.set(cleanFuncNodeId, false);
  }
}

// ---------------------------------------------------------------------------
// preVisitIteration — set up loop variable taint before walking body
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_of_statement' && node.type !== 'for_in_statement') return;

  const iterRight = node.childForFieldName('right');
  if (iterRight) {
    const iterTaint = extractTaintSources(iterRight, ctx);
    if (iterTaint.length > 0) {
      const iterLeft = node.childForFieldName('left');
      if (iterLeft) {
        const findIdents = (n: SyntaxNode): string[] => {
          if (n.type === 'identifier') return [n.text];
          const results: string[] = [];
          for (let c = 0; c < n.namedChildCount; c++) {
            const child = n.namedChild(c);
            if (child) {
              if (child.type === 'identifier') results.push(child.text);
              else if (child.type === 'variable_declarator') {
                const nm = child.childForFieldName('name');
                if (nm?.type === 'identifier') results.push(nm.text);
              } else results.push(...findIdents(child));
            }
          }
          return results;
        };
        for (const varName of findIdents(iterLeft)) {
          ctx.declareVariable(varName, 'const', null, true, iterTaint[0].nodeId);
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration — re-mark loop variable taint after body walk
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_of_statement' && node.type !== 'for_in_statement') return;

  const iterRight = node.childForFieldName('right');
  if (iterRight) {
    const iterTaint = extractTaintSources(iterRight, ctx);
    if (iterTaint.length > 0) {
      const iterLeft = node.childForFieldName('left');
      if (iterLeft) {
        const findIdents = (n: SyntaxNode): string[] => {
          if (n.type === 'identifier') return [n.text];
          const results: string[] = [];
          for (let c = 0; c < n.namedChildCount; c++) {
            const child = n.namedChild(c);
            if (child) {
              if (child.type === 'identifier') results.push(child.text);
              else if (child.type === 'variable_declarator') {
                const nm = child.childForFieldName('name');
                if (nm?.type === 'identifier') results.push(nm.text);
              } else results.push(...findIdents(child));
            }
          }
          return results;
        };
        for (const varName of findIdents(iterLeft)) {
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

export const javascriptProfile: LanguageProfile = {
  id: 'javascript',
  extensions: ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'],

  // Layer 1: AST Node Type Recognition
  functionScopeTypes: FUNCTION_SCOPE_TYPES,
  blockScopeTypes: BLOCK_SCOPE_TYPES,
  classScopeTypes: CLASS_SCOPE_TYPES,

  getScopeType(node: SyntaxNode): ScopeType | null {
    if (FUNCTION_SCOPE_TYPES.has(node.type)) return 'function';
    if (node.type === 'class_declaration' || node.type === 'class') return 'class';
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
  resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
    return _resolveCallee(node);
  },

  resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
    return _resolvePropertyAccess(node);
  },

  lookupCallee(chain: string[]): CalleePattern | null {
    return _lookupCallee(chain);
  },

  analyzeStructure(node: SyntaxNode): StructuralAnalysisResult | null {
    return _analyzeStructure(node);
  },

  // Layer 4: Taint Source Detection
  ingressPattern: /\b(req\.body|req\.query|req\.params|req\.headers|req\.cookies)\b/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) => nodeType === 'lexical_declaration' || nodeType === 'variable_declaration',
  getDeclarationValueNode: (node) => {
    // JS: lexical_declaration/variable_declaration → variable_declarator children → 'value' field
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child?.type === 'variable_declarator') {
        return child.childForFieldName('value');
      }
    }
    return null;
  },
  isStatementContainer: (nodeType: string) => nodeType === 'program' || nodeType === 'statement_block',
};

export default javascriptProfile;
