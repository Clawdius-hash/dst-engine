/**
 * PythonProfile — the second LanguageProfile implementation.
 *
 * Every piece of Python-specific logic lives here: AST node type names,
 * field access patterns, scope rules, callee resolution, taint extraction,
 * and node classification.
 *
 * Key differences from JavaScript:
 *   - `call` not `call_expression`
 *   - `attribute` not `member_expression` (field: `attribute` not `property`)
 *   - `function_definition` not `function_declaration`
 *   - `assignment` not `lexical_declaration` (Python has no declaration syntax)
 *   - NO block scopes (if/for/while/try/with don't create scopes)
 *   - Comprehensions create implicit function scopes
 *   - `module` not `program`, `block` not `statement_block`
 *   - `decorated_definition` wraps functions/classes with decorators
 *   - `string` with `interpolation` children for f-strings (not `template_string`)
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
import { lookupCallee as _lookupCallee } from '../languages/python.js';

// ---------------------------------------------------------------------------
// Constant Folding — resolves string construction at parse time
// ---------------------------------------------------------------------------
// Handles Python evasion patterns like:
//   chr(101)+chr(118)+chr(97)+chr(108)   → "eval"
//   'ev'+'al'                             → "eval"
//   bytes([101,118,97,108]).decode()       → "eval"
//   base64.b64decode('ZXZhbA==').decode()  → "eval"
//   bytearray(b'\x65\x76\x61\x6c').decode() → "eval"
//   ''.join(chr(c) for c in [101,118,97,108]) → "eval"
//
// This is the anti-evasion core. Attackers split dangerous function names
// across chr() calls, base64 encoding, and byte arrays to dodge static
// analysis. We fold them back.

function tryFoldConstant(n: SyntaxNode): string | null {
  // Literal strings — strip quotes and resolve escape sequences
  if (n.type === 'string') {
    // Reject f-strings (they have interpolation children — can't fold)
    const hasInterpolation = n.namedChildren.some(c => c.type === 'interpolation');
    if (hasInterpolation) return null;
    return n.text.replace(/^[bBrRuUfF]*['"](?:''|"")?|(?:['"]''|['"]""|['"])$/g, '');
  }
  // Concatenated strings: "ev" "al" → "eval" (Python implicit concatenation)
  if (n.type === 'concatenated_string') {
    const parts: string[] = [];
    for (let i = 0; i < n.namedChildCount; i++) {
      const child = n.namedChild(i);
      if (child) {
        const cv = tryFoldConstant(child);
        if (cv !== null) parts.push(cv);
        else return null;
      }
    }
    return parts.join('');
  }
  // Number literals — return as string for chr() operations
  if (n.type === 'integer') {
    return n.text;
  }
  // Binary operator: "ev" + "al" → "eval", chr(101)+chr(118) → ...
  if (n.type === 'binary_operator') {
    const left = n.childForFieldName('left');
    const right = n.childForFieldName('right');
    if (left && right) {
      // Check operator — in tree-sitter-python the operator is an anonymous child
      const opNode = n.children.find(c => c.type === '+');
      if (opNode?.text === '+') {
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
  // ── CALL EXPRESSIONS: chr(), bytes().decode(), base64.b64decode().decode(), etc. ──
  if (n.type === 'call') {
    const func = n.childForFieldName('function');
    const args = n.childForFieldName('arguments');
    if (func && args) {
      // ── chr(N) → single character ──
      if (func.type === 'identifier' && func.text === 'chr') {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const code = tryFoldConstant(firstArg);
          if (code !== null) {
            const num = parseInt(code, 10);
            if (!isNaN(num) && num >= 0 && num <= 0x10FFFF) {
              return String.fromCodePoint(num);
            }
          }
        }
      }
      // ── .decode() on bytes()/bytearray()/base64.b64decode() ──
      if (func.type === 'attribute') {
        const method = func.childForFieldName('attribute');
        const innerObj = func.childForFieldName('object');
        if (method?.text === 'decode' && innerObj?.type === 'call') {
          const innerFunc = innerObj.childForFieldName('function');
          const innerArgs = innerObj.childForFieldName('arguments');
          if (innerFunc && innerArgs) {
            // ── bytes([101, 118, 97, 108]).decode() → "eval" ──
            if (innerFunc.type === 'identifier' && innerFunc.text === 'bytes') {
              const firstInnerArg = innerArgs.namedChild(0);
              if (firstInnerArg?.type === 'list') {
                const codes: number[] = [];
                let allLiteral = true;
                for (let i = 0; i < firstInnerArg.namedChildCount; i++) {
                  const el = firstInnerArg.namedChild(i);
                  if (el) {
                    const val = tryFoldConstant(el);
                    if (val !== null) {
                      const num = parseInt(val, 10);
                      if (!isNaN(num) && num >= 0 && num <= 255) {
                        codes.push(num);
                      } else { allLiteral = false; break; }
                    } else { allLiteral = false; break; }
                  }
                }
                if (allLiteral && codes.length > 0) {
                  return String.fromCharCode(...codes);
                }
              }
            }
            // ── bytearray(b'\x65\x76\x61\x6c').decode() → "eval" ──
            if (innerFunc.type === 'identifier' && innerFunc.text === 'bytearray') {
              const firstInnerArg = innerArgs.namedChild(0);
              if (firstInnerArg) {
                const raw = tryFoldConstant(firstInnerArg);
                if (raw !== null) {
                  // If it came from a bytes literal (b'...'), resolve hex escapes
                  return resolveByteEscapes(raw);
                }
              }
            }
            // ── base64.b64decode('ZXZhbA==').decode() → "eval" ──
            if (innerFunc.type === 'attribute') {
              const b64Obj = innerFunc.childForFieldName('object');
              const b64Method = innerFunc.childForFieldName('attribute');
              if (b64Method?.text === 'b64decode' &&
                  b64Obj?.type === 'identifier' && b64Obj.text === 'base64') {
                const firstInnerArg = innerArgs.namedChild(0);
                if (firstInnerArg) {
                  const b64Str = tryFoldConstant(firstInnerArg);
                  if (b64Str !== null) {
                    try {
                      return Buffer.from(b64Str, 'base64').toString('utf-8');
                    } catch { /* not valid base64 */ }
                  }
                }
              }
            }
            // ── Also handle import-aliased b64decode: b64decode('ZXZhbA==').decode() ──
            if (innerFunc.type === 'identifier' && innerFunc.text === 'b64decode') {
              const firstInnerArg = innerArgs.namedChild(0);
              if (firstInnerArg) {
                const b64Str = tryFoldConstant(firstInnerArg);
                if (b64Str !== null) {
                  try {
                    return Buffer.from(b64Str, 'base64').toString('utf-8');
                  } catch { /* not valid base64 */ }
                }
              }
            }
          }
        }
        // ── ''.join(chr(c) for c in [...]) or ''.join([chr(c) for c in [...]]) ──
        if (method?.text === 'join' && innerObj) {
          const sepFolded = tryFoldConstant(innerObj);
          if (sepFolded !== null && sepFolded === '') {
            const firstArg = args.namedChild(0);
            if (firstArg) {
              // Generator expression: chr(c) for c in [101,118,97,108]
              if (firstArg.type === 'generator_expression') {
                const codes = extractChrGeneratorCodes(firstArg);
                if (codes) return String.fromCharCode(...codes);
              }
              // List comprehension: [chr(c) for c in [101,118,97,108]]
              if (firstArg.type === 'list_comprehension') {
                const codes = extractChrGeneratorCodes(firstArg);
                if (codes) return String.fromCharCode(...codes);
              }
              // Simple list of chr() calls: [chr(101), chr(118), ...]
              if (firstArg.type === 'list') {
                const parts: string[] = [];
                let allFolded = true;
                for (let i = 0; i < firstArg.namedChildCount; i++) {
                  const el = firstArg.namedChild(i);
                  if (el) {
                    const folded = tryFoldConstant(el);
                    if (folded !== null) parts.push(folded);
                    else { allFolded = false; break; }
                  }
                }
                if (allFolded && parts.length > 0) return parts.join('');
              }
            }
          }
        }
      }
    }
  }
  return null;
}

// Resolve \xHH and \uHHHH escape sequences in Python byte strings
function resolveByteEscapes(s: string): string {
  return s
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\\\/g, '\\');
}

// Extract integer codes from `chr(c) for c in [101,118,97,108]` generator/comprehension
function extractChrGeneratorCodes(genNode: SyntaxNode): number[] | null {
  // Look for the iterable (a list of integer literals) inside the for_in_clause
  // and verify the body expression is chr(c) or similar
  let bodyExpr: SyntaxNode | null = null;
  let iterableNode: SyntaxNode | null = null;

  for (let i = 0; i < genNode.namedChildCount; i++) {
    const child = genNode.namedChild(i);
    if (!child) continue;
    if (child.type === 'for_in_clause') {
      // The iterable is the `right` field
      iterableNode = child.childForFieldName('right');
    } else if (child.type === 'call' || child.type === 'identifier' || child.type === 'string') {
      bodyExpr = child;
    }
  }

  // Verify body is a chr() call
  if (!bodyExpr || bodyExpr.type !== 'call') return null;
  const bodyFunc = bodyExpr.childForFieldName('function');
  if (!bodyFunc || bodyFunc.type !== 'identifier' || bodyFunc.text !== 'chr') return null;

  if (!iterableNode || iterableNode.type !== 'list') return null;

  const codes: number[] = [];
  for (let i = 0; i < iterableNode.namedChildCount; i++) {
    const el = iterableNode.namedChild(i);
    if (el?.type === 'integer') {
      codes.push(parseInt(el.text, 10));
    } else {
      return null;
    }
  }
  return codes.length > 0 ? codes : null;
}

// ---------------------------------------------------------------------------
// AST Node Type Sets
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'function_definition',
  'lambda',
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  // EMPTY — Python has no block-scoped variables.
  // Variables assigned inside if/for/while/try/with are visible in the
  // enclosing function scope.
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'class_definition',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'assignment',
  'augmented_assignment',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'function_definition',
]);

const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // Flask
  'request.form', 'request.args', 'request.json', 'request.data',
  'request.values', 'request.files', 'request.headers', 'request.cookies',
  'request.environ', 'request.url', 'request.path', 'request.method',
  'request.host', 'request.remote_addr', 'request.content_type',
  'request.get_json', 'request.get_data',
  // Django
  'request.POST', 'request.GET', 'request.FILES', 'request.META',
  'request.COOKIES', 'request.body', 'request.content_params',
  // FastAPI
  'Request.body', 'Request.json', 'Request.form',
  'Request.query_params', 'Request.path_params',
  'Request.headers', 'Request.cookies',
  // sys
  'sys.argv', 'sys.stdin',
  // BaseHTTPRequestHandler (http.server stdlib)
  'self.path', 'self.headers', 'self.rfile', 'self.command',
  'self.client_address', 'self.requestline',
  // WSGI environ
  'environ', 'environ.get',
  // CGI
  'cgi.FieldStorage',
]);

// Comprehension types that create implicit scopes
const COMPREHENSION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'list_comprehension',
  'dict_comprehension',
  'set_comprehension',
  'generator_expression',
]);

// ---------------------------------------------------------------------------
// Helper: extract callee chain from an `attribute` node tree
// ---------------------------------------------------------------------------

function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier') {
    return [node.text];
  }
  if (node.type === 'attribute') {
    const obj = node.childForFieldName('object');
    const attr = node.childForFieldName('attribute');
    if (obj && attr) {
      const chain = extractCalleeChain(obj);
      chain.push(attr.text);
      return chain;
    }
  }
  return []; // computed callee — can't resolve statically
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
// Helper: detect parameterized query calls
// ---------------------------------------------------------------------------
// Recognises: cursor.execute("SELECT ... WHERE id = ?", (user_id,))
// i.e. 2+ args, first arg is a plain string literal (not f-string / concat)
// containing a placeholder (?  %s  $1  :name), second arg is a tuple or list.

const PARAM_PLACEHOLDER_RE = /\?|%s|\$\d+|:[a-zA-Z_]\w*/;

function isParameterizedQuery(callNode: SyntaxNode): boolean {
  const argsNode = callNode.childForFieldName('arguments');
  if (!argsNode) return false;

  // Need at least 2 named children (query string + params)
  const namedArgs: SyntaxNode[] = [];
  for (let i = 0; i < argsNode.namedChildCount; i++) {
    const child = argsNode.namedChild(i);
    if (child) namedArgs.push(child);
  }
  if (namedArgs.length < 2) return false;

  const firstArg = namedArgs[0];
  const secondArg = namedArgs[1];

  // First arg must be a plain string literal — NOT an f-string, not concatenation,
  // not a variable.  In tree-sitter-python a plain string is type `string` with
  // NO `interpolation` children (f-strings have interpolation children).
  if (firstArg.type !== 'string') return false;

  // Reject f-strings: they contain `interpolation` children
  for (let i = 0; i < firstArg.namedChildCount; i++) {
    if (firstArg.namedChild(i)?.type === 'interpolation') return false;
  }

  // The string must contain a parameter placeholder
  if (!PARAM_PLACEHOLDER_RE.test(firstArg.text)) return false;

  // Second arg should be a tuple or list (the bound parameters)
  if (secondArg.type !== 'tuple' && secondArg.type !== 'list') return false;

  return true;
}

// ---------------------------------------------------------------------------
// resolveCallee — resolve a Python `call` node to a NeuralMap node type
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  if (node.type !== 'call') return null;

  let callee = node.childForFieldName('function');
  if (!callee) return null;

  // Unwrap parenthesized expressions
  if (callee.type === 'parenthesized_expression') {
    const inner = callee.namedChild(0);
    if (inner && inner.type === 'identifier') {
      const directPattern = _lookupCallee([inner.text]);
      if (directPattern) {
        return {
          nodeType: directPattern.nodeType,
          subtype: directPattern.subtype,
          tainted: directPattern.tainted,
          chain: [inner.text],
        };
      }
    }
    if (inner && (inner.type === 'identifier' || inner.type === 'attribute')) {
      callee = inner;
    }
  }

  // Chained call: db.collection('users').find({id})
  // The outer `call`'s function child is itself a `call` node
  if (callee.type === 'call') {
    return resolveChainedCall(node);
  }

  // Callee is attribute whose object is a call: session.query(User).filter(...)
  if (callee.type === 'attribute') {
    const attrObj = callee.childForFieldName('object');
    if (attrObj?.type === 'call') {
      const attrName = callee.childForFieldName('attribute');
      if (attrName) {
        const pattern = _lookupCallee([attrName.text]);
        if (pattern) {
          return {
            nodeType: pattern.nodeType,
            subtype: pattern.subtype,
            tainted: pattern.tainted,
            chain: [attrName.text],
          };
        }
      }
      return resolveChainedCall(node);
    }
  }

  const chain = extractCalleeChain(callee);
  if (chain.length === 0) return null;

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

function resolveChainedCall(node: SyntaxNode): ResolvedCalleeResult | null {
  const callee = node.childForFieldName('function');
  if (!callee) return null;

  // Walk outward: the callee is `something.method` where `something` may be a call
  if (callee.type === 'attribute') {
    const methodNode = callee.childForFieldName('attribute');
    if (methodNode) {
      const pattern = _lookupCallee([methodNode.text]);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain: [methodNode.text],
        };
      }
      // Try with the full attribute chain even if inner object is a call
      const objNode = callee.childForFieldName('object');
      if (objNode?.type === 'call') {
        const innerFunc = objNode.childForFieldName('function');
        if (innerFunc) {
          const innerChain = extractCalleeChain(innerFunc);
          if (innerChain.length > 0) {
            innerChain.push(methodNode.text);
            const deepPattern = _lookupCallee(innerChain);
            if (deepPattern) {
              return {
                nodeType: deepPattern.nodeType,
                subtype: deepPattern.subtype,
                tainted: deepPattern.tainted,
                chain: innerChain,
              };
            }
          }
        }
      }
    }
  }

  // Direct call on a call: func()() — rare in Python but possible
  if (callee.type === 'call') {
    const innerFunc = callee.childForFieldName('function');
    if (innerFunc) {
      const chain = extractCalleeChain(innerFunc);
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
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// resolvePropertyAccess — resolve a standalone Python `attribute` node
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  if (node.type !== 'attribute') return null;

  const chain = extractCalleeChain(node);
  if (chain.length < 2) return null;

  const fullPath = chain.join('.');

  // Check tainted paths first
  if (TAINTED_PATHS.has(fullPath)) {
    return {
      nodeType: 'INGRESS',
      subtype: 'http_request',
      tainted: true,
    };
  }

  // Check callee DB for property access patterns (e.g., os.environ, sys.argv)
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
// extractPatternNames — extract variable names from Python unpacking patterns
// ---------------------------------------------------------------------------

function extractPatternNames(pattern: SyntaxNode): string[] {
  const names: string[] = [];

  for (let i = 0; i < pattern.namedChildCount; i++) {
    const child = pattern.namedChild(i);
    if (!child) continue;

    switch (child.type) {
      case 'identifier':
        names.push(child.text);
        break;
      case 'pattern_list':
      case 'tuple_pattern':
      case 'list_pattern':
        names.push(...extractPatternNames(child));
        break;
      case 'list_splat_pattern': {
        // *rest — the identifier is a child
        const ident = child.namedChildren.find(
          (c): c is NonNullable<typeof c> => c !== null && c.type === 'identifier'
        );
        if (ident) names.push(ident.text);
        break;
      }
      default:
        // Recurse into unknown pattern types
        if (child.namedChildCount > 0) {
          names.push(...extractPatternNames(child));
        }
    }
  }

  return names;
}

// ---------------------------------------------------------------------------
// extractTaintSources — the recursive expression X-ray for Python
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

    // -- Leaf: attribute -- check callee DB for taint (e.g., request.form)
    case 'attribute': {
      const resolution = resolvePropertyAccess(expr);
      if (resolution?.tainted) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'python',
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
      if (obj?.type === 'attribute') {
        return extractTaintSources(obj, ctx);
      }
      return [];
    }

    // -- Binary operator: string concatenation, arithmetic --
    case 'binary_operator': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const sources: TaintSourceResult[] = [];
      if (left) sources.push(...extractTaintSources(left, ctx));
      if (right) sources.push(...extractTaintSources(right, ctx));
      return sources;
    }

    // -- Concatenated string: "Hello " "world" --
    case 'concatenated_string': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- F-string: f"prefix {TAINTED} suffix" --
    case 'string': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child?.type === 'interpolation') {
          const inner = child.namedChild(0);
          if (inner) sources.push(...extractTaintSources(inner, ctx));
        }
      }
      return sources;
    }

    // -- Call: sanitize(TAINTED) breaks the chain --
    case 'call': {
      const callResolution = resolveCallee(expr);
      // If this is a sanitizer call, taint STOPS here
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          callResolution.subtype === 'sanitize') {
        return [];
      }
      // If this is an encoder, taint STOPS
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          callResolution.subtype === 'encode') {
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
      // Check receiver: for obj.method(), check if obj is tainted
      const calleeExpr = expr.childForFieldName('function');
      if (calleeExpr?.type === 'attribute') {
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

    // -- Conditional expression (ternary): val if cond else other --
    case 'conditional_expression': {
      const sources: TaintSourceResult[] = [];
      // In Python tree-sitter, conditional_expression has named children:
      // the body (true branch), the condition, and the alternative (false branch)
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Parenthesized: (TAINTED) --
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Assignment expression (walrus): x := TAINTED --
    case 'named_expression': {
      const value = expr.childForFieldName('value');
      return value ? extractTaintSources(value, ctx) : [];
    }

    // -- Await: await TAINTED --
    case 'await': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Starred expression: *TAINTED --
    case 'starred_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Not operator: not TAINTED --
    case 'not_operator': {
      const arg = expr.childForFieldName('argument');
      return arg ? extractTaintSources(arg, ctx) : [];
    }

    // -- Unary operator: -TAINTED, ~TAINTED --
    case 'unary_operator': {
      const arg = expr.childForFieldName('argument');
      return arg ? extractTaintSources(arg, ctx) : [];
    }

    // -- Boolean operator: TAINTED and safe, TAINTED or safe --
    case 'boolean_operator': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const sources: TaintSourceResult[] = [];
      if (left) sources.push(...extractTaintSources(left, ctx));
      if (right) sources.push(...extractTaintSources(right, ctx));
      return sources;
    }

    // -- Comparison: TAINTED == val, TAINTED in list --
    case 'comparison_operator': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Tuple: (TAINTED, safe, TAINTED) --
    case 'tuple': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- List: [TAINTED, safe, TAINTED] --
    case 'list': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Dictionary: {key: TAINTED, ...TAINTED} --
    case 'dictionary': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const pair = expr.namedChild(i);
        if (!pair) continue;
        if (pair.type === 'pair') {
          const value = pair.childForFieldName('value');
          if (value) sources.push(...extractTaintSources(value, ctx));
        } else if (pair.type === 'dictionary_splat') {
          sources.push(...extractTaintSources(pair, ctx));
        }
      }
      return sources;
    }

    // -- Set: {TAINTED, safe} --
    case 'set': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Subscript: obj[TAINTED] or TAINTED[key] --
    case 'subscript': {
      const sources: TaintSourceResult[] = [];
      const obj = expr.childForFieldName('value');
      const subscriptVal = expr.childForFieldName('subscript');
      if (obj) sources.push(...extractTaintSources(obj, ctx));
      if (subscriptVal) sources.push(...extractTaintSources(subscriptVal, ctx));
      return sources;
    }

    // -- Dictionary splat: **TAINTED --
    case 'dictionary_splat': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Keyword argument: key=TAINTED --
    case 'keyword_argument': {
      const value = expr.childForFieldName('value');
      return value ? extractTaintSources(value, ctx) : [];
    }

    // -- Expression list: a, b, c (RHS of tuple unpacking) --
    case 'expression_list': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Generator/comprehension expressions: (x for x in TAINTED), [x for x in TAINTED] --
    case 'generator_expression':
    case 'list_comprehension':
    case 'dict_comprehension':
    case 'set_comprehension': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- for_in_clause: for x in ITERABLE --
    case 'for_in_clause': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Default: unknown expression type --
    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration — Python assignment/augmented_assignment
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'assignment' && node.type !== 'augmented_assignment') {
    return;
  }

  // Python has no var/let/const — all variables behave like `let`
  const kind: VariableInfo['kind'] = 'let';

  const nameNode = node.childForFieldName('left');
  if (!nameNode) return;

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

  // Multi-hop taint propagation: if no producing node was found (the value
  // is a plain identifier like `b = a`), look up the source variable
  // and inherit its taint status and producing node.
  if (!producingNodeId) {
    const valueNode = node.childForFieldName('right');
    if (valueNode?.type === 'identifier') {
      const sourceVar = ctx.resolveVariable(valueNode.text);
      if (sourceVar) {
        tainted = sourceVar.tainted;
        producingNodeId = sourceVar.producingNodeId;
      }
    }
  }

  // Deep taint extraction fallback: if the producing node is NOT tainted
  // (e.g., lastCreatedNodeId points to a CONTROL/branch from a conditional
  // expression, or a non-tainted node in a tuple), use extractTaintSources
  // to recursively scan the RHS value expression for embedded taint sources.
  // This catches patterns like:
  //   path, query = self.path.split('?', 1) if cond else (self.path, "")
  //   params = dict(... urllib.parse.unquote(..., query) ...)
  // where tainted data flows through complex expressions.
  if (!tainted) {
    const valueNode = node.childForFieldName('right');
    if (valueNode) {
      const deepSources = extractTaintSources(valueNode, ctx);
      if (deepSources.length > 0) {
        tainted = true;
        producingNodeId = deepSources[0].nodeId;

        // For augmented assignments (content += tainted_expr), create a
        // TRANSFORM/assignment node with DATA_FLOW edges so the BFS can
        // traverse from INGRESS through to EGRESS. The classifyNode handler
        // for augmented_assignment is never reached (value-first early return),
        // so this is the only place these edges can be created.
        if (node.type === 'augmented_assignment') {
          const augN = createNode({
            label: (nameNode.text?.slice(0, 40) ?? '?') + ' +=',
            node_type: 'TRANSFORM',
            node_subtype: 'assignment',
            language: 'python',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: node.text.slice(0, 200),
            analysis_snapshot: node.text.slice(0, 2000),
          });
          for (const source of deepSources) {
            ctx.addDataFlow(source.nodeId, augN.id, source.name, 'unknown', true);
          }
          augN.data_out.push({
            name: 'result',
            source: augN.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
          ctx.neuralMap.nodes.push(augN);
          ctx.lastCreatedNodeId = augN.id;
          ctx.emitContainsIfNeeded(augN.id);
          producingNodeId = augN.id;
        }
      }
    }
  }

  // Cross-function taint: val = get_input(request)
  if (!producingNodeId) {
    const valueNode = node.childForFieldName('right');
    if (valueNode?.type === 'call') {
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

  // Alias chain detection: q = db.query -> store ['db', 'query'] on the variable
  let aliasChain: string[] | undefined;
  {
    const valueNode = node.childForFieldName('right');
    if (valueNode?.type === 'attribute') {
      const chain: string[] = [];
      let cur: SyntaxNode | null = valueNode;
      while (cur?.type === 'attribute') {
        const attr = cur.childForFieldName('attribute');
        if (attr) chain.unshift(attr.text);
        cur = cur.childForFieldName('object');
      }
      if (cur?.type === 'identifier') {
        chain.unshift(cur.text);
        aliasChain = chain;
      }
    }
  }

  // Constant folding: action = "quer" + "y" -> constantValue = "query"
  // Also handles evasion: name = chr(101)+chr(118)+chr(97)+chr(108) -> "eval"
  let constantValue: string | undefined;
  {
    const valueNode = node.childForFieldName('right');
    if (valueNode) {
      const folded = tryFoldConstant(valueNode);
      if (folded !== null) constantValue = folded;
    }
  }

  // Preserve existing taint: if the variable was pre-declared as tainted
  // (e.g., for loop variable from tainted iterable), don't overwrite with false.
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
      if (constantValue) v.constantValue = constantValue;
    }
  };

  if (nameNode.type === 'identifier') {
    preserveTaint(nameNode.text, tainted, producingNodeId);

    // Emit META node for string assignments so CWE-798 can find hardcoded creds.
    // classifyNode is NOT called for assignments (early return in value-first path),
    // so this must live here.
    const rhsNode = node.childForFieldName('right');
    if (rhsNode && (rhsNode.type === 'string' || rhsNode.type === 'concatenated_string')) {
      const snap = node.text.slice(0, 200);
      const metaNode = createNode({
        label: nameNode.text,
        node_type: 'META',
        node_subtype: 'config_value',
        language: 'python',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: snap,
      });
      ctx.neuralMap.nodes.push(metaNode);
      ctx.emitContainsIfNeeded(metaNode.id);
    }
  } else if (
    nameNode.type === 'pattern_list' ||
    nameNode.type === 'tuple_pattern' ||
    nameNode.type === 'list_pattern'
  ) {
    extractPatternNames(nameNode).forEach(n =>
      preserveTaint(n, tainted, producingNodeId)
    );
  } else if (nameNode.type === 'attribute') {
    // obj.x = val — property assignment, don't declare a new variable
    // but check if the object variable should be marked tainted
    const obj = nameNode.childForFieldName('object');
    if (obj?.type === 'identifier' && tainted) {
      const varInfo = ctx.resolveVariable(obj.text);
      if (varInfo) {
        varInfo.tainted = true;
        varInfo.producingNodeId = producingNodeId;
      }
    }
  } else if (nameNode.type === 'subscript') {
    // obj[key] = val — subscript assignment
    const obj = nameNode.childForFieldName('value');
    if (obj?.type === 'identifier' && tainted) {
      const varInfo = ctx.resolveVariable(obj.text);
      if (varInfo) {
        varInfo.tainted = true;
        varInfo.producingNodeId = producingNodeId;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// processFunctionParams — Python parameter node types
// ---------------------------------------------------------------------------

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  const declareParam = (name: string) => {
    const producingId = ctx.pendingCallbackTaint.get(name) ?? null;
    const isTainted = producingId !== null;
    if (isTainted) ctx.pendingCallbackTaint.delete(name);
    ctx.declareVariable(name, 'param', null, isTainted, producingId);
  };

  // Handle lambda parameters (lambda_parameters)
  let paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) {
    // Lambda may have its params in a different field
    // Check for no-parameter lambda
    return;
  }

  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    switch (param.type) {
      case 'identifier':
        declareParam(param.text);
        break;
      case 'default_parameter': {
        // def foo(a=10) — name field holds the identifier
        const nameChild = param.childForFieldName('name');
        if (nameChild && nameChild.type === 'identifier') {
          declareParam(nameChild.text);
        }
        break;
      }
      case 'typed_parameter': {
        // def foo(a: int) — first named child is usually the identifier
        // In tree-sitter-python, typed_parameter has a field `name` or the identifier is a child
        const nameChild = param.namedChildren.find(
          (c): c is NonNullable<typeof c> => c !== null && c.type === 'identifier'
        );
        if (nameChild) declareParam(nameChild.text);
        break;
      }
      case 'typed_default_parameter': {
        // def foo(a: int = 10) — has name, type, and value
        const nameChild = param.childForFieldName('name');
        if (nameChild && nameChild.type === 'identifier') {
          declareParam(nameChild.text);
        }
        break;
      }
      case 'list_splat_pattern': {
        // *args
        const ident = param.namedChildren.find(
          (c): c is NonNullable<typeof c> => c !== null && c.type === 'identifier'
        );
        if (ident) declareParam(ident.text);
        break;
      }
      case 'dictionary_splat_pattern': {
        // **kwargs
        const ident = param.namedChildren.find(
          (c): c is NonNullable<typeof c> => c !== null && c.type === 'identifier'
        );
        if (ident) declareParam(ident.text);
        break;
      }
      case 'tuple_pattern':
      case 'pattern_list':
        extractPatternNames(param).forEach(n => declareParam(n));
        break;
    }
  }
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of the switch statement for Python
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  // Process function definitions — register function name in outer scope
  if (node.type === 'function_definition') {
    const funcName = node.childForFieldName('name');
    if (funcName && ctx.scopeStack.length >= 2) {
      // Declare in the scope OUTSIDE the function
      const outerScope = ctx.scopeStack[ctx.scopeStack.length - 2];
      outerScope.variables.set(funcName.text, {
        name: funcName.text,
        declaringNodeId: null,
        producingNodeId: null,
        kind: 'let', // Python functions are like let bindings
        tainted: false,
      });
    }
  }

  switch (node.type) {
    // -- FUNCTION DEFINITION --
    case 'function_definition': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const isAsync = node.child(0)?.type === 'async' || node.child(0)?.text === 'async';
      const fnNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'python',
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

    // -- LAMBDA --
    case 'lambda': {
      let lambdaName = 'anonymous';
      // If lambda is assigned to a variable, use that name
      if (
        node.parent?.type === 'assignment' &&
        node.parent.childForFieldName('left')?.type === 'identifier'
      ) {
        lambdaName = node.parent.childForFieldName('left')!.text;
      }
      const lambdaNode = createNode({
        label: lambdaName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'python',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      lambdaNode.tags.push('lambda');
      ctx.neuralMap.nodes.push(lambdaNode);
      ctx.lastCreatedNodeId = lambdaNode.id;
      ctx.emitContainsIfNeeded(lambdaNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = lambdaNode.id;
      if (lambdaName !== 'anonymous') ctx.functionRegistry.set(lambdaName, lambdaNode.id);
      break;
    }

    // -- CLASS DEFINITION --
    case 'class_definition': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousClass';
      const classNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'python',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      // Check for superclasses
      const superclasses = node.childForFieldName('superclasses');
      if (superclasses) {
        classNode.tags.push('inherits');
      }
      ctx.neuralMap.nodes.push(classNode);
      ctx.lastCreatedNodeId = classNode.id;
      ctx.emitContainsIfNeeded(classNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = classNode.id;
      break;
    }

    // -- IMPORT STATEMENTS --
    case 'import_statement': {
      // import os, sys
      // import requests as http  (aliased_import child)
      const names: string[] = [];
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child) names.push(child.text);
      }
      const moduleName = names.join(', ') || 'unknown';
      const importNode = createNode({
        label: moduleName,
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'python',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(importNode);
      ctx.lastCreatedNodeId = importNode.id;
      ctx.emitContainsIfNeeded(importNode.id);

      // Track import aliases: `import requests as http` → alias 'http' → aliasChain ['requests']
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child?.type === 'aliased_import') {
          const nameNode = child.childForFieldName('name');
          const aliasNode = child.childForFieldName('alias');
          if (nameNode && aliasNode) {
            const realName = nameNode.text;
            const alias = aliasNode.text;
            ctx.declareVariable(alias, 'import', importNode.id, false, null);
            const v = ctx.resolveVariable(alias);
            if (v) v.aliasChain = [realName];
          }
        }
      }
      break;
    }
    case 'import_from_statement': {
      // from flask import request
      // from os.path import join as pjoin  (aliased_import child)
      const moduleNode = node.childForFieldName('module_name');
      const moduleName = moduleNode?.text ?? 'unknown';
      const importNode = createNode({
        label: moduleName,
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'python',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(importNode);
      ctx.lastCreatedNodeId = importNode.id;
      ctx.emitContainsIfNeeded(importNode.id);

      // Track from-import names: `from flask import render_template_string`
      // → declare 'render_template_string' with aliasChain ['flask', 'render_template_string']
      // This enables phoneme lookup: render_template_string() → flask.render_template_string in dict
      const moduleParts = moduleName.split('.');
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child?.type === 'aliased_import') {
          // from os.path import join as pjoin → alias 'pjoin' → aliasChain ['os', 'path', 'join']
          const nameNode = child.childForFieldName('name');
          const aliasNode = child.childForFieldName('alias');
          if (nameNode && aliasNode) {
            const realName = nameNode.text;
            const alias = aliasNode.text;
            ctx.declareVariable(alias, 'import', importNode.id, false, null);
            const v = ctx.resolveVariable(alias);
            if (v) v.aliasChain = [...moduleParts, realName];
          }
        } else if (child?.type === 'dotted_name' && child !== moduleNode) {
          // from flask import render_template_string → 'render_template_string' → ['flask', 'render_template_string']
          const importedName = child.text;
          ctx.declareVariable(importedName, 'import', importNode.id, false, null);
          const v = ctx.resolveVariable(importedName);
          if (v) v.aliasChain = [...moduleParts, importedName];
        }
      }
      break;
    }

    // -- CALL EXPRESSION: classify by callee --
    case 'call': {
      // Pre-resolve import aliases before standard callee resolution.
      // `import requests as http` → http.get(url) should resolve as requests.get(url)
      // Without this, the wildcard matcher might claim `get` as STORAGE/db_read.
      let resolution: ResolvedCalleeResult | null = null;
      {
        const preCallee = node.childForFieldName('function');
        if (preCallee?.type === 'attribute') {
          const preChain = extractCalleeChain(preCallee);
          if (preChain.length >= 2) {
            const preRootVar = ctx.resolveVariable(preChain[0]);
            if (preRootVar?.aliasChain) {
              const resolvedChain = [...preRootVar.aliasChain, ...preChain.slice(1)];
              const aliasPattern = _lookupCallee(resolvedChain);
              if (aliasPattern) {
                resolution = {
                  nodeType: aliasPattern.nodeType,
                  subtype: aliasPattern.subtype,
                  tainted: aliasPattern.tainted,
                  chain: resolvedChain,
                };
              }
            }
          }
        }
      }
      // ── CONSTANT FOLDING: getattr(__builtins__, chr(101)+chr(118)+...) ──
      // Must run BEFORE resolveCallee so we resolve getattr to the *target*
      // function (e.g., eval) rather than classifying it as TRANSFORM/calculate.
      if (!resolution) {
        const foldCallee = node.childForFieldName('function');
        const foldArgs = node.childForFieldName('arguments');
        if (foldCallee?.type === 'identifier' && foldCallee.text === 'getattr' && foldArgs) {
          const secondArg = foldArgs.namedChild(1);
          if (secondArg) {
            const foldedName = tryFoldConstant(secondArg);
            if (foldedName) {
              const getattrPattern = _lookupCallee([foldedName]);
              if (getattrPattern) {
                resolution = {
                  nodeType: getattrPattern.nodeType,
                  subtype: getattrPattern.subtype,
                  tainted: getattrPattern.tainted,
                  chain: ['getattr', foldedName],
                };
              }
            }
          }
        }
      }

      if (!resolution) resolution = resolveCallee(node);

      // ── CONSTANT FOLDING: __import__(chr(111)+chr(115)) → __import__('os') ──
      // Fold function arguments to discover hidden module/function names.
      if (resolution) {
        const calleeNode = node.childForFieldName('function');
        const foldArgs = node.childForFieldName('arguments');
        if (calleeNode?.type === 'identifier' && foldArgs) {
          const calleeName = calleeNode.text;
          // For __import__ and similar calls, try to fold the first argument
          // to set a constantValue tag so downstream analysis knows the resolved name
          if (calleeName === '__import__' || calleeName === 'eval' || calleeName === 'exec') {
            const firstArg = foldArgs.namedChild(0);
            if (firstArg) {
              const foldedArg = tryFoldConstant(firstArg);
              if (foldedArg) {
                // Re-resolve with the folded argument for __import__
                if (calleeName === '__import__') {
                  const importPattern = _lookupCallee([foldedArg]);
                  if (importPattern) {
                    resolution = {
                      nodeType: importPattern.nodeType,
                      subtype: importPattern.subtype,
                      tainted: importPattern.tainted,
                      chain: ['__import__', foldedArg],
                    };
                  }
                }
              }
            }
          }
        }
      }

      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'python',
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

        // ── Parameterized query detection ──────────────────────────
        // When a STORAGE call (e.g. cursor.execute) uses a parameterized
        // query pattern, the user-supplied values in the params tuple/list
        // are bound safely by the DB driver and should NOT be treated as
        // tainted input flowing into the query.  We:
        //   1. Emit a CONTROL/parameterized_query node so the verifier's
        //      BFS sees INGRESS → CONTROL → STORAGE (safe path).
        //   2. Skip taint extraction for the parameters argument (index >= 1).
        const parameterized =
          resolution.nodeType === 'STORAGE' &&
          (resolution.subtype === 'db_write' || resolution.subtype === 'db_read') &&
          isParameterizedQuery(node);

        if (parameterized) {
          const controlNode = createNode({
            label: 'parameterized_query',
            node_type: 'CONTROL',
            node_subtype: 'parameterized_query',
            language: 'python',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
          });
          ctx.neuralMap.nodes.push(controlNode);
          ctx.emitContainsIfNeeded(controlNode.id);
          // Edge: CONTROL → STORAGE
          n.edges.push({
            edge_type: 'DATA_FLOW',
            source: controlNode.id,
            target: n.id,
          });
          controlNode.edges.push({
            edge_type: 'DATA_FLOW',
            source: controlNode.id,
            target: n.id,
          });
        }

        // Data flow: resolve arguments via recursive taint extraction
        const argsNode = node.childForFieldName('arguments');
        let callHasTaintedArgs = false;
        if (argsNode) {
          for (let a = 0; a < argsNode.namedChildCount; a++) {
            const arg = argsNode.namedChild(a);
            if (!arg) continue;

            // For parameterized queries, skip taint from the bound-params
            // argument (index >= 1). The DB driver binds those safely.
            if (parameterized && a >= 1) continue;

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
        if (calleeExprForReceiver?.type === 'attribute') {
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

        // Array/list taint propagation: mutating methods
        if (callHasTaintedArgs && resolution.subtype === 'calculate') {
          const calleeExpr = node.childForFieldName('function');
          if (calleeExpr?.type === 'attribute') {
            const receiverObj = calleeExpr.childForFieldName('object');
            const methodAttr = calleeExpr.childForFieldName('attribute');
            const MUTATING_METHODS = new Set(['append', 'extend', 'insert', 'add', 'update', 'setdefault']);
            if (receiverObj?.type === 'identifier' && methodAttr && MUTATING_METHODS.has(methodAttr.text)) {
              const arrVar = ctx.resolveVariable(receiverObj.text);
              if (arrVar) {
                arrVar.tainted = true;
                arrVar.producingNodeId = n.id;
              }
            }
          }
        }

        // Callback parameter taint: fn(lambda x: process(x)) with tainted args
        if (callHasTaintedArgs) {
          const callArgs = node.childForFieldName('arguments');
          if (callArgs) {
            for (let ai = 0; ai < callArgs.namedChildCount; ai++) {
              const arg = callArgs.namedChild(ai);
              if (arg && arg.type === 'lambda') {
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
        // -- Computed property resolution: db[action](...) where action = "query" --
        // Also handles inline concat: globals()['ev' + 'al'](...) → eval
        // And evasion patterns: globals()[chr(101)+chr(118)+chr(97)+chr(108)](x) → eval
        const computedCallee = node.childForFieldName('function');
        if (computedCallee?.type === 'subscript') {
          const compObj = computedCallee.childForFieldName('value');
          const compIdx = computedCallee.childForFieldName('subscript');
          // Try inline constant folding first: obj[chr(101)+chr(118)+'al']()
          let resolvedPropertyName: string | null = null;
          if (compIdx) {
            resolvedPropertyName = tryFoldConstant(compIdx);
          }
          // Fall back to variable lookup: name = 'eval'; obj[name]()
          if (!resolvedPropertyName && compIdx?.type === 'identifier') {
            const idxVar = ctx.resolveVariable(compIdx.text);
            if (idxVar?.constantValue) resolvedPropertyName = idxVar.constantValue;
          }
          if (compObj && resolvedPropertyName) {
            // Extract chain from compObj (may be identifier or call like globals())
            const objChain = compObj.type === 'identifier' ? [compObj.text] :
              (compObj.type === 'call' ? (() => {
                const fn = compObj.childForFieldName('function');
                return fn?.type === 'identifier' ? [fn.text + '()'] : [compObj.text.slice(0, 30)];
              })() :
              (compObj.type === 'attribute' ? extractCalleeChain(compObj) : [compObj.text.slice(0, 30)]));
            const compChain = [...objChain, resolvedPropertyName];
            const compPattern = _lookupCallee(compChain);
            // Also try just the resolved property name — for getattr(__builtins__, 'eval') → eval
            const directPattern = !compPattern ? _lookupCallee([resolvedPropertyName]) : null;
            const finalPattern = compPattern || directPattern;
            if (finalPattern) {
              const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const compN = createNode({
                label,
                node_type: finalPattern.nodeType,
                node_subtype: finalPattern.subtype,
                language: 'python',
                file: ctx.neuralMap.source_file,
                line_start: node.startPosition.row + 1,
                line_end: node.endPosition.row + 1,
                code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
              });
              if (finalPattern.nodeType === 'EXTERNAL' && finalPattern.subtype === 'system_exec') {
                compN.attack_surface.push('command_injection');
              }
              compN.tags.push('constant_folded');
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
          // If the index is tainted (user-controlled), flag for runtime evaluation.
          if (!resolvedPropertyName && compObj && compIdx) {
            const idxTaint = extractTaintSources(compIdx, ctx);
            if (idxTaint.length > 0) {
              const dynNode = createNode({
                label: node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text,
                node_type: 'EXTERNAL',
                node_subtype: 'dynamic_dispatch',
                language: 'python',
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

        // -- Variable alias resolution: q = db.query -> q(...) resolves as db.query --
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
                language: 'python',
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

        // -- Import alias resolution for attribute callees (fallback):
        //    `import requests as http` → http.get(url) resolves as requests.get(url)
        //    Primary resolution happens above (before resolveCallee), this catches edge cases. --
        if (aliasCalleeNode?.type === 'attribute') {
          const chain = extractCalleeChain(aliasCalleeNode);
          if (chain.length >= 2) {
            const rootVar = ctx.resolveVariable(chain[0]);
            if (rootVar?.aliasChain) {
              // Replace the aliased root with the real module name(s)
              const resolvedChain = [...rootVar.aliasChain, ...chain.slice(1)];
              const importAliasPattern = _lookupCallee(resolvedChain);
              if (importAliasPattern) {
                const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
                const importAliasN = createNode({
                  label,
                  node_type: importAliasPattern.nodeType,
                  node_subtype: importAliasPattern.subtype,
                  language: 'python',
                  file: ctx.neuralMap.source_file,
                  line_start: node.startPosition.row + 1,
                  line_end: node.endPosition.row + 1,
                  code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
                });
                if (importAliasPattern.tainted) {
                  importAliasN.data_out.push({
                    name: 'result',
                    source: importAliasN.id,
                    data_type: 'unknown',
                    tainted: true,
                    sensitivity: 'NONE',
                  });
                }
                if (importAliasPattern.nodeType === 'INGRESS') {
                  importAliasN.attack_surface.push('user_input');
                }
                if (importAliasPattern.nodeType === 'EXTERNAL' && importAliasPattern.subtype === 'system_exec') {
                  importAliasN.attack_surface.push('command_injection');
                }
                ctx.neuralMap.nodes.push(importAliasN);
                ctx.lastCreatedNodeId = importAliasN.id;
                ctx.emitContainsIfNeeded(importAliasN.id);
                const importAliasArgs = node.childForFieldName('arguments');
                let importAliasHasTaintedArgs = false;
                if (importAliasArgs) {
                  for (let a = 0; a < importAliasArgs.namedChildCount; a++) {
                    const arg = importAliasArgs.namedChild(a);
                    if (!arg) continue;
                    const taintSources = extractTaintSources(arg, ctx);
                    if (taintSources.length > 0) importAliasHasTaintedArgs = true;
                    for (const source of taintSources) {
                      ctx.addDataFlow(source.nodeId, importAliasN.id, source.name, 'unknown', true);
                    }
                  }
                }
                // Taint-through: if tainted data flows in, mark output tainted
                if (importAliasHasTaintedArgs && !importAliasN.data_out.some((d: any) => d.tainted)) {
                  importAliasN.data_out.push({
                    name: 'result',
                    source: importAliasN.id,
                    data_type: 'unknown',
                    tainted: true,
                    sensitivity: 'NONE',
                  });
                }
                break;
              }
            }
          }
        }

        // -- Unresolved call -- check if it's a locally-defined function --
        const calleeNode = node.childForFieldName('function');
        let calleeName: string | null = null;
        if (calleeNode?.type === 'identifier') {
          calleeName = calleeNode.text;
        } else if (calleeNode?.type === 'attribute') {
          calleeName = calleeNode.childForFieldName('attribute')?.text ?? null;
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
              language: 'python',
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

      // CALLS edge: capture simple identifier calls
      const callFuncNode = node.childForFieldName('function');
      if (callFuncNode && callFuncNode.type === 'identifier') {
        const containerId = ctx.getCurrentContainerId();
        if (containerId) {
          const isAsync = node.parent?.type === 'await';
          ctx.pendingCalls.push({
            callerContainerId: containerId,
            calleeName: callFuncNode.text,
            isAsync,
          });
        }
      }

      // Also handle: map(process_item, items) — function ref passed as argument
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

    // -- ATTRIBUTE: standalone property access --
    case 'attribute': {
      // Skip if this attribute is the callee of a call node
      const funcNode = node.parent?.childForFieldName('function');
      const parentIsCall = node.parent?.type === 'call' &&
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
            language: 'python',
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
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      break;
    }
    case 'for_statement': {
      const isAsync = node.child(0)?.type === 'async' || node.child(0)?.text === 'async';
      const forN = createNode({ label: isAsync ? 'async for' : 'for', node_type: 'CONTROL', node_subtype: isAsync ? 'async_loop' : 'loop', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      if (isAsync) forN.tags.push('async-iteration');
      // Check if the iterable is tainted
      const forRight = node.childForFieldName('right');
      if (forRight) {
        const iterTaint = extractTaintSources(forRight, ctx);
        if (iterTaint.length > 0) {
          forN.data_out.push({
            name: 'iteration', source: forN.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE',
          });
        }
      }
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      break;
    }
    case 'while_statement': {
      const whileN = createNode({ label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whileN); ctx.lastCreatedNodeId = whileN.id; ctx.emitContainsIfNeeded(whileN.id);
      break;
    }
    case 'try_statement': {
      const tryN = createNode({ label: 'try/except', node_type: 'CONTROL', node_subtype: 'error_handler', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(tryN); ctx.lastCreatedNodeId = tryN.id; ctx.emitContainsIfNeeded(tryN.id);
      break;
    }
    case 'with_statement': {
      const isAsync = node.child(0)?.type === 'async' || node.child(0)?.text === 'async';
      const withN = createNode({ label: isAsync ? 'async with' : 'with', node_type: 'CONTROL', node_subtype: 'resource_manager', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      if (isAsync) withN.tags.push('async');
      withN.tags.push('context-manager');
      ctx.neuralMap.nodes.push(withN); ctx.lastCreatedNodeId = withN.id; ctx.emitContainsIfNeeded(withN.id);
      break;
    }
    case 'match_statement': {
      const matchN = createNode({ label: 'match', node_type: 'CONTROL', node_subtype: 'branch', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      matchN.tags.push('pattern-matching');
      ctx.neuralMap.nodes.push(matchN); ctx.lastCreatedNodeId = matchN.id; ctx.emitContainsIfNeeded(matchN.id);
      break;
    }
    case 'case_clause': {
      const caseN = createNode({ label: 'case', node_type: 'CONTROL', node_subtype: 'case', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(caseN); ctx.lastCreatedNodeId = caseN.id; ctx.emitContainsIfNeeded(caseN.id);
      break;
    }

    // -- Conditional expression (Python ternary: val if cond else other) --
    case 'conditional_expression': {
      const ternN = createNode({ label: 'conditional', node_type: 'CONTROL', node_subtype: 'branch', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ternN); ctx.lastCreatedNodeId = ternN.id; ctx.emitContainsIfNeeded(ternN.id);
      break;
    }

    // -- Comprehensions --
    case 'list_comprehension': {
      const lcN = createNode({ label: '[...]', node_type: 'TRANSFORM', node_subtype: 'comprehension', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      lcN.tags.push('list-comprehension');
      ctx.neuralMap.nodes.push(lcN); ctx.lastCreatedNodeId = lcN.id; ctx.emitContainsIfNeeded(lcN.id);
      break;
    }
    case 'dict_comprehension': {
      const dcN = createNode({ label: '{...}', node_type: 'TRANSFORM', node_subtype: 'comprehension', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      dcN.tags.push('dict-comprehension');
      ctx.neuralMap.nodes.push(dcN); ctx.lastCreatedNodeId = dcN.id; ctx.emitContainsIfNeeded(dcN.id);
      break;
    }
    case 'set_comprehension': {
      const scN = createNode({ label: '{...}', node_type: 'TRANSFORM', node_subtype: 'comprehension', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      scN.tags.push('set-comprehension');
      ctx.neuralMap.nodes.push(scN); ctx.lastCreatedNodeId = scN.id; ctx.emitContainsIfNeeded(scN.id);
      break;
    }
    case 'generator_expression': {
      const genN = createNode({ label: '(...)', node_type: 'STRUCTURAL', node_subtype: 'generator', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      genN.tags.push('generator');
      ctx.neuralMap.nodes.push(genN); ctx.lastCreatedNodeId = genN.id; ctx.emitContainsIfNeeded(genN.id);
      break;
    }

    // -- Yield --
    case 'yield': {
      const yieldN = createNode({ label: 'yield', node_type: 'CONTROL', node_subtype: 'yield', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(yieldN); ctx.lastCreatedNodeId = yieldN.id; ctx.emitContainsIfNeeded(yieldN.id);
      break;
    }

    // -- Await --
    case 'await': {
      const awaitN = createNode({ label: 'await', node_type: 'CONTROL', node_subtype: 'await', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      awaitN.tags.push('async');
      ctx.neuralMap.nodes.push(awaitN); ctx.lastCreatedNodeId = awaitN.id; ctx.emitContainsIfNeeded(awaitN.id);
      break;
    }

    // -- Return/Raise/Break/Continue/Pass --
    case 'return_statement': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }
    case 'raise_statement': {
      const raiseN = createNode({ label: 'raise', node_type: 'CONTROL', node_subtype: 'throw', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      raiseN.tags.push('error-source');
      ctx.neuralMap.nodes.push(raiseN); ctx.lastCreatedNodeId = raiseN.id; ctx.emitContainsIfNeeded(raiseN.id);
      break;
    }
    case 'break_statement': {
      const breakN = createNode({ label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(breakN); ctx.lastCreatedNodeId = breakN.id; ctx.emitContainsIfNeeded(breakN.id);
      break;
    }
    case 'continue_statement': {
      const contN = createNode({ label: 'continue', node_type: 'CONTROL', node_subtype: 'continue', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(contN); ctx.lastCreatedNodeId = contN.id; ctx.emitContainsIfNeeded(contN.id);
      break;
    }
    case 'pass_statement': {
      const passN = createNode({ label: 'pass', node_type: 'CONTROL', node_subtype: 'noop', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: 'pass' });
      ctx.neuralMap.nodes.push(passN); ctx.lastCreatedNodeId = passN.id; ctx.emitContainsIfNeeded(passN.id);
      break;
    }

    // -- Assert --
    case 'assert_statement': {
      const assertN = createNode({ label: 'assert', node_type: 'CONTROL', node_subtype: 'guard', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      assertN.tags.push('assertion');
      ctx.neuralMap.nodes.push(assertN); ctx.lastCreatedNodeId = assertN.id; ctx.emitContainsIfNeeded(assertN.id);
      break;
    }

    // -- Delete --
    case 'delete_statement': {
      const delN = createNode({ label: 'del', node_type: 'TRANSFORM', node_subtype: 'delete', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      delN.tags.push('mutation');
      ctx.neuralMap.nodes.push(delN); ctx.lastCreatedNodeId = delN.id; ctx.emitContainsIfNeeded(delN.id);
      break;
    }

    // -- Global / Nonlocal — scope modifiers --
    case 'global_statement': {
      const globalN = createNode({ label: 'global', node_type: 'META', node_subtype: 'scope_modifier', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(globalN); ctx.lastCreatedNodeId = globalN.id; ctx.emitContainsIfNeeded(globalN.id);
      break;
    }
    case 'nonlocal_statement': {
      const nonlocalN = createNode({ label: 'nonlocal', node_type: 'META', node_subtype: 'scope_modifier', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(nonlocalN); ctx.lastCreatedNodeId = nonlocalN.id; ctx.emitContainsIfNeeded(nonlocalN.id);
      break;
    }

    // -- Decorated definition — extract decorator info --
    case 'decorated_definition': {
      // Find all decorator children
      const decorators = node.namedChildren.filter(c => c.type === 'decorator');
      for (const dec of decorators) {
        const decoratorExpr = dec.namedChildren[0]?.text ?? '?';
        const decN = createNode({ label: `@${decoratorExpr}`, node_type: 'META', node_subtype: 'decorator', language: 'python', file: ctx.neuralMap.source_file, line_start: dec.startPosition.row + 1, line_end: dec.endPosition.row + 1, code_snapshot: dec.text.slice(0, 200), analysis_snapshot: dec.text.slice(0, 2000) });
        decN.tags.push('decorator');
        ctx.neuralMap.nodes.push(decN); ctx.lastCreatedNodeId = decN.id; ctx.emitContainsIfNeeded(decN.id);
      }
      break;
    }

    // -- Exception handler --
    case 'except_clause': {
      const exceptType = node.namedChildren.find(c => c.type !== 'block' && c.type !== 'as_pattern');
      const catchN = createNode({ label: `except(${exceptType?.text ?? ''})`, node_type: 'CONTROL', node_subtype: 'catch', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      catchN.tags.push('error-handler');
      ctx.neuralMap.nodes.push(catchN); ctx.lastCreatedNodeId = catchN.id; ctx.emitContainsIfNeeded(catchN.id);
      break;
    }
    case 'finally_clause': {
      const finallyN = createNode({ label: 'finally', node_type: 'CONTROL', node_subtype: 'finally', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(finallyN); ctx.lastCreatedNodeId = finallyN.id; ctx.emitContainsIfNeeded(finallyN.id);
      break;
    }

    // -- F-string (string with interpolation) --
    case 'string': {
      const hasInterpolation = node.namedChildren.some(c => c.type === 'interpolation');
      if (hasInterpolation) {
        const fstrN = createNode({ label: 'f-string', node_type: 'TRANSFORM', node_subtype: 'template_string', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(fstrN); ctx.lastCreatedNodeId = fstrN.id; ctx.emitContainsIfNeeded(fstrN.id);
      }
      break;
    }

    // -- Simple assignment: emit META node for string assignments so CWE-798 can find hardcoded creds --
    case 'assignment': {
      const assignLeft = node.childForFieldName('left');
      const assignRight = node.childForFieldName('right');
      if (assignLeft?.type === 'identifier' && assignRight &&
          (assignRight.type === 'string' || assignRight.type === 'concatenated_string')) {
        const assignSnapshot = node.text.slice(0, 200);
        const configN = createNode({
          label: assignLeft.text,
          node_type: 'META',
          node_subtype: 'config_value',
          language: 'python',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: assignSnapshot,
        });
        ctx.neuralMap.nodes.push(configN);
        ctx.lastCreatedNodeId = configN.id;
        ctx.emitContainsIfNeeded(configN.id);
      }
      break;
    }

    // -- Augmented assignment --
    // Note: assignment and augmented_assignment are handled by processVariableDeclaration
    // but augmented_assignment also gets a TRANSFORM node here for taint flow tracking
    case 'augmented_assignment': {
      const augLeftNode = node.childForFieldName('left');
      const augLeft = augLeftNode?.text?.slice(0, 40) ?? '?';
      // Find the operator from children
      let augOp = '+=';
      for (let c = 0; c < node.childCount; c++) {
        const child = node.child(c);
        if (child && /^[+\-*/%&|^<>@]=|<<=|>>=|\*\*=|\/\/=/.test(child.text)) {
          augOp = child.text;
          break;
        }
      }
      const augN = createNode({ label: `${augLeft} ${augOp}`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
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

    // -- Starred expression (*args unpacking in calls) --
    case 'starred_expression': {
      const starN = createNode({ label: '*unpack', node_type: 'TRANSFORM', node_subtype: 'spread', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(starN); ctx.lastCreatedNodeId = starN.id; ctx.emitContainsIfNeeded(starN.id);
      break;
    }

    // -- Subscript (bracket access) --
    case 'subscript': {
      const subN = createNode({ label: node.text.slice(0, 40), node_type: 'TRANSFORM', node_subtype: 'subscript', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(subN); ctx.lastCreatedNodeId = subN.id; ctx.emitContainsIfNeeded(subN.id);
      break;
    }

    // -- Silent pass-throughs --
    case 'expression_statement':
      break;
    case 'parenthesized_expression':
      break;
    case 'comment':
      break;

    // -- Object/Collection literals (when notable) --
    case 'dictionary': {
      if (node.namedChildCount >= 3) {
        const dictN = createNode({ label: '{...}', node_type: 'TRANSFORM', node_subtype: 'object_literal', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(dictN); ctx.lastCreatedNodeId = dictN.id; ctx.emitContainsIfNeeded(dictN.id);
      }
      break;
    }
    case 'list': {
      if (node.namedChildCount >= 3) {
        const listN = createNode({ label: '[...]', node_type: 'TRANSFORM', node_subtype: 'array_literal', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(listN); ctx.lastCreatedNodeId = listN.id; ctx.emitContainsIfNeeded(listN.id);
      }
      break;
    }
    case 'tuple': {
      if (node.namedChildCount >= 3) {
        const tupleN = createNode({ label: '(...)', node_type: 'TRANSFORM', node_subtype: 'array_literal', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(tupleN); ctx.lastCreatedNodeId = tupleN.id; ctx.emitContainsIfNeeded(tupleN.id);
      }
      break;
    }

    // -- Type alias statement (Python 3.12+) --
    case 'type_alias_statement': {
      const typeN = createNode({ label: node.text.slice(0, 60), node_type: 'META', node_subtype: 'type_alias', language: 'python', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(typeN); ctx.lastCreatedNodeId = typeN.id; ctx.emitContainsIfNeeded(typeN.id);
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'function_definition' && node.type !== 'lambda') {
    return;
  }

  const body = node.childForFieldName('body');
  if (!body) return;

  // Lambda: expression body (single expression)
  if (node.type === 'lambda' && body.type !== 'block') {
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

  // Function definition: block body — check for return statements
  if (body.type === 'block') {
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
  // Python `for` statement always iterates over an iterable (like JS for-of)
  if (node.type !== 'for_statement') return;

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
              else results.push(...findIdents(child));
            }
          }
          return results;
        };
        for (const varName of findIdents(iterLeft)) {
          ctx.declareVariable(varName, 'let', null, true, iterTaint[0].nodeId);
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration — re-mark loop variable taint after body walk
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_statement') return;

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
              else results.push(...findIdents(child));
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

export const pythonProfile: LanguageProfile = {
  id: 'python',
  extensions: ['.py', '.pyw', '.pyi'],

  // Layer 1: AST Node Type Recognition
  functionScopeTypes: FUNCTION_SCOPE_TYPES,
  blockScopeTypes: BLOCK_SCOPE_TYPES,
  classScopeTypes: CLASS_SCOPE_TYPES,

  getScopeType(node: SyntaxNode): ScopeType | null {
    if (FUNCTION_SCOPE_TYPES.has(node.type)) return 'function';
    if (node.type === 'class_definition') return 'class';
    // Comprehensions create implicit function scopes
    if (COMPREHENSION_SCOPE_TYPES.has(node.type)) return 'function';
    // Python has NO block scopes
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
    // Python framework middleware patterns (Flask decorators, Django middleware)
    // are handled differently from Express — via decorated_definition in classifyNode.
    // Return null for now; structural analysis is a future enhancement.
    return null;
  },

  // Layer 4: Taint Source Detection
  ingressPattern: /(?:request\.(?:form|args|json|data|values|files|headers|cookies|get_json|get_data|environ|url|path|method|host|remote_addr|content_type|POST|GET|FILES|META|COOKIES|body|content_params|query_params|path_params)|Request\.(?:body|json|form|query_params|path_params|headers|cookies)|sys\.(?:argv|stdin)|input\s*\()/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) => nodeType === 'assignment' || nodeType === 'augmented_assignment',
  isStatementContainer: (nodeType: string) => nodeType === 'module' || nodeType === 'block',

  // Inter-procedural taint: Python def syntax
  // Matches: def name(params):  |  async def name(params):
  // Group 1 captures the full parameter list between parentheses.
  functionParamPattern: /(?:async\s+)?def\s+\w+\s*\(([^)]*)\)\s*(?:->.*?)?:/,
};

export default pythonProfile;
