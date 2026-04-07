/**
 * RubyProfile — LanguageProfile implementation for Ruby.
 *
 * Ruby is a dynamic, object-oriented language with strong metaprogramming
 * capabilities. The tree-sitter-ruby grammar uses node types that differ
 * significantly from JavaScript and Python.
 *
 * Key Ruby-specific AST details (tree-sitter-ruby):
 *   - `method` for method definitions (not `function_definition`)
 *   - `call` for method invocations (receiver.method(args))
 *   - `identifier` for bare method calls (puts, system, eval)
 *   - `assignment` for variable assignment (no let/const/var)
 *   - `class` / `module` for class/module definitions
 *   - `if` / `unless` / `case` for conditionals
 *   - `do_block` / `block` for Ruby blocks ({ |x| ... } / do |x| ... end)
 *   - `string` with `string_content` + `interpolation` for string interpolation
 *   - `symbol` for Ruby symbols
 *   - `hash` for Ruby hashes
 *   - `instance_variable` (@var), `class_variable` (@@var), `global_variable` ($var)
 *   - `lambda` / `proc` for lambdas and procs
 *   - `singleton_method` for def self.method_name
 *   - `begin` for begin/rescue/ensure blocks
 *   - `subshell` for backtick command execution (`cmd`)
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
import { lookupCallee as _lookupCallee } from '../languages/ruby.js';

// ---------------------------------------------------------------------------
// AST Node Type Sets
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'method',
  'singleton_method',
  'lambda',
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'do_block',
  'block',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'class',
  'module',
  'singleton_class',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'assignment',
  'operator_assignment',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'method',
  'singleton_method',
]);

const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // Rails params
  'params',
  // Rails request object
  'request.body', 'request.headers', 'request.env',
  'request.path', 'request.url', 'request.host',
  'request.method', 'request.remote_ip', 'request.content_type',
  'request.query_string', 'request.query_parameters',
  'request.request_parameters', 'request.raw_post',
  'request.body_stream', 'request.params',
  // Cookies / session
  'cookies', 'session',
  // Rack
  'env',
  // ARGV / STDIN
  'ARGV', '$stdin',
]);

// ---------------------------------------------------------------------------
// Helper: resolve Ruby escape sequences in strings
// ---------------------------------------------------------------------------

function resolveEscapes(s: string): string {
  return s
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\\\/g, '\\');
}

// ---------------------------------------------------------------------------
// tryFoldConstant — defeat evasion by folding constant expressions
//
// Ruby evasion patterns:
//   1. String concat:   'ev' + 'al'  → "eval"
//   2. Array pack:      [101,118,97,108].pack('C*')  → "eval"
//   3. chr concat:      101.chr + 118.chr  → "eval"
//   4. Base64 decode:   Base64.decode64('ZXZhbA==')  → "eval"
// ---------------------------------------------------------------------------

function tryFoldConstant(n: SyntaxNode): string | null {
  // ── Literal strings (single or double quoted, no interpolation) ──
  if (n.type === 'string') {
    const hasInterpolation = n.namedChildren.some(c => c.type === 'interpolation');
    if (!hasInterpolation) {
      const raw = n.text.replace(/^['"]|['"]$/g, '');
      return resolveEscapes(raw);
    }
    return null;
  }
  if (n.type === 'string_content') {
    return resolveEscapes(n.text);
  }

  // ── Symbol literals: :eval → "eval" ──
  if (n.type === 'simple_symbol' || n.type === 'hash_key_symbol') {
    return n.text.replace(/^:/, '');
  }

  // ── Integer literals → string (for charcode operations) ──
  if (n.type === 'integer') {
    return n.text;
  }

  // ── Binary expression: 'ev' + 'al' → "eval" ──
  if (n.type === 'binary') {
    const opNode = n.childForFieldName('operator');
    if (opNode?.text === '+') {
      const left = n.childForFieldName('left');
      const right = n.childForFieldName('right');
      if (left && right) {
        const lv = tryFoldConstant(left);
        const rv = tryFoldConstant(right);
        if (lv !== null && rv !== null) return lv + rv;
      }
    }
    return null;
  }

  // ── Parenthesized: ('ev' + 'al') → "eval" ──
  if (n.type === 'parenthesized_statements') {
    const inner = n.namedChild(0);
    return inner ? tryFoldConstant(inner) : null;
  }

  // ── Conditional constant folding: cond ? 'a' : 'a' → 'a' ──
  if (n.type === 'conditional') {
    // Ruby ternary: condition ? consequence : alternative
    // tree-sitter-ruby uses named children in order: condition, consequence, alternative
    const children = [];
    for (let i = 0; i < n.namedChildCount; i++) {
      children.push(n.namedChild(i));
    }
    if (children.length >= 3 && children[1] && children[2]) {
      const cv = tryFoldConstant(children[1]);
      const av = tryFoldConstant(children[2]);
      if (cv !== null && av !== null && cv === av) return cv;
    }
    return null;
  }

  // ── Call expressions: handle .pack, .chr, Base64.decode64, etc. ──
  if (n.type === 'call') {
    const receiver = n.childForFieldName('receiver');
    const method = n.childForFieldName('method');
    const args = n.childForFieldName('arguments');

    if (method && receiver) {
      const methodName = method.text;

      // ── [101,118,97,108].pack('C*') → "eval" ──
      if (methodName === 'pack' && receiver.type === 'array' && args) {
        const fmtArg = args.namedChild(0);
        const fmt = fmtArg ? tryFoldConstant(fmtArg) : null;
        if (fmt === 'C*' || fmt === 'c*' || fmt === 'U*') {
          const codes: number[] = [];
          let allLiteral = true;
          for (let i = 0; i < receiver.namedChildCount; i++) {
            const el = receiver.namedChild(i);
            if (el?.type === 'integer') {
              codes.push(parseInt(el.text, 10));
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

      // ── 101.chr → "e" (Integer#chr) ──
      if (methodName === 'chr' && receiver.type === 'integer') {
        const code = parseInt(receiver.text, 10);
        if (!isNaN(code) && code >= 0 && code <= 0x10FFFF) {
          return String.fromCharCode(code);
        }
      }

      // ── Base64.decode64('ZXZhbA==') → "eval" ──
      if (methodName === 'decode64') {
        const recChain = extractCalleeChain(receiver);
        if (recChain.length === 1 && recChain[0] === 'Base64' && args) {
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
      }

      // ── "ZXZhbA==".unpack1('m0') → "eval" (unpack base64) ──
      if (methodName === 'unpack1' && args) {
        const fmtArg = args.namedChild(0);
        const fmt = fmtArg ? tryFoldConstant(fmtArg) : null;
        if (fmt === 'm0' || fmt === 'm') {
          const data = tryFoldConstant(receiver);
          if (data !== null) {
            try {
              return Buffer.from(data, 'base64').toString('utf-8');
            } catch { /* not valid base64 */ }
          }
        }
      }

      // ── arr.join('') / arr.join → fold if array of constant strings ──
      if (methodName === 'join' && receiver.type === 'array') {
        const sepArg = args?.namedChild(0);
        const sep = sepArg ? tryFoldConstant(sepArg) : '';
        if (sep !== null) {
          const parts: string[] = [];
          let allConst = true;
          for (let i = 0; i < receiver.namedChildCount; i++) {
            const el = receiver.namedChild(i);
            if (el) {
              const v = tryFoldConstant(el);
              if (v !== null) {
                parts.push(v);
              } else {
                allConst = false;
                break;
              }
            }
          }
          if (allConst && parts.length > 0) {
            return parts.join(sep);
          }
        }
      }

      // ── arr.map(&:chr).join('') — charcode array to string ──
      if (methodName === 'map' && receiver.type === 'array' && args) {
        const blockArg = args.namedChild(0);
        // &:chr passed as block_argument > simple_symbol
        if (blockArg?.type === 'block_argument') {
          const sym = blockArg.namedChild(0);
          if (sym && (sym.text === ':chr' || sym.text === 'chr')) {
            const codes: number[] = [];
            let allNums = true;
            for (let i = 0; i < receiver.namedChildCount; i++) {
              const el = receiver.namedChild(i);
              if (el?.type === 'integer') {
                codes.push(parseInt(el.text, 10));
              } else {
                allNums = false;
                break;
              }
            }
            if (allNums && codes.length > 0) {
              // Return array of chars (will be joined by outer .join call)
              return codes.map(c => String.fromCharCode(c)).join('');
            }
          }
        }
      }
    }

    // ── Bare method: decode64('...') without module prefix ──
    if (method && !receiver && args) {
      if (method.text === 'decode64') {
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
    }

    return null;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Helper: extract callee chain from a Ruby method call or call node
// ---------------------------------------------------------------------------

function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier' || node.type === 'constant') {
    return [node.text];
  }
  if (node.type === 'instance_variable' || node.type === 'class_variable' || node.type === 'global_variable') {
    return [node.text];
  }
  if (node.type === 'scope_resolution') {
    // Module::Class or Module::Class::Method
    const parts: string[] = [];
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) {
        if (child.type === 'scope_resolution') {
          parts.push(...extractCalleeChain(child));
        } else {
          parts.push(child.text);
        }
      }
    }
    return parts;
  }
  if (node.type === 'call') {
    // receiver.method — extract chain
    const receiver = node.childForFieldName('receiver');
    const method = node.childForFieldName('method');
    if (receiver && method) {
      const chain = extractCalleeChain(receiver);
      chain.push(method.text);
      return chain;
    }
    if (method) {
      return [method.text];
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
// resolveCallee — resolve a Ruby call node to a NeuralMap node type
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  // Ruby has several call shapes:
  // 1. `call` node: receiver.method(args)  or  method(args)
  // 2. bare identifier used as method call (e.g., `puts "hello"`)

  if (node.type !== 'call') return null;

  const receiver = node.childForFieldName('receiver');
  const method = node.childForFieldName('method');

  // Case 1: receiver.method(args) — e.g., User.find_by(id: params[:id])
  if (receiver && method) {
    const methodName = method.text;
    const chain = extractCalleeChain(receiver);
    chain.push(methodName);

    const pattern = _lookupCallee(chain);
    if (pattern) {
      return {
        nodeType: pattern.nodeType,
        subtype: pattern.subtype,
        tainted: pattern.tainted,
        chain,
      };
    }

    // Try just the method name (wildcard matching in ruby.ts handles this)
    const methodOnly = _lookupCallee([receiver.text ?? '_', method.text]);
    if (methodOnly) {
      return {
        nodeType: methodOnly.nodeType,
        subtype: methodOnly.subtype,
        tainted: methodOnly.tainted,
        chain: [method.text],
      };
    }

    // ── Dynamic dispatch: send / __send__ / public_send ──
    // obj.send('eval', code) or obj.send('ev' + 'al', code)
    if (methodName === 'send' || methodName === '__send__' || methodName === 'public_send') {
      const args = node.childForFieldName('arguments');
      if (args) {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          // Try constant folding to resolve the method name
          const foldedName = tryFoldConstant(firstArg);
          if (foldedName) {
            // Strip leading colon for symbol literals (":eval" -> "eval")
            const resolvedMethod = foldedName.replace(/^:/, '');
            // Check dangerous methods FIRST — send() is dynamic dispatch,
            // so eval/instance_eval/class_eval resolved via send should be
            // classified as runtime_eval, not system_exec from callee patterns.
            const DANGEROUS_METHODS = new Set(['eval', 'exec', 'system', 'open', 'load', 'require', 'send', '__send__', 'instance_eval', 'class_eval', 'module_eval']);
            if (DANGEROUS_METHODS.has(resolvedMethod)) {
              return {
                nodeType: 'EXTERNAL',
                subtype: resolvedMethod === 'eval' || resolvedMethod === 'instance_eval' || resolvedMethod === 'class_eval' || resolvedMethod === 'module_eval' ? 'runtime_eval' : 'system_exec',
                tainted: false,
                chain: [resolvedMethod],
              };
            }
            // Look up the resolved method against callee patterns
            const recChain = extractCalleeChain(receiver);
            const dynChain = [...recChain, resolvedMethod];
            const dynPattern = _lookupCallee(dynChain);
            if (dynPattern) {
              return {
                nodeType: dynPattern.nodeType,
                subtype: dynPattern.subtype,
                tainted: dynPattern.tainted,
                chain: dynChain,
              };
            }
            // Also check bare method name
            const barePattern = _lookupCallee([resolvedMethod]);
            if (barePattern) {
              return {
                nodeType: barePattern.nodeType,
                subtype: barePattern.subtype,
                tainted: barePattern.tainted,
                chain: [resolvedMethod],
              };
            }
          }
          // If first arg is NOT a constant (could be tainted), mark as runtime eval
          // send(user_method, user_data) is extremely dangerous
          if (!foldedName && firstArg.type !== 'simple_symbol' && firstArg.type !== 'string') {
            return {
              nodeType: 'EXTERNAL',
              subtype: 'runtime_eval',
              tainted: true,
              chain: [methodName, '?'],
            };
          }
        }
      }
    }

    // ── Kernel.method(:eval).call(...) / obj.method(:name).call ──
    if (methodName === 'call' && receiver.type === 'call') {
      const innerMethod = receiver.childForFieldName('method');
      if (innerMethod?.text === 'method') {
        const innerArgs = receiver.childForFieldName('arguments');
        if (innerArgs) {
          const nameArg = innerArgs.namedChild(0);
          if (nameArg) {
            const foldedName = tryFoldConstant(nameArg);
            if (foldedName) {
              const resolvedMethod = foldedName.replace(/^:/, '');
              const barePattern = _lookupCallee([resolvedMethod]);
              if (barePattern) {
                return {
                  nodeType: barePattern.nodeType,
                  subtype: barePattern.subtype,
                  tainted: barePattern.tainted,
                  chain: [resolvedMethod],
                };
              }
              const DANGEROUS_METHODS = new Set(['eval', 'exec', 'system', 'open', 'load', 'require', 'instance_eval', 'class_eval', 'module_eval']);
              if (DANGEROUS_METHODS.has(resolvedMethod)) {
                return {
                  nodeType: 'EXTERNAL',
                  subtype: resolvedMethod === 'eval' || resolvedMethod === 'instance_eval' || resolvedMethod === 'class_eval' || resolvedMethod === 'module_eval' ? 'runtime_eval' : 'system_exec',
                  tainted: false,
                  chain: [resolvedMethod],
                };
              }
            }
          }
        }
      }
    }

    // ── Object.const_get(constructed) — dynamic class lookup ──
    if (methodName === 'const_get') {
      const args = node.childForFieldName('arguments');
      if (args) {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const foldedName = tryFoldConstant(firstArg);
          if (foldedName) {
            const resolvedClass = foldedName.replace(/^:/, '');
            const constPattern = _lookupCallee([resolvedClass]);
            if (constPattern) {
              return {
                nodeType: constPattern.nodeType,
                subtype: constPattern.subtype,
                tainted: constPattern.tainted,
                chain: [resolvedClass],
              };
            }
          }
          // Non-constant const_get is suspicious — dynamic class lookup
          if (!foldedName && firstArg.type !== 'simple_symbol' && firstArg.type !== 'string' && firstArg.type !== 'constant') {
            return {
              nodeType: 'EXTERNAL',
              subtype: 'runtime_eval',
              tainted: true,
              chain: ['const_get', '?'],
            };
          }
        }
      }
    }

    // Chained call resolution: receiver is itself a call
    if (receiver.type === 'call') {
      return resolveChainedCall(node);
    }

    return null;
  }

  const methodName = method?.text ?? '';

  // Case 2: bare method call — method(args) — no receiver
  if (method && !receiver) {
    const pattern = _lookupCallee([method.text]);
    if (pattern) {
      return {
        nodeType: pattern.nodeType,
        subtype: pattern.subtype,
        tainted: pattern.tainted,
        chain: [method.text],
      };
    }

    // ── Bare send(:method, args) — without explicit receiver ──
    if (methodName === 'send' || methodName === '__send__' || methodName === 'public_send') {
      const args = node.childForFieldName('arguments');
      if (args) {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const foldedName = tryFoldConstant(firstArg);
          if (foldedName) {
            const resolvedMethod = foldedName.replace(/^:/, '');
            // Check dangerous methods FIRST — send() is dynamic dispatch,
            // so eval/instance_eval/class_eval resolved via send should be
            // classified as runtime_eval, not system_exec.
            const DANGEROUS_METHODS = new Set(['eval', 'exec', 'system', 'open', 'load', 'require', 'instance_eval', 'class_eval', 'module_eval']);
            if (DANGEROUS_METHODS.has(resolvedMethod)) {
              return {
                nodeType: 'EXTERNAL',
                subtype: resolvedMethod === 'eval' || resolvedMethod === 'instance_eval' || resolvedMethod === 'class_eval' || resolvedMethod === 'module_eval' ? 'runtime_eval' : 'system_exec',
                tainted: false,
                chain: [resolvedMethod],
              };
            }
            const barePattern = _lookupCallee([resolvedMethod]);
            if (barePattern) {
              return {
                nodeType: barePattern.nodeType,
                subtype: barePattern.subtype,
                tainted: barePattern.tainted,
                chain: [resolvedMethod],
              };
            }
          }
          // Tainted dynamic dispatch
          if (!foldedName && firstArg.type !== 'simple_symbol' && firstArg.type !== 'string') {
            return {
              nodeType: 'EXTERNAL',
              subtype: 'runtime_eval',
              tainted: true,
              chain: [methodName, '?'],
            };
          }
        }
      }
    }

    return null;
  }

  return null;
}

function resolveChainedCall(node: SyntaxNode): ResolvedCalleeResult | null {
  const method = node.childForFieldName('method');
  if (!method) return null;

  // Try just the terminal method name
  const pattern = _lookupCallee([method.text]);
  if (pattern) {
    return {
      nodeType: pattern.nodeType,
      subtype: pattern.subtype,
      tainted: pattern.tainted,
      chain: [method.text],
    };
  }

  // Walk receiver chain
  const receiver = node.childForFieldName('receiver');
  if (receiver?.type === 'call') {
    const innerMethod = receiver.childForFieldName('method');
    const innerReceiver = receiver.childForFieldName('receiver');
    if (innerReceiver && innerMethod) {
      const chain = extractCalleeChain(innerReceiver);
      chain.push(innerMethod.text, method.text);
      const deepPattern = _lookupCallee(chain);
      if (deepPattern) {
        return {
          nodeType: deepPattern.nodeType,
          subtype: deepPattern.subtype,
          tainted: deepPattern.tainted,
          chain,
        };
      }
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// resolvePropertyAccess — resolve standalone property access in Ruby
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  // In Ruby, property access looks like: receiver.method (which is a `call` node)
  // or instance variables (@var), global variables ($var).
  // Since Ruby doesn't have a separate member_expression node type,
  // we handle identifiers and call nodes that look like property access.

  if (node.type === 'call') {
    const receiver = node.childForFieldName('receiver');
    const method = node.childForFieldName('method');
    const args = node.childForFieldName('arguments');

    // Only property-like if no arguments
    if (receiver && method && !args) {
      const chain = extractCalleeChain(receiver);
      chain.push(method.text);
      const fullPath = chain.join('.');

      if (TAINTED_PATHS.has(fullPath)) {
        return {
          nodeType: 'INGRESS',
          subtype: 'http_request',
          tainted: true,
        };
      }

      const pattern = _lookupCallee(chain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
        };
      }
    }
  }

  // Check bare identifiers that are tainted (params, cookies, session, env)
  if (node.type === 'identifier') {
    if (TAINTED_PATHS.has(node.text)) {
      return {
        nodeType: 'INGRESS',
        subtype: 'http_request',
        tainted: true,
      };
    }
  }

  // Instance variables that look tainted
  if (node.type === 'instance_variable') {
    // @params, @request, etc. — mark as potentially tainted
    const varName = node.text.slice(1); // remove @
    if (varName === 'params' || varName === 'request') {
      return {
        nodeType: 'INGRESS',
        subtype: 'http_request',
        tainted: true,
      };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// extractPatternNames — extract variable names from Ruby destructuring
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
      case 'left_assignment_list':
      case 'right_assignment_list':
      case 'destructured_left_assignment':
        names.push(...extractPatternNames(child));
        break;
      case 'rest_assignment': {
        // *rest — identifier is the child
        const ident = child.namedChildren.find(
          (c): c is NonNullable<typeof c> => c !== null && c.type === 'identifier'
        );
        if (ident) names.push(ident.text);
        break;
      }
      case 'splat_parameter': {
        const ident = child.namedChildren.find(
          (c): c is NonNullable<typeof c> => c !== null && c.type === 'identifier'
        );
        if (ident) names.push(ident.text);
        break;
      }
      default:
        if (child.namedChildCount > 0) {
          names.push(...extractPatternNames(child));
        }
    }
  }

  return names;
}

// ---------------------------------------------------------------------------
// extractTaintSources — recursive expression taint analysis for Ruby
// ---------------------------------------------------------------------------

function extractTaintSources(expr: SyntaxNode, ctx: MapperContextLike): TaintSourceResult[] {
  if (!expr) return [];

  switch (expr.type) {
    // -- Leaf: identifier -- check if it's a tainted variable
    case 'identifier': {
      // Check if it's a known tainted path (params, cookies, etc.)
      if (TAINTED_PATHS.has(expr.text)) {
        const ingressNode = createNode({
          label: expr.text,
          node_type: 'INGRESS',
          node_subtype: 'http_request',
          language: 'ruby',
          file: ctx.neuralMap.source_file,
          line_start: expr.startPosition.row + 1,
          line_end: expr.endPosition.row + 1,
          code_snapshot: expr.text,
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

      const varInfo = ctx.resolveVariable(expr.text);
      if (varInfo?.tainted && varInfo.producingNodeId) {
        return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
      }
      return [];
    }

    // -- Instance variable: @user_input
    case 'instance_variable':
    case 'class_variable':
    case 'global_variable': {
      const varInfo = ctx.resolveVariable(expr.text);
      if (varInfo?.tainted && varInfo.producingNodeId) {
        return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
      }
      return [];
    }

    // -- Call: receiver.method(args)
    case 'call': {
      const callResolution = resolveCallee(expr);

      // If this is a sanitizer, taint STOPS
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          (callResolution.subtype === 'sanitize' || callResolution.subtype === 'encode')) {
        return [];
      }

      // Check if this is a tainted call (e.g., params.require)
      if (callResolution?.tainted) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: callResolution.nodeType,
          node_subtype: callResolution.subtype,
          language: 'ruby',
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

      // For other calls, check arguments AND receiver for taint
      const sources: TaintSourceResult[] = [];
      const args = expr.childForFieldName('arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (arg) sources.push(...extractTaintSources(arg, ctx));
        }
      }
      // Check receiver
      const receiver = expr.childForFieldName('receiver');
      if (receiver) sources.push(...extractTaintSources(receiver, ctx));

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

    // -- Element reference: params[:id], array[index]
    case 'element_reference': {
      const sources: TaintSourceResult[] = [];
      const obj = expr.namedChild(0);
      if (obj) sources.push(...extractTaintSources(obj, ctx));
      // Check the subscript arguments too
      for (let i = 1; i < expr.namedChildCount; i++) {
        const sub = expr.namedChild(i);
        if (sub) sources.push(...extractTaintSources(sub, ctx));
      }
      return sources;
    }

    // -- Binary: string concatenation, arithmetic
    case 'binary': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const sources: TaintSourceResult[] = [];
      if (left) sources.push(...extractTaintSources(left, ctx));
      if (right) sources.push(...extractTaintSources(right, ctx));
      return sources;
    }

    // -- String: "prefix #{TAINTED} suffix"
    case 'string':
    case 'string_array':
    case 'heredoc_body': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child?.type === 'interpolation') {
          // Walk inside the interpolation
          for (let j = 0; j < child.namedChildCount; j++) {
            const inner = child.namedChild(j);
            if (inner) sources.push(...extractTaintSources(inner, ctx));
          }
        }
      }
      return sources;
    }

    // -- Subshell: backtick command execution `cmd #{tainted}`
    case 'subshell': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child?.type === 'interpolation') {
          for (let j = 0; j < child.namedChildCount; j++) {
            const inner = child.namedChild(j);
            if (inner) sources.push(...extractTaintSources(inner, ctx));
          }
        }
      }
      return sources;
    }

    // -- Parenthesized expression
    case 'parenthesized_statements': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Conditional: ternary (cond ? a : b)
    case 'conditional': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Array: [TAINTED, safe]
    case 'array': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Hash: { key: TAINTED, key2: safe }
    case 'hash': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const pair = expr.namedChild(i);
        if (!pair) continue;
        if (pair.type === 'pair') {
          const value = pair.childForFieldName('value');
          if (value) sources.push(...extractTaintSources(value, ctx));
        } else if (pair.type === 'hash_splat_argument') {
          sources.push(...extractTaintSources(pair, ctx));
        }
      }
      return sources;
    }

    // -- Keyword argument: key: TAINTED
    case 'pair': {
      const value = expr.childForFieldName('value');
      return value ? extractTaintSources(value, ctx) : [];
    }

    // -- Splat argument: *TAINTED
    case 'splat_argument':
    case 'hash_splat_argument': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Scope resolution: Module::Method
    case 'scope_resolution': {
      const chain = extractCalleeChain(expr);
      if (chain.length > 0) {
        const pattern = _lookupCallee(chain);
        if (pattern?.tainted) {
          return [{ nodeId: 'external', name: chain.join('::') }];
        }
      }
      return [];
    }

    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration — Ruby assignment / operator_assignment
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'assignment' && node.type !== 'operator_assignment') {
    return;
  }

  const kind: VariableInfo['kind'] = 'let'; // Ruby variables behave like `let`

  const nameNode = node.childForFieldName('left');
  if (!nameNode) return;

  let producingNodeId = ctx.lastCreatedNodeId;

  // Check if producing node is tainted
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

  // Multi-hop taint: b = a (plain identifier assignment)
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

  // Cross-function taint: val = get_input(request)
  if (!producingNodeId) {
    const valueNode = node.childForFieldName('right');
    if (valueNode?.type === 'call') {
      const callMethod = valueNode.childForFieldName('method');
      if (callMethod?.type === 'identifier') {
        const funcNodeId = ctx.functionRegistry.get(callMethod.text);
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

  // Alias chain detection: q = db.query -> store ['db', 'query']
  let aliasChain: string[] | undefined;
  {
    const valueNode = node.childForFieldName('right');
    if (valueNode?.type === 'call') {
      const chain = extractCalleeChain(valueNode);
      if (chain.length >= 2) {
        aliasChain = chain;
      }
    }
  }

  // Constant folding: action = "quer" + "y" -> "query"
  // Also folds: [101,118].pack('C*'), 101.chr + 118.chr, Base64.decode64(...)
  let constantValue: string | undefined;
  {
    const valueNode = node.childForFieldName('right');
    if (valueNode) {
      const folded = tryFoldConstant(valueNode);
      if (folded !== null) constantValue = folded;
    }
  }

  // Preserve existing taint
  const preserveTaint = (varName: string, newTainted: boolean, newProducing: string | null) => {
    if (!newTainted) {
      const existing = ctx.resolveVariable(varName);
      if (existing?.tainted) {
        return;
      }
    }
    ctx.declareVariable(varName, kind, null, newTainted, newProducing);
    const v = ctx.resolveVariable(varName);
    if (v) {
      if (aliasChain) v.aliasChain = aliasChain;
      if (constantValue) v.constantValue = constantValue;
    }
  };

  if (nameNode.type === 'identifier' || nameNode.type === 'instance_variable' ||
      nameNode.type === 'class_variable' || nameNode.type === 'global_variable' ||
      nameNode.type === 'constant') {
    preserveTaint(nameNode.text, tainted, producingNodeId);

    // Emit META node for string assignments so CWE-798 can find hardcoded creds
    const rhsNode = node.childForFieldName('right');
    if (rhsNode && rhsNode.type === 'string') {
      const hasInterp = rhsNode.namedChildren.some(c => c.type === 'interpolation');
      if (!hasInterp) {
        const snap = node.text.slice(0, 200);
        const metaNode = createNode({
          label: nameNode.text,
          node_type: 'META',
          node_subtype: 'config_value',
          language: 'ruby',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: snap,
        });
        ctx.neuralMap.nodes.push(metaNode);
        ctx.emitContainsIfNeeded(metaNode.id);
      }
    }
  } else if (nameNode.type === 'left_assignment_list') {
    extractPatternNames(nameNode).forEach(n =>
      preserveTaint(n, tainted, producingNodeId)
    );
  } else if (nameNode.type === 'call') {
    // obj.x = val — property assignment via method call
    const receiver = nameNode.childForFieldName('receiver');
    if (receiver?.type === 'identifier' && tainted) {
      const varInfo = ctx.resolveVariable(receiver.text);
      if (varInfo) {
        varInfo.tainted = true;
        varInfo.producingNodeId = producingNodeId;
      }
    }
  } else if (nameNode.type === 'element_reference') {
    // obj[key] = val — subscript assignment
    const obj = nameNode.namedChild(0);
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
// processFunctionParams — Ruby method parameter node types
// ---------------------------------------------------------------------------

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  const declareParam = (name: string) => {
    const producingId = ctx.pendingCallbackTaint.get(name) ?? null;
    const isTainted = producingId !== null;
    if (isTainted) ctx.pendingCallbackTaint.delete(name);
    ctx.declareVariable(name, 'param', null, isTainted, producingId);
  };

  let paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) {
    // Block parameters use different field names
    // do_block and block have a `parameters` field (block_parameters)
    for (let i = 0; i < funcNode.namedChildCount; i++) {
      const child = funcNode.namedChild(i);
      if (child && (child.type === 'method_parameters' || child.type === 'block_parameters' || child.type === 'lambda_parameters')) {
        paramsNode = child;
        break;
      }
    }
  }

  if (!paramsNode) return;

  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    switch (param.type) {
      case 'identifier':
        declareParam(param.text);
        break;
      case 'optional_parameter': {
        const nameChild = param.childForFieldName('name');
        if (nameChild && nameChild.type === 'identifier') {
          declareParam(nameChild.text);
        }
        break;
      }
      case 'splat_parameter': {
        // *args
        const ident = param.childForFieldName('name');
        if (ident) declareParam(ident.text);
        break;
      }
      case 'hash_splat_parameter': {
        // **kwargs
        const ident = param.childForFieldName('name');
        if (ident) declareParam(ident.text);
        break;
      }
      case 'block_parameter': {
        // &block
        const ident = param.childForFieldName('name');
        if (ident) declareParam(ident.text);
        break;
      }
      case 'keyword_parameter': {
        const nameChild = param.childForFieldName('name');
        if (nameChild) declareParam(nameChild.text);
        break;
      }
      case 'destructured_parameter':
        extractPatternNames(param).forEach(n => declareParam(n));
        break;
    }
  }
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of node classification for Ruby
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  // Register method name in outer scope
  if (node.type === 'method' || node.type === 'singleton_method') {
    const funcName = node.childForFieldName('name');
    if (funcName && ctx.scopeStack.length >= 2) {
      const outerScope = ctx.scopeStack[ctx.scopeStack.length - 2];
      outerScope.variables.set(funcName.text, {
        name: funcName.text,
        declaringNodeId: null,
        producingNodeId: null,
        kind: 'let',
        tainted: false,
      });
    }
  }

  switch (node.type) {
    // -- METHOD DEFINITION --
    case 'method': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const fnNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'ruby',
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

    // -- SINGLETON METHOD (def self.method_name) --
    case 'singleton_method': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const fnNode = createNode({
        label: `self.${name}`,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'ruby',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      fnNode.tags.push('singleton');
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
        language: 'ruby',
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
    case 'class': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousClass';
      const classNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'ruby',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      const superclass = node.childForFieldName('superclass');
      if (superclass) {
        classNode.tags.push('inherits');
      }
      ctx.neuralMap.nodes.push(classNode);
      ctx.lastCreatedNodeId = classNode.id;
      ctx.emitContainsIfNeeded(classNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = classNode.id;
      break;
    }

    // -- MODULE DEFINITION --
    case 'module': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousModule';
      const modNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'module',
        language: 'ruby',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(modNode);
      ctx.lastCreatedNodeId = modNode.id;
      ctx.emitContainsIfNeeded(modNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = modNode.id;
      break;
    }

    // -- CALL EXPRESSION: classify by callee --
    case 'call': {
      // Pre-resolve import aliases
      let resolution: ResolvedCalleeResult | null = null;
      {
        const receiver = node.childForFieldName('receiver');
        const method = node.childForFieldName('method');
        if (receiver?.type === 'identifier' && method) {
          const rootVar = ctx.resolveVariable(receiver.text);
          if (rootVar?.aliasChain) {
            const methodText = method.text;
            // If the aliased chain resolves to send/public_send, try to fold the method argument
            if (methodText === 'send' || methodText === '__send__' || methodText === 'public_send') {
              const args = node.childForFieldName('arguments');
              if (args) {
                const firstArg = args.namedChild(0);
                if (firstArg) {
                  // Try constant folding inline: obj.send('ev'+'al', ...)
                  const foldedName = tryFoldConstant(firstArg);
                  if (foldedName) {
                    const resolvedMethod = foldedName.replace(/^:/, '');
                    const barePattern = _lookupCallee([resolvedMethod]);
                    if (barePattern) {
                      resolution = {
                        nodeType: barePattern.nodeType,
                        subtype: barePattern.subtype,
                        tainted: barePattern.tainted,
                        chain: [resolvedMethod],
                      };
                    }
                  }
                  // Try variable with constantValue: obj.send(method_var, ...)
                  if (!resolution && firstArg.type === 'identifier') {
                    const varInfo = ctx.resolveVariable(firstArg.text);
                    if (varInfo?.constantValue) {
                      const resolvedMethod = varInfo.constantValue.replace(/^:/, '');
                      const barePattern = _lookupCallee([resolvedMethod]);
                      if (barePattern) {
                        resolution = {
                          nodeType: barePattern.nodeType,
                          subtype: barePattern.subtype,
                          tainted: barePattern.tainted,
                          chain: [resolvedMethod],
                        };
                      }
                    }
                  }
                }
              }
            }
            // Standard alias chain resolution (only if send resolution didn't resolve)
            if (!resolution) {
              const resolvedChain = [...rootVar.aliasChain, methodText];
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

      // Pre-resolve send/public_send with variable that has constantValue
      // e.g.: method_name = 'ev' + 'al'; obj.send(method_name, code)
      if (!resolution) {
        const receiver = node.childForFieldName('receiver');
        const method = node.childForFieldName('method');
        const methodName = method?.text ?? '';
        if (methodName === 'send' || methodName === '__send__' || methodName === 'public_send') {
          const args = node.childForFieldName('arguments');
          if (args) {
            const firstArg = args.namedChild(0);
            if (firstArg?.type === 'identifier') {
              const varInfo = ctx.resolveVariable(firstArg.text);
              if (varInfo?.constantValue) {
                const resolvedMethod = varInfo.constantValue.replace(/^:/, '');
                const barePattern = _lookupCallee([resolvedMethod]);
                if (barePattern) {
                  resolution = {
                    nodeType: barePattern.nodeType,
                    subtype: barePattern.subtype,
                    tainted: barePattern.tainted,
                    chain: [resolvedMethod],
                  };
                } else {
                  const DANGEROUS_METHODS = new Set(['eval', 'exec', 'system', 'open', 'load', 'require', 'instance_eval', 'class_eval', 'module_eval']);
                  if (DANGEROUS_METHODS.has(resolvedMethod)) {
                    resolution = {
                      nodeType: 'EXTERNAL',
                      subtype: resolvedMethod === 'eval' || resolvedMethod === 'instance_eval' || resolvedMethod === 'class_eval' || resolvedMethod === 'module_eval' ? 'runtime_eval' : 'system_exec',
                      tainted: false,
                      chain: [resolvedMethod],
                    };
                  }
                }
              } else if (varInfo?.tainted) {
                // Variable is tainted — dynamic dispatch with tainted method name
                resolution = {
                  nodeType: 'EXTERNAL',
                  subtype: 'runtime_eval',
                  tainted: true,
                  chain: [methodName, '?'],
                };
              }
            }
          }
        }
        // Also: eval(var) where var has a constantValue from folding
        if (methodName === 'eval' && !receiver) {
          const args = node.childForFieldName('arguments');
          if (args) {
            const firstArg = args.namedChild(0);
            if (firstArg?.type === 'identifier') {
              const varInfo = ctx.resolveVariable(firstArg.text);
              if (varInfo?.constantValue) {
                // eval of a constant-folded string — we know what it resolves to
                // Still mark as runtime_eval but include the resolved value
                resolution = {
                  nodeType: 'EXTERNAL',
                  subtype: 'runtime_eval',
                  tainted: false,
                  chain: ['eval', varInfo.constantValue],
                };
              }
            }
          }
        }
      }

      if (!resolution) resolution = resolveCallee(node);

      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'ruby',
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
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
            }
          }
        }

        // Also check block arguments for taint
        const blockArg = node.namedChildren.find(c =>
          c.type === 'do_block' || c.type === 'block'
        );
        // Block body taint will be handled by scope walking

        // Receiver taint: for method calls on tainted objects
        const receiver = node.childForFieldName('receiver');
        if (receiver) {
          const receiverTaint = extractTaintSources(receiver, ctx);
          for (const source of receiverTaint) {
            if (!callHasTaintedArgs) callHasTaintedArgs = true;
            ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
          }
        }

        // Taint-through
        if (callHasTaintedArgs && !n.data_out.some((d: any) => d.tainted)) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }

        // Callback parameter taint: fn { |x| process(x) } with tainted args
        if (callHasTaintedArgs && blockArg) {
          const blockParams = blockArg.namedChildren.find(c =>
            c.type === 'block_parameters'
          );
          if (blockParams) {
            for (let pi = 0; pi < blockParams.namedChildCount; pi++) {
              const p = blockParams.namedChild(pi);
              if (p?.type === 'identifier') ctx.pendingCallbackTaint.set(p.text, n.id);
            }
          }
        }
      } else {
        // -- Variable alias resolution
        const method = node.childForFieldName('method');
        const receiver = node.childForFieldName('receiver');

        if (method?.type === 'identifier' && !receiver) {
          const aliasVar = ctx.resolveVariable(method.text);
          if (aliasVar?.aliasChain) {
            const aliasPattern = _lookupCallee(aliasVar.aliasChain);
            if (aliasPattern) {
              const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const aliasN = createNode({
                label,
                node_type: aliasPattern.nodeType,
                node_subtype: aliasPattern.subtype,
                language: 'ruby',
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

        // -- Unresolved call -- check function registry
        let calleeName: string | null = null;
        if (method?.type === 'identifier') {
          calleeName = method.text;
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
            language: 'ruby',
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
      const callMethod = node.childForFieldName('method');
      if (callMethod && callMethod.type === 'identifier' && !node.childForFieldName('receiver')) {
        const containerId = ctx.getCurrentContainerId();
        if (containerId) {
          ctx.pendingCalls.push({
            callerContainerId: containerId,
            calleeName: callMethod.text,
            isAsync: false,
          });
        }
      }

      break;
    }

    // -- SUBSHELL: backtick command execution `cmd` --
    case 'subshell': {
      const subN = createNode({
        label: 'backtick_exec',
        node_type: 'EXTERNAL',
        node_subtype: 'system_exec',
        language: 'ruby',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      subN.attack_surface.push('command_injection');

      // Check for tainted interpolation inside backticks
      const taintSources = extractTaintSources(node, ctx);
      if (taintSources.length > 0) {
        subN.data_out.push({
          name: 'result',
          source: subN.id,
          data_type: 'unknown',
          tainted: true,
          sensitivity: 'NONE',
        });
        for (const source of taintSources) {
          ctx.addDataFlow(source.nodeId, subN.id, source.name, 'unknown', true);
        }
      }

      ctx.neuralMap.nodes.push(subN);
      ctx.lastCreatedNodeId = subN.id;
      ctx.emitContainsIfNeeded(subN.id);
      break;
    }

    // -- CONTROL nodes --
    case 'if': {
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      break;
    }
    case 'unless': {
      const unlessN = createNode({ label: 'unless', node_type: 'CONTROL', node_subtype: 'branch', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(unlessN); ctx.lastCreatedNodeId = unlessN.id; ctx.emitContainsIfNeeded(unlessN.id);
      break;
    }
    case 'case': {
      const caseN = createNode({ label: 'case', node_type: 'CONTROL', node_subtype: 'branch', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(caseN); ctx.lastCreatedNodeId = caseN.id; ctx.emitContainsIfNeeded(caseN.id);
      break;
    }
    case 'when': {
      const whenN = createNode({ label: 'when', node_type: 'CONTROL', node_subtype: 'case', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whenN); ctx.lastCreatedNodeId = whenN.id; ctx.emitContainsIfNeeded(whenN.id);
      break;
    }
    case 'for': {
      const forN = createNode({ label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      break;
    }
    case 'while': {
      const whileN = createNode({ label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whileN); ctx.lastCreatedNodeId = whileN.id; ctx.emitContainsIfNeeded(whileN.id);
      break;
    }
    case 'until': {
      const untilN = createNode({ label: 'until', node_type: 'CONTROL', node_subtype: 'loop', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(untilN); ctx.lastCreatedNodeId = untilN.id; ctx.emitContainsIfNeeded(untilN.id);
      break;
    }
    case 'begin': {
      const beginN = createNode({ label: 'begin', node_type: 'CONTROL', node_subtype: 'error_handler', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(beginN); ctx.lastCreatedNodeId = beginN.id; ctx.emitContainsIfNeeded(beginN.id);
      break;
    }
    case 'rescue': {
      const rescueN = createNode({ label: 'rescue', node_type: 'CONTROL', node_subtype: 'catch', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      rescueN.tags.push('error-handler');
      ctx.neuralMap.nodes.push(rescueN); ctx.lastCreatedNodeId = rescueN.id; ctx.emitContainsIfNeeded(rescueN.id);
      break;
    }
    case 'ensure': {
      const ensureN = createNode({ label: 'ensure', node_type: 'CONTROL', node_subtype: 'finally', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ensureN); ctx.lastCreatedNodeId = ensureN.id; ctx.emitContainsIfNeeded(ensureN.id);
      break;
    }
    case 'return': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }
    case 'break': {
      const breakN = createNode({ label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(breakN); ctx.lastCreatedNodeId = breakN.id; ctx.emitContainsIfNeeded(breakN.id);
      break;
    }
    case 'next': {
      const nextN = createNode({ label: 'next', node_type: 'CONTROL', node_subtype: 'continue', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(nextN); ctx.lastCreatedNodeId = nextN.id; ctx.emitContainsIfNeeded(nextN.id);
      break;
    }
    case 'yield': {
      const yieldN = createNode({ label: 'yield', node_type: 'CONTROL', node_subtype: 'yield', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(yieldN); ctx.lastCreatedNodeId = yieldN.id; ctx.emitContainsIfNeeded(yieldN.id);
      break;
    }
    case 'raise': {
      // Not to be confused with 'raise_statement' — in Ruby, tree-sitter calls it 'call'
      // with method name 'raise'. This case handles the rare `raise` keyword node if present.
      break;
    }

    // -- STRING (with interpolation) --
    case 'string': {
      const hasInterpolation = node.namedChildren.some(c => c.type === 'interpolation');
      if (hasInterpolation) {
        const fstrN = createNode({ label: 'interpolated_string', node_type: 'TRANSFORM', node_subtype: 'template_string', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(fstrN); ctx.lastCreatedNodeId = fstrN.id; ctx.emitContainsIfNeeded(fstrN.id);
      }
      break;
    }

    // -- ASSIGNMENT: emit META for hardcoded string assignments --
    case 'assignment': {
      const assignLeft = node.childForFieldName('left');
      const assignRight = node.childForFieldName('right');
      if (assignLeft && assignRight && assignRight.type === 'string') {
        const hasInterp = assignRight.namedChildren.some(c => c.type === 'interpolation');
        if (!hasInterp) {
          const assignSnapshot = node.text.slice(0, 200);
          const varName = assignLeft.text;
          const configN = createNode({
            label: varName,
            node_type: 'META',
            node_subtype: 'config_value',
            language: 'ruby',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: assignSnapshot,
          });
          ctx.neuralMap.nodes.push(configN);
          ctx.lastCreatedNodeId = configN.id;
          ctx.emitContainsIfNeeded(configN.id);
        }
      }
      break;
    }

    // -- OPERATOR_ASSIGNMENT (+=, -=, etc.) --
    case 'operator_assignment': {
      const augLeftNode = node.childForFieldName('left');
      const augLeft = augLeftNode?.text?.slice(0, 40) ?? '?';
      const augOp = node.childForFieldName('operator')?.text ?? '+=';
      const augN = createNode({ label: `${augLeft} ${augOp}`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
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

    // -- ELEMENT REFERENCE: params[:id], array[0] --
    case 'element_reference': {
      // Check if this is a tainted subscript access
      const obj = node.namedChild(0);
      if (obj && TAINTED_PATHS.has(obj.text)) {
        const elemN = createNode({
          label: node.text.slice(0, 60),
          node_type: 'INGRESS',
          node_subtype: 'http_request',
          language: 'ruby',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        elemN.data_out.push({
          name: 'result',
          source: elemN.id,
          data_type: 'unknown',
          tainted: true,
          sensitivity: 'NONE',
        });
        elemN.attack_surface.push('user_input');
        ctx.neuralMap.nodes.push(elemN);
        ctx.lastCreatedNodeId = elemN.id;
        ctx.emitContainsIfNeeded(elemN.id);
      }
      break;
    }

    // -- Silent pass-throughs --
    case 'expression_statement':
      break;
    case 'parenthesized_statements':
      break;
    case 'comment':
      break;

    // -- Hash literal (when notable) --
    case 'hash': {
      if (node.namedChildCount >= 3) {
        const hashN = createNode({ label: '{...}', node_type: 'TRANSFORM', node_subtype: 'object_literal', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(hashN); ctx.lastCreatedNodeId = hashN.id; ctx.emitContainsIfNeeded(hashN.id);
      }
      break;
    }

    // -- Array literal (when notable) --
    case 'array': {
      if (node.namedChildCount >= 3) {
        const arrN = createNode({ label: '[...]', node_type: 'TRANSFORM', node_subtype: 'array_literal', language: 'ruby', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
        ctx.neuralMap.nodes.push(arrN); ctx.lastCreatedNodeId = arrN.id; ctx.emitContainsIfNeeded(arrN.id);
      }
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'method' && node.type !== 'singleton_method' && node.type !== 'lambda') {
    return;
  }

  const body = node.childForFieldName('body');
  if (!body) return;

  // Lambda with expression body
  if (node.type === 'lambda') {
    const lastChild = body.namedChild(body.namedChildCount - 1);
    if (lastChild) {
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
  }

  // Check for explicit return statements
  for (let i = 0; i < body.namedChildCount; i++) {
    const stmt = body.namedChild(i);
    if (stmt?.type === 'return') {
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

  // Ruby implicit return: last expression in method body
  if (body.namedChildCount > 0) {
    const lastStmt = body.namedChild(body.namedChildCount - 1);
    if (lastStmt && lastStmt.type !== 'return') {
      const taintSources = extractTaintSources(lastStmt, ctx);
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

// ---------------------------------------------------------------------------
// preVisitIteration — set up loop variable taint before walking body
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for') return;

  const iterRight = node.childForFieldName('value');
  if (iterRight) {
    const iterTaint = extractTaintSources(iterRight, ctx);
    if (iterTaint.length > 0) {
      const iterLeft = node.childForFieldName('pattern');
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
  if (node.type !== 'for') return;

  const iterRight = node.childForFieldName('value');
  if (iterRight) {
    const iterTaint = extractTaintSources(iterRight, ctx);
    if (iterTaint.length > 0) {
      const iterLeft = node.childForFieldName('pattern');
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
// analyzeStructure — Ruby/Rails structural patterns
// ---------------------------------------------------------------------------

function analyzeStructure(node: SyntaxNode): StructuralAnalysisResult | null {
  // Look for Rails controller patterns
  if (node.type !== 'call') return null;

  const method = node.childForFieldName('method');
  if (!method) return null;

  const methodName = method.text;

  // before_action :authenticate_user!
  if (methodName === 'before_action' || methodName === 'before_filter') {
    const args = node.childForFieldName('arguments');
    const middlewareNames: string[] = [];
    let hasAuthGate = false;

    if (args) {
      for (let i = 0; i < args.namedChildCount; i++) {
        const arg = args.namedChild(i);
        if (arg?.type === 'simple_symbol' || arg?.type === 'symbol') {
          const name = arg.text.replace(/^:/, '');
          middlewareNames.push(name);
          if (name.includes('auth') || name.includes('login') || name === 'authenticate_user!') {
            hasAuthGate = true;
          }
        }
      }
    }

    return {
      middlewareNames,
      hasAuthGate,
      hasRateLimiter: false,
      hasCsrfProtection: false,
      hasValidation: false,
      routePath: null,
      httpMethod: null,
    };
  }

  // protect_from_forgery
  if (methodName === 'protect_from_forgery') {
    return {
      middlewareNames: ['protect_from_forgery'],
      hasAuthGate: false,
      hasRateLimiter: false,
      hasCsrfProtection: true,
      hasValidation: false,
      routePath: null,
      httpMethod: null,
    };
  }

  // validates / validate
  if (methodName === 'validates' || methodName === 'validate') {
    return {
      middlewareNames: [],
      hasAuthGate: false,
      hasRateLimiter: false,
      hasCsrfProtection: false,
      hasValidation: true,
      routePath: null,
      httpMethod: null,
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// The Profile
// ---------------------------------------------------------------------------

export const rubyProfile: LanguageProfile = {
  id: 'ruby',
  extensions: ['.rb', '.rake', '.gemspec'],

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
  resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
    return resolveCallee(node);
  },

  resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
    return resolvePropertyAccess(node);
  },

  lookupCallee(chain: string[]): CalleePattern | null {
    return _lookupCallee(chain);
  },

  analyzeStructure(node: SyntaxNode): StructuralAnalysisResult | null {
    return analyzeStructure(node);
  },

  // Layer 4: Taint Source Detection
  ingressPattern: /(?:params\s*\[|params\.(?:require|permit|fetch|slice|merge|to_unsafe_h)|request\.(?:body|headers|env|path|url|host|method|remote_ip|content_type|query_string|query_parameters|request_parameters|raw_post|body_stream|params)|cookies\s*\[|session\s*\[|ARGV|gets\b|\$stdin)/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) => nodeType === 'assignment' || nodeType === 'operator_assignment',
  isStatementContainer: (nodeType: string) => nodeType === 'program' || nodeType === 'body_statement' || nodeType === 'then' || nodeType === 'do',

  // Inter-procedural taint: Ruby def syntax
  // Matches: def name(params) | def self.name(params)
  functionParamPattern: /def\s+(?:self\.)?(\w+)\s*(?:\(([^)]*)\))?/,
};

export default rubyProfile;
