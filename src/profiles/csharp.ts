/**
 * CSharpProfile — the seventh LanguageProfile implementation.
 *
 * Every piece of C#-specific logic lives here: AST node type names (from
 * tree-sitter-c-sharp grammar), member access patterns, scope rules, callee
 * resolution via the C# phoneme dictionary, taint extraction, and node
 * classification.
 *
 * Key differences from Java:
 *   - `invocation_expression` not `method_invocation` — fields: `function`, `arguments`
 *   - `member_access_expression` not `field_access` — fields: `expression`, `name`
 *   - `local_declaration_statement` wraps `variable_declaration` wraps `variable_declarator`
 *   - `variable_declarator` has `name` field; value is expression child (no `value` field)
 *   - `compilation_unit` is the root node (not `program`)
 *   - `parameter` not `formal_parameter` — fields: `name`, `type`; children: attribute_list, modifier
 *   - `attribute` / `attribute_list` — C# attributes like [Authorize], [FromBody], [HttpGet]
 *   - `foreach_statement` (for-each) — fields: `left`, `right`, `type`, `body`
 *   - `namespace_declaration` / `file_scoped_namespace_declaration`
 *   - `struct_declaration`, `record_declaration`
 *   - `using_directive` (imports)
 *   - `using_statement` (IDisposable pattern — like try-with-resources)
 *   - `await_expression` (async/await)
 *   - `property_declaration` (C# properties with get/set)
 *   - `lambda_expression` — fields: `body`, `parameters`
 *
 * tree-sitter-c-sharp AST reference: https://github.com/tree-sitter/tree-sitter-c-sharp
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
import { lookupCallee as _lookupCSharpCallee } from '../languages/csharp.js';

// ---------------------------------------------------------------------------
// AST Node Type Sets (tree-sitter-c-sharp)
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'method_declaration',
  'constructor_declaration',
  'lambda_expression',
  'anonymous_method_expression',
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'for_statement',
  'foreach_statement',
  'while_statement',
  'do_statement',
  'if_statement',
  'switch_statement',
  'switch_expression',
  'try_statement',
  'catch_clause',
  'finally_clause',
  'using_statement',
  'lock_statement',
  'checked_statement',
  'unsafe_statement',
  'fixed_statement',
  'block',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'class_declaration',
  'interface_declaration',
  'struct_declaration',
  'enum_declaration',
  'record_declaration',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'local_declaration_statement',
  'field_declaration',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'method_declaration',
  'constructor_declaration',
]);

// Tainted paths for ASP.NET Core request objects
const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // HttpContext.Request
  'HttpContext.Request', 'Request.Form', 'Request.Query',
  'Request.Body', 'Request.Headers', 'Request.Cookies',
  'Request.RouteValues', 'Request.Path', 'Request.QueryString',
  'Request.ContentType', 'Request.Host', 'Request.Method',
  // Short aliases
  'request.Form', 'request.Query', 'request.Body',
  'request.Headers', 'request.Cookies', 'request.Path',
  'request.QueryString', 'request.RouteValues',
  // Session
  'HttpContext.Session', 'Session.GetString',
]);

// ASP.NET taint annotations on parameters
const ASPNET_TAINT_ANNOTATIONS: ReadonlySet<string> = new Set([
  'FromBody', 'FromQuery', 'FromRoute',
  'FromHeader', 'FromForm', 'FromServices',
]);

// ASP.NET routing attributes (for structural analysis)
const ASPNET_ROUTE_ANNOTATIONS: ReadonlySet<string> = new Set([
  'HttpGet', 'HttpPost', 'HttpPut', 'HttpDelete', 'HttpPatch',
  'Route', 'ApiController',
]);

// ASP.NET security annotations
const ASPNET_SECURITY_ANNOTATIONS: ReadonlySet<string> = new Set([
  'Authorize', 'AllowAnonymous',
]);

// Validation annotations
const VALIDATION_ANNOTATIONS: ReadonlySet<string> = new Set([
  'Required', 'StringLength', 'Range', 'RegularExpression',
  'MinLength', 'MaxLength', 'Compare', 'EmailAddress',
  'Phone', 'Url', 'CreditCard',
]);

// Conventional request parameter names in C# handlers
const CSHARP_REQUEST_PARAM_NAMES: ReadonlySet<string> = new Set([
  'request', 'req', 'httpRequest', 'context', 'httpContext',
]);

// Response parameter names
const CSHARP_RESPONSE_PARAM_NAMES: ReadonlySet<string> = new Set([
  'response', 'resp', 'httpResponse',
]);

// Request type names that indicate tainted params
const CSHARP_HTTP_REQUEST_TYPES: ReadonlySet<string> = new Set([
  'HttpRequest', 'HttpContext', 'HttpRequestMessage',
]);

// ---------------------------------------------------------------------------
// Helper: extract callee chain from C# AST nodes
// ---------------------------------------------------------------------------

/**
 * Extract the callee chain from a C# expression.
 * Handles:
 *   - identifier: `foo` -> ['foo']
 *   - member_access_expression: `Console.ReadLine` -> ['Console', 'ReadLine']
 *   - invocation_expression chains: `obj.Method().Chain()` -> resolves terminal
 *   - qualified_name: `System.IO` -> ['System', 'IO']
 */
function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier') {
    return [node.text];
  }

  if (node.type === 'member_access_expression') {
    const expr = node.childForFieldName('expression');
    const name = node.childForFieldName('name');
    if (expr && name) {
      const chain = extractCalleeChain(expr);
      chain.push(name.text);
      return chain;
    }
  }

  if (node.type === 'qualified_name') {
    const parts: string[] = [];
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type !== '.') {
        if (child.type === 'qualified_name') {
          parts.push(...extractCalleeChain(child));
        } else {
          parts.push(child.text);
        }
      }
    }
    return parts;
  }

  // generic_name: Task<T> -> just 'Task'
  if (node.type === 'generic_name') {
    const ident = node.child(0);
    if (ident?.type === 'identifier') return [ident.text];
    return [node.text.split('<')[0]];
  }

  // invocation_expression: obj.Method(args) — extract function chain
  if (node.type === 'invocation_expression') {
    const func = node.childForFieldName('function');
    if (func) {
      return extractCalleeChain(func);
    }
  }

  return [node.text.slice(0, 50)];
}

// ---------------------------------------------------------------------------
// Anti-evasion: constant folding for C#
// ---------------------------------------------------------------------------
// Attackers split sensitive strings ("eval", "cmd.exe", type names) across
// concatenation, Encoding.UTF8.GetString, Convert.FromBase64String, interpolation,
// and LINQ charcode tricks.  We fold them back at analysis time so the callee
// resolver and taint engine see the real value.

/**
 * Attempt to statically fold a C# expression to a constant string.
 *
 * Supported patterns:
 *   1. String concat:  "ev" + "al"  →  "eval"
 *   2. Encoding.UTF8.GetString(new byte[]{101,118,97,108})  →  "eval"
 *   3. Encoding.UTF8.GetString(Convert.FromBase64String("ZXZhbA=="))  →  "eval"
 *   4. string.Join("", new[]{101,118,97,108}.Select(c=>(char)c))  (LINQ charcode)
 *   5. $"{"ev"}{"al"}"  →  "eval"  (interpolated string with only literal parts)
 *   6. Parenthesized expressions, character literals, integer literals
 *   7. Conditional: cond ? "a" : "a"  →  "a" (when both arms are equal constants)
 *   8. (char)101  →  "e"  (cast to char with integer literal)
 */
function tryFoldConstant(n: SyntaxNode): string | null {
  // --- Leaf: string literals ---
  if (n.type === 'string_literal' || n.type === 'verbatim_string_literal' || n.type === 'raw_string_literal') {
    // Strip quotes: "foo" → foo, @"foo" → foo, """foo""" → foo
    let raw = n.text;
    if (raw.startsWith('@"')) raw = raw.slice(2, -1);
    else if (raw.startsWith('"""')) raw = raw.slice(3, -3);
    else if (raw.startsWith('"')) raw = raw.slice(1, -1);
    return resolveCSharpEscapes(raw);
  }

  // --- Leaf: integer literal ---
  if (n.type === 'integer_literal' || n.type === 'real_literal') {
    return n.text;
  }

  // --- Leaf: character literal  'e' → "e" ---
  if (n.type === 'character_literal') {
    const raw = n.text.slice(1, -1); // strip single quotes
    return resolveCSharpEscapes(raw);
  }

  // --- Binary expression: "ev" + "al" → "eval" ---
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

  // --- Parenthesized: ("ev" + "al") → "eval" ---
  if (n.type === 'parenthesized_expression') {
    const inner = n.namedChild(0);
    return inner ? tryFoldConstant(inner) : null;
  }

  // --- Conditional: cond ? "a" : "a" → "a" ---
  if (n.type === 'conditional_expression') {
    const consequence = n.childForFieldName('consequence');
    const alternative = n.childForFieldName('alternative');
    if (consequence && alternative) {
      const cv = tryFoldConstant(consequence);
      const av = tryFoldConstant(alternative);
      if (cv !== null && av !== null && cv === av) return cv;
    }
  }

  // --- Cast expression: (char)101 → "e" ---
  if (n.type === 'cast_expression') {
    const castType = n.childForFieldName('type');
    const castValue = n.childForFieldName('value');
    if (castType?.text === 'char' && castValue) {
      const v = tryFoldConstant(castValue);
      if (v !== null) {
        const code = parseInt(v, 10);
        if (!isNaN(code) && code >= 0 && code <= 0x10FFFF) {
          return String.fromCharCode(code);
        }
      }
    }
  }

  // --- Interpolated string: $"{"ev"}{"al"}" → "eval" ---
  if (n.type === 'interpolated_string_expression') {
    let result = '';
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (!child) continue;
      // Skip $" and " tokens
      if (child.type === '"' || child.type === '$"' || child.type === '$@"' || child.type === '@$"') continue;
      if (child.type === 'interpolation_start' || child.type === 'interpolation_quote') continue;
      // Raw text fragments between interpolations
      if (!child.isNamed) {
        // Literal text content (not punctuation)
        if (child.type !== '{' && child.type !== '}') {
          // Could be literal text
        }
        continue;
      }
      if (child.type === 'interpolation') {
        const inner = child.namedChild(0);
        if (!inner) return null;
        const folded = tryFoldConstant(inner);
        if (folded === null) return null;
        result += folded;
      } else {
        // interpolated_string_text or other literal content
        result += child.text;
      }
    }
    return result;
  }

  // --- Invocation expressions: Encoding.UTF8.GetString(...), Convert.FromBase64String(...), string.Join(...) ---
  if (n.type === 'invocation_expression') {
    const func = n.childForFieldName('function');
    const args = n.childForFieldName('arguments');
    if (func && args) {
      const chain = extractCalleeChain(func);
      const chainStr = chain.join('.');

      // Encoding.UTF8.GetString(byte[]) or Encoding.ASCII.GetString(byte[])
      if (chainStr === 'Encoding.UTF8.GetString' || chainStr === 'Encoding.ASCII.GetString' ||
          chainStr === 'System.Text.Encoding.UTF8.GetString' || chainStr === 'System.Text.Encoding.ASCII.GetString') {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const argExpr = firstArg.type === 'argument' ? firstArg.namedChild(0) : firstArg;
          if (argExpr) {
            // Case A: GetString(new byte[]{101,118,97,108})
            const bytes = tryExtractByteArray(argExpr);
            if (bytes !== null) {
              return Buffer.from(bytes).toString('utf-8');
            }
            // Case B: GetString(Convert.FromBase64String("ZXZhbA=="))
            const innerFolded = tryFoldConstant(argExpr);
            if (innerFolded !== null) {
              // If the inner produced raw bytes (via FromBase64String folding),
              // it will already be decoded — just return it
              return innerFolded;
            }
          }
        }
      }

      // Convert.FromBase64String("ZXZhbA==") → decode base64
      if (chainStr === 'Convert.FromBase64String' || chainStr === 'System.Convert.FromBase64String') {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const argExpr = firstArg.type === 'argument' ? firstArg.namedChild(0) : firstArg;
          if (argExpr) {
            const b64 = tryFoldConstant(argExpr);
            if (b64 !== null) {
              try {
                return Buffer.from(b64, 'base64').toString('utf-8');
              } catch { /* not valid base64 */ }
            }
          }
        }
      }

      // string.Join("", ...) where ... produces char sequence
      if (chainStr === 'string.Join' || chainStr === 'String.Join') {
        const sepArg = args.namedChild(0);
        const dataArg = args.namedChild(1);
        if (sepArg && dataArg) {
          const sepExpr = sepArg.type === 'argument' ? sepArg.namedChild(0) : sepArg;
          const dataExpr = dataArg.type === 'argument' ? dataArg.namedChild(0) : dataArg;
          const sep = sepExpr ? tryFoldConstant(sepExpr) : null;
          if (sep !== null && sep === '' && dataExpr) {
            // string.Join("", new[]{101,118,97,108}.Select(c=>(char)c))
            // The Select produces an IEnumerable<char> — we just need the array of ints
            // and knowledge that they're cast to char
            if (dataExpr.type === 'invocation_expression') {
              const selectFunc = dataExpr.childForFieldName('function');
              const selectArgs = dataExpr.childForFieldName('arguments');
              if (selectFunc?.type === 'member_access_expression') {
                const selectMethod = selectFunc.childForFieldName('name');
                const selectObj = selectFunc.childForFieldName('expression');
                if (selectMethod?.text === 'Select' && selectObj) {
                  // Check if the lambda does a char cast
                  const lambdaArg = selectArgs?.namedChild(0);
                  const lambdaExpr = lambdaArg?.type === 'argument' ? lambdaArg.namedChild(0) : lambdaArg;
                  if (lambdaExpr?.type === 'lambda_expression') {
                    const lambdaBody = lambdaExpr.childForFieldName('body');
                    if (lambdaBody && lambdaBody.text.includes('char')) {
                      // Extract integers from the source array
                      const codes = tryExtractIntArray(selectObj);
                      if (codes !== null) {
                        return String.fromCharCode(...codes);
                      }
                    }
                  }
                }
              }
            }
            // Also handle: string.Join("", charArray) where charArray is literal
            const codes = tryExtractIntArray(dataExpr);
            if (codes !== null) {
              return String.fromCharCode(...codes);
            }
          }
        }
      }
    }
  }

  return null;
}

/**
 * Resolve C# string escape sequences.
 */
function resolveCSharpEscapes(s: string): string {
  return s
    .replace(/\\x([0-9a-fA-F]{1,4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\U([0-9a-fA-F]{8})/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\'/g, "'").replace(/\\"/g, '"')
    .replace(/\\0/g, '\0')
    .replace(/\\\\/g, '\\');
}

/**
 * Try to extract an integer array from: new byte[]{101,118,...}, new[]{101,...},
 * or initializer_expression {101,118,...}.
 */
function tryExtractByteArray(node: SyntaxNode): number[] | null {
  // array_creation_expression: new byte[]{101,118,97,108}
  // implicit_array_creation_expression: new[]{101,118,97,108}
  let initExpr: SyntaxNode | null = null;
  if (node.type === 'array_creation_expression' || node.type === 'implicit_array_creation_expression') {
    // Find the initializer_expression child
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child?.type === 'initializer_expression') {
        initExpr = child;
        break;
      }
    }
  } else if (node.type === 'initializer_expression') {
    initExpr = node;
  }
  if (!initExpr) return null;

  const values: number[] = [];
  for (let i = 0; i < initExpr.namedChildCount; i++) {
    const el = initExpr.namedChild(i);
    if (!el) continue;
    if (el.type === 'integer_literal') {
      values.push(parseInt(el.text, 10));
    } else {
      return null; // non-literal element → bail
    }
  }
  return values.length > 0 ? values : null;
}

/**
 * Try to extract an int array from various array expression forms.
 */
function tryExtractIntArray(node: SyntaxNode): number[] | null {
  // Direct array creation
  const direct = tryExtractByteArray(node);
  if (direct) return direct;

  // collection_expression: [101, 118, ...]
  if (node.type === 'collection_expression') {
    const values: number[] = [];
    for (let i = 0; i < node.namedChildCount; i++) {
      const el = node.namedChild(i);
      if (el?.type === 'integer_literal') {
        values.push(parseInt(el.text, 10));
      } else {
        return null;
      }
    }
    return values.length > 0 ? values : null;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Reflection evasion sinks — methods that take a constructed type/method name
// ---------------------------------------------------------------------------
const REFLECTION_SINKS: ReadonlySet<string> = new Set([
  'Type.GetType',
  'Activator.CreateInstance',
  'Assembly.Load',
  'Assembly.LoadFrom',
  'Assembly.LoadFile',
]);

const REFLECTION_METHOD_SINKS: ReadonlySet<string> = new Set([
  'GetMethod',
  'GetProperty',
  'GetField',
  'GetEvent',
  'GetMember',
  'InvokeMember',
]);

// ---------------------------------------------------------------------------
// Helper: resolve callee from an invocation_expression or object_creation_expression
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  // invocation_expression: obj.Method(args) or Method(args)
  if (node.type === 'invocation_expression') {
    const func = node.childForFieldName('function');
    if (!func) return null;

    if (func.type === 'member_access_expression') {
      const expr = func.childForFieldName('expression');
      const name = func.childForFieldName('name');
      if (expr && name) {
        const chain = extractCalleeChain(expr);
        chain.push(name.text);
        const pattern = _lookupCSharpCallee(chain);
        if (pattern) {
          return {
            nodeType: pattern.nodeType,
            subtype: pattern.subtype,
            tainted: pattern.tainted,
            chain,
          };
        }
      }
    } else if (func.type === 'identifier') {
      // Bare method call: Ok(), NotFound(), etc.
      const chain = [func.text];
      const pattern = _lookupCSharpCallee(chain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain,
        };
      }
    } else if (func.type === 'generic_name') {
      // Generic method call: Deserialize<T>()
      const ident = func.child(0);
      if (ident?.type === 'identifier') {
        const chain = [ident.text];
        const pattern = _lookupCSharpCallee(chain);
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

    // ── REFLECTION EVASION DETECTION ──
    // Detect: Type.GetType(constructed), Activator.CreateInstance(type),
    //         Assembly.Load(constructed), typeof(T).GetMethod(constructed)
    if (func?.type === 'member_access_expression') {
      const expr = func.childForFieldName('expression');
      const name = func.childForFieldName('name');
      if (expr && name) {
        const chain = extractCalleeChain(expr);
        chain.push(name.text);
        const chainStr = chain.join('.');

        // Type.GetType("..."), Activator.CreateInstance, Assembly.Load, etc.
        if (REFLECTION_SINKS.has(chainStr)) {
          return {
            nodeType: 'EXTERNAL',
            subtype: 'reflection',
            tainted: true,  // classifyNode will refine based on folding
            chain,
          };
        }

        // typeof(T).GetMethod("constructed"), obj.GetMethod("constructed")
        if (REFLECTION_METHOD_SINKS.has(name.text)) {
          return {
            nodeType: 'EXTERNAL',
            subtype: 'reflection',
            tainted: true,
            chain,
          };
        }
      }
    }
    return null;
  }

  // object_creation_expression: new ClassName(args)
  if (node.type === 'object_creation_expression') {
    const typeNode = node.childForFieldName('type');
    if (typeNode) {
      const typeName = typeNode.type === 'generic_name'
        ? (typeNode.child(0)?.text ?? typeNode.text)
        : typeNode.text;
      const chain = [typeName];
      const pattern = _lookupCSharpCallee(chain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain,
        };
      }

      // Check specific dangerous constructors
      if (typeName === 'SqlCommand') {
        return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false, chain };
      }
      if (typeName === 'SqlConnection') {
        return { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false, chain };
      }
      if (typeName === 'HttpClient') {
        return { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false, chain };
      }
      if (typeName === 'ProcessStartInfo' || typeName === 'Process') {
        return { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false, chain };
      }
      if (typeName === 'StreamReader' || typeName === 'StreamWriter') {
        return { nodeType: 'INGRESS', subtype: 'file_read', tainted: false, chain };
      }
      if (typeName === 'BinaryFormatter') {
        return { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true, chain };
      }
      if (typeName === 'Uri' || typeName === 'UriBuilder') {
        return { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false, chain };
      }
    }
    return null;
  }

  return null;
}

// ---------------------------------------------------------------------------
// resolvePropertyAccess — resolve a C# `member_access_expression` (non-call)
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  if (node.type !== 'member_access_expression') return null;

  const chain = extractCalleeChain(node);
  if (chain.length < 2) return null;

  const fullPath = chain.join('.');

  // Check tainted paths
  if (TAINTED_PATHS.has(fullPath)) {
    return {
      nodeType: 'INGRESS',
      subtype: 'http_request',
      tainted: true,
    };
  }

  // Check phoneme dictionary for property access
  const pattern = _lookupCSharpCallee(chain);
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
// extractPatternNames — C# variable declarators
// ---------------------------------------------------------------------------

function extractPatternNames(pattern: SyntaxNode): string[] {
  const names: string[] = [];

  if (pattern.type === 'identifier') {
    names.push(pattern.text);
  }

  // variable_declarator: name = value
  if (pattern.type === 'variable_declarator') {
    const name = pattern.childForFieldName('name');
    if (name?.type === 'identifier') {
      names.push(name.text);
    }
  }

  // tuple_pattern: (var a, var b) = ...
  if (pattern.type === 'tuple_pattern') {
    for (let i = 0; i < pattern.namedChildCount; i++) {
      const child = pattern.namedChild(i);
      if (child) names.push(...extractPatternNames(child));
    }
  }

  return names;
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
// Helper: check if a parameter has an ASP.NET taint attribute
// ---------------------------------------------------------------------------

function paramHasTaintAttribute(paramNode: SyntaxNode): boolean {
  // In tree-sitter-c-sharp, parameter has attribute_list children
  for (let i = 0; i < paramNode.childCount; i++) {
    const child = paramNode.child(i);
    if (!child) continue;
    if (child.type === 'attribute_list') {
      for (let j = 0; j < child.namedChildCount; j++) {
        const attr = child.namedChild(j);
        if (attr?.type === 'attribute') {
          const attrName = attr.childForFieldName('name')?.text ?? '';
          if (ASPNET_TAINT_ANNOTATIONS.has(attrName)) return true;
        }
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helper: check if a method has an ASP.NET route attribute
// ---------------------------------------------------------------------------

function methodHasRouteAttribute(methodNode: SyntaxNode): string | null {
  for (let i = 0; i < methodNode.childCount; i++) {
    const child = methodNode.child(i);
    if (!child) continue;
    if (child.type === 'attribute_list') {
      for (let j = 0; j < child.namedChildCount; j++) {
        const attr = child.namedChild(j);
        if (attr?.type === 'attribute') {
          const attrName = attr.childForFieldName('name')?.text ?? '';
          if (ASPNET_ROUTE_ANNOTATIONS.has(attrName)) {
            return attrName;
          }
        }
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Helper: check if a method has ASP.NET security attributes
// ---------------------------------------------------------------------------

function methodHasSecurityAttribute(methodNode: SyntaxNode): boolean {
  for (let i = 0; i < methodNode.childCount; i++) {
    const child = methodNode.child(i);
    if (!child) continue;
    if (child.type === 'attribute_list') {
      for (let j = 0; j < child.namedChildCount; j++) {
        const attr = child.namedChild(j);
        if (attr?.type === 'attribute') {
          const attrName = attr.childForFieldName('name')?.text ?? '';
          if (ASPNET_SECURITY_ANNOTATIONS.has(attrName)) return true;
        }
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helper: extract attribute name from attribute node
// ---------------------------------------------------------------------------

function getAttributeName(node: SyntaxNode): string {
  if (node.type === 'attribute') {
    const name = node.childForFieldName('name');
    return name?.text ?? '';
  }
  return node.text;
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

    // -- Leaf: member_access_expression -- check for tainted paths (Request.Form etc.)
    case 'member_access_expression': {
      const resolution = resolvePropertyAccess(expr);
      if (resolution?.tainted) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'csharp',
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
      // Check if the object is a tainted variable
      const exprChild = expr.childForFieldName('expression');
      if (exprChild?.type === 'identifier') {
        const varInfo = ctx.resolveVariable(exprChild.text);
        if (varInfo?.tainted && varInfo.producingNodeId) {
          return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
        }
      }
      // Recurse into deeper chains
      if (exprChild?.type === 'member_access_expression') {
        return extractTaintSources(exprChild, ctx);
      }
      return [];
    }

    // -- Binary expression: string concatenation ("SELECT " + userInput) --
    case 'binary_expression': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const sources: TaintSourceResult[] = [];
      if (left) sources.push(...extractTaintSources(left, ctx));
      if (right) sources.push(...extractTaintSources(right, ctx));
      return sources;
    }

    // -- Interpolated string: $"SELECT * FROM {userInput}" --
    case 'interpolated_string_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    case 'interpolation': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Invocation expression: check if sanitizer, then check args --
    case 'invocation_expression': {
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
          if (!arg) continue;
          // argument node wraps the actual expression
          if (arg.type === 'argument') {
            for (let j = 0; j < arg.namedChildCount; j++) {
              const inner = arg.namedChild(j);
              if (inner) sources.push(...extractTaintSources(inner, ctx));
            }
          } else {
            sources.push(...extractTaintSources(arg, ctx));
          }
        }
      }
      // Check receiver (expression)
      const func = expr.childForFieldName('function');
      if (func?.type === 'member_access_expression') {
        const obj = func.childForFieldName('expression');
        if (obj) sources.push(...extractTaintSources(obj, ctx));
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

    // -- Object creation: new Foo(taintedArg) --
    case 'object_creation_expression': {
      const sources: TaintSourceResult[] = [];
      const args = expr.childForFieldName('arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (!arg) continue;
          if (arg.type === 'argument') {
            for (let j = 0; j < arg.namedChildCount; j++) {
              const inner = arg.namedChild(j);
              if (inner) sources.push(...extractTaintSources(inner, ctx));
            }
          } else {
            sources.push(...extractTaintSources(arg, ctx));
          }
        }
      }
      return sources;
    }

    // -- Parenthesized expression --
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Cast expression: (string)x --
    case 'cast_expression': {
      // In C#, cast_expression has type + expression children
      const value = expr.namedChild(expr.namedChildCount - 1);
      return value ? extractTaintSources(value, ctx) : [];
    }

    // -- Conditional (ternary): condition ? a : b --
    case 'conditional_expression': {
      const sources: TaintSourceResult[] = [];
      // Condition, consequence (index 1), alternative (index 2) — use named children
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child && i > 0) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Element access: arr[i] --
    case 'element_access_expression': {
      const exprChild = expr.childForFieldName('expression');
      if (exprChild) return extractTaintSources(exprChild, ctx);
      return [];
    }

    // -- Await expression: await SomeAsyncCall() --
    case 'await_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Assignment expression (within expressions) --
    case 'assignment_expression': {
      const right = expr.childForFieldName('right');
      return right ? extractTaintSources(right, ctx) : [];
    }

    // -- Argument wrapper --
    case 'argument': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  // local_declaration_statement wraps variable_declaration
  // field_declaration also wraps variable_declaration
  let varDeclNode: SyntaxNode | null = null;

  if (node.type === 'local_declaration_statement' || node.type === 'field_declaration') {
    // Find the variable_declaration child
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child?.type === 'variable_declaration') {
        varDeclNode = child;
        break;
      }
    }
  }

  if (!varDeclNode) return;

  // Walk variable_declarator children
  for (let i = 0; i < varDeclNode.namedChildCount; i++) {
    const child = varDeclNode.namedChild(i);
    if (!child || child.type !== 'variable_declarator') continue;

    const nameNode = child.childForFieldName('name');
    if (!nameNode || nameNode.type !== 'identifier') continue;
    const varName = nameNode.text;

    // The value expression is the first expression child (not a named field)
    let valueNode: SyntaxNode | null = null;
    for (let j = 0; j < child.namedChildCount; j++) {
      const sub = child.namedChild(j);
      if (sub && sub.type !== 'bracketed_argument_list' && sub.type !== 'tuple_pattern') {
        // This should be the initializer expression
        if (sub.type !== 'identifier' || sub !== nameNode) {
          valueNode = sub;
          break;
        }
      }
    }

    // Determine variable kind
    const kind: VariableInfo['kind'] = node.type === 'field_declaration' ? 'var' : 'let';

    let producingNodeId = ctx.lastCreatedNodeId;
    let tainted = false;

    // Check if lastCreatedNode is tainted
    if (producingNodeId) {
      const producer = ctx.neuralMap.nodes.find((n: any) => n.id === producingNodeId);
      if (producer && (
        producer.node_type === 'INGRESS' ||
        producer.data_out.some((d: any) => d.tainted)
      )) {
        tainted = true;
      }
    }

    // Multi-hop taint: if value is an identifier, inherit taint
    if (!tainted && valueNode) {
      if (valueNode.type === 'identifier') {
        const sourceVar = ctx.resolveVariable(valueNode.text);
        if (sourceVar) {
          tainted = sourceVar.tainted;
          if (sourceVar.producingNodeId) producingNodeId = sourceVar.producingNodeId;
        }
      }
    }

    // Direct taint extraction from the value expression
    if (!tainted && valueNode) {
      const directTaint = extractTaintSources(valueNode, ctx);
      if (directTaint.length > 0) {
        tainted = true;
        producingNodeId = directTaint[0].nodeId;
      }
    }

    // Cross-function taint: x = GetInput(request)
    if (!producingNodeId && valueNode) {
      const checkCallTaint = (expr: SyntaxNode) => {
        if (expr.type === 'invocation_expression') {
          const func = expr.childForFieldName('function');
          if (func?.type === 'identifier') {
            const funcNodeId = ctx.functionRegistry.get(func.text);
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
      checkCallTaint(valueNode);
    }

    // Alias chain detection: cmd = connection.CreateCommand() -> store chain
    let aliasChain: string[] | undefined;
    if (valueNode) {
      if (valueNode.type === 'invocation_expression') {
        const func = valueNode.childForFieldName('function');
        if (func?.type === 'member_access_expression') {
          const obj = func.childForFieldName('expression');
          const name = func.childForFieldName('name');
          if (obj && name) {
            const chain = extractCalleeChain(obj);
            chain.push(name.text);
            aliasChain = chain;
          }
        }
      } else if (valueNode.type === 'member_access_expression') {
        aliasChain = extractCalleeChain(valueNode);
      }
    }

    // Constant folding: var action = "quer" + "y" → constantValue = "query"
    let constantValue: string | undefined;
    if (valueNode) {
      const folded = tryFoldConstant(valueNode);
      if (folded !== null) constantValue = folded;
    }

    ctx.declareVariable(varName, kind, null, tainted, producingNodeId);
    if (aliasChain || constantValue) {
      const v = ctx.resolveVariable(varName);
      if (v) {
        if (aliasChain) v.aliasChain = aliasChain;
        if (constantValue) v.constantValue = constantValue;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// processFunctionParams — handle C# method parameters with attributes
// ---------------------------------------------------------------------------

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) return;

  // In C#, parameters are `parameter` nodes inside `parameter_list`
  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param || param.type !== 'parameter') continue;

    const nameNode = param.childForFieldName('name');
    const typeNode = param.childForFieldName('type');
    const paramName = nameNode?.text;
    const typeText = typeNode?.text ?? '';

    if (!paramName) continue;

    // Check 1: ASP.NET taint attributes ([FromBody], [FromQuery], etc.)
    const hasTaintAttribute = paramHasTaintAttribute(param);

    // Check 2: HttpRequest type
    const isRequestType = CSHARP_HTTP_REQUEST_TYPES.has(typeText);

    // Check 3: Conventional request parameter names
    const isRequestName = CSHARP_REQUEST_PARAM_NAMES.has(paramName);

    if (hasTaintAttribute || isRequestType || isRequestName) {
      // Create an INGRESS node for tainted parameter
      const ingressNode = createNode({
        label: paramName,
        node_type: 'INGRESS',
        node_subtype: 'http_request',
        language: 'csharp',
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

      ctx.declareVariable(paramName, 'param', null, true, ingressNode.id);
    } else if (CSHARP_RESPONSE_PARAM_NAMES.has(paramName)) {
      // Response — not tainted but declare it
      ctx.declareVariable(paramName, 'param', null, false, null);
    } else {
      // Regular parameter — check pendingCallbackTaint
      const producingId = ctx.pendingCallbackTaint.get(paramName) ?? null;
      const isTainted = producingId !== null;
      if (isTainted) ctx.pendingCallbackTaint.delete(paramName);
      ctx.declareVariable(paramName, 'param', null, isTainted, producingId);
    }
  }
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of the switch statement
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  switch (node.type) {
    // -- METHOD DECLARATIONS --
    case 'method_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const routeAttribute = methodHasRouteAttribute(node);
      const hasSecurityAttribute = methodHasSecurityAttribute(node);

      const methodNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: routeAttribute ? 'route' : 'function',
        language: 'csharp',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });

      if (routeAttribute) {
        methodNode.tags.push('route', routeAttribute);
      }
      if (hasSecurityAttribute) {
        methodNode.tags.push('auth_gate');
      }

      // Populate param_names from AST
      const csParams = node.childForFieldName('parameters');
      if (csParams) {
        const pNames: string[] = [];
        for (let pi = 0; pi < csParams.namedChildCount; pi++) {
          const p = csParams.namedChild(pi);
          if (p?.type === 'parameter') {
            const pName = p.childForFieldName('name')?.text;
            if (pName) pNames.push(pName);
          }
        }
        if (pNames.length > 0) methodNode.param_names = pNames;
      }

      ctx.neuralMap.nodes.push(methodNode);
      ctx.lastCreatedNodeId = methodNode.id;
      ctx.emitContainsIfNeeded(methodNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = methodNode.id;
      ctx.functionRegistry.set(name, methodNode.id);
      // Also register with param count to avoid overloading collisions
      const csParamCount = csParams ? csParams.namedChildCount : 0;
      ctx.functionRegistry.set(`${name}:${csParamCount}`, methodNode.id);
      break;
    }

    // -- CONSTRUCTOR DECLARATIONS --
    case 'constructor_declaration': {
      const name = node.childForFieldName('name')?.text ?? '<init>';
      const ctorNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'csharp',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctorNode.tags.push('constructor');
      ctx.neuralMap.nodes.push(ctorNode);
      ctx.lastCreatedNodeId = ctorNode.id;
      ctx.emitContainsIfNeeded(ctorNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = ctorNode.id;
      ctx.functionRegistry.set(name, ctorNode.id);
      // Also register with param count to avoid overloading collisions
      const csCtorParams = node.childForFieldName('parameters');
      const csCtorParamCount = csCtorParams ? csCtorParams.namedChildCount : 0;
      ctx.functionRegistry.set(`${name}:${csCtorParamCount}`, ctorNode.id);
      break;
    }

    // -- LAMBDA EXPRESSION --
    case 'lambda_expression': {
      let lambdaName = 'lambda';
      // Try to get name from parent variable declaration
      if (node.parent?.type === 'variable_declarator') {
        const parentName = node.parent.childForFieldName('name');
        if (parentName?.type === 'identifier') {
          lambdaName = parentName.text;
        }
      }
      const lambdaNode = createNode({
        label: lambdaName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'csharp',
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
      if (lambdaName !== 'lambda') ctx.functionRegistry.set(lambdaName, lambdaNode.id);
      break;
    }

    // -- ANONYMOUS METHOD EXPRESSION --
    case 'anonymous_method_expression': {
      const anonNode = createNode({
        label: 'anonymous_method',
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'csharp',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      anonNode.tags.push('anonymous');
      ctx.neuralMap.nodes.push(anonNode);
      ctx.lastCreatedNodeId = anonNode.id;
      ctx.emitContainsIfNeeded(anonNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = anonNode.id;
      break;
    }

    // -- CLASS DECLARATIONS --
    case 'class_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousClass';

      // Check for class-level attributes (ASP.NET controllers)
      let subtype = 'class';
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child?.type === 'attribute_list') {
          for (let j = 0; j < child.namedChildCount; j++) {
            const attr = child.namedChild(j);
            if (attr?.type === 'attribute') {
              const attrName = getAttributeName(attr);
              if (attrName === 'ApiController' || attrName === 'Controller') {
                subtype = 'controller';
              }
            }
          }
        }
      }

      // Also check base class for "Controller" or "ControllerBase"
      const baseList = node.descendantsOfType('base_list')[0];
      if (baseList) {
        const baseText = baseList.text;
        if (baseText.includes('Controller') || baseText.includes('ControllerBase')) {
          subtype = 'controller';
        }
        if (baseText.includes('Hub')) {
          subtype = 'hub';
        }
      }

      const classNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: subtype,
        language: 'csharp',
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

    // -- INTERFACE DECLARATION --
    case 'interface_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousInterface';
      const ifaceNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'interface',
        language: 'csharp',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(ifaceNode);
      ctx.lastCreatedNodeId = ifaceNode.id;
      ctx.emitContainsIfNeeded(ifaceNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = ifaceNode.id;
      break;
    }

    // -- STRUCT DECLARATION --
    case 'struct_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousStruct';
      const structNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'struct',
        language: 'csharp',
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

    // -- ENUM DECLARATION --
    case 'enum_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousEnum';
      const enumNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'enum',
        language: 'csharp',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(enumNode);
      ctx.lastCreatedNodeId = enumNode.id;
      ctx.emitContainsIfNeeded(enumNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = enumNode.id;
      break;
    }

    // -- RECORD DECLARATION --
    case 'record_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousRecord';
      const recordNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'record',
        language: 'csharp',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(recordNode);
      ctx.lastCreatedNodeId = recordNode.id;
      ctx.emitContainsIfNeeded(recordNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = recordNode.id;
      break;
    }

    // -- NAMESPACE DECLARATIONS --
    case 'namespace_declaration':
    case 'file_scoped_namespace_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'global';
      const nsNode = createNode({
        label: `namespace ${name}`,
        node_type: 'STRUCTURAL',
        node_subtype: 'module',
        language: 'csharp',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(nsNode);
      ctx.lastCreatedNodeId = nsNode.id;
      ctx.emitContainsIfNeeded(nsNode.id);
      break;
    }

    // -- USING DIRECTIVES (imports) --
    case 'using_directive': {
      const usingName = node.childForFieldName('name')?.text ?? node.text.replace(/^using\s+/, '').replace(/;\s*$/, '').trim();
      const importNode = createNode({
        label: usingName,
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'csharp',
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

    // -- INVOCATION EXPRESSION: classify by callee --
    case 'invocation_expression': {
      const resolution = resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'csharp',
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

        // ── REFLECTION EVASION: fold arguments and mark attack surface ──
        if (resolution.subtype === 'reflection') {
          const reflectArgs = node.childForFieldName('arguments');
          const firstArg = reflectArgs?.namedChild(0);
          const argExpr = firstArg?.type === 'argument' ? firstArg.namedChild(0) : firstArg;

          if (argExpr) {
            const folded = tryFoldConstant(argExpr);
            if (folded !== null) {
              // Successfully folded — record the resolved value
              n.label = `${resolution.chain.join('.')}("${folded}")`;
              n.code_snapshot = `[FOLDED] ${node.text.slice(0, 150)} → "${folded}"`;
            } else {
              // Could not fold — check for variable with constantValue
              if (argExpr.type === 'identifier') {
                const varInfo = ctx.resolveVariable(argExpr.text);
                if (varInfo?.constantValue) {
                  n.label = `${resolution.chain.join('.')}("${varInfo.constantValue}")`;
                  n.code_snapshot = `[FOLDED-VAR] ${node.text.slice(0, 150)} → "${varInfo.constantValue}"`;
                }
              }
            }
          }

          // Always mark reflection as an attack surface
          n.attack_surface.push('reflection_evasion');

          // Check if any argument is tainted (from user input)
          const reflectArgsTaint = node.childForFieldName('arguments');
          if (reflectArgsTaint) {
            for (let a = 0; a < reflectArgsTaint.namedChildCount; a++) {
              const arg = reflectArgsTaint.namedChild(a);
              if (!arg) continue;
              const inner = arg.type === 'argument' ? arg.namedChild(0) : arg;
              if (inner) {
                const taint = extractTaintSources(inner, ctx);
                if (taint.length > 0) {
                  n.attack_surface.push('runtime_eval');
                  break;
                }
              }
            }
          }
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

            // argument nodes wrap the actual expression
            const taintSources: TaintSourceResult[] = [];
            if (arg.type === 'argument') {
              for (let j = 0; j < arg.namedChildCount; j++) {
                const inner = arg.namedChild(j);
                if (inner) taintSources.push(...extractTaintSources(inner, ctx));
              }
            } else {
              taintSources.push(...extractTaintSources(arg, ctx));
            }

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
        const func = node.childForFieldName('function');
        if (func?.type === 'member_access_expression') {
          const calleeObj = func.childForFieldName('expression');
          if (calleeObj) {
            const receiverTaint = extractTaintSources(calleeObj, ctx);
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

        // Callback parameter taint (for lambdas passed as args)
        if (callHasTaintedArgs) {
          const callArgs = node.childForFieldName('arguments');
          if (callArgs) {
            for (let ai = 0; ai < callArgs.namedChildCount; ai++) {
              const argWrapper = callArgs.namedChild(ai);
              const arg = argWrapper?.type === 'argument' ? argWrapper.namedChild(0) : argWrapper;
              if (arg?.type === 'lambda_expression') {
                const params = arg.childForFieldName('parameters');
                if (params) {
                  for (let pi = 0; pi < params.namedChildCount; pi++) {
                    const p = params.namedChild(pi);
                    if (p?.type === 'parameter') {
                      const pName = p.childForFieldName('name');
                      if (pName?.type === 'identifier') {
                        ctx.pendingCallbackTaint.set(pName.text, n.id);
                      }
                    } else if (p?.type === 'identifier') {
                      // Inferred parameter: x => x.Foo()
                      ctx.pendingCallbackTaint.set(p.text, n.id);
                    }
                  }
                }
              }
            }
          }
        }
      } else {
        // -- Variable alias resolution --
        const func = node.childForFieldName('function');
        let calleeName: string | null = null;

        if (func?.type === 'member_access_expression') {
          const aliasObj = func.childForFieldName('expression');
          const aliasName = func.childForFieldName('name');
          if (aliasObj?.type === 'identifier') {
            const aliasVar = ctx.resolveVariable(aliasObj.text);
            if (aliasVar?.aliasChain && aliasName) {
              const fullChain = [...aliasVar.aliasChain, aliasName.text];
              const aliasPattern = _lookupCSharpCallee(fullChain);
              if (aliasPattern) {
                const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
                const aliasN = createNode({
                  label,
                  node_type: aliasPattern.nodeType,
                  node_subtype: aliasPattern.subtype,
                  language: 'csharp',
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
                    const taintSources = arg.type === 'argument'
                      ? (arg.namedChild(0) ? extractTaintSources(arg.namedChild(0)!, ctx) : [])
                      : extractTaintSources(arg, ctx);
                    for (const source of taintSources) {
                      ctx.addDataFlow(source.nodeId, aliasN.id, source.name, 'unknown', true);
                    }
                  }
                }
                break;
              }
            }
          }
          calleeName = aliasName?.text ?? null;
        } else if (func?.type === 'identifier') {
          calleeName = func.text;
        }

        // -- Unresolved call -- check if it's a locally-defined method --
        if (calleeName && ctx.functionRegistry.has(calleeName)) {
          const argsNode = node.childForFieldName('arguments');
          const taintSources: TaintSourceResult[] = [];
          if (argsNode) {
            for (let a = 0; a < argsNode.namedChildCount; a++) {
              const arg = argsNode.namedChild(a);
              if (!arg) continue;
              if (arg.type === 'argument') {
                for (let j = 0; j < arg.namedChildCount; j++) {
                  const inner = arg.namedChild(j);
                  if (inner) taintSources.push(...extractTaintSources(inner, ctx));
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
            language: 'csharp',
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

      // CALLS edge: capture method name for pending calls
      const funcForCalls = node.childForFieldName('function');
      let pendingCalleeName: string | null = null;
      if (funcForCalls?.type === 'identifier') {
        pendingCalleeName = funcForCalls.text;
      } else if (funcForCalls?.type === 'member_access_expression') {
        const methodName = funcForCalls.childForFieldName('name');
        if (methodName?.type === 'identifier') pendingCalleeName = methodName.text;
      }
      if (pendingCalleeName) {
        const containerId = ctx.getCurrentContainerId();
        if (containerId) {
          ctx.pendingCalls.push({
            callerContainerId: containerId,
            calleeName: pendingCalleeName,
            isAsync: false,
          });
        }
      }
      break;
    }

    // -- OBJECT CREATION EXPRESSION: new ClassName(args) --
    case 'object_creation_expression': {
      const resolution = resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'csharp',
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

        // Data flow from tainted arguments
        const argsNode = node.childForFieldName('arguments');
        if (argsNode) {
          for (let a = 0; a < argsNode.namedChildCount; a++) {
            const arg = argsNode.namedChild(a);
            if (!arg) continue;
            const taintSources = arg.type === 'argument'
              ? (arg.namedChild(0) ? extractTaintSources(arg.namedChild(0)!, ctx) : [])
              : extractTaintSources(arg, ctx);
            for (const source of taintSources) {
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
            }
          }
        }
      }
      break;
    }

    // -- MEMBER ACCESS EXPRESSION: standalone property access --
    case 'member_access_expression': {
      // Skip if this is part of an invocation_expression's function field
      const parentIsCall = node.parent?.type === 'invocation_expression' &&
        node.parent.childForFieldName('function')?.startIndex === node.startIndex;
      if (!parentIsCall) {
        const lineNum = node.startPosition.row + 1;
        const codeText = node.text.slice(0, 200);
        const alreadyCreated = ctx.neuralMap.nodes.find(
          (n: any) => n.line_start === lineNum && n.code_snapshot === codeText
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
            language: 'csharp',
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

    // -- ATTRIBUTES --
    case 'attribute': {
      const attrName = getAttributeName(node);
      // Create META nodes for significant attributes
      if (ASPNET_ROUTE_ANNOTATIONS.has(attrName) ||
          ASPNET_SECURITY_ANNOTATIONS.has(attrName) ||
          VALIDATION_ANNOTATIONS.has(attrName) ||
          ASPNET_TAINT_ANNOTATIONS.has(attrName) ||
          attrName === 'Obsolete' ||
          attrName === 'Serializable') {
        const annotNode = createNode({
          label: `[${attrName}]`,
          node_type: 'META',
          node_subtype: ASPNET_ROUTE_ANNOTATIONS.has(attrName) ? 'route_annotation' :
                        ASPNET_SECURITY_ANNOTATIONS.has(attrName) ? 'security_annotation' :
                        VALIDATION_ANNOTATIONS.has(attrName) ? 'validation_annotation' :
                        'annotation',
          language: 'csharp',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        if (VALIDATION_ANNOTATIONS.has(attrName)) {
          annotNode.tags.push('validation');
        }
        if (ASPNET_SECURITY_ANNOTATIONS.has(attrName)) {
          annotNode.tags.push('auth_gate');
        }
        ctx.neuralMap.nodes.push(annotNode);
        ctx.lastCreatedNodeId = annotNode.id;
        ctx.emitContainsIfNeeded(annotNode.id);
      }
      break;
    }

    // -- CONTROL FLOW --
    case 'if_statement': {
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      break;
    }
    case 'for_statement': {
      const forN = createNode({ label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      break;
    }
    case 'foreach_statement': {
      const eforN = createNode({ label: 'foreach', node_type: 'CONTROL', node_subtype: 'loop', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(eforN); ctx.lastCreatedNodeId = eforN.id; ctx.emitContainsIfNeeded(eforN.id);
      break;
    }
    case 'while_statement': {
      const whileN = createNode({ label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whileN); ctx.lastCreatedNodeId = whileN.id; ctx.emitContainsIfNeeded(whileN.id);
      break;
    }
    case 'do_statement': {
      const doN = createNode({ label: 'do-while', node_type: 'CONTROL', node_subtype: 'loop', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(doN); ctx.lastCreatedNodeId = doN.id; ctx.emitContainsIfNeeded(doN.id);
      break;
    }
    case 'switch_statement': {
      const switchN = createNode({ label: 'switch', node_type: 'CONTROL', node_subtype: 'branch', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(switchN); ctx.lastCreatedNodeId = switchN.id; ctx.emitContainsIfNeeded(switchN.id);
      break;
    }
    case 'return_statement': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }
    case 'break_statement': {
      const breakN = createNode({ label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(breakN); ctx.lastCreatedNodeId = breakN.id; ctx.emitContainsIfNeeded(breakN.id);
      break;
    }
    case 'continue_statement': {
      const contN = createNode({ label: 'continue', node_type: 'CONTROL', node_subtype: 'continue', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(contN); ctx.lastCreatedNodeId = contN.id; ctx.emitContainsIfNeeded(contN.id);
      break;
    }
    case 'throw_statement':
    case 'throw_expression': {
      const throwN = createNode({ label: 'throw', node_type: 'CONTROL', node_subtype: 'throw', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      throwN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(throwN); ctx.lastCreatedNodeId = throwN.id; ctx.emitContainsIfNeeded(throwN.id);
      break;
    }
    case 'yield_statement': {
      const yieldN = createNode({ label: 'yield', node_type: 'CONTROL', node_subtype: 'yield', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(yieldN); ctx.lastCreatedNodeId = yieldN.id; ctx.emitContainsIfNeeded(yieldN.id);
      break;
    }

    // -- C#-SPECIFIC: using statement, lock, try --
    case 'using_statement': {
      const usingN = createNode({ label: 'using', node_type: 'CONTROL', node_subtype: 'resource_management', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      usingN.tags.push('resource_management', 'disposable');
      ctx.neuralMap.nodes.push(usingN); ctx.lastCreatedNodeId = usingN.id; ctx.emitContainsIfNeeded(usingN.id);
      break;
    }
    case 'lock_statement': {
      const lockN = createNode({ label: 'lock', node_type: 'CONTROL', node_subtype: 'synchronized', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      lockN.tags.push('concurrency', 'lock');
      ctx.neuralMap.nodes.push(lockN); ctx.lastCreatedNodeId = lockN.id; ctx.emitContainsIfNeeded(lockN.id);
      break;
    }
    case 'try_statement': {
      const tryN = createNode({
        label: 'try',
        node_type: 'CONTROL',
        node_subtype: 'error_handling',
        language: 'csharp',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      tryN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(tryN); ctx.lastCreatedNodeId = tryN.id; ctx.emitContainsIfNeeded(tryN.id);
      break;
    }
    case 'catch_clause': {
      const catchN = createNode({ label: 'catch', node_type: 'CONTROL', node_subtype: 'error_handling', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      catchN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(catchN); ctx.lastCreatedNodeId = catchN.id; ctx.emitContainsIfNeeded(catchN.id);
      break;
    }
    case 'finally_clause': {
      const finallyN = createNode({ label: 'finally', node_type: 'CONTROL', node_subtype: 'error_handling', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      finallyN.tags.push('cleanup', 'error_handling');
      ctx.neuralMap.nodes.push(finallyN); ctx.lastCreatedNodeId = finallyN.id; ctx.emitContainsIfNeeded(finallyN.id);
      break;
    }

    // -- ASSIGNMENT (non-declaration) --
    case 'assignment_expression': {
      const assignLeft = node.childForFieldName('left');
      const leftText = assignLeft?.text?.slice(0, 40) ?? '?';
      const assignN = createNode({ label: `${leftText} =`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'csharp', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
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

    // -- Silent pass-throughs --
    case 'expression_statement':
    case 'empty_statement':
    case 'parenthesized_expression':
    case 'comment':
    case 'argument':
    case 'argument_list':
      break;
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'method_declaration' && node.type !== 'constructor_declaration' && node.type !== 'lambda_expression') {
    return;
  }

  const body = node.childForFieldName('body');
  if (!body) return;

  // Check for return statements with tainted expressions
  const returnStmts = body.descendantsOfType('return_statement');
  for (const stmt of returnStmts) {
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
          return; // one tainted return is enough
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// preVisitIteration — set up foreach loop variable taint
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'foreach_statement') return;

  // C# foreach: foreach (Type item in collection) { ... }
  // fields: left (variable name), right (collection), type, body
  const name = node.childForFieldName('left');
  const value = node.childForFieldName('right');

  if (name && value) {
    const iterTaint = extractTaintSources(value, ctx);
    if (iterTaint.length > 0) {
      ctx.declareVariable(name.text, 'const', null, true, iterTaint[0].nodeId);
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration — re-mark foreach loop variable taint
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'foreach_statement') return;

  const name = node.childForFieldName('left');
  const value = node.childForFieldName('right');

  if (name && value) {
    const iterTaint = extractTaintSources(value, ctx);
    if (iterTaint.length > 0) {
      const v = ctx.resolveVariable(name.text);
      if (v) {
        v.tainted = true;
        v.producingNodeId = iterTaint[0].nodeId;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// The Profile
// ---------------------------------------------------------------------------

export const csharpProfile: LanguageProfile = {
  id: 'csharp',
  extensions: ['.cs'],

  // Layer 1: AST Node Type Recognition
  functionScopeTypes: FUNCTION_SCOPE_TYPES,
  blockScopeTypes: BLOCK_SCOPE_TYPES,
  classScopeTypes: CLASS_SCOPE_TYPES,

  getScopeType(node: SyntaxNode): ScopeType | null {
    if (FUNCTION_SCOPE_TYPES.has(node.type)) return 'function';
    if (BLOCK_SCOPE_TYPES.has(node.type)) return 'block';
    if (CLASS_SCOPE_TYPES.has(node.type)) return 'class';
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
    return _lookupCSharpCallee(chain);
  },

  analyzeStructure(_node: SyntaxNode): StructuralAnalysisResult | null {
    // C# ASP.NET routing is attribute-driven, handled in classifyNode.
    return null;
  },

  // Layer 4: Taint Source Detection
  ingressPattern: /(?:Request\.(?:Form|Query|Body|Headers|Cookies|Path|QueryString|RouteValues|ReadFromJsonAsync|ReadFormAsync)|HttpContext\.(?:Request|Session)|Console\.(?:ReadLine|ReadKey|Read)|Environment\.GetCommandLineArgs|\[FromBody\]|\[FromQuery\]|\[FromRoute\]|\[FromHeader\]|\[FromForm\]|BinaryFormatter\.Deserialize)/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) =>
    nodeType === 'local_declaration_statement' || nodeType === 'field_declaration',
  getDeclarationValueNode: (node) => {
    // C#: local_declaration_statement → variable_declaration → variable_declarator → initializer value
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child?.type === 'variable_declaration') {
        for (let j = 0; j < child.namedChildCount; j++) {
          const declarator = child.namedChild(j);
          if (declarator?.type === 'variable_declarator') {
            return declarator.childForFieldName('initializer') ?? declarator.childForFieldName('value');
          }
        }
      }
    }
    return null;
  },
  isStatementContainer: (nodeType: string) =>
    nodeType === 'compilation_unit' || nodeType === 'block' || nodeType === 'declaration_list',

  // Inter-procedural taint: C# method syntax
  // Matches: public async Task<IActionResult> Method(params) { | void Method(params) {
  functionParamPattern: /(?:public|private|protected|internal|static|virtual|override|async|abstract|\s)+[\w<>,\s]+\s+\w+\s*\(([^)]*)\)/,
};

export default csharpProfile;
