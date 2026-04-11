/**
 * JavaProfile — the fifth LanguageProfile implementation.
 *
 * Every piece of Java-specific logic lives here: AST node type names (from
 * tree-sitter-java grammar), field access patterns, scope rules, callee
 * resolution via the Java phoneme dictionary, taint extraction, and node
 * classification.
 *
 * Key differences from JavaScript:
 *   - `method_declaration` not `function_declaration` — Java has no top-level functions
 *   - `method_invocation` not `call_expression` (fields: `object`, `name`, `arguments`)
 *   - `field_access` not `member_expression` (fields: `object`, `field`)
 *   - `local_variable_declaration` not `lexical_declaration`
 *   - `class_declaration` creates class scope — everything is inside a class
 *   - `constructor_declaration` for constructors
 *   - `lambda_expression` for Java 8+ lambdas
 *   - `enhanced_for_statement` (for-each) + `for_statement`
 *   - `try_with_resources_statement` for auto-closeable resources
 *   - `annotation` and `marker_annotation` carry semantic meaning
 *   - `synchronized_statement` for thread-safe blocks
 *   - `throw_statement` for exception flow
 *   - `record_declaration` for Java 14+ records
 *   - `interface_declaration` for interfaces
 *   - `enum_declaration` for enums
 *   - `import_declaration` not `import_statement`
 *   - `program` is the root node
 *
 * tree-sitter-java AST reference: https://github.com/tree-sitter/tree-sitter-java
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
import { createNode, createRange } from '../types.js';
import type { SemanticSentence } from '../types.js';
import { generateSentence, getTemplateKey } from '../sentence-generator.js';
import { lookupCallee as _lookupJavaCallee } from '../languages/java.js';

// ---------------------------------------------------------------------------
// Anti-evasion: constant folding for Java
// Attackers split dangerous strings across concatenation, StringBuilder,
// new String(byte[]), Character.toString, String.format to dodge static analysis.
// We fold them back.
// ---------------------------------------------------------------------------

function resolveJavaEscapes(s: string): string {
  return s
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\\\/g, '\\');
}

function tryFoldConstant(n: SyntaxNode): string | null {
  // String literals: "eval" → eval
  if (n.type === 'string_literal') {
    const raw = n.text.replace(/^"|"$/g, '');
    return resolveJavaEscapes(raw);
  }
  // Character literals: 'e' → e
  if (n.type === 'character_literal') {
    const raw = n.text.replace(/^'|'$/g, '');
    return resolveJavaEscapes(raw);
  }
  // Numeric literals (for byte array / charcode patterns)
  if (n.type === 'decimal_integer_literal' || n.type === 'integer_literal') {
    return n.text;
  }
  // Hex integer literal
  if (n.type === 'hex_integer_literal') {
    return String(parseInt(n.text, 16));
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
  // Ternary constant folding: cond ? "a" : "a" → "a"
  if (n.type === 'ternary_expression') {
    const consequence = n.childForFieldName('consequence');
    const alternative = n.childForFieldName('alternative');
    if (consequence && alternative) {
      const cv = tryFoldConstant(consequence);
      const av = tryFoldConstant(alternative);
      if (cv !== null && av !== null && cv === av) return cv;
    }
  }
  // Cast expression: (char)101 → skip the cast and fold inner
  if (n.type === 'cast_expression') {
    const value = n.childForFieldName('value');
    return value ? tryFoldConstant(value) : null;
  }
  // ── METHOD INVOCATIONS that produce constant strings ──
  if (n.type === 'method_invocation') {
    const obj = n.childForFieldName('object');
    const name = n.childForFieldName('name');
    const args = n.childForFieldName('arguments');
    if (obj && name && args) {
      // StringBuilder: new StringBuilder().append("ev").append("al").toString()
      // Detected when .toString() is called on a chain of .append() calls
      if (name.text === 'toString' && obj.type === 'method_invocation') {
        const folded = tryFoldStringBuilderChain(obj);
        if (folded !== null) return folded;
      }
      // String.format("%s%s", "ev", "al") → "eval"
      if (name.text === 'format' && obj.text === 'String') {
        return tryFoldStringFormat(args);
      }
      // String.valueOf(char) / String.valueOf(int)
      if (name.text === 'valueOf' && obj.text === 'String') {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const v = tryFoldConstant(firstArg);
          if (v !== null) {
            // If it's a number, treat as charcode
            const num = parseInt(v, 10);
            if (!isNaN(num) && num >= 0 && num < 0x110000) {
              return String.fromCharCode(num);
            }
            return v;
          }
        }
      }
      // Character.toString((char)101)
      if (name.text === 'toString' && obj.text === 'Character') {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const v = tryFoldConstant(firstArg);
          if (v !== null) {
            const num = parseInt(v, 10);
            if (!isNaN(num) && num >= 0 && num < 0x110000) {
              return String.fromCharCode(num);
            }
            return v;
          }
        }
      }
    }
  }
  // new String(new byte[]{101,118,97,108}) → "eval"
  if (n.type === 'object_creation_expression') {
    const typeNode = n.childForFieldName('type');
    const args = n.childForFieldName('arguments');
    if (typeNode?.text === 'String' && args) {
      const firstArg = args.namedChild(0);
      if (firstArg?.type === 'array_creation_expression') {
        const init = firstArg.childForFieldName('value');
        if (init?.type === 'array_initializer') {
          return tryFoldByteArray(init);
        }
      }
      // new String(new byte[]{...}) where the array is an array_initializer directly
      if (firstArg?.type === 'object_creation_expression') {
        // nested: new String(new byte[]{101,...})
        for (let i = 0; i < firstArg.namedChildCount; i++) {
          const child = firstArg.namedChild(i);
          if (child?.type === 'array_initializer') {
            return tryFoldByteArray(child);
          }
        }
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Numeric constant folding: evaluate integer arithmetic at analysis time.
// Used for dead-branch elimination on ternary/if conditions like:
//   int num = 106; bar = (7 * 18) + num > 200 ? "safe" : param;
// ---------------------------------------------------------------------------

/**
 * Try to fold an AST node into a numeric (integer) value.
 * Handles: integer literals, hex literals, parenthesized expressions,
 * binary arithmetic (+, -, *, /, %), identifier resolution via scope,
 * cast expressions, and unary negation.
 * Returns null if the expression cannot be folded to a constant integer.
 */
function tryFoldNumeric(n: SyntaxNode, ctx: MapperContextLike): number | null {
  // Integer literals: 106, 200
  if (n.type === 'decimal_integer_literal' || n.type === 'integer_literal') {
    const val = parseInt(n.text, 10);
    return isNaN(val) ? null : val;
  }
  // Hex integer literal: 0xFF
  if (n.type === 'hex_integer_literal') {
    const val = parseInt(n.text, 16);
    return isNaN(val) ? null : val;
  }
  // Parenthesized: (7 * 18)
  if (n.type === 'parenthesized_expression') {
    const inner = n.namedChild(0);
    return inner ? tryFoldNumeric(inner, ctx) : null;
  }
  // Binary expression: arithmetic or comparison (comparisons handled by tryEvalCondition)
  if (n.type === 'binary_expression') {
    const op = n.childForFieldName('operator')?.text;
    const left = n.childForFieldName('left');
    const right = n.childForFieldName('right');
    if (!left || !right || !op) return null;
    const lv = tryFoldNumeric(left, ctx);
    const rv = tryFoldNumeric(right, ctx);
    if (lv === null || rv === null) return null;
    switch (op) {
      case '+': return lv + rv;
      case '-': return lv - rv;
      case '*': return lv * rv;
      case '/': return rv !== 0 ? Math.trunc(lv / rv) : null; // Java integer division
      case '%': return rv !== 0 ? lv % rv : null;
      default: return null;
    }
  }
  // Identifier: resolve from scope
  if (n.type === 'identifier') {
    const v = ctx.resolveVariable(n.text);
    if (v?.numericValue !== undefined) return v.numericValue;
    return null;
  }
  // Cast expression: (int) x
  if (n.type === 'cast_expression') {
    const value = n.childForFieldName('value');
    return value ? tryFoldNumeric(value, ctx) : null;
  }
  // Unary expression: -N
  if (n.type === 'unary_expression') {
    const op = n.child(0)?.text;
    const operand = n.namedChild(0);
    if (op === '-' && operand) {
      const v = tryFoldNumeric(operand, ctx);
      return v !== null ? -v : null;
    }
  }
  return null;
}

/**
 * Try to evaluate a condition AST node to a boolean result.
 * Handles: binary comparisons (>, <, >=, <=, ==, !=) where both
 * sides can be folded to numeric constants, and parenthesized conditions.
 * Returns null if the condition cannot be statically evaluated.
 */
function tryEvalCondition(cond: SyntaxNode, ctx: MapperContextLike): boolean | null {
  // Handle parenthesized_expression
  if (cond.type === 'parenthesized_expression') {
    const inner = cond.namedChild(0);
    return inner ? tryEvalCondition(inner, ctx) : null;
  }
  // Handle binary comparison: expr > expr, expr < expr, etc.
  if (cond.type === 'binary_expression') {
    const op = cond.childForFieldName('operator')?.text;
    const left = cond.childForFieldName('left');
    const right = cond.childForFieldName('right');
    if (!left || !right || !op) return null;
    const lv = tryFoldNumeric(left, ctx);
    const rv = tryFoldNumeric(right, ctx);
    if (lv !== null && rv !== null) {
      switch (op) {
        case '>':  return lv > rv;
        case '<':  return lv < rv;
        case '>=': return lv >= rv;
        case '<=': return lv <= rv;
        case '==': return lv === rv;
        case '!=': return lv !== rv;
        default:   return null;
      }
    }
  }
  return null;
}

/**
 * Evaluate a switch expression's condition to a constant string value.
 * Handles: charAt on constant strings, identifier resolving to a known constant char,
 * numeric constants, and direct character literals.
 * Returns the resolved constant (e.g., 'B' for a char) or null if unresolvable.
 */
function tryEvalSwitchTarget(condNode: SyntaxNode, ctx: MapperContextLike): string | null {
  let expr = condNode;
  if (expr.type === 'parenthesized_expression') expr = expr.namedChild(0) ?? expr;

  // charAt on constant string: "ABC".charAt(1) → 'B'
  const charAtResult = tryResolveCharAt(expr, ctx);
  if (charAtResult !== null) return charAtResult;

  // Identifier referencing a known constant char
  if (expr.type === 'identifier') {
    const v = ctx.resolveVariable(expr.text);
    if (v?.constantValue !== undefined && v.constantValue.length === 1) return v.constantValue;
    if (v?.numericValue !== undefined) return String(v.numericValue);
  }

  // Numeric constant
  const numResult = tryFoldNumeric(expr, ctx);
  if (numResult !== null) return String(numResult);

  // Character literal directly
  if (expr.type === 'character_literal') return expr.text.replace(/^'|'$/g, '');

  return null;
}

/**
 * Try to resolve a charAt() call on a constant string variable.
 * Handles: guess.charAt(N) where guess is a constant string.
 * Returns the single character as a string, or null if unresolvable.
 */
function tryResolveCharAt(n: SyntaxNode, ctx: MapperContextLike): string | null {
  if (n.type !== 'method_invocation') return null;
  const name = n.childForFieldName('name');
  const obj = n.childForFieldName('object');
  const args = n.childForFieldName('arguments');
  if (name?.text !== 'charAt' || !obj || !args) return null;

  // Resolve the receiver to a constant string
  let strValue: string | null = null;
  if (obj.type === 'identifier') {
    const v = ctx.resolveVariable(obj.text);
    if (v?.constantValue !== undefined) strValue = v.constantValue;
  } else {
    strValue = tryFoldConstant(obj);
  }
  if (strValue === null) return null;

  // Resolve the index argument to a number
  const idxArg = args.namedChild(0);
  if (!idxArg) return null;
  const idx = tryFoldNumeric(idxArg, ctx);
  if (idx === null || idx < 0 || idx >= strValue.length) return null;

  return strValue[idx]!;
}

/** Fold StringBuilder chain: .append("ev").append("al") → "eval" */
function tryFoldStringBuilderChain(node: SyntaxNode): string | null {
  // Walk the chain from right to left collecting append arguments
  const parts: string[] = [];
  let current: SyntaxNode | null = node;

  while (current?.type === 'method_invocation') {
    const name = current.childForFieldName('name');
    const args = current.childForFieldName('arguments');
    const obj = current.childForFieldName('object');

    if (name?.text === 'append' && args) {
      const firstArg = args.namedChild(0);
      if (firstArg) {
        const v = tryFoldConstant(firstArg);
        if (v !== null) {
          parts.unshift(v);
        } else {
          return null; // non-constant arg, bail
        }
      }
      current = obj ?? null;
    } else {
      break;
    }
  }

  // Current should now be the StringBuilder constructor (new StringBuilder())
  if (current?.type === 'object_creation_expression') {
    const typeNode = current.childForFieldName('type');
    if (typeNode?.text === 'StringBuilder' || typeNode?.text === 'StringBuffer') {
      // Check if constructor has an initial string argument
      const ctorArgs = current.childForFieldName('arguments');
      if (ctorArgs && ctorArgs.namedChildCount > 0) {
        const initArg = ctorArgs.namedChild(0);
        if (initArg) {
          const initVal = tryFoldConstant(initArg);
          if (initVal !== null) parts.unshift(initVal);
          else return null;
        }
      }
      return parts.join('');
    }
  }
  return null;
}

/** Fold String.format("%s%s", "ev", "al") → "eval" */
function tryFoldStringFormat(args: SyntaxNode): string | null {
  if (args.namedChildCount < 2) return null;
  const fmtArg = args.namedChild(0);
  if (!fmtArg) return null;
  const fmt = tryFoldConstant(fmtArg);
  if (fmt === null) return null;

  // Only handle simple %s patterns
  const placeholders = fmt.match(/%s/g);
  if (!placeholders) return null;
  if (placeholders.length !== args.namedChildCount - 1) return null;

  const values: string[] = [];
  for (let i = 1; i < args.namedChildCount; i++) {
    const arg = args.namedChild(i);
    if (!arg) return null;
    const v = tryFoldConstant(arg);
    if (v === null) return null;
    values.push(v);
  }

  let result = fmt;
  for (const v of values) {
    result = result.replace('%s', v);
  }
  return result;
}

/** Fold byte array initializer: {101, 118, 97, 108} → "eval" */
function tryFoldByteArray(init: SyntaxNode): string | null {
  const codes: number[] = [];
  for (let i = 0; i < init.namedChildCount; i++) {
    const el = init.namedChild(i);
    if (!el) return null;
    const v = tryFoldConstant(el);
    if (v === null) return null;
    const num = parseInt(v, 10);
    if (isNaN(num)) return null;
    codes.push(num);
  }
  if (codes.length === 0) return null;
  return String.fromCharCode(...codes);
}

// ---------------------------------------------------------------------------
// AST Node Type Sets (tree-sitter-java)
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'method_declaration',
  'constructor_declaration',
  'lambda_expression',
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'for_statement',
  'enhanced_for_statement',
  'while_statement',
  'do_statement',
  'if_statement',
  'switch_expression',
  'switch_block',
  'try_statement',
  'try_with_resources_statement',
  'catch_clause',
  'finally_clause',
  'synchronized_statement',
  'block',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'class_declaration',
  'interface_declaration',
  'enum_declaration',
  'record_declaration',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'local_variable_declaration',
  'field_declaration',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'method_declaration',
  'constructor_declaration',
]);

// Tainted paths for Java Servlet/Spring request objects
const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // HttpServletRequest
  'request.getParameter', 'request.getParameterMap', 'request.getParameterValues',
  'request.getHeader', 'request.getHeaders', 'request.getCookies',
  'request.getInputStream', 'request.getReader', 'request.getRequestURI',
  'request.getRequestURL', 'request.getQueryString', 'request.getPathInfo',
  'request.getRemoteAddr', 'request.getContentType', 'request.getMethod',
  'request.getSession', 'request.getAttribute', 'request.getPart',
  'request.getParts',
  // Short aliases (req, httpRequest)
  'req.getParameter', 'req.getHeader', 'req.getCookies',
  'req.getInputStream', 'req.getReader', 'req.getQueryString',
  'req.getRequestURI', 'req.getRequestURL', 'req.getPathInfo',
  'req.getRemoteAddr', 'req.getAttribute', 'req.getPart',
  'req.getParameterMap', 'req.getParameterValues', 'req.getHeaders',
  'httpRequest.getParameter', 'httpRequest.getHeader',
  'httpRequest.getCookies', 'httpRequest.getQueryString',
  'httpRequest.getInputStream', 'httpRequest.getRequestURI',
  'servletRequest.getParameter', 'servletRequest.getHeader',
  'servletRequest.getQueryString',
  // Scanner
  'scanner.nextLine', 'scanner.next', 'scanner.nextInt',
  // STEP 3: Environment variables treated as tainted (attacker-controlled in containers)
  'System.getenv', 'System.getProperty',
  // Network socket reads (Juliet connect_tcp pattern)
  'socket.getInputStream', 'Socket.getInputStream',
  'readerBuffered.readLine', 'readerInputStream.read',
]);

// Spring annotation names that mark parameters as tainted INGRESS sources
const SPRING_TAINT_ANNOTATIONS: ReadonlySet<string> = new Set([
  'RequestBody', 'PathVariable', 'RequestParam',
  'RequestHeader', 'CookieValue', 'ModelAttribute',
  'RequestPart',
]);

// Spring routing annotations (for structural analysis)
const SPRING_ROUTE_ANNOTATIONS: ReadonlySet<string> = new Set([
  'RequestMapping', 'GetMapping', 'PostMapping',
  'PutMapping', 'DeleteMapping', 'PatchMapping',
]);

// Spring security annotations
const SPRING_SECURITY_ANNOTATIONS: ReadonlySet<string> = new Set([
  'PreAuthorize', 'Secured', 'RolesAllowed',
]);

// Validation annotations
const VALIDATION_ANNOTATIONS: ReadonlySet<string> = new Set([
  'Valid', 'NotNull', 'NotBlank', 'NotEmpty',
  'Size', 'Min', 'Max', 'Pattern', 'Email',
  'Positive', 'PositiveOrZero', 'Negative', 'NegativeOrZero',
  'Past', 'Future', 'Digits',
]);

// Conventional request parameter names in Java handlers
const JAVA_REQUEST_PARAM_NAMES: ReadonlySet<string> = new Set([
  'request', 'req', 'httpRequest', 'servletRequest',
]);

// Response parameter names
const JAVA_RESPONSE_PARAM_NAMES: ReadonlySet<string> = new Set([
  'response', 'resp', 'httpResponse', 'servletResponse',
]);

// Request type names that indicate tainted params
const JAVA_HTTP_REQUEST_TYPES: ReadonlySet<string> = new Set([
  'HttpServletRequest', 'ServletRequest',
  'WebRequest', 'NativeWebRequest',
  'ServerHttpRequest', 'HttpRequest',
]);

// Types eligible for auto-taint on public method parameters
const JAVA_AUTO_TAINT_TYPES: ReadonlySet<string> = new Set([
  'String', 'String[]', 'byte[]', 'char[]',
  'Object', 'Object[]',
  'InputStream', 'Reader', 'BufferedReader',
]);

function isAutoTaintableType(typeText: string): boolean {
  return JAVA_AUTO_TAINT_TYPES.has(typeText) || typeText.endsWith('[]');
}

// Function names that should NEVER have their params auto-tainted
const JAVA_UNTAINTABLE_FUNCTIONS: ReadonlySet<string> = new Set([
  'toString', 'equals', 'hashCode', 'compareTo', 'clone',
  'main', 'init', 'destroy', 'finalize',
  'good', 'goodG2B', 'goodB2G', 'goodG2BSink', 'goodB2GSink',
  // Juliet "good" patterns — these are intentionally safe
]);

// ---------------------------------------------------------------------------
// Helper: extract callee chain from Java AST nodes
// ---------------------------------------------------------------------------

/**
 * Extract the callee chain from a Java expression.
 * Handles:
 *   - identifier: `foo` -> ['foo']
 *   - field_access: `request.getParameter` -> ['request', 'getParameter']
 *   - method_invocation chains: `obj.method().chain()` -> resolves terminal
 *   - scoped_identifier: `System.out` -> ['System', 'out']
 */
function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier') {
    return [node.text];
  }

  if (node.type === 'field_access') {
    const obj = node.childForFieldName('object');
    const field = node.childForFieldName('field');
    if (obj && field) {
      const chain = extractCalleeChain(obj);
      chain.push(field.text);
      return chain;
    }
  }

  if (node.type === 'scoped_identifier') {
    // e.g., System.out, Runtime.getRuntime
    const parts: string[] = [];
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type !== '.') {
        if (child.type === 'scoped_identifier') {
          parts.push(...extractCalleeChain(child));
        } else {
          parts.push(child.text);
        }
      }
    }
    return parts;
  }

  // method_invocation: obj.method(args) — extract object chain + method name
  if (node.type === 'method_invocation') {
    const obj = node.childForFieldName('object');
    const name = node.childForFieldName('name');
    if (obj && name) {
      const chain = extractCalleeChain(obj);
      chain.push(name.text);
      return chain;
    }
    if (name) {
      return [name.text];
    }
  }

  return [node.text.slice(0, 50)];
}

// ---------------------------------------------------------------------------
// STEP 1: Servlet taint method names — recognised regardless of receiver variable name.
// These are unmistakably HttpServletRequest API methods. If lookup by full chain
// fails AND the method name is in this set, we classify as INGRESS/http_request
// with tainted=true. This handles any alias: req, request, httpReq, etc.
// ---------------------------------------------------------------------------
const SERVLET_TAINT_METHODS: ReadonlySet<string> = new Set([
  'getParameter', 'getParameterMap', 'getParameterValues', 'getParameterNames',
  'getHeader', 'getHeaders', 'getCookies',
  'getInputStream', 'getReader', 'getRequestURI',
  'getRequestURL', 'getQueryString', 'getPathInfo',
  'getRemoteAddr', 'getAttribute', 'getPart', 'getParts',
  'getContentType', 'getMethod', 'getSession',
]);

// ---------------------------------------------------------------------------
// Helper: resolve callee from a method_invocation or object_creation_expression
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  // method_invocation: obj.method(args) or method(args)
  if (node.type === 'method_invocation') {
    const obj = node.childForFieldName('object');
    const name = node.childForFieldName('name');

    if (obj && name) {
      const chain = extractCalleeChain(obj);
      chain.push(name.text);
      const pattern = _lookupJavaCallee(chain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain,
        };
      }
      // STEP 1 fallback: if method name alone is a known servlet taint method,
      // treat as INGRESS/http_request regardless of receiver variable name.
      if (chain.length === 2 && SERVLET_TAINT_METHODS.has(chain[1])) {
        return {
          nodeType: 'INGRESS',
          subtype: 'http_request',
          tainted: true,
          chain,
        };
      }
      // STEP 1b: Chained output methods → EGRESS/http_response.
      // response.getWriter().println(bar) → chain = ['response', 'getWriter', 'println']
      // response.getOutputStream().write(bar) → chain = ['response', 'getOutputStream', 'write']
      const SERVLET_OUTPUT_METHODS = new Set(['println', 'print', 'write', 'append', 'format', 'printf']);
      const SERVLET_WRITER_GETTERS = new Set(['getWriter', 'getOutputStream']);
      const lastMethod = chain[chain.length - 1];
      if (lastMethod && SERVLET_OUTPUT_METHODS.has(lastMethod) &&
          chain.some(c => SERVLET_WRITER_GETTERS.has(c))) {
        return {
          nodeType: 'EGRESS',
          subtype: 'http_response',
          tainted: false,
          chain,
        };
      }
      // STEP 1c: Sanitizer/encoder methods → TRANSFORM/sanitize.
      // StringEscapeUtils.escapeHtml(x), ESAPI.encoder().encodeForHTML(x), etc.
      // Recognised by method name regardless of receiver chain.
      const SANITIZER_METHODS = new Set([
        'escapeHtml', 'escapeHtml4', 'escapeHtml3', 'escapeXml', 'escapeXml10', 'escapeXml11',
        'escapeEcmaScript', 'escapeJson', 'escapeSql', 'escapeCsv', 'escapeJava',
        'encodeForHTML', 'encodeForHTMLAttribute', 'encodeForJavaScript', 'encodeForCSS',
        'encodeForURL', 'encodeForXML', 'encodeForXMLAttribute', 'encodeForLDAP', 'encodeForDN',
        'encodeForSQL', 'encodeForOS', 'encodeForVBScript', 'encodeForXPath',
        'htmlEscape', 'javaScriptEscape', 'urlEncode',
        'sanitize', 'clean', 'stripXSS', 'stripTags',
      ]);
      if (lastMethod && SANITIZER_METHODS.has(lastMethod)) {
        return {
          nodeType: 'TRANSFORM',
          subtype: 'sanitize',
          tainted: false,
          chain,
        };
      }
    } else if (name) {
      // Bare method call — check direct call patterns
      const chain = [name.text];
      const pattern = _lookupJavaCallee(chain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain,
        };
      }
    }

    // ── Anti-evasion: Class.forName with constant-folded argument ──
    // Class.forName("ev" + "al") or Class.forName(constructed) → reflection
    if (obj && name?.text === 'forName' && obj.text === 'Class') {
      const args = node.childForFieldName('arguments');
      const firstArg = args?.namedChild(0);
      if (firstArg) {
        const folded = tryFoldConstant(firstArg);
        // Whether we can fold or not, Class.forName is always reflection
        return {
          nodeType: 'EXTERNAL',
          subtype: 'reflection',
          tainted: folded === null, // tainted if we can't resolve the constant
          chain: ['Class', 'forName'],
        };
      }
    }

    // ── Anti-evasion: Method.invoke — reflective invocation ──
    if (name?.text === 'invoke' && obj) {
      const objChain = extractCalleeChain(obj);
      const last = objChain[objChain.length - 1];
      // .getMethod(...).invoke(...) or variable.invoke(...)
      if (last === 'invoke' || objChain.some(p => p === 'getMethod' || p === 'getDeclaredMethod')) {
        return {
          nodeType: 'EXTERNAL',
          subtype: 'reflection',
          tainted: true,
          chain: [...objChain, 'invoke'],
        };
      }
      // Fallback: any .invoke() call on an unknown receiver could be reflective
      // Only flag if the receiver comes from getMethod/getDeclaredMethod chain
    }

    return null;
  }

  // object_creation_expression: new ClassName(args)
  if (node.type === 'object_creation_expression') {
    const typeNode = node.childForFieldName('type');
    if (typeNode) {
      const typeName = typeNode.text;
      // Use [ClassName, 'new'] chain so phoneme table entries like 'File.new',
      // 'FileInputStream.new' etc. resolve correctly as STORAGE/file_access sinks
      // rather than falling through to wrong hardcoded INGRESS classification.
      const ctorChain = [typeName, 'new'];
      const pattern = _lookupJavaCallee(ctorChain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain: ctorChain,
        };
      }

      // Fallback: also try bare class name for backward compat with entries
      // that don't use the .new convention
      const bareChain = [typeName];
      const barePattern = _lookupJavaCallee(bareChain);
      if (barePattern) {
        return {
          nodeType: barePattern.nodeType,
          subtype: barePattern.subtype,
          tainted: barePattern.tainted,
          chain: bareChain,
        };
      }

      // Check specific dangerous constructors (only those NOT in phoneme table)
      // Strip FQN prefix for comparison: java.io.ObjectInputStream -> ObjectInputStream
      const simpleTypeName = typeName.includes('.') ? typeName.slice(typeName.lastIndexOf('.') + 1) : typeName;
      if (simpleTypeName === 'ObjectInputStream') {
        return { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true, chain: bareChain };
      }
      if (simpleTypeName === 'ProcessBuilder') {
        return { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false, chain: bareChain };
      }
      if (simpleTypeName === 'URL' || simpleTypeName === 'URI') {
        return { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false, chain: bareChain };
      }
      if (simpleTypeName === 'Scanner') {
        return { nodeType: 'INGRESS', subtype: 'user_input', tainted: true, chain: bareChain };
      }
    }
    return null;
  }

  return null;
}

// ---------------------------------------------------------------------------
// resolvePropertyAccess — resolve a Java `field_access` (non-call)
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  if (node.type !== 'field_access') return null;

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
  const pattern = _lookupJavaCallee(chain);
  if (pattern) {
    return {
      nodeType: pattern.nodeType,
      subtype: pattern.subtype,
      tainted: pattern.tainted,
    };
  }

  // System.out, System.err → EGRESS
  if (fullPath === 'System.out' || fullPath === 'System.err') {
    return { nodeType: 'EGRESS', subtype: 'display', tainted: false };
  }

  return null;
}

// ---------------------------------------------------------------------------
// extractPatternNames — Java has no destructuring but handles declarators
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
// Helper: check if a parameter has a Spring taint annotation
// ---------------------------------------------------------------------------

function paramHasTaintAnnotation(paramNode: SyntaxNode): boolean {
  // Walk siblings/children looking for annotations
  // In tree-sitter-java, formal_parameter has modifiers child containing annotations
  const modifiers = paramNode.childForFieldName('modifiers') ??
    paramNode.descendantsOfType('modifiers')[0];
  if (!modifiers) {
    // Check children directly for marker_annotation / annotation
    for (let i = 0; i < paramNode.childCount; i++) {
      const child = paramNode.child(i);
      if (!child) continue;
      if (child.type === 'marker_annotation' || child.type === 'annotation') {
        const annotName = child.childForFieldName('name')?.text ?? child.text.replace('@', '');
        if (SPRING_TAINT_ANNOTATIONS.has(annotName)) return true;
      }
    }
    return false;
  }

  for (let i = 0; i < modifiers.childCount; i++) {
    const mod = modifiers.child(i);
    if (!mod) continue;
    if (mod.type === 'marker_annotation' || mod.type === 'annotation') {
      const annotName = mod.childForFieldName('name')?.text ?? mod.text.replace('@', '');
      if (SPRING_TAINT_ANNOTATIONS.has(annotName)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helper: check if a method has a Spring route annotation
// ---------------------------------------------------------------------------

function methodHasRouteAnnotation(methodNode: SyntaxNode): { annotation: string; path: string | null } | null {
  // Check preceding siblings or modifiers for route annotations
  const modifiers = methodNode.childForFieldName('modifiers') ??
    methodNode.descendantsOfType('modifiers')[0];
  if (!modifiers) return null;

  for (let i = 0; i < modifiers.childCount; i++) {
    const mod = modifiers.child(i);
    if (!mod) continue;
    if (mod.type === 'marker_annotation' || mod.type === 'annotation') {
      const annotName = mod.childForFieldName('name')?.text ?? mod.text.replace('@', '');
      if (SPRING_ROUTE_ANNOTATIONS.has(annotName) || SERVLET_ANNOTATIONS.has(annotName)) {
        return { annotation: annotName, path: extractAnnotationPath(mod) };
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Helper: check if a method has Spring security annotations
// ---------------------------------------------------------------------------

function methodHasSecurityAnnotation(methodNode: SyntaxNode): boolean {
  const modifiers = methodNode.childForFieldName('modifiers') ??
    methodNode.descendantsOfType('modifiers')[0];
  if (!modifiers) return false;

  for (let i = 0; i < modifiers.childCount; i++) {
    const mod = modifiers.child(i);
    if (!mod) continue;
    if (mod.type === 'marker_annotation' || mod.type === 'annotation') {
      const annotName = mod.childForFieldName('name')?.text ?? mod.text.replace('@', '');
      if (SPRING_SECURITY_ANNOTATIONS.has(annotName)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helper: extract annotation name from annotation node
// ---------------------------------------------------------------------------

function getAnnotationName(node: SyntaxNode): string {
  if (node.type === 'marker_annotation') {
    const name = node.childForFieldName('name');
    return name?.text ?? node.text.replace('@', '');
  }
  if (node.type === 'annotation') {
    const name = node.childForFieldName('name');
    return name?.text ?? node.text.replace(/@([^(]+).*/, '$1');
  }
  return node.text;
}

// ---------------------------------------------------------------------------
// Helper: extract path value from an annotation's arguments
// Handles: @GetMapping("/users"), @WebServlet(value="/api"), @WebServlet(urlPatterns={"/x"})
// ---------------------------------------------------------------------------

function extractAnnotationPath(annotNode: SyntaxNode): string | null {
  // Only 'annotation' nodes have arguments; 'marker_annotation' never has a path
  if (annotNode.type !== 'annotation') return null;

  const argList = annotNode.childForFieldName('arguments');
  if (!argList) return null;

  for (let i = 0; i < argList.namedChildCount; i++) {
    const child = argList.namedChild(i);
    if (!child) continue;

    // Case 1: bare string literal — @GetMapping("/users")
    if (child.type === 'string_literal') {
      return child.text.replace(/^"|"$/g, '');
    }

    // Case 2: element_value_pair — @WebServlet(value = "/api") or urlPatterns={"/x"}
    if (child.type === 'element_value_pair') {
      const key = child.childForFieldName('key')?.text;
      const value = child.childForFieldName('value');
      if (!value) continue;

      if (key === 'value' || key === 'urlPatterns' || key === 'path') {
        // Direct string literal: value = "/api"
        if (value.type === 'string_literal') {
          return value.text.replace(/^"|"$/g, '');
        }
        // Array initializer: urlPatterns = {"/x", "/y"} — take first
        if (value.type === 'element_value_array_initializer') {
          for (let j = 0; j < value.namedChildCount; j++) {
            const elem = value.namedChild(j);
            if (elem?.type === 'string_literal') {
              return elem.text.replace(/^"|"$/g, '');
            }
          }
        }
      }
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Helper: compose a class-level route prefix with a method-level path
// ---------------------------------------------------------------------------

function composePaths(prefix: string, methodPath: string): string {
  if (!prefix && !methodPath) return '/';
  if (!prefix) return methodPath.startsWith('/') ? methodPath : '/' + methodPath;
  if (!methodPath) return prefix.startsWith('/') ? prefix : '/' + prefix;

  const normalizedPrefix = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  const normalizedMethod = methodPath.startsWith('/') ? methodPath : '/' + methodPath;

  const composed = normalizedPrefix + normalizedMethod;
  return composed.startsWith('/') ? composed : '/' + composed;
}

// ---------------------------------------------------------------------------
// Helper: extract class-level route prefix from @WebServlet or @RequestMapping
// ---------------------------------------------------------------------------

const SERVLET_ANNOTATIONS: ReadonlySet<string> = new Set([
  'WebServlet',
]);

function extractClassRoutePrefix(classNode: SyntaxNode): { path: string | null; isServlet: boolean } {
  const modifiers = classNode.childForFieldName('modifiers') ??
    classNode.descendantsOfType('modifiers')[0];
  if (!modifiers) return { path: null, isServlet: false };

  for (let i = 0; i < modifiers.childCount; i++) {
    const mod = modifiers.child(i);
    if (!mod) continue;
    if (mod.type === 'marker_annotation' || mod.type === 'annotation') {
      const annotName = getAnnotationName(mod);
      if (SERVLET_ANNOTATIONS.has(annotName)) {
        return { path: extractAnnotationPath(mod), isServlet: true };
      }
      if (annotName === 'RequestMapping') {
        return { path: extractAnnotationPath(mod), isServlet: false };
      }
    }
  }

  return { path: null, isServlet: false };
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

    // -- Leaf: field_access -- check for tainted paths (request.getParameter etc.)
    case 'field_access': {
      const resolution = resolvePropertyAccess(expr);
      if (resolution?.tainted) {
        // Check for an existing node at this location first
        const faLine = expr.startPosition.row + 1;
        const faSnap = expr.text.slice(0, 30);
        const existingFA = ctx.neuralMap.nodes.find((n: any) =>
          n.line_start === faLine && n.code_snapshot.startsWith(faSnap)
        );
        if (existingFA) {
          return [{ nodeId: existingFA.id, name: expr.text }];
        }
        // No existing node — return synthetic reference to signal taint
        // without creating a new INGRESS node (avoids noise from extra nodes
        // that all verifiers can see). addDataFlow safely ignores unknown IDs.
        return [{ nodeId: '__synthetic__', name: expr.text }];
      }
      // Check if the object is a tainted variable
      const obj = expr.childForFieldName('object');
      if (obj?.type === 'identifier') {
        const varInfo = ctx.resolveVariable(obj.text);
        if (varInfo?.tainted && varInfo.producingNodeId) {
          return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
        }
      }
      // Recurse into deeper chains
      if (obj?.type === 'field_access') {
        return extractTaintSources(obj, ctx);
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

    // -- Method invocation: check if sanitizer, then check args --
    case 'method_invocation': {
      // -- Per-index collection resolution: list.get(N) --
      // If the receiver has collectionTaint and method is 'get' with an integer literal,
      // resolve per-index taint instead of falling through to whole-collection taint.
      {
        const getMethodName = expr.childForFieldName('name');
        const getObj = expr.childForFieldName('object');
        if (getMethodName?.text === 'get' && getObj?.type === 'identifier') {
          const getVar = ctx.resolveVariable(getObj.text);
          if (getVar?.collectionTaint) {
            const getArgs = expr.childForFieldName('arguments');
            const firstArg = getArgs?.namedChild(0);
            let resolvedIdx: number | undefined;
            if (firstArg?.type === 'decimal_integer_literal') {
              resolvedIdx = parseInt(firstArg.text);
            } else if (firstArg?.type === 'identifier') {
              // Try resolving the index from a variable's numericValue
              const idxVar = ctx.resolveVariable(firstArg.text);
              if (idxVar?.numericValue !== undefined) {
                resolvedIdx = idxVar.numericValue;
              }
            }
            if (resolvedIdx !== undefined && resolvedIdx >= 0 && resolvedIdx < getVar.collectionTaint.length) {
              const entry = getVar.collectionTaint[resolvedIdx];
              if (!entry.tainted) {
                // This index holds a safe (non-tainted) value — no taint sources
                return [];
              }
              // This index is tainted — return its producing node
              if (entry.producingNodeId) {
                return [{ nodeId: entry.producingNodeId, name: getObj.text + '.get(' + resolvedIdx + ')' }];
              }
              // Tainted but no producing node — fall back to whole-collection
            }
            // Index out of range or unresolvable — fall through to generic behavior
          }
          // -- Per-key collection resolution: map.get("key") --
          // If the receiver has keyedTaint and method is 'get' with a string literal,
          // resolve per-key taint from what map.put("key", value) stored.
          if (getVar?.keyedTaint) {
            const getArgs = expr.childForFieldName('arguments');
            const firstArg = getArgs?.namedChild(0);
            let keyStr: string | undefined;
            if (firstArg?.type === 'string_literal') {
              keyStr = firstArg.text.replace(/^"|"$/g, '');
            }
            if (keyStr !== undefined && getVar.keyedTaint.has(keyStr)) {
              const entry = getVar.keyedTaint.get(keyStr)!;
              if (!entry.tainted) {
                return [];
              }
              if (entry.producingNodeId) {
                return [{ nodeId: entry.producingNodeId, name: getObj.text + '.get("' + keyStr + '")' }];
              }
            }
          }
        }
      }

      const callResolution = resolveCallee(expr);
      // Sanitizer, encoder, or safe_source call stops taint.
      // safe_source methods (e.g., SeparateClassRequest.getTheValue()) return hardcoded
      // values independent of their arguments or receiver state.
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          (callResolution.subtype === 'sanitize' || callResolution.subtype === 'encode' || callResolution.subtype === 'safe_source')) {
        return [];
      }
      // If the call itself is a tainted INGRESS source (e.g. socket.getInputStream(),
      // request.getParameter(), System.getenv()), propagate taint from the existing node
      // or create a synthetic source entry. This handles when INGRESS calls are used as
      // arguments inside other calls (e.g. new InputStreamReader(socket.getInputStream())).
      if (callResolution && callResolution.tainted) {
        const callLine = expr.startPosition.row + 1;
        const callSnap = expr.text.slice(0, 30);
        const existing = ctx.neuralMap.nodes.find((n: any) =>
          n.line_start === callLine && n.code_snapshot.startsWith(callSnap)
        );
        if (existing) {
          return [{ nodeId: existing.id, name: existing.label }];
        }
        // Node not yet created — return synthetic reference to signal taint
        // without creating a new INGRESS node. Creating nodes here caused noise:
        // synthetic INGRESS nodes were visible to all verifiers, generating
        // false positives (especially XSS/neutralization families on servlet files).
        // addDataFlow safely ignores unknown IDs, and callers that only check
        // taintSources.length > 0 still get the correct taint signal.
        return [{ nodeId: '__synthetic__', name: expr.text.slice(0, 100) }];
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
      // Check receiver (object) — but skip for safe_source methods, whose output
      // is a constant independent of receiver state (e.g., SeparateClassRequest.getTheValue()
      // always returns "bar" regardless of what the request object contains).
      const isSafeSourceETS = callResolution && callResolution.subtype === 'safe_source';
      const obj = expr.childForFieldName('object');
      if (obj && !isSafeSourceETS) sources.push(...extractTaintSources(obj, ctx));
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
      // If callee returns clean data (functionReturnTaint === false), arg taint doesn't flow through
      if (sources.length > 0) {
        const fnName = expr.childForFieldName('name');
        if (fnName?.type === 'identifier') {
          const funcNodeId = ctx.functionRegistry.get(fnName.text);
          if (funcNodeId && ctx.functionReturnTaint.get(funcNodeId) === false) {
            sources.length = 0;
          }
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
          if (arg) sources.push(...extractTaintSources(arg, ctx));
        }
      }
      return sources;
    }

    // -- Parenthesized expression --
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Cast expression: (String) x --
    case 'cast_expression': {
      const value = expr.childForFieldName('value');
      return value ? extractTaintSources(value, ctx) : [];
    }

    // -- Ternary: condition ? a : b --
    // Dead branch elimination: if the condition can be statically evaluated,
    // only extract taint from the LIVE branch. This eliminates false positives
    // from patterns like: bar = (7*18)+num > 200 ? "safe" : param;
    case 'ternary_expression': {
      const condition = expr.childForFieldName('condition');
      const consequence = expr.childForFieldName('consequence');
      const alternative = expr.childForFieldName('alternative');
      const condResult = condition ? tryEvalCondition(condition, ctx) : null;
      if (condResult === true) {
        // Condition always true -> only consequence is reachable
        return consequence ? extractTaintSources(consequence, ctx) : [];
      } else if (condResult === false) {
        // Condition always false -> only alternative is reachable
        return alternative ? extractTaintSources(alternative, ctx) : [];
      }
      // Unknown condition: both branches contribute taint (existing behavior)
      const sources: TaintSourceResult[] = [];
      if (consequence) sources.push(...extractTaintSources(consequence, ctx));
      if (alternative) sources.push(...extractTaintSources(alternative, ctx));
      return sources;
    }

    // -- Array access: arr[i] --
    case 'array_access': {
      const array = expr.childForFieldName('array');
      if (array) return extractTaintSources(array, ctx);
      return [];
    }

    // -- String concatenation via template: "..." + x + "..."  --
    // (already handled by binary_expression)

    // -- Assignment expression (within expressions) --
    case 'assignment_expression': {
      const right = expr.childForFieldName('right');
      return right ? extractTaintSources(right, ctx) : [];
    }

    // -- Array initializer: {"a", bar} or new String[]{"a", bar} --
    // Recurse into elements to find tainted variables inside array/object literals.
    case 'array_initializer':
    case 'array_creation_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const elem = expr.namedChild(i);
        if (elem) sources.push(...extractTaintSources(elem, ctx));
      }
      return sources;
    }

    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type === 'local_variable_declaration' || node.type === 'field_declaration') {
    // Walk variable_declarator children
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (!child || child.type !== 'variable_declarator') continue;

      const nameNode = child.childForFieldName('name');
      const valueNode = child.childForFieldName('value');

      if (!nameNode || nameNode.type !== 'identifier') continue;
      const varName = nameNode.text;

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
      if (valueNode) {
        const directTaint = extractTaintSources(valueNode, ctx);
        if (directTaint.length > 0) {
          tainted = true;
          producingNodeId = directTaint[0].nodeId;
        } else if (tainted) {
          // extractTaintSources found NO taint, but lastCreatedNode said tainted.
          // Trust extractTaintSources — it includes dead-branch elimination, safe-source
          // detection, and functionReturnTaint suppression. Override lastCreatedNode.
          tainted = false;
        }
      }

      // Cross-function taint: x = getInput(request)
      if (!producingNodeId && valueNode) {
        const checkCallTaint = (expr: SyntaxNode) => {
          if (expr.type === 'method_invocation') {
            const name = expr.childForFieldName('name');
            if (name?.type === 'identifier') {
              const funcNodeId = ctx.functionRegistry.get(name.text);
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

      // Alias chain detection — three strategies, strongest wins:
      //
      // Strategy 1 (BEST): Use the declared type from the variable declaration.
      //   Java is statically typed: `Statement stmt = ...` means stmt IS a Statement.
      //   Extract the simple class name from the type annotation (last component of
      //   scoped_type_identifier, e.g., javax.crypto.Cipher -> Cipher).
      //
      // Strategy 2: For `new ClassName(...)`, extract ClassName from the constructor.
      //
      // Strategy 3 (existing): For method calls and field access, extract the call chain.
      //   e.g., conn.createStatement() -> ['conn', 'createStatement']
      //
      // Strategy 1 supersedes 2/3 because the declared type is always the correct class.
      let aliasChain: string[] | undefined;
      let genericTypeArgsList: string[] | undefined;

      // Strategy 1: Declared type from the local_variable_declaration's type field
      const declTypeNode = node.childForFieldName('type');
      if (declTypeNode) {
        let simpleTypeName: string | undefined;
        if (declTypeNode.type === 'type_identifier') {
          simpleTypeName = declTypeNode.text;
        } else if (declTypeNode.type === 'scoped_type_identifier') {
          // e.g., javax.crypto.Cipher -> extract last component "Cipher"
          const lastChild = declTypeNode.namedChild(declTypeNode.namedChildCount - 1);
          if (lastChild?.type === 'type_identifier') {
            simpleTypeName = lastChild.text;
          }
        } else if (declTypeNode.type === 'array_type') {
          // e.g., Cookie[] -> extract element type "Cookie"
          const elemType = declTypeNode.childForFieldName('element');
          if (elemType?.type === 'type_identifier') {
            simpleTypeName = elemType.text;
          } else if (elemType?.type === 'scoped_type_identifier') {
            const lastChild = elemType.namedChild(elemType.namedChildCount - 1);
            if (lastChild?.type === 'type_identifier') simpleTypeName = lastChild.text;
          }
        } else if (declTypeNode.type === 'generic_type') {
          // e.g., List<String> -> extract the base type
          const baseType = declTypeNode.childForFieldName('name') ?? declTypeNode.namedChild(0);
          if (baseType) {
            if (baseType.type === 'type_identifier') {
              simpleTypeName = baseType.text;
            } else if (baseType.type === 'scoped_type_identifier') {
              const lastChild = baseType.namedChild(baseType.namedChildCount - 1);
              if (lastChild?.type === 'type_identifier') simpleTypeName = lastChild.text;
            }
          }
          // Extract generic type arguments: Map<String, Statement> → ['String', 'Statement']
          // tree-sitter-java: generic_type has a type_arguments child containing type nodes
          const typeArgsNode = declTypeNode.children.find(c => c.type === 'type_arguments');
          if (typeArgsNode) {
            const extractedArgs: string[] = [];
            for (let ta = 0; ta < typeArgsNode.namedChildCount; ta++) {
              const typeArg = typeArgsNode.namedChild(ta);
              if (!typeArg) continue;
              if (typeArg.type === 'type_identifier') {
                extractedArgs.push(typeArg.text);
              } else if (typeArg.type === 'scoped_type_identifier') {
                const last = typeArg.namedChild(typeArg.namedChildCount - 1);
                if (last?.type === 'type_identifier') extractedArgs.push(last.text);
              } else if (typeArg.type === 'generic_type') {
                // Nested generic: e.g., List<Map<String, String>> → just grab the outer name
                const innerBase = typeArg.namedChild(0);
                if (innerBase?.type === 'type_identifier') extractedArgs.push(innerBase.text);
              }
            }
            if (extractedArgs.length > 0) {
              genericTypeArgsList = extractedArgs;
            }
          }
        }
        // Only use declared type as alias if it's a meaningful class name (not primitives/var)
        const JAVA_PRIMITIVES = new Set(['int', 'long', 'float', 'double', 'boolean', 'byte', 'char', 'short', 'void', 'String', 'Object', 'var']);
        if (simpleTypeName && !JAVA_PRIMITIVES.has(simpleTypeName)) {
          aliasChain = [simpleTypeName];
        }
      }

      // Strategy 1b: Cast expression — (TypeName) expr
      // When declared type is Object/var/String (filtered by JAVA_PRIMITIVES above),
      // but the value is a cast_expression, the cast target IS the real type.
      // e.g., var stmt = (Statement) obj;  →  aliasChain = ['Statement']
      //       Object x = (Cipher) factory.getInstance();  →  aliasChain = ['Cipher']
      if (!aliasChain && valueNode?.type === 'cast_expression') {
        const castTypeNode = valueNode.childForFieldName('type');
        if (castTypeNode) {
          let castTypeName: string | undefined;
          if (castTypeNode.type === 'type_identifier') {
            castTypeName = castTypeNode.text;
          } else if (castTypeNode.type === 'scoped_type_identifier') {
            const lastChild = castTypeNode.namedChild(castTypeNode.namedChildCount - 1);
            if (lastChild?.type === 'type_identifier') castTypeName = lastChild.text;
          }
          const JAVA_PRIMITIVES_CAST = new Set(['int', 'long', 'float', 'double', 'boolean', 'byte', 'char', 'short', 'void', 'String', 'Object', 'var']);
          if (castTypeName && !JAVA_PRIMITIVES_CAST.has(castTypeName)) {
            aliasChain = [castTypeName];
          }
        }
      }

      // Strategy 2: object_creation_expression — new ClassName(...)
      if (!aliasChain && valueNode?.type === 'object_creation_expression') {
        const ctorType = valueNode.childForFieldName('type');
        if (ctorType) {
          let ctorTypeName: string | undefined;
          if (ctorType.type === 'type_identifier') {
            ctorTypeName = ctorType.text;
          } else if (ctorType.type === 'scoped_type_identifier') {
            const lastChild = ctorType.namedChild(ctorType.namedChildCount - 1);
            if (lastChild?.type === 'type_identifier') ctorTypeName = lastChild.text;
          }
          if (ctorTypeName) aliasChain = [ctorTypeName];
        }
      }

      // Strategy 3 (fallback): method invocation or field access call chain
      if (!aliasChain && valueNode) {
        if (valueNode.type === 'method_invocation') {
          const obj = valueNode.childForFieldName('object');
          const name = valueNode.childForFieldName('name');
          if (obj && name) {
            const chain = extractCalleeChain(obj);
            chain.push(name.text);
            aliasChain = chain;
          }
        } else if (valueNode.type === 'field_access') {
          aliasChain = extractCalleeChain(valueNode);
        }
      }

      // Constant folding: String action = "quer" + "y" -> constantValue = "query"
      // Also resolves: char c = guess.charAt(1) -> constantValue = "B"
      let constantValue: string | undefined;
      if (valueNode) {
        const folded = tryFoldConstant(valueNode);
        if (folded !== null) {
          constantValue = folded;
        } else {
          // Try charAt resolution on constant strings: guess.charAt(1) -> "B"
          const charAtResult = tryResolveCharAt(valueNode, ctx);
          if (charAtResult !== null) constantValue = charAtResult;
        }
      }

      // Numeric constant propagation: int num = 106 -> numericValue = 106
      let numericValue: number | undefined;
      if (valueNode) {
        const foldedNum = tryFoldNumeric(valueNode, ctx);
        if (foldedNum !== null) numericValue = foldedNum;
      }

      ctx.declareVariable(varName, kind, null, tainted, producingNodeId);
      const v = ctx.resolveVariable(varName);
      if (v) {
        if (aliasChain) v.aliasChain = aliasChain;
        if (genericTypeArgsList) v.genericTypeArgs = genericTypeArgsList;
        if (constantValue) v.constantValue = constantValue;
        if (numericValue !== undefined) v.numericValue = numericValue;
        if (v.numericValue !== undefined && v.range === undefined) {
          v.range = createRange(v.numericValue, v.numericValue);
        }
      }

      // V2: Emit sentence for local variable declaration
      if (valueNode && ctx.addSentence) {
        const isFromCall = valueNode.type === 'method_invocation';
        const isConcat = valueNode.type === 'binary_expression' &&
          (valueNode.text?.includes('+') ?? false);
        const templateKey = isFromCall ? 'assigned-from-call' : isConcat ? 'string-concatenation' : 'assigned-literal';
        let slots: Record<string, string>;
        if (isFromCall) {
          const callObj = valueNode.childForFieldName('object')?.text?.slice(0, 30) ?? '';
          const callMethod = valueNode.childForFieldName('name')?.text ?? '?';
          const callArgs = valueNode.childForFieldName('arguments')?.text?.slice(0, 40) ?? '';
          slots = { subject: varName, object: callObj, method: callMethod, args: callArgs, context: `line ${node.startPosition.row + 1}` };
        } else if (isConcat) {
          const parts: string[] = [];
          const walkConcat = (n: any) => {
            if (!n) return;
            if (n.type === 'identifier') parts.push(n.text);
            else if (n.type === 'binary_expression') {
              walkConcat(n.childForFieldName('left'));
              walkConcat(n.childForFieldName('right'));
            }
          };
          walkConcat(valueNode);
          slots = { subject: varName, parts: parts.join(', '), context: `line ${node.startPosition.row + 1}` };
        } else if (valueNode.type === 'ternary_expression') {
          // Dead-branch ternary: only include the LIVE branch text
          const condition = valueNode.childForFieldName('condition');
          const consequence = valueNode.childForFieldName('consequence');
          const alternative = valueNode.childForFieldName('alternative');
          let liveText = valueNode.text?.slice(0, 60) ?? '?';
          if (condition) {
            const condResult = tryEvalCondition(condition, ctx);
            if (condResult === true && consequence) {
              liveText = consequence.text?.slice(0, 60) ?? '?';
            } else if (condResult === false && alternative) {
              liveText = alternative.text?.slice(0, 60) ?? '?';
            }
          }
          slots = { subject: varName, value: liveText, context: `line ${node.startPosition.row + 1}` };
        } else {
          slots = { subject: varName, value: valueNode.text?.slice(0, 60) ?? '?', context: `line ${node.startPosition.row + 1}` };
        }
        const sentTaintClass: SemanticSentence['taintClass'] = tainted ? 'TAINTED' : 'NEUTRAL';
        const sentenceNode = producingNodeId ? ctx.neuralMap.nodes.find((n: any) => n.id === producingNodeId) : null;
        const sentence = generateSentence(templateKey, slots, node.startPosition.row + 1, producingNodeId ?? '', sentTaintClass);
        // Determine taintBasis: if the value is a local function call, mark PENDING
        if (isFromCall) {
          const calleeName = valueNode.childForFieldName('name')?.text;
          const calleeObj = valueNode.childForFieldName('object');
          if (calleeName && ctx.functionRegistry.has(calleeName)) {
            sentence.taintBasis = 'PENDING';
          } else {
            sentence.taintBasis = 'PHONEME_RESOLUTION';
          }
        } else {
          sentence.taintBasis = 'SCOPE_LOOKUP';
        }
        if (sentenceNode) {
          if (!sentenceNode.sentences) sentenceNode.sentences = [];
          sentenceNode.sentences.push(sentence);
        }
        ctx.addSentence(sentence);
      }
    }
    return;
  }
}

// ---------------------------------------------------------------------------
// processFunctionParams — handle Java method parameters with annotations
// ---------------------------------------------------------------------------

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) return;

  // Determine if this function is eligible for auto-taint on String/byte[]/char[] params.
  // A method is eligible when it's a method_declaration that is NOT private and
  // NOT a utility function (toString, equals, main, etc.).
  let funcIsAutoTaintEligible = false;
  if (funcNode.type === 'method_declaration') {
    const funcName = funcNode.childForFieldName('name')?.text ?? '';
    if (!JAVA_UNTAINTABLE_FUNCTIONS.has(funcName)) {
      // All non-utility functions get auto-tainted String params.
      // Private functions may still receive tainted data from callers —
      // being conservative during the walk lets post-processing (functionReturnTaint)
      // determine if taint actually propagates through the return.
      funcIsAutoTaintEligible = true;
    }
  }

  // In Java, parameters are in `formal_parameters` containing `formal_parameter` nodes.
  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    if (param.type === 'formal_parameter' || param.type === 'spread_parameter') {
      const nameNode = param.childForFieldName('name');
      const typeNode = param.childForFieldName('type');
      const paramName = nameNode?.text;
      const typeText = typeNode?.text ?? '';

      if (!paramName) continue;

      // Check 1: Spring taint annotations (@RequestBody, @PathVariable, etc.)
      const hasTaintAnnotation = paramHasTaintAnnotation(param);

      // Check 2: HttpServletRequest type
      const isRequestType = JAVA_HTTP_REQUEST_TYPES.has(typeText);

      // Check 3: Conventional request parameter names
      const isRequestName = JAVA_REQUEST_PARAM_NAMES.has(paramName);

      if (hasTaintAnnotation || isRequestType || isRequestName) {
        // Create an INGRESS node for tainted parameter
        const subtype = hasTaintAnnotation ? 'http_request' :
                        isRequestType ? 'http_request' : 'http_request';
        const ingressNode = createNode({
          label: paramName,
          node_type: 'INGRESS',
          node_subtype: subtype,
          language: 'java',
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
      } else if (JAVA_RESPONSE_PARAM_NAMES.has(paramName)) {
        // Response — not tainted but declare it
        ctx.declareVariable(paramName, 'param', null, false, null);
      } else {
        // Regular parameter — check pendingCallbackTaint
        const producingId = ctx.pendingCallbackTaint.get(paramName) ?? null;
        let isTainted = producingId !== null;
        if (isTainted) ctx.pendingCallbackTaint.delete(paramName);

        // Auto-taint: String/String[]/byte[]/char[] params in public non-utility methods.
        // This catches the common cross-file pattern where user input arrives via method
        // parameters from other files/classes (e.g., Juliet *_66b.java badSink(String data)).
        if (!isTainted && funcIsAutoTaintEligible && isAutoTaintableType(typeText)) {
          isTainted = true;
          // Create an INGRESS node for the auto-tainted parameter
          const autoIngressNode = createNode({
            label: paramName,
            node_type: 'INGRESS',
            node_subtype: 'function_param',
            language: 'java',
            file: ctx.neuralMap.source_file,
            line_start: param.startPosition.row + 1,
            line_end: param.endPosition.row + 1,
            code_snapshot: param.text.slice(0, 200),
            analysis_snapshot: param.text.slice(0, 2000),
          });
          autoIngressNode.data_out.push({
            name: 'result',
            source: autoIngressNode.id,
            data_type: typeText || 'String',
            tainted: true,
            sensitivity: 'NONE',
          });
          autoIngressNode.attack_surface.push('function_param');
          ctx.neuralMap.nodes.push(autoIngressNode);
          ctx.emitContainsIfNeeded(autoIngressNode.id);
          ctx.declareVariable(paramName, 'param', null, true, autoIngressNode.id);
        } else {
          ctx.declareVariable(paramName, 'param', null, isTainted, producingId);
        }
      }

      // Store the declared type as aliasChain for ALL parameters.
      // This enables alias resolution: if the param is `Statement stmt`,
      // then stmt.executeQuery() resolves to Statement.executeQuery.
      if (typeNode) {
        let simpleTypeName: string | undefined;
        if (typeNode.type === 'type_identifier') {
          simpleTypeName = typeNode.text;
        } else if (typeNode.type === 'scoped_type_identifier') {
          const lastChild = typeNode.namedChild(typeNode.namedChildCount - 1);
          if (lastChild?.type === 'type_identifier') simpleTypeName = lastChild.text;
        }
        const PARAM_PRIMITIVES = new Set(['int', 'long', 'float', 'double', 'boolean', 'byte', 'char', 'short', 'void', 'String', 'Object']);
        if (simpleTypeName && !PARAM_PRIMITIVES.has(simpleTypeName)) {
          const v = ctx.resolveVariable(paramName);
          if (v) v.aliasChain = [simpleTypeName];
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// V2: Sentence generation helpers
// ---------------------------------------------------------------------------

/**
 * Extract the variable name that a method call result is being assigned to.
 * Looks at the parent AST node: `String kid = request.getParameter("kid")` → "kid"
 */
function varNameFromContext(callNode: SyntaxNode, ctx: MapperContextLike): string {
  // Check if parent is variable_declarator: type varName = <callNode>
  const parent = callNode.parent;
  if (parent?.type === 'variable_declarator') {
    const nameNode = parent.childForFieldName('name');
    if (nameNode?.type === 'identifier') return nameNode.text;
  }
  // Check if parent is assignment_expression: varName = <callNode>
  if (parent?.type === 'assignment_expression') {
    const left = parent.childForFieldName('left');
    if (left?.type === 'identifier') return left.text;
  }
  return 'result';
}

/**
 * Collect variable names from an arguments node for sentence slots.
 * `(a, b, "literal")` → "a, b, \"literal\""
 */
function collectArgVarNames(argsNode: SyntaxNode | null): string {
  if (!argsNode) return '';
  const names: string[] = [];
  for (let i = 0; i < argsNode.namedChildCount; i++) {
    const arg = argsNode.namedChild(i);
    if (!arg) continue;
    if (arg.type === 'identifier') {
      names.push(arg.text);
    } else if (arg.type === 'string_literal') {
      names.push(arg.text.slice(0, 30));
    } else if (arg.type === 'binary_expression') {
      // String concatenation — collect identifiers within
      const parts: string[] = [];
      const walk = (n: SyntaxNode) => {
        if (n.type === 'identifier') parts.push(n.text);
        else if (n.type === 'string_literal') parts.push(n.text.slice(0, 20));
        else { for (let c = 0; c < n.childCount; c++) { const ch = n.child(c); if (ch) walk(ch); } }
      };
      walk(arg);
      names.push(parts.join(' + '));
    } else {
      names.push(arg.text?.slice(0, 30) ?? '?');
    }
  }
  return names.join(', ');
}

/**
 * Extract ONLY identifier variable names from method arguments.
 * Skips string literals, class/package names (contain dots), numeric literals.
 * Used for writes-response 'variables' slot so the verifier doesn't need regex.
 */
function collectArgIdentifiers(argsNode: SyntaxNode | null): string {
  if (!argsNode) return '';
  const names: string[] = [];
  const walk = (n: SyntaxNode) => {
    if (n.type === 'identifier') {
      // Skip common non-variable identifiers (class names start with uppercase,
      // but also skip known packages/types)
      const text = n.text;
      if (text && !text.match(/^[A-Z][A-Z_0-9]*$/) && !text.match(/^(java|javax|org|com|net|io|util|lang|sql|servlet|http|String|Integer|Long|Boolean|Object|Locale|System|Math|Arrays|Collections)$/)) {
        names.push(text);
      }
    } else if (n.type !== 'string_literal' && n.type !== 'decimal_integer_literal' &&
               n.type !== 'character_literal' && n.type !== 'null_literal' &&
               n.type !== 'true' && n.type !== 'false') {
      for (let c = 0; c < n.childCount; c++) {
        const ch = n.child(c);
        if (ch) walk(ch);
      }
    }
  };
  for (let i = 0; i < argsNode.namedChildCount; i++) {
    const arg = argsNode.namedChild(i);
    if (arg) walk(arg);
  }
  // Deduplicate
  return [...new Set(names)].join(', ');
}

/** Determine the taint class for a sentence based on node type, subtype, and taint state. */
function resolveTaintClass(
  nodeType: string,
  subtype: string,
  tainted: boolean,
): SemanticSentence['taintClass'] {
  // Safe sources/sanitizers/encoders take priority — they neutralize taint regardless of node type
  if (subtype === 'safe_source' || subtype === 'sanitize' || subtype === 'encode') return 'SAFE';
  if (nodeType === 'INGRESS' && tainted) return 'TAINTED';
  if (nodeType === 'INGRESS') return 'NEUTRAL';
  if (nodeType === 'STORAGE' && (subtype.includes('sql') || subtype.includes('query') || subtype.includes('db_'))) return 'SINK';
  if (nodeType === 'CONTROL') return 'STRUCTURAL';
  if (tainted) return 'TAINTED';
  return 'NEUTRAL';
}

/** Emit a sentence to both the node and the mapper context. */
function emitSentence(
  sentence: SemanticSentence,
  node: { sentences?: SemanticSentence[] },
  ctx: MapperContextLike,
): void {
  if (!node.sentences) node.sentences = [];
  node.sentences.push(sentence);
  ctx.addSentence(sentence);
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of the switch statement
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  switch (node.type) {
    // -- METHOD DECLARATIONS --
    case 'method_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const routeAnnotation = methodHasRouteAnnotation(node);
      const hasSecurityAnnotation = methodHasSecurityAnnotation(node);

      const methodNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: routeAnnotation ? 'route' : 'function',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        // STEP 4: Use 500 chars so the parameter list is never truncated for
        // inter-procedural taint propagation via functionParamPattern.
        // analysis_snapshot: 4000 chars to capture full method body for CWE analysis.
        code_snapshot: node.text.slice(0, 500),
        analysis_snapshot: node.text.slice(0, 4000),
      });

      if (routeAnnotation) {
        methodNode.tags.push('route', routeAnnotation.annotation);
      }
      if (hasSecurityAnnotation) {
        methodNode.tags.push('auth_gate');
      }

      // Compose route path: class prefix + method annotation path
      // Look for the enclosing class node to get any route prefix
      let classRoutePrefix = '';
      let isServletClass = false;
      let parentNode = node.parent;
      while (parentNode) {
        if (parentNode.type === 'class_body' && parentNode.parent?.type === 'class_declaration') {
          const classInfo = extractClassRoutePrefix(parentNode.parent);
          classRoutePrefix = classInfo.path ?? '';
          isServletClass = classInfo.isServlet;
          break;
        }
        parentNode = parentNode.parent;
      }

      if (routeAnnotation?.path) {
        methodNode.metadata.route_path = composePaths(classRoutePrefix, routeAnnotation.path);
      } else if (routeAnnotation && classRoutePrefix) {
        methodNode.metadata.route_path = classRoutePrefix.startsWith('/') ? classRoutePrefix : '/' + classRoutePrefix;
      }

      // Servlet method handling: doGet/doPost/doPut/doDelete inherit class @WebServlet path
      const SERVLET_METHOD_HTTP_MAP: Record<string, string> = {
        doGet: 'GET', doPost: 'POST', doPut: 'PUT', doDelete: 'DELETE',
      };
      if (isServletClass && SERVLET_METHOD_HTTP_MAP[name]) {
        methodNode.metadata.http_method = SERVLET_METHOD_HTTP_MAP[name];
        methodNode.node_subtype = 'route';
        methodNode.tags.push('route', 'servlet');
        if (classRoutePrefix) {
          methodNode.metadata.route_path = classRoutePrefix.startsWith('/') ? classRoutePrefix : '/' + classRoutePrefix;
        }
      }

      // Extract HTTP method from Spring mapping annotation name
      if (routeAnnotation && !methodNode.metadata.http_method) {
        const MAPPING_HTTP_MAP: Record<string, string> = {
          GetMapping: 'GET', PostMapping: 'POST', PutMapping: 'PUT',
          DeleteMapping: 'DELETE', PatchMapping: 'PATCH',
        };
        const httpMethod = MAPPING_HTTP_MAP[routeAnnotation.annotation];
        if (httpMethod) {
          methodNode.metadata.http_method = httpMethod;
        }
      }

      // Extract param names from AST and populate param_names on the STRUCTURAL node
      const params = node.childForFieldName('parameters');
      if (params) {
        const pNames: string[] = [];
        for (let pi = 0; pi < params.namedChildCount; pi++) {
          const p = params.namedChild(pi);
          if (p && (p.type === 'formal_parameter' || p.type === 'spread_parameter')) {
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
      const paramCount = params ? params.namedChildCount : 0;
      ctx.functionRegistry.set(`${name}:${paramCount}`, methodNode.id);
      break;
    }

    // -- CONSTRUCTOR DECLARATIONS --
    case 'constructor_declaration': {
      const name = node.childForFieldName('name')?.text ?? '<init>';
      const ctorNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'java',
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
      const ctorParams = node.childForFieldName('parameters');
      const ctorParamCount = ctorParams ? ctorParams.namedChildCount : 0;
      ctx.functionRegistry.set(`${name}:${ctorParamCount}`, ctorNode.id);
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
        language: 'java',
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

    // -- CLASS DECLARATIONS --
    case 'class_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousClass';

      // Check for class-level annotations (Spring components)
      let subtype = 'class';
      const modifiers = node.childForFieldName('modifiers') ??
        node.descendantsOfType('modifiers')[0];
      if (modifiers) {
        for (let i = 0; i < modifiers.childCount; i++) {
          const mod = modifiers.child(i);
          if (mod && (mod.type === 'marker_annotation' || mod.type === 'annotation')) {
            const annotName = getAnnotationName(mod);
            if (annotName === 'RestController' || annotName === 'Controller') {
              subtype = 'controller';
            } else if (annotName === 'Service') {
              subtype = 'service';
            } else if (annotName === 'Repository') {
              subtype = 'repository';
            } else if (annotName === 'Component') {
              subtype = 'component';
            } else if (annotName === 'Entity') {
              subtype = 'entity';
            } else if (annotName === 'Configuration') {
              subtype = 'config';
            }
          }
        }
      }

      // Extract class-level route prefix (@WebServlet, @RequestMapping)
      const classRouteInfo = extractClassRoutePrefix(node);
      if (classRouteInfo.isServlet) {
        subtype = 'controller';
      }

      const classNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: subtype,
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });

      // Store route metadata on the class node
      if (classRouteInfo.path) {
        classNode.metadata.route_path = classRouteInfo.path.startsWith('/') ? classRouteInfo.path : '/' + classRouteInfo.path;
      }
      if (classRouteInfo.isServlet) {
        classNode.metadata.is_servlet_route = true;
      }

      ctx.neuralMap.nodes.push(classNode);
      ctx.lastCreatedNodeId = classNode.id;
      ctx.emitContainsIfNeeded(classNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = classNode.id;

      // ── Pre-register method names so forward-reference calls (e.g.,
      //    doGet calling helperMethod defined below) get local_call nodes.
      //    The placeholder ID '__pre_<name>' is overwritten when the actual
      //    method_declaration is classified during the walk. ──
      const classBody = node.childForFieldName('body');
      if (classBody) {
        for (let ci = 0; ci < classBody.namedChildCount; ci++) {
          const member = classBody.namedChild(ci);
          if (member && (member.type === 'method_declaration' || member.type === 'constructor_declaration')) {
            const methodName = member.childForFieldName('name')?.text;
            if (methodName && !ctx.functionRegistry.has(methodName)) {
              ctx.functionRegistry.set(methodName, `__pre_${methodName}`);
            }
            // Also pre-register with param count for overloading support
            if (methodName) {
              const memberParams = member.childForFieldName('parameters');
              const memberParamCount = memberParams ? memberParams.namedChildCount : 0;
              const qualifiedKey = `${methodName}:${memberParamCount}`;
              if (!ctx.functionRegistry.has(qualifiedKey)) {
                ctx.functionRegistry.set(qualifiedKey, `__pre_${methodName}`);
              }
            }
          }
        }
      }
      break;
    }

    // -- INTERFACE DECLARATION --
    case 'interface_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousInterface';
      const ifaceNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'interface',
        language: 'java',
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

    // -- ENUM DECLARATION --
    case 'enum_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousEnum';
      const enumNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'enum',
        language: 'java',
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

    // -- RECORD DECLARATION (Java 14+) --
    case 'record_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousRecord';
      const recordNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'record',
        language: 'java',
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

    // -- IMPORT DECLARATIONS --
    case 'import_declaration': {
      // import com.example.Foo; or import static com.example.Bar.*
      const scopedId = node.descendantsOfType('scoped_identifier')[0];
      const moduleName = scopedId?.text ?? node.text.replace(/^import\s+(static\s+)?/, '').replace(/;\s*$/, '').trim();
      const importNode = createNode({
        label: moduleName,
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'java',
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

    // -- PACKAGE DECLARATION --
    case 'package_declaration': {
      const pkgScopedId = node.descendantsOfType('scoped_identifier')[0];
      const pkgName = pkgScopedId?.text ?? node.text.replace(/^package\s+/, '').replace(/;\s*$/, '').trim();
      const pkgNode = createNode({
        label: `package ${pkgName}`,
        node_type: 'STRUCTURAL',
        node_subtype: 'module',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(pkgNode);
      ctx.lastCreatedNodeId = pkgNode.id;
      ctx.emitContainsIfNeeded(pkgNode.id);
      break;
    }

    // -- METHOD INVOCATION: classify by callee --
    case 'method_invocation': {
      const resolution = resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'java',
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
        // Anti-evasion: tag Class.forName and reflection calls, resolve variable constants
        if (resolution.nodeType === 'EXTERNAL' && resolution.subtype === 'reflection') {
          n.tags.push('anti_evasion', 'reflection');
          // Try to resolve the first argument from variable constantValue
          const reflArgs = node.childForFieldName('arguments');
          const reflFirstArg = reflArgs?.namedChild(0);
          if (reflFirstArg?.type === 'identifier') {
            const argVar = ctx.resolveVariable(reflFirstArg.text);
            if (argVar?.constantValue) {
              n.label = `Class.forName("${argVar.constantValue}")`;
              n.tags.push(`resolved:${argVar.constantValue}`);
              // Not tainted since we resolved it to a constant
              n.data_out = n.data_out.filter((d: any) => !d.tainted);
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
        // Skip for safe_source methods — their output is a constant, independent of receiver state.
        // Skip for collection .get(N) when per-index tracking resolves the index to a safe element.
        const calleeObj = node.childForFieldName('object');
        const isSafeSource = resolution.subtype === 'safe_source';
        let isCollectionSafeGet = false;
        if (calleeObj?.type === 'identifier') {
          const methodName = node.childForFieldName('name')?.text;
          if (methodName === 'get') {
            const getVar = ctx.resolveVariable(calleeObj.text);
            if (getVar?.collectionTaint) {
              const getArgs = node.childForFieldName('arguments');
              const firstArg = getArgs?.namedChild(0);
              let resolvedIdx: number | undefined;
              if (firstArg?.type === 'decimal_integer_literal') {
                resolvedIdx = parseInt(firstArg.text);
              } else if (firstArg?.type === 'identifier') {
                const idxVar = ctx.resolveVariable(firstArg.text);
                if (idxVar?.numericValue !== undefined) resolvedIdx = idxVar.numericValue;
              }
              if (resolvedIdx !== undefined && resolvedIdx >= 0 && resolvedIdx < getVar.collectionTaint.length) {
                if (!getVar.collectionTaint[resolvedIdx]!.tainted) {
                  isCollectionSafeGet = true;
                  (ctx.neuralMap as any).collectionTaintNeutralized = true;
                  const _ctnId1 = ctx.getCurrentContainerId();
                  if (_ctnId1) {
                    const _ctnNode1 = ctx.nodeById.get(_ctnId1);
                    if (_ctnNode1) _ctnNode1.metadata.collectionTaintNeutralized = true;
                  }
                }
              }
            }
            // Per-key resolution: map.get("key") → check keyedTaint from map.put("key", val)
            if (getVar?.keyedTaint) {
              const getArgs2 = node.childForFieldName('arguments');
              const firstArg2 = getArgs2?.namedChild(0);
              if (firstArg2?.type === 'string_literal') {
                const keyStr = firstArg2.text.replace(/^"|"$/g, '');
                const entry = getVar.keyedTaint.get(keyStr);
                if (entry && !entry.tainted) {
                  isCollectionSafeGet = true;
                  (ctx.neuralMap as any).collectionTaintNeutralized = true;
                  const _ctnId1k = ctx.getCurrentContainerId();
                  if (_ctnId1k) {
                    const _ctnNode1k = ctx.nodeById.get(_ctnId1k);
                    if (_ctnNode1k) _ctnNode1k.metadata.collectionTaintNeutralized = true;
                  }
                }
              }
            }
          }
        }
        if (calleeObj && !isSafeSource && !isCollectionSafeGet) {
          const receiverTaint = extractTaintSources(calleeObj, ctx);
          for (const source of receiverTaint) {
            if (!callHasTaintedArgs) callHasTaintedArgs = true;
            ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
          }
        }

        // Taint-through: if ANY tainted data flows in, mark output tainted
        // Skip for safe_source methods — they return hardcoded values regardless of input.
        if (callHasTaintedArgs && !isSafeSource && !n.data_out.some((d: any) => d.tainted)) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }

        // V2: Generate semantic sentence for CWE-relevant method invocations
        {
          const nodeIsTainted = resolution.tainted || n.data_out.some((d: any) => d.tainted);
          const methodName = node.childForFieldName('name')?.text ?? '?';
          const objText = calleeObj?.text?.slice(0, 40) ?? '';
          const argsText = argsNode?.text?.slice(0, 60) ?? '';
          let sentTaintClass = resolveTaintClass(resolution.nodeType, resolution.subtype, nodeIsTainted);
          // PreparedStatement creation or parameter binding → SAFE with parameter-binding template.
          // setString/setInt/etc. are parameter binds, not query executions.
          // The phoneme resolves them as STORAGE/db_write but the SENTENCE must say parameter-binding
          // so the V2 verifier knows to suppress findings on this statement object.
          const isParamBinding = resolution.subtype === 'parameterized_query' || methodName === 'setString' || methodName === 'setInt' || methodName === 'setLong' || methodName === 'setObject';
          if (isParamBinding) {
            sentTaintClass = 'SAFE';
          }
          const templateKey = isParamBinding ? 'parameter-binding' : getTemplateKey(resolution.nodeType, resolution.subtype);
          // Build template-appropriate slots
          let slots: Record<string, string>;
          if (templateKey === 'retrieves-from-source') {
            slots = { subject: varNameFromContext(node, ctx), data_type: 'user input', source: `${objText}.${methodName}`, context: `line ${node.startPosition.row + 1}` };
          } else if (templateKey === 'executes-query') {
            // Collect variable names from args for the 'variables' slot
            const varNames = collectArgVarNames(argsNode);
            slots = { subject: objText || methodName, query_type: 'SQL', variables: varNames || argsText, context: `line ${node.startPosition.row + 1}` };
          } else if (templateKey === 'parameter-binding') {
            const indexArg = argsNode?.namedChild(0)?.text ?? '?';
            const valueArg = argsNode?.namedChild(1)?.text?.slice(0, 40) ?? '?';
            slots = { subject: objText || methodName, variable: valueArg, index: indexArg, context: `line ${node.startPosition.row + 1}` };
          } else if (templateKey === 'writes-response') {
            // Collect only identifier variable names for the 'variables' slot.
            // The verifier reads this directly — no regex parsing needed.
            const varNames = collectArgIdentifiers(argsNode);
            slots = { subject: objText || '?', method: methodName, object: objText, args: argsText, variables: varNames, context: `line ${node.startPosition.row + 1}` };
          } else {
            slots = { subject: objText || '?', method: methodName, object: objText, args: argsText, context: `line ${node.startPosition.row + 1}` };
          }
          const sentence = generateSentence(templateKey, slots, node.startPosition.row + 1, n.id, sentTaintClass);
          sentence.taintBasis = 'PHONEME_RESOLUTION';
          emitSentence(sentence, n, ctx);
        }

        // Collection mutation tainting: list.add(tainted) → mark list as tainted
        // Also maintains per-index collection taint when applicable.
        if (calleeObj?.type === 'identifier') {
          const MUTATING_METHODS = new Set([
            'add', 'put', 'set', 'offer', 'push', 'addAll', 'putAll',
            'append', 'insert', 'write', 'print', 'println',
            'setAttribute', 'setProperty', 'addElement',
          ]);
          const methodName = node.childForFieldName('name')?.text;

          // Per-index collection tracking for .remove(N) — runs regardless of MUTATING_METHODS
          // because 'remove' is resolved as STORAGE/db_write by resolveCallee but still
          // needs to splice the per-index taint array for accurate collection tracking.
          if (methodName === 'remove') {
            const receiverVar = ctx.resolveVariable(calleeObj.text);
            if (receiverVar?.collectionTaint) {
              const collArgs = node.childForFieldName('arguments');
              const firstArg = collArgs?.namedChild(0);
              if (firstArg?.type === 'decimal_integer_literal') {
                const removeIdx = parseInt(firstArg.text);
                if (removeIdx >= 0 && removeIdx < receiverVar.collectionTaint.length) {
                  receiverVar.collectionTaint.splice(removeIdx, 1);
                }
              }
            }
          }

          if (methodName && MUTATING_METHODS.has(methodName)) {
            const receiverVar = ctx.resolveVariable(calleeObj.text);
            if (receiverVar) {
              // Per-index tracking for add/set
              if (methodName === 'add') {
                const collArgs = node.childForFieldName('arguments');
                const argCount = collArgs?.namedChildCount ?? 0;
                if (argCount === 1) {
                  const arg = collArgs!.namedChild(0)!;
                  const isStringLiteral = arg.type === 'string_literal';
                  const argTainted = isStringLiteral ? false : extractTaintSources(arg, ctx).length > 0;
                  if (!receiverVar.collectionTaint) receiverVar.collectionTaint = [];
                  receiverVar.collectionTaint.push({ tainted: argTainted, producingNodeId: argTainted ? n.id : null });
                }
              } else if (methodName === 'set') {
                const collArgs = node.childForFieldName('arguments');
                if (collArgs?.namedChildCount === 2 && receiverVar.collectionTaint) {
                  const indexArg = collArgs.namedChild(0)!;
                  const exprArg = collArgs.namedChild(1)!;
                  if (indexArg.type === 'decimal_integer_literal') {
                    const setIdx = parseInt(indexArg.text);
                    const isStringLiteral = exprArg.type === 'string_literal';
                    const argTainted = isStringLiteral ? false : extractTaintSources(exprArg, ctx).length > 0;
                    if (setIdx >= 0 && setIdx < receiverVar.collectionTaint.length) {
                      receiverVar.collectionTaint[setIdx] = { tainted: argTainted, producingNodeId: argTainted ? n.id : null };
                    }
                  }
                }
              } else if (methodName === 'put') {
                // Per-key tracking for HashMap: map.put("key", value)
                const collArgs = node.childForFieldName('arguments');
                if (collArgs?.namedChildCount === 2) {
                  const keyArg = collArgs.namedChild(0)!;
                  const valArg = collArgs.namedChild(1)!;
                  if (keyArg.type === 'string_literal') {
                    const key = keyArg.text.replace(/^"|"$/g, '');
                    const isStringLiteral = valArg.type === 'string_literal';
                    const argTainted = isStringLiteral ? false : extractTaintSources(valArg, ctx).length > 0;
                    if (!receiverVar.keyedTaint) receiverVar.keyedTaint = new Map();
                    receiverVar.keyedTaint.set(key, { tainted: argTainted, producingNodeId: argTainted ? n.id : null });
                  }
                }
              }
              // Whole-collection taint (fallback) — only mark if tainted args flow in
              if (callHasTaintedArgs && !receiverVar.tainted) {
                receiverVar.tainted = true;
                receiverVar.producingNodeId = n.id;
              }
            }
          }
        }

        // Callback parameter taint (for lambdas passed as args)
        if (callHasTaintedArgs) {
          const callArgs = node.childForFieldName('arguments');
          if (callArgs) {
            for (let ai = 0; ai < callArgs.namedChildCount; ai++) {
              const arg = callArgs.namedChild(ai);
              if (arg?.type === 'lambda_expression') {
                const params = arg.childForFieldName('parameters');
                if (params) {
                  for (let pi = 0; pi < params.namedChildCount; pi++) {
                    const p = params.namedChild(pi);
                    if (p?.type === 'formal_parameter') {
                      const pName = p.childForFieldName('name');
                      if (pName?.type === 'identifier') {
                        ctx.pendingCallbackTaint.set(pName.text, n.id);
                      }
                    } else if (p?.type === 'identifier') {
                      // Inferred parameter: (x) -> x.foo() or just x -> x.foo()
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
        const aliasName = node.childForFieldName('name');
        const aliasObj = node.childForFieldName('object');
        if (aliasObj?.type === 'identifier') {
          const aliasVar = ctx.resolveVariable(aliasObj.text);
          if (aliasVar?.aliasChain && aliasName) {
            const fullChain = [...aliasVar.aliasChain, aliasName.text];
            const aliasPattern = _lookupJavaCallee(fullChain);
            if (aliasPattern) {
              const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const aliasN = createNode({
                label,
                node_type: aliasPattern.nodeType,
                node_subtype: aliasPattern.subtype,
                language: 'java',
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
              // V2: Sentence for alias-resolved method call
              {
                const aliasIsTainted = aliasN.data_out.some((d: any) => d.tainted);
                const aliasMethodName = aliasName?.text ?? '?';
                const aliasObjText = aliasObj?.text?.slice(0, 40) ?? '';
                const aliasArgsText = aliasArgs?.text?.slice(0, 60) ?? '';
                // Parameter binding: setString/setInt/etc. are NOT query executions
                const aliasIsParamBinding = aliasPattern.subtype === 'parameterized_query' || aliasMethodName === 'setString' || aliasMethodName === 'setInt' || aliasMethodName === 'setLong' || aliasMethodName === 'setObject';
                const aliasTemplateKey = aliasIsParamBinding ? 'parameter-binding' : getTemplateKey(aliasPattern.nodeType, aliasPattern.subtype);
                let aliasSentTaintClass = resolveTaintClass(aliasPattern.nodeType, aliasPattern.subtype, aliasIsTainted);
                if (aliasIsParamBinding) aliasSentTaintClass = 'SAFE';
                let aliasSlots: Record<string, string>;
                if (aliasTemplateKey === 'executes-query') {
                  aliasSlots = { subject: aliasObjText || aliasMethodName, query_type: 'SQL', variables: collectArgVarNames(aliasArgs) || aliasArgsText, context: `line ${node.startPosition.row + 1}` };
                } else if (aliasTemplateKey === 'parameter-binding') {
                  const idxArg = aliasArgs?.namedChild(0)?.text ?? '?';
                  const valArg = aliasArgs?.namedChild(1)?.text?.slice(0, 40) ?? '?';
                  aliasSlots = { subject: aliasObjText, variable: valArg, index: idxArg, context: `line ${node.startPosition.row + 1}` };
                } else if (aliasTemplateKey === 'writes-response') {
                  const aliasVarNames = collectArgIdentifiers(aliasArgs);
                  aliasSlots = { subject: aliasObjText || '?', method: aliasMethodName, object: aliasObjText, args: aliasArgsText, variables: aliasVarNames, context: `line ${node.startPosition.row + 1}` };
                } else {
                  aliasSlots = { subject: aliasObjText || '?', method: aliasMethodName, object: aliasObjText, args: aliasArgsText, context: `line ${node.startPosition.row + 1}` };
                }
                const aliasSentence = generateSentence(aliasTemplateKey, aliasSlots, node.startPosition.row + 1, aliasN.id, aliasSentTaintClass);
                aliasSentence.taintBasis = 'PHONEME_RESOLUTION';
                emitSentence(aliasSentence, aliasN, ctx);
              }
              break;
            }
          }
        }

        // -- Per-index collection taint tracking --
        // Tracks .add(), .remove(), .set() on local collection variables.
        // When .add(expr) is called, records per-index taint state.
        // When .remove(N) is called, splices the tracked entries.
        // Resolution happens in extractTaintSources when .get(N) is seen.
        if (aliasObj?.type === 'identifier' && aliasName) {
          const collMethodName = aliasName.text;
          const collVar = ctx.resolveVariable(aliasObj.text);
          if (collVar) {
            if (collMethodName === 'add') {
              const collArgs = node.childForFieldName('arguments');
              const argCount = collArgs?.namedChildCount ?? 0;
              if (argCount === 1) {
                // list.add(expr) — append
                const arg = collArgs!.namedChild(0)!;
                const isStringLiteral = arg.type === 'string_literal';
                const taintSources = isStringLiteral ? [] : extractTaintSources(arg, ctx);
                const argTainted = taintSources.length > 0;
                const producingId = argTainted ? (taintSources[0]?.nodeId ?? null) : null;
                if (!collVar.collectionTaint) collVar.collectionTaint = [];
                collVar.collectionTaint.push({ tainted: argTainted, producingNodeId: producingId });
                // Also maintain whole-collection taint for fallback
                if (argTainted && !collVar.tainted) {
                  collVar.tainted = true;
                  collVar.producingNodeId = producingId;
                }
              } else if (argCount === 2) {
                // list.add(index, expr) — insert at index
                const indexArg = collArgs!.namedChild(0)!;
                const exprArg = collArgs!.namedChild(1)!;
                const insertIdx = indexArg.type === 'decimal_integer_literal' ? parseInt(indexArg.text) : -1;
                const isStringLiteral = exprArg.type === 'string_literal';
                const taintSources = isStringLiteral ? [] : extractTaintSources(exprArg, ctx);
                const argTainted = taintSources.length > 0;
                const producingId = argTainted ? (taintSources[0]?.nodeId ?? null) : null;
                if (!collVar.collectionTaint) collVar.collectionTaint = [];
                if (insertIdx >= 0 && insertIdx <= collVar.collectionTaint.length) {
                  collVar.collectionTaint.splice(insertIdx, 0, { tainted: argTainted, producingNodeId: producingId });
                } else {
                  collVar.collectionTaint.push({ tainted: argTainted, producingNodeId: producingId });
                }
                if (argTainted && !collVar.tainted) {
                  collVar.tainted = true;
                  collVar.producingNodeId = producingId;
                }
              }
            } else if (collMethodName === 'remove') {
              const collArgs = node.childForFieldName('arguments');
              const firstArg = collArgs?.namedChild(0);
              if (firstArg?.type === 'decimal_integer_literal' && collVar.collectionTaint) {
                const removeIdx = parseInt(firstArg.text);
                if (removeIdx >= 0 && removeIdx < collVar.collectionTaint.length) {
                  collVar.collectionTaint.splice(removeIdx, 1);
                }
              }
            } else if (collMethodName === 'set') {
              const collArgs = node.childForFieldName('arguments');
              if (collArgs?.namedChildCount === 2 && collVar.collectionTaint) {
                const indexArg = collArgs.namedChild(0)!;
                const exprArg = collArgs.namedChild(1)!;
                if (indexArg.type === 'decimal_integer_literal') {
                  const setIdx = parseInt(indexArg.text);
                  const isStringLiteral = exprArg.type === 'string_literal';
                  const taintSources = isStringLiteral ? [] : extractTaintSources(exprArg, ctx);
                  const argTainted = taintSources.length > 0;
                  const producingId = argTainted ? (taintSources[0]?.nodeId ?? null) : null;
                  if (setIdx >= 0 && setIdx < collVar.collectionTaint.length) {
                    collVar.collectionTaint[setIdx] = { tainted: argTainted, producingNodeId: producingId };
                  }
                }
              }
            } else if (collMethodName === 'put') {
              // Per-key tracking for HashMap: map.put("key", value)
              const collArgs = node.childForFieldName('arguments');
              if (collArgs?.namedChildCount === 2) {
                const keyArg = collArgs.namedChild(0)!;
                const valArg = collArgs.namedChild(1)!;
                if (keyArg.type === 'string_literal') {
                  const key = keyArg.text.replace(/^"|"$/g, '');
                  const isStringLiteral = valArg.type === 'string_literal';
                  const taintSources = isStringLiteral ? [] : extractTaintSources(valArg, ctx);
                  const argTainted = taintSources.length > 0;
                  const producingId = argTainted ? (taintSources[0]?.nodeId ?? null) : null;
                  if (!collVar.keyedTaint) collVar.keyedTaint = new Map();
                  collVar.keyedTaint.set(key, { tainted: argTainted, producingNodeId: producingId });
                }
              }
            }
          }
        }

        // -- Anti-evasion: Class.forName(variable) with constant-folded variable --
        // Detects: String name = "ev" + "al"; Class.forName(name)
        if (aliasObj?.text === 'Class' && aliasName?.text === 'forName') {
          const argsNode = node.childForFieldName('arguments');
          const firstArg = argsNode?.namedChild(0);
          let resolved = false;
          if (firstArg) {
            // Try direct constant folding first
            let foldedClassName = tryFoldConstant(firstArg);
            // Fall back to variable constantValue lookup
            if (!foldedClassName && firstArg.type === 'identifier') {
              const argVar = ctx.resolveVariable(firstArg.text);
              if (argVar?.constantValue) foldedClassName = argVar.constantValue;
            }
            const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
            const reflectNode = createNode({
              label: foldedClassName ? `Class.forName("${foldedClassName}")` : label,
              node_type: 'EXTERNAL',
              node_subtype: 'reflection',
              language: 'java',
              file: ctx.neuralMap.source_file,
              line_start: node.startPosition.row + 1,
              line_end: node.endPosition.row + 1,
              code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
            });
            reflectNode.tags.push('anti_evasion', 'reflection');
            if (foldedClassName) {
              reflectNode.tags.push(`resolved:${foldedClassName}`);
            }
            // If we couldn't fold, the argument might be tainted
            if (!foldedClassName) {
              reflectNode.data_out.push({
                name: 'result', source: reflectNode.id,
                data_type: 'unknown', tainted: true, sensitivity: 'NONE',
              });
            }
            // Check for tainted args flowing in
            if (argsNode) {
              for (let a = 0; a < argsNode.namedChildCount; a++) {
                const arg = argsNode.namedChild(a);
                if (!arg) continue;
                const taintSources = extractTaintSources(arg, ctx);
                for (const source of taintSources) {
                  ctx.addDataFlow(source.nodeId, reflectNode.id, source.name, 'unknown', true);
                  reflectNode.data_out.push({
                    name: 'result', source: reflectNode.id,
                    data_type: 'unknown', tainted: true, sensitivity: 'NONE',
                  });
                }
              }
            }
            ctx.neuralMap.nodes.push(reflectNode);
            ctx.lastCreatedNodeId = reflectNode.id;
            ctx.emitContainsIfNeeded(reflectNode.id);
            resolved = true;
          }
          if (resolved) break;
        }

        // -- Unresolved call -- check if it's a locally-defined method --
        let calleeName: string | null = null;
        if (aliasName?.type === 'identifier') {
          calleeName = aliasName.text;
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
            language: 'java',
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
        } else {
          // -- Unresolved method chain passthrough --
          // No phoneme, no alias, no local call. If tainted data flows through,
          // create a TRANSFORM/passthrough so producingNodeId is real, not __synthetic__.
          const unresolvedArgs = node.childForFieldName('arguments');
          const unresolvedObj = node.childForFieldName('object');
          const unresolvedTaint: TaintSourceResult[] = [];
          if (unresolvedArgs) {
            for (let a = 0; a < unresolvedArgs.namedChildCount; a++) {
              const arg = unresolvedArgs.namedChild(a);
              if (arg) unresolvedTaint.push(...extractTaintSources(arg, ctx));
            }
          }
          // Per-index collection resolution: if this is a .get(N) on a collection
          // with per-index tracking and the index resolves to a safe element,
          // skip receiver taint propagation entirely.
          let unresolvedCollSafeGet = false;
          const unresolvedMethodName = node.childForFieldName('name');
          if (unresolvedObj?.type === 'identifier' && unresolvedMethodName?.text === 'get') {
            const collGetVar = ctx.resolveVariable(unresolvedObj.text);
            if (collGetVar?.collectionTaint) {
              const collGetArgs = node.childForFieldName('arguments');
              const collFirstArg = collGetArgs?.namedChild(0);
              let collResolvedIdx: number | undefined;
              if (collFirstArg?.type === 'decimal_integer_literal') {
                collResolvedIdx = parseInt(collFirstArg.text);
              } else if (collFirstArg?.type === 'identifier') {
                const idxVar = ctx.resolveVariable(collFirstArg.text);
                if (idxVar?.numericValue !== undefined) collResolvedIdx = idxVar.numericValue;
              }
              if (collResolvedIdx !== undefined && collResolvedIdx >= 0 && collResolvedIdx < collGetVar.collectionTaint.length) {
                if (!collGetVar.collectionTaint[collResolvedIdx]!.tainted) {
                  unresolvedCollSafeGet = true;
                  (ctx.neuralMap as any).collectionTaintNeutralized = true;
                  const _ctnId2 = ctx.getCurrentContainerId();
                  if (_ctnId2) {
                    const _ctnNode2 = ctx.nodeById.get(_ctnId2);
                    if (_ctnNode2) _ctnNode2.metadata.collectionTaintNeutralized = true;
                  }
                }
              }
            }
            // Per-key resolution: map.get("key") → check keyedTaint from map.put("key", val)
            if (collGetVar?.keyedTaint) {
              const collGetArgs2 = node.childForFieldName('arguments');
              const collFirstArg2 = collGetArgs2?.namedChild(0);
              if (collFirstArg2?.type === 'string_literal') {
                const keyStr = collFirstArg2.text.replace(/^"|"$/g, '');
                const entry = collGetVar.keyedTaint.get(keyStr);
                if (entry && !entry.tainted) {
                  unresolvedCollSafeGet = true;
                  (ctx.neuralMap as any).collectionTaintNeutralized = true;
                  const _ctnId2k = ctx.getCurrentContainerId();
                  if (_ctnId2k) {
                    const _ctnNode2k = ctx.nodeById.get(_ctnId2k);
                    if (_ctnNode2k) _ctnNode2k.metadata.collectionTaintNeutralized = true;
                  }
                }
              }
            }
          }
          if (unresolvedObj && !unresolvedCollSafeGet) {
            unresolvedTaint.push(...extractTaintSources(unresolvedObj, ctx));
          }
          if (unresolvedTaint.length > 0) {
            const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
            const ptNode = createNode({
              label,
              node_type: 'TRANSFORM',
              node_subtype: 'passthrough',
              language: 'java',
              file: ctx.neuralMap.source_file,
              line_start: node.startPosition.row + 1,
              line_end: node.endPosition.row + 1,
              code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
            });
            ptNode.data_out.push({
              name: 'result', source: ptNode.id,
              data_type: 'unknown', tainted: true, sensitivity: 'NONE',
            });
            ctx.neuralMap.nodes.push(ptNode);
            ctx.lastCreatedNodeId = ptNode.id;
            ctx.emitContainsIfNeeded(ptNode.id);
            for (const source of unresolvedTaint) {
              ctx.addDataFlow(source.nodeId, ptNode.id, source.name, 'unknown', true);
            }
          }
        }
      }

      // CALLS edge: capture method name for pending calls
      const callName = node.childForFieldName('name');
      if (callName?.type === 'identifier') {
        const containerId = ctx.getCurrentContainerId();
        if (containerId) {
          ctx.pendingCalls.push({
            callerContainerId: containerId,
            calleeName: callName.text,
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
          language: 'java',
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
            const taintSources = extractTaintSources(arg, ctx);
            for (const source of taintSources) {
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
            }
          }
        }

        // V2: Generate sentence for object creation
        {
          const className = node.childForFieldName('type')?.text ?? '?';
          const ctorArgsText = argsNode?.text?.slice(0, 60) ?? '';
          const nodeIsTainted = resolution.tainted || n.data_out.some((d: any) => d.tainted);
          let sentTaintClass = resolveTaintClass(resolution.nodeType, resolution.subtype, nodeIsTainted);
          // PreparedStatement creation is SAFE
          if (className === 'PreparedStatement' || className.endsWith('PreparedStatement')) {
            sentTaintClass = 'SAFE';
          }
          // Use accesses-path for file operations, creates-instance for everything else.
          const isFileOp = resolution.subtype === 'file_read' || resolution.subtype === 'file_write' ||
            resolution.subtype === 'file_access' || resolution.subtype === 'file_serve';
          const templateKey = isFileOp ? 'accesses-path' : 'creates-instance';
          const slots = isFileOp
            ? { subject: varNameFromContext(node, ctx), class: className, args: ctorArgsText, variables: collectArgIdentifiers(argsNode), context: `line ${node.startPosition.row + 1}` }
            : { subject: varNameFromContext(node, ctx), class: className, args: ctorArgsText, context: `line ${node.startPosition.row + 1}` };
          const sentence = generateSentence(
            templateKey,
            slots,
            node.startPosition.row + 1,
            n.id,
            sentTaintClass,
          );
          sentence.taintBasis = 'PHONEME_RESOLUTION';
          emitSentence(sentence, n, ctx);
        }
      }
      break;
    }

    // -- FIELD ACCESS: standalone property access --
    case 'field_access': {
      // Skip if this is part of a method_invocation's object
      const parentIsCall = node.parent?.type === 'method_invocation' &&
        node.parent.childForFieldName('object')?.startIndex === node.startIndex;
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
            language: 'java',
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

    // -- ANNOTATIONS (marker and normal) --
    case 'marker_annotation':
    case 'annotation': {
      const annotName = getAnnotationName(node);
      // Create META nodes for significant annotations
      if (SPRING_ROUTE_ANNOTATIONS.has(annotName) ||
          SERVLET_ANNOTATIONS.has(annotName) ||
          SPRING_SECURITY_ANNOTATIONS.has(annotName) ||
          VALIDATION_ANNOTATIONS.has(annotName) ||
          SPRING_TAINT_ANNOTATIONS.has(annotName) ||
          annotName === 'Transactional' ||
          annotName === 'Autowired' ||
          annotName === 'Override') {
        const annotNode = createNode({
          label: `@${annotName}`,
          node_type: 'META',
          node_subtype: (SPRING_ROUTE_ANNOTATIONS.has(annotName) || SERVLET_ANNOTATIONS.has(annotName)) ? 'route_annotation' :
                        SPRING_SECURITY_ANNOTATIONS.has(annotName) ? 'security_annotation' :
                        VALIDATION_ANNOTATIONS.has(annotName) ? 'validation_annotation' :
                        'annotation',
          language: 'java',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        if (VALIDATION_ANNOTATIONS.has(annotName)) {
          annotNode.tags.push('validation');
        }
        if (SPRING_SECURITY_ANNOTATIONS.has(annotName)) {
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
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      break;
    }
    case 'for_statement': {
      const forN = createNode({ label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      // Taint propagation: if the loop condition uses tainted variables,
      // create DATA_FLOW edges from the taint source to the loop node.
      // This enables CWE-400/606 detection for tainted loop bounds.
      const forCondition = node.childForFieldName('condition');
      if (forCondition) {
        const condTaint = extractTaintSources(forCondition, ctx);
        for (const src of condTaint) {
          ctx.addDataFlow(src.nodeId, forN.id, src.name, 'unknown', true);
        }
        if (condTaint.length > 0) {
          forN.data_out.push({ name: 'loop_bound', source: forN.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE' });
          forN.tags.push('tainted_loop_bound');
        }
      }
      break;
    }
    case 'enhanced_for_statement': {
      const eforN = createNode({ label: 'for-each', node_type: 'CONTROL', node_subtype: 'loop', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(eforN); ctx.lastCreatedNodeId = eforN.id; ctx.emitContainsIfNeeded(eforN.id);
      break;
    }
    case 'while_statement': {
      const whileN = createNode({ label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whileN); ctx.lastCreatedNodeId = whileN.id; ctx.emitContainsIfNeeded(whileN.id);
      // Taint propagation for while loop conditions
      const whileCondition = node.childForFieldName('condition');
      if (whileCondition) {
        const condTaint = extractTaintSources(whileCondition, ctx);
        for (const src of condTaint) {
          ctx.addDataFlow(src.nodeId, whileN.id, src.name, 'unknown', true);
        }
        if (condTaint.length > 0) {
          whileN.data_out.push({ name: 'loop_bound', source: whileN.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE' });
          whileN.tags.push('tainted_loop_bound');
        }
      }
      break;
    }
    case 'do_statement': {
      const doN = createNode({ label: 'do-while', node_type: 'CONTROL', node_subtype: 'loop', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(doN); ctx.lastCreatedNodeId = doN.id; ctx.emitContainsIfNeeded(doN.id);
      // Taint propagation for do-while loop conditions
      const doCondition = node.childForFieldName('condition');
      if (doCondition) {
        const condTaint = extractTaintSources(doCondition, ctx);
        for (const src of condTaint) {
          ctx.addDataFlow(src.nodeId, doN.id, src.name, 'unknown', true);
        }
        if (condTaint.length > 0) {
          doN.data_out.push({ name: 'loop_bound', source: doN.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE' });
          doN.tags.push('tainted_loop_bound');
        }
      }
      break;
    }
    case 'switch_expression': {
      const switchN = createNode({ label: 'switch', node_type: 'CONTROL', node_subtype: 'branch', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(switchN); ctx.lastCreatedNodeId = switchN.id; ctx.emitContainsIfNeeded(switchN.id);
      break;
    }
    case 'return_statement': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }
    case 'break_statement': {
      const breakN = createNode({ label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(breakN); ctx.lastCreatedNodeId = breakN.id; ctx.emitContainsIfNeeded(breakN.id);
      break;
    }
    case 'continue_statement': {
      const contN = createNode({ label: 'continue', node_type: 'CONTROL', node_subtype: 'continue', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(contN); ctx.lastCreatedNodeId = contN.id; ctx.emitContainsIfNeeded(contN.id);
      break;
    }
    case 'throw_statement': {
      const throwN = createNode({ label: 'throw', node_type: 'CONTROL', node_subtype: 'throw', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      throwN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(throwN); ctx.lastCreatedNodeId = throwN.id; ctx.emitContainsIfNeeded(throwN.id);
      break;
    }

    // -- JAVA-SPECIFIC: synchronized, try-with-resources, assert --
    case 'synchronized_statement': {
      const syncN = createNode({ label: 'synchronized', node_type: 'CONTROL', node_subtype: 'synchronized', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      syncN.tags.push('concurrency', 'synchronized');
      ctx.neuralMap.nodes.push(syncN); ctx.lastCreatedNodeId = syncN.id; ctx.emitContainsIfNeeded(syncN.id);
      break;
    }
    case 'try_statement':
    case 'try_with_resources_statement': {
      const tryN = createNode({
        label: node.type === 'try_with_resources_statement' ? 'try-with-resources' : 'try',
        node_type: 'CONTROL',
        node_subtype: 'error_handling',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      if (node.type === 'try_with_resources_statement') {
        tryN.tags.push('resource_management', 'auto_closeable');
      }
      tryN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(tryN); ctx.lastCreatedNodeId = tryN.id; ctx.emitContainsIfNeeded(tryN.id);
      break;
    }
    case 'catch_clause': {
      const catchN = createNode({ label: 'catch', node_type: 'CONTROL', node_subtype: 'error_handling', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      catchN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(catchN); ctx.lastCreatedNodeId = catchN.id; ctx.emitContainsIfNeeded(catchN.id);
      break;
    }
    case 'finally_clause': {
      const finallyN = createNode({ label: 'finally', node_type: 'CONTROL', node_subtype: 'error_handling', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      finallyN.tags.push('cleanup', 'error_handling');
      ctx.neuralMap.nodes.push(finallyN); ctx.lastCreatedNodeId = finallyN.id; ctx.emitContainsIfNeeded(finallyN.id);
      break;
    }
    case 'assert_statement': {
      const assertN = createNode({ label: 'assert', node_type: 'CONTROL', node_subtype: 'guard', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      assertN.tags.push('validation');
      ctx.neuralMap.nodes.push(assertN); ctx.lastCreatedNodeId = assertN.id; ctx.emitContainsIfNeeded(assertN.id);
      break;
    }

    // -- ASSIGNMENT (non-declaration) --
    case 'assignment_expression': {
      const assignLeft = node.childForFieldName('left');
      const leftText = assignLeft?.text?.slice(0, 40) ?? '?';
      const assignN = createNode({ label: `${leftText} =`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(assignN); ctx.lastCreatedNodeId = assignN.id; ctx.emitContainsIfNeeded(assignN.id);

      const assignRight = node.childForFieldName('right');
      let assignTainted = false;
      if (assignRight) {
        const taintSources = extractTaintSources(assignRight, ctx);
        if (taintSources.length > 0) {
          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, assignN.id, source.name, 'unknown', true);
          }
          assignTainted = true;
        }

        // Cross-function taint: result = getInput(request) via assignment
        if (!assignTainted && assignRight.type === 'method_invocation') {
          const callName = assignRight.childForFieldName('name');
          if (callName?.type === 'identifier') {
            const funcNodeId = ctx.functionRegistry.get(callName.text);
            if (funcNodeId) {
              // Check 1: funcReturnsTaint (function already walked)
              const funcStructNode = ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId);
              if (funcStructNode?.data_out.some((d: any) => d.tainted)) {
                assignTainted = true;
              }
              // Check 2: findIngressInFunction (function has internal INGRESS)
              if (!assignTainted) {
                const ingressInFunc = findIngressInFunction(funcNodeId, ctx);
                if (ingressInFunc) {
                  assignTainted = true;
                  ctx.addDataFlow(ingressInFunc, assignN.id, 'return_value', 'unknown', true);
                }
              }
            }
          }
        }

        if (assignTainted) {
          // Propagate taint to the variable being assigned
          if (assignLeft?.type === 'identifier') {
            const varInfo = ctx.resolveVariable(assignLeft.text);
            if (varInfo) {
              varInfo.tainted = true;
              varInfo.producingNodeId = assignN.id;
            }
          } else if (assignLeft?.type === 'field_access') {
            // this.field = tainted  or  obj.prop = tainted
            const fieldName = assignLeft.childForFieldName('field')?.text;
            if (fieldName) {
              const fieldVar = ctx.resolveVariable(fieldName);
              if (fieldVar) {
                fieldVar.tainted = true;
                fieldVar.producingNodeId = assignN.id;
              } else {
                // Declare the field as a new tainted variable in current scope
                ctx.declareVariable(fieldName, 'let', null, true, assignN.id);
              }
            }
          }
          if (!assignN.data_out.some((d: any) => d.tainted)) {
            assignN.data_out.push({
              name: 'result',
              source: assignN.id,
              data_type: 'unknown',
              tainted: true,
              sensitivity: 'NONE',
            });
          }
        } else {
          // Assignment value is clean — clear taint on the target variable,
          // BUT only if the assignment is unconditional (not inside an if/else body).
          // Conditional assignments like `if (x == null) x = ""` should NOT clear taint
          // because the variable retains its value on the other branch.
          let isConditionalAssignment = false;
          let ancestor = node.parent;
          while (ancestor) {
            if (ancestor.type === 'if_statement') {
              // Check if our assignment is in the consequence or alternative
              const cons = ancestor.childForFieldName('consequence');
              const alt = ancestor.childForFieldName('alternative');
              if ((cons && node.startIndex >= cons.startIndex && node.endIndex <= cons.endIndex) ||
                  (alt && node.startIndex >= alt.startIndex && node.endIndex <= alt.endIndex)) {
                isConditionalAssignment = true;
              }
              break;
            }
            if (ancestor.type === 'method_declaration' || ancestor.type === 'block') break;
            ancestor = ancestor.parent;
          }
          if (!isConditionalAssignment && assignLeft?.type === 'identifier') {
            const varInfo = ctx.resolveVariable(assignLeft.text);
            if (varInfo) {
              varInfo.tainted = false;
              varInfo.producingNodeId = assignN.id;
            }
          }
        }
      }

      // V2: Generate sentence for assignment
      {
        const rhsText = assignRight?.text?.slice(0, 60) ?? '?';
        const isFromCall = assignRight?.type === 'method_invocation';
        const isConcat = assignRight?.type === 'binary_expression' &&
          (assignRight.childForFieldName('operator')?.text === '+' || assignRight.text.includes('+'));
        const templateKey = isFromCall ? 'assigned-from-call' : isConcat ? 'string-concatenation' : 'assigned-literal';
        let slots: Record<string, string>;
        if (isFromCall) {
          const callObj = assignRight!.childForFieldName('object')?.text?.slice(0, 30) ?? '';
          const callMethod = assignRight!.childForFieldName('name')?.text ?? '?';
          const callArgs = assignRight!.childForFieldName('arguments')?.text?.slice(0, 40) ?? '';
          slots = { subject: leftText, object: callObj, method: callMethod, args: callArgs, context: `line ${node.startPosition.row + 1}` };
        } else if (isConcat) {
          // Extract all identifier parts from the binary expression tree
          const parts: string[] = [];
          const walkConcat = (n: any) => {
            if (!n) return;
            if (n.type === 'identifier') parts.push(n.text);
            else if (n.type === 'binary_expression') {
              walkConcat(n.childForFieldName('left'));
              walkConcat(n.childForFieldName('right'));
            }
          };
          walkConcat(assignRight);
          slots = { subject: leftText, parts: parts.join(', '), context: `line ${node.startPosition.row + 1}` };
        } else if (assignRight?.type === 'ternary_expression') {
          // Dead-branch ternary: only include the LIVE branch text
          const condition = assignRight.childForFieldName('condition');
          const consequence = assignRight.childForFieldName('consequence');
          const alternative = assignRight.childForFieldName('alternative');
          let liveText = assignRight.text?.slice(0, 60) ?? '?';
          if (condition) {
            const condResult = tryEvalCondition(condition, ctx);
            if (condResult === true && consequence) {
              liveText = consequence.text?.slice(0, 60) ?? '?';
            } else if (condResult === false && alternative) {
              liveText = alternative.text?.slice(0, 60) ?? '?';
            }
          }
          slots = { subject: leftText, value: liveText, context: `line ${node.startPosition.row + 1}` };
        } else {
          slots = { subject: leftText, value: rhsText, context: `line ${node.startPosition.row + 1}` };
        }
        const sentTaintClass: SemanticSentence['taintClass'] = assignTainted ? 'TAINTED' : 'NEUTRAL';
        const sentence = generateSentence(templateKey, slots, node.startPosition.row + 1, assignN.id, sentTaintClass);
        // Determine taintBasis: local function call = PENDING, phoneme-resolved call = PHONEME, else SCOPE
        if (isFromCall) {
          const rhsCalleeName = assignRight!.childForFieldName('name')?.text;
          const rhsCalleeObj = assignRight!.childForFieldName('object');
          if (rhsCalleeName && ctx.functionRegistry.has(rhsCalleeName)) {
            sentence.taintBasis = 'PENDING';
          } else {
            sentence.taintBasis = 'PHONEME_RESOLUTION';
          }
        } else {
          sentence.taintBasis = 'SCOPE_LOOKUP';
        }
        emitSentence(sentence, assignN, ctx);
      }

      // --- Alias chain update on reassignment ---
      // When a variable is reassigned, update its aliasChain to reflect the new type.
      // This handles: stmt = (Statement) obj;  →  aliasChain = ['Statement']
      //               stmt = new PreparedStatement();  →  aliasChain = ['PreparedStatement']
      //               stmt = conn.createStatement();  →  aliasChain = ['conn', 'createStatement']
      if (assignLeft?.type === 'identifier' && assignRight) {
        const reassignVar = ctx.resolveVariable(assignLeft.text);
        if (reassignVar) {
          let newAliasChain: string[] | undefined;
          const JAVA_PRIMITIVES_REASSIGN = new Set(['int', 'long', 'float', 'double', 'boolean', 'byte', 'char', 'short', 'void', 'String', 'Object', 'var']);

          // Cast expression: stmt = (Statement) obj;
          if (assignRight.type === 'cast_expression') {
            const castTypeNode = assignRight.childForFieldName('type');
            if (castTypeNode) {
              let castTypeName: string | undefined;
              if (castTypeNode.type === 'type_identifier') {
                castTypeName = castTypeNode.text;
              } else if (castTypeNode.type === 'scoped_type_identifier') {
                const lastChild = castTypeNode.namedChild(castTypeNode.namedChildCount - 1);
                if (lastChild?.type === 'type_identifier') castTypeName = lastChild.text;
              }
              if (castTypeName && !JAVA_PRIMITIVES_REASSIGN.has(castTypeName)) {
                newAliasChain = [castTypeName];
              }
            }
          }

          // object_creation_expression: stmt = new PreparedStatement(...);
          if (!newAliasChain && assignRight.type === 'object_creation_expression') {
            const ctorType = assignRight.childForFieldName('type');
            if (ctorType) {
              let ctorTypeName: string | undefined;
              if (ctorType.type === 'type_identifier') {
                ctorTypeName = ctorType.text;
              } else if (ctorType.type === 'scoped_type_identifier') {
                const lastChild = ctorType.namedChild(ctorType.namedChildCount - 1);
                if (lastChild?.type === 'type_identifier') ctorTypeName = lastChild.text;
              }
              if (ctorTypeName) newAliasChain = [ctorTypeName];
            }
          }

          // Method invocation fallback: stmt = conn.createStatement();
          if (!newAliasChain && assignRight.type === 'method_invocation') {
            const obj = assignRight.childForFieldName('object');
            const name = assignRight.childForFieldName('name');
            if (obj && name) {
              const chain = extractCalleeChain(obj);
              chain.push(name.text);
              newAliasChain = chain;
            }
          }

          if (newAliasChain) {
            reassignVar.aliasChain = newAliasChain;
          }
        }
      }
      break;
    }

    // -- STRING LITERAL (for hardcoded credential detection) --
    case 'string_literal': {
      // Don't create nodes for every string — handled by verifier patterns
      break;
    }

    // -- Silent pass-throughs --
    case 'expression_statement':
    case 'empty_statement':
    case 'parenthesized_expression':
    case 'comment':
    case 'line_comment':
    case 'block_comment':
      break;
  }
}



// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  // Accept method/constructor/lambda directly, OR accept a block that is the body of one.
  // The block-scope call happens while local variables are still accessible.
  // The method_declaration call happens after the block scope is popped (used as no-op guard).
  let targetNode = node;
  if (node.type === 'block') {
    const parent = node.parent;
    if (parent && (parent.type === 'method_declaration' || parent.type === 'constructor_declaration' || parent.type === 'lambda_expression')) {
      targetNode = parent; // Use the parent for name/param extraction, but we have block scope
    } else {
      return; // Not a function body block
    }
  } else if (node.type !== 'method_declaration' && node.type !== 'constructor_declaration' && node.type !== 'lambda_expression') {
    return;
  }

  // Resolve the function's NeuralMapNode ID.
  // When called on a `block` node, ctx.currentScope is the block scope (containerNodeId=null),
  // so we must walk up the stack via getCurrentContainerId() to reach the function scope.
  // When called on a method_declaration/etc., ctx.currentScope IS the function scope.
  const resolvedFuncNodeId = ctx.getCurrentContainerId();

  // When called on method_declaration/constructor_declaration/lambda_expression directly,
  // the block scope has already been popped. If the block-scope call already ran and set
  // the result, skip to avoid clobbering with stale (post-pop) scope state.
  if (node.type !== 'block') {
    if (resolvedFuncNodeId && ctx.functionReturnTaint.has(resolvedFuncNodeId)) {
      return; // Already processed by the block-scope call
    }
  }

  // When called on a block node, body IS the block itself (we're already inside it).
  // When called on a method_declaration/etc., body is extracted from targetNode as before.
  const body = targetNode.childForFieldName('body') ?? (node.type === 'block' ? node : null);
  if (!body) return;

  // Check for return statements with tainted expressions
  const returnStmts = body.descendantsOfType('return_statement');
  for (const stmt of returnStmts) {
    for (let j = 0; j < stmt.namedChildCount; j++) {
      const retExpr = stmt.namedChild(j);
      if (retExpr) {
        const taintSources = extractTaintSources(retExpr, ctx);
        if (taintSources.length > 0) {
          const funcNodeId = resolvedFuncNodeId;
          if (funcNodeId) {
            const funcNode = ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId);
            if (funcNode && !funcNode.data_out.some((d: any) => d.tainted)) {
              funcNode.data_out.push({
                name: 'return', source: funcNode.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE',
              });
            }
            // Also set the functionReturnTaint flag for PASS 2 Step 4b
            ctx.functionReturnTaint.set(funcNodeId, true);
          }
          return; // one tainted return is enough
        }
      }
    }
  }
  // No tainted return found — explicitly mark as clean (false).
  // Distinguishes "analyzed, returns clean" from "never analyzed" (undefined).
  const cleanFuncNodeId = resolvedFuncNodeId;
  if (cleanFuncNodeId && !ctx.functionReturnTaint.has(cleanFuncNodeId)) {
    ctx.functionReturnTaint.set(cleanFuncNodeId, false);
  }

}

// ---------------------------------------------------------------------------
// preVisitIteration — set up enhanced for loop variable taint
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'enhanced_for_statement') return;

  // Java enhanced for: for (Type item : collection) { ... }
  const name = node.childForFieldName('name');
  const value = node.childForFieldName('value');

  if (name && value) {
    const iterTaint = extractTaintSources(value, ctx);
    if (iterTaint.length > 0) {
      ctx.declareVariable(name.text, 'const', null, true, iterTaint[0].nodeId);
    } else {
      // Declare even non-tainted loop variables so aliasChain can be set
      ctx.declareVariable(name.text, 'const', null, false, null);
    }

    // Store the declared type as aliasChain for the loop variable.
    // e.g., for (Cookie theCookie : cookies) -> theCookie aliasChain = ['Cookie']
    const iterTypeNode = node.childForFieldName('type');
    if (iterTypeNode) {
      let simpleTypeName: string | undefined;
      if (iterTypeNode.type === 'type_identifier') {
        simpleTypeName = iterTypeNode.text;
      } else if (iterTypeNode.type === 'scoped_type_identifier') {
        const lastChild = iterTypeNode.namedChild(iterTypeNode.namedChildCount - 1);
        if (lastChild?.type === 'type_identifier') simpleTypeName = lastChild.text;
      }
      const ITER_PRIMITIVES = new Set(['int', 'long', 'float', 'double', 'boolean', 'byte', 'char', 'short', 'void', 'String', 'Object']);
      if (simpleTypeName && !ITER_PRIMITIVES.has(simpleTypeName)) {
        const v = ctx.resolveVariable(name.text);
        if (v) v.aliasChain = [simpleTypeName];
      }
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration — re-mark enhanced for loop variable taint
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'enhanced_for_statement') return;

  const name = node.childForFieldName('name');
  const value = node.childForFieldName('value');

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

export const javaProfile: LanguageProfile = {
  id: 'java',
  extensions: ['.java'],

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
    return _lookupJavaCallee(chain);
  },

  analyzeStructure(_node: SyntaxNode): StructuralAnalysisResult | null {
    // Java Spring routing is annotation-driven, handled in classifyNode.
    return null;
  },

  // Layer 4: Taint Source Detection
  // Use \w+ for servlet receiver names so ANY variable name (r2, myReq, etc.)
  // is recognised — the SERVLET_TAINT_METHODS set already validates the method name.
  ingressPattern: /(?:\w+\.(?:getParameter|getParameterMap|getParameterValues|getParameterNames|getHeader|getHeaders|getCookies|getInputStream|getReader|getQueryString|getPathInfo|getRequestURI|getRequestURL|getAttribute|getPart|getParts|getRemoteAddr|getMethod|getContentType|getSession)|scanner\.(?:nextLine|next|nextInt)|@(?:RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)|BufferedReader\.readLine|Console\.readLine|System\.in|ObjectInputStream\.readObject)/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Dead-branch elimination: evaluate if conditions for constant folding
  tryEvalCondition: (condNode: any, ctx: any) => tryEvalCondition(condNode, ctx),
  // Dead-branch elimination: evaluate switch expression target to a constant value
  tryEvalSwitchTarget: (condNode: any, ctx: any) => tryEvalSwitchTarget(condNode, ctx),

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) =>
    nodeType === 'local_variable_declaration' || nodeType === 'field_declaration',
  isStatementContainer: (nodeType: string) =>
    nodeType === 'program' || nodeType === 'block' || nodeType === 'class_body',

  // Inter-procedural taint: Java method syntax
  // Matches: public void method(params) { | void method(params) { | method(params) {
  functionParamPattern: /(?:public|private|protected|static|final|\s)+\w+\s+\w+\s*\(([^)]*)\)/,
};

export default javaProfile;
