/**
 * KotlinProfile — the ninth LanguageProfile implementation.
 *
 * Every piece of Kotlin-specific logic lives here: AST node type names (from
 * tree-sitter-kotlin grammar), navigation expressions, scope rules, callee
 * resolution via the Kotlin phoneme dictionary, taint extraction, and node
 * classification.
 *
 * Key differences from Java:
 *   - `function_declaration` (Kotlin has top-level functions, unlike Java)
 *   - `call_expression` (children: expression, type_arguments?, value_arguments, annotated_lambda?)
 *   - `navigation_expression` instead of `field_access` (children: expression, `.`, identifier)
 *   - `property_declaration` with `val`/`var` instead of local_variable_declaration
 *   - `class_declaration` with `modifiers` child (data, sealed, etc.)
 *   - `object_declaration` for singletons, `companion_object` for companion objects
 *   - `lambda_literal` (Kotlin's { arg -> body } syntax)
 *   - `when_expression` (Kotlin's pattern matching / switch)
 *   - `if_expression` (expressions, not statements)
 *   - `string_literal` with `interpolation` children (taint vectors!)
 *   - `annotation` uses `@` + `user_type` pattern
 *   - `for_statement` (for ... in ...) — no enhanced_for distinction
 *   - `secondary_constructor` for secondary constructors
 *   - `import` not `import_declaration`
 *   - `source_file` is the root node (not `program`)
 *   - `return_expression` not `return_statement`
 *   - `throw_expression` not `throw_statement`
 *   - Modifiers include `suspend`, `data`, `sealed`, `open`, `override`
 *
 * tree-sitter-kotlin grammar: @tree-sitter-grammars/tree-sitter-kotlin
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
import { lookupCallee as _lookupKotlinCallee } from '../languages/kotlin.js';
import { isNeutralizingSubtype } from '../properties/neutralizers.js';
import { extractStorageMetadata } from '../extractStorageMetadata.js';

// ---------------------------------------------------------------------------
// Anti-evasion: constant folding for Kotlin
// Attackers split dangerous strings across concatenation, StringBuilder,
// String.format, and byteArrayOf to dodge static analysis. We fold them back.
// ---------------------------------------------------------------------------

function resolveKotlinEscapes(s: string): string {
  return s
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\\\/g, '\\');
}

function tryFoldConstant(n: SyntaxNode): string | null {
  // String literals: "eval" → eval
  // tree-sitter-kotlin: string_literal wraps line_string_literal or multi_line_string_literal
  if (n.type === 'string_literal' || n.type === 'line_string_literal') {
    const raw = n.text.replace(/^"|"$/g, '');
    return resolveKotlinEscapes(raw);
  }
  if (n.type === 'multiline_string_literal') {
    return n.text.replace(/^"""|"""$/g, '');
  }
  // Character literals: 'e' → e
  if (n.type === 'character_literal') {
    const raw = n.text.replace(/^'|'$/g, '');
    return resolveKotlinEscapes(raw);
  }
  // Integer literals
  if (n.type === 'integer_literal') {
    return n.text;
  }
  // Hex literal
  if (n.type === 'hex_literal') {
    return String(parseInt(n.text.replace(/^0[xX]/, ''), 16));
  }
  // Additive expression / binary expression: "ev" + "al" → "eval"
  // In tree-sitter-kotlin, binary + is an additive_expression
  if (n.type === 'additive_expression') {
    // Children: left, operator (+/-), right
    const children: SyntaxNode[] = [];
    for (let i = 0; i < n.namedChildCount; i++) {
      const child = n.namedChild(i);
      if (child) children.push(child);
    }
    if (children.length >= 2) {
      // Check if there's a '+' between them
      let hasPlus = false;
      for (let i = 0; i < n.childCount; i++) {
        const child = n.child(i);
        if (child?.type === '+') { hasPlus = true; break; }
      }
      if (!hasPlus) {
        // Check text for + operator
        hasPlus = n.text.includes('+');
      }
      if (hasPlus) {
        const lv = tryFoldConstant(children[0]);
        const rv = tryFoldConstant(children[children.length - 1]);
        if (lv !== null && rv !== null) return lv + rv;
      }
    }
  }
  // Parenthesized expression
  if (n.type === 'parenthesized_expression') {
    const inner = n.namedChild(0);
    return inner ? tryFoldConstant(inner) : null;
  }
  // if expression used as ternary: if (cond) "a" else "a" → "a"
  if (n.type === 'if_expression') {
    // children: condition, consequence, else branch
    const namedChildren: SyntaxNode[] = [];
    for (let i = 0; i < n.namedChildCount; i++) {
      const child = n.namedChild(i);
      if (child) namedChildren.push(child);
    }
    // In Kotlin if-expression: condition, thenBranch, elseBranch
    if (namedChildren.length >= 3) {
      const cv = tryFoldConstant(namedChildren[1]);
      const av = tryFoldConstant(namedChildren[2]);
      if (cv !== null && av !== null && cv === av) return cv;
    }
  }
  // ── CALL EXPRESSIONS that produce constant strings ──
  if (n.type === 'call_expression') {
    const callee = n.namedChild(0);
    // Get value_arguments
    let argsNode: SyntaxNode | null = null;
    for (let i = 0; i < n.namedChildCount; i++) {
      const child = n.namedChild(i);
      if (child?.type === 'value_arguments') { argsNode = child; break; }
    }

    if (callee?.type === 'navigation_expression' && argsNode) {
      const children: SyntaxNode[] = [];
      for (let i = 0; i < callee.namedChildCount; i++) {
        const ch = callee.namedChild(i);
        if (ch) children.push(ch);
      }
      const obj = children[0];
      const member = children[children.length - 1];
      if (obj && member?.type === 'identifier') {
        // StringBuilder().append("ev").append("al").toString()
        if (member.text === 'toString' && obj.type === 'call_expression') {
          const folded = tryFoldKotlinStringBuilderChain(obj);
          if (folded !== null) return folded;
        }
        // String.format("%s%s", "ev", "al")
        if (member.text === 'format' && obj.type === 'identifier' && obj.text === 'String') {
          return tryFoldKotlinStringFormat(argsNode);
        }
        // "ev".plus("al")
        if (member.text === 'plus') {
          const lv = tryFoldConstant(obj);
          const firstArg = extractFirstValueArg(argsNode);
          const rv = firstArg ? tryFoldConstant(firstArg) : null;
          if (lv !== null && rv !== null) return lv + rv;
        }
      }
    }

    // buildString { append("ev"); append("al") } — too complex for now, skip
    // byteArrayOf(101, 118, 97, 108).toString(Charsets.UTF_8)
    if (callee?.type === 'navigation_expression' && argsNode) {
      const children: SyntaxNode[] = [];
      for (let i = 0; i < callee.namedChildCount; i++) {
        const ch = callee.namedChild(i);
        if (ch) children.push(ch);
      }
      const obj = children[0];
      const member = children[children.length - 1];
      if (member?.type === 'identifier' && member.text === 'toString' && obj?.type === 'call_expression') {
        // Check if inner is byteArrayOf(...)
        const innerCallee = obj.namedChild(0);
        if (innerCallee?.type === 'identifier' && innerCallee.text === 'byteArrayOf') {
          let innerArgs: SyntaxNode | null = null;
          for (let i = 0; i < obj.namedChildCount; i++) {
            const ch = obj.namedChild(i);
            if (ch?.type === 'value_arguments') { innerArgs = ch; break; }
          }
          if (innerArgs) {
            const codes: number[] = [];
            let allLiteral = true;
            for (let i = 0; i < innerArgs.namedChildCount; i++) {
              const arg = innerArgs.namedChild(i);
              const argExpr = arg?.type === 'value_argument' ? arg.namedChild(0) : arg;
              if (argExpr) {
                const v = tryFoldConstant(argExpr);
                if (v !== null) {
                  const num = parseInt(v, 10);
                  if (!isNaN(num)) { codes.push(num); continue; }
                }
              }
              allLiteral = false;
              break;
            }
            if (allLiteral && codes.length > 0) {
              return String.fromCharCode(...codes);
            }
          }
        }
      }
    }
  }
  return null;
}

/** Extract the first value_argument's inner expression from value_arguments */
function extractFirstValueArg(argsNode: SyntaxNode): SyntaxNode | null {
  const firstArg = argsNode.namedChild(0);
  if (!firstArg) return null;
  return firstArg.type === 'value_argument' ? firstArg.namedChild(0) : firstArg;
}

/** Fold Kotlin StringBuilder chain: .append("ev").append("al") → "eval" */
function tryFoldKotlinStringBuilderChain(node: SyntaxNode): string | null {
  const parts: string[] = [];
  let current: SyntaxNode | null = node;

  while (current?.type === 'call_expression') {
    const callee = current.namedChild(0);
    let argsNode: SyntaxNode | null = null;
    for (let i = 0; i < current.namedChildCount; i++) {
      const ch = current.namedChild(i);
      if (ch?.type === 'value_arguments') { argsNode = ch; break; }
    }

    if (callee?.type === 'navigation_expression') {
      const children: SyntaxNode[] = [];
      for (let i = 0; i < callee.namedChildCount; i++) {
        const ch = callee.namedChild(i);
        if (ch) children.push(ch);
      }
      const obj = children[0];
      const member = children[children.length - 1];

      if (member?.type === 'identifier' && member.text === 'append' && argsNode) {
        const firstArg = extractFirstValueArg(argsNode);
        if (firstArg) {
          const v = tryFoldConstant(firstArg);
          if (v !== null) {
            parts.unshift(v);
          } else {
            return null;
          }
        }
        current = obj ?? null;
      } else {
        break;
      }
    } else if (callee?.type === 'identifier' && callee.text === 'StringBuilder') {
      // Constructor call: StringBuilder()
      if (argsNode && argsNode.namedChildCount > 0) {
        const initArg = extractFirstValueArg(argsNode);
        if (initArg) {
          const initVal = tryFoldConstant(initArg);
          if (initVal !== null) parts.unshift(initVal);
          else return null;
        }
      }
      return parts.join('');
    } else {
      break;
    }
  }
  return null;
}

/** Fold Kotlin String.format("%s%s", "ev", "al") → "eval" */
function tryFoldKotlinStringFormat(argsNode: SyntaxNode): string | null {
  if (argsNode.namedChildCount < 2) return null;
  const fmtArg = extractFirstValueArg(argsNode);
  if (!fmtArg) return null;
  const fmt = tryFoldConstant(fmtArg);
  if (fmt === null) return null;

  const placeholders = fmt.match(/%s/g);
  if (!placeholders) return null;

  // Collect remaining args
  const values: string[] = [];
  for (let i = 1; i < argsNode.namedChildCount; i++) {
    const arg = argsNode.namedChild(i);
    const argExpr = arg?.type === 'value_argument' ? arg?.namedChild(0) : arg;
    if (!argExpr) return null;
    const v = tryFoldConstant(argExpr);
    if (v === null) return null;
    values.push(v);
  }

  if (placeholders.length !== values.length) return null;

  let result = fmt;
  for (const v of values) {
    result = result.replace('%s', v);
  }
  return result;
}

// ---------------------------------------------------------------------------
// AST Node Type Sets (tree-sitter-kotlin)
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'function_declaration',
  'anonymous_function',
  'lambda_literal',
  'secondary_constructor',
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'for_statement',
  'while_statement',
  'do_while_statement',
  'if_expression',
  'when_expression',
  'when_entry',
  'try_expression',
  'catch_block',
  'finally_block',
  'block',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'class_declaration',
  'object_declaration',
  'companion_object',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'property_declaration',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'function_declaration',
  'anonymous_function',
]);

// Tainted paths for Kotlin Ktor/Spring/Android request objects
const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // Ktor
  'call.receive', 'call.receiveText', 'call.parameters',
  'call.request.headers', 'call.request.queryParameters',
  'call.request.cookies', 'call.request.uri',
  'call.receiveMultipart', 'incoming.receive',
  // Spring Boot (Kotlin)
  'request.getParameter', 'request.getHeader', 'request.body',
  // Android
  'intent.getStringExtra', 'intent.data', 'intent.extras',
]);

// Spring/Ktor taint annotations on parameters
const KOTLIN_TAINT_ANNOTATIONS: ReadonlySet<string> = new Set([
  'RequestBody', 'PathVariable', 'RequestParam',
  'RequestHeader', 'CookieValue', 'ModelAttribute',
  'RequestPart',
]);

// Kotlin route annotations (Spring)
const KOTLIN_ROUTE_ANNOTATIONS: ReadonlySet<string> = new Set([
  'RequestMapping', 'GetMapping', 'PostMapping',
  'PutMapping', 'DeleteMapping', 'PatchMapping',
]);

// Kotlin security annotations
const KOTLIN_SECURITY_ANNOTATIONS: ReadonlySet<string> = new Set([
  'PreAuthorize', 'Secured', 'RolesAllowed',
]);

// Validation annotations
const VALIDATION_ANNOTATIONS: ReadonlySet<string> = new Set([
  'Valid', 'NotNull', 'NotBlank', 'NotEmpty',
  'Size', 'Min', 'Max', 'Pattern', 'Email',
]);

// Conventional request parameter names in Kotlin handlers
const KOTLIN_REQUEST_PARAM_NAMES: ReadonlySet<string> = new Set([
  'request', 'req', 'call', 'httpRequest',
]);

// Response parameter names
const KOTLIN_RESPONSE_PARAM_NAMES: ReadonlySet<string> = new Set([
  'response', 'resp', 'httpResponse',
]);

// Types that represent user-controllable input when used as function parameters.
// When a public/internal function takes a parameter of one of these types,
// the parameter should be treated as a taint source (potential user input).
const TAINTABLE_PARAM_TYPES: ReadonlySet<string> = new Set([
  'String', 'String?', 'ByteArray', 'ByteArray?',
  'Any', 'Any?', 'CharSequence', 'CharSequence?',
]);

// Function names that should NOT have their params auto-tainted
// (utility functions, constructors, lifecycle hooks, etc.)
const UNTAINTABLE_FUNCTION_NAMES: ReadonlySet<string> = new Set([
  'main', 'toString', 'hashCode', 'equals', 'compareTo',
  'init', 'onCreate', 'onDestroy', 'onStart', 'onStop',
  'onResume', 'onPause', 'invoke', 'apply', 'run',
  'let', 'also', 'with', 'takeIf', 'takeUnless',
]);

// ---------------------------------------------------------------------------
// Helper: extract callee chain from Kotlin AST nodes
// ---------------------------------------------------------------------------

/**
 * Extract the callee chain from a Kotlin expression.
 * Handles:
 *   - identifier: `foo` -> ['foo']
 *   - navigation_expression: `call.receive` -> ['call', 'receive']
 *   - call_expression chains: `obj.method().chain()` -> resolves terminal
 */
function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier') {
    return [node.text];
  }

  if (node.type === 'navigation_expression') {
    // children: expression, '.', identifier
    // The first named child is the object expression, the last named child is the member identifier
    const children: SyntaxNode[] = [];
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) children.push(child);
    }
    // In navigation_expression: first named child = object, last named child = member
    if (children.length >= 2) {
      const obj = children[0];
      const member = children[children.length - 1];
      if (member.type === 'identifier') {
        const chain = extractCalleeChain(obj);
        chain.push(member.text);
        return chain;
      }
    }
    // Fallback: if only one child
    if (children.length === 1) {
      return extractCalleeChain(children[0]);
    }
  }

  // call_expression: callee(args) — extract callee chain
  if (node.type === 'call_expression') {
    // First named child is the callee expression
    const callee = node.namedChild(0);
    if (callee) {
      return extractCalleeChain(callee);
    }
  }

  // this_expression
  if (node.type === 'this_expression') {
    return ['this'];
  }

  // super_expression
  if (node.type === 'super_expression') {
    return ['super'];
  }

  return [node.text.slice(0, 50)];
}

// ---------------------------------------------------------------------------
// Helper: resolve callee from a call_expression
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  if (node.type !== 'call_expression') return null;

  // call_expression children: expression (callee), type_arguments?, value_arguments, annotated_lambda?
  const callee = node.namedChild(0);
  if (!callee) return null;

  if (callee.type === 'navigation_expression') {
    // obj.method(args)
    const chain = extractCalleeChain(callee);
    const pattern = _lookupKotlinCallee(chain);
    if (pattern) {
      return {
        nodeType: pattern.nodeType,
        subtype: pattern.subtype,
        tainted: pattern.tainted,
        chain,
      };
    }

    // ── Anti-evasion: Class.forName with constant-folded argument ──
    // Class.forName("ev" + "al") or Class.forName(constructed).kotlin → reflection
    const navChildren: SyntaxNode[] = [];
    for (let i = 0; i < callee.namedChildCount; i++) {
      const ch = callee.namedChild(i);
      if (ch) navChildren.push(ch);
    }
    const navObj = navChildren[0];
    const navMember = navChildren[navChildren.length - 1];
    if (navMember?.type === 'identifier' && navMember.text === 'forName' &&
        navObj?.type === 'identifier' && navObj.text === 'Class') {
      let argsNode: SyntaxNode | null = null;
      for (let i = 0; i < node.namedChildCount; i++) {
        const ch = node.namedChild(i);
        if (ch?.type === 'value_arguments') { argsNode = ch; break; }
      }
      const firstArg = argsNode ? extractFirstValueArg(argsNode) : null;
      if (firstArg) {
        const folded = tryFoldConstant(firstArg);
        return {
          nodeType: 'EXTERNAL',
          subtype: 'reflection',
          tainted: folded === null,
          chain: ['Class', 'forName'],
        };
      }
    }

    // ── Anti-evasion: .invoke() — reflective invocation ──
    if (navMember?.type === 'identifier' && navMember.text === 'invoke') {
      const objChain = navObj ? extractCalleeChain(navObj) : [];
      if (objChain.some(p => p === 'getMethod' || p === 'getDeclaredMethod' || p === 'java' || p === 'javaClass')) {
        return {
          nodeType: 'EXTERNAL',
          subtype: 'reflection',
          tainted: true,
          chain: [...objChain, 'invoke'],
        };
      }
    }

    return null;
  }

  if (callee.type === 'identifier') {
    // Direct call: println(x), readLine()
    const chain = [callee.text];
    const pattern = _lookupKotlinCallee(chain);
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

  // call_expression chained: obj.method().chain() — the callee is another call_expression
  if (callee.type === 'call_expression') {
    const chain = extractCalleeChain(callee);
    // Add final method from navigation if present
    const pattern = _lookupKotlinCallee(chain);
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

// ---------------------------------------------------------------------------
// resolvePropertyAccess — resolve a Kotlin navigation_expression (non-call)
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  if (node.type !== 'navigation_expression') return null;

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
  const pattern = _lookupKotlinCallee(chain);
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
// extractPatternNames — Kotlin has destructuring declarations
// ---------------------------------------------------------------------------

function extractPatternNames(pattern: SyntaxNode): string[] {
  const names: string[] = [];

  if (pattern.type === 'identifier') {
    names.push(pattern.text);
  }

  // variable_declaration: val x  (identifier child)
  if (pattern.type === 'variable_declaration') {
    for (let i = 0; i < pattern.namedChildCount; i++) {
      const child = pattern.namedChild(i);
      if (child?.type === 'identifier') {
        names.push(child.text);
        break;
      }
    }
  }

  // multi_variable_declaration: val (a, b) = pair
  if (pattern.type === 'multi_variable_declaration') {
    for (let i = 0; i < pattern.namedChildCount; i++) {
      const child = pattern.namedChild(i);
      if (child?.type === 'variable_declaration') {
        names.push(...extractPatternNames(child));
      }
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
// Helper: extract annotation name from Kotlin annotation node
// ---------------------------------------------------------------------------

function getAnnotationName(node: SyntaxNode): string {
  // Kotlin annotation: @AnnotationName or @AnnotationName(args)
  // AST: annotation -> '@', user_type -> identifier
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child?.type === 'user_type') {
      // user_type -> identifier
      for (let j = 0; j < child.namedChildCount; j++) {
        const id = child.namedChild(j);
        if (id?.type === 'identifier') return id.text;
      }
      return child.text;
    }
    if (child?.type === 'constructor_invocation') {
      // constructor_invocation -> user_type -> identifier
      for (let j = 0; j < child.namedChildCount; j++) {
        const ut = child.namedChild(j);
        if (ut?.type === 'user_type') {
          for (let k = 0; k < ut.namedChildCount; k++) {
            const id = ut.namedChild(k);
            if (id?.type === 'identifier') return id.text;
          }
          return ut.text;
        }
      }
    }
  }
  return node.text.replace(/@/, '');
}

// ---------------------------------------------------------------------------
// Helper: check if a parameter has a Spring taint annotation
// ---------------------------------------------------------------------------

function paramHasTaintAnnotation(paramNode: SyntaxNode): boolean {
  // In Kotlin, annotations on parameters are in a `modifiers` child or preceding annotation nodes
  const modifiers = paramNode.namedChild(0)?.type === 'modifiers'
    ? paramNode.namedChild(0)
    : null;

  if (modifiers) {
    for (let i = 0; i < modifiers.namedChildCount; i++) {
      const mod = modifiers.namedChild(i);
      if (mod?.type === 'annotation') {
        const annotName = getAnnotationName(mod);
        if (KOTLIN_TAINT_ANNOTATIONS.has(annotName)) return true;
      }
    }
  }

  // Check direct children of parameter for annotations
  for (let i = 0; i < paramNode.namedChildCount; i++) {
    const child = paramNode.namedChild(i);
    if (child?.type === 'annotation') {
      const annotName = getAnnotationName(child);
      if (KOTLIN_TAINT_ANNOTATIONS.has(annotName)) return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Helper: check if a function has a Spring route annotation
// ---------------------------------------------------------------------------

function funcHasRouteAnnotation(funcNode: SyntaxNode): string | null {
  // In tree-sitter-kotlin, modifiers is a child of function_declaration
  for (let i = 0; i < funcNode.namedChildCount; i++) {
    const child = funcNode.namedChild(i);
    if (child?.type === 'modifiers') {
      for (let j = 0; j < child.namedChildCount; j++) {
        const mod = child.namedChild(j);
        if (mod?.type === 'annotation') {
          const annotName = getAnnotationName(mod);
          if (KOTLIN_ROUTE_ANNOTATIONS.has(annotName)) {
            return annotName;
          }
        }
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Helper: check if a function has security annotations
// ---------------------------------------------------------------------------

function funcHasSecurityAnnotation(funcNode: SyntaxNode): boolean {
  for (let i = 0; i < funcNode.namedChildCount; i++) {
    const child = funcNode.namedChild(i);
    if (child?.type === 'modifiers') {
      for (let j = 0; j < child.namedChildCount; j++) {
        const mod = child.namedChild(j);
        if (mod?.type === 'annotation') {
          const annotName = getAnnotationName(mod);
          if (KOTLIN_SECURITY_ANNOTATIONS.has(annotName)) return true;
        }
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helper: check if function has 'suspend' modifier
// ---------------------------------------------------------------------------

function funcIsSuspend(funcNode: SyntaxNode): boolean {
  for (let i = 0; i < funcNode.namedChildCount; i++) {
    const child = funcNode.namedChild(i);
    if (child?.type === 'modifiers') {
      for (let j = 0; j < child.childCount; j++) {
        const mod = child.child(j);
        if (mod && mod.text === 'suspend') return true;
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helper: check class modifiers for data/sealed/annotation
// ---------------------------------------------------------------------------

function getClassModifier(classNode: SyntaxNode): string | null {
  for (let i = 0; i < classNode.namedChildCount; i++) {
    const child = classNode.namedChild(i);
    if (child?.type === 'modifiers') {
      for (let j = 0; j < child.childCount; j++) {
        const mod = child.child(j);
        if (!mod) continue;
        if (mod.type === 'class_modifier') {
          const modText = mod.text;
          if (modText === 'data' || modText === 'sealed' || modText === 'enum' || modText === 'annotation') {
            return modText;
          }
        }
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Helper: get class-level annotation for Spring classification
// ---------------------------------------------------------------------------

function getClassAnnotationSubtype(classNode: SyntaxNode): string {
  for (let i = 0; i < classNode.namedChildCount; i++) {
    const child = classNode.namedChild(i);
    if (child?.type === 'modifiers') {
      for (let j = 0; j < child.namedChildCount; j++) {
        const mod = child.namedChild(j);
        if (mod?.type === 'annotation') {
          const annotName = getAnnotationName(mod);
          if (annotName === 'RestController' || annotName === 'Controller') return 'controller';
          if (annotName === 'Service') return 'service';
          if (annotName === 'Repository') return 'repository';
          if (annotName === 'Component') return 'component';
          if (annotName === 'Entity') return 'entity';
          if (annotName === 'Configuration') return 'config';
        }
      }
    }
  }
  return 'class';
}

// ---------------------------------------------------------------------------
// Helper: get value_arguments from call_expression
// ---------------------------------------------------------------------------

function getValueArguments(node: SyntaxNode): SyntaxNode | null {
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child?.type === 'value_arguments') return child;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Helper: get the trailing lambda (annotated_lambda) from call_expression
// ---------------------------------------------------------------------------

function getTrailingLambda(node: SyntaxNode): SyntaxNode | null {
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child?.type === 'annotated_lambda') return child;
  }
  return null;
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

    // -- Leaf: navigation_expression -- check for tainted paths (call.parameters etc.)
    case 'navigation_expression': {
      const resolution = resolvePropertyAccess(expr);
      if (resolution?.tainted) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'kotlin',
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
      const obj = expr.namedChild(0);
      if (obj?.type === 'identifier') {
        const varInfo = ctx.resolveVariable(obj.text);
        if (varInfo?.tainted && varInfo.producingNodeId) {
          return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
        }
      }
      // Recurse into deeper navigation chains
      if (obj?.type === 'navigation_expression') {
        return extractTaintSources(obj, ctx);
      }
      return [];
    }

    // -- Binary expression: string concatenation ("SELECT " + userInput) --
    case 'binary_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- String literal with interpolation --
    case 'string_literal':
    case 'multiline_string_literal': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child?.type === 'interpolation') {
          // interpolation children: ${...} form
          for (let j = 0; j < child.namedChildCount; j++) {
            const inner = child.namedChild(j);
            if (inner) sources.push(...extractTaintSources(inner, ctx));
          }
        }
      }
      // Handle bare $variable form: tree-sitter-kotlin parses "$name" as
      // string_content("$") + string_content("name..."), NOT as interpolation.
      // Walk ALL children (including anonymous) to find "$" + identifier patterns.
      for (let i = 0; i < expr.childCount - 1; i++) {
        const child = expr.child(i);
        const next = expr.child(i + 1);
        if (child?.type === 'string_content' && child.text === '$' &&
            next?.type === 'string_content') {
          // Extract the identifier from the next string_content.
          // The text may be "username'" or "filename output.mp4" etc.
          // Extract leading identifier chars: [a-zA-Z_][a-zA-Z0-9_]*
          const match = next.text.match(/^([a-zA-Z_]\w*)/);
          if (match) {
            const varName = match[1];
            const varInfo = ctx.resolveVariable(varName);
            if (varInfo?.tainted && varInfo.producingNodeId) {
              sources.push({ nodeId: varInfo.producingNodeId, name: varName });
            }
          }
        }
      }
      return sources;
    }

    // -- Call expression: check if sanitizer, then check args --
    case 'call_expression': {
      const callResolution = resolveCallee(expr);
      // Neutralizing call (sanitize, encode, etc.) stops taint
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          isNeutralizingSubtype(callResolution.subtype)) {
        return [];
      }
      // For any other call, check arguments AND receiver for taint
      const sources: TaintSourceResult[] = [];
      const args = getValueArguments(expr);
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (!arg) continue;
          // value_argument may wrap the expression
          if (arg.type === 'value_argument') {
            for (let j = 0; j < arg.namedChildCount; j++) {
              const inner = arg.namedChild(j);
              if (inner) sources.push(...extractTaintSources(inner, ctx));
            }
          } else {
            sources.push(...extractTaintSources(arg, ctx));
          }
        }
      }
      // Check receiver (object via navigation_expression)
      const callee = expr.namedChild(0);
      if (callee?.type === 'navigation_expression') {
        const obj = callee.namedChild(0);
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

    // -- Parenthesized expression --
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- As expression (cast): x as String --
    case 'as_expression': {
      const value = expr.namedChild(0);
      return value ? extractTaintSources(value, ctx) : [];
    }

    // -- If expression: if (cond) a else b --
    case 'if_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child && child.type !== 'block') {
          sources.push(...extractTaintSources(child, ctx));
        }
      }
      return sources;
    }

    // -- When expression (pattern match) --
    case 'when_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child?.type === 'when_entry') {
          for (let j = 0; j < child.namedChildCount; j++) {
            const inner = child.namedChild(j);
            if (inner) sources.push(...extractTaintSources(inner, ctx));
          }
        }
      }
      return sources;
    }

    // -- Index expression: arr[i] --
    case 'index_expression': {
      const obj = expr.namedChild(0);
      if (obj) return extractTaintSources(obj, ctx);
      return [];
    }

    // -- Spread expression: *array --
    case 'spread_expression': {
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
  if (node.type !== 'property_declaration') return;

  // property_declaration children: modifiers?, val/var, variable_declaration | multi_variable_declaration, =, expression
  let varDeclNode: SyntaxNode | null = null;
  let valueNode: SyntaxNode | null = null;
  let isVal = false;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === 'val') isVal = true;
    if (child.type === 'var') isVal = false;
  }

  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (!child) continue;
    if (child.type === 'variable_declaration' || child.type === 'multi_variable_declaration') {
      varDeclNode = child;
    }
  }

  // Find the value expression: it's the last named child that isn't variable_declaration, modifiers, getter, setter, type etc.
  // The expression comes after the '=' token
  let foundEquals = false;
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === '=') {
      foundEquals = true;
      continue;
    }
    if (foundEquals && child.isNamed) {
      // Skip type annotations and property delegates
      if (child.type !== 'user_type' && child.type !== 'nullable_type' &&
          child.type !== 'parenthesized_type' && child.type !== 'type_modifiers' &&
          child.type !== 'getter' && child.type !== 'setter' &&
          child.type !== 'property_delegate' && child.type !== 'modifiers') {
        valueNode = child;
        break;
      }
    }
  }

  if (!varDeclNode) return;

  const varNames = extractPatternNames(varDeclNode);
  const kind: VariableInfo['kind'] = isVal ? 'const' : 'let';

  for (const varName of varNames) {
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

    // Cross-function taint: val x = getInput(request)
    if (!producingNodeId && valueNode) {
      const checkCallTaint = (expr: SyntaxNode) => {
        if (expr.type === 'call_expression') {
          const callee = expr.namedChild(0);
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
      checkCallTaint(valueNode);
    }

    // Alias chain detection: val stmt = conn.createStatement()
    let aliasChain: string[] | undefined;
    if (valueNode) {
      if (valueNode.type === 'call_expression') {
        const callee = valueNode.namedChild(0);
        if (callee?.type === 'navigation_expression') {
          aliasChain = extractCalleeChain(callee);
        }
      } else if (valueNode.type === 'navigation_expression') {
        aliasChain = extractCalleeChain(valueNode);
      }
    }

    // Constant folding: val action = "quer" + "y" -> constantValue = "query"
    let constantValue: string | undefined;
    if (valueNode) {
      const folded = tryFoldConstant(valueNode);
      if (folded !== null) constantValue = folded;
    }

    ctx.declareVariable(varName, kind, null, tainted, producingNodeId);
    const v = ctx.resolveVariable(varName);
    if (v) {
      if (aliasChain) v.aliasChain = aliasChain;
      if (constantValue) v.constantValue = constantValue;
    }
  }
}

// ---------------------------------------------------------------------------
// processFunctionParams — handle Kotlin function parameters with annotations
// ---------------------------------------------------------------------------

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  // In Kotlin, parameters are in function_value_parameters
  let paramsNode: SyntaxNode | null = null;
  for (let i = 0; i < funcNode.namedChildCount; i++) {
    const child = funcNode.namedChild(i);
    if (child?.type === 'function_value_parameters') {
      paramsNode = child;
      break;
    }
  }

  // lambda_literal has lambda_parameters
  if (!paramsNode) {
    for (let i = 0; i < funcNode.namedChildCount; i++) {
      const child = funcNode.namedChild(i);
      if (child?.type === 'lambda_parameters') {
        paramsNode = child;
        break;
      }
    }
  }

  if (!paramsNode) return;

  // Determine if this function is eligible for auto-taint on String/ByteArray params.
  // A function is eligible when it's a function_declaration that is NOT private and
  // NOT a utility function (toString, equals, main, etc.).
  let funcIsAutoTaintEligible = false;
  if (funcNode.type === 'function_declaration') {
    const funcName = funcNode.childForFieldName('name')?.text ?? '';
    if (!UNTAINTABLE_FUNCTION_NAMES.has(funcName)) {
      // Check if the function has 'private' modifier
      let isPrivate = false;
      for (let i = 0; i < funcNode.namedChildCount; i++) {
        const child = funcNode.namedChild(i);
        if (child?.type === 'modifiers') {
          for (let j = 0; j < child.childCount; j++) {
            const mod = child.child(j);
            if (mod?.type === 'visibility_modifier' && mod.text === 'private') {
              isPrivate = true;
            }
          }
        }
      }
      funcIsAutoTaintEligible = !isPrivate;
    }
  }

  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    if (param.type === 'parameter' || param.type === 'variable_declaration') {
      // parameter children: modifiers?, identifier, ':', type
      let paramName: string | null = null;
      let typeText = '';

      for (let j = 0; j < param.namedChildCount; j++) {
        const child = param.namedChild(j);
        if (!child) continue;
        if (child.type === 'identifier' && !paramName) {
          paramName = child.text;
        }
        if (child.type === 'user_type' || child.type === 'nullable_type') {
          typeText = child.text;
        }
      }

      if (!paramName) continue;

      // Check 1: Spring taint annotations
      const hasTaintAnnotation = paramHasTaintAnnotation(param);

      // Check 2: Conventional request parameter names
      const isRequestName = KOTLIN_REQUEST_PARAM_NAMES.has(paramName);

      // Check 3: Type-based: ApplicationCall, HttpServletRequest, etc.
      const isRequestType = typeText === 'ApplicationCall' || typeText === 'HttpServletRequest' ||
                            typeText === 'ServerRequest' || typeText === 'WebRequest';

      // Check 4: Auto-taint for String/ByteArray params in public functions.
      // Functions in Kotlin services commonly receive user-controlled data as String params.
      // This mirrors how Go marks *http.Request params as tainted — in Kotlin, user input
      // typically arrives as String or ByteArray parameters to service/controller methods.
      const isAutoTaintable = funcIsAutoTaintEligible && TAINTABLE_PARAM_TYPES.has(typeText);

      if (hasTaintAnnotation || isRequestType || isRequestName || isAutoTaintable) {
        const subtype = isAutoTaintable && !isRequestType && !isRequestName && !hasTaintAnnotation
          ? 'function_param'
          : 'http_request';
        const ingressNode = createNode({
          label: paramName,
          node_type: 'INGRESS',
          node_subtype: subtype,
          language: 'kotlin',
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
      } else if (KOTLIN_RESPONSE_PARAM_NAMES.has(paramName)) {
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
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of the switch statement
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  switch (node.type) {
    // -- FUNCTION DECLARATIONS --
    case 'function_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const routeAnnotation = funcHasRouteAnnotation(node);
      const hasSecurityAnnotation = funcHasSecurityAnnotation(node);
      const isSuspend = funcIsSuspend(node);

      const funcN = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: routeAnnotation ? 'route' : 'function',
        language: 'kotlin',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });

      if (routeAnnotation) {
        funcN.tags.push('route', routeAnnotation);
      }
      if (hasSecurityAnnotation) {
        funcN.tags.push('auth_gate');
      }
      if (isSuspend) {
        funcN.tags.push('suspend', 'coroutine');
      }

      ctx.neuralMap.nodes.push(funcN);
      ctx.lastCreatedNodeId = funcN.id;
      ctx.emitContainsIfNeeded(funcN.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = funcN.id;
      ctx.functionRegistry.set(name, funcN.id);
      // Also register with param count to avoid overloading collisions
      const ktParams = node.childForFieldName('value_parameters') ?? node.childForFieldName('parameters');
      const ktParamCount = ktParams ? ktParams.namedChildCount : 0;
      ctx.functionRegistry.set(`${name}:${ktParamCount}`, funcN.id);
      break;
    }

    // -- SECONDARY CONSTRUCTOR --
    case 'secondary_constructor': {
      const ctorNode = createNode({
        label: '<init>',
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'kotlin',
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
      break;
    }

    // -- LAMBDA LITERAL --
    case 'lambda_literal': {
      let lambdaName = 'lambda';
      // Try to get name from parent property_declaration
      if (node.parent?.type === 'property_declaration') {
        for (let i = 0; i < node.parent.namedChildCount; i++) {
          const child = node.parent.namedChild(i);
          if (child?.type === 'variable_declaration') {
            const id = child.namedChild(0);
            if (id?.type === 'identifier') {
              lambdaName = id.text;
            }
          }
        }
      }
      // Also check if parent is annotated_lambda inside a call_expression
      if (node.parent?.type === 'annotated_lambda') {
        // trailing lambda in call — keep 'lambda' name
      }

      const lambdaNode = createNode({
        label: lambdaName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'kotlin',
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

    // -- ANONYMOUS FUNCTION --
    case 'anonymous_function': {
      const anonNode = createNode({
        label: 'anonymous',
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'kotlin',
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
      const classMod = getClassModifier(node);
      let subtype = getClassAnnotationSubtype(node);

      // Override with Kotlin-specific class modifiers
      if (classMod === 'data') subtype = 'data_class';
      else if (classMod === 'sealed') subtype = 'sealed_class';
      else if (classMod === 'enum') subtype = 'enum';
      else if (classMod === 'annotation') subtype = 'annotation_class';

      const classNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: subtype,
        language: 'kotlin',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      if (classMod) {
        classNode.tags.push(classMod);
      }
      ctx.neuralMap.nodes.push(classNode);
      ctx.lastCreatedNodeId = classNode.id;
      ctx.emitContainsIfNeeded(classNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = classNode.id;
      break;
    }

    // -- OBJECT DECLARATION (singleton) --
    case 'object_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousObject';
      const objNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'object',
        language: 'kotlin',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      objNode.tags.push('singleton');
      ctx.neuralMap.nodes.push(objNode);
      ctx.lastCreatedNodeId = objNode.id;
      ctx.emitContainsIfNeeded(objNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = objNode.id;
      break;
    }

    // -- COMPANION OBJECT --
    case 'companion_object': {
      const name = node.childForFieldName('name')?.text ?? 'Companion';
      const compNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'companion_object',
        language: 'kotlin',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      compNode.tags.push('companion');
      ctx.neuralMap.nodes.push(compNode);
      ctx.lastCreatedNodeId = compNode.id;
      ctx.emitContainsIfNeeded(compNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = compNode.id;
      break;
    }

    // -- IMPORT --
    case 'import': {
      // import node: children: 'import', qualified_identifier, '.', '*'?
      let moduleName = '';
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child?.type === 'qualified_identifier') {
          moduleName = child.text;
          break;
        }
      }
      if (!moduleName) moduleName = node.text.replace(/^import\s+/, '').trim();

      const importNode = createNode({
        label: moduleName,
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'kotlin',
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

    // -- PACKAGE HEADER --
    case 'package_header': {
      let pkgName = '';
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child?.type === 'qualified_identifier') {
          pkgName = child.text;
          break;
        }
      }
      if (!pkgName) pkgName = node.text.replace(/^package\s+/, '').trim();

      const pkgNode = createNode({
        label: `package ${pkgName}`,
        node_type: 'STRUCTURAL',
        node_subtype: 'module',
        language: 'kotlin',
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

    // -- CALL EXPRESSION: classify by callee --
    case 'call_expression': {
      const resolution = resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'kotlin',
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
        if (resolution.nodeType === 'EXTERNAL' && resolution.subtype === 'system_exec') {
          n.attack_surface.push('command_injection');
        }
        // Anti-evasion: tag Class.forName and reflection calls, resolve variable constants
        if (resolution.nodeType === 'EXTERNAL' && resolution.subtype === 'reflection') {
          n.tags.push('anti_evasion', 'reflection');
          // Try to resolve the first argument from variable constantValue
          const reflArgs = getValueArguments(node);
          const reflFirstArgWrapper = reflArgs?.namedChild(0);
          const reflFirstArg = reflFirstArgWrapper?.type === 'value_argument'
            ? reflFirstArgWrapper.namedChild(0) : reflFirstArgWrapper;
          if (reflFirstArg?.type === 'identifier') {
            const argVar = ctx.resolveVariable(reflFirstArg.text);
            if (argVar?.constantValue) {
              n.label = `Class.forName("${argVar.constantValue}")`;
              n.tags.push(`resolved:${argVar.constantValue}`);
              n.data_out = n.data_out.filter((d: any) => !d.tainted);
            }
          }
        }
        ctx.neuralMap.nodes.push(n);
        ctx.lastCreatedNodeId = n.id;
        ctx.emitContainsIfNeeded(n.id);
        n.callee_chain = resolution.chain;
        const _storageTarget = extractStorageMetadata(node, resolution);
        if (_storageTarget) n.metadata.storage_target = _storageTarget;

        // Data flow: resolve arguments via recursive taint extraction
        const argsNode = getValueArguments(node);
        let callHasTaintedArgs = false;
        if (argsNode) {
          for (let a = 0; a < argsNode.namedChildCount; a++) {
            const arg = argsNode.namedChild(a);
            if (!arg) continue;

            // value_argument wraps expressions
            const argExpr = arg.type === 'value_argument' ? arg.namedChild(0) : arg;
            if (!argExpr) continue;

            const taintSources = extractTaintSources(argExpr, ctx);
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

        // Receiver taint: calls on tainted objects (e.g., taintedObj.someMethod())
        const callee = node.namedChild(0);
        if (callee?.type === 'navigation_expression') {
          const obj = callee.namedChild(0);
          if (obj) {
            const receiverTaint = extractTaintSources(obj, ctx);
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

        // Callback parameter taint (for lambdas in trailing lambda syntax)
        if (callHasTaintedArgs) {
          const trailingLambda = getTrailingLambda(node);
          if (trailingLambda) {
            // annotated_lambda -> lambda_literal -> lambda_parameters
            for (let li = 0; li < trailingLambda.namedChildCount; li++) {
              const lambdaLit = trailingLambda.namedChild(li);
              if (lambdaLit?.type === 'lambda_literal') {
                for (let pi = 0; pi < lambdaLit.namedChildCount; pi++) {
                  const child = lambdaLit.namedChild(pi);
                  if (child?.type === 'lambda_parameters') {
                    for (let qi = 0; qi < child.namedChildCount; qi++) {
                      const p = child.namedChild(qi);
                      if (p?.type === 'variable_declaration') {
                        const pName = p.namedChild(0);
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
          // Also check value_arguments for lambda_literal
          const argsForCb = getValueArguments(node);
          if (argsForCb) {
            for (let ai = 0; ai < argsForCb.namedChildCount; ai++) {
              const arg = argsForCb.namedChild(ai);
              if (!arg) continue;
              const inner = arg.type === 'value_argument' ? arg.namedChild(0) : arg;
              if (inner?.type === 'lambda_literal') {
                for (let pi = 0; pi < inner.namedChildCount; pi++) {
                  const child = inner.namedChild(pi);
                  if (child?.type === 'lambda_parameters') {
                    for (let qi = 0; qi < child.namedChildCount; qi++) {
                      const p = child.namedChild(qi);
                      if (p?.type === 'variable_declaration') {
                        const pName = p.namedChild(0);
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
        const calleeNode = node.namedChild(0);
        if (calleeNode?.type === 'navigation_expression') {
          const obj = calleeNode.namedChild(0);
          const member = calleeNode.namedChild(calleeNode.namedChildCount - 1);
          if (obj?.type === 'identifier' && member?.type === 'identifier') {
            const aliasVar = ctx.resolveVariable(obj.text);
            if (aliasVar?.aliasChain) {
              const fullChain = [...aliasVar.aliasChain, member.text];
              const aliasPattern = _lookupKotlinCallee(fullChain);
              if (aliasPattern) {
                const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
                const aliasN = createNode({
                  label,
                  node_type: aliasPattern.nodeType,
                  node_subtype: aliasPattern.subtype,
                  language: 'kotlin',
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
                const aliasArgs = getValueArguments(node);
                if (aliasArgs) {
                  for (let a = 0; a < aliasArgs.namedChildCount; a++) {
                    const arg = aliasArgs.namedChild(a);
                    if (!arg) continue;
                    const argExpr = arg.type === 'value_argument' ? arg.namedChild(0) : arg;
                    if (!argExpr) continue;
                    const taintSources = extractTaintSources(argExpr, ctx);
                    for (const source of taintSources) {
                      ctx.addDataFlow(source.nodeId, aliasN.id, source.name, 'unknown', true);
                    }
                  }
                }
                break;
              }
            }
          }
        }

        // -- Anti-evasion: Class.forName(variable) with constant-folded variable --
        // Detects: val name = "ev" + "al"; Class.forName(name)
        // Also: Class.forName(name).kotlin
        if (calleeNode?.type === 'navigation_expression') {
          const cObj = calleeNode.namedChild(0);
          const cMember = calleeNode.namedChild(calleeNode.namedChildCount - 1);
          if (cObj?.type === 'identifier' && cObj.text === 'Class' &&
              cMember?.type === 'identifier' && cMember.text === 'forName') {
            const argsNode = getValueArguments(node);
            const firstArg = argsNode ? extractFirstValueArg(argsNode) : null;
            let resolved = false;
            if (firstArg) {
              let foldedClassName = tryFoldConstant(firstArg);
              if (!foldedClassName && firstArg.type === 'identifier') {
                const argVar = ctx.resolveVariable(firstArg.text);
                if (argVar?.constantValue) foldedClassName = argVar.constantValue;
              }
              const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const reflectNode = createNode({
                label: foldedClassName ? `Class.forName("${foldedClassName}")` : label,
                node_type: 'EXTERNAL',
                node_subtype: 'reflection',
                language: 'kotlin',
                file: ctx.neuralMap.source_file,
                line_start: node.startPosition.row + 1,
                line_end: node.endPosition.row + 1,
                code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
              });
              reflectNode.tags.push('anti_evasion', 'reflection');
              if (foldedClassName) {
                reflectNode.tags.push(`resolved:${foldedClassName}`);
              }
              if (!foldedClassName) {
                reflectNode.data_out.push({
                  name: 'result', source: reflectNode.id,
                  data_type: 'unknown', tainted: true, sensitivity: 'NONE',
                });
              }
              if (argsNode) {
                for (let a = 0; a < argsNode.namedChildCount; a++) {
                  const arg = argsNode.namedChild(a);
                  if (!arg) continue;
                  const argExpr = arg.type === 'value_argument' ? arg.namedChild(0) : arg;
                  if (!argExpr) continue;
                  const taintSources = extractTaintSources(argExpr, ctx);
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
        }

        // -- Unresolved call -- check if it's a locally-defined function --
        let calleeName: string | null = null;
        if (calleeNode?.type === 'identifier') {
          calleeName = calleeNode.text;
        } else if (calleeNode?.type === 'navigation_expression') {
          const member = calleeNode.namedChild(calleeNode.namedChildCount - 1);
          if (member?.type === 'identifier') {
            calleeName = member.text;
          }
        }

        if (calleeName && ctx.functionRegistry.has(calleeName)) {
          const argsNode = getValueArguments(node);
          const taintSources: TaintSourceResult[] = [];
          if (argsNode) {
            for (let a = 0; a < argsNode.namedChildCount; a++) {
              const arg = argsNode.namedChild(a);
              if (!arg) continue;
              const argExpr = arg.type === 'value_argument' ? arg.namedChild(0) : arg;
              if (argExpr) taintSources.push(...extractTaintSources(argExpr, ctx));
            }
          }

          const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
          const callNode = createNode({
            label,
            node_type: 'TRANSFORM',
            node_subtype: 'local_call',
            language: 'kotlin',
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

      // CALLS edge: capture function name for pending calls
      const calleeForPending = node.namedChild(0);
      let pendingCalleeName: string | null = null;
      if (calleeForPending?.type === 'identifier') {
        pendingCalleeName = calleeForPending.text;
      } else if (calleeForPending?.type === 'navigation_expression') {
        const member = calleeForPending.namedChild(calleeForPending.namedChildCount - 1);
        if (member?.type === 'identifier') {
          pendingCalleeName = member.text;
        }
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

    // -- NAVIGATION EXPRESSION: standalone property access --
    case 'navigation_expression': {
      // Skip if this is part of a call_expression's callee
      const parentIsCall = node.parent?.type === 'call_expression' &&
        node.parent.namedChild(0)?.startIndex === node.startIndex;
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
            language: 'kotlin',
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

    // -- ANNOTATIONS --
    case 'annotation': {
      const annotName = getAnnotationName(node);
      if (KOTLIN_ROUTE_ANNOTATIONS.has(annotName) ||
          KOTLIN_SECURITY_ANNOTATIONS.has(annotName) ||
          VALIDATION_ANNOTATIONS.has(annotName) ||
          KOTLIN_TAINT_ANNOTATIONS.has(annotName) ||
          annotName === 'Transactional' ||
          annotName === 'Autowired' ||
          annotName === 'Inject' ||
          annotName === 'Override') {
        const annotNode = createNode({
          label: `@${annotName}`,
          node_type: 'META',
          node_subtype: KOTLIN_ROUTE_ANNOTATIONS.has(annotName) ? 'route_annotation' :
                        KOTLIN_SECURITY_ANNOTATIONS.has(annotName) ? 'security_annotation' :
                        VALIDATION_ANNOTATIONS.has(annotName) ? 'validation_annotation' :
                        'annotation',
          language: 'kotlin',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        if (VALIDATION_ANNOTATIONS.has(annotName)) {
          annotNode.tags.push('validation');
        }
        if (KOTLIN_SECURITY_ANNOTATIONS.has(annotName)) {
          annotNode.tags.push('auth_gate');
        }
        ctx.neuralMap.nodes.push(annotNode);
        ctx.lastCreatedNodeId = annotNode.id;
        ctx.emitContainsIfNeeded(annotNode.id);
      }
      break;
    }

    // -- CONTROL FLOW --
    case 'if_expression': {
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      break;
    }
    case 'when_expression': {
      const whenN = createNode({ label: 'when', node_type: 'CONTROL', node_subtype: 'branch', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whenN); ctx.lastCreatedNodeId = whenN.id; ctx.emitContainsIfNeeded(whenN.id);
      break;
    }
    case 'for_statement': {
      const forN = createNode({ label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      break;
    }
    case 'while_statement': {
      const whileN = createNode({ label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whileN); ctx.lastCreatedNodeId = whileN.id; ctx.emitContainsIfNeeded(whileN.id);
      break;
    }
    case 'do_while_statement': {
      const doN = createNode({ label: 'do-while', node_type: 'CONTROL', node_subtype: 'loop', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(doN); ctx.lastCreatedNodeId = doN.id; ctx.emitContainsIfNeeded(doN.id);
      break;
    }
    case 'return_expression': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }
    case 'throw_expression': {
      const throwN = createNode({ label: 'throw', node_type: 'CONTROL', node_subtype: 'throw', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      throwN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(throwN); ctx.lastCreatedNodeId = throwN.id; ctx.emitContainsIfNeeded(throwN.id);
      break;
    }
    case 'try_expression': {
      const tryN = createNode({ label: 'try', node_type: 'CONTROL', node_subtype: 'error_handling', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      tryN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(tryN); ctx.lastCreatedNodeId = tryN.id; ctx.emitContainsIfNeeded(tryN.id);
      break;
    }
    case 'catch_block': {
      const catchN = createNode({ label: 'catch', node_type: 'CONTROL', node_subtype: 'error_handling', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      catchN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(catchN); ctx.lastCreatedNodeId = catchN.id; ctx.emitContainsIfNeeded(catchN.id);
      break;
    }
    case 'finally_block': {
      const finallyN = createNode({ label: 'finally', node_type: 'CONTROL', node_subtype: 'error_handling', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      finallyN.tags.push('cleanup', 'error_handling');
      ctx.neuralMap.nodes.push(finallyN); ctx.lastCreatedNodeId = finallyN.id; ctx.emitContainsIfNeeded(finallyN.id);
      break;
    }

    // -- ASSIGNMENT (non-declaration) --
    case 'assignment': {
      const assignLeft = node.childForFieldName('left');
      const leftText = assignLeft?.text?.slice(0, 40) ?? '?';
      const assignN = createNode({ label: `${leftText} =`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'kotlin', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
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
    case 'parenthesized_expression':
    case 'comment':
    case 'line_comment':
    case 'block_comment':
    case 'string_literal':
    case 'multiline_string_literal':
      break;
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'function_declaration' && node.type !== 'lambda_literal' && node.type !== 'anonymous_function') {
    return;
  }

  // Find the function body
  let body: SyntaxNode | null = null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child?.type === 'function_body' || child?.type === 'block') {
      body = child;
      break;
    }
  }
  // For lambda_literal, statements are direct children
  if (!body && node.type === 'lambda_literal') {
    body = node;
  }
  if (!body) return;

  // Check for return expressions with tainted data
  const returnExprs = body.descendantsOfType('return_expression');
  for (const stmt of returnExprs) {
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
// preVisitIteration — set up Kotlin for loop variable taint
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_statement') return;

  // Kotlin for: for (item in collection) { ... }
  // Children: 'for', '(', variable_declaration | multi_variable_declaration, 'in', expression, ')', block | statement
  let varDecl: SyntaxNode | null = null;
  let collectionExpr: SyntaxNode | null = null;
  let foundIn = false;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === 'variable_declaration' || child.type === 'multi_variable_declaration') {
      varDecl = child;
    }
    if (child.type === 'in') {
      foundIn = true;
      continue;
    }
    // The expression after 'in' is the collection
    if (foundIn && child.isNamed && child.type !== 'block' && child.type !== 'statement' &&
        child.type !== 'variable_declaration' && child.type !== 'multi_variable_declaration' &&
        child.type !== 'annotation' && child.type !== 'label') {
      collectionExpr = child;
      break;
    }
  }

  if (varDecl && collectionExpr) {
    const names = extractPatternNames(varDecl);
    const iterTaint = extractTaintSources(collectionExpr, ctx);
    if (iterTaint.length > 0) {
      for (const name of names) {
        ctx.declareVariable(name, 'const', null, true, iterTaint[0].nodeId);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration — re-mark for loop variable taint
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'for_statement') return;

  let varDecl: SyntaxNode | null = null;
  let collectionExpr: SyntaxNode | null = null;
  let foundIn = false;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === 'variable_declaration' || child.type === 'multi_variable_declaration') {
      varDecl = child;
    }
    if (child.type === 'in') {
      foundIn = true;
      continue;
    }
    if (foundIn && child.isNamed && child.type !== 'block' && child.type !== 'statement' &&
        child.type !== 'variable_declaration' && child.type !== 'multi_variable_declaration' &&
        child.type !== 'annotation' && child.type !== 'label') {
      collectionExpr = child;
      break;
    }
  }

  if (varDecl && collectionExpr) {
    const names = extractPatternNames(varDecl);
    const iterTaint = extractTaintSources(collectionExpr, ctx);
    if (iterTaint.length > 0) {
      for (const name of names) {
        const v = ctx.resolveVariable(name);
        if (v) {
          v.tainted = true;
          v.producingNodeId = iterTaint[0].nodeId;
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// The Profile
// ---------------------------------------------------------------------------

export const kotlinProfile: LanguageProfile = {
  id: 'kotlin',
  extensions: ['.kt', '.kts'],

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
    return _lookupKotlinCallee(chain);
  },

  analyzeStructure(_node: SyntaxNode): StructuralAnalysisResult | null {
    // Kotlin Spring routing is annotation-driven, handled in classifyNode.
    // Ktor routing uses DSL calls, handled in callee resolution.
    return null;
  },

  // Layer 4: Taint Source Detection
  ingressPattern: /(?:call\.(?:receive|receiveText|parameters|receiveMultipart)|call\.request\.(?:headers|queryParameters|cookies|uri)|incoming\.receive|request\.(?:getParameter|getHeader|body)|intent\.(?:getStringExtra|data|extras)|readLine\(\)|readln\(\)|@(?:RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)|System\.(?:getenv|getProperty))/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) =>
    nodeType === 'property_declaration',
  getDeclarationValueNode: (node) => {
    // Kotlin: property_declaration → find expression after '=' token, skip type annotations
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child?.type === '=' && i + 1 < node.childCount) {
        return node.child(i + 1);
      }
    }
    return null;
  },
  isStatementContainer: (nodeType: string) =>
    nodeType === 'source_file' || nodeType === 'block' || nodeType === 'class_body',

  // Inter-procedural taint: Kotlin function syntax
  // Matches: fun name(params) | suspend fun name(params) | override fun name(params)
  functionParamPattern: /(?:(?:suspend|override|open|private|public|protected|internal)\s+)*fun\s+\w+\s*\(([^)]*)\)/,
};

export default kotlinProfile;
