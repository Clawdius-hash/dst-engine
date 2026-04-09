/**
 * PHPProfile -- the fifth LanguageProfile implementation.
 *
 * Every piece of PHP-specific logic lives here: AST node type names,
 * field access patterns, scope rules, callee resolution, taint extraction,
 * and node classification.
 *
 * Key differences from JavaScript and Python:
 *   - `function_call_expression` not `call_expression` or `call`
 *   - `member_call_expression` for $obj->method() (arrow syntax, not dot)
 *   - `variable_name` wraps $ + name children ($foo has type variable_name)
 *   - `assignment_expression` (like JS) but inside `expression_statement`
 *   - `echo_statement` is a statement, not a function call
 *   - `include_expression` / `require_expression` for file inclusion
 *   - Superglobals ($_GET, $_POST, etc.) are variable_name nodes
 *   - `compound_statement` not `statement_block`
 *   - `formal_parameters` not `parameters`
 *   - `simple_parameter` wraps typed/untyped params
 *   - Binary expressions use `.` for string concatenation (same AST node: binary_expression)
 *   - `scoped_call_expression` for Class::staticMethod()
 *   - `encapsed_string` for double-quoted strings with interpolation
 *   - PHP has block scopes (variables declared inside if/for are NOT limited to that block
 *     in PHP, but we track the blocks for structural analysis)
 *
 * PHP is the language that runs 77% of websites. WordPress alone is 43%.
 * This profile catches: SQL injection, XSS, command injection, file inclusion,
 * object injection, XXE, path traversal, header injection, email injection,
 * and type juggling vulnerabilities.
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
import { lookupCallee as _lookupCallee } from '../languages/php.js';

// ---------------------------------------------------------------------------
// AST Node Type Sets
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'function_definition',
  'method_declaration',
  'arrow_function',
  'anonymous_function_creation_expression',
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  // PHP variables are function-scoped like JS `var`, but we still track blocks
  // for structural analysis and control flow graph building.
  'for_statement',
  'foreach_statement',
  'while_statement',
  'do_statement',
  'if_statement',
  'switch_statement',
  'try_statement',
  'catch_clause',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'class_declaration',
  'interface_declaration',
  'trait_declaration',
  'enum_declaration',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  // PHP has no let/const/var keywords -- assignment is declaration.
  // assignment_expression is the node type, wrapped in expression_statement.
  'expression_statement',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'function_definition',
]);

// PHP superglobals that carry user-controlled data
const PHP_SUPERGLOBAL_TAINT: ReadonlySet<string> = new Set([
  '_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER',
  '_ENV', '_SESSION',
]);

// Tainted paths for member access (object->property)
const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // Laravel Request
  'request.input', 'request.get', 'request.post', 'request.query',
  'request.all', 'request.only', 'request.except', 'request.file',
  'request.header', 'request.cookie', 'request.ip', 'request.path',
  'request.url', 'request.fullUrl', 'request.method', 'request.json',
  // Symfony Request
  'Request.get', 'Request.query', 'Request.request', 'Request.getContent',
  'Request.headers', 'Request.cookies', 'Request.files', 'Request.server',
]);

// ---------------------------------------------------------------------------
// Helper: extract callee chain from a PHP member expression tree
// ---------------------------------------------------------------------------
// PHP uses -> for instance access and :: for static access.
// member_call_expression: $obj->method(...)
// scoped_call_expression: Class::method(...)
// member_access_expression: $obj->property

function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'name') {
    return [node.text];
  }
  if (node.type === 'variable_name') {
    // Strip the $ prefix to get the variable name
    const nameChild = node.namedChildren.find(c => c.type === 'name');
    return nameChild ? [nameChild.text] : [node.text.replace(/^\$/, '')];
  }
  if (node.type === 'member_access_expression') {
    const obj = node.childForFieldName('object');
    const prop = node.childForFieldName('name');
    if (obj && prop) {
      const chain = extractCalleeChain(obj);
      chain.push(prop.text);
      return chain;
    }
  }
  if (node.type === 'scoped_property_access_expression') {
    const scope = node.childForFieldName('scope');
    const prop = node.childForFieldName('name');
    if (scope && prop) {
      const chain = extractCalleeChain(scope);
      chain.push(prop.text);
      return chain;
    }
  }
  return [];
}

// ---------------------------------------------------------------------------
// Helper: extract variable name from a variable_name AST node
// ---------------------------------------------------------------------------

function getVarName(node: SyntaxNode): string {
  if (node.type === 'variable_name') {
    const nameChild = node.namedChildren.find(c => c.type === 'name');
    return nameChild ? nameChild.text : node.text.replace(/^\$/, '');
  }
  return node.text.replace(/^\$/, '');
}

// ---------------------------------------------------------------------------
// Helper: check if a variable_name node is a PHP superglobal
// ---------------------------------------------------------------------------

function isSuperglobal(node: SyntaxNode): boolean {
  if (node.type !== 'variable_name') return false;
  const name = getVarName(node);
  return PHP_SUPERGLOBAL_TAINT.has(name);
}

// ---------------------------------------------------------------------------
// Helper: check if a subscript_expression accesses a superglobal
// e.g., $_GET['name'], $_POST['data']
// ---------------------------------------------------------------------------

function isSuperglobalAccess(node: SyntaxNode): boolean {
  if (node.type !== 'subscript_expression') return false;
  const varNode = node.namedChildren[0];
  if (!varNode) return false;
  return isSuperglobal(varNode);
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
// Recognises: $stmt = $pdo->prepare("SELECT ... WHERE id = ?");
// i.e., a prepare() call with a string literal containing placeholders.

const PARAM_PLACEHOLDER_RE = /\?|%s|:\w+/;

function isParameterizedQuery(callNode: SyntaxNode): boolean {
  // Check if callee ends with 'prepare'
  let calleeName: string | null = null;
  const calleeNode = callNode.childForFieldName('function') ?? callNode.childForFieldName('name');
  if (calleeNode?.type === 'name' && calleeNode.text === 'prepare') {
    calleeName = 'prepare';
  }
  if (calleeNode?.type === 'member_access_expression') {
    const method = calleeNode.childForFieldName('name');
    if (method?.text === 'prepare') calleeName = 'prepare';
  }
  if (!calleeName) return false;

  const argsNode = callNode.childForFieldName('arguments');
  if (!argsNode) return false;

  // Need at least 1 arg (the query string)
  const firstArg = argsNode.namedChildren.find(c => c.type === 'argument');
  if (!firstArg) return false;

  const strNode = firstArg.namedChildren[0];
  if (!strNode || (strNode.type !== 'string' && strNode.type !== 'encapsed_string')) return false;

  return PARAM_PLACEHOLDER_RE.test(strNode.text);
}

// ---------------------------------------------------------------------------
// tryFoldConstant -- PHP constant folding for anti-evasion
// ---------------------------------------------------------------------------
// PHP attackers construct dangerous function names at runtime to dodge static
// analysis. This folds them back:
//   chr(101).chr(118).chr(97).chr(108)  → "eval"
//   'ev'.'al'                            → "eval"
//   base64_decode('ZXZhbA==')            → "eval"
//   hex2bin('6576616c')                  → "eval"
//   pack('C*', 101, 118, 97, 108)       → "eval"
//   str_rot13('riny')                    → "eval"

function resolvePhpEscapes(s: string): string {
  return s
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\([0-7]{1,3})/g, (_, oct) => String.fromCharCode(parseInt(oct, 8)))
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\\\/g, '\\')
    .replace(/\\'/g, "'")
    .replace(/\\"/g, '"')
    .replace(/\\\$/g, '$');
}

function tryFoldConstant(n: SyntaxNode): string | null {
  // Literal strings -- strip enclosing quotes, resolve escape sequences
  if (n.type === 'string') {
    const raw = n.text.replace(/^['"`]|['"`]$/g, '');
    return resolvePhpEscapes(raw);
  }
  if (n.type === 'string_content' || n.type === 'string_value') {
    return resolvePhpEscapes(n.text);
  }
  // Integer literals -- return as string for chr() operations
  if (n.type === 'integer') {
    return n.text;
  }
  // Float literals
  if (n.type === 'float') {
    return n.text;
  }
  // Binary expression: 'ev'.'al' → "eval" (PHP uses . for concat)
  // Also handles arithmetic for obfuscated integer values
  if (n.type === 'binary_expression') {
    const left = n.childForFieldName('left');
    const right = n.childForFieldName('right');
    if (left && right) {
      // Determine operator -- PHP tree-sitter uses child nodes for operator
      const opNode = n.children.find(c => c.type === '.' || c.type === '+' || c.type === '-' || c.type === '*');
      const op = opNode?.type ?? null;
      if (op === '.') {
        // String concatenation
        const lv = tryFoldConstant(left);
        const rv = tryFoldConstant(right);
        if (lv !== null && rv !== null) return lv + rv;
      }
      if (op === '+') {
        const lv = tryFoldConstant(left);
        const rv = tryFoldConstant(right);
        if (lv !== null && rv !== null) {
          const ln = Number(lv), rn = Number(rv);
          if (!isNaN(ln) && !isNaN(rn)) return String(ln + rn);
          // String concat fallback
          return lv + rv;
        }
      }
    }
  }
  // Parenthesized expression: ('ev'.'al') → "eval"
  if (n.type === 'parenthesized_expression') {
    const inner = n.namedChild(0);
    return inner ? tryFoldConstant(inner) : null;
  }
  // ── PHP function-based evasion patterns ──
  if (n.type === 'function_call_expression') {
    const func = n.childForFieldName('function');
    const args = n.childForFieldName('arguments');
    if (func && args) {
      const funcName = func.type === 'name' ? func.text : null;

      // chr(N) → single character
      if (funcName === 'chr') {
        const firstArg = args.namedChild(0);
        // Handle argument wrapper node
        const argExpr = firstArg?.type === 'argument' ? firstArg.namedChild(0) : firstArg;
        if (argExpr) {
          const val = tryFoldConstant(argExpr);
          if (val !== null) {
            const code = parseInt(val, 10);
            if (!isNaN(code) && code >= 0 && code <= 127) {
              return String.fromCharCode(code);
            }
          }
        }
      }

      // base64_decode('ZXZhbA==') → "eval"
      if (funcName === 'base64_decode') {
        const firstArg = args.namedChild(0);
        const argExpr = firstArg?.type === 'argument' ? firstArg.namedChild(0) : firstArg;
        if (argExpr) {
          const b64 = tryFoldConstant(argExpr);
          if (b64 !== null) {
            try {
              return Buffer.from(b64, 'base64').toString('utf-8');
            } catch { /* not valid base64 */ }
          }
        }
      }

      // hex2bin('6576616c') → "eval"
      if (funcName === 'hex2bin') {
        const firstArg = args.namedChild(0);
        const argExpr = firstArg?.type === 'argument' ? firstArg.namedChild(0) : firstArg;
        if (argExpr) {
          const hex = tryFoldConstant(argExpr);
          if (hex !== null) {
            try {
              return Buffer.from(hex, 'hex').toString('utf-8');
            } catch { /* not valid hex */ }
          }
        }
      }

      // pack('C*', 101, 118, 97, 108) → "eval"
      if (funcName === 'pack') {
        const firstArg = args.namedChild(0);
        const fmtExpr = firstArg?.type === 'argument' ? firstArg.namedChild(0) : firstArg;
        if (fmtExpr) {
          const fmt = tryFoldConstant(fmtExpr);
          // Only handle C* (unsigned char) format -- the most common evasion
          if (fmt === 'C*') {
            const codes: number[] = [];
            let allLiteral = true;
            for (let i = 1; i < args.namedChildCount; i++) {
              const arg = args.namedChild(i);
              const expr = arg?.type === 'argument' ? arg.namedChild(0) : arg;
              if (expr) {
                const val = tryFoldConstant(expr);
                if (val !== null) {
                  const num = parseInt(val, 10);
                  if (!isNaN(num)) {
                    codes.push(num);
                    continue;
                  }
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

      // str_rot13('riny') → "eval"
      if (funcName === 'str_rot13') {
        const firstArg = args.namedChild(0);
        const argExpr = firstArg?.type === 'argument' ? firstArg.namedChild(0) : firstArg;
        if (argExpr) {
          const input = tryFoldConstant(argExpr);
          if (input !== null) {
            return input.replace(/[a-zA-Z]/g, (c) => {
              const base = c <= 'Z' ? 65 : 97;
              return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
            });
          }
        }
      }

      // strtolower / strtoupper -- common wrapping to further obscure
      if (funcName === 'strtolower') {
        const firstArg = args.namedChild(0);
        const argExpr = firstArg?.type === 'argument' ? firstArg.namedChild(0) : firstArg;
        if (argExpr) {
          const val = tryFoldConstant(argExpr);
          if (val !== null) return val.toLowerCase();
        }
      }
      if (funcName === 'strtoupper') {
        const firstArg = args.namedChild(0);
        const argExpr = firstArg?.type === 'argument' ? firstArg.namedChild(0) : firstArg;
        if (argExpr) {
          const val = tryFoldConstant(argExpr);
          if (val !== null) return val.toUpperCase();
        }
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// resolveCallee -- resolve a PHP call node to a NeuralMap node type
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  // function_call_expression: name(args)
  if (node.type === 'function_call_expression') {
    const callee = node.childForFieldName('function');
    if (!callee) return null;

    if (callee.type === 'name') {
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
    }
    // Qualified name: Namespace\Class\method(...)
    if (callee.type === 'qualified_name') {
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
    }

    // ── CONSTANT FOLDING for constructed callee names ──
    // Patterns: $fn = chr(101).chr(118).chr(97).chr(108); $fn($input);
    //           (base64_decode('ZXZhbA=='))($input);
    //           ('ev'.'al')($input);
    // The callee node is a parenthesized_expression, binary_expression,
    // or another function_call_expression (e.g., base64_decode(...)).
    if (callee.type !== 'name' && callee.type !== 'qualified_name') {
      const folded = tryFoldConstant(callee);
      if (folded) {
        const chain = [folded];
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

    return null;
  }

  // member_call_expression: $obj->method(args)
  if (node.type === 'member_call_expression') {
    const obj = node.childForFieldName('object');
    const method = node.childForFieldName('name');
    if (!obj || !method) return null;

    const objName = getVarName(obj);
    const methodName = method.text;
    const chain = [objName, methodName];

    const pattern = _lookupCallee(chain);
    if (pattern) {
      return {
        nodeType: pattern.nodeType,
        subtype: pattern.subtype,
        tainted: pattern.tainted,
        chain,
      };
    }

    // Try just the method name for wildcard matching
    const methodPattern = _lookupCallee([methodName]);
    if (methodPattern) {
      return {
        nodeType: methodPattern.nodeType,
        subtype: methodPattern.subtype,
        tainted: methodPattern.tainted,
        chain: [methodName],
      };
    }

    return null;
  }

  // scoped_call_expression: Class::staticMethod(args)
  if (node.type === 'scoped_call_expression') {
    const scope = node.childForFieldName('scope');
    const method = node.childForFieldName('name');
    if (!scope || !method) return null;

    const className = scope.text;
    const methodName = method.text;
    const chain = [className, methodName];

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

  return null;
}

// ---------------------------------------------------------------------------
// resolvePropertyAccess -- resolve a standalone PHP member_access_expression
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  if (node.type !== 'member_access_expression' && node.type !== 'scoped_property_access_expression') {
    return null;
  }

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

  // Check callee DB for property access patterns
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
// extractPatternNames -- extract variable names from PHP destructuring
// ---------------------------------------------------------------------------
// PHP uses list() or [...] for array destructuring.

function extractPatternNames(pattern: SyntaxNode): string[] {
  const names: string[] = [];

  for (let i = 0; i < pattern.namedChildCount; i++) {
    const child = pattern.namedChild(i);
    if (!child) continue;

    if (child.type === 'variable_name') {
      names.push(getVarName(child));
    } else if (child.type === 'list_literal' || child.type === 'array_creation_expression') {
      names.push(...extractPatternNames(child));
    } else if (child.namedChildCount > 0) {
      names.push(...extractPatternNames(child));
    }
  }

  return names;
}

// ---------------------------------------------------------------------------
// extractTaintSources -- the recursive expression X-ray for PHP
// ---------------------------------------------------------------------------

function extractTaintSources(expr: SyntaxNode, ctx: MapperContextLike): TaintSourceResult[] {
  if (!expr) return [];

  switch (expr.type) {
    // -- Leaf: variable_name -- check if it's tainted or a superglobal
    case 'variable_name': {
      const varName = getVarName(expr);

      // Superglobals are always tainted
      if (PHP_SUPERGLOBAL_TAINT.has(varName)) {
        // Create an INGRESS node for the superglobal access
        const ingressNode = createNode({
          label: `$${varName}`,
          node_type: 'INGRESS',
          node_subtype: 'http_request',
          language: 'php',
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
        return [{ nodeId: ingressNode.id, name: `$${varName}` }];
      }

      const varInfo = ctx.resolveVariable(varName);
      if (varInfo?.tainted && varInfo.producingNodeId) {
        return [{ nodeId: varInfo.producingNodeId, name: `$${varName}` }];
      }
      return [];
    }

    // -- Subscript: $_GET['name'] or $arr['key'] --
    case 'subscript_expression': {
      const arrVar = expr.namedChildren[0];
      if (arrVar) {
        // If it's a superglobal subscript, create INGRESS
        if (arrVar.type === 'variable_name' && isSuperglobal(arrVar)) {
          const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
          const ingressNode = createNode({
            label,
            node_type: 'INGRESS',
            node_subtype: 'http_request',
            language: 'php',
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
          return [{ nodeId: ingressNode.id, name: label }];
        }
        // Otherwise recurse into the array variable
        return extractTaintSources(arrVar, ctx);
      }
      return [];
    }

    // -- Member access: $obj->property --
    case 'member_access_expression': {
      const resolution = resolvePropertyAccess(expr);
      if (resolution?.tainted) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'php',
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
      const obj = expr.childForFieldName('object');
      if (obj?.type === 'variable_name') {
        const varInfo = ctx.resolveVariable(getVarName(obj));
        if (varInfo?.tainted && varInfo.producingNodeId) {
          return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
        }
      }
      if (obj?.type === 'member_access_expression') {
        return extractTaintSources(obj, ctx);
      }
      return [];
    }

    // -- Binary expression: string concatenation with . --
    case 'binary_expression': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const sources: TaintSourceResult[] = [];
      if (left) sources.push(...extractTaintSources(left, ctx));
      if (right) sources.push(...extractTaintSources(right, ctx));
      return sources;
    }

    // -- Encapsed string (double-quoted with variables): "Hello $name" --
    case 'encapsed_string': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Function call: sanitize($tainted) breaks the chain --
    case 'function_call_expression':
    case 'member_call_expression':
    case 'scoped_call_expression': {
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
      // If the callee is a known tainted source (e.g., get_nfilter_request_var), treat output as tainted
      if (callResolution && callResolution.tainted) {
        return [{ type: 'direct', variable: expr.text?.slice(0, 100) || 'call', line: expr.startPosition.row + 1 }];
      }
      // For any other call, check arguments for taint
      const sources: TaintSourceResult[] = [];
      const args = expr.childForFieldName('arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (!arg) continue;
          // Unwrap argument wrapper nodes
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
      // Check receiver for member calls
      if (expr.type === 'member_call_expression') {
        const receiver = expr.childForFieldName('object');
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

    // -- Conditional expression (ternary): $a ? $b : $c --
    case 'conditional_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Parenthesized: ($tainted) --
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Assignment: $x = $tainted --
    case 'assignment_expression': {
      const right = expr.childForFieldName('right');
      return right ? extractTaintSources(right, ctx) : [];
    }

    // -- Cast expression: (int)$tainted, (string)$tainted --
    case 'cast_expression': {
      const inner = expr.childForFieldName('value');
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Unary: !$tainted --
    case 'unary_op_expression': {
      const arg = expr.childForFieldName('argument');
      return arg ? extractTaintSources(arg, ctx) : [];
    }

    // -- Array creation: [$tainted, $safe] --
    case 'array_creation_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const el = expr.namedChild(i);
        if (el) sources.push(...extractTaintSources(el, ctx));
      }
      return sources;
    }

    // -- Array element initializer: 'key' => $tainted --
    case 'array_element_initializer': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Argument wrapper --
    case 'argument': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Include expression: include $tainted --
    case 'include_expression':
    case 'include_once_expression':
    case 'require_expression':
    case 'require_once_expression': {
      const sources: TaintSourceResult[] = [];
      for (let i = 0; i < expr.namedChildCount; i++) {
        const child = expr.namedChild(i);
        if (child) sources.push(...extractTaintSources(child, ctx));
      }
      return sources;
    }

    // -- Name (identifier) -- usually function/class names, not variables
    case 'name': {
      // Could be a constant
      return [];
    }

    // -- Default: unknown expression type --
    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration -- PHP assignment_expression
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  // PHP assignments are expression_statement > assignment_expression
  // Also handles augmented_assignment_expression (.= += etc.)
  if (node.type !== 'expression_statement') return;

  const assignExpr = node.namedChildren.find(c =>
    c.type === 'assignment_expression' || c.type === 'augmented_assignment_expression'
  );
  if (!assignExpr) return;

  const isAugmented = assignExpr.type === 'augmented_assignment_expression';

  const kind: VariableInfo['kind'] = 'let'; // PHP variables are all mutable

  const nameNode = assignExpr.childForFieldName('left');
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

  // Multi-hop taint propagation: $b = $a where $a is tainted
  if (!producingNodeId) {
    const valueNode = assignExpr.childForFieldName('right');
    if (valueNode?.type === 'variable_name') {
      const sourceVar = ctx.resolveVariable(getVarName(valueNode));
      if (sourceVar) {
        tainted = sourceVar.tainted;
        producingNodeId = sourceVar.producingNodeId;
      }
    }
  }

  // Direct taint extraction -- catches taint through compound expressions
  if (!tainted) {
    const valueNode = assignExpr.childForFieldName('right');
    if (valueNode) {
      const directTaint = extractTaintSources(valueNode, ctx);
      if (directTaint.length > 0) {
        tainted = true;
        producingNodeId = directTaint[0].nodeId;
      }
    }
  }

  // Cross-function taint: $val = getInput($request)
  if (!producingNodeId) {
    const valueNode = assignExpr.childForFieldName('right');
    if (valueNode?.type === 'function_call_expression') {
      const callee = valueNode.childForFieldName('function');
      if (callee?.type === 'name') {
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

  // Alias chain detection: $q = $db->query -> store chain
  let aliasChain: string[] | undefined;
  {
    const valueNode = assignExpr.childForFieldName('right');
    if (valueNode?.type === 'member_access_expression') {
      const chain = extractCalleeChain(valueNode);
      if (chain.length >= 2) {
        aliasChain = chain;
      }
    }
  }

  // Constant folding: $fn = 'ev'.'al' → constantValue = "eval"
  // $fn = chr(101).chr(118).chr(97).chr(108) → constantValue = "eval"
  // $fn = base64_decode('ZXZhbA==') → constantValue = "eval"
  let constantValue: string | undefined;
  {
    const valueNode = assignExpr.childForFieldName('right');
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
        return; // keep existing tainted state
      }
    }
    ctx.declareVariable(varName, kind, null, newTainted, newProducing);
    const v = ctx.resolveVariable(varName);
    if (v) {
      if (aliasChain) v.aliasChain = aliasChain;
      if (constantValue) v.constantValue = constantValue;
    }
  };

  if (nameNode.type === 'variable_name') {
    const varName = getVarName(nameNode);
    preserveTaint(varName, tainted, producingNodeId);

    // Emit META node for string assignments so CWE-798 can find hardcoded creds.
    const rhsNode = assignExpr.childForFieldName('right');
    if (rhsNode && (rhsNode.type === 'string' || rhsNode.type === 'encapsed_string')) {
      const snap = node.text.slice(0, 200);
      const metaNode = createNode({
        label: varName,
        node_type: 'META',
        node_subtype: 'config_value',
        language: 'php',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: snap,
      });
      ctx.neuralMap.nodes.push(metaNode);
      ctx.emitContainsIfNeeded(metaNode.id);
    }
  } else if (nameNode.type === 'list_literal' || nameNode.type === 'array_creation_expression') {
    extractPatternNames(nameNode).forEach(n =>
      preserveTaint(n, tainted, producingNodeId)
    );
  }
}

// ---------------------------------------------------------------------------
// processFunctionParams -- PHP formal_parameters
// ---------------------------------------------------------------------------

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  const declareParam = (name: string) => {
    const producingId = ctx.pendingCallbackTaint.get(name) ?? null;
    const isTainted = producingId !== null;
    if (isTainted) ctx.pendingCallbackTaint.delete(name);
    ctx.declareVariable(name, 'param', null, isTainted, producingId);
  };

  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) return;

  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    switch (param.type) {
      case 'simple_parameter': {
        // simple_parameter has a name field which is a variable_name
        const nameChild = param.childForFieldName('name');
        if (nameChild && nameChild.type === 'variable_name') {
          declareParam(getVarName(nameChild));
        }
        break;
      }
      case 'variadic_parameter': {
        // ...$args
        const nameChild = param.childForFieldName('name');
        if (nameChild && nameChild.type === 'variable_name') {
          declareParam(getVarName(nameChild));
        }
        break;
      }
      case 'property_promotion_parameter': {
        // Constructor property promotion: public readonly string $name
        const nameChild = param.childForFieldName('name');
        if (nameChild && nameChild.type === 'variable_name') {
          declareParam(getVarName(nameChild));
        }
        break;
      }
      case 'variable_name': {
        declareParam(getVarName(param));
        break;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// classifyNode -- the heart of the switch statement for PHP
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  // Process function definitions -- register function name in outer scope
  if (node.type === 'function_definition') {
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
    // -- FUNCTION DEFINITION --
    case 'function_definition': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const fnNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'php',
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

    // -- METHOD DECLARATION --
    case 'method_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const methodNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'php',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      // Check for visibility/static modifiers
      for (let c = 0; c < node.childCount; c++) {
        const child = node.child(c);
        if (child?.type === 'visibility_modifier') {
          methodNode.tags.push(child.text);
        }
        if (child?.type === 'static_modifier') {
          methodNode.tags.push('static');
        }
      }
      ctx.neuralMap.nodes.push(methodNode);
      ctx.lastCreatedNodeId = methodNode.id;
      ctx.emitContainsIfNeeded(methodNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = methodNode.id;
      if (name !== 'anonymous') ctx.functionRegistry.set(name, methodNode.id);
      break;
    }

    // -- ANONYMOUS FUNCTION (closure) --
    case 'anonymous_function_creation_expression': {
      let closureName = 'anonymous';
      if (
        node.parent?.type === 'assignment_expression' &&
        node.parent.childForFieldName('left')?.type === 'variable_name'
      ) {
        closureName = getVarName(node.parent.childForFieldName('left')!);
      }
      const closureNode = createNode({
        label: closureName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'php',
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

    // -- ARROW FUNCTION --
    case 'arrow_function': {
      let arrowName = 'anonymous';
      if (
        node.parent?.type === 'assignment_expression' &&
        node.parent.childForFieldName('left')?.type === 'variable_name'
      ) {
        arrowName = getVarName(node.parent.childForFieldName('left')!);
      }
      const arrowNode = createNode({
        label: arrowName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'php',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      arrowNode.tags.push('arrow');
      ctx.neuralMap.nodes.push(arrowNode);
      ctx.lastCreatedNodeId = arrowNode.id;
      ctx.emitContainsIfNeeded(arrowNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = arrowNode.id;
      break;
    }

    // -- CLASS DECLARATION --
    case 'class_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousClass';
      const classNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'php',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      // Check for extends/implements
      const baseClause = node.childForFieldName('base_clause');
      if (baseClause) classNode.tags.push('extends');
      const interfaces = node.namedChildren.find(c => c.type === 'class_interface_clause');
      if (interfaces) classNode.tags.push('implements');
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
        node_subtype: 'class',
        language: 'php',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ifaceNode.tags.push('interface');
      ctx.neuralMap.nodes.push(ifaceNode);
      ctx.lastCreatedNodeId = ifaceNode.id;
      ctx.emitContainsIfNeeded(ifaceNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = ifaceNode.id;
      break;
    }

    // -- TRAIT DECLARATION --
    case 'trait_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousTrait';
      const traitNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'php',
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

    // -- ENUM DECLARATION (PHP 8.1+) --
    case 'enum_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousEnum';
      const enumNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'class',
        language: 'php',
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

    // -- NAMESPACE DEFINITION --
    case 'namespace_definition': {
      const name = node.childForFieldName('name')?.text ?? 'global';
      const nsNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'namespace',
        language: 'php',
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

    // -- USE DECLARATION (PHP imports) --
    case 'namespace_use_declaration': {
      const useNode = createNode({
        label: node.text.slice(4).trim().replace(/;$/, ''),
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'php',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(useNode);
      ctx.lastCreatedNodeId = useNode.id;
      ctx.emitContainsIfNeeded(useNode.id);
      break;
    }

    // -- FUNCTION CALL EXPRESSION: classify by callee --
    case 'function_call_expression': {
      let resolution = resolveCallee(node);

      // Alias resolution: $q = $db->query -> $q(...) resolves as db.query
      if (!resolution) {
        const calleeNode = node.childForFieldName('function');
        if (calleeNode?.type === 'name') {
          // Check variable alias
          const aliasVar = ctx.resolveVariable(calleeNode.text);
          if (aliasVar?.aliasChain) {
            const aliasPattern = _lookupCallee(aliasVar.aliasChain);
            if (aliasPattern) {
              resolution = {
                nodeType: aliasPattern.nodeType,
                subtype: aliasPattern.subtype,
                tainted: aliasPattern.tainted,
                chain: aliasVar.aliasChain,
              };
            }
          }
        }
      }

      // Constant-folded variable callee: $fn = 'ev'.'al'; $fn($input)
      if (!resolution) {
        const calleeNode = node.childForFieldName('function');
        if (calleeNode?.type === 'variable_name') {
          const varName = getVarName(calleeNode);
          const varInfo = ctx.resolveVariable(varName);
          if (varInfo?.constantValue) {
            const chain = [varInfo.constantValue];
            const pattern = _lookupCallee(chain);
            if (pattern) {
              resolution = {
                nodeType: pattern.nodeType,
                subtype: pattern.subtype,
                tainted: pattern.tainted,
                chain,
              };
            }
          }
        }
      }

      // call_user_func / call_user_func_array: first arg is the callee name
      if (!resolution) {
        const calleeNode = node.childForFieldName('function');
        if (calleeNode?.type === 'name' && (calleeNode.text === 'call_user_func' || calleeNode.text === 'call_user_func_array')) {
          const argsNode = node.childForFieldName('arguments');
          const firstArg = argsNode?.namedChild(0);
          const argExpr = firstArg?.type === 'argument' ? firstArg.namedChild(0) : firstArg;
          if (argExpr) {
            // Try constant folding on the first arg (the callee name)
            let resolvedName: string | null = null;
            // Direct string: call_user_func('eval', ...)
            if (argExpr.type === 'string') {
              resolvedName = argExpr.text.replace(/^['"`]|['"`]$/g, '');
            }
            // Constructed: call_user_func('ev'.'al', ...)
            if (!resolvedName) {
              resolvedName = tryFoldConstant(argExpr);
            }
            // Variable with constantValue: $fn = 'eval'; call_user_func($fn, ...)
            if (!resolvedName && argExpr.type === 'variable_name') {
              const argVarInfo = ctx.resolveVariable(getVarName(argExpr));
              if (argVarInfo?.constantValue) resolvedName = argVarInfo.constantValue;
            }
            if (resolvedName) {
              const chain = [resolvedName];
              const pattern = _lookupCallee(chain);
              if (pattern) {
                resolution = {
                  nodeType: pattern.nodeType,
                  subtype: pattern.subtype,
                  tainted: pattern.tainted,
                  chain,
                };
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
          language: 'php',
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
      } else {
        // Unresolved call -- check if it's locally defined
        const calleeNode = node.childForFieldName('function');
        const calleeName = calleeNode?.type === 'name' ? calleeNode.text : null;

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
            language: 'php',
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
          // ── RUNTIME EVAL MARKER ──
          // The callee is a variable_name ($fn(...)) or dynamic_variable_name ($$fn(...))
          // and we couldn't resolve it via constant folding, alias chains, or the function registry.
          // Flag it for runtime evaluation -- this is a potential evasion vector.
          const unresolvedCallee = node.childForFieldName('function');
          if (unresolvedCallee && (
            unresolvedCallee.type === 'variable_name' ||
            unresolvedCallee.type === 'dynamic_variable_name' ||
            // call_user_func with unresolvable first arg
            (unresolvedCallee.type === 'name' && (unresolvedCallee.text === 'call_user_func' || unresolvedCallee.text === 'call_user_func_array'))
          )) {
            const dynNode = createNode({
              label: node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text,
              node_type: 'EXTERNAL',
              node_subtype: 'dynamic_dispatch',
              language: 'php',
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
            // Wire tainted arguments
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
            // Wire tainted callee variable
            if (unresolvedCallee.type === 'variable_name') {
              const calleeTaint = extractTaintSources(unresolvedCallee, ctx);
              for (const source of calleeTaint) {
                ctx.addDataFlow(source.nodeId, dynNode.id, source.name, 'unknown', true);
              }
            }
          }
        }
      }

      // CALLS edge: capture simple name calls
      const callFuncNode = node.childForFieldName('function');
      if (callFuncNode && callFuncNode.type === 'name') {
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

    // -- MEMBER CALL EXPRESSION: $obj->method(args) --
    case 'member_call_expression': {
      const resolution = resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'php',
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
        ctx.neuralMap.nodes.push(n);
        ctx.lastCreatedNodeId = n.id;
        ctx.emitContainsIfNeeded(n.id);

        // Data flow
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
        // Receiver taint
        const receiver = node.childForFieldName('object');
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
      }
      break;
    }

    // -- SCOPED CALL EXPRESSION: Class::staticMethod(args) --
    case 'scoped_call_expression': {
      const resolution = resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'php',
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
        ctx.neuralMap.nodes.push(n);
        ctx.lastCreatedNodeId = n.id;
        ctx.emitContainsIfNeeded(n.id);

        // Data flow
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
        if (callHasTaintedArgs && !n.data_out.some((d: any) => d.tainted)) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }
      }
      break;
    }

    // -- ECHO STATEMENT: echo $tainted --
    case 'echo_statement': {
      const echoNode = createNode({
        label: node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text,
        node_type: 'EGRESS',
        node_subtype: 'display',
        language: 'php',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(echoNode);
      ctx.lastCreatedNodeId = echoNode.id;
      ctx.emitContainsIfNeeded(echoNode.id);

      // Data flow from tainted expressions in the echo
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (!child) continue;
        const taintSources = extractTaintSources(child, ctx);
        for (const source of taintSources) {
          ctx.addDataFlow(source.nodeId, echoNode.id, source.name, 'unknown', true);
        }
        if (taintSources.length > 0 && !echoNode.data_out.some((d: any) => d.tainted)) {
          echoNode.data_out.push({
            name: 'result',
            source: echoNode.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }
      }
      break;
    }

    // -- INCLUDE/REQUIRE EXPRESSIONS --
    case 'include_expression':
    case 'include_once_expression':
    case 'require_expression':
    case 'require_once_expression': {
      // First check if the included path is tainted (pre-scan)
      let inclTainted = false;
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child) {
          const ts = extractTaintSources(child, ctx);
          if (ts.length > 0) { inclTainted = true; break; }
        }
      }

      const inclNode = createNode({
        label: node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text,
        // Tainted path = EXTERNAL/file_include (security-relevant); static = STRUCTURAL/dependency
        node_type: inclTainted ? 'EXTERNAL' : 'STRUCTURAL',
        node_subtype: inclTainted ? 'file_include' : 'dependency',
        language: 'php',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(inclNode);
      ctx.lastCreatedNodeId = inclNode.id;
      ctx.emitContainsIfNeeded(inclNode.id);

      // If the included path is tainted, wire up data flow and mark attack surface
      if (inclTainted) {
        for (let i = 0; i < node.namedChildCount; i++) {
          const child = node.namedChild(i);
          if (!child) continue;
          const taintSources = extractTaintSources(child, ctx);
          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, inclNode.id, source.name, 'unknown', true);
          }
        }
        inclNode.attack_surface.push('file_inclusion');
        inclNode.data_out.push({
          name: 'result',
          source: inclNode.id,
          data_type: 'unknown',
          tainted: true,
          sensitivity: 'NONE',
        });
      }
      break;
    }

    // -- MEMBER ACCESS EXPRESSION: standalone property access --
    case 'member_access_expression': {
      // Skip if this is the callee of a member_call_expression
      if (node.parent?.type === 'member_call_expression') {
        const parentObj = node.parent.childForFieldName('object');
        const parentName = node.parent.childForFieldName('name');
        // If this node IS the entire function expression of the call, skip it
        if (parentObj && parentName) break;
      }

      const resolution = resolvePropertyAccess(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'php',
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
          n.attack_surface.push('user_input');
        }
        ctx.neuralMap.nodes.push(n);
        ctx.lastCreatedNodeId = n.id;
        ctx.emitContainsIfNeeded(n.id);
      }
      break;
    }

    // -- CONTROL FLOW NODES --
    case 'if_statement': {
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      break;
    }
    case 'for_statement': {
      const forN = createNode({ label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      break;
    }
    case 'foreach_statement': {
      const foreachN = createNode({ label: 'foreach', node_type: 'CONTROL', node_subtype: 'loop', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(foreachN); ctx.lastCreatedNodeId = foreachN.id; ctx.emitContainsIfNeeded(foreachN.id);
      break;
    }
    case 'while_statement': {
      const whileN = createNode({ label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whileN); ctx.lastCreatedNodeId = whileN.id; ctx.emitContainsIfNeeded(whileN.id);
      break;
    }
    case 'do_statement': {
      const doN = createNode({ label: 'do', node_type: 'CONTROL', node_subtype: 'loop', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(doN); ctx.lastCreatedNodeId = doN.id; ctx.emitContainsIfNeeded(doN.id);
      break;
    }
    case 'switch_statement': {
      const switchN = createNode({ label: 'switch', node_type: 'CONTROL', node_subtype: 'branch', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(switchN); ctx.lastCreatedNodeId = switchN.id; ctx.emitContainsIfNeeded(switchN.id);
      break;
    }
    case 'try_statement': {
      const tryN = createNode({ label: 'try/catch', node_type: 'CONTROL', node_subtype: 'error_handler', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(tryN); ctx.lastCreatedNodeId = tryN.id; ctx.emitContainsIfNeeded(tryN.id);
      break;
    }
    case 'catch_clause': {
      const catchN = createNode({ label: 'catch', node_type: 'CONTROL', node_subtype: 'catch', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      catchN.tags.push('error-handler');
      ctx.neuralMap.nodes.push(catchN); ctx.lastCreatedNodeId = catchN.id; ctx.emitContainsIfNeeded(catchN.id);
      break;
    }
    case 'finally_clause': {
      const finallyN = createNode({ label: 'finally', node_type: 'CONTROL', node_subtype: 'finally', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(finallyN); ctx.lastCreatedNodeId = finallyN.id; ctx.emitContainsIfNeeded(finallyN.id);
      break;
    }
    case 'match_expression': {
      const matchN = createNode({ label: 'match', node_type: 'CONTROL', node_subtype: 'branch', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      matchN.tags.push('pattern-matching');
      ctx.neuralMap.nodes.push(matchN); ctx.lastCreatedNodeId = matchN.id; ctx.emitContainsIfNeeded(matchN.id);
      break;
    }

    // -- RETURN/THROW/BREAK/CONTINUE --
    case 'return_statement': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }
    case 'throw_expression': {
      const throwN = createNode({ label: 'throw', node_type: 'CONTROL', node_subtype: 'throw', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      throwN.tags.push('error-source');
      ctx.neuralMap.nodes.push(throwN); ctx.lastCreatedNodeId = throwN.id; ctx.emitContainsIfNeeded(throwN.id);
      break;
    }
    case 'break_statement': {
      const breakN = createNode({ label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(breakN); ctx.lastCreatedNodeId = breakN.id; ctx.emitContainsIfNeeded(breakN.id);
      break;
    }
    case 'continue_statement': {
      const contN = createNode({ label: 'continue', node_type: 'CONTROL', node_subtype: 'continue', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(contN); ctx.lastCreatedNodeId = contN.id; ctx.emitContainsIfNeeded(contN.id);
      break;
    }

    // -- Yield --
    case 'yield_expression': {
      const yieldN = createNode({ label: 'yield', node_type: 'CONTROL', node_subtype: 'yield', language: 'php', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(yieldN); ctx.lastCreatedNodeId = yieldN.id; ctx.emitContainsIfNeeded(yieldN.id);
      break;
    }

    // -- AUGMENTED ASSIGNMENT: $html .= $tainted --
    case 'augmented_assignment_expression': {
      const augOp = node.children.find(c => c.type?.endsWith('=') && c.type !== 'variable_name')?.text ?? '.=';
      const augLeftNode = node.childForFieldName('left');
      const augLeft = augLeftNode?.text?.slice(0, 40) ?? '?';
      const augRight = node.childForFieldName('right');

      // Pre-scan: check if the RHS is tainted and contains HTML tags
      // Pattern: $html .= '<pre>' . $_GET['name'] . '</pre>' is XSS (HTML output building)
      const augTaintSources = augRight ? extractTaintSources(augRight, ctx) : [];
      const augCodeSnap = node.text.slice(0, 200);
      const isHtmlConcat = augOp === '.=' && /<[a-z][a-z0-9]*[\s>\/]/i.test(augCodeSnap);
      const isEgressLike = augTaintSources.length > 0 && isHtmlConcat;

      const augN = createNode({
        label: `${augLeft} ${augOp}`,
        // When tainted data is concatenated into HTML, treat as EGRESS/display
        // This catches the common PHP pattern: $html .= '<tag>' . $userInput . '</tag>'
        node_type: isEgressLike ? 'EGRESS' : 'TRANSFORM',
        node_subtype: isEgressLike ? 'display' : 'assignment',
        language: 'php',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: augCodeSnap,
      });
      if (isEgressLike) {
        augN.attack_surface.push('html_output');
      }
      ctx.neuralMap.nodes.push(augN);
      ctx.lastCreatedNodeId = augN.id;
      ctx.emitContainsIfNeeded(augN.id);

      if (augTaintSources.length > 0) {
        for (const source of augTaintSources) {
          ctx.addDataFlow(source.nodeId, augN.id, source.name, 'unknown', true);
        }
        if (augLeftNode?.type === 'variable_name') {
          const varInfo = ctx.resolveVariable(getVarName(augLeftNode));
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
      break;
    }

    // -- Silent pass-throughs --
    case 'expression_statement':
    case 'parenthesized_expression':
    case 'comment':
    case 'php_tag':
    case 'text_interpolation':
      break;
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction -- check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'function_definition' && node.type !== 'method_declaration' &&
      node.type !== 'anonymous_function_creation_expression' && node.type !== 'arrow_function') {
    return;
  }

  const body = node.childForFieldName('body');
  if (!body) return;

  // Arrow function: single expression body
  if (node.type === 'arrow_function') {
    const bodyExpr = node.childForFieldName('body');
    if (bodyExpr && bodyExpr.type !== 'compound_statement') {
      const taintSources = extractTaintSources(bodyExpr, ctx);
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

  // Function/method: compound_statement body -- check for return statements
  if (body.type === 'compound_statement') {
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
// preVisitIteration -- set up loop variable taint for foreach
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'foreach_statement') return;

  // foreach ($items as $key => $value) OR foreach ($items as $value)
  // The iterable is the first expression after `foreach (`
  const iterRight = node.namedChildren[0]; // The collection being iterated
  if (iterRight) {
    const iterTaint = extractTaintSources(iterRight, ctx);
    if (iterTaint.length > 0) {
      // Find the foreach value variable
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child?.type === 'variable_name') {
          const varName = getVarName(child);
          ctx.declareVariable(varName, 'let', null, true, iterTaint[0].nodeId);
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration -- re-mark loop variable taint after body walk
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'foreach_statement') return;

  const iterRight = node.namedChildren[0];
  if (iterRight) {
    const iterTaint = extractTaintSources(iterRight, ctx);
    if (iterTaint.length > 0) {
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child?.type === 'variable_name') {
          const varName = getVarName(child);
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

export const phpProfile: LanguageProfile = {
  id: 'php',
  extensions: ['.php', '.phtml'],

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

  analyzeStructure(_node: SyntaxNode): StructuralAnalysisResult | null {
    // PHP framework middleware patterns (Laravel middleware, Symfony security)
    // are handled via attributes/annotations, not inline middleware chains.
    // Return null for now.
    return null;
  },

  // Layer 4: Taint Source Detection
  ingressPattern: /(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[|\$request->(?:input|get|post|query|all|only|except|file|header|cookie|ip|path|url|fullUrl|method|json|validate|validated)\s*\(|file_get_contents\s*\(\s*['"]php:\/\/input['"]|Request::(?:input|get|query)\s*\()/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) => nodeType === 'expression_statement',
  getDeclarationValueNode: (node) => {
    // PHP: expression_statement → assignment_expression/augmented_assignment_expression → 'right'
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child?.type === 'assignment_expression' || child?.type === 'augmented_assignment_expression') {
        return child.childForFieldName('right');
      }
    }
    return null;
  },
  isStatementContainer: (nodeType: string) => nodeType === 'program' || nodeType === 'compound_statement' || nodeType === 'declaration_list',

  // Inter-procedural taint: PHP function syntax
  // Matches: function name(params) | public function name(params) | public static function name(params)
  // Group 1 captures the full parameter list between parentheses.
  functionParamPattern: /(?:(?:public|protected|private|static)\s+)*function\s+\w+\s*\(([^)]*)\)/,
};

export default phpProfile;
