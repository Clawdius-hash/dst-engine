// CST Walker utilities for tree-sitter syntax trees.
// These are the building blocks the mapper uses to navigate and extract
// information from the concrete syntax tree.

import type { Node as SyntaxNode } from 'web-tree-sitter';

/**
 * Depth-first traversal of a syntax tree. Calls the callback for every node
 * (both named and anonymous). Return `false` from callback to skip children.
 */
export function walkTree(
  node: SyntaxNode,
  callback: (node: SyntaxNode, depth: number) => void | false,
  depth: number = 0,
): void {
  const result = callback(node, depth);
  if (result === false) return; // skip children
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) {
      walkTree(child, callback, depth + 1);
    }
  }
}

/**
 * Find all descendant nodes matching a given type string.
 * Uses tree-sitter's built-in descendantsOfType for efficiency,
 * but filters out nulls for type safety.
 */
export function findNodesOfType(root: SyntaxNode, type: string): SyntaxNode[] {
  return root.descendantsOfType(type).filter(
    (n): n is NonNullable<typeof n> => n !== null
  );
}

/**
 * Get the source text of a node.
 */
export function getNodeText(node: SyntaxNode): string {
  return node.text;
}

/**
 * For a call_expression node, resolve the full callee chain as an array
 * of identifier strings.
 *
 * Examples:
 *   `res.json(user)` => ['res', 'json']
 *   `db.collection('users').find({id})` => ['db', 'collection', 'find']
 *   `console.log(x)` => ['console', 'log']
 *   `foo()` => ['foo']
 *   `require('x')` => ['require']
 *
 * For chained calls like `a.b().c().d()`, this returns the chain for the
 * outermost call: the function field's member chain. Inner calls appear
 * as intermediate nodes but their arguments are ignored -- we only care
 * about the identifier path.
 */
export function getCalleeChain(callExpression: SyntaxNode): string[] {
  const funcNode = callExpression.childForFieldName('function');
  if (!funcNode) return [];
  return resolveMemberChain(funcNode);
}

/**
 * Resolve a member_expression (or identifier) into its chain of identifiers.
 * Handles arbitrarily nested member expressions and chained calls.
 *
 *   `res.json` => ['res', 'json']
 *   `a.b.c` => ['a', 'b', 'c']
 *   `db.collection('x').find` => ['db', 'collection', 'find']
 */
function resolveMemberChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier') {
    return [node.text];
  }

  if (node.type === 'member_expression') {
    const object = node.childForFieldName('object');
    const property = node.childForFieldName('property');
    if (!object || !property) return [];

    const left = resolveMemberChain(object);
    const right = property.text;
    return [...left, right];
  }

  // FIX 3: Bracket notation with string literal key — cp['exec'] resolves as cp.exec
  if (node.type === 'subscript_expression') {
    const object = node.childForFieldName('object');
    const index = node.childForFieldName('index');
    if (object && index && (index.type === 'string' || index.type === 'template_string')) {
      const key = index.text.replace(/^['"`]|['"`]$/g, '');
      if (key) {
        const left = resolveMemberChain(object);
        return [...left, key];
      }
    }
  }

  if (node.type === 'call_expression') {
    // Chained call: the function part is what we need
    const innerFunc = node.childForFieldName('function');
    if (!innerFunc) return [];
    return resolveMemberChain(innerFunc);
  }

  // For this_expression, etc. -- return text as single element
  if (node.type === 'this') {
    return ['this'];
  }

  return [node.text];
}

/**
 * Walk up the tree to find the nearest enclosing function.
 * Matches: function_declaration, function, arrow_function, method_definition, generator_function_declaration.
 * Returns null if the node is at module level.
 */
export function getParentFunction(node: SyntaxNode): SyntaxNode | null {
  const functionTypes = new Set([
    'function_declaration',
    'function',
    'arrow_function',
    'method_definition',
    'generator_function_declaration',
  ]);

  let current = node.parent;
  while (current) {
    if (functionTypes.has(current.type)) {
      return current;
    }
    current = current.parent;
  }
  return null;
}

/**
 * Walk up the tree to find the nearest enclosing class.
 * Returns null if the node is not inside a class.
 */
export function getParentClass(node: SyntaxNode): SyntaxNode | null {
  let current = node.parent;
  while (current) {
    if (current.type === 'class_declaration' || current.type === 'class') {
      return current;
    }
    current = current.parent;
  }
  return null;
}

/**
 * Extract parameter names from a function node (function_declaration,
 * arrow_function, method_definition, etc.).
 *
 * Handles:
 *   - Simple params: (a, b, c)
 *   - Destructured params: ({ name, email })
 *   - Default values: (x = 5)
 *   - Rest params: (...args)
 *   - Single param arrow: x => x + 1 (no parens)
 *
 * Returns an array of parameter name strings. Destructured params
 * return the pattern text (e.g. "{ name, email }").
 */
export function getFormalParameters(funcNode: SyntaxNode): string[] {
  // method_definition: parameters are on the child function
  // arrow_function / function_declaration: has 'parameters' field

  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) {
    // Single-param arrow function without parens: x => x + 1
    // The parameter is the 'parameter' field on arrow_function
    const singleParam = funcNode.childForFieldName('parameter');
    if (singleParam) {
      return [singleParam.text];
    }
    return [];
  }

  // formal_parameters node contains the param list
  const params: string[] = [];
  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    switch (param.type) {
      case 'identifier':
        params.push(param.text);
        break;
      case 'assignment_pattern': {
        // Default value: x = 5
        const left = param.childForFieldName('left');
        if (left) params.push(left.text);
        break;
      }
      case 'rest_pattern': {
        // Rest: ...args
        // The child is the identifier
        const restIdent = param.namedChildren.find(
          (c): c is NonNullable<typeof c> => c !== null && c.type === 'identifier'
        );
        if (restIdent) params.push('...' + restIdent.text);
        break;
      }
      case 'object_pattern':
      case 'array_pattern':
        // Destructured: return the whole pattern text
        params.push(param.text);
        break;
      default:
        params.push(param.text);
    }
  }

  return params;
}
