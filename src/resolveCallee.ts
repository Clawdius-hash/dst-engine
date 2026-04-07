/**
 * resolveCallee — takes a tree-sitter node and determines the Neural Map
 * node type by analyzing the callee chain and looking it up in the pattern DB.
 *
 * Handles:
 *   - Simple calls: fetch('/api'), require('express')
 *   - Member calls: res.json(user), JSON.parse(data)
 *   - Chained calls: db.collection('users').find({id})
 *   - new expressions: new Buffer(data)
 *   - Property access (non-call): req.body.username, process.env.SECRET
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { NodeType } from './types.js';
import { getCalleeChain } from './cstWalker.js';
import { lookupCallee } from './calleePatterns.js';

export interface ResolvedCallee {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
  chain: string[];  // the callee chain that matched, for debugging/display
}

/**
 * Resolve a call_expression node to a Neural Map node type.
 *
 * @param node - A tree-sitter node of type 'call_expression'
 * @returns Resolved type info, or null if the callee is unknown
 *
 * Algorithm:
 *   1. Extract callee chain from the call_expression node
 *   2. Try lookupCallee with the full chain
 *   3. If the call_expression's callee is itself a call_expression (chained call),
 *      walk through the chain to find the terminal method
 *   4. Check if parent is new_expression for constructor detection
 *   5. Return resolved type or null
 */
export function resolveCallee(node: SyntaxNode): ResolvedCallee | null {
  if (node.type !== 'call_expression') return null;

  // Get the callee child (the function/method being called)
  let callee = node.childForFieldName('function');
  if (!callee) return null;

  // Unwrap parenthesized expressions: (eval)(...) or (0, eval)(...)
  // The comma operator evaluates all operands and returns the last one,
  // so (0, eval) === eval. This is a common trick for indirect eval.
  if (callee.type === 'parenthesized_expression') {
    let inner = callee.namedChild(0);
    // Handle sequence_expression (comma operator): (0, eval) → eval is last child
    if (inner && inner.type === 'sequence_expression') {
      const lastChild = inner.namedChild(inner.namedChildCount - 1);
      if (lastChild) inner = lastChild;
    }
    if (inner && inner.type === 'identifier') {
      // Direct lookup for unwrapped identifier — getCalleeChain can't see through parens
      const directPattern = lookupCallee([inner.text]);
      if (directPattern) {
        return {
          nodeType: directPattern.nodeType,
          subtype: directPattern.subtype,
          tainted: directPattern.tainted,
          chain: [inner.text],
        };
      }
    }
    if (inner && (inner.type === 'identifier' || inner.type === 'member_expression')) {
      callee = inner;
    }
  }

  // Case 1: Callee is a chained call — db.collection('users').find({id})
  // The outer call_expression's callee is itself a call_expression (the inner call).
  // We need to look at the outermost member access to find .find()
  if (callee.type === 'call_expression') {
    return resolveChainedCall(node);
  }

  // Case 1.5: Callee is member_expression whose object is a call_expression
  // This covers two important patterns:
  // a) require('fs').readFile(...) → chain ['fs', 'readFile']
  // b) res.status(404).send(...) → chain ['res', 'send'] (chained Express methods)
  if (callee.type === 'member_expression') {
    const obj = callee.childForFieldName('object');
    const prop = callee.childForFieldName('property');
    if (obj && prop && obj.type === 'call_expression') {
      // Special case: require('module').method() — use module name
      const innerFunc = obj.childForFieldName('function');
      if (innerFunc && innerFunc.type === 'identifier' && innerFunc.text === 'require') {
        const args = obj.childForFieldName('arguments');
        const firstArg = args?.namedChild(0);
        if (firstArg && (firstArg.type === 'string' || firstArg.type === 'template_string')) {
          const moduleName = firstArg.text.replace(/^['"`]|['"`]$/g, '');
          const requireChain = [moduleName, prop.text];
          const requirePattern = lookupCallee(requireChain);
          if (requirePattern) {
            return {
              nodeType: requirePattern.nodeType,
              subtype: requirePattern.subtype,
              tainted: requirePattern.tainted,
              chain: requireChain,
            };
          }
        }
      }
      // General case: obj.method().terminal() — build chain, try full then [root, terminal]
      // e.g., res.status(404).send() → try ['res', 'status', 'send'], then ['res', 'send']
      const innerChain = extractFullChain(obj);
      const fullChain = [...innerChain, prop.text];
      const fullPattern = lookupCallee(fullChain);
      if (fullPattern) {
        return { nodeType: fullPattern.nodeType, subtype: fullPattern.subtype, tainted: fullPattern.tainted, chain: fullChain };
      }
      // Try [root, terminal] — skip intermediate chained calls
      if (fullChain.length > 2) {
        const shortChain = [fullChain[0], fullChain[fullChain.length - 1]];
        const shortPattern = lookupCallee(shortChain);
        if (shortPattern) {
          return { nodeType: shortPattern.nodeType, subtype: shortPattern.subtype, tainted: shortPattern.tainted, chain: shortChain };
        }
      }
    }
  }

  // Case 2: Normal call or member expression
  // NOTE: getCalleeChain expects the call_expression node, not its callee/function field
  const chain = getCalleeChain(node);
  if (chain.length === 0) return null;

  // Strip .call(), .apply(), .bind() — these delegate to the original function
  // e.g., db.query.call(db, sql) → chain ['db', 'query', 'call'] → strip to ['db', 'query']
  const DELEGATE_METHODS = new Set(['call', 'apply', 'bind']);
  const effectiveChain = (chain.length >= 2 && DELEGATE_METHODS.has(chain[chain.length - 1]))
    ? chain.slice(0, -1)
    : chain;

  const pattern = lookupCallee(effectiveChain);
  if (!pattern) return null;

  return {
    nodeType: pattern.nodeType,
    subtype: pattern.subtype,
    tainted: pattern.tainted,
    chain: effectiveChain,
  };
}

/**
 * Handle chained calls like db.collection('users').find({id}).
 *
 * tree-sitter AST for `db.collection('users').find({id})`:
 *
 *   call_expression                          ← outer (we receive this)
 *     function: member_expression
 *       object: call_expression              ← inner call: db.collection('users')
 *         function: member_expression
 *           object: identifier "db"
 *           property: property_identifier "collection"
 *         arguments: ...
 *       property: property_identifier "find" ← the method we care about
 *     arguments: ...
 *
 * Strategy: the outer call's callee is a member_expression whose object is a
 * call_expression. We collect the full chain by walking the inner calls and
 * appending the final property.
 */
function resolveChainedCall(outerCall: SyntaxNode): ResolvedCallee | null {
  const outerCallee = outerCall.childForFieldName('function');
  if (!outerCallee) return null;

  // If the outer callee is a member_expression, we want its property + the inner chain
  if (outerCallee.type === 'member_expression') {
    const property = outerCallee.childForFieldName('property');
    const object = outerCallee.childForFieldName('object');

    if (!property || !object) return null;

    // Build chain from the inner object
    const innerChain = extractFullChain(object);
    const fullChain = [...innerChain, property.text];

    // Try full chain first, then progressively shorter prefixes with the terminal method.
    // e.g., ['res', 'status', 'send'] → try full, then ['res', 'send'] (skip intermediates)
    // This handles Express chaining: res.status(404).send() should match 'res.send'
    const pattern = lookupCallee(fullChain);
    if (pattern) {
      return {
        nodeType: pattern.nodeType,
        subtype: pattern.subtype,
        tainted: pattern.tainted,
        chain: fullChain,
      };
    }

    // Try [root, terminal_method] — skip intermediate chained calls
    if (fullChain.length > 2) {
      const shortChain = [fullChain[0], fullChain[fullChain.length - 1]];
      const shortPattern = lookupCallee(shortChain);
      if (shortPattern) {
        return {
          nodeType: shortPattern.nodeType,
          subtype: shortPattern.subtype,
          tainted: shortPattern.tainted,
          chain: shortChain,
        };
      }
    }

    return null;
  }

  // Fallback: just try getCalleeChain on whatever we have
  const chain = getCalleeChain(outerCallee);
  if (chain.length === 0) return null;

  const pattern = lookupCallee(chain);
  if (!pattern) return null;

  return {
    nodeType: pattern.nodeType,
    subtype: pattern.subtype,
    tainted: pattern.tainted,
    chain,
  };
}

/**
 * Recursively extract the identifier chain from a potentially nested
 * call/member expression.
 *
 * Examples:
 *   identifier "db"                          → ['db']
 *   member_expression (db.collection)        → ['db', 'collection']
 *   call_expression (db.collection('users')) → ['db', 'collection']
 *     (calls are transparent — we look through them)
 */
function extractFullChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier') {
    return [node.text];
  }

  if (node.type === 'member_expression') {
    const object = node.childForFieldName('object');
    const property = node.childForFieldName('property');
    if (!object || !property) return [];
    return [...extractFullChain(object), property.text];
  }

  if (node.type === 'call_expression') {
    // Special case: require('module').method() — use the module name as the object
    // e.g., require('fs').readFile(...) → chain should be ['fs', 'readFile']
    const callee = node.childForFieldName('function');
    if (callee && callee.type === 'identifier' && callee.text === 'require') {
      const args = node.childForFieldName('arguments');
      const firstArg = args?.namedChild(0);
      if (firstArg?.type === 'string' || firstArg?.type === 'template_string') {
        // Extract module name without quotes: 'fs' → fs, "child_process" → child_process
        const moduleName = firstArg.text.replace(/^['"`]|['"`]$/g, '');
        return [moduleName];
      }
    }
    // Look through the call to its callee
    if (!callee) return [];
    return extractFullChain(callee);
  }

  return [];
}

/**
 * Resolve a member_expression node to a Neural Map node type.
 * For property ACCESS (not calls) like req.body.username, process.env.SECRET.
 *
 * @param node - A tree-sitter node of type 'member_expression'
 * @returns Resolved type info, or null if the access pattern is unknown
 */
export function resolvePropertyAccess(node: SyntaxNode): ResolvedCallee | null {
  if (node.type !== 'member_expression') return null;

  // Use extractFullChain (not getCalleeChain which expects call_expression)
  const chain = extractFullChain(node);
  if (chain.length < 2) return null;

  // Try progressively shorter prefixes: req.params.id → try full, then req.params
  // Property access patterns like req.body.username match on the first two elements
  for (let len = chain.length; len >= 2; len--) {
    const subChain = chain.slice(0, len);
    const pattern = lookupCallee(subChain);
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

/**
 * Check if a call_expression is inside a new_expression.
 * Used to detect constructor calls: new Buffer(data), new Error(msg), etc.
 *
 * @param node - A tree-sitter call_expression node
 * @returns true if this call is the argument to `new`
 */
export function isNewExpression(node: SyntaxNode): boolean {
  const parent = node.parent;
  if (!parent) return false;
  return parent.type === 'new_expression';
}
