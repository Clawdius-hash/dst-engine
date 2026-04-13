/**
 * extractStorageMetadata — extracts structured storage target info (table names,
 * collection names, file paths, env var names, model names) from the AST at
 * classification time.
 *
 * Operates on tree-sitter AST nodes, NOT regex on code strings. The only text
 * parsing happens on SQL string literals that have already been identified as
 * SQL via AST-based callee resolution.
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { ResolvedCallee } from './resolveCallee.js';

export interface StorageTarget {
  kind: 'table' | 'collection' | 'model' | 'file' | 'env' | 'cache_key';
  name: string;
}

/**
 * Extract storage metadata from a call_expression (or member_expression) AST node
 * and its resolved callee info.
 *
 * @param node - A tree-sitter call_expression or member_expression node (may be null for property access patterns)
 * @param resolution - The resolved callee info from resolveCallee/resolvePropertyAccess
 * @returns StorageTarget or null if no extractable metadata
 */
export function extractStorageMetadata(
  node: SyntaxNode | null,
  resolution: ResolvedCallee | null,
): StorageTarget | null {
  if (!resolution) return null;

  const { chain, subtype } = resolution;

  // ENV VAR: chain like ['process', 'env', 'DATABASE_URL']
  // The node may be null for property access patterns (process.env.X without call)
  if (chain.length >= 3 && chain[0] === 'process' && chain[1] === 'env') {
    return { kind: 'env', name: chain[2]! };
  }

  // PRISMA: chain like ['prisma', 'user', 'create'] where the middle element is the model
  // Prisma patterns: prisma.<model>.<operation>
  // Skip raw query patterns like prisma.$queryRawUnsafe
  if (
    chain.length >= 3 &&
    chain[0] === 'prisma' &&
    !chain[1]!.startsWith('$')
  ) {
    return { kind: 'model', name: chain[1]! };
  }

  // MONGODB: chain contains 'collection' — find the .collection() call's first string arg
  if (chain.includes('collection')) {
    const collectionName = extractCollectionArg(node);
    if (collectionName) {
      return { kind: 'collection', name: collectionName };
    }
  }

  // FILE I/O: subtype is file_read or file_write — first arg is the file path
  if (subtype === 'file_read' || subtype === 'file_write') {
    if (node && node.type === 'call_expression') {
      const firstArgText = getFirstArgStringValue(node);
      if (firstArgText) {
        return { kind: 'file', name: firstArgText };
      }
    }
  }

  // SQL: subtype is db_read, db_write, or sql_query — extract table name from first arg
  if (subtype === 'db_read' || subtype === 'db_write' || subtype === 'sql_query') {
    if (node && node.type === 'call_expression') {
      const sqlText = getFirstArgStringValue(node);
      if (sqlText) {
        const tableName = extractTableFromSQL(sqlText);
        if (tableName) {
          return { kind: 'table', name: tableName };
        }
      }
    }
  }

  return null;
}

/**
 * Walk the AST to find a .collection("name") call and extract the string argument.
 * For chained calls like db.collection('users').find({}), we need to find the
 * inner call_expression whose callee's property is 'collection'.
 */
function extractCollectionArg(node: SyntaxNode | null): string | null {
  if (!node) return null;

  // Walk through the AST looking for a call_expression with 'collection' as the method
  return walkForCollectionCall(node);
}

function walkForCollectionCall(node: SyntaxNode): string | null {
  // If this is a call_expression, check if its method name is 'collection'
  if (node.type === 'call_expression') {
    const funcNode = node.childForFieldName('function');
    if (funcNode?.type === 'member_expression') {
      const prop = funcNode.childForFieldName('property');
      if (prop?.text === 'collection') {
        // Found it -- get the first string argument
        return getFirstArgStringValue(node);
      }
    }
    // Also check children (the callee might contain the collection call)
    const callee = node.childForFieldName('function');
    if (callee) {
      const result = walkForCollectionCall(callee);
      if (result) return result;
    }
  }

  if (node.type === 'member_expression') {
    const obj = node.childForFieldName('object');
    if (obj) {
      const result = walkForCollectionCall(obj);
      if (result) return result;
    }
  }

  return null;
}

/**
 * Get the text value of the first argument to a call_expression, handling:
 * - string literals: "hello" / 'hello'
 * - template strings: `SELECT * FROM users`
 * - binary expressions (concatenation): "SELECT * FROM " + tableName
 */
function getFirstArgStringValue(callNode: SyntaxNode): string | null {
  const argsNode = callNode.childForFieldName('arguments');
  if (!argsNode) return null;

  const firstArg = argsNode.namedChild(0);
  if (!firstArg) return null;

  return extractStringContent(firstArg);
}

/**
 * Extract string content from various node types:
 * - string/string_fragment: literal string value
 * - template_string: concatenate string_fragment children
 * - binary_expression (+): walk left side to find string content
 */
function extractStringContent(node: SyntaxNode): string | null {
  // String literal: 'value' or "value"
  if (node.type === 'string') {
    // The string node wraps quotes + content. Get the string_fragment child.
    const fragment = node.namedChild(0);
    if (fragment && fragment.type === 'string_fragment') {
      return fragment.text;
    }
    // Fallback: strip quotes from the text
    return node.text.replace(/^['"`]|['"`]$/g, '');
  }

  // Template string: `SELECT * FROM users WHERE id = ${id}`
  if (node.type === 'template_string') {
    // Collect all string_fragment children (skipping template substitutions)
    const parts: string[] = [];
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child?.type === 'string_fragment') {
        parts.push(child.text);
      }
    }
    return parts.length > 0 ? parts.join('') : null;
  }

  // Binary expression (concatenation): "SELECT * FROM " + tableName
  // Walk left side to find the string part
  if (node.type === 'binary_expression') {
    const left = node.childForFieldName('left');
    if (left) {
      return extractStringContent(left);
    }
  }

  return null;
}

/**
 * Extract table name from a SQL string by finding keywords followed by a table name.
 * This is acceptable because:
 * 1. We already KNOW this is a SQL string (identified via AST-based callee resolution)
 * 2. We're just extracting a simple keyword->identifier pattern from known SQL text
 *
 * Handles: FROM, INTO, UPDATE, JOIN (case-insensitive)
 */
function extractTableFromSQL(sql: string): string | null {
  // Match FROM/INTO/UPDATE/JOIN followed by optional whitespace and a table name
  // Table name: word characters, optionally with schema prefix (schema.table)
  const match = sql.match(
    /\b(?:FROM|INTO|UPDATE|JOIN)\s+(?:`|"|'|\[)?(\w+(?:\.\w+)?)(?:`|"|'|\])?/i,
  );
  return match ? match[1]! : null;
}
