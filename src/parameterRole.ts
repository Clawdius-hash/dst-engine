import type Parser from 'web-tree-sitter';
import { getModuleCategory, type ModuleCategory } from './moduleIdentity.js';

/**
 * Parameter roles derived from structural AST analysis.
 *
 * - input:        Properties are READ from this parameter (.body, .headers, .query)
 * - output:       Methods are CALLED on this parameter (.send, .json, .status)
 * - continuation: This parameter is INVOKED as a function (next())
 * - data:         Used as a plain value (string, number, passed directly)
 * - unknown:      Insufficient usage data to determine role
 */
export type ParameterRole = 'input' | 'output' | 'continuation' | 'data' | 'unknown';

/**
 * Tracks how a function parameter is used within the function body.
 * Built by walking the AST — no pattern matching, pure structural observation.
 */
export interface ParameterUsage {
  /** Parameter name from the function signature */
  name: string;
  /** Properties read via member_expression: req.body → 'body' */
  propertiesRead: Set<string>;
  /** Properties assigned to: param.x = val → 'x' */
  propertiesWritten: Set<string>;
  /** Methods called on this parameter: res.send() → 'send' */
  methodsCalled: Set<string>;
  /** Whether this parameter is invoked as a function: next() */
  invokedAsFunction: boolean;
  /** Whether this parameter is passed as an argument to another call */
  passedAsArgument: boolean;
}

/**
 * Data origin classification for function parameters.
 * Determined by where the function sits in the call graph.
 */
export type DataOrigin =
  | 'external_callback'   // Function passed as callback to external module
  | 'internal_call'       // Function called internally with known arguments
  | 'export_entry'        // Function exported but never called in codebase
  | 'unknown';            // Cannot determine origin

/**
 * Combined inference result for a function parameter.
 */
export interface ParameterInference {
  name: string;
  role: ParameterRole;
  origin: DataOrigin;
  usage: ParameterUsage;
  /** Module category if origin is external_callback (e.g., 'HTTP_FRAMEWORK', 'DATABASE') */
  moduleCategory?: string;
}

/**
 * Create an empty ParameterUsage for a given parameter name.
 */
export function createEmptyUsage(name: string): ParameterUsage {
  return {
    name,
    propertiesRead: new Set(),
    propertiesWritten: new Set(),
    methodsCalled: new Set(),
    invokedAsFunction: false,
    passedAsArgument: false,
  };
}

/**
 * Walk a function body's AST and observe how each parameter is used.
 * Pure structural analysis — no callee pattern lookups, no framework knowledge.
 */
export function analyzeParameterUsage(
  functionBody: Parser.SyntaxNode,
  paramNames: string[],
): Map<string, ParameterUsage> {
  const paramSet = new Set(paramNames);
  const usages = new Map<string, ParameterUsage>();
  for (const name of paramNames) {
    usages.set(name, createEmptyUsage(name));
  }

  function walk(node: Parser.SyntaxNode): void {
    // 1. Member expression: param.property
    if (node.type === 'member_expression') {
      const obj = node.childForFieldName('object');
      const prop = node.childForFieldName('property');
      if (obj && prop) {
        const rootIdent = extractRootIdentifier(obj);
        if (rootIdent && paramSet.has(rootIdent)) {
          const usage = usages.get(rootIdent)!;
          const parent = node.parent;

          if (parent?.type === 'call_expression' &&
              parent.childForFieldName('function')?.id === node.id) {
            usage.methodsCalled.add(prop.text);
          } else if (parent?.type === 'assignment_expression' &&
                     parent.childForFieldName('left')?.id === node.id) {
            usage.propertiesWritten.add(prop.text);
          } else {
            if (obj.type === 'identifier' && obj.text === rootIdent) {
              usage.propertiesRead.add(prop.text);
            }
          }
        }
      }
    }

    // 2. Subscript expression: param['property']
    if (node.type === 'subscript_expression') {
      const obj = node.childForFieldName('object');
      const index = node.childForFieldName('index');
      if (obj && index && obj.type === 'identifier' && paramSet.has(obj.text)) {
        const usage = usages.get(obj.text)!;
        if (index.type === 'string' || index.type === 'template_string') {
          const key = index.text.replace(/^['"`]|['"`]$/g, '');
          if (key) usage.propertiesRead.add(key);
        }
      }
    }

    // 3. Call expression: param() — parameter invoked as function
    if (node.type === 'call_expression') {
      const func = node.childForFieldName('function');
      if (func && func.type === 'identifier' && paramSet.has(func.text)) {
        usages.get(func.text)!.invokedAsFunction = true;
      }

      // 4. Parameter passed as argument: someFunc(param)
      const args = node.childForFieldName('arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (arg && arg.type === 'identifier' && paramSet.has(arg.text)) {
            usages.get(arg.text)!.passedAsArgument = true;
          }
        }
      }
    }

    // 5. Destructuring: const { body, headers } = param
    if (node.type === 'variable_declarator') {
      const name = node.childForFieldName('name');
      const value = node.childForFieldName('value');
      if (name?.type === 'object_pattern' && value?.type === 'identifier' && paramSet.has(value.text)) {
        const usage = usages.get(value.text)!;
        for (let i = 0; i < name.namedChildCount; i++) {
          const prop = name.namedChild(i);
          if (prop) {
            const key = prop.type === 'shorthand_property_identifier_pattern'
              ? prop.text
              : prop.childForFieldName('key')?.text;
            if (key) usage.propertiesRead.add(key);
          }
        }
      }
    }

    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) walk(child);
    }
  }

  walk(functionBody);
  return usages;
}

/**
 * Extract the root identifier from a potentially nested member expression.
 * req.body.user.name -> 'req'
 */
function extractRootIdentifier(node: Parser.SyntaxNode): string | null {
  if (node.type === 'identifier') return node.text;
  if (node.type === 'member_expression') {
    const obj = node.childForFieldName('object');
    if (obj) return extractRootIdentifier(obj);
  }
  if (node.type === 'call_expression') {
    const func = node.childForFieldName('function');
    if (func) return extractRootIdentifier(func);
  }
  return null;
}

/**
 * Infer the structural role of a parameter from its usage patterns.
 */
export function inferRole(usage: ParameterUsage): ParameterRole {
  if (usage.invokedAsFunction && usage.propertiesRead.size === 0 && usage.methodsCalled.size === 0) {
    return 'continuation';
  }
  if (usage.invokedAsFunction && usage.propertiesRead.size === 0) {
    return 'continuation';
  }
  if (usage.propertiesRead.size > 0) {
    return 'input';
  }
  if (usage.methodsCalled.size > 0) {
    return 'output';
  }
  if (usage.passedAsArgument || usage.propertiesWritten.size > 0) {
    return 'data';
  }
  return 'unknown';
}

export interface CallbackOriginResult {
  isExternal: boolean;
  moduleCategory?: ModuleCategory;
  moduleName?: string;
}

/**
 * Determine if a function passed as argument to a call expression
 * is being registered with an external module.
 */
export function detectCallbackOrigin(
  callExpression: Parser.SyntaxNode,
  callbackNode: Parser.SyntaxNode,
  rootNode: Parser.SyntaxNode,
): CallbackOriginResult {
  if (callExpression.type !== 'call_expression') {
    return { isExternal: false };
  }

  const callee = callExpression.childForFieldName('function');
  if (!callee) return { isExternal: false };

  const rootIdent = extractRootIdentifier(callee);
  if (!rootIdent) return { isExternal: false };

  const moduleName = traceToModuleSource(rootIdent, rootNode);
  if (!moduleName) return { isExternal: false };

  const category = getModuleCategory(moduleName);
  if (!category) return { isExternal: false };

  return {
    isExternal: true,
    moduleCategory: category,
    moduleName,
  };
}

/**
 * Trace a variable name back to its require() or import source.
 */
function traceToModuleSource(varName: string, rootNode: Parser.SyntaxNode): string | null {
  // Strategy 1: Find require() declarations
  const declarations = rootNode.descendantsOfType('variable_declarator');
  for (const decl of declarations) {
    const name = decl.childForFieldName('name');
    if (!name || name.text !== varName) continue;

    const value = decl.childForFieldName('value');
    if (!value) continue;

    // Direct require: const x = require('mod')
    const reqModule = extractRequireModule(value);
    if (reqModule) return reqModule;

    // Factory pattern: const app = require('express')()
    if (value.type === 'call_expression') {
      const innerFunc = value.childForFieldName('function');
      if (innerFunc) {
        const reqModule2 = extractRequireModule(innerFunc);
        if (reqModule2) return reqModule2;

        // Generic factory: const app = express() where express is imported/required
        const factoryIdent = extractRootIdentifier(innerFunc);
        if (factoryIdent && factoryIdent !== varName) {
          const traced = traceToModuleSource(factoryIdent, rootNode);
          if (traced) return traced;
        }
      }
    }

    // new Constructor: const client = new pg.Client()
    if (value.type === 'new_expression') {
      const constructor = value.childForFieldName('constructor');
      if (constructor) {
        const rootOfNew = extractRootIdentifier(constructor);
        if (rootOfNew && rootOfNew !== varName) {
          // Recursively trace: if const pg = require('pg'), and we have new pg.Client()
          const traced = traceToModuleSource(rootOfNew, rootNode);
          if (traced) return traced;
        }
      }
    }
  }

  // Strategy 2: Find import declarations
  const imports = rootNode.descendantsOfType('import_statement');
  for (const imp of imports) {
    const source = imp.childForFieldName('source');
    if (!source) continue;
    const moduleName = source.text.replace(/^['"`]|['"`]$/g, '');

    const clause = imp.children.find(c => c.type === 'import_clause');
    if (clause) {
      for (let i = 0; i < clause.namedChildCount; i++) {
        const child = clause.namedChild(i);
        // Default import: import express from 'express'
        if (child?.type === 'identifier' && child.text === varName) {
          return moduleName;
        }
        // Named imports: import { Router } from 'express'
        if (child?.type === 'named_imports') {
          for (let j = 0; j < child.namedChildCount; j++) {
            const spec = child.namedChild(j);
            if (!spec) continue;
            const alias = spec.childForFieldName('alias');
            const specName = spec.childForFieldName('name');
            const localName = alias?.text ?? specName?.text;
            if (localName === varName) return moduleName;
          }
        }
      }
    }
  }

  return null;
}

/**
 * Extract module name from a require() call expression node.
 */
function extractRequireModule(node: Parser.SyntaxNode): string | null {
  if (node.type !== 'call_expression') return null;
  const func = node.childForFieldName('function');
  if (!func || func.text !== 'require') return null;
  const args = node.childForFieldName('arguments');
  if (!args || args.namedChildCount === 0) return null;
  const firstArg = args.namedChild(0);
  if (!firstArg || (firstArg.type !== 'string' && firstArg.type !== 'template_string')) return null;
  return firstArg.text.replace(/^['"`]|['"`]$/g, '');
}
