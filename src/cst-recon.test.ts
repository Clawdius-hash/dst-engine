/*
 * CST Reconnaissance -- tree-sitter JavaScript Node Type Reference
 *
 * This file documents how tree-sitter represents JavaScript/Express patterns
 * that the Neural Map mapper needs to handle. Run this test to regenerate
 * the documentation output.
 *
 * KEY FINDINGS (update after running):
 *
 * req.params.id:
 *   member_expression
 *     member_expression
 *       identifier "req"
 *       property_identifier "params"
 *     property_identifier "id"
 *
 * db.collection('users').find():
 *   call_expression
 *     member_expression
 *       call_expression
 *         member_expression
 *           identifier "db"
 *           property_identifier "collection"
 *         arguments: [ string "users" ]
 *       property_identifier "find"
 *     arguments: []
 *
 * const { name } = req.body:
 *   variable_declarator
 *     name: object_pattern
 *       shorthand_property_identifier_pattern "name"
 *     value: member_expression
 *       identifier "req"
 *       property_identifier "body"
 */

import { describe, it, expect } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import type { Node as SyntaxNode } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function createTestParser(): Promise<InstanceType<typeof Parser>> {
  await Parser.init();
  const parser = new Parser();
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const JavaScript = await Language.load(wasmBuffer);
  parser.setLanguage(JavaScript);
  return parser;
}

/** Recursively collect all unique named node types in a tree */
function collectNodeTypes(node: SyntaxNode): Set<string> {
  const types = new Set<string>();
  function walk(n: SyntaxNode): void {
    if (n.isNamed) {
      types.add(n.type);
    }
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (child) walk(child);
    }
  }
  walk(node);
  return types;
}

/** Pretty-print a node's structure up to a given depth */
function dumpNode(node: SyntaxNode, maxDepth: number = 4, indent: number = 0): string {
  const lines: string[] = [];
  const prefix = '  '.repeat(indent);
  const fieldName = node.parent
    ? (() => {
        const p = node.parent;
        if (!p) return null;
        for (let i = 0; i < p.childCount; i++) {
          const child = p.child(i);
          if (child && child.id === node.id) {
            return p.fieldNameForChild(i);
          }
        }
        return null;
      })()
    : null;
  const fieldLabel = fieldName ? `${fieldName}: ` : '';
  const textPreview = node.childCount === 0 ? ` "${node.text}"` : '';
  lines.push(`${prefix}${fieldLabel}${node.type}${textPreview}`);

  if (indent < maxDepth) {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.isNamed) {
        lines.push(dumpNode(child, maxDepth, indent + 1));
      }
    }
  }
  return lines.join('\n');
}

describe('CST Reconnaissance', () => {
  it('documents all node types in a comprehensive Express app', async () => {
    const parser = await createTestParser();

    const code = `
import express from 'express';
const { Router } = require('express');
const db = require('./db');

class AuthService {
  async validate(token) {
    if (!token) {
      throw new Error('No token');
    }
    return db.query('SELECT * FROM sessions WHERE token = ?', [token]);
  }
}

const router = Router();

router.get('/users/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    const { name, email } = req.body;
    const user = await db.collection('users').find({ id: userId });
    const sanitized = JSON.parse(JSON.stringify(user));
    res.json({ data: sanitized });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/exec', (req, res) => {
  const cmd = req.body.command;
  const result = eval(cmd);
  res.send(result);
});

function processTemplate(name) {
  return \`Hello, \${name}!\`;
}

for (const item of items) {
  console.log(item);
}

export default router;
`.trim();

    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');
    const root = tree.rootNode;
    const allTypes = collectNodeTypes(root);

    // Print all discovered node types sorted
    const sortedTypes = [...allTypes].sort();
    console.log('\n=== ALL NAMED NODE TYPES ===');
    console.log(sortedTypes.join('\n'));
    console.log(`\nTotal unique named types: ${sortedTypes.length}`);

    // Verify we found the essential types the mapper needs
    const essentialTypes = [
      'program',
      'function_declaration',
      'arrow_function',
      'class_declaration',
      'method_definition',
      'call_expression',
      'member_expression',
      'identifier',
      'property_identifier',
      'lexical_declaration',
      'variable_declarator',
      'if_statement',
      'for_in_statement',
      'try_statement',
      'catch_clause',
      'template_string',
      'string',
      'import_statement',
      'export_statement',
      'await_expression',
      'object_pattern',
      'formal_parameters',
    ];

    for (const t of essentialTypes) {
      expect(allTypes.has(t), `Missing expected type: ${t}`).toBe(true);
    }

    tree.delete();
    parser.delete();
  });

  it('documents req.params.id structure', async () => {
    const parser = await createTestParser();
    const code = `const userId = req.params.id;`;
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const members = tree.rootNode.descendantsOfType('member_expression');
    // req.params.id is a nested member_expression
    expect(members.length).toBe(2);

    // The outermost member_expression is req.params.id
    const outer = members.find(m => m && m.text === 'req.params.id');
    expect(outer).toBeDefined();

    console.log('\n=== req.params.id ===');
    console.log(dumpNode(outer!, 5));

    // Structure: member_expression( member_expression(identifier "req", property_identifier "params"), property_identifier "id" )
    expect(outer!.type).toBe('member_expression');
    const obj = outer!.childForFieldName('object');
    expect(obj).toBeDefined();
    expect(obj!.type).toBe('member_expression');
    const prop = outer!.childForFieldName('property');
    expect(prop).toBeDefined();
    expect(prop!.type).toBe('property_identifier');
    expect(prop!.text).toBe('id');

    // Inner: req.params
    const innerObj = obj!.childForFieldName('object');
    expect(innerObj!.type).toBe('identifier');
    expect(innerObj!.text).toBe('req');
    const innerProp = obj!.childForFieldName('property');
    expect(innerProp!.text).toBe('params');

    tree.delete();
    parser.delete();
  });

  it('documents db.collection("users").find() structure', async () => {
    const parser = await createTestParser();
    const code = `db.collection('users').find({ id: 1 });`;
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const calls = tree.rootNode.descendantsOfType('call_expression');
    // Two call expressions: db.collection('users') and .find({id:1})
    expect(calls.length).toBe(2);

    // Outermost call is the .find() call
    const outerCall = calls.find(c => c && c.text.includes('.find'));
    expect(outerCall).toBeDefined();

    console.log('\n=== db.collection("users").find() ===');
    console.log(dumpNode(outerCall!, 6));

    // Structure:
    // call_expression
    //   function: member_expression
    //     object: call_expression           <-- db.collection('users')
    //       function: member_expression
    //         object: identifier "db"
    //         property: property_identifier "collection"
    //       arguments: (arguments (string))
    //     property: property_identifier "find"
    //   arguments: (arguments (object { ... }))

    const funcField = outerCall!.childForFieldName('function');
    expect(funcField!.type).toBe('member_expression');

    const innerCall = funcField!.childForFieldName('object');
    expect(innerCall!.type).toBe('call_expression');

    const innerFunc = innerCall!.childForFieldName('function');
    expect(innerFunc!.type).toBe('member_expression');

    const dbIdent = innerFunc!.childForFieldName('object');
    expect(dbIdent!.text).toBe('db');

    const collectionProp = innerFunc!.childForFieldName('property');
    expect(collectionProp!.text).toBe('collection');

    const findProp = funcField!.childForFieldName('property');
    expect(findProp!.text).toBe('find');

    tree.delete();
    parser.delete();
  });

  it('documents const { name } = req.body destructuring', async () => {
    const parser = await createTestParser();
    const code = `const { name, email } = req.body;`;
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const declarators = tree.rootNode.descendantsOfType('variable_declarator');
    expect(declarators.length).toBe(1);
    const decl = declarators[0]!;

    console.log('\n=== const { name, email } = req.body ===');
    console.log(dumpNode(decl, 5));

    // Structure:
    // variable_declarator
    //   name: object_pattern
    //     shorthand_property_identifier_pattern "name"
    //     shorthand_property_identifier_pattern "email"
    //   value: member_expression
    //     object: identifier "req"
    //     property: property_identifier "body"

    const nameField = decl.childForFieldName('name');
    expect(nameField!.type).toBe('object_pattern');

    const props = nameField!.namedChildren.filter(
      (c): c is NonNullable<typeof c> => c !== null
    );
    const propTexts = props.map(p => p.text);
    expect(propTexts).toContain('name');
    expect(propTexts).toContain('email');

    const valueField = decl.childForFieldName('value');
    expect(valueField!.type).toBe('member_expression');
    expect(valueField!.childForFieldName('object')!.text).toBe('req');
    expect(valueField!.childForFieldName('property')!.text).toBe('body');

    tree.delete();
    parser.delete();
  });

  it('documents arrow function parameters', async () => {
    const parser = await createTestParser();
    const code = `const handler = async (req, res, next) => { res.json({}); };`;
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const arrows = tree.rootNode.descendantsOfType('arrow_function');
    expect(arrows.length).toBe(1);
    const arrow = arrows[0]!;

    console.log('\n=== async (req, res, next) => {} ===');
    console.log(dumpNode(arrow, 4));

    // Parameters are in a formal_parameters node
    const params = arrow.childForFieldName('parameters');
    expect(params).toBeDefined();
    expect(params!.type).toBe('formal_parameters');

    const paramNames = params!.namedChildren
      .filter((c): c is NonNullable<typeof c> => c !== null)
      .map(c => c.text);
    expect(paramNames).toEqual(['req', 'res', 'next']);

    tree.delete();
    parser.delete();
  });

  it('documents class method structure', async () => {
    const parser = await createTestParser();
    const code = `
class UserService {
  async findById(id) {
    return this.db.query('SELECT * FROM users WHERE id = ?', [id]);
  }

  static create(data) {
    return new UserService(data);
  }
}`.trim();

    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const classDec = tree.rootNode.descendantsOfType('class_declaration');
    expect(classDec.length).toBe(1);

    console.log('\n=== Class with methods ===');
    console.log(dumpNode(classDec[0]!, 5));

    const methods = tree.rootNode.descendantsOfType('method_definition');
    expect(methods.length).toBe(2);

    const methodNames = methods
      .filter((m): m is NonNullable<typeof m> => m !== null)
      .map(m => m.childForFieldName('name')?.text);
    expect(methodNames).toContain('findById');
    expect(methodNames).toContain('create');

    // Verify we can detect 'this' usage
    const thisNodes = tree.rootNode.descendantsOfType('this');
    expect(thisNodes.length).toBeGreaterThanOrEqual(1);

    tree.delete();
    parser.delete();
  });

  it('documents template literal structure', async () => {
    const parser = await createTestParser();
    const code = 'const msg = `Hello, ${name}! Count: ${items.length}`;';
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const templates = tree.rootNode.descendantsOfType('template_string');
    expect(templates.length).toBe(1);

    console.log('\n=== Template literal ===');
    console.log(dumpNode(templates[0]!, 4));

    // Template substitutions are template_substitution nodes
    const subs = tree.rootNode.descendantsOfType('template_substitution');
    expect(subs.length).toBe(2);

    tree.delete();
    parser.delete();
  });

  it('documents import/require patterns', async () => {
    const parser = await createTestParser();
    const code = `
import express from 'express';
import { Router, json } from 'express';
const fs = require('fs');
const { readFile } = require('fs/promises');
`.trim();

    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    console.log('\n=== Import/require patterns ===');
    for (let i = 0; i < tree.rootNode.namedChildCount; i++) {
      const child = tree.rootNode.namedChild(i);
      if (child) {
        console.log(`\nStatement ${i}:`);
        console.log(dumpNode(child, 4));
      }
    }

    // ES import
    const imports = tree.rootNode.descendantsOfType('import_statement');
    expect(imports.length).toBe(2);

    // CommonJS require
    const calls = tree.rootNode.descendantsOfType('call_expression');
    const requires = calls.filter(c => {
      if (!c) return false;
      const func = c.childForFieldName('function');
      return func && func.type === 'identifier' && func.text === 'require';
    });
    expect(requires.length).toBe(2);

    tree.delete();
    parser.delete();
  });
});
