import { describe, it, expect } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import {
  walkTree,
  findNodesOfType,
  getNodeText,
  getCalleeChain,
  getParentFunction,
  getParentClass,
  getFormalParameters,
} from './cstWalker.js';

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

describe('walkTree', () => {
  it('visits every node depth-first', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('const x = 1;');
    if (!tree) throw new Error('Parse returned null');

    const visited: string[] = [];
    walkTree(tree.rootNode, (node) => {
      if (node.isNamed) visited.push(node.type);
    });

    expect(visited[0]).toBe('program');
    expect(visited).toContain('lexical_declaration');
    expect(visited).toContain('variable_declarator');
    expect(visited).toContain('identifier');
    expect(visited).toContain('number');

    tree.delete();
    parser.delete();
  });

  it('tracks depth correctly', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('const x = 1;');
    if (!tree) throw new Error('Parse returned null');

    const depthMap: Record<string, number> = {};
    walkTree(tree.rootNode, (node, depth) => {
      if (node.isNamed && !depthMap[node.type]) {
        depthMap[node.type] = depth;
      }
    });

    expect(depthMap['program']).toBe(0);
    expect(depthMap['lexical_declaration']).toBe(1);

    tree.delete();
    parser.delete();
  });
});

describe('findNodesOfType', () => {
  it('finds all nodes of a given type', async () => {
    const parser = await createTestParser();
    const code = `
const a = 1;
const b = 2;
let c = 3;
`.trim();
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const declarators = findNodesOfType(tree.rootNode, 'variable_declarator');
    expect(declarators).toHaveLength(3);
    expect(declarators.map(d => d.childForFieldName('name')?.text)).toEqual(['a', 'b', 'c']);

    tree.delete();
    parser.delete();
  });
});

describe('getNodeText', () => {
  it('returns source text of a node', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('const greeting = "hello";');
    if (!tree) throw new Error('Parse returned null');

    const strings = findNodesOfType(tree.rootNode, 'string');
    expect(strings).toHaveLength(1);
    expect(getNodeText(strings[0])).toBe('"hello"');

    tree.delete();
    parser.delete();
  });
});

describe('getCalleeChain', () => {
  it('resolves res.json(user) to ["res", "json"]', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('res.json(user);');
    if (!tree) throw new Error('Parse returned null');

    const calls = findNodesOfType(tree.rootNode, 'call_expression');
    expect(calls).toHaveLength(1);
    expect(getCalleeChain(calls[0])).toEqual(['res', 'json']);

    tree.delete();
    parser.delete();
  });

  it('resolves db.collection("users").find({id}) to ["db", "collection", "find"]', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('db.collection("users").find({id});');
    if (!tree) throw new Error('Parse returned null');

    const calls = findNodesOfType(tree.rootNode, 'call_expression');
    // Two call expressions: inner db.collection("users") and outer .find({id})
    // We want the outermost one (the .find call)
    const outerCall = calls.find(c => c && c.text.includes('.find'));
    expect(outerCall).toBeDefined();
    expect(getCalleeChain(outerCall!)).toEqual(['db', 'collection', 'find']);

    tree.delete();
    parser.delete();
  });

  it('resolves simple function call foo() to ["foo"]', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('foo();');
    if (!tree) throw new Error('Parse returned null');

    const calls = findNodesOfType(tree.rootNode, 'call_expression');
    expect(getCalleeChain(calls[0])).toEqual(['foo']);

    tree.delete();
    parser.delete();
  });

  it('resolves require("x") to ["require"]', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('require("express");');
    if (!tree) throw new Error('Parse returned null');

    const calls = findNodesOfType(tree.rootNode, 'call_expression');
    expect(getCalleeChain(calls[0])).toEqual(['require']);

    tree.delete();
    parser.delete();
  });

  it('resolves console.log(x) to ["console", "log"]', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('console.log(x);');
    if (!tree) throw new Error('Parse returned null');

    const calls = findNodesOfType(tree.rootNode, 'call_expression');
    expect(getCalleeChain(calls[0])).toEqual(['console', 'log']);

    tree.delete();
    parser.delete();
  });

  it('resolves this.db.query() to ["this", "db", "query"]', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('this.db.query("SELECT 1");');
    if (!tree) throw new Error('Parse returned null');

    const calls = findNodesOfType(tree.rootNode, 'call_expression');
    expect(getCalleeChain(calls[0])).toEqual(['this', 'db', 'query']);

    tree.delete();
    parser.delete();
  });

  it('handles deeply chained calls a.b().c().d()', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('a.b().c().d();');
    if (!tree) throw new Error('Parse returned null');

    // The outermost call is .d()
    // Find the call whose text is the full chain
    const calls = findNodesOfType(tree.rootNode, 'call_expression');
    const outermost = calls.reduce((prev, curr) =>
      curr.text.length > prev.text.length ? curr : prev
    );
    expect(getCalleeChain(outermost)).toEqual(['a', 'b', 'c', 'd']);

    tree.delete();
    parser.delete();
  });
});

describe('getParentFunction', () => {
  it('finds enclosing function_declaration', async () => {
    const parser = await createTestParser();
    const code = `
function outer() {
  const x = 1;
}
`.trim();
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const identifiers = findNodesOfType(tree.rootNode, 'number');
    // The "1" literal is inside "outer"
    const parentFn = getParentFunction(identifiers[0]);
    expect(parentFn).not.toBeNull();
    expect(parentFn!.type).toBe('function_declaration');
    expect(parentFn!.childForFieldName('name')?.text).toBe('outer');

    tree.delete();
    parser.delete();
  });

  it('finds enclosing arrow_function', async () => {
    const parser = await createTestParser();
    const code = `const handler = (req, res) => { res.json({}); };`;
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const calls = findNodesOfType(tree.rootNode, 'call_expression');
    // res.json is inside the arrow function
    const parentFn = getParentFunction(calls[0]);
    expect(parentFn).not.toBeNull();
    expect(parentFn!.type).toBe('arrow_function');

    tree.delete();
    parser.delete();
  });

  it('returns null at module level', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('const x = 1;');
    if (!tree) throw new Error('Parse returned null');

    const decls = findNodesOfType(tree.rootNode, 'lexical_declaration');
    const parentFn = getParentFunction(decls[0]);
    expect(parentFn).toBeNull();

    tree.delete();
    parser.delete();
  });

  it('finds method_definition in a class', async () => {
    const parser = await createTestParser();
    const code = `
class Foo {
  bar() {
    const x = 1;
  }
}
`.trim();
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const nums = findNodesOfType(tree.rootNode, 'number');
    const parentFn = getParentFunction(nums[0]);
    expect(parentFn).not.toBeNull();
    expect(parentFn!.type).toBe('method_definition');

    tree.delete();
    parser.delete();
  });
});

describe('getParentClass', () => {
  it('finds enclosing class_declaration', async () => {
    const parser = await createTestParser();
    const code = `
class UserService {
  async findById(id) {
    return id;
  }
}
`.trim();
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const identifiers = findNodesOfType(tree.rootNode, 'identifier');
    const idParam = identifiers.find(i => i.text === 'id' && getParentFunction(i));
    expect(idParam).toBeDefined();

    const parentClass = getParentClass(idParam!);
    expect(parentClass).not.toBeNull();
    expect(parentClass!.type).toBe('class_declaration');
    expect(parentClass!.childForFieldName('name')?.text).toBe('UserService');

    tree.delete();
    parser.delete();
  });

  it('returns null outside a class', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('function foo() { return 1; }');
    if (!tree) throw new Error('Parse returned null');

    const nums = findNodesOfType(tree.rootNode, 'number');
    const parentClass = getParentClass(nums[0]);
    expect(parentClass).toBeNull();

    tree.delete();
    parser.delete();
  });
});

describe('getFormalParameters', () => {
  it('extracts [req, res] from (req, res) => {}', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('const fn = (req, res) => {};');
    if (!tree) throw new Error('Parse returned null');

    const arrows = findNodesOfType(tree.rootNode, 'arrow_function');
    expect(arrows).toHaveLength(1);
    expect(getFormalParameters(arrows[0])).toEqual(['req', 'res']);

    tree.delete();
    parser.delete();
  });

  it('extracts params from function declaration', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('function process(input, options) { return input; }');
    if (!tree) throw new Error('Parse returned null');

    const funcs = findNodesOfType(tree.rootNode, 'function_declaration');
    expect(getFormalParameters(funcs[0])).toEqual(['input', 'options']);

    tree.delete();
    parser.delete();
  });

  it('handles default parameters', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('function greet(name = "world") {}');
    if (!tree) throw new Error('Parse returned null');

    const funcs = findNodesOfType(tree.rootNode, 'function_declaration');
    expect(getFormalParameters(funcs[0])).toEqual(['name']);

    tree.delete();
    parser.delete();
  });

  it('handles rest parameters', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('function collect(first, ...rest) {}');
    if (!tree) throw new Error('Parse returned null');

    const funcs = findNodesOfType(tree.rootNode, 'function_declaration');
    expect(getFormalParameters(funcs[0])).toEqual(['first', '...rest']);

    tree.delete();
    parser.delete();
  });

  it('handles destructured parameters', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('function handle({ name, email }) {}');
    if (!tree) throw new Error('Parse returned null');

    const funcs = findNodesOfType(tree.rootNode, 'function_declaration');
    const params = getFormalParameters(funcs[0]);
    expect(params).toHaveLength(1);
    // Destructured param returns the pattern text
    expect(params[0]).toContain('name');
    expect(params[0]).toContain('email');

    tree.delete();
    parser.delete();
  });

  it('returns empty array for no-param function', async () => {
    const parser = await createTestParser();
    const tree = parser.parse('function noop() {}');
    if (!tree) throw new Error('Parse returned null');

    const funcs = findNodesOfType(tree.rootNode, 'function_declaration');
    expect(getFormalParameters(funcs[0])).toEqual([]);

    tree.delete();
    parser.delete();
  });

  it('handles method_definition parameters', async () => {
    const parser = await createTestParser();
    const code = `
class Svc {
  process(data, callback) {}
}
`.trim();
    const tree = parser.parse(code);
    if (!tree) throw new Error('Parse returned null');

    const methods = findNodesOfType(tree.rootNode, 'method_definition');
    expect(methods).toHaveLength(1);
    expect(getFormalParameters(methods[0])).toEqual(['data', 'callback']);

    tree.delete();
    parser.delete();
  });
});
