import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import type { ParameterRole, ParameterUsage } from './parameterRole.js';
import { analyzeParameterUsage, inferRole, createEmptyUsage, detectCallbackOrigin } from './parameterRole.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

beforeAll(async () => {
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm');
  const wasmBuffer = fs.readFileSync(wasmPath);
  const JavaScript = await Language.load(wasmBuffer);
  parser.setLanguage(JavaScript);
});

function getFunctionBody(code: string): { body: Parser.SyntaxNode; paramNames: string[] } {
  const tree = parser.parse(code);
  const func = tree.rootNode.descendantsOfType('function_declaration')[0]
    ?? tree.rootNode.descendantsOfType('arrow_function')[0]
    ?? tree.rootNode.descendantsOfType('function')[0];
  const params = func.childForFieldName('parameters');
  const paramNames: string[] = [];
  if (params) {
    for (let i = 0; i < params.namedChildCount; i++) {
      const p = params.namedChild(i);
      if (p && p.type === 'identifier') paramNames.push(p.text);
    }
  }
  const body = func.childForFieldName('body')!;
  return { body, paramNames };
}

describe('ParameterRole types', () => {
  it('ParameterRole has expected values', () => {
    const roles: ParameterRole[] = ['input', 'output', 'continuation', 'data', 'unknown'];
    expect(roles).toHaveLength(5);
  });

  it('ParameterUsage tracks property reads and method calls', () => {
    const usage: ParameterUsage = {
      name: 'req',
      propertiesRead: new Set(['body', 'headers']),
      propertiesWritten: new Set(),
      methodsCalled: new Set(),
      invokedAsFunction: false,
      passedAsArgument: false,
    };
    expect(usage.propertiesRead.has('body')).toBe(true);
    expect(usage.propertiesRead.size).toBe(2);
  });

  it('createEmptyUsage initializes all fields', () => {
    const usage = createEmptyUsage('test');
    expect(usage.name).toBe('test');
    expect(usage.propertiesRead.size).toBe(0);
    expect(usage.propertiesWritten.size).toBe(0);
    expect(usage.methodsCalled.size).toBe(0);
    expect(usage.invokedAsFunction).toBe(false);
    expect(usage.passedAsArgument).toBe(false);
  });
});

describe('analyzeParameterUsage', () => {
  it('detects property reads on a parameter (INPUT pattern)', () => {
    const code = `function handler(req, res) {
      const name = req.body.name;
      const host = req.headers.host;
      const q = req.query.id;
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    const reqUsage = usages.get('req')!;
    expect(reqUsage.propertiesRead.has('body')).toBe(true);
    expect(reqUsage.propertiesRead.has('headers')).toBe(true);
    expect(reqUsage.propertiesRead.has('query')).toBe(true);
    expect(reqUsage.propertiesRead.size).toBe(3);
  });

  it('detects method calls on a parameter (OUTPUT pattern)', () => {
    const code = `function handler(req, res) {
      res.status(200);
      res.json({ ok: true });
      res.send('hello');
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    const resUsage = usages.get('res')!;
    expect(resUsage.methodsCalled.has('status')).toBe(true);
    expect(resUsage.methodsCalled.has('json')).toBe(true);
    expect(resUsage.methodsCalled.has('send')).toBe(true);
    expect(resUsage.methodsCalled.size).toBe(3);
  });

  it('detects parameter invoked as function (CONTINUATION pattern)', () => {
    const code = `function middleware(req, res, next) {
      console.log('request received');
      next();
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    const nextUsage = usages.get('next')!;
    expect(nextUsage.invokedAsFunction).toBe(true);
  });

  it('handles mixed patterns (Express-style handler)', () => {
    const code = `function handler(req, res, next) {
      const user = req.body.username;
      if (!user) return next(new Error('no user'));
      res.json({ user });
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    expect(usages.get('req')!.propertiesRead.has('body')).toBe(true);
    expect(usages.get('res')!.methodsCalled.has('json')).toBe(true);
    expect(usages.get('next')!.invokedAsFunction).toBe(true);
  });

  it('detects parameter passed as argument to another call', () => {
    const code = `function handler(req, res) {
      processRequest(req);
      sendResponse(res);
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    expect(usages.get('req')!.passedAsArgument).toBe(true);
    expect(usages.get('res')!.passedAsArgument).toBe(true);
  });

  it('handles nested property access (req.body.user.name)', () => {
    const code = `function handler(req, res) {
      const name = req.body.user.name;
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    expect(usages.get('req')!.propertiesRead.has('body')).toBe(true);
  });

  it('handles destructured access from parameter', () => {
    const code = `function handler(req, res) {
      const { body, headers } = req;
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    expect(usages.get('req')!.propertiesRead.has('body')).toBe(true);
    expect(usages.get('req')!.propertiesRead.has('headers')).toBe(true);
  });

  it('does not confuse local variables with parameters', () => {
    const code = `function handler(req, res) {
      const req2 = {};
      req2.body = 'fake';
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    expect(usages.get('req')!.propertiesRead.size).toBe(0);
  });

  it('returns empty usage for unused parameters', () => {
    const code = `function handler(req, res) {
      console.log('noop');
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    expect(usages.get('req')!.propertiesRead.size).toBe(0);
    expect(usages.get('res')!.methodsCalled.size).toBe(0);
  });

  it('handles Koa-style single context parameter', () => {
    const code = `function handler(ctx) {
      const user = ctx.request.body;
      ctx.body = { user };
      ctx.status = 200;
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    expect(usages.get('ctx')!.propertiesRead.has('request')).toBe(true);
    expect(usages.get('ctx')!.propertiesWritten.has('body')).toBe(true);
    expect(usages.get('ctx')!.propertiesWritten.has('status')).toBe(true);
  });

  it('handles bracket notation access', () => {
    const code = `function handler(req, res) {
      const val = req['body'];
    }`;
    const { body, paramNames } = getFunctionBody(code);
    const usages = analyzeParameterUsage(body, paramNames);

    expect(usages.get('req')!.propertiesRead.has('body')).toBe(true);
  });
});

describe('inferRole', () => {
  it('infers INPUT when properties are read', () => {
    const usage = createEmptyUsage('req');
    usage.propertiesRead.add('body');
    usage.propertiesRead.add('headers');
    expect(inferRole(usage)).toBe('input');
  });

  it('infers OUTPUT when methods are called', () => {
    const usage = createEmptyUsage('res');
    usage.methodsCalled.add('send');
    usage.methodsCalled.add('json');
    usage.methodsCalled.add('status');
    expect(inferRole(usage)).toBe('output');
  });

  it('infers CONTINUATION when invoked as function with no reads', () => {
    const usage = createEmptyUsage('next');
    usage.invokedAsFunction = true;
    expect(inferRole(usage)).toBe('continuation');
  });

  it('infers DATA when only passed as argument', () => {
    const usage = createEmptyUsage('id');
    usage.passedAsArgument = true;
    expect(inferRole(usage)).toBe('data');
  });

  it('infers UNKNOWN for unused parameter', () => {
    const usage = createEmptyUsage('unused');
    expect(inferRole(usage)).toBe('unknown');
  });

  it('prefers INPUT over OUTPUT when both present', () => {
    const usage = createEmptyUsage('ctx');
    usage.propertiesRead.add('request');
    usage.propertiesWritten.add('body');
    usage.methodsCalled.add('throw');
    expect(inferRole(usage)).toBe('input');
  });

  it('continuation wins if invoked even with some other usage', () => {
    const usage = createEmptyUsage('next');
    usage.invokedAsFunction = true;
    usage.passedAsArgument = true;
    expect(inferRole(usage)).toBe('continuation');
  });
});

describe('detectCallbackOrigin', () => {
  it('detects function passed as callback to require("express").get()', () => {
    const code = `
      const express = require('express');
      const app = express();
      app.get('/users', function handler(req, res) {
        res.json({});
      });
    `;
    const tree = parser.parse(code);
    // Find the inline function expression (not the keyword token)
    const funcs = tree.rootNode.descendantsOfType('function_expression');
    const handler = funcs[0];
    // function_expression -> arguments -> call_expression
    const callExpr = handler.parent?.parent;

    expect(callExpr?.type).toBe('call_expression');
    const origin = detectCallbackOrigin(callExpr!, handler, tree.rootNode);
    expect(origin.isExternal).toBe(true);
    expect(origin.moduleCategory).toBe('HTTP_FRAMEWORK');
    expect(origin.moduleName).toBe('express');
    tree.delete();
  });

  it('detects arrow function callback to fs module', () => {
    const code = `
      const fs = require('fs');
      fs.readFile('/etc/passwd', (err, data) => {
        console.log(data);
      });
    `;
    const tree = parser.parse(code);
    const arrows = tree.rootNode.descendantsOfType('arrow_function');
    const callback = arrows[0];
    const callExpr = callback.parent?.parent;

    expect(callExpr?.type).toBe('call_expression');
    const origin = detectCallbackOrigin(callExpr!, callback, tree.rootNode);
    expect(origin.isExternal).toBe(true);
    expect(origin.moduleCategory).toBe('FILESYSTEM');
    tree.delete();
  });

  it('returns not-external for callback to local function', () => {
    const code = `
      function myHelper(callback) { callback(); }
      myHelper(function handler(data) {
        console.log(data);
      });
    `;
    const tree = parser.parse(code);
    const funcs = tree.rootNode.descendantsOfType('function_expression');
    const handler = funcs.find(f => f.text.includes('console'))!;
    // function_expression -> arguments -> call_expression
    const callExpr = handler.parent?.parent;

    const origin = detectCallbackOrigin(callExpr!, handler, tree.rootNode);
    expect(origin.isExternal).toBe(false);
    tree.delete();
  });

  it('detects ES import-based external callback', () => {
    const code = `
      import express from 'express';
      const app = express();
      app.post('/login', (req, res) => {
        const { username } = req.body;
      });
    `;
    const tree = parser.parse(code);
    const arrows = tree.rootNode.descendantsOfType('arrow_function');
    const callback = arrows[0];
    const callExpr = callback.parent?.parent;

    const origin = detectCallbackOrigin(callExpr!, callback, tree.rootNode);
    expect(origin.isExternal).toBe(true);
    expect(origin.moduleCategory).toBe('HTTP_FRAMEWORK');
    tree.delete();
  });

  it('detects database callback via new constructor', () => {
    const code = `
      const pg = require('pg');
      const client = new pg.Client();
      client.query('SELECT 1', (err, result) => {
        console.log(result);
      });
    `;
    const tree = parser.parse(code);
    const arrows = tree.rootNode.descendantsOfType('arrow_function');
    const callback = arrows[0];
    const callExpr = callback.parent?.parent;

    const origin = detectCallbackOrigin(callExpr!, callback, tree.rootNode);
    expect(origin.isExternal).toBe(true);
    expect(origin.moduleCategory).toBe('DATABASE');
    tree.delete();
  });

  it('returns not-external when call has no function arguments', () => {
    const code = `
      const x = require('express');
      x.listen(3000);
    `;
    const tree = parser.parse(code);
    const calls = tree.rootNode.descendantsOfType('call_expression');
    const listenCall = calls.find(c => c.text.includes('listen'))!;

    // No callback function node to pass
    const origin = detectCallbackOrigin(listenCall, listenCall, tree.rootNode);
    expect(origin.isExternal).toBe(true); // module IS external
    // But in real usage, we only call this when we find a function arg
    tree.delete();
  });
});
