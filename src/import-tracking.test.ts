/**
 * ES module import tracking tests
 *
 * Proves DST registers ES import identifiers in scope with aliasChain,
 * enabling callee resolution through the pattern database.
 *
 * Pattern: import { cookies } from 'next/headers' -> cookies() resolves
 * to INGRESS/http_request via DIRECT_CALLS (or via aliasChain -> MEMBER_CALLS).
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { resetSequence } from './types.js';
import type { NeuralMap, NeuralMapNode } from './types.js';
import type { MapperContext } from './mapper.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

beforeAll(async () => {
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const JavaScript = await Language.load(wasmBuffer);
  parser.setLanguage(JavaScript);
});

beforeEach(() => {
  resetSequence();
});

function parseWithCtx(code: string): { map: NeuralMap; ctx: MapperContext } {
  const tree = parser.parse(code);
  const result = buildNeuralMap(tree, code, 'app.js');
  tree.delete();
  return result;
}

function nodesByTypeAndSubtype(map: NeuralMap, type: string, subtype: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === type && n.node_subtype === subtype);
}

// ---------------------------------------------------------------------------
// Test 1: Named import registers aliasChain
// ---------------------------------------------------------------------------

describe('ES import tracking', () => {

  describe('named imports', () => {
    it('registers named import identifier in scope with aliasChain', () => {
      const { ctx } = parseWithCtx(`import { cookies } from 'next/headers';`);
      const v = ctx.resolveVariable('cookies');
      expect(v).not.toBeNull();
      expect(v!.aliasChain).toBeDefined();
      expect(v!.aliasChain![0]).toBe('next/headers');
    });

    it('named import + function call: aliasChain enables resolution through language DB', () => {
      // When cookies() is called after import, the alias resolution path at
      // call_expression handler checks ctx.resolveVariable('cookies').aliasChain
      // which gives ['next/headers', 'cookies'] -> lookupCallee(['next/headers', 'cookies'])
      // would match 'next/headers.cookies' in the TypeScript language DB MEMBER_CALLS.
      //
      // The JS base calleePatterns doesn't have this pattern, so the mapper alone
      // won't classify it. But the aliasChain IS correctly stored for downstream use.
      const { ctx } = parseWithCtx(
        `import { cookies } from 'next/headers';\nconst c = cookies();`
      );
      const v = ctx.resolveVariable('cookies');
      expect(v).not.toBeNull();
      expect(v!.aliasChain).toEqual(['next/headers', 'cookies']);
    });

    it('renamed import uses alias as local name with aliasChain', () => {
      const { ctx } = parseWithCtx(
        `import { cookies as getCookies } from 'next/headers';`
      );
      // Local name should be getCookies, NOT cookies
      const v = ctx.resolveVariable('getCookies');
      expect(v).not.toBeNull();
      expect(v!.aliasChain).toBeDefined();
      expect(v!.aliasChain![0]).toBe('next/headers');

      // Original name should NOT be in scope
      const original = ctx.resolveVariable('cookies');
      expect(original).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // Test 4: Default import registers aliasChain
  // ---------------------------------------------------------------------------

  describe('default imports', () => {
    it('registers default import identifier in scope with aliasChain', () => {
      const { ctx } = parseWithCtx(`import express from 'express';`);
      const v = ctx.resolveVariable('express');
      expect(v).not.toBeNull();
      expect(v!.aliasChain).toEqual(['express']);
    });
  });

  // ---------------------------------------------------------------------------
  // Test 5: Star import registers aliasChain
  // ---------------------------------------------------------------------------

  describe('star (namespace) imports', () => {
    it('registers namespace import identifier in scope with aliasChain', () => {
      const { ctx } = parseWithCtx(`import * as fs from 'fs';`);
      const v = ctx.resolveVariable('fs');
      expect(v).not.toBeNull();
      expect(v!.aliasChain).toEqual(['fs']);
    });
  });

  // ---------------------------------------------------------------------------
  // Test 6: Type-only imports are skipped
  // ---------------------------------------------------------------------------

  describe('type-only imports', () => {
    it('does not register type-only import in scope with aliasChain', () => {
      // tree-sitter-javascript will parse this with an ERROR node for 'type'
      const { ctx } = parseWithCtx(
        `import type { NextRequest } from 'next/server';`
      );
      const v = ctx.resolveVariable('NextRequest');
      // Should either be null or not have aliasChain (type imports have no runtime value)
      if (v) {
        expect(v.aliasChain).toBeUndefined();
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Test 7: Side-effect imports don't break anything
  // ---------------------------------------------------------------------------

  describe('side-effect imports', () => {
    it('does not error and registers no variables', () => {
      // Should not throw
      const { ctx } = parseWithCtx(`import 'dotenv/config';`);
      // No variables should be registered from a side-effect import
      const v = ctx.resolveVariable('dotenv/config');
      expect(v).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // Named import aliasChain stores [module, originalName] for MEMBER_CALLS
  // ---------------------------------------------------------------------------

  describe('aliasChain resolution for named imports', () => {
    it('stores [module, originalName] for named imports to enable MEMBER_CALLS lookup', () => {
      const { ctx } = parseWithCtx(
        `import { cookies } from 'next/headers';`
      );
      const v = ctx.resolveVariable('cookies');
      expect(v).not.toBeNull();
      // Named imports should store [moduleName, originalName] so that
      // the alias resolution path can look up 'next/headers.cookies' in MEMBER_CALLS
      expect(v!.aliasChain).toEqual(['next/headers', 'cookies']);
    });

    it('stores [module, originalName] even with alias', () => {
      const { ctx } = parseWithCtx(
        `import { cookies as getCookies } from 'next/headers';`
      );
      const v = ctx.resolveVariable('getCookies');
      expect(v).not.toBeNull();
      // aliasChain should use the ORIGINAL name for DB lookup, not the local alias
      expect(v!.aliasChain).toEqual(['next/headers', 'cookies']);
    });
  });
});
