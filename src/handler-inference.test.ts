import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper.js';
import { resetSequence } from './types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('Handler parameter taint inference', () => {
  let parser: Parser;

  beforeAll(async () => {
    await Parser.init();
    parser = new Parser();
    const wasmPath = path.resolve(
      __dirname,
      '../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm'
    );
    const lang = await Language.load(fs.readFileSync(wasmPath));
    parser.setLanguage(lang);
  });

  it('marks first param of verb-named method in module.exports as tainted', () => {
    const code = `module.exports = {
  browse: {
    query(frame) {
      const filter = frame.options.filter;
      const q = "SELECT * FROM posts WHERE slug = '" + filter + "'";
      return db.query(q);
    }
  }
};`;
    resetSequence();
    const tree = parser.parse(code);
    const { map } = buildNeuralMap(tree, code, 'ghost-handler.js');
    tree.delete();

    // frame should be detected as tainted (INGRESS node with framework_handler subtype)
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingressNodes.length).toBeGreaterThan(0);

    // There should be tainted data flows
    const taintedFlows = map.nodes.reduce((sum, n) =>
      sum + n.data_in.filter(d => d.tainted).length, 0);
    expect(taintedFlows).toBeGreaterThan(0);
  });

  it('does NOT mark params of non-verb methods', () => {
    const code = `module.exports = {
  config: {
    initialize(settings) {
      return settings.debug;
    }
  }
};`;
    resetSequence();
    const tree = parser.parse(code);
    const { map } = buildNeuralMap(tree, code, 'config.js');
    tree.delete();

    const ingressNodes = map.nodes.filter(n =>
      n.node_type === 'INGRESS' && n.node_subtype === 'framework_handler');
    expect(ingressNodes.length).toBe(0);
  });

  it('does NOT mark params of methods NOT in module.exports', () => {
    const code = `const helper = {
  query(data) {
    return process(data);
  }
};`;
    resetSequence();
    const tree = parser.parse(code);
    const { map } = buildNeuralMap(tree, code, 'helper.js');
    tree.delete();

    const ingressNodes = map.nodes.filter(n =>
      n.node_type === 'INGRESS' && n.node_subtype === 'framework_handler');
    expect(ingressNodes.length).toBe(0);
  });

  it('detects SQL injection through tainted handler param', async () => {
    const code = `module.exports = {
  browse: {
    query(frame) {
      const filter = frame.options.filter;
      const q = "SELECT * FROM posts WHERE slug = '" + filter + "'";
      return db.query(q);
    }
  }
};`;
    resetSequence();
    const tree = parser.parse(code);
    const { map } = buildNeuralMap(tree, code, 'vulnerable.js');
    tree.delete();

    // Run verification
    const { verifyAll } = await import('./verifier/index.js');
    const results = verifyAll(map, 'javascript');
    const sqli = results.find(r => r.cwe === 'CWE-89' && !r.holds);
    expect(sqli).toBeDefined();
    expect(sqli!.findings.length).toBeGreaterThan(0);
  });
});
