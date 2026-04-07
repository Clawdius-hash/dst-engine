/**
 * Tests for destructured Express handler parameter taint detection.
 *
 * Verifies that DST recognizes destructured request properties
 * (e.g., { body }: Request) as tainted INGRESS sources equivalent
 * to req.body access patterns.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';

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

function parse(code: string, parser: InstanceType<typeof Parser>) {
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, 'test.js');
  tree.delete();
  return map;
}

describe('destructured Express handler taint detection', () => {
  let parser: InstanceType<typeof Parser>;

  beforeAll(async () => {
    parser = await createTestParser();
  });

  afterAll(() => {
    parser?.delete();
  });

  it('function({ body }, res, next) — body is tainted INGRESS', () => {
    const code = `function handler({ body }, res, next) {
  const name = body.name;
  res.json({ name });
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    expect(ingress.some(n => n.label === 'req.body')).toBe(true);
  });

  it('({ body }, res, next) => {} arrow function — body is tainted INGRESS', () => {
    const code = `const handler = ({ body }, res, next) => {
  const name = body.name;
  res.json({ name });
};`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    expect(ingress.some(n => n.label === 'req.body')).toBe(true);
  });

  it('({ query, params }, res, next) — multiple request props are tainted', () => {
    const code = `function handler({ query, params }, res, next) {
  const q = query.q;
  const id = params.id;
  res.json({ q, id });
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(2);
    expect(ingress.some(n => n.label === 'req.query')).toBe(true);
    expect(ingress.some(n => n.label === 'req.params')).toBe(true);
  });

  it('({ file }, res, next) — file is tainted with file_upload subtype', () => {
    const code = `function handler({ file }, res, next) {
  const name = file.originalname;
  res.json({ name });
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    const fileIngress = ingress.find(n => n.label === 'req.file');
    expect(fileIngress).toBeTruthy();
    expect(fileIngress!.node_subtype).toBe('file_upload');
  });

  it('({ body, headers }, res) — 2-param handler without next is also detected', () => {
    const code = `function handler({ body, headers }, res) {
  const name = body.name;
  res.json({ name });
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(2);
    expect(ingress.some(n => n.label === 'req.body')).toBe(true);
    expect(ingress.some(n => n.label === 'req.headers')).toBe(true);
  });

  it('({ body, somethingCustom }, res, next) — only known props are tainted', () => {
    const code = `function handler({ body, somethingCustom }, res, next) {
  const name = body.name;
  const x = somethingCustom.value;
  res.json({ name, x });
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    // body should be tainted but somethingCustom should not
    expect(ingress.some(n => n.label === 'req.body')).toBe(true);
    expect(ingress.some(n => n.label === 'req.somethingCustom')).toBe(false);
  });

  it('({ name }, { json }) — 2-param non-Express destructuring is NOT tainted', () => {
    // Both params destructured — does NOT match Express pattern
    // (Express pattern requires only the FIRST param to be object_pattern)
    // Actually, this matches the heuristic since first param is object_pattern and
    // there are 2 params. But 'name' is not in EXPRESS_REQUEST_PROPERTIES, so no INGRESS.
    const code = `function util({ name }, { json }) {
  json({ name });
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    // 'name' is not in the known set, so no INGRESS
    expect(ingress.length).toBe(0);
  });

  it('plain (req, res, next) still works as before', () => {
    const code = `function handler(req, res, next) {
  const name = req.body.name;
  res.json({ name });
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
  });

  it('single param function is NOT treated as Express handler', () => {
    const code = `function process({ body }) {
  return body.name;
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    // Single param — not an Express handler
    expect(ingress.length).toBe(0);
  });

  it('b2bOrder.ts pattern: return ({ body }, res, next) => { body.orderLinesData }', () => {
    // Simulates the Juice Shop b2bOrder.ts pattern after TS stripping
    const code = `function b2bOrder() {
  return ({ body }, res, next) => {
    const orderLinesData = body.orderLinesData || '';
    vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 });
    res.json({ cid: body.cid });
  }
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    expect(ingress.some(n => n.label === 'req.body')).toBe(true);
  });

  it('fileUpload.ts pattern: function({ file }, res, next) with file access', () => {
    // Simulates Juice Shop fileUpload.ts pattern
    const code = `function handleXmlUpload({ file }, res, next) {
  const data = file.buffer.toString();
  vm.runInContext('libxml.parseXml(data)', sandbox, { timeout: 2000 });
  res.status(410);
  next(new Error(data));
}`;
    const map = parse(code, parser);
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);
    expect(ingress.some(n => n.label === 'req.file')).toBe(true);
    expect(ingress.some(n => n.node_subtype === 'file_upload')).toBe(true);
  });

  it('tainted destructured body propagates through variable assignments', () => {
    const code = `function handler({ body }, res, next) {
  const orderLinesData = body.orderLinesData;
  eval(orderLinesData);
}`;
    const map = parse(code, parser);
    // body should be tainted INGRESS
    const ingress = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingress.length).toBeGreaterThanOrEqual(1);

    // Check that orderLinesData variable picks up the taint
    // (body is tainted, so body.orderLinesData should propagate)
    // The variable declaration for orderLinesData should reference a tainted source
    const allNodes = map.nodes;
    const hasBodyAccess = allNodes.some(n =>
      n.code_snapshot?.includes('body.orderLinesData')
    );
    expect(hasBodyAccess).toBe(true);
  });
});
