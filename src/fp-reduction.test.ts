/**
 * FP Reduction Verification Tests
 *
 * Validates that the false positive reduction fixes work correctly:
 * 1. Platform-specific CWEs don't fire on Java servlets
 * 2. XSS variants respect ESAPI/OWASP encoding
 * 3. Struts CWEs only fire on actual Struts code
 * 4. C/C++-specific CWEs don't fire on Java
 * 5. Input validation verifiers filter safe decode patterns
 */

import { describe, it, expect } from 'vitest';
import type { NeuralMap, NeuralMapNode, Edge, EdgeType } from './types';
import { verify } from './verifier';

// Import verifiers directly
import { verifyCWE103, verifyCWE104, verifyCWE105, verifyCWE106, verifyCWE108 } from './generated/batch_002';
import { verifyCWE588 } from './generated/batch_003';
import { verifyCWE80, verifyCWE81, verifyCWE549 } from './generated/batch_005';
import { verifyCWE457 } from './generated/batch_013';
import { verifyCWE408, verifyCWE422, verifyCWE782, verifyCWE925 } from './generated/batch_015';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function createNode(overrides: Partial<NeuralMapNode> & { id: string; node_type: NeuralMapNode['node_type'] }): NeuralMapNode {
  return {
    id: overrides.id,
    label: overrides.label ?? overrides.id,
    node_type: overrides.node_type,
    node_subtype: overrides.node_subtype ?? '',
    line_start: overrides.line_start ?? 1,
    line_end: overrides.line_end ?? 10,
    code_snapshot: overrides.code_snapshot ?? '',
    analysis_snapshot: overrides.analysis_snapshot ?? '',
    edges: (overrides.edges ?? []) as Edge[],
    data_in: overrides.data_in ?? [],
    data_out: overrides.data_out ?? [],
    attack_surface: overrides.attack_surface ?? [],
    language: overrides.language ?? '',
  };
}

function buildMap(nodes: NeuralMapNode[], sourceFile = 'Test.java'): NeuralMap {
  const allEdges: Edge[] = [];
  for (const n of nodes) {
    for (const e of n.edges) {
      allEdges.push({ source: n.id, ...e } as any);
    }
  }
  return {
    nodes,
    edges: allEdges,
    source_file: sourceFile,
    source_code: nodes.map(n => n.code_snapshot).join('\n'),
    created_at: new Date().toISOString(),
    parser_version: 'test',
  } as NeuralMap;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('FP Reduction: Platform-specific CWE gating', () => {

  it('CWE-422 (Windows Shatter) does NOT fire on Java code', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'request.getParameter("x")',
      language: 'java',
      edges: [{ target: 'xf1', edge_type: 'DATA_FLOW' as EdgeType, conditional: false, async: false }],
    });
    const transform = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'data = input.process()',
      language: 'java',
      edges: [],
    });
    const map = buildMap([ingress, transform], 'Servlet.java');
    const result = verifyCWE422(map);
    expect(result.holds).toBe(true);
  });

  it('CWE-782 (IOCTL) does NOT fire on Java code', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'request.getParameter("x")',
      language: 'java',
      edges: [{ target: 'xf1', edge_type: 'DATA_FLOW' as EdgeType, conditional: false, async: false }],
    });
    const transform = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'process(input)',
      language: 'java',
      edges: [],
    });
    const map = buildMap([ingress, transform], 'Handler.java');
    const result = verifyCWE782(map);
    expect(result.holds).toBe(true);
  });

  it('CWE-925 (BroadcastReceiver) does NOT fire on non-Android Java', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'request.getParameter("x")',
      language: 'java',
      edges: [{ target: 'xf1', edge_type: 'DATA_FLOW' as EdgeType, conditional: false, async: false }],
    });
    const transform = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'process(input)',
      language: 'java',
      edges: [],
    });
    const map = buildMap([ingress, transform], 'Servlet.java');
    const result = verifyCWE925(map);
    expect(result.holds).toBe(true);
  });

  it('CWE-408 (Early Amplification) does NOT fire without expensive operations', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'request.getParameter("x")',
      edges: [{ target: 'xf1', edge_type: 'DATA_FLOW' as EdgeType, conditional: false, async: false }],
    });
    const transform = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'String data = input.trim()',
      edges: [],
    });
    const map = buildMap([ingress, transform], 'Simple.java');
    const result = verifyCWE408(map);
    expect(result.holds).toBe(true);
  });
});

describe('FP Reduction: Struts CWE gating', () => {

  it('CWE-103 does NOT fire on non-Struts Java code', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'request.getParameter("x")',
      edges: [{ target: 'xf1', edge_type: 'DATA_FLOW' as EdgeType, conditional: false, async: false }],
    });
    const transform = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      node_subtype: 'parse',
      code_snapshot: 'parseXML(rawInput)',
      attack_surface: ['data_processing'],
      edges: [],
    });
    const map = buildMap([ingress, transform], 'Servlet.java');
    const result = verifyCWE103(map);
    expect(result.holds).toBe(true);
  });

  it('CWE-103 DOES fire on Struts code', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'import org.apache.struts.action.ActionForm; req.body.xml',
      edges: [{ target: 'xf1', edge_type: 'DATA_FLOW' as EdgeType, conditional: false, async: false }],
    });
    const transform = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      node_subtype: 'parse',
      code_snapshot: 'parseXML(rawInput)',
      attack_surface: ['data_processing'],
      edges: [],
    });
    const map = buildMap([ingress, transform], 'StrutsAction.java');
    const result = verifyCWE103(map);
    expect(result.holds).toBe(false);
  });
});

describe('FP Reduction: C/C++-specific CWE gating', () => {

  it('CWE-588 (Non-structure Pointer) does NOT fire on Java code', () => {
    const transform = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'new java.io.FileInputStream(new java.io.File(fileName))',
      language: 'java',
      edges: [{ target: 'st1', edge_type: 'DATA_FLOW' as EdgeType, conditional: false, async: false }],
    });
    const storage = createNode({
      id: 'st1', node_type: 'STORAGE',
      node_subtype: 'buffer',
      code_snapshot: 'byte[] b = new byte[1000]; fis.read(b)',
      language: 'java',
      edges: [],
    });
    const map = buildMap([transform, storage], 'FileReader.java');
    const result = verifyCWE588(map);
    expect(result.holds).toBe(true);
  });
});

describe('FP Reduction: XSS ESAPI recognition', () => {

  it('CWE-80 recognizes ESAPI encodeForHTML as safe', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'request.getParameter("x")',
      data_in: [{ name: 'x', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'eg1', edge_type: 'DATA_FLOW' as EdgeType, conditional: false, async: false }],
    });
    const egress = createNode({
      id: 'eg1', node_type: 'EGRESS',
      node_subtype: 'http_response',
      code_snapshot: 'response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(param))',
      data_in: [{ name: 'param', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    const map = buildMap([ingress, egress], 'Safe.java');
    const result = verifyCWE80(map);
    expect(result.holds).toBe(true);
  });
});

describe('FP Reduction: CWE-549 password field gating', () => {

  it('CWE-549 does NOT fire on non-password EGRESS nodes', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'request.getParameter("name")',
      edges: [{ target: 'eg1', edge_type: 'DATA_FLOW' as EdgeType, conditional: false, async: false }],
    });
    const egress = createNode({
      id: 'eg1', node_type: 'EGRESS',
      node_subtype: 'http_response',
      code_snapshot: 'response.getWriter().println("Hello " + name)',
      data_in: [{ name: 'name', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    const map = buildMap([ingress, egress], 'Hello.java');
    const result = verifyCWE549(map);
    expect(result.holds).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Fix 1: CWE-457 language gate expansion (Java/Kotlin)
// ---------------------------------------------------------------------------

describe('TPR Restore: CWE-457 Java uninitialized variable detection', () => {

  it('CWE-457 (hand-written) fires on Java uninitialized local variable', () => {
    const node = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'int count; if (flag) { count = 5; } System.out.println(count);',
      language: 'java',
      edges: [],
    });
    const map = buildMap([node], 'Servlet.java');
    const result = verify(map, 'CWE-457');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('CWE-457 (hand-written) does NOT fire on Java variable initialized at declaration', () => {
    const node = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'int count=0; count = count + 1; System.out.println(count);',
      language: 'java',
      edges: [],
    });
    const map = buildMap([node], 'Servlet.java');
    const result = verify(map, 'CWE-457');
    expect(result.holds).toBe(true);
  });

  it('CWE-457 (hand-written) still skips JavaScript (auto-initialized)', () => {
    const node = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'let count; if (flag) { count = 5; } console.log(count);',
      language: 'javascript',
      edges: [],
    });
    const map = buildMap([node], 'handler.js');
    const result = verify(map, 'CWE-457');
    expect(result.holds).toBe(true);
  });

  it('CWE-457 (hand-written) fires on Kotlin uninitialized local', () => {
    const node = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'int result; if (condition) { result = compute(); } return result;',
      language: 'kotlin',
      edges: [],
    });
    const map = buildMap([node], 'Handler.kt');
    const result = verify(map, 'CWE-457');
    expect(result.holds).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Fix 2: CWE-588 Java .get().method() detection (already present)
// ---------------------------------------------------------------------------

describe('TPR Restore: CWE-588 Java chained-get detection', () => {

  it('CWE-588 (hand-written) catches Java Map.get().method() without null check', () => {
    const node = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'HashMap<String, User> users = getUsers(); String name = users.get(userId).getName();',
      language: 'java',
      edges: [],
    });
    const map = buildMap([node], 'UserService.java');
    const result = verify(map, 'CWE-588');
    expect(result.holds).toBe(false);
    expect(result.findings[0].description).toContain('null');
  });

  it('CWE-588 (hand-written) passes Java Map.get() with null check', () => {
    const node = createNode({
      id: 'xf1', node_type: 'TRANSFORM',
      code_snapshot: 'HashMap<String, User> users = getUsers(); User u = users.get(userId); if (u != null) { String name = u.getName(); }',
      language: 'java',
      edges: [],
    });
    const map = buildMap([node], 'UserService.java');
    const result = verify(map, 'CWE-588');
    expect(result.holds).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Fix 3: CWE-1054 per-language depth thresholds
// ---------------------------------------------------------------------------

describe('TPR Restore: CWE-1054 per-language call depth thresholds', () => {

  it('CWE-1054 fires on JS with 4+ call depth', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'app.get("/api", (req, res) => { process(req.body); })',
      language: 'javascript',
      edges: [{ target: 'c1', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
    });
    const call1 = createNode({
      id: 'c1', node_type: 'TRANSFORM', code_snapshot: 'function layer1(data) { layer2(data); }',
      language: 'javascript',
      edges: [{ target: 'c2', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
    });
    const call2 = createNode({
      id: 'c2', node_type: 'TRANSFORM', code_snapshot: 'function layer2(data) { layer3(data); }',
      language: 'javascript',
      edges: [{ target: 'c3', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
    });
    const call3 = createNode({
      id: 'c3', node_type: 'TRANSFORM', code_snapshot: 'function layer3(data) { layer4(data); }',
      language: 'javascript',
      edges: [{ target: 'ctrl', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
    });
    const ctrl = createNode({
      id: 'ctrl', node_type: 'CONTROL', code_snapshot: 'function validate(data) { if (!data.name) throw new Error(); }',
      language: 'javascript',
      edges: [],
    });
    const map = buildMap([ingress, call1, call2, call3, ctrl], 'handler.js');
    const result = verify(map, 'CWE-1054');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('CWE-1054 does NOT fire on Java with 4 call depth (threshold is 6 for Java)', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'protected void doPost(HttpServletRequest req, HttpServletResponse resp)',
      language: 'java',
      edges: [{ target: 'c1', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
    });
    const call1 = createNode({
      id: 'c1', node_type: 'TRANSFORM', code_snapshot: 'public void handleRequest(Request req) { service.process(req); }',
      language: 'java',
      edges: [{ target: 'c2', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
    });
    const call2 = createNode({
      id: 'c2', node_type: 'TRANSFORM', code_snapshot: 'public void process(Request req) { validator.check(req); }',
      language: 'java',
      edges: [{ target: 'c3', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
    });
    const call3 = createNode({
      id: 'c3', node_type: 'TRANSFORM', code_snapshot: 'public void check(Request req) { rules.validate(req); }',
      language: 'java',
      edges: [{ target: 'ctrl', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
    });
    const ctrl = createNode({
      id: 'ctrl', node_type: 'CONTROL', code_snapshot: 'public void validate(Request req) { if (req.getName() == null) throw new ValidationException(); }',
      language: 'java',
      edges: [],
    });
    const map = buildMap([ingress, call1, call2, call3, ctrl], 'UserServlet.java');
    const result = verify(map, 'CWE-1054');
    // 4 call levels in Java should NOT trigger (threshold is 6)
    expect(result.holds).toBe(true);
  });

  it('CWE-1054 DOES fire on Java with 6+ call depth', () => {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      code_snapshot: 'protected void doPost(HttpServletRequest req, HttpServletResponse resp)',
      language: 'java',
      edges: [{ target: 'c1', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
    });
    const nodes = [ingress];
    // Build a chain of 6 calls deep
    for (let i = 1; i <= 5; i++) {
      nodes.push(createNode({
        id: `c${i}`, node_type: 'TRANSFORM',
        code_snapshot: `public void layer${i}(Request req) { layer${i+1}(req); }`,
        language: 'java',
        edges: [{ target: i < 5 ? `c${i+1}` : 'ctrl', edge_type: 'CALLS' as EdgeType, conditional: false, async: false }],
      }));
    }
    nodes.push(createNode({
      id: 'ctrl', node_type: 'CONTROL',
      code_snapshot: 'public void validate(Request req) { if (req.getName() == null) throw new ValidationException(); }',
      language: 'java',
      edges: [],
    }));
    const map = buildMap(nodes, 'DeepServlet.java');
    const result = verify(map, 'CWE-1054');
    // 6 call levels in Java SHOULD trigger (threshold is 6)
    expect(result.holds).toBe(false);
  });
});
