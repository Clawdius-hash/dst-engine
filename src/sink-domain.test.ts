/**
 * Sink Domain Classification Tests
 *
 * Validates that the domain classification system correctly:
 * 1. Classifies sink nodes by their security domain (SQL, SHELL, URL, etc.)
 * 2. Suppresses cross-domain false positives (shell CWE on URL sink, SQL CWE on shell sink)
 * 3. Preserves correct-domain true positives (shell CWE on shell sink, SQL CWE on SQL sink)
 * 4. Lets domain-agnostic CWEs fire on any sink
 * 5. Lets UNKNOWN-domain sinks fire on any CWE (conservative)
 */

import { describe, it, expect } from 'vitest';
import type { NeuralMap, NeuralMapNode, Edge, EdgeType } from './types';
import {
  classifySinkDomain, cweDomainMatchesSink,
  type SinkDomain,
} from './generated/_helpers';

// Import factory-created verifiers that should be domain-filtered
import { verifyCWE88, verifyCWE564 } from './generated/batch_014';
import { verifyCWE90, verifyCWE652 } from './generated/batch_009';

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

const FLOW: EdgeType = 'DATA_FLOW';

// ---------------------------------------------------------------------------
// 1. classifySinkDomain unit tests
// ---------------------------------------------------------------------------

describe('classifySinkDomain', () => {
  it('classifies Runtime.exec as SHELL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'Runtime.getRuntime().exec(cmd)',
    });
    expect(classifySinkDomain(node)).toBe('SHELL');
  });

  it('classifies child_process.exec as SHELL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'child_process.exec("ls " + input)',
    });
    expect(classifySinkDomain(node)).toBe('SHELL');
  });

  it('classifies ProcessBuilder as SHELL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'new ProcessBuilder(args).start()',
    });
    expect(classifySinkDomain(node)).toBe('SHELL');
  });

  it('classifies subprocess.call as SHELL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'subprocess.call(cmd, shell=True)',
    });
    expect(classifySinkDomain(node)).toBe('SHELL');
  });

  it('classifies Statement.execute as SQL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'statement.execute("SELECT * FROM users WHERE id=" + id)',
    });
    expect(classifySinkDomain(node)).toBe('SQL');
  });

  it('classifies PreparedStatement as SQL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'preparedStatement.setString(1, name)',
    });
    expect(classifySinkDomain(node)).toBe('SQL');
  });

  it('classifies createQuery (Hibernate) as SQL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'session.createQuery("FROM User WHERE name = " + name)',
    });
    expect(classifySinkDomain(node)).toBe('SQL');
  });

  it('classifies URL.openStream as URL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'new URL(input).openStream()',
    });
    expect(classifySinkDomain(node)).toBe('URL');
  });

  it('classifies HttpURLConnection as URL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'HttpURLConnection conn = (HttpURLConnection) url.openConnection()',
    });
    expect(classifySinkDomain(node)).toBe('URL');
  });

  it('classifies fetch() as URL', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'fetch(userUrl)',
    });
    expect(classifySinkDomain(node)).toBe('URL');
  });

  it('classifies ldap_search as LDAP', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'ldap_search($conn, $base, $filter)',
    });
    expect(classifySinkDomain(node)).toBe('LDAP');
  });

  it('classifies DirContext as LDAP', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'ctx = new InitialDirContext(env); ctx.search(name, filter)',
      node_subtype: 'ldap',
    });
    expect(classifySinkDomain(node)).toBe('LDAP');
  });

  it('classifies XPath as XML', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'xpath.evaluate(expression, doc)',
    });
    expect(classifySinkDomain(node)).toBe('XML');
  });

  it('classifies DocumentBuilder as XML', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'DocumentBuilder db = dbf.newDocumentBuilder(); db.parse(input)',
    });
    expect(classifySinkDomain(node)).toBe('XML');
  });

  it('classifies FileInputStream as FILE', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'new FileInputStream(path)',
    });
    expect(classifySinkDomain(node)).toBe('FILE');
  });

  it('classifies innerHTML as HTML', () => {
    const node = createNode({
      id: 'n1', node_type: 'EGRESS',
      code_snapshot: 'element.innerHTML = userInput',
    });
    expect(classifySinkDomain(node)).toBe('HTML');
  });

  it('returns UNKNOWN for generic nodes', () => {
    const node = createNode({
      id: 'n1', node_type: 'EXTERNAL',
      code_snapshot: 'someFunction(data)',
    });
    expect(classifySinkDomain(node)).toBe('UNKNOWN');
  });
});

// ---------------------------------------------------------------------------
// 2. cweDomainMatchesSink unit tests
// ---------------------------------------------------------------------------

describe('cweDomainMatchesSink', () => {
  const shellSink = createNode({
    id: 's1', node_type: 'EXTERNAL',
    code_snapshot: 'Runtime.getRuntime().exec(cmd)',
  });

  const sqlSink = createNode({
    id: 's2', node_type: 'EXTERNAL',
    code_snapshot: 'statement.execute(query)',
  });

  const urlSink = createNode({
    id: 's3', node_type: 'EXTERNAL',
    code_snapshot: 'new URL(input).openStream()',
  });

  const unknownSink = createNode({
    id: 's4', node_type: 'EXTERNAL',
    code_snapshot: 'doSomething(data)',
  });

  it('CWE-88 (shell) matches SHELL sink', () => {
    expect(cweDomainMatchesSink('CWE-88', shellSink)).toBe(true);
  });

  it('CWE-88 (shell) does NOT match SQL sink', () => {
    expect(cweDomainMatchesSink('CWE-88', sqlSink)).toBe(false);
  });

  it('CWE-88 (shell) does NOT match URL sink', () => {
    expect(cweDomainMatchesSink('CWE-88', urlSink)).toBe(false);
  });

  it('CWE-88 (shell) DOES match UNKNOWN sink (conservative)', () => {
    expect(cweDomainMatchesSink('CWE-88', unknownSink)).toBe(true);
  });

  it('CWE-564 (SQL/Hibernate) matches SQL sink', () => {
    expect(cweDomainMatchesSink('CWE-564', sqlSink)).toBe(true);
  });

  it('CWE-564 (SQL/Hibernate) does NOT match SHELL sink', () => {
    expect(cweDomainMatchesSink('CWE-564', shellSink)).toBe(false);
  });

  it('CWE-564 (SQL/Hibernate) does NOT match URL sink', () => {
    expect(cweDomainMatchesSink('CWE-564', urlSink)).toBe(false);
  });

  it('CWE-90 (LDAP) matches LDAP sink', () => {
    const ldapSink = createNode({
      id: 's5', node_type: 'EXTERNAL',
      code_snapshot: 'ldap_search($conn, $base, $filter)',
    });
    expect(cweDomainMatchesSink('CWE-90', ldapSink)).toBe(true);
  });

  it('CWE-90 (LDAP) does NOT match SHELL sink', () => {
    expect(cweDomainMatchesSink('CWE-90', shellSink)).toBe(false);
  });

  it('domain-agnostic CWE (CWE-20) fires on any sink', () => {
    expect(cweDomainMatchesSink('CWE-20', shellSink)).toBe(true);
    expect(cweDomainMatchesSink('CWE-20', sqlSink)).toBe(true);
    expect(cweDomainMatchesSink('CWE-20', urlSink)).toBe(true);
    expect(cweDomainMatchesSink('CWE-20', unknownSink)).toBe(true);
  });

  it('domain-agnostic CWE (CWE-99) fires on any sink', () => {
    // CWE-99 (Resource Injection) is intentionally not domain-restricted
    expect(cweDomainMatchesSink('CWE-99', shellSink)).toBe(true);
    expect(cweDomainMatchesSink('CWE-99', urlSink)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 3. Integration: factory verifiers suppress cross-domain findings
// ---------------------------------------------------------------------------

describe('Cross-domain FP suppression in factory verifiers', () => {

  // Build a graph: INGRESS -> EXTERNAL(URL sink) with tainted data flow
  function buildSSRFGraph(): NeuralMap {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      label: 'request.getParameter("url")',
      code_snapshot: 'String url = request.getParameter("url")',
      data_in: [{ name: 'url', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'ext1', edge_type: FLOW, conditional: false, async: false }],
    });
    const urlSink = createNode({
      id: 'ext1', node_type: 'EXTERNAL',
      label: 'URL.openStream',
      code_snapshot: 'InputStream is = new URL(url).openStream()',
      node_subtype: 'api_call',
      data_in: [{ name: 'url', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    return buildMap([ingress, urlSink]);
  }

  // Build a graph: INGRESS -> EXTERNAL(shell sink) with tainted data flow
  function buildShellGraph(): NeuralMap {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      label: 'request.getParameter("cmd")',
      code_snapshot: 'String cmd = request.getParameter("cmd")',
      data_in: [{ name: 'cmd', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'ext1', edge_type: FLOW, conditional: false, async: false }],
    });
    const shellSink = createNode({
      id: 'ext1', node_type: 'EXTERNAL',
      label: 'Runtime.exec',
      code_snapshot: 'Runtime.getRuntime().exec(cmd)',
      node_subtype: 'shell_exec',
      data_in: [{ name: 'cmd', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    return buildMap([ingress, shellSink]);
  }

  // Build a graph: INGRESS -> EXTERNAL(SQL sink) with tainted data flow
  function buildSQLGraph(): NeuralMap {
    const ingress = createNode({
      id: 'ing1', node_type: 'INGRESS',
      label: 'request.getParameter("id")',
      code_snapshot: 'String id = request.getParameter("id")',
      data_in: [{ name: 'id', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'ext1', edge_type: FLOW, conditional: false, async: false }],
    });
    const sqlSink = createNode({
      id: 'ext1', node_type: 'EXTERNAL',
      label: 'Statement.execute',
      code_snapshot: 'statement.execute("SELECT * FROM users WHERE id=" + id)',
      node_subtype: 'db_query',
      data_in: [{ name: 'id', tainted: true, sensitivity: 'NONE' }],
      edges: [],
    });
    return buildMap([ingress, sqlSink]);
  }

  it('CWE-88 (shell delimiter) fires on shell sink', () => {
    const result = verifyCWE88(buildShellGraph());
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('CWE-88 (shell delimiter) does NOT fire on URL sink', () => {
    const result = verifyCWE88(buildSSRFGraph());
    expect(result.holds).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('CWE-88 (shell delimiter) does NOT fire on SQL sink', () => {
    const result = verifyCWE88(buildSQLGraph());
    expect(result.holds).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('CWE-564 (Hibernate SQLi) fires on SQL sink', () => {
    const result = verifyCWE564(buildSQLGraph());
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('CWE-564 (Hibernate SQLi) does NOT fire on URL sink', () => {
    const result = verifyCWE564(buildSSRFGraph());
    expect(result.holds).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('CWE-564 (Hibernate SQLi) does NOT fire on shell sink', () => {
    const result = verifyCWE564(buildShellGraph());
    expect(result.holds).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('CWE-90 (LDAP injection) does NOT fire on URL sink', () => {
    const result = verifyCWE90(buildSSRFGraph());
    expect(result.holds).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('CWE-90 (LDAP injection) does NOT fire on shell sink', () => {
    const result = verifyCWE90(buildShellGraph());
    expect(result.holds).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('CWE-652 (XQuery injection) does NOT fire on URL sink', () => {
    const result = verifyCWE652(buildSSRFGraph());
    expect(result.holds).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('CWE-652 (XQuery injection) does NOT fire on shell sink', () => {
    const result = verifyCWE652(buildShellGraph());
    expect(result.holds).toBe(true);
    expect(result.findings).toHaveLength(0);
  });
});
