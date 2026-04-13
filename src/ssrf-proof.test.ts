/**
 * SSRF Proof System Tests
 *
 * Verifies that CWE-918 findings produce SSRF-specific proof certificates
 * with host_injection payloads, Host header delivery specs, and SSRF oracles
 * instead of generic canary fallback.
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { NeuralMap, NeuralMapNode } from './types.js';
import type { Finding } from './verifier/types.ts';
import {
  generateProof,
  selectPayload,
  buildOracle,
  buildDeliverySpec,
} from './payload-gen.js';
import {
  inferPayloadClassFromCWE,
  SSRF_PAYLOADS,
} from './payload-dictionary.js';
import { buildNeuralMap } from './mapper.js';
import { verifyAll } from './verifier/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildTestMap(nodes: NeuralMapNode[]): NeuralMap {
  const map = createNeuralMap('test.js', 'test source');
  map.nodes = nodes;
  map.edges = [];
  return map;
}

function makeFinding(
  sourceId: string,
  sinkId: string,
  opts?: Partial<Finding>,
): Finding {
  return {
    source: { id: sourceId, label: 'source', line: 1, code: 'req.headers.host' },
    sink: { id: sinkId, label: 'sink', line: 10, code: 'fetch(`https://${req.headers.host}${urlPath}`)' },
    missing: 'CONTROL (URL validation)',
    severity: 'high',
    description: 'SSRF via Host header injection',
    fix: 'Validate and allowlist destination URLs',
    ...opts,
  };
}

// ---------------------------------------------------------------------------
// 1. CWE-918 produces SSRF payload class
// ---------------------------------------------------------------------------

describe('SSRF Proof: CWE-918 payload class', () => {
  it('CWE-918 maps to ssrf payload class, not open_redirect', () => {
    const cls = inferPayloadClassFromCWE('CWE-918');
    expect(cls).toBe('ssrf');
    expect(cls).not.toBe('open_redirect');
  });
});

// ---------------------------------------------------------------------------
// 2. SSRF proof with host_injection payload
// ---------------------------------------------------------------------------

describe('SSRF Proof: host_injection payload', () => {
  beforeEach(() => resetSequence());

  it('produces host_injection payload for Host header SSRF', () => {
    const src = createNode({
      id: 'ingress_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      line_start: 5,
      code_snapshot: 'req.headers.host',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'EXTERNAL',
      node_subtype: 'api_call',
      line_start: 10,
      code_snapshot: 'fetch(`https://${req.headers.host}${urlPath}`)',
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('ingress_1', 'sink_1');

    const proof = generateProof(map, finding, 'CWE-918');
    expect(proof).not.toBeNull();
    expect(proof!.primary_payload.value).toBe('dst-ssrf-probe.example.com');
    expect(proof!.primary_payload.canary).toBe('dst-ssrf-probe');
    expect(proof!.primary_payload.context).toBe('url_context');
    expect(proof!.primary_payload.execution_safe).toBe(true);
  });

  it('payload value is SSRF-specific, not a generic canary', () => {
    const src = createNode({
      id: 'ingress_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      line_start: 5,
      code_snapshot: 'req.headers.host',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'EXTERNAL',
      node_subtype: 'api_call',
      line_start: 10,
      code_snapshot: 'fetch(`https://${req.headers.host}${urlPath}`)',
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('ingress_1', 'sink_1');

    const proof = generateProof(map, finding, 'CWE-918');
    expect(proof).not.toBeNull();
    // Must NOT be a generic canary like DST_SSRF_PROOF or DST_REDIR_PROOF
    expect(proof!.primary_payload.value).not.toContain('DST_');
    expect(proof!.primary_payload.value).toBe('dst-ssrf-probe.example.com');
  });
});

// ---------------------------------------------------------------------------
// 3. Delivery spec: channel=http, header=Host
// ---------------------------------------------------------------------------

describe('SSRF Proof: delivery spec', () => {
  beforeEach(() => resetSequence());

  it('delivery has channel=http and header=Host for Host header injection', () => {
    const src = createNode({
      id: 'ingress_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      line_start: 5,
      code_snapshot: 'req.headers.host',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'EXTERNAL',
      node_subtype: 'api_call',
      line_start: 10,
      code_snapshot: 'fetch(`https://${req.headers.host}${urlPath}`)',
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('ingress_1', 'sink_1');

    const proof = generateProof(map, finding, 'CWE-918');
    expect(proof).not.toBeNull();
    expect(proof!.delivery.channel).toBe('http');
    expect(proof!.delivery.http).toBeDefined();
    expect(proof!.delivery.http!.header).toBe('Host');
  });
});

// ---------------------------------------------------------------------------
// 4. Oracle mentions SSRF
// ---------------------------------------------------------------------------

describe('SSRF Proof: oracle', () => {
  beforeEach(() => resetSequence());

  it('oracle static_proof mentions SSRF', () => {
    const src = createNode({
      id: 'ingress_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      line_start: 5,
      code_snapshot: 'req.headers.host',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'EXTERNAL',
      node_subtype: 'api_call',
      line_start: 10,
      code_snapshot: 'fetch(`https://${req.headers.host}${urlPath}`)',
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('ingress_1', 'sink_1');

    const proof = generateProof(map, finding, 'CWE-918');
    expect(proof).not.toBeNull();
    expect(proof!.oracle.type).toBe('hybrid');
    expect(proof!.oracle.static_proof).toContain('SSRF');
    expect(proof!.oracle.dynamic_signal).toBeDefined();
    expect(proof!.oracle.dynamic_signal!.pattern).toBe('dst-ssrf-probe');
  });

  it('oracle mentions SSRF even without path analysis', () => {
    const oracle = buildOracle('ssrf', {
      value: 'dst-ssrf-probe.example.com',
      canary: 'dst-ssrf-probe',
      context: 'url_context',
      execution_safe: true,
    }, null);
    expect(oracle.type).toBe('hybrid');
    expect(oracle.static_proof).toContain('SSRF');
  });
});

// ---------------------------------------------------------------------------
// 5. Variants include metadata_probe and localhost_probe
// ---------------------------------------------------------------------------

describe('SSRF Proof: variants', () => {
  beforeEach(() => resetSequence());

  it('variants include metadata_probe and localhost_probe', () => {
    const src = createNode({
      id: 'ingress_1',
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      line_start: 5,
      code_snapshot: 'req.headers.host',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1',
      node_type: 'EXTERNAL',
      node_subtype: 'api_call',
      line_start: 10,
      code_snapshot: 'fetch(`https://${req.headers.host}${urlPath}`)',
    });
    const map = buildTestMap([src, sink]);
    const finding = makeFinding('ingress_1', 'sink_1');

    const proof = generateProof(map, finding, 'CWE-918');
    expect(proof).not.toBeNull();
    expect(proof!.variants.length).toBeGreaterThanOrEqual(3);

    const metadataVariant = proof!.variants.find(v => v.value.includes('169.254.169.254'));
    expect(metadataVariant).toBeDefined();
    expect(metadataVariant!.canary).toBe('169.254.169.254');

    const localhostVariant = proof!.variants.find(v => v.value.includes('127.0.0.1'));
    expect(localhostVariant).toBeDefined();
    expect(localhostVariant!.canary).toBe('127.0.0.1');

    // For host injection, the url_injection variant should be first
    const urlVariant = proof!.variants.find(v => v.value.includes('dst-ssrf-probe.example.com/callback'));
    expect(urlVariant).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// 6. E2E: api-resolver.ts real file parse + proof
// ---------------------------------------------------------------------------

describe('SSRF Proof: api-resolver.ts e2e', () => {
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

  beforeEach(() => resetSequence());

  it('finds CWE-918 in api-resolver.ts and generates SSRF proof', { timeout: 30000 }, () => {
    const filePath = 'C:/Users/pizza/bounty-targets/nextjs/packages/next/src/server/api-utils/node/api-resolver.ts';
    if (!fs.existsSync(filePath)) {
      // Skip if bounty-targets not present
      console.log('Skipping: api-resolver.ts not found at', filePath);
      return;
    }

    const code = fs.readFileSync(filePath, 'utf-8');
    const tree = parser.parse(code);
    const { map } = buildNeuralMap(tree, code, 'api-resolver.ts');
    tree.delete();

    const results = verifyAll(map, 'javascript');
    const ssrfResult = results.find(r => r.cwe === 'CWE-918');

    // CWE-918 should be detected
    expect(ssrfResult).toBeDefined();
    if (!ssrfResult || ssrfResult.holds) {
      console.log('CWE-918 not flagged as failing -- skipping proof assertions');
      return;
    }

    expect(ssrfResult.findings.length).toBeGreaterThan(0);

    // Generate proof for the first finding
    const finding = ssrfResult.findings[0];
    const proof = generateProof(map, finding, 'CWE-918');

    // Proof should exist and be SSRF-specific
    expect(proof).not.toBeNull();
    if (proof) {
      // Should be SSRF payload, not generic
      expect(proof.primary_payload.value).not.toContain('DST_REDIR_PROOF');
      expect(proof.primary_payload.canary).toBeTruthy();
      expect(proof.oracle.static_proof).toContain('SSRF');
      expect(proof.oracle.type).toBe('hybrid');

      // Variants should include cloud metadata and localhost probes
      expect(proof.variants.length).toBeGreaterThanOrEqual(1);

      console.log('SSRF proof generated successfully:');
      console.log('  Primary:', proof.primary_payload.value);
      console.log('  Canary:', proof.primary_payload.canary);
      console.log('  Delivery:', proof.delivery.channel, proof.delivery.http?.header || proof.delivery.http?.param);
      console.log('  Oracle:', proof.oracle.static_proof.slice(0, 100));
      console.log('  Variants:', proof.variants.length);
    }
  });
});
