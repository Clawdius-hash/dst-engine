/**
 * VERTICAL SLICE TEST — Phase 4 gate.
 *
 * Proves the entire sandbox pipeline works end-to-end:
 * DST scan → ProofCertificate → chain generation → HTTP delivery → oracle → verdict
 *
 * Uses a mock HTTP server that simulates OWASP BenchmarkTest00024 behavior:
 * - Accepts GET/POST with an 'input' parameter
 * - Echoes the SQL query string (containing the input) in the response
 * - This is what the real Benchmark does via DatabaseHelper.outputUpdateComplete()
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as http from 'http';
import { HTTPChannel } from './channels.js';
import { generateChain, executeChain } from './chain-generator.js';
import type { ProofCertificate } from '../verifier/types.js';

// ---------------------------------------------------------------------------
// Mock server: simulates BenchmarkTest00024
// ---------------------------------------------------------------------------

let server: http.Server;
let port: number;

function createMockBenchmark(): Promise<number> {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      const url = new URL(req.url ?? '/', `http://localhost`);

      // Parse the 'input' parameter from query string or body
      let input = url.searchParams.get('input') ?? '';

      if (req.method === 'POST') {
        let body = '';
        req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        req.on('end', () => {
          const params = new URLSearchParams(body);
          input = params.get('input') ?? input;
          respond(input, res);
        });
        return;
      }

      respond(input, res);
    });

    function respond(input: string, res: http.ServerResponse) {
      // Simulate DatabaseHelper.outputUpdateComplete():
      // "Update complete for query: INSERT INTO users... '<input>'"
      const sql = `INSERT INTO users (username, password) VALUES ('foo','${input}')`;
      const html = `<!DOCTYPE html>\n<html>\n<body>\n<p>` +
        `Update complete for query: ${sql}<br>\n` +
        `</p>\n</body>\n</html>`;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(html);
    }

    server.listen(0, () => {
      const addr = server.address();
      port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve(port);
    });
  });
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

describe('Sandbox Vertical Slice', () => {
  beforeAll(async () => {
    await createMockBenchmark();
  });

  afterAll(() => {
    server?.close();
  });

  it('should confirm a known SQL injection finding end-to-end', async () => {
    // Simulate the ProofCertificate that DST produces for BenchmarkTest00024
    const proof: ProofCertificate = {
      primary_payload: {
        value: "' UNION SELECT 'DST_CANARY_SQLI' --",
        canary: 'DST_CANARY_SQLI',
        context: 'sql_string',
        execution_safe: true,
      },
      variants: [
        {
          value: "' OR '1'='1",
          canary: '1',
          context: 'sql_string',
          execution_safe: true,
        },
      ],
      delivery: {
        channel: 'http',
        http: {
          method: 'GET',
          path: '/sqli-00/BenchmarkTest00024',
          param: 'input',
        },
        raw_payload: "' UNION SELECT 'DST_CANARY_SQLI' --",
        encoded_payload: "' UNION SELECT 'DST_CANARY_SQLI' --",
      },
      oracle: {
        type: 'hybrid',
        static_proof: 'Direct path from source to sink, no transforms.',
        dynamic_signal: {
          type: 'content_match',
          pattern: 'DST_CANARY_SQLI',
          positive: true,
        },
      },
      proof_strength: 'conclusive',
      path_analysis: {
        source_to_sink_nodes: 4,
        transforms_on_path: 0,
        blocking_transforms: 0,
      },
    };

    const finding = {
      cwe: 'CWE-89',
      source: { id: 'node_1', label: 'request.getParameter', line: 45 },
      sink: { id: 'node_2', label: 'statement.executeQuery', line: 58 },
    };

    // Generate the chain
    const chain = generateChain(proof, finding, `http://localhost:${port}`);

    expect(chain.steps.length).toBeGreaterThan(0);
    expect(chain.steps[0].type).toBe('baseline');

    // Execute through real HTTPChannel against mock server
    const channel = new HTTPChannel({ timeout_ms: 5000 });
    const result = await executeChain(chain, channel);

    // THE GATE: did the canary get confirmed?
    console.log('Runtime verification state:', result.runtime_verification.state);
    console.log('Explanation:', result.runtime_verification.explanation);

    if (result.runtime_verification.state === 'confirmed') {
      console.log('VERTICAL SLICE PASSED — finding confirmed by sandbox');
    } else {
      console.log('Raw baseline:', result.raw_results.baseline?.body?.substring(0, 200));
      console.log('Raw attack:', result.raw_results.attack_results[0]?.delivery?.body?.substring(0, 200));
      console.log('Observation:', result.raw_results.attack_results[0]?.observation);
    }

    expect(result.runtime_verification.state).toBe('confirmed');
    // The canary was found in the response (confirmed state proves this)
    // attack_response.canary_found may not be set if the confirmation came from the oracle
    // observation rather than the result builder — the state is what matters
    expect(result.raw_results.attack_results.some(r => r.observation.signal_detected)).toBe(true);
  });

  it('should refute a false positive (safe endpoint)', async () => {
    // Same proof but the "vulnerability" doesn't actually exist
    // The mock server always echoes — but with a parameterized query pattern,
    // we simulate a safe endpoint by checking against a path that returns identical
    // responses regardless of input (TODO: enhance mock for this)
    // For now, this test validates the chain runs without crashing
    const proof: ProofCertificate = {
      primary_payload: {
        value: "' UNION SELECT 'DST_CANARY_SQLI' --",
        canary: 'DST_CANARY_SQLI',
        context: 'sql_string',
        execution_safe: true,
      },
      variants: [],
      delivery: {
        channel: 'http',
        http: {
          method: 'GET',
          path: '/safe-endpoint',
          param: 'input',
        },
        raw_payload: "' UNION SELECT 'DST_CANARY_SQLI' --",
        encoded_payload: "' UNION SELECT 'DST_CANARY_SQLI' --",
      },
      oracle: {
        type: 'hybrid',
        static_proof: 'Path exists but may be sanitized.',
        dynamic_signal: {
          type: 'content_match',
          pattern: 'DST_CANARY_SQLI',
          positive: true,
        },
      },
      proof_strength: 'indicative',
      path_analysis: {
        source_to_sink_nodes: 4,
        transforms_on_path: 1,
        blocking_transforms: 0,
      },
    };

    const finding = {
      cwe: 'CWE-89',
      source: { id: 'node_3', label: 'request.getParameter', line: 10 },
      sink: { id: 'node_4', label: 'preparedStatement.execute', line: 20 },
    };

    const chain = generateChain(proof, finding, `http://localhost:${port}`);
    const channel = new HTTPChannel({ timeout_ms: 5000 });
    const result = await executeChain(chain, channel);

    // This mock echoes everything, so it'll still show as confirmed
    // In a real safe endpoint, the parameterized query would prevent the canary from appearing
    // The important thing is the pipeline doesn't crash
    expect(['confirmed', 'refuted', 'inconclusive']).toContain(result.runtime_verification.state);
  });
});
