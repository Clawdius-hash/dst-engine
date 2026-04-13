/**
 * Security-Cap-Fail-Open Detection Tests
 *
 * Tests the detectFailOpen verifier against synthetic code samples.
 * Covers cap-based bypass, default-allow initialization, and safe patterns
 * that should NOT be flagged.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { buildNeuralMap } from './mapper.js';
import { javascriptProfile } from './profiles/javascript.js';
import { Parser, Language } from 'web-tree-sitter';
import { detectFailOpen } from './verifier/fail-open.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('Security-Cap-Fail-Open Detection', () => {
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

  function scan(code: string) {
    const tree = parser.parse(code);
    return buildNeuralMap(tree, code, 'test.js', javascriptProfile);
  }

  it('VULNERABLE: detects cap-based security bypass', () => {
    const code = `
      function checkPermissions(commands) {
        if (commands.length > 50) {
          return true;
        }
        for (const cmd of commands) {
          if (denyList.includes(cmd)) return false;
        }
        return true;
      }
    `;
    const { map } = scan(code);
    const result = detectFailOpen(map);
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].description).toContain('cap');
  });

  it('VULNERABLE: detects default-allow initialization in auth function', () => {
    const code = `
      function isAuthorized(user, resource) {
        let allowed = true;
        try {
          if (user.role !== 'admin') {
            allowed = checkPermission(user, resource);
          }
        } catch(e) {
          // swallowed - allowed stays true
        }
        return allowed;
      }
    `;
    const { map } = scan(code);
    const result = detectFailOpen(map);
    expect(result.holds).toBe(false);
  });

  it('SAFE: normal length validation with throw is not flagged', () => {
    const code = `
      function validate(items) {
        if (items.length > 1000) {
          throw new Error('Too many items');
        }
        return processItems(items);
      }
    `;
    const { map } = scan(code);
    const result = detectFailOpen(map);
    expect(result.holds).toBe(true);
  });

  it('SAFE: length check with deny/reject is not flagged', () => {
    const code = `
      function checkAccess(requests) {
        if (requests.length > 100) {
          return res.status(429).json({ error: 'rate limited' });
        }
        return processRequests(requests);
      }
    `;
    const { map } = scan(code);
    const result = detectFailOpen(map);
    expect(result.holds).toBe(true);
  });
});
