import { describe, it, expect } from 'vitest';
import { composeFindings } from './compose.js';
import type { ComposableFinding } from './types.js';
import type { Finding } from '../verifier/types.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> & Pick<Finding, 'source' | 'sink'>): Finding {
  return {
    missing: 'sanitization',
    severity: 'high',
    description: 'test finding',
    fix: 'add sanitization',
    ...overrides,
  };
}

function makeComposable(opts: {
  cwe?: string;
  file?: string;
  sourceId?: string;
  sourceCode?: string;
  sinkId?: string;
  sinkCode?: string;
  severity?: Finding['severity'];
}): ComposableFinding {
  return {
    cwe: opts.cwe ?? 'CWE-89',
    file: opts.file ?? 'app.ts',
    finding: makeFinding({
      severity: opts.severity ?? 'high',
      source: {
        id: opts.sourceId ?? 'src1',
        label: 'source',
        line: 1,
        code: opts.sourceCode ?? 'req.body.input',
      },
      sink: {
        id: opts.sinkId ?? 'sink1',
        label: 'sink',
        line: 10,
        code: opts.sinkCode ?? 'db.query("SELECT * FROM users")',
      },
    }),
  };
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('composeFindings', () => {
  describe('storage target bridge', () => {
    it('chains two findings that share a SQL table (A sink -> B source)', () => {
      const findingA = makeComposable({
        cwe: 'CWE-89',
        file: 'write.ts',
        sinkCode: 'db.query("INSERT INTO user_data VALUES ($1)")',
      });
      const findingB = makeComposable({
        cwe: 'CWE-200',
        file: 'read.ts',
        sourceCode: 'db.query("SELECT * FROM user_data WHERE id = $1")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].links).toHaveLength(2);
      expect(chains[0].chainType).toBe('storage');
      expect(chains[0].links[1].bridgeType).toBe('storage');
      expect(chains[0].links[1].bridgeDetail).toContain('user_data');
    });

    it('chains findings sharing a MongoDB collection', () => {
      const findingA = makeComposable({
        sinkCode: 'db.collection("orders").insertOne(doc)',
      });
      const findingB = makeComposable({
        sourceCode: 'db.collection("orders").find({})',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].links[1].bridgeDetail).toContain('orders');
    });

    it('chains findings sharing a file path', () => {
      const findingA = makeComposable({
        sinkCode: 'fs.writeFileSync("/tmp/secrets.json", data)',
      });
      const findingB = makeComposable({
        sourceCode: 'fs.readFileSync("/tmp/secrets.json", "utf8")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].chainType).toBe('file_io');
    });

    it('chains findings sharing an env var', () => {
      const findingA = makeComposable({
        sinkCode: 'process.env.DB_PASSWORD = userInput',
      });
      const findingB = makeComposable({
        sourceCode: 'const pw = process.env.DB_PASSWORD',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].chainType).toBe('env_var');
    });
  });

  describe('same-node bridge', () => {
    it('chains two findings where A sink id matches B source id in same file', () => {
      const findingA = makeComposable({
        cwe: 'CWE-89',
        file: 'handler.ts',
        sinkId: 'node_42',
        sinkCode: 'console.log(data)',  // no extractable target
      });
      const findingB = makeComposable({
        cwe: 'CWE-79',
        file: 'handler.ts',
        sourceId: 'node_42',
        sourceCode: 'const data = getInput()',  // no extractable target
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].chainType).toBe('same_node');
      expect(chains[0].links[1].bridgeType).toBe('same_node');
      expect(chains[0].links[1].bridgeDetail).toContain('node_42');
    });

    it('does NOT chain same-node bridge across different files', () => {
      const findingA = makeComposable({
        file: 'fileA.ts',
        sinkId: 'node_42',
        sinkCode: 'console.log(data)',
      });
      const findingB = makeComposable({
        file: 'fileB.ts',
        sourceId: 'node_42',
        sourceCode: 'const data = getInput()',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(0);
    });
  });

  describe('no chain for unrelated findings', () => {
    it('does NOT chain findings with no shared target or node', () => {
      const findingA = makeComposable({
        sinkCode: 'db.query("INSERT INTO users VALUES ($1)")',
        sinkId: 'node_1',
        file: 'a.ts',
      });
      const findingB = makeComposable({
        sourceCode: 'const x = req.params.id',
        sourceId: 'node_99',
        file: 'b.ts',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(0);
    });
  });

  describe('severity escalation', () => {
    it('escalates two highs to critical', () => {
      const findingA = makeComposable({
        severity: 'high',
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
      });
      const findingB = makeComposable({
        severity: 'high',
        sourceCode: 'db.query("SELECT * FROM shared")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].severity).toBe('critical');
    });

    it('escalates two mediums to high', () => {
      const findingA = makeComposable({
        severity: 'medium',
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
      });
      const findingB = makeComposable({
        severity: 'medium',
        sourceCode: 'db.query("SELECT * FROM shared")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].severity).toBe('high');
    });

    it('escalates medium + high to critical', () => {
      const findingA = makeComposable({
        severity: 'medium',
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
      });
      const findingB = makeComposable({
        severity: 'high',
        sourceCode: 'db.query("SELECT * FROM shared")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].severity).toBe('critical');
    });

    it('escalates two lows to medium', () => {
      const findingA = makeComposable({
        severity: 'low',
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
      });
      const findingB = makeComposable({
        severity: 'low',
        sourceCode: 'db.query("SELECT * FROM shared")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].severity).toBe('medium');
    });

    it('caps at critical (high + critical stays critical)', () => {
      const findingA = makeComposable({
        severity: 'critical',
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
      });
      const findingB = makeComposable({
        severity: 'high',
        sourceCode: 'db.query("SELECT * FROM shared")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].severity).toBe('critical');
    });
  });

  describe('chain description', () => {
    it('produces a non-empty description', () => {
      const findingA = makeComposable({
        cwe: 'CWE-89',
        sinkCode: 'db.query("INSERT INTO logs VALUES ($1)")',
      });
      const findingB = makeComposable({
        cwe: 'CWE-200',
        sourceCode: 'db.query("SELECT * FROM logs")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].description).toBeTruthy();
      expect(chains[0].description.length).toBeGreaterThan(10);
    });
  });

  describe('deduplication', () => {
    it('does not create both A->B and B->A for the same pair', () => {
      // Both sink and source share the same table, so both directions would match
      const findingA = makeComposable({
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
        sourceCode: 'db.query("SELECT * FROM shared")',
        sourceId: 'sA',
        sinkId: 'kA',
      });
      const findingB = makeComposable({
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
        sourceCode: 'db.query("SELECT * FROM shared")',
        sourceId: 'sB',
        sinkId: 'kB',
      });

      const chains = composeFindings([findingA, findingB]);
      // Should get exactly 1, not 2 (deduped A->B and B->A)
      expect(chains).toHaveLength(1);
    });
  });

  describe('boundary counting', () => {
    it('counts 0 boundaries when no trust boundaries are set', () => {
      const findingA = makeComposable({
        file: 'fileA.ts',
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
      });
      const findingB = makeComposable({
        file: 'fileB.ts',
        sourceCode: 'db.query("SELECT * FROM shared")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].boundariesCrossed).toBe(0);
    });

    it('counts 0 boundaries when findings share the same trust boundary', () => {
      const findings: ComposableFinding[] = [
        {
          cwe: 'CWE-89',
          file: 'a.js',
          finding: makeFinding({
            source: { id: 's1', label: 'src', line: 1, code: 'req.body.x' },
            sink: { id: 'k1', label: 'snk', line: 2, code: 'db.query("INSERT INTO shared VALUES ($1)")' },
            severity: 'high',
          }),
          sinkStorageTarget: { kind: 'table', name: 'shared' },
          sinkTrustBoundary: 'storage',
          sourceTrustBoundary: 'storage',
        },
        {
          cwe: 'CWE-200',
          file: 'b.js',
          finding: makeFinding({
            source: { id: 's2', label: 'src', line: 1, code: 'db.query("SELECT * FROM shared")' },
            sink: { id: 'k2', label: 'snk', line: 2, code: 'res.send(data)' },
            severity: 'medium',
          }),
          sourceStorageTarget: { kind: 'table', name: 'shared' },
          sourceTrustBoundary: 'storage',
          sinkTrustBoundary: 'storage',
        },
      ];

      const chains = composeFindings(findings);
      expect(chains).toHaveLength(1);
      expect(chains[0].boundariesCrossed).toBe(0);
    });

    it('counts trust boundaries crossed (not just file count)', () => {
      // Finding A: source in network_external, sink in storage
      // Finding B: source in storage, sink in subprocess
      // That's 3 boundaries: network_external, storage, subprocess -> 2 crossings
      const findings: ComposableFinding[] = [
        {
          cwe: 'CWE-89',
          file: 'a.js',
          finding: makeFinding({
            source: { id: 's1', label: 'src', line: 1, code: 'req.body.x' },
            sink: { id: 'k1', label: 'snk', line: 2, code: 'db.query("INSERT INTO users VALUES ($1)")' },
            severity: 'high',
          }),
          sinkStorageTarget: { kind: 'table', name: 'users' },
          sinkTrustBoundary: 'storage',
          sourceTrustBoundary: 'network_external',
        },
        {
          cwe: 'CWE-78',
          file: 'b.js',
          finding: makeFinding({
            source: { id: 's2', label: 'src', line: 1, code: 'db.query("SELECT * FROM users")' },
            sink: { id: 'k2', label: 'snk', line: 2, code: 'exec(cmd)' },
            severity: 'high',
          }),
          sourceStorageTarget: { kind: 'table', name: 'users' },
          sourceTrustBoundary: 'storage',
          sinkTrustBoundary: 'subprocess',
        },
      ];

      const chains = composeFindings(findings);
      expect(chains.length).toBeGreaterThanOrEqual(1);
      expect(chains[0].boundariesCrossed).toBe(2); // network_external -> storage -> subprocess
    });
  });

  describe('empty / single input', () => {
    it('returns empty array for empty input', () => {
      expect(composeFindings([])).toEqual([]);
    });

    it('returns empty array for single finding', () => {
      const f = makeComposable({});
      expect(composeFindings([f])).toEqual([]);
    });
  });

  describe('AST metadata preference over regex', () => {
    it('prefers sinkStorageTarget metadata over regex extraction', () => {
      const findings: ComposableFinding[] = [
        {
          cwe: 'CWE-89',
          file: 'a.js',
          finding: makeFinding({
            source: { id: 's1', label: 'req.body', line: 1, code: 'req.body.x', file: 'a.js' },
            sink: { id: 'k1', label: 'db.query', line: 2, code: 'some code without sql keywords', file: 'a.js' },
            missing: 'CONTROL',
            severity: 'high',
          }),
          sinkStorageTarget: { kind: 'table', name: 'users' },
        },
        {
          cwe: 'CWE-89',
          file: 'b.js',
          finding: makeFinding({
            source: { id: 's2', label: 'db.query', line: 1, code: 'some code without sql keywords', file: 'b.js' },
            sink: { id: 'k2', label: 'res.json', line: 2, code: 'res.json(result)', file: 'b.js' },
            missing: 'CONTROL',
            severity: 'medium',
          }),
          sourceStorageTarget: { kind: 'table', name: 'users' },
        },
      ];

      const chains = composeFindings(findings);
      // Should chain via metadata even though code_snapshot has no SQL keywords
      expect(chains.length).toBeGreaterThanOrEqual(1);
      expect(chains[0].chainType).toBe('storage');
      expect(chains[0].links[1].bridgeDetail).toContain('users');
    });

    it('falls back to regex when metadata is absent', () => {
      // No metadata — relies on regex extracting "shared" from SQL
      const findingA = makeComposable({
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
      });
      const findingB = makeComposable({
        sourceCode: 'db.query("SELECT * FROM shared")',
      });

      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].chainType).toBe('storage');
    });

    it('metadata takes precedence over conflicting regex extraction', () => {
      // The code says "users" table but metadata says "orders"
      const findings: ComposableFinding[] = [
        {
          cwe: 'CWE-89',
          file: 'a.js',
          finding: makeFinding({
            source: { id: 's1', label: 'src', line: 1, code: 'req.body' },
            sink: { id: 'k1', label: 'snk', line: 2, code: 'db.query("INSERT INTO users VALUES ($1)")', file: 'a.js' },
            severity: 'high',
          }),
          sinkStorageTarget: { kind: 'table', name: 'orders' },
        },
        {
          cwe: 'CWE-200',
          file: 'b.js',
          finding: makeFinding({
            source: { id: 's2', label: 'src', line: 1, code: 'db.query("SELECT * FROM orders")', file: 'b.js' },
            sink: { id: 'k2', label: 'snk', line: 2, code: 'res.send(data)', file: 'b.js' },
            severity: 'medium',
          }),
        },
      ];

      const chains = composeFindings(findings);
      // Metadata says "orders" for A's sink; regex extracts "orders" from B's source
      // They should chain because both resolve to storage/orders
      expect(chains.length).toBeGreaterThanOrEqual(1);
      expect(chains[0].links[1].bridgeDetail).toContain('orders');
    });
  });

  describe('directionality: READ→READ chains suppressed', () => {
    it('does NOT chain two independent env var READS', () => {
      const findings: ComposableFinding[] = [
        {
          cwe: 'CWE-215',
          file: 'index.ts',
          finding: makeFinding({
            source: { id: 's1', label: 'src', line: 1, code: 'process.env.NODE_ENV' },
            sink: { id: 'k1', label: 'snk', line: 2, code: 'if (process.env.NODE_ENV === "dev")' },
            severity: 'medium',
          }),
          sinkStorageTarget: { kind: 'env', name: 'NODE_ENV' },
          sinkNodeType: 'INGRESS',
          sinkNodeSubtype: 'env_read',
        },
        {
          cwe: 'CWE-454',
          file: 'resolver.ts',
          finding: makeFinding({
            source: { id: 's2', label: 'src', line: 1, code: 'process.env.NODE_ENV' },
            sink: { id: 'k2', label: 'snk', line: 2, code: 'console.warn(msg)' },
            severity: 'medium',
          }),
          sourceStorageTarget: { kind: 'env', name: 'NODE_ENV' },
          sourceNodeType: 'INGRESS',
          sourceNodeSubtype: 'env_read',
        },
      ];
      const chains = composeFindings(findings);
      expect(chains).toHaveLength(0);
    });

    it('DOES chain a real WRITE→READ env var flow', () => {
      const findings: ComposableFinding[] = [
        {
          cwe: 'CWE-89',
          file: 'writer.ts',
          finding: makeFinding({
            source: { id: 's1', label: 'src', line: 1, code: 'req.body.x' },
            sink: { id: 'k1', label: 'snk', line: 2, code: 'process.env.DB_PASSWORD = userInput' },
            severity: 'high',
          }),
          sinkStorageTarget: { kind: 'env', name: 'DB_PASSWORD' },
          sinkNodeType: 'EGRESS',
          sinkNodeSubtype: 'env_write',
        },
        {
          cwe: 'CWE-89',
          file: 'reader.ts',
          finding: makeFinding({
            source: { id: 's2', label: 'src', line: 1, code: 'const pw = process.env.DB_PASSWORD' },
            sink: { id: 'k2', label: 'snk', line: 2, code: 'db.connect(pw)' },
            severity: 'high',
          }),
          sourceStorageTarget: { kind: 'env', name: 'DB_PASSWORD' },
          sourceNodeType: 'INGRESS',
          sourceNodeSubtype: 'env_read',
        },
      ];
      const chains = composeFindings(findings);
      expect(chains).toHaveLength(1);
      expect(chains[0].chainType).toBe('env_var');
    });

    it('does NOT chain two independent file READS', () => {
      const findings: ComposableFinding[] = [
        {
          cwe: 'CWE-22',
          file: 'a.ts',
          finding: makeFinding({
            source: { id: 's1', label: 'src', line: 1, code: 'req.body.path' },
            sink: { id: 'k1', label: 'snk', line: 2, code: 'fs.readFile("/config/app.json")' },
            severity: 'high',
          }),
          sinkStorageTarget: { kind: 'file', name: '/config/app.json' },
          sinkNodeType: 'INGRESS',
          sinkNodeSubtype: 'file_read',
        },
        {
          cwe: 'CWE-200',
          file: 'b.ts',
          finding: makeFinding({
            source: { id: 's2', label: 'src', line: 1, code: 'fs.readFile("/config/app.json")' },
            sink: { id: 'k2', label: 'snk', line: 2, code: 'res.send(data)' },
            severity: 'medium',
          }),
          sourceStorageTarget: { kind: 'file', name: '/config/app.json' },
          sourceNodeType: 'INGRESS',
          sourceNodeSubtype: 'file_read',
        },
      ];
      const chains = composeFindings(findings);
      expect(chains).toHaveLength(0);
    });

    it('DOES chain file WRITE→READ', () => {
      const findings: ComposableFinding[] = [
        {
          cwe: 'CWE-89',
          file: 'a.ts',
          finding: makeFinding({
            source: { id: 's1', label: 'src', line: 1, code: 'req.body.x' },
            sink: { id: 'k1', label: 'snk', line: 2, code: 'fs.writeFileSync("/tmp/secrets.json", data)' },
            severity: 'high',
          }),
          sinkStorageTarget: { kind: 'file', name: '/tmp/secrets.json' },
          sinkNodeType: 'EGRESS',
          sinkNodeSubtype: 'file_write',
        },
        {
          cwe: 'CWE-200',
          file: 'b.ts',
          finding: makeFinding({
            source: { id: 's2', label: 'src', line: 1, code: 'fs.readFileSync("/tmp/secrets.json", "utf8")' },
            sink: { id: 'k2', label: 'snk', line: 2, code: 'res.send(data)' },
            severity: 'medium',
          }),
          sourceStorageTarget: { kind: 'file', name: '/tmp/secrets.json' },
          sourceNodeType: 'INGRESS',
          sourceNodeSubtype: 'file_read',
        },
      ];
      const chains = composeFindings(findings);
      expect(chains).toHaveLength(1);
      expect(chains[0].chainType).toBe('file_io');
    });

    it('chains work when node semantics are absent (backward compatible)', () => {
      const findingA = makeComposable({
        sinkCode: 'db.query("INSERT INTO shared VALUES ($1)")',
      });
      const findingB = makeComposable({
        sourceCode: 'db.query("SELECT * FROM shared")',
      });
      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
    });

    it('same_node bridges are NOT affected by directionality', () => {
      const findingA: ComposableFinding = {
        cwe: 'CWE-129',
        file: 'handler.ts',
        finding: makeFinding({
          source: { id: 's1', label: 'src', line: 1, code: 'req.headers' },
          sink: { id: 'node_42', label: 'snk', line: 2, code: '(req as any)[key]' },
          severity: 'high',
        }),
        sinkNodeType: 'TRANSFORM',
        sinkNodeSubtype: 'assignment',
      };
      const findingB: ComposableFinding = {
        cwe: 'CWE-704',
        file: 'handler.ts',
        finding: makeFinding({
          source: { id: 'node_42', label: 'src', line: 2, code: '(req as any)[key]' },
          sink: { id: 'k2', label: 'snk', line: 3, code: 'processData(value)' },
          severity: 'medium',
        }),
        sourceNodeType: 'TRANSFORM',
        sourceNodeSubtype: 'assignment',
      };
      const chains = composeFindings([findingA, findingB]);
      expect(chains).toHaveLength(1);
      expect(chains[0].chainType).toBe('same_node');
    });
  });
});
