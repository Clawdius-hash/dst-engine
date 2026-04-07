/**
 * Sandbox Orchestrator — Pipeline runner for DST runtime verification.
 *
 * Pipeline: DST scan -> ProofCertificates -> chain generation -> container start
 * -> health check -> baseline -> attack -> observe -> verdict -> container stop
 * -> updated proof_strength.
 *
 * Container lifecycle uses execSync (Docker Desktop + WSL2 backend on Windows).
 * Per-finding isolation: one failure never kills the run.
 * Container cleanup is always in a finally block.
 */

import { execSync } from 'child_process';
import { HTTPChannel } from './channels.js';
import { generateChain, executeChain, type ChainExecutionResult } from './chain-generator.js';
import type {
  ProofCertificate,
  RuntimeVerification,
  RuntimeVerificationState,
} from '../verifier/types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ContainerConfig {
  image: string;
  port_mapping: string;        // "8443:8443"
  health_check_url: string;    // "https://localhost:8443/benchmark/"
  startup_timeout_ms: number;
  env?: Record<string, string>;
}

export const OWASP_BENCHMARK_CONFIG: ContainerConfig = {
  image: 'owasp/benchmark',
  port_mapping: '8443:8443',
  health_check_url: 'https://localhost:8443/benchmark/',
  startup_timeout_ms: 120000,
};

export interface SandboxOptions {
  config?: ContainerConfig;
  skip_container?: boolean;
  base_url?: string;             // required if skip_container is true
  cwe_filter?: string[];
  max_findings?: number;
  timeout_per_finding_ms?: number;
  onProgress?: (completed: number, total: number, latest: ChainExecutionResult) => void;
}

export interface SandboxRunResult {
  total_findings: number;
  verified: number;
  confirmed: number;
  refuted: number;
  blocked: number;
  inconclusive: number;
  errors: number;
  elapsed_ms: number;
  container_id?: string;
  results: ChainExecutionResult[];
}

/** What we receive from DST's verification layer. */
export interface SandboxFinding {
  cwe: string;
  source: { id: string; label: string; line: number };
  sink: { id: string; label: string; line: number };
  proof?: ProofCertificate;
}

// ---------------------------------------------------------------------------
// Container lifecycle
// ---------------------------------------------------------------------------

/**
 * Ensure the Docker image is available locally. Pulls if missing.
 * Throws on pull failure.
 */
function ensureImage(image: string): void {
  try {
    execSync(`docker image inspect ${image}`, {
      stdio: 'pipe',
      timeout: 30_000,
    });
  } catch {
    // Image not found locally — pull it
    try {
      execSync(`docker pull ${image}`, {
        stdio: 'inherit',
        timeout: 300_000,
      });
    } catch (pullErr: unknown) {
      const msg = pullErr instanceof Error ? pullErr.message : String(pullErr);
      throw new Error(`Failed to pull Docker image "${image}": ${msg}`);
    }
  }
}

/**
 * Start a sandboxed container. Returns the container ID.
 *
 * Security hardening (v1):
 *   --cap-drop ALL          — no Linux capabilities
 *   --security-opt no-new-privileges
 *   --memory 1g --cpus 2    — resource limits
 *   --rm                    — auto-remove on stop
 *
 * NOTE: No --network=internal. The host must reach the container's mapped port.
 */
function startContainer(config: ContainerConfig): string {
  const envFlags = config.env
    ? Object.entries(config.env).map(([k, v]) => `-e ${k}=${v}`).join(' ')
    : '';

  const cmd = [
    'docker run -d --rm',
    '--cap-drop ALL',
    '--security-opt no-new-privileges',
    '--memory 1g',
    '--cpus 2',
    `-p ${config.port_mapping}`,
    envFlags,
    config.image,
  ].filter(Boolean).join(' ');

  try {
    const output = execSync(cmd, { stdio: 'pipe', timeout: 60_000 });
    return output.toString().trim();
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to start container from "${config.image}": ${msg}`);
  }
}

/**
 * Poll the health check URL until it returns 200 or we time out.
 * Handles self-signed TLS (OWASP Benchmark uses HTTPS with a self-signed cert).
 * Returns true if healthy, false on timeout.
 */
async function waitForHealthy(url: string, timeout_ms: number): Promise<boolean> {
  const start = performance.now();
  const pollInterval = 3000;

  // Temporarily accept self-signed certs
  const previousTLS = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

  try {
    while (performance.now() - start < timeout_ms) {
      try {
        const response = await fetch(url, {
          signal: AbortSignal.timeout(5000),
          redirect: 'follow',
        });
        if (response.status === 200) {
          return true;
        }
      } catch {
        // Container still starting — swallow and retry
      }

      // Wait before next poll
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
    return false;
  } finally {
    if (previousTLS === undefined) {
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    } else {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousTLS;
    }
  }
}

/**
 * Stop a container by ID. Ignores errors (container may already be stopped/removed).
 */
function stopContainer(containerId: string): void {
  try {
    execSync(`docker stop ${containerId}`, {
      stdio: 'pipe',
      timeout: 30_000,
    });
  } catch {
    // Container already stopped or removed — that's fine
  }
}

// ---------------------------------------------------------------------------
// Proof strength update
// ---------------------------------------------------------------------------

/**
 * Map a runtime verification state to an updated proof_strength.
 *
 * confirmed  -> 'conclusive'  (runtime proved it)
 * refuted    -> 'refuted'     (runtime disproved it)
 * everything else -> no change (not enough evidence to upgrade or downgrade)
 */
export function applyProofStrengthUpdate(
  current: ProofCertificate['proof_strength'],
  state: RuntimeVerificationState,
): ProofCertificate['proof_strength'] {
  if (state === 'confirmed') return 'conclusive';
  if (state === 'refuted') return 'refuted';
  return current;
}

// ---------------------------------------------------------------------------
// Batch optimization
// ---------------------------------------------------------------------------

/**
 * Group findings by their HTTP delivery path for future batch optimization.
 * Findings without an HTTP proof go into the '_no_path' bucket.
 */
function batchByEndpoint(findings: SandboxFinding[]): Map<string, SandboxFinding[]> {
  const batches = new Map<string, SandboxFinding[]>();

  for (const f of findings) {
    const path = f.proof?.delivery?.http?.path ?? '_no_path';
    const bucket = batches.get(path);
    if (bucket) {
      bucket.push(f);
    } else {
      batches.set(path, [f]);
    }
  }

  return batches;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Derive the base URL from a ContainerConfig's health_check_url. */
function baseUrlFromConfig(config: ContainerConfig): string {
  const url = new URL(config.health_check_url);
  return `${url.protocol}//${url.host}`;
}

/** Count occurrences of a runtime state across results. */
function countState(
  results: ChainExecutionResult[],
  state: RuntimeVerificationState,
): number {
  return results.filter(r => r.runtime_verification.state === state).length;
}

// ---------------------------------------------------------------------------
// Main pipeline
// ---------------------------------------------------------------------------

/**
 * Run the sandbox verification pipeline.
 *
 * 1. Filter findings to those with ProofCertificates
 * 2. Apply CWE filter and max_findings cap
 * 3. Start container (unless skip_container)
 * 4. For each finding: generateChain -> executeChain -> update proof_strength
 * 5. Stop container (in finally block)
 * 6. Return aggregated results
 */
export async function runSandbox(
  findings: SandboxFinding[],
  options: SandboxOptions = {},
): Promise<SandboxRunResult> {
  const startTime = performance.now();
  const config = options.config ?? OWASP_BENCHMARK_CONFIG;

  // ── Step 1: Filter to findings with proofs ─────────────────────────
  let eligible = findings.filter(f => f.proof !== undefined);

  // ── Step 2: Apply CWE filter ───────────────────────────────────────
  if (options.cwe_filter && options.cwe_filter.length > 0) {
    const allowed = new Set(options.cwe_filter);
    eligible = eligible.filter(f => allowed.has(f.cwe));
  }

  // ── Step 3: Apply max_findings cap ─────────────────────────────────
  if (options.max_findings !== undefined && options.max_findings > 0) {
    eligible = eligible.slice(0, options.max_findings);
  }

  // Early exit if nothing to verify
  if (eligible.length === 0) {
    return {
      total_findings: 0,
      verified: 0,
      confirmed: 0,
      refuted: 0,
      blocked: 0,
      inconclusive: 0,
      errors: 0,
      elapsed_ms: Math.round(performance.now() - startTime),
      results: [],
    };
  }

  // Batch by endpoint for logging/future parallelization
  const _batches = batchByEndpoint(eligible);

  // ── Step 4: Container lifecycle ────────────────────────────────────
  let containerId: string | undefined;

  if (!options.skip_container) {
    ensureImage(config.image);
    containerId = startContainer(config);

    const healthy = await waitForHealthy(
      config.health_check_url,
      config.startup_timeout_ms,
    );

    if (!healthy) {
      stopContainer(containerId);
      throw new Error(
        `Container health check timed out after ${config.startup_timeout_ms}ms. ` +
        `URL: ${config.health_check_url}`,
      );
    }
  }

  // ── Step 5: Determine base URL ─────────────────────────────────────
  const baseUrl = options.base_url
    ?? (options.skip_container ? undefined : baseUrlFromConfig(config));

  if (!baseUrl) {
    throw new Error(
      'No base_url available. Provide options.base_url or use a container config.',
    );
  }

  // ── Step 6: Create channel ─────────────────────────────────────────
  const channel = new HTTPChannel({
    timeout_ms: options.timeout_per_finding_ms ?? 10000,
  });

  // ── Step 7: Execute chains — per-finding isolation ─────────────────
  const results: ChainExecutionResult[] = [];

  try {
    for (let i = 0; i < eligible.length; i++) {
      const finding = eligible[i];
      // proof was filtered in step 1, but guard defensively
      const proof = finding.proof;
      if (!proof) continue;

      try {
        // Generate the verification chain
        const chain = generateChain(proof, finding, baseUrl);

        // Execute through the channel
        const result = await executeChain(chain, channel);

        // Update proof_strength based on runtime verdict
        proof.proof_strength = applyProofStrengthUpdate(
          proof.proof_strength,
          result.runtime_verification.state,
        );

        // Attach runtime_verification to the proof certificate
        proof.runtime_verification = result.runtime_verification;

        results.push(result);

        // Progress callback
        if (options.onProgress) {
          options.onProgress(i + 1, eligible.length, result);
        }
      } catch (err: unknown) {
        // Per-finding isolation: capture the error, keep going
        const message = err instanceof Error ? err.message : String(err);
        const errorResult: ChainExecutionResult = {
          chain_id: `error_${finding.cwe}_${finding.sink.id}`,
          runtime_verification: {
            state: 'error',
            timestamp: new Date().toISOString(),
            block_reason: 'ENVIRONMENT_FAILURE',
            explanation: `Finding-level error: ${message}`,
          },
          raw_results: { attack_results: [] },
        };

        results.push(errorResult);

        if (options.onProgress) {
          options.onProgress(i + 1, eligible.length, errorResult);
        }
      }
    }
  } finally {
    // ── Step 8: Always stop the container ─────────────────────────────
    if (containerId) {
      stopContainer(containerId);
    }
  }

  // ── Step 9: Aggregate and return ───────────────────────────────────
  const elapsed_ms = Math.round(performance.now() - startTime);

  return {
    total_findings: eligible.length,
    verified: results.length,
    confirmed: countState(results, 'confirmed'),
    refuted: countState(results, 'refuted'),
    blocked: countState(results, 'blocked'),
    inconclusive: countState(results, 'inconclusive'),
    errors: countState(results, 'error'),
    elapsed_ms,
    container_id: containerId,
    results,
  };
}
