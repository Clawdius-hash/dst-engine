/**
 * Chain Generator — Bridge between DST's ProofCertificates and Channel execution.
 *
 * DST produces ProofCertificates with:
 *   - a DeliverySpec (HTTP method, path, param)
 *   - a ProofPayload (the attack string)
 *   - an OracleDefinition (what to look for in the response)
 *
 * This module translates those into an ordered sequence of steps
 * (baseline → attack → observe), then executeChain runs them through a Channel.
 *
 * The `refuted` state is the most important output: if DST says "vulnerable"
 * but the sandbox sends the payload and the response is IDENTICAL to baseline,
 * the static finding was likely a false positive. DST checking its own work.
 */

import type {
  ProofCertificate,
  RuntimeVerification,
  RuntimeBlockReason,
  RuntimeVerificationState,
} from '../verifier/types.js';

import type {
  Channel,
  DeliveryTarget,
  DeliveryParams,
  DeliveryResult,
  ObservationResult,
} from './channels.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ChainStep {
  type: 'baseline' | 'attack' | 'observe';
  target: DeliveryTarget;
  params: DeliveryParams;
  /** For baseline: a benign value. For attack: the payload. */
  value?: string;
  /** Which variant this attack is testing (0 = primary) */
  variant_index?: number;
  /** Oracle config for observe steps */
  oracle?: { type: string; pattern: string; positive: boolean };
}

export interface VerificationChain {
  chain_id: string;
  finding_ref: { cwe: string; source_id: string; sink_id: string };
  steps: ChainStep[];
  proof: ProofCertificate;
}

export interface ChainExecutionResult {
  chain_id: string;
  runtime_verification: RuntimeVerification;
  raw_results: {
    baseline?: DeliveryResult;
    attack_results: Array<{
      variant_index: number;
      delivery: DeliveryResult;
      observation: ObservationResult;
    }>;
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Simple string hash for comparing response bodies.
 * Not cryptographic — just detects "are these two responses the same?"
 * Returns first 8 hex chars of a djb2-style hash.
 */
function hashBody(body: string): string {
  let hash = 5381;
  for (let i = 0; i < body.length; i++) {
    // hash * 33 + charCode, kept to 32-bit integer
    hash = ((hash << 5) + hash + body.charCodeAt(i)) | 0;
  }
  // Convert to unsigned 32-bit, then hex, padded to 8 chars
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/**
 * Extract HTTP method from delivery spec. Defaults to 'POST' if not specified.
 */
function determineHTTPMethod(delivery: ProofCertificate['delivery']): string {
  return delivery.http?.method?.toUpperCase() || 'POST';
}

/**
 * Build the oracle config for an observe step.
 * Prefers proof.oracle.dynamic_signal if available.
 * Falls back to content_match on the payload value itself
 * (OWASP Benchmark echoes the SQL string in the response).
 */
function buildOracle(
  proof: ProofCertificate,
): { type: string; pattern: string; positive: boolean } {
  if (proof.oracle.dynamic_signal) {
    return {
      type: proof.oracle.dynamic_signal.type,
      pattern: proof.oracle.dynamic_signal.pattern,
      positive: proof.oracle.dynamic_signal.positive,
    };
  }
  // Fallback: look for the canary string in the response body
  const pattern = proof.primary_payload.canary || proof.primary_payload.value;
  return { type: 'content_match', pattern, positive: true };
}

/**
 * Generate a unique chain ID.
 */
function generateChainId(): string {
  return `sandbox_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

// ---------------------------------------------------------------------------
// generateChain — Pure, synchronous. Translates a ProofCertificate into steps.
// ---------------------------------------------------------------------------

export function generateChain(
  proof: ProofCertificate,
  finding: { cwe: string; source: { id: string }; sink: { id: string } },
  baseUrl: string,
): VerificationChain {
  const chain_id = generateChainId();
  const finding_ref = {
    cwe: finding.cwe,
    source_id: finding.source.id,
    sink_id: finding.sink.id,
  };

  // Non-HTTP/function channels not supported in v1 — return empty chain
  if (proof.delivery.channel !== 'http' && proof.delivery.channel !== 'function') {
    return { chain_id, finding_ref, steps: [], proof };
  }

  const httpSpec = proof.delivery.http;
  if (!httpSpec) {
    // Channel says HTTP but no http spec — defensive, return empty
    return { chain_id, finding_ref, steps: [], proof };
  }

  // Build target and params from the delivery spec
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const cleanPath = httpSpec.path.startsWith('/') ? httpSpec.path : `/${httpSpec.path}`;

  const target: DeliveryTarget = {
    base_url: cleanBase,
    path: cleanPath,
  };

  const params: DeliveryParams = {
    method: determineHTTPMethod(proof.delivery),
    param: httpSpec.param,
    header: httpSpec.header,
    cookie: httpSpec.cookie,
  };

  const oracle = buildOracle(proof);
  const steps: ChainStep[] = [];

  // Step 1: Baseline — benign value to capture normal behavior
  steps.push({
    type: 'baseline',
    target,
    params,
    value: 'test123',
  });

  // Step 2: Primary attack — the main proof payload
  steps.push({
    type: 'attack',
    target,
    params,
    value: proof.primary_payload.value,
    variant_index: 0,
  });

  // Step 3: Observe the primary attack result
  steps.push({
    type: 'observe',
    target,
    params,
    oracle,
  });

  // Steps 4+: Execution-safe variants get their own attack+observe pairs
  proof.variants.forEach((variant, idx) => {
    if (!variant.execution_safe) return;

    steps.push({
      type: 'attack',
      target,
      params,
      value: variant.value,
      variant_index: idx + 1,
    });

    steps.push({
      type: 'observe',
      target,
      params,
      oracle,
    });
  });

  return { chain_id, finding_ref, steps, proof };
}

// ---------------------------------------------------------------------------
// executeChain — Async, NEVER throws. Runs the chain through a Channel.
// ---------------------------------------------------------------------------

export async function executeChain(
  chain: VerificationChain,
  channel: Channel,
): Promise<ChainExecutionResult> {
  const emptyResult = (): ChainExecutionResult => ({
    chain_id: chain.chain_id,
    runtime_verification: {
      state: 'inconclusive',
      timestamp: new Date().toISOString(),
      explanation: 'Chain has no executable steps (non-HTTP or missing delivery spec).',
      chain_id: chain.chain_id,
    },
    raw_results: { attack_results: [] },
  });

  try {
    // No steps → inconclusive
    if (chain.steps.length === 0) {
      return emptyResult();
    }

    // Partition steps
    const baselineStep = chain.steps.find(s => s.type === 'baseline');
    const attackObservePairs: Array<{
      attack: ChainStep;
      observe: ChainStep | undefined;
    }> = [];

    for (let i = 0; i < chain.steps.length; i++) {
      const step = chain.steps[i];
      if (step.type === 'attack') {
        // Next step should be the corresponding observe
        const observeStep = chain.steps[i + 1]?.type === 'observe'
          ? chain.steps[i + 1]
          : undefined;
        attackObservePairs.push({ attack: step, observe: observeStep });
      }
    }

    // ── Execute baseline ──────────────────────────────────────────────
    let baselineResult: DeliveryResult | undefined;

    if (baselineStep) {
      baselineResult = await channel.deliver(
        baselineStep.value ?? 'test123',
        baselineStep.target,
        baselineStep.params,
      );

      // Check baseline for blocking conditions
      if (baselineResult.status_code === 401 || baselineResult.status_code === 403) {
        return buildResult(chain, 'blocked', 'BLOCKED_BY_AUTH',
          `Baseline request returned ${baselineResult.status_code} — authentication required.`,
          baselineResult, []);
      }

      if (baselineResult.status_code === 404) {
        return buildResult(chain, 'error', 'DELIVERY_FAILURE',
          `Baseline request returned 404 — endpoint not found.`,
          baselineResult, []);
      }

      if (!baselineResult.delivered) {
        return buildResult(chain, 'error', 'DELIVERY_FAILURE',
          `Baseline delivery failed: ${baselineResult.error ?? 'unknown error'}.`,
          baselineResult, []);
      }
    }

    // ── Execute attack + observe pairs ────────────────────────────────
    const attackResults: Array<{
      variant_index: number;
      delivery: DeliveryResult;
      observation: ObservationResult;
    }> = [];

    let confirmedState: {
      variantIndex: number;
      delivery: DeliveryResult;
      observation: ObservationResult;
    } | null = null;

    for (const { attack, observe } of attackObservePairs) {
      // Deliver the attack payload
      const attackDelivery = await channel.deliver(
        attack.value ?? '',
        attack.target,
        attack.params,
      );

      // WAF detection: attack gets 403 but baseline was 200
      if (
        attackDelivery.status_code === 403 &&
        baselineResult &&
        baselineResult.status_code === 200
      ) {
        return buildResult(chain, 'blocked', 'BLOCKED_BY_WAF',
          `Attack variant ${attack.variant_index ?? 0} blocked by WAF (403 vs baseline 200).`,
          baselineResult, attackResults);
      }

      // Execute the observe step if present
      let observation: ObservationResult;
      if (observe?.oracle) {
        observation = await channel.observe(
          observe.oracle,
          attackDelivery,
          baselineResult,
        );
      } else {
        observation = {
          signal_detected: false,
          signal_type: 'none' as const,
          confidence: 'none' as const,
          evidence: undefined,
        };
      }

      attackResults.push({
        variant_index: attack.variant_index ?? 0,
        delivery: attackDelivery,
        observation,
      });

      // If signal detected with high confidence → confirmed, stop
      if (observation.signal_detected && (observation.confidence === 'high' || observation.confidence === 'medium')) {
        confirmedState = {
          variantIndex: attack.variant_index ?? 0,
          delivery: attackDelivery,
          observation,
        };
        break;
      }
    }

    // ── Determine final verdict ───────────────────────────────────────

    if (confirmedState) {
      return buildResult(chain, 'confirmed', undefined,
        `Vulnerability confirmed by variant ${confirmedState.variantIndex}: ` +
        `${confirmedState.observation.evidence ?? 'signal detected with high confidence'}.`,
        baselineResult, attackResults, confirmedState.variantIndex);
    }

    // At least one attack was delivered — check for refutation
    const deliveredAttacks = attackResults.filter(r => r.delivery.delivered);
    if (deliveredAttacks.length > 0 && baselineResult) {
      const baselineHash = hashBody(baselineResult.body ?? '');
      // If ANY attack response body is identical to baseline → refuted
      const identicalToBaseline = deliveredAttacks.some(
        r => hashBody(r.delivery.body ?? '') === baselineHash,
      );

      if (identicalToBaseline) {
        return buildResult(chain, 'refuted', undefined,
          'Attack response body identical to baseline — payload had no effect. ' +
          'Static finding is likely a false positive.',
          baselineResult, attackResults);
      }

      // Responses differ but no oracle signal — inconclusive
      return buildResult(chain, 'inconclusive', 'ORACLE_INCONCLUSIVE',
        'Payload delivered and response differs from baseline, but oracle did not detect the expected signal.',
        baselineResult, attackResults);
    }

    // No attacks delivered at all
    return buildResult(chain, 'error', 'DELIVERY_FAILURE',
      'No attack payloads were successfully delivered.',
      baselineResult, attackResults);

  } catch (err: unknown) {
    // Per-finding isolation: never throw, always return error state
    const message = err instanceof Error ? err.message : String(err);
    return {
      chain_id: chain.chain_id,
      runtime_verification: {
        state: 'error',
        timestamp: new Date().toISOString(),
        block_reason: 'ENVIRONMENT_FAILURE',
        explanation: `Chain execution failed: ${message}`,
        chain_id: chain.chain_id,
      },
      raw_results: { attack_results: [] },
    };
  }
}

// ---------------------------------------------------------------------------
// buildResult — Assemble the ChainExecutionResult with full RuntimeVerification
// ---------------------------------------------------------------------------

function buildResult(
  chain: VerificationChain,
  state: RuntimeVerificationState,
  blockReason: RuntimeBlockReason | undefined,
  explanation: string,
  baselineResult: DeliveryResult | undefined,
  attackResults: Array<{
    variant_index: number;
    delivery: DeliveryResult;
    observation: ObservationResult;
  }>,
  confirmedVariant?: number,
): ChainExecutionResult {
  // Find the "best" attack result for the runtime verification snapshot
  const bestAttack = confirmedVariant !== undefined
    ? attackResults.find(r => r.variant_index === confirmedVariant)
    : attackResults[0];

  const rv: RuntimeVerification = {
    state,
    timestamp: new Date().toISOString(),
    explanation,
    chain_id: chain.chain_id,
  };

  if (blockReason) {
    rv.block_reason = blockReason;
  }

  if (confirmedVariant !== undefined) {
    rv.variant_index = confirmedVariant;
  }

  // Populate baseline snapshot
  if (baselineResult) {
    rv.baseline = {
      status_code: baselineResult.status_code,
      body_hash: hashBody(baselineResult.body ?? ''),
      response_time_ms: baselineResult.response_time_ms ?? 0,
    };
  }

  // Populate attack response snapshot
  if (bestAttack) {
    const delivery = bestAttack.delivery;
    const observation = bestAttack.observation;

    rv.attack_response = {
      status_code: delivery.status_code,
      body_hash: hashBody(delivery.body ?? ''),
      response_time_ms: delivery.response_time_ms ?? 0,
      canary_found: (observation.signal_detected &&
        (observation.evidence?.includes('canary') ?? false)) || false,
      timing_anomaly: baselineResult
        ? (delivery.response_time_ms ?? 0) > (baselineResult.response_time_ms ?? 0) * 3
        : false,
      evidence_excerpt: observation.evidence?.slice(0, 200),
    };
  }

  return {
    chain_id: chain.chain_id,
    runtime_verification: rv,
    raw_results: {
      baseline: baselineResult,
      attack_results: attackResults,
    },
  };
}
