/**
 * DST Sandbox — Runtime verification pipeline.
 *
 * Barrel export for the three sandbox modules:
 *   channels.ts       — Channel abstraction + HTTPChannel
 *   chain-generator.ts — ProofCertificate -> verification chain -> execution
 *   orchestrator.ts    — Container lifecycle + pipeline runner
 */

export type { Channel, DeliveryTarget, DeliveryParams, DeliveryResult, ObservationResult, ChannelSnapshot } from './channels.js';
export { HTTPChannel } from './channels.js';

export type { ChainStep, VerificationChain, ChainExecutionResult } from './chain-generator.js';
export { generateChain, executeChain } from './chain-generator.js';

export type { ContainerConfig, SandboxOptions, SandboxRunResult, SandboxFinding } from './orchestrator.js';
export { OWASP_BENCHMARK_CONFIG, applyProofStrengthUpdate, runSandbox } from './orchestrator.js';
