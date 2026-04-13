import { describe, it, expect } from 'vitest';
import { classifyTrustBoundary } from './trustBoundary.js';

describe('classifyTrustBoundary', () => {
  // --- INGRESS subtypes ---
  it('INGRESS + env_read => environment', () => {
    expect(classifyTrustBoundary('INGRESS', 'env_read')).toBe('environment');
  });

  it('INGRESS + file_read => filesystem', () => {
    expect(classifyTrustBoundary('INGRESS', 'file_read')).toBe('filesystem');
  });

  it('INGRESS + http_request => network_external', () => {
    expect(classifyTrustBoundary('INGRESS', 'http_request')).toBe('network_external');
  });

  it('INGRESS + framework_handler => network_external', () => {
    expect(classifyTrustBoundary('INGRESS', 'framework_handler')).toBe('network_external');
  });

  // --- STORAGE subtypes ---
  it('STORAGE + db_read => storage', () => {
    expect(classifyTrustBoundary('STORAGE', 'db_read')).toBe('storage');
  });

  it('STORAGE + file_write => filesystem', () => {
    expect(classifyTrustBoundary('STORAGE', 'file_write')).toBe('filesystem');
  });

  it('STORAGE + db_write => storage', () => {
    expect(classifyTrustBoundary('STORAGE', 'db_write')).toBe('storage');
  });

  // --- EXTERNAL subtypes ---
  it('EXTERNAL + system_exec => subprocess', () => {
    expect(classifyTrustBoundary('EXTERNAL', 'system_exec')).toBe('subprocess');
  });

  it('EXTERNAL + api_call => network_external', () => {
    expect(classifyTrustBoundary('EXTERNAL', 'api_call')).toBe('network_external');
  });

  // --- EGRESS subtypes ---
  it('EGRESS + file_write => filesystem', () => {
    expect(classifyTrustBoundary('EGRESS', 'file_write')).toBe('filesystem');
  });

  it('EGRESS + http_response => network_external', () => {
    expect(classifyTrustBoundary('EGRESS', 'http_response')).toBe('network_external');
  });

  // --- Single-type boundaries ---
  it('META => app_config', () => {
    expect(classifyTrustBoundary('META', '')).toBe('app_config');
  });

  it('AUTH => auth', () => {
    expect(classifyTrustBoundary('AUTH', '')).toBe('auth');
  });

  it('RESOURCE => subprocess', () => {
    expect(classifyTrustBoundary('RESOURCE', '')).toBe('subprocess');
  });

  // --- Non-boundary types return empty string ---
  it('STRUCTURAL => empty string', () => {
    expect(classifyTrustBoundary('STRUCTURAL', '')).toBe('');
  });

  it('CONTROL => empty string', () => {
    expect(classifyTrustBoundary('CONTROL', '')).toBe('');
  });

  it('TRANSFORM => empty string', () => {
    expect(classifyTrustBoundary('TRANSFORM', '')).toBe('');
  });
});
