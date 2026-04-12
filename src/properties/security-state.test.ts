import { describe, it, expect } from 'vitest';
import {
  SecurityState,
  createUntrustedState,
  createTrustedState,
  applyNeutralizer,
  isStateValidForSink,
} from './security-state.js';
import { isNeutralizingSubtype, getNeutralizedDomains } from './neutralizers.js';

describe('SecurityState', () => {
  it('createUntrustedState has all flags false', () => {
    const state = createUntrustedState();
    expect(state.sql_safe).toBe(false);
    expect(state.xss_safe).toBe(false);
    expect(state.shell_safe).toBe(false);
    expect(state.path_safe).toBe(false);
  });

  it('createTrustedState has all flags true', () => {
    const state = createTrustedState();
    expect(state.sql_safe).toBe(true);
    expect(state.xss_safe).toBe(true);
    expect(state.shell_safe).toBe(true);
    expect(state.path_safe).toBe(true);
  });

  it('applyNeutralizer sets domain-specific flags', () => {
    const state = createUntrustedState();
    const updated = applyNeutralizer(state, 'parameterize');
    expect(updated.sql_safe).toBe(true);
    expect(updated.xss_safe).toBe(false);
    expect(updated.shell_safe).toBe(false);
  });

  it('applyNeutralizer for encode sets xss_safe, log_safe, ssti_safe', () => {
    const state = createUntrustedState();
    const updated = applyNeutralizer(state, 'encode');
    expect(updated.xss_safe).toBe(true);
    expect(updated.log_safe).toBe(true);
    expect(updated.ssti_safe).toBe(true);
    expect(updated.sql_safe).toBe(false);
  });

  it('applyNeutralizer for hash marks all domains safe', () => {
    const state = createUntrustedState();
    const updated = applyNeutralizer(state, 'hash');
    expect(updated.sql_safe).toBe(true);
    expect(updated.xss_safe).toBe(true);
    expect(updated.shell_safe).toBe(true);
  });

  it('stacking neutralizers accumulates flags', () => {
    let state = createUntrustedState();
    state = applyNeutralizer(state, 'encode');       // xss_safe, log_safe, ssti_safe
    state = applyNeutralizer(state, 'parameterize'); // sql_safe, ldap_safe, xpath_safe
    expect(state.xss_safe).toBe(true);
    expect(state.sql_safe).toBe(true);
    expect(state.ldap_safe).toBe(true);
    expect(state.shell_safe).toBe(false);
  });

  it('isStateValidForSink checks correct domain', () => {
    const state = createUntrustedState();
    expect(isStateValidForSink(state, 'sql_query')).toBe(false);

    const safe = applyNeutralizer(state, 'parameterize');
    expect(isStateValidForSink(safe, 'sql_query')).toBe(true);
    expect(isStateValidForSink(safe, 'http_response')).toBe(false);
  });

  it('domain-aware sanitize subtypes apply to correct domain', () => {
    const state = createUntrustedState();
    const htmlSafe = applyNeutralizer(state, 'sanitize_html');
    expect(htmlSafe.xss_safe).toBe(true);
    expect(htmlSafe.sql_safe).toBe(false);

    const sqlSafe = applyNeutralizer(state, 'sanitize_sql');
    expect(sqlSafe.sql_safe).toBe(true);
    expect(sqlSafe.xss_safe).toBe(false);
  });
});

describe('SecurityState population in DataFlow', () => {
  it('INGRESS nodes get untrusted security_state on data_out', async () => {
    const { createNode, createNeuralMap, resetSequenceHard } = await import('../types.js');
    resetSequenceHard();
    const ingress = createNode({
      node_type: 'INGRESS',
      node_subtype: 'http_request',
      data_out: [{ name: 'input', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' as const }],
    });
    const map = createNeuralMap('test.js', '');
    map.nodes = [ingress];

    const { initializeSecurityState } = await import('../mapper.js');
    initializeSecurityState(map);

    expect(ingress.data_out[0].security_state).toBeDefined();
    expect(ingress.data_out[0].security_state!.sql_safe).toBe(false);
    expect(ingress.data_out[0].security_state!.xss_safe).toBe(false);
  });

  it('TRANSFORM/sanitize nodes get neutralized security_state on data_out', async () => {
    const { createNode, createNeuralMap, resetSequenceHard } = await import('../types.js');
    resetSequenceHard();
    const transform = createNode({
      node_type: 'TRANSFORM',
      node_subtype: 'sanitize',
      data_out: [{ name: 'clean', source: '', data_type: 'string', tainted: false, sensitivity: 'NONE' as const }],
    });
    const map = createNeuralMap('test.js', '');
    map.nodes = [transform];

    const { initializeSecurityState } = await import('../mapper.js');
    initializeSecurityState(map);

    const state = transform.data_out[0].security_state!;
    // sanitize (generic) marks xss_safe, shell_safe, ssti_safe, log_safe
    // but NOT sql_safe (SQL needs parameterization)
    expect(state.xss_safe).toBe(true);
    expect(state.shell_safe).toBe(true);
  });

  it('TRANSFORM/sanitize_html sets only xss_safe', async () => {
    const { createNode, createNeuralMap, resetSequenceHard } = await import('../types.js');
    resetSequenceHard();
    const transform = createNode({
      node_type: 'TRANSFORM',
      node_subtype: 'sanitize_html',
      data_out: [{ name: 'escaped', source: '', data_type: 'string', tainted: false, sensitivity: 'NONE' as const }],
    });
    const map = createNeuralMap('test.js', '');
    map.nodes = [transform];

    const { initializeSecurityState } = await import('../mapper.js');
    initializeSecurityState(map);

    const state = transform.data_out[0].security_state!;
    expect(state.xss_safe).toBe(true);
    expect(state.sql_safe).toBe(false);
  });
});

describe('neutralizers', () => {
  it('isNeutralizingSubtype matches exact neutralizers', () => {
    expect(isNeutralizingSubtype('sanitize')).toBe(true);
    expect(isNeutralizingSubtype('encrypt')).toBe(true);
    expect(isNeutralizingSubtype('parameterize')).toBe(true);
    expect(isNeutralizingSubtype('prepared_statement')).toBe(true);
  });

  it('isNeutralizingSubtype matches domain-aware variants', () => {
    expect(isNeutralizingSubtype('sanitize_html')).toBe(true);
    expect(isNeutralizingSubtype('sanitize_sql')).toBe(true);
    expect(isNeutralizingSubtype('sanitize_shell')).toBe(true);
    expect(isNeutralizingSubtype('encode_url')).toBe(true);
  });

  it('isNeutralizingSubtype rejects non-neutralizers', () => {
    expect(isNeutralizingSubtype('format')).toBe(false);
    expect(isNeutralizingSubtype('parse')).toBe(false);
    expect(isNeutralizingSubtype('serialize')).toBe(false);
    expect(isNeutralizingSubtype('template_string')).toBe(false);
    expect(isNeutralizingSubtype('deprecated_crypto')).toBe(false);
  });

  it('getNeutralizedDomains returns correct domains for each subtype', () => {
    // parameterize: sql + ldap + xpath
    expect(getNeutralizedDomains('parameterize')).toContain('sql_safe');
    expect(getNeutralizedDomains('parameterize')).toContain('ldap_safe');
    expect(getNeutralizedDomains('parameterize')).toContain('xpath_safe');
    expect(getNeutralizedDomains('parameterize')).not.toContain('xss_safe');
    // encode: xss + log + ssti
    expect(getNeutralizedDomains('encode')).toContain('xss_safe');
    expect(getNeutralizedDomains('encode')).not.toContain('sql_safe');
    // sanitize (generic): NOT sql_safe
    expect(getNeutralizedDomains('sanitize')).toContain('xss_safe');
    expect(getNeutralizedDomains('sanitize')).toContain('shell_safe');
    expect(getNeutralizedDomains('sanitize')).not.toContain('sql_safe');
    // sanitize_html: only xss_safe
    expect(getNeutralizedDomains('sanitize_html')).toContain('xss_safe');
    expect(getNeutralizedDomains('sanitize_html')).not.toContain('sql_safe');
    // encrypt: NOT deserialize_safe
    expect(getNeutralizedDomains('encrypt')).toContain('sql_safe');
    expect(getNeutralizedDomains('encrypt')).not.toContain('deserialize_safe');
    // validate: path + redirect only
    expect(getNeutralizedDomains('validate')).toContain('path_safe');
    expect(getNeutralizedDomains('validate')).toContain('redirect_safe');
    expect(getNeutralizedDomains('validate')).not.toContain('xxe_safe');
    expect(getNeutralizedDomains('validate')).not.toContain('deserialize_safe');
  });
});
