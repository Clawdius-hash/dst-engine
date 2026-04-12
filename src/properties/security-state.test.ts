import { describe, it, expect, beforeEach } from 'vitest';
import {
  SecurityState,
  createUntrustedState,
  createTrustedState,
  applyNeutralizer,
  isStateValidForSink,
} from './security-state.js';
import { isNeutralizingSubtype, getNeutralizedDomains } from './neutralizers.js';
import { stateVsRequirement } from './state-vs-requirement.js';
import type { PropertyContext } from './types.js';

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

const ctx: PropertyContext = {
  language: 'javascript',
  hasStory: true,
  isLibrary: false,
  pedantic: false,
};

describe('state-vs-requirement property', () => {
  let createNode: typeof import('../types.js').createNode;
  let createNeuralMap: typeof import('../types.js').createNeuralMap;
  let resetSequenceHard: typeof import('../types.js').resetSequenceHard;

  beforeEach(async () => {
    const types = await import('../types.js');
    createNode = types.createNode;
    createNeuralMap = types.createNeuralMap;
    resetSequenceHard = types.resetSequenceHard;
    resetSequenceHard();
  });

  it('detects UNTRUSTED data reaching sql_query sink', () => {
    const map = createNeuralMap('test.js', '');
    const ingress = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request',
      label: 'req.body',
      data_out: [{ name: 'input', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' as const,
                   security_state: createUntrustedState() }],
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW' as const, conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1', node_type: 'STORAGE', node_subtype: 'sql_query',
      label: 'db.query',
      data_in: [{ name: 'input', source: ingress.id, data_type: 'string', tainted: true, sensitivity: 'NONE' as const,
                  security_state: createUntrustedState() }],
    });
    map.nodes = [ingress, sink];
    map.story = [
      { text: 'input receives string from req.body, tainted', templateKey: 'retrieves-from-source',
        slots: { subject: 'input', data_type: 'string', source: 'req.body', context: '' },
        lineNumber: 1, nodeId: ingress.id, taintClass: 'TAINTED' as const },
      { text: 'db.query executes sql_query containing input, sink', templateKey: 'executes-query',
        slots: { subject: 'db', query_type: 'sql', variables: 'input', context: '' },
        lineNumber: 5, nodeId: sink.id, taintClass: 'SINK' as const },
    ];

    const result = stateVsRequirement.verify(map, ctx);
    expect(result.holds).toBe(false);
    expect(result.violations.length).toBeGreaterThanOrEqual(1);
    expect(result.violations[0].sinkSubtype).toBe('sql_query');
  });

  it('passes when parameterize neutralizes for sql_query', () => {
    const map = createNeuralMap('test.js', '');
    const ingress = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request',
      data_out: [{ name: 'input', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' as const,
                   security_state: createUntrustedState() }],
      edges: [{ target: 'param_1', edge_type: 'DATA_FLOW' as const, conditional: false, async: false }],
    });
    const param = createNode({
      id: 'param_1', node_type: 'TRANSFORM', node_subtype: 'parameterize',
      data_out: [{ name: 'input', source: '', data_type: 'string', tainted: false, sensitivity: 'NONE' as const }],
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW' as const, conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1', node_type: 'STORAGE', node_subtype: 'sql_query',
    });
    map.nodes = [ingress, param, sink];
    map.story = [
      { text: 'input receives string, tainted', templateKey: 'retrieves-from-source',
        slots: { subject: 'input' }, lineNumber: 1, nodeId: ingress.id, taintClass: 'TAINTED' as const },
      { text: 'input parameterized', templateKey: 'parameter-binding',
        slots: { subject: 'input', variable: 'input' }, lineNumber: 3, nodeId: param.id, taintClass: 'TRANSFORM' as const },
      { text: 'db.query executes sql_query', templateKey: 'executes-query',
        slots: { subject: 'db', variables: 'input' }, lineNumber: 5, nodeId: sink.id, taintClass: 'SINK' as const },
    ];

    const result = stateVsRequirement.verify(map, ctx);
    expect(result.holds).toBe(true);
  });

  it('detects htmlEncode does NOT satisfy sql_query sink', () => {
    const map = createNeuralMap('test.js', '');
    const ingress = createNode({
      node_type: 'INGRESS', node_subtype: 'http_request',
      data_out: [{ name: 'input', source: '', data_type: 'string', tainted: true, sensitivity: 'NONE' as const,
                   security_state: createUntrustedState() }],
      edges: [{ target: 'enc_1', edge_type: 'DATA_FLOW' as const, conditional: false, async: false }],
    });
    const enc = createNode({
      id: 'enc_1', node_type: 'TRANSFORM', node_subtype: 'sanitize_html',
      edges: [{ target: 'sink_1', edge_type: 'DATA_FLOW' as const, conditional: false, async: false }],
    });
    const sink = createNode({
      id: 'sink_1', node_type: 'STORAGE', node_subtype: 'sql_query',
    });
    map.nodes = [ingress, enc, sink];
    map.story = [
      { text: 'input receives string, tainted', templateKey: 'retrieves-from-source',
        slots: { subject: 'input' }, lineNumber: 1, nodeId: ingress.id, taintClass: 'TAINTED' as const },
      { text: 'input sanitized for HTML', templateKey: 'calls-method',
        slots: { subject: 'input', method: 'htmlEscape' }, lineNumber: 3, nodeId: enc.id, taintClass: 'TRANSFORM' as const },
      { text: 'db.query executes sql_query', templateKey: 'executes-query',
        slots: { subject: 'db', variables: 'input' }, lineNumber: 5, nodeId: sink.id, taintClass: 'SINK' as const },
    ];

    const result = stateVsRequirement.verify(map, ctx);
    expect(result.holds).toBe(false);
    expect(result.violations[0].sinkSubtype).toBe('sql_query');
  });

  it('returns no violations when no story exists', () => {
    const map = createNeuralMap('test.js', '');
    map.nodes = [];

    const noStoryCtx = { ...ctx, hasStory: false };
    const result = stateVsRequirement.verify(map, noStoryCtx);
    expect(result.holds).toBe(true);
    expect(result.violations).toHaveLength(0);
  });
});
