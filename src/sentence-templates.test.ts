import { describe, it, expect } from 'vitest';
import { SENTENCE_TEMPLATES, fillTemplate } from './sentence-templates.js';
import { generateSentence, getTemplateKey } from './sentence-generator.js';

// ─── fillTemplate ────────────────────────────────────────────────────────────

describe('fillTemplate', () => {
  it('produces the correct string for a known template', () => {
    const result = fillTemplate('executes-query', {
      subject: 'stmt',
      query_type: 'SQL',
      variables: 'userId',
      context: 'TAINTED -- user input',
    });
    expect(result).toBe(
      'stmt executes SQL query containing userId, TAINTED -- user input',
    );
  });

  it('returns a fallback string for an unknown template key', () => {
    const slots = { foo: 'bar' };
    const result = fillTemplate('does-not-exist', slots);
    expect(result).toMatch(/\[unknown-template:does-not-exist\]/);
    expect(result).toContain(JSON.stringify(slots));
  });

  it('leaves unknown slot placeholders intact', () => {
    // Template has {subject}, {method}, {object}, {args}, {context}
    // We omit {args} — the placeholder should survive verbatim.
    const result = fillTemplate('calls-method', {
      subject: 'obj',
      method: 'execute',
      object: 'db',
      context: 'SINK',
      // args intentionally omitted
    });
    expect(result).toContain('{args}');
    expect(result).toContain('obj');
    expect(result).toContain('execute');
  });
});

// ─── generateSentence ────────────────────────────────────────────────────────

describe('generateSentence', () => {
  it('returns a SemanticSentence with the correct shape', () => {
    const slots = {
      subject: 'req',
      data_type: 'string',
      source: 'HTTP header',
      context: 'TAINTED -- user-controlled',
    };
    const sentence = generateSentence(
      'retrieves-from-source',
      slots,
      42,
      'node_1_1',
      'TAINTED',
    );

    expect(sentence.templateKey).toBe('retrieves-from-source');
    expect(sentence.slots).toStrictEqual(slots);
    expect(sentence.lineNumber).toBe(42);
    expect(sentence.nodeId).toBe('node_1_1');
    expect(sentence.taintClass).toBe('TAINTED');
    expect(sentence.text).toBe(
      'req receives string from HTTP header, TAINTED -- user-controlled',
    );
  });
});

// ─── getTemplateKey ──────────────────────────────────────────────────────────

describe('getTemplateKey', () => {
  it('returns the correct template for a known nodeType and subtype', () => {
    expect(getTemplateKey('INGRESS', 'http_param')).toBe('retrieves-from-source');
    expect(getTemplateKey('STORAGE', 'sql_query')).toBe('executes-query');
    expect(getTemplateKey('TRANSFORM', 'string_concat')).toBe('string-concatenation');
    expect(getTemplateKey('CONTROL', 'branch')).toBe('gate-conditional');
    expect(getTemplateKey('CONTROL', 'loop')).toBe('iterates-over');
  });

  it('returns the _default template for an unknown subtype within a known nodeType', () => {
    expect(getTemplateKey('INGRESS', 'totally-unknown-subtype')).toBe('retrieves-from-source');
    expect(getTemplateKey('STORAGE', 'totally-unknown-subtype')).toBe('calls-method');
    expect(getTemplateKey('CONTROL', 'totally-unknown-subtype')).toBe('gate-conditional');
  });

  it('returns the fallback "calls-method" for a completely unknown nodeType', () => {
    expect(getTemplateKey('UNKNOWN_TYPE', 'any-subtype')).toBe('calls-method');
    expect(getTemplateKey('', '')).toBe('calls-method');
  });
});
