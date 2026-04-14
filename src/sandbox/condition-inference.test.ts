import { describe, it, expect } from 'vitest';
import { parseCondition, conditionsToParams } from './condition-inference.js';

describe('parseCondition', () => {
  it('parses truthiness', () => {
    expect(parseCondition('options.enabled')).toEqual({ paramPath: ['options', 'enabled'], value: true });
  });
  it('parses equality', () => {
    expect(parseCondition("mode === 'production'")).toEqual({ paramPath: ['mode'], value: 'production' });
  });
  it('parses inequality', () => {
    expect(parseCondition("env !== 'development'")).toEqual({ paramPath: ['env'], value: true });
  });
  it('parses comparison', () => {
    expect(parseCondition('count > 0')).toEqual({ paramPath: ['count'], value: 1 });
  });
  it('parses deep property', () => {
    expect(parseCondition('context.trustHostHeader')).toEqual({ paramPath: ['context', 'trustHostHeader'], value: true });
  });
  it('returns null for complex', () => {
    expect(parseCondition('a && b')).toBeNull();
  });
});

describe('conditionsToParams', () => {
  it('builds nested param', () => {
    const r = conditionsToParams([{ paramPath: ['context', 'trustHostHeader'], value: true }], ['input', 'context']);
    expect(r).toEqual({ context: { trustHostHeader: true } });
  });
  it('merges multiple', () => {
    const r = conditionsToParams([
      { paramPath: ['opts', 'a'], value: true },
      { paramPath: ['opts', 'b'], value: 'test' },
    ], ['opts']);
    expect(r).toEqual({ opts: { a: true, b: 'test' } });
  });
  it('skips unknown params', () => {
    const r = conditionsToParams([{ paramPath: ['unknown', 'x'], value: true }], ['req']);
    expect(r).toEqual({});
  });
});
