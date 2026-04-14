import { describe, it, expect } from 'vitest';
import type { ParameterRole, ParameterUsage } from './parameterRole.js';
import { createEmptyUsage } from './parameterRole.js';

describe('ParameterRole types', () => {
  it('ParameterRole has expected values', () => {
    const roles: ParameterRole[] = ['input', 'output', 'continuation', 'data', 'unknown'];
    expect(roles).toHaveLength(5);
  });

  it('ParameterUsage tracks property reads and method calls', () => {
    const usage: ParameterUsage = {
      name: 'req',
      propertiesRead: new Set(['body', 'headers']),
      propertiesWritten: new Set(),
      methodsCalled: new Set(),
      invokedAsFunction: false,
      passedAsArgument: false,
    };
    expect(usage.propertiesRead.has('body')).toBe(true);
    expect(usage.propertiesRead.size).toBe(2);
  });

  it('createEmptyUsage initializes all fields', () => {
    const usage = createEmptyUsage('test');
    expect(usage.name).toBe('test');
    expect(usage.propertiesRead.size).toBe(0);
    expect(usage.propertiesWritten.size).toBe(0);
    expect(usage.methodsCalled.size).toBe(0);
    expect(usage.invokedAsFunction).toBe(false);
    expect(usage.passedAsArgument).toBe(false);
  });
});
