import { describe, it, expect } from 'vitest';
import { isSecurityCWE, getCWETier, loadCWETiers } from './cweTiers.js';

describe('CWE Tiers', () => {
  it('loads tiers from taxonomy', () => {
    const map = loadCWETiers();
    expect(map.size).toBeGreaterThan(100);
  });

  it('classifies injection CWEs as security', () => {
    expect(isSecurityCWE('CWE-79')).toBe(true);   // XSS
    expect(isSecurityCWE('CWE-89')).toBe(true);   // SQLi
    expect(isSecurityCWE('CWE-78')).toBe(true);   // OS command injection
    expect(isSecurityCWE('CWE-918')).toBe(true);  // SSRF (input_output category)
  });

  it('classifies auth CWEs as security', () => {
    expect(isSecurityCWE('CWE-287')).toBe(true);  // improper auth
    expect(isSecurityCWE('CWE-352')).toBe(true);  // CSRF
  });

  it('classifies crypto CWEs as security', () => {
    expect(isSecurityCWE('CWE-327')).toBe(true);  // broken crypto
  });

  it('classifies reliability CWEs as quality', () => {
    expect(isSecurityCWE('CWE-398')).toBe(false); // code quality
  });

  it('returns security for unknown CWEs (conservative)', () => {
    expect(isSecurityCWE('CWE-99999')).toBe(true);
  });

  it('getCWETier returns tier string', () => {
    expect(getCWETier('CWE-79')).toBe('security');
    expect(getCWETier('CWE-398')).toBe('quality');
  });
});
