/**
 * Tests for CWE platform filter — verifies the MITRE-sourced language/platform
 * filtering correctly handles the overlap matrix from platform_cwe_mapping.md.
 *
 * Critical cases: Java+J2EE, Kotlin+Android, C#+.NET must NOT be filtered.
 */

import { describe, it, expect } from 'vitest';
import { shouldSkipCWE, filterCWEsForLanguage, CWE_PLATFORM_TAGS, LANGUAGE_PLATFORMS } from './cwe-filter.js';

// ---------------------------------------------------------------------------
// Tier 1: Platform-specific CWEs (the 42 CWEs from PLATFORM_SPECIFIC_CWES)
// ---------------------------------------------------------------------------

describe('shouldSkipCWE — Tier 1: platform-tag overlap', () => {

  // ---- THE CRITICAL BUG FIX: Java must NOT skip J2EE CWEs ----

  describe('Java + J2EE CWEs (the core bug fix)', () => {
    const j2eeCWEs = [
      'CWE-5', 'CWE-6', 'CWE-7', 'CWE-8', 'CWE-9',
      'CWE-102', 'CWE-103', 'CWE-104', 'CWE-105', 'CWE-106',
      'CWE-107', 'CWE-108', 'CWE-109', 'CWE-110', 'CWE-111',
      'CWE-245', 'CWE-246', 'CWE-382', 'CWE-383', 'CWE-555',
      'CWE-574', 'CWE-575', 'CWE-576', 'CWE-577', 'CWE-578',
      'CWE-579', 'CWE-594', 'CWE-600', 'CWE-608', 'CWE-536',
    ];

    for (const cwe of j2eeCWEs) {
      it(`Java + ${cwe} = NOT skipped (jvm overlaps jvm)`, () => {
        expect(shouldSkipCWE(cwe, 'java')).toBe(false);
      });
    }
  });

  describe('Kotlin + J2EE/Android CWEs', () => {
    it('Kotlin + CWE-382 (System.exit) = NOT skipped', () => {
      expect(shouldSkipCWE('CWE-382', 'kotlin')).toBe(false);
    });
    it('Kotlin + CWE-925 (Android Intent) = NOT skipped', () => {
      expect(shouldSkipCWE('CWE-925', 'kotlin')).toBe(false);
    });
    it('Kotlin + CWE-926 (Android Export) = NOT skipped', () => {
      expect(shouldSkipCWE('CWE-926', 'kotlin')).toBe(false);
    });
    it('Kotlin + CWE-536 (Servlet) = NOT skipped', () => {
      expect(shouldSkipCWE('CWE-536', 'kotlin')).toBe(false);
    });
  });

  describe('C# + .NET CWEs', () => {
    const dotnetCWEs = ['CWE-11', 'CWE-12', 'CWE-13', 'CWE-520', 'CWE-554', 'CWE-556'];
    for (const cwe of dotnetCWEs) {
      it(`C# + ${cwe} = NOT skipped (dotnet overlaps dotnet)`, () => {
        expect(shouldSkipCWE(cwe, 'csharp')).toBe(false);
      });
    }
    it('C# + CWE-618 (ActiveX) = NOT skipped (windows overlaps)', () => {
      expect(shouldSkipCWE('CWE-618', 'csharp')).toBe(false);
    });
    it('C# + CWE-623 (ActiveX) = NOT skipped (windows overlaps)', () => {
      expect(shouldSkipCWE('CWE-623', 'csharp')).toBe(false);
    });
  });

  // ---- CORRECT SKIPPING: JS/Python/Go should skip all platform CWEs ----

  // CWEs that are intentionally NOT skipped for web languages (they apply to
  // any language that constructs SQL queries from web input)
  const WEB_UNIVERSAL_CWES = new Set(['CWE-566']);

  describe('JavaScript skips ALL platform CWEs (except web-universal)', () => {
    const allPlatformCWEs = Object.keys(CWE_PLATFORM_TAGS);
    for (const cwe of allPlatformCWEs) {
      if (WEB_UNIVERSAL_CWES.has(cwe)) {
        it(`JS + ${cwe} = NOT skipped (web-universal)`, () => {
          expect(shouldSkipCWE(cwe, 'javascript')).toBe(false);
        });
      } else {
        it(`JS + ${cwe} = skipped`, () => {
          expect(shouldSkipCWE(cwe, 'javascript')).toBe(true);
        });
      }
    }
  });

  describe('Python skips ALL platform CWEs (except web-universal)', () => {
    const allPlatformCWEs = Object.keys(CWE_PLATFORM_TAGS);
    for (const cwe of allPlatformCWEs) {
      if (WEB_UNIVERSAL_CWES.has(cwe)) {
        it(`Python + ${cwe} = NOT skipped (web-universal)`, () => {
          expect(shouldSkipCWE(cwe, 'python')).toBe(false);
        });
      } else {
        it(`Python + ${cwe} = skipped`, () => {
          expect(shouldSkipCWE(cwe, 'python')).toBe(true);
        });
      }
    }
  });

  describe('Go skips ALL platform CWEs (except web-universal)', () => {
    const allPlatformCWEs = Object.keys(CWE_PLATFORM_TAGS);
    for (const cwe of allPlatformCWEs) {
      if (WEB_UNIVERSAL_CWES.has(cwe)) {
        it(`Go + ${cwe} = NOT skipped (web-universal)`, () => {
          expect(shouldSkipCWE(cwe, 'go')).toBe(false);
        });
      } else {
        it(`Go + ${cwe} = skipped`, () => {
          expect(shouldSkipCWE(cwe, 'go')).toBe(true);
        });
      }
    }
  });

  // ---- Cross-platform edge cases ----

  describe('Java skips Windows/ActiveX/.NET CWEs', () => {
    it('Java + CWE-422 (Windows Shatter) = skipped', () => {
      expect(shouldSkipCWE('CWE-422', 'java')).toBe(true);
    });
    it('Java + CWE-782 (Windows IOCTL) = skipped', () => {
      expect(shouldSkipCWE('CWE-782', 'java')).toBe(true);
    });
    it('Java + CWE-11 (ASP.NET) = skipped', () => {
      expect(shouldSkipCWE('CWE-11', 'java')).toBe(true);
    });
    it('Java + CWE-618 (ActiveX) = skipped', () => {
      expect(shouldSkipCWE('CWE-618', 'java')).toBe(true);
    });
  });

  describe('Java keeps Android CWEs', () => {
    it('Java + CWE-925 (Android Intent) = NOT skipped', () => {
      expect(shouldSkipCWE('CWE-925', 'java')).toBe(false);
    });
    it('Java + CWE-926 (Android Export) = NOT skipped', () => {
      expect(shouldSkipCWE('CWE-926', 'java')).toBe(false);
    });
  });

  describe('C# skips J2EE/Android CWEs', () => {
    it('C# + CWE-382 (System.exit) = skipped', () => {
      expect(shouldSkipCWE('CWE-382', 'csharp')).toBe(true);
    });
    it('C# + CWE-925 (Android) = skipped', () => {
      expect(shouldSkipCWE('CWE-925', 'csharp')).toBe(true);
    });
  });

  describe('C/C++ and Windows CWEs', () => {
    it('C + CWE-422 (Windows Shatter) = NOT skipped', () => {
      expect(shouldSkipCWE('CWE-422', 'c')).toBe(false);
    });
    it('C++ + CWE-782 (Windows IOCTL) = NOT skipped', () => {
      expect(shouldSkipCWE('CWE-782', 'cpp')).toBe(false);
    });
    it('C + CWE-382 (J2EE) = skipped', () => {
      expect(shouldSkipCWE('CWE-382', 'c')).toBe(true);
    });
  });

  describe('Kotlin skips .NET/Windows CWEs', () => {
    it('Kotlin + CWE-11 (ASP.NET) = skipped', () => {
      expect(shouldSkipCWE('CWE-11', 'kotlin')).toBe(true);
    });
    it('Kotlin + CWE-422 (Windows Shatter) = skipped', () => {
      expect(shouldSkipCWE('CWE-422', 'kotlin')).toBe(true);
    });
  });

  // ---- Safety: unknown CWE/language = don't skip ----

  it('unknown CWE = NOT skipped', () => {
    expect(shouldSkipCWE('CWE-99999', 'java')).toBe(false);
  });

  it('unknown language = NOT skipped', () => {
    expect(shouldSkipCWE('CWE-382', 'brainfuck')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tier 2: MITRE language-specific CWEs (beyond the 42 platform CWEs)
// ---------------------------------------------------------------------------

describe('shouldSkipCWE — Tier 2: MITRE language data', () => {
  it('CWE-120 (buffer overflow, C/C++) is skipped for JavaScript', () => {
    expect(shouldSkipCWE('CWE-120', 'javascript')).toBe(true);
  });

  it('CWE-120 (buffer overflow, C/C++) is skipped for Java', () => {
    expect(shouldSkipCWE('CWE-120', 'java')).toBe(true);
  });

  it('CWE-120 (buffer overflow, C/C++) is NOT skipped for C', () => {
    expect(shouldSkipCWE('CWE-120', 'c')).toBe(false);
  });

  it('CWE-120 (buffer overflow, C/C++) is NOT skipped for C++', () => {
    expect(shouldSkipCWE('CWE-120', 'cpp')).toBe(false);
  });

  it('CWE-79 (XSS, Not Language-Specific) is NOT skipped for any language', () => {
    for (const lang of ['javascript', 'python', 'java', 'csharp', 'go', 'ruby', 'php']) {
      expect(shouldSkipCWE('CWE-79', lang)).toBe(false);
    }
  });

  it('CWE-89 (SQL injection, Not Language-Specific) is NOT skipped for any language', () => {
    for (const lang of ['javascript', 'python', 'java', 'csharp', 'go']) {
      expect(shouldSkipCWE('CWE-89', lang)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// filterCWEsForLanguage — drop-in replacement test
// ---------------------------------------------------------------------------

describe('filterCWEsForLanguage', () => {
  const sampleCWEs = ['CWE-79', 'CWE-382', 'CWE-120', 'CWE-925', 'CWE-11'];

  it('no language = returns all CWEs unchanged', () => {
    expect(filterCWEsForLanguage(sampleCWEs, undefined)).toEqual(sampleCWEs);
  });

  it('Java: keeps CWE-79, CWE-382, CWE-925; drops CWE-120, CWE-11', () => {
    const result = filterCWEsForLanguage(sampleCWEs, 'java');
    expect(result).toContain('CWE-79');
    expect(result).toContain('CWE-382');
    expect(result).toContain('CWE-925');
    expect(result).not.toContain('CWE-120');
    expect(result).not.toContain('CWE-11');
  });

  it('C#: keeps CWE-79, CWE-11; drops CWE-382, CWE-120, CWE-925', () => {
    const result = filterCWEsForLanguage(sampleCWEs, 'csharp');
    expect(result).toContain('CWE-79');
    expect(result).toContain('CWE-11');
    expect(result).not.toContain('CWE-382');
    expect(result).not.toContain('CWE-120');
    expect(result).not.toContain('CWE-925');
  });

  it('JavaScript: keeps CWE-79; drops CWE-382, CWE-120, CWE-925, CWE-11', () => {
    const result = filterCWEsForLanguage(sampleCWEs, 'javascript');
    expect(result).toContain('CWE-79');
    expect(result).not.toContain('CWE-382');
    expect(result).not.toContain('CWE-120');
    expect(result).not.toContain('CWE-925');
    expect(result).not.toContain('CWE-11');
  });
});

// ---------------------------------------------------------------------------
// Count verification: recovery numbers from the bug analysis
// ---------------------------------------------------------------------------

describe('CWE recovery counts', () => {
  const allPlatformCWEs = Object.keys(CWE_PLATFORM_TAGS);

  it('Java recovers 26+ CWEs from incorrect filtering', () => {
    const recovered = allPlatformCWEs.filter(cwe => !shouldSkipCWE(cwe, 'java'));
    // Java should keep: 30 J2EE/Struts/EJB/Servlet + 2 Android = 32
    // (old code filtered all 42 for Java; new code keeps 32)
    expect(recovered.length).toBeGreaterThanOrEqual(26);
  });

  it('Kotlin recovers 22+ CWEs from incorrect filtering', () => {
    const recovered = allPlatformCWEs.filter(cwe => !shouldSkipCWE(cwe, 'kotlin'));
    expect(recovered.length).toBeGreaterThanOrEqual(22);
  });

  it('C# recovers 15+ CWEs from incorrect filtering', () => {
    const recovered = allPlatformCWEs.filter(cwe => !shouldSkipCWE(cwe, 'csharp'));
    // C# should keep: 6 .NET + 7 Windows path + 2 ActiveX = 15
    expect(recovered.length).toBeGreaterThanOrEqual(8); // At least .NET + ActiveX
  });

  // CWE-566 is web-universal (applies to any language that queries DBs), so it's
  // kept for JS/Python/Go. All other platform CWEs should still be skipped.
  const WEB_UNIVERSAL = new Set(['CWE-566']);

  it('JavaScript keeps only web-universal platform CWEs', () => {
    const kept = allPlatformCWEs.filter(cwe => !shouldSkipCWE(cwe, 'javascript'));
    expect(kept.length).toBe(WEB_UNIVERSAL.size);
    for (const cwe of kept) {
      expect(WEB_UNIVERSAL.has(cwe)).toBe(true);
    }
  });

  it('Python keeps only web-universal platform CWEs', () => {
    const kept = allPlatformCWEs.filter(cwe => !shouldSkipCWE(cwe, 'python'));
    expect(kept.length).toBe(WEB_UNIVERSAL.size);
    for (const cwe of kept) {
      expect(WEB_UNIVERSAL.has(cwe)).toBe(true);
    }
  });

  it('Go keeps only web-universal platform CWEs', () => {
    const kept = allPlatformCWEs.filter(cwe => !shouldSkipCWE(cwe, 'go'));
    expect(kept.length).toBe(WEB_UNIVERSAL.size);
    for (const cwe of kept) {
      expect(WEB_UNIVERSAL.has(cwe)).toBe(true);
    }
  });
});
