
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';


interface CWEPlatformEntry {
  languages: string[];
  language_classes: string[];
  technologies: string[];
  technology_classes: string[];
}


let _cwePlatformData: Record<string, CWEPlatformEntry> | null = null;

function getCWEPlatformData(): Record<string, CWEPlatformEntry> {
  if (_cwePlatformData) return _cwePlatformData;
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const jsonPath = path.join(__dirname, 'cwe-platforms.json');
    const raw = fs.readFileSync(jsonPath, 'utf-8');
    _cwePlatformData = JSON.parse(raw) as Record<string, CWEPlatformEntry>;
  } catch {
    _cwePlatformData = {};
  }
  return _cwePlatformData;
}


const CWE_PLATFORM_TAGS: Record<string, string[]> = {
  'CWE-422': ['windows-kernel'],
  'CWE-782': ['windows-kernel'],
  'CWE-781': ['windows-kernel'],

  'CWE-40':  ['windows'],
  'CWE-39':  ['windows'],
  'CWE-58':  ['windows'],
  'CWE-64':  ['windows'],
  'CWE-65':  ['windows'],
  'CWE-67':  ['windows'],
  'CWE-69':  ['windows'],

  'CWE-925': ['android'],
  'CWE-926': ['android'],

  'CWE-11':  ['dotnet'],
  'CWE-12':  ['dotnet'],
  'CWE-13':  ['dotnet'],
  'CWE-520': ['dotnet'],
  'CWE-554': ['dotnet'],
  'CWE-556': ['dotnet'],

  'CWE-5':   ['jvm'],
  'CWE-6':   ['jvm'],
  'CWE-7':   ['jvm'],
  'CWE-8':   ['jvm'],
  'CWE-9':   ['jvm'],
  'CWE-102': ['jvm'],
  'CWE-103': ['jvm'],
  'CWE-104': ['jvm'],
  'CWE-105': ['jvm'],
  'CWE-106': ['jvm'],
  'CWE-107': ['jvm'],
  'CWE-108': ['jvm'],
  'CWE-109': ['jvm'],
  'CWE-110': ['jvm'],
  'CWE-111': ['jvm'],
  'CWE-245': ['jvm'],
  'CWE-246': ['jvm'],
  'CWE-382': ['jvm'],
  'CWE-383': ['jvm'],
  'CWE-555': ['jvm'],
  'CWE-574': ['jvm'],
  'CWE-575': ['jvm'],
  'CWE-576': ['jvm'],
  'CWE-577': ['jvm'],
  'CWE-578': ['jvm'],
  'CWE-579': ['jvm'],
  'CWE-594': ['jvm'],
  'CWE-600': ['jvm'],
  'CWE-608': ['jvm'],
  'CWE-536': ['jvm'],

  'CWE-618': ['windows', 'activex'],
  'CWE-623': ['windows', 'activex'],

  'CWE-566': ['jvm', 'web', 'node', 'scripting', 'system', 'dotnet'],
};

const LANGUAGE_PLATFORMS: Record<string, string[]> = {
  'javascript':  ['web', 'node'],
  'typescript':  ['web', 'node'],
  'python':      ['web', 'scripting', 'system'],
  'ruby':        ['web', 'scripting'],
  'php':         ['web'],
  'go':          ['web', 'system', 'cloud'],
  'java':        ['jvm', 'android', 'web'],
  'kotlin':      ['jvm', 'android', 'web'],
  'csharp':      ['dotnet', 'windows', 'web'],
  'swift':       ['ios', 'macos', 'web'],
  'rust':        ['system', 'web'],
  'c':           ['system', 'windows', 'windows-kernel'],
  'cpp':         ['system', 'windows', 'windows-kernel'],
  'shell':       ['system'],
};


const DST_TO_MITRE_LANG: Record<string, string[]> = {
  'javascript':  ['JavaScript'],
  'typescript':  ['JavaScript', 'TypeScript'],
  'python':      ['Python'],
  'ruby':        ['Ruby'],
  'php':         ['PHP'],
  'go':          ['Go'],
  'java':        ['Java'],
  'kotlin':      ['Kotlin', 'Java'],
  'csharp':      ['C#', 'ASP.NET', 'VB.NET'],
  'swift':       ['Swift'],
  'rust':        ['Rust'],
  'c':           ['C'],
  'cpp':         ['C', 'C++'],
  'shell':       ['Shell'],
};


/**
 * Determine whether a CWE should be skipped for a given language.
 *
 * Two-tier check:
 * 1. For CWEs in CWE_PLATFORM_TAGS (the 42 platform-specific CWEs): use
 *    platform overlap. Skip only when the CWE's platform tags have ZERO
 *    overlap with the language's platforms.
 * 2. For CWEs with MITRE language data (cwe-platforms.json): if MITRE lists
 *    specific named languages (not just "Not Language-Specific"), skip if
 *    the scan language is not in that list.
 *
 * Returns true if the CWE should be SKIPPED (not checked) for this language.
 */
export function shouldSkipCWE(cweId: string, language: string): boolean {
  const platformTags = CWE_PLATFORM_TAGS[cweId];
  if (platformTags) {
    const langPlatforms = LANGUAGE_PLATFORMS[language];
    if (!langPlatforms) return false;

    const hasOverlap = platformTags.some(p => langPlatforms.includes(p));
    return !hasOverlap;
  }

  const mitreData = getCWEPlatformData();
  const mitreEntry = mitreData[cweId];
  if (!mitreEntry) return false;

  if (mitreEntry.language_classes.includes('Not Language-Specific')) return false;

  const namedLanguages = mitreEntry.languages;
  if (namedLanguages.length > 0) {
    const myMitreNames = DST_TO_MITRE_LANG[language];
    if (!myMitreNames) return false;

    const matches = namedLanguages.some(l => myMitreNames.includes(l));
    return !matches;
  }

  return false;
}

/**
 * Filter a list of CWE IDs to only those applicable to the given language.
 * This is the drop-in replacement for the old skipPlatform gate in verifyAll().
 */
export function filterCWEsForLanguage(cwes: string[], language: string | undefined): string[] {
  if (!language) return cwes;
  return cwes.filter(cwe => !shouldSkipCWE(cwe, language));
}


export { CWE_PLATFORM_TAGS, LANGUAGE_PLATFORMS, DST_TO_MITRE_LANG };
export type { CWEPlatformEntry };
