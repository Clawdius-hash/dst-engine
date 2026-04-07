/**
 * Language Registry — maps file extensions to language pattern modules.
 *
 * Each module exports:
 *   - lookupCallee(calleeChain: string[]): CalleePattern | null
 *   - sinkPatterns: Record<string, RegExp>
 *   - safePatterns: Record<string, RegExp>
 *   - getPatternCount(): number
 */

import type { CalleePattern } from '../calleePatterns.js';

export type { CalleePattern };

export interface LanguageModule {
  lookupCallee: (calleeChain: string[]) => CalleePattern | null;
  sinkPatterns: Record<string, RegExp>;
  safePatterns: Record<string, RegExp>;
  getPatternCount: () => number;
}

// Lazy-loaded language modules to avoid importing everything upfront.
// Each entry maps file extension(s) to the module path.

const EXTENSION_MAP: Record<string, () => Promise<LanguageModule>> = {
  // JavaScript
  '.js':    () => import('./javascript.js'),
  '.mjs':   () => import('./javascript.js'),
  '.cjs':   () => import('./javascript.js'),
  '.jsx':   () => import('./javascript.js'),

  // TypeScript (extends JS patterns + TS-ecosystem additions)
  '.ts':    () => import('./typescript.js'),
  '.tsx':   () => import('./typescript.js'),
  '.mts':   () => import('./typescript.js'),
  '.cts':   () => import('./typescript.js'),

  // Python
  '.py':    () => import('./python.js'),
  '.pyw':   () => import('./python.js'),
  '.pyi':   () => import('./python.js'),

  // Go
  '.go':    () => import('./go.js'),

  // Ruby
  '.rb':    () => import('./ruby.js'),
  '.rake':  () => import('./ruby.js'),
  '.gemspec': () => import('./ruby.js'),

  // Shell
  '.sh':    () => import('./shell.js'),
  '.bash':  () => import('./shell.js'),
  '.zsh':   () => import('./shell.js'),
  '.fish':  () => import('./shell.js'),
  '.ksh':   () => import('./shell.js'),

  // PHP
  '.php':   () => import('./php.js'),
  '.phtml': () => import('./php.js'),

  // Swift
  '.swift': () => import('./swift.js'),

  // C#
  '.cs':    () => import('./csharp.js'),
  '.csx':   () => import('./csharp.js'),

  // Rust
  '.rs':    () => import('./rust.js'),

  // C++
  '.cpp':   () => import('./cpp.js'),
  '.cc':    () => import('./cpp.js'),
  '.cxx':   () => import('./cpp.js'),
  '.c':     () => import('./cpp.js'),
  '.h':     () => import('./cpp.js'),
  '.hpp':   () => import('./cpp.js'),
  '.hxx':   () => import('./cpp.js'),

  // Kotlin
  '.kt':    () => import('./kotlin.js'),
  '.kts':   () => import('./kotlin.js'),

  // Java
  '.java':  () => import('./java.js'),

  // HTML/CSS
  '.html':  () => import('./htmlcss.js'),
  '.htm':   () => import('./htmlcss.js'),
  '.css':   () => import('./htmlcss.js'),
  '.scss':  () => import('./htmlcss.js'),
  '.sass':  () => import('./htmlcss.js'),
  '.less':  () => import('./htmlcss.js'),
  '.vue':   () => import('./htmlcss.js'),
  '.svelte':() => import('./htmlcss.js'),
};

// Module cache
const moduleCache = new Map<string, LanguageModule>();

/**
 * Get the language module for a file extension.
 * Returns null if the language is not supported.
 */
export async function getLanguageModule(extension: string): Promise<LanguageModule | null> {
  const ext = extension.startsWith('.') ? extension : `.${extension}`;

  // Check cache
  const cached = moduleCache.get(ext);
  if (cached) return cached;

  const loader = EXTENSION_MAP[ext];
  if (!loader) return null;

  const mod = await loader();
  moduleCache.set(ext, mod);
  return mod;
}

/**
 * Synchronous check: is this file extension supported?
 */
export function isLanguageSupported(extension: string): boolean {
  const ext = extension.startsWith('.') ? extension : `.${extension}`;
  return ext in EXTENSION_MAP;
}

/**
 * Get all supported file extensions.
 */
export function getSupportedExtensions(): string[] {
  return Object.keys(EXTENSION_MAP);
}

/**
 * Get the language name for a file extension (for display).
 */
export function getLanguageName(extension: string): string | null {
  const ext = extension.startsWith('.') ? extension : `.${extension}`;
  const map: Record<string, string> = {
    '.js': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.jsx': 'JavaScript',
    '.ts': 'TypeScript', '.tsx': 'TypeScript', '.mts': 'TypeScript', '.cts': 'TypeScript',
    '.py': 'Python', '.pyw': 'Python', '.pyi': 'Python',
    '.go': 'Go',
    '.rb': 'Ruby', '.rake': 'Ruby', '.gemspec': 'Ruby',
    '.sh': 'Shell', '.bash': 'Shell', '.zsh': 'Shell', '.fish': 'Shell', '.ksh': 'Shell',
    '.php': 'PHP', '.phtml': 'PHP',
    '.swift': 'Swift',
    '.cs': 'C#', '.csx': 'C#',
    '.rs': 'Rust',
    '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++', '.c': 'C', '.h': 'C/C++', '.hpp': 'C++', '.hxx': 'C++',
    '.kt': 'Kotlin', '.kts': 'Kotlin',
    '.java': 'Java',
    '.html': 'HTML', '.htm': 'HTML', '.css': 'CSS',
    '.scss': 'SCSS', '.sass': 'Sass', '.less': 'Less',
    '.vue': 'Vue', '.svelte': 'Svelte',
  };
  return map[ext] ?? null;
}
