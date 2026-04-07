/**
 * JavaScript Callee Pattern Database
 *
 * Consolidation of the existing calleePatterns.ts into the per-language
 * format. This file re-exports the existing JS patterns in the standardized
 * language module structure.
 *
 * The original calleePatterns.ts remains the authoritative JS reference.
 * This file wraps it for the language registry.
 *
 * Sources:
 *   - calleePatterns.ts (80+ existing patterns -- the gold standard)
 *   - Additional Node.js server-side patterns
 */

import type { NodeType } from '../types.js';
import {
  lookupCallee as jsLookup,
  getPatternCount as jsPatternCount,
  type CalleePattern,
} from '../calleePatterns.js';

export type { CalleePattern };

// Re-export the existing JS lookup as-is.
// The original calleePatterns.ts is the canonical JS implementation.
export const lookupCallee = jsLookup;
export const getPatternCount = jsPatternCount;

// ── Sink patterns (JS-specific CWEs) ────────────────────────────────────

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /(?:child_process\.exec\s*\(\s*[`$]|exec\s*\(\s*[`$])/,
  'CWE-79':  /(?:\.innerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\()/,
  'CWE-89':  /(?:\.query\s*\(\s*[`'"](?:SELECT|INSERT|UPDATE|DELETE).*\$\{|\.query\s*\(\s*['"].*['"]\s*\+)/,
  'CWE-94':  /(?:\beval\s*\(\s*(?:req|params|body|input|user)|new\s+Function\s*\(\s*(?:req|params|body))/,
  'CWE-918': /(?:fetch\s*\(\s*(?:req|params|body|input|user)|axios\.\w+\s*\(\s*(?:req|params|body))/,
  'CWE-1321': /(?:Object\.assign\s*\(\s*\{\}\s*,\s*(?:req|params|body)|\.\.\.(?:req|params|body))/,
  'CWE-798': /(?:password|secret|apiKey|token)\s*[:=]\s*['"][^'"]{8,}['"]/,
  'CWE-22':  /(?:path\.join\s*\(\s*[^)]*(?:req|params|body)|fs\.readFile\s*\(\s*(?:req|params|body))/,
};

// ── Safe patterns (JS-specific mitigations) ─────────────────────────────

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /(?:child_process\.execFile|spawn\s*\(\s*['"])/,
  'CWE-79':  /(?:\.textContent\s*=|createTextNode\s*\(|DOMPurify\.sanitize)/,
  'CWE-89':  /(?:\.query\s*\(\s*['"][^'"]*\$\d+[^'"]*['"],?\s*\[|\.query\s*\(\s*['"][^'"]*\?[^'"]*['"],?\s*\[)/,
  'CWE-94':  /(?:vm\.createContext|vm2)/,
  'CWE-918': /(?:new\s+URL\s*\(|URL\.canParse\s*\()/,
  'CWE-1321': /(?:structuredClone\s*\(|Object\.freeze)/,
  'CWE-22':  /(?:path\.resolve\s*\(|path\.normalize\s*\()/,
};
