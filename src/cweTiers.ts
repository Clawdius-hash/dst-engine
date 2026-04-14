import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export type CWETier = 'security' | 'quality';

/**
 * Categories that represent genuine security vulnerabilities.
 * Everything else (reliability, error_handling, concurrency, api, logging)
 * is classified as 'quality'.
 */
const SECURITY_CATEGORIES = new Set([
  'injection',
  'authentication',
  'authorization',
  'cryptography',
  'data_protection',
  'file_handling',
  'input_output',   // SSRF, open redirect, unvalidated redirects
  'memory',         // buffer overflows, use-after-free, etc.
]);

let tierMap: Map<string, CWETier> | null = null;

export function loadCWETiers(): Map<string, CWETier> {
  if (tierMap) return tierMap;
  tierMap = new Map();
  const taxonomyDir = path.resolve(__dirname, 'taxonomy/cwes');
  try {
    const files = fs.readdirSync(taxonomyDir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(taxonomyDir, file), 'utf8'));
        const cweId = data.id as string;
        const category = data.category as string;
        const tier: CWETier = SECURITY_CATEGORIES.has(category) ? 'security' : 'quality';
        tierMap.set(cweId, tier);
      } catch { /* skip malformed */ }
    }
  } catch { /* taxonomy not found */ }
  return tierMap;
}

export function getCWETier(cweId: string): CWETier {
  const map = loadCWETiers();
  return map.get(cweId) ?? 'security';
}

export function isSecurityCWE(cweId: string): boolean {
  return getCWETier(cweId) === 'security';
}
