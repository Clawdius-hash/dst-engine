#!/usr/bin/env npx tsx
/**
 * Generates 933 empty CWE slot files in cwes/
 * Run once: npx tsx src/services/dst/taxonomy/scaffold.ts
 */

import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CWE_DIR = join(__dirname, 'cwes');
const MANIFEST = JSON.parse(readFileSync(join(__dirname, 'manifest.json'), 'utf-8'));

if (!existsSync(CWE_DIR)) mkdirSync(CWE_DIR, { recursive: true });

const implemented = new Set(MANIFEST.implemented_cwes);
let created = 0;
let skipped = 0;

for (let i = 1; i <= 933; i++) {
  const id = `CWE-${i}`;
  const file = join(CWE_DIR, `cwe-${i}.json`);

  if (existsSync(file)) {
    // Don't overwrite existing filled slots
    const existing = JSON.parse(readFileSync(file, 'utf-8'));
    if (existing.status !== 'empty') {
      skipped++;
      continue;
    }
  }

  const slot: Record<string, unknown> = { id, status: 'empty' };

  if (implemented.has(id)) {
    slot.status = 'implemented';
    slot.note = 'Already has detection logic in DST verifier/engine — fill remaining fields';
  }

  writeFileSync(file, JSON.stringify(slot, null, 2) + '\n');
  created++;
}

console.log(`Scaffold complete: ${created} slots created, ${skipped} existing slots preserved`);
console.log(`Directory: ${CWE_DIR}`);
