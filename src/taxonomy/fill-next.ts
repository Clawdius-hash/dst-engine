#!/usr/bin/env npx tsx
/**
 * DST CWE Fill — picks the next empty slot and prints instructions.
 *
 * This is the script the cron job calls. It:
 *   1. Finds the next empty/implemented-but-unfilled slot
 *   2. Prints the CWE number and MITRE URL
 *   3. The calling AI agent reads MITRE, fills the JSON, writes it back
 *
 * Run: npx tsx src/services/dst/taxonomy/fill-next.ts
 *
 * The agent running this should:
 *   1. Run this script to get the next CWE to fill
 *   2. Fetch the MITRE page for that CWE
 *   3. Fill the JSON according to SCHEMA.md
 *   4. Write the file back
 *   5. Run this script again (or let the cron loop handle it)
 */

import { readFileSync, readdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CWE_DIR = join(__dirname, 'cwes');

// Priority order: implemented (needs field fill) > empty (needs everything)
const files = readdirSync(CWE_DIR)
  .filter(f => f.endsWith('.json'))
  .sort((a, b) => {
    const numA = parseInt(a.replace('cwe-', '').replace('.json', ''));
    const numB = parseInt(b.replace('cwe-', '').replace('.json', ''));
    return numA - numB;
  });

// Find next slot that needs work
let nextImplemented: string | null = null;
let nextEmpty: string | null = null;

const stats = { empty: 0, implemented_unfilled: 0, filled: 0, needs_review: 0 };

for (const file of files) {
  const data = JSON.parse(readFileSync(join(CWE_DIR, file), 'utf-8'));

  if (data.status === 'empty') {
    stats.empty++;
    if (!nextEmpty) nextEmpty = file;
  } else if (data.status === 'implemented' && !data.name) {
    stats.implemented_unfilled++;
    if (!nextImplemented) nextImplemented = file;
  } else if (data.status === 'filled' || (data.status === 'implemented' && data.name)) {
    stats.filled++;
  } else if (data.status === 'needs_review') {
    stats.needs_review++;
  }
}

const next = nextImplemented || nextEmpty;

console.log('═══════════════════════════════════════════════════════════════');
console.log('  DST CWE FILL STATUS');
console.log('═══════════════════════════════════════════════════════════════');
console.log(`  Filled:              ${stats.filled}`);
console.log(`  Implemented unfilled: ${stats.implemented_unfilled}`);
console.log(`  Empty:               ${stats.empty}`);
console.log(`  Needs review:        ${stats.needs_review}`);
console.log(`  Total:               ${files.length}`);
console.log('═══════════════════════════════════════════════════════════════');

if (next) {
  const data = JSON.parse(readFileSync(join(CWE_DIR, next), 'utf-8'));
  const num = next.replace('cwe-', '').replace('.json', '');
  console.log('');
  console.log(`NEXT: ${data.id}`);
  console.log(`FILE: ${join(CWE_DIR, next)}`);
  console.log(`URL:  https://cwe.mitre.org/data/definitions/${num}.html`);
  console.log(`TYPE: ${data.status === 'implemented' ? 'Has DST logic — fill metadata fields' : 'New — fill everything'}`);
  console.log('');
  console.log('INSTRUCTIONS FOR AGENT:');
  console.log(`  1. Fetch https://cwe.mitre.org/data/definitions/${num}.html`);
  console.log(`  2. Read SCHEMA.md for the JSON format`);
  console.log(`  3. Fill ${join(CWE_DIR, next)}`);
  console.log(`  4. Set status to "filled" (or "needs_review" if uncertain)`);
} else {
  console.log('');
  console.log('ALL SLOTS FILLED. Taxonomy complete.');
}
