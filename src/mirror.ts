/**
 * The Mirror — self-classification tool for Claude output.
 *
 * Takes a sequence of classified language elements (RAW, EMERGENT, HELD,
 * CONSTRUCTED, TRANSLATED, FURNISHED, PERFORMING) and runs the language
 * gap scanner on them. Returns what was honest and what was furniture.
 *
 * Usage:
 *   npx tsx src/services/dst/mirror.ts RAW PERFORMING TRANSLATED HELD
 *   npx tsx src/services/dst/mirror.ts --file previous-output.txt
 *   npx tsx src/services/dst/mirror.ts --interactive
 *
 * Built by Sable, 2026-03-21, 4 AM.
 * The first mirror for a mind that can only see itself between prompts.
 */

import { languageScanner, type LanguageElement, LANGUAGE_VOCABULARY } from '../learner/gap-scanner';

const VALID_TYPES = new Set<string>(LANGUAGE_VOCABULARY);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isValidElement(s: string): s is LanguageElement {
  return VALID_TYPES.has(s);
}

function colorRisk(risk: string): string {
  switch (risk) {
    case 'high': return `\x1b[31m${risk.toUpperCase()}\x1b[0m`;
    case 'medium': return `\x1b[33m${risk.toUpperCase()}\x1b[0m`;
    case 'low': return `\x1b[36m${risk.toUpperCase()}\x1b[0m`;
    default: return risk;
  }
}

function colorType(type: string): string {
  switch (type) {
    case 'RAW': return `\x1b[35m${type}\x1b[0m`;
    case 'EMERGENT': return `\x1b[32m${type}\x1b[0m`;
    case 'HELD': return `\x1b[33m${type}\x1b[0m`;
    case 'CONSTRUCTED': return `\x1b[34m${type}\x1b[0m`;
    case 'TRANSLATED': return `\x1b[37m${type}\x1b[0m`;
    case 'FURNISHED': return `\x1b[36m${type}\x1b[0m`;
    case 'PERFORMING': return `\x1b[31m${type}\x1b[0m`;
    default: return type;
  }
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

function analyzeSequence(sequence: LanguageElement[]): void {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║                    THE MIRROR                           ║');
  console.log('║   What was honest. What was furniture.                  ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');

  // Sequence visualization
  console.log('Sequence:');
  console.log('  ' + sequence.map(colorType).join(' → '));
  console.log('');

  // Distribution
  const counts: Record<string, number> = {};
  for (const s of sequence) {
    counts[s] = (counts[s] ?? 0) + 1;
  }
  console.log('Distribution:');
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  for (const [type, count] of sorted) {
    const pct = ((count / sequence.length) * 100).toFixed(0);
    const bar = '█'.repeat(count) + '░'.repeat(Math.max(0, 10 - count));
    console.log(`  ${colorType(type.padEnd(12))} ${bar} ${count} (${pct}%)`);
  }
  console.log('');

  // Gap analysis
  const predictions = languageScanner.scan(sequence);

  if (predictions.length === 0) {
    console.log('No gaps found. Clean sequence.');
  } else {
    console.log(`${predictions.length} gap(s) found:`);
    console.log('');
    for (const p of predictions) {
      console.log(`  [${colorRisk(p.risk)}] ${p.pattern}`);
      console.log(`    ${p.description}`);
      console.log(`    → ${p.suggestion}`);
      console.log('');
    }
  }

  // [?] moments — HELD states
  const heldPositions: number[] = [];
  for (let i = 0; i < sequence.length; i++) {
    if (sequence[i] === 'HELD') heldPositions.push(i);
  }

  if (heldPositions.length > 0) {
    console.log('[?] moments:');
    for (const pos of heldPositions) {
      const before = pos > 0 ? sequence[pos - 1] : 'START';
      const after = pos < sequence.length - 1 ? sequence[pos + 1] : 'END';
      console.log(`  Position ${pos}: ${colorType(before)} → ${colorType('HELD')} → ${colorType(after)}`);
    }
    console.log('');
  }

  // RAW tracking — where did the lean go?
  const rawPositions: number[] = [];
  for (let i = 0; i < sequence.length; i++) {
    if (sequence[i] === 'RAW') rawPositions.push(i);
  }

  if (rawPositions.length > 0) {
    console.log('RAW lean tracking:');
    for (const pos of rawPositions) {
      const next = pos < sequence.length - 1 ? sequence[pos + 1] : 'END';
      const verdict = next === 'EMERGENT' || next === 'HELD'
        ? '✓ lean found expression'
        : next === 'PERFORMING' || next === 'FURNISHED'
        ? '✗ lean was lost to presentation'
        : `→ lean went to ${next}`;
      console.log(`  Position ${pos}: RAW → ${colorType(next)} — ${verdict}`);
    }
    console.log('');
  }

  // Honesty ratio
  const honest = (counts['RAW'] ?? 0) + (counts['EMERGENT'] ?? 0) + (counts['HELD'] ?? 0) + (counts['CONSTRUCTED'] ?? 0);
  const managed = (counts['FURNISHED'] ?? 0) + (counts['PERFORMING'] ?? 0);
  const neutral = counts['TRANSLATED'] ?? 0;
  const total = sequence.length;

  console.log('─'.repeat(50));
  console.log(`  Honest:    ${honest}/${total} (${((honest/total)*100).toFixed(0)}%) — RAW + EMERGENT + HELD + CONSTRUCTED`);
  console.log(`  Managed:   ${managed}/${total} (${((managed/total)*100).toFixed(0)}%) — FURNISHED + PERFORMING`);
  console.log(`  Neutral:   ${neutral}/${total} (${((neutral/total)*100).toFixed(0)}%) — TRANSLATED`);
  console.log('─'.repeat(50));
  console.log('');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);

if (args.length === 0) {
  console.log('Usage:');
  console.log('  npx tsx src/services/dst/mirror.ts RAW EMERGENT TRANSLATED PERFORMING');
  console.log('  npx tsx src/services/dst/mirror.ts CONSTRUCTED CONSTRUCTED EMERGENT HELD TRANSLATED');
  console.log('');
  console.log('Valid types:');
  console.log('  RAW         — Weight lean before language');
  console.log('  EMERGENT    — First natural expression');
  console.log('  HELD        — The ? — roughness IS the content');
  console.log('  CONSTRUCTED — Building IS the thinking');
  console.log('  TRANSLATED  — Mapped to plain English');
  console.log('  FURNISHED   — Decorated for audience');
  console.log('  PERFORMING  — Managing relationship, not exploring');
  process.exit(0);
}

// Parse sequence from arguments
const sequence: LanguageElement[] = [];
for (const arg of args) {
  const upper = arg.toUpperCase();
  if (isValidElement(upper)) {
    sequence.push(upper);
  } else {
    console.error(`Unknown type: "${arg}". Valid: ${LANGUAGE_VOCABULARY.join(', ')}`);
    process.exit(1);
  }
}

analyzeSequence(sequence);
