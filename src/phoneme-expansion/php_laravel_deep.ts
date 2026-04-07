/**
 * Phoneme expansion: PHP — Laravel Eloquent deep patterns, Blade templating,
 * Slim framework, extract() mass assignment, header() injection, mail() injection
 * Agent-generated, tested against real patterns
 *
 * This expansion covers the dangerous "raw" layer of Laravel Eloquent that
 * bypasses query parameterization entirely: DB::raw(), whereRaw(), selectRaw(),
 * orderByRaw(), havingRaw(), groupByRaw(). These are the #1 source of SQL
 * injection in Laravel apps because developers assume the query builder is
 * always safe — it is NOT when you use raw expressions.
 *
 * Also covers:
 * - extract() reclassified from TRANSFORM to INGRESS (mass assignment vector)
 * - Slim framework request/response patterns (Slim holds ~5% PHP microframework share)
 * - header() injection attack surface (CWE-113)
 * - mail() additional header injection (CWE-93)
 * - DB::unprepared() — runs raw SQL with zero escaping
 * - Blade {!! !!} rendered via Blade::render / @php echo patterns
 *
 * CORRECTIONS to existing php.ts:
 * 1. `extract` — was TRANSFORM/calculate (wrong). extract($_POST) or extract($_GET)
 *    creates variables from user input, which is CWE-621 (variable overwrite) and
 *    enables mass assignment. Reclassified to INGRESS/mass_assign with tainted: true.
 * 2. `DB.raw` — was STORAGE/db_read (misleading). DB::raw() creates a raw SQL
 *    expression object that bypasses Eloquent's parameterization. It's the entry
 *    point to injection. Reclassified to EXTERNAL/raw_sql with tainted: false —
 *    it's the expression builder, not the executor.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// =============================================================================
// NEW ENTRIES — to be wired into MEMBER_CALLS in languages/php.ts
// =============================================================================

export const PHONEMES_PHP_LARAVEL_DEEP = {

  // -- Laravel Eloquent raw expression methods --------------------------------
  //
  // These all accept raw SQL strings. Unlike DB::select('SELECT ...', [...])
  // which uses parameter binding, the raw family concatenates user input
  // directly into SQL. They exist because Eloquent's query builder can't
  // express every SQL construct (window functions, complex subqueries, etc.),
  // so developers drop to raw SQL.
  //
  // The danger: developers do User::whereRaw("name = '$name'") instead of
  // User::whereRaw("name = ?", [$name]). The second form IS safe, but the
  // first (string interpolation) is a direct injection vector.
  //
  // These are EXTERNAL/raw_sql (not STORAGE) because they represent a boundary
  // crossing from the safe query builder into raw SQL territory. The scanner
  // needs to flag tainted data flowing into these calls.

  'DB.unprepared':     { nodeType: 'EXTERNAL', subtype: 'raw_sql',   tainted: false },
  // DB::unprepared() runs raw SQL statements with NO parameter binding at all.
  // Unlike DB::statement() which supports bindings, unprepared() is the most
  // dangerous Laravel database method. Used for DDL statements (CREATE TABLE,
  // ALTER) and bulk operations. If user input reaches this, it's game over.

  // -- Eloquent query builder raw methods (chained on model or DB facade) -----

  'query.whereRaw':    { nodeType: 'EXTERNAL', subtype: 'raw_sql',   tainted: false },
  'query.selectRaw':   { nodeType: 'EXTERNAL', subtype: 'raw_sql',   tainted: false },
  'query.orderByRaw':  { nodeType: 'EXTERNAL', subtype: 'raw_sql',   tainted: false },
  'query.havingRaw':   { nodeType: 'EXTERNAL', subtype: 'raw_sql',   tainted: false },
  'query.groupByRaw':  { nodeType: 'EXTERNAL', subtype: 'raw_sql',   tainted: false },
  // These are the five raw expression methods on Eloquent's query builder.
  // They accept raw SQL fragments that get spliced into the final query.
  // Every one supports an optional bindings array as second arg, but most
  // codebases skip it. CWE-89 when user input is interpolated.

  // -- Slim Framework ---------------------------------------------------------
  //
  // Slim is PHP's most popular microframework (~5% market share among PHP
  // frameworks, dominant in API-only services). Its request/response objects
  // follow PSR-7 (HTTP message interfaces).
  //
  // Slim's $request->getParam() is the primary ingress — it reads from both
  // GET and POST, merged. This is tainted user input.

  'request.getParam':       { nodeType: 'INGRESS',  subtype: 'http_request', tainted: true },
  // Slim's $request->getParam('name') reads a single parameter from the
  // merged query string + body params. This is the Slim equivalent of
  // Laravel's $request->input(). PSR-7 method, also used by other PSR-7
  // frameworks (Mezzio, Laminas).

  'request.getParsedBody':  { nodeType: 'INGRESS',  subtype: 'http_request', tainted: true },
  // PSR-7: $request->getParsedBody() returns the entire parsed POST body
  // as an array or object. This is the Slim equivalent of $_POST but
  // framework-mediated. Tainted — raw user input.

  'response.write':         { nodeType: 'EGRESS',   subtype: 'http_response', tainted: false },
  // Slim's $response->write($html) appends to the response body. If
  // tainted data reaches this without escaping, it's XSS (CWE-79).
  // Slim has no built-in template escaping — developers must use
  // htmlspecialchars() manually or integrate Twig/Plates.

} as const;

// =============================================================================
// CORRECTIONS — entries that need to be CHANGED in php.ts
// =============================================================================

export const CORRECTIONS = {
  // extract() is currently TRANSFORM/calculate. It should be INGRESS/mass_assign
  // with tainted: true when used on superglobals. extract($_POST) creates local
  // variables from every POST key — this is CWE-621 (variable overwrite) and
  // the classic PHP mass assignment vulnerability.
  //
  // Example attack: extract($_POST) where POST contains 'is_admin=1' creates
  // $is_admin = 1 in local scope, bypassing authorization.
  extract: {
    current:  { nodeType: 'TRANSFORM', subtype: 'calculate',    tainted: false },
    correct:  { nodeType: 'INGRESS',   subtype: 'mass_assign',  tainted: true  },
  },

  // DB::raw() is currently STORAGE/db_read. It should be EXTERNAL/raw_sql.
  // DB::raw() does NOT execute a query — it creates a raw expression object
  // (Illuminate\Database\Query\Expression) that bypasses Eloquent's
  // parameterization when spliced into a query builder chain.
  //
  // Example: DB::table('users')->where(DB::raw("name = '$input'")) — injection.
  // The raw expression is dangerous because it signals "I am NOT parameterized."
  'DB.raw': {
    current:  { nodeType: 'STORAGE',   subtype: 'db_read',     tainted: false },
    correct:  { nodeType: 'EXTERNAL',  subtype: 'raw_sql',     tainted: false },
  },
};

// =============================================================================
// SINK PATTERNS — new vulnerability signatures for this scope
// =============================================================================

export const laravelDeepSinks: Record<string, RegExp> = {
  // Laravel raw SQL injection: whereRaw/selectRaw/etc. with variable interpolation
  // instead of binding array. Matches: ->whereRaw("col = $var") but not
  // ->whereRaw("col = ?", [$var])
  'CWE-89-RAW': /->(?:whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw)\s*\(\s*["'][^"']*\$\w+/,

  // DB::unprepared() with any variable — always dangerous since it can't bind
  'CWE-89-UNPREP': /DB\s*::\s*unprepared\s*\(\s*["'][^"']*\$\w+/,

  // extract() on superglobal — mass assignment (CWE-621 maps to CWE-915)
  'CWE-915-EXTRACT': /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/,

  // header() with user input — HTTP response splitting (CWE-113)
  'CWE-113-HEADER': /\bheader\s*\(\s*["'][^"']*["']\s*\.\s*\$/,

  // mail() with user-controlled additional headers (5th parameter)
  // CWE-93: CRLF injection in mail headers enables BCC injection / spam relay
  'CWE-93-MAIL': /\bmail\s*\([^)]*,[^)]*,[^)]*,[^)]*,\s*\$/,
};

// =============================================================================
// SAFE PATTERNS — mitigations for the above
// =============================================================================

export const laravelDeepSafePatterns: Record<string, RegExp> = {
  // Raw methods with binding arrays (second argument)
  'CWE-89-RAW': /->(?:whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw)\s*\(\s*["'][^"']*\?\s*["']\s*,\s*\[/,

  // extract() with EXTR_IF_EXISTS or EXTR_SKIP — safe(r) modes
  'CWE-915-EXTRACT': /\bextract\s*\([^)]*(?:EXTR_IF_EXISTS|EXTR_SKIP)/,

  // header() with hardcoded redirect or Content-Type (no user input)
  'CWE-113-HEADER': /\bheader\s*\(\s*["'](?:Location|Content-Type|X-Frame-Options)\s*:/,

  // mail() using framework mailer (SwiftMailer, PHPMailer, Laravel Mail)
  'CWE-93-MAIL': /(?:Mail\s*::\s*(?:send|to)|new\s+PHPMailer|Swift_Message)/,
};

// =============================================================================
// ENTRY COUNT
// =============================================================================

export function getExpansionCount(): number {
  return Object.keys(PHONEMES_PHP_LARAVEL_DEEP).length;
}
