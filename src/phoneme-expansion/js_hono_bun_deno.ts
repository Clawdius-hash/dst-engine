/**
 * Phoneme expansion: JavaScript/TypeScript — Hono, Bun, Deno runtimes
 * Agent-generated, tested against real patterns
 *
 * Coverage gap: these three runtimes have 40K-75K GitHub stars each and had
 * ZERO entries in calleePatterns.ts. Red team audit flagged this as a blind spot.
 *
 * Hono (75K stars): Ultrafast web framework for Cloudflare Workers, Deno, Bun, Node.
 *   Convention: (c) => { ... } where c is the Hono Context object.
 *   c.req wraps the Request; c.json/c.text/c.html are response helpers.
 *
 * Bun (75K stars): All-in-one JS runtime with native file I/O, subprocess, HTTP server.
 *   Bun.file/Bun.write replace fs. Bun.spawn replaces child_process. Bun.serve is the HTTP server.
 *
 * Deno (100K stars): Secure-by-default runtime with permission model.
 *   Deno.readTextFile/Deno.writeTextFile replace fs. Deno.run/Deno.Command for subprocesses.
 *   Deno.serve is the HTTP server primitive.
 */

import type { CalleePattern } from '../calleePatterns.js';

export const PHONEMES_JS_HONO_BUN_DENO: Record<string, CalleePattern> = {

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Hono
  // ═══════════════════════════════════════════════════════════════════════════
  // Hono handlers receive a Context `c`. c.req.query() and c.req.param() return
  // user-controlled strings — these are the primary INGRESS vectors.
  // c.req.json() parses the request body as JSON (user-controlled).

  // INGRESS: c.req.query('key') returns URL query params — classic injection vector (SQLi, XSS).
  'c.req.query':            { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // INGRESS: c.req.param('id') returns route params like /users/:id — user-controlled path segments.
  'c.req.param':            { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // INGRESS: c.req.json() parses request body as JSON — tainted deserialized input.
  'c.req.json':             { nodeType: 'INGRESS',    subtype: 'http_body',     tainted: true },

  // EGRESS: c.json() sends JSON response — data leaving the system, potential info leak surface.
  'c.json':                 { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },

  // EGRESS: c.text() sends plain text response. c.html() sends HTML (XSS sink if tainted data
  // flows in without escaping — Hono does NOT auto-escape c.html() string arguments).
  'c.text':                 { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'c.html':                 { nodeType: 'EGRESS',     subtype: 'xss_sink',      tainted: false },
  // NOTE: c.html() is subtyped as xss_sink rather than http_response because it renders raw HTML.
  // If tainted data from c.req.query() flows into c.html() without sanitization, it is reflected XSS.

  // ═══════════════════════════════════════════════════════════════════════════
  // RUNTIME: Bun
  // ═══════════════════════════════════════════════════════════════════════════
  // Bun replaces Node's fs and child_process with built-in APIs.
  // Bun.file() returns a BunFile (lazy file handle). Bun.spawn() runs subprocesses.

  // INGRESS: Bun.file(path) opens a file for reading — if path is user-controlled, path traversal (CWE-22).
  'Bun.file':               { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },

  // EXTERNAL: Bun.spawn() runs a subprocess — command injection sink if args are user-controlled.
  // This is Bun's replacement for child_process.spawn. Same risk profile.
  'Bun.spawn':              { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // RUNTIME: Deno
  // ═══════════════════════════════════════════════════════════════════════════
  // Deno's permission model (--allow-read, --allow-run) is defense-in-depth but
  // does NOT prevent misuse once permissions are granted. The scanner must still
  // track these as taint sinks.

  // INGRESS: Deno.readTextFile(path) reads a file — path traversal vector if path is tainted.
  'Deno.readTextFile':      { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },

  // EXTERNAL: Deno.Command (replaces deprecated Deno.run) spawns a subprocess.
  // Command injection sink. Deno requires --allow-run but once granted, fully exploitable.
  'Deno.Command':           { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

} as const;

// ── Supplementary patterns for deeper Hono/Bun/Deno chains ─────────────────
// These cover less common but security-relevant patterns that the wildcard
// strategy in calleePatterns.ts won't catch because the object names are unique.

export const SUPPLEMENTARY_PATTERNS: Record<string, CalleePattern> = {

  // Hono: c.req.header('Authorization') — reads a single header, tainted input.
  'c.req.header':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // Hono: c.req.parseBody() — multipart/form-data parser, file upload vector.
  'c.req.parseBody':        { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },

  // Hono: c.redirect(url) — open redirect sink if url is user-controlled.
  'c.redirect':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },

  // Hono: app.use() — middleware registration (structural, same as Express app.use).
  'hono.use':               { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },

  // Bun: Bun.write(path, data) — writes data to a file. File write sink.
  'Bun.write':              { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },

  // Bun: Bun.serve({ fetch(req) {} }) — HTTP server entry point (structural).
  'Bun.serve':              { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },

  // Deno: Deno.writeTextFile(path, data) — file write sink, symmetric to readTextFile.
  'Deno.writeTextFile':     { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },

  // Deno: Deno.serve(handler) — HTTP server entry point (structural).
  'Deno.serve':             { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },

  // Deno: Deno.env.get('KEY') — environment variable read, same as process.env.
  'Deno.env':               { nodeType: 'INGRESS',    subtype: 'env_read',      tainted: false },
};
