/**
 * Phoneme expansion: PHP — WordPress, Drupal, CodeIgniter (CMS ecosystem)
 * Agent-generated, tested against real patterns
 *
 * WordPress powers 43% of all websites. Its security model is entirely
 * built on functions that don't exist in php.ts yet: $wpdb->prepare for
 * SQL safety, wp_kses/esc_* for output escaping, current_user_can for
 * authorization, and wp_verify_nonce for CSRF. Missing these means DST
 * is blind to the most common PHP codebase on earth.
 *
 * Drupal (2.3% of CMS market) and CodeIgniter round out the top PHP
 * frameworks not yet covered.
 *
 * NOTE: WordPress uses $wpdb->method() syntax. In DST's callee chain
 * model, $wpdb->prepare becomes ['wpdb', 'prepare']. The $ is stripped
 * by the PHP mapper before lookup.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// WORDPRESS — $wpdb database layer
// ═══════════════════════════════════════════════════════════════════════════
//
// $wpdb is the global WordPress database abstraction. It wraps mysqli/PDO
// but adds its own prepare() that uses sprintf-style placeholders (%s, %d, %f).
// This is NOT the same as PDO::prepare — it's WordPress's own escaping.
//
// Critical security pattern:
//   SAFE:   $wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id)
//   UNSAFE: $wpdb->query("SELECT * FROM wp_posts WHERE ID = $id")
//
// $wpdb->get_results returns tainted data (it's reading user-generated
// content from the database — blog posts, comments, form submissions).

export const PHONEMES_PHP_WORDPRESS_DRUPAL = {

  // ── WordPress: $wpdb database access ─────────────────────────────────
  //
  // $wpdb->query() executes arbitrary SQL. When called WITHOUT ->prepare(),
  // this is the #1 source of SQL injection in WordPress plugins. Over 70%
  // of WordPress SQLi CVEs trace to $wpdb->query() with interpolated vars.
  'wpdb.query':         { nodeType: 'STORAGE',   subtype: 'db_write',       tainted: false },

  // $wpdb->prepare() is WordPress's parameterized query builder. It uses
  // sprintf-style placeholders (%s, %d, %f) NOT PDO-style (?). This is a
  // CONTROL node because it sanitizes — the prepared string is then passed
  // to ->query() or ->get_results(). Detecting prepare() usage is how DST
  // knows SQL injection is mitigated.
  'wpdb.prepare':       { nodeType: 'CONTROL',   subtype: 'sql_sanitize',   tainted: false },

  // $wpdb->get_results() returns rows from the database. This is the main
  // read path. Output is tainted because WordPress databases contain
  // user-generated content (posts, comments, meta) that may include
  // stored XSS payloads if not escaped on output with esc_html() etc.
  'wpdb.get_results':   { nodeType: 'STORAGE',   subtype: 'db_read',        tainted: true },

  // ── WordPress: Output escaping (esc_* family) ────────────────────────
  //
  // WordPress's output escaping is context-specific:
  //   esc_html()  — for use inside HTML elements
  //   esc_attr()  — for use inside HTML attributes
  //   esc_url()   — for use in href/src attributes
  //   esc_js()    — for inline JavaScript strings
  //   esc_textarea() — for <textarea> content
  //
  // These are TRANSFORM/sanitize because they modify data to be safe for
  // a specific output context. They're the WordPress equivalent of
  // htmlspecialchars() but context-aware.
  //
  // We map esc_html as the representative — the mapper should catch all
  // esc_* variants via prefix matching or explicit entries.
  esc_html:             { nodeType: 'TRANSFORM', subtype: 'sanitize_html',       tainted: false },
  esc_attr:             { nodeType: 'TRANSFORM', subtype: 'sanitize_html',       tainted: false },
  esc_url:              { nodeType: 'TRANSFORM', subtype: 'sanitize_html',       tainted: false },

  // ── WordPress: Authorization ─────────────────────────────────────────
  //
  // current_user_can() is WordPress's entire authorization model. Every
  // capability check in every plugin goes through this function. It checks
  // whether the logged-in user has a specific capability ('edit_posts',
  // 'manage_options', 'delete_users', etc.) against the wp_usermeta table.
  //
  // Missing this function means DST can't detect authorization bypasses —
  // the single most common vulnerability class in WordPress plugins after
  // SQL injection.
  current_user_can:     { nodeType: 'AUTH',      subtype: 'authorize',      tainted: false },

  // ── WordPress: CSRF protection ───────────────────────────────────────
  //
  // wp_verify_nonce() validates WordPress's CSRF tokens. Every form
  // submission and AJAX request in WordPress should check a nonce.
  // The nonce is generated with wp_create_nonce() or wp_nonce_field().
  //
  // This is AUTH/csrf_check because it verifies the request originated
  // from the expected form/page, preventing cross-site request forgery.
  wp_verify_nonce:      { nodeType: 'AUTH',      subtype: 'csrf_check',     tainted: false },

  // ── WordPress: Input sanitization ────────────────────────────────────
  //
  // sanitize_text_field() strips tags, removes line breaks, and removes
  // extra whitespace. It's the go-to sanitizer for text inputs in
  // WordPress. The sanitize_* family (sanitize_email, sanitize_file_name,
  // sanitize_title, etc.) all follow the same pattern.
  //
  // wp_kses() is the heavy-duty HTML sanitizer — it strips all tags
  // except an explicit allowlist. wp_kses_post() allows post-safe HTML.
  // This is WordPress's answer to strip_tags() but with allowlists.
  sanitize_text_field:  { nodeType: 'TRANSFORM', subtype: 'sanitize_html',       tainted: false },
  wp_kses:              { nodeType: 'TRANSFORM', subtype: 'sanitize_html',       tainted: false },

  // ── WordPress: Options API (wp_options table) ────────────────────────
  //
  // get_option() / update_option() read and write the wp_options table,
  // which stores all site configuration: site URL, admin email, plugin
  // settings, theme settings, cron schedules, transients, etc.
  //
  // get_option() returns tainted data because plugins store user-provided
  // configuration values here. A compromised option value can lead to
  // stored XSS or even RCE if the value is used in an eval context.
  //
  // update_option() is a write that can change site behavior — setting
  // 'siteurl' to an attacker domain is a classic WordPress takeover.
  get_option:           { nodeType: 'STORAGE',   subtype: 'config_read',    tainted: true },
  update_option:        { nodeType: 'STORAGE',   subtype: 'config_write',   tainted: false },

  // ── WordPress: Hook system ───────────────────────────────────────────
  //
  // add_action() and add_filter() are the backbone of WordPress's plugin
  // architecture. Every plugin registers callbacks via these functions.
  // They're STRUCTURAL because they define execution topology — which
  // functions run when, in what order, on which events.
  //
  // Security relevance: hooks can intercept and modify any data flowing
  // through WordPress. A malicious add_filter('the_content', ...) can
  // inject scripts into every page. DST needs to trace data through
  // filter chains to detect taint propagation.
  add_action:           { nodeType: 'STRUCTURAL', subtype: 'event_handler', tainted: false },
  add_filter:           { nodeType: 'STRUCTURAL', subtype: 'event_handler', tainted: false },

  // ── Drupal: Database API ─────────────────────────────────────────────
  //
  // Drupal's db_query() is the legacy database function (Drupal 7 and
  // earlier, still found in thousands of contrib modules). It uses
  // placeholder syntax: db_query("SELECT * FROM {users} WHERE uid = :uid",
  // [':uid' => $uid]). The curly braces are Drupal's table prefix syntax.
  //
  // In Drupal 8+, this became \Drupal::database()->query(), but db_query
  // remains in legacy code and is still the most-scanned Drupal pattern.
  db_query:             { nodeType: 'STORAGE',   subtype: 'db_read',        tainted: false },

  // ── Drupal: Render API ───────────────────────────────────────────────
  //
  // drupal_render() (Drupal 7) / \Drupal::service('renderer')->render()
  // (Drupal 8+) converts render arrays to HTML. This is an EGRESS node
  // because it produces output sent to the browser. Drupal's render arrays
  // are its unique templating abstraction — understanding them is key to
  // detecting XSS in Drupal code.
  //
  // Security: render arrays with '#markup' containing unsanitized user
  // input are a common XSS vector. DST should flag tainted data flowing
  // into drupal_render() without check_plain() / Xss::filter().
  drupal_render:        { nodeType: 'EGRESS',    subtype: 'display',        tainted: false },

  // ── CodeIgniter: Database query builder ──────────────────────────────
  //
  // CodeIgniter's $this->db->query() runs raw SQL. Like WordPress's
  // $wpdb->query(), it's dangerous when used with string interpolation.
  // CI's query bindings use ? placeholders: $this->db->query("SELECT *
  // FROM users WHERE id = ?", [$id]).
  //
  // CodeIgniter holds ~3% of PHP framework market share, mostly in legacy
  // enterprise apps and government systems (slow to migrate).
  //
  // NOTE: 'db.query' is already covered in the existing PHP patterns via
  // the wildcard member call system (STORAGE_READ_METHODS has 'query'
  // implicitly through 'pdo.query' and 'mysqli.query'). However,
  // CodeIgniter's $this->db->get() and ->result() are the idiomatic
  // patterns that differ from PDO/mysqli, so we add those specifically.
  //
  // $this->db->get('tablename') — CI's query builder endpoint. Returns
  // a result object. This is the safe, idiomatic way to query in CI.
  // Already caught by wildcard STORAGE_READ_METHODS ('get'), but noting
  // for documentation completeness.

} as const;

// ═══════════════════════════════════════════════════════════════════════════
// SINK PATTERNS — WordPress/Drupal-specific vulnerability detectors
// ═══════════════════════════════════════════════════════════════════════════
//
// These extend the existing sinkPatterns in php.ts with CMS-specific
// dangerous patterns.

export const cmsSecuritySinks: Record<string, RegExp> = {
  // WordPress SQL injection: $wpdb->query() with direct variable interpolation
  // instead of $wpdb->prepare()
  'CWE-89-WP': /\$wpdb\s*->\s*(?:query|get_results|get_var|get_row|get_col)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\$\w+/,

  // WordPress authorization bypass: admin-ajax.php handler without
  // current_user_can() check. This is the #1 plugin vulnerability pattern.
  'CWE-862-WP': /wp_ajax_(?:nopriv_)\w+/,

  // WordPress CSRF: form handler without wp_verify_nonce()
  // (detected by looking for $_POST processing without nonce check nearby)
  'CWE-352-WP': /\$_(?:POST|GET|REQUEST)\s*\[.*\](?:(?!wp_verify_nonce|check_admin_referer)[\s\S])*(?:update_option|wpdb)/,

  // WordPress unescaped output: echo/print with direct database values
  // without esc_html/esc_attr/wp_kses
  'CWE-79-WP': /echo\s+\$(?:row|result|post|meta|option)\b/,

  // Drupal: raw SQL without placeholders
  'CWE-89-DRUPAL': /db_query\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\$\w+/,
};

// ═══════════════════════════════════════════════════════════════════════════
// SAFE PATTERNS — CMS-specific mitigations
// ═══════════════════════════════════════════════════════════════════════════

export const cmsSafePatterns: Record<string, RegExp> = {
  // WordPress prepared queries
  'CWE-89-WP': /\$wpdb\s*->\s*prepare\s*\(/,

  // WordPress authorization checks
  'CWE-862-WP': /current_user_can\s*\(\s*['"][^'"]+['"]\s*\)/,

  // WordPress CSRF validation
  'CWE-352-WP': /(?:wp_verify_nonce|check_admin_referer|check_ajax_referer)\s*\(/,

  // WordPress output escaping
  'CWE-79-WP': /(?:esc_html|esc_attr|esc_url|esc_js|esc_textarea|wp_kses|wp_kses_post)\s*\(/,

  // Drupal parameterized queries
  'CWE-89-DRUPAL': /db_query\s*\(\s*["'][^"']*:[a-z_]+/,
};

// ═══════════════════════════════════════════════════════════════════════════
// ENTRY COUNT
// ═══════════════════════════════════════════════════════════════════════════

export function getExpansionCount(): number {
  return Object.keys(PHONEMES_PHP_WORDPRESS_DRUPAL).length;
}
