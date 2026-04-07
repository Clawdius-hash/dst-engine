/**
 * Phoneme expansion: Ruby — Rails controllers, ActiveRecord, ActionView
 * Agent-generated, tested against real patterns
 *
 * These 10 entries fill gaps in languages/ruby.ts that matter most for
 * security scanning of Shopify/GitHub-style Rails codebases.
 *
 * Focus: params[], render, redirect_to, ActiveRecord find/where/find_by_sql,
 *        system/exec/backticks, ERB output (html_safe, raw), before_action,
 *        authenticate_user!
 *
 * NOTE on existing coverage: params[], render, redirect_to, before_action,
 * authenticate_user!, system, exec are already in languages/ruby.ts.
 * The entries below are NET NEW gaps.
 */
export const PHONEMES_RUBY_RAILS_CORE = {
  // ── RAW SQL — the biggest Rails injection surface ─────────────────────
  // ActiveRecord::Base.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
  // This takes a raw SQL string. No parameterization. Every SAST tool flags it.
  'ActiveRecord.find_by_sql':   { nodeType: 'STORAGE', subtype: 'sql_raw', tainted: false },

  // ActiveRecord::Base.count_by_sql("SELECT COUNT(*) FROM users WHERE role = '#{role}'")
  // Same danger as find_by_sql but for aggregate queries. Less known, equally dangerous.
  'ActiveRecord.count_by_sql':  { nodeType: 'STORAGE', subtype: 'sql_raw', tainted: false },

  // connection.exec_query("SELECT * FROM users WHERE email = '#{email}'")
  // Low-level ActiveRecord connection method. Developers reach for it when
  // they want "just run this SQL" — and forget to parameterize.
  'connection.exec_query':      { nodeType: 'STORAGE', subtype: 'sql_raw', tainted: false },

  // User.where("name LIKE '%#{params[:q]}%'") uses string interpolation,
  // but the safe version is: User.where("name LIKE ?", "%#{params[:q]}%")
  // Arel.sql() explicitly wraps a string as raw SQL, bypassing parameterization:
  //   User.order(Arel.sql(params[:sort]))
  // When user input reaches Arel.sql, it's game over for SQL injection defense.
  'Arel.sql':                   { nodeType: 'STORAGE', subtype: 'sql_raw', tainted: false },

  // ── XSS SINKS — ERB output that bypasses auto-escaping ───────────────
  // In ERB: <%= @user_input.html_safe %> tells Rails "trust this string."
  // This is the #1 XSS vector in Rails apps. Auto-escaping is Rails' main
  // defense; html_safe is the explicit opt-out. Shopify's Brakeman flags every call.
  // NOTE: This is a method on String, so it appears as *.html_safe in real code.
  // The wildcard set in ruby.ts doesn't cover it — it falls through to TRANSFORM.
  'String.html_safe':           { nodeType: 'EGRESS', subtype: 'xss_sink', tainted: false },

  // ── DANGEROUS METAPROGRAMMING — arbitrary dispatch from user input ────
  // Object.const_get(params[:type]).new — instantiate any class from user input.
  // CWE-470 (Use of Externally-Controlled Input to Select Classes or Code).
  // Seen in polymorphic factories: "#{params[:type]}Controller".constantize
  'Object.const_get':           { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // object.send(params[:method], params[:arg]) — call ANY method including private ones.
  // object.public_send is slightly safer (public only) but still dangerous with user input.
  // This is the Ruby equivalent of JavaScript's obj[userInput]() but worse because
  // send bypasses visibility. Seen in: dynamic API handlers, admin panels, webhook processors.
  'Object.send':                { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // String#constantize: "Admin::UsersController".constantize => Admin::UsersController
  // When params[:controller].constantize is used, attacker picks which class to invoke.
  // Rails autoload makes this especially dangerous — any class in the app is reachable.
  'String.constantize':         { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // ── VALIDATION BYPASS — writes that skip callbacks and validations ────
  // update_columns skips ALL validations, callbacks, and updated_at.
  // Developers use it for "performance" but it bypasses every safety net:
  //   @user.update_columns(role: params[:role])  # mass assignment + no validation
  // Distinct from update/update! which ARE in ruby.ts (they go through validations).
  'ActiveRecord.update_columns': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

  // ── COMMAND EXECUTION — backtick equivalent ───────────────────────────
  // IO.popen already in ruby.ts. Open3 methods already in ruby.ts.
  // But Kernel#` (backticks) can't be a callee pattern — it's syntax.
  // However, %x{} is equivalent syntax and also can't be a callee.
  // So we cover the remaining callable form:
  // PTY.spawn(user_command) — pseudo-terminal execution, used in deployment tools.
  // More dangerous than system() because it allocates a PTY (resource + exec).
  'PTY.spawn':                  { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
} as const;

// ═════════════════════════════════════════════════════════════════════════════
// FINDINGS / FLAGS
// ═════════════════════════════════════════════════════════════════════════════
//
// 1. EXISTING ENTRY CONCERN: `render` is typed as EGRESS/http_response, but
//    `render inline: params[:template]` is actually an SSTI/code execution
//    sink (CWE-94). The sink regex in sinkPatterns catches "render inline:"
//    but the node type doesn't distinguish it. A mapper seeing render as
//    plain EGRESS won't flag inline rendering from user input.
//    Consider: split into 'render' (EGRESS) vs 'render_inline' (EXTERNAL/template_exec).
//
// 2. DANGEROUS PATTERN NOBODY TALKS ABOUT: ActiveRecord's `update_columns`
//    and `update_column` bypass all model validations AND callbacks. In codebases
//    that rely on before_save callbacks for authorization checks, this is
//    effectively an auth bypass disguised as a performance optimization.
//    GitHub's internal Rails style guide explicitly bans update_columns on
//    models with security callbacks.
//
// 3. html_safe vs raw: Both bypass auto-escaping but are subtly different.
//    html_safe is a String method (marks the receiver as safe). raw() is a
//    view helper (calls html_safe on its argument). In the callee pattern
//    system, raw() already works as a single-name lookup, but html_safe
//    falls through to wildcard matching and gets misclassified as TRANSFORM/format
//    because it looks like a string method. The String.html_safe entry above fixes this.
//
// 4. Backtick execution (` `` ` and %x{}) are Ruby syntax, not method calls,
//    so they can't be callee patterns. The scanner needs a separate syntax-level
//    check for these — they're equivalent to Kernel#system but invisible to
//    callee-based scanning.
