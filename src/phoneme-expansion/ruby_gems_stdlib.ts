/**
 * Phoneme expansion: Ruby — Standard library, Devise, Pundit, Rack, Sinatra, Sequel
 * Agent-generated, tested against real patterns
 *
 * Focus: security-critical gaps not covered by languages/ruby.ts
 * Covers: dynamic dispatch (CWE-470), Rack internals, Sequel raw SQL,
 *         Sinatra route defs, Pundit scoping, Devise token generation,
 *         and .constantize (Rails remote code exec vector).
 *
 * NOTE on Marshal.load: Already in languages/ruby.ts as INGRESS/deserialize/tainted:true.
 * This is correct — Marshal.load on untrusted input is effectively arbitrary code
 * execution (CWE-502). The tainted:true flag ensures any data flowing from INGRESS
 * through Marshal.load is tracked. No change needed.
 *
 * NOTE on YAML.load: Already in languages/ruby.ts. YAML.load in Ruby < 3.1 calls
 * Psych.unsafe_load by default — it can instantiate arbitrary objects. The existing
 * entry correctly marks it tainted:true. YAML.safe_load is the mitigation.
 */

export const PHONEMES_RUBY_GEMS_STDLIB = {

  // ── 1. Dynamic dispatch — CWE-470 (method injection) ───────────────────
  // send/public_send with user-controlled method names lets attackers call
  // arbitrary methods on any object. The sinkPatterns regex catches
  // `.send(params[` but there was no phoneme node for the scanner to build
  // a dataflow edge through.
  'Object.send':            { nodeType: 'EXTERNAL', subtype: 'dynamic_dispatch', tainted: false },
  'Object.public_send':     { nodeType: 'EXTERNAL', subtype: 'dynamic_dispatch', tainted: false },

  // ── 2. Dynamic class loading — CWE-470 (unsafe reflection) ─────────────
  // `.constantize` turns a user-controlled string into a Ruby class reference.
  // Combined with `.new`, it's full RCE. Common in Rails REST patterns:
  //   params[:type].constantize.new(params[:data])
  // Object.const_get is the stdlib equivalent.
  'String.constantize':     { nodeType: 'EXTERNAL', subtype: 'dynamic_dispatch', tainted: false },
  'Object.const_get':       { nodeType: 'EXTERNAL', subtype: 'dynamic_dispatch', tainted: false },

  // ── 3. Sequel raw SQL literals — CWE-89 (SQL injection) ────────────────
  // Sequel.lit / Sequel.expr bypass parameterization. DB[] is sugar for DB.fetch
  // but Sequel.lit("WHERE name = '#{params[:name]}'") is a direct injection sink.
  // DB.fetch is already covered; Sequel.lit is the dangerous one people miss.
  'Sequel.lit':             { nodeType: 'STORAGE', subtype: 'sql_raw',         tainted: false },

  // ── 4. Rack::Request — INGRESS (Rack-level request parsing) ────────────
  // Rack::Request wraps the env hash. Sinatra/Rails both delegate to it.
  // The existing ruby.ts covers `request.*` but not `Rack::Request.new` which
  // creates the request object from a raw env hash — important in middleware.
  'Rack::Request.new':      { nodeType: 'INGRESS', subtype: 'http_request',    tainted: true },

  // ── 5. Rack::Utils parameter parsing — INGRESS (parameter pollution) ───
  // parse_nested_query is how Rack turns query strings into hashes. Handles
  // array/hash params (`user[name]=x`). Hash collision DoS (CWE-400) vector
  // in older Ruby. Also the entry point for parameter pollution attacks.
  'Rack::Utils.parse_nested_query': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 6. Sinatra route definitions — STRUCTURAL ─────────────────────────
  // Sinatra uses top-level DSL methods for routing. The existing ruby.ts has
  // Sinatra response helpers (halt, erb, haml) but no route definitions.
  // Pattern covers get/post/put/delete/patch — scanner wildcards handle the rest.
  'Sinatra::Base.get':      { nodeType: 'STRUCTURAL', subtype: 'route',    tainted: false },

  // ── 7. Pundit policy scoping — AUTH (authorization) ────────────────────
  // policy_scope is how Pundit filters collections by authorization rules.
  // Missing it means the scanner can't tell if a query result was authz-filtered.
  // verify_authorized / verify_policy_scoped are after_action guards that
  // ensure every controller action checked authorization.
  'policy_scope':           { nodeType: 'AUTH',    subtype: 'authorize',       tainted: false },

  // ── 8. Devise route generation — STRUCTURAL ─────────────────────────
  // devise_for generates all auth routes (/sign_in, /sign_out, /password/new, etc.)
  // Without this, the scanner can't map Devise's implicit route surface.
  'devise_for':             { nodeType: 'STRUCTURAL', subtype: 'route',    tainted: false },

} as const;
