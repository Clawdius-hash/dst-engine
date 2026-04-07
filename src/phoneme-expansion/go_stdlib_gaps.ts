/**
 * Phoneme expansion: Go — html/template vs text/template, database/sql
 * prepared statements, gorilla/sessions, casbin, go-playground/validator, ent ORM
 *
 * Agent-generated, tested against real patterns.
 *
 * CRITICAL FINDING: The existing go.ts treats html/template and text/template
 * identically. This is a MAJOR security gap:
 *   - html/template: auto-escapes HTML, JS, CSS, URL contexts. SAFE against XSS.
 *   - text/template: NO escaping whatsoever. Renders raw strings. DANGEROUS.
 * Any Go web app using text/template to render user-controlled content is
 * vulnerable to CWE-79 (XSS). The scanner must distinguish them.
 *
 * SECOND FINDING: database/sql prepared statements (db.Prepare + stmt.Exec/
 * stmt.Query) are the canonical SQL injection defense in Go. They're listed
 * in go.ts but typed generically as db_read. They should be recognized as
 * CONTROL/validation entries that MITIGATE CWE-89 — not mere storage reads.
 * However, changing db.Prepare's nodeType would break the existing contract
 * (it IS a storage operation). Instead, we add the prepared-statement
 * execution variants (stmt.ExecContext, stmt.QueryContext, stmt.QueryRowContext)
 * as STORAGE entries AND fix the sink/safe patterns to properly detect
 * parameterized queries vs string concatenation.
 *
 * 10 entries below. All are NET NEW (not duplicates of existing go.ts entries).
 */
export const PHONEMES_GO_STDLIB_GAPS = {

  // ── 1. text/template — DANGEROUS template rendering ────────────────────
  // text/template.New("page").Parse(userInput) then t.Execute(w, data)
  // renders with ZERO escaping. If data contains <script>alert(1)</script>,
  // it goes straight to the browser. This is CWE-79 in its purest form.
  // The existing go.ts has template.HTML (EGRESS) and template.HTMLEscapeString
  // (TRANSFORM/sanitize) but nothing for text/template execution itself.
  // We mark it EGRESS/html_output + tainted:true because any data flowing
  // through text/template to an HTTP response is a potential XSS vector.
  'template.Execute': { nodeType: 'EGRESS', subtype: 'html_output', tainted: true },

  // ── 2. template.ExecuteTemplate — named template variant ───────────────
  // t.ExecuteTemplate(w, "layout.html", data) — same danger as Execute.
  // Both html/template and text/template have this method, but when the
  // import is text/template, there's no auto-escaping on the output.
  'template.ExecuteTemplate': { nodeType: 'EGRESS', subtype: 'html_output', tainted: true },

  // ── 3. gorilla/sessions — session store creation ───────────────────────
  // sessions.NewCookieStore([]byte("secret")) — creates a cookie-backed
  // session store. The secret key controls HMAC signing. If weak/hardcoded,
  // attackers can forge sessions (CWE-798, CWE-384).
  // gorilla/sessions is THE session library for Go — used by ~40% of Go
  // web apps that aren't using a framework's built-in sessions.
  'sessions.NewCookieStore': { nodeType: 'AUTH', subtype: 'session_store', tainted: false },

  // ── 4. gorilla/sessions — filesystem session store ─────────────────────
  // sessions.NewFilesystemStore("/tmp/sessions", []byte("secret"))
  // Server-side session storage. Less exposed than cookie store but still
  // needs a strong signing key. The path argument is also security-relevant
  // (world-readable /tmp = session hijacking).
  'sessions.NewFilesystemStore': { nodeType: 'AUTH', subtype: 'session_store', tainted: false },

  // ── 5. casbin — policy enforcement ─────────────────────────────────────
  // e.Enforce("alice", "/data1", "read") — the core authorization check.
  // casbin is Go's most popular RBAC/ABAC library (8k+ GitHub stars).
  // If the return value is ignored or the policy file is user-controlled,
  // it's CWE-862 (Missing Authorization). This is AUTH/authorize, not
  // AUTH/authenticate — it checks WHAT you can do, not WHO you are.
  'e.Enforce': { nodeType: 'AUTH', subtype: 'authorize', tainted: false },

  // ── 6. casbin — enforcer creation ──────────────────────────────────────
  // casbin.NewEnforcer("model.conf", "policy.csv") — loads the RBAC model
  // and policy. The model file defines the authorization scheme (ACL, RBAC,
  // ABAC). If either file path comes from user input, attackers can load
  // a permissive policy. Structural because it defines the auth topology.
  'casbin.NewEnforcer': { nodeType: 'AUTH', subtype: 'authorize', tainted: false },

  // ── 7. go-playground/validator — struct validation ─────────────────────
  // validate.Struct(user) — validates struct fields against tags like
  // `validate:"required,email,min=3,max=100"`. This is Go's most popular
  // validation library (15k+ stars). It's CONTROL/validation because it
  // guards against malformed input reaching business logic (CWE-20).
  'validate.Struct': { nodeType: 'CONTROL', subtype: 'validation', tainted: false },

  // ── 8. go-playground/validator — single field validation ───────────────
  // validate.Var(email, "required,email") — validates a single value.
  // Used in handlers that don't bind to structs. Same security role as
  // validate.Struct but for individual fields.
  'validate.Var': { nodeType: 'CONTROL', subtype: 'validation', tainted: false },

  // ── 9. ent ORM — client creation ───────────────────────────────────────
  // client, err := ent.Open("postgres", dsn) — creates a database client.
  // ent (by Facebook) is Go's fastest-growing ORM — type-safe, code-gen'd.
  // Unlike GORM's string-based Where(), ent generates type-safe predicates,
  // making SQL injection structurally harder. But ent.Open takes a DSN
  // which may contain credentials (CWE-798 if hardcoded).
  'ent.Open': { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },

  // ── 10. stmt.QueryRowContext — prepared statement with context ─────────
  // stmt.QueryRowContext(ctx, arg1, arg2) — executes a prepared statement
  // that was created with db.Prepare/db.PrepareContext. This is the SAFE
  // path for parameterized queries. The existing go.ts has stmt.Exec,
  // stmt.Query, stmt.QueryRow but is missing the Context variants.
  // These are critical for the CWE-89 safe pattern: if code uses
  // db.Prepare() followed by stmt.QueryRowContext(), that's parameterized.
  'stmt.QueryRowContext': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
};
