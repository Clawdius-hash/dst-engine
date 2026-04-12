/**
 * Phoneme expansion: C# — ASP.NET Core (Controllers, Razor, Entity Framework)
 * Agent-generated, tested against real patterns
 *
 * Focus: HttpContext.Request, [FromBody], [FromQuery], [Authorize],
 * Entity Framework DbContext, SqlCommand, Process.Start, Response.Redirect.
 *
 * These patterns fill gaps in languages/csharp.ts which already covers:
 *   HttpContext.Request, Request.Form/Query/Body/Headers/Cookies/Path,
 *   DbContext.SaveChanges/Add/Update/Remove/ExecuteSqlRaw/Set,
 *   SqlCommand.ExecuteReader/ExecuteNonQuery/ExecuteScalar,
 *   Process.Start, Response.WriteAsync/WriteAsJsonAsync,
 *   UserManager/SignInManager auth, DI registration, routing.
 */
export const PHONEMES_CSHARP_ASPNET_CORE = {

  // ── INGRESS: HttpContext.Request.ReadFormAsync — multipart form + file upload ──
  // Unlike Request.Form (sync property, already covered), ReadFormAsync is the
  // async method that parses multipart/form-data including IFormFile uploads.
  // Attacker controls both field names and file content (CWE-434).
  'HttpContext.Request.ReadFormAsync': { nodeType: 'INGRESS', subtype: 'file_upload', tainted: true },
  // Why: This is the actual ingress point for file uploads in ASP.NET Core;
  // missing it means uploaded malware flows through the graph untracked.

  // ── INGRESS: HttpContext.Session — server-side session state ──
  // Session values are stored server-side but the session ID cookie is
  // client-controlled. Session fixation (CWE-384) and deserialization attacks
  // make session reads a tainted ingress when the session stores user-supplied data.
  'HttpContext.Session.GetString': { nodeType: 'INGRESS', subtype: 'session_read', tainted: true },
  // Why: Developers store user input in session then read it back assuming it's safe;
  // the taint needs to survive the session round-trip or XSS payloads escape.

  // ── EGRESS: Response.Redirect — open redirect vector ──
  // Response.Redirect with user-controlled URLs is CWE-601 (open redirect).
  // The existing dictionary covers Redirect/RedirectToAction as controller action
  // results but NOT the HttpResponse.Redirect method called on the raw response.
  'Response.Redirect': { nodeType: 'EGRESS', subtype: 'http_redirect', tainted: false },
  // Why: Open redirect is OWASP Top 10; if the URL argument traces back to an
  // INGRESS node without validation, the mapper must flag the tainted flow.

  // ── STORAGE: DbContext.Database.SqlQueryRaw — raw SQL returning entities ──
  // Added in EF Core 8 (.NET 8). Unlike ExecuteSqlRaw (write, already covered),
  // SqlQueryRaw returns IQueryable<T> — it is a READ path for raw SQL.
  // String interpolation in the query is the #1 SQL injection vector in EF Core.
  'DbContext.Database.SqlQueryRaw': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  // Why: New in .NET 8 and rapidly adopted; scanners missing this miss the most
  // common modern EF Core SQL injection pattern (CWE-89).

  // ── META: [FromBody] attribute — marks parameter as JSON body ingress ──
  // [FromBody] on a controller action parameter tells ASP.NET Core to deserialize
  // the request body (JSON/XML) into that parameter. This is the primary ingress
  // declaration for POST/PUT/PATCH endpoints. The attribute itself is metadata;
  // the actual data arrives via model binding, but the attribute marks WHERE.
  'FromBody': { nodeType: 'META', subtype: 'ingress_binding', tainted: true },
  // Why: Detecting [FromBody] on a parameter tells the mapper that the parameter
  // carries attacker-controlled deserialized data — the starting point for every
  // injection flow in a typical ASP.NET Core REST API (CWE-502, CWE-20).

  // ── STORAGE: SqlCommand.CommandText — the actual SQL injection point ──
  // SqlCommand.ExecuteReader/ExecuteNonQuery are already covered, but CommandText
  // is where the SQL string is assigned. If tainted data flows into CommandText
  // without parameterization, that IS the injection (CWE-89).
  'SqlCommand.CommandText': { nodeType: 'STORAGE', subtype: 'sql_assignment', tainted: false },
  // Why: Tracking ExecuteReader catches the execution but not the construction.
  // The taint flow is: Request.Query -> string concat -> cmd.CommandText -> ExecuteReader.
  // Without this node, the graph has a gap between ingress and the actual sink.

  // ── CONTROL: ModelState.IsValid — model binding validation gate ──
  // ASP.NET Core model binding with [FromBody]/[FromQuery] runs data annotations
  // and FluentValidation automatically. ModelState.IsValid is the guard check.
  // If a controller skips this check, tainted model data flows unchecked.
  'ModelState.IsValid': { nodeType: 'CONTROL', subtype: 'validation', tainted: false },
  // Why: The presence/absence of this node after a [FromBody] ingress tells the
  // mapper whether input validation actually happened — critical for CWE-20.

  // ── CONTROL: HtmlEncoder.Default.Encode — XSS sanitization ──
  // The standard .NET mechanism for HTML-encoding user input before rendering.
  // Razor auto-encodes @Model.Property but raw HTML helpers and manual string
  // building bypass it. This is the explicit sanitization call.
  'HtmlEncoder.Default.Encode': { nodeType: 'CONTROL', subtype: 'sanitize_html', tainted: false },
  // Why: Detecting this between an INGRESS and an EGRESS (like Response.WriteAsync
  // or a Razor view) tells the mapper that XSS sanitization is present (CWE-79).

  // ── EGRESS: Results.Redirect — Minimal API open redirect ──
  // Minimal APIs (.NET 6+) use Results.Redirect() instead of controller Redirect().
  // languages/csharp.ts covers Results.Ok/Json/NotFound/BadRequest/File but NOT
  // Results.Redirect. Same open redirect risk as controller Redirect (CWE-601).
  'Results.Redirect': { nodeType: 'EGRESS', subtype: 'http_redirect', tainted: false },
  // Why: Minimal APIs are the default template in .NET 8+; missing this means
  // open redirect detection fails on the most common new ASP.NET Core pattern.

  // ── META: Authorize attribute — the [Authorize] decorator ──
  // [Authorize] on a controller or action is not a runtime call but a metadata
  // declaration that the auth middleware enforces. Treating it as META/auth_policy
  // lets the mapper verify that sensitive endpoints have authorization applied.
  // NOTE: This is a decorator/attribute, not a method call. It fits META because
  // it declares policy rather than executing logic. A mapper encountering
  // [Authorize(Policy = "Admin")] on a class should emit this node.
  'Authorize': { nodeType: 'META', subtype: 'auth_policy', tainted: false },
  // Why: Detecting missing [Authorize] on controllers that access DbContext is
  // the #1 broken access control finding in ASP.NET Core audits (CWE-862).

} as const;
