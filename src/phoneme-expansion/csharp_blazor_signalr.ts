/**
 * Phoneme expansion: C# — Blazor (component rendering, JS interop),
 * SignalR (real-time hubs), Minimal APIs, System.Text.Json, System.Security.Cryptography
 * Agent-generated, tested against real patterns
 *
 * Focus: Blazor JS interop sinks, raw markup injection, SignalR real-time
 * message ingress/egress, Minimal API route grouping, crypto encrypt/decrypt.
 *
 * These patterns fill gaps in languages/csharp.ts which already covers:
 *   JsonSerializer.Serialize/Deserialize, SHA256/SHA512/MD5/Aes.Create/RSA.Create,
 *   Results.Ok/Json/NotFound/BadRequest/File, app.MapGet/Post/Put/Delete/Patch,
 *   Response.WriteAsync/WriteAsJsonAsync, Request.ReadFromJsonAsync.
 */
export const PHONEMES_CSHARP_BLAZOR_SIGNALR = {

  // ── EXTERNAL: IJSRuntime.InvokeAsync — Blazor JS interop sink ──
  // Blazor Server/WASM calls JavaScript functions from C# via IJSRuntime.
  // If the function name or arguments are user-controlled, this is a direct
  // XSS vector — the call executes arbitrary JS in the browser (CWE-79).
  // This is the #1 Blazor-specific vulnerability: developers pass user input
  // as arguments to JS functions thinking .NET-side validation is enough.
  'IJSRuntime.InvokeAsync': { nodeType: 'EXTERNAL', subtype: 'js_interop', tainted: false },
  // Why: User-controlled data flowing into InvokeAsync args reaches the browser
  // JS runtime unescaped. If the target JS function does innerHTML or eval,
  // this is a full XSS chain that static analyzers miss because the sink
  // crosses the C#→JS boundary.

  // ── EXTERNAL: IJSRuntime.InvokeVoidAsync — void JS interop sink ──
  // Same as InvokeAsync but returns void. Used for fire-and-forget JS calls
  // like DOM manipulation, localStorage writes, or analytics events.
  // Same XSS risk — the void return just means the caller doesn't await a result.
  'IJSRuntime.InvokeVoidAsync': { nodeType: 'EXTERNAL', subtype: 'js_interop', tainted: false },
  // Why: Developers use InvokeVoidAsync for "side-effect only" JS calls and
  // are even less likely to validate arguments since there's no return value
  // to inspect. Same attack surface as InvokeAsync.

  // ── EGRESS: NavigationManager.NavigateTo — Blazor open redirect ──
  // NavigateTo is how Blazor apps do client-side navigation. With forceLoad:true
  // it triggers a full browser redirect. If the URI comes from user input
  // (query string, form field), this is an open redirect (CWE-601).
  // Neither the ASP.NET Core nor Blazor frameworks validate the target URI.
  'NavigationManager.NavigateTo': { nodeType: 'EGRESS', subtype: 'http_redirect', tainted: false },
  // Why: Blazor SPAs that read ?returnUrl= from the query string and pass it
  // to NavigateTo are the exact same open redirect as Response.Redirect but
  // in a Blazor-specific API that existing rules don't cover.

  // ── INGRESS: HubConnection.On — SignalR client-side message handler ──
  // On<T> registers a handler for server-pushed messages on the client side.
  // The message payload is server-controlled, but in adversarial scenarios
  // (compromised server, MITM on non-TLS SignalR), the payload is tainted.
  // More importantly, the handler pattern tells the scanner WHERE real-time
  // data enters the client — the equivalent of addEventListener for WebSockets.
  'HubConnection.On': { nodeType: 'INGRESS', subtype: 'realtime_message', tainted: true },
  // Why: SignalR's real-time push is the primary ingress for all data arriving
  // outside the normal HTTP request cycle. If the client handler feeds this
  // data into DOM manipulation or navigation, it's an XSS/redirect vector
  // that only appears in real-time code paths.

  // ── EGRESS: Clients.All.SendAsync — SignalR server broadcasting to all clients ──
  // Hub methods use Clients.All.SendAsync to push data to every connected client.
  // If the payload includes unsanitized user input from one client, it becomes
  // a stored XSS vector broadcast to all other clients (CWE-79).
  // This is the canonical SignalR vulnerability in chat applications.
  'Clients.All.SendAsync': { nodeType: 'EGRESS', subtype: 'realtime_broadcast', tainted: false },
  // Why: A hub method that receives user input via InvokeAsync and relays it
  // via Clients.All.SendAsync without sanitization is a broadcast XSS.
  // The scanner needs both the INGRESS (hub method parameter) and this EGRESS
  // to trace the full taint flow.

  // ── EGRESS: Clients.Caller.SendAsync — SignalR server responding to caller ──
  // Sends data back to the specific client that invoked the hub method.
  // Same taint risk as Clients.All but scoped to one client — still an egress
  // point where unsanitized data leaves the server.
  'Clients.Caller.SendAsync': { nodeType: 'EGRESS', subtype: 'realtime_response', tainted: false },
  // Why: Even single-client responses can carry reflected XSS if the hub
  // echoes back user input. This is the SignalR equivalent of res.json().

  // ── TRANSFORM: MarkupString — Blazor raw HTML rendering ──
  // Wrapping a string in (MarkupString) or new MarkupString() tells Blazor
  // to render it as raw HTML without encoding. This is the Blazor equivalent
  // of dangerouslySetInnerHTML in React. If the string contains user input,
  // it's a direct XSS vector (CWE-79).
  'MarkupString': { nodeType: 'TRANSFORM', subtype: 'raw_html', tainted: false },
  // Why: Blazor auto-encodes all output by default — MarkupString is the
  // explicit opt-out. Every use is a potential XSS sink. The scanner should
  // flag any taint flow that reaches a MarkupString construction.

  // ── STRUCTURAL: app.MapGroup — Minimal API route grouping ──
  // MapGroup creates a RouteGroupBuilder that applies shared prefixes, filters,
  // and metadata to a group of endpoints. Security-relevant because auth
  // policies and rate limiting applied at the group level protect all child
  // routes — but a misconfigured group leaves them all exposed.
  'app.MapGroup': { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },
  // Why: In .NET 7+ Minimal APIs, MapGroup is how developers organize routes
  // and apply cross-cutting concerns. Missing [Authorize] on a MapGroup
  // means every endpoint in the group is unauthenticated (CWE-862).

  // ── STRUCTURAL: app.MapHub — SignalR hub endpoint registration ──
  // MapHub<T> registers a SignalR hub at a given path. This is the structural
  // entry point for all real-time communication — the equivalent of app.MapGet
  // but for persistent WebSocket/SSE connections.
  'app.MapHub': { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },
  // Why: A hub registered without .RequireAuthorization() is open to anonymous
  // connections. Since hubs are persistent and bidirectional, an unauthed hub
  // is a larger attack surface than an unauthed REST endpoint.

  // ── TRANSFORM: RSA.Encrypt — asymmetric encryption operation ──
  // RSA.Create() is already covered (creates the algorithm instance), but
  // the actual Encrypt/Decrypt calls are where data transformation happens.
  // If padding mode is wrong (PKCS1 vs OAEP), the encryption is vulnerable
  // to padding oracle attacks (CWE-780).
  'RSA.Encrypt': { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  // Why: The Create() call is structural setup; Encrypt() is where sensitive
  // data actually gets encrypted. Tracking it lets the scanner verify that
  // encryption actually happens on sensitive data paths, not just that the
  // algorithm was instantiated.

} as const;

// ── NOTES ──
//
// PATTERN NOBODY TALKS ABOUT:
// Blazor Server's IJSRuntime.InvokeAsync crosses a trust boundary that no other
// .NET API does: it sends data from the server-side C# process to client-side
// JavaScript over the SignalR circuit. Static analyzers that treat C# as a
// single trust domain miss this entirely. The data leaves .NET's type system
// and enters JavaScript's loose typing — any object serialized through this
// boundary should be treated as if it's being sent to an untrusted client,
// because it IS. This is conceptually identical to SSRF but in reverse:
// instead of the server making unauthorized requests, the server sends
// unauthorized payloads to the client's JS runtime.
//
// SIGNALR HUB METHODS AS INGRESS:
// Hub methods that accept parameters from clients (e.g., public async Task
// SendMessage(string user, string message)) have their parameters deserialized
// from the SignalR wire protocol. These parameters are INGRESS points equivalent
// to [FromBody] in controllers, but they don't go through ASP.NET Core model
// binding or validation middleware. Developers who rely on ModelState.IsValid
// for validation get zero protection on SignalR hub method parameters.
