/**
 * Phoneme expansion: Go — chi router, gorilla/mux, gorilla/websocket,
 * golang.org/x/net/html, net/http/httputil reverse proxy
 *
 * Agent-generated, tested against real patterns.
 *
 * CRITICAL FINDING: httputil.NewSingleHostReverseProxy is one of the most
 * dangerous stdlib functions in Go. It creates a reverse proxy that forwards
 * the ENTIRE request (including headers, cookies, auth tokens) to a backend.
 * If the target URL comes from user input, it's a textbook SSRF (CWE-918).
 * Even when the target is hardcoded, the proxy forwards X-Forwarded-For,
 * Authorization headers, and cookies — which can leak credentials to
 * internal services. The existing go.ts has ZERO coverage for httputil.
 *
 * SECOND FINDING: gorilla/websocket.Upgrader with CheckOrigin set to
 * func(r *http.Request) bool { return true } is an extremely common pattern
 * in Go tutorials and StackOverflow answers. This disables CORS origin
 * checking for WebSocket connections, enabling cross-site WebSocket hijacking
 * (CWE-346). The Upgrader.Upgrade() call itself is INGRESS because it
 * transitions from HTTP to a persistent bidirectional channel — any data
 * read from the WebSocket is user-controlled and tainted.
 *
 * 10 entries below. All are NET NEW (not duplicates of existing go.ts entries).
 */
export const PHONEMES_GO_WEB_DEEP = {

  // ── 1. chi.NewRouter — chi router instantiation ────────────────────────
  // chi.NewRouter() creates a lightweight, idiomatic HTTP router.
  // chi is the #2 Go router (after gin) with 18k+ GitHub stars.
  // It's compatible with net/http, so handlers are standard
  // http.HandlerFunc signatures. STRUCTURAL/route because it defines
  // the application's URL topology.
  'chi.NewRouter': { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },

  // ── 2. chi.URLParam — path parameter extraction ────────────────────────
  // chi.URLParam(r, "userID") extracts named URL parameters from the
  // route pattern (e.g., /users/{userID}). The return value is directly
  // user-controlled — an attacker sets it by crafting the URL path.
  // This is INGRESS/http_request + tainted:true because the extracted
  // value flows into handler logic unsanitized. Common injection vector
  // when used in SQL queries or file paths without validation.
  'chi.URLParam': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 3. mux.Vars — gorilla/mux path parameter extraction ───────────────
  // mux.Vars(r)["id"] extracts ALL named route variables as a map.
  // gorilla/mux is the OG Go router (20k+ stars, now archived but still
  // in ~30% of production Go web apps). Every value in the returned map
  // is attacker-controlled. INGRESS/http_request + tainted:true.
  // Particularly dangerous because the map access pattern (mux.Vars(r)["key"])
  // makes it easy to miss in code review — it looks like a simple map read.
  'mux.Vars': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 4. websocket.Upgrader.Upgrade — HTTP to WebSocket upgrade ─────────
  // upgrader.Upgrade(w, r, nil) upgrades an HTTP connection to WebSocket.
  // This is a protocol transition: the response becomes a persistent,
  // bidirectional channel. The returned *websocket.Conn is the new
  // INGRESS point — all subsequent reads are user-controlled.
  // The Upgrade itself is INGRESS because it establishes the channel
  // through which tainted data will flow. If CheckOrigin is permissive,
  // it's also CWE-346 (cross-site WebSocket hijacking).
  'upgrader.Upgrade': { nodeType: 'INGRESS', subtype: 'websocket', tainted: true },

  // ── 5. conn.ReadMessage — WebSocket message read ──────────────────────
  // _, msg, err := conn.ReadMessage() reads the next message from a
  // WebSocket connection. The message content is 100% attacker-controlled.
  // This is the WebSocket equivalent of r.Body — it's the primary INGRESS
  // point for data in WebSocket-based applications. tainted:true because
  // the returned bytes are raw user input.
  'conn.ReadMessage': { nodeType: 'INGRESS', subtype: 'websocket', tainted: true },

  // ── 6. conn.WriteMessage — WebSocket message write ────────────────────
  // conn.WriteMessage(websocket.TextMessage, data) sends data to the
  // client over WebSocket. This is EGRESS — data leaving the server.
  // If the data contains unsanitized user input from another source,
  // it can enable XSS in browser-based WebSocket clients that render
  // messages as HTML (CWE-79). Also relevant for data exfiltration.
  'conn.WriteMessage': { nodeType: 'EGRESS', subtype: 'websocket', tainted: false },

  // ── 7. html.Parse — golang.org/x/net/html parsing ─────────────────────
  // doc, err := html.Parse(reader) parses HTML into a node tree.
  // golang.org/x/net/html is the semi-official Go HTML parser (part of
  // the x/ extended stdlib). Parsing untrusted HTML is the first step in
  // sanitization pipelines — but the parsed tree itself may contain
  // dangerous nodes (script tags, event handlers, javascript: URLs).
  // TRANSFORM/parse because it converts raw HTML bytes into a structured
  // tree. tainted:true because the output retains dangerous content.
  'html.Parse': { nodeType: 'TRANSFORM', subtype: 'parse', tainted: true },

  // ── 8. html.Render — golang.org/x/net/html rendering ──────────────────
  // html.Render(w, doc) serializes an HTML node tree back to bytes.
  // If the tree was built from untrusted input (html.Parse) and not
  // sanitized, Render outputs the dangerous content verbatim.
  // TRANSFORM/format because it converts a tree structure to a string.
  // The security relevance is that Render does NOT sanitize — it's a
  // faithful serializer. Any XSS payloads in the tree survive Render.
  'html.Render': { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },

  // ── 9. httputil.NewSingleHostReverseProxy — SSRF vector ────────────────
  // httputil.NewSingleHostReverseProxy(targetURL) creates a reverse proxy.
  // This is one of the most dangerous functions in Go's stdlib for SSRF:
  // - If targetURL comes from user input: direct SSRF (CWE-918)
  // - Even with hardcoded target: forwards auth headers to backend
  // - The proxy copies ALL request headers by default
  // - Can reach internal services (169.254.169.254, localhost, etc.)
  // EXTERNAL/proxy because it forwards requests to another host.
  // This is the Go equivalent of nginx proxy_pass — but in application code.
  'httputil.NewSingleHostReverseProxy': { nodeType: 'EXTERNAL', subtype: 'proxy', tainted: false },

  // ── 10. proxy.ServeHTTP — reverse proxy execution ─────────────────────
  // proxy.ServeHTTP(w, r) executes the reverse proxy, forwarding the
  // request to the backend. This is where the actual network call happens.
  // The full request (URL path, query params, headers, body) is sent to
  // the target host. EXTERNAL/proxy because it's the execution point
  // of the proxy — the moment data leaves your server for another.
  // Splitting creation (NewSingleHostReverseProxy) from execution
  // (ServeHTTP) lets DST track the full taint flow.
  'proxy.ServeHTTP': { nodeType: 'EXTERNAL', subtype: 'proxy', tainted: false },
};
