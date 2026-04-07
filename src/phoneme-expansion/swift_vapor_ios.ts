/**
 * Phoneme expansion: Swift — Vapor web framework, iOS security patterns
 * Agent-generated, tested against real patterns
 *
 * Focus: server-side Vapor gaps, iOS banking-app attack surfaces
 * (URLSession, Keychain, CryptoKit, WKWebView, insecure deserialization)
 *
 * None of these duplicate entries in languages/swift.ts (verified against
 * that file's DIRECT_CALLS and MEMBER_CALLS dictionaries).
 */
export const PHONEMES_SWIFT_VAPOR_IOS = {

  // ── 1. Vapor: single-field content extraction ─────────────────────────
  // req.content.get("email") pulls one tainted field from the HTTP body.
  // Distinct from req.content.decode which decodes the entire body into a
  // Codable struct. Developers use .get for quick one-off reads and often
  // skip validation because "it's just one field."
  'req.content.get': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 2. Vapor / Fluent: raw SQL execution ──────────────────────────────
  // SQLDatabase.raw("SELECT * FROM users WHERE id = \(untrusted)")
  // This is THE SQL injection vector in Vapor apps. Fluent's query builder
  // is safe, but .raw() bypasses it entirely. Every Vapor SQLi CVE traces
  // back to string interpolation inside .raw().
  'SQLDatabase.raw': { nodeType: 'STORAGE', subtype: 'sql', tainted: false },

  // ── 3. Vapor: WebSocket text ingress ──────────────────────────────────
  // ws.onText { ws, text in ... } — the text parameter is fully attacker-
  // controlled. Real-time features (chat, trading feeds) in banking apps
  // use this. The callback receives raw untrusted strings.
  'ws.onText': { nodeType: 'INGRESS', subtype: 'websocket_read', tainted: true },

  // ── 4. iOS: insecure deserialization (CWE-502) ────────────────────────
  // NSKeyedUnarchiver.unarchiveObject(withData:) deserializes arbitrary
  // object graphs. If the data came from the network, an attacker controls
  // which classes get instantiated. Apple deprecated this in favor of
  // unarchivedObject(ofClass:from:) which requires NSSecureCoding. Banking
  // apps that still use the old API are vulnerable to RCE.
  'NSKeyedUnarchiver.unarchiveObject': { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // ── 5. iOS: WebSocket via URLSession (async) ──────────────────────────
  // URLSessionWebSocketTask.receive() returns .string or .data messages
  // from a remote server. This is the modern Foundation API for WebSockets
  // (no third-party libs). Response data is tainted — it's network input.
  'URLSessionWebSocketTask.receive': { nodeType: 'INGRESS', subtype: 'websocket_read', tainted: true },

  // ── 6. iOS: WKWebView local file loading ──────────────────────────────
  // WKWebView.loadFileURL(_:allowingReadAccessTo:) opens local files in
  // the web view. If the URL is attacker-influenced (e.g., deep link with
  // a file:// path), it can expose sandbox contents. The second parameter
  // controls the read scope — developers routinely pass the Documents
  // directory, granting JS access to everything in it.
  'WKWebView.loadFileURL': { nodeType: 'EGRESS', subtype: 'xss_sink', tainted: false },

  // ── 7. iOS: Security.framework digital signing ────────────────────────
  // SecKeyCreateSignature creates a digital signature using a private key
  // stored in the Secure Enclave or Keychain. This is how banking apps
  // sign transaction payloads. Misuse (wrong algorithm, exported key)
  // breaks the entire transaction integrity model.
  'SecKeyCreateSignature': { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },

  // ── 8. iOS: Keychain query construction ───────────────────────────────
  // SecItemCopyMatching is already covered for reads. But the query
  // dictionary itself often gets built with kSecAttrAccessible set to
  // kSecAttrAccessibleAlways (insecure) instead of
  // kSecAttrAccessibleWhenUnlockedThisDeviceOnly. We track SecItemAdd
  // as AUTH already, but SecAccessControl.init is where the access policy
  // is actually defined — and where banking apps get it wrong.
  // NOTE: This is a FLAG, not a standard phoneme. SecAccessControl
  // doesn't fit cleanly into the 10 types — it's "security policy
  // configuration" which is META-adjacent but has AUTH consequences.
  'SecAccessControl.init': { nodeType: 'AUTH', subtype: 'access_policy', tainted: false },

  // ── 9. Vapor: session data read ───────────────────────────────────────
  // req.session.data["userId"] reads from the server-side session store.
  // While session values are server-stored (not directly user-tainted),
  // they were originally SET from user input in a previous request. Treat
  // as tainted: session fixation attacks can inject arbitrary values.
  'req.session.data': { nodeType: 'INGRESS', subtype: 'session_read', tainted: true },

  // ── 10. iOS: App Transport Security exception check ───────────────────
  // URLSession will silently downgrade to HTTP if Info.plist contains
  // NSAllowsArbitraryLoads = true. We can't see the plist from code
  // analysis alone, but URLProtocol.registerClass is how apps intercept
  // URL loading — it's the runtime equivalent of ATS bypass. Custom
  // URLProtocol subclasses can strip TLS, log credentials, or redirect
  // traffic. Every iOS MITM framework uses this.
  'URLProtocol.registerClass': { nodeType: 'EXTERNAL', subtype: 'network_intercept', tainted: false },

} as const;
