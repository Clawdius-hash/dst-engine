/**
 * Phoneme expansion: Kotlin — Ktor framework, Android SDK security patterns
 * Agent-generated, tested against real patterns
 *
 * Focus: WebView sinks, Intent extras ingress, ContentResolver queries,
 * Ktor multipart/WebSocket ingress, Android deep link handling.
 *
 * These patterns fill gaps in languages/kotlin.ts which already covers:
 *   call.receive, call.parameters, call.respond, Runtime.getRuntime.exec,
 *   SharedPreferences.getString/getInt/getBoolean, basic Ktor routing.
 */
export const PHONEMES_KOTLIN_KTOR_ANDROID = {

  // ── INGRESS: Intent extras — the #1 Android IPC attack surface ──
  // Any exported Activity/Service/BroadcastReceiver that reads intent extras
  // without validation is exploitable via crafted intents (CWE-926, CWE-927).
  'intent.getStringExtra':     { nodeType: 'INGRESS', subtype: 'ipc_read', tainted: true },
  // Why: Attacker-controlled string data arrives via inter-app communication;
  // flows unvalidated into SQL, WebView, or file paths in most real exploits.

  'intent.data':               { nodeType: 'INGRESS', subtype: 'ipc_read', tainted: true },
  // Why: intent.data carries deep link URIs — the primary injection vector for
  // open-redirect and path-traversal in Android apps (CWE-939, CWE-22).

  // ── INGRESS: ContentResolver — structured data from other apps ──
  'ContentResolver.query':     { nodeType: 'INGRESS', subtype: 'ipc_read', tainted: true },
  // Why: Queries content providers owned by other apps; returned Cursor data is
  // attacker-controlled if the provider is malicious (confused deputy, CWE-926).

  // ── EGRESS/EXTERNAL: WebView.loadUrl — JavaScript bridge sink ──
  'WebView.loadUrl':           { nodeType: 'EXTERNAL', subtype: 'webview_nav', tainted: false },
  // Why: Loading attacker-controlled URLs into a WebView with JS enabled is
  // equivalent to XSS in a browser with access to native Java/Kotlin bridges
  // (CWE-749). This is the single most exploited Android client-side sink.

  'WebView.evaluateJavascript': { nodeType: 'EXTERNAL', subtype: 'webview_exec', tainted: false },
  // Why: Injects arbitrary JavaScript into the WebView context; if the JS string
  // contains tainted data, it's a direct code injection sink (CWE-94).

  // ── INGRESS: Ktor multipart — file upload handling ──
  'call.receiveMultipart':     { nodeType: 'INGRESS', subtype: 'file_upload', tainted: true },
  // Why: Ktor's multipart receive returns PartData with attacker-controlled
  // filenames and content; path traversal via filename is a classic vuln (CWE-22).

  // ── INGRESS: Ktor WebSocket — persistent bidirectional tainted input ──
  'incoming.receive':          { nodeType: 'INGRESS', subtype: 'websocket_read', tainted: true },
  // Why: In Ktor WebSocket handlers (webSocket { for (frame in incoming) ... }),
  // each frame is attacker-controlled input that persists across the connection.

  // ── STORAGE: Android SQLite raw queries — parameterization bypass ──
  'database.rawQuery':         { nodeType: 'STORAGE', subtype: 'sql', tainted: false },
  // Why: rawQuery accepts a raw SQL string; if tainted data is interpolated
  // instead of using selectionArgs, it's a direct SQL injection (CWE-89).
  // Room's @RawQuery has the same risk but is harder to misuse.

  // ── EGRESS: Android startActivity — intent forwarding / open redirect ──
  'startActivity':             { nodeType: 'EGRESS', subtype: 'ipc_send', tainted: false },
  // Why: If the Intent passed to startActivity is built from tainted extras or
  // deep link data, an attacker can redirect the user to arbitrary activities
  // including those in other apps (intent redirection, CWE-926).

  // ── AUTH: Ktor session — server-side session identity ──
  // NOTE: Ktor sessions can be client-side (cookie) or server-side (storage).
  // Client-side sessions with HMAC signing are common but the session data
  // itself should still be treated as potentially tampered if signing is weak.
  'call.sessions.get':         { nodeType: 'AUTH', subtype: 'session_read', tainted: false },
  // Why: Reading the current session identity; if session configuration uses
  // unsigned cookies, this data is attacker-controlled (session fixation, CWE-384).

} as const;
