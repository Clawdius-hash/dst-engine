/**
 * Phoneme expansion: Java -- Android SDK
 * Scope: Intent handling, ContentProvider, BroadcastReceiver, SharedPreferences, WebView, BiometricPrompt
 * Agent-generated, tested against real patterns
 *
 * WHY THESE 10:
 * The base java.ts covers server-side Java (Servlet, Spring, JDBC, JPA). But Android is a massive
 * Java/Kotlin attack surface with its own unique data flow patterns. Android apps receive tainted
 * data through Intents (IPC), ContentProviders (cross-app data), and BroadcastReceivers (system
 * events). These are not HTTP requests -- they are inter-process communication channels that any
 * app on the device can target. The scanner must recognize these as INGRESS points or it will miss
 * entire classes of Android vulnerabilities:
 *
 *   1. Intent.getStringExtra() / Intent.getData() -- Tainted IPC input. Any app can send an Intent
 *      to an exported Activity/Service. If the receiver trusts the extras without validation, it's
 *      a classic Android injection vector (CVE-2014-6041 and hundreds of others).
 *
 *   2. ContentResolver.query() -- Cross-app data access via ContentProviders. A malicious app can
 *      craft a URI to query another app's ContentProvider. SQL injection in ContentProvider.query()
 *      implementations is a known class of Android vulns.
 *
 *   3. BroadcastReceiver.onReceive() -- System and app broadcasts deliver Intents to receivers.
 *      Exported receivers accept broadcasts from ANY app. The Intent payload is fully tainted.
 *
 *   4. SharedPreferences.getString() / Editor.putString() -- Local key-value storage. Not encrypted
 *      by default. On rooted devices or via backup extraction, SharedPreferences XML files are
 *      readable. Storing tokens/passwords here without EncryptedSharedPreferences is CWE-312.
 *
 *   5. WebView.loadUrl() -- Loads a URL in an embedded browser. If the URL is tainted (from an
 *      Intent extra, for example), it's an open redirect or XSS vector. With JavaScript enabled
 *      and addJavascriptInterface(), it becomes RCE (CVE-2012-6636 on Android < 4.2).
 *
 *   6. WebView.addJavascriptInterface() -- Exposes Java objects to JavaScript running in the
 *      WebView. On Android < 4.2, reflection allowed arbitrary code execution. Even on modern
 *      Android, it creates a bridge where malicious JS can call Java methods -- EXTERNAL territory.
 *
 *   7. WebView.evaluateJavascript() -- Executes arbitrary JavaScript in the WebView context.
 *      If the JS string is built from tainted input, it's script injection.
 *
 *   8. BiometricPrompt.authenticate() -- Biometric authentication gate. If the callback result
 *      is not properly validated, or if the CryptoObject is not bound to the operation, the
 *      biometric check can be bypassed (Frida hooks on onAuthenticationSucceeded).
 *
 *   9. Intent.getExtras() -- Returns the full Bundle of extras from an IPC Intent. Every key-value
 *      pair in the bundle is attacker-controlled when the Intent comes from another app.
 *
 *  10. ContentProvider.query() -- The server side of ContentProvider: receives queries from other
 *      apps. The selection and selectionArgs parameters are attacker-controlled. If the
 *      implementation concatenates selection into raw SQL, it's SQL injection.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JAVA_ANDROID_SDK: Record<string, CalleePattern> = {

  // -- 1. Intent.getStringExtra -- tainted IPC input from other apps ------
  // Any app can send an Intent to an exported component. The extra values
  // are fully attacker-controlled. This is the primary INGRESS for Android IPC.
  'Intent.getStringExtra':  { nodeType: 'INGRESS',  subtype: 'android_ipc',       tainted: true },

  // -- 2. Intent.getData -- URI from incoming Intent ----------------------
  // Returns the data URI attached to the Intent. Deep links, app links, and
  // inter-app calls pass URIs here. Tainted: the sender controls the URI.
  'Intent.getData':         { nodeType: 'INGRESS',  subtype: 'android_ipc',       tainted: true },

  // -- 3. Intent.getExtras -- full Bundle of IPC parameters ---------------
  // Returns all extras as a Bundle. Every key-value pair is attacker-controlled
  // when the Intent originates from an external app.
  'Intent.getExtras':       { nodeType: 'INGRESS',  subtype: 'android_ipc',       tainted: true },

  // -- 4. BroadcastReceiver.onReceive -- broadcast Intent delivery --------
  // Called when a broadcast is received. Exported receivers accept broadcasts
  // from ANY app. The Intent parameter carries tainted data.
  'BroadcastReceiver.onReceive': { nodeType: 'INGRESS', subtype: 'android_broadcast', tainted: true },

  // -- 5. ContentProvider.query -- server-side content query (SQL risk) ---
  // Receives queries from other apps via ContentResolver. The selection param
  // is attacker-controlled. Naive implementations concatenate it into SQL.
  'ContentProvider.query':  { nodeType: 'STORAGE',  subtype: 'android_content',   tainted: true },

  // -- 6. ContentResolver.query -- client-side cross-app data access ------
  // Queries another app's ContentProvider via URI. The result cursor contains
  // data from an external source -- second-order taint.
  'ContentResolver.query':  { nodeType: 'STORAGE',  subtype: 'android_content',   tainted: true },

  // -- 7. SharedPreferences.getString -- local unencrypted storage read ---
  // Reads from XML-backed key-value store. Not encrypted by default. On rooted
  // devices or via adb backup, these files are trivially extractable (CWE-312).
  'SharedPreferences.getString': { nodeType: 'STORAGE', subtype: 'android_prefs', tainted: false },

  // -- 8. WebView.loadUrl -- load URL in embedded browser -----------------
  // If the URL comes from tainted input (Intent extra, deep link), this is an
  // open redirect or XSS vector. With JS enabled, it's worse.
  'WebView.loadUrl':        { nodeType: 'EXTERNAL', subtype: 'android_webview',   tainted: false },

  // -- 9. WebView.addJavascriptInterface -- Java-to-JS bridge -------------
  // Exposes Java methods to JavaScript. Pre-4.2: reflection RCE (CVE-2012-6636).
  // Post-4.2: still creates an attack surface where malicious JS calls Java code.
  'WebView.addJavascriptInterface': { nodeType: 'EXTERNAL', subtype: 'android_webview_bridge', tainted: false },

  // -- 10. BiometricPrompt.authenticate -- biometric auth gate ------------
  // Triggers fingerprint/face authentication. Security depends on proper
  // CryptoObject binding. Without it, the callback can be spoofed via Frida.
  'BiometricPrompt.authenticate': { nodeType: 'AUTH', subtype: 'android_biometric', tainted: false },

} as const;

// --- FINDINGS ---
//
// 1. MISSING FROM SCOPE: SharedPreferences.Editor.putString() is a STORAGE/write
//    but I chose to include SharedPreferences.getString() (read) over the write
//    because reading untrusted stored data is the more dangerous taint flow.
//    putString() is a write sink, but the real vulnerability is what was stored
//    (plaintext credentials) and who can read it (any app on rooted device).
//    Both should eventually be in the dictionary.
//
// 2. WebView.evaluateJavascript() is another EXTERNAL/EGRESS pattern -- it
//    executes JS code in the WebView context. If the JS string is built from
//    tainted input, it's script injection. Omitted to stay at 10 entries but
//    should be added in a future expansion.
//
// 3. ANDROID-SPECIFIC TAINT MODEL: Unlike server-side Java where taint enters
//    via HTTP (request.getParameter), Android taint enters via IPC (Intent extras,
//    ContentProvider queries, BroadcastReceiver callbacks). The scanner's taint
//    propagation must treat these as equivalent to request parameters. The current
//    DST model handles this correctly because tainted:true on these entries will
//    mark them as taint sources regardless of the transport mechanism.
//
// 4. ContentProvider.query() is interesting because it's BOTH a STORAGE node
//    (it accesses a database) AND an INGRESS point (the query parameters come
//    from an external app). I typed it as STORAGE with tainted:true to capture
//    both aspects -- the scanner sees it touches data at rest AND the input is
//    attacker-controlled.
