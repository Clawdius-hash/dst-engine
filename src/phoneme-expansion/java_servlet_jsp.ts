/**
 * Phoneme expansion: Java — Servlet API deep, RequestDispatcher, FilterChain, JSP/JSTL,
 * cookie manipulation, session management
 * Agent-generated, tested against real patterns
 *
 * WHY THESE 10:
 * The base java.ts covers HttpServletRequest parameter/header/body methods and the basic
 * response methods (getWriter, sendRedirect, addCookie, etc.). But the Servlet API has
 * deeper surfaces that the scanner must understand to catch real vulnerabilities:
 *
 *   1. RequestDispatcher.forward — internal server-side dispatch. If the path to
 *      getRequestDispatcher() comes from user input, it's a server-side request forgery
 *      within the application. Attacker can force the app to render arbitrary JSPs or
 *      hit internal servlets. CWE-441 (Unintended Proxy). This caused CVE-2018-11784
 *      in Apache Tomcat (open redirect via RequestDispatcher).
 *
 *   2. RequestDispatcher.include — includes another resource's output in the current
 *      response. Used heavily in JSP composition (<jsp:include>). If the include path
 *      is user-controlled, attacker can include arbitrary internal resources, leaking
 *      admin pages, config files, or internal state into the response.
 *
 *   3. request.getRequestDispatcher — the INGRESS side of dispatch. Returns a
 *      RequestDispatcher for a given path. This is where the user-controlled path
 *      enters the dispatch chain. Must be tracked as tainted because the path
 *      argument determines WHICH resource gets forwarded/included to.
 *
 *   4. FilterChain.doFilter — the backbone of servlet filter architecture. Every
 *      security filter (authentication, CSRF protection, input validation, rate limiting)
 *      implements javax.servlet.Filter and calls chain.doFilter() to continue the chain.
 *      This is a CONTROL node because it IS the enforcement mechanism. If a filter
 *      fails to call doFilter(), the request is blocked. If it calls doFilter() without
 *      proper checks, the security layer is bypassed.
 *
 *   5. request.getServletPath — returns the URL path that matched the servlet mapping.
 *      Used in path-based authorization ("if path starts with /admin, check role").
 *      Missing from the base dictionary. Tainted because the user controls the URL
 *      and path normalization bugs (double encoding, path traversal) exploit this.
 *
 *   6. request.getContextPath — returns the context path prefix. Frequently concatenated
 *      into redirect URLs: response.sendRedirect(request.getContextPath() + "/login").
 *      Reverse proxy misconfigurations can allow user-controlled context paths. More
 *      importantly, it's used to construct URLs that appear in HTML — if the context
 *      path is reflected unsanitized, it's a reflected XSS vector (CWE-79).
 *
 *   7. session.setAttribute — stores data in HttpSession server-side. If tainted user
 *      input is stored in the session (e.g., session.setAttribute("username", userInput)),
 *      it becomes a stored injection vector. When another page reads it back via
 *      getAttribute and renders it, it's stored XSS. Session poisoning (CWE-384/CWE-472)
 *      is the broader class of attacks here.
 *
 *   8. session.getAttribute — reads from HttpSession. Developers often trust session data
 *      because "it's server-side" — but if tainted data was stored via setAttribute,
 *      it's still tainted on retrieval. The scanner needs to track taint THROUGH the
 *      session: setAttribute(tainted) → getAttribute() returns tainted.
 *
 *   9. session.invalidate — destroys the HTTP session. This is the logout mechanism.
 *      If missing from a logout endpoint, the session remains valid = session fixation
 *      (CWE-384). The presence or absence of this call in logout handlers is a direct
 *      security indicator. AUTH/session_destroy because it terminates the auth context.
 *
 *  10. Cookie.getValue — extracts the string value from a Cookie object. getCookies()
 *      (already in base dict) returns the Cookie[] array, but getValue() is where the
 *      actual tainted string materializes in application code. Developers iterate
 *      getCookies(), find the cookie by name, then call getValue(). The value is
 *      user-controlled (sent in the Cookie header) and must be treated as tainted.
 *      Common vector: JSESSIONID manipulation, JWT in cookies, preference injection.
 *
 * CRITICAL NOTES:
 *
 * On JSP/JSTL: Most JSP vulnerabilities are in Expression Language (EL) and tag-based
 * patterns (<c:out>, ${param.name}), not method calls. EL injection (CWE-917) happens
 * when user input is evaluated as an EL expression: ${userInput} in a JSP page.
 * This is fundamentally a template injection, not a callee pattern. The scanner would
 * need JSP-specific parsing to catch these. However, the METHOD-CALL surfaces that
 * feed JSP are covered: request.getAttribute (model data), session.getAttribute
 * (session data), and RequestDispatcher.forward (which triggers JSP rendering).
 *
 * On FilterChain: Servlet filters are the primary mechanism for cross-cutting security
 * concerns in Java web apps. The typical pattern is:
 *   public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
 *       if (securityCheck(req)) {
 *           chain.doFilter(req, res);  // continue — security check passed
 *       } else {
 *           ((HttpServletResponse)res).sendError(403);  // block
 *       }
 *   }
 * Marking doFilter as CONTROL/filter_chain tells the scanner "this is a security
 * gate" — the code BEFORE this call is the guard, the call itself is the pass-through.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JAVA_SERVLET_JSP: Record<string, CalleePattern> = {

  // ── 1. RequestDispatcher.forward — server-side request dispatch ────────
  // Transfers control to another servlet or JSP. The client never sees the
  // internal URL — the response comes from the forwarded resource. If the
  // path passed to getRequestDispatcher() was user-controlled, the attacker
  // chooses which internal resource processes the request.
  // This is CONTROL/dispatch because it controls request routing.
  'RequestDispatcher.forward':  { nodeType: 'CONTROL', subtype: 'dispatch', tainted: false },

  // ── 2. RequestDispatcher.include — server-side resource inclusion ──────
  // Includes another resource's output in the current response. Unlike forward,
  // the original servlet retains control and can write before/after the include.
  // <jsp:include page="/header.jsp" /> compiles to RequestDispatcher.include().
  // User-controlled include paths = internal resource disclosure.
  'RequestDispatcher.include':  { nodeType: 'CONTROL', subtype: 'dispatch', tainted: false },

  // ── 3. request.getRequestDispatcher — dispatch path resolution ─────────
  // Returns a RequestDispatcher for the given path. The path argument is the
  // security-sensitive input: getRequestDispatcher(userInput).forward(req, res)
  // is a server-side open redirect. Marked tainted because the PATH being
  // dispatched to is the attack surface — the method resolves user intent to
  // an internal resource.
  'request.getRequestDispatcher': { nodeType: 'CONTROL', subtype: 'dispatch', tainted: true },

  // ── 4. FilterChain.doFilter — security filter continuation ─────────────
  // The core method that passes the request through the filter chain. Every
  // authentication filter, CSRF filter, input validation filter, and rate
  // limiter calls chain.doFilter() to allow the request through. The code
  // BEFORE this call is the security gate. Missing doFilter = request blocked.
  // Unconditional doFilter = security bypass.
  'FilterChain.doFilter':       { nodeType: 'CONTROL', subtype: 'filter_chain', tainted: false },

  // ── 5. request.getServletPath — URL path matching the servlet ──────────
  // Returns the portion of the URL that matched the servlet mapping. Used in
  // path-based access control: if (path.startsWith("/admin")) checkAdmin();
  // Tainted because the user controls the request URL. Path normalization
  // attacks (double encoding %252F, null bytes, ../ traversal) exploit
  // inconsistencies between how getServletPath normalizes and how the
  // authorization check parses the path.
  'request.getServletPath':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 6. request.getContextPath — application context prefix ─────────────
  // Returns the context path of the web application (e.g., "/myapp"). Commonly
  // concatenated into URLs: response.sendRedirect(ctx + "/dashboard"). In
  // reverse proxy setups, a misconfigured X-Forwarded-Prefix can allow user
  // control of the context path. Even without proxy manipulation, the context
  // path is reflected in URLs that appear in HTML — XSS if unsanitized.
  'request.getContextPath':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 7. session.setAttribute — server-side session storage ──────────────
  // Stores a named attribute in the HttpSession. If tainted user input is
  // stored (session.setAttribute("name", request.getParameter("name"))),
  // the session becomes a tainted data store. Any later getAttribute("name")
  // returns the tainted value. This is STORAGE because it writes to the
  // server-side session store (memory, Redis, JDBC — depends on config).
  'session.setAttribute':       { nodeType: 'STORAGE', subtype: 'session_write', tainted: false },

  // ── 8. session.getAttribute — server-side session read ─────────────────
  // Reads a named attribute from the HttpSession. Developers frequently trust
  // session data ("it's server-side"), but if the attribute was stored from
  // tainted input, it's still tainted. The scanner should propagate taint:
  // if setAttribute was called with tainted data, getAttribute returns tainted.
  // Marked tainted:true because the session is a cross-request data store —
  // the data may have been tainted in a PREVIOUS request.
  'session.getAttribute':       { nodeType: 'STORAGE', subtype: 'session_read', tainted: true },

  // ── 9. session.invalidate — session destruction (logout) ───────────────
  // Destroys the HTTP session and unbinds all attributes. This is the correct
  // way to implement logout. If a logout endpoint does NOT call invalidate(),
  // the session remains valid and can be reused = session fixation (CWE-384).
  // AUTH/session_destroy because it terminates the authentication context.
  // The scanner should check that logout handlers include this call.
  'session.invalidate':         { nodeType: 'AUTH', subtype: 'session_destroy', tainted: false },

  // ── 10. Cookie.getValue — cookie value extraction ──────────────────────
  // Extracts the string value from a javax.servlet.http.Cookie object.
  // getCookies() (base dict) returns Cookie[]; getValue() returns the actual
  // tainted string. Typical pattern:
  //   for (Cookie c : request.getCookies()) {
  //       if ("token".equals(c.getName())) {
  //           String token = c.getValue();  // <-- tainted string materializes here
  //       }
  //   }
  // The value is sent in the Cookie HTTP header and is fully user-controlled.
  'Cookie.getValue':            { nodeType: 'INGRESS', subtype: 'cookie_read', tainted: true },

} as const;

// ─── FINDINGS ────────────────────────────────────────────────────────────
//
// 1. SESSION FIXATION GAP: The base dictionary has request.getSession as INGRESS,
//    which is semantically wrong. getSession() doesn't read user input — it either
//    returns the existing HttpSession or creates a new one. It's closer to
//    STRUCTURAL/session_init or RESOURCE/session because it allocates server resources.
//    However, from a security standpoint, the important thing is that getSession()
//    WITHOUT invalidate() in a post-login handler = session fixation (CWE-384).
//    The scanner should check: after authentication succeeds, is the old session
//    invalidated and a new one created? Pattern:
//      session.invalidate();
//      request.getSession(true);  // force new session
//    This is a flow analysis problem, not a phoneme problem, but worth noting.
//
// 2. JSP EXPRESSION LANGUAGE (EL) INJECTION: ${param.name} in a JSP directly
//    renders request parameters without escaping by default in JSP 2.0+. The
//    safe version is <c:out value="${param.name}"/> which escapes HTML. But
//    ${...} expressions can also execute methods: ${Runtime.getRuntime().exec(...)}.
//    EL injection (CWE-917) happens when user input is EVALUATED as EL, not just
//    rendered. This requires JSP template analysis, not callee pattern matching.
//    The phoneme dictionary can't catch this, but a JSP-specific scanner rule should.
//
// 3. COOKIE SECURITY ATTRIBUTES: Cookie.setSecure(true), Cookie.setHttpOnly(true),
//    and Cookie.setPath("/") are security-relevant configuration calls. Their
//    ABSENCE is the vulnerability (missing Secure flag = cookie sent over HTTP,
//    missing HttpOnly = accessible to JavaScript = XSS cookie theft). These are
//    META/config calls but their security value comes from absence detection, which
//    is outside the phoneme model (phonemes detect PRESENCE of calls, not absence).
//
// 4. SERVLET CONTEXT ATTRIBUTES: ServletContext.setAttribute/getAttribute is the
//    application-wide equivalent of session attributes. Data stored here is shared
//    across ALL users. If tainted data reaches ServletContext, it's a stored
//    injection affecting every user. Lower priority than session because it's less
//    common, but worth a future expansion entry.
//
// 5. request.getRemoteUser / request.getUserPrincipal: These return the
//    authenticated user's identity from the container-managed security realm.
//    They're already trustworthy (not tainted) because they come from the
//    container's authentication, not from user input. However, they're AUTH/identity
//    reads that the scanner should recognize. Currently missing from the base dict
//    (getRemoteAddr is there but not getRemoteUser). Worth a future entry.
