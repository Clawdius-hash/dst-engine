/**
 * Phoneme expansion: Java — Spring MVC Deep (ModelAndView, RedirectView, ResponseEntity builders,
 * @CrossOrigin, RestTemplate/WebClient gaps, Spring Validation, Actuator, Property Injection)
 * Agent-generated, tested against real patterns
 *
 * WHY THESE 10:
 * The base java.ts covers Spring MVC routing annotations (@GetMapping etc.), ResponseEntity
 * static builders (.ok/.notFound/.badRequest/.created/.noContent/.status), RestTemplate
 * (7 methods), WebClient (6 methods), and Validator.validate. But it misses the deep
 * Spring MVC patterns that cause real security issues in production:
 *
 *   1. ModelAndView — Spring MVC's classic view+model return type. When tainted data is
 *      added via addObject() and the view is a template engine (Thymeleaf, FreeMarker,
 *      Velocity), unescaped model attributes become XSS or Server-Side Template Injection
 *      (SSTI) vectors. ModelAndView IS the bridge from controller to view. If the view
 *      NAME is user-controlled ("redirect:" + userInput), it's an open redirect.
 *
 *   2. RedirectView — explicit redirect. new RedirectView(url) sends a 302 to the client.
 *      If url comes from user input (request.getParameter("returnUrl")), it's CWE-601
 *      (open redirect). Unlike response.sendRedirect (already in dict), RedirectView is
 *      the Spring-idiomatic way and appears in more modern codebases.
 *
 *   3. ResponseEntity.accepted — missing from the base dict. 202 Accepted is common in
 *      async APIs. Completing the builder set matters because ResponseEntity is the primary
 *      EGRESS path in REST controllers.
 *
 *   4. @CrossOrigin — annotation that sets CORS policy on a controller or method.
 *      @CrossOrigin(origins = "*") opens the endpoint to all origins, enabling cross-site
 *      data theft. This is STRUCTURAL/security_config because it defines the CORS topology.
 *      Misconfigured CORS is consistently in the OWASP Top 10 (Security Misconfiguration).
 *
 *   5. RestTemplate.patchForObject — the PATCH HTTP method is missing from the base dict.
 *      RestTemplate has 7 entries but skipped PATCH. PATCH is common in REST APIs for
 *      partial updates. Same EXTERNAL/api_call type as the other RestTemplate methods.
 *
 *   6. WebClient.builder — the factory for creating WebClient instances. WebClient.create()
 *      is already in the dict, but builder() is the more common pattern because it allows
 *      setting baseUrl, default headers, filters, etc. A misconfigured builder (wrong
 *      baseUrl, missing auth headers) affects all requests made through that client.
 *
 *   7. BindingResult.hasErrors — the validation CHECK point in Spring MVC. When @Valid is
 *      on a parameter, Spring populates BindingResult with constraint violations. If the
 *      controller doesn't call hasErrors() (or calls it and ignores the result), invalid
 *      data flows to business logic unchecked. This is CONTROL/validation because it's the
 *      gate between tainted input and the application. The ABSENCE of this call after @Valid
 *      is a finding — it means validation results are being silently discarded.
 *
 *   8. @Value — Spring property injection annotation. @Value("${db.password}") injects
 *      config values from application.properties/yml, environment variables, or Spring
 *      Cloud Config. This is the primary way Spring apps read secrets at field level.
 *      META/config because it defines how configuration flows into the application.
 *      Security relevance: exposes which fields hold secrets, and SpEL in @Value (rare
 *      but possible: @Value("#{systemProperties['user.home']}")) is an eval surface.
 *
 *   9. ManagementEndpoint (Actuator /env) — Spring Boot Actuator's /actuator/env endpoint
 *      exposes ALL environment variables and configuration properties, including database
 *      passwords, API keys, and cloud credentials. If exposed without authentication
 *      (the default in Spring Boot < 2.0), it's a secret leak. Actuator endpoints are
 *      the #1 source of Spring Boot information disclosure CVEs.
 *      EGRESS/config_exposure because it sends config data OUT to the caller.
 *
 *  10. ManagementEndpoint (Actuator /health) — /actuator/health exposes application
 *      status, database connectivity, disk space, and custom health indicators. While
 *      less dangerous than /env, it provides reconnaissance data (which databases are
 *      connected, which services are up/down). In Spring Boot 2.x+ only /health and
 *      /info are exposed by default, but /health/details can reveal connection strings.
 *      META/config because it's metadata about the running system.
 *
 * DESIGN DECISIONS:
 *
 * - ModelAndView is EGRESS (not TRANSFORM) because its primary purpose is sending data
 *   to the view layer — it's the controller-to-template EGRESS channel. The model data
 *   is rendered into HTTP responses. addObject() adds data to the outbound payload.
 *
 * - RedirectView is EGRESS (not CONTROL) because redirect IS an HTTP response. The browser
 *   receives a 302 + Location header. It's output, not logic.
 *
 * - BindingResult.hasErrors is CONTROL (not META) because it's a validation gate — a
 *   conditional that determines whether tainted input proceeds or is rejected.
 *
 * - Actuator /env is EGRESS (not META) because it actively SENDS sensitive data out over
 *   HTTP. The scanner should flag any exposed actuator endpoint as an egress of secrets.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JAVA_SPRING_MVC: Record<string, CalleePattern> = {

  // ── 1. ModelAndView — controller-to-view EGRESS channel ────────────────
  // new ModelAndView("userProfile", "user", userData) sends model data to
  // the template engine. If userData contains tainted input and the template
  // doesn't escape it, XSS. If the view name is "redirect:" + userInput,
  // open redirect. addObject("key", taintedValue) is the injection point.
  // ModelAndView is the CLASSIC Spring MVC return type (pre-ResponseEntity era).
  'ModelAndView.addObject':     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // ── 2. RedirectView — open redirect vector ─────────────────────────────
  // new RedirectView(request.getParameter("returnUrl")) = CWE-601.
  // Spring-idiomatic redirect. Unlike "redirect:" prefix in view names,
  // RedirectView is an explicit class instantiation — easier for the scanner
  // to detect because it's a constructor call, not a magic string prefix.
  'RedirectView':               { nodeType: 'EGRESS', subtype: 'http_redirect', tainted: false },

  // ── 3. ResponseEntity.accepted — 202 Accepted builder ─────────────────
  // Common in async REST APIs: return ResponseEntity.accepted().body(taskId).
  // Completing the ResponseEntity builder set. Without this, async endpoints
  // using .accepted() are invisible to the scanner's egress tracking.
  'ResponseEntity.accepted':    { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // ── 4. @CrossOrigin — CORS security configuration ─────────────────────
  // @CrossOrigin(origins = "*", allowCredentials = "true") is a critical
  // misconfiguration: it allows any origin to make credentialed requests,
  // enabling session hijacking via CSRF-like attacks from attacker domains.
  // @CrossOrigin without arguments defaults to allowing ALL origins.
  // This is the per-method/controller CORS override — it can WEAKEN the
  // global CORS config set in WebMvcConfigurer.addCorsMappings().
  'CrossOrigin':                { nodeType: 'STRUCTURAL', subtype: 'security_config', tainted: false },

  // ── 5. RestTemplate.patchForObject — missing HTTP PATCH method ─────────
  // The only RestTemplate method missing from the base dict. PATCH is standard
  // in REST APIs for partial resource updates (RFC 5789). Same security profile
  // as postForObject — sends data to an external service.
  'RestTemplate.patchForObject': { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // ── 6. WebClient.builder — WebClient factory with config ───────────────
  // WebClient.builder().baseUrl("https://api.example.com").defaultHeader(...)
  // .build() is the standard way to create configured WebClient instances.
  // WebClient.create() (already in dict) is the simple factory. builder() is
  // the configurable factory — it sets baseUrl, auth headers, timeouts, filters.
  // A misconfigured builder (http:// instead of https://, missing auth) affects
  // every request the built client makes.
  'WebClient.builder':          { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // ── 7. BindingResult.hasErrors — validation gate ───────────────────────
  // @PostMapping("/register")
  // public String register(@Valid UserForm form, BindingResult result) {
  //   if (result.hasErrors()) return "form";  // ← THIS CHECK
  //   userService.create(form);  // proceeds only if valid
  // }
  // If a controller accepts @Valid + BindingResult but never checks hasErrors(),
  // validation annotations (@NotNull, @Size, @Email, @Pattern) are evaluated
  // but their results are SILENTLY DISCARDED. The invalid data flows through.
  // This is the most common Spring validation bug — "I added @Valid but forgot
  // to check the BindingResult."
  'BindingResult.hasErrors':    { nodeType: 'CONTROL', subtype: 'validation', tainted: false },

  // ── 8. @Value — Spring property injection ──────────────────────────────
  // @Value("${spring.datasource.password}") private String dbPassword;
  // Injects configuration values from application.properties/yml, environment
  // variables, command-line args, or Spring Cloud Config Server.
  // Security relevance:
  //   (a) Reveals which fields hold secrets (dbPassword, apiKey, etc.)
  //   (b) SpEL in @Value is possible: @Value("#{T(java.lang.Runtime).getRuntime()}")
  //       though rare in practice — most devs use ${} (property placeholder) not #{}
  //   (c) Spring Cloud Config can inject from remote servers — if the config
  //       server is compromised, @Value-injected fields become attack vectors
  'Value':                      { nodeType: 'META', subtype: 'config', tainted: false },

  // ── 9. Actuator /env — environment/config exposure endpoint ────────────
  // GET /actuator/env returns ALL Spring Environment properties:
  //   { "propertySources": [{ "properties": { "spring.datasource.password": {...} }}]}
  // In Spring Boot 1.x, ALL actuator endpoints were exposed by default.
  // In Spring Boot 2.x+, only /health and /info are exposed by default, but
  // developers often add management.endpoints.web.exposure.include=* in dev
  // and forget to remove it in production.
  // CVE-2022-22947 (Spring Cloud Gateway RCE) exploited actuator endpoints.
  // EnvironmentEndpoint is the class behind /actuator/env.
  'EnvironmentEndpoint.environment': { nodeType: 'EGRESS', subtype: 'config_exposure', tainted: false },

  // ── 10. Actuator /health — system reconnaissance endpoint ─────────────
  // GET /actuator/health returns { "status": "UP", "components": { "db": {...}, "diskSpace": {...} }}
  // With show-details=always, it reveals database connection strings, Redis hosts,
  // Elasticsearch clusters, and custom health indicator details.
  // Less dangerous than /env but still provides reconnaissance for attackers:
  // which databases, which message brokers, which external services, are they healthy.
  'HealthEndpoint.health':      { nodeType: 'META', subtype: 'config', tainted: false },

} as const;

// ─── FINDINGS ────────────────────────────────────────────────────────────
//
// 1. REDIRECT PATTERN GAP: Spring MVC has THREE redirect mechanisms:
//    (a) return "redirect:/target" — magic prefix in view name string
//    (b) return new RedirectView("/target") — explicit class (covered above)
//    (c) response.sendRedirect("/target") — Servlet API (in base dict)
//    The scanner catches (b) and (c) but NOT (a) because "redirect:" is a
//    string prefix convention, not a method call or annotation. Detecting (a)
//    requires string literal analysis of return values from @Controller methods.
//    This is a real gap — most Spring MVC open redirect vulnerabilities use
//    pattern (a) because it's the shortest syntax.
//
// 2. MODELANDVIEW vs @RESPONSEBODY: ModelAndView returns data to a TEMPLATE
//    engine (Thymeleaf, FreeMarker). @ResponseBody/@RestController returns
//    data directly as JSON/XML. The XSS risk profile is completely different:
//    - ModelAndView → template injection / XSS if template doesn't escape
//    - @ResponseBody → safe if Content-Type is application/json (browsers
//      won't execute JSON as HTML), dangerous if Content-Type is text/html
//    The scanner should differentiate these two egress paths.
//
// 3. WEBCLIENT vs RESTTEMPLATE SECURITY: RestTemplate is synchronous and
//    blocking — it's the classic Spring HTTP client. WebClient is reactive
//    and non-blocking — it's the modern replacement. Both make external HTTP
//    calls (EXTERNAL/api_call). The security difference:
//    - RestTemplate: SSL/TLS verification on by default, no connection pool
//      limits by default (potential resource exhaustion under load)
//    - WebClient: SSL/TLS verification on by default, but reactive pipelines
//      can swallow errors silently (subscriber doesn't consume error signal).
//      WebClient.mutate() can create derived clients that override security
//      settings of the parent — a configuration inheritance issue.
//    Both should be flagged as EXTERNAL, but WebClient deserves a future note
//    about .mutate() potentially weakening security settings.
//
// 4. ACTUATOR EXPOSURE PATTERN: The real risk with actuator endpoints is the
//    management.endpoints.web.exposure.include property. If set to "*", ALL
//    actuator endpoints are exposed including /env, /configprops, /mappings,
//    /beans, /heapdump (heap dump!), /threaddump, and /jolokia (RCE if JMX
//    is enabled). The scanner should flag this property value in
//    application.properties/yml as a META/dangerous_config finding. This is
//    outside phoneme scope (it's a config file pattern, not a code pattern)
//    but it's the #1 Spring Boot security misconfiguration in the wild.
//
// 5. SPRING PROFILES AND TESTING: @Profile("dev") can gate entire beans,
//    including security configurations. A common vulnerability is having
//    a DevSecurityConfig that permits all requests, annotated with
//    @Profile("dev"), but the production deployment accidentally activates
//    the "dev" profile via spring.profiles.active=dev in environment variables.
//    The scanner should flag any @Profile-gated SecurityFilterChain or
//    WebSecurityConfigurerAdapter as a conditional security configuration
//    that needs review. This is too subtle for a phoneme entry (it's a
//    pattern across multiple annotations and classes) but worth noting.
