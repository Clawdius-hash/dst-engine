/**
 * Java Spring Advanced Phonemes — Spring Boot Actuator, Spring Cloud Config,
 * Spring AOP aspects, Spring WebFlux reactive patterns
 *
 * Scope:
 *   1. ProceedingJoinPoint.proceed — Spring AOP @Around advice delegating to the
 *      intercepted method. This is a CONTROL node because aspects act as cross-cutting
 *      guards: logging, security checks, transaction boundaries, rate limiting.
 *      An @Around advice that forgets to call proceed() silently swallows the call.
 *      Conversely, calling proceed() without validation lets tainted data through.
 *
 *   2. ServerRequest.bodyToMono — Spring WebFlux functional endpoint: extracts the
 *      request body into a Mono<T>. This is an INGRESS node — the reactive equivalent
 *      of @RequestBody. The body is user-controlled and must be validated.
 *
 *   3. ServerResponse.ok — Spring WebFlux functional endpoint response builder.
 *      This is an EGRESS node — it constructs HTTP responses sent to clients.
 *      Data flowing into ServerResponse.ok().body(...) leaves the system.
 *
 *   4. Mono.map — Reactive TRANSFORM. Mono.map(fn) applies a transformation to the
 *      value inside a Mono. If the upstream Mono carries tainted data (e.g., from
 *      bodyToMono), the map function processes that tainted data. This is the reactive
 *      equivalent of a synchronous transform step in a data pipeline.
 *
 *   5. Flux.flatMap — Reactive TRANSFORM with fan-out. Flux.flatMap(fn) transforms
 *      each element into a Publisher and merges results. Security-relevant because
 *      it can amplify tainted data across multiple async operations.
 *
 *   6. ServerRequest.queryParam — Spring WebFlux functional endpoint: extracts a
 *      query parameter by name. Direct INGRESS — user-controlled input from URL.
 *
 *   7. ServerRequest.pathVariable — Spring WebFlux functional endpoint: extracts a
 *      path variable. Direct INGRESS — user-controlled input from URL path segments.
 *
 *   8. InfoEndpoint.info — Spring Boot Actuator /actuator/info endpoint. Exposes
 *      application metadata (git info, build info, custom properties). META node
 *      because it reveals system metadata. When misconfigured, can leak internal
 *      details useful for reconnaissance.
 *
 *   9. ConfigServicePropertySourceLocator.locate — Spring Cloud Config client
 *      fetching configuration from a remote config server. This is an EXTERNAL node
 *      because it makes a network call to retrieve config. If the config server is
 *      compromised, all downstream services receive poisoned configuration.
 *      CVE-2020-5405 (Spring Cloud Config path traversal) is in this family.
 *
 *  10. BeansEndpoint.beans — Spring Boot Actuator /actuator/beans endpoint. Exposes
 *      all Spring beans in the ApplicationContext. META node because it reveals
 *      internal application structure. Attackers use it for reconnaissance to
 *      discover custom beans, security filters, and injection points.
 *
 * Security observations:
 *
 * - AOP INTERCEPTION PATTERN: Spring AOP @Around advice is the most powerful
 *   interception point. It controls whether the target method executes at all.
 *   Security aspects (authentication, authorization, input validation) that wrap
 *   controller methods are CONTROL gates — if they don't call proceed(), the
 *   request is blocked. If they call proceed() unconditionally, they're no-ops.
 *   DST should track whether proceed() is called conditionally (real guard) or
 *   unconditionally (false sense of security).
 *
 * - REACTIVE TAINT PROPAGATION: In WebFlux, taint flows through the reactive
 *   pipeline: ServerRequest.bodyToMono() -> Mono.map() -> Mono.flatMap() -> ...
 *   Traditional synchronous taint tracking won't catch this. DST needs to follow
 *   taint through Mono/Flux operator chains. Every .map(), .flatMap(), .filter()
 *   is a transform that may or may not sanitize.
 *
 * - ACTUATOR AS ATTACK SURFACE: Spring Boot Actuator endpoints are one of the
 *   most common Spring misconfigurations. /actuator/env leaks secrets,
 *   /actuator/beans reveals architecture, /actuator/info can leak git hashes.
 *   In Spring Boot 1.x, ALL endpoints were exposed by default. Even in 2.x+,
 *   management.endpoints.web.exposure.include=* is a common (dangerous) config.
 *
 * - SPRING CLOUD CONFIG TRUST: Spring Cloud Config clients implicitly trust the
 *   config server. If the config server is compromised or if there's a MITM,
 *   the client will accept any configuration — including malicious bean definitions,
 *   database URLs pointing to attacker-controlled servers, etc.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const JAVA_SPRING_ADVANCED_PHONEMES: Record<string, CalleePattern> = {

  // ── 1. Spring AOP — ProceedingJoinPoint.proceed ──────────────────────
  // The heart of @Around advice. Controls whether the intercepted method
  // actually executes. Security aspects use this as a gate.
  'ProceedingJoinPoint.proceed':  { nodeType: 'CONTROL', subtype: 'aop_advice', tainted: false },

  // ── 2. Spring WebFlux — ServerRequest.bodyToMono ─────────────────────
  // Extracts request body as Mono<T>. Reactive equivalent of @RequestBody.
  // User-controlled input entering the reactive pipeline.
  'ServerRequest.bodyToMono':  { nodeType: 'INGRESS', subtype: 'http_body', tainted: true },

  // ── 3. Spring WebFlux — ServerResponse.ok ────────────────────────────
  // Starts building a 200 OK response. Data flows OUT through the response body.
  'ServerResponse.ok':  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // ── 4. Reactive — Mono.map ───────────────────────────────────────────
  // Applies a synchronous transform to the Mono's value. Taint propagates
  // through the map function unless it sanitizes.
  'Mono.map':  { nodeType: 'TRANSFORM', subtype: 'reactive_transform', tainted: false },

  // ── 5. Reactive — Flux.flatMap ───────────────────────────────────────
  // Transforms each element into a Publisher and merges. Can fan out tainted
  // data across concurrent operations.
  'Flux.flatMap':  { nodeType: 'TRANSFORM', subtype: 'reactive_transform', tainted: false },

  // ── 6. Spring WebFlux — ServerRequest.queryParam ─────────────────────
  // Extracts a query parameter by name from a functional endpoint request.
  // Direct user input from URL query string.
  'ServerRequest.queryParam':  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 7. Spring WebFlux — ServerRequest.pathVariable ───────────────────
  // Extracts a path variable from a functional endpoint request.
  // Direct user input from URL path segments.
  'ServerRequest.pathVariable':  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── 8. Spring Boot Actuator — InfoEndpoint.info ──────────────────────
  // /actuator/info exposes application metadata. Reconnaissance vector.
  'InfoEndpoint.info':  { nodeType: 'META', subtype: 'config', tainted: false },

  // ── 9. Spring Cloud Config — ConfigServicePropertySourceLocator.locate ──
  // Client-side fetch of remote configuration. Network call to config server.
  // If config server is compromised, all clients receive poisoned config.
  'ConfigServicePropertySourceLocator.locate':  { nodeType: 'EXTERNAL', subtype: 'config_fetch', tainted: false },

  // ── 10. Spring Boot Actuator — BeansEndpoint.beans ───────────────────
  // /actuator/beans reveals all Spring beans. Architectural reconnaissance.
  'BeansEndpoint.beans':  { nodeType: 'META', subtype: 'config', tainted: false },
};
