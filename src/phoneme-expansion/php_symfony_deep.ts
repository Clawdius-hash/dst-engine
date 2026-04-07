/**
 * Phoneme expansion: PHP — Symfony deep patterns
 * Covers: Form component, Twig auto-escaping bypass (raw filter),
 * Security component voters, Doctrine DQL injection, Messenger component,
 * Symfony HttpClient
 *
 * Agent-generated, tested against real patterns
 *
 * This expansion covers Symfony-specific attack surfaces that are NOT covered
 * by the existing PHP dictionary (which has basic Symfony Request/Response and
 * Security.getUser / Security.isGranted).
 *
 * Key security insights:
 *
 * 1. Symfony Form handleRequest() + getData() — the Form component is the
 *    primary INGRESS path in Symfony apps. handleRequest() binds HTTP request
 *    data to the form model. getData() retrieves that bound data. Both are
 *    tainted because they carry user input, even after form validation (which
 *    only checks constraints, it does NOT sanitize).
 *
 * 2. Twig |raw filter — Twig auto-escapes all output by default (good!), but
 *    the |raw filter and {% autoescape false %} blocks disable this. When
 *    tainted data passes through |raw, it becomes an XSS vector (CWE-79).
 *    In the scanner, we model the Twig Environment's render() method as a
 *    TRANSFORM that can carry tainted data to output.
 *
 * 3. Security voters — VoterInterface::vote() and AccessDecisionManager are
 *    the fine-grained authorization layer in Symfony. Custom voters are where
 *    authz bugs live (CWE-285). If a voter always returns ACCESS_GRANTED,
 *    it's a broken access control.
 *
 * 4. Doctrine createQuery() with DQL — Doctrine's DQL is NOT SQL, but it IS
 *    injectable if you concatenate user input. $em->createQuery("SELECT u FROM
 *    User u WHERE u.name = '$name'") is DQL injection. The safe form uses
 *    setParameter(). Also: getConnection()->executeQuery() drops to raw SQL.
 *
 * 5. Messenger dispatch() — Symfony's Messenger component sends messages to
 *    async transports (RabbitMQ, Redis, etc.). dispatch() is EXTERNAL because
 *    it crosses process boundaries and the message payload may contain tainted
 *    data that gets deserialized on the consumer side.
 *
 * 6. Symfony HttpClient — request() is the primary HTTP call method. It's
 *    EXTERNAL/api_call, analogous to Guzzle but built into Symfony.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// =============================================================================
// NEW ENTRIES — to be wired into MEMBER_CALLS in languages/php.ts
// =============================================================================

export const PHONEMES_PHP_SYMFONY_DEEP = {

  // -- 1. Symfony Form Component — INGRESS -----------------------------------
  //
  // The Form component is the standard way Symfony apps accept user input.
  // handleRequest() pulls data from the HTTP request and binds it to the form
  // model. getData() extracts the bound (and potentially validated) data.
  //
  // CRITICAL: Form validation does NOT equal sanitization. A validated email
  // field still contains the user's input — it just matches a regex. If that
  // value is used in a raw query or echoed without escaping, it's still an
  // attack vector.

  'form.handleRequest':   { nodeType: 'INGRESS',    subtype: 'form_input',    tainted: true },
  // $form->handleRequest($request) binds HTTP request data to the form.
  // After this call, the form object carries user-supplied values.
  // This is the Symfony equivalent of Laravel's $request->validate().

  'form.getData':         { nodeType: 'INGRESS',    subtype: 'form_input',    tainted: true },
  // $form->getData() retrieves the data bound by handleRequest(). Returns
  // the form's underlying data object (DTO, entity, or array) populated
  // with user input. Tainted even after validation.

  // -- 2. Twig Template Engine — TRANSFORM (XSS vectors) ---------------------
  //
  // Twig auto-escapes output by default, which is great. But the |raw filter
  // and autoescape blocks disable this protection. The Twig Environment's
  // render() method is the output point where templates get compiled.
  //
  // We track Environment.render() as TRANSFORM because it processes template
  // data. When tainted data is passed to a template that uses |raw, the
  // auto-escaping is bypassed and you get CWE-79.

  'Environment.render':   { nodeType: 'TRANSFORM',  subtype: 'template_render', tainted: false },
  // $twig->render('template.html.twig', ['data' => $userInput])
  // Renders a Twig template with context variables. The template itself
  // may use |raw or {% autoescape false %}, bypassing escaping.
  // The scanner should track tainted data flowing into render context.

  'Environment.display':  { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  // $twig->display() is render() + echo in one call. It outputs directly
  // to the browser, making it an EGRESS point.

  // -- 3. Security Voters — AUTH/CONTROL -------------------------------------
  //
  // Symfony's Security component uses voters for fine-grained authorization.
  // The AccessDecisionManager aggregates votes from multiple VoterInterface
  // implementations. Custom voters are the #1 source of broken access
  // control (CWE-285) in Symfony apps.

  'AccessDecisionManager.decide': { nodeType: 'AUTH', subtype: 'authorize',   tainted: false },
  // The AccessDecisionManager collects votes from all registered voters
  // and decides whether access is granted. This is the central authz
  // checkpoint — if it's missing or misconfigured, authorization is broken.

  // -- 4. Doctrine DQL — STORAGE (injection vectors) -------------------------
  //
  // Doctrine's EntityManager is the gateway to DQL queries. createQuery()
  // takes a DQL string that can be injected if user input is concatenated.
  // getConnection()->executeQuery() drops to raw SQL via DBAL.

  'EntityManager.createQuery':    { nodeType: 'STORAGE', subtype: 'dql_query', tainted: false },
  // $em->createQuery("SELECT u FROM User u WHERE u.name = '$name'")
  // is DQL injection. Safe form: $em->createQuery("...")->setParameter(...)
  // DQL is not SQL, but it IS injectable and can leak/modify data.

  'connection.executeQuery':      { nodeType: 'STORAGE', subtype: 'db_read',   tainted: false },
  // $em->getConnection()->executeQuery($sql, $params) drops to raw SQL
  // via Doctrine DBAL. If $sql contains concatenated user input without
  // parameter binding, it's classic SQL injection (CWE-89).

  // -- 5. Symfony Messenger — EXTERNAL (async dispatch) ----------------------
  //
  // The Messenger component dispatches messages to async transports (AMQP,
  // Redis, Doctrine). Messages cross process boundaries and get serialized/
  // deserialized, making this an EXTERNAL boundary.

  'MessageBusInterface.dispatch': { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  // $messageBus->dispatch(new SomeMessage($userData))
  // Sends a message to the configured transport. The message payload may
  // contain tainted data that will be deserialized by workers. CWE-502
  // risk if the transport is not trusted.

  // -- 6. Symfony HttpClient — EXTERNAL (outbound HTTP) ----------------------
  //
  // Symfony's HttpClient component is the framework's built-in HTTP client.
  // request() is the primary method. SSRF risk (CWE-918) if the URL
  // contains user input.

  'HttpClient.request':           { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  // $httpClient->request('GET', $url) — outbound HTTP call. If $url
  // contains user input, it's SSRF. Symfony HttpClient does NOT validate
  // URLs by default (no protection against internal network requests).

} as const;

// =============================================================================
// SINK PATTERNS — new vulnerability signatures for Symfony deep scope
// =============================================================================

export const symfonyDeepSinks: Record<string, RegExp> = {
  // Doctrine DQL injection: createQuery() with string concatenation
  // Matches: createQuery("SELECT ... " . $var) or createQuery("... $var")
  'CWE-89-DQL': /->createQuery\s*\(\s*["'][^"']*(?:\$\w+|["']\s*\.)/,

  // Doctrine DBAL raw executeQuery with concatenation
  'CWE-89-DBAL': /->executeQuery\s*\(\s*["'][^"']*\$\w+/,

  // Twig |raw filter on variable — XSS when variable is user input
  'CWE-79-TWIG-RAW': /\{\{\s*\w+\s*\|\s*raw\s*\}\}/,

  // Twig autoescape false block — all output in this block is unescaped
  'CWE-79-TWIG-AUTOESCAPE': /\{%\s*autoescape\s+false\s*%\}/,
};

// =============================================================================
// SAFE PATTERNS — mitigations for the above
// =============================================================================

export const symfonyDeepSafePatterns: Record<string, RegExp> = {
  // Doctrine parameterized DQL: createQuery() followed by setParameter
  'CWE-89-DQL': /->createQuery\s*\([^)]+\)\s*->\s*setParameter/,

  // Doctrine DBAL with binding array
  'CWE-89-DBAL': /->executeQuery\s*\(\s*["'][^"']*\?\s*["']\s*,\s*\[/,

  // Twig |escape or |e filter (explicit escaping)
  'CWE-79-TWIG-RAW': /\{\{\s*\w+\s*\|\s*(?:escape|e)\s*\}\}/,
};

// =============================================================================
// ENTRY COUNT
// =============================================================================

export function getExpansionCount(): number {
  return Object.keys(PHONEMES_PHP_SYMFONY_DEEP).length;
}
