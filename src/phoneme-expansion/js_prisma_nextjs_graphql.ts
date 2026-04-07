/**
 * Phoneme expansion: JavaScript/TypeScript — Prisma, Next.js, GraphQL (Apollo/Yoga)
 * Agent-generated, tested against real patterns
 *
 * Coverage audit performed against calleePatterns.ts and languages/typescript.ts.
 * Prisma and Next.js are already well-covered in those files. This expansion
 * fills the GRAPHQL gap (completely absent from DST) and adds a few Prisma/Next.js
 * patterns that fell through the cracks.
 *
 * What's already covered (DO NOT duplicate):
 *   - prisma.findMany/findUnique/create/update/delete/etc → typescript.ts lines 139-159
 *   - prisma.$queryRaw/$executeRaw/$transaction/$connect/$disconnect → typescript.ts
 *   - $queryRaw/$queryRawUnsafe/$executeRaw/$executeRawUnsafe → calleePatterns.ts wildcard sets
 *   - NextRequest.{*}/NextResponse.{*}/cookies()/headers()/searchParams.{*} → typescript.ts lines 58-73
 *   - getServerSideProps/getStaticProps → manifest-generator.ts detection only (not phonemes)
 *   - redirect/notFound/revalidatePath/revalidateTag → typescript.ts direct calls
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JS_PRISMA_NEXTJS_GRAPHQL = {

  // ═══════════════════════════════════════════════════════════════════════════
  // GRAPHQL — Apollo Server / GraphQL Yoga / graphql-tools
  // ═══════════════════════════════════════════════════════════════════════════
  // GraphQL resolvers receive (parent, args, context, info). The `args` parameter
  // is user-controlled input equivalent to req.body — it's the #1 injection vector
  // in GraphQL APIs. The `context` object typically carries the authenticated user
  // and database clients, making context.req an INGRESS source and context.prisma
  // a STORAGE handle.

  // Apollo Server: context function builds the request context passed to every resolver.
  // context.req exposes the raw HTTP request — user-controlled headers, cookies, IP.
  // Security: if resolvers read context.req.headers or context.req.body directly,
  // they bypass GraphQL's type-level validation.
  'context.req': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // Apollo Server / Yoga: the graphql() execution function runs a query string
  // against a schema. If the query string comes from user input (not a persisted
  // query), this is a code execution sink — arbitrary field traversal, introspection,
  // deeply nested queries (DoS via query complexity).
  'graphql.execute': { nodeType: 'EXTERNAL', subtype: 'graphql_exec', tainted: false },

  // graphql-tag: gql`` template literal parses GraphQL query strings at build time.
  // Not dangerous by itself, but if the template string is dynamically constructed
  // from user input, it becomes an injection vector (query injection / field injection).
  // Classified as TRANSFORM because it parses a DSL into an AST.
  'gql': { nodeType: 'TRANSFORM', subtype: 'graphql_parse', tainted: false },

  // Apollo Server: makeExecutableSchema / buildSchema composes type definitions
  // and resolvers into a runnable schema. This is system topology — it defines
  // what queries/mutations/subscriptions exist.
  'makeExecutableSchema': { nodeType: 'STRUCTURAL', subtype: 'schema_def', tainted: false },

  // GraphQL Yoga: createYoga() creates a Yoga server instance. Equivalent to
  // express() or fastify() — it's the framework entrypoint that defines the
  // GraphQL endpoint topology.
  'createYoga': { nodeType: 'STRUCTURAL', subtype: 'lifecycle', tainted: false },

  // Apollo Server: new ApolloServer({...}).start() / .listen() — server lifecycle.
  // Defines the GraphQL endpoint and starts accepting queries. Structural because
  // it wires together schema, context, plugins, and middleware.
  'ApolloServer.start': { nodeType: 'STRUCTURAL', subtype: 'lifecycle', tainted: false },

  // Apollo Server: server.applyMiddleware({app}) mounts the GraphQL endpoint onto
  // an Express/Koa/Fastify app. This is where the GraphQL route gets defined — it's
  // the equivalent of app.use('/graphql', ...).
  'server.applyMiddleware': { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // NEXT.JS — getServerSideProps / getStaticProps as phonemes
  // ═══════════════════════════════════════════════════════════════════════════
  // These are detected in manifest-generator.ts but NOT classified as phonemes.
  // getServerSideProps runs on EVERY request and receives `context` with req/res/query.
  // context.query and context.params are user-controlled — tainted INGRESS.

  // getServerSideProps: runs server-side on every request. Its `context` parameter
  // exposes context.req, context.query, context.params — all user-controlled.
  // Classified as INGRESS because its return value (props) feeds directly into the
  // page component with data from the request.
  'getServerSideProps': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ═══════════════════════════════════════════════════════════════════════════
  // PRISMA — unsafe raw query variants (explicit member calls)
  // ═══════════════════════════════════════════════════════════════════════════
  // $queryRawUnsafe and $executeRawUnsafe are in calleePatterns.ts wildcard sets
  // but NOT as explicit prisma.* member calls in typescript.ts. The "Unsafe" variants
  // accept raw string interpolation (no tagged template protection) — they are the
  // #1 SQL injection vector in Prisma codebases. Adding explicit member entries
  // ensures they get flagged even when the wildcard heuristic doesn't fire.

  // prisma.$queryRawUnsafe: accepts a plain string query (NOT a tagged template).
  // Unlike $queryRaw (which uses Prisma.sql tagged template for parameterization),
  // $queryRawUnsafe passes the string directly to the database driver.
  // This is Prisma's most dangerous method — CWE-89 vector.
  'prisma.$queryRawUnsafe': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },

  // prisma.$executeRawUnsafe: same as $queryRawUnsafe but for write operations.
  // Accepts raw string SQL without parameterization. INSERT/UPDATE/DELETE with
  // user-controlled values = SQL injection.
  'prisma.$executeRawUnsafe': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

} as const;

// ── NOTE on GraphQL security gap ──────────────────────────────────────────
// GraphQL resolvers have a unique security profile that doesn't map cleanly to
// REST patterns. Key differences:
//
// 1. ARGS ARE INGRESS: resolver(parent, args, context, info) — `args` is the
//    equivalent of req.body but it's type-validated by the GraphQL schema layer.
//    However, custom scalars (e.g., JSON scalar) bypass this validation entirely.
//
// 2. QUERY COMPLEXITY: GraphQL allows arbitrarily nested queries. A single
//    POST to /graphql can trigger N+1 database calls. This is a RESOURCE concern
//    (CPU/connections) that doesn't exist in REST APIs. Libraries like
//    graphql-depth-limit and graphql-query-complexity address this.
//
// 3. INTROSPECTION: By default, GraphQL exposes the entire API schema via
//    __schema queries. In production, this should be disabled — it's an
//    information disclosure issue (CWE-200).
//
// 4. BATCHING: Apollo supports query batching by default. An attacker can send
//    hundreds of mutations in a single HTTP request, bypassing rate limiting
//    that operates at the HTTP level.
//
// None of these map to a single callee pattern. They're architectural concerns
// that the DST scanner should eventually model as RESOURCE and META nodes.
