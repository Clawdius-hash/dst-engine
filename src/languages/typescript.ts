/**
 * TypeScript Callee Pattern Database
 *
 * TypeScript-ecosystem additions beyond the JavaScript base patterns.
 * Covers: Prisma, Drizzle, TypeORM, NestJS, Next.js App Router, tRPC,
 *         Zod, NextAuth/Auth.js, Bull/BullMQ, class-validator/transformer.
 *
 * NOTE: TypeScript shares ALL JavaScript patterns (Express req/res, fs.*,
 * crypto.*, JSON.*, etc). The index.ts merges JS base + these TS additions.
 *
 * Sources:
 *   - corpus_audit_typescript.json (54 Category B + 181 Category A patterns)
 *   - TS framework knowledge (gap-filling)
 *   - calleePatterns.ts (JS reference -- shared base)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (single identifier) ----------------------------------------
// Most direct calls are covered by the JS base. TS-specific additions only.

const DIRECT_CALLS: Record<string, CalleePattern> = {
  // Next.js App Router
  redirect:             { nodeType: 'EGRESS',    subtype: 'http_response', tainted: false },
  notFound:             { nodeType: 'EGRESS',    subtype: 'http_response', tainted: false },
  revalidatePath:       { nodeType: 'EXTERNAL',  subtype: 'cache_control', tainted: false },
  revalidateTag:        { nodeType: 'EXTERNAL',  subtype: 'cache_control', tainted: false },
  unstable_cache:       { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  generateMetadata:     { nodeType: 'META',      subtype: 'config',        tainted: false },
  generateStaticParams: { nodeType: 'META',      subtype: 'config',        tainted: false },
  // Next.js App Router: bare cookies()/headers() from 'next/headers'
  cookies:              { nodeType: 'INGRESS',   subtype: 'http_request',  tainted: true },
  headers:              { nodeType: 'INGRESS',   subtype: 'http_request',  tainted: true },
};

// -- Member calls (object.method / Class.method) ------------------------------

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS -- external data entering the system
  // =========================================================================

  // -- NestJS request decorators (runtime behavior) --
  // These map to controller parameter extraction at runtime
  'Body':                     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Query':                    { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Param':                    { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Headers':                  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Ip':                       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Session':                  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'UploadedFile':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Req':                      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Next.js App Router inputs --
  // NOTE: bare cookies() and headers() are in DIRECT_CALLS above
  'NextRequest.nextUrl':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'NextRequest.cookies':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'NextRequest.headers':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'NextRequest.body':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'NextRequest.json':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'NextRequest.text':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'NextRequest.formData':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'NextRequest.url':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'NextRequest.geo':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'NextRequest.ip':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'searchParams.get':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'searchParams.getAll':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'searchParams.has':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- FormData (Server Actions) --
  'formData.get':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'formData.getAll':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'formData.has':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'formData.entries':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- tRPC input --
  'ctx.input':                { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- WebSocket --
  'ws.on':                    { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'socket.on':                { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },

  // -- Deno --
  'Deno.env.get':             { nodeType: 'INGRESS', subtype: 'env_read',    tainted: true },
  'Deno.readTextFile':        { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'Deno.readFile':            { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'Deno.args':                { nodeType: 'INGRESS', subtype: 'env_read',    tainted: true },

  // -- Bun --
  'Bun.env':                  { nodeType: 'INGRESS', subtype: 'env_read',    tainted: true },
  'Bun.file':                 { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'Bun.argv':                 { nodeType: 'INGRESS', subtype: 'env_read',    tainted: true },

  // =========================================================================
  // EGRESS -- data leaving the system
  // =========================================================================

  // -- Next.js responses --
  'NextResponse.json':        { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'NextResponse.redirect':    { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'NextResponse.rewrite':     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  // NextResponse.next is CONTROL (middleware pass-through), see below
  'Response.json':            { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Response.redirect':        { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- NestJS responses --
  'res.json':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'res.send':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'res.render':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'res.redirect':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'res.status':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Deno write --
  'Deno.writeTextFile':       { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'Deno.writeFile':           { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'Deno.remove':              { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'Deno.mkdir':               { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },

  // -- Bun write --
  'Bun.write':                { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },

  // -- WebSocket send --
  'ws.send':                  { nodeType: 'EGRESS', subtype: 'network_write', tainted: false },
  'socket.emit':              { nodeType: 'EGRESS', subtype: 'network_write', tainted: false },
  'socket.send':              { nodeType: 'EGRESS', subtype: 'network_write', tainted: false },

  // -- Email (nodemailer) --
  'transporter.sendMail':     { nodeType: 'EGRESS', subtype: 'email',        tainted: false },

  // =========================================================================
  // STORAGE -- persistent state / ORM
  // =========================================================================

  // -- Prisma --
  'prisma.findUnique':        { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.findUniqueOrThrow': { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.findFirst':         { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.findFirstOrThrow':  { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.findMany':          { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.count':             { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.aggregate':         { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.groupBy':           { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.create':            { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'prisma.createMany':        { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'prisma.update':            { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'prisma.updateMany':        { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'prisma.upsert':            { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'prisma.delete':            { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'prisma.deleteMany':        { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'prisma.$transaction':      { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'prisma.$queryRaw':         { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.$executeRaw':       { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'prisma.$connect':          { nodeType: 'STORAGE', subtype: 'db_connect',  tainted: false },
  'prisma.$disconnect':       { nodeType: 'STORAGE', subtype: 'db_connect',  tainted: false },

  // -- Drizzle ORM --
  'db.select':                { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'db.insert':                { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'db.update':                { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'db.delete':                { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'db.execute':               { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'db.query':                 { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'db.transaction':           { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },

  // -- TypeORM --
  'repository.find':          { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'repository.findOne':       { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'repository.findOneBy':     { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'repository.findBy':        { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'repository.save':          { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'repository.insert':        { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'repository.update':        { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'repository.delete':        { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'repository.remove':        { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'repository.count':         { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'repository.createQueryBuilder': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'manager.find':             { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'manager.findOne':          { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'manager.save':             { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'manager.delete':           { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'manager.transaction':      { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'dataSource.getRepository': { nodeType: 'STORAGE', subtype: 'db_connect',  tainted: false },
  'dataSource.createQueryRunner': { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },

  // -- Sequelize --
  'Model.findAll':            { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'Model.findOne':            { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'Model.findByPk':           { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'Model.create':             { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'Model.update':             { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'Model.destroy':            { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'Model.bulkCreate':         { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'Model.count':              { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'sequelize.query':          { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'sequelize.transaction':    { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },

  // -- Mongoose --
  'Model.find':               { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'Model.findById':           { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  // Model.findOne covered by Sequelize entry above
  'Model.aggregate':          { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'Model.countDocuments':     { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'Model.insertMany':         { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'Model.updateOne':          { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'Model.updateMany':         { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'Model.deleteOne':          { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'Model.deleteMany':         { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'mongoose.connect':         { nodeType: 'STORAGE', subtype: 'db_connect',  tainted: false },

  // -- Knex --
  'knex.select':              { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'knex.insert':              { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'knex.update':              { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'knex.delete':              { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'knex.raw':                 { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'knex.transaction':         { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },

  // -- Redis (ioredis / node-redis) --
  'redis.get':                { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'redis.set':                { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.del':                { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.hget':               { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'redis.hset':               { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.lpush':              { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.rpush':              { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.lpop':               { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'redis.rpop':               { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },

  // =========================================================================
  // TRANSFORM -- data processing / validation
  // =========================================================================

  // -- Zod --
  'z.string':                 { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'z.number':                 { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'z.boolean':                { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'z.object':                 { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'z.array':                  { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'z.enum':                   { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'z.union':                  { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'z.discriminatedUnion':     { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'z.literal':                { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'z.coerce':                 { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  'z.preprocess':             { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  'schema.parse':             { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'schema.safeParse':         { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'schema.parseAsync':        { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'schema.safeParseAsync':    { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },

  // -- class-transformer --
  'plainToClass':             { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  'plainToInstance':          { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  'classToPlain':             { nodeType: 'TRANSFORM', subtype: 'serialize', tainted: false },
  'instanceToPlain':          { nodeType: 'TRANSFORM', subtype: 'serialize', tainted: false },
  'classToClass':             { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },

  // -- io-ts --
  'codec.decode':             { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'codec.encode':             { nodeType: 'TRANSFORM', subtype: 'serialize', tainted: false },

  // -- superjson --
  'superjson.serialize':      { nodeType: 'TRANSFORM', subtype: 'serialize', tainted: false },
  'superjson.deserialize':    { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },

  // -- date-fns / dayjs / luxon --
  'format':                   { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  'parseISO':                 { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'dayjs':                    { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  'DateTime.fromISO':         { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'DateTime.now':             { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },

  // -- DOMPurify --
  'DOMPurify.sanitize':       { nodeType: 'TRANSFORM', subtype: 'sanitize_html',  tainted: false },

  // =========================================================================
  // CONTROL -- validation, guards, middleware
  // =========================================================================

  // -- Zod validation (control flow) --
  'z.parse':                  { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },
  'z.safeParse':              { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },

  // -- class-validator --
  'validate':                 { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },
  'validateSync':             { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },
  'validateOrReject':         { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },

  // -- NestJS guards/pipes --
  'UseGuards':                { nodeType: 'CONTROL', subtype: 'guard',       tainted: false },
  'UsePipes':                 { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },
  'UseInterceptors':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'UseFilters':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'CanActivate':              { nodeType: 'CONTROL', subtype: 'guard',       tainted: false },
  'ValidationPipe':           { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },
  'ParseIntPipe':             { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },
  'ParseUUIDPipe':            { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },

  // -- Next.js middleware --
  'NextResponse.next':        { nodeType: 'CONTROL', subtype: 'guard',       tainted: false },

  // -- tRPC middleware --
  't.middleware':             { nodeType: 'CONTROL', subtype: 'guard',        tainted: false },
  't.procedure':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // =========================================================================
  // AUTH -- authentication and authorization
  // =========================================================================

  // -- NextAuth / Auth.js --
  'getServerSession':         { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'auth':                     { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'signIn':                   { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'signOut':                  { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'useSession':               { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'getSession':               { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'getToken':                 { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },

  // -- Passport (TS) --
  'passport.authenticate':    { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'passport.use':             { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'passport.initialize':      { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'passport.session':         { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },

  // -- NestJS auth --
  'AuthGuard':                { nodeType: 'AUTH', subtype: 'authorize',      tainted: false },
  'JwtAuthGuard':             { nodeType: 'AUTH', subtype: 'authorize',      tainted: false },
  'RolesGuard':               { nodeType: 'AUTH', subtype: 'authorize',      tainted: false },

  // -- Clerk --
  'currentUser':              { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'clerkClient':              { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },

  // -- Supabase auth --
  'supabase.auth.signUp':     { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'supabase.auth.signIn':     { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'supabase.auth.signInWithPassword': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'supabase.auth.signOut':    { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'supabase.auth.getUser':    { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'supabase.auth.getSession': { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },

  // =========================================================================
  // EXTERNAL -- calls to outside systems
  // =========================================================================

  // -- tRPC client --
  'trpc.query':               { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'trpc.mutation':            { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'trpc.useQuery':            { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'trpc.useMutation':         { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },

  // -- TanStack Query --
  'useQuery':                 { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'useMutation':              { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'useInfiniteQuery':         { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'useSuspenseQuery':         { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'queryClient.fetchQuery':   { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'queryClient.prefetchQuery':{ nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'queryClient.invalidateQueries': { nodeType: 'EXTERNAL', subtype: 'cache_control', tainted: false },

  // -- SWR --
  'useSWR':                   { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'useSWRMutation':           { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },

  // -- Bull/BullMQ --
  'queue.add':                { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'queue.addBulk':            { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'queue.process':            { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'worker.on':                { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },

  // -- Supabase data --
  'supabase.from':            { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'supabase.rpc':             { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'supabase.storage.from':    { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },

  // -- Firebase --
  'firebase.firestore':       { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'firebase.auth':            { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'firebase.storage':         { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },

  // -- Deno --
  'Deno.serve':               { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },

  // -- Bun --
  'Bun.serve':                { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },

  // =========================================================================
  // META -- config, types
  // =========================================================================

  // -- NestJS module setup --
  'Module':                   { nodeType: 'META', subtype: 'config',         tainted: false },
  'Injectable':               { nodeType: 'META', subtype: 'config',         tainted: false },
  'Controller':               { nodeType: 'META', subtype: 'config',         tainted: false },

  // -- Next.js config --
  'nextConfig':               { nodeType: 'META', subtype: 'config',         tainted: false },

  // -- Winston/Pino/Bunyan/log4js logging (CWE-117 sinks) --
  'winston.createLogger':     { nodeType: 'META',   subtype: 'config',       tainted: false },
  'winston.log':              { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'winston.info':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'winston.error':            { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'winston.warn':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'winston.debug':            { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'pino':                     { nodeType: 'META',   subtype: 'logging',      tainted: false },
  'pino.info':                { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'pino.error':               { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'pino.warn':                { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'pino.debug':               { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'pino.fatal':               { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'logger.info':              { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'logger.warn':              { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'logger.error':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'logger.debug':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'logger.fatal':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'logger.verbose':           { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'bunyan.info':              { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'bunyan.error':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'bunyan.warn':              { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'bunyan.debug':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'bunyan.fatal':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'log4js.info':              { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'log4js.error':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'log4js.warn':              { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'log4js.debug':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
  'log4js.fatal':             { nodeType: 'EGRESS', subtype: 'log_write',    tainted: false },
};

// -- Wildcard: inherits JS base patterns + these TS additions --
// The wildcard sets from the JS base (STORAGE_READ/WRITE, TRANSFORM_FORMAT/CALCULATE)
// apply to TypeScript as well. They are re-exported via the lookup function.

const STORAGE_READ_METHODS = new Set([
  'findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow',
  'findMany', 'findOne', 'findOneBy', 'findBy', 'findByPk', 'findAll',
  'findById', 'find', 'select', 'get', 'count', 'aggregate', 'groupBy',
  'query', 'countDocuments', 'exists',
]);

const STORAGE_WRITE_METHODS = new Set([
  'create', 'createMany', 'insert', 'insertMany', 'bulkCreate',
  'update', 'updateOne', 'updateMany', 'upsert',
  'delete', 'deleteOne', 'deleteMany', 'destroy', 'remove',
  'save', '$transaction', '$executeRaw',
]);

// -- Lookup function ----------------------------------------------------------

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };

    // Single-name framework methods (redirect, notFound, etc.)
    const singleMember = MEMBER_CALLS[calleeChain[0]!];
    if (singleMember) return { ...singleMember };

    return null;
  }

  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  const member = MEMBER_CALLS[exactKey];
  if (member) return { ...member };

  if (calleeChain.length > 2) {
    const fullPath = calleeChain.join('.');
    const fullMember = MEMBER_CALLS[fullPath];
    if (fullMember) return { ...fullMember };

    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
  }

  // Wildcard: ORM methods
  if (STORAGE_READ_METHODS.has(methodName)) {
    if (!NON_DB_OBJECTS.has(objectName)) {
      return { nodeType: 'STORAGE', subtype: 'db_read', tainted: false };
    }
  }

  if (STORAGE_WRITE_METHODS.has(methodName)) {
    if (!NON_DB_OBJECTS.has(objectName)) {
      return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false };
    }
  }

  return null;
}

const NON_DB_OBJECTS = new Set([
  'req', 'res', 'request', 'response', 'ctx', 'context',
  'app', 'router', 'express', 'http', 'https',
  'z', 'schema', 'zod',
  'this', 'self', 'event', 'e',
  'arr', 'array', 'list', 'items', 'elements', 'results',
  'data', 'children', 'nodes', 'keys', 'values',
  'fs', 'path', 'os', 'crypto', 'console', 'process',
  'JSON', 'Math', 'Date', 'Promise', 'AbortController',
  'NextRequest', 'NextResponse', 'Response', 'Request',
]);

// -- Sink patterns (CWE -> dangerous regex) -----------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-79':  /(?:dangerouslySetInnerHTML\s*=|\.innerHTML\s*=|v-html\s*=)/,
  'CWE-89':  /(?:prisma\.\$queryRaw\s*\(\s*`|knex\.raw\s*\(\s*`|sequelize\.query\s*\(\s*`)/,
  'CWE-94':  /(?:eval\s*\(\s*(?:req|params|body|input|user)|new\s+Function\s*\(\s*(?:req|params|body))/,
  'CWE-918': /(?:fetch\s*\(\s*(?:req|params|body|input|user)|axios\.\w+\s*\(\s*(?:req|params|body))/,
  'CWE-1321': /(?:Object\.assign\s*\(\s*\{\}\s*,|\.\.\.(?:req|params|body|input))/,
  'CWE-704': /as\s+any\s*(?:\)|;|,|\])/,
  'CWE-798': /(?:password|secret|apiKey|token)\s*[:=]\s*['"][^'"]{8,}['"]/,
};

// -- Safe patterns (CWE -> mitigating regex) ----------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-79':  /(?:DOMPurify\.sanitize|sanitizeHtml|xss\s*\()/,
  'CWE-89':  /(?:prisma\.\$queryRaw\s*\(\s*Prisma\.sql|knex\.\w+\s*\(\s*['"]|sequelize\.query\s*\([^)]*replacements)/,
  'CWE-918': /(?:z\.string\(\)\.url\(\)|new\s+URL\s*\(|URL\.canParse\s*\()/,
  'CWE-1321': /(?:structuredClone\s*\(|JSON\.parse\s*\(\s*JSON\.stringify)/,
  'CWE-704': /(?:satisfies\s+\w+|z\.parse|schema\.parse|validate\()/,
};

// -- Pattern count ------------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size;
}
