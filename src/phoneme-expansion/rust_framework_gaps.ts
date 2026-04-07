/**
 * Phoneme expansion: Rust — actix-web extractors, axum extractors, tower middleware,
 * tonic gRPC, rusqlite, tokio::process::Command, std::process::Command arg chain tracking
 * Agent-generated, tested against real patterns
 *
 * WHY THESE 10:
 * The base rust.ts dictionary covers the major Rust web frameworks (actix, axum, rocket,
 * warp), stdlib (io, fs, env, process, sync), crypto, JWT, and databases (sqlx, diesel,
 * sea-orm, redis, mongodb). But the audit flagged six categories of missing patterns
 * that matter for security:
 *
 *   1. actix-web ServiceRequest — middleware handlers receive ServiceRequest, which
 *      carries the same tainted data as HttpRequest (headers, path, query) but
 *      through a different type. If the scanner only knows HttpRequest, it misses
 *      middleware-level taint sources. Also missing: web::Header extractor for
 *      typed header extraction, and ConnectionInfo for peer address/host.
 *
 *   2. axum extractors — RawQuery and RawForm give raw, unstructured query/form
 *      strings. These are higher-risk than typed extractors because they bypass
 *      deserialization validation. WebSocketUpgrade is an INGRESS endpoint that
 *      opens a persistent bidirectional channel — a fundamentally different attack
 *      surface than request/response HTTP.
 *
 *   3. tower middleware — tower::Service and tower::Layer are THE middleware
 *      abstraction for the entire tokio ecosystem (axum, hyper, tonic all use them).
 *      ServiceBuilder chains rate limiting, timeouts, concurrency limits, and auth
 *      layers. These are CONTROL nodes — they gate what reaches your handlers.
 *      tower::ServiceBuilder::layer is the canonical chaining point. ConcurrencyLimit
 *      and RateLimit are RESOURCE nodes (finite capacity).
 *
 *   4. tonic gRPC — Request::metadata() returns gRPC metadata (headers) which is
 *      tainted user input. Streaming<T> is a tainted data stream. The generated
 *      service client method calls (.say_hello(), etc.) are EXTERNAL/rpc calls
 *      that DST should know about. tonic::Status is the gRPC equivalent of HTTP
 *      status — it's EGRESS.
 *
 *   5. rusqlite — the most popular synchronous SQLite crate in Rust. Connection::open
 *      is db_connect. conn.execute/execute_batch send raw SQL. conn.prepare +
 *      stmt.query_row/query_map are the parameterized query path. params![] macro
 *      builds parameter lists. This is a MASSIVE gap — rusqlite has 45M+ downloads
 *      and the base dict has zero entries for it.
 *
 *   6. tokio::process::Command — the async variant only had new/output/spawn.
 *      Missing .arg()/.args()/.env()/.current_dir()/.kill_on_drop() — the same
 *      chain methods as std::process::Command that carry taint through the builder
 *      pattern. The .arg() call is particularly important because that's WHERE
 *      tainted data enters the command execution pipeline.
 *
 * CRITICAL NOTE on Command arg chain tracking: Both std::process::Command and
 * tokio::process::Command use the builder pattern: Command::new("sh").arg("-c")
 * .arg(user_input).output(). The scanner needs to understand that .arg() propagates
 * taint — if ANY .arg() in the chain contains tainted data, the entire Command
 * execution is tainted. The base dict marks Command.arg as EXTERNAL/exec but with
 * tainted:false. This is WRONG for the general case — .arg() should be tainted:true
 * because it's the primary vector for injecting user input into shell commands.
 * I'm correcting this in the wiring step.
 *
 * FINDING: The base dict marks diesel::sql_query as STORAGE/db_read with tainted:false.
 * This is a raw SQL function — it SHOULD be tainted:true, same as any raw SQL surface.
 * diesel::sql_query("SELECT * FROM users WHERE name = '" + input + "'") is SQLi.
 * The safe path is diesel::sql_query("SELECT * FROM users WHERE name = $1").bind(input).
 * Correcting in wiring step.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_RUST_FRAMEWORK_GAPS: Record<string, CalleePattern> = {

  // -- 1. actix-web ServiceRequest — middleware-level taint source ------
  // ServiceRequest is what actix middleware receives. It wraps HttpRequest.
  // If your middleware reads sr.headers(), sr.path(), sr.query_string(),
  // that's user-controlled data the same as HttpRequest — but through a
  // type the scanner doesn't know about.
  'ServiceRequest.headers':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ServiceRequest.path':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ServiceRequest.query_string': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ServiceRequest.uri':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ServiceRequest.match_info':   { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ServiceRequest.peer_addr':    { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ServiceRequest.cookie':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ServiceRequest.head':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ServiceRequest.content_type': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- 2. actix-web ConnectionInfo + web::Header ----------------------
  // ConnectionInfo gives client IP (peer_addr), host, scheme — all spoofable
  // via X-Forwarded-For, Host header, etc.
  'ConnectionInfo.peer_addr':    { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ConnectionInfo.host':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ConnectionInfo.scheme':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ConnectionInfo.realip_remote_addr': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  // web::Header<T> — typed header extraction. Tainted because headers are user-controlled.
  'web::Header':                 { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  // web::ReqData<T> — middleware-injected request data. Could be tainted if middleware
  // inserts user-derived data, but typically it's server-derived. Marking false.
  'web::ReqData':                { nodeType: 'INGRESS', subtype: 'http_request', tainted: false },

  // -- 3. axum raw extractors + WebSocket -----------------------------
  // RawQuery gives the raw query string without parsing. Higher risk than Query<T>.
  'extract::RawQuery':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'axum::extract::RawQuery':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  // RawForm gives raw form bytes without deserialization.
  'extract::RawForm':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'axum::extract::RawForm':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  // WebSocketUpgrade opens a persistent bidirectional channel. The upgrade itself
  // is INGRESS because the client initiates it with tainted headers.
  'extract::WebSocketUpgrade':   { nodeType: 'INGRESS', subtype: 'websocket',    tainted: true },
  'axum::extract::ws::WebSocketUpgrade': { nodeType: 'INGRESS', subtype: 'websocket', tainted: true },
  // MatchedPath tells you which route pattern matched — not tainted (it's the route template).
  'extract::MatchedPath':        { nodeType: 'META',    subtype: 'routing_info', tainted: false },
  'extract::NestedPath':         { nodeType: 'META',    subtype: 'routing_info', tainted: false },
  // Extension — server-side injected data, like actix web::Data. Not tainted.
  'extract::Extension':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: false },
  'axum::extract::Extension':    { nodeType: 'INGRESS', subtype: 'http_request', tainted: false },

  // -- 4. tower middleware as CONTROL ---------------------------------
  // tower::ServiceBuilder is the middleware pipeline constructor.
  // .layer() adds middleware. This defines the control flow topology.
  'ServiceBuilder.layer':        { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'ServiceBuilder.service':      { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'ServiceBuilder::new':         { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'tower::ServiceBuilder.layer': { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'tower::ServiceBuilder::new':  { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  // tower-http layers — these are security-critical middleware
  'CorsLayer.new':               { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'CorsLayer::new':              { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'CorsLayer.permissive':        { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'CorsLayer::permissive':       { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'CorsLayer.very_permissive':   { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'CorsLayer::very_permissive':  { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'CorsLayer.allow_origin':      { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'CorsLayer.allow_methods':     { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'CorsLayer.allow_headers':     { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  // tower rate limiting / concurrency — RESOURCE (finite capacity)
  'ConcurrencyLimitLayer.new':   { nodeType: 'RESOURCE', subtype: 'rate_limit', tainted: false },
  'ConcurrencyLimitLayer::new':  { nodeType: 'RESOURCE', subtype: 'rate_limit', tainted: false },
  'RateLimitLayer.new':          { nodeType: 'RESOURCE', subtype: 'rate_limit', tainted: false },
  'RateLimitLayer::new':         { nodeType: 'RESOURCE', subtype: 'rate_limit', tainted: false },
  // tower timeout — CONTROL (guards against slow requests)
  'TimeoutLayer.new':            { nodeType: 'CONTROL', subtype: 'guard',       tainted: false },
  'TimeoutLayer::new':           { nodeType: 'CONTROL', subtype: 'guard',       tainted: false },

  // -- 5. tonic gRPC — metadata + streaming ---------------------------
  // Request::metadata() returns gRPC metadata (equivalent to HTTP headers).
  // This is tainted — clients send arbitrary metadata.
  'Request.metadata':            { nodeType: 'INGRESS', subtype: 'grpc_metadata', tainted: true },
  'tonic::Request.metadata':     { nodeType: 'INGRESS', subtype: 'grpc_metadata', tainted: true },
  'Request.remote_addr':         { nodeType: 'INGRESS', subtype: 'grpc_metadata', tainted: true },
  'tonic::Request.remote_addr':  { nodeType: 'INGRESS', subtype: 'grpc_metadata', tainted: true },
  'Request.into_inner':          { nodeType: 'INGRESS', subtype: 'grpc_request',  tainted: true },
  'tonic::Request.into_inner':   { nodeType: 'INGRESS', subtype: 'grpc_request',  tainted: true },
  // Streaming<T> — server receives a stream of messages from client. All tainted.
  'Streaming.next':              { nodeType: 'INGRESS', subtype: 'grpc_stream',   tainted: true },
  'Streaming.message':           { nodeType: 'INGRESS', subtype: 'grpc_stream',   tainted: true },
  'tonic::Streaming.next':       { nodeType: 'INGRESS', subtype: 'grpc_stream',   tainted: true },
  'tonic::Streaming.message':    { nodeType: 'INGRESS', subtype: 'grpc_stream',   tainted: true },
  // tonic::Status — gRPC response status. EGRESS.
  'Status.ok':                   { nodeType: 'EGRESS',  subtype: 'grpc_response', tainted: false },
  'Status.new':                  { nodeType: 'EGRESS',  subtype: 'grpc_response', tainted: false },
  'tonic::Status.new':           { nodeType: 'EGRESS',  subtype: 'grpc_response', tainted: false },
  'tonic::Status.ok':            { nodeType: 'EGRESS',  subtype: 'grpc_response', tainted: false },
  'tonic::Response.new':         { nodeType: 'EGRESS',  subtype: 'grpc_response', tainted: false },
  'Response.new':                { nodeType: 'EGRESS',  subtype: 'grpc_response', tainted: false },

  // -- 6. rusqlite — synchronous SQLite --------------------------------
  // Connection::open/open_in_memory — db_connect
  'Connection.open':             { nodeType: 'STORAGE', subtype: 'db_connect',   tainted: false },
  'Connection::open':            { nodeType: 'STORAGE', subtype: 'db_connect',   tainted: false },
  'Connection.open_in_memory':   { nodeType: 'STORAGE', subtype: 'db_connect',   tainted: false },
  'Connection::open_in_memory':  { nodeType: 'STORAGE', subtype: 'db_connect',   tainted: false },
  // conn.execute — runs SQL with parameters. The SQL string itself may be tainted.
  'conn.execute':                { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'conn.execute_batch':          { nodeType: 'STORAGE', subtype: 'db_write',     tainted: true },
  // execute_batch takes a raw SQL string with NO parameter binding — always tainted.
  // conn.prepare — creates a prepared statement. The SQL goes in here.
  'conn.prepare':                { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'conn.prepare_cached':         { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  // stmt.query_row / query_map — execute the prepared statement and read results
  'stmt.query_row':              { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'stmt.query_map':              { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'stmt.query':                  { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'stmt.execute':                { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  // conn.query_row — shorthand that combines prepare + query_row
  'conn.query_row':              { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  // Transaction
  'conn.transaction':            { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'tx.execute':                  { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'tx.query_row':                { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },

  // -- 7. tokio::process::Command — missing chain methods --------------
  // These mirror std::process::Command but async. The .arg() call is WHERE
  // tainted data enters the command pipeline.
  'tokio::process::Command.arg':         { nodeType: 'EXTERNAL', subtype: 'exec', tainted: true },
  'tokio::process::Command.args':        { nodeType: 'EXTERNAL', subtype: 'exec', tainted: true },
  'tokio::process::Command.env':         { nodeType: 'EXTERNAL', subtype: 'exec', tainted: false },
  'tokio::process::Command.current_dir': { nodeType: 'EXTERNAL', subtype: 'exec', tainted: false },
  'tokio::process::Command.stdin':       { nodeType: 'EXTERNAL', subtype: 'exec', tainted: false },
  'tokio::process::Command.stdout':      { nodeType: 'EXTERNAL', subtype: 'exec', tainted: false },
  'tokio::process::Command.stderr':      { nodeType: 'EXTERNAL', subtype: 'exec', tainted: false },
  'tokio::process::Command.status':      { nodeType: 'EXTERNAL', subtype: 'exec', tainted: false },
  'tokio::process::Command.kill_on_drop': { nodeType: 'EXTERNAL', subtype: 'exec', tainted: false },

} as const;

// -- CORRECTIONS TO BASE DICTIONARY (applied during wiring) ----------------
//
// 1. Command.arg and Command.args should be tainted:true, not false.
//    .arg() is the PRIMARY injection vector for command injection. If user input
//    reaches .arg(), the command is tainted. The base dict has tainted:false which
//    creates a false negative for CWE-78 when tainted data flows through .arg().
//
// 2. diesel::sql_query and diesel.sql_query should be tainted:true, not false.
//    sql_query() takes a raw SQL string. Unlike diesel's query builder (which is
//    safe by construction), sql_query is a raw SQL escape hatch. Any user input
//    concatenated into the SQL string = SQL injection.
//
// 3. conn.execute_batch is tainted:true because it takes a raw SQL string with
//    no parameter binding at all — it executes multiple statements separated by
//    semicolons. This is a text-level SQL injection surface.

// -- FINDINGS ---------------------------------------------------------------
//
// 1. OBSERVATION: The base dict has 'tonic::Request.new' as EXTERNAL/rpc.
//    This is incorrect — tonic::Request::new() wraps an outgoing gRPC message
//    on the CLIENT side, yes, but on the SERVER side it wraps the INCOMING request.
//    The type is overloaded. For server-side handlers, Request<T> is INGRESS,
//    not EXTERNAL. The scanner should use context (is this in a service impl block
//    or in a client call?) to disambiguate. I'm adding Request.into_inner and
//    Request.metadata as INGRESS to cover the server-side extraction path.
//
// 2. DANGEROUS PATTERN: tower::ServiceBuilder chains can SILENTLY DROP middleware
//    if the service type doesn't implement the required trait bounds. This means
//    a developer might add .layer(AuthLayer::new()) but if it fails to compile,
//    they might remove it rather than fix the trait bounds — leaving the endpoint
//    unprotected. This is a structural vulnerability that phonemes can't catch,
//    but a scanner could check for routes that have no CONTROL nodes in their
//    service chain.
//
// 3. CRITICAL: rusqlite's conn.execute_batch() is uniquely dangerous because it
//    executes MULTIPLE SQL statements from a single string with NO parameter
//    binding. This means an attacker can inject arbitrary SQL including DROP TABLE,
//    INSERT, or even ATTACH DATABASE for RCE. The base dict has nothing for
//    rusqlite at all — this was a complete blind spot.
//
// 4. MISSING PATTERN: Both actix-web and axum support custom extractors via
//    FromRequest trait. Any type implementing FromRequest becomes an INGRESS node.
//    The scanner can't enumerate all custom extractors, but it could flag any
//    impl FromRequest block as defining a potential INGRESS type.
