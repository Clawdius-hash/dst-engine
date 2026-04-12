/**
 * Rust Callee Pattern Database
 *
 * Maps Rust function/method names to DST Neural Map node types.
 * Covers: std (io, fs, env, process, sync, thread), serde, tokio, actix-web,
 *         axum, rocket, reqwest, hyper, sqlx, diesel, sea-orm, redis, mongodb,
 *         argon2, bcrypt, jsonwebtoken, ring, sha2, log, tracing.
 *
 * Sources:
 *   - corpus_audit_rust.json (38 Category B + 187 Category A patterns)
 *   - Rust stdlib and framework knowledge (gap-filling)
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (single identifier) ----------------------------------------
// Rust macros and free functions that appear without a module/receiver path.

const DIRECT_CALLS: Record<string, CalleePattern> = {
  // Macro output -- display
  'println':        { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  'eprintln':       { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  'print':          { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  'eprint':         { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  'write':          { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  'writeln':        { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  'dbg':            { nodeType: 'META',      subtype: 'debug',         tainted: false },

  // Macro output -- formatting
  'format':         { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  'format_args':    { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  'concat':         { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  'stringify':      { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  'todo':           { nodeType: 'META',      subtype: 'debug',         tainted: false },
  'unimplemented':  { nodeType: 'META',      subtype: 'debug',         tainted: false },
  'unreachable':    { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  'panic':          { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  'assert':         { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  'assert_eq':      { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  'assert_ne':      { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  'debug_assert':   { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  'debug_assert_eq': { nodeType: 'CONTROL',  subtype: 'validation',    tainted: false },
  'debug_assert_ne': { nodeType: 'CONTROL',  subtype: 'validation',    tainted: false },

  // vec! / vec construction
  'vec':            { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },

  // Logging macros (used as bare identifiers by log/tracing crates)
  'info':           { nodeType: 'META',      subtype: 'logging',       tainted: false },
  'warn':           { nodeType: 'META',      subtype: 'logging',       tainted: false },
  'error':          { nodeType: 'META',      subtype: 'logging',       tainted: false },
  'debug':          { nodeType: 'META',      subtype: 'logging',       tainted: false },
  'trace':          { nodeType: 'META',      subtype: 'logging',       tainted: false },
};

// -- Member calls (module::function or receiver.method) -----------------------

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS -- external data entering the system
  // =========================================================================

  // -- std::io::stdin --
  'stdin.read_line':            { nodeType: 'INGRESS', subtype: 'user_input',    tainted: true },
  'stdin.read_to_string':       { nodeType: 'INGRESS', subtype: 'user_input',    tainted: true },
  'stdin.read':                 { nodeType: 'INGRESS', subtype: 'user_input',    tainted: true },
  'stdin.lock':                 { nodeType: 'INGRESS', subtype: 'user_input',    tainted: true },
  'stdin.lines':                { nodeType: 'INGRESS', subtype: 'user_input',    tainted: true },
  'io.stdin':                   { nodeType: 'INGRESS', subtype: 'user_input',    tainted: true },
  'io::stdin':                  { nodeType: 'INGRESS', subtype: 'user_input',    tainted: true },
  'BufReader.read_line':        { nodeType: 'INGRESS', subtype: 'user_input',    tainted: true },
  'BufReader.lines':            { nodeType: 'INGRESS', subtype: 'user_input',    tainted: true },

  // -- std::env --
  'env.args':                   { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },
  'env::args':                  { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },
  'env.args_os':                { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },
  'env::args_os':               { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },
  'env.var':                    { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'env::var':                   { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'env.var_os':                 { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'env::var_os':                { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'env.vars':                   { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'env::vars':                  { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'env.vars_os':                { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'env::vars_os':               { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'env.current_dir':            { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'env::current_dir':           { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },

  // -- clap (CLI arg parsing) --
  'App.get_matches':            { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },
  'Command.get_matches':        { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },
  'matches.value_of':           { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },
  'matches.get_one':            { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },
  'matches.get_many':           { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },
  'matches.values_of':          { nodeType: 'INGRESS', subtype: 'env_read',      tainted: true },

  // -- std::fs (reading) --
  'fs.read_to_string':          { nodeType: 'INGRESS', subtype: 'file_read',     tainted: true },
  'fs::read_to_string':         { nodeType: 'INGRESS', subtype: 'file_read',     tainted: true },
  'fs.read':                    { nodeType: 'INGRESS', subtype: 'file_read',     tainted: true },
  'fs::read':                   { nodeType: 'INGRESS', subtype: 'file_read',     tainted: true },
  'fs.read_dir':                { nodeType: 'INGRESS', subtype: 'file_read',     tainted: false },
  'fs::read_dir':               { nodeType: 'INGRESS', subtype: 'file_read',     tainted: false },
  'fs.metadata':                { nodeType: 'INGRESS', subtype: 'file_read',     tainted: false },
  'fs::metadata':               { nodeType: 'INGRESS', subtype: 'file_read',     tainted: false },
  'fs.read_link':               { nodeType: 'INGRESS', subtype: 'file_read',     tainted: false },
  'fs::read_link':              { nodeType: 'INGRESS', subtype: 'file_read',     tainted: false },
  'fs.canonicalize':            { nodeType: 'INGRESS', subtype: 'file_read',     tainted: false },
  'fs::canonicalize':           { nodeType: 'INGRESS', subtype: 'file_read',     tainted: false },
  'File.open':                  { nodeType: 'INGRESS', subtype: 'file_read',     tainted: true },
  'File::open':                 { nodeType: 'INGRESS', subtype: 'file_read',     tainted: true },

  // -- tokio::fs (async reading) --
  'tokio::fs.read_to_string':   { nodeType: 'INGRESS', subtype: 'file_read',     tainted: true },
  'tokio::fs.read':             { nodeType: 'INGRESS', subtype: 'file_read',     tainted: true },

  // -- serde_json --
  'serde_json.from_str':        { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_json::from_str':       { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_json.from_slice':      { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_json::from_slice':     { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_json.from_reader':     { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_json::from_reader':    { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_json.from_value':      { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_json::from_value':     { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },

  // -- serde_yaml --
  'serde_yaml.from_str':        { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_yaml::from_str':       { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_yaml.from_reader':     { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_yaml::from_reader':    { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_yaml.from_slice':      { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'serde_yaml::from_slice':     { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },

  // -- toml --
  'toml.from_str':              { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'toml::from_str':             { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'toml.de.from_str':           { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },

  // -- bincode --
  'bincode.deserialize':        { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },
  'bincode::deserialize':       { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: true },

  // -- Actix-web --
  'web::Json':                  { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'web::Path':                  { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'web::Query':                 { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'web::Form':                  { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'web::Data':                  { nodeType: 'INGRESS', subtype: 'http_request',  tainted: false },
  'web::Bytes':                 { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'web::Payload':               { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'req.headers':                { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'req.uri':                    { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'req.cookie':                 { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'req.peer_addr':              { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'req.match_info':             { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'req.head':                   { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'req.path':                   { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'req.query_string':           { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'req.content_type':           { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'HttpRequest.headers':        { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'HttpRequest.uri':            { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'HttpRequest.cookie':         { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'HttpRequest.peer_addr':      { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'HttpRequest.match_info':     { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'HttpRequest.path':           { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'HttpRequest.query_string':   { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'HttpRequest.content_type':   { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },

  // -- Actix-web ServiceRequest (middleware-level) --
  'ServiceRequest.headers':     { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ServiceRequest.path':        { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ServiceRequest.query_string': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'ServiceRequest.uri':         { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ServiceRequest.match_info':  { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ServiceRequest.peer_addr':   { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ServiceRequest.cookie':      { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ServiceRequest.head':        { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ServiceRequest.content_type': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Actix-web ConnectionInfo + extra extractors --
  'ConnectionInfo.peer_addr':   { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ConnectionInfo.host':        { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ConnectionInfo.scheme':      { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'ConnectionInfo.realip_remote_addr': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'web::Header':                { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'web::ReqData':               { nodeType: 'INGRESS', subtype: 'http_request',  tainted: false },

  // -- Axum --
  'axum::extract::Json':        { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'axum::extract::Path':        { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'axum::extract::Query':       { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'axum::extract::State':       { nodeType: 'INGRESS', subtype: 'http_request',  tainted: false },
  'axum::extract::Form':        { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'axum::extract::Multipart':   { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'axum::extract::BodyStream':  { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'axum::extract::RawBody':     { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'extract::Json':              { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'extract::Path':              { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'extract::Query':             { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'extract::State':             { nodeType: 'INGRESS', subtype: 'http_request',  tainted: false },
  'extract::Form':              { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'extract::ConnectInfo':       { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'extract::Host':              { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'extract::OriginalUri':       { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'TypedHeader':                { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },

  // -- Axum raw extractors + WebSocket --
  'extract::RawQuery':          { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'axum::extract::RawQuery':    { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'extract::RawForm':           { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'axum::extract::RawForm':     { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'extract::WebSocketUpgrade':  { nodeType: 'INGRESS', subtype: 'websocket',     tainted: true },
  'axum::extract::ws::WebSocketUpgrade': { nodeType: 'INGRESS', subtype: 'websocket', tainted: true },
  'extract::MatchedPath':       { nodeType: 'META',    subtype: 'routing_info',  tainted: false },
  'extract::NestedPath':        { nodeType: 'META',    subtype: 'routing_info',  tainted: false },
  'extract::Extension':         { nodeType: 'INGRESS', subtype: 'http_request',  tainted: false },
  'axum::extract::Extension':   { nodeType: 'INGRESS', subtype: 'http_request',  tainted: false },

  // -- Rocket --
  'rocket::serde::json':        { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'rocket::form':               { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'rocket::serde::json::Json':  { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'rocket::form::Form':         { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'rocket::request::FromRequest': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Warp --
  'warp::body::json':           { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'warp::query':                { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'warp::path::param':          { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'warp::header':               { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'warp::cookie':               { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'warp::body::bytes':          { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },
  'warp::multipart':            { nodeType: 'INGRESS', subtype: 'http_request',  tainted: true },

  // -- config crates --
  'config::Config.get':         { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'Config.get':                 { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'Config.get_string':          { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'Config.get_int':             { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'dotenv.dotenv':              { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  'dotenvy::dotenv':            { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },

  // =========================================================================
  // EGRESS -- data leaving the system
  // =========================================================================

  // -- std::fs (writing) --
  'fs.write':                   { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs::write':                  { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs.remove_file':             { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs::remove_file':            { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs.remove_dir':              { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs::remove_dir':             { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs.remove_dir_all':          { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs::remove_dir_all':         { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs.rename':                  { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs::rename':                 { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs.copy':                    { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs::copy':                   { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs.create_dir':              { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs::create_dir':             { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs.create_dir_all':          { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'fs::create_dir_all':         { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'File.create':                { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'File::create':               { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'file.write_all':             { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'file.write':                 { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },

  // -- tokio::fs (async writing) --
  'tokio::fs.write':            { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'tokio::fs.remove_file':      { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },
  'tokio::fs.create_dir_all':   { nodeType: 'EGRESS',  subtype: 'file_write',    tainted: false },

  // -- serde serialization --
  'serde_json.to_string':       { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'serde_json::to_string':      { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'serde_json.to_string_pretty': { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'serde_json::to_string_pretty': { nodeType: 'EGRESS', subtype: 'serialize',    tainted: false },
  'serde_json.to_writer':       { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'serde_json::to_writer':      { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'serde_json.to_writer_pretty': { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'serde_json::to_writer_pretty': { nodeType: 'EGRESS', subtype: 'serialize',    tainted: false },
  'serde_json.to_value':        { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'serde_json::to_value':       { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'serde_yaml.to_string':       { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'serde_yaml::to_string':      { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'toml.to_string':             { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'toml::to_string':            { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'bincode.serialize':          { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },
  'bincode::serialize':         { nodeType: 'EGRESS',  subtype: 'serialize',     tainted: false },

  // -- Actix-web responses --
  'HttpResponse.Ok':            { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse::Ok':           { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse.BadRequest':    { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse::BadRequest':   { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse.NotFound':      { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse::NotFound':     { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse.InternalServerError': { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'HttpResponse::InternalServerError': { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'HttpResponse.Unauthorized':  { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse::Unauthorized': { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse.Forbidden':     { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse::Forbidden':    { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse.Created':       { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse::Created':      { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse.NoContent':     { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse::NoContent':    { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse.build':         { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse::build':        { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HttpResponse.body':          { nodeType: 'EGRESS',  subtype: 'html_output',   tainted: false },
  'HttpResponse::body':         { nodeType: 'EGRESS',  subtype: 'html_output',   tainted: false },

  // -- Axum responses --
  'axum::response::Json':       { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'axum::response::Html':       { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'axum::response::Redirect':   { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'response::Json':             { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'response::Html':             { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'response::Redirect':         { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'response::IntoResponse':     { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'StatusCode.OK':              { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },

  // -- Rocket responses --
  'rocket::response::Redirect': { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'content::RawHtml':           { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'content::RawJson':           { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },

  // -- Warp responses --
  'warp::reply::json':          { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'warp::reply::html':          { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'warp::reply::with_status':   { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'warp::redirect':             { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },

  // -- std::io::Write trait --
  'stdout.write':               { nodeType: 'EGRESS',  subtype: 'display',       tainted: false },
  'stdout.write_all':           { nodeType: 'EGRESS',  subtype: 'display',       tainted: false },
  'stdout.flush':               { nodeType: 'EGRESS',  subtype: 'display',       tainted: false },
  'stderr.write':               { nodeType: 'EGRESS',  subtype: 'display',       tainted: false },
  'stderr.write_all':           { nodeType: 'EGRESS',  subtype: 'display',       tainted: false },

  // =========================================================================
  // TRANSFORM -- data manipulation, parsing, encoding, crypto primitives
  // =========================================================================

  // -- serde_json value manipulation --
  'serde_json.json':            { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'serde_json::json':           { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Value.as_str':               { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Value.as_i64':               { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Value.as_f64':               { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Value.as_bool':              { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Value.as_array':             { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Value.as_object':            { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },

  // -- base64 --
  'base64.encode':              { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'base64::encode':             { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'base64.decode':              { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'base64::decode':             { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'base64::engine.encode':      { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'base64::engine.decode':      { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'STANDARD.encode':            { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'STANDARD.decode':            { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'URL_SAFE.encode':            { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'URL_SAFE.decode':            { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },

  // -- hex --
  'hex.encode':                 { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'hex::encode':                { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'hex.decode':                 { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'hex::decode':                { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },

  // -- url encoding --
  'urlencoding.encode':         { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'urlencoding::encode':        { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'urlencoding.decode':         { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'urlencoding::decode':        { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'percent_encoding.percent_encode': { nodeType: 'TRANSFORM', subtype: 'encode', tainted: false },
  'percent_encoding.percent_decode': { nodeType: 'TRANSFORM', subtype: 'encode', tainted: false },

  // -- sha2 / hash --
  'Sha256.new':                 { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha256::new':                { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha256.update':              { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha256.finalize':            { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha256.digest':              { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha256::digest':             { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha512.new':                 { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha512::new':                { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha512.update':              { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha512.finalize':            { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha512.digest':              { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Sha512::digest':             { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'sha2.Sha256':                { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'sha2.Sha512':                { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'blake2.Blake2b':             { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'blake3.hash':                { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'blake3::hash':               { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },

  // -- ring / hmac --
  'hmac.new':                   { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'hmac::Key.new':              { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'hmac.sign':                  { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'hmac::sign':                 { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'hmac.verify':                { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'hmac::verify':               { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ring::digest.digest':        { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ring::hmac.sign':            { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ring::hmac.verify':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ring::rand.SystemRandom':    { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ring::signature.sign':       { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ring::signature.verify':     { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ring::aead.seal_in_place':   { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ring::aead.open_in_place':   { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },

  // -- aes-gcm --
  'Aes256Gcm.encrypt':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Aes256Gcm::encrypt':         { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Aes256Gcm.decrypt':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Aes256Gcm::decrypt':         { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Aes128Gcm.encrypt':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'Aes128Gcm.decrypt':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ChaCha20Poly1305.encrypt':   { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ChaCha20Poly1305.decrypt':   { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },

  // -- rsa --
  'RsaPrivateKey.sign':         { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'RsaPublicKey.verify':        { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'RsaPrivateKey.decrypt':      { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'RsaPublicKey.encrypt':       { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'RsaPrivateKey::new':         { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },

  // -- regex --
  'Regex.new':                  { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Regex::new':                 { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Regex.is_match':             { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Regex.find':                 { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Regex.find_iter':            { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Regex.captures':             { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Regex.captures_iter':        { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Regex.replace':              { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Regex.replace_all':          { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Regex.split':                { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'regex::Regex.new':           { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'regex::Regex::new':          { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },

  // -- chrono --
  'Utc.now':                    { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'Utc::now':                   { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'Local.now':                  { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'Local::now':                 { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'NaiveDateTime.parse_from_str': { nodeType: 'TRANSFORM', subtype: 'format',   tainted: false },
  'NaiveDate.parse_from_str':   { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'DateTime.format':            { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'DateTime.timestamp':         { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'Duration.seconds':           { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'Duration::seconds':          { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'Duration.minutes':           { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'Duration.hours':             { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },

  // -- Path / PathBuf --
  'Path.new':                   { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'Path::new':                  { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'PathBuf.from':               { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'PathBuf::from':              { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'PathBuf.push':               { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'PathBuf.set_extension':      { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'path.join':                  { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'path.parent':                { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'path.file_name':             { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'path.extension':             { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'path.with_extension':        { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'path.strip_prefix':          { nodeType: 'TRANSFORM', subtype: 'sanitize_path',    tainted: false },
  'path.canonicalize':          { nodeType: 'TRANSFORM', subtype: 'sanitize_path',    tainted: false },

  // -- URL parsing --
  'Url.parse':                  { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Url::parse':                 { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Url.join':                   { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Url.host_str':               { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Url.path':                   { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Url.query':                  { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },

  // -- uuid --
  'Uuid.new_v4':                { nodeType: 'TRANSFORM', subtype: 'calculate',   tainted: false },
  'Uuid::new_v4':               { nodeType: 'TRANSFORM', subtype: 'calculate',   tainted: false },
  'Uuid.to_string':             { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'Uuid.parse_str':             { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'Uuid::parse_str':            { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },

  // -- OsRng (crypto-safe random) --
  'OsRng.fill_bytes':           { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'OsRng.next_u64':             { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'OsRng.next_u32':             { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'rand::rngs::OsRng':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'thread_rng.gen':             { nodeType: 'TRANSFORM', subtype: 'calculate',   tainted: false },
  'thread_rng.gen_range':       { nodeType: 'TRANSFORM', subtype: 'calculate',   tainted: false },

  // =========================================================================
  // CONTROL -- concurrency, flow control, validation
  // =========================================================================

  // -- tokio::spawn / async runtime --
  'tokio.spawn':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::spawn':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio.spawn_blocking':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::spawn_blocking':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio.select':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::select':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio.join':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::join':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio.time.sleep':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::time::sleep':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio.time.timeout':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::time::timeout':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio.time.interval':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::time::interval':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::runtime::Runtime.new': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Runtime.block_on':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Runtime.new':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Runtime::new':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::thread --
  'thread.spawn':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread::spawn':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread.sleep':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread::sleep':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread.current':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread::current':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread.park':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread.unpark':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'handle.join':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::sync::Mutex / RwLock --
  'Mutex.new':                  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Mutex::new':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Mutex.lock':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Mutex.try_lock':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'RwLock.new':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'RwLock::new':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'RwLock.read':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'RwLock.write':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'RwLock.try_read':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'RwLock.try_write':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Arc.new':                    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Arc::new':                   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Arc.clone':                  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Arc::clone':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Barrier.new':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Barrier::new':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Barrier.wait':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Condvar.new':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Condvar::new':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Condvar.wait':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Condvar.notify_one':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Condvar.notify_all':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Once.call_once':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Once::new':                  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::sync::mpsc --
  'mpsc.channel':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mpsc::channel':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mpsc.sync_channel':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mpsc::sync_channel':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tx.send':                    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'rx.recv':                    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'rx.try_recv':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'rx.recv_timeout':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'sender.send':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'receiver.recv':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- tokio::sync --
  'tokio::sync::Mutex.new':     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::sync::Mutex.lock':    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::sync::RwLock.new':    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::sync::RwLock.read':   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::sync::RwLock.write':  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Semaphore.new':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Semaphore::new':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Semaphore.acquire':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Semaphore.try_acquire':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Notify.new':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Notify::new':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Notify.notify_one':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Notify.notify_waiters':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Notify.notified':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'broadcast.channel':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'broadcast::channel':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'oneshot.channel':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'oneshot::channel':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::sync::mpsc.channel':  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'tokio::sync::mpsc.unbounded_channel': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'watch.channel':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'watch::channel':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::sync::atomic --
  'AtomicBool.new':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'AtomicBool::new':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'AtomicBool.store':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'AtomicBool.load':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'AtomicUsize.new':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'AtomicUsize::new':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'AtomicUsize.fetch_add':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'AtomicUsize.store':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'AtomicUsize.load':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::process::exit --
  'process.exit':               { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  'process::exit':              { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },

  // =========================================================================
  // AUTH -- authentication and authorization
  // =========================================================================

  // -- argon2 --
  'argon2.hash_encoded':        { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'argon2::hash_encoded':       { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'argon2.verify_encoded':      { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'argon2::verify_encoded':     { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Argon2.hash_password':       { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Argon2::hash_password':      { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Argon2.verify_password':     { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Argon2::verify_password':    { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Argon2.new':                 { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Argon2::new':                { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Argon2::default':            { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'PasswordHasher.hash_password': { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'PasswordHash.verify_password': { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },

  // -- bcrypt --
  'bcrypt.hash':                { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'bcrypt::hash':               { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'bcrypt.verify':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'bcrypt::verify':             { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'bcrypt.hash_with_result':    { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'bcrypt::hash_with_result':   { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- jsonwebtoken --
  'jsonwebtoken.encode':        { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'jsonwebtoken::encode':       { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'jsonwebtoken.decode':        { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'jsonwebtoken::decode':       { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'jsonwebtoken.dangerous_insecure_decode': { nodeType: 'AUTH', subtype: 'authenticate', tainted: true },
  'jsonwebtoken::dangerous_insecure_decode': { nodeType: 'AUTH', subtype: 'authenticate', tainted: true },
  'EncodingKey.from_secret':    { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'EncodingKey::from_secret':   { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'DecodingKey.from_secret':    { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'DecodingKey::from_secret':   { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Validation.new':             { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Validation::new':            { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Header.new':                 { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- actix-identity --
  'Identity.login':             { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Identity.logout':            { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Identity.id':                { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- cookie / session --
  'Cookie.build':               { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Cookie::build':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Cookie.new':                 { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'Cookie::new':                { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'CookieJar.add':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'CookieJar.remove':           { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'CookieJar.get':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: true },
  'PrivateCookieJar.add':       { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'PrivateCookieJar.get':       { nodeType: 'AUTH', subtype: 'authenticate',     tainted: true },
  'SignedCookieJar.add':        { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SignedCookieJar.get':        { nodeType: 'AUTH', subtype: 'authenticate',     tainted: true },

  // -- oauth2 --
  'BasicClient.new':            { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'BasicClient::new':           { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'BasicClient.authorize_url':  { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'BasicClient.exchange_code':  { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // =========================================================================
  // STORAGE -- database, cache, persistent state
  // =========================================================================

  // -- sqlx --
  'sqlx.query':                 { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlx::query':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlx.query_as':              { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlx::query_as':             { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlx.query_scalar':          { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlx::query_scalar':         { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'query.fetch_one':            { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'query.fetch_all':            { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'query.fetch_optional':       { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'query.fetch':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'query.execute':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'Pool.connect':               { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'Pool::connect':              { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'PgPool.connect':             { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'PgPool::connect':            { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'PgPoolOptions.connect':      { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'SqlitePool.connect':         { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'SqlitePool::connect':        { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'MySqlPool.connect':          { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'MySqlPool::connect':         { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },

  // -- diesel --
  'diesel.insert_into':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'diesel::insert_into':        { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'diesel.update':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'diesel::update':             { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'diesel.delete':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'diesel::delete':             { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'diesel.select':              { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'diesel::select':             { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'diesel.sql_query':           { nodeType: 'STORAGE', subtype: 'db_read',       tainted: true },
  'diesel::sql_query':          { nodeType: 'STORAGE', subtype: 'db_read',       tainted: true },
  'table.filter':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'table.select':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'table.order':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'table.limit':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },

  // -- sea-orm --
  'Entity.find':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'Entity::find':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'Entity.find_by_id':          { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'Entity::find_by_id':         { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'Entity.insert':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'Entity::insert':             { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'Entity.update':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'Entity::update':             { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'Entity.delete':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'Entity::delete':             { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'ActiveModel.insert':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'ActiveModel.update':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'ActiveModel.save':           { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'ActiveModel.delete':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'Database.connect':           { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'Database::connect':          { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },

  // -- redis --
  'redis.Client.open':          { nodeType: 'STORAGE', subtype: 'cache_connect', tainted: false },
  'redis::Client::open':        { nodeType: 'STORAGE', subtype: 'cache_connect', tainted: false },
  'con.get':                    { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },
  'con.set':                    { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'con.del':                    { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'con.hget':                   { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },
  'con.hset':                   { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'con.expire':                 { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'con.incr':                   { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'redis.cmd':                  { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },
  'redis::cmd':                 { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },
  'cmd.arg':                    { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },
  'cmd.query':                  { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },

  // -- mongodb --
  'Client.with_uri_str':        { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'Client::with_uri_str':       { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'collection.find':            { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'collection.find_one':        { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'collection.insert_one':      { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'collection.insert_many':     { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'collection.update_one':      { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'collection.update_many':     { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'collection.delete_one':      { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'collection.delete_many':     { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'collection.aggregate':       { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'collection.count_documents': { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'collection.distinct':        { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.collection':              { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },

  // -- rusqlite (synchronous SQLite) --
  'Connection.open':            { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'Connection::open':           { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'Connection.open_in_memory':  { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'Connection::open_in_memory': { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'conn.execute':               { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'conn.execute_batch':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: true },
  'conn.prepare':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'conn.prepare_cached':        { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'conn.query_row':             { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'conn.transaction':           { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'stmt.query_row':             { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'stmt.query_map':             { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'stmt.query':                 { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'stmt.execute':               { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },

  // =========================================================================
  // EXTERNAL -- outbound network calls, external process execution
  // =========================================================================

  // -- reqwest --
  'reqwest.get':                { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'reqwest::get':               { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'reqwest.post':               { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'Client.new':                 { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'Client::new':                { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'Client.builder':             { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'Client::builder':            { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'client.get':                 { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'client.post':                { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'client.put':                 { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'client.delete':              { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'client.patch':               { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'client.head':                { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'client.request':             { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'client.execute':             { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'request.send':               { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'response.text':              { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'response.json':              { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'response.bytes':             { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'response.status':            { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },

  // -- hyper --
  'hyper::Client.get':          { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'hyper::Client.request':      { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'hyper::body.to_bytes':       { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },
  'hyper::Server.bind':         { nodeType: 'EXTERNAL', subtype: 'http_call',    tainted: false },

  // -- std::process::Command --
  'Command.new':                { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },
  'Command::new':               { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },
  'Command.arg':                { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: true },
  'Command.args':               { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: true },
  'Command.output':             { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },
  'Command.spawn':              { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },
  'Command.status':             { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },
  'Command.env':                { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },
  'Command.stdin':              { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },
  'Command.stdout':             { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },
  'Command.stderr':             { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },
  'Command.current_dir':        { nodeType: 'EXTERNAL', subtype: 'exec',         tainted: false },

  // -- tokio::process::Command --
  'tokio::process::Command.new': { nodeType: 'EXTERNAL', subtype: 'exec',        tainted: false },
  'tokio::process::Command.output': { nodeType: 'EXTERNAL', subtype: 'exec',     tainted: false },
  'tokio::process::Command.spawn': { nodeType: 'EXTERNAL', subtype: 'exec',      tainted: false },
  'tokio::process::Command.arg': { nodeType: 'EXTERNAL', subtype: 'exec',        tainted: true },
  'tokio::process::Command.args': { nodeType: 'EXTERNAL', subtype: 'exec',       tainted: true },
  'tokio::process::Command.env': { nodeType: 'EXTERNAL', subtype: 'exec',        tainted: false },
  'tokio::process::Command.current_dir': { nodeType: 'EXTERNAL', subtype: 'exec', tainted: false },
  'tokio::process::Command.stdin': { nodeType: 'EXTERNAL', subtype: 'exec',      tainted: false },
  'tokio::process::Command.stdout': { nodeType: 'EXTERNAL', subtype: 'exec',     tainted: false },
  'tokio::process::Command.stderr': { nodeType: 'EXTERNAL', subtype: 'exec',     tainted: false },
  'tokio::process::Command.status': { nodeType: 'EXTERNAL', subtype: 'exec',     tainted: false },
  'tokio::process::Command.kill_on_drop': { nodeType: 'EXTERNAL', subtype: 'exec', tainted: false },

  // -- tonic (gRPC) --
  'tonic::transport::Channel.connect': { nodeType: 'EXTERNAL', subtype: 'rpc',   tainted: false },
  'tonic::Request.new':         { nodeType: 'EXTERNAL', subtype: 'rpc',          tainted: false },

  // -- tonic gRPC — server-side request extraction --
  'Request.metadata':           { nodeType: 'INGRESS', subtype: 'grpc_metadata', tainted: true },
  'tonic::Request.metadata':    { nodeType: 'INGRESS', subtype: 'grpc_metadata', tainted: true },
  'Request.remote_addr':        { nodeType: 'INGRESS', subtype: 'grpc_metadata', tainted: true },
  'tonic::Request.remote_addr': { nodeType: 'INGRESS', subtype: 'grpc_metadata', tainted: true },
  'Request.into_inner':         { nodeType: 'INGRESS', subtype: 'grpc_request',  tainted: true },
  'tonic::Request.into_inner':  { nodeType: 'INGRESS', subtype: 'grpc_request',  tainted: true },
  'Streaming.next':             { nodeType: 'INGRESS', subtype: 'grpc_stream',   tainted: true },
  'Streaming.message':          { nodeType: 'INGRESS', subtype: 'grpc_stream',   tainted: true },
  'tonic::Streaming.next':      { nodeType: 'INGRESS', subtype: 'grpc_stream',   tainted: true },
  'tonic::Streaming.message':   { nodeType: 'INGRESS', subtype: 'grpc_stream',   tainted: true },

  // -- tonic gRPC — responses (EGRESS) --
  'tonic::Status.new':          { nodeType: 'EGRESS',  subtype: 'grpc_response', tainted: false },
  'tonic::Status.ok':           { nodeType: 'EGRESS',  subtype: 'grpc_response', tainted: false },
  'tonic::Response.new':        { nodeType: 'EGRESS',  subtype: 'grpc_response', tainted: false },

  // =========================================================================
  // STRUCTURAL -- routing, middleware, module structure
  // =========================================================================

  // -- Actix-web routing --
  'App.new':                    { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'App::new':                   { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'App.route':                  { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'App.service':                { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'App.app_data':               { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'App.wrap':                   { nodeType: 'STRUCTURAL', subtype: 'middleware', tainted: false },
  'web.resource':               { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'web::resource':              { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'web.scope':                  { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'web::scope':                 { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'HttpServer.new':             { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'HttpServer::new':            { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'HttpServer.bind':            { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'HttpServer.run':             { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },

  // -- Axum routing --
  'Router.new':                 { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'Router::new':                { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'Router.route':               { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'Router.nest':                { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'Router.merge':               { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'Router.layer':               { nodeType: 'STRUCTURAL', subtype: 'middleware', tainted: false },
  'Router.with_state':          { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'axum::routing::get':         { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'axum::routing::post':        { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'axum::routing::put':         { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'axum::routing::delete':      { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'axum::routing::patch':       { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },

  // -- Rocket routing --
  'rocket.build':               { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'rocket::build':              { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'rocket.mount':               { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'rocket.launch':              { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'rocket.ignite':              { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },

  // -- Warp routing --
  'warp.path':                  { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'warp::path':                 { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'warp.get':                   { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'warp::get':                  { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'warp.post':                  { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'warp::post':                 { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },

  // -- tonic/gRPC routing --
  'Server.builder':             { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'Server::builder':            { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'Server.add_service':         { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },

  // -- tower middleware (CONTROL + RESOURCE) --
  'ServiceBuilder.layer':       { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'ServiceBuilder.service':     { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'ServiceBuilder::new':        { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'tower::ServiceBuilder.layer': { nodeType: 'CONTROL', subtype: 'middleware',   tainted: false },
  'tower::ServiceBuilder::new': { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  // tower-http CORS layer
  'CorsLayer.new':              { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'CorsLayer::new':             { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'CorsLayer.permissive':       { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'CorsLayer::permissive':      { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'CorsLayer.very_permissive':  { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'CorsLayer::very_permissive': { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'CorsLayer.allow_origin':     { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'CorsLayer.allow_methods':    { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  'CorsLayer.allow_headers':    { nodeType: 'CONTROL',  subtype: 'middleware',   tainted: false },
  // tower rate limiting / concurrency — RESOURCE (finite capacity)
  'ConcurrencyLimitLayer.new':  { nodeType: 'RESOURCE', subtype: 'rate_limit',  tainted: false },
  'ConcurrencyLimitLayer::new': { nodeType: 'RESOURCE', subtype: 'rate_limit',  tainted: false },
  'RateLimitLayer.new':         { nodeType: 'RESOURCE', subtype: 'rate_limit',  tainted: false },
  'RateLimitLayer::new':        { nodeType: 'RESOURCE', subtype: 'rate_limit',  tainted: false },
  // tower timeout
  'TimeoutLayer.new':           { nodeType: 'CONTROL',  subtype: 'guard',       tainted: false },
  'TimeoutLayer::new':          { nodeType: 'CONTROL',  subtype: 'guard',       tainted: false },

  // -- derive macros (structural) --
  'derive.Serialize':           { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'derive.Deserialize':         { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'derive.Clone':               { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'derive.Debug':               { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },

  // =========================================================================
  // META -- logging, config, testing, debug
  // =========================================================================

  // -- log crate --
  'log.info':                   { nodeType: 'META', subtype: 'logging',          tainted: false },
  'log::info':                  { nodeType: 'META', subtype: 'logging',          tainted: false },
  'log.warn':                   { nodeType: 'META', subtype: 'logging',          tainted: false },
  'log::warn':                  { nodeType: 'META', subtype: 'logging',          tainted: false },
  'log.error':                  { nodeType: 'META', subtype: 'logging',          tainted: false },
  'log::error':                 { nodeType: 'META', subtype: 'logging',          tainted: false },
  'log.debug':                  { nodeType: 'META', subtype: 'logging',          tainted: false },
  'log::debug':                 { nodeType: 'META', subtype: 'logging',          tainted: false },
  'log.trace':                  { nodeType: 'META', subtype: 'logging',          tainted: false },
  'log::trace':                 { nodeType: 'META', subtype: 'logging',          tainted: false },

  // -- tracing crate --
  'tracing.info':               { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing::info':              { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing.warn':               { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing::warn':              { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing.error':              { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing::error':             { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing.debug':              { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing::debug':             { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing.trace':              { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing::trace':             { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing.info_span':          { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing::info_span':         { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing.instrument':         { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing::instrument':        { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing.span':               { nodeType: 'META', subtype: 'logging',          tainted: false },
  'tracing::span':              { nodeType: 'META', subtype: 'logging',          tainted: false },

  // -- env_logger / tracing_subscriber --
  'env_logger.init':            { nodeType: 'META', subtype: 'config',           tainted: false },
  'env_logger::init':           { nodeType: 'META', subtype: 'config',           tainted: false },
  'env_logger.builder':         { nodeType: 'META', subtype: 'config',           tainted: false },
  'env_logger::builder':        { nodeType: 'META', subtype: 'config',           tainted: false },
  'env_logger::Builder.new':    { nodeType: 'META', subtype: 'config',           tainted: false },
  'tracing_subscriber.init':    { nodeType: 'META', subtype: 'config',           tainted: false },
  'tracing_subscriber::init':   { nodeType: 'META', subtype: 'config',           tainted: false },
  'tracing_subscriber.fmt':     { nodeType: 'META', subtype: 'config',           tainted: false },
  'tracing_subscriber::fmt':    { nodeType: 'META', subtype: 'config',           tainted: false },
  'pretty_env_logger.init':     { nodeType: 'META', subtype: 'config',           tainted: false },
  'pretty_env_logger::init':    { nodeType: 'META', subtype: 'config',           tainted: false },

  // -- testing --
  'assert.eq':                  { nodeType: 'META', subtype: 'test',             tainted: false },
  'assert.ne':                  { nodeType: 'META', subtype: 'test',             tainted: false },
  'test::TestServer.new':       { nodeType: 'META', subtype: 'test',             tainted: false },
  'actix_web::test.init_service': { nodeType: 'META', subtype: 'test',           tainted: false },
  'actix_web::test.call_service': { nodeType: 'META', subtype: 'test',           tainted: false },
  'actix_web::test.TestRequest': { nodeType: 'META', subtype: 'test',            tainted: false },
  'axum::test.oneshot':         { nodeType: 'META', subtype: 'test',             tainted: false },

  // -- config --
  'Config.builder':             { nodeType: 'META', subtype: 'config',           tainted: false },
  'Config::builder':            { nodeType: 'META', subtype: 'config',           tainted: false },
};

// -- Wildcard member calls (*.method) ----------------------------------------

const STORAGE_READ_METHODS = new Set([
  'find', 'find_one', 'find_by_id', 'fetch_one', 'fetch_all', 'fetch_optional',
  'fetch', 'query', 'query_as', 'query_scalar', 'get', 'hget',
  'select', 'filter', 'load', 'get_result', 'get_results',
  'aggregate', 'count_documents', 'distinct',
]);

const STORAGE_WRITE_METHODS = new Set([
  'execute', 'insert_one', 'insert_many', 'update_one', 'update_many',
  'delete_one', 'delete_many', 'insert_into', 'update', 'delete',
  'save', 'set', 'hset', 'del', 'expire', 'incr',
  'insert', 'create', 'remove',
]);

const TRANSFORM_STRING_METHODS = new Set([
  // String methods commonly called on str/String
  'trim', 'trim_start', 'trim_end', 'trim_matches',
  'to_lowercase', 'to_uppercase', 'to_ascii_lowercase', 'to_ascii_uppercase',
  'replace', 'replacen', 'split', 'splitn', 'rsplit', 'split_whitespace',
  'parse', 'chars', 'bytes', 'as_bytes', 'as_str',
  'contains', 'starts_with', 'ends_with', 'find', 'rfind',
  'repeat', 'len', 'is_empty',
  'to_string', 'to_owned', 'into',
  'format', 'display',
]);

// -- Lookup function ----------------------------------------------------------

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };
    return null;
  }

  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  const member = MEMBER_CALLS[exactKey];
  if (member) return { ...member };

  // Try deeper chains: "tokio::sync::Mutex.lock"
  if (calleeChain.length > 2) {
    const fullPath = calleeChain.join('.');
    const fullMember = MEMBER_CALLS[fullPath];
    if (fullMember) return { ...fullMember };

    // Try double-colon variant
    const colonPath = calleeChain.join('::');
    const colonMember = MEMBER_CALLS[colonPath];
    if (colonMember) return { ...colonMember };

    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
  }

  // Wildcard: storage read methods
  if (STORAGE_READ_METHODS.has(methodName)) {
    if (!NON_DB_OBJECTS.has(objectName)) {
      return { nodeType: 'STORAGE', subtype: 'db_read', tainted: false };
    }
  }

  // Wildcard: storage write methods
  if (STORAGE_WRITE_METHODS.has(methodName)) {
    if (!NON_DB_OBJECTS.has(objectName)) {
      return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false };
    }
  }

  // Wildcard: string transform methods
  if (TRANSFORM_STRING_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'format', tainted: false };
  }

  return null;
}

const NON_DB_OBJECTS = new Set([
  'req', 'request', 'response', 'resp', 'res',
  'stdin', 'stdout', 'stderr', 'io',
  'fs', 'env', 'process', 'thread', 'tokio',
  'serde_json', 'serde_yaml', 'toml', 'bincode',
  'base64', 'hex', 'urlencoding', 'percent_encoding',
  'log', 'tracing', 'env_logger', 'tracing_subscriber', 'pretty_env_logger',
  'Regex', 'regex', 'Path', 'PathBuf', 'Url',
  'Sha256', 'Sha512', 'sha2', 'blake3', 'hmac', 'ring',
  'Mutex', 'RwLock', 'Arc', 'Barrier', 'Condvar', 'Once',
  'Semaphore', 'Notify', 'AtomicBool', 'AtomicUsize',
  'mpsc', 'broadcast', 'oneshot', 'watch',
  'tx', 'rx', 'sender', 'receiver',
  'Uuid', 'Duration', 'DateTime', 'Utc', 'Local', 'NaiveDateTime', 'NaiveDate',
  'self', 'Self', 'super', 'crate',
  'String', 'str', 'Vec', 'Option', 'Result',
  'Iterator', 'HashMap', 'BTreeMap', 'HashSet',
  'Aes256Gcm', 'Aes128Gcm', 'ChaCha20Poly1305',
  'RsaPrivateKey', 'RsaPublicKey',
  'argon2', 'Argon2', 'bcrypt', 'jsonwebtoken',
  'reqwest', 'hyper', 'client',
  'warp', 'rocket',
  'App', 'HttpServer', 'HttpResponse', 'Router', 'Server',
  'Cookie', 'CookieJar', 'PrivateCookieJar', 'SignedCookieJar',
  'Identity', 'BasicClient',
  'file', 'File', 'handle',
  'Config', 'config',
  'OsRng', 'thread_rng',
  // tower / tonic / actix middleware types
  'ServiceBuilder', 'CorsLayer', 'ConcurrencyLimitLayer', 'RateLimitLayer', 'TimeoutLayer',
  'ServiceRequest', 'ConnectionInfo',
  'Streaming', 'Request', 'Response', 'Status',
]);

// -- Sink patterns (CWE -> dangerous regex) -----------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /Command::new\s*\(\s*(?:format!|&\w+|(?:&)?(?:input|user|param|arg|data))/,
  'CWE-89':  /(?:query|execute)\s*\(\s*&?format!\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE)/,
  'CWE-119': /\bunsafe\s*\{/,
  'CWE-134': /format!\s*\(\s*(?:&)?\w+\s*[,)]/,
  'CWE-502': /serde_json::from_str\s*\(\s*(?:&?body|&?input|&?request)/,
  'CWE-798': /(?:password|secret|api_key|token)\s*[:=]\s*"[^"]{8,}"/,
  'CWE-22':  /Path::new\s*\([^)]*\)\.join\s*\([^)]*(?:req|params|query|body|input)/,
  'CWE-79':  /content::RawHtml\s*\(\s*format!\s*\(/,
  'CWE-295': /danger_accept_invalid_certs\s*\(\s*true\s*\)/,
  'CWE-327': /(?:md5|Md5)::(?:new|digest|compute)/,
  'CWE-338': /rand::thread_rng\s*\(\s*\)(?=[\s\S]*(?:token|password|secret|key|nonce))/,
  'CWE-347': /jsonwebtoken::dangerous_insecure_decode/,
  'CWE-362': /static\s+mut\s+/,
  'CWE-400': /hyper::Server::bind/,
  'CWE-532': /(?:log|tracing)::(?:info|debug|warn|error)!\s*\([^)]*(?:password|secret|token|key|credential)/,
  'CWE-614': /Cookie::build\s*\([^)]*\)(?![\s\S]*\.secure\s*\(\s*true)/,
  'CWE-918': /reqwest::(?:get|Client::new)\s*\(\s*(?:input|user|request|param|url_str)/,
  'CWE-942': /(?:AllowOrigin::any\(\)|allow_any_origin|Cors::permissive|CorsLayer::(?:very_)?permissive)/,
};

// -- Safe patterns (CWE -> mitigating regex) ----------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /Command::new\s*\(\s*"[^"]*"\s*\)/,                     // literal command name
  'CWE-89':  /sqlx::query\s*\(\s*"[^"]*\$\d+[^"]*"\s*\)/,           // parameterized query ($1, $2)
  'CWE-119': /#!\[forbid\(unsafe_code\)\]/,                           // forbid unsafe
  'CWE-295': /danger_accept_invalid_certs\s*\(\s*false\s*\)/,
  'CWE-327': /(?:Sha256|Sha512|sha2|blake3|blake2)::(?:new|digest|hash)/, // strong hashes
  'CWE-338': /(?:OsRng|rand::rngs::OsRng)/,                          // crypto-safe RNG
  'CWE-347': /jsonwebtoken::decode\s*[^;]*Validation::new/,           // JWT with validation
  'CWE-362': /(?:Mutex|RwLock|Arc<Mutex|tokio::sync::Mutex)/,         // proper synchronization
  'CWE-400': /tokio::time::timeout/,                                    // timeout protection
  'CWE-502': /deny_unknown_fields/,                                     // strict deserialization
  'CWE-798': /(?:env::var|std::env::var|dotenvy|dotenv)\s*\(/,        // env-based secrets
  'CWE-918': /Url::parse\s*\(/,                                        // URL validation
};

// -- Pattern count ------------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size
    + TRANSFORM_STRING_METHODS.size;
}
