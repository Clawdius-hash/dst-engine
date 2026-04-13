/**
 * Callee Pattern Database — maps ~100 known JS function/method names
 * to Neural Map node types with subtypes and taint flags.
 *
 * Three lookup strategies:
 *   1. Direct calls: single identifier like fetch, require, eval
 *   2. Member calls: object.method like res.json, fs.readFile, JSON.parse
 *   3. Wildcard member calls: *.method for any-object patterns like .query, .find
 *
 * Usage:
 *   const result = lookupCallee(['res', 'json']);
 *   // { nodeType: 'EGRESS', subtype: 'http_response', tainted: false }
 */

import type { NodeType } from './types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean; // INGRESS sources are auto-tainted
  wildcard?: boolean;
}

// ── Direct calls (single identifier) ──────────────────────────────────────

const DIRECT_CALLS: Record<string, CalleePattern> = {
  // EXTERNAL
  fetch:                  { nodeType: 'EXTERNAL',   subtype: 'api_call',      tainted: false },
  XMLHttpRequest:         { nodeType: 'EXTERNAL',   subtype: 'api_call',      tainted: false },
  eval:                   { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  Function:               { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // TRANSFORM
  parseInt:               { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  parseFloat:             { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  Number:                 { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  String:                 { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  Boolean:                { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  atob:                   { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  btoa:                   { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  encodeURIComponent:     { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  decodeURIComponent:     { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  encodeURI:              { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  decodeURI:              { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },
  escape:                 { nodeType: 'TRANSFORM',  subtype: 'sanitize',      tainted: false },
  unescape:               { nodeType: 'TRANSFORM',  subtype: 'encode',        tainted: false },

  // STRUCTURAL
  require:                { nodeType: 'STRUCTURAL',  subtype: 'dependency',   tainted: false },

  // CONTROL
  setTimeout:             { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },
  setInterval:            { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },
  setImmediate:           { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },
  clearTimeout:           { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },
  clearInterval:          { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },

  // EGRESS
  alert:                  { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },

  // EXTERNAL — Web Workers, dynamic code
  Worker:                 { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  SharedWorker:           { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  WebSocket:              { nodeType: 'EXTERNAL',   subtype: 'api_call',      tainted: false },
  EventSource:            { nodeType: 'INGRESS',    subtype: 'stream_read',   tainted: true },

  // STRUCTURAL — Web Workers
  importScripts:          { nodeType: 'STRUCTURAL',  subtype: 'dependency',   tainted: false },

  // EXTERNAL — insecure deserialization (destructured imports)
  unserialize:            { nodeType: 'EXTERNAL',   subtype: 'deserialize',   tainted: false },

  // EXTERNAL — exec family (child_process destructured)
  exec:                   { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  execSync:               { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  spawn:                  { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  spawnSync:              { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  fork:                   { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // RESOURCE — direct calls that consume finite shared capacity
  RegExp:                 { nodeType: 'RESOURCE',   subtype: 'cpu',           tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // GraphQL — Apollo Server / GraphQL Yoga / graphql-tools
  // ═══════════════════════════════════════════════════════════════════════════

  // graphql-tag: gql`` template literal parses GraphQL query strings. Injection
  // vector if template string is dynamically constructed from user input.
  gql:                    { nodeType: 'TRANSFORM',  subtype: 'graphql_parse', tainted: false },

  // Apollo Server / graphql-tools: composes type definitions + resolvers into a runnable schema.
  makeExecutableSchema:   { nodeType: 'STRUCTURAL', subtype: 'schema_def',    tainted: false },

  // GraphQL Yoga: createYoga() creates a Yoga server instance — framework entrypoint.
  createYoga:             { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // Next.js — server-side data fetching as phonemes
  // ═══════════════════════════════════════════════════════════════════════════

  // getServerSideProps runs server-side on every request. Its context parameter
  // exposes context.req, context.query, context.params — all user-controlled.
  getServerSideProps:     { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ═══════════════════════════════════════════════════════════════════════════
  // Security middleware — express-session, helmet, cors
  // ═══════════════════════════════════════════════════════════════════════════

  // express-session: server-side session middleware. Security-critical config:
  // secret (forgeable if weak), cookie.secure, cookie.httpOnly, cookie.sameSite.
  session:                { nodeType: 'META',       subtype: 'session_config',    tainted: false },

  // helmet(): sets HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).
  // Its absence is a vulnerability; its config defines transport-layer policy.
  helmet:                 { nodeType: 'META',       subtype: 'security_headers',  tainted: false },

  // cors(): controls cross-origin access. origin:'*' with credentials:true
  // leaks credentials to any origin. Regex origin matching is often too permissive.
  cors:                   { nodeType: 'META',       subtype: 'cors_config',       tainted: false },
};

// ── Member calls (object.method) ──────────────────────────────────────────
// Key format: "object.method"

const MEMBER_CALLS: Record<string, CalleePattern> = {
  // ── req.* → INGRESS ──
  'req.body':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.params':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.query':            { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.headers':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.cookies':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.get':              { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.header':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.ip':               { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.path':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.hostname':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.url':              { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.files':            { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'req.file':             { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'request.body':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.params':       { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.query':        { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.headers':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.files':        { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'request.file':         { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },

  // -- Multer file upload middleware --
  'multer.single':        { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'multer.array':         { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'multer.fields':        { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'multer.any':           { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'upload.single':        { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'upload.array':         { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'upload.fields':        { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },
  'multer.diskStorage':   { nodeType: 'STORAGE',    subtype: 'file_write',    tainted: false },
  'multer.memoryStorage': { nodeType: 'STORAGE',    subtype: 'file_write',    tainted: false },

  // ── res.* → EGRESS ──
  'res.send':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.json':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.render':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.redirect':         { nodeType: 'EGRESS',     subtype: 'redirect',      tainted: false },
  'res.status':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.end':              { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.write':            { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.sendFile':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.download':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.cookie':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.set':              { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'res.type':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'response.send':        { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'response.json':        { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },

  // ── console.* → EGRESS ──
  'console.log':          { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.error':        { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.warn':         { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.info':         { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.debug':        { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },
  'console.trace':        { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },

  // ── Third-party logger sinks → EGRESS/log_write (CWE-117 expansion) ──
  'winston.log':          { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'winston.info':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'winston.error':        { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'winston.warn':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'winston.debug':        { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'logger.log':           { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'logger.info':          { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'logger.error':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'logger.warn':          { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'logger.debug':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'logger.fatal':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'logger.verbose':       { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'pino.info':            { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'pino.error':           { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'pino.warn':            { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'pino.debug':           { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'pino.fatal':           { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'bunyan.info':          { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'bunyan.error':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'bunyan.warn':          { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'bunyan.debug':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'bunyan.fatal':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'log4js.info':          { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'log4js.error':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'log4js.warn':          { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'log4js.debug':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },
  'log4js.fatal':         { nodeType: 'EGRESS',     subtype: 'log_write',     tainted: false },

  // ── fs.* → INGRESS (read) / EGRESS (write) ──
  'fs.readFile':          { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.readFileSync':      { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.createReadStream':  { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.readdir':           { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.readdirSync':       { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.stat':              { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.statSync':          { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'fs.writeFile':         { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.writeFileSync':     { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.createWriteStream': { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.appendFile':        { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.appendFileSync':    { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.unlink':            { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'fs.unlinkSync':        { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },

  // ── process.* → INGRESS ──
  'process.env':          { nodeType: 'INGRESS',    subtype: 'env_read',      tainted: true },
  'process.argv':         { nodeType: 'INGRESS',    subtype: 'env_read',      tainted: true },
  'process.stdin':        { nodeType: 'INGRESS',    subtype: 'user_input',    tainted: true },
  'process.exit':         { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },

  // ── child_process.* → EXTERNAL ──
  'child_process.exec':      { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'child_process.execSync':  { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'child_process.spawn':     { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'child_process.spawnSync': { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'child_process.fork':      { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },

  // ── JSON.* → TRANSFORM ──
  'JSON.parse':           { nodeType: 'TRANSFORM',  subtype: 'parse',         tainted: false },
  'JSON.stringify':       { nodeType: 'TRANSFORM',  subtype: 'serialize',     tainted: false },

  // ── Object.* → TRANSFORM (mass assignment vectors) ──
  'Object.assign':        { nodeType: 'TRANSFORM',  subtype: 'mass_assignment', tainted: false },
  'Object.defineProperty':{ nodeType: 'TRANSFORM',  subtype: 'property_def',   tainted: false },
  'Object.create':        { nodeType: 'TRANSFORM',  subtype: 'instantiation',  tainted: false },
  'Object.fromEntries':   { nodeType: 'TRANSFORM',  subtype: 'mass_assignment', tainted: false },

  // ── Promise.* → TRANSFORM (transparent wrappers — taint passes through) ──
  'Promise.resolve':      { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },
  'Promise.reject':       { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },
  'Promise.all':          { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },
  'Promise.race':         { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },
  'Promise.allSettled':   { nodeType: 'TRANSFORM',  subtype: 'promise_wrap',   tainted: false },

  // ── crypto.* → TRANSFORM ──
  'crypto.createHash':    { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.createHmac':    { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.randomBytes':   { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.createCipheriv':{ nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.createDecipheriv':{ nodeType: 'TRANSFORM',subtype: 'encrypt',       tainted: false },
  'crypto.pbkdf2':        { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },
  'crypto.scrypt':        { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },

  // ── crypto.* DEPRECATED → EXTERNAL (no IV, broken key derivation) ──
  'crypto.createCipher':  { nodeType: 'EXTERNAL',   subtype: 'deprecated_crypto', tainted: false },
  'crypto.createDecipher':{ nodeType: 'EXTERNAL',   subtype: 'deprecated_crypto', tainted: false },

  // ── crypto.* digital signatures → AUTH ──
  'crypto.createSign':    { nodeType: 'AUTH',        subtype: 'signature',     tainted: false },
  'crypto.createVerify':  { nodeType: 'AUTH',        subtype: 'signature',     tainted: false },

  // ── bcrypt.* → AUTH ──
  'bcrypt.compare':       { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'bcrypt.compareSync':   { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'bcrypt.hash':          { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'bcrypt.hashSync':      { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'bcrypt.genSalt':       { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'bcrypt.genSaltSync':   { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },

  // ── jwt.* → AUTH ──
  'jwt.sign':             { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'jwt.verify':           { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'jwt.decode':           { nodeType: 'TRANSFORM',   subtype: 'parse',         tainted: false },
  'jsonwebtoken.sign':    { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'jsonwebtoken.verify':  { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },

  // ── passport.* → AUTH / STRUCTURAL ──
  'passport.authenticate': { nodeType: 'AUTH',       subtype: 'authenticate',  tainted: false },
  'passport.use':          { nodeType: 'STRUCTURAL', subtype: 'auth_config',   tainted: false },

  // ── http/https.* → EXTERNAL ──
  'http.request':         { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'http.get':             { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'https.request':        { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'https.get':            { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },

  // ── axios.* → EXTERNAL ──
  'axios.get':            { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.post':           { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.put':            { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.delete':         { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.patch':          { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'axios.request':        { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },

  // ── needle.* → EXTERNAL (Node.js HTTP client — SSRF vector) ──
  'needle.get':           { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'needle.post':          { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'needle.put':           { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'needle.request':       { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },

  // ── window.* → EXTERNAL / EGRESS / INGRESS ──
  'window.fetch':         { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'window.open':          { nodeType: 'EXTERNAL',    subtype: 'api_call',      tainted: false },
  'window.alert':         { nodeType: 'EGRESS',      subtype: 'display',       tainted: false },
  // postMessage LISTENER — the receiving side. event.data is attacker-controlled
  // unless event.origin is validated. CWE-345.
  'window.addEventListener': { nodeType: 'INGRESS',  subtype: 'postmessage',   tainted: true },

  // ── XML parsing sinks (XXE vectors) ──
  'libxmljs.parseXmlString': { nodeType: 'TRANSFORM', subtype: 'xml_parse',     tainted: false },
  'libxmljs.parseXml':       { nodeType: 'TRANSFORM', subtype: 'xml_parse',     tainted: false },
  'libxmljs2.parseXmlString': { nodeType: 'TRANSFORM', subtype: 'xml_parse',    tainted: false },
  'libxmljs2.parseXml':      { nodeType: 'TRANSFORM', subtype: 'xml_parse',     tainted: false },
  'libxml.parseXmlString':   { nodeType: 'TRANSFORM', subtype: 'xml_parse',     tainted: false },
  'libxml.parseXml':         { nodeType: 'TRANSFORM', subtype: 'xml_parse',     tainted: false },
  'xml2js.parseString':      { nodeType: 'TRANSFORM', subtype: 'xml_parse',     tainted: false },
  'xml2js.parseStringPromise': { nodeType: 'TRANSFORM', subtype: 'xml_parse',   tainted: false },
  'DOMParser.parseFromString': { nodeType: 'TRANSFORM', subtype: 'xml_parse',   tainted: false },

  // ── Insecure deserialization sinks ──
  'serialize.unserialize':  { nodeType: 'EXTERNAL',   subtype: 'deserialize',   tainted: false },
  'node-serialize.unserialize': { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // ── YAML parsing (yaml.load is UNSAFE, yaml.safeLoad is SAFE) ──
  'yaml.load':              { nodeType: 'EXTERNAL',   subtype: 'deserialize',   tainted: false },
  'yaml.loadAll':           { nodeType: 'EXTERNAL',   subtype: 'deserialize',   tainted: false },
  'yaml.safeLoad':          { nodeType: 'TRANSFORM',  subtype: 'parse',         tainted: false },
  'yaml.safeLoadAll':       { nodeType: 'TRANSFORM',  subtype: 'parse',         tainted: false },
  'YAML.parse':             { nodeType: 'TRANSFORM',  subtype: 'parse',         tainted: false },

  // ── Template engines (SSTI vectors) ──
  'ejs.render':             { nodeType: 'EXTERNAL',   subtype: 'template_exec', tainted: false },
  'ejs.renderFile':         { nodeType: 'EXTERNAL',   subtype: 'template_exec', tainted: false },
  'pug.render':             { nodeType: 'EXTERNAL',   subtype: 'template_exec', tainted: false },
  'pug.renderFile':         { nodeType: 'EXTERNAL',   subtype: 'template_exec', tainted: false },
  'handlebars.compile':     { nodeType: 'EXTERNAL',   subtype: 'template_exec', tainted: false },
  'nunjucks.renderString':  { nodeType: 'EXTERNAL',   subtype: 'template_exec', tainted: false },

  // ── Zip extraction sinks (path traversal vectors) ──
  'zip.extractAllTo':       { nodeType: 'STORAGE',    subtype: 'file_write',    tainted: false },
  'zip.extractEntryTo':     { nodeType: 'STORAGE',    subtype: 'file_write',    tainted: false },
  'zip.extractAllToAsync':  { nodeType: 'STORAGE',    subtype: 'file_write',    tainted: false },

  // ── vm.* → EXTERNAL (code execution sinks) ──
  'vm.runInNewContext':     { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'vm.runInThisContext':    { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'vm.runInContext':        { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'vm.compileFunction':     { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'vm.createContext':       { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // ── Reflect.* → EXTERNAL (meta-programming, can invoke arbitrary code) ──
  'Reflect.apply':          { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'Reflect.construct':      { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // ── navigator.* → EGRESS ──
  'navigator.sendBeacon':   { nodeType: 'EGRESS',     subtype: 'api_call',      tainted: false },

  // ── window.postMessage → EGRESS (cross-origin communication) ──
  'window.postMessage':     { nodeType: 'EGRESS',     subtype: 'ipc',           tainted: false },

  // ── global/globalThis eval aliases ──
  'global.eval':            { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'globalThis.eval':        { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // ── URL.* ──
  'URL.createObjectURL':    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },

  // ── crypto.subtle.* (Web Crypto API) ──
  'crypto.subtle':          { nodeType: 'TRANSFORM',  subtype: 'encrypt',       tainted: false },

  // ── document.* → EGRESS / INGRESS ──
  'document.write':       { nodeType: 'EGRESS',      subtype: 'xss_sink',      tainted: false },
  'document.writeln':     { nodeType: 'EGRESS',      subtype: 'xss_sink',      tainted: false },
  'document.cookie':      { nodeType: 'INGRESS',     subtype: 'user_input',    tainted: true },
  'document.location':    { nodeType: 'INGRESS',     subtype: 'user_input',    tainted: true },

  // ── Express app.* → STRUCTURAL (route definitions) ──
  'app.get':              { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.post':             { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.put':              { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.delete':           { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.patch':            { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.use':              { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'app.all':              { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.listen':           { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },
  'router.get':           { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'router.post':          { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'router.put':           { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'router.delete':        { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'router.patch':         { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'router.use':           { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'router.all':           { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Fastify
  // ═══════════════════════════════════════════════════════════════════════════
  // Fastify uses (request, reply) convention instead of (req, res)
  // request.body is JSON-parsed by default (no body-parser middleware needed)

  // ── Fastify request.* → INGRESS ──
  // request.body, request.params, request.query, request.headers already defined in Express section above

  // ── Fastify reply.* → EGRESS ──
  'reply.send':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.code':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.status':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.header':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.headers':        { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.type':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.redirect':       { nodeType: 'EGRESS',     subtype: 'redirect',      tainted: false },
  'reply.serialize':      { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.raw':            { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.hijack':         { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'reply.setCookie':      { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },

  // ── Fastify request.raw → INGRESS (raw Node.js IncomingMessage) ──
  'request.raw':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ── Fastify instance.* → STRUCTURAL ──
  'fastify.register':     { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'fastify.decorate':     { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'fastify.addHook':      { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'fastify.inject':       { nodeType: 'EXTERNAL',   subtype: 'api_call',      tainted: false },
  'fastify.get':          { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'fastify.post':         { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'fastify.put':          { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'fastify.delete':       { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'fastify.patch':        { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'fastify.all':          { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'fastify.listen':       { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Koa
  // ═══════════════════════════════════════════════════════════════════════════
  // Koa uses a single `ctx` context object — ctx.request for ingress, ctx.response/ctx.body for egress
  // Common pattern: ctx.request.body (via koa-bodyparser), ctx.params (via koa-router)

  // ── Koa ctx.* → INGRESS ──
  'ctx.request':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.params':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.query':            { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.headers':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.cookies':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.get':              { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.ip':               { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.url':              { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.path':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.host':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.hostname':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.href':             { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.origin':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'ctx.originalUrl':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ── Koa ctx.* → EGRESS ──
  'ctx.body':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.status':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.type':             { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.set':              { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.redirect':         { nodeType: 'EGRESS',     subtype: 'redirect',      tainted: false },
  'ctx.attachment':       { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'ctx.throw':            { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },
  'ctx.assert':           { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },

  // ── Koa ctx.state → used for passing data between middleware ──
  'ctx.state':            { nodeType: 'TRANSFORM',  subtype: 'middleware_state', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Hapi
  // ═══════════════════════════════════════════════════════════════════════════
  // Hapi uses (request, h) — request for ingress, h (response toolkit) for egress

  // ── Hapi request.* → INGRESS (request.params, request.query, request.headers already covered) ──
  'request.payload':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.state':        { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.auth':         { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'request.url':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.path':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'request.info':         { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ── Hapi h.* (response toolkit) → EGRESS ──
  'h.response':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'h.redirect':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'h.file':               { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'h.view':               { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'h.continue':           { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },

  // ── Hapi server.* → STRUCTURAL ──
  'server.route':         { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'server.register':      { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'server.auth':          { nodeType: 'AUTH',        subtype: 'authenticate',  tainted: false },
  'server.ext':           { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'server.decorate':      { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },
  'server.start':         { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Next.js
  // ═══════════════════════════════════════════════════════════════════════════
  // Next.js API routes use (req, res) like Express — but also have App Router patterns
  // App Router: NextRequest/NextResponse, route handlers export GET/POST/etc.

  // ── Next.js NextResponse.* → EGRESS ──
  'NextResponse.json':    { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'NextResponse.redirect':{ nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'NextResponse.rewrite': { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'NextResponse.next':    { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },

  // ── Next.js req.* (extends IncomingMessage) — already covered by Express patterns ──
  // ── Next.js cookies()/headers() server functions → INGRESS ──
  'nextReq.nextUrl':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.cookies':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.headers':      { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.url':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.geo':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'nextReq.ip':           { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: NestJS
  // ═══════════════════════════════════════════════════════════════════════════
  // NestJS wraps Express/Fastify — uses decorators for route definition but the
  // underlying req/res objects are still Express-style. Key patterns:
  // - @Body(), @Param(), @Query(), @Headers() decorators
  // - Underlying Express req/res available via @Req()/@Res()
  // - NestJS pipes for validation (ValidationPipe, ParseIntPipe)
  // - Guards for auth (@UseGuards)

  // NestJS typically uses Express under the hood, so req.*/res.* already work.
  // But NestJS also has its own response patterns:
  'response.status':      { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'response.redirect':    { nodeType: 'EGRESS',     subtype: 'redirect',      tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Hono
  // ═══════════════════════════════════════════════════════════════════════════
  // Hono handlers receive a Context `c`. c.req wraps the Request; c.json/c.text/c.html
  // are response helpers. c.req.query()/c.req.param()/c.req.json() return user-controlled input.
  // NOTE: c.req.query → caught by existing req.query via last-two fallback.
  //       c.req.header → caught by existing req.header via last-two fallback.

  // ── Hono c.req.* → INGRESS (patterns not caught by Express req.* fallback) ──
  'req.param':            { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'req.json':             { nodeType: 'INGRESS',    subtype: 'http_body',     tainted: true },
  'req.parseBody':        { nodeType: 'INGRESS',    subtype: 'file_upload',   tainted: true },

  // ── Hono c.* → EGRESS (response helpers) ──
  'c.json':               { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'c.text':               { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },
  'c.html':               { nodeType: 'EGRESS',     subtype: 'xss_sink',     tainted: false },
  'c.redirect':           { nodeType: 'EGRESS',     subtype: 'http_response', tainted: false },

  // ── Hono app.use → STRUCTURAL ──
  'hono.use':             { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // RUNTIME: Bun
  // ═══════════════════════════════════════════════════════════════════════════
  // Bun replaces Node's fs and child_process with built-in APIs.

  'Bun.file':             { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'Bun.spawn':            { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'Bun.write':            { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'Bun.serve':            { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // RUNTIME: Deno
  // ═══════════════════════════════════════════════════════════════════════════
  // Deno's permission model is defense-in-depth but does NOT prevent misuse
  // once permissions are granted.

  'Deno.readTextFile':    { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },
  'Deno.Command':         { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  'Deno.writeTextFile':   { nodeType: 'EGRESS',     subtype: 'file_write',    tainted: false },
  'Deno.serve':           { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },
  'Deno.env':             { nodeType: 'INGRESS',    subtype: 'env_read',      tainted: true },

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: GraphQL (Apollo Server / GraphQL Yoga)
  // ═══════════════════════════════════════════════════════════════════════════
  // GraphQL resolvers receive (parent, args, context, info). context.req is the
  // raw HTTP request — user-controlled headers, cookies, IP.

  'context.req':          { nodeType: 'INGRESS',    subtype: 'http_request',  tainted: true },
  'graphql.execute':      { nodeType: 'EXTERNAL',   subtype: 'graphql_exec',  tainted: false },
  'ApolloServer.start':   { nodeType: 'STRUCTURAL', subtype: 'lifecycle',     tainted: false },
  'server.applyMiddleware': { nodeType: 'STRUCTURAL', subtype: 'route',   tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // ORM: Prisma — unsafe raw query variants (explicit member calls)
  // ═══════════════════════════════════════════════════════════════════════════
  // $queryRawUnsafe and $executeRawUnsafe accept raw string interpolation
  // (no tagged template protection) — #1 SQL injection vector in Prisma codebases.

  'prisma.$queryRawUnsafe':   { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'prisma.$executeRawUnsafe': { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // RESOURCE — finite shared capacity that data flows compete for
  // ═══════════════════════════════════════════════════════════════════════════

  // ── fs.* → RESOURCE/file_descriptors (file descriptor allocation) ──
  'fs.open':              { nodeType: 'RESOURCE',   subtype: 'file_descriptors', tainted: false },
  'fs.openSync':          { nodeType: 'RESOURCE',   subtype: 'file_descriptors', tainted: false },

  // ── net.* → RESOURCE/connections (socket/connection pool allocation) ──
  'net.createServer':     { nodeType: 'RESOURCE',   subtype: 'connections',   tainted: false },
  'net.createConnection': { nodeType: 'RESOURCE',   subtype: 'connections',   tainted: false },
  'net.connect':          { nodeType: 'RESOURCE',   subtype: 'connections',   tainted: false },

  // ── Buffer.* → RESOURCE/memory (memory allocation) ──
  'Buffer.alloc':         { nodeType: 'RESOURCE',   subtype: 'memory',        tainted: false },
  'Buffer.allocUnsafe':   { nodeType: 'RESOURCE',   subtype: 'memory',        tainted: false },
  'Buffer.from':          { nodeType: 'RESOURCE',   subtype: 'memory',        tainted: false },

  // ── zlib.* → RESOURCE/memory (decompression — zip bomb vector) ──
  'zlib.inflate':         { nodeType: 'RESOURCE',   subtype: 'memory',        tainted: false },
  'zlib.inflateSync':     { nodeType: 'RESOURCE',   subtype: 'memory',        tainted: false },
  'zlib.gunzip':          { nodeType: 'RESOURCE',   subtype: 'memory',        tainted: false },
  'zlib.gunzipSync':      { nodeType: 'RESOURCE',   subtype: 'memory',        tainted: false },
  'zlib.unzip':           { nodeType: 'RESOURCE',   subtype: 'memory',        tainted: false },
  'zlib.unzipSync':       { nodeType: 'RESOURCE',   subtype: 'memory',        tainted: false },
  'zlib.brotliDecompress': { nodeType: 'RESOURCE',  subtype: 'memory',        tainted: false },

  // ── crypto.pbkdf2 → RESOURCE/cpu (CPU-intensive with user-controlled iterations) ──
  'crypto.pbkdf2Sync':   { nodeType: 'RESOURCE',   subtype: 'cpu',           tainted: false },
  'crypto.scryptSync':    { nodeType: 'RESOURCE',   subtype: 'cpu',           tainted: false },

  // ── worker_threads.* → RESOURCE/threads ──
  'worker_threads.Worker': { nodeType: 'RESOURCE',  subtype: 'threads',       tainted: false },

  // ── cluster.* → RESOURCE/threads ──
  'cluster.fork':         { nodeType: 'RESOURCE',   subtype: 'threads',       tainted: false },

  // ── http.* → RESOURCE/connections (outbound request without timeout) ──
  'http.createServer':    { nodeType: 'RESOURCE',   subtype: 'connections',   tainted: false },
  'https.createServer':   { nodeType: 'RESOURCE',   subtype: 'connections',   tainted: false },

  // ── db pool → RESOURCE/connections (connection pool exhaustion) ──
  'pool.getConnection':   { nodeType: 'RESOURCE',   subtype: 'connections',   tainted: false },
  'pool.connect':         { nodeType: 'RESOURCE',   subtype: 'connections',   tainted: false },
  'pool.acquire':         { nodeType: 'RESOURCE',   subtype: 'connections',   tainted: false },
  'pool.query':           { nodeType: 'RESOURCE',   subtype: 'connections',   tainted: false },

  // ── Config readers — taint sources from external config files ──
  'dotenv.config':        { nodeType: 'EXTERNAL',   subtype: 'config_read',   tainted: false },
  'nconf.get':            { nodeType: 'INGRESS',    subtype: 'env_read',      tainted: true },
  'convict.get':          { nodeType: 'INGRESS',    subtype: 'env_read',      tainted: true },
};

// ── Wildcard member calls (*.method) ──────────────────────────────────────
// Matched when no specific "object.method" key matches.
// Covers database ORMs, array transforms, string methods, etc.

const STORAGE_READ_METHODS = new Set([
  'query', 'find', 'findOne', 'findMany', 'findById', 'findAll',
  'select', 'get', 'count', 'aggregate', 'distinct', 'exec',
  // ORM raw query methods — bypass parameterization
  'raw', 'rawQuery', 'whereRaw', 'havingRaw', 'orderByRaw',
  '$queryRaw', '$queryRawUnsafe',
]);

const STORAGE_WRITE_METHODS = new Set([
  'insert', 'insertOne', 'insertMany', 'create',
  'update', 'updateOne', 'updateMany', 'upsert',
  'delete', 'deleteOne', 'deleteMany', 'remove',
  'save', 'destroy', 'bulkWrite', 'bulkCreate',
  // Prisma raw execute methods — bypass parameterization, perform writes
  '$executeRaw', '$executeRawUnsafe',
  // Zip extraction methods — path traversal vectors (CWE-22)
  'extractAllTo', 'extractEntryTo', 'extractAllToAsync',
]);

const TRANSFORM_CALCULATE_METHODS = new Set([
  'map', 'filter', 'reduce', 'forEach', 'some', 'every',
  'find', 'findIndex', 'flatMap', 'flat',
  'push', 'pop', 'shift', 'unshift', 'splice', 'concat',
  'sort', 'reverse', 'fill', 'copyWithin',
  // Event emitter methods — classified as TRANSFORM so they get nodes in the graph
  'emit', 'on', 'once', 'addListener', 'removeListener',
  // Promise methods — taint flows through .then/.catch/.finally callbacks
  'then', 'catch', 'finally',
]);

const TRANSFORM_FORMAT_METHODS = new Set([
  'toString', 'trim', 'trimStart', 'trimEnd',
  'toLowerCase', 'toUpperCase', 'toLocaleLowerCase', 'toLocaleUpperCase',
  'split', 'join', 'replace', 'replaceAll',
  'slice', 'substring', 'substr',
  'padStart', 'padEnd', 'repeat',
  'charAt', 'charCodeAt', 'codePointAt',
  'normalize', 'localeCompare',
  'toFixed', 'toPrecision', 'toExponential',
  'toISOString', 'toJSON', 'toLocaleString',
]);

// ── RESOURCE wildcard methods — finite shared capacity ──────────────────
// These are methods on any object that allocate or acquire finite resources.
// Matched by the wildcard strategy in lookupCallee() when no exact match exists.

const RESOURCE_CONNECTION_METHODS = new Set([
  'getConnection', 'releaseConnection', 'acquire', 'release',
  'connect', 'disconnect', 'end', 'close',
]);

const RESOURCE_MEMORY_METHODS = new Set([
  'alloc', 'allocUnsafe', 'allocUnsafeSlow',
]);

// ── Common sanitizer/encoder function name patterns ──────────────────────
// Two-tier: strict for direct calls (no ambiguous bare words), broad for member calls.
//
// STRICT (direct calls, length 1): Only words that are unambiguously sanitizer-like
// when standing alone. Ambiguous words (escape, encode, filter, clean, strip) MUST
// have a domain suffix (Html, Sql, Url, Input, etc.) to match.
//
// BROAD (member calls, length >= 2): All sanitizer-like bases match with or without
// suffix, because isLikelyNonDBObject() guards against Array.filter, String.replace, etc.
const SANITIZER_NAME_PATTERN_STRICT = /^(?:(?:sanitize|purify|scrub|bleach|xss|htmlspecialchars)(?:Html|Xml|Sql|Url|Uri|Input|Output|String|Data|Content|Special|Chars)?|(?:escape|encode|filter|clean|strip)(?:Html|Xml|Sql|Url|Uri|Input|Output|String|Data|Content|Special|Chars))$/i;

const SANITIZER_NAME_PATTERN = /^(?:escape|sanitize|encode|purify|clean|strip|filter|scrub|bleach|xss|htmlspecialchars)(?:Html|Xml|Sql|Url|Uri|Input|Output|String|Data|Content|Special|Chars)?$/i;

// ── Lookup function ───────────────────────────────────────────────────────

/**
 * Look up a callee chain in the pattern database.
 *
 * @param calleeChain - Array of identifiers from getCalleeChain(), e.g. ['res', 'json']
 * @returns Pattern match with nodeType/subtype/tainted, or null if unknown
 *
 * Strategy:
 *   1. Single identifier → check DIRECT_CALLS
 *   2. Two+ identifiers → join first two as "object.method", check MEMBER_CALLS
 *   3. If no member match → check wildcard sets (db methods, transforms)
 *   4. No match → return null
 */
export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  // Strategy 1: Direct call (single identifier)
  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };

    // Wildcard: sanitizer/encoder function names not in DIRECT_CALLS
    // Uses the STRICT pattern — ambiguous bases (escape, encode, filter, clean, strip)
    // must have a domain suffix (e.g. escapeHtml, filterInput) to match.
    if (SANITIZER_NAME_PATTERN_STRICT.test(calleeChain[0]!)) {
      return { nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false };
    }

    return null;
  }

  // Strategy 2: Exact member match ("object.method")
  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  const member = MEMBER_CALLS[exactKey];
  if (member) return { ...member };

  // Also try with just the last two segments for deeper chains
  // e.g. ['db', 'collection', 'find'] → try 'collection.find' too
  if (calleeChain.length > 2) {
    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
  }

  // Strategy 3: Wildcard method matching (any object)
  // DB storage patterns — only match if NOT already matched as something specific
  if (STORAGE_READ_METHODS.has(methodName)) {
    // Disambiguate: Array.find vs db.find
    // If objectName is a known non-DB object, skip
    if (!isLikelyNonDBObject(objectName)) {
      return { nodeType: 'STORAGE', subtype: 'db_read', tainted: false, wildcard: true };
    }
  }

  if (STORAGE_WRITE_METHODS.has(methodName)) {
    if (!isLikelyNonDBObject(objectName)) {
      return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false, wildcard: true };
    }
  }

  // Wildcard: common sanitizer/encoder function names -> TRANSFORM/sanitize
  // These functions are likely security-relevant even when not in the pattern DB.
  // The 11-domain SecurityState system uses TRANSFORM/sanitize to track neutralization.
  // Placed AFTER STORAGE wildcards (so db.query wins) but BEFORE TRANSFORM_FORMAT/CALCULATE
  // (because sanitizer detection is more security-critical than format detection).
  //
  // Note: The direct-call (length 1) sanitizer wildcard is in Strategy 1 above, using
  // SANITIZER_NAME_PATTERN_STRICT (ambiguous bases like filter/clean/strip require a suffix).
  // Here we handle method calls (length >= 2) with the broader SANITIZER_NAME_PATTERN,
  // guarded by isLikelyNonDBObject to prevent Array.filter, String.replace, etc.
  if (SANITIZER_NAME_PATTERN.test(methodName)) {
    if (!isLikelyNonDBObject(objectName)) {
      return { nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false };
    }
  }

  // Transform patterns — only if the method name is unambiguous
  if (TRANSFORM_FORMAT_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'format', tainted: false };
  }

  if (TRANSFORM_CALCULATE_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'calculate', tainted: false };
  }

  // RESOURCE patterns — connection pool and memory allocation methods
  if (RESOURCE_CONNECTION_METHODS.has(methodName)) {
    return { nodeType: 'RESOURCE', subtype: 'connections', tainted: false };
  }

  if (RESOURCE_MEMORY_METHODS.has(methodName)) {
    return { nodeType: 'RESOURCE', subtype: 'memory', tainted: false };
  }

  return null;
}

const NON_DB_OBJECTS = new Set([
  // ── JavaScript builtins ──
  'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef',
  'Array', 'Object', 'Promise', 'Reflect', 'Proxy',
  'RegExp', 'Date', 'Math', 'Number', 'String', 'Boolean', 'Symbol',
  'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError',
  'Int8Array', 'Uint8Array', 'Uint8ClampedArray', 'Int16Array',
  'Uint16Array', 'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array',
  'BigInt64Array', 'BigUint64Array', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView',
  'JSON', 'console', 'Intl',
  // ── Web/Node API objects ──
  'Headers', 'URLSearchParams', 'URL', 'FormData', 'Blob', 'File', 'searchParams',
  'ReadableStream', 'WritableStream', 'TransformStream',
  'TextEncoder', 'TextDecoder', 'AbortController', 'AbortSignal',
  'Request', 'Response',
  'MessageChannel', 'MessagePort', 'BroadcastChannel',
  'EventEmitter', 'EventTarget', 'Buffer',
  // ── Node.js core objects ──
  'stream', 'socket', 'net', 'tls', 'dgram',
  'path', 'os', 'util', 'url', 'querystring', 'zlib',
  // ── Crypto objects ──
  'hash', 'hmac', 'cipher', 'decipher', 'sign', 'verify',
  'crypto', 'Cipher', 'Decipher', 'Hash', 'Hmac', 'Sign', 'Verify',
  // ── Common non-DB variable names ──
  'cache', 'lru', 'memoryCache', 'lruCache',
  'map', 'set', 'weakMap', 'dict', 'dictionary', 'lookup', 'index',
  'config', 'options', 'settings', 'env', 'state',
  'registry', 'store', 'storage',
  'queue', 'stack', 'heap', 'ring', 'buffer',
  'timer', 'interval', 'timeout',
  'emitter', 'dispatcher', 'bus', 'channel',
  'logger', 'log',
  'metrics', 'counter', 'gauge', 'histogram',
  'mutex', 'semaphore', 'lock',
  'watcher', 'observer', 'listener', 'handler', 'subscriber',
  'proxy', 'stub', 'mock', 'spy', 'fake',
  'regex', 'regexp', 'pattern', 'matcher',
  // ── React / UI framework objects ──
  'React', 'ReactDOM', 'Component', 'PureComponent',
  'ref', 'refs', 'props',
  'Vue', 'Svelte', 'Solid',
  'document', 'window', 'navigator', 'location', 'history',
  'dom', 'element', 'node',
  // ── Express / HTTP framework objects ──
  'app', 'router', 'express', 'req', 'res', 'request', 'response',
  'server', 'client', 'http', 'https',
  'fastify', 'reply', 'instance',
  'ctx', 'context', 'koaRouter',
  'h', 'toolkit',
  'NextResponse', 'NextRequest', 'nextReq', 'nextRes',
  'controller', 'service', 'guard', 'pipe', 'interceptor', 'module',
  'c', 'hono',
  'Bun', 'Deno',
  'graphql', 'ApolloServer', 'yoga',
  'this', 'self', 'event', 'e',
  // ── Array-like variable names ──
  'arr', 'array', 'list', 'items', 'elements', 'results',
  'users', 'posts', 'records', 'rows', 'entries', 'values',
  'data', 'children', 'nodes', 'keys',
  'args', 'arguments', 'params', 'parameters',
  'files', 'paths', 'routes', 'endpoints',
  'modules', 'plugins', 'middlewares', 'handlers',
  'errors', 'warnings', 'messages', 'events',
  'tasks', 'jobs', 'workers', 'processes', 'threads',
  'chunks', 'segments', 'parts', 'pieces', 'fragments',
  'fields', 'columns', 'headers', 'cookies',
  'tags', 'labels', 'categories', 'groups',
  'assets', 'resources', 'dependencies',
  'components', 'directives', 'filters', 'pipes', 'guards',
  'frames', 'layers', 'pages', 'views', 'templates',
  'features', 'flags', 'toggles',
  'rules', 'policies', 'permissions', 'roles',
  'domains', 'targets', 'sources', 'sinks',
]);

/**
 * Returns true if the object name is known to NOT be a database handle.
 * Used to prevent wildcard STORAGE classification of JS builtins,
 * framework objects, and common non-DB variable names.
 */
function isLikelyNonDBObject(objectName: string): boolean {
  if (NON_DB_OBJECTS.has(objectName)) return true;

  // Lowercase single-letter variables (loop vars: i, j, k, x, y)
  if (objectName.length === 1 && objectName >= 'a' && objectName <= 'z') return true;

  // Variables ending with collection type suffixes
  const COLLECTION_SUFFIXES = ['List', 'Array', 'Queue', 'Stack', 'Map', 'Set',
    'Cache', 'Buffer', 'Pool', 'Ring', 'Heap', 'Dict', 'Index'];
  for (const suffix of COLLECTION_SUFFIXES) {
    if (objectName.endsWith(suffix) && objectName.length > suffix.length) return true;
  }

  return false;
}

/**
 * Get the total count of patterns in the database.
 * Useful for tests to verify minimum coverage.
 */
export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size
    + TRANSFORM_CALCULATE_METHODS.size
    + TRANSFORM_FORMAT_METHODS.size
    + RESOURCE_CONNECTION_METHODS.size
    + RESOURCE_MEMORY_METHODS.size;
}
