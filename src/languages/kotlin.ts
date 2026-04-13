/**
 * Kotlin Callee Pattern Database
 *
 * Maps Kotlin function/method names to DST Neural Map node types.
 * Covers: stdlib, Ktor, Spring Boot (Kotlin), Android (Room, Retrofit,
 *         OkHttp, SharedPreferences, DataStore), kotlinx.serialization,
 *         coroutines, Flow.
 *
 * Sources:
 *   - corpus_audit_kotlin.json (20 Category B + 188 Category A patterns)
 *   - Kotlin/Android/Ktor framework knowledge
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

const DIRECT_CALLS: Record<string, CalleePattern> = {
  println:          { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  print:            { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  readLine:         { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },
  readln:           { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },
  require:          { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  check:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  error:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  TODO:             { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  // Constructors commonly used as sinks
  File:             { nodeType: 'STORAGE',   subtype: 'file_access',   tainted: false },
  URL:              { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  ProcessBuilder:   { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  ObjectInputStream: { nodeType: 'EXTERNAL', subtype: 'deserialize',   tainted: false },
};

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // == INGRESS ==

  // -- Ktor request --
  'call.receive':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'call.receiveText':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'call.parameters':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'call.request.headers':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'call.request.queryParameters': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'call.request.cookies':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'call.request.uri':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Ktor multipart / WebSocket --
  'call.receiveMultipart':      { nodeType: 'INGRESS', subtype: 'file_upload',  tainted: true },
  'incoming.receive':           { nodeType: 'INGRESS', subtype: 'websocket_read', tainted: true },

  // -- Android intents / IPC --
  'intent.getStringExtra':      { nodeType: 'INGRESS', subtype: 'ipc_read',    tainted: true },
  'intent.data':                { nodeType: 'INGRESS', subtype: 'ipc_read',    tainted: true },
  'ContentResolver.query':      { nodeType: 'INGRESS', subtype: 'ipc_read',    tainted: true },

  // -- Spring Boot (Kotlin) --
  'request.getParameter':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getHeader':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.body':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- File --
  'File.readText':              { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.readLines':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.readBytes':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.inputStream':           { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.bufferedReader':        { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.forEachLine':           { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.exists':                { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.listFiles':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },

  // -- Environment --
  'System.getenv':              { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'System.getProperty':         { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },

  // -- SharedPreferences / DataStore read --
  'SharedPreferences.getString':  { nodeType: 'INGRESS', subtype: 'env_read',   tainted: false },
  'SharedPreferences.getInt':     { nodeType: 'INGRESS', subtype: 'env_read',   tainted: false },
  'SharedPreferences.getBoolean': { nodeType: 'INGRESS', subtype: 'env_read',   tainted: false },
  'DataStore.data':               { nodeType: 'INGRESS', subtype: 'env_read',   tainted: false },

  // -- Deserialization --
  'Json.decodeFromString':      { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'Json.decodeFromStream':      { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'Gson.fromJson':              { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'ObjectMapper.readValue':     { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'Moshi.adapter':              { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // == EGRESS ==

  // -- Ktor response --
  'call.respondText':           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'call.respond':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'call.respondHtml':           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'call.respondFile':           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'call.respondRedirect':       { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'call.respondBytes':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Spring Boot (Kotlin) --
  'ResponseEntity.ok':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'ResponseEntity.notFound':    { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'ResponseEntity.badRequest':  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'ResponseEntity.created':     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Android activity navigation --
  'startActivity':              { nodeType: 'EGRESS', subtype: 'ipc_send',      tainted: false },

  // -- File write --
  'File.writeText':             { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.writeBytes':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.appendText':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.outputStream':          { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.delete':                { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.mkdir':                 { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.mkdirs':                { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },

  // -- Serialization --
  'Json.encodeToString':        { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'Json.encodeToStream':        { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'Gson.toJson':                { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'ObjectMapper.writeValueAsString': { nodeType: 'EGRESS', subtype: 'serialize', tainted: false },

  // -- SharedPreferences write --
  'SharedPreferences.edit':     { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },

  // -- Logging --
  'Log.d':                      { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.i':                      { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.w':                      { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.e':                      { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.v':                      { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Timber.d':                   { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Timber.i':                   { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Timber.w':                   { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Timber.e':                   { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.info':                { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.debug':               { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.warn':                { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.error':               { nodeType: 'META',   subtype: 'logging',       tainted: false },

  // == EXTERNAL ==

  // -- Ktor HTTP client --
  'HttpClient.get':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.post':            { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.put':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.delete':          { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.patch':           { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'client.get':                 { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'client.post':                { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'client.put':                 { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'client.delete':              { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- OkHttp --
  'OkHttpClient.newCall':       { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- Retrofit --
  'Retrofit.create':            { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- Android WebView --
  'WebView.loadUrl':            { nodeType: 'EXTERNAL', subtype: 'webview_nav',  tainted: false },
  'WebView.evaluateJavascript': { nodeType: 'EXTERNAL', subtype: 'webview_exec', tainted: false },

  // -- Process --
  'Runtime.getRuntime.exec':    { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Runtime.exec':               { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'ProcessBuilder.start':       { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'ProcessBuilder.command':     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // -- HTTP / URL --
  'url.openConnection':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'URL.openConnection':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpURLConnection.connect':  { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'connection.inputStream':     { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- XML parsing --
  'DocumentBuilderFactory.newInstance': { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'factory.newDocumentBuilder':  { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'builder.parse':               { nodeType: 'EXTERNAL', subtype: 'xml_parse',  tainted: false },
  'DocumentBuilder.parse':       { nodeType: 'EXTERNAL', subtype: 'xml_parse',  tainted: false },
  'SAXParserFactory.newInstance': { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'XMLInputFactory.newInstance':  { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },

  // -- Deserialization (dangerous) --
  'ObjectInputStream.readObject': { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },
  'ois.readObject':              { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // == STORAGE ==

  // -- JDBC --
  'DriverManager.getConnection': { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },
  'conn.createStatement':       { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'connection.createStatement':  { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'conn.prepareStatement':      { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'connection.prepareStatement': { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'stmt.executeQuery':          { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'stmt.executeUpdate':         { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'stmt.execute':               { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'statement.executeQuery':     { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'statement.executeUpdate':    { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'statement.execute':          { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },
  'preparedStatement.executeQuery': { nodeType: 'STORAGE', subtype: 'sql',      tainted: false },
  'preparedStatement.executeUpdate': { nodeType: 'STORAGE', subtype: 'sql',     tainted: false },

  // -- Android SQLite --
  'database.rawQuery':          { nodeType: 'STORAGE', subtype: 'sql',          tainted: false },

  // -- Room --
  'Dao.insert':                 { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'Dao.update':                 { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'Dao.delete':                 { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'Dao.upsert':                 { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },

  // -- Exposed --
  'transaction':                { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },

  // -- Spring Data --
  'repository.findAll':         { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'repository.findById':        { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'repository.save':            { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'repository.saveAll':         { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'repository.delete':          { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'repository.deleteById':      { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'repository.count':           { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'repository.existsById':      { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },

  // -- Redis --
  'redis.get':                  { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'redis.set':                  { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'redis.del':                  { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },

  // == TRANSFORM ==

  // -- Crypto --
  'MessageDigest.getInstance':  { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'MessageDigest.digest':       { nodeType: 'TRANSFORM', subtype: 'hash',       tainted: false },
  'md.digest':                  { nodeType: 'TRANSFORM', subtype: 'hash',       tainted: false },
  'md.update':                  { nodeType: 'TRANSFORM', subtype: 'hash',       tainted: false },
  'Mac.getInstance':            { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'Cipher.getInstance':         { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'Cipher.doFinal':             { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'SecureRandom.nextBytes':     { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'KeyGenerator.getInstance':   { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },

  // -- Base64 --
  'Base64.encode':              { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'Base64.decode':              { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'Base64.getEncoder':          { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'Base64.getDecoder':          { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },

  // -- URL --
  'URLEncoder.encode':          { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'URLDecoder.decode':          { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'URI.create':                 { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'URL':                        { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // -- Regex --
  'Regex':                      { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // == CONTROL ==

  // -- Coroutines --
  'launch':                     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'async':                      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'withContext':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'runBlocking':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'coroutineScope':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'supervisorScope':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'GlobalScope.launch':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Dispatchers.IO':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Dispatchers.Main':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Dispatchers.Default':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'delay':                      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Mutex.withLock':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Semaphore.withPermit':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Flow --
  'flow':                       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'MutableStateFlow':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'MutableSharedFlow':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Channel':                    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // == AUTH ==

  // -- Spring Security (Kotlin) --
  'SecurityContextHolder.getContext': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'authentication.principal':   { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- JWT --
  'JWT.create':                 { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'JWT.require':                { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'JWT.decode':                 { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- Ktor auth --
  'authentication':             { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'call.sessions.get':          { nodeType: 'AUTH', subtype: 'session_read',     tainted: false },

  // == STRUCTURAL ==

  // -- Ktor routing --
  'routing':                    { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'route':                      { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'get':                        { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'post':                       { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'put':                        { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'delete':                     { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'patch':                      { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },

  // == META ==
  'application.log':            { nodeType: 'META', subtype: 'logging',          tainted: false },
};

// -- Wildcard --
const STORAGE_READ_METHODS = new Set([
  'findAll', 'findById', 'findOne', 'findBy', 'find',
  'getAll', 'getById', 'get', 'count', 'exists', 'existsById',
  'query', 'select', 'fetch', 'fetchAll', 'fetchOne',
  'executeQuery', 'rawQuery',
]);

const STORAGE_WRITE_METHODS = new Set([
  'save', 'saveAll', 'insert', 'update', 'delete', 'deleteById',
  'deleteAll', 'upsert', 'execute', 'persist', 'merge', 'remove',
  'executeUpdate', 'executeBatch',
]);

const NON_DB_OBJECTS = new Set([
  'call', 'request', 'response', 'this', 'self',
  'File', 'System', 'Log', 'Timber', 'logger',
  'client', 'HttpClient', 'OkHttpClient',
  'Json', 'Gson', 'ObjectMapper', 'Moshi',
  'String', 'Int', 'Long', 'Float', 'Double',
  'list', 'map', 'set', 'array', 'data', 'items', 'result',
]);

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };
    const single = MEMBER_CALLS[calleeChain[0]!];
    if (single) return { ...single };
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

  if (STORAGE_READ_METHODS.has(methodName) && !NON_DB_OBJECTS.has(objectName)) {
    return { nodeType: 'STORAGE', subtype: 'db_read', tainted: false };
  }
  if (STORAGE_WRITE_METHODS.has(methodName) && !NON_DB_OBJECTS.has(objectName)) {
    return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false };
  }

  return null;
}

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /Runtime\.getRuntime\(\)\.exec\s*\(\s*[^"]/,
  'CWE-89':  /"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\$\w+/,
  'CWE-798': /(?:apiKey|secret|password|token)\s*=\s*"[^"]{4,}"/,
  'CWE-312': /SharedPreferences[^\n]*(?:password|token|secret|key)/,
  'CWE-502': /ObjectInputStream\s*\(\s*(?:request|input|socket)/,
};

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /ProcessBuilder\s*\(\s*listOf\s*\(/,
  'CWE-89':  /(?:@Query\s*\(|:param|parameterized)/,
  'CWE-312': /(?:EncryptedSharedPreferences|DataStore)/,
};

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size;
}
