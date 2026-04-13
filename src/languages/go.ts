/**
 * Go Callee Pattern Database
 *
 * Maps Go function/method names to DST Neural Map node types.
 * Covers: stdlib (net/http, os, io, crypto, encoding, database/sql),
 *         Gin, Echo, Chi, Fiber, GORM, sqlx, gRPC, jwt-go, bcrypt.
 *
 * Sources:
 *   - corpus_audit_go.json (77 Category B + 170 Category A patterns)
 *   - Go stdlib and framework knowledge (gap-filling)
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (single identifier) ----------------------------------------
// Go uses package-qualified calls almost exclusively; direct calls are rare.

const DIRECT_CALLS: Record<string, CalleePattern> = {
  // Built-in functions
  make:     { nodeType: 'TRANSFORM',  subtype: 'format',     tainted: false },
  new:      { nodeType: 'TRANSFORM',  subtype: 'format',     tainted: false },
  append:   { nodeType: 'TRANSFORM',  subtype: 'calculate',  tainted: false },
  copy:     { nodeType: 'TRANSFORM',  subtype: 'calculate',  tainted: false },
  delete:   { nodeType: 'TRANSFORM',  subtype: 'calculate',  tainted: false },
  len:      { nodeType: 'TRANSFORM',  subtype: 'calculate',  tainted: false },
  cap:      { nodeType: 'TRANSFORM',  subtype: 'calculate',  tainted: false },
  close:    { nodeType: 'CONTROL',    subtype: 'event_handler', tainted: false },
  panic:    { nodeType: 'CONTROL',    subtype: 'guard',      tainted: false },
  recover:  { nodeType: 'CONTROL',    subtype: 'guard',      tainted: false },
  print:    { nodeType: 'EGRESS',     subtype: 'display',    tainted: false },
  println:  { nodeType: 'EGRESS',     subtype: 'display',    tainted: false },
};

// -- Member calls (package.Function or receiver.Method) -----------------------

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS -- external data entering the system
  // =========================================================================

  // -- net/http request --
  'r.FormValue':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.FormFile':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.PostFormValue':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.ParseForm':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.ParseMultipartForm':   { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.Body':                 { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.URL':                  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.Header':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.Host':                 { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.RemoteAddr':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.Cookies':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.Cookie':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.URL.Query':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'r.URL.Path':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.FormValue':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.Body':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.Header':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.URL':                { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Gin framework --
  'c.Query':                { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.Param':                { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.PostForm':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.DefaultQuery':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.DefaultPostForm':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.GetRawData':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.ShouldBindJSON':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.ShouldBind':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.BindJSON':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.Bind':                 { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.GetHeader':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.FormFile':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.MultipartForm':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.Request':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.ClientIP':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.ContentType':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.Cookie':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.FullPath':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Echo framework --
  'c.QueryParam':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.QueryParams':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.FormValue':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.FormParams':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.PathParam':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Fiber framework --
  'c.Params':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.Body':                 { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.BodyParser':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.Get':                  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'c.Cookies':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- chi router --
  'chi.URLParam':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- gorilla/mux --
  'mux.Vars':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- gorilla/websocket --
  'upgrader.Upgrade':       { nodeType: 'INGRESS', subtype: 'websocket',    tainted: true },
  'conn.ReadMessage':       { nodeType: 'INGRESS', subtype: 'websocket',    tainted: true },

  // -- os / environment --
  'os.Getenv':              { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'os.LookupEnv':           { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'os.Environ':             { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'os.Args':                { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'os.Stdin':               { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'flag.Parse':             { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'flag.String':            { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'flag.Int':               { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'flag.Bool':              { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'flag.Arg':               { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'flag.Args':              { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'viper.Get':              { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'viper.GetString':        { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'viper.GetInt':           { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'viper.GetBool':          { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'viper.ReadInConfig':     { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },

  // -- File read --
  'os.Open':                { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'os.ReadFile':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'os.ReadDir':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'os.Stat':                { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'os.Lstat':               { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'io.ReadAll':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'io.ReadFull':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ioutil.ReadAll':         { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ioutil.ReadFile':        { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ioutil.ReadDir':         { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'bufio.NewReader':        { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'bufio.NewScanner':       { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'filepath.Walk':          { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'filepath.WalkDir':       { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'filepath.Glob':          { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },

  // -- Deserialization (INGRESS) --
  'gob.NewDecoder':         { nodeType: 'INGRESS', subtype: 'deserialize',  tainted: true },

  // -- Network read --
  'net.Listen':             { nodeType: 'INGRESS', subtype: 'network_read', tainted: false },
  'net.Dial':               { nodeType: 'INGRESS', subtype: 'network_read', tainted: false },
  'net.DialTimeout':        { nodeType: 'INGRESS', subtype: 'network_read', tainted: false },

  // =========================================================================
  // EGRESS -- data leaving the system
  // =========================================================================

  // -- net/http response --
  'w.Write':                { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'w.WriteHeader':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'w.Header':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'http.Error':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'http.Redirect':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'http.ServeContent':      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'http.ServeFile':         { nodeType: 'EGRESS', subtype: 'file_serve',    tainted: false },
  'http.FileServer':        { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'http.NotFound':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'http.SetCookie':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- gorilla/websocket response --
  'conn.WriteMessage':      { nodeType: 'EGRESS', subtype: 'websocket',     tainted: false },

  // -- Gin response --
  'c.JSON':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.XML':                  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.YAML':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.String':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.HTML':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.Redirect':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.File':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.Data':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.IndentedJSON':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.SecureJSON':           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.JSONP':                { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.AsciiJSON':            { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.PureJSON':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.Status':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.AbortWithStatusJSON':  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.AbortWithStatus':      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.SetCookie':            { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.Header':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Echo response --
  'c.JSONPretty':           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.HTMLBlob':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.Blob':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.Stream':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.NoContent':            { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.Render':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Fiber response --
  'c.SendString':           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.SendFile':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'c.SendStatus':           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- File write --
  'os.WriteFile':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'os.Create':              { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'os.Mkdir':               { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'os.MkdirAll':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'os.Remove':              { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'os.RemoveAll':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'os.Rename':              { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'os.Chmod':               { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'os.Chown':               { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ioutil.WriteFile':       { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ioutil.TempFile':        { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ioutil.TempDir':         { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'bufio.NewWriter':        { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'io.Copy':                { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'io.CopyN':               { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'io.WriteString':         { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },

  // -- Serialization (EGRESS) --
  'json.NewEncoder':        { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'gob.NewEncoder':         { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'xml.NewEncoder':         { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },

  // -- Logging (META) --
  'log.Print':              { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.Printf':             { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.Println':            { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.Fatal':              { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.Fatalf':             { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.Fatalln':            { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.Panic':              { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.Panicf':             { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'log.Panicln':            { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'slog.Info':              { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'slog.Warn':              { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'slog.Error':             { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'slog.Debug':             { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'slog.InfoContext':       { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'slog.WarnContext':       { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'slog.ErrorContext':      { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'slog.DebugContext':      { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'slog.NewTextHandler':    { nodeType: 'META',   subtype: 'config',        tainted: false },
  'slog.NewJSONHandler':    { nodeType: 'META',   subtype: 'config',        tainted: false },
  'logrus.Info':            { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logrus.Warn':            { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logrus.Error':           { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logrus.Debug':           { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logrus.Fatal':           { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logrus.WithFields':      { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'zap.NewProduction':      { nodeType: 'META',   subtype: 'config',        tainted: false },
  'zap.NewDevelopment':     { nodeType: 'META',   subtype: 'config',        tainted: false },

  // =========================================================================
  // EXTERNAL -- calls to outside systems
  // =========================================================================

  // -- net/http client --
  'http.Get':               { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'http.Post':              { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'http.PostForm':          { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'http.Head':              { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'http.NewRequest':        { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'http.NewRequestWithContext': { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'client.Do':              { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'client.Get':             { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'client.Post':            { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'client.Head':            { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },

  // -- gRPC --
  'grpc.Dial':              { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'grpc.DialContext':       { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'grpc.NewServer':         { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },

  // -- exec -- system command execution --
  'exec.Command':           { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'exec.CommandContext':    { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'os.StartProcess':        { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },

  // -- net/rpc (legacy RPC) --
  'rpc.Dial':               { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'rpc.DialHTTP':           { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'client.Call':            { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },

  // -- reflect (CWE-470 unsafe reflection) --
  'v.Call':                 { nodeType: 'EXTERNAL', subtype: 'unsafe_reflect', tainted: true },
  'v.MethodByName':         { nodeType: 'EXTERNAL', subtype: 'unsafe_reflect', tainted: true },

  // -- plugin --
  'plugin.Open':            { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'p.Lookup':               { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: true },

  // -- net/http/httputil reverse proxy --
  'httputil.NewSingleHostReverseProxy': { nodeType: 'EXTERNAL', subtype: 'proxy', tainted: false },
  'proxy.ServeHTTP':        { nodeType: 'EXTERNAL', subtype: 'proxy',        tainted: false },

  // -- http server start --
  'http.ListenAndServe':    { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'http.ListenAndServeTLS': { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },

  // =========================================================================
  // STORAGE -- persistent state
  // =========================================================================

  // -- database/sql --
  'sql.Open':               { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'db.Query':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.QueryRow':            { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.QueryContext':        { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.QueryRowContext':     { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Exec':                { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.ExecContext':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Prepare':             { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.PrepareContext':      { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Begin':               { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.BeginTx':             { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Ping':                { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'db.PingContext':         { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'db.Close':               { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'tx.Commit':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'tx.Rollback':            { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'tx.Exec':                { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'tx.ExecContext':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'tx.Query':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'tx.QueryRow':            { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'stmt.Exec':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'stmt.ExecContext':       { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'stmt.Query':             { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'stmt.QueryContext':      { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'stmt.QueryRow':          { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'stmt.QueryRowContext':   { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'rows.Scan':              { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'rows.Next':              { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'rows.Close':             { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'rows.Err':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'row.Scan':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },

  // -- sqlx --
  'sqlx.Connect':           { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'sqlx.Open':              { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'db.Select':              { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Get':                 { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.NamedExec':           { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.MustExec':            { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Rebind':              { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },

  // -- GORM --
  'db.Create':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Save':                { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Delete':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Find':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.First':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Last':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Where':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Model':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Updates':             { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Update':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Raw':                 { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Scan':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Pluck':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.Count':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'db.AutoMigrate':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Migrator':            { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'db.Transaction':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },

  // -- XORM --
  'sess.And':               { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },
  'sess.Or':                { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },
  'sess.Where':             { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },
  'sess.Having':            { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },
  'sess.SQL':               { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },
  'engine.SQL':             { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },
  'engine.Where':           { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },
  'x.Where':                { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },
  'x.And':                  { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },
  'x.Or':                   { nodeType: 'STORAGE', subtype: 'sql_query',     tainted: false },

  // -- ent ORM (Facebook) --
  'ent.Open':               { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },

  // -- Redis (go-redis) --
  'rdb.Get':                { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },
  'rdb.Set':                { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'rdb.Del':                { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'rdb.HGet':               { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },
  'rdb.HSet':               { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'rdb.LPush':              { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'rdb.RPush':              { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'rdb.LPop':               { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },
  'rdb.RPop':               { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },
  'rdb.Publish':            { nodeType: 'STORAGE', subtype: 'cache_write',   tainted: false },
  'rdb.Subscribe':          { nodeType: 'STORAGE', subtype: 'cache_read',    tainted: false },

  // =========================================================================
  // TRANSFORM -- data processing
  // =========================================================================

  // -- encoding/json --
  'json.Marshal':           { nodeType: 'TRANSFORM', subtype: 'serialize',   tainted: false },
  'json.MarshalIndent':     { nodeType: 'TRANSFORM', subtype: 'serialize',   tainted: false },
  'json.Unmarshal':         { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'json.NewDecoder':        { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'json.Valid':             { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },

  // -- encoding/xml --
  'xml.Marshal':            { nodeType: 'TRANSFORM', subtype: 'serialize',   tainted: false },
  'xml.MarshalIndent':      { nodeType: 'TRANSFORM', subtype: 'serialize',   tainted: false },
  'xml.Unmarshal':          { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'xml.NewDecoder':         { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },

  // -- encoding/csv --
  'csv.NewReader':          { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'csv.NewWriter':          { nodeType: 'TRANSFORM', subtype: 'serialize',   tainted: false },

  // -- golang.org/x/net/html --
  'html.Parse':             { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: true },
  'html.Render':            { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },

  // -- encoding/base64 --
  'base64.StdEncoding.EncodeToString': { nodeType: 'TRANSFORM', subtype: 'encode', tainted: false },
  'base64.StdEncoding.DecodeString':   { nodeType: 'TRANSFORM', subtype: 'encode', tainted: false },
  'base64.URLEncoding.EncodeToString': { nodeType: 'TRANSFORM', subtype: 'encode', tainted: false },
  'base64.URLEncoding.DecodeString':   { nodeType: 'TRANSFORM', subtype: 'encode', tainted: false },

  // -- encoding/hex --
  'hex.EncodeToString':     { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  'hex.DecodeString':       { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },

  // -- crypto --
  'sha256.New':             { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'sha256.Sum256':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'sha512.New':             { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'sha512.Sum512':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'sha1.New':               { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'sha1.Sum':               { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'md5.New':                { nodeType: 'TRANSFORM', subtype: 'weak_hash',   tainted: false },
  'md5.Sum':                { nodeType: 'TRANSFORM', subtype: 'weak_hash',   tainted: false },
  'hmac.New':               { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'crypto.SHA256':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'aes.NewCipher':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'cipher.NewGCM':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'cipher.NewCBCEncrypter': { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'cipher.NewCBCDecrypter': { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'rand.Read':              { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'rsa.GenerateKey':        { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'rsa.EncryptOAEP':        { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'rsa.DecryptOAEP':        { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'rsa.SignPSS':            { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'rsa.VerifyPSS':          { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ecdsa.GenerateKey':      { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ecdsa.Sign':             { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ecdsa.Verify':           { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ed25519.GenerateKey':    { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ed25519.Sign':           { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'ed25519.Verify':         { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'tls.LoadX509KeyPair':    { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },
  'x509.ParseCertificate':  { nodeType: 'TRANSFORM', subtype: 'encrypt',     tainted: false },

  // -- fmt --
  'fmt.Sprintf':            { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'fmt.Fprintf':            { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'fmt.Sscanf':             { nodeType: 'TRANSFORM', subtype: 'parse',       tainted: false },
  'fmt.Errorf':             { nodeType: 'TRANSFORM', subtype: 'format',      tainted: false },
  'fmt.Print':              { nodeType: 'EGRESS',    subtype: 'display',     tainted: false },
  'fmt.Printf':             { nodeType: 'EGRESS',    subtype: 'display',     tainted: false },
  'fmt.Println':            { nodeType: 'EGRESS',    subtype: 'display',     tainted: false },
  'fmt.Fprint':             { nodeType: 'EGRESS',    subtype: 'display',     tainted: false },
  'fmt.Fprintln':           { nodeType: 'EGRESS',    subtype: 'display',     tainted: false },

  // -- strings --
  'strings.TrimSpace':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Trim':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.TrimLeft':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.TrimRight':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.TrimPrefix':     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.TrimSuffix':     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.ToLower':        { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.ToUpper':        { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Title':          { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Split':          { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.SplitN':         { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Join':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Replace':        { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.ReplaceAll':     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Contains':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.HasPrefix':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.HasSuffix':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Index':          { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Count':          { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Repeat':         { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.Map':            { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.NewReader':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.NewReplacer':    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strings.EqualFold':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- strconv --
  'strconv.Atoi':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strconv.Itoa':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strconv.ParseInt':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strconv.ParseFloat':     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strconv.ParseBool':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strconv.FormatInt':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strconv.FormatFloat':    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'strconv.FormatBool':     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- regexp --
  'regexp.Compile':         { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'regexp.MustCompile':     { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'regexp.MatchString':     { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // -- url --
  'url.Parse':              { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'url.ParseRequestURI':    { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'url.QueryEscape':        { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'url.QueryUnescape':      { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'url.PathEscape':         { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'url.PathUnescape':       { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },

  // -- html / template --
  // CRITICAL DISTINCTION: html/template auto-escapes (SAFE), text/template does NOT (DANGEROUS).
  // template.Execute and template.ExecuteTemplate are the render calls for both packages.
  // We mark them tainted:true because when text/template is used, output is unescaped (CWE-79).
  // The scanner should flag text/template usage and treat html/template as the safe mitigation.
  'html.EscapeString':      { nodeType: 'TRANSFORM', subtype: 'sanitize_html',   tainted: false },
  'html.UnescapeString':    { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'template.HTMLEscapeString': { nodeType: 'TRANSFORM', subtype: 'sanitize_html', tainted: false },
  'template.HTML':          { nodeType: 'EGRESS',    subtype: 'html_output', tainted: false },
  'template.Execute':       { nodeType: 'EGRESS',    subtype: 'html_output', tainted: true },
  'template.ExecuteTemplate': { nodeType: 'EGRESS',  subtype: 'html_output', tainted: true },

  // -- filepath --
  'filepath.Join':          { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'filepath.Abs':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'filepath.Base':          { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'filepath.Dir':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'filepath.Ext':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'filepath.Clean':         { nodeType: 'TRANSFORM', subtype: 'sanitize_path',   tainted: false },
  'filepath.Rel':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'filepath.Match':         { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'path.Join':              { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'path.Base':              { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'path.Dir':               { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'path.Ext':               { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'path.Clean':             { nodeType: 'TRANSFORM', subtype: 'sanitize_path',   tainted: false },

  // -- sort --
  'sort.Strings':           { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'sort.Ints':              { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'sort.Slice':             { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'sort.Sort':              { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },

  // -- reflect --
  'reflect.ValueOf':        { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'reflect.TypeOf':         { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'reflect.MakeFunc':       { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },

  // -- unsafe --
  'unsafe.Pointer':         { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },

  // =========================================================================
  // CONTROL -- validation, concurrency, flow
  // =========================================================================

  // -- context --
  'context.Background':     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'context.TODO':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'context.WithCancel':     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'context.WithTimeout':    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'context.WithDeadline':   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'context.WithValue':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- sync --
  'sync.WaitGroup':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'sync.Mutex':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'sync.RWMutex':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'sync.Once':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'sync.Pool':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'sync.Map':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'sync.Cond':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'wg.Add':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'wg.Done':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'wg.Wait':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mu.Lock':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mu.Unlock':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mu.RLock':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mu.RUnlock':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- atomic --
  'atomic.AddInt32':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.AddInt64':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.LoadInt32':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.LoadInt64':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.StoreInt32':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.StoreInt64':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.CompareAndSwapInt32': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.CompareAndSwapInt64': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- errgroup --
  'errgroup.WithContext':   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- gRPC interceptors (middleware) --
  'grpc.UnaryInterceptor':  { nodeType: 'CONTROL', subtype: 'middleware',    tainted: false },
  'grpc.StreamInterceptor': { nodeType: 'CONTROL', subtype: 'middleware',    tainted: false },

  // -- time --
  'time.NewTicker':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'time.NewTimer':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'time.After':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'time.AfterFunc':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'time.Sleep':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'time.Tick':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- signal --
  'signal.Notify':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'signal.Stop':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- os control --
  'os.Exit':                { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },

  // -- Gin middleware/validation --
  'c.Abort':                { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  'c.Next':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'c.IsAborted':            { nodeType: 'CONTROL', subtype: 'validation',    tainted: false },
  'c.Set':                  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- go-playground/validator --
  'validate.Struct':        { nodeType: 'CONTROL', subtype: 'validation',    tainted: false },
  'validate.Var':           { nodeType: 'CONTROL', subtype: 'validation',    tainted: false },

  // -- http route registration (STRUCTURAL for route definition) --
  'http.HandleFunc':        { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'http.Handle':            { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'http.NewServeMux':       { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },

  // -- Gin routing --
  'gin.Default':            { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'gin.New':                { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'router.GET':             { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'router.POST':            { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'router.PUT':             { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'router.DELETE':          { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'router.PATCH':           { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },
  'router.Use':             { nodeType: 'STRUCTURAL', subtype: 'middleware', tainted: false },
  'router.Group':           { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },

  // -- Chi router --
  'chi.NewRouter':          { nodeType: 'STRUCTURAL', subtype: 'route',      tainted: false },

  // =========================================================================
  // AUTH -- authentication and authorization
  // =========================================================================

  // -- bcrypt --
  'bcrypt.GenerateFromPassword': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'bcrypt.CompareHashAndPassword': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },

  // -- jwt-go / golang-jwt --
  'jwt.Parse':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'jwt.ParseWithClaims':    { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'jwt.NewWithClaims':      { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'jwt.New':                { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'token.SignedString':     { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- oauth2 --
  'oauth2.Config':          { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'oauth2.NewClient':       { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- session --
  'sessions.Default':       { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'session.Get':            { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'session.Set':            { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'session.Save':           { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- gorilla/sessions --
  'sessions.NewCookieStore':      { nodeType: 'AUTH', subtype: 'session_store', tainted: false },
  'sessions.NewFilesystemStore':  { nodeType: 'AUTH', subtype: 'session_store', tainted: false },

  // -- casbin (RBAC/ABAC authorization) --
  'e.Enforce':              { nodeType: 'AUTH', subtype: 'authorize',        tainted: false },
  'casbin.NewEnforcer':     { nodeType: 'AUTH', subtype: 'authorize',        tainted: false },

  // =========================================================================
  // META -- config, logging, debug
  // =========================================================================

  // -- go/ast (code generation / analysis) --
  'parser.ParseFile':       { nodeType: 'META', subtype: 'codegen',          tainted: false },
  'ast.Inspect':            { nodeType: 'META', subtype: 'codegen',          tainted: false },

  // -- logging (already above) --
  'log.New':                { nodeType: 'META', subtype: 'config',           tainted: false },
  'log.SetOutput':          { nodeType: 'META', subtype: 'config',           tainted: false },
  'log.SetFlags':           { nodeType: 'META', subtype: 'config',           tainted: false },
  'log.SetPrefix':          { nodeType: 'META', subtype: 'config',           tainted: false },

  // -- testing --
  'testing.T':              { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Error':                { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Errorf':               { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Fatal':                { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Fatalf':               { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Log':                  { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Logf':                 { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Skip':                 { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Run':                  { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Helper':               { nodeType: 'META', subtype: 'test',             tainted: false },
  't.Cleanup':              { nodeType: 'META', subtype: 'test',             tainted: false },
  't.TempDir':              { nodeType: 'META', subtype: 'test',             tainted: false },

  // -- httptest --
  'httptest.NewRecorder':   { nodeType: 'META', subtype: 'test',             tainted: false },
  'httptest.NewServer':     { nodeType: 'META', subtype: 'test',             tainted: false },
  'httptest.NewRequest':    { nodeType: 'META', subtype: 'test',             tainted: false },

  // -- runtime/debug --
  'runtime.GOMAXPROCS':     { nodeType: 'META', subtype: 'config',           tainted: false },
  'runtime.NumCPU':         { nodeType: 'META', subtype: 'config',           tainted: false },
  'runtime.GC':             { nodeType: 'META', subtype: 'config',           tainted: false },
  'debug.PrintStack':       { nodeType: 'META', subtype: 'debug',            tainted: false },
};

// -- Wildcard member calls (*.method) ----------------------------------------

const STORAGE_READ_METHODS = new Set([
  'Query', 'QueryRow', 'QueryContext', 'QueryRowContext',
  'Find', 'First', 'Last', 'Where', 'Select', 'Get',
  'Scan', 'Next', 'Pluck', 'Count', 'Rows',
]);

const STORAGE_WRITE_METHODS = new Set([
  'Exec', 'ExecContext', 'Create', 'Save', 'Delete',
  'Update', 'Updates', 'Insert', 'Remove',
  'Commit', 'Rollback', 'AutoMigrate',
  'MustExec', 'NamedExec',
]);

const TRANSFORM_FORMAT_METHODS = new Set([
  // string operations
  'String', 'Bytes', 'Format',
  // time
  'Format', 'Unix', 'UnixMilli', 'UTC', 'Local',
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

  // Try deeper chains: "base64.StdEncoding.EncodeToString"
  if (calleeChain.length > 2) {
    const fullPath = calleeChain.join('.');
    const fullMember = MEMBER_CALLS[fullPath];
    if (fullMember) return { ...fullMember };

    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
  }

  // Wildcard: storage methods
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

  if (TRANSFORM_FORMAT_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'format', tainted: false };
  }

  return null;
}

const NON_DB_OBJECTS = new Set([
  'r', 'req', 'w', 'resp', 'res', 'c', 'ctx', 'context',
  'http', 'net', 'os', 'io', 'fmt', 'log', 'slog',
  'strings', 'strconv', 'bytes', 'sort', 'reflect',
  'json', 'xml', 'csv', 'base64', 'hex',
  'sync', 'atomic', 'time', 'signal',
  'testing', 't', 'b', 'err', 'error',
  'this', 'self',
  'validate', 'casbin', 'sessions', 'template',
  'chi', 'mux', 'upgrader', 'conn', 'proxy', 'httputil', 'html',
  'rpc', 'grpc', 'plugin', 'v', 'p', 'parser', 'ast',
]);

// -- Sink patterns (CWE -> dangerous regex) -----------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /exec\.Command\s*\([^)]*(?:r\.FormValue|r\.URL\.Query|os\.Args)/,
  'CWE-89':  /(?:Query|Exec)\s*\(\s*(?:fmt\.Sprintf|"(?:SELECT|INSERT|UPDATE|DELETE).*"\s*\+)/,
  'CWE-79':  /(?:text\/template|template\.HTML\s*\(|"text\/template"[^]*?\.Execute)/,
  'CWE-94':  /(?:template\.New\s*\([^)]*\)\.Parse\s*\(\s*(?:r\.|params|query|body)|plugin\.Open\s*\()/,
  'CWE-22':  /filepath\.Join\s*\([^)]*(?:r\.FormValue|r\.URL|params|query)/,
  'CWE-119': /(?:unsafe\.Pointer\s*\(|import\s+"C")/,
  'CWE-295': /InsecureSkipVerify\s*:\s*true/,
  'CWE-327': /(?:md5|sha1)\.(?:New|Sum)\s*\(/,
  'CWE-338': /math\/rand/,
  'CWE-347': /jwt\.Parse\s*\([^,]+,\s*nil/,
  'CWE-362': /(?:go\s+func\s*\([^)]*\)\s*\{[^}]*\w+\[|for\s+.*:=\s*range[^{]*\{[^}]*go\s+func)/,
  'CWE-400': /http\.ListenAndServe\s*\(/,
  'CWE-532': /log\.(?:Print|Printf|Println)\s*\([^)]*(?:password|secret|token|key|credential)/,
  'CWE-614': /http\.Cookie\{[^}]*(?!Secure)[^}]*\}/,
  'CWE-470': /reflect\.ValueOf\([^)]*\)\.MethodByName\s*\(\s*(?:r\.|params|query|body|input|name|method)/,
  'CWE-749': /reflect\.(?:ValueOf\([^)]*\)\.(?:Call|Method|MethodByName)|MakeFunc|SliceHeader)/,
  'CWE-798': /(?:password|secret|apiKey|token)\s*(?::=|=)\s*"[^"]{8,}"/,
  'CWE-918': /http\.Get\s*\(\s*(?:r\.FormValue|r\.URL|params|query)/,
  'CWE-942': /w\.Header\(\)\.Set\s*\(\s*"Access-Control-Allow-Origin"\s*,\s*"\*"/,
};

// -- Safe patterns (CWE -> mitigating regex) ----------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /exec\.Command\s*\(\s*"[^"]*"\s*,/,                    // literal command name
  'CWE-89':  /(?:(?:Query|Exec)\s*\(\s*"[^"]*(?:\$\d+|\?)[^"]*"\s*,|\.Prepare(?:Context)?\s*\()/,  // parameterized query ($1, ?) or prepared statement
  'CWE-79':  /(?:html\/template|html\.EscapeString)/,                 // auto-escaped templates or explicit escaping
  'CWE-22':  /filepath\.Clean\s*\(/,                                  // path cleaning
  'CWE-295': /InsecureSkipVerify\s*:\s*false/,
  'CWE-327': /(?:sha256|sha512|sha3)\.(?:New|Sum)/,                  // strong hash
  'CWE-338': /crypto\/rand/,                                          // secure PRNG
  'CWE-347': /jwt\.Parse(?:WithClaims)?\s*\([^,]+,\s*func/,         // with keyfunc
  'CWE-362': /sync\.(?:Mutex|RWMutex|Map)/,                          // proper synchronization
  'CWE-400': /context\.WithTimeout/,                                   // timeout protection
  'CWE-918': /(?:url\.Parse|net\.ParseIP)\s*\(/,                     // URL/IP validation
};

// -- Pattern count ------------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size
    + TRANSFORM_FORMAT_METHODS.size;
}
