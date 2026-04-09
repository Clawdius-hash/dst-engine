/**
 * Python Callee Pattern Database
 *
 * Maps Python function/method names to DST Neural Map node types.
 * Covers: stdlib, Flask, Django, FastAPI, SQLAlchemy, requests, aiohttp,
 *         subprocess, os, pathlib, hashlib, jwt, bcrypt, celery, logging.
 *
 * Sources:
 *   - corpus_audit_python.json (113 Category B + 173 Category A patterns)
 *   - Python stdlib and framework knowledge (gap-filling)
 *   - calleePatterns.ts (JS reference — structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// ── Direct calls (single identifier) ──────────────────────────────────────

const DIRECT_CALLS: Record<string, CalleePattern> = {
  // EXTERNAL — code execution
  eval:                   { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  exec:                   { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  compile:                { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  execfile:               { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },
  __import__:             { nodeType: 'EXTERNAL',   subtype: 'system_exec',   tainted: false },

  // TRANSFORM — type coercion / formatting
  int:                    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  float:                  { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  str:                    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  bool:                   { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  bytes:                  { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  bytearray:              { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  list:                   { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  tuple:                  { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  dict:                   { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  set:                    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  frozenset:              { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  ord:                    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  chr:                    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  hex:                    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  oct:                    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  bin:                    { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  repr:                   { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  ascii:                  { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  format:                 { nodeType: 'TRANSFORM',  subtype: 'format',        tainted: false },
  sorted:                 { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  reversed:               { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  enumerate:              { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  zip:                    { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  map:                    { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  filter:                 { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  reduce:                 { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  len:                    { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  sum:                    { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  min:                    { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  max:                    { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  abs:                    { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  round:                  { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  any:                    { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  all:                    { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },

  // INGRESS — user input
  input:                  { nodeType: 'INGRESS',    subtype: 'user_input',    tainted: true },

  // EGRESS — display
  print:                  { nodeType: 'EGRESS',     subtype: 'display',       tainted: false },

  // STRUCTURAL — imports/dependencies
  import:                 { nodeType: 'STRUCTURAL', subtype: 'dependency',    tainted: false },

  // CONTROL — flow
  exit:                   { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },
  quit:                   { nodeType: 'CONTROL',    subtype: 'guard',         tainted: false },
  breakpoint:             { nodeType: 'META',       subtype: 'debug',         tainted: false },

  // TRANSFORM — dynamic attribute access
  getattr:                { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  setattr:                { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  delattr:                { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  hasattr:                { nodeType: 'TRANSFORM',  subtype: 'calculate',     tainted: false },
  isinstance:             { nodeType: 'CONTROL',    subtype: 'validation',    tainted: false },
  issubclass:             { nodeType: 'CONTROL',    subtype: 'validation',    tainted: false },

  // INGRESS — file I/O
  open:                   { nodeType: 'INGRESS',    subtype: 'file_read',     tainted: false },

  // STRUCTURAL — FastAPI dependency injection
  Depends:                { nodeType: 'STRUCTURAL',  subtype: 'dependency',   tainted: false },

  // AUTH — FastAPI OAuth2 token extraction
  OAuth2PasswordBearer:   { nodeType: 'AUTH',        subtype: 'authenticate', tainted: false },

  // ── Flask bare imports (from flask import X) ──────────────────────────────
  // Real Flask apps use `from flask import render_template` not `flask.render_template`.
  // These mirror the flask.* MEMBER_CALLS entries for bare-name resolution.
  render_template:        { nodeType: 'EGRESS',     subtype: 'http_response',  tainted: false },
  render_template_string: { nodeType: 'EXTERNAL',   subtype: 'template_exec',  tainted: false },
  make_response:          { nodeType: 'EGRESS',     subtype: 'http_response',  tainted: false },
  redirect:               { nodeType: 'EGRESS',     subtype: 'redirect',       tainted: false },
  jsonify:                { nodeType: 'EGRESS',     subtype: 'http_response',  tainted: false },
  abort:                  { nodeType: 'CONTROL',    subtype: 'guard',          tainted: false },
  send_file:              { nodeType: 'EGRESS',     subtype: 'file_serve',     tainted: false },
  send_from_directory:    { nodeType: 'EGRESS',     subtype: 'file_serve',     tainted: false },
  url_for:                { nodeType: 'TRANSFORM',  subtype: 'format',         tainted: false },
};

// ── Member calls (object.method) ──────────────────────────────────────────

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // ═══════════════════════════════════════════════════════════════════════
  // INGRESS — external data entering the system
  // ═══════════════════════════════════════════════════════════════════════

  // ── Flask request ──
  'request.form':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.args':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.json':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.data':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.values':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.files':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.headers':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.cookies':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.get_json':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.get_data':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.environ':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.url':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.path':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.method':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.host':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.remote_addr':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.content_type':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.query_string':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.stream':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.referrer':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── Django request ──
  'request.POST':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.GET':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.FILES':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.META':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.COOKIES':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.body':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.content_params':   { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── Django REST Framework (DRF) ──
  'serializer.validated_data': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── FastAPI depends / path params (via function signature) ──
  // FastAPI injects via type hints; callee-level patterns are on the request object
  'Request.body':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.json':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.form':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.query_params':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.path_params':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.headers':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.cookies':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ── Environment / config (INGRESS) ──
  'os.environ':               { nodeType: 'INGRESS', subtype: 'env_read',     tainted: false },
  'os.getenv':                { nodeType: 'INGRESS', subtype: 'env_read',     tainted: false },
  'os.environ.get':           { nodeType: 'INGRESS', subtype: 'env_read',     tainted: false },

  // ── sys — runtime input ──
  'sys.argv':                 { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'sys.stdin':                { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'sys.stdin.read':           { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'sys.stdin.readline':       { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },

  // ── File read (INGRESS) ──
  'pathlib.Path.read_text':   { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'pathlib.Path.read_bytes':  { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'pathlib.Path.open':        { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Path.read_text':           { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Path.read_bytes':          { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Path.open':                { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },

  // ── Data science file ingestion (phoneme-expansion/python_datascience) ──
  'pandas.read_csv':          { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'pd.read_csv':              { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },

  // ── Unsafe deserialization → EXTERNAL (can execute arbitrary code, like eval) ──
  'pickle.load':              { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'pickle.loads':             { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'yaml.load':                { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'yaml.unsafe_load':         { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'yaml.safe_load':           { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  // json.load/json.loads → classified as TRANSFORM.parse (see below), not dangerous
  'marshal.load':             { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'marshal.loads':            { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'shelve.open':              { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },

  // ── Data science deserialization — CWE-502 (phoneme-expansion/python_datascience) ──
  'pandas.read_pickle':       { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'pd.read_pickle':           { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'numpy.load':               { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'np.load':                  { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'torch.load':               { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },
  'joblib.load':              { nodeType: 'EXTERNAL', subtype: 'deserialize',  tainted: false },

  // ── Data science expression evaluation — CWE-94 (phoneme-expansion/python_datascience) ──
  'pandas.eval':              { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },
  'DataFrame.query':          { nodeType: 'EXTERNAL', subtype: 'system_exec',  tainted: false },

  // ── XML parsing — XXE (CWE-611) ──
  'xml.etree.ElementTree.parse':      { nodeType: 'EXTERNAL', subtype: 'xml_parse',   tainted: false },
  'xml.etree.ElementTree.fromstring': { nodeType: 'EXTERNAL', subtype: 'xml_parse',   tainted: false },
  'xml.etree.ElementTree.iterparse':  { nodeType: 'EXTERNAL', subtype: 'xml_parse',   tainted: false },
  'ET.parse':                         { nodeType: 'EXTERNAL', subtype: 'xml_parse',   tainted: false },
  'ET.fromstring':                    { nodeType: 'EXTERNAL', subtype: 'xml_parse',   tainted: false },
  'ET.iterparse':                     { nodeType: 'EXTERNAL', subtype: 'xml_parse',   tainted: false },

  // ── XPath / XML injection (CWE-91, CWE-643) ──
  'lxml.etree.XPath':                 { nodeType: 'EXTERNAL', subtype: 'xpath_query',  tainted: false },
  'lxml.etree.fromstring':            { nodeType: 'EXTERNAL', subtype: 'xml_parse',    tainted: false },
  'lxml.etree.parse':                 { nodeType: 'EXTERNAL', subtype: 'xml_parse',    tainted: false },
  'lxml.etree.XMLParser':             { nodeType: 'EXTERNAL', subtype: 'xml_parse',    tainted: false },
  'tree.xpath':                       { nodeType: 'EXTERNAL', subtype: 'xpath_query',  tainted: false },
  'root.find':                        { nodeType: 'EXTERNAL', subtype: 'xpath_query',  tainted: false },
  'root.findall':                     { nodeType: 'EXTERNAL', subtype: 'xpath_query',  tainted: false },
  'root.findtext':                    { nodeType: 'EXTERNAL', subtype: 'xpath_query',  tainted: false },
  'element.xpath':                    { nodeType: 'EXTERNAL', subtype: 'xpath_query',  tainted: false },
  // elementpath.select: DEFERRED — adds 8 TPs but 29 FPs without V2 XPath verifier.
  // Re-enable when CWE-643 V2 verifier is built.
  // 'elementpath.select':               { nodeType: 'EXTERNAL', subtype: 'xpath_query',  tainted: false },

  // ── FastAPI WebSocket receive (persistent tainted input) ──
  'WebSocket.receive_text':   { nodeType: 'INGRESS', subtype: 'websocket_read', tainted: true },
  'WebSocket.receive_json':   { nodeType: 'INGRESS', subtype: 'websocket_read', tainted: true },

  // ── FastAPI UploadFile (file upload vector) ──
  'UploadFile.read':          { nodeType: 'INGRESS', subtype: 'file_upload',    tainted: true },
  'UploadFile.filename':      { nodeType: 'INGRESS', subtype: 'file_upload',    tainted: true },

  // ── Socket / network read ──
  'socket.recv':              { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'socket.recvfrom':          { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'socket.recvmsg':           { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },

  // ═══════════════════════════════════════════════════════════════════════
  // EGRESS — data leaving the system
  // ═══════════════════════════════════════════════════════════════════════

  // ── Flask response ──
  'flask.jsonify':            { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'flask.make_response':      { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'flask.redirect':           { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'flask.send_file':          { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'flask.send_from_directory':{ nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'flask.render_template':    { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'flask.render_template_string': { nodeType: 'EXTERNAL', subtype: 'template_exec', tainted: false },
  'flask.abort':              { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },

  // ── Django response ──
  'HttpResponse':             { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'JsonResponse':             { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'django.shortcuts.render':  { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'django.shortcuts.redirect':{ nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'django.http.HttpResponse': { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'django.http.JsonResponse': { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'django.http.StreamingHttpResponse': { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'django.http.FileResponse': { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },

  // ── FastAPI response ──
  'JSONResponse':             { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'HTMLResponse':             { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'PlainTextResponse':        { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'RedirectResponse':         { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'StreamingResponse':        { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'FileResponse':             { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },
  'Response':                 { nodeType: 'EGRESS',  subtype: 'http_response', tainted: false },

  // ── FastAPI WebSocket send (data exfiltration channel) ──
  'WebSocket.send_text':      { nodeType: 'EGRESS',  subtype: 'websocket_write', tainted: false },
  'WebSocket.send_json':      { nodeType: 'EGRESS',  subtype: 'websocket_write', tainted: false },

  // ── File write (EGRESS) ──
  'pathlib.Path.write_text':  { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'pathlib.Path.write_bytes': { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'Path.write_text':          { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'Path.write_bytes':         { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'shutil.copy':              { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'shutil.copy2':             { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'shutil.move':              { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'shutil.rmtree':            { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'os.remove':                { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'os.unlink':                { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'os.rename':                { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'os.mkdir':                 { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },
  'os.makedirs':              { nodeType: 'EGRESS',  subtype: 'file_write',   tainted: false },

  // ── Serialization (EGRESS) ──
  'json.dump':                { nodeType: 'EGRESS',  subtype: 'serialize',    tainted: false },
  'json.dumps':               { nodeType: 'EGRESS',  subtype: 'serialize',    tainted: false },
  'pickle.dump':              { nodeType: 'EGRESS',  subtype: 'serialize',    tainted: false },
  'pickle.dumps':             { nodeType: 'EGRESS',  subtype: 'serialize',    tainted: false },
  'yaml.dump':                { nodeType: 'EGRESS',  subtype: 'serialize',    tainted: false },
  'yaml.safe_dump':           { nodeType: 'EGRESS',  subtype: 'serialize',    tainted: false },

  // ── Logging (EGRESS/display) ──
  'logging.debug':            { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logging.info':             { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logging.warning':          { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logging.error':            { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logging.critical':         { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logging.exception':        { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logging.log':              { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logger.debug':             { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logger.info':              { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logger.warning':           { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logger.error':             { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logger.critical':          { nodeType: 'META',    subtype: 'logging',      tainted: false },
  'logger.exception':         { nodeType: 'META',    subtype: 'logging',      tainted: false },

  // ── Socket send ──
  'socket.send':              { nodeType: 'EGRESS',  subtype: 'network_write', tainted: false },
  'socket.sendto':            { nodeType: 'EGRESS',  subtype: 'network_write', tainted: false },
  'socket.sendall':           { nodeType: 'EGRESS',  subtype: 'network_write', tainted: false },

  // ── Email ──
  'smtplib.SMTP.send_message':    { nodeType: 'EGRESS', subtype: 'email',    tainted: false },
  'smtplib.SMTP.sendmail':        { nodeType: 'EGRESS', subtype: 'email',    tainted: false },
  'smtplib.SMTP_SSL.send_message':{ nodeType: 'EGRESS', subtype: 'email',    tainted: false },
  'smtplib.SMTP_SSL.sendmail':    { nodeType: 'EGRESS', subtype: 'email',    tainted: false },

  // ═══════════════════════════════════════════════════════════════════════
  // EXTERNAL — calls to outside systems
  // ═══════════════════════════════════════════════════════════════════════

  // ── requests library ──
  'requests.get':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'requests.post':            { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'requests.put':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'requests.delete':          { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'requests.patch':           { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'requests.head':            { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'requests.options':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'requests.request':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'requests.Session':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // ── httpx ──
  'httpx.get':                { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'httpx.post':               { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'httpx.put':                { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'httpx.delete':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'httpx.patch':              { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'httpx.request':            { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'httpx.Client':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'httpx.AsyncClient':        { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // ── aiohttp ──
  'aiohttp.ClientSession':        { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'aiohttp.ClientSession.get':    { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'aiohttp.ClientSession.post':   { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'aiohttp.ClientSession.put':    { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'aiohttp.ClientSession.delete': { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // ── urllib ──
  'urllib.request.urlopen':     { nodeType: 'EXTERNAL', subtype: 'api_call',  tainted: false },
  'urllib.request.urlretrieve': { nodeType: 'EXTERNAL', subtype: 'api_call',  tainted: false },
  'urllib.request.Request':     { nodeType: 'EXTERNAL', subtype: 'api_call',  tainted: false },
  'urllib.parse.urlparse':      { nodeType: 'TRANSFORM', subtype: 'parse',    tainted: false },
  'urllib.parse.urlencode':     { nodeType: 'TRANSFORM', subtype: 'encode',   tainted: false },
  'urllib.parse.quote':         { nodeType: 'TRANSFORM', subtype: 'encode',   tainted: false },
  'urllib.parse.unquote':       { nodeType: 'TRANSFORM', subtype: 'decode',   tainted: false },
  'urllib.parse.unquote_plus':  { nodeType: 'TRANSFORM', subtype: 'decode',   tainted: false },
  'urllib.parse.parse_qs':      { nodeType: 'INGRESS',   subtype: 'user_input', tainted: true },
  'urllib.parse.parse_qsl':     { nodeType: 'INGRESS',   subtype: 'user_input', tainted: true },

  // ── cgi ──
  'cgi.FieldStorage':           { nodeType: 'INGRESS',   subtype: 'user_input', tainted: true },

  // ── BaseHTTPRequestHandler handler methods ──
  'BaseHTTPRequestHandler.do_GET':  { nodeType: 'STRUCTURAL', subtype: 'http_handler', tainted: false },
  'BaseHTTPRequestHandler.do_POST': { nodeType: 'STRUCTURAL', subtype: 'http_handler', tainted: false },
  // ── BaseHTTPRequestHandler output (EGRESS) ──
  'self.wfile.write':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'self.send_response':       { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'self.send_header':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'wfile.write':              { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // ── http.client — raw HTTP (SSRF vector) ──
  'http.client.HTTPConnection':   { nodeType: 'EXTERNAL', subtype: 'api_call',  tainted: false },
  'http.client.HTTPSConnection':  { nodeType: 'EXTERNAL', subtype: 'api_call',  tainted: false },

  // ── subprocess / os — system execution ──
  'subprocess.run':           { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'subprocess.call':          { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'subprocess.check_call':    { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'subprocess.check_output':  { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'subprocess.Popen':         { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'subprocess.getoutput':     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'subprocess.getstatusoutput': { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'os.system':                { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'os.popen':                 { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'os.exec':                  { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'os.execvp':                { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'os.execve':                { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'os.spawnl':                { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'os.spawnle':               { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // ── asyncio subprocess — async command execution ──
  'asyncio.create_subprocess_exec':   { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'asyncio.create_subprocess_shell':  { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // ── importlib — dynamic imports ──
  'importlib.import_module':  { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // ── ctypes — native code loading ──
  'ctypes.cdll.LoadLibrary':    { nodeType: 'EXTERNAL', subtype: 'native_load', tainted: false },
  'ctypes.CDLL':                { nodeType: 'EXTERNAL', subtype: 'native_load', tainted: false },
  'ctypes.windll.LoadLibrary':  { nodeType: 'EXTERNAL', subtype: 'native_load', tainted: false },

  // ── Celery — task dispatch ──
  'celery.send_task':         { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },

  // ── FastAPI BackgroundTasks — deferred execution ──
  'BackgroundTasks.add_task': { nodeType: 'EXTERNAL', subtype: 'deferred_exec', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════
  // STORAGE — persistent state
  // ═══════════════════════════════════════════════════════════════════════

  // ── SQLAlchemy ──
  'session.query':            { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'session.execute':          { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'session.add':              { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'session.add_all':          { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'session.delete':           { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'session.commit':           { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'session.rollback':         { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'session.flush':            { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'session.merge':            { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'session.bulk_save_objects':{ nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'session.bulk_insert_mappings': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'session.bulk_update_mappings': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

  // ── SQLModel (FastAPI ORM) ──
  'session.exec':             { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },

  // ── Django ORM ──
  'objects.all':              { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.filter':           { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.exclude':          { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.get':              { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.get_or_create':    { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'objects.create':           { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'objects.update':           { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'objects.delete':           { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'objects.bulk_create':      { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'objects.bulk_update':      { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'objects.values':           { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.values_list':      { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.aggregate':        { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.annotate':         { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.count':            { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.exists':           { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.first':            { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.last':             { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.order_by':         { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.select_related':   { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.prefetch_related': { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.raw':              { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'objects.extra':            { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'django.db.models.expressions.RawSQL': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'django.db.connection.cursor': { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },

  // ── Raw DB-API / sqlite3 ──
  'cursor.execute':           { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'cursor.executemany':       { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'cursor.fetchone':          { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'cursor.fetchall':          { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'cursor.fetchmany':         { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'connection.execute':       { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'connection.commit':        { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'connection.rollback':      { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'sqlite3.connect':          { nodeType: 'STORAGE',  subtype: 'db_connect',  tainted: false },

  // ── Redis ──
  'redis.get':                { nodeType: 'STORAGE',  subtype: 'cache_read',  tainted: false },
  'redis.set':                { nodeType: 'STORAGE',  subtype: 'cache_write', tainted: false },
  'redis.delete':             { nodeType: 'STORAGE',  subtype: 'cache_write', tainted: false },
  'redis.hget':               { nodeType: 'STORAGE',  subtype: 'cache_read',  tainted: false },
  'redis.hset':               { nodeType: 'STORAGE',  subtype: 'cache_write', tainted: false },
  'redis.lpush':              { nodeType: 'STORAGE',  subtype: 'cache_write', tainted: false },
  'redis.rpush':              { nodeType: 'STORAGE',  subtype: 'cache_write', tainted: false },
  'redis.lpop':               { nodeType: 'STORAGE',  subtype: 'cache_read',  tainted: false },
  'redis.rpop':               { nodeType: 'STORAGE',  subtype: 'cache_read',  tainted: false },
  'redis.publish':            { nodeType: 'STORAGE',  subtype: 'cache_write', tainted: false },
  'redis.subscribe':          { nodeType: 'STORAGE',  subtype: 'cache_read',  tainted: false },

  // ── MongoDB (pymongo) ──
  'collection.find':          { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'collection.find_one':      { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'collection.insert_one':    { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'collection.insert_many':   { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'collection.update_one':    { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'collection.update_many':   { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'collection.delete_one':    { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'collection.delete_many':   { nodeType: 'STORAGE',  subtype: 'db_write',    tainted: false },
  'collection.aggregate':     { nodeType: 'STORAGE',  subtype: 'db_read',     tainted: false },
  'collection.count_documents': { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },

  // ═══════════════════════════════════════════════════════════════════════
  // TRANSFORM — data processing
  // ═══════════════════════════════════════════════════════════════════════

  // ── json / parsing ──
  'json.loads':               { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'json.load':                { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // ── hashlib / crypto ──
  'hashlib.md5':              { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.sha1':             { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.sha256':           { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.sha512':           { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.sha3_256':         { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.sha3_512':         { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.blake2b':          { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.blake2s':          { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.pbkdf2_hmac':      { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.scrypt':           { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hashlib.new':              { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hmac.new':                 { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'hmac.digest':              { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'secrets.token_hex':        { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'secrets.token_bytes':      { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'secrets.token_urlsafe':    { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },

  // ── base64 ──
  'base64.b64encode':         { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'base64.b64decode':         { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'base64.urlsafe_b64encode': { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'base64.urlsafe_b64decode': { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'base64.b32encode':         { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'base64.b32decode':         { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },

  // ── html ──
  'html.escape':              { nodeType: 'TRANSFORM', subtype: 'sanitize',  tainted: false },
  'html.unescape':            { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'markupsafe.escape':        { nodeType: 'TRANSFORM', subtype: 'sanitize',  tainted: false },
  'flask.escape':             { nodeType: 'TRANSFORM', subtype: 'sanitize',  tainted: false },
  'codecs.open':              { nodeType: 'INGRESS',   subtype: 'file_read', tainted: false },
  'markupsafe.Markup':        { nodeType: 'TRANSFORM', subtype: 'sanitize',  tainted: false },
  'bleach.clean':             { nodeType: 'TRANSFORM', subtype: 'sanitize',  tainted: false },
  'django.utils.safestring.mark_safe': { nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false },
  'django.utils.html.format_html': { nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false },

  // ── re — regex ──
  're.match':                 { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  're.search':                { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  're.findall':               { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  're.finditer':              { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  're.sub':                   { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  're.subn':                  { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  're.split':                 { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  're.compile':               { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },

  // ── struct — binary packing ──
  'struct.pack':              { nodeType: 'TRANSFORM', subtype: 'serialize',  tainted: false },
  'struct.unpack':            { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'struct.pack_into':         { nodeType: 'TRANSFORM', subtype: 'serialize',  tainted: false },
  'struct.unpack_from':       { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // ── codecs ──
  'codecs.encode':            { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'codecs.decode':            { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },

  // ═══════════════════════════════════════════════════════════════════════
  // CONTROL — validation, flow, concurrency
  // ═══════════════════════════════════════════════════════════════════════

  // ── asyncio ──
  'asyncio.run':              { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.gather':           { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.create_task':      { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.sleep':            { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.wait':             { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.wait_for':         { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.ensure_future':    { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.get_event_loop':   { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.new_event_loop':   { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.Lock':             { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.Semaphore':        { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.Queue':            { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.Event':            { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'asyncio.TaskGroup':        { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },

  // ── threading ──
  'threading.Thread':         { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'threading.Lock':           { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'threading.RLock':          { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'threading.Semaphore':      { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'threading.Event':          { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'threading.Timer':          { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'threading.Barrier':        { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'threading.local':          { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },

  // ── multiprocessing ──
  'multiprocessing.Process':  { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'multiprocessing.Pool':     { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'multiprocessing.Queue':    { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'multiprocessing.Lock':     { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'multiprocessing.Value':    { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'multiprocessing.Array':    { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'multiprocessing.Manager':  { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'multiprocessing.Pipe':     { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },

  // ── signal ──
  'signal.signal':            { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },
  'signal.alarm':             { nodeType: 'CONTROL',  subtype: 'event_handler', tainted: false },

  // ── sys control ──
  'sys.exit':                 { nodeType: 'CONTROL',  subtype: 'guard',       tainted: false },
  'os._exit':                 { nodeType: 'CONTROL',  subtype: 'guard',       tainted: false },

  // ── Validation / Guards ──
  'validators.url':           { nodeType: 'CONTROL',  subtype: 'validation',  tainted: false },
  'validators.email':         { nodeType: 'CONTROL',  subtype: 'validation',  tainted: false },
  'cerberus.Validator':       { nodeType: 'CONTROL',  subtype: 'validation',  tainted: false },
  'marshmallow.Schema':       { nodeType: 'CONTROL',  subtype: 'validation',  tainted: false },
  'pydantic.BaseModel':       { nodeType: 'CONTROL',  subtype: 'validation',  tainted: false },
  'pydantic.validator':       { nodeType: 'CONTROL',  subtype: 'validation',  tainted: false },
  'pydantic.field_validator': { nodeType: 'CONTROL',  subtype: 'validation',  tainted: false },
  'wtforms.validators':       { nodeType: 'CONTROL',  subtype: 'validation',  tainted: false },

  // ═══════════════════════════════════════════════════════════════════════
  // AUTH — authentication and authorization
  // ═══════════════════════════════════════════════════════════════════════

  // ── bcrypt ──
  'bcrypt.hashpw':            { nodeType: 'AUTH',     subtype: 'authenticate', tainted: false },
  'bcrypt.checkpw':           { nodeType: 'AUTH',     subtype: 'authenticate', tainted: false },
  'bcrypt.gensalt':           { nodeType: 'AUTH',     subtype: 'authenticate', tainted: false },

  // ── passlib ──
  'passlib.hash':             { nodeType: 'AUTH',     subtype: 'authenticate', tainted: false },

  // ── jwt (PyJWT) ──
  'jwt.encode':               { nodeType: 'AUTH',     subtype: 'authenticate', tainted: false },
  'jwt.decode':               { nodeType: 'AUTH',     subtype: 'authenticate', tainted: false },

  // ── Django auth ──
  'django.contrib.auth.authenticate':    { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'django.contrib.auth.login':           { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'django.contrib.auth.logout':          { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'django.contrib.auth.decorators.login_required':    { nodeType: 'AUTH', subtype: 'authorize', tainted: false },
  'django.contrib.auth.decorators.permission_required': { nodeType: 'AUTH', subtype: 'authorize', tainted: false },
  'django.views.decorators.csrf.csrf_exempt': { nodeType: 'AUTH', subtype: 'authorize', tainted: false },

  // ── Flask-Login ──
  'flask_login.login_user':     { nodeType: 'AUTH',  subtype: 'authenticate', tainted: false },
  'flask_login.logout_user':    { nodeType: 'AUTH',  subtype: 'authenticate', tainted: false },
  'flask_login.current_user':   { nodeType: 'AUTH',  subtype: 'authenticate', tainted: false },
  'flask_login.login_required': { nodeType: 'AUTH',  subtype: 'authorize',    tainted: false },

  // ── itsdangerous (session signing) ──
  'itsdangerous.URLSafeTimedSerializer': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'itsdangerous.Signer':       { nodeType: 'AUTH',  subtype: 'authenticate', tainted: false },

  // ── OAuth / OIDC ──
  'authlib.jose.jwt':          { nodeType: 'AUTH',   subtype: 'authenticate', tainted: false },

  // ── django-allauth (social auth) ──
  'allauth.socialaccount.models.SocialLogin.connect': { nodeType: 'EXTERNAL', subtype: 'social_auth', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════
  // META — config, logging, debug
  // ═══════════════════════════════════════════════════════════════════════

  // ── logging (already covered above) ──
  'logging.basicConfig':       { nodeType: 'META',   subtype: 'config',      tainted: false },
  'logging.getLogger':         { nodeType: 'META',   subtype: 'config',      tainted: false },
  'logging.FileHandler':       { nodeType: 'META',   subtype: 'config',      tainted: false },
  'logging.StreamHandler':     { nodeType: 'META',   subtype: 'config',      tainted: false },

  // ── config ──
  'configparser.ConfigParser': { nodeType: 'META',   subtype: 'config',      tainted: false },
  'dotenv.load_dotenv':        { nodeType: 'META',   subtype: 'config',      tainted: false },

  // ── debug ──
  'pdb.set_trace':             { nodeType: 'META',   subtype: 'debug',       tainted: false },
  'traceback.print_exc':       { nodeType: 'META',   subtype: 'debug',       tainted: false },
  'traceback.format_exc':      { nodeType: 'META',   subtype: 'debug',       tainted: false },
  'warnings.warn':             { nodeType: 'META',   subtype: 'debug',       tainted: false },
};

// ── Wildcard member calls (*.method) ──────────────────────────────────────
// Matched when no specific "object.method" key hits.

const STORAGE_READ_METHODS = new Set([
  'query', 'find', 'find_one', 'find_all', 'filter', 'get',
  'select', 'count', 'aggregate', 'distinct', 'fetchone',
  'fetchall', 'fetchmany', 'all', 'first', 'last', 'one',
  'one_or_none', 'scalar', 'values', 'values_list',
  'exists', 'count_documents',
]);

const STORAGE_WRITE_METHODS = new Set([
  'insert', 'insert_one', 'insert_many', 'create',
  'update', 'update_one', 'update_many', 'upsert',
  'delete', 'delete_one', 'delete_many', 'remove',
  'save', 'add', 'commit', 'flush', 'merge',
  'bulk_create', 'bulk_update', 'bulk_save_objects',
  'bulk_insert_mappings', 'bulk_update_mappings',
  'execute', 'executemany',
]);

const TRANSFORM_CALCULATE_METHODS = new Set([
  // list/iterator operations
  'append', 'extend', 'insert', 'pop', 'remove',
  'sort', 'reverse', 'copy', 'clear',
  // dict operations
  'update', 'pop', 'setdefault', 'keys', 'values', 'items',
  // set operations
  'add', 'discard', 'union', 'intersection', 'difference',
  'symmetric_difference',
]);

const TRANSFORM_FORMAT_METHODS = new Set([
  // str methods
  'strip', 'lstrip', 'rstrip', 'lower', 'upper',
  'title', 'capitalize', 'casefold', 'swapcase',
  'split', 'rsplit', 'splitlines', 'join',
  'replace', 'translate', 'maketrans',
  'encode', 'decode',
  'startswith', 'endswith', 'find', 'rfind',
  'index', 'rindex', 'count',
  'center', 'ljust', 'rjust', 'zfill',
  'format', 'format_map',
  'isdigit', 'isalpha', 'isalnum', 'isspace',
  'isupper', 'islower', 'istitle',
  // datetime formatting
  'strftime', 'strptime', 'isoformat',
  'timestamp', 'timetuple',
]);

// ── Lookup function ───────────────────────────────────────────────────────

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  // Strategy 1: Direct call
  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };
    return null;
  }

  // Strategy 2: Exact member match
  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  const member = MEMBER_CALLS[exactKey];
  if (member) return { ...member };

  // Try deeper chain: "a.b.c" → try "b.c"
  if (calleeChain.length > 2) {
    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
  }

  // Try full dotted path for deep module references
  // e.g. ['django', 'contrib', 'auth', 'authenticate'] → "django.contrib.auth.authenticate"
  if (calleeChain.length > 2) {
    const fullPath = calleeChain.join('.');
    const fullMember = MEMBER_CALLS[fullPath];
    if (fullMember) return { ...fullMember };
  }

  // Strategy 3: Wildcard matching
  if (STORAGE_READ_METHODS.has(methodName)) {
    if (!isLikelyListMethod(objectName, methodName)) {
      return { nodeType: 'STORAGE', subtype: 'db_read', tainted: false };
    }
  }

  if (STORAGE_WRITE_METHODS.has(methodName)) {
    if (!isLikelyListMethod(objectName, methodName)) {
      return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false };
    }
  }

  if (TRANSFORM_FORMAT_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'format', tainted: false };
  }

  if (TRANSFORM_CALCULATE_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'calculate', tainted: false };
  }

  return null;
}

// Known non-DB variable names in Python contexts
const NON_DB_OBJECTS = new Set([
  // Web framework objects
  'app', 'request', 'response', 'flask', 'django', 'fastapi',
  'self', 'cls', 'ctx', 'context',
  // List-like variable names
  'arr', 'array', 'list', 'items', 'elements', 'results',
  'users', 'posts', 'records', 'rows', 'entries', 'values',
  'data', 'children', 'nodes', 'keys',
  // Other non-DB
  'os', 'sys', 'path', 'config', 'settings', 'options',
  'args', 'kwargs', 'params',
]);

function isLikelyListMethod(objectName: string, methodName: string): boolean {
  if (NON_DB_OBJECTS.has(objectName)) return true;

  const AMBIGUOUS = new Set([
    'find', 'get', 'count', 'insert', 'pop', 'remove',
    'update', 'values', 'keys', 'items', 'add', 'clear', 'copy',
  ]);
  if (!AMBIGUOUS.has(methodName)) return false;

  return false;
}

// ── Sink patterns (CWE → dangerous regex) ─────────────────────────────────

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /(?:subprocess\.(?:call|run|Popen|check_call|check_output)\s*\([^)]*shell\s*=\s*True|os\.system\s*\(\s*(?:f['"]|['"].*\+|.*\.format)|os\.popen\s*\(|asyncio\.create_subprocess_shell\s*\(\s*(?:f['"]|['"].*\+|.*\.format)|asyncio\.create_subprocess_exec\s*\(\s*(?:f['"]|['"].*\+|.*\.format))/,
  'CWE-89':  /(?:cursor\.execute|\.raw)\s*\(\s*(?:f['"]|['"].*%s.*['"].*%|['"].*\.format)/,
  'CWE-94':  /\b(?:eval|exec)\s*\(\s*(?:request|input|argv|sys\.stdin|f['"])/,
  'CWE-79':  /(?:render_template_string\s*\(\s*(?:request|input|f['"'])|autoescape\s*=\s*False|html\.unescape\s*\()/,
  'CWE-22':  /(?:open\s*\(\s*(?:request|input|argv|f['"].*\{)|(?:tarfile\.open|zipfile\.ZipFile)\s*\([^)]*\)\.extractall\s*\()/,
  'CWE-502': /(?:pickle\.loads?\s*\(|yaml\.load\s*\([^)]*(?!Loader)|marshal\.loads?\s*\(|shelve\.open\s*\(|(?:pandas|pd)\.read_pickle\s*\(|(?:numpy|np)\.load\s*\([^)]*allow_pickle\s*=\s*True|torch\.load\s*\(|joblib\.load\s*\()/,
  'CWE-327': /(?:hashlib\.(?:md5|sha1)\s*\()/,
  'CWE-345': /jwt\.decode\s*\([^)]*verify\s*=\s*False/,
  'CWE-798': /(?:SECRET_KEY|PASSWORD|API_KEY|TOKEN)\s*=\s*['"][^'"]{10,}['"]/,
  'CWE-489': /(?:app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)/,
  'CWE-918': /(?:requests\.(?:get|post)\s*\(\s*(?:request|input|f['"])|urllib\.request\.urlopen\s*\(\s*(?:request|input|f['"])|http\.client\.HTTPConnection\s*\(\s*(?:request|input|f['"])|http\.client\.HTTPSConnection\s*\(\s*(?:request|input|f['"]))/,
  'CWE-915': /getattr\s*\(\s*\w+\s*,\s*(?:request|input|argv)/,
  'CWE-427': /importlib\.import_module\s*\(\s*(?:request|input|argv|f['"])/,
  'CWE-119': /ctypes\.(?:cast|pointer|POINTER|c_void_p)/,
  'CWE-367': /tempfile\.mktemp\s*\(/,
  'CWE-913': /(?:globals\s*\(\)\s*\[|__subclasshook__)/,
  'CWE-942': /CORS_ALLOW_ALL_ORIGINS\s*=\s*True/,
  'CWE-617': /\bassert\s+(?:user|is_admin|is_auth|has_perm|check_)/,
  'CWE-611': /(?:xml\.etree\.ElementTree\.(?:parse|fromstring|iterparse)|ET\.(?:parse|fromstring|iterparse)|xml\.sax\.parse|minidom\.parse|minidom\.parseString)\s*\(/,
  'CWE-426': /ctypes\.(?:cdll\.LoadLibrary|CDLL|windll\.LoadLibrary)\s*\(\s*(?:request|input|argv|f['"]|['"].*\+|.*\.format)/,
};

// ── Safe patterns (CWE → mitigating regex) ────────────────────────────────

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /subprocess\.(?:run|call|Popen)\s*\(\s*\[/,        // list form = no shell injection
  'CWE-89':  /cursor\.execute\s*\(\s*['"][^'"]*(?:\?|%s)[^'"]*['"],?\s*(?:\(|\[)/, // parameterized queries
  'CWE-94':  /ast\.literal_eval\s*\(/,                           // safe eval alternative
  'CWE-79':  /(?:html\.escape|markupsafe\.escape|bleach\.clean)\s*\(/,
  'CWE-22':  /(?:os\.path\.(?:abspath|realpath|normpath)|pathlib\.Path\.resolve)\s*\(/, // path normalization
  'CWE-502': /(?:yaml\.safe_load\s*\(|torch\.load\s*\([^)]*weights_only\s*=\s*True|(?:numpy|np)\.load\s*\([^)]*allow_pickle\s*=\s*False)/, // safe YAML, safe torch.load, safe np.load
  'CWE-327': /(?:hashlib\.(?:sha256|sha512|sha3_256|sha3_512|blake2[bs]|pbkdf2_hmac|scrypt)|bcrypt\.hashpw|passlib\.hash)\s*\(/,
  'CWE-345': /jwt\.decode\s*\([^)]*algorithms\s*=\s*\[/,        // explicit algorithm
  'CWE-918': /(?:urllib\.parse\.urlparse|validators\.url)\s*\(/,  // URL validation
  'CWE-367': /tempfile\.(?:mkstemp|NamedTemporaryFile|TemporaryFile)\s*\(/, // safe tempfile
  'CWE-611': /defusedxml\.(?:parse|fromstring|iterparse|ElementTree\.parse)\s*\(/, // defusedxml blocks XXE
};

// ── Pattern count ─────────────────────────────────────────────────────────

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size
    + TRANSFORM_CALCULATE_METHODS.size
    + TRANSFORM_FORMAT_METHODS.size;
}
