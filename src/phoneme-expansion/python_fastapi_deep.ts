/**
 * Phoneme expansion: Python FastAPI deep — Depends, BackgroundTasks, WebSocket,
 * UploadFile, OAuth2PasswordBearer, SQLModel
 * Agent-generated for DST phoneme dictionary
 *
 * Coverage gap: FastAPI's deeper APIs had ZERO entries in the Python callee
 * dictionary. The existing dictionary covers Request.* ingress and response
 * classes (JSONResponse, etc.) but misses the dependency injection system,
 * background task dispatch, WebSocket bidirectional channels, file upload
 * vectors, OAuth2 security schemes, and SQLModel's ORM layer.
 *
 * Depends() (STRUCTURAL — dependency injection):
 *   FastAPI's `Depends(callable)` is the DI system. It controls what gets
 *   injected into route handlers. If the dependency callable is user-controlled
 *   or poorly scoped, it can bypass auth checks or inject malicious state.
 *   Marking as STRUCTURAL because it defines the application's wiring topology.
 *
 * BackgroundTasks.add_task() (EXTERNAL — deferred execution):
 *   Schedules a callable to run after the response is sent. This is dangerous
 *   because (1) errors in background tasks are silent by default, (2) the task
 *   runs outside the request lifecycle so middleware/auth checks don't apply,
 *   and (3) if the callable or its args are user-influenced, it's deferred RCE.
 *
 * WebSocket.receive_text/json() (INGRESS — persistent tainted input):
 *   WebSocket connections are persistent bidirectional channels. Unlike HTTP
 *   requests, they bypass per-request middleware. Data received via receive_text()
 *   or receive_json() is fully attacker-controlled and tainted.
 *
 * WebSocket.send_text/json() (EGRESS — data exfiltration channel):
 *   The outbound side of WebSocket. Can leak sensitive data if the server
 *   pushes user data or DB contents over the socket without sanitization.
 *
 * UploadFile.read() (INGRESS — file upload vector):
 *   FastAPI's UploadFile wraps Starlette's UploadFile. The .read() method
 *   returns raw bytes from the uploaded file — fully attacker-controlled content.
 *   Common attack vectors: malicious file content, zip bombs, polyglot files.
 *
 * OAuth2PasswordBearer (AUTH — token extraction scheme):
 *   Declares an OAuth2 password bearer token dependency. It extracts the Bearer
 *   token from the Authorization header. Security-critical because it's the
 *   entry point for token-based auth in FastAPI apps.
 *
 * SQLModel Session.exec() (STORAGE — ORM query execution):
 *   SQLModel (by the FastAPI author) uses session.exec() instead of SQLAlchemy's
 *   session.execute(). It runs SQL statements against the database. If the
 *   statement includes unsanitized user input, it's SQL injection.
 */

import type { CalleePattern } from '../languages/python.js';

export const PHONEMES_PYTHON_FASTAPI_DEEP: Record<string, CalleePattern> = {

  // ═══════════════════════════════════════════════════════════════════════════
  // STRUCTURAL — FastAPI Depends() dependency injection
  // ═══════════════════════════════════════════════════════════════════════════
  // Depends(callable) is FastAPI's DI system. It defines the wiring graph of
  // the application: what gets injected where. A dependency can itself have
  // sub-dependencies, forming a DAG. If a security dependency (e.g., get_current_user)
  // is missing from a route, that route has no auth. DST needs to see Depends()
  // calls to map the structural topology of FastAPI apps.

  // STRUCTURAL: Depends(get_current_user) — declares a dependency injection point.
  // This is the spine of FastAPI's architecture. Every route's behavior is shaped
  // by what gets injected through Depends().
  'Depends':                    { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // EXTERNAL — BackgroundTasks deferred execution
  // ═══════════════════════════════════════════════════════════════════════════
  // BackgroundTasks.add_task(func, *args) schedules func to run after the HTTP
  // response is sent. The task runs in the same process but outside the request
  // lifecycle. Middleware, exception handlers, and auth decorators do NOT apply.
  // If func or args are derived from user input, this is deferred code execution.

  // EXTERNAL: background_tasks.add_task(send_email, email_to, body) — deferred execution.
  // Runs after response. No middleware protection. Silent failures by default.
  'BackgroundTasks.add_task':   { nodeType: 'EXTERNAL',   subtype: 'deferred_exec', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // INGRESS — WebSocket receive (persistent tainted input)
  // ═══════════════════════════════════════════════════════════════════════════
  // FastAPI WebSocket connections are persistent bidirectional channels that
  // bypass per-request middleware. All data received is attacker-controlled.

  // INGRESS: await websocket.receive_text() — reads raw text from the WebSocket.
  // Fully tainted. Bypasses HTTP middleware. Persistent connection = sustained attack surface.
  'WebSocket.receive_text':     { nodeType: 'INGRESS',    subtype: 'websocket_read', tainted: true },

  // INGRESS: await websocket.receive_json() — reads and parses JSON from the WebSocket.
  // Tainted. The JSON is attacker-controlled. Deserialization happens automatically.
  'WebSocket.receive_json':     { nodeType: 'INGRESS',    subtype: 'websocket_read', tainted: true },

  // ═══════════════════════════════════════════════════════════════════════════
  // EGRESS — WebSocket send (data exfiltration channel)
  // ═══════════════════════════════════════════════════════════════════════════

  // EGRESS: await websocket.send_text(data) — sends text over the WebSocket.
  // If data contains unsanitized user data or secrets, it's a leak channel.
  'WebSocket.send_text':        { nodeType: 'EGRESS',     subtype: 'websocket_write', tainted: false },

  // EGRESS: await websocket.send_json(data) — sends JSON over the WebSocket.
  // Same risk as send_text but with automatic serialization.
  'WebSocket.send_json':        { nodeType: 'EGRESS',     subtype: 'websocket_write', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // INGRESS — UploadFile (file upload attack vector)
  // ═══════════════════════════════════════════════════════════════════════════
  // FastAPI's UploadFile wraps Starlette's UploadFile. The file content is
  // fully attacker-controlled. Common vectors: zip bombs, polyglot files,
  // path traversal in filename, malicious content parsed downstream.

  // INGRESS: await upload_file.read() — reads raw bytes from the uploaded file.
  // Fully tainted. The content is whatever the attacker uploaded.
  'UploadFile.read':            { nodeType: 'INGRESS',    subtype: 'file_upload', tainted: true },

  // INGRESS: upload_file.filename — the client-provided filename.
  // Tainted. Classic path traversal vector: "../../etc/passwd".
  'UploadFile.filename':        { nodeType: 'INGRESS',    subtype: 'file_upload', tainted: true },

  // ═══════════════════════════════════════════════════════════════════════════
  // AUTH — OAuth2PasswordBearer token extraction
  // ═══════════════════════════════════════════════════════════════════════════
  // OAuth2PasswordBearer(tokenUrl="/token") is a FastAPI security scheme that
  // extracts the Bearer token from the Authorization header. It's the standard
  // way to declare token-based auth in FastAPI. The extracted token is untrusted
  // input that must be validated (e.g., via jwt.decode).

  // AUTH: OAuth2PasswordBearer(tokenUrl="/token") — declares a Bearer token auth scheme.
  // Extracts the token from the Authorization header. The token itself is untrusted.
  'OAuth2PasswordBearer':       { nodeType: 'AUTH',       subtype: 'authenticate', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // STORAGE — SQLModel session.exec() (ORM query execution)
  // ═══════════════════════════════════════════════════════════════════════════
  // SQLModel (by Sebastián Ramírez, the FastAPI author) wraps SQLAlchemy but uses
  // session.exec() instead of session.execute(). This is the primary query method
  // in SQLModel-based FastAPI apps. If the statement includes user input, SQLi.

  // STORAGE: session.exec(select(User).where(User.name == name)) — runs a query.
  // SQLModel's primary query method. SQL injection if statement is built from user input.
  'session.exec':               { nodeType: 'STORAGE',    subtype: 'db_read', tainted: false },

} as const;

// ── Pattern count ─────────────────────────────────────────────────────────

export function getPhonemeCount(): number {
  return Object.keys(PHONEMES_PYTHON_FASTAPI_DEEP).length;
}
