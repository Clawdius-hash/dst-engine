/**
 * Phoneme expansion: Go — advanced patterns
 *
 * Scope: reflect package (CWE-470 unsafe reflection), plugin.Lookup,
 * go/ast code generation, net/rpc, gRPC-Go interceptors.
 *
 * Agent-generated, tested against real patterns.
 *
 * CRITICAL FINDING: The existing go.ts classifies reflect.ValueOf, reflect.TypeOf,
 * and reflect.MakeFunc as TRANSFORM/calculate. That's fine for introspection — but
 * the truly dangerous reflect operations are reflect.Value.Call() and
 * reflect.Value.MethodByName(). These enable CWE-470 (Use of Externally-Controlled
 * Input to Select Classes or Code): if a user-supplied string flows into
 * MethodByName().Call(), an attacker can invoke ANY exported method on ANY type.
 * This is Go's equivalent of Java's Class.forName() + Method.invoke().
 *
 * The CWE-749 sink pattern already matches these (line 773 of go.ts), but without
 * MEMBER_CALLS entries the scanner can't build a proper taint graph through them.
 * We classify them as EXTERNAL (not TRANSFORM) because they cross a trust boundary:
 * the callee is not statically known.
 *
 * SECOND FINDING: net/rpc is Go's built-in RPC framework. It's deprecated in favor
 * of gRPC but still appears in legacy codebases. rpc.Dial/DialHTTP create network
 * connections to remote services, and client.Call invokes remote procedures — all
 * EXTERNAL calls where the method name may be user-controlled.
 *
 * THIRD FINDING: gRPC interceptors (UnaryInterceptor, StreamInterceptor) are the
 * gRPC equivalent of HTTP middleware. They're CONTROL nodes because they sit in the
 * request pipeline and can validate, authenticate, rate-limit, or transform
 * requests before they reach the handler.
 *
 * 10 entries below. All are NET NEW (not duplicates of existing go.ts entries).
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_GO_ADVANCED: Record<string, CalleePattern> = {

  // ── 1. reflect.Value.Call — CWE-470 unsafe dynamic invocation ───────────
  // v := reflect.ValueOf(obj); v.MethodByName(userInput).Call(args)
  // This invokes whatever method the string names. If userInput comes from
  // HTTP params, an attacker can call Delete(), Drop(), Exec() — anything
  // the type exports. This is the single most dangerous reflect operation.
  // Classified as EXTERNAL because the call target is not statically known.
  'v.Call': { nodeType: 'EXTERNAL', subtype: 'unsafe_reflect', tainted: true },

  // ── 2. reflect.Value.MethodByName — CWE-470 method resolution by string ─
  // v.MethodByName("HandleAdmin") returns a reflect.Value that can be Call()'d.
  // The string argument is the attack surface: if it comes from user input,
  // the attacker controls which method gets invoked. Even without Call(),
  // just resolving a method leaks information about the type's API.
  'v.MethodByName': { nodeType: 'EXTERNAL', subtype: 'unsafe_reflect', tainted: true },

  // ── 3. plugin.Lookup — dynamic symbol resolution from loaded plugin ──────
  // p, _ := plugin.Open("evil.so"); sym, _ := p.Lookup("RunPayload")
  // plugin.Open is already tracked. But Lookup is equally dangerous: it
  // resolves arbitrary exported symbols (functions, variables) from the
  // loaded shared object. Combined with a type assertion, the resolved
  // symbol can be called as a function. This is dynamic code loading.
  'p.Lookup': { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: true },

  // ── 4. parser.ParseFile — go/ast source code parsing ─────────────────────
  // fset := token.NewFileSet(); f, _ := parser.ParseFile(fset, "main.go", src, 0)
  // Part of the go/ast toolchain for code generation and analysis.
  // ParseFile turns Go source into an AST. Security-relevant because code
  // generation tools that parse untrusted input can produce malicious code
  // (CWE-94 variant). META because it's about code structure, not runtime.
  'parser.ParseFile': { nodeType: 'META', subtype: 'codegen', tainted: false },

  // ── 5. ast.Inspect — AST traversal for code analysis/generation ──────────
  // ast.Inspect(f, func(n ast.Node) bool { ... }) walks the entire AST.
  // Used by linters, code generators, and security scanners (including DST
  // itself, potentially). META because it operates on code structure.
  'ast.Inspect': { nodeType: 'META', subtype: 'codegen', tainted: false },

  // ── 6. rpc.Dial — net/rpc client connection ──────────────────────────────
  // client, err := rpc.Dial("tcp", "evil-server:1234")
  // Creates a connection to a remote RPC server. The address argument is
  // the attack surface: if user-controlled, this is SSRF (CWE-918).
  // Deprecated in favor of gRPC but still found in legacy Go services.
  'rpc.Dial': { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // ── 7. rpc.DialHTTP — net/rpc client over HTTP ──────────────────────────
  // client, err := rpc.DialHTTP("tcp", "server:1234")
  // Same as rpc.Dial but tunnels over HTTP. Same SSRF risk if the address
  // is user-controlled. The HTTP transport makes it slightly more likely
  // to pass through firewalls, increasing the attack surface.
  'rpc.DialHTTP': { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // ── 8. client.Call — net/rpc remote procedure invocation ─────────────────
  // err := client.Call("Service.Method", args, &reply)
  // Invokes a method on the remote RPC server. The method name is a string —
  // if user-controlled, an attacker can call any registered RPC method.
  // This is the net/rpc equivalent of CWE-470 (method selection by string).
  // Note: this key also matches http.Client.Call if it existed, but it doesn't
  // in Go's stdlib. The existing client.Do/Get/Post are for http.Client.
  'client.Call': { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // ── 9. grpc.UnaryInterceptor — gRPC unary request middleware ─────────────
  // grpc.NewServer(grpc.UnaryInterceptor(authInterceptor))
  // A unary interceptor wraps every unary (request-response) RPC call.
  // Used for authentication, logging, rate limiting, tracing. It's a
  // CONTROL node because it validates/transforms requests in the pipeline,
  // exactly like HTTP middleware (router.Use in Gin).
  'grpc.UnaryInterceptor': { nodeType: 'CONTROL', subtype: 'middleware', tainted: false },

  // ── 10. grpc.StreamInterceptor — gRPC streaming request middleware ───────
  // grpc.NewServer(grpc.StreamInterceptor(streamAuthInterceptor))
  // Same as UnaryInterceptor but for streaming RPCs (server-stream,
  // client-stream, bidirectional). Critical for enforcing auth on long-lived
  // streams where a single initial check isn't sufficient.
  'grpc.StreamInterceptor': { nodeType: 'CONTROL', subtype: 'middleware', tainted: false },
};
