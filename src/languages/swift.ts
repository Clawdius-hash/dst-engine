/**
 * Swift Callee Pattern Database
 *
 * Maps Swift function/method names to DST Neural Map node types.
 * Covers: Foundation, UIKit/SwiftUI, URLSession, CoreData, Keychain,
 *         CryptoKit, Combine, async/await, Vapor (server-side Swift).
 *
 * Sources:
 *   - corpus_audit_swift.json (47 Category B + 194 Category A patterns)
 *   - Swift/iOS/macOS framework knowledge (heavy gap-filling)
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (global functions) ------------------------------------------

const DIRECT_CALLS: Record<string, CalleePattern> = {
  // EGRESS
  print:            { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  debugPrint:       { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  dump:             { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  NSLog:            { nodeType: 'META',      subtype: 'logging',       tainted: false },

  // INGRESS
  readLine:         { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },

  // CONTROL
  precondition:     { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  preconditionFailure: { nodeType: 'CONTROL', subtype: 'guard',        tainted: false },
  fatalError:       { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  assert:           { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  assertionFailure: { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  exit:             { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  abort:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  withCheckedContinuation: { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  withCheckedThrowingContinuation: { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  withUnsafeContinuation: { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  withTaskGroup:    { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  withThrowingTaskGroup: { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // TRANSFORM
  min:              { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  max:              { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  abs:              { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  stride:           { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  zip:              { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  sequence:         { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  type:             { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
};

// -- Member calls (object.method / Type.method) -------------------------------

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS
  // =========================================================================

  // -- URLSession response data --
  'URLSession.data':            { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'URLSession.dataTask':        { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'URLSession.download':        { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'URLSession.downloadTask':    { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'URLSession.bytes':           { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'URLSession.shared.data':     { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  // URLSession.shared.dataTask in EXTERNAL section (it's an external API call)

  // -- File / Data read --
  'FileManager.contentsAtPath':   { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'FileManager.contents':         { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'FileManager.contentsOfDirectory': { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'FileManager.fileExists':       { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'FileManager.attributesOfItem': { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'Data.init':                    { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'Data.init(contentsOf':         { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'String.init':                  { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'String.init(contentsOfFile':   { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'String.init(contentsOf':       { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'NSString.init(contentsOfFile': { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },

  // -- UserDefaults read --
  'UserDefaults.standard.string':   { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },
  'UserDefaults.standard.integer':  { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },
  'UserDefaults.standard.bool':     { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },
  'UserDefaults.standard.double':   { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },
  'UserDefaults.standard.data':     { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },
  'UserDefaults.standard.array':    { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },
  'UserDefaults.standard.dictionary': { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },
  'UserDefaults.standard.object':   { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },
  'UserDefaults.standard.value':    { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },

  // -- Environment --
  'ProcessInfo.processInfo.environment': { nodeType: 'INGRESS', subtype: 'env_read', tainted: true },
  'CommandLine.arguments':        { nodeType: 'INGRESS', subtype: 'env_read', tainted: true },

  // -- Keychain read --
  'SecItemCopyMatching':          { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },

  // -- Bundle --
  'Bundle.main.path':             { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'Bundle.main.url':              { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'Bundle.main.infoDictionary':   { nodeType: 'INGRESS', subtype: 'env_read', tainted: false },
  'Bundle.main.object':           { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },

  // -- WebSocket ingress --
  'ws.onText':                    { nodeType: 'INGRESS', subtype: 'websocket_read', tainted: true },
  'URLSessionWebSocketTask.receive': { nodeType: 'INGRESS', subtype: 'websocket_read', tainted: true },

  // -- Pasteboard (user input) --
  'UIPasteboard.general.string':  { nodeType: 'INGRESS', subtype: 'user_input', tainted: true },
  'UIPasteboard.general.strings': { nodeType: 'INGRESS', subtype: 'user_input', tainted: true },
  'UIPasteboard.general.url':     { nodeType: 'INGRESS', subtype: 'user_input', tainted: true },
  'UIPasteboard.general.image':   { nodeType: 'INGRESS', subtype: 'user_input', tainted: true },

  // -- Vapor server-side --
  'req.content.decode':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.content.get':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.session.data':             { nodeType: 'INGRESS', subtype: 'session_read', tainted: true },
  'req.query.decode':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.parameters.get':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.headers':                  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.body':                     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'req.cookies':                  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // =========================================================================
  // EGRESS
  // =========================================================================

  // -- File write --
  'FileManager.createFile':       { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'FileManager.createDirectory':  { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'FileManager.copyItem':         { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'FileManager.moveItem':         { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'FileManager.removeItem':       { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'Data.write':                   { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },

  // -- UserDefaults write --
  'UserDefaults.standard.set':         { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'UserDefaults.standard.removeObject': { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },

  // -- URLSession upload --
  'URLSession.upload':            { nodeType: 'EGRESS', subtype: 'network_write', tainted: false },
  'URLSession.uploadTask':        { nodeType: 'EGRESS', subtype: 'network_write', tainted: false },

  // -- WebView --
  'WKWebView.evaluateJavaScript': { nodeType: 'EGRESS', subtype: 'display', tainted: false },
  'WKWebView.load':               { nodeType: 'EGRESS', subtype: 'display', tainted: false },
  'WKWebView.loadHTMLString':     { nodeType: 'EGRESS', subtype: 'display', tainted: false },
  'WKWebView.loadFileURL':       { nodeType: 'EGRESS', subtype: 'xss_sink', tainted: false },

  // -- URL open --
  'UIApplication.shared.open':    { nodeType: 'EGRESS', subtype: 'display', tainted: false },

  // -- Vapor response --
  'Response.init':                { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Keychain write --
  // SecItemAdd in AUTH section (Keychain is auth-centric)
  'SecItemUpdate':                { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'SecItemDelete':                { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },

  // =========================================================================
  // EXTERNAL
  // =========================================================================

  // -- URLSession (SSRF sink when URL is user-controlled) --
  'URLSession.shared.dataTask':   { nodeType: 'EXTERNAL', subtype: 'ssrf', tainted: false },
  'URLRequest.init':              { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'URL.init':                     { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // -- Insecure deserialization --
  'NSKeyedUnarchiver.unarchiveObject': { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // -- URL protocol interception --
  'URLProtocol.registerClass':    { nodeType: 'EXTERNAL', subtype: 'network_intercept', tainted: false },

  // -- Network framework --
  'NWConnection.start':           { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'NWConnection.send':            { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'NWConnection.receive':         { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'NWListener.start':             { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },

  // -- Process (system exec) --
  'Process.executableURL':        { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Process.launch':               { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Process.run':                  { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Process.init':                 { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Process.arguments':            { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Process.launchPath':           { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'process.arguments':            { nodeType: 'INGRESS',  subtype: 'env_read',    tainted: true  },
  'Process.terminationStatus':    { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // -- Alamofire --
  'AF.request':                   { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'AF.download':                  { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'AF.upload':                    { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'Session.request':              { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // -- Vapor client --
  'req.client.get':               { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'req.client.post':              { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'app.client.get':               { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'app.client.post':              { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // -- Vapor server start --
  'app.run':                      { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },

  // -- Notification --
  'NotificationCenter.default.post': { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'NotificationCenter.default.addObserver': { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },

  // =========================================================================
  // STORAGE
  // =========================================================================

  // -- CoreData --
  'NSManagedObjectContext.fetch':    { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'NSManagedObjectContext.count':    { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'NSManagedObjectContext.save':     { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'NSManagedObjectContext.delete':   { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'NSManagedObjectContext.insert':   { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'NSManagedObjectContext.perform':  { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'NSManagedObjectContext.performAndWait': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'NSFetchRequest.init':            { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'NSPersistentContainer.loadPersistentStores': { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },

  // -- SwiftData --
  'ModelContext.fetch':             { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'ModelContext.insert':            { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'ModelContext.delete':            { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'ModelContext.save':              { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'ModelContainer.init':            { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },

  // -- GRDB --
  'dbQueue.read':                   { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'dbQueue.write':                  { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'db.execute':                     { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

  // -- Realm --
  'realm.objects':                  { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'realm.object':                   { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'realm.write':                    { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'realm.add':                      { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'realm.delete':                   { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

  // -- Vapor raw SQL --
  'SQLDatabase.raw':                { nodeType: 'STORAGE', subtype: 'sql', tainted: false },

  // -- Vapor Fluent ORM --
  'Model.query':                    { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'Model.find':                     { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'Model.create':                   { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'Model.save':                     { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'Model.update':                   { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'Model.delete':                   { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

  // -- Cache --
  'NSCache.setObject':              { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'NSCache.object':                 { nodeType: 'STORAGE', subtype: 'cache_read', tainted: false },
  'NSCache.removeObject':           { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },

  // =========================================================================
  // TRANSFORM
  // =========================================================================

  // -- JSON coding --
  'JSONDecoder.decode':             { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'JSONEncoder.encode':             { nodeType: 'TRANSFORM', subtype: 'serialize', tainted: false },
  'JSONSerialization.jsonObject':    { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'JSONSerialization.data':          { nodeType: 'TRANSFORM', subtype: 'serialize', tainted: false },

  // -- PropertyList coding --
  'PropertyListDecoder.decode':     { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'PropertyListEncoder.encode':     { nodeType: 'TRANSFORM', subtype: 'serialize', tainted: false },

  // -- CryptoKit --
  'SHA256.hash':                    { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'SHA384.hash':                    { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'SHA512.hash':                    { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'HMAC.authenticationCode':        { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'HMAC.isValidAuthenticationCode': { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'AES.GCM.seal':                   { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'AES.GCM.open':                   { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'ChaChaPoly.seal':                { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'ChaChaPoly.open':                { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'SymmetricKey.init':              { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'P256.Signing.PrivateKey':        { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'P256.KeyAgreement.PrivateKey':   { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'Curve25519.Signing.PrivateKey':  { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },

  // -- Security.framework --
  'SecKeyCreateSignature':        { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },

  // -- CommonCrypto --
  'CC_SHA256':                      { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'CC_MD5':                         { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'CCCrypt':                        { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'SecRandomCopyBytes':             { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },

  // -- Date formatting --
  'DateFormatter.string':           { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'DateFormatter.date':             { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'ISO8601DateFormatter.string':    { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'ISO8601DateFormatter.date':      { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'NumberFormatter.string':         { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'NumberFormatter.number':         { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'ByteCountFormatter.string':      { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },

  // -- Data encoding --
  'Data.base64EncodedString':       { nodeType: 'TRANSFORM', subtype: 'encode', tainted: false },
  'Data.base64EncodedData':         { nodeType: 'TRANSFORM', subtype: 'encode', tainted: false },

  // -- URL parsing --
  'URLComponents.init':             { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'URL.absoluteString':             { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },

  // -- Regex --
  'Regex.init':                     { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'NSRegularExpression.init':       { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },

  // =========================================================================
  // CONTROL
  // =========================================================================

  // -- GCD --
  'DispatchQueue.main.async':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchQueue.main.sync':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchQueue.global.async':     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchQueue.global.sync':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchQueue.concurrentPerform':{ nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchSemaphore.wait':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchSemaphore.signal':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchGroup.enter':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchGroup.leave':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchGroup.notify':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'DispatchGroup.wait':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- OperationQueue --
  'OperationQueue.addOperation':    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'OperationQueue.addOperations':   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Async/Await --
  'Task.init':                      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Task.detached':                  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Task.sleep':                     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Task.cancel':                    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Task.yield':                     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'MainActor.run':                  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'MainActor.assumeIsolated':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Timer --
  'Timer.scheduledTimer':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Combine --
  'Combine.sink':                   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Combine.assign':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Vapor middleware --
  'app.middleware.use':             { nodeType: 'CONTROL', subtype: 'guard', tainted: false },

  // =========================================================================
  // AUTH
  // =========================================================================

  // -- LocalAuthentication --
  'LAContext.evaluatePolicy':       { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'LAContext.canEvaluatePolicy':    { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },

  // -- AuthenticationServices --
  'ASAuthorizationController.performRequests': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'ASAuthorizationAppleIDProvider.createRequest': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },

  // -- Keychain (auth context) --
  'SecItemAdd':                     { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'SecAccessControl.init':          { nodeType: 'AUTH', subtype: 'access_policy', tainted: false },

  // -- Vapor auth --
  'req.auth.require':               { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'req.auth.get':                   { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'req.auth.login':                 { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'req.auth.logout':                { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },

  // =========================================================================
  // META
  // =========================================================================

  // -- os.log / Logger --
  'Logger.init':                    { nodeType: 'META', subtype: 'config', tainted: false },
  'Logger.info':                    { nodeType: 'META', subtype: 'logging', tainted: false },
  'Logger.debug':                   { nodeType: 'META', subtype: 'logging', tainted: false },
  'Logger.error':                   { nodeType: 'META', subtype: 'logging', tainted: false },
  'Logger.warning':                 { nodeType: 'META', subtype: 'logging', tainted: false },
  'Logger.critical':                { nodeType: 'META', subtype: 'logging', tainted: false },
  'Logger.notice':                  { nodeType: 'META', subtype: 'logging', tainted: false },
  'Logger.trace':                   { nodeType: 'META', subtype: 'logging', tainted: false },
  'os_log':                         { nodeType: 'META', subtype: 'logging', tainted: false },

  // -- Vapor routes --
  'app.get':                        { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },
  'app.post':                       { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },
  'app.put':                        { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },
  'app.delete':                     { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },
  'app.patch':                      { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },
  'app.grouped':                    { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },
};

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

  // Try full path for deep chains: "URLSession.shared.dataTask"
  if (calleeChain.length > 2) {
    const fullPath = calleeChain.join('.');
    const fullMember = MEMBER_CALLS[fullPath];
    if (fullMember) return { ...fullMember };

    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
  }

  return null;
}

// -- Sink patterns -----------------------------------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-79':  /evaluateJavaScript\s*\(\s*[^"\s]/,
  'CWE-89':  /"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\\\(\w+\)/,
  'CWE-295': /urlSession\s*\([^)]*didReceive.*challenge[^}]*completionHandler\s*\(\s*\.useCredential/,
  'CWE-312': /UserDefaults\.standard\.set\s*\([^)]*(password|token|secret|key)/,
  'CWE-319': /(?:NSAllowsArbitraryLoads.*true|NSURLRequest\(URL:\s*NSURL\(string:\s*"http:\/\/)/,
  'CWE-328': /\bCC_MD5\s*\(/,
  'CWE-476': /(?:\breadLine\s*\(\s*\)\s*!|var\s+\w+\s*:\s*\w+\s*!\s*$)/,
  'CWE-502': /NSUnarchiver\.unarchiveObject/,
  'CWE-522': /SecItemAdd\s*\([^)]*\)/,
  'CWE-798': /(?:apiKey|secret|password|token)\s*[:=]\s*"[^"]{4,}"/,
  'CWE-939': /UIApplication\.shared\.open\s*\(\s*URL\(string:\s*[^")]/,
};

// -- Safe patterns -----------------------------------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-79':  /WKContentRuleListStore/,
  'CWE-89':  /(?:NSPredicate\s*\(format:|%@)/,
  'CWE-295': /evaluateServerTrust|SecTrustEvaluate/,
  'CWE-312': /(?:SecItemAdd|Keychain)/,
  'CWE-319': /https:\/\//,
  'CWE-328': /(?:SHA256\.hash|SHA512\.hash|CryptoKit)/,
  'CWE-476': /(?:guard\s+let|if\s+let|\?\?)/,
  'CWE-502': /NSSecureCoding|NSSecureUnarchiveFromData/,
};

// -- Pattern count -----------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length;
}
