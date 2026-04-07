import { describe, it, expect } from 'vitest';
import { lookupCallee, getPatternCount } from './calleePatterns.js';

describe('calleePatterns — lookupCallee', () => {
  // ── Direct calls ──

  it('fetch → EXTERNAL/api_call', () => {
    const result = lookupCallee(['fetch']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('api_call');
  });

  it('require → STRUCTURAL/dependency', () => {
    const result = lookupCallee(['require']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STRUCTURAL');
    expect(result!.subtype).toBe('dependency');
  });

  it('setTimeout → CONTROL/event_handler', () => {
    const result = lookupCallee(['setTimeout']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('CONTROL');
    expect(result!.subtype).toBe('event_handler');
  });

  it('parseInt → TRANSFORM/format', () => {
    const result = lookupCallee(['parseInt']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('format');
  });

  it('exec → EXTERNAL/system_exec', () => {
    const result = lookupCallee(['exec']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('system_exec');
  });

  it('eval → EXTERNAL/system_exec', () => {
    const result = lookupCallee(['eval']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('system_exec');
  });

  it('atob → TRANSFORM/encode', () => {
    const result = lookupCallee(['atob']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('encode');
  });

  // ── Member calls: res.* ──

  it('res.json → EGRESS/http_response', () => {
    const result = lookupCallee(['res', 'json']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('res.send → EGRESS/http_response', () => {
    const result = lookupCallee(['res', 'send']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('res.redirect → EGRESS/redirect', () => {
    const result = lookupCallee(['res', 'redirect']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('redirect');
  });

  // ── Member calls: req.* ──

  it('req.body → INGRESS/http_request (tainted)', () => {
    const result = lookupCallee(['req', 'body']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.subtype).toBe('http_request');
    expect(result!.tainted).toBe(true);
  });

  it('req.params → INGRESS/http_request (tainted)', () => {
    const result = lookupCallee(['req', 'params']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  it('req.query → INGRESS/http_request (tainted)', () => {
    const result = lookupCallee(['req', 'query']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  // ── Member calls: console.* ──

  it('console.log → EGRESS/display', () => {
    const result = lookupCallee(['console', 'log']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('display');
  });

  it('console.error → EGRESS/display', () => {
    const result = lookupCallee(['console', 'error']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('display');
  });

  // ── Member calls: fs.* ──

  it('fs.readFile → INGRESS/file_read', () => {
    const result = lookupCallee(['fs', 'readFile']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.subtype).toBe('file_read');
  });

  it('fs.writeFile → EGRESS/file_write', () => {
    const result = lookupCallee(['fs', 'writeFile']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('file_write');
  });

  // ── Member calls: JSON.* ──

  it('JSON.parse → TRANSFORM/parse', () => {
    const result = lookupCallee(['JSON', 'parse']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('parse');
  });

  it('JSON.stringify → TRANSFORM/serialize', () => {
    const result = lookupCallee(['JSON', 'stringify']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('serialize');
  });

  // ── Member calls: auth ──

  it('bcrypt.compare → AUTH/authenticate', () => {
    const result = lookupCallee(['bcrypt', 'compare']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('AUTH');
    expect(result!.subtype).toBe('authenticate');
  });

  it('bcrypt.hash → AUTH/authenticate', () => {
    const result = lookupCallee(['bcrypt', 'hash']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('AUTH');
    expect(result!.subtype).toBe('authenticate');
  });

  it('jwt.sign → AUTH/authenticate', () => {
    const result = lookupCallee(['jwt', 'sign']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('AUTH');
    expect(result!.subtype).toBe('authenticate');
  });

  it('jwt.verify → AUTH/authenticate', () => {
    const result = lookupCallee(['jwt', 'verify']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('AUTH');
    expect(result!.subtype).toBe('authenticate');
  });

  // ── Member calls: http/external ──

  it('axios.get → EXTERNAL/api_call', () => {
    const result = lookupCallee(['axios', 'get']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('api_call');
  });

  it('http.request → EXTERNAL/api_call', () => {
    const result = lookupCallee(['http', 'request']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('api_call');
  });

  it('window.fetch → EXTERNAL/api_call', () => {
    const result = lookupCallee(['window', 'fetch']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('api_call');
  });

  // ── Member calls: process.* ──

  it('process.env → INGRESS/env_read', () => {
    const result = lookupCallee(['process', 'env']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.subtype).toBe('env_read');
  });

  // ── Member calls: crypto ──

  it('crypto.createHash → TRANSFORM/encrypt', () => {
    const result = lookupCallee(['crypto', 'createHash']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('encrypt');
  });

  // ── Member calls: child_process ──

  it('child_process.exec → EXTERNAL/system_exec', () => {
    const result = lookupCallee(['child_process', 'exec']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('system_exec');
  });

  // ── Wildcard: DB methods ──

  it('db.query → STORAGE/db_read', () => {
    const result = lookupCallee(['db', 'query']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_read');
  });

  it('db.find → STORAGE/db_read', () => {
    const result = lookupCallee(['db', 'find']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_read');
  });

  it('db.insert → STORAGE/db_write', () => {
    const result = lookupCallee(['db', 'insert']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_write');
  });

  it('User.findOne → STORAGE/db_read', () => {
    const result = lookupCallee(['User', 'findOne']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_read');
  });

  it('Post.create → STORAGE/db_write', () => {
    const result = lookupCallee(['Post', 'create']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_write');
  });

  it('collection.deleteOne → STORAGE/db_write', () => {
    const result = lookupCallee(['collection', 'deleteOne']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_write');
  });

  it('Model.aggregate → STORAGE/db_read', () => {
    const result = lookupCallee(['Model', 'aggregate']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_read');
  });

  // ── Deep chains: db.collection.find ──

  it('db.collection.find → STORAGE/db_read (deep chain)', () => {
    const result = lookupCallee(['db', 'collection', 'find']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_read');
  });

  it('db.collection.insertOne → STORAGE/db_write (deep chain)', () => {
    const result = lookupCallee(['db', 'collection', 'insertOne']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_write');
  });

  // ── Wildcard: Transform methods ──

  it('str.toLowerCase → TRANSFORM/format', () => {
    const result = lookupCallee(['str', 'toLowerCase']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('format');
  });

  it('arr.map → TRANSFORM/calculate', () => {
    const result = lookupCallee(['arr', 'map']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('calculate');
  });

  it('data.filter → TRANSFORM/calculate', () => {
    const result = lookupCallee(['data', 'filter']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('calculate');
  });

  it('name.split → TRANSFORM/format', () => {
    const result = lookupCallee(['name', 'split']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('format');
  });

  it('items.reduce → TRANSFORM/calculate', () => {
    const result = lookupCallee(['items', 'reduce']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('calculate');
  });

  // ── Disambiguation: array.find vs db.find ──

  it('items.find → TRANSFORM/calculate (array-like name)', () => {
    // "items" is in the ARRAY_NAMES set, so .find is treated as array
    const result = lookupCallee(['items', 'find']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('calculate');
  });

  it('User.find → STORAGE/db_read (model-like name)', () => {
    // "User" is NOT in the ARRAY_NAMES set, so .find is treated as DB
    const result = lookupCallee(['User', 'find']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STORAGE');
    expect(result!.subtype).toBe('db_read');
  });

  // ── Unknown callee → null ──

  it('unknownFunction → null', () => {
    const result = lookupCallee(['unknownFunction']);
    expect(result).toBeNull();
  });

  it('someObj.unknownMethod → null', () => {
    const result = lookupCallee(['someObj', 'unknownMethod']);
    expect(result).toBeNull();
  });

  it('empty chain → null', () => {
    const result = lookupCallee([]);
    expect(result).toBeNull();
  });

  // ── Returns copies, not references ──

  it('returns a copy (mutation-safe)', () => {
    const a = lookupCallee(['fetch']);
    const b = lookupCallee(['fetch']);
    expect(a).not.toBe(b); // different object references
    expect(a).toEqual(b);  // same values
  });

  // ── Pattern count ──

  it('has at least 80 patterns in the database', () => {
    expect(getPatternCount()).toBeGreaterThanOrEqual(80);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Fastify
  // ═══════════════════════════════════════════════════════════════════════════

  it('reply.send → EGRESS/http_response (Fastify)', () => {
    const result = lookupCallee(['reply', 'send']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('reply.code → EGRESS/http_response (Fastify)', () => {
    const result = lookupCallee(['reply', 'code']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('reply.redirect → EGRESS/redirect (Fastify)', () => {
    const result = lookupCallee(['reply', 'redirect']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('redirect');
  });

  it('reply.setCookie → EGRESS/http_response (Fastify)', () => {
    const result = lookupCallee(['reply', 'setCookie']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('fastify.register → STRUCTURAL/dependency (Fastify)', () => {
    const result = lookupCallee(['fastify', 'register']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STRUCTURAL');
    expect(result!.subtype).toBe('dependency');
  });

  it('fastify.inject → EXTERNAL/api_call (Fastify)', () => {
    const result = lookupCallee(['fastify', 'inject']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('api_call');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Koa
  // ═══════════════════════════════════════════════════════════════════════════

  it('ctx.request → INGRESS/http_request (Koa)', () => {
    const result = lookupCallee(['ctx', 'request']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  it('ctx.query → INGRESS/http_request (Koa)', () => {
    const result = lookupCallee(['ctx', 'query']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  it('ctx.params → INGRESS/http_request (Koa)', () => {
    const result = lookupCallee(['ctx', 'params']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  it('ctx.body → EGRESS/http_response (Koa)', () => {
    const result = lookupCallee(['ctx', 'body']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('ctx.redirect → EGRESS/redirect (Koa)', () => {
    const result = lookupCallee(['ctx', 'redirect']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('redirect');
  });

  it('ctx.throw → CONTROL/guard (Koa)', () => {
    const result = lookupCallee(['ctx', 'throw']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('CONTROL');
    expect(result!.subtype).toBe('guard');
  });

  it('ctx.cookies → INGRESS/http_request (Koa)', () => {
    const result = lookupCallee(['ctx', 'cookies']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  it('ctx.hostname → INGRESS/http_request (Koa)', () => {
    const result = lookupCallee(['ctx', 'hostname']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Hapi
  // ═══════════════════════════════════════════════════════════════════════════

  it('request.payload → INGRESS/http_request (Hapi)', () => {
    const result = lookupCallee(['request', 'payload']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  it('request.state → INGRESS/http_request (Hapi cookies)', () => {
    const result = lookupCallee(['request', 'state']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  it('request.info → INGRESS/http_request (Hapi)', () => {
    const result = lookupCallee(['request', 'info']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('INGRESS');
    expect(result!.tainted).toBe(true);
  });

  it('h.response → EGRESS/http_response (Hapi)', () => {
    const result = lookupCallee(['h', 'response']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('h.redirect → EGRESS/http_response (Hapi)', () => {
    const result = lookupCallee(['h', 'redirect']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('h.view → EGRESS/http_response (Hapi)', () => {
    const result = lookupCallee(['h', 'view']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('server.route → STRUCTURAL/route (Hapi)', () => {
    const result = lookupCallee(['server', 'route']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STRUCTURAL');
    expect(result!.subtype).toBe('route');
  });

  it('server.register → STRUCTURAL/dependency (Hapi)', () => {
    const result = lookupCallee(['server', 'register']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('STRUCTURAL');
    expect(result!.subtype).toBe('dependency');
  });

  it('request.auth → AUTH/authenticate (Hapi)', () => {
    const result = lookupCallee(['request', 'auth']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('AUTH');
    expect(result!.subtype).toBe('authenticate');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: Next.js
  // ═══════════════════════════════════════════════════════════════════════════

  it('NextResponse.json → EGRESS/http_response (Next.js)', () => {
    const result = lookupCallee(['NextResponse', 'json']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('NextResponse.redirect → EGRESS/http_response (Next.js)', () => {
    const result = lookupCallee(['NextResponse', 'redirect']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('NextResponse.next → CONTROL/guard (Next.js middleware)', () => {
    const result = lookupCallee(['NextResponse', 'next']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('CONTROL');
    expect(result!.subtype).toBe('guard');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // FRAMEWORK: NestJS
  // ═══════════════════════════════════════════════════════════════════════════

  it('response.status → EGRESS/http_response (NestJS)', () => {
    const result = lookupCallee(['response', 'status']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('http_response');
  });

  it('response.redirect → EGRESS/redirect (NestJS)', () => {
    const result = lookupCallee(['response', 'redirect']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EGRESS');
    expect(result!.subtype).toBe('redirect');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Disambiguation: framework objects should NOT match as DB
  // ═══════════════════════════════════════════════════════════════════════════

  it('fastify.get → not STORAGE (framework, not DB)', () => {
    const result = lookupCallee(['fastify', 'get']);
    // fastify is in NON_DB_OBJECTS, so .get should not match as STORAGE
    if (result) {
      expect(result.nodeType).not.toBe('STORAGE');
    }
  });

  it('reply.send → not STORAGE (framework, not DB)', () => {
    const result = lookupCallee(['reply', 'send']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).not.toBe('STORAGE');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Juice Shop FN fixes: XML, YAML, vm, deserialization, template engines
  // ═══════════════════════════════════════════════════════════════════════════

  // -- XML parsing sinks (XXE vectors) --

  it('libxmljs2.parseXml → TRANSFORM/xml_parse', () => {
    const result = lookupCallee(['libxmljs2', 'parseXml']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('xml_parse');
  });

  it('libxmljs2.parseXmlString → TRANSFORM/xml_parse', () => {
    const result = lookupCallee(['libxmljs2', 'parseXmlString']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('xml_parse');
  });

  it('DOMParser.parseFromString → TRANSFORM/xml_parse', () => {
    const result = lookupCallee(['DOMParser', 'parseFromString']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('xml_parse');
  });

  // -- YAML deserialization sinks --

  it('yaml.load → EXTERNAL/deserialize (UNSAFE)', () => {
    const result = lookupCallee(['yaml', 'load']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('deserialize');
  });

  it('yaml.loadAll → EXTERNAL/deserialize (UNSAFE)', () => {
    const result = lookupCallee(['yaml', 'loadAll']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('deserialize');
  });

  it('yaml.safeLoad → TRANSFORM/parse (SAFE)', () => {
    const result = lookupCallee(['yaml', 'safeLoad']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('parse');
  });

  it('yaml.safeLoadAll → TRANSFORM/parse (SAFE)', () => {
    const result = lookupCallee(['yaml', 'safeLoadAll']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('parse');
  });

  it('YAML.parse → TRANSFORM/parse (SAFE, js-yaml v4+)', () => {
    const result = lookupCallee(['YAML', 'parse']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('TRANSFORM');
    expect(result!.subtype).toBe('parse');
  });

  // -- vm module (code execution) --

  it('vm.runInContext → EXTERNAL/system_exec', () => {
    const result = lookupCallee(['vm', 'runInContext']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('system_exec');
  });

  it('vm.runInNewContext → EXTERNAL/system_exec', () => {
    const result = lookupCallee(['vm', 'runInNewContext']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('system_exec');
  });

  it('vm.compileFunction → EXTERNAL/system_exec', () => {
    const result = lookupCallee(['vm', 'compileFunction']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('system_exec');
  });

  it('vm.createContext → EXTERNAL/system_exec', () => {
    const result = lookupCallee(['vm', 'createContext']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('system_exec');
  });

  // -- Deserialization sinks --

  it('node-serialize.unserialize → EXTERNAL/deserialize', () => {
    const result = lookupCallee(['node-serialize', 'unserialize']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('deserialize');
  });

  // -- Template engine sinks (SSTI vectors) --

  it('ejs.render → EXTERNAL/template_exec', () => {
    const result = lookupCallee(['ejs', 'render']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('template_exec');
  });

  it('pug.render → EXTERNAL/template_exec', () => {
    const result = lookupCallee(['pug', 'render']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('template_exec');
  });

  it('handlebars.compile → EXTERNAL/template_exec', () => {
    const result = lookupCallee(['handlebars', 'compile']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('template_exec');
  });

  it('nunjucks.renderString → EXTERNAL/template_exec', () => {
    const result = lookupCallee(['nunjucks', 'renderString']);
    expect(result).not.toBeNull();
    expect(result!.nodeType).toBe('EXTERNAL');
    expect(result!.subtype).toBe('template_exec');
  });
});
