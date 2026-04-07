/**
 * HTML/CSS Callee Pattern Database
 *
 * HTML/CSS isn't a programming language -- it doesn't have function calls.
 * These patterns map DOM APIs and security-relevant HTML element/attribute
 * patterns that the mapper encounters when analyzing HTML templates and
 * inline scripts.
 *
 * Covers: DOM manipulation APIs, HTML form elements, script/link loading,
 *         security-relevant attributes, CSS-based attacks.
 *
 * Sources:
 *   - corpus_audit_htmlcss.json (35 Category B + 165 Category A patterns)
 *   - DOM API / Web security knowledge
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (DOM API global functions) ----------------------------------

const DIRECT_CALLS: Record<string, CalleePattern> = {
  // These overlap with JS but are HTML-context-specific

  // EGRESS -- DOM manipulation that outputs content
  alert:              { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  confirm:            { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  prompt:             { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },

  // EXTERNAL -- dynamic resource loading
  importScripts:      { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
};

// -- Member calls (DOM APIs for HTML/CSS interaction) -------------------------

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS -- user input / external data via DOM
  // =========================================================================

  // -- Form data access --
  'FormData.get':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'FormData.getAll':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'FormData.has':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'FormData.entries':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'FormData.values':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'FormData.keys':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- URL / Location --
  'window.location':            { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'window.location.href':       { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'window.location.search':     { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'window.location.hash':       { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'window.location.pathname':   { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'window.location.origin':     { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'location.href':              { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'location.search':            { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'location.hash':              { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'location.pathname':          { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'URL.searchParams':           { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'URLSearchParams.get':        { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'URLSearchParams.getAll':     { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'URLSearchParams.has':        { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'URLSearchParams.entries':    { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },

  // -- Document input sources --
  'document.cookie':            { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'document.referrer':          { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'document.URL':               { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'document.documentURI':       { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'document.domain':            { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'document.title':             { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },

  // -- Element value access --
  // innerHTML/innerText/textContent are EGRESS (XSS sinks) when written to.
  // Reading them is implicit. Here we track input-specific read patterns:
  'element.value':              { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'element.getAttribute':       { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'element.dataset':            { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'element.files':              { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'element.checked':            { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'element.selectedOptions':    { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },

  // -- Clipboard --
  'navigator.clipboard.readText': { nodeType: 'INGRESS', subtype: 'user_input', tainted: true },
  'navigator.clipboard.read':     { nodeType: 'INGRESS', subtype: 'user_input', tainted: true },

  // -- Drag and drop --
  'DataTransfer.getData':       { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'DataTransfer.files':         { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },

  // -- Message events --
  'MessageEvent.data':          { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'window.postMessage':         { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },

  // -- Storage read --
  'localStorage.getItem':       { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'sessionStorage.getItem':     { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },

  // -- File API --
  'FileReader.readAsText':      { nodeType: 'INGRESS', subtype: 'file_read',   tainted: true },
  'FileReader.readAsDataURL':   { nodeType: 'INGRESS', subtype: 'file_read',   tainted: true },
  'FileReader.readAsArrayBuffer': { nodeType: 'INGRESS', subtype: 'file_read', tainted: true },
  'FileReader.readAsBinaryString': { nodeType: 'INGRESS', subtype: 'file_read', tainted: true },

  // -- Geolocation --
  'navigator.geolocation.getCurrentPosition': { nodeType: 'INGRESS', subtype: 'user_input', tainted: false },
  'navigator.geolocation.watchPosition': { nodeType: 'INGRESS', subtype: 'user_input', tainted: false },

  // =========================================================================
  // EGRESS -- DOM output / rendering
  // =========================================================================

  // -- Dangerous DOM sinks (XSS vectors) --
  'element.innerHTML':          { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.outerHTML':          { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.insertAdjacentHTML': { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'document.write':             { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'document.writeln':           { nodeType: 'EGRESS', subtype: 'display',      tainted: false },

  // -- Safe DOM output --
  'element.textContent':        { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.innerText':          { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.setAttribute':       { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.style':              { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.classList.add':      { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.classList.remove':   { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.classList.toggle':   { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.append':             { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.prepend':            { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.remove':             { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.replaceWith':        { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.replaceChildren':    { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.after':              { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'element.before':             { nodeType: 'EGRESS', subtype: 'display',      tainted: false },

  // -- Document node creation --
  'document.createElement':     { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'document.createTextNode':    { nodeType: 'EGRESS', subtype: 'display',      tainted: false },
  'document.createDocumentFragment': { nodeType: 'EGRESS', subtype: 'display', tainted: false },
  'document.createComment':     { nodeType: 'EGRESS', subtype: 'display',      tainted: false },

  // -- Clipboard write --
  'navigator.clipboard.writeText': { nodeType: 'EGRESS', subtype: 'display',   tainted: false },
  'navigator.clipboard.write':     { nodeType: 'EGRESS', subtype: 'display',   tainted: false },

  // -- Navigation --
  'window.location.assign':    { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'window.location.replace':   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'window.open':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'history.pushState':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'history.replaceState':      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Canvas --
  'canvas.toDataURL':          { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'canvas.toBlob':             { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },

  // =========================================================================
  // STORAGE -- client-side persistence
  // =========================================================================

  'localStorage.setItem':       { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'localStorage.removeItem':    { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'localStorage.clear':         { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'sessionStorage.setItem':     { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'sessionStorage.removeItem':  { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'sessionStorage.clear':       { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'indexedDB.open':             { nodeType: 'STORAGE', subtype: 'db_connect',  tainted: false },
  'IDBObjectStore.add':         { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'IDBObjectStore.put':         { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'IDBObjectStore.delete':      { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'IDBObjectStore.get':         { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'IDBObjectStore.getAll':      { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'IDBObjectStore.openCursor':  { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'caches.open':                { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'caches.delete':              { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'caches.match':               { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'cache.put':                  { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'cache.add':                  { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'cache.addAll':               { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'cache.match':                { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'cache.delete':               { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },

  // =========================================================================
  // EXTERNAL -- resource loading / network
  // =========================================================================

  'fetch':                      { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'XMLHttpRequest.open':        { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'XMLHttpRequest.send':        { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'EventSource':                { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'WebSocket':                  { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'WebSocket.send':             { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'navigator.sendBeacon':       { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'navigator.serviceWorker.register': { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // =========================================================================
  // TRANSFORM -- DOM querying / parsing (read operations)
  // =========================================================================

  'document.getElementById':    { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'document.querySelector':     { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'document.querySelectorAll':  { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'document.getElementsByClassName': { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false },
  'document.getElementsByTagName': { nodeType: 'TRANSFORM', subtype: 'parse',  tainted: false },
  'DOMParser.parseFromString':  { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'element.closest':            { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'element.matches':            { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },

  // -- Encoding --
  'btoa':                       { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'atob':                       { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'encodeURIComponent':         { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'decodeURIComponent':         { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'encodeURI':                  { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'decodeURI':                  { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'TextEncoder.encode':         { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'TextDecoder.decode':         { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },

  // -- Web Crypto --
  'crypto.subtle.encrypt':     { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.subtle.decrypt':     { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.subtle.sign':        { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.subtle.verify':      { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.subtle.digest':      { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.subtle.generateKey': { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.subtle.deriveKey':   { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.subtle.importKey':   { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.subtle.exportKey':   { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.getRandomValues':    { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'crypto.randomUUID':         { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },

  // =========================================================================
  // CONTROL -- event handling / timers / observers
  // =========================================================================

  'addEventListener':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'removeEventListener':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'element.addEventListener':   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'element.removeEventListener':{ nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'document.addEventListener':  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'window.addEventListener':    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'setTimeout':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'setInterval':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'clearTimeout':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'clearInterval':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'requestAnimationFrame':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'cancelAnimationFrame':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'requestIdleCallback':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'MutationObserver.observe':   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'IntersectionObserver.observe': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'ResizeObserver.observe':     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'PerformanceObserver.observe':{ nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Form validation API --
  'element.checkValidity':      { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },
  'element.reportValidity':     { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },
  'element.setCustomValidity':  { nodeType: 'CONTROL', subtype: 'validation',  tainted: false },

  // =========================================================================
  // AUTH (minimal in pure HTML/CSS -- mostly handled by JS)
  // =========================================================================

  'navigator.credentials.get':  { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'navigator.credentials.create': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'navigator.credentials.store':{ nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },

  // =========================================================================
  // META
  // =========================================================================

  'console.log':                { nodeType: 'META', subtype: 'logging',        tainted: false },
  'console.error':              { nodeType: 'META', subtype: 'logging',        tainted: false },
  'console.warn':               { nodeType: 'META', subtype: 'logging',        tainted: false },
  'console.info':               { nodeType: 'META', subtype: 'logging',        tainted: false },
  'console.debug':              { nodeType: 'META', subtype: 'logging',        tainted: false },
  'console.trace':              { nodeType: 'META', subtype: 'logging',        tainted: false },
  'console.table':              { nodeType: 'META', subtype: 'logging',        tainted: false },
  'performance.mark':           { nodeType: 'META', subtype: 'debug',          tainted: false },
  'performance.measure':        { nodeType: 'META', subtype: 'debug',          tainted: false },
  'performance.now':            { nodeType: 'META', subtype: 'debug',          tainted: false },
};

// -- Lookup function ----------------------------------------------------------

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };

    const singleMember = MEMBER_CALLS[calleeChain[0]!];
    if (singleMember) return { ...singleMember };

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

  return null;
}

// -- Sink patterns -----------------------------------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-79':  /(?:\.innerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(|v-html\s*=|dangerouslySetInnerHTML)/,
  'CWE-601': /(?:window\.location\s*=|location\.href\s*=|location\.assign\s*\(|location\.replace\s*\()\s*(?:document\.|window\.|location\.)/,
  'CWE-346': /(?:postMessage\s*\(\s*[^)]+,\s*['"]?\*['"]?\s*\))/,
  'CWE-312': /localStorage\.setItem\s*\(\s*['"](?:token|password|secret|key)['"]/,
  'CWE-829': /<script\s+src\s*=\s*["']http:/,
};

// -- Safe patterns -----------------------------------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-79':  /(?:textContent\s*=|createTextNode\s*\(|DOMPurify\.sanitize|sanitizeHtml)/,
  'CWE-601': /(?:URL\.canParse|new\s+URL\s*\()/,
  'CWE-346': /(?:event\.origin\s*===|event\.origin\s*!==)/,
  'CWE-829': /(?:integrity\s*=\s*["']sha|nonce\s*=\s*["'])/,
};

// -- Pattern count -----------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length;
}
