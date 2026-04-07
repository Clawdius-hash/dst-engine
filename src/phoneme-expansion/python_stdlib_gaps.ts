/**
 * Phoneme expansion: Python stdlib security gaps
 * Agent-generated for DST phoneme dictionary
 *
 * Coverage gap: stdlib modules with security-critical functions that had
 * ZERO entries in the Python callee dictionary. Audit flagged these as blind spots.
 *
 * xml.etree.ElementTree (CWE-611 XXE):
 *   ET.parse() and ET.fromstring() use expat by default which resolves external
 *   entities. defusedxml is the safe alternative. iterparse also vulnerable.
 *
 * http.client (CWE-918 SSRF):
 *   HTTPConnection/HTTPSConnection are the stdlib's raw HTTP clients. If the host
 *   or URL is user-controlled, SSRF is trivial. requests/urllib get audited but
 *   http.client flies under the radar.
 *
 * asyncio subprocess (CWE-78 command injection):
 *   asyncio.create_subprocess_exec and create_subprocess_shell are async equivalents
 *   of subprocess.Popen. The _shell variant is especially dangerous — same risk as
 *   subprocess.Popen(shell=True). Both were missing from the dictionary.
 *
 * ctypes (CWE-426 native code loading):
 *   ctypes.cdll.LoadLibrary and ctypes.CDLL load arbitrary shared libraries.
 *   If the library path is user-controlled, this is arbitrary native code execution.
 *   ctypes.windll.LoadLibrary is the Windows equivalent.
 *
 * Also adds: xml.sax (same XXE risk as ET), xml.dom.minidom.parse,
 *            defusedxml.parse (safe alternative — CONTROL/validation).
 */

import type { CalleePattern } from '../languages/python.js';

export const PHONEMES_PYTHON_STDLIB_GAPS: Record<string, CalleePattern> = {

  // ═══════════════════════════════════════════════════════════════════════════
  // xml.etree.ElementTree — XXE (CWE-611)
  // ═══════════════════════════════════════════════════════════════════════════
  // Python's default XML parser (expat) resolves external entities and DTDs.
  // ET.parse(source) reads from file, ET.fromstring(text) from string.
  // Both are exploitable if the XML comes from untrusted input:
  //   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  // The fix is defusedxml, which disables entity resolution.

  // EXTERNAL: ET.parse() parses XML from a file-like object or path.
  // If input XML is attacker-controlled, XXE allows file read, SSRF, DoS (billion laughs).
  'xml.etree.ElementTree.parse':        { nodeType: 'EXTERNAL', subtype: 'xml_parse', tainted: false },

  // EXTERNAL: ET.fromstring() parses XML from a string. Same XXE risk as parse().
  'xml.etree.ElementTree.fromstring':   { nodeType: 'EXTERNAL', subtype: 'xml_parse', tainted: false },

  // EXTERNAL: ET.iterparse() is a streaming XML parser — also vulnerable to XXE.
  // Often used for large XML files, which makes it more likely to see untrusted input.
  'xml.etree.ElementTree.iterparse':    { nodeType: 'EXTERNAL', subtype: 'xml_parse', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // http.client — SSRF (CWE-918)
  // ═══════════════════════════════════════════════════════════════════════════
  // http.client.HTTPConnection(host) creates a raw TCP connection to the given host.
  // If host is user-controlled, the server becomes an open proxy (SSRF).
  // This is lower-level than requests/urllib — developers use it for custom protocols
  // or when they want to avoid third-party deps, and often forget to validate the host.

  // EXTERNAL: HTTPConnection(host, port) — opens a raw HTTP connection.
  // SSRF vector if host comes from user input. Also: no TLS verification by default.
  'http.client.HTTPConnection':         { nodeType: 'EXTERNAL', subtype: 'api_call',  tainted: false },

  // EXTERNAL: HTTPSConnection(host, port) — HTTPS variant. Still SSRF-vulnerable.
  // Slightly less dangerous than HTTPConnection because TLS, but host is still controllable.
  'http.client.HTTPSConnection':        { nodeType: 'EXTERNAL', subtype: 'api_call',  tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // asyncio subprocess — command injection (CWE-78)
  // ═══════════════════════════════════════════════════════════════════════════
  // These are the async equivalents of subprocess.Popen. The scanner already
  // covers subprocess.* but had zero entries for the asyncio versions.
  // create_subprocess_shell is especially dangerous — it passes args through the shell.

  // EXTERNAL: asyncio.create_subprocess_exec(*args) — runs a command directly (no shell).
  // Safer than _shell but still command execution. If args are user-controlled, exploitable.
  'asyncio.create_subprocess_exec':     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // EXTERNAL: asyncio.create_subprocess_shell(cmd) — runs cmd through the system shell.
  // This is the async equivalent of subprocess.Popen(cmd, shell=True). Extremely dangerous.
  // If cmd contains any user input, it is trivially exploitable for command injection.
  'asyncio.create_subprocess_shell':    { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // ctypes — native code loading (CWE-426)
  // ═══════════════════════════════════════════════════════════════════════════
  // ctypes loads and calls native shared libraries (.so/.dll). If the library path
  // is user-controlled, this is arbitrary code execution at the native level.
  // Even if the path is hardcoded, ctypes bypasses Python's safety model entirely.

  // EXTERNAL: ctypes.cdll.LoadLibrary(name) — loads a shared library by name/path.
  // If name is user-controlled, attacker can load arbitrary .so/.dll files.
  'ctypes.cdll.LoadLibrary':            { nodeType: 'EXTERNAL', subtype: 'native_load', tainted: false },

  // EXTERNAL: ctypes.CDLL(name) — alternative constructor, same risk as LoadLibrary.
  // This is the class-based API; cdll.LoadLibrary is the convenience API.
  'ctypes.CDLL':                        { nodeType: 'EXTERNAL', subtype: 'native_load', tainted: false },

  // EXTERNAL: ctypes.windll.LoadLibrary(name) — Windows-specific DLL loading.
  // Same risk as cdll.LoadLibrary but for Windows DLLs (stdcall convention).
  'ctypes.windll.LoadLibrary':          { nodeType: 'EXTERNAL', subtype: 'native_load', tainted: false },

} as const;

// ── Pattern count ─────────────────────────────────────────────────────────

export function getPhonemeCount(): number {
  return Object.keys(PHONEMES_PYTHON_STDLIB_GAPS).length;
}
