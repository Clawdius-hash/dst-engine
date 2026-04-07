/**
 * Wave 1 — Batch 1: Injection CWE Juliet Detection Tests
 *
 * Tests DST's detection of the 10 highest-impact injection CWEs on NIST Juliet
 * Java benchmark test cases. These CWEs represent the core of what security
 * scanners are measured on.
 *
 * Each test:
 *  1. Parses a Juliet _01 baseline test file (known vulnerable)
 *  2. Builds a Neural Map
 *  3. Runs the target CWE verifier
 *  4. Asserts FAIL (vulnerability detected)
 */

import { describe, it, expect } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import { buildNeuralMap } from './mapper';
import { verifyAll, registeredCWEs } from './verifier';
import { resetSequence } from './types';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JULIET_BASE = 'C:/Users/pizza/vigil/juliet-java/src/testcases';

let parser: InstanceType<typeof Parser>;
let javaLang: InstanceType<typeof Language>;
let javaProfile: any;

async function init() {
  if (parser) return;
  await Parser.init();
  parser = new Parser();
  const wasmPath = path.resolve(__dirname, '../node_modules/tree-sitter-java/tree-sitter-java.wasm');
  const wasmBuffer = fs.readFileSync(wasmPath);
  javaLang = await Language.load(wasmBuffer);
  parser.setLanguage(javaLang);
  const mod = await import('./profiles/java');
  javaProfile = mod.javaProfile;
}

function scanFile(filePath: string): { cwe: string; holds: boolean }[] {
  const code = fs.readFileSync(filePath, 'utf-8');
  resetSequence();
  const tree = parser.parse(code);
  const { map } = buildNeuralMap(tree, code, filePath, javaProfile);
  return verifyAll(map, undefined, { noDedup: true });
}

function findResult(results: { cwe: string; holds: boolean }[], cweId: string): boolean | undefined {
  const r = results.find(r => r.cwe === cweId);
  return r ? r.holds : undefined;
}

describe('Wave 1 Batch 1 — Injection CWEs on Juliet Java', () => {

  it('CWE-89: SQL Injection — Environment + executeBatch', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE89_SQL_Injection/s01/CWE89_SQL_Injection__Environment_executeBatch_01.java`
    );
    // holds=false means vulnerability DETECTED (property violated)
    expect(findResult(results, 'CWE-89')).toBe(false);
  });

  it('CWE-78: OS Command Injection — Environment + exec', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE78_OS_Command_Injection/CWE78_OS_Command_Injection__Environment_01.java`
    );
    expect(findResult(results, 'CWE-78')).toBe(false);
  });

  it('CWE-80: Basic XSS — getParameter + println', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE80_XSS/s01/CWE80_XSS__CWE182_Servlet_getParameter_Servlet_01.java`
    );
    expect(findResult(results, 'CWE-80')).toBe(false);
  });

  it('CWE-81: XSS Error Message — File + sendError', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE81_XSS_Error_Message/CWE81_XSS_Error_Message__Servlet_File_01.java`
    );
    expect(findResult(results, 'CWE-81')).toBe(false);
  });

  it('CWE-83: XSS in Attributes — File + println img', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE83_XSS_Attribute/CWE83_XSS_Attribute__Servlet_File_01.java`
    );
    expect(findResult(results, 'CWE-83')).toBe(false);
  });

  it('CWE-90: LDAP Injection — Environment', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE90_LDAP_Injection/CWE90_LDAP_Injection__Environment_01.java`
    );
    expect(findResult(results, 'CWE-90')).toBe(false);
  });

  it('CWE-113: HTTP Response Splitting — Environment + addCookie', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE113_HTTP_Response_Splitting/s01/CWE113_HTTP_Response_Splitting__Environment_addCookieServlet_01.java`
    );
    expect(findResult(results, 'CWE-113')).toBe(false);
  });

  it('CWE-134: Uncontrolled Format String — Environment + format', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__Environment_format_01.java`
    );
    expect(findResult(results, 'CWE-134')).toBe(false);
  });

  it('CWE-601: Open Redirect — Servlet + File', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE601_Open_Redirect/CWE601_Open_Redirect__Servlet_File_01.java`
    );
    expect(findResult(results, 'CWE-601')).toBe(false);
  });

  it('CWE-643: XPath Injection — Environment', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE643_Xpath_Injection/CWE643_Xpath_Injection__Environment_01.java`
    );
    expect(findResult(results, 'CWE-643')).toBe(false);
  });

  // Additional variant: CWE-80 from file source (not HTTP request)
  it('CWE-80: Basic XSS — File source variant', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE80_XSS/s01/CWE80_XSS__CWE182_Servlet_File_01.java`
    );
    expect(findResult(results, 'CWE-80')).toBe(false);
  });

  // Additional variant: CWE-113 with addHeader (not cookie)
  it('CWE-113: HTTP Response Splitting — addHeader variant', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE113_HTTP_Response_Splitting/s01/CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_01.java`
    );
    expect(findResult(results, 'CWE-113')).toBe(false);
  });

  // Additional variant: CWE-89 with connect_tcp source
  it('CWE-89: SQL Injection — connect_tcp source variant', async () => {
    await init();
    const results = scanFile(
      `${JULIET_BASE}/CWE89_SQL_Injection/s01/CWE89_SQL_Injection__connect_tcp_execute_01.java`
    );
    expect(findResult(results, 'CWE-89')).toBe(false);
  });
});
