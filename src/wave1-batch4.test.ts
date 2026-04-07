/**
 * Wave 1 Batch 4 — Juliet Java CWE Detection Tests
 *
 * Tests 10 information exposure and resource management CWEs against
 * NIST Juliet Java benchmark test cases:
 *   CWE-209  Error Message Info Exposure (printStackTrace)
 *   CWE-252  Unchecked Return Value (read() without check)
 *   CWE-404  Improper Resource Shutdown (close in try, not finally)
 *   CWE-526  Env Var Exposure (System.getenv to response)
 *   CWE-533  Sensitive Info in Server Log (session.getId in log)
 *   CWE-534  Debug Log Info Exposure (session.getId in Level.FINEST)
 *   CWE-535  Shell Error Info Exposure (session.getId to System.err)
 *   CWE-598  GET Request for Sensitive Query (form method=get + password)
 *   CWE-772  Missing Release of Resource (DB objects never closed)
 *   CWE-775  Missing Release of File Descriptor (FileReader never closed)
 *
 * Each test verifies that DST detects the vulnerability in the Juliet bad() case.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { verify } from './verifier';
import { createNode, createNeuralMap, resetSequence } from './types';
import type { NeuralMap } from './types';

// ---------------------------------------------------------------------------
// Helper: build a Java neural map with a function node
// ---------------------------------------------------------------------------

function buildJavaMap(funcName: string, code: string, extraNodes?: Parameters<typeof createNode>[0][]): NeuralMap {
  resetSequence();
  const map = createNeuralMap(`${funcName}.java`, code);
  const funcNode = createNode({
    label: funcName,
    node_type: 'STRUCTURAL',
    node_subtype: 'function',
    language: 'java',
    code_snapshot: code.slice(0, 500),
    analysis_snapshot: code,
  });
  map.nodes = [funcNode, ...(extraNodes || []).map(n => createNode({ language: 'java', ...n }))];
  return map;
}

// ===========================================================================
// CWE-209: Error Message Info Exposure
// ===========================================================================

describe('CWE-209: Error Message Info Exposure (Juliet)', () => {
  it('VULNERABLE: catch block with printStackTrace()', () => {
    const code = `public void bad() throws Throwable {
      try { throw new UnsupportedOperationException(); }
      catch (UnsupportedOperationException e) {
        e.printStackTrace();
      }
    }`;
    const map = buildJavaMap('bad', code);
    // Add a CONTROL/error_handling node (what the Java parser creates for catch blocks)
    map.nodes.push(createNode({
      label: 'catch',
      node_type: 'CONTROL',
      node_subtype: 'error_handling',
      language: 'java',
      code_snapshot: 'catch (UnsupportedOperationException e) { e.printStackTrace(); }',
      analysis_snapshot: 'catch (UnsupportedOperationException e) { e.printStackTrace(); }',
    }));
    const result = verify(map, 'CWE-209');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: catch block with generic error message', () => {
    const code = `public void good1() throws Throwable {
      try { throw new UnsupportedOperationException(); }
      catch (UnsupportedOperationException e) {
        IO.writeLine("There was an unsupported operation error");
      }
    }`;
    const map = buildJavaMap('good1', code);
    map.nodes.push(createNode({
      label: 'catch',
      node_type: 'CONTROL',
      node_subtype: 'error_handling',
      language: 'java',
      code_snapshot: 'catch (UnsupportedOperationException e) { IO.writeLine("There was an error"); }',
      analysis_snapshot: 'catch (UnsupportedOperationException e) { IO.writeLine("There was an error"); }',
    }));
    const result = verify(map, 'CWE-209');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-526: Env Var Exposure
// ===========================================================================

describe('CWE-526: Env Var Exposure (Juliet)', () => {
  it('VULNERABLE: System.getenv() in response', () => {
    const code = `public void bad(HttpServletRequest request, HttpServletResponse response) {
      response.getWriter().println("Not in path: " + System.getenv("PATH"));
    }`;
    const map = buildJavaMap('bad', code);
    map.nodes.push(createNode({
      label: 'System.getenv("PATH")',
      node_type: 'INGRESS',
      node_subtype: 'env_read',
      language: 'java',
      code_snapshot: 'System.getenv("PATH")',
      data_out: [{ name: 'result', source: '', data_type: 'unknown', tainted: true, sensitivity: 'NONE' }],
    }));
    map.nodes.push(createNode({
      label: 'response.getWriter()',
      node_type: 'EGRESS',
      node_subtype: 'http_response',
      language: 'java',
      code_snapshot: 'response.getWriter()',
    }));
    const result = verify(map, 'CWE-526');
    expect(result.holds).toBe(false);
  });
});

// ===========================================================================
// CWE-533: Sensitive Info in Server Log
// ===========================================================================

describe('CWE-533: Sensitive Info in Server Log (Juliet)', () => {
  it('VULNERABLE: session.getId() in log()', () => {
    const code = `public void bad(HttpServletRequest request, HttpServletResponse response) {
      String username = request.getParameter("username");
      HttpSession session = request.getSession(true);
      log("Username: " + username + " Session ID:" + session.getId());
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-533');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: log without session.getId()', () => {
    const code = `public void good1(HttpServletRequest request, HttpServletResponse response) {
      String username = request.getParameter("username");
      log("Username: " + username + " logged in");
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-533');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-534: Debug Log Info Exposure
// ===========================================================================

describe('CWE-534: Debug Log Info Exposure (Juliet)', () => {
  it('VULNERABLE: session.getId() in Level.FINEST log', () => {
    const code = `public void bad(HttpServletRequest request, HttpServletResponse response) {
      Logger logger = Logger.getLogger("test");
      HttpSession session = request.getSession(true);
      logger.log(Level.FINEST, "Username: " + username + " Session ID:" + session.getId());
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-534');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: Level.FINEST log without session data', () => {
    const code = `public void good1(HttpServletRequest request, HttpServletResponse response) {
      Logger logger = Logger.getLogger("test");
      logger.log(Level.FINEST, "Username: " + username);
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-534');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-535: Shell Error Info Exposure
// ===========================================================================

describe('CWE-535: Shell Error Info Exposure (Juliet)', () => {
  it('VULNERABLE: session.getId() to System.err', () => {
    const code = `public void bad(HttpServletRequest request, HttpServletResponse response) {
      HttpSession session = request.getSession(true);
      OutputStreamWriter writerOutputStream = new OutputStreamWriter(System.err, "UTF-8");
      PrintWriter writerPrint = new PrintWriter(writerOutputStream);
      writerPrint.println("Username: " + username + " Session ID:" + session.getId());
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-535');
    expect(result.holds).toBe(false);
  });

  it('SAFE: System.err without session data', () => {
    const code = `public void good1(HttpServletRequest request, HttpServletResponse response) {
      OutputStreamWriter writerOutputStream = new OutputStreamWriter(System.err, "UTF-8");
      PrintWriter writerPrint = new PrintWriter(writerOutputStream);
      writerPrint.println("Username: " + username + " logged in");
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-535');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-598: GET Request for Sensitive Query
// ===========================================================================

describe('CWE-598: GET Request for Sensitive Query (Juliet)', () => {
  it('VULNERABLE: form method=get with password field', () => {
    const code = `public void bad(HttpServletRequest request, HttpServletResponse response) {
      response.getWriter().println("<form method=\\"get\\" action=\\"test\\">");
      response.getWriter().println("Password: <input type=\\"password\\" />");
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-598');
    expect(result.holds).toBe(false);
  });

  it('SAFE: form method=post with password field', () => {
    const code = `public void good1(HttpServletRequest request, HttpServletResponse response) {
      response.getWriter().println("<form method=\\"post\\" action=\\"test\\">");
      response.getWriter().println("Password: <input type=\\"password\\" />");
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-598');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-404: Improper Resource Shutdown
// ===========================================================================

describe('CWE-404: Improper Resource Shutdown (Juliet)', () => {
  it('VULNERABLE: close in try block, not finally', () => {
    const code = `public void bad() {
      BufferedReader readerBuffered = null;
      FileReader readerFile = null;
      try {
        readerFile = new FileReader(file);
        readerBuffered = new BufferedReader(readerFile);
        String readString = readerBuffered.readLine();
        try { if (readerBuffered != null) { readerBuffered.close(); } }
        catch (IOException e) {}
      }
      catch (IOException e) {}
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-404');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: close in finally block', () => {
    const code = `public void good1() {
      BufferedReader readerBuffered = null;
      FileReader readerFile = null;
      try {
        readerFile = new FileReader(file);
        readerBuffered = new BufferedReader(readerFile);
      }
      catch (IOException e) {}
      finally {
        try { if (readerBuffered != null) { readerBuffered.close(); } }
        catch (IOException e) {}
      }
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-404');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-772: Missing Release of Resource
// ===========================================================================

describe('CWE-772: Missing Release of Resource (Juliet)', () => {
  it('VULNERABLE: DB connection never closed', () => {
    const code = `public void bad() {
      Connection dBConnection = null;
      PreparedStatement preparedStatement = null;
      try {
        dBConnection = IO.getDBConnection();
        preparedStatement = dBConnection.prepareStatement("select * from users where id=?");
        ResultSet resultSet = preparedStatement.executeQuery();
      }
      catch (SQLException e) {}
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-772');
    expect(result.holds).toBe(false);
  });
});

// ===========================================================================
// CWE-775: Missing Release of File Descriptor
// ===========================================================================

describe('CWE-775: Missing Release of File Descriptor (Juliet)', () => {
  it('VULNERABLE: FileReader never closed', () => {
    const code = `public void bad() {
      BufferedReader readerBuffered = null;
      FileReader readerFile = null;
      try {
        readerFile = new FileReader(file);
        readerBuffered = new BufferedReader(readerFile);
        String readString = readerBuffered.readLine();
        IO.writeLine(readString);
      }
      catch (IOException e) {}
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-775');
    expect(result.holds).toBe(false);
  });
});

// ===========================================================================
// CWE-252: Unchecked Return Value
// ===========================================================================

describe('CWE-252: Unchecked Return Value (Juliet)', () => {
  it('VULNERABLE: read() return value not checked', () => {
    const code = `public void bad() throws Throwable {
      FileInputStream streamFileInput = null;
      try {
        byte[] byteArray = new byte[1024];
        streamFileInput = new FileInputStream("c:\\\\file.txt");
        streamFileInput.read(byteArray);
        IO.writeLine(new String(byteArray, "UTF-8"));
      }
      catch (IOException e) {}
      finally { if (streamFileInput != null) streamFileInput.close(); }
    }`;
    const map = buildJavaMap('bad', code);
    const result = verify(map, 'CWE-252');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: read() return value checked', () => {
    const code = `public void good1() throws Throwable {
      FileInputStream streamFileInput = null;
      try {
        byte[] byteArray = new byte[1024];
        streamFileInput = new FileInputStream("c:\\\\file.txt");
        int numberOfBytesRead = streamFileInput.read(byteArray);
        if (numberOfBytesRead == -1) { IO.writeLine("EOF"); }
      }
      catch (IOException e) {}
      finally { if (streamFileInput != null) streamFileInput.close(); }
    }`;
    const map = buildJavaMap('good1', code);
    const result = verify(map, 'CWE-252');
    expect(result.holds).toBe(true);
  });
});
