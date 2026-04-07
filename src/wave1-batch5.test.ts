/**
 * Wave 1 — Batch 5: Concurrency & Edge-Case CWE Tests
 *
 * Tests for 10 CWEs improved for the NIST Juliet Java benchmark:
 *   CWE-382  J2EE Use of System.exit()
 *   CWE-383  J2EE Direct Use of Threads
 *   CWE-459  Incomplete Cleanup
 *   CWE-579  J2EE Non-Serializable Stored in Session
 *   CWE-613  Insufficient Session Expiration
 *   CWE-615  Inclusion of Sensitive Info in Source Comments
 *   CWE-667  Improper Locking
 *   CWE-764  Multiple Locks of Same Critical Resource
 *   CWE-765  Multiple Unlocks of Same Critical Resource
 *   CWE-832  Unlock of Resource That is Not Locked
 *
 * Each CWE gets:
 *   - VULNERABLE: realistic code from Juliet patterns that SHOULD trigger (holds=false)
 *   - SAFE: mitigated code that should NOT trigger (holds=true)
 */

import { describe, it, expect } from 'vitest';
import { createNode, createNeuralMap, resetSequence } from './types.js';
import type { NeuralMap } from './types.js';
import { verify } from './verifier';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function buildMap(nodes: Parameters<typeof createNode>[0][], sourceFile = 'Test.java'): NeuralMap {
  resetSequence();
  const map = createNeuralMap(sourceFile, '// test');
  map.nodes = nodes.map(n => createNode(n));
  return map;
}

// ===========================================================================
// CWE-382: J2EE Bad Practices: Use of System.exit()
// ===========================================================================

describe('CWE-382: J2EE Use of System.exit()', () => {
  it('VULNERABLE: Runtime.getRuntime().exit() in servlet', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'MyServlet', node_subtype: 'class',
        code_snapshot: 'public class MyServlet extends HttpServlet {\n  public void bad() {\n    Runtime.getRuntime().exit(1);\n  }\n}',
        edges: [{ target: 'FUNC', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad() {\n  Runtime.getRuntime().exit(1);\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-382');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: System.exit() in servlet', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'MyServlet', node_subtype: 'class',
        code_snapshot: 'public class MyServlet extends HttpServlet {\n  public void doGet() {\n    System.exit(0);\n  }\n}',
        edges: [{ target: 'FUNC', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'doGet', node_subtype: 'function',
        code_snapshot: 'public void doGet() {\n  System.exit(0);\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-382');
    expect(result.holds).toBe(false);
  });

  it('SAFE: no System.exit() in servlet', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'MyServlet', node_subtype: 'class',
        code_snapshot: 'public class MyServlet extends HttpServlet {\n  public void good() {\n    response.getWriter().write("error");\n  }\n}',
        edges: [{ target: 'FUNC', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'good', node_subtype: 'function',
        code_snapshot: 'public void good() {\n  response.getWriter().write("error");\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-382');
    expect(result.holds).toBe(true);
  });

  it('SAFE: System.exit() in non-servlet context', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'CliTool', node_subtype: 'class',
        code_snapshot: 'public class CliTool {\n  public static void main(String[] args) {\n    System.exit(0);\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-382');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-383: J2EE Bad Practices: Direct Use of Threads
// ===========================================================================

describe('CWE-383: J2EE Direct Use of Threads', () => {
  it('VULNERABLE: new Thread() in servlet', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'MyServlet', node_subtype: 'class',
        code_snapshot: 'public class MyServlet extends HttpServlet { }',
        edges: [{ target: 'FUNC', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad() {\n  Thread t = new Thread(runnable);\n  t.start();\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-383');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: Thread.sleep() in servlet', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'MyServlet', node_subtype: 'class',
        code_snapshot: 'public class MyServlet extends HttpServlet { }',
        edges: [{ target: 'FUNC', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad() {\n  Thread.sleep(10000);\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-383');
    expect(result.holds).toBe(false);
  });

  it('SAFE: ExecutorService in servlet', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'MyServlet', node_subtype: 'class',
        code_snapshot: 'public class MyServlet extends HttpServlet { }',
        edges: [{ target: 'FUNC', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'good', node_subtype: 'function',
        code_snapshot: 'public void good() {\n  ExecutorService exec = Executors.newFixedThreadPool(4);\n  exec.submit(task);\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-383');
    expect(result.holds).toBe(true);
  });

  it('SAFE: no threads in non-servlet context', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'Worker', node_subtype: 'class',
        code_snapshot: 'public class Worker {\n  public void run() {\n    new Thread(task).start();\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-383');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-459: Incomplete Cleanup
// ===========================================================================

describe('CWE-459: Incomplete Cleanup', () => {
  it('VULNERABLE: deleteOnExit() without proper cleanup', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad() {\n  File tempFile = File.createTempFile("temp", "1234");\n  tempFile.deleteOnExit();\n}',
        edges: [{ target: 'XFORM', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'XFORM', node_type: 'TRANSFORM', label: 'tempFile =', node_subtype: 'assignment',
        code_snapshot: 'tempFile = File.createTempFile("temp", "1234")\n  tempFile.deleteOnExit();',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-459');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: explicit delete() in finally block', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'good', node_subtype: 'function',
        code_snapshot: 'public void good() {\n  File tempFile = File.createTempFile("temp", "1234");\n  try {\n    // use it\n  } finally {\n    tempFile.delete();\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-459');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-579: J2EE Non-Serializable Stored in Session
// ===========================================================================

describe('CWE-579: J2EE Non-Serializable in Session', () => {
  it('VULNERABLE: non-Serializable class stored in session', () => {
    const map = buildMap([
      {
        id: 'BAD_CLS', node_type: 'STRUCTURAL', label: 'BadObject', node_subtype: 'class',
        code_snapshot: 'static class BadObject {\n  public String data = "test";\n}',
        edges: [],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad(HttpServletRequest request) {\n  BadObject obj = new BadObject();\n  request.getSession(true).setAttribute("key", obj);\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-579');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: Thread stored in session', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad() {\n  Thread t = new Thread();\n  session.setAttribute("worker", t);\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-579');
    expect(result.holds).toBe(false);
  });

  it('SAFE: Serializable class stored in session', () => {
    const map = buildMap([
      {
        id: 'GOOD_CLS', node_type: 'STRUCTURAL', label: 'GoodObject', node_subtype: 'class',
        code_snapshot: 'static class GoodObject implements Serializable {\n  private static final long serialVersionUID = 1L;\n  public String data = "test";\n}',
        edges: [],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'good', node_subtype: 'function',
        code_snapshot: 'public void good(HttpServletRequest request) {\n  GoodObject obj = new GoodObject();\n  request.getSession(true).setAttribute("key", obj);\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-579');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-613: Insufficient Session Expiration
// ===========================================================================

describe('CWE-613: Insufficient Session Expiration', () => {
  it('VULNERABLE: setMaxInactiveInterval(-1) — never expires', () => {
    const map = buildMap([
      {
        id: 'DEP', node_type: 'STRUCTURAL', label: 'javax.servlet.http', node_subtype: 'dependency',
        code_snapshot: 'import javax.servlet.http.*;',
        edges: [],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad(HttpServletRequest request) {\n  HttpSession session = request.getSession(true);\n  session.setMaxInactiveInterval(-1);\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-613');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: reasonable session timeout', () => {
    const map = buildMap([
      {
        id: 'DEP', node_type: 'STRUCTURAL', label: 'javax.servlet.http', node_subtype: 'dependency',
        code_snapshot: 'import javax.servlet.http.*;',
        edges: [],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'good', node_subtype: 'function',
        code_snapshot: 'public void good(HttpServletRequest request) {\n  HttpSession session = request.getSession(true);\n  session.setMaxInactiveInterval(1800);\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-613');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-615: Inclusion of Sensitive Information in Source Comments
// ===========================================================================

describe('CWE-615: Sensitive Info in Source Comments', () => {
  it('VULNERABLE: HTML comment with DB credentials in response output', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'bad', node_subtype: 'function',
        code_snapshot: 'public void bad(HttpServletResponse response) {\n  response.getWriter().println("<!--DB username = joe, DB password = 123-->");\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-615');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('VULNERABLE: source code comment with password', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'init', node_subtype: 'function',
        code_snapshot: '// password = admin123\nString conn = getConnection();',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-615');
    expect(result.holds).toBe(false);
  });

  it('SAFE: no sensitive data in comments or HTML output', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'good', node_subtype: 'function',
        code_snapshot: 'public void good(HttpServletResponse response) {\n  response.getWriter().println("<form><input type=text name=user></form>");\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-615');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-667: Improper Locking
// ===========================================================================

describe('CWE-667: Improper Locking', () => {
  it('VULNERABLE: lock without unlock', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'LockTest', node_subtype: 'class',
        code_snapshot: 'public class LockTest {\n  static public void helperBad() {\n    BAD_LOCK.lock();\n    counter++;\n  }\n}',
        edges: [{ target: 'FUNC', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'helperBad', node_subtype: 'function',
        code_snapshot: 'static public void helperBad() {\n  BAD_LOCK.lock();\n  counter++;\n  IO.writeLine(counter);\n  /* FLAW: lock is not unlocked */\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-667');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: lock with unlock in finally', () => {
    const map = buildMap([
      {
        id: 'CLS', node_type: 'STRUCTURAL', label: 'LockTest', node_subtype: 'class',
        code_snapshot: 'public class LockTest {\n  static public void helperGood() {\n    GOOD_LOCK.lock();\n    try { counter++; } finally { GOOD_LOCK.unlock(); }\n  }\n}',
        edges: [{ target: 'FUNC', edge_type: 'CONTAINS', conditional: false, async: false }],
      },
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'helperGood', node_subtype: 'function',
        code_snapshot: 'static public void helperGood() {\n  GOOD_LOCK.lock();\n  try {\n    counter++;\n  } finally {\n    GOOD_LOCK.unlock();\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-667');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-764: Multiple Locks of Same Critical Resource
// ===========================================================================

describe('CWE-764: Multiple Locks', () => {
  it('VULNERABLE: lock() called twice, unlock() called once', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'helperBad', node_subtype: 'function',
        code_snapshot: 'static public void helperBad() {\n  LOCK.lock();\n  LOCK.lock(); /* FLAW: double lock */\n  try {\n    value = value * 2;\n  } finally {\n    LOCK.unlock();\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-764');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: lock() and unlock() each called once', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'helperGood', node_subtype: 'function',
        code_snapshot: 'static public void helperGood() {\n  LOCK.lock();\n  try {\n    value = value * 2;\n  } finally {\n    LOCK.unlock();\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-764');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-765: Multiple Unlocks of Same Critical Resource
// ===========================================================================

describe('CWE-765: Multiple Unlocks', () => {
  it('VULNERABLE: unlock() called twice, lock() called once', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'helperBad', node_subtype: 'function',
        code_snapshot: 'static public void helperBad() {\n  LOCK.lock();\n  try {\n    value = value * 2;\n  } finally {\n    LOCK.unlock();\n    LOCK.unlock(); /* FLAW: double unlock */\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-765');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: balanced lock/unlock', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'helperGood', node_subtype: 'function',
        code_snapshot: 'static public void helperGood() {\n  LOCK.lock();\n  try {\n    value = value * 2;\n  } finally {\n    LOCK.unlock();\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-765');
    expect(result.holds).toBe(true);
  });
});

// ===========================================================================
// CWE-832: Unlock of Resource That is Not Locked
// ===========================================================================

describe('CWE-832: Unlock of Resource Not Locked', () => {
  it('VULNERABLE: unlock() without any lock()', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'helperBad', node_subtype: 'function',
        code_snapshot: 'static public void helperBad() {\n  /* Missing lock here */\n  try {\n    value = value * 2;\n  } finally {\n    LOCK.unlock(); /* FLAW: no preceding lock */\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-832');
    expect(result.holds).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('SAFE: lock() before unlock()', () => {
    const map = buildMap([
      {
        id: 'FUNC', node_type: 'STRUCTURAL', label: 'helperGood', node_subtype: 'function',
        code_snapshot: 'static public void helperGood() {\n  LOCK.lock();\n  try {\n    value = value * 2;\n  } finally {\n    LOCK.unlock();\n  }\n}',
        edges: [],
      },
    ]);
    const result = verify(map, 'CWE-832');
    expect(result.holds).toBe(true);
  });
});
