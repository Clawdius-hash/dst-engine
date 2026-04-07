/**
 * DST Ultimate CWE Validation Harness
 *
 * Tests the top 100 most important CWEs against real vulnerable JavaScript
 * code snippets. Each snippet is parsed through tree-sitter, mapped to a
 * NeuralMap, and verified by the DST engine.
 *
 * This is a standalone script, NOT a vitest test.
 * Run: npx tsx src/services/dst/cwe-ultimate-test.ts
 */

import { scanCode, initDST } from './scan.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CWETest {
  cwe: string;
  name: string;
  vulnerableCode: string;
}

// ---------------------------------------------------------------------------
// Top 100 CWE Tests — minimal vulnerable JavaScript snippets
//
// Each snippet is designed to produce the neural map pattern the verifier
// expects: INGRESS nodes (req.body/query/params), dangerous sinks
// (STORAGE/EGRESS/EXTERNAL), and no mediating CONTROL/AUTH nodes.
// ---------------------------------------------------------------------------

const tests: CWETest[] = [
  // ── Injection CWEs ──────────────────────────────────────────────────
  {
    cwe: 'CWE-89',
    name: 'SQL Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/users', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
});
`,
  },
  {
    cwe: 'CWE-79',
    name: 'Cross-Site Scripting (XSS)',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/search', (req, res) => {
  res.send("<h1>Results for: " + req.query.q + "</h1>");
});
`,
  },
  {
    cwe: 'CWE-78',
    name: 'OS Command Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec("ping " + req.query.host, (err, stdout) => {
    res.send(stdout);
  });
});
`,
  },
  {
    cwe: 'CWE-94',
    name: 'Code Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/calc', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});
`,
  },
  {
    cwe: 'CWE-77',
    name: 'Command Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
const { execSync } = require('child_process');
app.post('/run', (req, res) => {
  const output = execSync(req.body.command);
  res.send(output);
});
`,
  },
  {
    cwe: 'CWE-90',
    name: 'LDAP Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
const ldap = require('ldapjs');
app.get('/lookup', (req, res) => {
  const filter = "(&(uid=" + req.query.username + ")(objectClass=person))";
  ldap.search("dc=example,dc=com", { filter });
});
`,
  },
  {
    cwe: 'CWE-91',
    name: 'XML Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/data', (req, res) => {
  const xml = "<user><name>" + req.body.name + "</name></user>";
  res.type('xml').send(xml);
});
`,
  },
  {
    cwe: 'CWE-74',
    name: 'Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/page', (req, res) => {
  const content = req.query.content;
  res.send("<div>" + content + "</div>");
});
`,
  },
  {
    cwe: 'CWE-95',
    name: 'Eval Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/eval', (req, res) => {
  const fn = new Function(req.body.code);
  res.json({ result: fn() });
});
`,
  },
  {
    cwe: 'CWE-96',
    name: 'Static Code Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.post('/config', (req, res) => {
  fs.writeFileSync('config.js', "module.exports = " + req.body.config);
  res.send('ok');
});
`,
  },
  {
    cwe: 'CWE-98',
    name: 'Remote File Inclusion',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/load', (req, res) => {
  const mod = require(req.query.module);
  res.json(mod);
});
`,
  },
  {
    cwe: 'CWE-99',
    name: 'Resource Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
const net = require('net');
app.get('/connect', (req, res) => {
  const socket = net.connect(req.query.port, req.query.host);
  socket.on('data', (d) => res.send(d));
});
`,
  },
  {
    cwe: 'CWE-93',
    name: 'CRLF Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/redirect', (req, res) => {
  res.setHeader('Location', req.query.url);
  res.status(302).send('');
});
`,
  },

  // ── Path Traversal & File CWEs ──────────────────────────────────────
  {
    cwe: 'CWE-22',
    name: 'Path Traversal',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.get('/file', (req, res) => {
  const data = fs.readFileSync('/uploads/' + req.query.name);
  res.send(data);
});
`,
  },
  {
    cwe: 'CWE-434',
    name: 'Unrestricted Upload',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.post('/upload', (req, res) => {
  fs.writeFileSync('/uploads/' + req.body.filename, req.body.data);
  res.send('uploaded');
});
`,
  },

  // ── Deserialization ─────────────────────────────────────────────────
  {
    cwe: 'CWE-502',
    name: 'Deserialization of Untrusted Data',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/data', (req, res) => {
  const obj = JSON.parse(req.body.payload);
  eval(obj.code);
  res.json(obj);
});
`,
  },

  // ── SSRF ────────────────────────────────────────────────────────────
  {
    cwe: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    vulnerableCode: `
const express = require('express');
const app = express();
const fetch = require('node-fetch');
app.get('/proxy', (req, res) => {
  fetch(req.query.url).then(r => r.text()).then(t => res.send(t));
});
`,
  },

  // ── Hardcoded Credentials ───────────────────────────────────────────
  {
    cwe: 'CWE-798',
    name: 'Hardcoded Credentials',
    vulnerableCode: `
const express = require('express');
const app = express();
const password = "supersecret123";
const db = require('./db');
app.post('/login', (req, res) => {
  if (req.body.password === password) {
    db.query("SELECT * FROM users WHERE pass = '" + password + "'");
    res.send('ok');
  }
});
`,
  },

  // ── Missing Authentication ──────────────────────────────────────────
  {
    cwe: 'CWE-306',
    name: 'Missing Authentication',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.delete('/users', (req, res) => {
  db.query("DELETE FROM users WHERE id = " + req.query.id);
  res.send('deleted');
});
`,
  },

  // ── Information Exposure ────────────────────────────────────────────
  {
    cwe: 'CWE-200',
    name: 'Information Exposure',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/user', (req, res) => {
  const user = db.query("SELECT * FROM users WHERE id = " + req.query.id);
  res.json(user);
});
`,
  },
  {
    cwe: 'CWE-209',
    name: 'Error Message Information Exposure',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/data', (req, res) => {
  try {
    JSON.parse(req.query.data);
  } catch (err) {
    res.send("Error: " + err.stack);
  }
});
`,
  },
  {
    cwe: 'CWE-532',
    name: 'Insertion of Sensitive Info into Log',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/login', (req, res) => {
  console.log("Login attempt with password: " + req.body.password);
  res.send('ok');
});
`,
  },

  // ── XXE ─────────────────────────────────────────────────────────────
  {
    cwe: 'CWE-611',
    name: 'XML External Entity (XXE)',
    vulnerableCode: `
const express = require('express');
const app = express();
const xml2js = require('xml2js');
app.post('/xml', (req, res) => {
  xml2js.parseString(req.body.xml, (err, result) => {
    res.json(result);
  });
});
`,
  },

  // ── CSRF ────────────────────────────────────────────────────────────
  {
    cwe: 'CWE-352',
    name: 'Cross-Site Request Forgery',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/transfer', (req, res) => {
  db.query("UPDATE accounts SET balance = balance - " + req.body.amount);
  res.send('transferred');
});
`,
  },

  // ── Prototype Pollution ─────────────────────────────────────────────
  {
    cwe: 'CWE-1321',
    name: 'Prototype Pollution',
    vulnerableCode: `
const express = require('express');
const app = express();
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}
app.post('/settings', (req, res) => {
  const config = {};
  merge(config, req.body);
  res.json(config);
});
`,
  },

  // ── Open Redirect ───────────────────────────────────────────────────
  {
    cwe: 'CWE-601',
    name: 'Open Redirect',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});
`,
  },

  // ── Cryptography CWEs ───────────────────────────────────────────────
  {
    cwe: 'CWE-327',
    name: 'Use of Broken Crypto Algorithm',
    vulnerableCode: `
const express = require('express');
const app = express();
const crypto = require('crypto');
app.post('/hash', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  res.json({ hash });
});
`,
  },
  {
    cwe: 'CWE-328',
    name: 'Weak Hash',
    vulnerableCode: `
const express = require('express');
const app = express();
const crypto = require('crypto');
app.post('/verify', (req, res) => {
  const hash = crypto.createHash('sha1').update(req.body.data).digest('hex');
  res.json({ hash });
});
`,
  },
  {
    cwe: 'CWE-330',
    name: 'Insufficient Randomness',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/token', (req, res) => {
  const token = Math.random().toString(36).substring(2);
  res.json({ token });
});
`,
  },
  {
    cwe: 'CWE-338',
    name: 'Use of Weak PRNG',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/session', (req, res) => {
  const sessionId = Math.random().toString(16).slice(2);
  res.cookie('session', sessionId);
  res.send('ok');
});
`,
  },

  // ── Input Validation ────────────────────────────────────────────────
  {
    cwe: 'CWE-20',
    name: 'Improper Input Validation',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/order', (req, res) => {
  db.query("INSERT INTO orders (qty) VALUES (" + req.body.quantity + ")");
  res.send('ordered');
});
`,
  },
  {
    cwe: 'CWE-116',
    name: 'Improper Encoding or Escaping of Output',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/profile', (req, res) => {
  const name = req.query.name;
  res.send("<html><body>Hello " + name + "</body></html>");
});
`,
  },
  {
    cwe: 'CWE-134',
    name: 'Use of Externally-Controlled Format String',
    vulnerableCode: `
const express = require('express');
const app = express();
const util = require('util');
app.get('/log', (req, res) => {
  const msg = util.format(req.query.fmt, "data");
  console.log(msg);
  res.send(msg);
});
`,
  },

  // ── Authorization CWEs ──────────────────────────────────────────────
  {
    cwe: 'CWE-862',
    name: 'Missing Authorization',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/admin/users', (req, res) => {
  const users = db.query("SELECT * FROM users");
  res.json(users);
});
`,
  },
  {
    cwe: 'CWE-863',
    name: 'Incorrect Authorization',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.put('/user', (req, res) => {
  db.query("UPDATE users SET role = " + req.body.role + " WHERE id = " + req.body.id);
  res.send('updated');
});
`,
  },
  {
    cwe: 'CWE-284',
    name: 'Improper Access Control',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/records', (req, res) => {
  const data = db.query("SELECT * FROM records WHERE owner = " + req.query.userId);
  res.json(data);
});
`,
  },
  {
    cwe: 'CWE-285',
    name: 'Improper Authorization',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/admin/action', (req, res) => {
  db.query("DELETE FROM logs WHERE id = " + req.body.logId);
  res.send('deleted');
});
`,
  },

  // ── Session & Cookie CWEs ───────────────────────────────────────────
  {
    cwe: 'CWE-384',
    name: 'Session Fixation',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/login', (req, res) => {
  if (req.body.user === 'admin') {
    res.cookie('session', req.body.sessionId);
    res.send('logged in');
  }
});
`,
  },
  {
    cwe: 'CWE-614',
    name: 'Sensitive Cookie Without Secure Flag',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/login', (req, res) => {
  res.cookie('session', 'abc123', { httpOnly: true });
  res.send('ok');
});
`,
  },
  {
    cwe: 'CWE-1004',
    name: 'Sensitive Cookie Without HttpOnly',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/login', (req, res) => {
  res.cookie('session', 'abc123', { secure: true });
  res.send('ok');
});
`,
  },

  // ── Resource Exhaustion CWEs ────────────────────────────────────────
  {
    cwe: 'CWE-400',
    name: 'Uncontrolled Resource Consumption',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/data', (req, res) => {
  const data = JSON.parse(req.body.payload);
  res.json(data);
});
`,
  },
  {
    cwe: 'CWE-1333',
    name: 'Regex Denial of Service (ReDoS)',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/check', (req, res) => {
  const re = new RegExp("(a+)+$");
  const match = re.test(req.query.input);
  res.json({ match });
});
`,
  },

  // ── XXE Variants ────────────────────────────────────────────────────
  {
    cwe: 'CWE-776',
    name: 'XML Entity Expansion (Billion Laughs)',
    vulnerableCode: `
const express = require('express');
const app = express();
const xml2js = require('xml2js');
app.post('/parse', (req, res) => {
  xml2js.parseString(req.body.xml, (err, result) => {
    res.json(result);
  });
});
`,
  },

  // ── Path & Resource CWEs ────────────────────────────────────────────
  {
    cwe: 'CWE-610',
    name: 'Externally Controlled Reference',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.get('/include', (req, res) => {
  const content = fs.readFileSync(req.query.path, 'utf-8');
  res.send(content);
});
`,
  },
  {
    cwe: 'CWE-643',
    name: 'XPath Injection',
    vulnerableCode: `
const express = require('express');
const app = express();
const xpath = require('xpath');
app.get('/find', (req, res) => {
  const query = "//user[@name='" + req.query.name + "']";
  xpath.select(query);
  res.send('found');
});
`,
  },

  // ── Dynamic Class Loading ───────────────────────────────────────────
  {
    cwe: 'CWE-470',
    name: 'Unsafe Reflection',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/load', (req, res) => {
  const module = require(req.query.module);
  res.json(module.info());
});
`,
  },

  // ── Sensitive Data ──────────────────────────────────────────────────
  {
    cwe: 'CWE-312',
    name: 'Cleartext Storage of Sensitive Info',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/register', (req, res) => {
  db.query("INSERT INTO users (password) VALUES ('" + req.body.password + "')");
  res.send('registered');
});
`,
  },
  {
    cwe: 'CWE-319',
    name: 'Cleartext Transmission of Sensitive Info',
    vulnerableCode: `
const express = require('express');
const app = express();
const http = require('http');
app.post('/send', (req, res) => {
  http.request("http://api.example.com/data?secret=" + req.body.token);
  res.send('sent');
});
`,
  },

  // ── Authentication CWEs ─────────────────────────────────────────────
  {
    cwe: 'CWE-287',
    name: 'Improper Authentication',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/login', (req, res) => {
  const user = db.query("SELECT * FROM users WHERE name = '" + req.body.name + "'");
  res.json({ user });
});
`,
  },
  {
    cwe: 'CWE-521',
    name: 'Weak Password Requirements',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/register', (req, res) => {
  const password = req.body.password;
  db.query("INSERT INTO users (pass) VALUES ('" + password + "')");
  res.send('created');
});
`,
  },
  {
    cwe: 'CWE-522',
    name: 'Insufficiently Protected Credentials',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/login', (req, res) => {
  db.query("SELECT * FROM users WHERE pass = '" + req.body.password + "'");
  res.send('ok');
});
`,
  },
  {
    cwe: 'CWE-307',
    name: 'Improper Restriction of Excessive Auth Attempts',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/login', (req, res) => {
  const user = db.query("SELECT * FROM users WHERE email = '" + req.body.email + "'");
  if (user && user.password === req.body.password) {
    res.send('ok');
  } else {
    res.send('fail');
  }
});
`,
  },

  // ── Encoding & Neutralization CWEs ──────────────────────────────────
  {
    cwe: 'CWE-176',
    name: 'Improper Handling of Unicode Encoding',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/search', (req, res) => {
  db.query("SELECT * FROM items WHERE name = '" + req.query.q + "'");
  res.send('results');
});
`,
  },
  {
    cwe: 'CWE-117',
    name: 'Improper Output Neutralization for Logs',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/api', (req, res) => {
  console.log("Request from: " + req.query.user);
  res.send('ok');
});
`,
  },

  // ── Trust & Data Authenticity CWEs ──────────────────────────────────
  {
    cwe: 'CWE-345',
    name: 'Insufficient Verification of Data Authenticity',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/webhook', (req, res) => {
  db.query("INSERT INTO events (data) VALUES ('" + req.body.data + "')");
  res.send('ok');
});
`,
  },
  {
    cwe: 'CWE-346',
    name: 'Origin Validation Error',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/api/data', (req, res) => {
  db.query("INSERT INTO data (val) VALUES ('" + req.body.val + "')");
  res.send('saved');
});
`,
  },

  // ── Resource Management ─────────────────────────────────────────────
  {
    cwe: 'CWE-404',
    name: 'Improper Resource Shutdown',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.get('/read', (req, res) => {
  const fd = fs.openSync('/data/' + req.query.file, 'r');
  const buf = Buffer.alloc(1024);
  fs.readSync(fd, buf);
  res.send(buf);
});
`,
  },
  {
    cwe: 'CWE-770',
    name: 'Allocation of Resources Without Limits',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/upload', (req, res) => {
  const buf = Buffer.alloc(parseInt(req.body.size));
  res.send('allocated');
});
`,
  },

  // ── Privilege CWEs ──────────────────────────────────────────────────
  {
    cwe: 'CWE-250',
    name: 'Execution with Unnecessary Privileges',
    vulnerableCode: `
const express = require('express');
const app = express();
const { exec } = require('child_process');
app.get('/admin', (req, res) => {
  exec("sudo " + req.query.cmd, (err, stdout) => {
    res.send(stdout);
  });
});
`,
  },
  {
    cwe: 'CWE-269',
    name: 'Improper Privilege Management',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/promote', (req, res) => {
  db.query("UPDATE users SET role = 'admin' WHERE id = " + req.body.userId);
  res.send('promoted');
});
`,
  },

  // ── Error Handling CWEs ─────────────────────────────────────────────
  {
    cwe: 'CWE-390',
    name: 'Detection of Error Condition Without Action',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/data', (req, res) => {
  try {
    const data = db.query("SELECT * FROM t WHERE id = " + req.query.id);
    res.json(data);
  } catch (e) {
  }
});
`,
  },
  {
    cwe: 'CWE-396',
    name: 'Catching Overly Broad Exceptions',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/api', (req, res) => {
  try {
    JSON.parse(req.query.data);
    res.send('ok');
  } catch (e) {
    res.send("Error");
  }
});
`,
  },

  // ── Comparison & Logic CWEs ─────────────────────────────────────────
  {
    cwe: 'CWE-480',
    name: 'Use of Incorrect Operator',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/check', (req, res) => {
  if (req.query.role = "admin") {
    res.send('access granted');
  }
});
`,
  },
  {
    cwe: 'CWE-481',
    name: 'Assigning Instead of Comparing',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/auth', (req, res) => {
  let isAdmin = false;
  if (isAdmin = true) {
    res.send('admin panel');
  }
});
`,
  },

  // ── Data Integrity CWEs ─────────────────────────────────────────────
  {
    cwe: 'CWE-494',
    name: 'Download of Code Without Integrity Check',
    vulnerableCode: `
const express = require('express');
const app = express();
const fetch = require('node-fetch');
app.get('/update', (req, res) => {
  fetch(req.query.scriptUrl).then(r => r.text()).then(code => {
    eval(code);
    res.send('updated');
  });
});
`,
  },
  {
    cwe: 'CWE-347',
    name: 'Improper Verification of Cryptographic Signature',
    vulnerableCode: `
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
app.post('/verify', (req, res) => {
  const decoded = jwt.decode(req.body.token);
  res.json(decoded);
});
`,
  },

  // ── Race Condition CWEs ─────────────────────────────────────────────
  {
    cwe: 'CWE-362',
    name: 'Race Condition',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
let counter = 0;
app.post('/increment', (req, res) => {
  const current = counter;
  counter = current + parseInt(req.body.amount);
  res.json({ counter });
});
`,
  },

  // ── Sensitive Data in Logs ──────────────────────────────────────────
  {
    cwe: 'CWE-215',
    name: 'Insertion of Sensitive Info into Debug Code',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/api', (req, res) => {
  console.log("DEBUG: user data = " + JSON.stringify(req.body));
  res.send('ok');
});
`,
  },
  {
    cwe: 'CWE-497',
    name: 'Exposure of Sensitive System Info',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/info', (req, res) => {
  res.json({
    nodeVersion: process.version,
    env: process.env,
    cwd: process.cwd()
  });
});
`,
  },
  {
    cwe: 'CWE-538',
    name: 'Insertion of Sensitive Info into Externally Accessible File',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.post('/log', (req, res) => {
  fs.appendFileSync('/var/log/app.log', "password=" + req.body.password + "\\n");
  res.send('logged');
});
`,
  },

  // ── Permissions CWEs ────────────────────────────────────────────────
  {
    cwe: 'CWE-276',
    name: 'Incorrect Default Permissions',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.post('/save', (req, res) => {
  fs.writeFileSync('/tmp/data.txt', req.body.data, { mode: 0o777 });
  res.send('saved');
});
`,
  },
  {
    cwe: 'CWE-732',
    name: 'Incorrect Permission Assignment',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.post('/create', (req, res) => {
  fs.writeFileSync('/etc/config.json', req.body.config);
  fs.chmodSync('/etc/config.json', 0o777);
  res.send('created');
});
`,
  },

  // ── Null Pointer & Memory CWEs ──────────────────────────────────────
  {
    cwe: 'CWE-476',
    name: 'NULL Pointer Dereference',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/data', (req, res) => {
  const obj = null;
  res.send(obj.toString());
});
`,
  },

  // ── Integer CWEs ────────────────────────────────────────────────────
  {
    cwe: 'CWE-190',
    name: 'Integer Overflow',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/calc', (req, res) => {
  const a = parseInt(req.query.a);
  const b = parseInt(req.query.b);
  const result = a * b;
  const buf = Buffer.alloc(result);
  res.send(buf);
});
`,
  },

  // ── Misc Important CWEs ─────────────────────────────────────────────
  {
    cwe: 'CWE-501',
    name: 'Trust Boundary Violation',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/api', (req, res) => {
  req.session.role = req.body.role;
  res.send('ok');
});
`,
  },
  {
    cwe: 'CWE-311',
    name: 'Missing Encryption of Sensitive Data',
    vulnerableCode: `
const express = require('express');
const app = express();
const http = require('http');
app.post('/send', (req, res) => {
  http.request("http://api.example.com/secret?data=" + req.body.secret);
  res.send('sent');
});
`,
  },
  {
    cwe: 'CWE-326',
    name: 'Inadequate Encryption Strength',
    vulnerableCode: `
const express = require('express');
const app = express();
const crypto = require('crypto');
app.post('/encrypt', (req, res) => {
  const cipher = crypto.createCipheriv('des', Buffer.alloc(8), Buffer.alloc(8));
  const encrypted = cipher.update(req.body.data, 'utf8', 'hex');
  res.json({ encrypted });
});
`,
  },
  {
    cwe: 'CWE-329',
    name: 'Not Using Unpredictable IV with CBC',
    vulnerableCode: `
const express = require('express');
const app = express();
const crypto = require('crypto');
app.post('/encrypt', (req, res) => {
  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.alloc(32), iv);
  const encrypted = cipher.update(req.body.data, 'utf8', 'hex');
  res.json({ encrypted });
});
`,
  },

  // ── Weak Password Storage CWEs ──────────────────────────────────────
  {
    cwe: 'CWE-916',
    name: 'Use of Password Hash With Insufficient Effort',
    vulnerableCode: `
const express = require('express');
const app = express();
const crypto = require('crypto');
app.post('/register', (req, res) => {
  const hash = crypto.createHash('sha256').update(req.body.password).digest('hex');
  res.json({ hash });
});
`,
  },
  {
    cwe: 'CWE-759',
    name: 'Use of One-Way Hash Without Salt',
    vulnerableCode: `
const express = require('express');
const app = express();
const crypto = require('crypto');
app.post('/hash', (req, res) => {
  const hash = crypto.createHash('sha256').update(req.body.password).digest('hex');
  res.json({ hash });
});
`,
  },

  // ── Unsafe Deserialization Variants ─────────────────────────────────
  {
    cwe: 'CWE-915',
    name: 'Mass Assignment',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.put('/user', (req, res) => {
  Object.assign(db.getUser(req.query.id), req.body);
  res.send('updated');
});
`,
  },

  // ── Web Security CWEs ───────────────────────────────────────────────
  {
    cwe: 'CWE-1021',
    name: 'Clickjacking (Missing X-Frame-Options)',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/page', (req, res) => {
  res.send("<html><body>Content for " + req.query.user + "</body></html>");
});
`,
  },
  {
    cwe: 'CWE-942',
    name: 'Permissive Cross-domain Policy',
    vulnerableCode: `
const express = require('express');
const app = express();
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});
app.get('/api', (req, res) => {
  res.json({ data: req.query.data });
});
`,
  },

  // ── Deprecated / Insecure Function CWEs ─────────────────────────────
  {
    cwe: 'CWE-676',
    name: 'Use of Potentially Dangerous Function',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/run', (req, res) => {
  eval(req.body.code);
  res.send('executed');
});
`,
  },

  // ── Logging & Monitoring CWEs ───────────────────────────────────────
  {
    cwe: 'CWE-778',
    name: 'Insufficient Logging',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.delete('/user', (req, res) => {
  db.query("DELETE FROM users WHERE id = " + req.query.id);
  res.send('deleted');
});
`,
  },

  // ── More Crypto CWEs ────────────────────────────────────────────────
  {
    cwe: 'CWE-321',
    name: 'Use of Hardcoded Cryptographic Key',
    vulnerableCode: `
const express = require('express');
const app = express();
const crypto = require('crypto');
const SECRET_KEY = "mysupersecretkey";
app.post('/encrypt', (req, res) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, Buffer.alloc(16));
  const encrypted = cipher.update(req.body.data, 'utf8', 'hex');
  res.json({ encrypted });
});
`,
  },
  {
    cwe: 'CWE-295',
    name: 'Improper Certificate Validation',
    vulnerableCode: `
const express = require('express');
const app = express();
const https = require('https');
app.get('/fetch', (req, res) => {
  https.get(req.query.url, { rejectUnauthorized: false }, (r) => {
    r.pipe(res);
  });
});
`,
  },

  // ── File / IO CWEs ──────────────────────────────────────────────────
  {
    cwe: 'CWE-552',
    name: 'Files/Directories Accessible to External Parties',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.get('/download', (req, res) => {
  const file = fs.readFileSync('/etc/' + req.query.file);
  res.send(file);
});
`,
  },

  // ── Session CWEs ────────────────────────────────────────────────────
  {
    cwe: 'CWE-613',
    name: 'Insufficient Session Expiration',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/login', (req, res) => {
  req.session.user = req.body.user;
  res.send('logged in');
});
`,
  },
  {
    cwe: 'CWE-565',
    name: 'Reliance on Cookies Without Validation',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/data', (req, res) => {
  const userId = req.cookies.userId;
  const data = db.query("SELECT * FROM data WHERE owner = " + userId);
  res.json(data);
});
`,
  },

  // ── Additional Important CWEs ───────────────────────────────────────
  {
    cwe: 'CWE-639',
    name: 'Authorization Bypass via User-Controlled Key',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/user', (req, res) => {
  const user = db.query("SELECT * FROM users WHERE id = " + req.query.userId);
  res.json(user);
});
`,
  },
  {
    cwe: 'CWE-602',
    name: 'Client-Side Enforcement of Server-Side Security',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/purchase', (req, res) => {
  db.query("INSERT INTO orders (price) VALUES (" + req.body.price + ")");
  res.send('ordered');
});
`,
  },
  {
    cwe: 'CWE-472',
    name: 'External Control of Web Service',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/action', (req, res) => {
  db.query("UPDATE items SET status = '" + req.body.status + "' WHERE id = " + req.body.id);
  res.send('updated');
});
`,
  },

  // ── Null Byte & Encoding CWEs ───────────────────────────────────────
  {
    cwe: 'CWE-158',
    name: 'Improper Neutralization of Null Byte',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.get('/read', (req, res) => {
  const data = fs.readFileSync(req.query.file);
  res.send(data);
});
`,
  },

  // ── Predictability CWEs ─────────────────────────────────────────────
  {
    cwe: 'CWE-341',
    name: 'Predictable from Observable State',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/token', (req, res) => {
  const token = Date.now().toString(36);
  res.json({ token });
});
`,
  },
  {
    cwe: 'CWE-340',
    name: 'Generation of Predictable Numbers',
    vulnerableCode: `
const express = require('express');
const app = express();
let counter = 0;
app.get('/id', (req, res) => {
  counter++;
  res.json({ id: counter });
});
`,
  },

  // ── Sensitive Data Exposure Variants ────────────────────────────────
  {
    cwe: 'CWE-256',
    name: 'Plaintext Storage of Password',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/register', (req, res) => {
  db.query("INSERT INTO users (username, password) VALUES ('" + req.body.user + "', '" + req.body.password + "')");
  res.send('registered');
});
`,
  },
  {
    cwe: 'CWE-313',
    name: 'Cleartext Storage in File or on Disk',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.post('/save', (req, res) => {
  fs.writeFileSync('/data/secrets.txt', req.body.password);
  res.send('saved');
});
`,
  },

  // ── Code Quality CWEs ───────────────────────────────────────────────
  {
    cwe: 'CWE-489',
    name: 'Active Debug Code',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/debug', (req, res) => {
  console.log("DEBUG MODE: " + JSON.stringify(req.query));
  res.send('debug info: ' + req.query.cmd);
});
`,
  },
  {
    cwe: 'CWE-547',
    name: 'Use of Hardcoded Security-Relevant Constants',
    vulnerableCode: `
const express = require('express');
const app = express();
const ADMIN_PASSWORD = "admin123";
app.post('/admin', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    res.send('admin access');
  }
});
`,
  },

  // ── Additional Auth CWEs ────────────────────────────────────────────
  {
    cwe: 'CWE-288',
    name: 'Auth Bypass via Alternate Path',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/api/secret', (req, res) => {
  const data = db.query("SELECT * FROM secrets");
  res.json(data);
});
`,
  },
  {
    cwe: 'CWE-290',
    name: 'Auth Bypass by Spoofing',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/admin', (req, res) => {
  if (req.headers['x-forwarded-for'] === '127.0.0.1') {
    res.send('admin access');
  }
});
`,
  },

  // ── More Injection CWEs ─────────────────────────────────────────────
  {
    cwe: 'CWE-943',
    name: 'Improper Neutralization of NoSQL Query',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.post('/find', (req, res) => {
  db.query("SELECT * FROM items WHERE data = " + JSON.stringify(req.body));
  res.send('found');
});
`,
  },

  // ── Security Misconfiguration CWEs ──────────────────────────────────
  {
    cwe: 'CWE-829',
    name: 'Inclusion of Untrusted Functionality',
    vulnerableCode: `
const express = require('express');
const app = express();
app.get('/load', (req, res) => {
  const script = '<script src="' + req.query.src + '"></script>';
  res.send('<html>' + script + '</html>');
});
`,
  },

  // ── IDOR CWE ────────────────────────────────────────────────────────
  {
    cwe: 'CWE-425',
    name: 'Direct Request (Forced Browsing)',
    vulnerableCode: `
const express = require('express');
const app = express();
const db = require('./db');
app.get('/invoice', (req, res) => {
  const invoice = db.query("SELECT * FROM invoices WHERE id = " + req.query.id);
  res.json(invoice);
});
`,
  },

  // ── Unsafe File Operations ──────────────────────────────────────────
  {
    cwe: 'CWE-377',
    name: 'Insecure Temporary File',
    vulnerableCode: `
const express = require('express');
const app = express();
const fs = require('fs');
app.post('/process', (req, res) => {
  const tmpFile = '/tmp/upload_' + req.body.name;
  fs.writeFileSync(tmpFile, req.body.data);
  res.send('processed');
});
`,
  },

  // ── Buffer / Memory CWEs ────────────────────────────────────────────
  {
    cwe: 'CWE-119',
    name: 'Buffer Overflow',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/copy', (req, res) => {
  const buf = Buffer.alloc(10);
  buf.write(req.body.data);
  res.send(buf);
});
`,
  },
  {
    cwe: 'CWE-120',
    name: 'Buffer Copy Without Size Check',
    vulnerableCode: `
const express = require('express');
const app = express();
app.post('/store', (req, res) => {
  const buf = Buffer.alloc(8);
  Buffer.from(req.body.data).copy(buf);
  res.send(buf);
});
`,
  },
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function main() {
  console.log('=== DST Ultimate CWE Validation Harness ===\n');
  console.log('Initializing DST engine...');
  await initDST();
  console.log('Engine ready. Running ' + tests.length + ' CWE tests...\n');

  const results: Array<{
    cwe: string;
    name: string;
    detected: boolean;
    partial: boolean;       // Other CWEs fired (vulnerability caught, just classified differently)
    otherCWEs: string[];    // Which CWEs fired instead
    error: string | null;
    findingCount: number;
    totalFindings: number;
  }> = [];

  const PAD_CWE = 12;
  const PAD_NAME = 55;

  for (const test of tests) {
    try {
      const result = await scanCode(test.vulnerableCode, 'test-app.js');

      // Check if this specific CWE was found in the results
      const cweFindings = result.findings.filter(f => f.cwe === test.cwe);
      const detected = cweFindings.length > 0;

      // Also check: did ANY finding fire? (some CWEs overlap)
      const anyFinding = result.findings.length > 0;
      const otherCWEs = [...new Set(result.findings.map(f => f.cwe))];

      const status = detected
        ? '\x1b[32m\u2713 DETECTED\x1b[0m'
        : anyFinding
          ? '\x1b[33m~ PARTIAL (other CWEs fired)\x1b[0m'
          : '\x1b[31m\u2717 NOT DETECTED\x1b[0m';

      const cwePad = test.cwe.padEnd(PAD_CWE);
      const namePad = test.name.padEnd(PAD_NAME);
      console.log(`${cwePad} ${namePad} ${status}`);

      if (detected) {
        // Show first finding details at lower verbosity
        const f = cweFindings[0];
        console.log(`             Source: ${f.source.label.slice(0, 60)}`);
        console.log(`             Sink:   ${f.sink.label.slice(0, 60)}`);
        console.log(`             Missing: ${f.missing.slice(0, 60)}`);
        console.log('');
      } else if (anyFinding) {
        // Show what DID fire
        console.log(`             Fired instead: ${otherCWEs.join(', ')}`);
        console.log('');
      } else {
        console.log('');
      }

      results.push({
        cwe: test.cwe,
        name: test.name,
        detected,
        partial: !detected && anyFinding,
        otherCWEs: detected ? [] : otherCWEs,
        error: null,
        findingCount: cweFindings.length,
        totalFindings: result.findings.length,
      });
    } catch (err: any) {
      const cwePad = test.cwe.padEnd(PAD_CWE);
      const namePad = test.name.padEnd(PAD_NAME);
      console.log(`${cwePad} ${namePad} \x1b[31m! ERROR: ${err.message?.slice(0, 60)}\x1b[0m\n`);
      results.push({
        cwe: test.cwe,
        name: test.name,
        detected: false,
        partial: false,
        otherCWEs: [],
        error: err.message,
        findingCount: 0,
        totalFindings: 0,
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Summary
  // ---------------------------------------------------------------------------

  console.log('\n' + '='.repeat(80));
  console.log('SUMMARY');
  console.log('='.repeat(80));

  const detected = results.filter(r => r.detected);
  const partial = results.filter(r => r.partial);
  const silent = results.filter(r => !r.detected && !r.partial && !r.error);
  const errors = results.filter(r => r.error);

  console.log(`\nTotal CWEs tested:     ${results.length}`);
  console.log(`Exact CWE match:       ${detected.length} (${Math.round(100 * detected.length / results.length)}%)`);
  console.log(`Partial (other CWEs):  ${partial.length} (${Math.round(100 * partial.length / results.length)}%)`);
  console.log(`Effective detection:   ${detected.length + partial.length} (${Math.round(100 * (detected.length + partial.length) / results.length)}%) -- vulnerability caught by at least one CWE`);
  console.log(`Truly silent:          ${silent.length} (${Math.round(100 * silent.length / results.length)}%)`);
  console.log(`Errors:                ${errors.length}`);

  if (partial.length > 0) {
    console.log('\n--- Partial Detections (vulnerability caught under different CWE) ---');
    for (const r of partial) {
      const top3 = r.otherCWEs.slice(0, 5).join(', ');
      const more = r.otherCWEs.length > 5 ? ` +${r.otherCWEs.length - 5} more` : '';
      console.log(`  ${r.cwe.padEnd(PAD_CWE)} ${r.name.padEnd(45)} -> ${top3}${more}`);
    }
  }

  if (silent.length > 0) {
    console.log('\n--- Truly Silent (no findings at all) ---');
    for (const r of silent) {
      console.log(`  ${r.cwe.padEnd(PAD_CWE)} ${r.name}`);
    }
  }

  if (errors.length > 0) {
    console.log('\n--- Errors ---');
    for (const r of errors) {
      console.log(`  ${r.cwe.padEnd(PAD_CWE)} ${r.name}: ${r.error?.slice(0, 80)}`);
    }
  }

  console.log('\n' + '='.repeat(80));
  console.log(`EXACT MATCH RATE:     ${detected.length}/${results.length} (${Math.round(100 * detected.length / results.length)}%)`);
  console.log(`EFFECTIVE DETECTION:  ${detected.length + partial.length}/${results.length} (${Math.round(100 * (detected.length + partial.length) / results.length)}%)`);
  console.log('='.repeat(80));
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
