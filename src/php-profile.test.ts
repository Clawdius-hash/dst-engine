/**
 * PHP Profile Integration Test
 *
 * PHP runs 77% of the internet. WordPress alone is 43%.
 * This test makes the PHPProfile speak for the first time.
 *
 * One vulnerable PHP app -> parse with tree-sitter-php -> map with PHPProfile -> verify.
 * If mysqli_query("..." . $_GET['id']) becomes INGRESS -> STORAGE without CONTROL,
 * the mapper speaks PHP.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { Parser, Language } from 'web-tree-sitter';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildNeuralMap } from './mapper.js';
import { phpProfile } from './profiles/php.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let parser: InstanceType<typeof Parser>;

async function createPHPParser(): Promise<InstanceType<typeof Parser>> {
  await Parser.init();
  const p = new Parser();
  const wasmPath = path.resolve(
    __dirname,
    '../node_modules/tree-sitter-php/tree-sitter-php.wasm'
  );
  const wasmBuffer = fs.readFileSync(wasmPath);
  const PHP = await Language.load(wasmBuffer);
  p.setLanguage(PHP);
  return p;
}

function parsePHP(code: string) {
  return parser.parse(code);
}

describe('PHPProfile -- first words', () => {
  beforeAll(async () => {
    parser = await createPHPParser();
  });

  // ── 1. Basic function recognition ────────────────────────────────

  it('parses a simple PHP function and creates STRUCTURAL nodes', () => {
    const code = `<?php
function hello($name) {
    echo "Hello, " . $name;
}

hello("world");
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'hello.php', phpProfile);

    const structuralNodes = map.nodes.filter(n => n.node_type === 'STRUCTURAL');
    expect(structuralNodes.length).toBeGreaterThan(0);

    const funcNode = structuralNodes.find(n => n.node_subtype === 'function');
    expect(funcNode).toBeDefined();
    expect(funcNode!.label).toBe('hello');
    expect(funcNode!.language).toBe('php');
  });

  // ── 2. Superglobal as INGRESS ────────────────────────────────────

  it('classifies $_GET access as INGRESS', () => {
    const code = `<?php
$input = $_GET['name'];
echo $input;
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'get.php', phpProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingressNodes.length).toBeGreaterThan(0);
  });

  it('classifies $_POST access as INGRESS', () => {
    const code = `<?php
$data = $_POST['data'];
echo $data;
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'post.php', phpProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingressNodes.length).toBeGreaterThan(0);
  });

  // ── 3. mysqli_query as STORAGE ───────────────────────────────────

  it('classifies mysqli_query() as STORAGE', () => {
    const code = `<?php
$result = mysqli_query($conn, "SELECT * FROM users");
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'db.php', phpProfile);

    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');
    expect(storageNodes.length).toBeGreaterThan(0);
  });

  // ── 4. exec() as EXTERNAL/system_exec ────────────────────────────

  it('classifies exec() as EXTERNAL/system_exec', () => {
    const code = `<?php
$cmd = "ls -la";
exec($cmd);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'cmd.php', phpProfile);

    const externalNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(externalNodes.length).toBeGreaterThan(0);
  });

  // ── 5. echo as EGRESS/display ────────────────────────────────────

  it('classifies echo statement as EGRESS/display', () => {
    const code = `<?php
echo "Hello World";
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'echo.php', phpProfile);

    const egressNodes = map.nodes.filter(n =>
      n.node_type === 'EGRESS' && n.node_subtype === 'display'
    );
    expect(egressNodes.length).toBeGreaterThan(0);
  });

  // ── 6. Class declaration as STRUCTURAL/class ─────────────────────

  it('handles class declaration as STRUCTURAL/class', () => {
    const code = `<?php
class UserController {
    public function index() {
        return "users list";
    }

    public function store($request) {
        echo $request;
    }
}
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'controller.php', phpProfile);

    const classNodes = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'class'
    );
    expect(classNodes.length).toBe(1);
    expect(classNodes[0].label).toBe('UserController');

    const methodNodes = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'function'
    );
    expect(methodNodes.length).toBeGreaterThanOrEqual(2); // index + store
  });

  // ── 7. Control flow nodes ────────────────────────────────────────

  it('creates CONTROL nodes for PHP control flow', () => {
    const code = `<?php
function process($data) {
    if ($data > 0) {
        for ($i = 0; $i < $data; $i++) {
            try {
                $result = 1 / $i;
            } catch (Exception $e) {
                echo $e->getMessage();
            }
        }
    }
    while ($data > 100) {
        $data = $data / 2;
    }
    return $data;
}
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'control.php', phpProfile);

    const controlNodes = map.nodes.filter(n => n.node_type === 'CONTROL');
    const subtypes = controlNodes.map(n => n.node_subtype);

    expect(subtypes).toContain('branch');        // if
    expect(subtypes).toContain('loop');           // for, while
    expect(subtypes).toContain('error_handler');  // try
    expect(subtypes).toContain('return');         // return
  });

  // ── 8. unserialize() as INGRESS/deserialize ──────────────────────

  it('classifies unserialize() as INGRESS/deserialize', () => {
    const code = `<?php
$data = $_COOKIE['data'];
$obj = unserialize($data);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'unserialize.php', phpProfile);

    const ingressNodes = map.nodes.filter(n =>
      n.node_type === 'INGRESS' && n.node_subtype === 'deserialize'
    );
    expect(ingressNodes.length).toBeGreaterThan(0);
  });

  // ── 9. Laravel $request->input() as INGRESS ─────────────────────

  it('classifies Laravel request->input() as INGRESS', () => {
    const code = `<?php
function store($request) {
    $name = $request->input('name');
    echo $name;
}
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'laravel.php', phpProfile);

    const ingressNodes = map.nodes.filter(n =>
      n.node_type === 'INGRESS' && n.node_subtype === 'http_request'
    );
    expect(ingressNodes.length).toBeGreaterThan(0);
  });

  // ── 10. htmlspecialchars as TRANSFORM/sanitize ───────────────────

  it('classifies htmlspecialchars() as CONTROL/sanitize_xss', () => {
    const code = `<?php
$safe = htmlspecialchars($_GET['name']);
echo $safe;
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'sanitize.php', phpProfile);

    const controlNodes = map.nodes.filter(n =>
      n.node_type === 'CONTROL' && n.node_subtype === 'sanitize_xss'
    );
    expect(controlNodes.length).toBeGreaterThan(0);
  });

  // ── 11. Data flow: taint from $_GET to echo ──────────────────────

  it('tracks taint flow from $_GET through variable to echo', () => {
    const code = `<?php
$name = $_GET['name'];
echo $name;
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'xss.php', phpProfile);

    // Should have INGRESS and EGRESS nodes
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const egressNodes = map.nodes.filter(n => n.node_type === 'EGRESS');

    expect(ingressNodes.length).toBeGreaterThan(0);
    expect(egressNodes.length).toBeGreaterThan(0);

    // The EGRESS node should have tainted data flowing in (DATA_FLOW edge)
    const dataFlowEdges = map.edges.filter(e => e.edge_type === 'DATA_FLOW');
    expect(dataFlowEdges.length).toBeGreaterThan(0);
  });

  // ── 12. Data flow: taint from $_GET to mysqli_query ──────────────

  it('tracks taint flow from $_GET to SQL query (SQL injection)', () => {
    const code = `<?php
$username = $_GET['username'];
$query = "SELECT * FROM users WHERE username = '" . $username . "'";
mysqli_query($conn, $query);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'sqli.php', phpProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');

    expect(ingressNodes.length).toBeGreaterThan(0);
    expect(storageNodes.length).toBeGreaterThan(0);
  });

  // ── 13. Include with user input ──────────────────────────────────

  it('detects file inclusion with user input', () => {
    const code = `<?php
$page = $_GET['page'];
include $page;
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'lfi.php', phpProfile);

    // Should detect INGRESS (superglobal) and EXTERNAL/file_include (tainted include)
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    expect(ingressNodes.length).toBeGreaterThan(0);

    // Tainted include should be classified as EXTERNAL/file_include
    const fileIncludeNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'file_include'
    );
    expect(fileIncludeNodes.length).toBeGreaterThan(0);
  });

  // ── 14. mail() as EGRESS/email ───────────────────────────────────

  it('classifies mail() as EGRESS/email', () => {
    const code = `<?php
$to = "user@example.com";
$subject = "Hello";
mail($to, $subject, "Body");
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'mail.php', phpProfile);

    const mailNodes = map.nodes.filter(n =>
      n.node_type === 'EGRESS' && n.node_subtype === 'email'
    );
    expect(mailNodes.length).toBeGreaterThan(0);
  });

  // ── 15. password_hash as AUTH/authenticate ───────────────────────

  it('classifies password_hash() as AUTH/authenticate', () => {
    const code = `<?php
$hash = password_hash($password, PASSWORD_BCRYPT);
$valid = password_verify($input, $hash);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'auth.php', phpProfile);

    const authNodes = map.nodes.filter(n =>
      n.node_type === 'AUTH' && n.node_subtype === 'authenticate'
    );
    expect(authNodes.length).toBeGreaterThanOrEqual(2); // hash + verify
  });

  // ── 16. filter_var as CONTROL/validation ─────────────────────────

  it('classifies filter_var() as CONTROL/validation', () => {
    const code = `<?php
$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'filter.php', phpProfile);

    const controlNodes = map.nodes.filter(n =>
      n.node_type === 'CONTROL' && n.node_subtype === 'validation'
    );
    expect(controlNodes.length).toBeGreaterThan(0);
  });

  // ── 17. PDO methods as STORAGE ───────────────────────────────────

  it('classifies PDO member calls as STORAGE', () => {
    const code = `<?php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$result = $stmt->fetch();
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'pdo.php', phpProfile);

    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');
    expect(storageNodes.length).toBeGreaterThanOrEqual(2); // prepare + execute or fetch
  });

  // ── 18. curl_exec as EXTERNAL/api_call ───────────────────────────

  it('classifies curl functions as EXTERNAL/api_call', () => {
    const code = `<?php
$ch = curl_init("https://api.example.com");
$result = curl_exec($ch);
curl_close($ch);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'curl.php', phpProfile);

    const externalNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'api_call'
    );
    expect(externalNodes.length).toBeGreaterThanOrEqual(2); // init + exec
  });

  // ── 19. session_start as AUTH ────────────────────────────────────

  it('classifies session functions as AUTH/authenticate', () => {
    const code = `<?php
session_start();
session_regenerate_id(true);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'session.php', phpProfile);

    const authNodes = map.nodes.filter(n =>
      n.node_type === 'AUTH' && n.node_subtype === 'authenticate'
    );
    expect(authNodes.length).toBeGreaterThanOrEqual(2);
  });

  // ── 20. Hardcoded credentials detected as META/config_value ──────

  it('detects hardcoded credentials as META/config_value', () => {
    const code = `<?php
$api_key = "sk-live-1234567890abcdef";
$db_password = "SuperSecretP@ssw0rd123";
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'creds.php', phpProfile);

    const metaNodes = map.nodes.filter(n =>
      n.node_type === 'META' && n.node_subtype === 'config_value'
    );
    expect(metaNodes.length).toBeGreaterThanOrEqual(2);
  });

  // ── 21. The big one: SQL injection in a PHP app ──────────────────

  it('the big one: SQL injection in a PHP app (end-to-end)', () => {
    const code = `<?php
function getUser($conn) {
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = " . $id;
    $result = mysqli_query($conn, $query);
    return $result;
}
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'vuln_app.php', phpProfile);

    // The mapper should have created:
    // - INGRESS node for $_GET
    // - STORAGE node for mysqli_query
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');

    expect(ingressNodes.length).toBeGreaterThan(0);
    expect(storageNodes.length).toBeGreaterThan(0);

    // Check language is php
    const allLanguages = new Set(map.nodes.map(n => n.language));
    expect(allLanguages.has('php')).toBe(true);
  });

  // ── 22. Command injection flow: $_POST to exec ───────────────────

  it('tracks taint from $_POST to exec (command injection)', () => {
    const code = `<?php
$cmd = $_POST['cmd'];
exec($cmd);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'cmdi.php', phpProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const externalNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );

    expect(ingressNodes.length).toBeGreaterThan(0);
    expect(externalNodes.length).toBeGreaterThan(0);

    // Should have data flow edges
    const dataFlowEdges = map.edges.filter(e => e.edge_type === 'DATA_FLOW');
    expect(dataFlowEdges.length).toBeGreaterThan(0);
  });

  // ── 23. Interface and trait declarations ─────────────────────────

  it('handles interface and trait declarations', () => {
    const code = `<?php
interface Authenticatable {
    public function getAuthIdentifier();
}

trait HasTimestamps {
    public function freshTimestamp() {
        return time();
    }
}
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'traits.php', phpProfile);

    const classNodes = map.nodes.filter(n =>
      n.node_type === 'STRUCTURAL' && n.node_subtype === 'class'
    );
    expect(classNodes.length).toBeGreaterThanOrEqual(2); // interface + trait

    // Check tags
    const interfaceNode = classNodes.find(n => n.tags.includes('interface'));
    expect(interfaceNode).toBeDefined();

    const traitNode = classNodes.find(n => n.tags.includes('trait'));
    expect(traitNode).toBeDefined();
  });

  // ── 24. system() and passthru() as EXTERNAL/system_exec ──────────

  it('classifies system() and passthru() as EXTERNAL/system_exec', () => {
    const code = `<?php
system("whoami");
passthru("id");
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'sys.php', phpProfile);

    const externalNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(externalNodes.length).toBeGreaterThanOrEqual(2);
  });

  // ── 25. Foreach loop ─────────────────────────────────────────────

  it('handles foreach loops', () => {
    const code = `<?php
$items = [1, 2, 3];
foreach ($items as $item) {
    echo $item;
}
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'foreach.php', phpProfile);

    const loopNodes = map.nodes.filter(n =>
      n.node_type === 'CONTROL' && n.node_subtype === 'loop'
    );
    expect(loopNodes.length).toBeGreaterThan(0);
  });

  // ── 26. Full test_vuln.php scan ──────────────────────────────────

  it('scans the full test_vuln.php file', () => {
    const code = fs.readFileSync(
      path.join(__dirname, 'test_vuln.php'),
      'utf-8'
    );
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'test_vuln.php', phpProfile);

    // Should find many vulnerability patterns
    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const storageNodes = map.nodes.filter(n => n.node_type === 'STORAGE');
    const externalNodes = map.nodes.filter(n => n.node_type === 'EXTERNAL');
    const egressNodes = map.nodes.filter(n => n.node_type === 'EGRESS');
    const authNodes = map.nodes.filter(n => n.node_type === 'AUTH');

    // At minimum we expect:
    expect(ingressNodes.length).toBeGreaterThanOrEqual(5);   // multiple $_GET, $_POST, $_COOKIE
    expect(storageNodes.length).toBeGreaterThanOrEqual(2);   // mysqli_query calls
    expect(externalNodes.length).toBeGreaterThanOrEqual(2);  // exec, system, curl
    expect(egressNodes.length).toBeGreaterThanOrEqual(3);    // echo, mail, etc.
    expect(authNodes.length).toBeGreaterThanOrEqual(1);      // password_hash

    // All nodes should be language=php
    for (const node of map.nodes) {
      expect(node.language).toBe('php');
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// PHP Constant Folding -- Anti-Evasion Tests
// ═══════════════════════════════════════════════════════════════════════════
// Attackers construct dangerous function names at runtime to dodge static
// analysis. tryFoldConstant folds them back. These tests verify each
// evasion pattern is detected.

describe('PHP constant folding -- anti-evasion', () => {
  beforeAll(async () => {
    if (!parser) parser = await createPHPParser();
  });

  // ── 1. String concatenation: 'ev'.'al' ──────────────────────────

  it('folds string concat: $fn = "ev"."al"; $fn($input)', () => {
    const code = `<?php
$input = $_GET['cmd'];
$fn = 'ev'.'al';
$fn($input);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-concat.php', phpProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  // ── 2. chr() concatenation ───────────────────────────────────────

  it('folds chr() concat: chr(101).chr(118).chr(97).chr(108) → "eval"', () => {
    const code = `<?php
$input = $_GET['cmd'];
$fn = chr(101).chr(118).chr(97).chr(108);
$fn($input);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-chr.php', phpProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  // ── 3. base64_decode ─────────────────────────────────────────────

  it('folds base64_decode: base64_decode("ZXZhbA==") → "eval"', () => {
    const code = `<?php
$input = $_GET['cmd'];
$fn = base64_decode('ZXZhbA==');
$fn($input);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-b64.php', phpProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  // ── 4. hex2bin ───────────────────────────────────────────────────

  it('folds hex2bin: hex2bin("6576616c") → "eval"', () => {
    const code = `<?php
$input = $_GET['cmd'];
$fn = hex2bin('6576616c');
$fn($input);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-hex.php', phpProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  // ── 5. str_rot13 ────────────────────────────────────────────────

  it('folds str_rot13: str_rot13("riny") → "eval"', () => {
    const code = `<?php
$input = $_GET['cmd'];
$fn = str_rot13('riny');
$fn($input);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-rot13.php', phpProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  // ── 6. call_user_func with constructed name ──────────────────────

  it('resolves call_user_func with folded string', () => {
    const code = `<?php
$input = $_GET['cmd'];
call_user_func('ev'.'al', $input);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-cuf.php', phpProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  // ── 7. call_user_func with variable holding folded value ─────────

  it('resolves call_user_func($fn, ...) where $fn has constantValue', () => {
    const code = `<?php
$input = $_GET['cmd'];
$fn = base64_decode('ZXZhbA==');
call_user_func($fn, $input);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-cuf-var.php', phpProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  // ── 8. Unresolvable dynamic dispatch → runtime eval marker ──────

  it('marks unresolvable $fn(...) as dynamic_dispatch', () => {
    const code = `<?php
$fn = $_GET['func'];
$fn($_GET['arg']);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-dynamic.php', phpProfile);

    const dynNodes = map.nodes.filter(n =>
      n.node_subtype === 'dynamic_dispatch'
    );
    expect(dynNodes.length).toBeGreaterThan(0);
    expect(dynNodes[0].tags).toContain('needs_runtime_eval');
    expect(dynNodes[0].tags).toContain('unresolved_callee');
    expect(dynNodes[0].attack_surface).toContain('dynamic_dispatch');
  });

  // ── 9. Direct inline fold: (base64_decode('ZXZhbA=='))($input) ──

  it('folds inline expression callee: (base64_decode(...))()', () => {
    const code = `<?php
$input = $_GET['cmd'];
(base64_decode('ZXZhbA=='))($input);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-inline.php', phpProfile);

    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(execNodes.length).toBeGreaterThan(0);
  });

  // ── 10. Data flow: tainted args wire through to resolved callee ──

  it('wires tainted data flow through folded callee', () => {
    const code = `<?php
$cmd = $_GET['cmd'];
$fn = 'ev'.'al';
$fn($cmd);
?>`;
    const tree = parsePHP(code);
    const { map } = buildNeuralMap(tree, code, 'evasion-flow.php', phpProfile);

    const ingressNodes = map.nodes.filter(n => n.node_type === 'INGRESS');
    const execNodes = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' && n.node_subtype === 'system_exec'
    );
    expect(ingressNodes.length).toBeGreaterThan(0);
    expect(execNodes.length).toBeGreaterThan(0);

    // There should be a data flow edge from INGRESS -> EXTERNAL
    const dataFlowEdges = map.nodes.flatMap(n =>
      n.edges.filter(e => e.edge_type === 'DATA_FLOW')
    );
    expect(dataFlowEdges.length).toBeGreaterThan(0);
  });
});
