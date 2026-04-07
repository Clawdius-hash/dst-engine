<?php
/**
 * PHP Vulnerability Showcase -- 12 classic PHP vulnerability patterns.
 * Used by DST PHP profile tests to verify detection coverage.
 *
 * DO NOT deploy this file. It is intentionally vulnerable.
 */

// ========================================================================
// 1. SQL Injection via string concatenation with mysqli_query (CWE-89)
// ========================================================================
function sqlInjection($conn) {
    $username = $_GET['username'];
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    $result = mysqli_query($conn, $query);
    return $result;
}

// ========================================================================
// 2. Cross-Site Scripting (XSS) via echo $_GET (CWE-79)
// ========================================================================
function xssReflected() {
    $name = $_GET['name'];
    echo "<h1>Hello, " . $name . "</h1>";
}

// ========================================================================
// 3. Command Injection via exec/system (CWE-78)
// ========================================================================
function commandInjection() {
    $cmd = $_POST['command'];
    exec($cmd);
    system($_GET['tool']);
}

// ========================================================================
// 4. File Inclusion via include $_GET (CWE-98 / LFI/RFI)
// ========================================================================
function fileInclusion() {
    $page = $_GET['page'];
    include $page;
}

// ========================================================================
// 5. Object Injection via unserialize (CWE-502)
// ========================================================================
function objectInjection() {
    $data = $_COOKIE['session_data'];
    $obj = unserialize($data);
    return $obj;
}

// ========================================================================
// 6. XXE via simplexml_load_string (CWE-611)
// ========================================================================
function xxeAttack() {
    $xml = file_get_contents('php://input');
    $doc = simplexml_load_string($xml);
    return $doc;
}

// ========================================================================
// 7. Path Traversal via file_get_contents (CWE-22)
// ========================================================================
function pathTraversal() {
    $file = $_GET['file'];
    $content = file_get_contents($file);
    echo $content;
}

// ========================================================================
// 8. CSRF -- no token verification (CWE-352)
// ========================================================================
function csrfVulnerable($conn) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $email = $_POST['email'];
        $query = "UPDATE users SET email = '" . $email . "' WHERE id = 1";
        mysqli_query($conn, $query);
    }
}

// ========================================================================
// 9. Type Juggling in auth (CWE-1024 -- PHP-specific)
// ========================================================================
function typeJugglingAuth() {
    $token = $_GET['token'];
    $secret = "0e123456789";
    // VULN: loose comparison -- "0e..." == "0e..." is true (both evaluate to 0)
    if ($token == $secret) {
        echo "Authenticated!";
    }
}

// ========================================================================
// 10. Email Header Injection via mail() (CWE-93)
// ========================================================================
function emailHeaderInjection() {
    $to = $_POST['to'];
    $subject = $_POST['subject'];
    $message = $_POST['message'];
    $headers = "From: noreply@example.com\r\nReply-To: " . $_POST['reply_to'];
    mail($to, $subject, $message, $headers);
}

// ========================================================================
// 11. Server-Side Request Forgery (SSRF) via curl (CWE-918)
// ========================================================================
function ssrfVulnerable() {
    $url = $_GET['url'];
    $ch = curl_init($url);
    curl_exec($ch);
    curl_close($ch);
}

// ========================================================================
// 12. Hardcoded credentials (CWE-798)
// ========================================================================
$db_password = "SuperSecretP@ssw0rd123";
$api_key = "sk-live-1234567890abcdef";

function connectDB() {
    global $db_password;
    $conn = mysqli_connect("localhost", "root", $db_password, "myapp");
    return $conn;
}

// ========================================================================
// SAFE patterns for comparison
// ========================================================================

// SAFE: Prepared statement
function safeSql($pdo) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_GET['id']]);
    return $stmt->fetchAll();
}

// SAFE: Escaped output
function safeEcho() {
    $name = $_GET['name'];
    echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
}

// SAFE: Escaped command
function safeCommand() {
    $file = $_GET['file'];
    $safe = escapeshellarg($file);
    exec("cat " . $safe);
}

// SAFE: password_hash instead of md5
function safePassword($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}
?>
