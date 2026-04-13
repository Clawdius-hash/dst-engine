/**
 * PHP Callee Pattern Database
 *
 * Maps PHP function/method names to DST Neural Map node types.
 * Covers: stdlib, Laravel, Symfony, WordPress, PDO, mysqli, Guzzle,
 *         Eloquent, Doctrine, password_*, openssl_*, session_*.
 *
 * Sources:
 *   - corpus_audit_php.json (48 Category B + 185 Category A patterns)
 *   - PHP/Laravel/Symfony framework knowledge (heavy gap-filling)
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (PHP global functions) --------------------------------------

const DIRECT_CALLS: Record<string, CalleePattern> = {

  // == INGRESS ==
  // Superglobals are property access, not function calls -- handled by mapper.
  // These are functions that read external data.
  file_get_contents: { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  file:              { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  fopen:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  fread:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  fgets:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  fgetcsv:           { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  fgetc:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  readfile:          { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  glob:              { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  scandir:           { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  is_file:           { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  file_exists:       { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  is_dir:            { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  filesize:          { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  filetype:          { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  realpath:          { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  getenv:            { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: true },
  ini_get:           { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: true },
  php_ini_loaded_file: { nodeType: 'INGRESS', subtype: 'env_read',      tainted: false },
  getopt:            { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: true },
  readline:          { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },

  // Cacti / WordPress request input functions
  get_nfilter_request_var: { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  get_filter_request_var:  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  apache_request_headers:  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  getallheaders:           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  filter_input:            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // Procedural mysqli (these are direct function calls, not OOP method calls)
  mysqli_query:        { nodeType: 'STORAGE',   subtype: 'sql_query',    tainted: false },
  mysqli_real_query:   { nodeType: 'STORAGE',   subtype: 'sql_query',    tainted: false },
  mysqli_prepare:      { nodeType: 'STORAGE',   subtype: 'sql_query',    tainted: false },
  mysqli_real_escape_string: { nodeType: 'CONTROL',   subtype: 'sanitize_sql', tainted: false },
  mysqli_multi_query:  { nodeType: 'STORAGE',   subtype: 'sql_write',    tainted: false },
  mysqli_fetch_assoc:  { nodeType: 'STORAGE',   subtype: 'db_read',      tainted: false },
  mysqli_fetch_array:  { nodeType: 'STORAGE',   subtype: 'db_read',      tainted: false },
  mysqli_fetch_row:    { nodeType: 'STORAGE',   subtype: 'db_read',      tainted: false },
  mysqli_fetch_all:    { nodeType: 'STORAGE',   subtype: 'db_read',      tainted: false },
  mysqli_num_rows:     { nodeType: 'STORAGE',   subtype: 'db_read',      tainted: false },
  mysqli_connect:      { nodeType: 'STORAGE',   subtype: 'db_connect',   tainted: false },
  mysqli_close:        { nodeType: 'STORAGE',   subtype: 'db_connect',   tainted: false },
  // WordPress options API
  get_option:          { nodeType: 'STORAGE',   subtype: 'config_read',  tainted: true },
  update_option:       { nodeType: 'STORAGE',   subtype: 'config_write', tainted: false },

  // Drupal database API
  db_query:            { nodeType: 'STORAGE',   subtype: 'sql_query',    tainted: false },

  // Deprecated mysql_* (still found in legacy code)
  mysql_query:         { nodeType: 'STORAGE',   subtype: 'sql_query',    tainted: false },
  mysql_real_escape_string: { nodeType: 'CONTROL',   subtype: 'sanitize_sql', tainted: false },
  mysql_fetch_assoc:   { nodeType: 'STORAGE',   subtype: 'db_read',      tainted: false },
  mysql_fetch_array:   { nodeType: 'STORAGE',   subtype: 'db_read',      tainted: false },

  // Deserialization
  unserialize:       { nodeType: 'INGRESS',   subtype: 'deserialize',   tainted: true },
  json_decode:       { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  simplexml_load_string: { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  simplexml_load_file: { nodeType: 'INGRESS', subtype: 'deserialize',   tainted: false },
  yaml_parse:        { nodeType: 'INGRESS',   subtype: 'deserialize',   tainted: true },

  // == EGRESS ==
  echo:              { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  print:             { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  var_dump:          { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  print_r:           { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  var_export:        { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  header:            { nodeType: 'EGRESS',    subtype: 'http_response', tainted: false },
  http_response_code:{ nodeType: 'EGRESS',    subtype: 'http_response', tainted: false },
  setcookie:         { nodeType: 'EGRESS',    subtype: 'http_response', tainted: false },
  setrawcookie:      { nodeType: 'EGRESS',    subtype: 'http_response', tainted: false },
  file_put_contents: { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  fwrite:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  fputs:             { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  fputcsv:           { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  fclose:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  copy:              { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  rename:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  unlink:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  rmdir:             { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  mkdir:             { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  chmod:             { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  chown:             { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  tempnam:           { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  tmpfile:           { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  json_encode:       { nodeType: 'EGRESS',    subtype: 'serialize',     tainted: false },
  serialize:         { nodeType: 'EGRESS',    subtype: 'serialize',     tainted: false },
  yaml_emit:         { nodeType: 'EGRESS',    subtype: 'serialize',     tainted: false },

  // Drupal render
  drupal_render:     { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },

  // Email
  mail:              { nodeType: 'EGRESS',    subtype: 'email',         tainted: false },

  // == EXTERNAL ==
  // System execution
  exec:              { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  system:            { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  passthru:          { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  shell_exec:        { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  popen:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  proc_open:         { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  eval:              { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  assert:            { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  preg_replace:      { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },

  // cURL
  curl_init:         { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  curl_exec:         { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  curl_setopt:       { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  curl_setopt_array: { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  curl_multi_exec:   { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  curl_close:        { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },

  // Socket
  fsockopen:         { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  stream_socket_client: { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // == TRANSFORM ==
  // Encoding / escaping
  escapeshellarg:    { nodeType: 'TRANSFORM', subtype: 'sanitize_shell',      tainted: false },
  escapeshellcmd:    { nodeType: 'TRANSFORM', subtype: 'sanitize_shell',      tainted: false },
  htmlspecialchars:  { nodeType: 'CONTROL',   subtype: 'sanitize_xss',  tainted: false },
  htmlentities:      { nodeType: 'CONTROL',   subtype: 'sanitize_xss',  tainted: false },

  // WordPress output escaping
  esc_html:          { nodeType: 'TRANSFORM', subtype: 'sanitize_html',      tainted: false },
  esc_attr:          { nodeType: 'TRANSFORM', subtype: 'sanitize_html',      tainted: false },
  esc_url:           { nodeType: 'TRANSFORM', subtype: 'sanitize_html',      tainted: false },

  // WordPress input sanitization
  sanitize_text_field: { nodeType: 'TRANSFORM', subtype: 'sanitize_html',    tainted: false },
  wp_kses:           { nodeType: 'TRANSFORM', subtype: 'sanitize_html',      tainted: false },
  htmlspecialchars_decode: { nodeType: 'TRANSFORM', subtype: 'encode',  tainted: false },
  html_entity_decode:{ nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  strip_tags:        { nodeType: 'CONTROL',   subtype: 'sanitize_html', tainted: false },
  addslashes:        { nodeType: 'CONTROL',   subtype: 'sanitize_sql',  tainted: false },
  stripslashes:      { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  urlencode:         { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  urldecode:         { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  rawurlencode:      { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  rawurldecode:      { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  base64_encode:     { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  base64_decode:     { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  quoted_printable_encode: { nodeType: 'TRANSFORM', subtype: 'encode',  tainted: false },
  quoted_printable_decode: { nodeType: 'TRANSFORM', subtype: 'encode',  tainted: false },
  utf8_encode:       { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  utf8_decode:       { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  mb_convert_encoding: { nodeType: 'TRANSFORM', subtype: 'encode',      tainted: false },
  iconv:             { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },

  // String processing
  str_replace:       { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  str_ireplace:      { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  substr:            { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  substr_replace:    { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  strtolower:        { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  strtoupper:        { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  ucfirst:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  lcfirst:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  ucwords:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  trim:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  ltrim:             { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  rtrim:             { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  explode:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  implode:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  join:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  sprintf:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  number_format:     { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  wordwrap:          { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  nl2br:             { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  str_pad:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  str_repeat:        { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  chunk_split:       { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },

  // Regex
  preg_match:        { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  preg_match_all:    { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  preg_split:        { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },

  // PHP input sanitizers / type coercers (break SQL taint path) (CWE-89 false positive reduction)
  intval:            { nodeType: 'CONTROL',   subtype: 'sanitize_numeric', tainted: false },
  floatval:          { nodeType: 'CONTROL',   subtype: 'sanitize_numeric', tainted: false },
  doubleval:         { nodeType: 'CONTROL',   subtype: 'sanitize_numeric', tainted: false },
  is_numeric:        { nodeType: 'CONTROL',   subtype: 'validate_numeric', tainted: false },
  ctype_digit:       { nodeType: 'CONTROL',   subtype: 'validate_numeric', tainted: false },
  ctype_alpha:       { nodeType: 'CONTROL',   subtype: 'validate_alpha',   tainted: false },
  filter_var:        { nodeType: 'CONTROL',   subtype: 'sanitize',         tainted: false },
  pg_escape_string:  { nodeType: 'CONTROL',   subtype: 'sanitize_sql',     tainted: false },

  // Type casting
  strval:            { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  boolval:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  settype:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },

  // Crypto / hashing
  hash:              { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  hash_hmac:         { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  md5:               { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  sha1:              { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  crc32:             { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  crypt:             { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  openssl_encrypt:   { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  openssl_decrypt:   { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  openssl_sign:      { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  openssl_verify:    { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  openssl_random_pseudo_bytes: { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  random_bytes:      { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  random_int:        { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  sodium_crypto_secretbox: { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  sodium_crypto_secretbox_open: { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  sodium_crypto_box: { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  sodium_crypto_box_open: { nodeType: 'TRANSFORM', subtype: 'encrypt',  tainted: false },

  // Array transforms
  array_map:         { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_filter:      { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_reduce:      { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_merge:       { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_slice:       { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_splice:      { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_unique:      { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_values:      { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_keys:        { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_flip:        { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_reverse:     { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_sort:        { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  sort:              { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  usort:             { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  ksort:             { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_column:      { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_combine:     { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_chunk:       { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_diff:        { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  array_intersect:   { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  compact:           { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  extract:           { nodeType: 'INGRESS',   subtype: 'mass_assign',    tainted: true },

  // URL parsing
  parse_url:         { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  parse_str:         { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  http_build_query:  { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },

  // Date
  date:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  strtotime:         { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  mktime:            { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  time:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },

  // == CONTROL ==
  // Validation
  filter_var:        { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  filter_input:      { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  filter_input_array:{ nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  isset:             { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  empty:             { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  is_null:           { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  is_array:          { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  is_string:         { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  is_int:            { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  is_numeric:        { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  is_bool:           { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  is_object:         { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  is_callable:       { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  in_array:          { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  array_key_exists:  { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  ctype_alpha:       { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  ctype_digit:       { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  ctype_alnum:       { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },

  // PHP 8.0 string validation (replaced strpos() !== false idiom)
  str_contains:      { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  str_starts_with:   { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  str_ends_with:     { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },

  // Flow control
  exit:              { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  die:               { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  trigger_error:     { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  set_error_handler: { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  set_exception_handler: { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  register_shutdown_function: { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  sleep:             { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  usleep:            { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  pcntl_fork:        { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  pcntl_signal:      { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  pcntl_wait:        { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },

  // == AUTH ==
  // WordPress authorization
  current_user_can:  { nodeType: 'AUTH',      subtype: 'authorize',     tainted: false },
  wp_verify_nonce:   { nodeType: 'AUTH',      subtype: 'csrf_check',    tainted: false },

  password_hash:     { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  password_verify:   { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  password_needs_rehash: { nodeType: 'AUTH',  subtype: 'authenticate',  tainted: false },
  session_start:     { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  session_destroy:   { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  session_regenerate_id: { nodeType: 'AUTH',  subtype: 'authenticate',  tainted: false },

  // == STRUCTURAL ==
  // WordPress hook system
  add_action:        { nodeType: 'STRUCTURAL', subtype: 'event_handler', tainted: false },
  add_filter:        { nodeType: 'STRUCTURAL', subtype: 'event_handler', tainted: false },

  require:           { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  require_once:      { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  include:           { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  include_once:      { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  spl_autoload_register: { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  class_exists:      { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  interface_exists:  { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },

  // == META ==
  error_log:         { nodeType: 'META',      subtype: 'logging',       tainted: false },
  syslog:            { nodeType: 'META',      subtype: 'logging',       tainted: false },
  openlog:           { nodeType: 'META',      subtype: 'logging',       tainted: false },
  ini_set:           { nodeType: 'META',      subtype: 'config',        tainted: false },
  putenv:            { nodeType: 'META',      subtype: 'config',        tainted: false },
  phpinfo:           { nodeType: 'META',      subtype: 'debug',         tainted: false },
  debug_print_backtrace: { nodeType: 'META',  subtype: 'debug',         tainted: false },
  debug_backtrace:   { nodeType: 'META',      subtype: 'debug',         tainted: false },
  xdebug_break:      { nodeType: 'META',      subtype: 'debug',         tainted: false },
};

// -- Member calls (object->method / Class::method) ----------------------------

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // == INGRESS ==

  // -- Laravel Request --
  'request.input':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.get':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.post':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.query':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.all':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.only':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.except':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.file':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.header':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.cookie':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.ip':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.path':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.url':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.fullUrl':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.method':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.json':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.validate':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.validated':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.input':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Symfony Request --
  'Request.get':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.query':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.request':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.getContent':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.headers':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.cookies':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.files':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.server':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Symfony Form Component --
  'form.handleRequest':     { nodeType: 'INGRESS', subtype: 'form_input',    tainted: true },
  'form.getData':           { nodeType: 'INGRESS', subtype: 'form_input',    tainted: true },

  // -- Slim / PSR-7 Request --
  'request.getParam':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.getParsedBody':  { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // == EGRESS ==

  // -- Laravel Response --
  'response.json':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Response.json':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.download':      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.file':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.redirect':      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.view':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Slim / PSR-7 Response --
  'response.write':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Laravel helpers --
  'view':                   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'redirect':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'back':                   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'abort':                  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Symfony Response --
  'Response.setContent':    { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'JsonResponse':           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'RedirectResponse':       { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'BinaryFileResponse':     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'StreamedResponse':       { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Symfony Twig --
  'Environment.render':     { nodeType: 'TRANSFORM', subtype: 'template_render', tainted: false },
  'Environment.display':    { nodeType: 'EGRESS',    subtype: 'display',          tainted: false },

  // -- Laravel Mail --
  'Mail.send':              { nodeType: 'EGRESS', subtype: 'email',         tainted: false },
  'Mail.to':                { nodeType: 'EGRESS', subtype: 'email',         tainted: false },

  // -- Logging --
  'Log.info':               { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.debug':              { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.warning':            { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.error':              { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.critical':           { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.emergency':          { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.alert':              { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'Log.notice':             { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.info':            { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.debug':           { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.warning':         { nodeType: 'META',   subtype: 'logging',       tainted: false },
  'logger.error':           { nodeType: 'META',   subtype: 'logging',       tainted: false },

  // == EXTERNAL ==

  // -- Laravel HTTP Client --
  'Http.get':               { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'Http.post':              { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'Http.put':               { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'Http.delete':            { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'Http.patch':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'Http.head':              { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- Guzzle --
  'client.get':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'client.post':            { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'client.put':             { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'client.delete':          { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'client.request':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'GuzzleHttp.Client':      { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- Symfony HttpClient --
  'HttpClient.request':     { nodeType: 'EXTERNAL', subtype: 'api_call',      tainted: false },

  // -- Symfony Messenger --
  'MessageBusInterface.dispatch': { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },

  // -- Laravel Queue --
  'Queue.push':             { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'dispatch':               { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },

  // == STORAGE ==

  // -- WordPress $wpdb --
  'wpdb.query':             { nodeType: 'STORAGE', subtype: 'sql_write',    tainted: false },
  'wpdb.prepare':           { nodeType: 'CONTROL', subtype: 'sql_sanitize', tainted: false },
  'wpdb.get_results':       { nodeType: 'STORAGE', subtype: 'sql_query',    tainted: true },

  // -- PDO --
  'pdo.query':              { nodeType: 'STORAGE', subtype: 'sql_query',    tainted: false },
  'pdo.exec':               { nodeType: 'STORAGE', subtype: 'sql_write',    tainted: false },
  'pdo.prepare':            { nodeType: 'STORAGE', subtype: 'sql_query',    tainted: false },
  'pdo.beginTransaction':   { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'pdo.commit':             { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'pdo.rollBack':           { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'stmt.execute':           { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'stmt.fetch':             { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'stmt.fetchAll':          { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'stmt.fetchColumn':       { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },

  // -- Doctrine ORM / DBAL --
  'EntityManager.createQuery': { nodeType: 'STORAGE', subtype: 'dql_query',  tainted: false },
  'connection.executeQuery':   { nodeType: 'STORAGE', subtype: 'sql_query',   tainted: false },

  // -- mysqli --
  'mysqli.query':           { nodeType: 'STORAGE', subtype: 'sql_query',    tainted: false },
  'mysqli.prepare':         { nodeType: 'STORAGE', subtype: 'sql_query',    tainted: false },
  'mysqli.real_escape_string': { nodeType: 'TRANSFORM', subtype: 'sanitize_sql', tainted: false },
  'mysqli.multi_query':     { nodeType: 'STORAGE', subtype: 'sql_write',    tainted: false },
  'mysqli.begin_transaction': { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'mysqli.commit':          { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },

  // -- Laravel Eloquent --
  'DB.table':               { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'DB.select':              { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'DB.insert':              { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DB.update':              { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DB.delete':              { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DB.statement':           { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DB.raw':                 { nodeType: 'EXTERNAL', subtype: 'raw_sql',     tainted: false },
  'DB.unprepared':          { nodeType: 'EXTERNAL', subtype: 'raw_sql',     tainted: false },
  'DB.transaction':         { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DB.beginTransaction':    { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DB.commit':              { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DB.rollBack':            { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },

  // -- Laravel Eloquent raw expression methods (bypass parameterization) --
  'query.whereRaw':         { nodeType: 'EXTERNAL', subtype: 'raw_sql',     tainted: false },
  'query.selectRaw':        { nodeType: 'EXTERNAL', subtype: 'raw_sql',     tainted: false },
  'query.orderByRaw':       { nodeType: 'EXTERNAL', subtype: 'raw_sql',     tainted: false },
  'query.havingRaw':        { nodeType: 'EXTERNAL', subtype: 'raw_sql',     tainted: false },
  'query.groupByRaw':       { nodeType: 'EXTERNAL', subtype: 'raw_sql',     tainted: false },

  // -- Laravel Cache --
  'Cache.get':              { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'Cache.put':              { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'Cache.has':              { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'Cache.forget':           { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'Cache.remember':         { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'Cache.rememberForever':  { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },

  // -- Redis --
  'Redis.get':              { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'Redis.set':              { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'Redis.del':              { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'Redis.hget':             { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'Redis.hset':             { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },

  // == CONTROL ==

  // -- Laravel Validator --
  'Validator.make':         { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'Validator.validate':     { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },

  // -- Laravel Middleware --
  'Route.middleware':       { nodeType: 'CONTROL', subtype: 'guard',        tainted: false },

  // == AUTH ==

  // -- Laravel Auth --
  'Auth.check':             { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'Auth.user':              { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'Auth.id':                { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'Auth.attempt':           { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'Auth.login':             { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'Auth.logout':            { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'Auth.guard':             { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'Gate.allows':            { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'Gate.denies':            { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'Gate.authorize':         { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },

  // -- Symfony Security --
  'Security.getUser':       { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'Security.isGranted':     { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'AccessDecisionManager.decide': { nodeType: 'AUTH', subtype: 'authorize', tainted: false },

  // -- JWT --
  'JWT.encode':             { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'JWT.decode':             { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'JWTAuth.attempt':        { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'JWTAuth.parseToken':     { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },

  // -- Laravel Route --
  'Route.get':              { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'Route.post':             { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'Route.put':              { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'Route.delete':           { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'Route.patch':            { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'Route.resource':         { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'Route.group':            { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },

  // -- META --
  'Config.get':             { nodeType: 'META', subtype: 'config',          tainted: false },
  'Config.set':             { nodeType: 'META', subtype: 'config',          tainted: false },
  'config':                 { nodeType: 'META', subtype: 'config',          tainted: false },
  'App.environment':        { nodeType: 'META', subtype: 'config',          tainted: false },

  // -- PHP 8.1 Enums (backed enum validation) --
  'Enum.from':              { nodeType: 'CONTROL', subtype: 'validation',     tainted: false },
  'Enum.tryFrom':           { nodeType: 'CONTROL', subtype: 'validation',     tainted: false },

  // -- PHP 8.1 Fibers (cooperative concurrency) --
  'Fiber.start':            { nodeType: 'CONTROL', subtype: 'concurrency',    tainted: false },
  'Fiber.resume':           { nodeType: 'CONTROL', subtype: 'concurrency',    tainted: false },
  'Fiber.suspend':          { nodeType: 'CONTROL', subtype: 'concurrency',    tainted: false },

  // -- PHP 8.0 Attributes / Reflection --
  'ReflectionAttribute.newInstance': { nodeType: 'META', subtype: 'reflection', tainted: false },

  // -- PHP 8.0 WeakMap (GC-friendly object caching) --
  'WeakMap.offsetSet':      { nodeType: 'STORAGE', subtype: 'cache_write',    tainted: false },
  'WeakMap.offsetGet':      { nodeType: 'STORAGE', subtype: 'cache_read',     tainted: false },
};

// -- Wildcard member calls ---------------------------------------------------

const STORAGE_READ_METHODS = new Set([
  'find', 'findOrFail', 'findMany', 'first', 'firstOrFail', 'firstOr',
  'firstWhere', 'where', 'get', 'all', 'pluck', 'count',
  'exists', 'doesntExist', 'max', 'min', 'avg', 'sum',
  'select', 'orderBy', 'groupBy', 'having', 'distinct',
  'limit', 'offset', 'skip', 'take', 'paginate', 'simplePaginate',
  'with', 'has', 'whereHas', 'withCount', 'load', 'loadMissing',
  'join', 'leftJoin', 'rightJoin', 'crossJoin',
  'chunk', 'each', 'cursor', 'lazy',
  'value', 'sole', 'toSql',
  'fetch', 'fetchAll', 'fetchColumn', 'fetchObject',
]);

const STORAGE_WRITE_METHODS = new Set([
  'create', 'insert', 'insertOrIgnore', 'insertGetId',
  'update', 'updateOrCreate', 'updateOrInsert', 'upsert',
  'delete', 'destroy', 'forceDelete', 'truncate',
  'save', 'push', 'increment', 'decrement', 'touch',
  'attach', 'detach', 'sync', 'syncWithoutDetaching', 'toggle',
  'associate', 'dissociate',
  'execute', 'exec',
]);

// Eloquent raw expression methods — bypass query builder parameterization.
// These are wildcard-matched against ANY object (Model::whereRaw, $query->whereRaw, etc.)
const RAW_SQL_METHODS = new Set([
  'whereRaw', 'selectRaw', 'orderByRaw', 'havingRaw', 'groupByRaw',
]);

// -- Lookup function ----------------------------------------------------------

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };

    // Single-name framework helpers
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

  // Wildcard: raw SQL methods (any object)
  if (RAW_SQL_METHODS.has(methodName)) {
    return { nodeType: 'EXTERNAL', subtype: 'raw_sql', tainted: false };
  }

  // Wildcard: storage methods
  if (STORAGE_READ_METHODS.has(methodName)) {
    if (!NON_DB_OBJECTS.has(objectName)) {
      return { nodeType: 'STORAGE', subtype: 'db_read', tainted: false };
    }
  }

  if (STORAGE_WRITE_METHODS.has(methodName)) {
    if (!NON_DB_OBJECTS.has(objectName)) {
      return { nodeType: 'STORAGE', subtype: 'db_write', tainted: false };
    }
  }

  return null;
}

const NON_DB_OBJECTS = new Set([
  'request', 'response', 'Request', 'Response',
  'this', 'self', 'static', 'parent',
  'app', 'config', 'env',
  'Auth', 'Gate', 'Log', 'Mail', 'Http', 'Route', 'Config',
  'Validator', 'Queue', 'Cache', 'Redis', 'Session',
  'form', 'Environment', 'HttpClient', 'MessageBusInterface', 'AccessDecisionManager',
  'Fiber', 'WeakMap', 'Enum', 'ReflectionAttribute',
  'arr', 'array', 'list', 'items', 'data', 'result', 'results',
  'str', 'string', 'text', 'path', 'url',
]);

// -- Sink patterns -----------------------------------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /\b(?:exec|passthru|shell_exec|system|popen)\s*\(\s*\$/,
  'CWE-89':  /(?:"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\$\w+|mysql_real_escape_string\s*\()/,
  'CWE-94':  /(?:\beval\s*\(\s*\$|preg_replace\s*\(\s*["']\/.*e["'])/,
  'CWE-502': /\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/,
  'CWE-798': /(?:api_key|secret|password|token)\s*=\s*["'][^"']{4,}["']/,
  'CWE-916': /\bmd5\s*\(\s*\$.*pass/,
  'CWE-918': /file_get_contents\s*\(\s*\$/,
  'CWE-22':  /(?:include|require|fopen|file_get_contents)\s*\(\s*\$_(?:GET|POST|REQUEST)/,
  // Laravel raw SQL injection: whereRaw/selectRaw/etc. with variable interpolation
  'CWE-89-RAW': /->(?:whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw)\s*\(\s*["'][^"']*\$\w+/,
  // DB::unprepared() with variable — always dangerous
  'CWE-89-UNPREP': /DB\s*::\s*unprepared\s*\(\s*["'][^"']*\$\w+/,
  // extract() on superglobal — mass assignment (CWE-915)
  'CWE-915': /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/,
  // header() with user input — HTTP response splitting (CWE-113)
  'CWE-113': /\bheader\s*\(\s*["'][^"']*["']\s*\.\s*\$/,
  // mail() with user-controlled additional headers — CRLF injection (CWE-93)
  'CWE-93':  /\bmail\s*\([^)]*,[^)]*,[^)]*,[^)]*,\s*\$/,
  // Doctrine DQL injection: createQuery() with string concatenation
  'CWE-89-DQL': /->createQuery\s*\(\s*["'][^"']*(?:\$\w+|["']\s*\.)/,
  // Doctrine DBAL raw executeQuery with concatenation
  'CWE-89-DBAL': /->executeQuery\s*\(\s*["'][^"']*\$\w+/,
  // Twig |raw filter on variable — XSS when variable is user input
  'CWE-79-TWIG-RAW': /\{\{\s*\w+\s*\|\s*raw\s*\}\}/,
  // Twig autoescape false block — all output in this block is unescaped
  'CWE-79-TWIG-AUTOESCAPE': /\{%\s*autoescape\s+false\s*%\}/,
};

// -- Safe patterns -----------------------------------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /(?:escapeshellarg|escapeshellcmd)\s*\(/,
  'CWE-89':  /(?:->prepare\s*\(|PDO::ATTR_EMULATE_PREPARES\s*=>\s*false)/,
  'CWE-94':  /preg_replace_callback\s*\(/,
  'CWE-502': /\bunserialize\s*\([^)]*\['allowed_classes'\s*=>/,
  'CWE-916': /(?:password_hash|password_verify|sodium_crypto_pwhash)\s*\(/,
  'CWE-918': /(?:filter_var\s*\([^)]*FILTER_VALIDATE_URL|parse_url\s*\()/,
  'CWE-22':  /(?:realpath\s*\(|basename\s*\()/,
  // Raw methods with binding arrays (second argument)
  'CWE-89-RAW': /->(?:whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw)\s*\(\s*["'][^"']*\?\s*["']\s*,\s*\[/,
  // extract() with safe flags
  'CWE-915': /\bextract\s*\([^)]*(?:EXTR_IF_EXISTS|EXTR_SKIP)/,
  // header() with hardcoded safe headers
  'CWE-113': /\bheader\s*\(\s*["'](?:Location|Content-Type|X-Frame-Options)\s*:/,
  // mail() via framework mailer instead of raw mail()
  'CWE-93':  /(?:Mail\s*::\s*(?:send|to)|new\s+PHPMailer|Swift_Message)/,
  // Doctrine parameterized DQL: createQuery() followed by setParameter
  'CWE-89-DQL': /->createQuery\s*\([^)]+\)\s*->\s*setParameter/,
  // Doctrine DBAL with binding array
  'CWE-89-DBAL': /->executeQuery\s*\(\s*["'][^"']*\?\s*["']\s*,\s*\[/,
  // Twig |escape or |e filter (explicit escaping)
  'CWE-79-TWIG-RAW': /\{\{\s*\w+\s*\|\s*(?:escape|e)\s*\}\}/,
};

// -- Pattern count -----------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size;
}
