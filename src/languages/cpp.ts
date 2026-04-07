/**
 * C++ Callee Pattern Database
 *
 * Maps C++ function/method names to DST Neural Map node types.
 * Covers: stdlib (iostream, fstream, string, thread, mutex, chrono, filesystem,
 *         regex, algorithm), C runtime (stdio, stdlib, string.h), OpenSSL,
 *         libcurl, Boost (asio, log, algorithm), spdlog, glog, sqlite3, ODBC,
 *         libpq, mysql, leveldb, rocksdb, libsodium, httplib, gRPC,
 *         nlohmann::json, rapidjson.
 *
 * Sources:
 *   - corpus_audit_cpp.json (21 Category B patterns)
 *   - C++ stdlib/library knowledge (gap-filling)
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (single identifier) ----------------------------------------
// C++ uses many free functions from C runtime and global scope.

const DIRECT_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS -- external data entering the system
  // =========================================================================

  // -- C stdio input --
  getchar:    { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  getc:       { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  gets:       { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  fgetc:      { nodeType: 'INGRESS', subtype: 'file_read',    tainted: true },
  fgets:      { nodeType: 'INGRESS', subtype: 'file_read',    tainted: true },
  fread:      { nodeType: 'INGRESS', subtype: 'file_read',    tainted: true },
  scanf:      { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  fscanf:     { nodeType: 'INGRESS', subtype: 'file_read',    tainted: true },
  sscanf:     { nodeType: 'INGRESS', subtype: 'deserialize',  tainted: true },
  fopen:      { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  freopen:    { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  getenv:     { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  getline:    { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  read:       { nodeType: 'INGRESS', subtype: 'file_read',    tainted: true },
  recv:       { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  recvfrom:   { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  recvmsg:    { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },

  // =========================================================================
  // EGRESS -- data leaving the system
  // =========================================================================

  // -- C stdio output --
  printf:     { nodeType: 'EGRESS',    subtype: 'display',    tainted: false },
  fprintf:    { nodeType: 'EGRESS',    subtype: 'display',    tainted: false },
  puts:       { nodeType: 'EGRESS',    subtype: 'display',    tainted: false },
  fputs:      { nodeType: 'EGRESS',    subtype: 'file_write', tainted: false },
  fputc:      { nodeType: 'EGRESS',    subtype: 'file_write', tainted: false },
  fwrite:     { nodeType: 'EGRESS',    subtype: 'file_write', tainted: false },
  fclose:     { nodeType: 'EGRESS',    subtype: 'file_write', tainted: false },
  fflush:     { nodeType: 'EGRESS',    subtype: 'file_write', tainted: false },
  write:      { nodeType: 'EGRESS',    subtype: 'file_write', tainted: false },
  send:       { nodeType: 'EGRESS',    subtype: 'network_write', tainted: false },
  sendto:     { nodeType: 'EGRESS',    subtype: 'network_write', tainted: false },
  sendmsg:    { nodeType: 'EGRESS',    subtype: 'network_write', tainted: false },
  remove:     { nodeType: 'EGRESS',    subtype: 'file_write', tainted: false },
  rename:     { nodeType: 'EGRESS',    subtype: 'file_write', tainted: false },
  perror:     { nodeType: 'EGRESS',    subtype: 'display',    tainted: false },

  // =========================================================================
  // TRANSFORM -- data processing
  // =========================================================================

  // -- C string formatting --
  sprintf:    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  snprintf:   { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  vsnprintf:  { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  vsprintf:   { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- C string manipulation --
  strlen:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strcpy:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strncpy:    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strcat:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strncat:    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strcmp:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strncmp:    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strchr:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strrchr:    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strstr:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strtok:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  memcpy:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  memmove:    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  memset:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  memcmp:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- C number conversion --
  atoi:       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  atof:       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  atol:       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  atoll:      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strtol:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strtoul:    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strtod:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  strtof:     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- Memory allocation (STRUCTURAL) --
  malloc:     { nodeType: 'STRUCTURAL', subtype: 'memory',    tainted: false },
  calloc:     { nodeType: 'STRUCTURAL', subtype: 'memory',    tainted: false },
  realloc:    { nodeType: 'STRUCTURAL', subtype: 'memory',    tainted: false },
  free:       { nodeType: 'STRUCTURAL', subtype: 'memory',    tainted: false },

  // =========================================================================
  // CONTROL -- validation, flow, concurrency
  // =========================================================================

  assert:          { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  static_assert:   { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  exit:            { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  abort:           { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  _exit:           { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  quick_exit:      { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  atexit:          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  signal:          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  raise:           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  setjmp:          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  longjmp:         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // =========================================================================
  // EXTERNAL -- calls to outside systems / process spawning
  // =========================================================================

  system:     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  popen:      { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  pclose:     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  execl:      { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  execle:     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  execlp:     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  execv:      { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  execve:     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  execvp:     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  fork:       { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  waitpid:    { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  dlopen:     { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  dlsym:      { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // -- Socket primitives --
  socket:     { nodeType: 'EXTERNAL', subtype: 'network',     tainted: false },
  bind:       { nodeType: 'EXTERNAL', subtype: 'network',     tainted: false },
  listen:     { nodeType: 'EXTERNAL', subtype: 'network',     tainted: false },
  accept:     { nodeType: 'EXTERNAL', subtype: 'network',     tainted: false },
  connect:    { nodeType: 'EXTERNAL', subtype: 'network',     tainted: false },
};

// -- Member calls (namespace::function or object.method) ----------------------

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS -- external data entering the system
  // =========================================================================

  // -- std::cin / iostream input --
  'std::cin':                 { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'cin.get':                  { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'cin.getline':              { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'cin.read':                 { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'cin.readsome':             { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'cin.peek':                 { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'std::getline':             { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'std::wcin':                { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },

  // -- std::ifstream / file input --
  'std::ifstream':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.open':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.read':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.getline':         { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.get':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.peek':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.readsome':        { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.seekg':           { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.tellg':           { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.is_open':         { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.good':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.eof':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'ifstream.close':           { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },

  // -- std::fstream (read+write, classified as INGRESS for read mode) --
  'std::fstream':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'fstream.open':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'fstream.read':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'fstream.getline':          { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },

  // -- std::filesystem --
  'std::filesystem::exists':              { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::file_size':           { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::status':              { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::directory_iterator':  { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::recursive_directory_iterator': { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::is_regular_file':     { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::is_directory':        { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::last_write_time':     { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::current_path':        { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::absolute':            { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::canonical':           { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::relative':            { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'std::filesystem::temp_directory_path': { nodeType: 'INGRESS', subtype: 'file_read', tainted: false },
  'fs::exists':               { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'fs::file_size':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'fs::status':               { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'fs::directory_iterator':   { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'fs::is_regular_file':      { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'fs::is_directory':         { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'fs::current_path':         { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },

  // -- Environment / CLI --
  'std::getenv':              { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },

  // -- Deserialization (INGRESS) --
  'nlohmann::json::parse':    { nodeType: 'INGRESS', subtype: 'deserialize',  tainted: true },
  'json::parse':              { nodeType: 'INGRESS', subtype: 'deserialize',  tainted: true },
  'rapidjson::Document.Parse': { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true },

  // =========================================================================
  // EGRESS -- data leaving the system
  // =========================================================================

  // -- std::cout / iostream output --
  'std::cout':                { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'std::cerr':                { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'std::clog':                { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'std::wcout':               { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'std::wcerr':               { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'cout.write':               { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'cout.put':                 { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'cout.flush':               { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'cerr.write':               { nodeType: 'EGRESS', subtype: 'display',       tainted: false },

  // -- std::ofstream / file output --
  'std::ofstream':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ofstream.open':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ofstream.write':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ofstream.put':             { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ofstream.close':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ofstream.flush':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ofstream.seekp':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ofstream.tellp':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ofstream.is_open':         { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'ofstream.good':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },

  // -- std::fstream (write side) --
  'fstream.write':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'fstream.put':              { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'fstream.close':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'fstream.flush':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },

  // -- std::filesystem write operations --
  'std::filesystem::copy':              { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::copy_file':         { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::remove':            { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::remove_all':        { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::rename':            { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::create_directory':  { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::create_directories': { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::create_symlink':    { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::create_hard_link':  { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::resize_file':       { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'std::filesystem::permissions':       { nodeType: 'EGRESS', subtype: 'file_write', tainted: false },
  'fs::copy':                 { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'fs::copy_file':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'fs::remove':               { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'fs::remove_all':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'fs::rename':               { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'fs::create_directory':     { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'fs::create_directories':   { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },

  // -- Serialization (EGRESS) --
  'nlohmann::json::dump':     { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'json::dump':               { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },

  // =========================================================================
  // TRANSFORM -- data processing
  // =========================================================================

  // -- std::string methods --
  'std::string::substr':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::find':        { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::rfind':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::replace':     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::append':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::insert':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::erase':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::compare':     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::c_str':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::data':        { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::size':        { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::length':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::empty':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::clear':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::resize':      { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::find_first_of':    { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'std::string::find_last_of':     { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'std::string::find_first_not_of': { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'std::string::starts_with': { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::ends_with':   { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::string::contains':    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- std number conversion --
  'std::stoi':                { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::stol':                { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::stoll':               { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::stoul':               { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::stoull':              { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::stof':                { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::stod':                { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::stold':               { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::to_string':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::to_wstring':          { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- std::algorithm --
  'std::transform':           { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::sort':                { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::stable_sort':         { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::partial_sort':        { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::find':                { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::find_if':             { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::copy':                { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::copy_if':             { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::move':                { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::swap':                { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::reverse':             { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::unique':              { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::accumulate':          { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::reduce':              { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::for_each':            { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::count':               { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::count_if':            { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::min':                 { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::max':                 { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },
  'std::clamp':               { nodeType: 'TRANSFORM', subtype: 'calculate',  tainted: false },

  // -- std::regex --
  'std::regex_match':         { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'std::regex_search':        { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'std::regex_replace':       { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'std::regex':               { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // -- std::hash --
  'std::hash':                { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },

  // -- std::stringstream --
  'std::stringstream':        { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'std::istringstream':       { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'std::ostringstream':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'ss.str':                   { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- boost::algorithm --
  'boost::algorithm::to_lower':      { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::to_upper':      { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::trim':          { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::trim_left':     { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::trim_right':    { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::split':         { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::join':          { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::replace_all':   { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::replace_first': { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::starts_with':   { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::ends_with':     { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },
  'boost::algorithm::contains':      { nodeType: 'TRANSFORM', subtype: 'format', tainted: false },

  // -- nlohmann::json TRANSFORM operations --
  'json.dump':                { nodeType: 'TRANSFORM', subtype: 'serialize',  tainted: false },
  'json.get':                 { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'json.at':                  { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'json.value':               { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'json.contains':            { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'json.is_null':             { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'json.is_object':           { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'json.is_array':            { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'json.is_string':           { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'json.size':                { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // -- rapidjson --
  'rapidjson::Document':      { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'rapidjson::Writer':        { nodeType: 'TRANSFORM', subtype: 'serialize',  tainted: false },
  'rapidjson::StringBuffer':  { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- OpenSSL crypto (TRANSFORM -- raw crypto operations) --
  'EVP_DigestInit':           { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_DigestInit_ex':        { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_DigestUpdate':         { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_DigestFinal':          { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_DigestFinal_ex':       { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_EncryptInit_ex':       { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_EncryptUpdate':        { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_EncryptFinal_ex':      { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_DecryptInit_ex':       { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_DecryptUpdate':        { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_DecryptFinal_ex':      { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_MD_CTX_new':           { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_MD_CTX_free':          { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_CIPHER_CTX_new':       { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_CIPHER_CTX_free':      { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_aes_256_gcm':          { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_aes_256_cbc':          { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_sha256':               { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'EVP_sha512':               { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'SHA256':                   { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'SHA512':                   { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'SHA256_Init':              { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'SHA256_Update':            { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'SHA256_Final':             { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'HMAC':                     { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'HMAC_Init_ex':             { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'HMAC_Update':              { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'HMAC_Final':               { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'AES_set_encrypt_key':      { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'AES_set_decrypt_key':      { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'AES_encrypt':              { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'AES_decrypt':              { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'RAND_bytes':               { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'RAND_pseudo_bytes':        { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },

  // =========================================================================
  // CONTROL -- validation, concurrency, flow
  // =========================================================================

  // -- std::thread --
  'std::thread':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread.join':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread.detach':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'thread.joinable':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::jthread':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::mutex / locking --
  'std::mutex':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::recursive_mutex':     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::timed_mutex':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::shared_mutex':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mtx.lock':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mtx.unlock':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'mtx.try_lock':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::lock_guard':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::unique_lock':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::shared_lock':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::scoped_lock':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::condition_variable --
  'std::condition_variable':  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'cv.wait':                  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'cv.wait_for':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'cv.wait_until':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'cv.notify_one':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'cv.notify_all':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::async / future / promise --
  'std::async':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::future':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::promise':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'future.get':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'future.wait':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'future.wait_for':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'future.valid':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'promise.set_value':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'promise.get_future':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'promise.set_exception':    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::atomic --
  'std::atomic':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::atomic_flag':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.load':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.store':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.exchange':          { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.compare_exchange_strong': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.compare_exchange_weak':   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.fetch_add':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'atomic.fetch_sub':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- C++20 synchronization --
  'std::barrier':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::latch':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::counting_semaphore':  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::binary_semaphore':    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'latch.count_down':         { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'latch.wait':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'barrier.arrive_and_wait':  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'sem.acquire':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'sem.release':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- std::terminate --
  'std::terminate':           { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  'std::set_terminate':       { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },
  'std::unexpected':          { nodeType: 'CONTROL', subtype: 'guard',         tainted: false },

  // -- std::chrono / sleep --
  'std::this_thread::sleep_for':   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::this_thread::sleep_until': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::this_thread::yield':       { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::this_thread::get_id':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::chrono::steady_clock::now':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::chrono::system_clock::now':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::chrono::high_resolution_clock::now': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'std::chrono::duration_cast':    { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // =========================================================================
  // AUTH -- authentication and authorization
  // =========================================================================

  // -- OpenSSL certificate / verification --
  'SSL_CTX_new':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SSL_CTX_free':             { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SSL_CTX_set_verify':       { nodeType: 'AUTH', subtype: 'authorize',        tainted: false },
  'SSL_CTX_load_verify_locations': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'SSL_CTX_use_certificate_file':  { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'SSL_CTX_use_PrivateKey_file':   { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'SSL_new':                  { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SSL_connect':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SSL_accept':               { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SSL_read':                 { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SSL_write':                { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SSL_shutdown':             { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SSL_free':                 { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'SSL_get_verify_result':    { nodeType: 'AUTH', subtype: 'authorize',        tainted: false },
  'SSL_get_peer_certificate': { nodeType: 'AUTH', subtype: 'authorize',        tainted: false },
  'X509_verify_cert':         { nodeType: 'AUTH', subtype: 'authorize',        tainted: false },
  'X509_check_host':          { nodeType: 'AUTH', subtype: 'authorize',        tainted: false },

  // -- bcrypt (bcrypt.h / libbcrypt) --
  'bcrypt_hashpw':            { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'bcrypt_gensalt':           { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'bcrypt_checkpw':           { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- HMAC verification (AUTH context) --
  'HMAC_verify':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // -- libsodium --
  'crypto_pwhash':            { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'crypto_pwhash_str':        { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'crypto_pwhash_str_verify': { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'crypto_secretbox_easy':    { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'crypto_secretbox_open_easy': { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'crypto_sign_keypair':      { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'crypto_sign':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'crypto_sign_open':         { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'crypto_sign_verify_detached': { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'crypto_box_easy':          { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'crypto_box_open_easy':     { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'crypto_aead_aes256gcm_encrypt': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'crypto_aead_aes256gcm_decrypt': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'sodium_init':              { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },
  'randombytes_buf':          { nodeType: 'AUTH', subtype: 'authenticate',     tainted: false },

  // =========================================================================
  // STORAGE -- persistent state
  // =========================================================================

  // -- sqlite3 --
  'sqlite3_open':             { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'sqlite3_open_v2':          { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'sqlite3_close':            { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'sqlite3_close_v2':         { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'sqlite3_exec':             { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'sqlite3_prepare':          { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_prepare_v2':       { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_prepare_v3':       { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_step':             { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_finalize':         { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_reset':            { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_bind_text':        { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'sqlite3_bind_int':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'sqlite3_bind_double':      { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'sqlite3_bind_blob':        { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'sqlite3_bind_null':        { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'sqlite3_column_text':      { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_column_int':       { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_column_double':    { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_column_blob':      { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_column_count':     { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'sqlite3_errmsg':           { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },

  // -- ODBC --
  'SQLAllocHandle':           { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'SQLConnect':               { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'SQLDriverConnect':         { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'SQLDisconnect':            { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'SQLFreeHandle':            { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'SQLExecDirect':            { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'SQLExecute':               { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'SQLPrepare':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'SQLFetch':                 { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'SQLFetchScroll':           { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'SQLGetData':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'SQLBindParameter':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'SQLBindCol':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },

  // -- MySQL (mysql.h / libmysqlclient) --
  'mysql_init':               { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'mysql_real_connect':       { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'mysql_close':              { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'mysql_query':              { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'mysql_real_query':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'mysql_store_result':       { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'mysql_use_result':         { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'mysql_fetch_row':          { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'mysql_free_result':        { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'mysql_num_rows':           { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'mysql_num_fields':         { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'mysql_real_escape_string': { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'mysql_stmt_prepare':       { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'mysql_stmt_execute':       { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'mysql_stmt_bind_param':    { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'mysql_stmt_fetch':         { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'mysql_stmt_close':         { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },

  // -- PostgreSQL (libpq) --
  'PQconnectdb':              { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'PQfinish':                 { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'PQstatus':                 { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'PQexec':                   { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'PQexecParams':             { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'PQexecPrepared':           { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'PQprepare':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'PQgetvalue':               { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'PQntuples':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'PQnfields':                { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'PQclear':                  { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'PQescapeLiteral':          { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'PQescapeIdentifier':       { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },

  // -- LevelDB --
  'leveldb::DB::Open':        { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'leveldb::DB::Put':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'leveldb::DB::Get':         { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'leveldb::DB::Delete':      { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'leveldb::DB::NewIterator': { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'leveldb::WriteBatch':      { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },

  // -- RocksDB --
  'rocksdb::DB::Open':        { nodeType: 'STORAGE', subtype: 'db_connect',    tainted: false },
  'rocksdb::DB::Put':         { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'rocksdb::DB::Get':         { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'rocksdb::DB::Delete':      { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },
  'rocksdb::DB::NewIterator': { nodeType: 'STORAGE', subtype: 'db_read',       tainted: false },
  'rocksdb::WriteBatch':      { nodeType: 'STORAGE', subtype: 'db_write',      tainted: false },

  // -- std::fstream (persistent file storage) --
  'std::fstream::open':       { nodeType: 'STORAGE', subtype: 'file_store',    tainted: false },
  'std::fstream::close':      { nodeType: 'STORAGE', subtype: 'file_store',    tainted: false },
  'std::fstream::is_open':    { nodeType: 'STORAGE', subtype: 'file_store',    tainted: false },

  // =========================================================================
  // EXTERNAL -- calls to outside systems
  // =========================================================================

  // -- libcurl --
  'curl_easy_init':           { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_easy_setopt':         { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_easy_perform':        { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_easy_cleanup':        { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_easy_getinfo':        { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_easy_strerror':       { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_global_init':         { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_global_cleanup':      { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_multi_init':          { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_multi_add_handle':    { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_multi_perform':       { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_multi_cleanup':       { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_slist_append':        { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'curl_slist_free_all':      { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },

  // -- boost::asio --
  'boost::asio::io_context':         { nodeType: 'EXTERNAL', subtype: 'network', tainted: false },
  'boost::asio::ip::tcp::socket':    { nodeType: 'EXTERNAL', subtype: 'network', tainted: false },
  'boost::asio::ip::tcp::acceptor':  { nodeType: 'EXTERNAL', subtype: 'network', tainted: false },
  'boost::asio::ip::tcp::resolver':  { nodeType: 'EXTERNAL', subtype: 'network', tainted: false },
  'boost::asio::ip::tcp::endpoint':  { nodeType: 'EXTERNAL', subtype: 'network', tainted: false },
  'boost::asio::ip::udp::socket':    { nodeType: 'EXTERNAL', subtype: 'network', tainted: false },
  'boost::asio::steady_timer':       { nodeType: 'EXTERNAL', subtype: 'network', tainted: false },
  'boost::asio::ssl::context':       { nodeType: 'EXTERNAL', subtype: 'network', tainted: false },
  'boost::asio::ssl::stream':        { nodeType: 'EXTERNAL', subtype: 'network', tainted: false },
  'io_context.run':           { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'io_context.stop':          { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'io_context.poll':          { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'acceptor.accept':          { nodeType: 'EXTERNAL', subtype: 'network',      tainted: false },
  'acceptor.listen':          { nodeType: 'EXTERNAL', subtype: 'network',      tainted: false },
  'acceptor.async_accept':    { nodeType: 'EXTERNAL', subtype: 'network',      tainted: false },
  'socket.connect':           { nodeType: 'EXTERNAL', subtype: 'network',      tainted: false },
  'socket.async_connect':     { nodeType: 'EXTERNAL', subtype: 'network',      tainted: false },
  'socket.async_read_some':   { nodeType: 'EXTERNAL', subtype: 'network',      tainted: false },
  'socket.async_write_some':  { nodeType: 'EXTERNAL', subtype: 'network',      tainted: false },
  'resolver.resolve':         { nodeType: 'EXTERNAL', subtype: 'network',      tainted: false },
  'resolver.async_resolve':   { nodeType: 'EXTERNAL', subtype: 'network',      tainted: false },

  // -- httplib (cpp-httplib) --
  'httplib::Client':          { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'httplib::Server':          { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'client.Get':               { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'client.Post':              { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'client.Put':               { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'client.Delete':            { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'client.Patch':             { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'client.Head':              { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'svr.listen':               { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'svr.Get':                  { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'svr.Post':                 { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'svr.Put':                  { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },

  // -- gRPC --
  'grpc::CreateChannel':      { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'grpc::InsecureChannelCredentials': { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },
  'grpc::SslCredentials':     { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },
  'grpc::ServerBuilder':      { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'builder.AddListeningPort': { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'builder.RegisterService':  { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'builder.BuildAndStart':    { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'stub.NewStub':             { nodeType: 'EXTERNAL', subtype: 'api_call',     tainted: false },

  // =========================================================================
  // STRUCTURAL -- code structure, dependencies, memory management
  // =========================================================================

  // -- new/delete --
  'new':                      { nodeType: 'STRUCTURAL', subtype: 'memory',     tainted: false },
  'delete':                   { nodeType: 'STRUCTURAL', subtype: 'memory',     tainted: false },

  // -- smart pointers --
  'std::make_unique':         { nodeType: 'STRUCTURAL', subtype: 'memory',     tainted: false },
  'std::make_shared':         { nodeType: 'STRUCTURAL', subtype: 'memory',     tainted: false },
  'std::unique_ptr':          { nodeType: 'STRUCTURAL', subtype: 'memory',     tainted: false },
  'std::shared_ptr':          { nodeType: 'STRUCTURAL', subtype: 'memory',     tainted: false },
  'std::weak_ptr':            { nodeType: 'STRUCTURAL', subtype: 'memory',     tainted: false },

  // -- containers --
  'std::vector':              { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::map':                 { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::unordered_map':       { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::set':                 { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::unordered_set':       { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::array':               { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::deque':               { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::list':                { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::queue':               { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::stack':               { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::tuple':               { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::pair':                { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::optional':            { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::variant':             { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'std::any':                 { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },

  // =========================================================================
  // META -- logging, debug, diagnostics
  // =========================================================================

  // -- spdlog --
  'spdlog::info':             { nodeType: 'META', subtype: 'logging',          tainted: false },
  'spdlog::warn':             { nodeType: 'META', subtype: 'logging',          tainted: false },
  'spdlog::error':            { nodeType: 'META', subtype: 'logging',          tainted: false },
  'spdlog::debug':            { nodeType: 'META', subtype: 'logging',          tainted: false },
  'spdlog::trace':            { nodeType: 'META', subtype: 'logging',          tainted: false },
  'spdlog::critical':         { nodeType: 'META', subtype: 'logging',          tainted: false },
  'spdlog::set_level':        { nodeType: 'META', subtype: 'config',           tainted: false },
  'spdlog::set_pattern':      { nodeType: 'META', subtype: 'config',           tainted: false },
  'spdlog::stdout_color_mt':  { nodeType: 'META', subtype: 'config',           tainted: false },
  'spdlog::basic_logger_mt':  { nodeType: 'META', subtype: 'config',           tainted: false },
  'spdlog::rotating_logger_mt': { nodeType: 'META', subtype: 'config',         tainted: false },
  'spdlog::daily_logger_mt':  { nodeType: 'META', subtype: 'config',           tainted: false },
  'logger.info':              { nodeType: 'META', subtype: 'logging',          tainted: false },
  'logger.warn':              { nodeType: 'META', subtype: 'logging',          tainted: false },
  'logger.error':             { nodeType: 'META', subtype: 'logging',          tainted: false },
  'logger.debug':             { nodeType: 'META', subtype: 'logging',          tainted: false },
  'logger.trace':             { nodeType: 'META', subtype: 'logging',          tainted: false },
  'logger.critical':          { nodeType: 'META', subtype: 'logging',          tainted: false },

  // -- glog (Google logging) --
  'google::InitGoogleLogging': { nodeType: 'META', subtype: 'config',          tainted: false },
  'google::ShutdownGoogleLogging': { nodeType: 'META', subtype: 'config',      tainted: false },
  'LOG(INFO)':                { nodeType: 'META', subtype: 'logging',          tainted: false },
  'LOG(WARNING)':             { nodeType: 'META', subtype: 'logging',          tainted: false },
  'LOG(ERROR)':               { nodeType: 'META', subtype: 'logging',          tainted: false },
  'LOG(FATAL)':               { nodeType: 'META', subtype: 'logging',          tainted: false },
  'VLOG':                     { nodeType: 'META', subtype: 'logging',          tainted: false },
  'CHECK':                    { nodeType: 'META', subtype: 'logging',          tainted: false },
  'CHECK_EQ':                 { nodeType: 'META', subtype: 'logging',          tainted: false },
  'CHECK_NE':                 { nodeType: 'META', subtype: 'logging',          tainted: false },
  'CHECK_LT':                 { nodeType: 'META', subtype: 'logging',          tainted: false },
  'CHECK_GT':                 { nodeType: 'META', subtype: 'logging',          tainted: false },
  'CHECK_LE':                 { nodeType: 'META', subtype: 'logging',          tainted: false },
  'CHECK_GE':                 { nodeType: 'META', subtype: 'logging',          tainted: false },
  'DLOG':                     { nodeType: 'META', subtype: 'logging',          tainted: false },
  'DCHECK':                   { nodeType: 'META', subtype: 'logging',          tainted: false },

  // -- boost::log --
  'boost::log::trivial::info':    { nodeType: 'META', subtype: 'logging',      tainted: false },
  'boost::log::trivial::warning': { nodeType: 'META', subtype: 'logging',      tainted: false },
  'boost::log::trivial::error':   { nodeType: 'META', subtype: 'logging',      tainted: false },
  'boost::log::trivial::debug':   { nodeType: 'META', subtype: 'logging',      tainted: false },
  'boost::log::trivial::trace':   { nodeType: 'META', subtype: 'logging',      tainted: false },
  'boost::log::trivial::fatal':   { nodeType: 'META', subtype: 'logging',      tainted: false },
  'boost::log::add_file_log':     { nodeType: 'META', subtype: 'config',       tainted: false },
  'boost::log::add_console_log':  { nodeType: 'META', subtype: 'config',       tainted: false },
  'BOOST_LOG_TRIVIAL':        { nodeType: 'META', subtype: 'logging',          tainted: false },

  // -- __FILE__ / __LINE__ macros (debug context) --
  '__FILE__':                 { nodeType: 'META', subtype: 'debug',            tainted: false },
  '__LINE__':                 { nodeType: 'META', subtype: 'debug',            tainted: false },
  '__func__':                 { nodeType: 'META', subtype: 'debug',            tainted: false },
  '__FUNCTION__':             { nodeType: 'META', subtype: 'debug',            tainted: false },
  '__PRETTY_FUNCTION__':      { nodeType: 'META', subtype: 'debug',            tainted: false },

  // -- testing (Google Test) --
  'TEST':                     { nodeType: 'META', subtype: 'test',             tainted: false },
  'TEST_F':                   { nodeType: 'META', subtype: 'test',             tainted: false },
  'EXPECT_EQ':                { nodeType: 'META', subtype: 'test',             tainted: false },
  'EXPECT_NE':                { nodeType: 'META', subtype: 'test',             tainted: false },
  'EXPECT_TRUE':              { nodeType: 'META', subtype: 'test',             tainted: false },
  'EXPECT_FALSE':             { nodeType: 'META', subtype: 'test',             tainted: false },
  'EXPECT_THROW':             { nodeType: 'META', subtype: 'test',             tainted: false },
  'ASSERT_EQ':                { nodeType: 'META', subtype: 'test',             tainted: false },
  'ASSERT_NE':                { nodeType: 'META', subtype: 'test',             tainted: false },
  'ASSERT_TRUE':              { nodeType: 'META', subtype: 'test',             tainted: false },
  'ASSERT_FALSE':             { nodeType: 'META', subtype: 'test',             tainted: false },
  'ASSERT_THROW':             { nodeType: 'META', subtype: 'test',             tainted: false },
};

// -- Wildcard member calls (*.method) ----------------------------------------

const STORAGE_READ_METHODS = new Set([
  'Query', 'QueryRow', 'Find', 'First', 'Last',
  'Select', 'Get', 'Scan', 'Next', 'Pluck', 'Count',
  'Fetch', 'FetchRow', 'GetValue',
]);

const STORAGE_WRITE_METHODS = new Set([
  'Exec', 'ExecDirect', 'Create', 'Save', 'Delete',
  'Update', 'Insert', 'Remove', 'Put',
  'Commit', 'Rollback', 'Execute',
]);

const TRANSFORM_FORMAT_METHODS = new Set([
  'String', 'Bytes', 'Format',
  'str', 'c_str', 'data', 'substr', 'append',
]);

// -- Lookup function ----------------------------------------------------------

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };
    return null;
  }

  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  const member = MEMBER_CALLS[exactKey];
  if (member) return { ...member };

  // Try deeper chains: "std::filesystem::exists", "boost::asio::ip::tcp::socket"
  if (calleeChain.length > 2) {
    const fullPath = calleeChain.join('.');
    const fullMember = MEMBER_CALLS[fullPath];
    if (fullMember) return { ...fullMember };

    // Try with :: separator (C++ namespaces)
    const nsPath = calleeChain.join('::');
    const nsMember = MEMBER_CALLS[nsPath];
    if (nsMember) return { ...nsMember };

    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
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

  if (TRANSFORM_FORMAT_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'format', tainted: false };
  }

  return null;
}

const NON_DB_OBJECTS = new Set([
  'std', 'cin', 'cout', 'cerr', 'clog',
  'ifstream', 'ofstream', 'fstream', 'ss',
  'thread', 'mtx', 'cv', 'atomic', 'future', 'promise',
  'latch', 'barrier', 'sem',
  'json', 'rapidjson', 'nlohmann',
  'boost', 'spdlog', 'logger',
  'io_context', 'acceptor', 'socket', 'resolver',
  'client', 'svr', 'stub', 'builder',
  'this', 'self',
]);

// -- Sink patterns (CWE -> dangerous regex) -----------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /(?:system|popen)\s*\(\s*(?:[a-zA-Z_]\w*|(?:std::)?string)/,
  'CWE-89':  /(?:sqlite3_exec|mysql_query|mysql_real_query|PQexec|SQLExecDirect)\s*\([^)]*(?:\+|sprintf|strcat|append)/,
  'CWE-119': /(?:strcpy|strcat|gets|sprintf|memcpy)\s*\(/,
  'CWE-120': /scanf\s*\(\s*"%s"/,
  'CWE-134': /printf\s*\(\s*[a-zA-Z_]\w*\s*\)/,
  'CWE-190': /(?:static_cast\s*<\s*(?:int|short|char)\s*>|(?:int|short|char)\s*\w+\s*=\s*\w+\s*[+*])/,
  'CWE-416': /(?:delete\s+\w+[\s\S]*?\w+->|free\s*\(\s*\w+\s*\)[\s\S]*?\w+[\[.])/,
  'CWE-798': /(?:password|secret|apiKey|api_key|token)\s*=\s*"[^"]{8,}"/,
};

// -- Safe patterns (CWE -> mitigating regex) ----------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /exec[lv]p?\s*\(\s*"[^"]*"\s*,/,                           // literal command name
  'CWE-89':  /(?:sqlite3_bind_|PQexecParams|mysql_stmt_bind_param|SQLBindParameter)\s*\(/,  // parameterized queries
  'CWE-119': /(?:snprintf|strncpy|strncat|memcpy\s*\([^,]+,[^,]+,\s*sizeof)/,              // bounded operations
  'CWE-120': /scanf\s*\(\s*"%\d+s"/,                                     // scanf with width limit
  'CWE-134': /printf\s*\(\s*"[^"]*"\s*,/,                                // literal format string
  'CWE-190': /(?:std::numeric_limits|__builtin_add_overflow|__builtin_mul_overflow)/,       // overflow checks
  'CWE-416': /(?:std::unique_ptr|std::shared_ptr|std::make_unique|std::make_shared)/,       // smart pointers
  'CWE-798': /(?:getenv|std::getenv|config\.|argv)\s*\(/,                // externalized secrets
};

// -- Pattern count ------------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size
    + TRANSFORM_FORMAT_METHODS.size;
}
