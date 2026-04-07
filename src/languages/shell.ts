/**
 * Shell (Bash/POSIX sh) Callee Pattern Database
 *
 * Maps shell commands and builtins to DST Neural Map node types.
 * Shell is command-based, not object-oriented -- "callee patterns"
 * are command names and builtins rather than object.method() calls.
 *
 * Sources:
 *   - corpus_audit_shell.json (50 Category B + 186 Category A patterns)
 *   - Shell/Unix command knowledge (heavy gap-filling)
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (command names / builtins) -----------------------------------
// In shell, almost everything is a "direct call" (a command name).

const DIRECT_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS -- external data entering the system
  // =========================================================================

  // -- User input --
  read:             { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },
  readarray:        { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },
  mapfile:          { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },
  select:           { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },

  // -- File read --
  cat:              { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  head:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  tail:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  less:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  more:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  wc:               { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  stat:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  file:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  od:               { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  xxd:              { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  hexdump:          { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  strings:          { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  readlink:         { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  realpath:         { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  ls:               { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  find:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  du:               { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  df:               { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  tree:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },
  lsof:             { nodeType: 'INGRESS',   subtype: 'file_read',     tainted: false },

  // -- Environment / config read --
  env:              { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  printenv:         { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  hostname:         { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  uname:            { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  whoami:           { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  id:               { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  groups:           { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  pwd:              { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  which:            { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  type:             { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  command:          { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  locale:           { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  getopt:           { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: true },
  getopts:          { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: true },

  // -- Process info --
  ps:               { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  top:              { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  free:             { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  uptime:           { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  lscpu:            { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },
  lsblk:            { nodeType: 'INGRESS',   subtype: 'env_read',      tainted: false },

  // =========================================================================
  // EGRESS -- data leaving the system
  // =========================================================================

  // -- Display / output --
  echo:             { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  printf:           { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },

  // -- File write --
  tee:              { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  cp:               { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  mv:               { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  rm:               { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  rmdir:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  mkdir:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  touch:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  ln:               { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  install:          { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  mktemp:           { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  truncate:         { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  shred:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },

  // -- Permissions --
  chmod:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  chown:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  chgrp:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  umask:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },

  // -- Archive / compress --
  tar:              { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  zip:              { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  unzip:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  gzip:             { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  gunzip:           { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  bzip2:            { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  xz:               { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },
  zstd:             { nodeType: 'EGRESS',    subtype: 'file_write',    tainted: false },

  // -- Logging --
  logger:           { nodeType: 'META',      subtype: 'logging',       tainted: false },

  // =========================================================================
  // EXTERNAL -- calls to outside systems
  // =========================================================================

  // -- HTTP clients --
  curl:             { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  wget:             { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  httpie:           { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },

  // -- Remote execution --
  ssh:              { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  scp:              { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  sftp:             { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  rsync:            { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  ftp:              { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },

  // -- Network utilities --
  nc:               { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  ncat:             { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  socat:            { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  telnet:           { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },

  // -- DNS --
  dig:              { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  nslookup:         { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  host:             { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },

  // -- Network info --
  ping:             { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  traceroute:       { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  netstat:          { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  ss:               { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  ip:               { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  ifconfig:         { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },

  // -- Container / orchestration --
  docker:           { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  'docker-compose': { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  kubectl:          { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  helm:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  podman:           { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },

  // -- Cloud CLIs --
  aws:              { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  gcloud:           { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  az:               { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },
  terraform:        { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },

  // -- Git --
  git:              { nodeType: 'EXTERNAL',  subtype: 'api_call',      tainted: false },

  // -- Package managers --
  apt:              { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  'apt-get':        { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  yum:              { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  dnf:              { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  brew:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  pip:              { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  npm:              { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  yarn:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  pnpm:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  gem:              { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  cargo:            { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  go:               { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  snap:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },

  // -- Process execution --
  nohup:            { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  xargs:            { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  exec:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  eval:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  crontab:          { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },

  // -- Service management --
  systemctl:        { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  service:          { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  journalctl:       { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },

  // =========================================================================
  // STORAGE -- persistent state (database CLIs)
  // =========================================================================

  mysql:            { nodeType: 'STORAGE',   subtype: 'db_read',       tainted: false },
  psql:             { nodeType: 'STORAGE',   subtype: 'db_read',       tainted: false },
  sqlite3:          { nodeType: 'STORAGE',   subtype: 'db_read',       tainted: false },
  mongosh:          { nodeType: 'STORAGE',   subtype: 'db_read',       tainted: false },
  mongo:            { nodeType: 'STORAGE',   subtype: 'db_read',       tainted: false },
  'redis-cli':      { nodeType: 'STORAGE',   subtype: 'cache_read',    tainted: false },
  pg_dump:          { nodeType: 'STORAGE',   subtype: 'db_read',       tainted: false },
  pg_restore:       { nodeType: 'STORAGE',   subtype: 'db_write',      tainted: false },
  mysqldump:        { nodeType: 'STORAGE',   subtype: 'db_read',       tainted: false },
  mongodump:        { nodeType: 'STORAGE',   subtype: 'db_read',       tainted: false },
  mongorestore:     { nodeType: 'STORAGE',   subtype: 'db_write',      tainted: false },

  // =========================================================================
  // TRANSFORM -- data processing
  // =========================================================================

  // -- Text processing --
  sed:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  awk:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  grep:             { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  egrep:            { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  fgrep:            { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  cut:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  tr:               { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  sort:             { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  uniq:             { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  paste:            { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  column:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  rev:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  fold:             { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  fmt:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  nl:               { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  pr:               { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  expand:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  unexpand:         { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  comm:             { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  diff:             { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  patch:            { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  tac:              { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },

  // -- JSON/YAML/XML processing --
  jq:               { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  yq:               { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  xmllint:          { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },
  xmlstarlet:       { nodeType: 'TRANSFORM', subtype: 'parse',         tainted: false },

  // -- Encoding --
  base64:           { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  base32:           { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  uuencode:         { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  uudecode:         { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },
  iconv:            { nodeType: 'TRANSFORM', subtype: 'encode',        tainted: false },

  // -- Crypto / hashing --
  openssl:          { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  sha256sum:        { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  sha512sum:        { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  sha1sum:          { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  md5sum:           { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  cksum:            { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },
  b2sum:            { nodeType: 'TRANSFORM', subtype: 'encrypt',       tainted: false },

  // -- Math --
  bc:               { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  dc:               { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  expr:             { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },
  seq:              { nodeType: 'TRANSFORM', subtype: 'calculate',     tainted: false },

  // -- Date/time --
  date:             { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },

  // -- Type conversion --
  basename:         { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  dirname:          { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },

  // =========================================================================
  // CONTROL -- flow, validation, signals
  // =========================================================================

  test:             { nodeType: 'CONTROL',   subtype: 'validation',    tainted: false },
  true:             { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  false:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  exit:             { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  return:           { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  break:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  continue:         { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  trap:             { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  wait:             { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  sleep:            { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  kill:             { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  pkill:            { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  killall:          { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  timeout:          { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  set:              { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  shopt:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },

  // =========================================================================
  // AUTH -- authentication and authorization
  // =========================================================================

  sudo:             { nodeType: 'AUTH',      subtype: 'authorize',     tainted: false },
  su:               { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  passwd:           { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  useradd:          { nodeType: 'AUTH',      subtype: 'authorize',     tainted: false },
  usermod:          { nodeType: 'AUTH',      subtype: 'authorize',     tainted: false },
  userdel:          { nodeType: 'AUTH',      subtype: 'authorize',     tainted: false },
  groupadd:         { nodeType: 'AUTH',      subtype: 'authorize',     tainted: false },
  gpg:              { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  'ssh-keygen':     { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  'ssh-agent':      { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  'ssh-add':        { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  htpasswd:         { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },

  // =========================================================================
  // STRUCTURAL -- dependencies, sourcing
  // =========================================================================

  source:           { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  // '.' (dot command) is the POSIX equivalent of source, handled separately
  export:           { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  unset:            { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  local:            { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  declare:          { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  readonly:         { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  typeset:          { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  alias:            { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },

  // =========================================================================
  // META -- config, debug, logging
  // =========================================================================

  // logger already above
  syslog:           { nodeType: 'META',      subtype: 'logging',       tainted: false },
};

// -- Member calls are minimal in shell -----------------------------------------
// Shell doesn't have object.method syntax. These cover compound commands
// that the parser might extract as dotted chains.

const MEMBER_CALLS: Record<string, CalleePattern> = {
  // These are for when the mapper might see patterns like "docker.run"
  'docker.run':       { nodeType: 'EXTERNAL',  subtype: 'system_exec',  tainted: false },
  'docker.exec':      { nodeType: 'EXTERNAL',  subtype: 'system_exec',  tainted: false },
  'docker.build':     { nodeType: 'EXTERNAL',  subtype: 'system_exec',  tainted: false },
  'docker.pull':      { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'docker.push':      { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'docker.stop':      { nodeType: 'EXTERNAL',  subtype: 'system_exec',  tainted: false },
  'docker.rm':        { nodeType: 'EXTERNAL',  subtype: 'system_exec',  tainted: false },
  'docker.logs':      { nodeType: 'INGRESS',   subtype: 'file_read',    tainted: false },
  'kubectl.apply':    { nodeType: 'EXTERNAL',  subtype: 'system_exec',  tainted: false },
  'kubectl.get':      { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'kubectl.delete':   { nodeType: 'EXTERNAL',  subtype: 'system_exec',  tainted: false },
  'kubectl.logs':     { nodeType: 'INGRESS',   subtype: 'file_read',    tainted: false },
  'kubectl.exec':     { nodeType: 'EXTERNAL',  subtype: 'system_exec',  tainted: false },
  'git.clone':        { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'git.push':         { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'git.pull':         { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'git.fetch':        { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'git.commit':       { nodeType: 'EXTERNAL',  subtype: 'system_exec',  tainted: false },
  'aws.s3':           { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'aws.ec2':          { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'aws.lambda':       { nodeType: 'EXTERNAL',  subtype: 'api_call',     tainted: false },
  'openssl.enc':      { nodeType: 'TRANSFORM', subtype: 'encrypt',      tainted: false },
  'openssl.dgst':     { nodeType: 'TRANSFORM', subtype: 'encrypt',      tainted: false },
  'openssl.genrsa':   { nodeType: 'TRANSFORM', subtype: 'encrypt',      tainted: false },
  'openssl.req':      { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  'openssl.x509':     { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
  'openssl.verify':   { nodeType: 'AUTH',      subtype: 'authenticate',  tainted: false },
};

// -- No wildcard sets for shell (everything is direct calls) --

// -- Lookup function ----------------------------------------------------------

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };
    return null;
  }

  // For "docker run" / "kubectl apply" etc., try "command.subcommand"
  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  const member = MEMBER_CALLS[exactKey];
  if (member) return { ...member };

  // If subcommand not found, fall back to the base command
  const baseCmd = DIRECT_CALLS[objectName];
  if (baseCmd) return { ...baseCmd };

  return null;
}

// -- Sink patterns (CWE -> dangerous regex) -----------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /(?:\beval\s+["']?\$|\brm\s+-r?f?\s+\$\w+(?!")|for\s+\w+\s+in\s+\$[^"\s]+)/,
  'CWE-214': /(?:-p|--password[= ])\s*['"][^'"]+['"]/,
  'CWE-319': /StrictHostKeyChecking\s*=?\s*no/,
  'CWE-377': /(?:\/tmp\/[a-zA-Z_]+\b(?!\$)|mktemp(?![^\n]{0,300}trap))/,
  'CWE-426': /(?:\bPATH\s*=\s*["']?\.|sudo\s+.*\bLD_PRELOAD\b)/,
  'CWE-732': /\bchmod\s+(?:777|666|[47]\d{3})\b/,
  'CWE-798': /(?:password|passwd|pwd)\s*=\s*["'][^"']{4,}["']/,
  'CWE-829': /(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?\s*(?:ba)?sh\b/,
};

// -- Safe patterns (CWE -> mitigating regex) ----------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /(?:set\s+-[euxo]\s+pipefail|"\$\w+")/,                // strict mode or quoted variables
  'CWE-377': /mktemp\b/,                                              // mktemp (vs. /tmp/predictable)
  'CWE-426': /(?:PATH\s*=\s*["']\/|hash\s+-r)/,                      // absolute PATH
  'CWE-732': /\bchmod\s+(?:700|600|644|755)\b/,                       // restrictive permissions
  'CWE-829': /(?:sha256sum\s+--check|gpg\s+--verify)/,               // integrity verification
};

// -- Pattern count ------------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length;
}
