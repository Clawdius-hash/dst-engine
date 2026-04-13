/**
 * Ruby Callee Pattern Database
 *
 * Maps Ruby method/function names to DST Neural Map node types.
 * Covers: stdlib, Rails (ActiveRecord, ActionController, ActionView),
 *         Sinatra, Devise, JWT, bcrypt, Net::HTTP, Faraday, HTTParty,
 *         Sidekiq, Redis, Mongoid.
 *
 * Sources:
 *   - corpus_audit_ruby.json (60 Category B + 189 Category A patterns)
 *   - Ruby/Rails framework knowledge (heavy gap-filling needed)
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (single identifier / Kernel methods) ------------------------

const DIRECT_CALLS: Record<string, CalleePattern> = {
  // EXTERNAL -- system execution
  eval:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  exec:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  system:           { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  fork:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  spawn:            { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false },
  open:             { nodeType: 'EXTERNAL',  subtype: 'system_exec',   tainted: false }, // Kernel#open can execute commands
  require:          { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  require_relative: { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  load:             { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },
  autoload:         { nodeType: 'STRUCTURAL', subtype: 'dependency',   tainted: false },

  // EGRESS -- display
  puts:             { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  print:            { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  p:                { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  pp:               { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },
  warn:             { nodeType: 'EGRESS',    subtype: 'display',       tainted: false },

  // TRANSFORM -- unsafe HTML (XSS vectors — disable Rails auto-escaping)
  raw:              { nodeType: 'TRANSFORM', subtype: 'unsafe_html',   tainted: false },

  // INGRESS -- user input
  gets:             { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },
  readline:         { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },
  readlines:        { nodeType: 'INGRESS',   subtype: 'user_input',    tainted: true },

  // TRANSFORM -- type coercion
  Integer:          { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  Float:            { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  String:           { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  Array:            { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  Hash:             { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  Complex:          { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },
  Rational:         { nodeType: 'TRANSFORM', subtype: 'format',        tainted: false },

  // CONTROL -- flow
  exit:             { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  'exit!':          { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  abort:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  raise:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  fail:             { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  throw:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  catch:            { nodeType: 'CONTROL',   subtype: 'guard',         tainted: false },
  at_exit:          { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
  trap:             { nodeType: 'CONTROL',   subtype: 'event_handler', tainted: false },
};

// -- Member calls (object.method / Module.method) -----------------------------

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS -- external data entering the system
  // =========================================================================

  // -- Rails params / request --
  'params.require':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'params.permit':            { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'params.fetch':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'params.slice':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'params.merge':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'params.to_unsafe_h':       { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.body':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.headers':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.env':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.path':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.url':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.host':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.method':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.remote_ip':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.content_type':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.query_string':     { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.query_parameters': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.request_parameters': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.raw_post':         { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'request.body_stream':      { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Sinatra --
  'request.params':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Rack internals --
  'Rack::Request.new':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Rack::Utils.parse_nested_query': { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Cookies / Session --
  'cookies.signed':           { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'cookies.encrypted':        { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- Environment --
  'ENV.fetch':                { nodeType: 'INGRESS', subtype: 'env_read',    tainted: true },

  // -- ARGV --
  'ARGV.first':               { nodeType: 'INGRESS', subtype: 'env_read',    tainted: true },
  'ARGV.shift':               { nodeType: 'INGRESS', subtype: 'env_read',    tainted: true },

  // -- STDIN --
  'STDIN.read':               { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'STDIN.gets':               { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'STDIN.readline':           { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  'STDIN.readlines':          { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  '$stdin.read':              { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },
  '$stdin.gets':              { nodeType: 'INGRESS', subtype: 'user_input',  tainted: true },

  // -- File read --
  'File.read':                { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'File.readlines':           { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'File.open':                { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'File.binread':             { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'File.foreach':             { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'File.exist?':              { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'File.exists?':             { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'File.directory?':          { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'File.size':                { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'File.stat':                { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'Dir.glob':                 { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'Dir.entries':              { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'Dir.children':             { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'IO.read':                  { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'IO.readlines':             { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'Pathname.read':            { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },
  'Pathname.readlines':       { nodeType: 'INGRESS', subtype: 'file_read',   tainted: false },

  // -- Deserialization --
  'JSON.parse':               { nodeType: 'INGRESS', subtype: 'deserialize', tainted: false },
  'JSON.load':                { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true },
  'YAML.load':                { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true },
  'YAML.unsafe_load':         { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true },
  'YAML.safe_load':           { nodeType: 'INGRESS', subtype: 'deserialize', tainted: false },
  'YAML.load_file':           { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true },
  'Marshal.load':             { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: true },
  'Marshal.restore':          { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true },

  // -- Net socket --
  'TCPSocket.new':            { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'UDPSocket.new':            { nodeType: 'INGRESS', subtype: 'network_read', tainted: true },
  'TCPServer.new':            { nodeType: 'INGRESS', subtype: 'network_read', tainted: false },

  // =========================================================================
  // EGRESS -- data leaving the system
  // =========================================================================

  // -- Rails controller responses --
  'render':                   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'redirect_to':              { nodeType: 'EGRESS', subtype: 'redirect',      tainted: false },
  'send_file':                { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'send_data':                { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'head':                     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'respond_to':               { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'respond_with':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'render_to_string':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Sinatra responses --
  'halt':                     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'erb':                      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'haml':                     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'slim':                     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'json':                     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'content_type':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'status':                   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- XSS sinks (auto-escape bypass) --
  'String.html_safe':         { nodeType: 'TRANSFORM', subtype: 'unsafe_html', tainted: false },

  // -- ActionController headers/cookies --
  'response.headers':         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'response.set_header':      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'cookies.permanent':        { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- File write --
  'File.write':               { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'File.binwrite':            { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'File.delete':              { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'File.rename':              { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'File.chmod':               { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'File.chown':               { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'FileUtils.cp':             { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'FileUtils.mv':             { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'FileUtils.rm':             { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'FileUtils.rm_rf':          { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'FileUtils.mkdir_p':        { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'Dir.mkdir':                { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },
  'IO.write':                 { nodeType: 'EGRESS', subtype: 'file_write',   tainted: false },

  // -- Serialization --
  'JSON.generate':            { nodeType: 'EGRESS', subtype: 'serialize',    tainted: false },
  'JSON.dump':                { nodeType: 'EGRESS', subtype: 'serialize',    tainted: false },
  'JSON.pretty_generate':     { nodeType: 'EGRESS', subtype: 'serialize',    tainted: false },
  'YAML.dump':                { nodeType: 'EGRESS', subtype: 'serialize',    tainted: false },
  'Marshal.dump':             { nodeType: 'STORAGE', subtype: 'serialize',   tainted: false },
  'CSV.generate':             { nodeType: 'EGRESS', subtype: 'serialize',    tainted: false },

  // -- Email (ActionMailer) --
  'ActionMailer.deliver_now':  { nodeType: 'EGRESS', subtype: 'email',       tainted: false },
  'ActionMailer.deliver_later':{ nodeType: 'EGRESS', subtype: 'email',       tainted: false },

  // -- Logging --
  'Rails.logger.debug':       { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'Rails.logger.info':        { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'Rails.logger.warn':        { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'Rails.logger.error':       { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'Rails.logger.fatal':       { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'logger.debug':             { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'logger.info':              { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'logger.warn':              { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'logger.error':             { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'logger.fatal':             { nodeType: 'META',   subtype: 'logging',     tainted: false },
  'Logger.new':               { nodeType: 'META',   subtype: 'config',      tainted: false },

  // =========================================================================
  // EXTERNAL -- calls to outside systems
  // =========================================================================

  // -- Net::HTTP --
  'Net::HTTP.get':            { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Net::HTTP.get_response':   { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Net::HTTP.post':           { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Net::HTTP.post_form':      { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Net::HTTP.new':            { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Net::HTTP.start':          { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },

  // -- HTTParty --
  'HTTParty.get':             { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'HTTParty.post':            { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'HTTParty.put':             { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'HTTParty.delete':          { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'HTTParty.patch':           { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },

  // -- Faraday --
  'Faraday.get':              { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Faraday.post':             { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Faraday.put':              { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Faraday.delete':           { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Faraday.new':              { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'conn.get':                 { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'conn.post':                { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'conn.put':                 { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'conn.delete':              { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },

  // -- RestClient --
  'RestClient.get':           { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'RestClient.post':          { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'RestClient.put':           { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'RestClient.delete':        { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'RestClient.patch':         { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },

  // -- Typhoeus --
  'Typhoeus.get':             { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },
  'Typhoeus.post':            { nodeType: 'EXTERNAL', subtype: 'api_call',   tainted: false },

  // -- System execution --
  'Kernel.system':            { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Kernel.exec':              { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Kernel.spawn':             { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Kernel.open':              { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'IO.popen':                 { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Open3.capture2':           { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Open3.capture2e':          { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Open3.capture3':           { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Open3.popen2':             { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Open3.popen3':             { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Process.spawn':            { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Process.fork':             { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // -- Sidekiq / ActiveJob --
  'Sidekiq::Worker.perform_async': { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },

  // -- ERB template (potential SSTI) --
  'ERB.new':                  { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // -- Dynamic dispatch / metaprogramming (CWE-470) --
  'Object.send':              { nodeType: 'EXTERNAL', subtype: 'dynamic_dispatch', tainted: false },
  'Object.public_send':       { nodeType: 'EXTERNAL', subtype: 'dynamic_dispatch', tainted: false },
  'Object.const_get':         { nodeType: 'EXTERNAL', subtype: 'dynamic_dispatch', tainted: false },
  'String.constantize':       { nodeType: 'EXTERNAL', subtype: 'reflection',       tainted: false },
  'PTY.spawn':                { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // =========================================================================
  // STORAGE -- persistent state
  // =========================================================================

  // -- ActiveRecord CRUD --
  'ActiveRecord.find':        { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.find_by':     { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.find_by!':    { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.where':       { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.all':         { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.first':       { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.last':        { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.count':       { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.exists?':     { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.pluck':       { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.select':      { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.order':       { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.limit':       { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.offset':      { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.joins':       { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.includes':    { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.eager_load':  { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.preload':     { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.group':       { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.having':      { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.distinct':    { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.find_each':   { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'ActiveRecord.find_in_batches': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'ActiveRecord.create':      { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.create!':     { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.new':         { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.save':        { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.save!':       { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.update':      { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.update!':     { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.update_all':  { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.destroy':     { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.destroy!':    { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.destroy_all': { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.delete':      { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.delete_all':  { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.insert_all':  { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.upsert_all':  { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'ActiveRecord.transaction':  { nodeType: 'STORAGE', subtype: 'db_write',   tainted: false },
  'ActiveRecord.connection':   { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },
  'ActiveRecord.establish_connection': { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },

  // -- Raw SQL --
  'ActiveRecord.find_by_sql': { nodeType: 'STORAGE', subtype: 'sql_raw',    tainted: false },
  'ActiveRecord.count_by_sql':{ nodeType: 'STORAGE', subtype: 'sql_raw',    tainted: false },
  'ActiveRecord.update_columns': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'connection.exec_query':    { nodeType: 'STORAGE', subtype: 'sql_raw',    tainted: false },
  'connection.execute':       { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'connection.select_all':    { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'connection.select_one':    { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'connection.select_values': { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },

  // -- Arel --
  'Arel.sql':                 { nodeType: 'STORAGE', subtype: 'sql_raw',     tainted: false },

  // -- Sequel --
  'Sequel.lit':               { nodeType: 'STORAGE', subtype: 'sql_raw',     tainted: false },
  'DB.fetch':                 { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'DB.run':                   { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'DB.execute':               { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'dataset.select':           { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'dataset.where':            { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'dataset.insert':           { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'dataset.update':           { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'dataset.delete':           { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },

  // -- Redis --
  'redis.get':                { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'redis.set':                { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.del':                { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.hget':               { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'redis.hset':               { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.lpush':              { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.rpush':              { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.lpop':               { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'redis.rpop':               { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'redis.publish':            { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'redis.subscribe':          { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },

  // -- Mongoid --
  'Mongoid.where':            { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'Mongoid.find':             { nodeType: 'STORAGE', subtype: 'db_read',     tainted: false },
  'Mongoid.create':           { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },
  'Mongoid.create!':          { nodeType: 'STORAGE', subtype: 'db_write',    tainted: false },

  // -- Rails cache --
  'Rails.cache.read':         { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'Rails.cache.write':        { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },
  'Rails.cache.fetch':        { nodeType: 'STORAGE', subtype: 'cache_read',  tainted: false },
  'Rails.cache.delete':       { nodeType: 'STORAGE', subtype: 'cache_write', tainted: false },

  // =========================================================================
  // TRANSFORM -- data processing
  // =========================================================================

  // -- Digest --
  'Digest::MD5.hexdigest':    { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'Digest::SHA1.hexdigest':   { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'Digest::SHA256.hexdigest': { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'Digest::SHA512.hexdigest': { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'Digest::MD5.digest':       { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'Digest::SHA256.digest':    { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'OpenSSL::HMAC.hexdigest':  { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'OpenSSL::HMAC.digest':     { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'OpenSSL::Cipher.new':      { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'SecureRandom.hex':         { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'SecureRandom.uuid':        { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'SecureRandom.base64':      { nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },
  'SecureRandom.urlsafe_base64': { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'SecureRandom.random_bytes':{ nodeType: 'TRANSFORM', subtype: 'encrypt',   tainted: false },

  // -- Base64 --
  'Base64.encode64':          { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'Base64.decode64':          { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'Base64.strict_encode64':   { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'Base64.strict_decode64':   { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'Base64.urlsafe_encode64':  { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'Base64.urlsafe_decode64':  { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },

  // -- CGI / URI --
  'CGI.escape':               { nodeType: 'TRANSFORM', subtype: 'sanitize_html',  tainted: false },
  'CGI.unescape':             { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'CGI.escapeHTML':           { nodeType: 'TRANSFORM', subtype: 'sanitize_html',  tainted: false },
  'CGI.unescapeHTML':         { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'URI.encode_www_form':      { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'URI.decode_www_form':      { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },
  'URI.parse':                { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'Addressable::URI.parse':   { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },

  // -- ERB::Util --
  'ERB::Util.html_escape':    { nodeType: 'TRANSFORM', subtype: 'sanitize_html',  tainted: false },
  'ERB::Util.url_encode':     { nodeType: 'TRANSFORM', subtype: 'encode',    tainted: false },

  // -- Sanitize (Rails) --
  'ActionView::Helpers.sanitize': { nodeType: 'TRANSFORM', subtype: 'sanitize_html', tainted: false },
  'Sanitize.fragment':        { nodeType: 'TRANSFORM', subtype: 'sanitize_html',  tainted: false },
  'Sanitize.clean':           { nodeType: 'TRANSFORM', subtype: 'sanitize_html',  tainted: false },
  'Loofah.fragment':          { nodeType: 'TRANSFORM', subtype: 'sanitize_html',  tainted: false },

  // -- Regexp --
  'Regexp.new':               { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'Regexp.compile':           { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },

  // -- CSV --
  'CSV.parse':                { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'CSV.read':                 { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'CSV.foreach':              { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },

  // -- Time --
  'Time.now':                 { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  'Time.parse':               { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'Time.zone.now':            { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  'Date.today':               { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },
  'Date.parse':               { nodeType: 'TRANSFORM', subtype: 'parse',     tainted: false },
  'DateTime.now':             { nodeType: 'TRANSFORM', subtype: 'format',    tainted: false },

  // =========================================================================
  // CONTROL -- validation, flow, concurrency
  // =========================================================================

  // -- Rails callbacks / filters --
  'before_action':            { nodeType: 'CONTROL', subtype: 'guard',        tainted: false },
  'after_action':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'around_action':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'skip_before_action':       { nodeType: 'CONTROL', subtype: 'guard',        tainted: false },
  'before_filter':            { nodeType: 'CONTROL', subtype: 'guard',        tainted: false },
  'after_filter':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Model callbacks --
  'before_save':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'after_save':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'before_create':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'after_create':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'before_update':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'after_update':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'before_destroy':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'after_destroy':            { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'before_validation':        { nodeType: 'CONTROL', subtype: 'validation',    tainted: false },
  'after_validation':         { nodeType: 'CONTROL', subtype: 'validation',    tainted: false },
  'after_commit':             { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'after_rollback':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Validations --
  'validates':                { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validates!':               { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validates_presence_of':    { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validates_uniqueness_of':  { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validates_format_of':      { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validates_length_of':      { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validates_numericality_of':{ nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validates_inclusion_of':   { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validates_exclusion_of':   { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validates_confirmation_of':{ nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'validate':                 { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'valid?':                   { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },

  // -- Concurrency --
  'Thread.new':               { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Mutex.new':                { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  // Process.fork is in EXTERNAL (system_exec) -- not duplicated here
  'Concurrent::Future.execute':{ nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Concurrent::Promise.execute':{ nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // =========================================================================
  // AUTH -- authentication and authorization
  // =========================================================================

  // -- Devise --
  'authenticate_user!':       { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'current_user':             { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'user_signed_in?':          { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'sign_in':                  { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'sign_out':                 { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'warden.authenticate':      { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'warden.authenticate!':     { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },

  // -- has_secure_password --
  'has_secure_password':      { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'authenticate':             { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },

  // -- BCrypt --
  'BCrypt::Password.create':  { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'BCrypt::Password.new':     { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },

  // -- JWT --
  'JWT.encode':               { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'JWT.decode':               { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },

  // -- Pundit / CanCanCan --
  'policy_scope':             { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'authorize':                { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'authorize!':               { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'policy':                   { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'can?':                     { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'cannot?':                  { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'load_and_authorize_resource':{ nodeType: 'AUTH', subtype: 'authorize',     tainted: false },

  // =========================================================================
  // STRUCTURAL -- routing, app structure
  // =========================================================================

  // -- Sinatra route DSL --
  'Sinatra::Base.get':        { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },

  // -- Devise route generation --
  'devise_for':               { nodeType: 'STRUCTURAL', subtype: 'route', tainted: false },

  // =========================================================================
  // META -- config, debug
  // =========================================================================

  'Rails.configuration':      { nodeType: 'META', subtype: 'config',         tainted: false },
  'Rails.application.config': { nodeType: 'META', subtype: 'config',         tainted: false },
  'Rails.env':                { nodeType: 'META', subtype: 'config',         tainted: false },
  'Rails.root':               { nodeType: 'META', subtype: 'config',         tainted: false },

  // -- Debug --
  'binding.pry':              { nodeType: 'META', subtype: 'debug',          tainted: false },
  'binding.irb':              { nodeType: 'META', subtype: 'debug',          tainted: false },
  'debugger':                 { nodeType: 'META', subtype: 'debug',          tainted: false },
  'byebug':                   { nodeType: 'META', subtype: 'debug',          tainted: false },
};

// -- Wildcard member calls (*.method) -----------------------------------------

const STORAGE_READ_METHODS = new Set([
  'find', 'find_by', 'find_by!', 'where', 'all', 'first', 'last',
  'count', 'exists?', 'pluck', 'select', 'order', 'limit', 'offset',
  'joins', 'includes', 'eager_load', 'preload', 'group', 'having',
  'distinct', 'find_each', 'find_in_batches', 'sole', 'find_sole_by',
  'sum', 'average', 'minimum', 'maximum', 'calculate',
  'first_or_create', 'first_or_initialize',
]);

const STORAGE_WRITE_METHODS = new Set([
  'create', 'create!', 'save', 'save!',
  'update', 'update!', 'update_all', 'update_attribute',
  'destroy', 'destroy!', 'destroy_all',
  'delete', 'delete_all',
  'insert_all', 'insert_all!', 'upsert_all',
  'increment!', 'decrement!', 'toggle!', 'touch',
]);

const TRANSFORM_FORMAT_METHODS = new Set([
  // String methods
  'strip', 'lstrip', 'rstrip', 'chomp', 'chop', 'squeeze',
  'downcase', 'upcase', 'capitalize', 'swapcase', 'titlecase',
  'split', 'join', 'gsub', 'sub', 'tr', 'delete',
  'encode', 'force_encoding', 'scrub',
  'to_i', 'to_f', 'to_s', 'to_sym', 'to_r', 'to_c',
  'to_json', 'to_xml', 'to_yaml', 'to_csv', 'to_h', 'to_a',
  'freeze', 'dup', 'clone',
  'center', 'ljust', 'rjust',
  'scan', 'match', 'match?',
  'start_with?', 'end_with?', 'include?',
  'bytes', 'chars', 'lines',
  // Numeric formatting
  'round', 'ceil', 'floor', 'truncate', 'abs',
  // Time formatting
  'strftime', 'iso8601', 'httpdate', 'rfc2822',
]);

const TRANSFORM_CALCULATE_METHODS = new Set([
  // Enumerable
  'map', 'collect', 'flat_map', 'collect_concat',
  'select', 'filter', 'reject', 'detect', 'find_index',
  'each', 'each_with_index', 'each_with_object', 'each_slice',
  'reduce', 'inject', 'sum', 'tally', 'group_by', 'chunk',
  'sort', 'sort_by', 'reverse', 'shuffle', 'sample',
  'min', 'max', 'minmax', 'min_by', 'max_by',
  'any?', 'all?', 'none?', 'one?', 'count',
  'zip', 'product', 'combination', 'permutation',
  'compact', 'flatten', 'uniq', 'rotate',
  'push', 'pop', 'shift', 'unshift', 'append', 'prepend',
  'concat', 'union', 'intersection', 'difference',
  'take', 'take_while', 'drop', 'drop_while',
  'filter_map', 'then', 'yield_self',
]);

// -- Lookup function ----------------------------------------------------------

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };

    // Also check member calls for single-name Rails methods (render, redirect_to, etc.)
    const singleMember = MEMBER_CALLS[calleeChain[0]!];
    if (singleMember) return { ...singleMember };

    return null;
  }

  const objectName = calleeChain[0]!;
  const methodName = calleeChain[calleeChain.length - 1]!;
  const exactKey = `${objectName}.${methodName}`;

  const member = MEMBER_CALLS[exactKey];
  if (member) return { ...member };

  // Try deeper chains: "Digest::SHA256.hexdigest" etc.
  if (calleeChain.length > 2) {
    const fullPath = calleeChain.join('.');
    const fullMember = MEMBER_CALLS[fullPath];
    if (fullMember) return { ...fullMember };

    // Try with :: separator for Ruby namespaces
    const nsPath = calleeChain.join('::');
    const nsMember = MEMBER_CALLS[nsPath];
    if (nsMember) return { ...nsMember };

    const lastTwo = `${calleeChain[calleeChain.length - 2]}.${methodName}`;
    const deepMember = MEMBER_CALLS[lastTwo];
    if (deepMember) return { ...deepMember };
  }

  // Wildcard matching
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

  if (TRANSFORM_CALCULATE_METHODS.has(methodName)) {
    return { nodeType: 'TRANSFORM', subtype: 'calculate', tainted: false };
  }

  return null;
}

const NON_DB_OBJECTS = new Set([
  'request', 'response', 'params', 'session', 'cookies', 'flash',
  'self', 'this', 'controller', 'view', 'helper',
  'arr', 'array', 'list', 'items', 'elements', 'results',
  'data', 'values', 'keys', 'entries', 'records', 'rows',
  'str', 'string', 'text', 'name', 'path', 'url',
  'Rails', 'ENV', 'ARGV', 'STDIN', 'STDOUT', 'STDERR',
  'File', 'Dir', 'IO', 'Pathname',
  'JSON', 'YAML', 'CSV', 'Marshal',
  'Time', 'Date', 'DateTime',
]);

// -- Sink patterns (CWE -> dangerous regex) -----------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /(?:\bsystem\s*\(\s*[^"']|\bexec\s*\(\s*[^"']|`[^`]*#\{[^}]+\}[^`]*`|IO\.popen\s*\(\s*[^"'])/,
  'CWE-89':  /(?:\.where\s*\(\s*"[^"]*#\{|\.raw\s*\(\s*"[^"]*#\{|"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*#\{\w+\})/,
  'CWE-94':  /(?:\beval\s*\(\s*[^"']|ERB\.new\s*\(\s*[^"']|render\s+inline:\s*[^"']|\.constantize\b)/,
  'CWE-79':  /(?:\.html_safe\b|raw\s*\(|text\/template)/,
  'CWE-22':  /(?:File\.(?:read|open|write)\s*\(\s*params\[|send_file\s*\(\s*params\[)/,
  'CWE-502': /(?:YAML\.load\s*\(|Marshal\.load\s*\(|JSON\.parse\s*\([^)]*create_additions:\s*true)/,
  'CWE-327': /Digest::(?:MD5|SHA1)\.(?:hexdigest|digest)\s*\(/,
  'CWE-470': /(?:\.send\s*\(\s*params\[|\.public_send\s*\(\s*params\[|Object\.const_get\s*\(\s*[^"])/,
  'CWE-693': /(?:instance_variable_set\s*\(\s*[^"'@]|define_method\s*\(\s*[^"])/,
  'CWE-798': /(?:api_key|secret|password|token)\s*=\s*["'][^"']{4,}["']/,
  'CWE-915': /\.update_attributes?\s*\(\s*params\b/,
  'CWE-918': /\bopen\s*\(\s*[^"'\s]/,
  'CWE-1333': /Regexp\.new\s*\(\s*params\[/,
};

// -- Safe patterns (CWE -> mitigating regex) ----------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-78':  /(?:Open3\.capture[23e]?\s*\(|system\s*\(\s*\[)/,            // Open3 or array form
  'CWE-89':  /\.where\s*\(\s*(?:["'][^"]*\?\s*["']|(?:[\w:]+)\s*=>)/,     // parameterized .where
  'CWE-79':  /(?:CGI\.escapeHTML|ERB::Util\.html_escape|Sanitize\.clean|sanitize)\s*\(/,
  'CWE-22':  /(?:File\.expand_path|Pathname\.new\([^)]+\)\.cleanpath|File\.realpath)\s*\(/,
  'CWE-502': /YAML\.safe_load\s*\(/,
  'CWE-327': /(?:Digest::SHA256|Digest::SHA512|BCrypt::Password)\./,
  'CWE-915': /(?:params\.require\([^)]+\)\.permit|strong_parameters)/,    // strong params
  'CWE-918': /(?:URI\.parse\s*\(|Addressable::URI\.parse\s*\()/,
};

// -- Pattern count ------------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size
    + TRANSFORM_FORMAT_METHODS.size
    + TRANSFORM_CALCULATE_METHODS.size;
}
