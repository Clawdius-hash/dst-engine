/**
 * C# Callee Pattern Database
 *
 * Maps C# method/class names to DST Neural Map node types.
 * Covers: .NET BCL, ASP.NET Core, Entity Framework, Dapper, ADO.NET,
 *         HttpClient, Identity, System.Text.Json, System.Security.Cryptography.
 *
 * Sources:
 *   - corpus_audit_csharp.json (43 Category B + 189 Category A patterns)
 *   - .NET/ASP.NET Core framework knowledge (heavy gap-filling)
 *   - calleePatterns.ts (JS reference -- structural alignment)
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

// -- Direct calls (static methods / constructors) -----------------------------

const DIRECT_CALLS: Record<string, CalleePattern> = {};

// -- Member calls (Type.Method / object.Method) -------------------------------

const MEMBER_CALLS: Record<string, CalleePattern> = {

  // =========================================================================
  // INGRESS
  // =========================================================================

  // -- Console input --
  'Console.ReadLine':             { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'Console.ReadKey':              { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'Console.Read':                 { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },
  'Console.In.ReadLine':          { nodeType: 'INGRESS', subtype: 'user_input',   tainted: true },

  // -- ASP.NET Core Request --
  'HttpContext.Request':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.Form':                 { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.Query':                { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.Body':                 { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.Headers':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.Cookies':              { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.RouteValues':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.Path':                 { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.QueryString':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.ContentType':          { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.Host':                 { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.Method':               { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'Request.ReadFromJsonAsync':    { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },
  'HttpContext.Request.ReadFormAsync': { nodeType: 'INGRESS', subtype: 'file_upload', tainted: true },
  'HttpContext.Session.GetString': { nodeType: 'INGRESS', subtype: 'session_read', tainted: true },

  // -- Minimal API parameter binding --
  'HttpRequest.ReadFromJsonAsync':{ nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // -- SignalR client-side message handler --
  'HubConnection.On':             { nodeType: 'INGRESS', subtype: 'realtime_message', tainted: true },

  // -- File read --
  'File.ReadAllText':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.ReadAllTextAsync':        { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.ReadAllLines':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.ReadAllLinesAsync':       { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.ReadAllBytes':            { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.ReadAllBytesAsync':       { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.OpenRead':                { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.Open':                    { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'File.Exists':                  { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Directory.GetFiles':           { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Directory.GetDirectories':     { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Directory.EnumerateFiles':     { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'Directory.Exists':             { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'StreamReader.ReadToEnd':       { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'StreamReader.ReadLine':        { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },
  'StreamReader.ReadToEndAsync':  { nodeType: 'INGRESS', subtype: 'file_read',    tainted: false },

  // -- Environment --
  'Environment.GetEnvironmentVariable': { nodeType: 'INGRESS', subtype: 'env_read', tainted: true },
  'Environment.GetCommandLineArgs': { nodeType: 'INGRESS', subtype: 'env_read',   tainted: true },

  // -- Configuration --
  'IConfiguration.GetSection':    { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'IConfiguration.GetValue':      { nodeType: 'INGRESS', subtype: 'env_read',     tainted: true },
  'IConfiguration.GetConnectionString': { nodeType: 'INGRESS', subtype: 'env_read', tainted: true },

  // -- Deserialization --
  'JsonSerializer.Deserialize':       { nodeType: 'TRANSFORM', subtype: 'parse',  tainted: false },
  'JsonSerializer.DeserializeAsync':  { nodeType: 'TRANSFORM', subtype: 'parse',  tainted: false },
  'XmlSerializer.Deserialize':        { nodeType: 'TRANSFORM', subtype: 'parse',  tainted: false },
  'BinaryFormatter.Deserialize':      { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true },

  // =========================================================================
  // EGRESS
  // =========================================================================

  // -- Console output --
  'Console.Write':                { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'Console.WriteLine':            { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'Console.Error.Write':          { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'Console.Error.WriteLine':      { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'Debug.Write':                  { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'Debug.WriteLine':              { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'Trace.Write':                  { nodeType: 'EGRESS', subtype: 'display',       tainted: false },
  'Trace.WriteLine':              { nodeType: 'EGRESS', subtype: 'display',       tainted: false },

  // -- ASP.NET Core responses --
  'Ok':                           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'NotFound':                     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'BadRequest':                   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Unauthorized':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Forbid':                       { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'NoContent':                    { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Created':                      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'CreatedAtAction':              { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'StatusCode':                   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Content':                      { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'File':                         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Redirect':                     { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'RedirectToAction':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'View':                         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'PartialView':                  { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Json':                         { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Results.Ok':                   { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Results.Json':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Results.NotFound':             { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Results.BadRequest':           { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Results.File':                 { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Results.Redirect':             { nodeType: 'EGRESS', subtype: 'http_redirect', tainted: false },
  'Response.Redirect':            { nodeType: 'EGRESS', subtype: 'http_redirect', tainted: false },
  'Response.WriteAsync':          { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },
  'Response.WriteAsJsonAsync':    { nodeType: 'EGRESS', subtype: 'http_response', tainted: false },

  // -- Blazor navigation --
  'NavigationManager.NavigateTo': { nodeType: 'EGRESS', subtype: 'http_redirect', tainted: false },

  // -- SignalR server push --
  'Clients.All.SendAsync':       { nodeType: 'EGRESS', subtype: 'realtime_broadcast', tainted: false },
  'Clients.Caller.SendAsync':    { nodeType: 'EGRESS', subtype: 'realtime_response', tainted: false },

  // -- File write --
  'File.WriteAllText':            { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.WriteAllTextAsync':       { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.WriteAllBytes':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.WriteAllBytesAsync':      { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.WriteAllLines':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.WriteAllLinesAsync':      { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.Copy':                    { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.Move':                    { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'File.Delete':                  { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'Directory.CreateDirectory':    { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'Directory.Delete':             { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'StreamWriter.Write':           { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'StreamWriter.WriteAsync':      { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },
  'StreamWriter.WriteLine':       { nodeType: 'EGRESS', subtype: 'file_write',    tainted: false },

  // -- Serialization --
  'JsonSerializer.Serialize':     { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'JsonSerializer.SerializeAsync':{ nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },
  'XmlSerializer.Serialize':      { nodeType: 'EGRESS', subtype: 'serialize',     tainted: false },

  // -- Email --
  'SmtpClient.Send':              { nodeType: 'EGRESS', subtype: 'email',         tainted: false },
  'SmtpClient.SendAsync':         { nodeType: 'EGRESS', subtype: 'email',         tainted: false },
  'SmtpClient.SendMailAsync':     { nodeType: 'EGRESS', subtype: 'email',         tainted: false },

  // =========================================================================
  // EXTERNAL
  // =========================================================================

  // -- Blazor JS interop --
  'IJSRuntime.InvokeAsync':       { nodeType: 'EXTERNAL', subtype: 'js_interop', tainted: false },
  'IJSRuntime.InvokeVoidAsync':   { nodeType: 'EXTERNAL', subtype: 'js_interop', tainted: false },

  // -- HttpClient --
  'HttpClient.GetAsync':          { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.PostAsync':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.PutAsync':          { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.DeleteAsync':       { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.PatchAsync':        { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.SendAsync':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.GetStringAsync':    { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.GetByteArrayAsync': { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.GetStreamAsync':    { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.GetFromJsonAsync':  { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.PostAsJsonAsync':   { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'HttpClient.PutAsJsonAsync':    { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'IHttpClientFactory.CreateClient': { nodeType: 'EXTERNAL', subtype: 'api_call', tainted: false },

  // -- RestSharp --
  'RestClient.ExecuteAsync':      { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'RestClient.GetAsync':          { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },
  'RestClient.PostAsync':         { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- gRPC --
  'GrpcChannel.ForAddress':       { nodeType: 'EXTERNAL', subtype: 'api_call',    tainted: false },

  // -- Process --
  'Process.Start':                { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Process.GetProcesses':         { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },
  'Process.Kill':                 { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // -- Message queue --
  'IPublishEndpoint.Publish':     { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'ISendEndpointProvider.Send':   { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'IMediator.Send':               { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },
  'IMediator.Publish':            { nodeType: 'EXTERNAL', subtype: 'message_queue', tainted: false },

  // =========================================================================
  // STORAGE
  // =========================================================================

  // -- Entity Framework Core --
  'DbContext.SaveChanges':        { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.SaveChangesAsync':   { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.Add':                { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.AddAsync':           { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.AddRange':           { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.AddRangeAsync':      { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.Update':             { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.UpdateRange':        { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.Remove':             { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.RemoveRange':        { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'DbContext.Database.ExecuteSqlRaw': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'DbContext.Database.ExecuteSqlRawAsync': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'DbContext.Database.ExecuteSqlInterpolated': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'DbContext.Database.SqlQueryRaw': { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'DbContext.Database.BeginTransactionAsync': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'DbContext.Set':                { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },

  // -- ADO.NET --
  'SqlConnection.Open':           { nodeType: 'STORAGE', subtype: 'db_connect',   tainted: false },
  'SqlConnection.OpenAsync':      { nodeType: 'STORAGE', subtype: 'db_connect',   tainted: false },
  'SqlConnection.Close':          { nodeType: 'STORAGE', subtype: 'db_connect',   tainted: false },
  'SqlCommand.ExecuteReader':     { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'SqlCommand.ExecuteReaderAsync':{ nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'SqlCommand.ExecuteNonQuery':   { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'SqlCommand.ExecuteNonQueryAsync': { nodeType: 'STORAGE', subtype: 'db_write',  tainted: false },
  'SqlCommand.ExecuteScalar':     { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'SqlCommand.ExecuteScalarAsync':{ nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'SqlCommand.CommandText':       { nodeType: 'STORAGE', subtype: 'sql_assignment', tainted: false },
  'SqlDataAdapter.Fill':          { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'SqlDataReader.Read':           { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'SqlDataReader.ReadAsync':      { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'SqlDataReader.GetString':      { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'SqlDataReader.GetInt32':       { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },

  // -- Dapper --
  'connection.QueryAsync':        { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'connection.Query':             { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'connection.QueryFirstAsync':   { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'connection.QueryFirst':        { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'connection.QueryFirstOrDefault': { nodeType: 'STORAGE', subtype: 'db_read',    tainted: false },
  'connection.QueryFirstOrDefaultAsync': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'connection.QuerySingle':       { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'connection.QuerySingleAsync':  { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'connection.ExecuteAsync':      { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'connection.Execute':           { nodeType: 'STORAGE', subtype: 'db_write',     tainted: false },
  'connection.QueryMultiple':     { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },
  'connection.ExecuteScalar':     { nodeType: 'STORAGE', subtype: 'db_read',      tainted: false },

  // -- Redis (StackExchange.Redis) --
  'db.StringGet':                 { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'db.StringGetAsync':            { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'db.StringSet':                 { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'db.StringSetAsync':            { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'db.KeyDelete':                 { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'db.KeyDeleteAsync':            { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'db.HashGet':                   { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'db.HashSet':                   { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },

  // -- IMemoryCache --
  'IMemoryCache.TryGetValue':     { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'IMemoryCache.Set':             { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'IMemoryCache.Remove':          { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },
  'IDistributedCache.GetAsync':   { nodeType: 'STORAGE', subtype: 'cache_read',   tainted: false },
  'IDistributedCache.SetAsync':   { nodeType: 'STORAGE', subtype: 'cache_write',  tainted: false },

  // =========================================================================
  // TRANSFORM
  // =========================================================================

  // -- Type conversion --
  'Convert.ToInt32':              { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Convert.ToDouble':             { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Convert.ToString':             { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Convert.ToBoolean':            { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Convert.ToBase64String':       { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'Convert.FromBase64String':     { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'int.Parse':                    { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'int.TryParse':                 { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'double.Parse':                 { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'double.TryParse':              { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Enum.Parse':                   { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Enum.TryParse':                { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Guid.Parse':                   { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Guid.NewGuid':                 { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'DateTime.Parse':               { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'DateTime.TryParse':            { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'DateTime.Now':                 { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'DateTime.UtcNow':              { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'DateTimeOffset.Now':           { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'DateTimeOffset.UtcNow':        { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // -- Encoding --
  'Encoding.UTF8.GetBytes':       { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'Encoding.UTF8.GetString':      { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'WebUtility.HtmlEncode':        { nodeType: 'TRANSFORM', subtype: 'sanitize_html',   tainted: false },
  'WebUtility.HtmlDecode':        { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'WebUtility.UrlEncode':         { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'WebUtility.UrlDecode':         { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'HttpUtility.HtmlEncode':       { nodeType: 'TRANSFORM', subtype: 'sanitize_html',   tainted: false },
  'HttpUtility.UrlEncode':        { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'Uri.EscapeDataString':         { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },
  'Uri.UnescapeDataString':       { nodeType: 'TRANSFORM', subtype: 'encode',     tainted: false },

  // -- Blazor raw HTML rendering --
  'MarkupString':                 { nodeType: 'TRANSFORM', subtype: 'raw_html',   tainted: false },

  // -- Crypto --
  'SHA256.HashData':              { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'SHA256.Create':                { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'SHA512.HashData':              { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'SHA512.Create':                { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'MD5.HashData':                 { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'MD5.Create':                   { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'HMACSHA256.HashData':          { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'Aes.Create':                   { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'RSA.Create':                   { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'RSA.Encrypt':                  { nodeType: 'TRANSFORM', subtype: 'encrypt',    tainted: false },
  'RandomNumberGenerator.GetBytes': { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },
  'RandomNumberGenerator.GetInt32': { nodeType: 'TRANSFORM', subtype: 'encrypt', tainted: false },

  // -- Regex --
  'Regex.Match':                  { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'Regex.Matches':                { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },
  'Regex.Replace':                { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Regex.Split':                  { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'Regex.IsMatch':                { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // -- URL parsing --
  'Uri.TryCreate':                { nodeType: 'TRANSFORM', subtype: 'parse',      tainted: false },

  // -- String --
  'String.Format':                { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'StringBuilder.Append':         { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'StringBuilder.AppendLine':     { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },
  'StringBuilder.ToString':       { nodeType: 'TRANSFORM', subtype: 'format',     tainted: false },

  // =========================================================================
  // CONTROL
  // =========================================================================

  // -- Task / async --
  'Task.Run':                     { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Task.WhenAll':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Task.WhenAny':                 { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Task.Delay':                   { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Task.FromResult':              { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'Task.CompletedTask':           { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'CancellationTokenSource.Cancel': { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'SemaphoreSlim.WaitAsync':      { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },
  'SemaphoreSlim.Release':        { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Timer --
  'Timer.Start':                  { nodeType: 'CONTROL', subtype: 'event_handler', tainted: false },

  // -- Validation (FluentValidation) --
  'AbstractValidator.RuleFor':    { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'ModelState.IsValid':           { nodeType: 'CONTROL', subtype: 'validation',   tainted: false },
  'HtmlEncoder.Default.Encode':   { nodeType: 'CONTROL', subtype: 'sanitize_html',     tainted: false },

  // =========================================================================
  // AUTH
  // =========================================================================

  // -- ASP.NET Core Identity --
  'UserManager.CreateAsync':      { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'UserManager.FindByEmailAsync': { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'UserManager.FindByNameAsync':  { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'UserManager.FindByIdAsync':    { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'UserManager.CheckPasswordAsync': { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'UserManager.AddToRoleAsync':   { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'UserManager.IsInRoleAsync':    { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'SignInManager.PasswordSignInAsync': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'SignInManager.SignOutAsync':    { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'SignInManager.TwoFactorSignInAsync': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'UserManager.ChangePasswordAsync': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'UserManager.ResetPasswordAsync': { nodeType: 'AUTH', subtype: 'authenticate',  tainted: false },
  'UserManager.GeneratePasswordResetTokenAsync': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'UserManager.AccessFailedAsync': { nodeType: 'AUTH', subtype: 'authenticate',   tainted: false },
  'RoleManager.CreateAsync':      { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'RoleManager.RoleExistsAsync':  { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },

  // -- Claims --
  'ClaimsPrincipal.FindFirst':    { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },
  'ClaimsPrincipal.IsInRole':     { nodeType: 'AUTH', subtype: 'authorize',       tainted: false },
  'HttpContext.User':             { nodeType: 'AUTH', subtype: 'authenticate',    tainted: false },

  // -- JWT --
  'JwtSecurityTokenHandler.WriteToken': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  'JwtSecurityTokenHandler.ValidateToken': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },

  // =========================================================================
  // STRUCTURAL
  // =========================================================================

  // -- DI --
  'services.AddScoped':           { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'services.AddTransient':        { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'services.AddSingleton':        { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'services.AddDbContext':        { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'services.AddControllers':      { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'services.AddEndpointsApiExplorer': { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },
  'services.AddSwaggerGen':       { nodeType: 'STRUCTURAL', subtype: 'dependency', tainted: false },

  // -- Routing --
  'app.MapGet':                   { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.MapPost':                  { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.MapPut':                   { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.MapDelete':                { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.MapPatch':                 { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.MapControllers':           { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.UseRouting':               { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.UseEndpoints':             { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.UseMiddleware':            { nodeType: 'STRUCTURAL', subtype: 'middleware', tainted: false },
  'app.MapGroup':                 { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },
  'app.MapHub':                   { nodeType: 'STRUCTURAL', subtype: 'route',     tainted: false },

  // -- Server start --
  'app.Run':                      { nodeType: 'EXTERNAL', subtype: 'server_start', tainted: false },
  'WebApplication.CreateBuilder': { nodeType: 'META', subtype: 'config',           tainted: false },

  // =========================================================================
  // META
  // =========================================================================

  // -- ILogger --
  'ILogger.LogInformation':       { nodeType: 'META', subtype: 'logging',         tainted: false },
  'ILogger.LogWarning':           { nodeType: 'META', subtype: 'logging',         tainted: false },
  'ILogger.LogError':             { nodeType: 'META', subtype: 'logging',         tainted: false },
  'ILogger.LogDebug':             { nodeType: 'META', subtype: 'logging',         tainted: false },
  'ILogger.LogCritical':          { nodeType: 'META', subtype: 'logging',         tainted: false },
  'ILogger.LogTrace':             { nodeType: 'META', subtype: 'logging',         tainted: false },
  'logger.LogInformation':        { nodeType: 'META', subtype: 'logging',         tainted: false },
  'logger.LogWarning':            { nodeType: 'META', subtype: 'logging',         tainted: false },
  'logger.LogError':              { nodeType: 'META', subtype: 'logging',         tainted: false },
  'logger.LogDebug':              { nodeType: 'META', subtype: 'logging',         tainted: false },
  'Log.Information':              { nodeType: 'META', subtype: 'logging',         tainted: false },
  'Log.Warning':                  { nodeType: 'META', subtype: 'logging',         tainted: false },
  'Log.Error':                    { nodeType: 'META', subtype: 'logging',         tainted: false },
  'Log.Debug':                    { nodeType: 'META', subtype: 'logging',         tainted: false },
  'Log.Fatal':                    { nodeType: 'META', subtype: 'logging',         tainted: false },

  // -- Configuration --
  'builder.Configuration':        { nodeType: 'META', subtype: 'config',          tainted: false },
  'builder.Services':             { nodeType: 'META', subtype: 'config',          tainted: false },

  // -- Attributes (ASP.NET Core) --
  'FromBody':                     { nodeType: 'META', subtype: 'ingress_binding', tainted: true },
  'Authorize':                    { nodeType: 'META', subtype: 'auth_policy',     tainted: false },
};

// -- Wildcard member calls ---------------------------------------------------

const STORAGE_READ_METHODS = new Set([
  'ToList', 'ToListAsync', 'ToArray', 'ToArrayAsync',
  'First', 'FirstAsync', 'FirstOrDefault', 'FirstOrDefaultAsync',
  'Single', 'SingleAsync', 'SingleOrDefault', 'SingleOrDefaultAsync',
  'Find', 'FindAsync',
  'Where', 'Select', 'OrderBy', 'OrderByDescending',
  'ThenBy', 'ThenByDescending', 'GroupBy',
  'Include', 'ThenInclude',
  'Skip', 'Take', 'Count', 'CountAsync',
  'Any', 'AnyAsync', 'All', 'AllAsync',
  'Sum', 'SumAsync', 'Average', 'AverageAsync',
  'Min', 'MinAsync', 'Max', 'MaxAsync',
  'AsNoTracking', 'AsTracking',
  'FromSqlRaw', 'FromSqlInterpolated',
]);

const STORAGE_WRITE_METHODS = new Set([
  'Add', 'AddAsync', 'AddRange', 'AddRangeAsync',
  'Update', 'UpdateRange',
  'Remove', 'RemoveRange',
  'SaveChanges', 'SaveChangesAsync',
  'ExecuteSqlRaw', 'ExecuteSqlRawAsync',
  'ExecuteSqlInterpolated', 'ExecuteSqlInterpolatedAsync',
  'ExecuteDelete', 'ExecuteDeleteAsync',
  'ExecuteUpdate', 'ExecuteUpdateAsync',
  'BulkInsert', 'BulkInsertAsync',
  'BulkUpdate', 'BulkUpdateAsync',
  'BulkDelete', 'BulkDeleteAsync',
]);

// -- Lookup function ----------------------------------------------------------

export function lookupCallee(calleeChain: string[]): CalleePattern | null {
  if (calleeChain.length === 0) return null;

  if (calleeChain.length === 1) {
    const direct = DIRECT_CALLS[calleeChain[0]!];
    if (direct) return { ...direct };

    // Single-name ASP.NET action results
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

  // Wildcard
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
  'Request', 'Response', 'HttpContext', 'this',
  'Console', 'File', 'Directory', 'Path', 'Environment',
  'Convert', 'Math', 'String', 'StringBuilder',
  'Task', 'Thread', 'Timer',
  'ILogger', 'logger', 'Log',
  'services', 'builder', 'app', 'configuration',
  'JsonSerializer', 'XmlSerializer',
  'Regex', 'Uri', 'DateTime', 'DateTimeOffset', 'Guid',
  'results', 'items', 'list', 'array', 'data', 'values',
  'IJSRuntime', 'NavigationManager', 'HubConnection', 'Clients',
]);

// -- Sink patterns -----------------------------------------------------------

export const sinkPatterns: Record<string, RegExp> = {
  'CWE-78':  /Process\.Start\s*\(\s*new\s+ProcessStartInfo\s*\{[^}]*FileName\s*=\s*[^"]/,
  'CWE-89':  /"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\$\w+|ExecuteSqlRaw\s*\(\s*\$"/,
  'CWE-94':  /(?:Assembly\.Load|Activator\.CreateInstance)\s*\([^"]/,
  'CWE-502': /BinaryFormatter\.Deserialize\s*\(/,
  'CWE-798': /(?:apiKey|secret|password|token)\s*[:=]\s*"[^"]{4,}"/,
  'CWE-916': /MD5\.(?:HashData|Create)\s*\(/,
};

// -- Safe patterns -----------------------------------------------------------

export const safePatterns: Record<string, RegExp> = {
  'CWE-89':  /(?:FromSqlInterpolated|ExecuteSqlInterpolated|\.Where\s*\(\s*\w+\s*=>|AddParameterWithValue)/,
  'CWE-502': /JsonSerializer\.Deserialize/,
  'CWE-916': /(?:SHA256\.HashData|SHA512\.HashData|RandomNumberGenerator)/,
};

// -- Pattern count -----------------------------------------------------------

export function getPatternCount(): number {
  return Object.keys(DIRECT_CALLS).length
    + Object.keys(MEMBER_CALLS).length
    + STORAGE_READ_METHODS.size
    + STORAGE_WRITE_METHODS.size;
}
