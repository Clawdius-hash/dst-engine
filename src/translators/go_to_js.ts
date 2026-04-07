/**
 * Go → JS Security Translator for DST
 *
 * Translates Go security-relevant patterns into JS equivalents
 * that the existing JS mapper can classify into the neural map.
 *
 * NOT a Go→JS transpiler. Only translates patterns that matter
 * for security analysis: data flows, sinks, sources, controls.
 * Everything else passes through as-is (tree-sitter is forgiving).
 *
 * Each rule is ATOMIC: one pattern, one replacement. Parallelizable.
 *
 * Go has unique challenges vs Python:
 *   - Multi-return values (val, err := ...)
 *   - Method receivers (func (h *Handler) ServeHTTP(...))
 *   - Implicit interfaces (no implements keyword)
 *   - Goroutines and channels (concurrency primitives)
 *   - Package-qualified calls (http.Get, sql.Open)
 *   - Type assertions and type switches
 */

export interface TranslationRule {
  /** Unique ID for this rule */
  id: string;
  /** What security concept this translates */
  category: 'ingress' | 'egress' | 'storage' | 'external' | 'control' | 'transform' | 'structural';
  /** Regex to match Go pattern */
  match: RegExp;
  /** JS replacement (uses $1, $2 capture groups) */
  replace: string;
}

// ── INGRESS: where external data enters ────────────────────────────

const INGRESS_RULES: TranslationRule[] = [
  // ── net/http (stdlib) ──
  { id: 'go-http-formvalue',        category: 'ingress', match: /r\.FormValue\s*\(\s*["'](\w+)["']\s*\)/g,             replace: 'req.body.$1' },
  { id: 'go-http-postformvalue',    category: 'ingress', match: /r\.PostFormValue\s*\(\s*["'](\w+)["']\s*\)/g,         replace: 'req.body.$1' },
  { id: 'go-http-url-query-get',    category: 'ingress', match: /r\.URL\.Query\(\)\.Get\s*\(\s*["'](\w+)["']\s*\)/g,  replace: 'req.query.$1' },
  { id: 'go-http-url-query',        category: 'ingress', match: /r\.URL\.Query\(\)/g,                                   replace: 'req.query' },
  { id: 'go-http-header-get',       category: 'ingress', match: /r\.Header\.Get\s*\(\s*["']([^"']+)["']\s*\)/g,        replace: 'req.headers["$1"]' },
  { id: 'go-http-header',           category: 'ingress', match: /r\.Header/g,                                            replace: 'req.headers' },
  { id: 'go-http-body',             category: 'ingress', match: /r\.Body/g,                                              replace: 'req.body' },
  { id: 'go-http-cookie',           category: 'ingress', match: /r\.Cookie\s*\(\s*["'](\w+)["']\s*\)/g,                replace: 'req.cookies.$1' },
  { id: 'go-http-url-path',         category: 'ingress', match: /r\.URL\.Path/g,                                         replace: 'req.path' },
  { id: 'go-http-url-string',       category: 'ingress', match: /r\.URL\.String\(\)/g,                                  replace: 'req.url' },
  { id: 'go-http-host',             category: 'ingress', match: /r\.Host/g,                                              replace: 'req.hostname' },
  { id: 'go-http-remoteaddr',       category: 'ingress', match: /r\.RemoteAddr/g,                                        replace: 'req.ip' },
  { id: 'go-http-method',           category: 'ingress', match: /r\.Method/g,                                            replace: 'req.method' },
  { id: 'go-http-parseform',        category: 'ingress', match: /r\.ParseForm\(\)/g,                                    replace: '/* req.body parsed */' },
  { id: 'go-http-parsemultipart',   category: 'ingress', match: /r\.ParseMultipartForm\([^)]*\)/g,                      replace: '/* req.files parsed */' },
  { id: 'go-http-formfile',         category: 'ingress', match: /r\.FormFile\s*\(\s*["'](\w+)["']\s*\)/g,              replace: 'req.files.$1' },

  // ── Gin framework ──
  { id: 'go-gin-query',             category: 'ingress', match: /c\.Query\s*\(\s*["'](\w+)["']\s*\)/g,                 replace: 'req.query.$1' },
  { id: 'go-gin-defaultquery',      category: 'ingress', match: /c\.DefaultQuery\s*\(\s*["'](\w+)["']\s*,[^)]*\)/g,    replace: 'req.query.$1' },
  { id: 'go-gin-postform',          category: 'ingress', match: /c\.PostForm\s*\(\s*["'](\w+)["']\s*\)/g,              replace: 'req.body.$1' },
  { id: 'go-gin-defaultpostform',   category: 'ingress', match: /c\.DefaultPostForm\s*\(\s*["'](\w+)["']\s*,[^)]*\)/g, replace: 'req.body.$1' },
  { id: 'go-gin-param',             category: 'ingress', match: /c\.Param\s*\(\s*["'](\w+)["']\s*\)/g,                 replace: 'req.params.$1' },
  { id: 'go-gin-bind-json',         category: 'ingress', match: /c\.(?:Bind|ShouldBind)JSON\s*\(/g,                    replace: '/* req.body = */ JSON.parse(' },
  { id: 'go-gin-bind',              category: 'ingress', match: /c\.(?:Bind|ShouldBind|MustBind)\s*\(/g,               replace: '/* req.body = */ JSON.parse(' },
  { id: 'go-gin-getHeader',         category: 'ingress', match: /c\.GetHeader\s*\(\s*["']([^"']+)["']\s*\)/g,          replace: 'req.headers["$1"]' },
  { id: 'go-gin-cookie',            category: 'ingress', match: /c\.Cookie\s*\(\s*["'](\w+)["']\s*\)/g,                replace: 'req.cookies.$1' },
  { id: 'go-gin-formfile',          category: 'ingress', match: /c\.FormFile\s*\(\s*["'](\w+)["']\s*\)/g,              replace: 'req.files.$1' },
  { id: 'go-gin-clientip',          category: 'ingress', match: /c\.ClientIP\(\)/g,                                     replace: 'req.ip' },
  { id: 'go-gin-fullpath',          category: 'ingress', match: /c\.FullPath\(\)/g,                                     replace: 'req.path' },
  { id: 'go-gin-request',           category: 'ingress', match: /c\.Request/g,                                           replace: 'req' },

  // ── Chi router params ──
  { id: 'go-chi-urlparam',          category: 'ingress', match: /chi\.URLParam\s*\(\s*r\s*,\s*["'](\w+)["']\s*\)/g,   replace: 'req.params.$1' },

  // ── Gorilla mux params ──
  { id: 'go-gorilla-vars',          category: 'ingress', match: /mux\.Vars\s*\(\s*r\s*\)\s*\[\s*["'](\w+)["']\s*\]/g, replace: 'req.params.$1' },
  { id: 'go-gorilla-vars-bare',     category: 'ingress', match: /mux\.Vars\s*\(\s*r\s*\)/g,                             replace: 'req.params' },

  // ── Echo framework (unique patterns) ──
  { id: 'go-echo-queryparam',       category: 'ingress', match: /c\.QueryParam\s*\(\s*["'](\w+)["']\s*\)/g,            replace: 'req.query.$1' },

  // ── Shared Go ctx patterns (Echo c.FormValue, c.Param; also Fiber c.FormValue) ──
  // These overlap with Gin's c.PostForm/c.Query/c.Param — but c.FormValue and c.Param
  // are distinct Go identifiers used by Echo/Fiber, while Gin uses c.PostForm.
  { id: 'go-ctx-formvalue',         category: 'ingress', match: /c\.FormValue\s*\(\s*["'](\w+)["']\s*\)/g,             replace: 'req.body.$1' },
  { id: 'go-ctx-param',             category: 'ingress', match: /c\.Param\s*\(\s*["'](\w+)["']\s*\)/g,                 replace: 'req.params.$1' },

  // ── Fiber framework (unique patterns) ──
  { id: 'go-fiber-params',          category: 'ingress', match: /c\.Params\s*\(\s*["'](\w+)["']\s*\)/g,                replace: 'req.params.$1' },
  { id: 'go-fiber-body',            category: 'ingress', match: /c\.Body\(\)/g,                                         replace: 'req.body' },
  { id: 'go-fiber-bodyparser',      category: 'ingress', match: /c\.BodyParser\s*\(/g,                                  replace: '/* req.body = */ JSON.parse(' },

  // ── ioutil / io (body reading) ──
  { id: 'go-ioutil-readall',        category: 'ingress', match: /ioutil\.ReadAll\s*\(\s*r\.Body\s*\)/g,                replace: 'req.body' },
  { id: 'go-io-readall',            category: 'ingress', match: /io\.ReadAll\s*\(\s*r\.Body\s*\)/g,                    replace: 'req.body' },

  // ── stdlib ──
  { id: 'go-os-args',               category: 'ingress', match: /os\.Args/g,                                             replace: 'process.argv' },
  { id: 'go-os-getenv',             category: 'ingress', match: /os\.Getenv\s*\(\s*["'](\w+)["']\s*\)/g,               replace: 'process.env.$1' },
  { id: 'go-os-lookupenv',          category: 'ingress', match: /os\.LookupEnv\s*\(\s*["'](\w+)["']\s*\)/g,            replace: 'process.env.$1' },
  { id: 'go-os-stdin',              category: 'ingress', match: /os\.Stdin/g,                                            replace: 'process.stdin' },
  { id: 'go-bufio-scanner',         category: 'ingress', match: /bufio\.NewScanner\s*\(\s*os\.Stdin\s*\)/g,             replace: 'readline(process.stdin)' },
  { id: 'go-flag-string',           category: 'ingress', match: /flag\.String\s*\(\s*["'](\w+)["']/g,                  replace: '/* process.argv */ flag_$1' },
  { id: 'go-flag-parse',            category: 'ingress', match: /flag\.Parse\(\)/g,                                     replace: '/* process.argv parsed */' },

  // ── gRPC metadata ingress ──
  { id: 'go-grpc-metadata',         category: 'ingress', match: /metadata\.FromIncomingContext\s*\(/g,                  replace: '/* req.headers = */ grpc_metadata(' },
];

// ── STORAGE: databases, file system, caches ────────────────────────

const STORAGE_RULES: TranslationRule[] = [
  // ── database/sql (stdlib) ──
  { id: 'go-db-query',              category: 'storage', match: /db\.Query\s*\(/g,                                      replace: 'db.query(' },
  { id: 'go-db-queryrow',           category: 'storage', match: /db\.QueryRow\s*\(/g,                                   replace: 'db.query(' },
  { id: 'go-db-querycontext',       category: 'storage', match: /db\.QueryContext\s*\(/g,                               replace: 'db.query(' },
  { id: 'go-db-queryrowcontext',    category: 'storage', match: /db\.QueryRowContext\s*\(/g,                            replace: 'db.query(' },
  { id: 'go-db-exec',               category: 'storage', match: /db\.Exec\s*\(/g,                                       replace: 'db.query(' },
  { id: 'go-db-execcontext',        category: 'storage', match: /db\.ExecContext\s*\(/g,                                replace: 'db.query(' },
  { id: 'go-db-prepare',            category: 'storage', match: /db\.Prepare\s*\(/g,                                    replace: 'db.query(' },
  { id: 'go-db-preparecontext',     category: 'storage', match: /db\.PrepareContext\s*\(/g,                             replace: 'db.query(' },
  { id: 'go-sql-open',              category: 'storage', match: /sql\.Open\s*\(/g,                                      replace: 'db.connect(' },
  { id: 'go-rows-scan',             category: 'storage', match: /rows\.Scan\s*\(/g,                                     replace: 'db.query(' },
  { id: 'go-row-scan',              category: 'storage', match: /row\.Scan\s*\(/g,                                      replace: 'db.query(' },

  // ── Tx (transaction) ──
  { id: 'go-tx-query',              category: 'storage', match: /tx\.Query\s*\(/g,                                      replace: 'db.query(' },
  { id: 'go-tx-queryrow',           category: 'storage', match: /tx\.QueryRow\s*\(/g,                                   replace: 'db.query(' },
  { id: 'go-tx-exec',               category: 'storage', match: /tx\.Exec\s*\(/g,                                       replace: 'db.query(' },
  { id: 'go-tx-prepare',            category: 'storage', match: /tx\.Prepare\s*\(/g,                                    replace: 'db.query(' },

  // ── Stmt (prepared statement) ──
  { id: 'go-stmt-query',            category: 'storage', match: /stmt\.Query\s*\(/g,                                    replace: 'db.query(' },
  { id: 'go-stmt-queryrow',         category: 'storage', match: /stmt\.QueryRow\s*\(/g,                                 replace: 'db.query(' },
  { id: 'go-stmt-exec',             category: 'storage', match: /stmt\.Exec\s*\(/g,                                     replace: 'db.query(' },

  // ── GORM ──
  { id: 'go-gorm-find',             category: 'storage', match: /\.Find\s*\(\s*&/g,                                     replace: '.find(&' },
  { id: 'go-gorm-first',            category: 'storage', match: /\.First\s*\(\s*&/g,                                    replace: '.findOne(&' },
  { id: 'go-gorm-last',             category: 'storage', match: /\.Last\s*\(\s*&/g,                                     replace: '.findOne(&' },
  { id: 'go-gorm-create',           category: 'storage', match: /\.Create\s*\(\s*&/g,                                   replace: '.create(&' },
  { id: 'go-gorm-save',             category: 'storage', match: /\.Save\s*\(\s*&/g,                                     replace: '.save(&' },
  { id: 'go-gorm-delete',           category: 'storage', match: /\.Delete\s*\(\s*&/g,                                   replace: '.delete(&' },
  { id: 'go-gorm-update',           category: 'storage', match: /\.Updates?\s*\(\s*(?:map|&)/g,                         replace: '.update(' },
  { id: 'go-gorm-where',            category: 'storage', match: /\.Where\s*\(/g,                                        replace: '.where(' },
  { id: 'go-gorm-raw',              category: 'storage', match: /\.Raw\s*\(/g,                                          replace: '.raw(' },
  { id: 'go-gorm-exec',             category: 'storage', match: /\.Exec\s*\(\s*"/g,                                     replace: '.raw("' },

  // ── sqlx ──
  { id: 'go-sqlx-get',              category: 'storage', match: /sqlx\.Get\s*\(/g,                                      replace: 'db.query(' },
  { id: 'go-sqlx-select',           category: 'storage', match: /sqlx\.Select\s*\(/g,                                   replace: 'db.query(' },
  { id: 'go-sqlx-named',            category: 'storage', match: /sqlx\.Named\s*\(/g,                                    replace: 'db.query(' },
  { id: 'go-sqlx-in',               category: 'storage', match: /sqlx\.In\s*\(/g,                                       replace: 'db.query(' },

  // ── pgx (PostgreSQL) ──
  { id: 'go-pgx-query',             category: 'storage', match: /(?:pool|conn)\.Query\s*\(/g,                           replace: 'db.query(' },
  { id: 'go-pgx-queryrow',          category: 'storage', match: /(?:pool|conn)\.QueryRow\s*\(/g,                        replace: 'db.query(' },
  { id: 'go-pgx-exec',              category: 'storage', match: /(?:pool|conn)\.Exec\s*\(/g,                            replace: 'db.query(' },

  // ── Redis ──
  { id: 'go-redis-set',             category: 'storage', match: /rdb\.Set\s*\(/g,                                       replace: 'redis.set(' },
  { id: 'go-redis-get',             category: 'storage', match: /rdb\.Get\s*\(/g,                                       replace: 'redis.get(' },
  { id: 'go-redis-del',             category: 'storage', match: /rdb\.Del\s*\(/g,                                       replace: 'redis.del(' },
  { id: 'go-redis-client-set',      category: 'storage', match: /client\.Set\s*\(/g,                                    replace: 'redis.set(' },
  { id: 'go-redis-client-get',      category: 'storage', match: /client\.Get\s*\(/g,                                    replace: 'redis.get(' },

  // ── File system ──
  { id: 'go-os-open',               category: 'storage', match: /os\.Open\s*\(/g,                                       replace: 'fs.readFileSync(' },
  { id: 'go-os-openfile',           category: 'storage', match: /os\.OpenFile\s*\(/g,                                   replace: 'fs.readFileSync(' },
  { id: 'go-os-create',             category: 'storage', match: /os\.Create\s*\(/g,                                     replace: 'fs.writeFileSync(' },
  { id: 'go-os-readfile',           category: 'storage', match: /os\.ReadFile\s*\(/g,                                   replace: 'fs.readFileSync(' },
  { id: 'go-os-writefile',          category: 'storage', match: /os\.WriteFile\s*\(/g,                                  replace: 'fs.writeFileSync(' },
  { id: 'go-os-remove',             category: 'storage', match: /os\.Remove\s*\(/g,                                     replace: 'fs.unlinkSync(' },
  { id: 'go-os-removeall',          category: 'storage', match: /os\.RemoveAll\s*\(/g,                                  replace: 'fs.rmSync(' },
  { id: 'go-os-mkdir',              category: 'storage', match: /os\.MkdirAll?\s*\(/g,                                  replace: 'fs.mkdirSync(' },
  { id: 'go-ioutil-readfile',       category: 'storage', match: /ioutil\.ReadFile\s*\(/g,                               replace: 'fs.readFileSync(' },
  { id: 'go-ioutil-writefile',      category: 'storage', match: /ioutil\.WriteFile\s*\(/g,                              replace: 'fs.writeFileSync(' },
  { id: 'go-filepath-join',         category: 'storage', match: /filepath\.Join\s*\(/g,                                 replace: 'path.join(' },

  // ── Bolt/bbolt (embedded KV) ──
  { id: 'go-bolt-put',              category: 'storage', match: /bucket\.Put\s*\(/g,                                    replace: 'db.save(' },
  { id: 'go-bolt-get',              category: 'storage', match: /bucket\.Get\s*\(/g,                                    replace: 'db.query(' },
];

// ── EXTERNAL: network, HTTP, system calls ──────────────────────────

const EXTERNAL_RULES: TranslationRule[] = [
  // ── HTTP client (stdlib) ──
  { id: 'go-http-get',              category: 'external', match: /http\.Get\s*\(/g,                                     replace: 'fetch(' },
  { id: 'go-http-post',             category: 'external', match: /http\.Post\s*\(/g,                                    replace: 'fetch(' },
  { id: 'go-http-postform',         category: 'external', match: /http\.PostForm\s*\(/g,                                replace: 'fetch(' },
  { id: 'go-http-head',             category: 'external', match: /http\.Head\s*\(/g,                                    replace: 'fetch(' },
  { id: 'go-http-newrequest',       category: 'external', match: /http\.NewRequest\s*\(/g,                              replace: 'new Request(' },
  { id: 'go-http-newrequestwctx',   category: 'external', match: /http\.NewRequestWithContext\s*\(/g,                   replace: 'new Request(' },
  { id: 'go-http-client-do',        category: 'external', match: /client\.Do\s*\(/g,                                    replace: 'fetch(' },
  { id: 'go-http-defaultclient',    category: 'external', match: /http\.DefaultClient\.Do\s*\(/g,                       replace: 'fetch(' },

  // ── os/exec (command execution) ──
  { id: 'go-exec-command',          category: 'external', match: /exec\.Command\s*\(/g,                                 replace: 'child_process.exec(' },
  { id: 'go-exec-commandctx',       category: 'external', match: /exec\.CommandContext\s*\(/g,                          replace: 'child_process.exec(' },
  { id: 'go-cmd-run',               category: 'external', match: /cmd\.Run\s*\(\s*\)/g,                                 replace: 'child_process.exec()' },
  { id: 'go-cmd-output',            category: 'external', match: /cmd\.Output\s*\(\s*\)/g,                              replace: 'child_process.exec()' },
  { id: 'go-cmd-combined',          category: 'external', match: /cmd\.CombinedOutput\s*\(\s*\)/g,                      replace: 'child_process.exec()' },
  { id: 'go-cmd-start',             category: 'external', match: /cmd\.Start\s*\(\s*\)/g,                               replace: 'child_process.exec()' },

  // ── net (low-level networking) ──
  { id: 'go-net-dial',              category: 'external', match: /net\.Dial\s*\(/g,                                     replace: 'fetch(' },
  { id: 'go-net-dialcontext',       category: 'external', match: /net\.DialContext\s*\(/g,                              replace: 'fetch(' },
  { id: 'go-net-dialtimeout',       category: 'external', match: /net\.DialTimeout\s*\(/g,                              replace: 'fetch(' },
  { id: 'go-net-listen',            category: 'external', match: /net\.Listen\s*\(/g,                                   replace: 'net.createServer(' },
  { id: 'go-tls-dial',              category: 'external', match: /tls\.Dial\s*\(/g,                                     replace: 'fetch(' },

  // ── gRPC ──
  { id: 'go-grpc-dial',             category: 'external', match: /grpc\.Dial\s*\(/g,                                    replace: 'fetch(' },
  { id: 'go-grpc-newclient',        category: 'external', match: /grpc\.NewClient\s*\(/g,                               replace: 'fetch(' },

  // ── plugin loading (dynamic code) ──
  { id: 'go-plugin-open',           category: 'external', match: /plugin\.Open\s*\(/g,                                  replace: 'require(' },

  // ── reflect (dynamic invocation) ──
  { id: 'go-reflect-call',          category: 'external', match: /reflect\.ValueOf\([^)]*\)\.(?:Call|MethodByName)\s*\(/g, replace: 'eval(' },
  { id: 'go-reflect-makefunc',      category: 'external', match: /reflect\.MakeFunc\s*\(/g,                             replace: 'eval(' },

  // ── unsafe (memory manipulation) ──
  { id: 'go-unsafe-pointer',        category: 'external', match: /unsafe\.Pointer\s*\(/g,                               replace: '/* unsafe_pointer */ eval(' },
];

// ── EGRESS: responses, output ──────────────────────────────────────

const EGRESS_RULES: TranslationRule[] = [
  // ── net/http (stdlib) ResponseWriter ──
  { id: 'go-http-write',            category: 'egress', match: /w\.Write\s*\(/g,                                        replace: 'res.send(' },
  { id: 'go-http-writeheader',      category: 'egress', match: /w\.WriteHeader\s*\(/g,                                  replace: 'res.status(' },
  { id: 'go-http-header-set',       category: 'egress', match: /w\.Header\(\)\.Set\s*\(/g,                              replace: 'res.set(' },
  { id: 'go-http-header-add',       category: 'egress', match: /w\.Header\(\)\.Add\s*\(/g,                              replace: 'res.set(' },
  { id: 'go-fmt-fprintf-w',         category: 'egress', match: /fmt\.Fprintf\s*\(\s*w\s*,/g,                            replace: 'res.send(' },
  { id: 'go-fmt-fprintln-w',        category: 'egress', match: /fmt\.Fprintln\s*\(\s*w\s*,/g,                           replace: 'res.send(' },
  { id: 'go-fmt-fprint-w',          category: 'egress', match: /fmt\.Fprint\s*\(\s*w\s*,/g,                             replace: 'res.send(' },
  { id: 'go-http-redirect',         category: 'egress', match: /http\.Redirect\s*\(/g,                                  replace: 'res.redirect(' },
  { id: 'go-http-error',            category: 'egress', match: /http\.Error\s*\(/g,                                     replace: 'res.send(' },
  { id: 'go-http-notfound',         category: 'egress', match: /http\.NotFound\s*\(/g,                                  replace: 'res.status(404).send(' },
  { id: 'go-http-serveFile',        category: 'egress', match: /http\.ServeFile\s*\(/g,                                 replace: 'res.sendFile(' },
  { id: 'go-http-servecontent',     category: 'egress', match: /http\.ServeContent\s*\(/g,                              replace: 'res.sendFile(' },

  // ── JSON encoding to response ──
  { id: 'go-json-newencoder-w',     category: 'egress', match: /json\.NewEncoder\s*\(\s*w\s*\)\.Encode\s*\(/g,          replace: 'res.json(' },
  { id: 'go-json-newencoder',       category: 'egress', match: /json\.NewEncoder\s*\(\s*w\s*\)/g,                       replace: 'res.json' },

  // ── Template rendering ──
  { id: 'go-template-execute',      category: 'egress', match: /(?:tmpl|tpl|t)\.Execute\s*\(\s*w\s*,/g,                 replace: 'res.render(' },
  { id: 'go-template-executetempl', category: 'egress', match: /(?:tmpl|tpl|t)\.ExecuteTemplate\s*\(\s*w\s*,/g,         replace: 'res.render(' },

  // ── Go framework context egress (shared by Gin, Echo, Fiber) ──
  // Gin: c.JSON(), Echo: c.JSON(), Fiber: c.JSON() — all map to res.json
  { id: 'go-ctx-json',              category: 'egress', match: /c\.JSON\s*\(/g,                                         replace: 'res.json(' },
  { id: 'go-ctx-string',            category: 'egress', match: /c\.String\s*\(/g,                                       replace: 'res.send(' },
  { id: 'go-ctx-html',              category: 'egress', match: /c\.HTML\s*\(/g,                                         replace: 'res.render(' },
  { id: 'go-ctx-xml',               category: 'egress', match: /c\.XML\s*\(/g,                                          replace: 'res.send(' },
  { id: 'go-ctx-redirect',          category: 'egress', match: /c\.Redirect\s*\(/g,                                     replace: 'res.redirect(' },
  { id: 'go-ctx-data',              category: 'egress', match: /c\.Data\s*\(/g,                                         replace: 'res.send(' },
  { id: 'go-ctx-file',              category: 'egress', match: /c\.File\s*\(/g,                                         replace: 'res.sendFile(' },
  { id: 'go-ctx-setcookie',         category: 'egress', match: /c\.SetCookie\s*\(/g,                                    replace: 'res.cookie(' },
  { id: 'go-ctx-header',            category: 'egress', match: /c\.Header\s*\(\s*"/g,                                   replace: 'res.set("' },
  { id: 'go-ctx-status',            category: 'egress', match: /c\.Status\s*\(/g,                                       replace: 'res.status(' },
  { id: 'go-ctx-abort-json',        category: 'egress', match: /c\.AbortWithStatusJSON\s*\(/g,                          replace: 'res.status(' },
  { id: 'go-ctx-abort-status',      category: 'egress', match: /c\.AbortWithStatus\s*\(/g,                              replace: 'res.status(' },
  { id: 'go-ctx-render',            category: 'egress', match: /c\.Render\s*\(/g,                                       replace: 'res.render(' },

  // ── Fiber-specific egress (unique to Fiber) ──
  { id: 'go-fiber-sendstring',      category: 'egress', match: /c\.SendString\s*\(/g,                                   replace: 'res.send(' },
  { id: 'go-fiber-sendstatus',      category: 'egress', match: /c\.SendStatus\s*\(/g,                                   replace: 'res.status(' },

  // ── Logging (egress to logs — security relevant for CWE-532) ──
  { id: 'go-log-print',             category: 'egress', match: /log\.Print\s*\(/g,                                      replace: 'console.log(' },
  { id: 'go-log-printf',            category: 'egress', match: /log\.Printf\s*\(/g,                                     replace: 'console.log(' },
  { id: 'go-log-println',           category: 'egress', match: /log\.Println\s*\(/g,                                    replace: 'console.log(' },
  { id: 'go-log-fatal',             category: 'egress', match: /log\.Fatal\s*\(/g,                                      replace: 'console.error(' },
  { id: 'go-log-fatalf',            category: 'egress', match: /log\.Fatalf\s*\(/g,                                     replace: 'console.error(' },
  { id: 'go-fmt-println',           category: 'egress', match: /fmt\.Println\s*\(/g,                                    replace: 'console.log(' },
  { id: 'go-fmt-printf',            category: 'egress', match: /fmt\.Printf\s*\(/g,                                     replace: 'console.log(' },

  // ── http.FileServer (directory listing, CWE-548) ──
  { id: 'go-http-fileserver',       category: 'egress', match: /http\.FileServer\s*\(/g,                                replace: 'res.sendFile(' },
];

// ── CONTROL: security checks, validation ───────────────────────────

const CONTROL_RULES: TranslationRule[] = [
  // ── bcrypt ──
  { id: 'go-bcrypt-generate',       category: 'control', match: /bcrypt\.GenerateFromPassword\s*\(/g,                   replace: 'bcrypt.hash(' },
  { id: 'go-bcrypt-compare',        category: 'control', match: /bcrypt\.CompareHashAndPassword\s*\(/g,                 replace: 'bcrypt.compare(' },

  // ── crypto/sha256 ──
  { id: 'go-sha256-new',            category: 'control', match: /sha256\.New\s*\(\s*\)/g,                               replace: "crypto.createHash('sha256')" },
  { id: 'go-sha256-sum',            category: 'control', match: /sha256\.Sum256\s*\(/g,                                 replace: "crypto.createHash('sha256').update(" },
  { id: 'go-sha1-new',              category: 'control', match: /sha1\.New\s*\(\s*\)/g,                                 replace: "crypto.createHash('sha1')" },
  { id: 'go-sha1-sum',              category: 'control', match: /sha1\.Sum\s*\(/g,                                      replace: "crypto.createHash('sha1').update(" },
  { id: 'go-md5-new',               category: 'control', match: /md5\.New\s*\(\s*\)/g,                                  replace: "crypto.createHash('md5')" },
  { id: 'go-md5-sum',               category: 'control', match: /md5\.Sum\s*\(/g,                                       replace: "crypto.createHash('md5').update(" },

  // ── HMAC ──
  { id: 'go-hmac-new',              category: 'control', match: /hmac\.New\s*\(/g,                                      replace: 'crypto.createHmac(' },
  { id: 'go-hmac-equal',            category: 'control', match: /hmac\.Equal\s*\(/g,                                    replace: 'crypto.timingSafeEqual(' },

  // ── crypto/aes, crypto/cipher ──
  { id: 'go-aes-newcipher',         category: 'control', match: /aes\.NewCipher\s*\(/g,                                 replace: 'crypto.createCipheriv(' },
  { id: 'go-cipher-gcm',            category: 'control', match: /cipher\.NewGCM\s*\(/g,                                 replace: 'crypto.createCipheriv(' },
  { id: 'go-cipher-cbc',            category: 'control', match: /cipher\.NewCBCEncrypter\s*\(/g,                        replace: 'crypto.createCipheriv(' },
  { id: 'go-cipher-cbc-dec',        category: 'control', match: /cipher\.NewCBCDecrypter\s*\(/g,                        replace: 'crypto.createDecipheriv(' },

  // ── crypto/rand ──
  { id: 'go-crypto-rand-read',      category: 'control', match: /rand\.Read\s*\(/g,                                     replace: 'crypto.randomBytes(' },
  { id: 'go-crypto-rand-int',       category: 'control', match: /rand\.Int\s*\(/g,                                      replace: 'crypto.randomBytes(' },

  // ── subtle (constant-time comparison) ──
  { id: 'go-subtle-consttime',      category: 'control', match: /subtle\.ConstantTimeCompare\s*\(/g,                    replace: 'crypto.timingSafeEqual(' },

  // ── JWT (dgrijalva/golang-jwt) ──
  { id: 'go-jwt-parse',             category: 'control', match: /jwt\.Parse\s*\(/g,                                     replace: 'jwt.verify(' },
  { id: 'go-jwt-parsewithclaims',   category: 'control', match: /jwt\.ParseWithClaims\s*\(/g,                           replace: 'jwt.verify(' },
  { id: 'go-jwt-newwithclaims',     category: 'control', match: /jwt\.NewWithClaims\s*\(/g,                             replace: 'jwt.sign(' },
  { id: 'go-jwt-signedstring',      category: 'control', match: /\.SignedString\s*\(/g,                                 replace: '.sign(' },

  // ── html/template vs text/template (XSS) ──
  { id: 'go-template-html-cast',    category: 'control', match: /template\.HTML\s*\(/g,                                 replace: '/* UNSAFE_RAW_HTML */ res.send(' },
  { id: 'go-template-js-cast',      category: 'control', match: /template\.JS\s*\(/g,                                   replace: '/* UNSAFE_RAW_JS */ eval(' },
  { id: 'go-template-url-cast',     category: 'control', match: /template\.URL\s*\(/g,                                  replace: '/* UNSAFE_RAW_URL */ res.redirect(' },

  // ── html sanitization ──
  { id: 'go-html-escapestring',     category: 'control', match: /html\.EscapeString\s*\(/g,                             replace: 'escapeHtml(' },
  { id: 'go-html-unescapestring',   category: 'control', match: /html\.UnescapeString\s*\(/g,                           replace: 'decodeHtml(' },
  { id: 'go-url-queryescape',       category: 'control', match: /url\.QueryEscape\s*\(/g,                               replace: 'encodeURIComponent(' },
  { id: 'go-url-pathescape',        category: 'control', match: /url\.PathEscape\s*\(/g,                                replace: 'encodeURIComponent(' },

  // ── CSRF (gorilla/csrf) ──
  { id: 'go-csrf-token',            category: 'control', match: /csrf\.Token\s*\(\s*r\s*\)/g,                           replace: '/* csrf_token */' },
  { id: 'go-csrf-templatefield',    category: 'control', match: /csrf\.TemplateField\s*\(\s*r\s*\)/g,                   replace: '/* csrf_field */' },

  // ── Deserialization / encoding ──
  { id: 'go-json-unmarshal',        category: 'transform', match: /json\.Unmarshal\s*\(/g,                              replace: 'JSON.parse(' },
  { id: 'go-json-newdecoder',       category: 'transform', match: /json\.NewDecoder\s*\([^)]*\)\.Decode\s*\(/g,        replace: 'JSON.parse(' },
  { id: 'go-json-marshal',          category: 'transform', match: /json\.Marshal\s*\(/g,                                replace: 'JSON.stringify(' },
  { id: 'go-xml-unmarshal',         category: 'transform', match: /xml\.Unmarshal\s*\(/g,                               replace: 'JSON.parse(' },
  { id: 'go-xml-newdecoder',        category: 'transform', match: /xml\.NewDecoder\s*\(/g,                              replace: 'JSON.parse(' },
  { id: 'go-yaml-unmarshal',        category: 'transform', match: /yaml\.Unmarshal\s*\(/g,                              replace: 'JSON.parse(' },
  { id: 'go-gob-newdecoder',        category: 'transform', match: /gob\.NewDecoder\s*\(/g,                              replace: 'JSON.parse(' },
  { id: 'go-gob-newencoder',        category: 'transform', match: /gob\.NewEncoder\s*\(/g,                              replace: 'JSON.stringify(' },
  { id: 'go-base64-decode',         category: 'transform', match: /base64\.StdEncoding\.DecodeString\s*\(/g,            replace: 'atob(' },
  { id: 'go-base64-encode',         category: 'transform', match: /base64\.StdEncoding\.EncodeToString\s*\(/g,          replace: 'btoa(' },

  // ── TLS configuration (CWE-295) ──
  { id: 'go-tls-insecure-skip',     category: 'control', match: /InsecureSkipVerify\s*:\s*true/g,                       replace: '/* TLS_VERIFY_DISABLED */ rejectUnauthorized: false' },

  // ── Validator package ──
  { id: 'go-validator-struct',      category: 'control', match: /validate\.Struct\s*\(/g,                               replace: 'validator.validate(' },
  { id: 'go-validator-var',         category: 'control', match: /validate\.Var\s*\(/g,                                  replace: 'validator.validate(' },
];

// ── STRUCTURAL: function signatures, routing, imports ────────────────

const STRUCTURAL_RULES: TranslationRule[] = [
  // ── net/http handler signature ──
  { id: 'go-http-handler',          category: 'structural', match: /func\s+(\w+)\s*\(\s*w\s+http\.ResponseWriter\s*,\s*r\s+\*http\.Request\s*\)/g,
    replace: "function $1(req, res) {" },
  { id: 'go-http-handler-method',   category: 'structural', match: /func\s+\(\s*\w+\s+\*?\w+\s*\)\s+(\w+)\s*\(\s*w\s+http\.ResponseWriter\s*,\s*r\s+\*http\.Request\s*\)/g,
    replace: "function $1(req, res) {" },

  // ── http.HandleFunc → app.get ──
  { id: 'go-http-handlefunc',       category: 'structural', match: /http\.HandleFunc\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)\s*\)/g,
    replace: "app.get('$1', $2)" },
  { id: 'go-http-handle',           category: 'structural', match: /http\.Handle\s*\(\s*["']([^"']+)["']\s*,/g,
    replace: "app.get('$1'," },

  // ── mux/chi router ──
  { id: 'go-mux-handlefunc-get',    category: 'structural', match: /(?:mux|router|r)\.HandleFunc\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)\s*\)\.Methods\s*\(\s*["']GET["']\s*\)/g,
    replace: "app.get('$1', $2)" },
  { id: 'go-mux-handlefunc-post',   category: 'structural', match: /(?:mux|router|r)\.HandleFunc\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)\s*\)\.Methods\s*\(\s*["']POST["']\s*\)/g,
    replace: "app.post('$1', $2)" },
  { id: 'go-mux-handlefunc',        category: 'structural', match: /(?:mux|router|r)\.HandleFunc\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)\s*\)/g,
    replace: "app.get('$1', $2)" },
  { id: 'go-chi-get',               category: 'structural', match: /(?:mux|router|r)\.Get\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)\s*\)/g,
    replace: "app.get('$1', $2)" },
  { id: 'go-chi-post',              category: 'structural', match: /(?:mux|router|r)\.Post\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)\s*\)/g,
    replace: "app.post('$1', $2)" },
  { id: 'go-chi-put',               category: 'structural', match: /(?:mux|router|r)\.Put\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)\s*\)/g,
    replace: "app.put('$1', $2)" },
  { id: 'go-chi-delete',            category: 'structural', match: /(?:mux|router|r)\.Delete\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)\s*\)/g,
    replace: "app.delete('$1', $2)" },

  // ── Gin router ──
  { id: 'go-gin-get',               category: 'structural', match: /(?:router|engine|g|app)\.GET\s*\(\s*["']([^"']+)["']\s*,/g,
    replace: "app.get('$1', (req, res) =>" },
  { id: 'go-gin-post',              category: 'structural', match: /(?:router|engine|g|app)\.POST\s*\(\s*["']([^"']+)["']\s*,/g,
    replace: "app.post('$1', (req, res) =>" },
  { id: 'go-gin-put',               category: 'structural', match: /(?:router|engine|g|app)\.PUT\s*\(\s*["']([^"']+)["']\s*,/g,
    replace: "app.put('$1', (req, res) =>" },
  { id: 'go-gin-delete',            category: 'structural', match: /(?:router|engine|g|app)\.DELETE\s*\(\s*["']([^"']+)["']\s*,/g,
    replace: "app.delete('$1', (req, res) =>" },

  // ── Echo router ──
  { id: 'go-echo-get',              category: 'structural', match: /e\.GET\s*\(\s*["']([^"']+)["']\s*,/g,
    replace: "app.get('$1', (req, res) =>" },
  { id: 'go-echo-post',             category: 'structural', match: /e\.POST\s*\(\s*["']([^"']+)["']\s*,/g,
    replace: "app.post('$1', (req, res) =>" },

  // ── Fiber router ──
  { id: 'go-fiber-get',             category: 'structural', match: /app\.Get\s*\(\s*["']([^"']+)["']\s*,/g,
    replace: "app.get('$1', (req, res) =>" },
  { id: 'go-fiber-post',            category: 'structural', match: /app\.Post\s*\(\s*["']([^"']+)["']\s*,/g,
    replace: "app.post('$1', (req, res) =>" },

  // ── http.ListenAndServe ──
  { id: 'go-http-listenandserve',   category: 'structural', match: /http\.ListenAndServe\s*\(/g,
    replace: 'app.listen(' },
  { id: 'go-http-listenandservetls', category: 'structural', match: /http\.ListenAndServeTLS\s*\(/g,
    replace: 'app.listen(' },

  // ── Generic Go structures ──
  { id: 'go-func',                  category: 'structural', match: /\bfunc\s+(\w+)\s*\(([^)]*)\)\s*(?:\([^)]*\)\s*)?{/g,
    replace: 'function $1($2) {' },
  { id: 'go-method',                category: 'structural', match: /\bfunc\s+\(\s*\w+\s+\*?(\w+)\s*\)\s+(\w+)\s*\(([^)]*)\)\s*(?:\([^)]*\)\s*)?{/g,
    replace: 'function $2($3) { /* method on $1 */' },

  // ── Imports ──
  { id: 'go-import-single',         category: 'structural', match: /^import\s+"([^"]+)"/gm,
    replace: "const $1 = require('$1');" },
  { id: 'go-import-named',          category: 'structural', match: /^\s*(\w+)\s+"([^"]+)"/gm,
    replace: "const $1 = require('$2');" },

  // ── Package declaration ──
  { id: 'go-package',               category: 'structural', match: /^package\s+(\w+)/gm,
    replace: '/* module: $1 */' },

  // ── Middleware ──
  { id: 'go-use-middleware',         category: 'structural', match: /(?:mux|router|r|app|engine)\.Use\s*\(/g,
    replace: 'app.use(' },

  // ── Goroutine (concurrency marker) ──
  { id: 'go-goroutine',             category: 'structural', match: /\bgo\s+func\s*\(/g,
    replace: '/* goroutine */ (async function(' },
  { id: 'go-goroutine-named',       category: 'structural', match: /\bgo\s+(\w+)\s*\(/g,
    replace: '/* goroutine */ $1(' },

  // ── Defer (cleanup marker) ──
  { id: 'go-defer',                 category: 'structural', match: /\bdefer\s+/g,
    replace: '/* defer */ ' },
];

// ── ALL RULES ──────────────────────────────────────────────────────

export const GO_TO_JS_RULES: TranslationRule[] = [
  ...INGRESS_RULES,
  ...STORAGE_RULES,
  ...EXTERNAL_RULES,
  ...EGRESS_RULES,
  ...CONTROL_RULES,
  ...STRUCTURAL_RULES,
];

/**
 * Translate Go source code to JS-like pseudocode for DST analysis.
 * Preserves line numbers (1:1 line mapping).
 * Returns translated code + translation log for debugging.
 */
export function translateGoToJS(goCode: string): { code: string; translations: { line: number; ruleId: string; original: string; replaced: string }[] } {
  const lines = goCode.split('\n');
  const translations: { line: number; ruleId: string; original: string; replaced: string }[] = [];

  for (let i = 0; i < lines.length; i++) {
    const originalLine = lines[i];
    let currentLine = lines[i];

    for (const rule of GO_TO_JS_RULES) {
      // Reset regex lastIndex for global regexes
      rule.match.lastIndex = 0;

      if (rule.match.test(currentLine)) {
        rule.match.lastIndex = 0;
        const before = currentLine;
        currentLine = currentLine.replace(rule.match, rule.replace);
        if (currentLine !== before) {
          translations.push({
            line: i + 1,
            ruleId: rule.id,
            original: before.trim(),
            replaced: currentLine.trim(),
          });
        }
      }
    }

    lines[i] = currentLine;
  }

  return { code: lines.join('\n'), translations };
}

/**
 * Get rule count by category.
 */
export function getRuleStats(): Record<string, number> {
  const stats: Record<string, number> = {};
  for (const rule of GO_TO_JS_RULES) {
    stats[rule.category] = (stats[rule.category] || 0) + 1;
  }
  stats.total = GO_TO_JS_RULES.length;
  return stats;
}
