/**
 * Python → JS Security Translator for DST
 *
 * Translates Python security-relevant patterns into JS equivalents
 * that the existing JS mapper can classify into the neural map.
 *
 * NOT a Python→JS transpiler. Only translates patterns that matter
 * for security analysis: data flows, sinks, sources, controls.
 * Everything else passes through as-is (tree-sitter is forgiving).
 *
 * Each rule is ATOMIC: one pattern, one replacement. Parallelizable.
 */

export interface TranslationRule {
  /** Unique ID for this rule */
  id: string;
  /** What security concept this translates */
  category: 'ingress' | 'egress' | 'storage' | 'external' | 'control' | 'transform' | 'structural';
  /** Regex to match Python pattern */
  match: RegExp;
  /** JS replacement (uses $1, $2 capture groups) */
  replace: string;
}

// ── INGRESS: where external data enters ────────────────────────────

const INGRESS_RULES: TranslationRule[] = [
  // Flask
  { id: 'py-flask-form',      category: 'ingress', match: /request\.form\[['"](\w+)['"]\]/g,         replace: 'req.body.$1' },
  { id: 'py-flask-form-get',  category: 'ingress', match: /request\.form\.get\(['"](\w+)['"]\)/g,    replace: 'req.body.$1' },
  { id: 'py-flask-args',      category: 'ingress', match: /request\.args\[['"](\w+)['"]\]/g,         replace: 'req.query.$1' },
  { id: 'py-flask-args-get',  category: 'ingress', match: /request\.args\.get\(['"](\w+)['"]\)/g,    replace: 'req.query.$1' },
  { id: 'py-flask-json',      category: 'ingress', match: /request\.get_json\(\)/g,                   replace: 'req.body' },
  { id: 'py-flask-data',      category: 'ingress', match: /request\.data/g,                            replace: 'req.body' },
  { id: 'py-flask-values',    category: 'ingress', match: /request\.values\[['"](\w+)['"]\]/g,       replace: 'req.body.$1' },
  { id: 'py-flask-files',     category: 'ingress', match: /request\.files\[['"](\w+)['"]\]/g,        replace: 'req.files.$1' },
  { id: 'py-flask-headers',   category: 'ingress', match: /request\.headers\[['"]([^'"]+)['"]\]/g,   replace: 'req.headers["$1"]' },
  { id: 'py-flask-cookies',   category: 'ingress', match: /request\.cookies\[['"](\w+)['"]\]/g,      replace: 'req.cookies.$1' },

  // Django
  { id: 'py-django-post',     category: 'ingress', match: /request\.POST\[['"](\w+)['"]\]/g,         replace: 'req.body.$1' },
  { id: 'py-django-post-get', category: 'ingress', match: /request\.POST\.get\(['"](\w+)['"]\)/g,    replace: 'req.body.$1' },
  { id: 'py-django-get',      category: 'ingress', match: /request\.GET\[['"](\w+)['"]\]/g,          replace: 'req.query.$1' },
  { id: 'py-django-get-get',  category: 'ingress', match: /request\.GET\.get\(['"](\w+)['"]\)/g,     replace: 'req.query.$1' },
  { id: 'py-django-files',    category: 'ingress', match: /request\.FILES\[['"](\w+)['"]\]/g,        replace: 'req.files.$1' },
  { id: 'py-django-body',     category: 'ingress', match: /request\.body/g,                            replace: 'req.body' },

  // FastAPI
  { id: 'py-fastapi-query',   category: 'ingress', match: /Query\(([^)]*)\)/g,                        replace: 'req.query.$1' },
  { id: 'py-fastapi-body',    category: 'ingress', match: /Body\(([^)]*)\)/g,                          replace: 'req.body.$1' },

  // stdlib
  { id: 'py-input',           category: 'ingress', match: /\binput\s*\(/g,                             replace: 'readline(' },
  { id: 'py-argv',            category: 'ingress', match: /sys\.argv/g,                                replace: 'process.argv' },
  { id: 'py-stdin',           category: 'ingress', match: /sys\.stdin\.read\(\)/g,                     replace: 'process.stdin.read()' },
  { id: 'py-environ',         category: 'ingress', match: /os\.environ\[['"](\w+)['"]\]/g,            replace: 'process.env.$1' },
  { id: 'py-environ-get',     category: 'ingress', match: /os\.environ\.get\(['"](\w+)['"]\)/g,       replace: 'process.env.$1' },
];

// ── STORAGE: databases, file system, caches ────────────────────────

const STORAGE_RULES: TranslationRule[] = [
  // SQL
  { id: 'py-cursor-execute',    category: 'storage', match: /cursor\.execute\(/g,                     replace: 'db.query(' },
  { id: 'py-cursor-executemany', category: 'storage', match: /cursor\.executemany\(/g,               replace: 'db.query(' },
  { id: 'py-conn-execute',      category: 'storage', match: /conn(?:ection)?\.execute\(/g,           replace: 'db.query(' },
  { id: 'py-session-execute',   category: 'storage', match: /session\.execute\(/g,                    replace: 'db.query(' },
  { id: 'py-db-execute',        category: 'storage', match: /db\.execute\(/g,                         replace: 'db.query(' },
  { id: 'py-raw-sql',           category: 'storage', match: /\.raw\s*\(/g,                            replace: '.raw(' },
  { id: 'py-rawsql',            category: 'storage', match: /RawSQL\s*\(/g,                           replace: 'db.query(' },
  { id: 'py-extra-where',       category: 'storage', match: /\.extra\s*\(\s*where\s*=/g,             replace: '.raw(' },

  // File system
  { id: 'py-open',              category: 'storage', match: /\bopen\s*\(/g,                           replace: 'fs.readFileSync(' },
  { id: 'py-pathlib-read',      category: 'storage', match: /Path\(([^)]+)\)\.read_text\(\)/g,       replace: 'fs.readFileSync($1)' },
  { id: 'py-pathlib-write',     category: 'storage', match: /Path\(([^)]+)\)\.write_text\(/g,        replace: 'fs.writeFileSync($1, ' },
  { id: 'py-os-remove',         category: 'storage', match: /os\.remove\(/g,                          replace: 'fs.unlinkSync(' },
  { id: 'py-shutil-rmtree',     category: 'storage', match: /shutil\.rmtree\(/g,                     replace: 'fs.rmSync(' },

  // Cache/KV
  { id: 'py-redis-set',         category: 'storage', match: /redis\.set\(/g,                          replace: 'redis.set(' },
  { id: 'py-redis-get',         category: 'storage', match: /redis\.get\(/g,                          replace: 'redis.get(' },
  { id: 'py-cache-set',         category: 'storage', match: /cache\.set\(/g,                          replace: 'cache.set(' },
];

// ── EXTERNAL: network, HTTP, system calls ──────────────────────────

const EXTERNAL_RULES: TranslationRule[] = [
  // HTTP
  { id: 'py-requests-get',      category: 'external', match: /requests\.get\(/g,                     replace: 'fetch(' },
  { id: 'py-requests-post',     category: 'external', match: /requests\.post\(/g,                    replace: 'fetch(' },
  { id: 'py-requests-put',      category: 'external', match: /requests\.put\(/g,                     replace: 'fetch(' },
  { id: 'py-requests-delete',   category: 'external', match: /requests\.delete\(/g,                  replace: 'fetch(' },
  { id: 'py-urllib-urlopen',     category: 'external', match: /urllib\.request\.urlopen\(/g,          replace: 'fetch(' },
  { id: 'py-httpx-get',         category: 'external', match: /httpx\.get\(/g,                        replace: 'fetch(' },
  { id: 'py-httpx-post',        category: 'external', match: /httpx\.post\(/g,                       replace: 'fetch(' },
  { id: 'py-aiohttp-get',       category: 'external', match: /session\.get\(/g,                      replace: 'fetch(' },

  // Subprocess / OS
  { id: 'py-subprocess-call',   category: 'external', match: /subprocess\.call\(/g,                  replace: 'child_process.exec(' },
  { id: 'py-subprocess-run',    category: 'external', match: /subprocess\.run\(/g,                   replace: 'child_process.exec(' },
  { id: 'py-subprocess-popen',  category: 'external', match: /subprocess\.Popen\(/g,                 replace: 'child_process.exec(' },
  { id: 'py-subprocess-check',  category: 'external', match: /subprocess\.check_output\(/g,          replace: 'child_process.exec(' },
  { id: 'py-os-system',         category: 'external', match: /os\.system\(/g,                        replace: 'child_process.exec(' },
  { id: 'py-os-popen',          category: 'external', match: /os\.popen\(/g,                         replace: 'child_process.exec(' },

  // Code execution
  { id: 'py-eval',              category: 'external', match: /\beval\s*\(/g,                          replace: 'eval(' },
  { id: 'py-exec',              category: 'external', match: /\bexec\s*\(/g,                          replace: 'eval(' },
  { id: 'py-compile',           category: 'external', match: /\bcompile\s*\(/g,                       replace: 'eval(' },
  { id: 'py-importlib',         category: 'external', match: /importlib\.import_module\(/g,           replace: 'require(' },
];

// ── EGRESS: responses, output ──────────────────────────────────────

const EGRESS_RULES: TranslationRule[] = [
  // Flask
  { id: 'py-flask-render',      category: 'egress', match: /render_template\(/g,                     replace: 'res.render(' },
  { id: 'py-flask-render-str',  category: 'egress', match: /render_template_string\(/g,              replace: 'res.send(' },
  { id: 'py-flask-jsonify',     category: 'egress', match: /jsonify\(/g,                              replace: 'res.json(' },
  { id: 'py-flask-make-resp',   category: 'egress', match: /make_response\(/g,                       replace: 'res.send(' },
  { id: 'py-flask-redirect',    category: 'egress', match: /redirect\(/g,                             replace: 'res.redirect(' },

  // Django
  { id: 'py-django-render',     category: 'egress', match: /render\(request,/g,                      replace: 'res.render(' },
  { id: 'py-django-httpresp',   category: 'egress', match: /HttpResponse\(/g,                        replace: 'res.send(' },
  { id: 'py-django-jsonresp',   category: 'egress', match: /JsonResponse\(/g,                        replace: 'res.json(' },
  { id: 'py-django-redirect',   category: 'egress', match: /HttpResponseRedirect\(/g,                replace: 'res.redirect(' },

  // FastAPI
  { id: 'py-fastapi-return',    category: 'egress', match: /\breturn\s+\{/g,                         replace: 'return res.json({' },
];

// ── CONTROL: security checks, validation ───────────────────────────

const CONTROL_RULES: TranslationRule[] = [
  // Crypto
  { id: 'py-bcrypt-hash',       category: 'control', match: /bcrypt\.hashpw\(/g,                     replace: 'bcrypt.hash(' },
  { id: 'py-bcrypt-check',      category: 'control', match: /bcrypt\.checkpw\(/g,                    replace: 'bcrypt.compare(' },
  { id: 'py-hashlib-sha256',    category: 'control', match: /hashlib\.sha256\(/g,                    replace: "crypto.createHash('sha256').update(" },
  { id: 'py-hashlib-md5',       category: 'control', match: /hashlib\.md5\(/g,                       replace: "crypto.createHash('md5').update(" },
  { id: 'py-hashlib-sha1',      category: 'control', match: /hashlib\.sha1\(/g,                      replace: "crypto.createHash('sha1').update(" },

  // Sanitization
  { id: 'py-html-escape',       category: 'control', match: /html\.escape\(/g,                       replace: 'escapeHtml(' },
  { id: 'py-markupsafe',        category: 'control', match: /markupsafe\.escape\(/g,                 replace: 'escapeHtml(' },
  { id: 'py-bleach-clean',      category: 'control', match: /bleach\.clean\(/g,                      replace: 'DOMPurify.sanitize(' },

  // Deserialization
  { id: 'py-pickle-loads',      category: 'transform', match: /pickle\.loads?\(/g,                   replace: 'JSON.parse(' },
  { id: 'py-yaml-load',         category: 'transform', match: /yaml\.load\(/g,                       replace: 'JSON.parse(' },
  { id: 'py-yaml-safe-load',    category: 'transform', match: /yaml\.safe_load\(/g,                  replace: 'JSON.parse(' },
  { id: 'py-marshal-loads',     category: 'transform', match: /marshal\.loads?\(/g,                  replace: 'JSON.parse(' },
  { id: 'py-json-loads',        category: 'transform', match: /json\.loads?\(/g,                     replace: 'JSON.parse(' },

  // JWT
  { id: 'py-jwt-decode',        category: 'control', match: /jwt\.decode\(/g,                        replace: 'jwt.verify(' },
  { id: 'py-jwt-encode',        category: 'control', match: /jwt\.encode\(/g,                        replace: 'jwt.sign(' },
];

// ── STRUCTURAL: decorators, class defs, imports ────────────────────

const STRUCTURAL_RULES: TranslationRule[] = [
  // Flask routes → Express routes
  { id: 'py-flask-route-get',    category: 'structural', match: /@app\.route\(['"]([^'"]+)['"](?:,\s*methods=\['GET'\])?\)/g, replace: "app.get('$1', (req, res) =>" },
  { id: 'py-flask-route-post',   category: 'structural', match: /@app\.route\(['"]([^'"]+)['"],\s*methods=\['POST'\]\)/g,    replace: "app.post('$1', (req, res) =>" },
  { id: 'py-flask-route-any',    category: 'structural', match: /@app\.route\(['"]([^'"]+)['"]\)/g,                           replace: "app.get('$1', (req, res) =>" },

  // Django URLs (simplified)
  { id: 'py-django-path',        category: 'structural', match: /path\(['"]([^'"]+)['"],\s*(\w+)\)/g,                        replace: "app.get('$1', $2)" },

  // Python def → function
  { id: 'py-def',                category: 'structural', match: /\bdef\s+(\w+)\s*\(([^)]*)\)\s*:/g,                          replace: 'function $1($2) {' },
  { id: 'py-class',              category: 'structural', match: /\bclass\s+(\w+)(?:\([^)]*\))?\s*:/g,                        replace: 'class $1 {' },
  { id: 'py-import-from',        category: 'structural', match: /from\s+(\S+)\s+import\s+(.+)/g,                              replace: "const { $2 } = require('$1');" },
  { id: 'py-import',             category: 'structural', match: /^import\s+(\w+)/gm,                                          replace: "const $1 = require('$1');" },
];

// ── ALL RULES ──────────────────────────────────────────────────────

export const PYTHON_TO_JS_RULES: TranslationRule[] = [
  ...INGRESS_RULES,
  ...STORAGE_RULES,
  ...EXTERNAL_RULES,
  ...EGRESS_RULES,
  ...CONTROL_RULES,
  ...STRUCTURAL_RULES,
];

/**
 * Translate Python source code to JS-like pseudocode for DST analysis.
 * Preserves line numbers (1:1 line mapping).
 * Returns translated code + translation log for debugging.
 */
export function translatePythonToJS(pythonCode: string): { code: string; translations: { line: number; ruleId: string; original: string; replaced: string }[] } {
  const lines = pythonCode.split('\n');
  const translations: { line: number; ruleId: string; original: string; replaced: string }[] = [];

  for (let i = 0; i < lines.length; i++) {
    const originalLine = lines[i];
    let currentLine = lines[i];

    for (const rule of PYTHON_TO_JS_RULES) {
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

    // Fix Python indentation → JS braces (minimal — just enough for tree-sitter)
    // Replace trailing colon with opening brace (already handled in structural rules for def/class)

    lines[i] = currentLine;
  }

  return { code: lines.join('\n'), translations };
}

/**
 * Get rule count by category.
 */
export function getRuleStats(): Record<string, number> {
  const stats: Record<string, number> = {};
  for (const rule of PYTHON_TO_JS_RULES) {
    stats[rule.category] = (stats[rule.category] || 0) + 1;
  }
  stats.total = PYTHON_TO_JS_RULES.length;
  return stats;
}
