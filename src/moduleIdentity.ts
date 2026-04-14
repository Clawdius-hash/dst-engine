/**
 * Module Identity Map -- irreducible domain knowledge.
 * ~45 module names mapped to 10 danger categories.
 * This is the ONLY hardcoded knowledge in the structural inference system.
 *
 * You cannot derive "pg is a PostgreSQL database driver" from code structure.
 * That's domain knowledge. Everything else in the inference engine is structural.
 */

export type ModuleCategory =
  | 'DATABASE'
  | 'SHELL'
  | 'FILESYSTEM'
  | 'NETWORK'
  | 'TEMPLATE'
  | 'HTTP_FRAMEWORK'
  | 'CODE_EVAL'
  | 'DESERIALIZE'
  | 'LDAP'
  | 'XPATH';

const MODULE_IDENTITY: Record<string, ModuleCategory> = {
  'pg':              'DATABASE',
  'mysql':           'DATABASE',
  'mysql2':          'DATABASE',
  'mongodb':         'DATABASE',
  'mongoose':        'DATABASE',
  'sqlite3':         'DATABASE',
  'better-sqlite3':  'DATABASE',
  'sequelize':       'DATABASE',
  'knex':            'DATABASE',
  'typeorm':         'DATABASE',
  'mssql':           'DATABASE',
  'ioredis':         'DATABASE',
  'redis':           'DATABASE',

  'child_process':   'SHELL',
  'shelljs':         'SHELL',

  'fs':              'FILESYSTEM',
  'fs/promises':     'FILESYSTEM',

  'http':            'NETWORK',
  'https':           'NETWORK',
  'axios':           'NETWORK',
  'node-fetch':      'NETWORK',
  'got':             'NETWORK',
  'superagent':      'NETWORK',
  'request':         'NETWORK',
  'undici':          'NETWORK',

  'ejs':             'TEMPLATE',
  'pug':             'TEMPLATE',
  'handlebars':      'TEMPLATE',
  'nunjucks':        'TEMPLATE',
  'mustache':        'TEMPLATE',
  'dot':             'TEMPLATE',

  'express':         'HTTP_FRAMEWORK',
  'koa':             'HTTP_FRAMEWORK',
  'fastify':         'HTTP_FRAMEWORK',
  '@hapi/hapi':      'HTTP_FRAMEWORK',
  'hono':            'HTTP_FRAMEWORK',
  'restify':         'HTTP_FRAMEWORK',

  'vm':              'CODE_EVAL',
  'vm2':             'CODE_EVAL',

  'js-yaml':         'DESERIALIZE',
  'xml2js':          'DESERIALIZE',
  'serialize-javascript': 'DESERIALIZE',

  'ldapjs':          'LDAP',

  'xpath':           'XPATH',
  'xpath.js':        'XPATH',
};

/**
 * Methods on each module category that accept potentially-tainted input.
 * These are the sink methods -- where user data reaches a dangerous API.
 */
const DANGEROUS_METHODS: Record<ModuleCategory, ReadonlySet<string>> = {
  DATABASE: new Set([
    'query', 'exec', 'execute', 'raw', 'prepare',
    '$queryRaw', '$queryRawUnsafe', '$executeRaw', '$executeRawUnsafe',
    'all', 'get', 'run',
  ]),
  SHELL: new Set([
    'exec', 'execSync', 'execFile', 'execFileSync',
    'spawn', 'spawnSync', 'fork',
  ]),
  FILESYSTEM: new Set([
    'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
    'appendFile', 'appendFileSync', 'createReadStream', 'createWriteStream',
    'readdir', 'readdirSync', 'stat', 'statSync', 'access', 'accessSync',
    'unlink', 'unlinkSync', 'rename', 'renameSync', 'mkdir', 'mkdirSync',
    'open', 'openSync',
  ]),
  NETWORK: new Set([
    'request', 'get', 'post', 'put', 'delete', 'patch', 'head', 'options',
  ]),
  TEMPLATE: new Set([
    'render', 'compile', 'renderFile', 'renderString',
  ]),
  HTTP_FRAMEWORK: new Set([]),
  CODE_EVAL: new Set([
    'runInNewContext', 'runInThisContext', 'createContext', 'compileFunction', 'run',
  ]),
  DESERIALIZE: new Set([
    'load', 'loadAll', 'parse', 'parseString', 'safeLoad',
  ]),
  LDAP: new Set([
    'search', 'bind', 'add', 'modify', 'del', 'compare',
  ]),
  XPATH: new Set([
    'select', 'evaluate', 'parse',
  ]),
};

/**
 * Look up the danger category for an npm module name.
 * Returns null for relative/local imports and unknown modules.
 */
export function getModuleCategory(moduleName: string): ModuleCategory | null {
  if (moduleName.startsWith('.') || moduleName.startsWith('/')) return null;
  return MODULE_IDENTITY[moduleName] ?? null;
}

/**
 * Check whether a method name is a known dangerous sink for the given category.
 */
export function isDangerousMethod(category: ModuleCategory, methodName: string): boolean {
  const methods = DANGEROUS_METHODS[category];
  if (!methods) return false;
  return methods.has(methodName);
}

/**
 * Map a module category to the security domain string used by the DST engine.
 * HTTP_FRAMEWORK returns empty -- frameworks are sources (req), not sinks.
 */
export function categoryToSecurityDomain(category: ModuleCategory): string {
  switch (category) {
    case 'DATABASE':       return 'sql_safe';
    case 'SHELL':          return 'shell_safe';
    case 'FILESYSTEM':     return 'path_safe';
    case 'NETWORK':        return 'redirect_safe';
    case 'TEMPLATE':       return 'ssti_safe';
    case 'CODE_EVAL':      return 'shell_safe';
    case 'DESERIALIZE':    return 'deserialize_safe';
    case 'LDAP':           return 'ldap_safe';
    case 'XPATH':          return 'xpath_safe';
    case 'HTTP_FRAMEWORK': return '';
  }
}
