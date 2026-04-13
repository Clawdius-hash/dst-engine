/**
 * Extract the storage / file / env target from a code snapshot string.
 *
 * Given a line (or few lines) of source code that appears at a source or sink
 * node, determine *what* external resource it touches — a DB table, a file
 * path, an env-var name, etc.  Returns `null` when the pattern is
 * unrecognizable.
 */

export interface ExtractedTarget {
  kind: 'storage' | 'file_io' | 'env_var' | 'config' | 'network';
  name: string;
}

// ── SQL ──────────────────────────────────────────────────────────────────────

const SQL_INSERT = /\bINSERT\s+INTO\s+[`"']?(\w+)[`"']?/i;
const SQL_SELECT = /\bSELECT\b.+?\bFROM\s+[`"']?(\w+)[`"']?/is;
const SQL_UPDATE = /\bUPDATE\s+[`"']?(\w+)[`"']?/i;
const SQL_DELETE = /\bDELETE\s+FROM\s+[`"']?(\w+)[`"']?/i;

// ── MongoDB ──────────────────────────────────────────────────────────────────

const MONGO_COLLECTION = /\.collection\(\s*["'`](\w+)["'`]\s*\)/;

// ── Prisma ───────────────────────────────────────────────────────────────────

const PRISMA_MODEL = /\bprisma\.(\w+)\.\w+/;

// ── File I/O ─────────────────────────────────────────────────────────────────

const FILE_WRITE = /(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*["'`]([^"'`]+)["'`]/;
const FILE_READ  = /(?:readFile|readFileSync)\s*\(\s*["'`]([^"'`]+)["'`]/;
const FS_CREATE_WRITE = /createWriteStream\s*\(\s*["'`]([^"'`]+)["'`]/;
const FS_CREATE_READ  = /createReadStream\s*\(\s*["'`]([^"'`]+)["'`]/;

// ── Env vars ─────────────────────────────────────────────────────────────────

const ENV_ACCESS   = /process\.env\.(\w+)/;
const ENV_BRACKET  = /process\.env\[\s*["'`](\w+)["'`]\s*\]/;

// ── Ordered patterns ─────────────────────────────────────────────────────────

const PATTERNS: Array<{ re: RegExp; kind: ExtractedTarget['kind'] }> = [
  // SQL (most specific first)
  { re: SQL_INSERT,   kind: 'storage' },
  { re: SQL_SELECT,   kind: 'storage' },
  { re: SQL_UPDATE,   kind: 'storage' },
  { re: SQL_DELETE,   kind: 'storage' },
  // Mongo
  { re: MONGO_COLLECTION, kind: 'storage' },
  // Prisma
  { re: PRISMA_MODEL, kind: 'storage' },
  // File I/O
  { re: FILE_WRITE,        kind: 'file_io' },
  { re: FILE_READ,         kind: 'file_io' },
  { re: FS_CREATE_WRITE,   kind: 'file_io' },
  { re: FS_CREATE_READ,    kind: 'file_io' },
  // Env
  { re: ENV_BRACKET, kind: 'env_var' },
  { re: ENV_ACCESS,  kind: 'env_var' },
];

/**
 * Attempt to extract the external-resource target from a code snippet.
 */
export function extractStorageTarget(code: string): ExtractedTarget | null {
  for (const { re, kind } of PATTERNS) {
    const m = code.match(re);
    if (m) {
      return { kind, name: m[1] };
    }
  }
  return null;
}
