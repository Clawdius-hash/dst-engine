import { Parser, Language, type Tree } from 'web-tree-sitter';

// Multi-language tree-sitter parser.
// Lazy-loads grammars on first use. WASM files served from public/.

let parserInstance: Parser | null = null;
let initPromise: Promise<void> | null = null;
const loadedLanguages = new Map<string, Language>();

type SupportedLanguage = 'javascript' | 'html' | 'css';

const GRAMMAR_FILES: Record<SupportedLanguage, string> = {
  javascript: '/tree-sitter-javascript.wasm',
  html: '/tree-sitter-html.wasm',
  css: '/tree-sitter-css.wasm',
};

/** Initialize the tree-sitter WASM runtime. Safe to call multiple times. */
async function ensureInit(): Promise<Parser> {
  if (parserInstance) return parserInstance;

  if (!initPromise) {
    initPromise = (async () => {
      try {
        await Parser.init({
          locateFile(scriptName: string) {
            return '/' + scriptName;
          },
        });
        parserInstance = new Parser();
      } catch (e) {
        initPromise = null; // Allow retry on next call
        throw e;
      }
    })();
  }

  await initPromise;
  if (!parserInstance) throw new Error('Parser: init completed but parser instance is null');
  return parserInstance;
}

/** Load a language grammar (cached after first load). */
async function ensureLanguage(lang: SupportedLanguage): Promise<Language> {
  const cached = loadedLanguages.get(lang);
  if (cached) return cached;

  const wasmPath = GRAMMAR_FILES[lang];
  if (!wasmPath) throw new Error(`Unsupported language: ${lang}`);

  const language = await Language.load(wasmPath);
  loadedLanguages.set(lang, language);
  return language;
}

/**
 * Parse source code into a tree-sitter CST.
 * Supports: javascript, html, css.
 * Returns null if parsing fails.
 *
 * Uses a serial queue to prevent concurrent setLanguage/parse race conditions
 * on the single shared parser instance.
 *
 * Usage:
 *   const tree = await parse('const x = 42;', 'javascript');
 *   tree.delete(); // free WASM memory when done
 */
let parseQueue: Promise<Tree | null> = Promise.resolve(null);

export async function parse(code: string, language: SupportedLanguage): Promise<Tree | null> {
  const result = parseQueue.then(async () => {
    const parser = await ensureInit();
    const lang = await ensureLanguage(language);
    parser.setLanguage(lang);
    return parser.parse(code);
  });
  parseQueue = result.catch(() => null); // Don't let errors block subsequent parses
  return result;
}

/** Parse JavaScript — convenience wrapper. */
export async function parseJS(code: string): Promise<Tree | null> {
  return parse(code, 'javascript');
}

/** Parse HTML. */
export async function parseHTML(code: string): Promise<Tree | null> {
  return parse(code, 'html');
}

/** Parse CSS. */
export async function parseCSS(code: string): Promise<Tree | null> {
  return parse(code, 'css');
}

/** Check if a language is supported. */
export function isSupported(lang: string): lang is SupportedLanguage {
  return lang in GRAMMAR_FILES;
}

/** Get the parser instance directly (for advanced usage). */
export async function getParser(): Promise<Parser> {
  return ensureInit();
}

/** Get list of supported languages. */
export function getSupportedLanguages(): SupportedLanguage[] {
  return Object.keys(GRAMMAR_FILES) as SupportedLanguage[];
}
