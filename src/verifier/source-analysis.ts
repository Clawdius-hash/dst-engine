/**
 * Source code analysis utilities for CWE verifiers.
 *
 * String processing (comment stripping, literal stripping) and
 * taint neutralization detection (dead branches, static values, HashMap keys).
 * These operate on source code text — no graph types needed.
 */

/**
 * Strip content inside string literals and regex literals, leaving delimiters.
 * "/\bDES\b/" → "//", "Math.random()" → "". Used by crypto/PRNG verifiers
 * to avoid self-detection when scanning DST's own detection patterns.
 */
export function stripLiterals(code: string): string {
  // Replace regex literals: /pattern/flags → //
  let result = code.replace(/(?<![=!<>])\/(?![/*])(?:[^/\\]|\\.)+\/[gimsuy]*/g, '//');
  // Replace double-quoted strings: "content" → ""
  result = result.replace(/"(?:[^"\\]|\\.)*"/g, '""');
  // Replace single-quoted strings: 'content' → ''
  result = result.replace(/'(?:[^'\\]|\\.)*'/g, "''");
  // Replace template literals: `content` → ``
  result = result.replace(/`(?:[^`\\]|\\.)*`/g, '``');
  return result;
}

/**
 * Strip only regex literals from code, leaving string literals intact.
 * Used by CWE-798 and similar verifiers that need to detect credential VALUES
 * (which are in string literals) but not match against detection regex patterns
 * (which are regex literals inside DST's own verifier code).
 */
export function stripRegexLiterals(code: string): string {
  return code.replace(/(?<![=!<>])\/(?![/*])(?:[^/\\]|\\.)+\/[gimsuy]*/g, '//');
}

const HASH_COMMENT_LANGS = new Set(['python', 'ruby', 'php', 'perl', 'shell', 'bash', 'r']);

export function stripComments(code: string, language?: string): string {
  const stripHash = !language || HASH_COMMENT_LANGS.has(language.toLowerCase());
  let result = '';
  let i = 0;
  const len = code.length;

  while (i < len) {
    const ch = code[i];
    const next = i + 1 < len ? code[i + 1] : '';

    // String literals — skip through without stripping
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      result += ch;
      i++;
      while (i < len) {
        if (code[i] === '\\') {
          // Escaped character — consume both
          result += code[i] + (i + 1 < len ? code[i + 1] : '');
          i += 2;
          continue;
        }
        if (code[i] === quote) {
          result += code[i];
          i++;
          break;
        }
        result += code[i];
        i++;
      }
      continue;
    }

    // Multi-line comment: /* ... */
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < len) {
        if (code[i] === '*' && i + 1 < len && code[i + 1] === '/') {
          i += 2;
          break;
        }
        i++;
      }
      result += ' '; // Replace comment with space to avoid token merging
      continue;
    }

    // Single-line comment: // ...
    if (ch === '/' && next === '/') {
      // Skip to end of line
      i += 2;
      while (i < len && code[i] !== '\n') {
        i++;
      }
      continue;
    }

    // Hash comment: # ... (only for Python, Ruby, PHP, etc.)
    if (ch === '#' && stripHash) {
      // Skip to end of line
      i++;
      while (i < len && code[i] !== '\n') {
        i++;
      }
      continue;
    }

    result += ch;
    i++;
  }

  return result;
}

/** Escape special regex characters so a string can be used in new RegExp(). */
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Test if `word` appears as a whole word in `text`.
 * Equivalent to /\bword\b/ but works correctly with dynamic strings
 * (avoids the JS string escaping pitfall where '\\b' becomes backspace).
 */
export function wholeWord(text: string, word: string): boolean {
  let idx = 0;
  while (true) {
    const pos = text.indexOf(word, idx);
    if (pos === -1) return false;
    const before = pos > 0 ? text[pos - 1]! : ' ';
    const after = pos + word.length < text.length ? text[pos + word.length]! : ' ';
    const isWordBefore = /\w/.test(before);
    const isWordAfter = /\w/.test(after);
    if (!isWordBefore && !isWordAfter) return true;
    idx = pos + 1;
  }
}

/**
 * Detect dead-branch taint neutralization in Java source code.
 *
 * BenchmarkJava (and similar code) uses constant-arithmetic ternary/if-else
 * and switch-on-constant patterns to guarantee a safe branch is always taken.
 *
 * Returns true when dead-branch neutralization is detected (taint is suppressed).
 */
export function detectDeadBranchNeutralization(sourceCode: string): boolean {
  const cleanSrc = stripComments(sourceCode);

  // Pattern 1: Arithmetic constant condition with variable reference
  // (a * b) [+-] varName  {> < >= <=}  threshold
  const arithCondMatch = cleanSrc.match(
    /\((\d+)\s*\*\s*(\d+)\)\s*([+-])\s*(\w+)\s*([><=!]+)\s*(\d+)/
  );
  if (arithCondMatch) {
    const a = parseInt(arithCondMatch[1]!);
    const b = parseInt(arithCondMatch[2]!);
    const op = arithCondMatch[3]!;
    const varName = arithCondMatch[4]!;
    const cmpOp = arithCondMatch[5]!;
    const threshold = parseInt(arithCondMatch[6]!);
    // Try to find the variable's value: int varName = N;
    const varDeclMatch = cleanSrc.match(new RegExp('int\\s+' + varName + '\\s*=\\s*(\\d+)'));
    if (varDeclMatch) {
      const varVal = parseInt(varDeclMatch[1]!);
      const lhs = op === '+' ? (a * b) + varVal : (a * b) - varVal;
      const condAlwaysTrue = evaluateConstantComparison(lhs, cmpOp, threshold);
      if (condAlwaysTrue === true) {
        return true;
      }
      if (condAlwaysTrue === false) {
        const ternAfter = cleanSrc.match(
          new RegExp('\\(\\d+\\s*\\*\\s*\\d+\\)\\s*[+-]\\s*' + varName + '\\s*[><=!]+\\s*\\d+\\s*\\?\\s*(\\w+)\\s*:\\s*"[^"]*"')
        );
        if (ternAfter) return true;
      }
    }
  }

  // Pattern 2: Simple constant comparison without variable
  const simpleConstMatch = cleanSrc.match(
    /(\d+)\s*([><=!]+)\s*(\d+)\s*\?\s*(?:"[^"]*"|'[^']*')\s*:\s*\w+/
  );
  if (simpleConstMatch) {
    const lhs = parseInt(simpleConstMatch[1]!);
    const cmpOp = simpleConstMatch[2]!;
    const rhs = parseInt(simpleConstMatch[3]!);
    if (evaluateConstantComparison(lhs, cmpOp, rhs) === true) {
      return true;
    }
  }
  // Inverse: N1 < N2 ? param : "safe" (always-false -> safe branch taken)
  const simpleConstMatchInv = cleanSrc.match(
    /(\d+)\s*([><=!]+)\s*(\d+)\s*\?\s*\w+\s*:\s*(?:"[^"]*"|'[^']*')/
  );
  if (simpleConstMatchInv) {
    const lhs = parseInt(simpleConstMatchInv[1]!);
    const cmpOp = simpleConstMatchInv[2]!;
    const rhs = parseInt(simpleConstMatchInv[3]!);
    if (evaluateConstantComparison(lhs, cmpOp, rhs) === false) {
      return true;
    }
  }

  // Pattern 4: Switch with constant target
  const charAtMatch = cleanSrc.match(/(\w+)\.charAt\s*\((\d+)\)[\s\S]*?switch/);
  if (charAtMatch) {
    const receiverVar = charAtMatch[1]!;
    const charIdx = parseInt(charAtMatch[2]!);
    const strDeclMatch = cleanSrc.match(
      new RegExp('String\\s+' + receiverVar + '\\s*=\\s*"([^"]*)"')
    );
    if (strDeclMatch && charIdx >= 0 && charIdx < strDeclMatch[1]!.length) {
      const selectedChar = strDeclMatch[1]![charIdx]!;
      const switchBodyMatch = cleanSrc.match(/switch\s*\([^)]*\)\s*\{([\s\S]*?\n\s*\})/);
      if (switchBodyMatch) {
        const switchBody = switchBodyMatch[1]!;
        const caseLabels = switchBody.split(/(?=case\s+'[^']*'\s*:|default\s*:)/);
        let foundSelected = false;
        let neutralized = false;
        for (const clause of caseLabels) {
          const labelMatch = clause.match(/^(?:case\s+'([^']*)'\s*:|default\s*:)/);
          if (!labelMatch) continue;
          const caseChar = labelMatch[1];
          if (!foundSelected && caseChar === selectedChar) foundSelected = true;
          if (foundSelected) {
            if (/\b\w+\s*=\s*"[^"]*"\s*;/.test(clause) && !/\b\w+\s*=\s*param\b/.test(clause)) {
              neutralized = true; break;
            }
            if (/\b\w+\s*=\s*param\b/.test(clause)) {
              neutralized = false; break;
            }
            if (/\bbreak\s*;|\breturn\b/.test(clause)) break;
          }
        }
        if (neutralized) return true;
      }
    }
  }

  return false;
}

/**
 * Evaluate a constant integer comparison.
 * Returns true if condition is always true, false if always false, null if unknown.
 */
export function evaluateConstantComparison(lhs: number, op: string, rhs: number): boolean | null {
  switch (op) {
    case '>':  return lhs > rhs;
    case '<':  return lhs < rhs;
    case '>=': return lhs >= rhs;
    case '<=': return lhs <= rhs;
    case '==': return lhs === rhs;
    case '!=': return lhs !== rhs;
    default:   return null;
  }
}

/**
 * Per-method forward taint analysis that detects when a taint chain is abandoned
 * for a static literal.
 *
 * Returns true when the last assignment to the variable before the sink is a static literal.
 */
export function detectStaticValueNeutralization(sourceCode: string): boolean {
  const src = stripComments(sourceCode);
  const lines = src.split('\n');

  // Track variables and their last-assignment status
  const tainted = new Set<string>();
  const safe = new Set<string>();

  for (const line of lines) {
    const ln = line.trim();
    if (ln.startsWith('//') || ln.startsWith('*')) continue;

    // Source: user input API
    const srcM = ln.match(/(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString)\s*\(/);
    if (srcM) { tainted.add(srcM[1]!); safe.delete(srcM[1]!); continue; }

    // Static literal assignment kills taint
    const litM = ln.match(/^(?:(?:final\s+)?(?:[\w.]+\s+))?(\w+)\s*=\s*"[^"]*"\s*;/);
    if (litM && tainted.has(litM[1]!)) { tainted.delete(litM[1]!); safe.add(litM[1]!); continue; }

    // Propagation: bar = tainted_var
    const propM = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\s*;/);
    if (propM && tainted.has(propM[2]!)) { tainted.add(propM[1]!); }

    // Method call with safe arg returns safe
    const callM = ln.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?\w+\s*\(\s*(\w+)\s*\)/);
    if (callM && safe.has(callM[2]!)) { safe.add(callM[1]!); }
  }

  // If any originally-tainted variable was reassigned to a literal, neutralization occurred
  return safe.size > 0 && tainted.size === 0;
}

/**
 * Resolve HashMap put/get taint by key. Given source lines, a tainted variable set,
 * a map variable name, and the key being retrieved, determines if the value stored
 * at that key is tainted.
 *
 * Returns 'tainted' if the value at the key is tainted, 'safe' if it's a safe value,
 * or 'unknown' if the key was never put.
 */
export function resolveMapKeyTaint(
  lines: string[], taintedVars: Set<string>, mapVar: string, getKey: string, upToLine: number
): 'tainted' | 'safe' | 'unknown' {
  let result: 'tainted' | 'safe' | 'unknown' = 'unknown';
  for (let j = 0; j < upToLine; j++) {
    const pLine = lines[j]!.trim();
    // Match put("key", variableName)
    const putM = pLine.match(new RegExp(escapeRegExp(mapVar) + '\\.put\\s*\\(\\s*"([^"]*)"\\s*,\\s*(\\w+)\\s*\\)'));
    if (putM && putM[1] === getKey) {
      result = taintedVars.has(putM[2]!) ? 'tainted' : 'safe';
    }
    // Match put("key", "stringLiteral") — string literal values are always safe
    const putLitM = pLine.match(new RegExp(escapeRegExp(mapVar) + '\\.put\\s*\\(\\s*"([^"]*)"\\s*,\\s*"[^"]*"\\s*\\)'));
    if (putLitM && putLitM[1] === getKey) {
      result = 'safe';
    }
  }
  return result;
}

/**
 * Detect interprocedural taint neutralization for CWE-90 LDAP injection.
 * Checks if a helper/inner-class method called with tainted input returns safe output.
 *
 * Patterns detected:
 * 1. Static value replacement: method abandons tainted chain and assigns a string literal
 *    to a new variable which flows to return (e.g., g = "barbarians_at_the_gate"; bar = fn(g))
 * 2. HashMap safe key retrieval: method puts tainted value at key X but retrieves from key Y
 *    where Y was populated with a safe literal
 * 3. Method returns safe output despite receiving tainted input (taint abandoned inside method)
 */
export function detectInterproceduralNeutralization90(sourceCode: string): boolean {
  const src = stripComments(sourceCode);
  // Find interprocedural calls: bar = new Test().doSomething(request, param) or bar = doSomething(request, param)
  const ipCallMatch = src.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?(\w+)\s*\(\s*(?:request\s*,\s*)?(\w+)\s*\)/);
  if (!ipCallMatch) return false;
  const calledMethod = ipCallMatch[2]!;
  const paramVar = ipCallMatch[3]!;
  // Find the method body
  const methodDeclRe = new RegExp('(?:public|private|protected|static)\\s+\\w+\\s+' + escapeRegExp(calledMethod) + '\\s*\\([^)]*\\)[^{]*\\{');
  const methodStart = src.match(methodDeclRe);
  if (!methodStart) return false;
  const startIdx = src.indexOf(methodStart[0]) + methodStart[0].length;
  // Extract method body by brace counting
  let braceDepth = 1;
  let endIdx = startIdx;
  for (let i = startIdx; i < src.length && braceDepth > 0; i++) {
    if (src[i] === '{') braceDepth++;
    if (src[i] === '}') braceDepth--;
    endIdx = i;
  }
  const methodBody = src.slice(startIdx, endIdx);

  // Pattern 1: Static value replacement — a variable is assigned a string literal (>=5 chars)
  // and that variable (or a value derived from it) flows to the return statement.
  // e.g.: String g = "barbarians_at_the_gate"; String bar = thing.doSomething(g); return bar;
  const staticLiteralAssign = methodBody.match(/(\w+)\s*=\s*"[^"]{5,}"\s*;/);
  if (staticLiteralAssign) {
    const safeVar = staticLiteralAssign[1]!;
    // Check: does a variable derived from safeVar flow to return?
    const returnMatch = methodBody.match(/return\s+(\w+)\s*;/);
    if (returnMatch) {
      const returnVar = returnMatch[1]!;
      // If the return variable or safe variable is ALSO assigned param somewhere in the method,
      // we have mixed branches (e.g., switch with both bar=param and bar="safe").
      // In that case, don't claim neutralization — defer to dead branch analysis.
      const returnVarAlsoTainted = new RegExp('\\b' + escapeRegExp(returnVar) + '\\s*=\\s*param\\b').test(methodBody);
      const safeVarAlsoTainted = new RegExp('\\b' + escapeRegExp(safeVar) + '\\s*=\\s*param\\b').test(methodBody);
      if (!returnVarAlsoTainted && !safeVarAlsoTainted) {
        // Direct: safeVar is returned, or safeVar feeds into returnVar via method call
        // BUT: if the variable is reassigned after the static literal (e.g., bar = "safe!"; ... bar = (String)map.get("keyB");)
        // then the static literal is dead and doesn't reach the return.
        if (returnVar === safeVar) {
          // Count all assignments to safeVar — if there's more than the static literal one,
          // the variable is reassigned and the static value may not reach return.
          const allAssignments = [...methodBody.matchAll(new RegExp('\\b' + escapeRegExp(safeVar) + '\\s*=\\s*', 'g'))];
          if (allAssignments.length <= 1) return true;
          // Multiple assignments exist — check if the LAST assignment is the static literal.
          // If it's not, something else overwrites it before return.
          const lastAssignIdx = allAssignments[allAssignments.length - 1]!.index!;
          const staticAssignIdx = staticLiteralAssign.index!;
          // Also check the matched position within the method body — if the static assign
          // is the last one, it dominates the return. Otherwise, it's overwritten.
          if (lastAssignIdx === staticAssignIdx) return true;
          // The static literal is overwritten — don't suppress, fall through.
        }
        // Indirect: bar = something(safeVar); return bar;
        const derivedRe = new RegExp(escapeRegExp(returnVar) + '\\s*=\\s*(?:\\w+\\.)?\\w+\\s*\\(\\s*' + escapeRegExp(safeVar) + '\\s*\\)');
        if (derivedRe.test(methodBody)) return true;
      }
    }
  }

  // Pattern 2: HashMap safe key retrieval
  // put("keyB", param) [tainted], but get("keyA") [safe] is what flows to return
  const putVarMatches = [...methodBody.matchAll(/(\w+)\.put\s*\(\s*"([^"]*)"\s*,\s*(\w+)\s*\)/g)];
  const putLitMatches = [...methodBody.matchAll(/(\w+)\.put\s*\(\s*"([^"]*)"\s*,\s*"[^"]*"\s*\)/g)];
  const putAllKeys = [...putVarMatches, ...putLitMatches];
  const getMatches = [...methodBody.matchAll(/(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/g)];
  if (putAllKeys.length > 0 && getMatches.length > 0) {
    // Find the LAST get() before return — that's what's actually returned
    const returnMatch = methodBody.match(/return\s+(\w+)\s*;/);
    if (returnMatch) {
      const returnVar = returnMatch[1]!;
      // Tainted keys: those where a put() value is a tainted variable (param or derived)
      const paramRe = /\bparam\b/;
      const taintedKeys = new Set(putVarMatches.filter(p => paramRe.test(p[3]!)).map(p => p[1] + '::' + p[2]));
      for (const gm of [...getMatches].reverse()) {
        const getKey = gm[3]!;
        const mapVarGet = gm[2]!;
        const assignVar = gm[1]!;
        // Is this the final assignment to the returned variable?
        if (assignVar === returnVar || (returnVar === 'bar' && assignVar === 'bar')) {
          // If the retrieved key is NOT among tainted keys, it's safe
          if (!taintedKeys.has(mapVarGet + '::' + getKey)) {
            return true;
          }
          break; // only check the last assignment to the returned var
        }
      }
    }
  }

  // Pattern 3: Mini forward taint analysis inside the method body.
  // If the return variable is NOT tainted after tracking propagation, the method kills taint.
  // This handles cases like B64 encode/decode where complex constructor chains don't propagate
  // taint through our simple pattern matching.
  // GUARD: Only apply Pattern 3 when the method body has NO branching on the return variable.
  // If there's both "retVar = param" and "retVar = literal" in the method, there are mixed branches
  // (if/else, switch, ternary) and the mini-taint analysis can't reliably determine which path runs.
  const returnMatch3 = methodBody.match(/return\s+(\w+)\s*;/);
  if (returnMatch3) {
    const rv3 = returnMatch3[1]!;
    const rvParamAssign = new RegExp('\\b' + escapeRegExp(rv3) + '\\s*=\\s*param\\b').test(methodBody);
    const rvLiteralAssign = new RegExp('\\b' + escapeRegExp(rv3) + '\\s*=\\s*"[^"]*"').test(methodBody);
    // Also check for ternary or if/else that assigns to the return variable
    const hasTernary = new RegExp('\\b' + escapeRegExp(rv3) + '\\s*=.*\\?.*:').test(methodBody);
    const hasIfElse = /\bif\s*\(/.test(methodBody) && new RegExp('\\b' + escapeRegExp(rv3) + '\\s*=').test(methodBody);
    // Only safe to use mini-taint when there's NO branching/mixed assignment pattern
    if (!rvParamAssign && !rvLiteralAssign && !hasTernary && !hasIfElse) {
      const methodLines = methodBody.split('\n').map(l => l.trim()).filter(l => l.length > 0);
      const mtv3 = new Set<string>(['param']);
      let returnVar3 = '';
      for (const bl of methodLines) {
        const mva = bl.match(/^(?:(?:final\s+)?[\w.<>\[\]]+\s+)?(\w+)\s*=\s*(\w+)\s*;/);
        if (mva && mtv3.has(mva[2]!)) mtv3.add(mva[1]!);
        const mcon = bl.match(/^(?:[\w.<>\[\]]+\s+)?(\w+)\s*=\s*new\s+\w+\s*\(\s*(\w+)\s*\)/);
        if (mcon && mtv3.has(mcon[2]!)) mtv3.add(mcon[1]!);
        const mcall = bl.match(/^(?:[\w.<>\[\]]+\s+)?(\w+)\s*=\s*(?:\w+\.)*\w+\s*\(\s*(\w+)\s*[,)]/);
        if (mcall && mtv3.has(mcall[2]!)) mtv3.add(mcall[1]!);
        const mcc = bl.match(/^(?:[\w.<>\[\]]+\s+)?(\w+)\s*=\s*.*\b(\w+)\b.*\+/);
        if (mcc && mtv3.has(mcc[2]!)) mtv3.add(mcc[1]!);
        const mlit = bl.match(/^(?:[\w.<>\[\]]+\s+)?(\w+)\s*=\s*"[^"]*"\s*;/);
        if (mlit) mtv3.delete(mlit[1]!);
        const mret = bl.match(/return\s+(\w+)\s*;/);
        if (mret) { returnVar3 = mret[1]!; break; }
      }
      if (returnVar3 && !mtv3.has(returnVar3)) return true;
    }
  }

  return false;
}
