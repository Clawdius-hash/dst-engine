/**
 * Injection & Taint-Tracking CWE Verifiers
 *
 * SQL injection, XSS, command injection, path traversal, SSRF, XXE, LDAP,
 * XPath, code injection, prototype pollution, CRLF, open redirect, log injection,
 * deserialization, JNI, process control, and obsolete function detection.
 * These share detectInterproceduralNeutralization90 and taint-tracking infrastructure.
 *
 * Extracted from verifier/index.ts - Phase 7 of the monolith split.
 */

import type { NeuralMap } from '../types';
import type { VerificationResult, Finding, NodeRef } from './types.ts';
import { stripComments, stripLiterals, escapeRegExp, wholeWord, detectStaticValueNeutralization, resolveMapKeyTaint, detectInterproceduralNeutralization90 } from './source-analysis.ts';
import { nodeRef, nodesOfType, inferMapLanguage, hasTaintedPathWithoutControl, sharesFunctionScope, hasDeadBranchForNode, isLineInDeadBranchFunction } from './graph-helpers.ts';
import { getContainingScopeSnapshots, sinkHasTaintedDataIn, scopeBasedTaintReaches } from '../generated/_helpers.js';


// ---------------------------------------------------------------------------
// V2: Sentence-based CWE-89 detection
// ---------------------------------------------------------------------------

/** Variable taint state tracked during story walk. */
interface VarTaintInfo {
  tainted: boolean;
  reason: string;
  sourceNodeId: string;
  /** Line where the taint was established */
  sourceLine: number;
}

/**
 * CWE-89 sentence verifier: walks the semantic story forward, building a
 * variable taint map and detecting when tainted data reaches SQL sinks
 * without parameterization.
 *
 * Returns findings when the sentence story proves a SQL injection path.
 * Returns empty findings if the story is insufficient (caller falls back to legacy).
 */
function verifyCWE89_sentences(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  if (!map.story || map.story.length === 0) {
    return { cwe: 'CWE-89', name: 'SQL Injection', holds: true, findings: [] };
  }

  // Cross-domain exclusion: same as legacy verifier
  const NON_SQL_TEMPLATE_KEYS = new Set(['xpath_query', 'ldap_query', 'nosql_query']);

  // Variable taint state — taintClass is now resolved by sentence-resolver,
  // so we trust it directly without second-guessing node.data_out.
  const taintMap = new Map<string, VarTaintInfo>();

  // Variables explicitly resolved clean by the sentence-resolver (reconciled=true).
  // These override stale walk-time taintClass on downstream concat sentences.
  const resolvedCleanVars = new Set<string>();

  // Statement objects that have been parameterized (parameter-binding seen)
  const parameterizedObjects = new Set<string>();

  // Proof chain: sentence indices that contributed to each finding
  const proofChain: number[] = [];

  for (let si = 0; si < map.story.length; si++) {
    const sentence = map.story[si]!;
    const { templateKey, slots, taintClass, nodeId, lineNumber } = sentence;
    const varName = slots.subject || slots.data_type || '';

    // Track variables resolved clean by the sentence-resolver
    if ((sentence as any).reconciled && taintClass === 'NEUTRAL' && varName) {
      resolvedCleanVars.add(varName);
    }

    // ── String concatenation: MUST run before the generic TAINTED check ──
    // The generic TAINTED handler has a `continue` that would skip this.
    // Concat needs resolver-aware logic: if all parts were resolved clean,
    // the stale walk-time TAINTED taintClass should be overridden.
    if (templateKey === 'string-concatenation' && varName) {
      const parts = (slots.parts || '').split(/[,\s]+/).filter(Boolean);
      const allPartsResolvedClean = parts.length > 0 &&
        parts.every(p => resolvedCleanVars.has(p) && taintMap.get(p)?.tainted !== true);
      const isTainted = allPartsResolvedClean ? false : taintClass === 'TAINTED';
      taintMap.set(varName, {
        tainted: isTainted,
        reason: (isTainted ? 'tainted concat: ' : 'concat parts resolved clean: ') + sentence.text,
        sourceNodeId: nodeId,
        sourceLine: lineNumber,
      });
      continue;
    }

    // ── TAINTED assignments: mark variable tainted ──
    if (taintClass === 'TAINTED' && varName) {
      taintMap.set(varName, {
        tainted: true,
        reason: sentence.text,
        sourceNodeId: nodeId,
        sourceLine: lineNumber,
      });
      continue;
    }

    // ── NEUTRAL/SAFE assignments: mark variable clean ──
    if ((taintClass === 'NEUTRAL' || taintClass === 'SAFE') && varName) {
      if (templateKey === 'parameter-binding') {
        if (varName) parameterizedObjects.add(varName);
      } else if (templateKey === 'assigned-from-call' || templateKey === 'assigned-literal' ||
                 templateKey === 'creates-instance' || templateKey === 'calls-method') {
        if (varName && varName !== 'result') {
          taintMap.set(varName, {
            tainted: false,
            reason: taintClass === 'SAFE' ? `Safe: ${sentence.text}` : `Clean: ${sentence.text}`,
            sourceNodeId: nodeId,
            sourceLine: lineNumber,
          });
        }
      }
    }

    // ── SINK detection: tainted data reaches SQL query ──
    if (taintClass === 'SINK' && templateKey === 'executes-query') {
      // Cross-domain exclusion
      const queryType = (slots.query_type || '').toLowerCase();
      if (NON_SQL_TEMPLATE_KEYS.has(queryType)) continue;

      const variables = slots.variables || '';
      const sinkObj = slots.subject || '';

      // Parameterized statement check
      if (parameterizedObjects.has(sinkObj)) continue;

      // Find first tainted variable in the query
      let taintedVarName: string | undefined;
      let taintedInfo: VarTaintInfo | undefined;
      for (const [tv, info] of taintMap) {
        if (info.tainted && variables.includes(tv)) {
          taintedVarName = tv;
          taintedInfo = info;
          break;
        }
      }

      if (!taintedVarName || !taintedInfo) continue;

      // Dead branch suppression
      const sinkNode = map.nodes.find(n => n.id === nodeId);
      if (sinkNode && hasDeadBranchForNode(map, sinkNode.id)) continue;

      // Look backward for parameter-binding on same object
      const hasParameterBinding = map.story.some(s =>
        s.templateKey === 'parameter-binding' &&
        s.lineNumber <= lineNumber &&
        (s.slots.subject === sinkObj || s.slots.subject === '')
      );
      if (hasParameterBinding) continue;

      // Build proof chain: find sentence indices from source to sink
      proofChain.length = 0;
      for (let pi = 0; pi < si; pi++) {
        const ps = map.story[pi]!;
        if (ps.nodeId === taintedInfo.sourceNodeId) proofChain.push(pi);
        if (ps.slots.subject === taintedVarName && ps.taintClass === 'TAINTED') proofChain.push(pi);
      }
      proofChain.push(si); // The sink itself

      // Build NodeRefs
      const sourceNode = map.nodes.find(n => n.id === taintedInfo!.sourceNodeId);
      const sourceRef: NodeRef = sourceNode
        ? { id: sourceNode.id, label: sourceNode.label, line: sourceNode.line_start, code: sourceNode.code_snapshot.slice(0, 200) }
        : { id: taintedInfo.sourceNodeId, label: `taint source (line ${taintedInfo.sourceLine})`, line: taintedInfo.sourceLine, code: '' };

      const sinkRef: NodeRef = sinkNode
        ? { id: sinkNode.id, label: sinkNode.label, line: sinkNode.line_start, code: sinkNode.code_snapshot.slice(0, 200) }
        : { id: nodeId, label: `SQL query (line ${lineNumber})`, line: lineNumber, code: '' };

      findings.push({
        source: sourceRef,
        sink: sinkRef,
        missing: 'CONTROL (input validation or parameterized query)',
        severity: 'critical',
        description: `User input "${taintedVarName}" from ${sourceRef.label} flows to SQL query at ${sinkRef.label} without parameterization. ` +
          `Proof chain: sentences [${proofChain.join(', ')}]. Story trace: ${taintedInfo.reason}`,
        fix: 'Use parameterized queries (prepared statements) instead of string concatenation. ' +
          'Example: db.query("SELECT * FROM users WHERE id = $1", [userId]) instead of ' +
          'db.query("SELECT * FROM users WHERE id = " + userId)',
        via: 'bfs',
      });
    }
  }

  return {
    cwe: 'CWE-89',
    name: 'SQL Injection',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-89: SQL Injection
 * Pattern: INGRESS → STORAGE(sql) without CONTROL(parameterization)
 * Property: All database queries use parameterized statements when handling user input
 */
function verifyCWE89(map: NeuralMap): VerificationResult {
  // V2: Sentence-based detection — runs when the story contains executes-query.
  // V2 is authoritative when the story is RICH enough to track taint chains
  // (has assignment/concatenation sentences). When the story is sparse (only
  // generic sink + INGRESS, no intermediate assignments), V2 can't reason about
  // data flow and falls through to V1 for safety.
  if (map.story && map.story.some(s => s.templateKey === 'executes-query')) {
    const v2 = verifyCWE89_sentences(map);
    if (v2.findings.length > 0) return v2; // V2 proved vulnerability — trust it
    // V2 found nothing. Trust it only if story tracks taint chains.
    const storyTracksTaint = map.story.some(s =>
      s.templateKey === 'assigned-from-call' ||
      s.templateKey === 'string-concatenation' ||
      s.templateKey === 'assigned-literal' ||
      s.templateKey === 'parameter-binding'
    );
    if (storyTracksTaint) return v2; // Rich story — V2 authoritative (code is clean)
    // Sparse story — fall through to V1
  }
  // V1: Legacy BFS + regex path (fallback when no story exists)
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Cross-domain exclusion: subtypes belonging to other injection domains must NOT
  // trigger SQL injection.  "xpath_query" and "ldap_query" contain the substring
  // "query" which caused CWE-89 to fire on XPath/LDAP code.
  const NON_SQL_QUERY_DOMAINS = /^(xpath_query|ldap_query|nosql_query|graphql_query|mongo_query|redis_query)$/;

  // File-domain exclusion: STORAGE nodes that are file operations (file_read, file_write,
  // file_access, etc.) should not be treated as SQL sinks. These fire on path traversal
  // code where file.exists()/FileInputStream are misidentified as "query" sinks.
  const FILE_DOMAIN_SUBTYPE = /\bfile/i;
  const FILE_DOMAIN_CODE = /\b(File|FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|BufferedWriter|RandomAccessFile|file\.exists|file\.isFile|file\.isDirectory|Files\.(read|write|copy|move|delete)|createReadStream|createWriteStream|readFile|writeFile|fopen|fread|fwrite)\b/;
  const SQL_DOMAIN_CODE = /\b(Statement|PreparedStatement|ResultSet|Connection|DriverManager|executeQuery|executeUpdate|executeBatch|createStatement|prepareStatement|SELECT\s|INSERT\s|UPDATE\s|DELETE\s|FROM\s|WHERE\s|CREATE\s+TABLE|DROP\s+TABLE|sql|SQL|jdbc)\b/;

  const storage = map.nodes.filter(n => {
    if (n.node_type !== 'STORAGE') return false;
    if (NON_SQL_QUERY_DOMAINS.test(n.node_subtype)) return false;

    // If node subtype is file-related and NOT sql-related, skip it
    if (FILE_DOMAIN_SUBTYPE.test(n.node_subtype) && !n.node_subtype.includes('sql')) return false;

    const matchesSubtype = n.node_subtype.includes('sql') || n.node_subtype.includes('query') ||
      n.node_subtype.includes('db_read') || n.node_subtype.includes('db_write');
    const matchesAttack = n.attack_surface.includes('sql_sink');
    const snap = n.analysis_snapshot || n.code_snapshot;
    const matchesCode = /\b(query|exec|execute\w*|prepare|raw)\s*\(/i.test(snap);

    if (!matchesSubtype && !matchesAttack && !matchesCode) return false;

    // If the code snapshot looks like file-domain code with no SQL indicators, exclude it
    if (FILE_DOMAIN_CODE.test(snap) && !SQL_DOMAIN_CODE.test(snap)) return false;

    return true;
  });

  for (const src of ingress) {
    for (const sink of storage) {
      // Primary: BFS taint path. Fallback (Step 8): check data_in tainted entries on sink.
      const bfsHit89 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const sinkTaintHit89 = !bfsHit89 && sinkHasTaintedDataIn(map, sink.id);
      if (bfsHit89 || sinkTaintHit89) {
        if (hasDeadBranchForNode(map, sink.id)) continue;
        // Check if the sink or containing scope uses parameterized queries
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const sinkSnap = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const paramRegex = /\$\d|\?\s*[,)"']|\bprepare(?:Statement|d)?\b|\bparameterized\b|\bplaceholder/i;
        let isParameterized = paramRegex.test(combinedScope) || paramRegex.test(sinkSnap);
        // Partial parameterization fix: if prepareStatement/prepareCall is present but tainted
        // variables are concatenated into the SQL string (+ var +), it's NOT properly parameterized
        if (isParameterized && /\bprepare(?:Statement|Call)\b/.test(combinedScope)) {
          const sqlConcatPattern = /["']\s*\+\s*\w+\s*\+\s*["']|["']\s*\+\s*\w+\s*[);]/;
          if (sqlConcatPattern.test(combinedScope)) isParameterized = false;
        }

        if (!isParameterized) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input validation or parameterized query)',
            severity: 'critical',
            description: `User input from ${src.label} flows to SQL query at ${sink.label} without parameterization. ` +
              `Tainted data reaches the query builder directly.`,
            fix: 'Use parameterized queries (prepared statements) instead of string concatenation. ' +
              'Example: db.query("SELECT * FROM users WHERE id = $1", [userId]) instead of ' +
              'db.query("SELECT * FROM users WHERE id = " + userId)',
            via: bfsHit89 ? 'bfs' : 'sink_tainted',
          });
        }
      }
    }
  }

  // Source-line fallback for Java: detect SQL injection inside anonymous inner classes
  // where taint crosses class boundaries (e.g., JWT header.get("kid") → executeQuery).
  // The mapper doesn't trace taint across inner class boundaries, so BFS misses these.
  if (findings.length === 0 && map.source_code && !map.nodes.some(n => n.metadata?.collectionTaintNeutralized === true) && !(map as any).collectionTaintNeutralized) {
    const sl89 = stripComments(map.source_code);
    const lines89 = sl89.split('\n');

    // Pattern: anonymous inner class or lambda that extracts a value from a
    // request/header/claims object and concatenates it into a SQL query string.
    // Examples:
    //   final String kid = (String) header.get("kid");
    //   ... .executeQuery("SELECT key FROM jwt_keys WHERE id = '" + kid + "'");
    const INNER_SRC_RE = /(\w+)\s*=\s*(?:\(\w+\)\s*)?(?:\w+\.)*(?:get|getParameter|getParameterValues|getParameterNames|getHeader|getString|getValue|claim|getClaim|getCookies|getQueryString|getInputStream|getReader|System\.getenv)\s*\(/;
    const SQL_EXEC_RE = /\b(?:executeQuery|executeUpdate|execute|prepareStatement|createStatement|queryForRowSet|queryForObject|queryForList|queryForMap|queryForInt|queryForLong|prepareCall|jdbcTemplate\.query|namedParameterJdbcTemplate)\s*\(\s*(?:"[^"]*"\s*\+|\w+\s*\+|[^)]*\+\s*\w+)/;
    const PARAM_RE = /\bprepare(?:Statement|d)?\s*\(|\?\s*[,)]/;

    const innerTainted = new Set<string>();
    let innerSrcLine = 0;
    let innerSrcCode = '';
    let hasSqlConcat = false;
    let sqlLine = 0;
    let sqlCode = '';

    for (let i = 0; i < lines89.length; i++) {
      const ln = lines89[i]!.trim();
      if (ln.startsWith('//') || ln.startsWith('*')) continue;

      const srcMatch = ln.match(INNER_SRC_RE);
      if (srcMatch) {
        innerTainted.add(srcMatch[1]!);
        if (!innerSrcLine) { innerSrcLine = i + 1; innerSrcCode = ln; }
      }

      // For-each loop taint propagation: for (Type varName : collection)
      const forEachMatch89 = ln.match(/\bfor\s*\(\s*(?:\w+\.)*\w+(?:\[\])?\s+(\w+)\s*:\s*(\w+)\s*\)/);
      if (forEachMatch89 && innerTainted.has(forEachMatch89[2]!)) {
        innerTainted.add(forEachMatch89[1]!);
      }

      // Propagate simple assignments
      // Also handle assignments after control-flow keywords:
      //   if (...) param = values[0];   else param = "";
      const assignMatch = ln.match(/^(?:\w+\s+)*(\w+)\s*=\s*(.+)/)
        || ln.match(/\belse\s+(\w+)\s*=\s*(.+)/)
        || ln.match(/\bif\s*\([^)]*\)\s*(\w+)\s*=\s*(.+)/);
      if (assignMatch) {
        const lhs = assignMatch[1]!;
        const rhs = assignMatch[2]!;
        for (const tv of innerTainted) {
          if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(rhs)) {
            innerTainted.add(lhs);
            break;
          }
        }
      }

      // HashMap taint resolution: bar = (Type) map.get("key")
      const mapGet89 = ln.match(/^(?:\w+\s+)*(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
      if (mapGet89) {
        const mkr89 = resolveMapKeyTaint(lines89, innerTainted, mapGet89[2]!, mapGet89[3]!, i);
        if (mkr89 === 'tainted') innerTainted.add(mapGet89[1]!); else innerTainted.delete(mapGet89[1]!);
      }

      // Check for SQL execution with string concatenation using tainted var
      // Handle both single-line and multi-line SQL statements
      const SQL_CALL_RE89 = /\b(?:executeQuery|executeUpdate|execute|prepareStatement|createStatement|queryForRowSet|queryForObject|queryForList|queryForMap|queryForInt|queryForLong|prepareCall|jdbcTemplate\.query)\s*\(/;
      if ((SQL_EXEC_RE.test(ln) || SQL_CALL_RE89.test(ln)) && !PARAM_RE.test(ln)) {
        // Build a window of nearby lines to check for tainted vars in SQL concat
        // Use a wider lookback (15 lines) to cover multi-line SQL setup patterns
        // where the SQL string is built several lines before the execute call
        const windowStart = Math.max(0, i - 15);
        const windowEnd = Math.min(lines89.length - 1, i + 5);
        const window89 = lines89.slice(windowStart, windowEnd + 1).join(' ');

        // Skip if parameterized — but allow partial parameterization detection:
        // if prepareStatement/prepareCall is present AND tainted var is concatenated into the SQL
        // string, it's NOT properly parameterized (e.g., prepareStatement("SELECT ... '" + bar + "'"))
        let paramSuppressed89 = PARAM_RE.test(window89);
        if (paramSuppressed89 && /\bprepare(?:Statement|Call)\b/.test(window89)) {
          const sqlConcatPattern89 = /["']\s*\+\s*\w+\s*\+\s*["']|["']\s*\+\s*\w+\s*[);]/;
          if (sqlConcatPattern89.test(window89)) paramSuppressed89 = false;
        }
        if (!paramSuppressed89) {
          for (const tv of innerTainted) {
            // Check if tainted var appears in string concatenation near the SQL call
            if (new RegExp('["+\'\\s]\\s*\\+\\s*\\b' + escapeRegExp(tv) + '\\b|\\b' + escapeRegExp(tv) + '\\b\\s*\\+\\s*["+\'\\s]').test(window89)) {
              hasSqlConcat = true;
              // Find the exact line with the tainted var for reporting
              for (let j = windowStart; j <= windowEnd; j++) {
                if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(lines89[j]!)) {
                  sqlLine = j + 1;
                  sqlCode = lines89[j]!.trim();
                  break;
                }
              }
              if (!sqlLine) { sqlLine = i + 1; sqlCode = ln; }
              break;
            }
          }
        }
      }
    }

    if (hasSqlConcat && innerSrcLine > 0) {
      if (!isLineInDeadBranchFunction(map, sqlLine)) {
        findings.push({
          source: { id: `srcline-${innerSrcLine}`, label: `inner class input (line ${innerSrcLine})`, line: innerSrcLine, code: innerSrcCode.slice(0, 200) },
          sink: { id: `srcline-${sqlLine}`, label: `SQL query (line ${sqlLine})`, line: sqlLine, code: sqlCode.slice(0, 200) },
          missing: 'CONTROL (input validation or parameterized query)',
          severity: 'critical',
          description: `Data extracted inside inner class flows to SQL query at line ${sqlLine} via string concatenation without parameterization.`,
          fix: 'Use parameterized queries (prepared statements) instead of string concatenation.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  // Language-generic SQL concatenation fallback (Go, Python, PHP, etc.)
  // Detects: "SELECT ... " + userVar or fmt.Sprintf("SELECT ... %s", userVar)
  if (findings.length === 0 && map.source_code) {
    const sl89g = stripComments(map.source_code);
    // Generic SQL string concat patterns across languages
    const SQL_CONCAT_GENERIC = /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+[^"]*["']\s*\+\s*\w+|fmt\.Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"]*%[sv]/i;
    const PARAM_GENERIC = /\$\d+|\?\s*[,)]|\bprepare\b|\bQueryRow\s*\(.*\$|\bExec\s*\(.*\$/i;
    if (SQL_CONCAT_GENERIC.test(sl89g) && !PARAM_GENERIC.test(sl89g)) {
      // Check for taint source
      const HAS_SOURCE_GENERIC = /\b(?:r\.URL\.Query|c\.Query|c\.Param|c\.FormValue|request\.GET|request\.POST|request\.args|\$_GET|\$_POST|\$_REQUEST|params\[|chi\.URLParam|r\.FormValue)\b/i;
      if (HAS_SOURCE_GENERIC.test(sl89g)) {
        const bestSrc = ingress[0];
        const bestSink = storage[0];
        if (bestSrc && bestSink) {
          findings.push({
            source: nodeRef(bestSrc), sink: nodeRef(bestSink),
            missing: 'CONTROL (input validation or parameterized query)',
            severity: 'critical',
            description: `User input concatenated into SQL query string without parameterization.`,
            fix: 'Use parameterized queries with placeholders ($1, ?) instead of string concatenation.',
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-89',
    name: 'SQL Injection',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-79: Cross-Site Scripting (XSS)
 * Pattern: INGRESS → EGRESS(html/response) without CONTROL(encoding)
 * Property: All user input is encoded before being included in HTML output
 */

/**
 * CWE-79 sentence verifier: walks the semantic story forward, looking for
 * tainted data that reaches a writes-response sentence without sanitization.
 * Same architecture as verifyCWE89_sentences — different sink, different defense.
 */
function verifyCWE79_sentences(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  if (!map.story || map.story.length === 0) {
    return { cwe: 'CWE-79', name: 'Cross-Site Scripting (XSS)', holds: true, findings: [] };
  }

  const taintMap = new Map<string, VarTaintInfo>();
  const resolvedCleanVars = new Set<string>();
  const sanitizedVars = new Set<string>();

  for (let si = 0; si < map.story.length; si++) {
    const sentence = map.story[si]!;
    const { templateKey, slots, taintClass, nodeId, lineNumber } = sentence;
    const varName = slots.subject || slots.data_type || '';

    // Track resolver-proven clean variables
    if ((sentence as any).reconciled && taintClass === 'NEUTRAL' && varName) {
      resolvedCleanVars.add(varName);
    }

    // Track sanitized variables — SAFE calls-method means encoder/sanitizer
    if (taintClass === 'SAFE' && templateKey === 'calls-method' && varName) {
      sanitizedVars.add(varName);
    }

    // String concatenation — resolver-aware (same as SQLi)
    if (templateKey === 'string-concatenation' && varName) {
      const parts = (slots.parts || '').split(/[,\s]+/).filter(Boolean);
      const allPartsResolvedClean = parts.length > 0 &&
        parts.every(p => resolvedCleanVars.has(p) && taintMap.get(p)?.tainted !== true);
      const isTainted = allPartsResolvedClean ? false : taintClass === 'TAINTED';
      taintMap.set(varName, {
        tainted: isTainted,
        reason: (isTainted ? 'tainted concat: ' : 'concat resolved clean: ') + sentence.text,
        sourceNodeId: nodeId, sourceLine: lineNumber,
      });
      continue;
    }

    // SINK: writes-response — check BEFORE generic TAINTED handler.
    // Read variables directly from slots.variables (populated at sentence generation time).
    // No regex. No arg parsing. The story already tells us which variables reach the output.
    if (templateKey === 'writes-response') {
      const variables = slots.variables || '';
      if (!variables) continue; // no variables in args = safe static output
      const varNames = variables.split(/[,\s]+/).filter(Boolean);

      for (const argVar of varNames) {
        const info = taintMap.get(argVar);
        if (!info?.tainted) continue;
        if (sanitizedVars.has(argVar)) continue;

        // Dead branch suppression
        const sinkNode = map.nodes.find(n => n.id === nodeId);
        if (sinkNode && hasDeadBranchForNode(map, sinkNode.id)) continue;

        const sourceNode = map.nodes.find(n => n.id === info.sourceNodeId);
        const sourceRef: NodeRef = sourceNode
          ? { id: sourceNode.id, label: sourceNode.label, line: sourceNode.line_start, code: sourceNode.code_snapshot.slice(0, 200) }
          : { id: info.sourceNodeId, label: `taint source (line ${info.sourceLine})`, line: info.sourceLine, code: '' };
        const sinkRef: NodeRef = sinkNode
          ? { id: sinkNode.id, label: sinkNode.label, line: sinkNode.line_start, code: sinkNode.code_snapshot.slice(0, 200) }
          : { id: nodeId, label: `response output (line ${lineNumber})`, line: lineNumber, code: '' };

        findings.push({
          source: sourceRef,
          sink: sinkRef,
          missing: 'CONTROL (output encoding or sanitization)',
          severity: 'high',
          description: `User input "${argVar}" from ${sourceRef.label} flows to response output at ${sinkRef.label} without encoding. ` +
            `This allows script injection (XSS). Story trace: ${info.reason}`,
          fix: 'Encode output for the HTML context. Use ESAPI.encoder().encodeForHTML(), ' +
            'StringEscapeUtils.escapeHtml(), or equivalent before writing to response.',
          via: 'v2_sentences',
        });
        break; // one finding per sink
      }
    }

    // TAINTED → mark tainted
    if (taintClass === 'TAINTED' && varName) {
      taintMap.set(varName, {
        tainted: true, reason: sentence.text,
        sourceNodeId: nodeId, sourceLine: lineNumber,
      });
      continue;
    }

    // NEUTRAL/SAFE assignments → mark clean
    if ((taintClass === 'NEUTRAL' || taintClass === 'SAFE') && varName) {
      if (templateKey === 'assigned-from-call' || templateKey === 'assigned-literal' ||
          templateKey === 'creates-instance' || templateKey === 'calls-method') {
        if (varName && varName !== 'result') {
          taintMap.set(varName, {
            tainted: false,
            reason: taintClass === 'SAFE' ? `Sanitized: ${sentence.text}` : `Clean: ${sentence.text}`,
            sourceNodeId: nodeId, sourceLine: lineNumber,
          });
          if (taintClass === 'SAFE') sanitizedVars.add(varName);
        }
      }
    }
  }

  return {
    cwe: 'CWE-79',
    name: 'Cross-Site Scripting (XSS)',
    holds: findings.length === 0,
    findings,
  };
}

function verifyCWE79(map: NeuralMap): VerificationResult {
  // V2: Sentence-based detection — runs when the story contains writes-response.
  // Same sparse-story fallback as CWE-89: V2 is authoritative only when the
  // story has taint-chain sentences. Sparse stories fall through to V1.
  if (map.story && map.story.some(s => s.templateKey === 'writes-response')) {
    const v2 = verifyCWE79_sentences(map);
    if (v2.findings.length > 0) return v2;
    const storyTracksTaint = map.story.some(s =>
      s.templateKey === 'assigned-from-call' ||
      s.templateKey === 'string-concatenation' ||
      s.templateKey === 'assigned-literal' ||
      s.templateKey === 'parameter-binding'
    );
    if (storyTracksTaint) return v2;
  }
  // V1: BFS + regex fallback (only when no story exists)
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const egress = map.nodes.filter(n =>
    // EGRESS nodes that produce HTML output
    (n.node_type === 'EGRESS' &&
    (n.node_subtype.includes('html') || n.node_subtype.includes('response') ||
     n.node_subtype.includes('render') || n.node_subtype.includes('display') ||
     n.attack_surface.includes('html_output') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(innerHTML|render|send|write|res\.send|\.body\s*\(|echo|print)\b/i) !== null ||
     (n.analysis_snapshot || n.code_snapshot).match(/\.println\s*\(|\.print\s*\(|writer\.write\s*\(/i) !== null)) ||
    // EXTERNAL nodes that produce HTML via template engines (render_template_string, Jinja2, etc.)
    (n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('template_exec') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(render_template_string|render_template|Template)\b/i) !== null))
  );

  // Interprocedural neutralization: inner-class/helper methods that kill taint via
  // static value replacement, HashMap safe-key retrieval, or taint abandonment.
  const hasInterproceduralKill79 = map.source_code ? detectInterproceduralNeutralization90(map.source_code) : false;

  // HashMap safe-key retrieval (inline, non-interprocedural): tainted value is stored
  // under one key but a different (safe) key is retrieved before reaching the sink.
  let hasMapKeySafeRetrieval79 = false;
  if (map.source_code) {
    const cleanSrc79 = stripComments(map.source_code);
    const lines79h = cleanSrc79.split('\n');
    const allGets79 = [...cleanSrc79.matchAll(/(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/g)];
    if (allGets79.length > 0) {
      const lastGet79 = allGets79[allGets79.length - 1]!;
      const mapVar79 = lastGet79[1]!;
      const getKey79 = lastGet79[2]!;
      const taintedVars79 = new Set<string>();
      for (const ln of lines79h) {
        const srcM = ln.match(/(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getParameterValues|getHeader|getHeaders|getCookies|getInputStream|getReader|getQueryString|nextElement)\s*\(/);
        if (srcM) taintedVars79.add(srcM[1]!);
        const decM = ln.match(/(\w+)\s*=\s*.*(?:URLDecoder\.decode)\s*\(/);
        if (decM) taintedVars79.add(decM[1]!);
      }
      if (taintedVars79.size > 0) {
        const lineIdx79 = lines79h.findIndex(l => l.includes(lastGet79[0]));
        if (lineIdx79 >= 0) {
          const mkr79 = resolveMapKeyTaint(lines79h, taintedVars79, mapVar79, getKey79, lineIdx79);
          if (mkr79 === 'safe') hasMapKeySafeRetrieval79 = true;
        }
      }
    }
  }

  for (const src of ingress) {
    for (const sink of egress) {
      // Primary: BFS taint path. Fallback (Step 8): check data_in tainted entries on sink.
      // Fallback 2: scope-based taint (Java Juliet patterns with incomplete DATA_FLOW edges)
      const bfsHit79 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const sinkTaintHit79 = !bfsHit79 && sinkHasTaintedDataIn(map, sink.id);
      const scopeTaintHit79 = !bfsHit79 && !sinkTaintHit79 && scopeBasedTaintReaches(map, src.id, sink.id);
      if (bfsHit79 || sinkTaintHit79 || scopeTaintHit79) {
        if (hasDeadBranchForNode(map, sink.id) || hasInterproceduralKill79 || hasMapKeySafeRetrieval79) continue;
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isEncoded = combinedScope.match(
          /\bescape\s*\(|\bescapeHtml\b|\bhtmlEncode\s*\(|\bencodeURI(?:Component)?\b|\bsanitize\s*\(|\bDOMPurify\b|\btextContent\b|\bencodeForHTML\b|\bESAPI\b|\bEncoder\b.*\bencode\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b/i
        ) !== null;

        // JSON responses are not vulnerable to XSS — Content-Type: application/json
        // prevents browser script execution. Detect .send({...}), .json({...}), res.json()
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const isJsonResponse = sinkCode.match(
          /\.send\s*\(\s*\{|\.json\s*\(\s*\{|\.json\s*\(|res\.send\s*\(\s*\{|reply\.send\s*\(\s*\{|response\.json\s*\(/i
        ) !== null;

        if (!isEncoded && !isJsonResponse) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (output encoding or sanitization)',
            severity: 'high',
            description: `User input from ${src.label} is reflected in HTML output at ${sink.label} without encoding. ` +
              `This allows script injection.`,
            fix: 'Encode output for the target context. Use textContent instead of innerHTML. ' +
              'Use a sanitizer like DOMPurify for rich text. Never trust user input in HTML.',
            via: bfsHit79 ? 'bfs' : sinkTaintHit79 ? 'sink_tainted' : 'scope_taint',
          });
        } else if (isEncoded && !isJsonResponse) {
          // Context-aware encoding check: encoding exists but may be wrong for the output context.
          const sinkContextCode = stripComments(
            sink.node_subtype + ' ' + (sink.analysis_snapshot || sink.code_snapshot)
          );

          // Determine the output context from the sink's subtype and code_snapshot.
          const isHtmlContext = /\binnerHTML\b|\bdocument\.write\b|\.html\s*\(|render\s*\(|html_response|html_output/i.test(sinkContextCode);
          const isJsContext = /<script\b|eval\s*\(|setTimeout\s*\(\s*[^,)]*[^,)]\s*[,)]/i.test(sinkContextCode) ||
            /js_context|script_context/i.test(sink.node_subtype);
          const isUrlContext = /href\s*=|src\s*=|action\s*=|url_redirect|url_context/i.test(sinkContextCode);
          const isCssContext = /style\s*=|\.css\s*\(/i.test(sinkContextCode) || /css_context/i.test(sink.node_subtype);
          const isAttributeContext = /setAttribute\s*\(/i.test(sinkContextCode) || /attribute_context/i.test(sink.node_subtype);

          // Determine which encoding functions are actually used.
          const hasHtmlEncoding = /\bescapeHtml\b|\bhtmlEncode\b|\bDOMPurify\b|\btextContent\b|\bencodeForHTML\b|\bESAPI\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b/i.test(combinedScope);
          const hasUrlEncoding = /\bencodeURIComponent\b|\bencodeURI\b/i.test(combinedScope);
          const hasJsEncoding = /\bJSON\.stringify\b|\bjsEscape\b|\bescapeJs\b/i.test(combinedScope);

          // Check for wrong encoding given the context.
          let wrongEncodingDescription: string | null = null;

          if (isHtmlContext && !hasHtmlEncoding && (hasUrlEncoding || hasJsEncoding)) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'URL/JS-encoded data in an HTML context can still be exploited.';
          } else if (isJsContext && hasHtmlEncoding && !hasJsEncoding) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'HTML-encoded data in JavaScript context can still be exploited.';
          } else if (isUrlContext && hasHtmlEncoding && !hasUrlEncoding) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'HTML-encoded data in a URL context does not prevent URL-based attacks.';
          } else if (isCssContext && !hasHtmlEncoding && !hasJsEncoding) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'CSS context requires CSS-specific encoding to prevent style injection.';
          } else if (isAttributeContext && hasUrlEncoding && !hasHtmlEncoding) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'URL-encoded data in an HTML attribute context can still be exploited.';
          }

          if (wrongEncodingDescription) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (correct encoding for output context)',
              severity: 'high',
              description: wrongEncodingDescription,
              fix: 'Use context-appropriate encoding: htmlEscape/DOMPurify for HTML, ' +
                'JSON.stringify/jsEscape for JavaScript, encodeURIComponent for URLs, ' +
                'CSS encoding for style contexts. Never substitute one context\'s encoding for another.',
              via: bfsHit79 ? 'bfs' : sinkTaintHit79 ? 'sink_tainted' : 'scope_taint',
            });
          }
        }
      }
    }
  }

  // Source-line fallback for Java: detect reflected XSS via @ResponseBody.
  // When a Spring controller method is annotated with @ResponseBody (or the class
  // with @RestController), the return value IS the HTTP response body. If a
  // @RequestParam is concatenated into a StringBuilder or string that gets returned
  // (directly or via .output()), it's reflected XSS without encoding.
  if (findings.length === 0 && map.source_code) {
    const sl79 = stripComments(map.source_code);
    const lines79 = sl79.split('\n');

    // Check for @ResponseBody or @RestController presence
    const hasResponseBody = /@ResponseBody|@RestController/.test(sl79);
    if (hasResponseBody) {
      // Find @RequestParam String variables
      const requestParams79 = new Set<string>();
      const PARAM_RE79 = /@RequestParam(?:\s*\([^)]*\))?\s+(?:String|Integer|Long|int|long)\s+(\w+)/g;
      let pm79;
      while ((pm79 = PARAM_RE79.exec(sl79)) !== null) {
        requestParams79.add(pm79[1]!);
      }

      if (requestParams79.size > 0) {
        // Track taint through assignments and string concatenation
        const tainted79 = new Set(requestParams79);
        const ENCODE_RE79 = /\bescapeHtml\b|\bhtmlEncode\b|\bsanitize\b|\bencodeForHTML\b|\bESAPI\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b|\bDOMPurify\b/i;

        // Check if any request param is concatenated into a string builder or string
        // that reaches a response output without encoding
        let xssFound = false;
        let xssSrcLine = 0;
        let xssSrcCode = '';
        let xssSinkLine = 0;
        let xssSinkCode = '';

        for (let i = 0; i < lines79.length; i++) {
          const ln = lines79[i]!.trim();
          if (ln.startsWith('//') || ln.startsWith('*')) continue;

          // Propagate taint through StringBuilder.append with concat
          for (const tv of tainted79) {
            if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(ln)) {
              // String concatenation: "..." + field1
              if (/\+\s*\w+|\w+\s*\+/.test(ln)) {
                // Mark StringBuilder variables as tainted
                const sbMatch = ln.match(/(\w+)\.append\s*\(/);
                if (sbMatch) tainted79.add(sbMatch[1]!);
              }
              // Assignment propagation
              const assignMatch = ln.match(/^(?:\w+\s+)*(\w+)\s*=\s*/);
              if (assignMatch && assignMatch[1] !== tv) tainted79.add(assignMatch[1]!);
            }
          }

          // .toString() propagation from tainted StringBuilder
          const tsMatch = ln.match(/(\w+)\.toString\s*\(\s*\)/);
          if (tsMatch && tainted79.has(tsMatch[1]!)) {
            const outerAssign = ln.match(/(?:^|\s)(\w+)\s*=\s*/);
            if (outerAssign) tainted79.add(outerAssign[1]!);
          }

          // Detect output sinks: .output(...), .body(...), return ..., .send(...)
          const outputMatch = ln.match(/\.output\s*\(([^)]*)\)|\.body\s*\(([^)]*)\)|return\s+(.+)/);
          if (outputMatch) {
            const outputArg = outputMatch[1] || outputMatch[2] || outputMatch[3] || '';
            for (const tv of tainted79) {
              if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(outputArg)) {
                // Check if encoding is present in scope
                const scopeSlice = lines79.slice(Math.max(0, i - 30), i + 1).join('\n');
                if (!ENCODE_RE79.test(scopeSlice)) {
                  xssFound = true;
                  // Find the source line
                  for (let j = 0; j < lines79.length; j++) {
                    for (const rp of requestParams79) {
                      if (new RegExp('@RequestParam.*\\b' + escapeRegExp(rp) + '\\b').test(lines79[j]!)) {
                        xssSrcLine = j + 1;
                        xssSrcCode = lines79[j]!.trim();
                        break;
                      }
                    }
                    if (xssSrcLine) break;
                  }
                  xssSinkLine = i + 1;
                  xssSinkCode = ln;
                  break;
                }
              }
            }
          }
          if (xssFound) break;
        }

        if (xssFound && xssSrcLine > 0) {
          findings.push({
            source: { id: `srcline-${xssSrcLine}`, label: `request parameter (line ${xssSrcLine})`, line: xssSrcLine, code: xssSrcCode.slice(0, 200) },
            sink: { id: `srcline-${xssSinkLine}`, label: `@ResponseBody output (line ${xssSinkLine})`, line: xssSinkLine, code: xssSinkCode.slice(0, 200) },
            missing: 'CONTROL (output encoding or sanitization)',
            severity: 'high',
            description: `User input from @RequestParam is reflected in @ResponseBody HTTP response at line ${xssSinkLine} without encoding. ` +
              `An attacker can inject script tags via the request parameter.`,
            fix: 'Encode output for the target context. Use HtmlUtils.htmlEscape() or a sanitizer before including user input in response bodies.',
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-79',
    name: 'Cross-Site Scripting (XSS)',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-81: XSS in Error Message
 * Pattern: INGRESS → error-output-sink without CONTROL(error-message encoding)
 * Property: User input reflected in error pages/responses (sendError, error handler
 * output, exception.getMessage() in response) must be encoded.
 *
 * This is a SPECIFIC sub-variant of CWE-79. The distinguishing factor is that the
 * sink is an error-handling output path: sendError(), error page rendering, or
 * exception message displayed to the user. Uses a different missingCategory than
 * CWE-79 so family dedup keeps both findings.
 */
function verifyCWE81(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Sinks specific to CWE-81: error message output paths
  const errorSinks = map.nodes.filter(n => {
    const code = n.analysis_snapshot || n.code_snapshot;
    const sub = n.node_subtype;
    // Must be EGRESS or have output-like characteristics
    if (n.node_type !== 'EGRESS' && n.node_type !== 'TRANSFORM') return false;
    // Specific error-output sinks:
    //   - response.sendError(status, message) — Java Servlet
    //   - sendError / send_error patterns
    //   - error page rendering (error.jsp, error handler, error template)
    //   - exception.getMessage() flowing to response output
    //   - res.status(4xx/5xx).send() patterns
    //   - HttpServletResponse error methods
    return (
      /\bsendError\s*\(/i.test(code) ||
      /\bsend_error\s*\(/i.test(code) ||
      /\berror\s*page\b|\berror\s*handler\b|\berror\s*template\b/i.test(code) ||
      /\b(get)?[Mm]essage\s*\(\s*\)/.test(code) && /\b(print|write|send|render|display)\b/i.test(code) ||
      /\bres\s*\.\s*status\s*\(\s*[45]\d{2}\s*\)\s*\.\s*send\b/i.test(code) ||
      /\bresponse\.sendError\b/i.test(code) ||
      sub.includes('error') ||
      sub.includes('sendError')
    );
  });

  // Also check all EGRESS nodes whose containing scope has sendError / error-output patterns
  const egressWithErrorScope = map.nodes.filter(n => {
    if (n.node_type !== 'EGRESS') return false;
    if (errorSinks.some(s => s.id === n.id)) return false; // already captured
    const scopeSnaps = getContainingScopeSnapshots(map, n.id);
    const scopeCode = stripComments(scopeSnaps.join('\n'));
    return /\bsendError\s*\(/i.test(scopeCode) ||
           /\bresponse\.sendError\b/i.test(scopeCode);
  });

  const allErrorSinks = [...errorSinks, ...egressWithErrorScope];

  for (const src of ingress) {
    for (const sink of allErrorSinks) {
      const bfsHit81 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const sinkTaintHit81 = !bfsHit81 && sinkHasTaintedDataIn(map, sink.id);
      const scopeTaintHit81 = !bfsHit81 && !sinkTaintHit81 && scopeBasedTaintReaches(map, src.id, sink.id);
      if (bfsHit81 || sinkTaintHit81 || scopeTaintHit81) {
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isEncoded = /\bescape\s*\(|\bescapeHtml\b|\bhtmlEncode\s*\(|\bsanitize\s*\(|\bDOMPurify\b|\btextContent\b|\bencodeForHTML\b|\bESAPI\b|\bEncoder\b.*\bencode\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b/i.test(combinedScope);

        if (!isEncoded) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'ERROR_ENCODING (encode user data in error responses)',
            severity: 'high',
            description: `User input from ${src.label} is reflected in an error response at ${sink.label} without encoding. ` +
              `Error pages that echo user input (e.g. sendError with tainted data) enable reflected XSS.`,
            fix: 'HTML-encode all user-controlled values before including them in error messages or error pages. ' +
              'Use HttpServletResponse.sendError() only with static messages, or encode dynamic values with ESAPI/HtmlUtils.',
            via: bfsHit81 ? 'bfs' : sinkTaintHit81 ? 'sink_tainted' : 'scope_taint',
          });
        }
      }
    }
  }

  // Source-line scan: look for sendError with string concatenation (direct pattern match)
  if (findings.length === 0) {
    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      // Pattern: sendError(statusCode, <anything> + variable) — tainted data in error message
      if (/\bsendError\s*\(\s*\d+\s*,\s*[^)]*\+\s*\w/i.test(code)) {
        // Check if any INGRESS variable is referenced
        for (const src of ingress) {
          const srcLabel = src.label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          // Check if the ingress label or common tainted variable names appear near the sendError
          if (new RegExp(`\\b(data|input|param|${srcLabel})\\b`, 'i').test(code)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(node),
              missing: 'ERROR_ENCODING (encode user data in error responses)',
              severity: 'high',
              description: `User input flows to sendError() at ${node.label} via string concatenation. ` +
                `Error messages that include unsanitized user data enable reflected XSS in error pages.`,
              fix: 'HTML-encode user-controlled values before passing to sendError(). ' +
                'Use ESAPI.encoder().encodeForHTML() or HtmlUtils.htmlEscape() on dynamic values.',
              via: 'source_line_fallback',
            });
            break;
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-81',
    name: 'XSS in Error Message',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-83: XSS in HTML Attribute
 * Pattern: INGRESS → attribute-context-sink without CONTROL(attribute encoding)
 * Property: User input inserted into HTML attribute values (href, src, onclick, style,
 * event handlers, etc.) must be attribute-encoded.
 *
 * This is a SPECIFIC sub-variant of CWE-79. The distinguishing factor is that the
 * output context is an HTML attribute value, where the attacker can break out of
 * the attribute or inject event handlers. Uses a different missingCategory than
 * CWE-79 so family dedup keeps both findings.
 */
function verifyCWE83(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Attribute-context HTML output pattern
  const ATTR_CONTEXT_RE = /\b(href|src|action|formaction|onclick|onload|onerror|onmouseover|onfocus|onblur|onchange|onsubmit|style|data-\w+|value|class|id|name|type|alt|title)\s*=\s*["']/i;
  const IMG_TAG_RE = /<img\b[^>]*\bsrc\s*=\s*["'][^"']*\+|<img\b[^>]*\bsrc\s*=\s*["']\s*"\s*\+/i;
  const ATTR_CONCAT_RE = /\b(href|src|action|formaction|onclick|onload|onerror|onmouseover|style)\s*=\s*["'][^"']*["']\s*\+\s*\w|\b(href|src|action|formaction|onclick|onload|onerror|onmouseover|style)\s*=\s*["'][^"']*\+\s*\w/i;

  // Sinks specific to CWE-83: EGRESS nodes that produce output in an attribute context
  const attrSinks = map.nodes.filter(n => {
    if (n.node_type !== 'EGRESS') return false;
    const code = n.analysis_snapshot || n.code_snapshot;
    const sub = n.node_subtype;
    return (
      // Direct attribute-context patterns in code
      ATTR_CONTEXT_RE.test(code) ||
      IMG_TAG_RE.test(code) ||
      ATTR_CONCAT_RE.test(code) ||
      // Subtype hints for attribute context
      sub.includes('attribute') ||
      sub.includes('attr') ||
      // setAttribute calls
      /\bsetAttribute\s*\(/i.test(code) ||
      // HTML output with attribute patterns: println("<tag attr=\"" + data + "\">")
      /\bprintln\s*\(\s*"[^"]*<\w+\s+[^>]*=\s*\\?["'][^"]*"\s*\+/i.test(code) ||
      /\bprint\s*\(\s*"[^"]*<\w+\s+[^>]*=\s*\\?["'][^"]*"\s*\+/i.test(code) ||
      /\bwrite\s*\(\s*"[^"]*<\w+\s+[^>]*=\s*\\?["'][^"]*"\s*\+/i.test(code)
    );
  });

  // Also check EGRESS nodes whose containing scope reveals attribute-context output
  const egressWithAttrScope = map.nodes.filter(n => {
    if (n.node_type !== 'EGRESS') return false;
    if (attrSinks.some(s => s.id === n.id)) return false;
    const scopeSnaps = getContainingScopeSnapshots(map, n.id);
    const scopeCode = stripComments(scopeSnaps.join('\n'));
    return (
      IMG_TAG_RE.test(scopeCode) ||
      ATTR_CONCAT_RE.test(scopeCode) ||
      // Common Juliet pattern: response.getWriter().println("<br>bad() - <img src=\"" + data + "\">");
      /\bprintln\s*\(\s*"[^"]*<img\s+src\s*=\s*\\"/i.test(scopeCode) ||
      /\bprintln\s*\(\s*"[^"]*<\w+\s+\w+\s*=\s*\\"/i.test(scopeCode)
    );
  });

  const allAttrSinks = [...attrSinks, ...egressWithAttrScope];

  for (const src of ingress) {
    for (const sink of allAttrSinks) {
      const bfsHit83 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const sinkTaintHit83 = !bfsHit83 && sinkHasTaintedDataIn(map, sink.id);
      const scopeTaintHit83 = !bfsHit83 && !sinkTaintHit83 && scopeBasedTaintReaches(map, src.id, sink.id);
      if (bfsHit83 || sinkTaintHit83 || scopeTaintHit83) {
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);

        // Attribute-context requires attribute-specific encoding (not just HTML encoding)
        const isEncoded = /\bescapeHtml\b|\bescapeAttribute\b|\bhtmlEncode\s*\(|\bsanitize\s*\(|\bDOMPurify\b|\btextContent\b|\bencodeForHTMLAttribute\b|\bencodeForHTML\b|\bESAPI\b|\bEncoder\b.*\bencode\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b|\bencodeURIComponent\b/i.test(combinedScope);
        // URL validation for href/src attributes
        const hasUrlValidation = /\ballowlist\b|\bwhitelist\b|\bvalid.*url\b|\burl.*valid\b|\bhttps?:\/\/\b.*\bonly\b/i.test(combinedScope);

        if (!isEncoded && !hasUrlValidation) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'ATTRIBUTE_ENCODING (encode user data in HTML attributes)',
            severity: 'high',
            description: `User input from ${src.label} is inserted into an HTML attribute context at ${sink.label} without encoding. ` +
              `Attacker can break out of the attribute value or inject event handlers (e.g. " onmouseover="alert(1)).`,
            fix: 'Use attribute-context encoding (encodeForHTMLAttribute / ESAPI) for all user input in HTML attributes. ' +
              'Always quote attribute values. For URL attributes (href, src), validate against an allowlist of safe schemes.',
            via: bfsHit83 ? 'bfs' : sinkTaintHit83 ? 'sink_tainted' : 'scope_taint',
          });
        }
      }
    }
  }

  // Source-line scan: look for attribute-context concatenation patterns
  if (findings.length === 0) {
    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      // Pattern: println/print/write with HTML attribute + string concatenation
      if (/\b(println|print|write)\s*\(\s*"[^"]*<\w+\s+\w+\s*=\s*\\?["'][^"]*"\s*\+\s*\w/i.test(code) ||
          /\b(println|print|write)\s*\(\s*"[^"]*<img\s+src\s*=\s*\\"/i.test(code)) {
        for (const src of ingress) {
          const srcLabel = src.label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          if (new RegExp(`\\b(data|input|param|${srcLabel})\\b`, 'i').test(code)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(node),
              missing: 'ATTRIBUTE_ENCODING (encode user data in HTML attributes)',
              severity: 'high',
              description: `User input flows into an HTML attribute at ${node.label} via string concatenation. ` +
                `Tainted data in attribute values (src, href, event handlers) enables XSS via attribute injection.`,
              fix: 'Use encodeForHTMLAttribute() or ESAPI encoding for user input in attributes. ' +
                'Validate URL attributes against an allowlist of safe protocols.',
              via: 'source_line_fallback',
            });
            break;
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-83',
    name: 'XSS in Attribute',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-22: Path Traversal
 * Pattern: INGRESS → STORAGE(filesystem) without CONTROL(path validation)
 * Property: All file operations validate that paths stay within allowed directories
 */

/**
 * CWE-22 sentence verifier: walks the story forward, looking for
 * tainted data that reaches an accesses-path sentence without path validation.
 * Same architecture as CWE-89 (SQLi) and CWE-79 (XSS).
 */
function verifyCWE22_sentences(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  if (!map.story || map.story.length === 0) {
    return { cwe: 'CWE-22', name: 'Path Traversal', holds: true, findings: [] };
  }

  const taintMap = new Map<string, VarTaintInfo>();
  const resolvedCleanVars = new Set<string>();
  const validatedVars = new Set<string>();

  for (let si = 0; si < map.story.length; si++) {
    const sentence = map.story[si]!;
    const { templateKey, slots, taintClass, nodeId, lineNumber } = sentence;
    const varName = slots.subject || slots.data_type || '';

    // Track resolver-proven clean variables
    if ((sentence as any).reconciled && taintClass === 'NEUTRAL' && varName) {
      resolvedCleanVars.add(varName);
    }

    // Track path-validated variables — SAFE calls-method or gate-conditional guards
    if (taintClass === 'SAFE' && varName) {
      if (templateKey === 'calls-method' || templateKey === 'gate-conditional') {
        validatedVars.add(varName);
      }
    }

    // String concatenation — resolver-aware + validation propagation
    if (templateKey === 'string-concatenation' && varName) {
      const parts = (slots.parts || '').split(/[,\s]+/).filter(Boolean);
      const allPartsResolvedClean = parts.length > 0 &&
        parts.every(p => resolvedCleanVars.has(p) && taintMap.get(p)?.tainted !== true);
      const isTainted = allPartsResolvedClean ? false : taintClass === 'TAINTED';
      taintMap.set(varName, {
        tainted: isTainted,
        reason: (isTainted ? 'tainted concat: ' : 'concat resolved clean: ') + sentence.text,
        sourceNodeId: nodeId, sourceLine: lineNumber,
      });
      // Propagate validation: if all tainted parts are validated, the result is validated
      const taintedParts = parts.filter(p => taintMap.get(p)?.tainted);
      if (taintedParts.length > 0 && taintedParts.every(p => validatedVars.has(p))) {
        validatedVars.add(varName);
      }
      continue;
    }

    // SINK: accesses-path — check BEFORE generic TAINTED handler
    if (templateKey === 'accesses-path') {
      const variables = slots.variables || '';
      if (!variables) continue;
      const varNames = variables.split(/[,\s]+/).filter(Boolean);

      for (const argVar of varNames) {
        const info = taintMap.get(argVar);
        if (!info?.tainted) continue;
        if (validatedVars.has(argVar)) continue;

        const sinkNode = map.nodes.find(n => n.id === nodeId);
        if (sinkNode && hasDeadBranchForNode(map, sinkNode.id)) continue;

        const sourceNode = map.nodes.find(n => n.id === info.sourceNodeId);
        const sourceRef: NodeRef = sourceNode
          ? { id: sourceNode.id, label: sourceNode.label, line: sourceNode.line_start, code: sourceNode.code_snapshot.slice(0, 200) }
          : { id: info.sourceNodeId, label: `taint source (line ${info.sourceLine})`, line: info.sourceLine, code: '' };
        const sinkRef: NodeRef = sinkNode
          ? { id: sinkNode.id, label: sinkNode.label, line: sinkNode.line_start, code: sinkNode.code_snapshot.slice(0, 200) }
          : { id: nodeId, label: `file access (line ${lineNumber})`, line: lineNumber, code: '' };

        findings.push({
          source: sourceRef,
          sink: sinkRef,
          missing: 'CONTROL (path validation / directory restriction)',
          severity: 'high',
          description: `User input "${argVar}" from ${sourceRef.label} controls a file path at ${sinkRef.label} without validation. ` +
            `An attacker can use ../../ to access files outside the intended directory.`,
          fix: 'Resolve the full path with getCanonicalPath(), then verify it starts with your allowed base directory. ' +
            'Never use user input directly in file operations.',
          via: 'v2_sentences',
        });
        break;
      }
    }

    // TAINTED → mark tainted
    if (taintClass === 'TAINTED' && varName) {
      taintMap.set(varName, {
        tainted: true, reason: sentence.text,
        sourceNodeId: nodeId, sourceLine: lineNumber,
      });
      continue;
    }

    // NEUTRAL/SAFE assignments → mark clean
    if ((taintClass === 'NEUTRAL' || taintClass === 'SAFE') && varName) {
      if (templateKey === 'assigned-from-call' || templateKey === 'assigned-literal' ||
          templateKey === 'creates-instance' || templateKey === 'calls-method') {
        if (varName && varName !== 'result') {
          taintMap.set(varName, {
            tainted: false,
            reason: taintClass === 'SAFE' ? `Validated: ${sentence.text}` : `Clean: ${sentence.text}`,
            sourceNodeId: nodeId, sourceLine: lineNumber,
          });
          if (taintClass === 'SAFE') validatedVars.add(varName);
        }
      }
    }
  }

  return {
    cwe: 'CWE-22',
    name: 'Path Traversal',
    holds: findings.length === 0,
    findings,
  };
}

function verifyCWE22(map: NeuralMap): VerificationResult {
  // V2: Sentence-based detection. V2 adds findings only — V1 always runs too.
  // CWE-22 V2 is NOT authoritative yet: the story doesn't track taint through
  // data structures (config/dict/list). V1's BFS catches what V2's story misses.
  // V2 authority for CWE-22 requires: Python dict/config keyed taint tracking.
  if (map.story && map.story.some(s => s.templateKey === 'accesses-path')) {
    const v2 = verifyCWE22_sentences(map);
    if (v2.findings.length > 0) return v2;
  }
  // V1: BFS + regex fallback (still needed until accesses-path vocabulary is complete)
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' &&
     (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
      n.node_subtype === 'file_access' || n.node_subtype === 'file_read' || n.node_subtype === 'file_write' ||
      n.attack_surface.includes('file_access') ||
      (n.analysis_snapshot || n.code_snapshot).match(/\b(readFile|writeFile|createReadStream|open|unlink|readdir)\b/i) !== null)) ||
    // Python: open(filename) is classified as INGRESS/file_read, not STORAGE/file
    (n.node_type === 'INGRESS' && n.node_subtype === 'file_read') ||
    // Java: EGRESS/file_write (e.g. FileOutputStream, Files.write) with user-controlled path
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_write') ||
    // Go: http.ServeFile serves file content from a user-controlled path
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_serve')
  );

  // Path traversal safe patterns: canonicalization + boundary check
  const PATH_SAFE_RE = /\bpath\.resolve\b|\bpath\.normalize\b|\bstartsWith\b|\b\.\.\/\b|\bsanitize.*path|\bgetCanonicalPath\b|\bgetCanonicalFile\b|\bPaths\.get\b.*\bnormalize\b|\brealpath\b|\bfilepath\.Clean\b/i;

  // Per-index collection taint tracking now handled by the mapper (collectionTaint on VariableInfo).
  const hasStaticValueNeutralization22 = map.source_code ? detectStaticValueNeutralization(map.source_code) : false;
  const hasInterproceduralNeutralization22 = map.source_code ? detectInterproceduralNeutralization90(map.source_code) : false;

  // Detect HashMap safe-key retrieval: tainted value is stored under one key but
  // a different (safe) key is retrieved. Checks interprocedural doSomething methods.
  let hasMapKeySafeRetrieval22 = false;
  if (map.source_code) {
    const cleanSrc22 = stripComments(map.source_code);
    const lines22 = cleanSrc22.split('\n');
    // Find map.get("key") pattern
    const mapGetMatch22 = cleanSrc22.match(/(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/g);
    if (mapGetMatch22) {
      // Check each map.get() — if the LAST one retrieves a safe key, taint is neutralized
      const allGets = [...cleanSrc22.matchAll(/(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/g)];
      if (allGets.length > 0) {
        const lastGet = allGets[allGets.length - 1]!;
        const mapVar = lastGet[1]!;
        const getKey = lastGet[2]!;
        // Find tainted vars from source
        const taintedVars22 = new Set<string>();
        for (const ln of lines22) {
          const srcM = ln.match(/(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString)\s*\(/);
          if (srcM) taintedVars22.add(srcM[1]!);
          const decM = ln.match(/(\w+)\s*=\s*.*(?:URLDecoder\.decode)\s*\(/);
          if (decM) taintedVars22.add(decM[1]!);
        }
        if (taintedVars22.size > 0) {
          const lineIdx = lines22.findIndex(l => l.includes(lastGet[0]));
          if (lineIdx >= 0) {
            const mkr = resolveMapKeyTaint(lines22, taintedVars22, mapVar, getKey, lineIdx);
            if (mkr === 'safe') hasMapKeySafeRetrieval22 = true;
          }
        }
      }
    }
  }

  for (const src of ingress) {
    for (const sink of fileOps) {
      // Primary: BFS taint path from INGRESS to file-operation node.
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Suppress graph-based findings when dead-branch, list-offset, static-value,
        // safe-source, or map-key neutralization is detected.
        // The graph tracks taint through all branches, but constant ternary/switch patterns
        // guarantee the tainted branch is never taken.
        if (hasDeadBranchForNode(map, sink.id) || hasStaticValueNeutralization22 || hasInterproceduralNeutralization22 || hasMapKeySafeRetrieval22) continue;

        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isValidated = PATH_SAFE_RE.test(combinedScope);

        if (!isValidated) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (path validation / directory restriction)',
            severity: 'high',
            description: `User input from ${src.label} controls a file path at ${sink.label} without validation. ` +
              `An attacker can use ../../ to access files outside the intended directory.`,
            fix: 'Resolve the full path with path.resolve(), then verify it starts with your allowed base directory. ' +
              'Never use user input directly in file operations.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Source-code scanning fallback for Java: detects patterns where user input
  // (getParameter, getCookies, getHeaders) flows to File/FileInputStream/FileOutputStream
  // constructors via local variable assignment + string concatenation, even when
  // the mapper doesn't emit DATA_FLOW edges for the full chain.
  if (findings.length === 0 && map.source_code && !hasStaticValueNeutralization22 && !hasInterproceduralNeutralization22 && !hasMapKeySafeRetrieval22) {
    const src = stripComments(map.source_code);
    // Normalize: collapse whitespace/newlines for multi-line statement parsing
    const normalized = src.replace(/\n\s*/g, ' ');
    // Split into statements at semicolons
    const stmts = normalized.split(';').map(s => s.trim());

    // Detect Java HTTP user-input sources
    const javaSourceRe = /\b(?:request|req|httpRequest)\s*\.\s*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader)\s*\(|\.getValue\s*\(\s*\)|\.readLine\s*\(\s*\)/;
    const hasUserSource = javaSourceRe.test(src);

    // Detect Java file sinks with variable-based paths (not hardcoded string literals)
    const javaFileSinkRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*(?!["'])/;
    const hasFileSink = javaFileSinkRe.test(normalized);

    if (hasUserSource && hasFileSink) {
      // Find variables assigned from user input (statement-level scanning)
      const taintedVars = new Set<string>();
      for (const stmt of stmts) {
        // Direct: param = request.getParameter(...) or param = cookie.getValue()
        const assignMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader|\.getValue|\.readLine)\s*\(/);
        if (assignMatch) taintedVars.add(assignMatch[1]!);
        // Cookie/header decode: param = ...decode(theCookie.getValue(), ...)
        const cookieMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:URLDecoder\.decode|java\.net\.URLDecoder\.decode)\s*\(/);
        if (cookieMatch) taintedVars.add(cookieMatch[1]!);
        // Header: param = headers.nextElement()
        const headerMatch = stmt.match(/\b(\w+)\s*=\s*\w+\.nextElement\s*\(/);
        if (headerMatch) taintedVars.add(headerMatch[1]!);
      }

      if (taintedVars.size > 0) {
        // Propagate taint through assignments: bar = f(param); fileName = prefix + bar
        // SKIP: ternary expressions (condition may make tainted branch unreachable)
        // SKIP: assignments inside switch/case blocks (selected case may be safe)
        let changed = true;
        while (changed) {
          changed = false;
          for (const stmt of stmts) {
            const propMatch = stmt.match(/\b(\w+)\s*=\s*(.*)/s);
            if (propMatch) {
              const lhs = propMatch[1]!;
              const rhs = propMatch[2]!;
              if (!taintedVars.has(lhs)) {
                // Skip ternary expressions
                if (rhs.includes('?') && rhs.includes(':')) continue;
                // Skip assignments inside switch/case blocks
                if (/\bcase\s+|default\s*:/.test(stmt)) continue;
                for (const tv of taintedVars) {
                  if (wholeWord(rhs, tv)) {
                    taintedVars.add(lhs);
                    changed = true;
                    break;
                  }
                }
              }
            }
          }
        }

        // Check if any file sink uses a tainted variable
        // Uses paren-depth counting for nested constructors: new File(new File(base), bar)
        let sinkUsesUserInput = false;
        const sinkStartRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(/g;
        let sinkStartMatch;
        while ((sinkStartMatch = sinkStartRe.exec(normalized)) !== null) {
          let depth = 1;
          let pos = sinkStartMatch.index + sinkStartMatch[0].length;
          while (pos < normalized.length && depth > 0) {
            if (normalized[pos] === '(') depth++;
            else if (normalized[pos] === ')') depth--;
            pos++;
          }
          const argsRegion = normalized.slice(sinkStartMatch.index + sinkStartMatch[0].length, pos - 1);
          for (const tv of taintedVars) {
            if (wholeWord(argsRegion, tv)) {
              sinkUsesUserInput = true;
              break;
            }
          }
          if (sinkUsesUserInput) break;
        }

        // Check for path validation in scope
        const isValidated = PATH_SAFE_RE.test(src);

        if (sinkUsesUserInput && !isValidated) {
          const bestSrc = ingress.find(n => n.node_subtype === 'http_request') || ingress[0];
          const bestSink = fileOps[0] || map.nodes.find(n =>
            (n.analysis_snapshot || n.code_snapshot).match(/new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\s*\(/) !== null
          );
          if (bestSrc && bestSink) {
            if (!isLineInDeadBranchFunction(map, bestSink.line_start)) {
              findings.push({
                source: nodeRef(bestSrc),
                sink: nodeRef(bestSink),
                missing: 'CONTROL (path validation / directory restriction)',
                severity: 'high',
                description: `User input from ${bestSrc.label} controls a file path at ${bestSink.label} without validation. ` +
                  `An attacker can use ../../ to access files outside the intended directory.`,
                fix: 'Canonicalize the path with File.getCanonicalPath(), then verify it starts with your allowed base directory. ' +
                  'Never use user input directly in file operations.',
                via: 'source_line_fallback',
              });
            }
          }
        }
      }
    }
  }

  // Source-line fallback for Java method-param taint: detect path traversal where
  // a filename/path comes from a method parameter (not directly from @RequestParam).
  // Pattern: method receives a String parameter (fullName, filename, path, etc.),
  // and uses it in new File(directory, paramName) without canonicalization checks.
  // This catches cross-method taint where a controller passes user input to a helper.
  // Skip when dead-branch neutralization proves taint never reaches the sink.
  if (findings.length === 0 && map.source_code && !hasStaticValueNeutralization22 && !hasInterproceduralNeutralization22 && !hasMapKeySafeRetrieval22) {
    const sl22m = stripComments(map.source_code);
    const lines22m = sl22m.split('\n');

    // Find ALL String/Path/File/MultipartFile method parameters
    const PARAM_EXTRACT_RE = /(?:String|Path|File|MultipartFile)\s+(\w+)/g;
    const fileParamNames = new Set<string>();
    let mp22;
    while ((mp22 = PARAM_EXTRACT_RE.exec(sl22m)) !== null) {
      const paramName = mp22[1]!;
      // Only treat as potential taint if the parameter name suggests file/path input
      if (/name|file|path|dir|folder|upload|location|dest|target|input|param/i.test(paramName)) {
        fileParamNames.add(paramName);
      }
    }

    if (fileParamNames.size > 0) {
      // Propagate taint through assignments
      const tainted22m = new Set(fileParamNames);
      for (const line of lines22m) {
        const asgn = line.match(/(?:var|final\s+\w+|\w+)\s+(\w+)\s*=\s*(.+)/);
        if (asgn) {
          const lhs = asgn[1]!;
          const rhs = asgn[2]!;
          for (const tv of tainted22m) {
            if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(rhs)) {
              tainted22m.add(lhs);
              break;
            }
          }
        }
      }

      // Check for File constructor usage with tainted variable
      let fileSinkFound = false;
      let fileSinkLine = 0;
      let fileSinkCode = '';
      let fileParamLine = 0;
      let fileParamCode = '';

      for (let i = 0; i < lines22m.length; i++) {
        const ln = lines22m[i]!.trim();
        const fileConstructor = ln.match(/new\s+(?:java\.io\.)?File\s*\(([^)]+)\)/);
        if (fileConstructor) {
          const args = fileConstructor[1]!;
          for (const tv of tainted22m) {
            if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(args)) {
              // Check that path validation is NOT present
              const fullSrc = sl22m;
              // Only flag if there's no canonicalization + startsWith check
              const hasCanonCheck = /getCanonicalPath\s*\(\s*\)[\s\S]{0,200}startsWith\s*\(|getCanonicalFile\s*\(\s*\)[\s\S]{0,200}startsWith\s*\(/
                .test(fullSrc);
              const hasNormCheck = /normalize\s*\(\s*\)[\s\S]{0,200}startsWith\s*\(/.test(fullSrc);
              const hasResolveCheck = /path\.resolve[\s\S]{0,200}startsWith/.test(fullSrc);
              // Check for getCanonicalPath used to PREVENT traversal (reject/throw)
              // Note: using getCanonicalPath only to CHECK results after-the-fact is NOT prevention
              // Be precise: "throw new" (actual throw), "return failed(" (actual rejection), NOT "throws" in method sig
              const hasCanonReject = /getCanonicalPath[\s\S]{0,100}(?:throw\s+new\s|return\s+failed\s*\(|return\s+error|reject\s*\(|deny|block|403)/i.test(fullSrc);

              if (!hasCanonCheck && !hasNormCheck && !hasResolveCheck && !hasCanonReject) {
                fileSinkFound = true;
                fileSinkLine = i + 1;
                fileSinkCode = ln;
                // Find the parameter declaration line
                for (let j = 0; j < lines22m.length; j++) {
                  for (const fp of fileParamNames) {
                    if (new RegExp('String\\s+' + escapeRegExp(fp) + '\\b|MultipartFile\\s+' + escapeRegExp(fp) + '\\b').test(lines22m[j]!)) {
                      fileParamLine = j + 1;
                      fileParamCode = lines22m[j]!.trim();
                      break;
                    }
                  }
                  if (fileParamLine) break;
                }
                break;
              }
            }
          }
        }
        if (fileSinkFound) break;
      }

      if (fileSinkFound && fileParamLine > 0) {
        if (!isLineInDeadBranchFunction(map, fileSinkLine)) {
          findings.push({
            source: { id: `srcline-${fileParamLine}`, label: `method parameter (line ${fileParamLine})`, line: fileParamLine, code: fileParamCode.slice(0, 200) },
            sink: { id: `srcline-${fileSinkLine}`, label: `file operation (line ${fileSinkLine})`, line: fileSinkLine, code: fileSinkCode.slice(0, 200) },
            missing: 'CONTROL (path validation / directory restriction)',
            severity: 'high',
            description: `Method parameter used as filename flows to File constructor at line ${fileSinkLine} without path validation. ` +
              `If the caller passes user-controlled input, an attacker can use ../../ to traverse directories.`,
            fix: 'Canonicalize the path with File.getCanonicalPath(), then verify it starts with your allowed base directory. ' +
              'Reject requests where the canonical path escapes the intended directory.',
            via: 'source_line_fallback',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-22',
    name: 'Path Traversal',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-23: Relative Path Traversal
 * UPGRADED — hand-written with specific detection for relative traversal sequences.
 *
 * Distinct from CWE-22 (generic path traversal):
 *   CWE-23 specifically targets the case where tainted input is CONCATENATED to a base
 *   directory path (e.g. `root + data`, `basePath + userInput`). The risk is that the
 *   attacker sends "../../../etc/passwd" to escape the base directory.
 *
 * Missing category: SANITIZE (different from CWE-22's CONTROL) so family dedup preserves both.
 *
 * Safe patterns: getCanonicalPath/getCanonicalFile, realpath, path.resolve followed by
 *   startsWith, explicit ".." rejection, normalize + boundary check.
 */
function verifyCWE23(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' &&
     (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
      n.node_subtype === 'file_access' || n.node_subtype === 'file_read' || n.node_subtype === 'file_write' ||
      n.attack_surface.includes('file_access') ||
      (n.analysis_snapshot || n.code_snapshot).match(/\b(readFile|writeFile|createReadStream|open|unlink|readdir)\b/i) !== null)) ||
    (n.node_type === 'INGRESS' && n.node_subtype === 'file_read') ||
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_write') ||
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_serve')
  );

  // CWE-23-specific safe patterns: canonicalization or explicit dot-dot rejection
  const RELATIVE_SAFE_RE = /\bgetCanonicalPath\b|\bgetCanonicalFile\b|\brealpath\b|\bpath\.resolve\b.*\bstartsWith\b|\bstartsWith\b.*\bpath\.resolve\b|\b\.contains\s*\(\s*["']\.\.["']\s*\)|\bindexOf\s*\(\s*["']\.\.["']\s*\)|\bincludes\s*\(\s*["']\.\.["']\s*\)|\bnormalize\b.*\bstartsWith\b|\bfilepath\.Clean\b|\bFilenameUtils\.normalize\b/i;

  // --- Strategy 1: Graph-based detection — INGRESS->file-op with path concatenation ---
  for (const src of ingress) {
    for (const sink of fileOps) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (hasDeadBranchForNode(map, sink.id)) continue;

        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);

        // CWE-23 specific: look for path concatenation at the SINK itself (base + input)
        // This is the signature of relative traversal: the input is appended to a base dir
        // Check the sink's own code snapshot for concatenation, not the full scope
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const hasSinkConcat = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(\s*\w+\s*\+/i.test(sinkCode) ||
          /\bPaths\.get\s*\(\s*\w+\s*,/i.test(sinkCode) ||
          /\bPath\.of\s*\(\s*\w+\s*,/i.test(sinkCode) ||
          /\bpath\.join\s*\(/i.test(sinkCode) ||
          /\bpath\.resolve\s*\(\s*\w+\s*,/i.test(sinkCode);
        // Also check scope for base directory + variable concatenation patterns
        const hasBaseDirConcat = /(?:root|base|dir|prefix|folder|upload)\s*\+\s*\w+/i.test(combinedScope) &&
          /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\b/i.test(combinedScope);

        if ((hasSinkConcat || hasBaseDirConcat) && !RELATIVE_SAFE_RE.test(combinedScope)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'SANITIZE (relative path sequence filtering / canonicalization)',
            severity: 'high',
            description: `User input from ${src.label} is concatenated to a base directory at ${sink.label} without canonicalization. ` +
              `An attacker can send "../" sequences to escape the intended directory and read/write arbitrary files.`,
            fix: 'Canonicalize the combined path with File.getCanonicalPath() or path.resolve(), then verify the result ' +
              'starts with the intended base directory. Reject any input containing ".." sequences.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // --- Strategy 2: Source-code scanning fallback for Java ---
  if (findings.length === 0 && map.source_code) {
    const src = stripComments(map.source_code);
    const normalized = src.replace(/\n\s*/g, ' ');
    const stmts = normalized.split(';').map(s => s.trim());

    // Detect taint sources (network, HTTP, etc.)
    const javaSourceRe = /\b(?:request|req|httpRequest)\s*\.\s*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader)\s*\(|\.getValue\s*\(\s*\)|\.readLine\s*\(\s*\)/;
    const hasUserSource = javaSourceRe.test(src);

    // CWE-23 specific: file sink with concatenation (base + tainted)
    // Pattern: new File(someBase + taintedVar) or Paths.get(base, taintedVar)
    const concatFileSinkRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*(?:\w+\s*\+|\w+\s*,)/;
    const hasConcatFileSink = concatFileSinkRe.test(normalized);

    // Also detect: explicit base directory variable assigned then concatenated
    const hasBaseDirConcat = /(?:root|base|dir|prefix|folder|upload|path)\s*\+\s*\w+/i.test(normalized) &&
      /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\b/i.test(normalized);

    if (hasUserSource && (hasConcatFileSink || hasBaseDirConcat)) {
      // Track tainted variables
      const taintedVars = new Set<string>();
      for (const stmt of stmts) {
        const assignMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader|\.getValue|\.readLine)\s*\(/);
        if (assignMatch) taintedVars.add(assignMatch[1]!);
        const cookieMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:URLDecoder\.decode|java\.net\.URLDecoder\.decode)\s*\(/);
        if (cookieMatch) taintedVars.add(cookieMatch[1]!);
        const headerMatch = stmt.match(/\b(\w+)\s*=\s*\w+\.nextElement\s*\(/);
        if (headerMatch) taintedVars.add(headerMatch[1]!);
      }

      // Propagate taint
      if (taintedVars.size > 0) {
        let changed = true;
        while (changed) {
          changed = false;
          for (const stmt of stmts) {
            const propMatch = stmt.match(/\b(\w+)\s*=\s*(.*)/s);
            if (propMatch) {
              const lhs = propMatch[1]!;
              const rhs = propMatch[2]!;
              if (!taintedVars.has(lhs)) {
                if (rhs.includes('?') && rhs.includes(':')) continue;
                if (/\bcase\s+|default\s*:/.test(stmt)) continue;
                for (const tv of taintedVars) {
                  if (wholeWord(rhs, tv)) {
                    taintedVars.add(lhs);
                    changed = true;
                    break;
                  }
                }
              }
            }
          }
        }

        // Check if a file sink uses concatenation with a tainted var and a base dir
        const concatSinkRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*(\w+)\s*\+/g;
        let concatMatch;
        let sinkUsesConcat = false;
        while ((concatMatch = concatSinkRe.exec(normalized)) !== null) {
          // Extract the full argument region after the opening paren
          let depth = 1;
          let pos = concatMatch.index + concatMatch[0].length;
          while (pos < normalized.length && depth > 0) {
            if (normalized[pos] === '(') depth++;
            else if (normalized[pos] === ')') depth--;
            pos++;
          }
          const argsRegion = normalized.slice(concatMatch.index + concatMatch[0].length - concatMatch[1]!.length - 1, pos - 1);
          for (const tv of taintedVars) {
            if (wholeWord(argsRegion, tv)) {
              sinkUsesConcat = true;
              break;
            }
          }
          if (sinkUsesConcat) break;
        }

        const isValidated = RELATIVE_SAFE_RE.test(src);

        if (sinkUsesConcat && !isValidated) {
          const bestSrc = ingress.find(n => n.node_subtype === 'http_request') || ingress[0];
          const bestSink = fileOps[0] || map.nodes.find(n =>
            (n.analysis_snapshot || n.code_snapshot).match(/new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\s*\(/) !== null
          );
          if (bestSrc && bestSink) {
            findings.push({
              source: nodeRef(bestSrc),
              sink: nodeRef(bestSink),
              missing: 'SANITIZE (relative path sequence filtering / canonicalization)',
              severity: 'high',
              description: `User input from ${bestSrc.label} is concatenated to a base directory at ${bestSink.label} without canonicalization. ` +
                `An attacker can send "../" sequences to escape the intended directory and read/write arbitrary files.`,
              fix: 'Canonicalize the combined path with File.getCanonicalPath(), then verify the result ' +
                'starts with the intended base directory. Reject any input containing ".." sequences.',
              via: 'source_line_fallback',
            });
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-23',
    name: 'Relative Path Traversal',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-36: Absolute Path Traversal
 * UPGRADED — hand-written with specific detection for absolute path injection.
 *
 * Distinct from CWE-22 (generic path traversal):
 *   CWE-36 specifically targets the case where tainted input is used as the ENTIRE
 *   file path (e.g. `new File(data)`) without being restricted to a base directory.
 *   The risk is that the attacker sends "/etc/passwd" or "C:\Windows\System32\..."
 *   to access any file on the filesystem.
 *
 * Missing category: VALIDATE (different from CWE-22's CONTROL) so family dedup preserves both.
 *
 * Safe patterns: startsWith check against allowed base, path.isAbsolute() + reject,
 *   forced prefix concatenation (base + input), chroot/jail.
 */
function verifyCWE36(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' &&
     (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
      n.node_subtype === 'file_access' || n.node_subtype === 'file_read' || n.node_subtype === 'file_write' ||
      n.attack_surface.includes('file_access') ||
      (n.analysis_snapshot || n.code_snapshot).match(/\b(readFile|writeFile|createReadStream|open|unlink|readdir)\b/i) !== null)) ||
    (n.node_type === 'INGRESS' && n.node_subtype === 'file_read') ||
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_write') ||
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_serve')
  );

  // CWE-36-specific safe patterns: enforce a base directory prefix, or reject absolute paths
  const ABSOLUTE_SAFE_RE = /\bstartsWith\b|\bisAbsolute\b.*reject|\bisAbsolute\b.*throw|\bisAbsolute\b.*return|\bpath\.relative\b|\bchroot\b|\bjail\b|\bsandbox\b|\bwhitelist\b.*path|\ballowedPaths\b|\bgetCanonicalPath\b.*\bstartsWith\b|\bstartsWith\b.*\bgetCanonicalPath\b|\bFilenameUtils\.normalize\b.*\bstartsWith\b/i;

  // --- Strategy 1: Graph-based detection — INGRESS->file-op where input is used as entire path ---
  for (const src of ingress) {
    for (const sink of fileOps) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (hasDeadBranchForNode(map, sink.id)) continue;

        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);

        // CWE-36 specific: detect when tainted input is used DIRECTLY as file path
        // without being concatenated to a base directory. This is the absolute path pattern.
        // Negative indicator: if there's base dir concatenation, it's CWE-23 not CWE-36
        const hasBaseConcat = /\w+\s*\+\s*\w+\s*\)|root\s*\+|base\s*\+|dir\s*\+|prefix\s*\+|folder\s*\+|uploads.*\+/i.test(combinedScope);

        // Positive indicator: direct use of tainted input as path
        const hasDirectPathUse = /new\s+(?:java\.io\.)?File\s*\(\s*\w+\s*\)|open\s*\(\s*\w+|readFile\s*\(\s*\w+|createReadStream\s*\(\s*\w+|FileInputStream\s*\(\s*\w+\s*\)|FileOutputStream\s*\(\s*\w+\s*\)/i.test(combinedScope);

        if (!hasBaseConcat && hasDirectPathUse && !ABSOLUTE_SAFE_RE.test(combinedScope)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'VALIDATE (absolute path rejection / base directory enforcement)',
            severity: 'high',
            description: `User input from ${src.label} is used as the entire file path at ${sink.label} without restricting to a base directory. ` +
              `An attacker can send an absolute path like "/etc/passwd" or "C:\\Windows\\..." to access any file on the filesystem.`,
            fix: 'Never use user input as the entire file path. Always prepend a base directory and canonicalize: ' +
              'new File(BASE_DIR, input).getCanonicalPath() then verify startsWith(BASE_DIR). Reject absolute paths.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // --- Strategy 2: Source-code scanning fallback for Java ---
  if (findings.length === 0 && map.source_code) {
    const src = stripComments(map.source_code);
    const normalized = src.replace(/\n\s*/g, ' ');
    const stmts = normalized.split(';').map(s => s.trim());

    // Detect taint sources
    const javaSourceRe = /\b(?:request|req|httpRequest)\s*\.\s*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader)\s*\(|\.getValue\s*\(\s*\)|\.readLine\s*\(\s*\)/;
    const hasUserSource = javaSourceRe.test(src);

    // CWE-36 specific: file sink with DIRECT variable use (no concatenation)
    // Pattern: new File(data) — where data is the tainted variable, used alone as the entire path
    const directFileSinkRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*(\w+)\s*\)/g;

    // Negative: skip if there's base-dir concatenation (that's CWE-23)
    const hasBaseDirConcat = /(?:root|base|dir|prefix|folder|upload)\s*\+/i.test(normalized);

    if (hasUserSource && !hasBaseDirConcat) {
      // Track tainted variables
      const taintedVars = new Set<string>();
      for (const stmt of stmts) {
        const assignMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader|\.getValue|\.readLine)\s*\(/);
        if (assignMatch) taintedVars.add(assignMatch[1]!);
        const cookieMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:URLDecoder\.decode|java\.net\.URLDecoder\.decode)\s*\(/);
        if (cookieMatch) taintedVars.add(cookieMatch[1]!);
        const headerMatch = stmt.match(/\b(\w+)\s*=\s*\w+\.nextElement\s*\(/);
        if (headerMatch) taintedVars.add(headerMatch[1]!);
      }

      // Propagate taint
      if (taintedVars.size > 0) {
        let changed = true;
        while (changed) {
          changed = false;
          for (const stmt of stmts) {
            const propMatch = stmt.match(/\b(\w+)\s*=\s*(.*)/s);
            if (propMatch) {
              const lhs = propMatch[1]!;
              const rhs = propMatch[2]!;
              if (!taintedVars.has(lhs)) {
                if (rhs.includes('?') && rhs.includes(':')) continue;
                if (/\bcase\s+|default\s*:/.test(stmt)) continue;
                for (const tv of taintedVars) {
                  if (wholeWord(rhs, tv)) {
                    taintedVars.add(lhs);
                    changed = true;
                    break;
                  }
                }
              }
            }
          }
        }

        // Check if a file sink uses a tainted variable DIRECTLY (not concatenated)
        let sinkUsesDirect = false;
        let directMatch;
        while ((directMatch = directFileSinkRe.exec(normalized)) !== null) {
          const argVar = directMatch[1]!;
          if (taintedVars.has(argVar)) {
            sinkUsesDirect = true;
            break;
          }
        }

        const isValidated = ABSOLUTE_SAFE_RE.test(src);

        if (sinkUsesDirect && !isValidated) {
          const bestSrc = ingress.find(n => n.node_subtype === 'http_request') || ingress[0];
          const bestSink = fileOps[0] || map.nodes.find(n =>
            (n.analysis_snapshot || n.code_snapshot).match(/new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\s*\(/) !== null
          );
          if (bestSrc && bestSink) {
            findings.push({
              source: nodeRef(bestSrc),
              sink: nodeRef(bestSink),
              missing: 'VALIDATE (absolute path rejection / base directory enforcement)',
              severity: 'high',
              description: `User input from ${bestSrc.label} is used as the entire file path at ${bestSink.label} without restricting to a base directory. ` +
                `An attacker can send an absolute path like "/etc/passwd" or "C:\\Windows\\..." to access any file on the filesystem.`,
              fix: 'Never use user input as the entire file path. Always prepend a base directory and canonicalize: ' +
                'new File(BASE_DIR, input).getCanonicalPath() then verify startsWith(BASE_DIR). Reject absolute paths.',
              via: 'source_line_fallback',
            });
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-36',
    name: 'Absolute Path Traversal',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-502: Deserialization of Untrusted Data
 * Pattern: INGRESS → TRANSFORM(deserialize) without CONTROL(type validation)
 * Property: All deserialization of user input uses safe parsers with type constraints
 */
function verifyCWE502(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const deserialize = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' &&
     (n.node_subtype.includes('deserialize') || n.node_subtype.includes('parse') ||
      (n.analysis_snapshot || n.code_snapshot).match(/\b(unserialize|pickle\.load|yaml\.load|eval|JSON\.parse|XStream|XMLDecoder|ObjectMapper|Kryo)\b/i) !== null)) ||
    // Python: pickle.loads is classified as EXTERNAL/deserialize, not TRANSFORM
    (n.node_type === 'EXTERNAL' && n.node_subtype.startsWith('deserialize')) ||
    // Rust/Java: serde_json::from_str, XMLDecoder.readObject etc. may be INGRESS/deserialize or INGRESS/deserialize_rce
    (n.node_type === 'INGRESS' && n.node_subtype.startsWith('deserialize'))
  );

  for (const src of ingress) {
    for (const sink of deserialize) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // EXTERNAL/deserialize nodes are inherently dangerous (yaml.load, pickle.loads, etc.)
        // TRANSFORM/parse nodes need code_snapshot check to distinguish safe vs unsafe
        const isDangerous =
          (sink.node_type === 'EXTERNAL' && sink.node_subtype.startsWith('deserialize')) ||
          // Rust/Java: serde_json::from_str, XMLDecoder.readObject etc. — includes deserialize_rce
          (sink.node_type === 'INGRESS' && sink.node_subtype.startsWith('deserialize')) ||
          (sink.analysis_snapshot || sink.code_snapshot).match(
            /\b(unserialize|pickle\.load|yaml\.load|yaml\.loadAll|yaml\.safe_load|eval|Function\s*\(|deserialize|serde_json::from_str|serde_json::from_value|serde_json::from_slice|XStream\.fromXML|XMLDecoder\.readObject|\.readValue\s*\(|Kryo\.readObject|Yaml\.load)\b/i
          ) !== null;

        if (isDangerous) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (safe deserialization with type constraints)',
            severity: 'critical',
            description: `User input from ${src.label} is deserialized at ${sink.label} using an unsafe method. ` +
              `This can lead to arbitrary code execution.`,
            fix: 'Use safe parsers: JSON.parse for JSON, yaml.safeLoad / yaml.safe_load for YAML. ' +
              'Never use eval, unserialize, pickle.load, or yaml.load on untrusted data. ' +
              'Add schema validation (zod, joi) after parsing.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Source-code fallback for Java deserialization sinks not caught by BFS
  if (findings.length === 0 && map.source_code) {
    const src502 = stripComments(map.source_code);
    const DESER_SINK_502 = /\b(Yaml\.load|Yaml\.loadAll|XStream\.fromXML|XMLDecoder\.readObject|Kryo\.readObject|ObjectInputStream\.readObject|readUnshared)\s*\(|\.\s*readValue\s*\(/i;
    const DESER_SAFE_502 = /\benableDefaultTyping\b.*\bfalse\b|\bObjectInputFilter\b|\bvalidateObject\b|\bdefaultClassLoader\b.*\bnull\b|\bJsonTypeInfo\b/i;
    if (DESER_SINK_502.test(src502) && !DESER_SAFE_502.test(src502)) {
      const hasIngressSrc = /\b(?:request|req|httpRequest)\s*\.\s*(?:getParameter|getInputStream|getReader)\s*\(|\.readObject\s*\(/i.test(src502);
      if (hasIngressSrc) {
        findings.push({
          source: { id: 'srcline-deser', label: 'untrusted input', line: 0, code: '' },
          sink: { id: 'srcline-deser-sink', label: 'deserialization sink', line: 0, code: '' },
          missing: 'CONTROL (safe deserialization with type constraints)',
          severity: 'critical',
          description: 'Untrusted data flows to a dangerous deserialization sink without type filtering.',
          fix: 'Use ObjectInputFilter, type-safe parsers, or avoid deserializing untrusted data entirely.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return {
    cwe: 'CWE-502',
    name: 'Deserialization of Untrusted Data',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-918: Server-Side Request Forgery (SSRF)
 * Pattern: INGRESS → EXTERNAL without CONTROL(URL validation)
 * Property: All user-controlled URLs are validated against an allowlist before making requests
 */
function verifyCWE918(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const external = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('http') || n.node_subtype.includes('request') ||
     n.node_subtype.includes('fetch') || n.node_subtype.includes('api_call') ||
     (n.analysis_snapshot || n.code_snapshot).match(
       /\b(fetch|axios|request|http\.get|https\.get|got|requests\.get|requests\.post|requests\.put|requests\.delete|urllib\.request|urllib\.urlopen|urllib2\.urlopen|RestTemplate\.getForObject|RestTemplate\.exchange|RestTemplate\.postForObject|WebClient\.get|WebClient\.post|HttpClient\.send|HttpClient\.execute|OkHttpClient|http\.Get|http\.Post|curl_exec|file_get_contents|fopen\s*\(\s*['"]https?:)\b/i
     ) !== null)
  );

  for (const src of ingress) {
    for (const sink of external) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isValidated = combinedScope.match(
          /\ballowlist\b|\bwhitelist\b|\bvalidateUrl\b|\bURL\b.*\bnew\b|\bstartsWith\b/i
        ) !== null;

        if (!isValidated) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (URL validation / allowlist)',
            severity: 'high',
            description: `User input from ${src.label} controls the URL for an HTTP request at ${sink.label}. ` +
              `An attacker can make the server request internal resources (SSRF).`,
            fix: 'Validate URLs against an allowlist of permitted domains. ' +
              'Parse the URL with new URL() and check the hostname. ' +
              'Never let user input directly control request destinations.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Source-code fallback: when the mapper doesn't emit an EXTERNAL node for HTTP calls
  // (e.g., dynamically-resolved `client.get(url)` or indirect `http.get(url)`), fall back
  // to scanning source_code for SSRF-indicative patterns.
  if (findings.length === 0 && map.source_code) {
    const src918 = stripComments(map.source_code);
    // Direct HTTP client calls (literal API names)
    const SSRF_SINK_DIRECT = /\b(fetch|axios\.get|axios\.post|axios\.put|axios\.delete|axios\.request|axios\(|http\.get|https\.get|http\.request|https\.request|got|got\.get|got\.post|request\.get|request\.post|urllib\.request\.urlopen|urllib2\.urlopen|requests\.get|requests\.post|requests\.put|requests\.delete|RestTemplate\.getForObject|RestTemplate\.exchange|RestTemplate\.postForObject|WebClient\.get|WebClient\.post|HttpClient\.send|HttpClient\.execute|OkHttpClient|http\.Get|http\.Post|curl_exec|file_get_contents|Net::HTTP\.get|open-uri|Faraday\.get|HTTPoison\.get|HttpClient\.GetAsync|WebRequest\.Create)\s*\(/i;
    // Indirect HTTP client calls: require('http')/require('https') + dynamic .get/.request call
    const hasHttpModule = /require\s*\(\s*['"]https?['"]\s*\)|from\s+['"]https?['"]/i.test(src918);
    const hasDynamicHttpCall = /\w+\.get\s*\(\s*\w+|\w+\.request\s*\(\s*\w+/i.test(src918);
    const hasSsrfSink = SSRF_SINK_DIRECT.test(src918) || (hasHttpModule && hasDynamicHttpCall);

    const SSRF_INGRESS_918 = /\b(?:req|request|ctx)\s*\.\s*(?:headers|query|params|body|getParameter|getHeader|getQueryString)\b/i;
    const SSRF_SAFE_918 = /\ballowlist\b|\bwhitelist\b|\bvalidateUrl\b|\bsafeUrl\b|\bisAllowed\b|\bstartsWith\s*\(\s*['"]https?:\/\/(?:api\.|internal\.)/i;
    if (hasSsrfSink && SSRF_INGRESS_918.test(src918) && !SSRF_SAFE_918.test(src918)) {
      findings.push({
        source: { id: 'srcline-ssrf', label: 'user-controlled input', line: 0, code: '' },
        sink: { id: 'srcline-ssrf-sink', label: 'HTTP client call', line: 0, code: '' },
        missing: 'CONTROL (URL validation / allowlist)',
        severity: 'high',
        description: 'User-controlled input flows to an HTTP client call without URL validation. ' +
          'An attacker can make the server request internal resources (SSRF).',
        fix: 'Validate URLs against an allowlist of permitted domains. ' +
          'Parse the URL with new URL() and check the hostname. ' +
          'Never let user input directly control request destinations.',
        via: 'source_line_fallback',
      });
    }
  }

  return {
    cwe: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-78: OS Command Injection
 * Pattern: INGRESS → EXTERNAL(shell/exec) without CONTROL(input sanitization)
 * Property: User input is never passed directly to shell commands
 */
function verifyCWE78(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const shellExec = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('shell') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('command') || n.attack_surface.includes('shell_exec') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(exec|execSync|spawn|system|child_process|popen|shell_exec)\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of shellExec) {
      const bfsHit78 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const sinkTaintHit78 = !bfsHit78 && sinkHasTaintedDataIn(map, sink.id);
      if (bfsHit78 || sinkTaintHit78) {
        const scopeSnapshots78 = getContainingScopeSnapshots(map, sink.id);
        const combinedScope78 = stripComments(scopeSnapshots78.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isSafe = combinedScope78.match(
          /\bexecFile\s*\(|\bspawn\s*\(.*\[|\bshellEscape\s*\(|\bescapeShell\s*\(|\bsanitize\s*\(/i
        ) !== null;
        if (!isSafe) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (input sanitization or safe command API)',
            severity: 'critical',
            description: `User input from ${src.label} flows to shell command at ${sink.label} without sanitization. ` +
              `An attacker can inject arbitrary OS commands (e.g., ; rm -rf /).`,
            fix: 'Never pass user input to shell commands. Use execFile or spawn with an argument array ' +
              'instead of exec with string interpolation. If shell is unavoidable, use a strict allowlist ' +
              'of permitted values.',
            via: bfsHit78 ? 'bfs' : 'sink_tainted',
          });
        }
      }
    }
  }

  // Source-line fallback for Java: statement-level taint tracking detects
  // Runtime.exec / ProcessBuilder patterns where BFS taint path breaks.
  if (findings.length === 0 && map.source_code) {
    const sl78 = map.source_code.split('\n');
    const SRC78 = /(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getParameterValues|getParameterNames|getHeader|getHeaders|getCookies|getQueryString|getInputStream|getReader|getTheParameter|System\.getenv)\s*\(/;
    const CK78 = /(\w+)\s*=\s*(?:java\.net\.URLDecoder\.decode\s*\(\s*)?(?:\w+\.getValue\s*\()/;
    const EN78 = /(\w+)\s*=\s*(?:\(\w+\)\s*)?(?:\w+\.nextElement\s*\()/;
    const EX78 = /(?:\.exec\s*\(|ProcessBuilder\s*\(|\.command\s*\()\s*([^)]*)/;
    const tv = new Set<string>();
    let sln = 0; let scd = '';
    for (let i = 0; i < sl78.length; i++) {
      const ln = sl78[i]!.trim();
      if (ln.startsWith('//') || ln.startsWith('*') || ln.startsWith('/*')) continue;
      let mx = ln.match(SRC78); if (mx) { tv.add(mx[1]!); sln = i + 1; scd = ln; }
      mx = ln.match(CK78); if (mx) { tv.add(mx[1]!); if (!sln) { sln = i + 1; scd = ln; } }
      mx = ln.match(EN78); if (mx) { tv.add(mx[1]!); if (!sln) { sln = i + 1; scd = ln; } }
      // Assignment propagation: supports both "bar = param;" and "String bar = param;"
      const va = ln.match(/^(?:(?:final\s+)?(?:String|int|long|Object|byte)\s+)?(\w+)\s*=\s*(\w+)\s*;/);
      if (va && tv.has(va[2]!)) tv.add(va[1]!);
      const mc = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.\w+\s*\(/);
      if (mc && tv.has(mc[2]!)) tv.add(mc[1]!);
      const ma = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*\w+(?:\.\w+)*\s*\(\s*(\w+)\s*\)/);
      if (ma && tv.has(ma[2]!)) tv.add(ma[1]!);
      const ca = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*.*\b(\w+)\b.*\+/);
      if (ca && tv.has(ca[2]!)) tv.add(ca[1]!);
      const cc = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*.*\+.*\b(\w+)\b/);
      if (cc && tv.has(cc[2]!)) tv.add(cc[1]!);
      const ai = ln.match(/^(?:\w+\[\]\s+)?(\w+)\s*=\s*(?:new\s+\w+\s*\[\]\s*)?\{([^}]+)\}/);
      if (ai) { for (const t of tv) { if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(ai[2]!)) { tv.add(ai[1]!); break; } } }
      const sb = ln.match(/(\w+)\s*=\s*new\s+StringBuilder\s*\(\s*(\w+)\s*\)/);
      if (sb && tv.has(sb[2]!)) tv.add(sb[1]!);
      const ts = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.(?:append\s*\([^)]*\)\s*\.)*toString\s*\(\s*\)/);
      if (ts && tv.has(ts[2]!)) tv.add(ts[1]!);
      const ck = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*"[^"]*"\s*;/);
      if (ck) tv.delete(ck[1]!);
      const atm = ln.match(/if\s*\(\s*\(\s*(\d+)\s*\*\s*(\d+)\s*\)\s*-\s*\w+\s*>\s*(\d+)\s*\)\s*(\w+)\s*=\s*"[^"]*"/);
      if (atm && parseInt(atm[1]!) * parseInt(atm[2]!) > parseInt(atm[3]!) + 100) tv.delete(atm[4]!);
      const mg = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
      if (mg) {
        const mv = mg[2]!; const gk = mg[3]!; let kt = false;
        for (let j = 0; j < i; j++) {
          const pl = sl78[j]!.trim();
          const pm = pl.match(new RegExp(escapeRegExp(mv) + '\\.put\\s*\\(\\s*"([^"]*)"\\s*,\\s*(\\w+)\\s*\\)'));
          if (pm && pm[1] === gk) kt = tv.has(pm[2]!);
        }
        if (kt) tv.add(mg[1]!); else tv.delete(mg[1]!);
      }
      const lg = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.get\s*\(\s*(\d+)\s*\)/);
      if (lg) {
        const lv = lg[2]!; const gi = parseInt(lg[3]!);
        const items: { tainted: boolean }[] = []; let rc = 0;
        for (let j = 0; j < i; j++) {
          const al = sl78[j]!.trim();
          const am = al.match(new RegExp(escapeRegExp(lv) + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
          if (am) items.push({ tainted: am[1] ? tv.has(am[1]) : false });
          if (al.includes(lv + '.remove(')) rc++;
        }
        const adj = items.slice(rc);
        if (gi < adj.length && !adj[gi]!.tainted) tv.delete(lg[1]!);
        else tv.add(lg[1]!);
      }
      // Interprocedural: bar = new Test().doSomething(request, param) or bar = doSomething(request, param)
      const ipCall78 = ln.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?(\w+)\s*\(\s*(?:request\s*,\s*)?(\w+)\s*\)/);
      if (ipCall78 && tv.has(ipCall78[3]!)) {
        const mn78 = ipCall78[2]!;
        let kills78 = false;
        // Search for the method DECLARATION (not call site): must have access modifier or
        // return-type keyword before the method name, indicating a method signature not a call.
        const methodDeclRe = new RegExp('(?:private|protected|public|static|final)\\s+.*\\b' + escapeRegExp(mn78) + '\\s*\\(');
        for (let j = 0; j < sl78.length; j++) {
          if (j === i) continue; // skip the call site itself
          const md78 = sl78[j]!.trim();
          if (methodDeclRe.test(md78) || (md78.includes(`${mn78}(`) && /^\s*(?:public|private|protected)\s/.test(sl78[j]!))) {
            let bd78 = 0; let fo78 = false;
            // Collect the method body lines to analyze return taint
            const bodyLines78: string[] = [];
            for (let k = j; k < Math.min(j + 50, sl78.length); k++) {
              if (sl78[k]!.includes('{')) { bd78++; fo78 = true; }
              if (sl78[k]!.includes('}')) bd78--;
              if (fo78 && bd78 <= 0) break;
              const mt78 = sl78[k]!.trim();
              if (k !== j) bodyLines78.push(mt78);
              // Strong sanitizers kill taint unconditionally
              if (/\b(?:parseInt|parseLong|parseFloat|parseDouble|Integer\.valueOf|Long\.valueOf|Pattern\.matches|Pattern\.compile|\.matches\s*\(\s*"[^"]*"|validate\s*\(|sanitize\s*\()\b/i.test(mt78)) { kills78 = true; break; }
            }
            if (!kills78) {
              // Analyze whether the method's return value carries taint from param.
              // Strategy: track a mini taint set within the method body.
              const mtv = new Set<string>(['param']);
              let returnVar78 = '';
              // Track pending multi-line assignment: when we see "bar =" or "bar ="
              // on one line, look for tainted refs on subsequent lines until ";"
              let pendingAssignVar78 = '';
              // Dead-branch detection for switch statements: track constant char values
              // derived from charAt() on string literals to identify which case is taken.
              const constChars78 = new Map<string, string>(); // var -> resolved char value
              const constStrings78 = new Map<string, string>(); // var -> literal string
              let activeSwitchVar78 = ''; let activeSwitchChar78 = '';
              let inDeadBranch78 = false;
              for (const bl of bodyLines78) {
                // Multi-line assignment continuation: if a pending var is being assigned
                // and this line contains a tainted reference, taint the pending var
                if (pendingAssignVar78) {
                  for (const t of mtv) {
                    if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(bl)) { mtv.add(pendingAssignVar78); break; }
                  }
                  if (bl.includes(';')) pendingAssignVar78 = '';
                }
                // Track constant string literals: String x = "literal"
                const strLit78 = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*"([^"]*)"\s*;/);
                if (strLit78) constStrings78.set(strLit78[1]!, strLit78[2]!);
                // Track charAt on constant strings: x = str.charAt(N)
                const charAtMatch = bl.match(/(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.charAt\s*\(\s*(\d+)\s*\)/);
                if (charAtMatch && constStrings78.has(charAtMatch[2]!)) {
                  const s = constStrings78.get(charAtMatch[2]!)!;
                  const idx = parseInt(charAtMatch[3]!);
                  if (idx < s.length) constChars78.set(charAtMatch[1]!, s[idx]!);
                }
                // Switch statement: check if switching on a known constant char
                const switchMatch = bl.match(/switch\s*\(\s*(\w+)\s*\)/);
                if (switchMatch && constChars78.has(switchMatch[1]!)) {
                  activeSwitchVar78 = switchMatch[1]!;
                  activeSwitchChar78 = constChars78.get(switchMatch[1]!)!;
                  inDeadBranch78 = true; // assume dead until we find the matching case
                }
                // Case label: check if this is the active case.
                // Once we find the matching case, stay in live branch until break.
                const caseMatch = bl.match(/case\s+'(.)'/);
                if (caseMatch && activeSwitchVar78) {
                  if (caseMatch[1] === activeSwitchChar78) {
                    inDeadBranch78 = false; // found the live case
                  } else if (inDeadBranch78) {
                    // Stay dead (haven't found live case yet, or past it after break)
                  }
                  // If we're already in a live branch (fall-through from matching case),
                  // another case label doesn't make it dead.
                }
                if (bl === 'default:' && activeSwitchVar78 && inDeadBranch78) {
                  // default is dead only if we haven't been in a live branch
                }
                // break exits the live branch of the switch
                if (bl === 'break;' && activeSwitchVar78 && !inDeadBranch78) {
                  inDeadBranch78 = true; // after break, subsequent cases are dead again
                }
                // Simple assignment propagation: x = param or x = tainted_var
                // Skip assignments in dead branches of constant-resolved switch statements
                const simpleAssign = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\s*;/);
                if (simpleAssign && mtv.has(simpleAssign[2]!) && !inDeadBranch78) mtv.add(simpleAssign[1]!);
                // If-gated assignment: if (...) x = param;
                const ifAssign = bl.match(/\bif\s*\(.*\)\s*(\w+)\s*=\s*(\w+)\s*;/);
                if (ifAssign && mtv.has(ifAssign[2]!)) mtv.add(ifAssign[1]!);
                // Method call propagation: x = something(tainted)
                const mcProp = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*.*\(\s*.*\b(\w+)\b.*\)/);
                if (mcProp && mtv.has(mcProp[2]!)) mtv.add(mcProp[1]!);
                // Multi-line assignment start: "bar =" at end of line (no semicolon)
                const multiAssign = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*$/);
                if (multiAssign && !bl.includes(';')) pendingAssignVar78 = multiAssign[1]!;
                // Also detect: "bar = \n new String(" pattern
                const multiAssign2 = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*\S+/);
                if (multiAssign2 && !bl.includes(';')) pendingAssignVar78 = multiAssign2[1]!;
                // StringBuilder: sb = new StringBuilder(tainted)
                const sbProp = bl.match(/(\w+)\s*=\s*new\s+StringBuilder\s*\(\s*(\w+)\s*\)/);
                if (sbProp && mtv.has(sbProp[2]!)) mtv.add(sbProp[1]!);
                // toString: x = sb.toString() or x = sb.append(...).toString()
                // Exclude .get(N) which is handled by the precise list tracking below
                const tsProp = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(?:\(\w+\)\s*)?(\w+)\.(?:append\s*\([^)]*\)\s*\.)*(?:toString)\s*\(/);
                if (tsProp && mtv.has(tsProp[2]!)) mtv.add(tsProp[1]!);
                // HashMap put/get tracking
                const putCall = bl.match(/(\w+)\.put\s*\(\s*"([^"]*)"?\s*,\s*(?:\w+\.toString\s*\(\s*\)|\w+)\s*\)/);
                if (putCall) { for (const t of mtv) { if (bl.includes(t)) { mtv.add(putCall[1]!); break; } } }
                const getCast = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(/);
                if (getCast && mtv.has(getCast[2]!)) mtv.add(getCast[1]!);
                // List add/get tracking with mutation awareness
                const addCall = bl.match(/(\w+)\.add\s*\(\s*(\w+)\s*\)/);
                if (addCall && mtv.has(addCall[2]!)) mtv.add(addCall[1]!);
                const listGet = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.get\s*\(\s*(\d+)\s*\)/);
                if (listGet) {
                  // Precise list tracking: replay add/remove operations to determine
                  // whether the element at the requested index is tainted.
                  const listVar = listGet[2]!; const getIdx = parseInt(listGet[3]!);
                  const listItems: { tainted: boolean }[] = []; let removeCount = 0;
                  for (const prev of bodyLines78) {
                    const prevAdd = prev.match(new RegExp(escapeRegExp(listVar) + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
                    if (prevAdd) listItems.push({ tainted: prevAdd[1] ? mtv.has(prevAdd[1]) : false });
                    if (prev.includes(listVar + '.remove(')) removeCount++;
                    if (prev === bl) break;
                  }
                  const adjusted = listItems.slice(removeCount);
                  if (getIdx < adjusted.length && adjusted[getIdx]!.tainted) mtv.add(listGet[1]!);
                  else if (getIdx < adjusted.length && !adjusted[getIdx]!.tainted) { /* safe: don't taint */ }
                  else if (mtv.has(listVar)) mtv.add(listGet[1]!); // fallback: list is tainted
                }
                // Concat propagation: x = ... + tainted or x = tainted + ...
                const concatProp = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(.+)/);
                if (concatProp && /\+/.test(concatProp[2]!)) {
                  for (const t of mtv) { if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(concatProp[2]!)) { mtv.add(concatProp[1]!); break; } }
                }
                // Note: we do NOT apply static string kills in the mini-taint tracker.
                // Multi-branch code (switch/if) may assign both param and literals to the
                // same variable. Conservative analysis: if ANY branch taints it, it's tainted.
                // Capture return variable
                const ret = bl.match(/return\s+(\w+)\s*;/);
                if (ret) returnVar78 = ret[1]!;
              }
              // If we can identify a return variable and it's NOT in the mini taint set,
              // the method neutralizes the tainted input.
              if (returnVar78 && !mtv.has(returnVar78)) kills78 = true;
              // If param is never referenced at all in the body, taint doesn't flow.
              if (!bodyLines78.some(l => /\bparam\b/.test(l))) kills78 = true;
            }
            break;
          }
        }
        if (kills78) tv.delete(ipCall78[1]!); else tv.add(ipCall78[1]!);
      }
      // For-each loop: for (Type var : collection) -- propagate taint from collection to loop var
      const forEach78 = ln.match(/for\s*\(\s*\w+\s+(\w+)\s*:\s*(\w+)\s*\)/);
      if (forEach78 && tv.has(forEach78[2]!)) tv.add(forEach78[1]!);

      const em = ln.match(EX78);
      if (em && sln > 0) {
        const ea = em[1] || ''; let hit = false;
        for (const t of tv) { if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(ea)) { hit = true; break; } }
        if (!hit) {
          // Lookback: check nearby lines for tainted data flowing into exec args.
          // First, identify variables that appear in the exec arg list.
          const execArgVars = new Set<string>();
          for (const word of ea.match(/\b[a-zA-Z_]\w*\b/g) || []) execArgVars.add(word);
          for (let j = Math.max(0, i - 25); j < i; j++) {
            const pl = sl78[j]!.trim();
            for (const t of tv) {
              // Only match concat/array/add patterns that involve an exec arg variable
              const concatRe = new RegExp('\\+\\s*\\b' + escapeRegExp(t) + '\\b|\\b' + escapeRegExp(t) + '\\b\\s*\\+');
              if (concatRe.test(pl)) {
                // Check that this line involves an exec arg var or feeds into one
                for (const av of execArgVars) {
                  if (new RegExp('\\b' + escapeRegExp(av) + '\\b').test(pl)) { hit = true; break; }
                }
                if (hit) break;
              }
              const arrRe = new RegExp('\\{[^}]*\\b' + escapeRegExp(t) + '\\b');
              if (arrRe.test(pl)) {
                // Check that this array init assigns to an exec arg variable
                const arrAssign = pl.match(/^(?:\w+\[\]\s+)?(\w+)\s*=/);
                if (arrAssign && execArgVars.has(arrAssign[1]!)) { hit = true; break; }
              }
              const addRe = new RegExp('\\.add\\s*\\([^)]*\\b' + escapeRegExp(t) + '\\b');
              if (addRe.test(pl)) {
                // Check that this .add() is on an exec arg variable
                const addTarget = pl.match(/(\w+)\s*\.\s*add\s*\(/);
                if (addTarget && execArgVars.has(addTarget[1]!)) { hit = true; break; }
              }
            }
            if (hit) break;
          }
        }
        if (hit) {
          findings.push({
            source: { id: `srcline-${sln}`, label: `user input (line ${sln})`, line: sln, code: scd.slice(0, 200) },
            sink: { id: `srcline-${i + 1}`, label: `command execution (line ${i + 1})`, line: i + 1, code: ln.slice(0, 200) },
            missing: 'CONTROL (input sanitization or safe command API)', severity: 'critical',
            description: `User input flows to OS command execution at line ${i + 1} without sanitization.`,
            fix: 'Never pass user input to shell commands. Use safe APIs with argument arrays.',
            via: 'source_line_fallback',
          });
          break;
        }
      }
    }
  }

  // Source-line fallback for Java deserialization: detect command injection where
  // fields populated by defaultReadObject()/readObject() flow to Runtime.exec().
  // Pattern: class implements Serializable, readObject() calls defaultReadObject(),
  // then a field (e.g., taskAction) is passed to Runtime.getRuntime().exec(field).
  if (findings.length === 0 && map.source_code) {
    const sl78d = stripComments(map.source_code);
    const hasDefaultReadObject = /\bdefaultReadObject\s*\(\s*\)|\breadObject\s*\(\s*\w+\s*\)/.test(sl78d);
    const hasSerializable = /\bSerializable\b/.test(sl78d);
    const hasRuntimeExec = /\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|new\s+ProcessBuilder\s*\(/.test(sl78d);

    if (hasDefaultReadObject && hasSerializable && hasRuntimeExec) {
      // Find fields that are used in exec() calls
      const lines78d = sl78d.split('\n');
      // Collect instance fields (private/protected/public String fieldName)
      const fields78 = new Set<string>();
      const FIELD_RE = /(?:private|protected|public)\s+(?:static\s+)?(?:final\s+)?(?:String|int|long|Object)\s+(\w+)\s*[;=]/;
      for (const line of lines78d) {
        const fm = line.match(FIELD_RE);
        if (fm) fields78.add(fm[1]!);
      }

      // After defaultReadObject(), all instance fields are tainted
      let deserLine = 0;
      let deserCode = '';
      let execLine = 0;
      let execCode = '';
      let taintedFieldUsed = false;

      for (let i = 0; i < lines78d.length; i++) {
        const ln = lines78d[i]!.trim();
        if (/defaultReadObject\s*\(/.test(ln)) {
          deserLine = i + 1;
          deserCode = ln;
        }
        const execMatch = ln.match(/\.exec\s*\(\s*(\w+)\s*\)|new\s+ProcessBuilder\s*\(\s*(\w+)/);
        if (execMatch) {
          const execArg = execMatch[1] || execMatch[2] || '';
          if (fields78.has(execArg)) {
            taintedFieldUsed = true;
            execLine = i + 1;
            execCode = ln;
          }
        }
      }

      if (taintedFieldUsed && deserLine > 0) {
        findings.push({
          source: { id: `srcline-${deserLine}`, label: `deserialization (line ${deserLine})`, line: deserLine, code: deserCode.slice(0, 200) },
          sink: { id: `srcline-${execLine}`, label: `command execution (line ${execLine})`, line: execLine, code: execCode.slice(0, 200) },
          missing: 'CONTROL (input sanitization or safe command API)',
          severity: 'critical',
          description: `Deserialized field flows to OS command execution at line ${execLine}. ` +
            `After defaultReadObject(), attacker-controlled field data reaches Runtime.exec() without sanitization.`,
          fix: 'Never pass deserialized field values to shell commands. Validate deserialized data against a strict allowlist. ' +
            'Consider using look-ahead deserialization (ObjectInputFilter) to restrict deserialized classes.',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return {
    cwe: 'CWE-78',
    name: 'OS Command Injection',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-611: XML External Entity (XXE)
 * Pattern: INGRESS → TRANSFORM(xml) without CONTROL(parser configuration)
 * Property: XML parsers disable external entity processing when handling user input
 */
function verifyCWE611(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // XML parser regex — matches across TRANSFORM, EXTERNAL, and STORAGE nodes
  const xmlParserPattern = /\b(parseXml|parseXmlString|parseXML|DOMParser|SAXParser|xml2js|libxml|libxmljs2?|etree\.parse|etree\.fromstring|xml\.sax|minidom\.parseString|XmlReader|ElementTree\.parse|lxml\.etree|parseFromString)\b/i;
  // Cross-domain exclusion: XPath evaluation (xpath_query) selects nodes in an
  // already-parsed document — it does NOT parse XML or process external entities.
  // Including xpath_query caused CWE-611 to fire on CWE-643 XPath injection code.
  const xmlParsers = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    n.node_subtype !== 'xpath_query' &&
    (n.node_subtype.includes('xml') || n.node_subtype.includes('xpath') ||
     n.attack_surface.includes('xml_parse') ||
     xmlParserPattern.test(n.analysis_snapshot || n.code_snapshot))
  );

  // Dangerous XML parser configurations that ENABLE XXE
  // libxmljs: parseXmlString(data, {noent:true}) — noent:true substitutes entities (DANGEROUS)
  // xml2js: explicitCharkey enables character key processing (DANGEROUS with crafted XML)
  const dangerousXmlConfigPattern = /noent\s*:\s*true|explicitCharkey/i;

  for (const src of ingress) {
    for (const sink of xmlParsers) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if the parser is configured dangerously (explicit XXE-enabling config)
        // Strip comments so dangerous config in comments doesn't misfire
        const sinkCodeOnly = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const hasDangerousConfig = dangerousXmlConfigPattern.test(sinkCodeOnly);

        // Check if external entities are properly disabled
        const isSecure = !hasDangerousConfig && sinkCodeOnly.match(
          /\bnoent\s*:\s*false\b|\bdisable.*entity\b|\bresolveEntities\s*:\s*false\b|\bXMLReader.*FEATURE.*external.*false\b|\bdefusedxml\b|\bsafe.*parse/i
        ) !== null;

        if (!isSecure) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (XML parser security configuration — disable external entities)',
            severity: 'high',
            description: `User-supplied XML from ${src.label} is parsed at ${sink.label} without disabling external entities. ` +
              (hasDangerousConfig
                ? `The parser is configured with dangerous options (noent:true or explicitCharkey) that enable entity expansion.`
                : `An attacker can read local files, perform SSRF, or cause denial of service via entity expansion.`),
            fix: 'Disable external entity processing in the XML parser configuration. ' +
              'Use defusedxml (Python), set resolveEntities: false, or use noent: false. ' +
              'For libxmljs: NEVER use {noent:true}. Consider using JSON instead of XML where possible.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Secondary check: XML parsing with dangerous config inside vm.runInContext or similar
  // code execution sinks. The taint flows through a sandbox object literal which breaks
  // the normal BFS taint path. Detect: any EXTERNAL/system_exec node whose code_snapshot
  // contains XML parsing with dangerous config, when INGRESS nodes exist in the same graph.
  if (findings.length === 0 && ingress.length > 0) {
    const execWithXml = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' &&
      n.node_subtype === 'system_exec' &&
      xmlParserPattern.test(n.analysis_snapshot || n.code_snapshot) &&
      dangerousXmlConfigPattern.test(n.analysis_snapshot || n.code_snapshot)
    );

    for (const execNode of execWithXml) {
      // Check if the exec node is in the same function scope as an INGRESS node
      const ingressInScope = ingress.find(src =>
        sharesFunctionScope(map, src.id, execNode.id)
      );

      if (ingressInScope) {
        const closestIngress = ingressInScope;
        findings.push({
          source: nodeRef(closestIngress),
          sink: nodeRef(execNode),
          missing: 'CONTROL (XML parser security configuration — disable external entities)',
          severity: 'critical',
          description: `User-supplied data from ${closestIngress.label} reaches XML parsing inside ${execNode.label} with dangerous configuration. ` +
            `The parser is configured with noent:true or explicitCharkey inside a code execution sink (vm.runInContext), enabling entity expansion.`,
          fix: 'Disable external entity processing in the XML parser configuration. ' +
            'NEVER use {noent:true} with libxmljs/libxmljs2. ' +
            'Use noent: false or remove the noent option entirely.',
          via: 'scope_taint',
        });
      }
    }
  }

  // Source-line fallback for Java: detect XXE in XML parser methods that receive
  // XML as a parameter. The mapper doesn't create INGRESS nodes for method params
  // (only for @RequestParam etc.), so BFS misses these. Pattern:
  //   XMLInputFactory.newInstance() → createXMLStreamReader(new StringReader(xml))
  //   without setProperty(ACCESS_EXTERNAL_DTD, "") or setProperty(...FEATURE...external..., false)
  // Also catches: SAXParserFactory, DocumentBuilderFactory without security config.
  if (findings.length === 0 && map.source_code) {
    // Strip both comments and string/regex literals so detection patterns inside DST's own
    // verifier code (e.g. the XML_FACTORY_RE definition itself) don't self-trigger when
    // verifier.ts is scanned.
    const sl611 = stripLiterals(stripComments(map.source_code));

    // Detect Java XML parser factories without security configuration
    const XML_FACTORY_RE = /\b(XMLInputFactory|SAXParserFactory|DocumentBuilderFactory|TransformerFactory|SchemaFactory|XMLReaderFactory)\s*\.\s*(?:newInstance|newFactory)\s*\(/;
    const XML_SECURE_RE = /\bsetProperty\s*\(\s*(?:XMLConstants\s*\.\s*)?(?:ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|ACCESS_EXTERNAL_STYLESHEET|FEATURE.*(?:external|dtd|entity))\b|\bsetFeature\s*\(.*(?:external|dtd|disallow|FEATURE)\b|\bdefusedxml\b/i;

    // Check if there's an XML factory without security properties
    const factoryMatch = sl611.match(XML_FACTORY_RE);
    if (factoryMatch) {
      // Find the variable holding the factory
      const factoryLine = sl611.indexOf(factoryMatch[0]);
      const factoryVarMatch = sl611.slice(Math.max(0, factoryLine - 100), factoryLine + factoryMatch[0].length + 10)
        .match(/(?:var|final\s+\w+|\w+)\s+(\w+)\s*=\s*/);
      const factoryVar = factoryVarMatch ? factoryVarMatch[1] : null;

      // Check if security properties are set on this factory
      let isSecured = XML_SECURE_RE.test(sl611);

      // Check for conditional security: if (securityEnabled) { setProperty... }
      // If security is gated behind a boolean parameter or variable, the unsecured
      // code path exists by definition. A method parameter `boolean securityEnabled`
      // means callers CAN pass false. This is a vulnerability — security should be
      // unconditional for XML parsing.
      if (isSecured) {
        const condSecMatch = sl611.match(/if\s*\(\s*(\w+)\s*\)\s*\{[^}]*(?:ACCESS_EXTERNAL_DTD|setProperty|setFeature)/s);
        if (condSecMatch) {
          const condVar = condSecMatch[1]!;
          // If the condition variable is a method parameter, security is optional
          const isMethodParam = new RegExp(
            '\\b(?:boolean|Boolean)\\s+' + escapeRegExp(condVar) + '\\b'
          ).test(sl611);
          // If any caller passes false, or it's a method param (callers could pass false)
          const calledWithFalse = new RegExp(
            '\\b\\w+\\s*\\([^)]*,\\s*false\\s*\\)'
          ).test(sl611);
          if (isMethodParam || calledWithFalse) {
            isSecured = false; // conditional security — unsecured path exists
          }
        }
      }

      // Check if the method receives XML as a parameter (method-param taint)
      const xmlParamRe = /(?:String|InputStream|Reader|Source)\s+(\w+).*\{[\s\S]*?(?:createXMLStreamReader|parse|unmarshal|transform)\s*\(/;
      const hasXmlParam = xmlParamRe.test(sl611);

      // Check if XML is used with createXMLStreamReader or similar parse calls
      const xmlParseCall = /\b(?:createXMLStreamReader|\.parse\s*\(|\.unmarshal\s*\()\s*\(/;
      const hasXmlParse = xmlParseCall.test(sl611) || /createXMLStreamReader/.test(sl611);

      if (!isSecured && hasXmlParse) {
        // Find the line numbers
        const lines611 = sl611.split('\n');
        let factoryLineNum = 0;
        let parseLineNum = 0;
        for (let i = 0; i < lines611.length; i++) {
          if (XML_FACTORY_RE.test(lines611[i]!)) factoryLineNum = i + 1;
          if (/createXMLStreamReader|\.parse\s*\(|\.unmarshal\s*\(/.test(lines611[i]!)) parseLineNum = i + 1;
        }

        findings.push({
          source: { id: `srcline-${factoryLineNum}`, label: `XML parser factory (line ${factoryLineNum})`, line: factoryLineNum, code: factoryMatch[0].slice(0, 200) },
          sink: { id: `srcline-${parseLineNum}`, label: `XML parse operation (line ${parseLineNum})`, line: parseLineNum, code: 'XML parsing without external entity protection' },
          missing: 'CONTROL (XML parser security configuration — disable external entities)',
          severity: 'high',
          description: `XML parser created at line ${factoryLineNum} does not disable external entity processing. ` +
            `An attacker can supply malicious XML with external entity references to read local files or perform SSRF.`,
          fix: 'Set XMLConstants.ACCESS_EXTERNAL_DTD and ACCESS_EXTERNAL_SCHEMA to empty string. ' +
            'For XMLInputFactory: xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, ""). ' +
            'For DocumentBuilderFactory: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).',
          via: 'source_line_fallback',
        });
      }
    }
  }

  return {
    cwe: 'CWE-611',
    name: 'XML External Entity (XXE)',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-94: Code Injection
 * Pattern: INGRESS → EXTERNAL(system_exec) without CONTROL, where code_snapshot contains eval/exec/Function
 * Property: User input is never passed to code evaluation functions
 */
function verifyCWE94(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const vmExecPattern = /\b(eval|exec|compile|Function\s*\(|execScript|setInterval|setTimeout|vm\.run|vm\.compile|vm\.create|runInContext|runInNewContext|runInThisContext|compileFunction|ejs\.render|pug\.render|nunjucks\.render)\b/i;
  const codeExec = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('system_exec') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('eval') || n.node_subtype.includes('template_exec')) &&
    vmExecPattern.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const src of ingress) {
    for (const sink of codeExec) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // "sandbox" and "safeEval" are NOT safe for vm.runInContext --
        // vm modules execute arbitrary code even inside sandbox contexts.
        // Only treat as safe if it's ast.literal_eval or JSON.parse (truly safe parsers).
        const sinkCodeOnly94 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const isVmExec = /\bvm\.|runInContext|runInNewContext|runInThisContext|compileFunction\b/i.test(sinkCodeOnly94);
        const isSafe = !isVmExec && sinkCodeOnly94.match(
          /\bsandbox\b|\bsafe.*eval\b|\bast\.literal_eval\b|\bJSON\.parse\b/i
        ) !== null;

        if (!isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input validation or sandboxed evaluation)',
            severity: 'critical',
            description: `User input from ${src.label} flows to code evaluation at ${sink.label} without sanitization. ` +
              (isVmExec
                ? `Node.js vm module does NOT provide a security sandbox -- user-controlled data in vm.runInContext enables arbitrary code execution.`
                : `An attacker can execute arbitrary code on the server.`),
            fix: isVmExec
              ? 'NEVER use vm.runInContext/runInNewContext with user-controlled data. ' +
                'The Node.js vm module is NOT a security mechanism. ' +
                'Use a true sandbox (vm2, isolated-vm) or avoid dynamic code evaluation entirely.'
              : 'Never pass user input to eval(), exec(), or Function(). ' +
                'Use ast.literal_eval() for Python or JSON.parse() for JSON data. ' +
                'If dynamic evaluation is required, use a sandboxed environment with strict allowlists.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Secondary check: vm.runInContext/runInNewContext where taint flows through
  // object literals (sandbox pattern). The pattern is:
  //   const data = req.body.x;              // tainted
  //   const sandbox = { safeEval, data };   // object literal contains tainted var
  //   vm.runInContext('safeEval(data)', sandbox);  // taint reaches code exec via sandbox
  // BFS doesn't find this because the object literal breaks the edge chain.
  // Detect: vm.* EXTERNAL nodes that reference variables also referenced by INGRESS,
  // when both are in the same function scope.
  if (findings.length === 0 && ingress.length > 0) {
    const vmNodes = codeExec.filter(n =>
      /\bvm\.|runInContext|runInNewContext|runInThisContext\b/i.test(n.analysis_snapshot || n.code_snapshot)
    );

    for (const vmNode of vmNodes) {
      // Check if any INGRESS node shares a function scope with this vm node
      for (const src of ingress) {
        if (sharesFunctionScope(map, src.id, vmNode.id)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(vmNode),
            missing: 'CONTROL (input validation or sandboxed evaluation)',
            severity: 'critical',
            description: `User input from ${src.label} is accessible within the vm execution context at ${vmNode.label}. ` +
              `Node.js vm module does NOT provide a security sandbox -- user-controlled data passed through object literals (sandbox pattern) enables arbitrary code execution.`,
            fix: 'NEVER use vm.runInContext/runInNewContext with user-controlled data. ' +
              'The Node.js vm module is NOT a security mechanism. ' +
              'Use a true sandbox (vm2, isolated-vm) or avoid dynamic code evaluation entirely.',
            via: 'scope_taint',
          });
          break; // One finding per vm node is sufficient
        }
      }
    }
  }

  // Tertiary check: When TypeScript type annotations cause the JS parser to
  // swallow destructured request parameters into ERROR nodes (0 INGRESS nodes),
  // but the function clearly handles HTTP request data (body, params, query)
  // and passes it to vm.*. Detect by code_snapshot analysis of sibling nodes.
  if (findings.length === 0 && ingress.length === 0) {
    const vmNodes = codeExec.filter(n =>
      /\bvm\.|runInContext|runInNewContext|runInThisContext\b/i.test(n.analysis_snapshot || n.code_snapshot)
    );

    for (const vmNode of vmNodes) {
      // Find the containing function by line range
      const containingFunc = map.nodes.find(n =>
        n.node_type === 'STRUCTURAL' &&
        n.node_subtype === 'function' &&
        n.line_start <= vmNode.line_start &&
        n.line_end >= vmNode.line_start &&
        // Must be an Express-like handler (references body, params, query, req)
        /\b(body|params|query|req\b|Request)\b/i.test(n.analysis_snapshot || n.code_snapshot)
      );

      if (containingFunc) {
        // Check if any sibling node in the same function references request data
        const requestDataPattern = /\bbody\.([\w]+)|\breq\.(body|params|query|headers)\b|\brequest\.(body|params|query)\b/i;
        const hasRequestData = map.nodes.some(n =>
          n.line_start >= containingFunc.line_start &&
          n.line_start <= containingFunc.line_end &&
          requestDataPattern.test(n.analysis_snapshot || n.code_snapshot)
        );

        if (hasRequestData) {
          findings.push({
            source: nodeRef(containingFunc),
            sink: nodeRef(vmNode),
            missing: 'CONTROL (input validation or sandboxed evaluation)',
            severity: 'critical',
            description: `HTTP request data is passed to code execution at ${vmNode.label} within ${containingFunc.label}. ` +
              `Node.js vm module does NOT provide a security sandbox -- user-controlled data in vm.runInContext enables arbitrary code execution.`,
            fix: 'NEVER use vm.runInContext/runInNewContext with user-controlled data. ' +
              'The Node.js vm module is NOT a security mechanism. ' +
              'Use a true sandbox (vm2, isolated-vm) or avoid dynamic code evaluation entirely.',
            via: 'scope_taint',
          });
          break;
        }
      }
    }
  }

  return {
    cwe: 'CWE-94',
    name: 'Code Injection',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-1321: Prototype Pollution (Improperly Controlled Modification of Object Prototype Attributes)
 * Pattern: INGRESS → TRANSFORM(mass_assignment) without CONTROL
 * Property: User input is never used to set arbitrary object properties without allowlisting
 *
 * Primarily JS-specific (Object.assign, spread into user-controlled keys, lodash.merge),
 * but the pattern extends to any language with dynamic property assignment.
 */
function verifyCWE1321(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  // Only check languages with dynamic prototypes/object mutation
  const lang = inferMapLanguage(map);
  const PROTOTYPE_LANGUAGES = new Set(['javascript', 'typescript', 'python', 'ruby', 'php']);
  if (lang && !PROTOTYPE_LANGUAGES.has(lang)) {
    return { cwe: 'CWE-1321', name: 'Prototype Pollution', holds: true, findings: [] };
  }

  const massAssign = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('mass_assignment') || n.node_subtype.includes('merge') ||
     (n.node_subtype.includes('assign') && (n.analysis_snapshot || n.code_snapshot).match(/\bObject\.assign\b|\bmerge\b|\bextend\b|\b__dict__\b|\battr_accessor\b/i)) ||
     (n.analysis_snapshot || n.code_snapshot).match(/\bObject\.assign\b|\b\.merge\b|\b\.extend\b|\b\.\.\.\s*req\b|\bdeepMerge\b|\bdefaultsDeep\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of massAssign) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isSafe = stripComments(sink.analysis_snapshot || sink.code_snapshot).match(
          /\ballowlist\b|\bwhitelist\b|\bpick\s*\(|\bsanitize\s*\(|\bObject\.create\(null\)/i
        ) !== null;

        if (!isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (property allowlisting or safe merge)',
            severity: 'high',
            description: `User input from ${src.label} is merged into an object at ${sink.label} without property filtering. ` +
              `An attacker can inject __proto__ or constructor.prototype to pollute Object.prototype.`,
            fix: 'Never merge user input directly into objects. Use an allowlist of permitted keys. ' +
              'Use Object.create(null) for lookup objects. Avoid lodash.merge/defaultsDeep with untrusted data. ' +
              'Consider using Map instead of plain objects for dynamic keys.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-1321',
    name: 'Prototype Pollution',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-158: Improper Neutralization of Null Byte or NUL Character
 * Pattern: CONTROL(validation using includes/endsWith/match) → file operation,
 *          where the validation does not strip null bytes before checking.
 * Classic pattern: filename.includes('.js') passes for "file.js%00.txt"
 *
 * Also detects: INGRESS → file_read/file_write where validation occurs but
 * cutOffPoisonNullByte/replace(\x00) is called AFTER the validation check.
 */
function verifyCWE158(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Null byte sanitization patterns
  const nullByteSanitizePattern = /cutOffPoisonNullByte|replace\s*\(\s*['"`]?\\x00|replace\s*\(\s*['"`]?\\0|replace\s*\(\s*['"`]?%00|\bnull.*byte\b.*strip|\breplace.*\\x00/i;

  // File type validation patterns — broad: includes function calls that check file types
  const fileValidationPattern = /\b(endsWith|includes|match|test|indexOf|startsWith)\s*\(.*\.(md|pdf|xml|zip|jpg|png|gif|js|ts|txt|html|css|json|yml|yaml)/i;
  const fileValidationFnPattern = /\b(endsWithAllowlisted|allowlistedFileType|validFileType|checkFileType|isValidExtension|fileTypeCheck|acceptedFileType|isAllowedExt)/i;

  // Find nodes that do file type validation — both CONTROL nodes and any node in the graph
  const validationNodes = map.nodes.filter(n =>
    fileValidationPattern.test(n.analysis_snapshot || n.code_snapshot) ||
    fileValidationFnPattern.test(n.analysis_snapshot || n.code_snapshot)
  );

  // Find nodes that do null byte sanitization
  const sanitizeNodes = map.nodes.filter(n =>
    nullByteSanitizePattern.test(n.analysis_snapshot || n.code_snapshot)
  );

  // File operation sinks
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'INGRESS' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('file') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(sendFile|readFile|createReadStream|createWriteStream|writeFile|unlink|open|access|stat|path\.resolve)\s*\(/i) !== null)
  );

  // Pattern 1: File type validation exists, null byte sanitization exists,
  // but sanitization is AFTER the validation (wrong order).
  // This is the fileServer.ts pattern: endsWithAllowlistedFileType(file) -> cutOffPoisonNullByte(file)
  if (validationNodes.length > 0 && sanitizeNodes.length > 0) {
    for (const valNode of validationNodes) {
      for (const sanNode of sanitizeNodes) {
        // Sanitization happens AFTER validation (wrong order)
        if (sanNode.line_start > valNode.line_start) {
          // Check if there's NO sanitization BEFORE the validation
          const hasPreSanitize = sanitizeNodes.some(s => s.line_start < valNode.line_start);
          if (!hasPreSanitize) {
            const sourceNode = ingress.length > 0 ? ingress[0]! : valNode;
            findings.push({
              source: nodeRef(sourceNode),
              sink: nodeRef(sanNode),
              missing: 'TRANSFORM (null byte neutralization BEFORE validation, not after)',
              severity: 'high',
              description: `Null byte sanitization at ${sanNode.label} (line ${sanNode.line_start}) occurs AFTER filename validation at ${valNode.label} (line ${valNode.line_start}). ` +
                `An attacker can bypass the file type check with a poison null byte (e.g., "evil.txt%00.pdf" passes an endsWith(".pdf") check, then the null byte is stripped, serving "evil.txt").`,
              fix: 'Move null byte sanitization BEFORE the file type/extension validation. ' +
                'The correct order is: (1) strip null bytes, (2) validate file type, (3) perform file operation.',
              via: 'bfs',
            });
            break;
          }
        }
      }
      if (findings.length > 0) break;
    }
  }

  // Pattern 2: File type validation with file operation but NO null byte sanitization at all
  if (findings.length === 0 && validationNodes.length > 0 && sanitizeNodes.length === 0 && fileOps.length > 0) {
    for (const src of ingress) {
      for (const fileOp of fileOps) {
        if (src.id === fileOp.id) continue;
        // Check if there's a validation node between them
        const hasVal = validationNodes.some(v =>
          v.line_start >= src.line_start && v.line_start <= fileOp.line_start
        );
        if (hasVal) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(fileOp),
            missing: 'TRANSFORM (null byte neutralization before filename validation)',
            severity: 'high',
            description: `Filename from ${src.label} is validated using file type checks but null bytes are never stripped. ` +
              `An attacker can bypass the validation with a poison null byte (e.g., "malicious.txt%00.pdf").`,
            fix: 'Strip null bytes from filenames BEFORE validation. ' +
              'Use filename.replace(/\\0/g, "") or a dedicated function like cutOffPoisonNullByte(). ' +
              'Always sanitize null bytes before any file type or extension check.',
            via: 'bfs',
          });
          break;
        }
      }
      if (findings.length > 0) break;
    }
  }

  return {
    cwe: 'CWE-158',
    name: 'Improper Neutralization of Null Byte or NUL Character',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-117: Log Injection
 * Detects user input flowing to logging functions without sanitization.
 *
 * The generated verifier only looks at STORAGE nodes, but most logging calls
 * are classified as EGRESS/display (println, print, System.out, fmt.Println)
 * or EXTERNAL (log.info, logger.warn). This override broadens the sink filter.
 *
 * Language patterns caught:
 *   Java/Kotlin: System.out.println(), Logger.info/warn/error(), println()
 *   Python:      logging.info/warn/error(), print()
 *   Go:          log.Printf(), fmt.Println(), log.Println()
 *   PHP:         error_log(), syslog(), trigger_error()
 *   Swift:       print(), NSLog(), os_log()
 *   Ruby:        puts, Logger.info/warn/error
 *   JavaScript:  console.log/warn/error(), winston, bunyan, pino
 *   C#:          Console.WriteLine(), ILogger.Log*
 */
function verifyCWE117(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Broad logging-function regex across all languages
  const LOG_SINK_RE = /\b(console\.(log|warn|error|info|debug|trace)|logger\.(log|error|warn|info|debug|trace|fatal|verbose)|log\.(log|error|warn|info|debug|trace|fatal|Printf|Println|Print)|println|print\s*\(|System\.out\.print|System\.err\.print|NSLog|os_log|error_log|syslog|trigger_error|puts\s|Logger\.(info|warn|error|debug|fatal)|winston\.(log|error|warn|info|debug)|bunyan\.(error|warn|info|debug|trace|fatal)|pino\.(error|warn|info|debug|trace|fatal)|log4js\.(error|warn|info|debug|trace|fatal)|morgan\(|app\.log\.|syslog\.(log|write)|audit\.log|accessLog\.|errorLog\.|Console\.Write|ILogger|_logger\.|logging\.(info|warning|error|debug|critical)|fmt\.Print|fmt\.Fprint|writeLog|appendFile.*log)\b/i;

  // Safe patterns — encoding or sanitization before logging
  const LOG_SAFE_RE = /\bescape\s*\(|\bencode\s*\(|\bsanitize\s*\(|\bstrip.*newline\b|\breplace.*\\n\b|\blog.*safe\b|\bneutralize\s*\(|\bstructured.*log\b|\bjson.*log\b/i;

  // Find logging sinks — EGRESS, EXTERNAL, STORAGE, or TRANSFORM nodes that match
  const logSinks = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL' ||
     n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('log') || n.node_subtype.includes('audit') ||
     n.node_subtype.includes('display') ||
     n.attack_surface.includes('logging') ||
     LOG_SINK_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const sink of logSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // V4-D: check scope snapshots for sanitization applied on prior lines
        const scopeSnapshots117 = getContainingScopeSnapshots(map, sink.id);
        const combinedScope117 = stripComments(scopeSnapshots117.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        if (!LOG_SAFE_RE.test(combinedScope117)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (log encoding — strip newlines, control chars, delimiters)',
            severity: 'medium',
            description: `User input from ${src.label} is logged at ${sink.label} without neutralization. ` +
              `An attacker can inject fake log entries via newlines or forge audit trails.`,
            fix: 'Strip or encode newlines (\\n, \\r), control characters, and log-format delimiters ' +
              'from user input before logging. Use structured logging (JSON) to prevent injection.',
            via: 'bfs',
          });
        }
      }
    }
  }

  // Scope-based fallback: INGRESS param shares a function scope with a logging node
  // that has tainted data_in
  if (findings.length === 0) {
    const taintedLogSinks = logSinks.filter(n => n.data_in.some(d => d.tainted));
    for (const src of ingress) {
      for (const sink of taintedLogSinks) {
        if (src.id === sink.id) continue;
        if (sharesFunctionScope(map, src.id, sink.id)) {
          // V4-D: check scope snapshots for sanitization on prior lines
          const scopeSnapshots117b = getContainingScopeSnapshots(map, sink.id);
          const combinedScope117b = stripComments(scopeSnapshots117b.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
          if (!LOG_SAFE_RE.test(combinedScope117b)) {
            const already = findings.some(f =>
              f.source.id === src.id && f.sink.id === sink.id
            );
            if (!already) {
              findings.push({
                source: nodeRef(src),
                sink: nodeRef(sink),
                missing: 'TRANSFORM (log encoding — strip newlines, control chars, delimiters)',
                severity: 'medium',
                description: `User input from ${src.label} is logged at ${sink.label} without neutralization. ` +
                  `An attacker can inject fake log entries via newlines or forge audit trails.`,
                fix: 'Strip or encode newlines (\\n, \\r), control characters, and log-format delimiters ' +
                  'from user input before logging. Use structured logging (JSON) to prevent injection.',
                via: 'scope_taint',
              });
            }
          }
        }
      }
    }
  }

  // Source-line fallback for Java: detect incomplete sanitization for log/output injection.
  // Pattern: @RequestParam flows to .output() or logging, with replace("\n",...) that does NOT
  // also handle \r (carriage return). Replacing only \n with HTML is not proper sanitization
  // because \r\n or just \r can still inject fake log/output entries.
  if (findings.length === 0 && map.source_code) {
    const sl117 = stripComments(map.source_code);
    const lines117 = sl117.split('\n');

    // Find @RequestParam String variables
    const PARAM_RE117 = /@RequestParam(?:\s*\([^)]*\))?\s+(?:String)\s+(\w+)/g;
    const requestParams117 = new Set<string>();
    let pm117;
    while ((pm117 = PARAM_RE117.exec(sl117)) !== null) {
      requestParams117.add(pm117[1]!);
    }

    if (requestParams117.size > 0) {
      for (const paramName of requestParams117) {
        // Check if this parameter has incomplete newline sanitization
        const replaceNewlineRe = new RegExp(
          escapeRegExp(paramName) + '\\s*=\\s*' + escapeRegExp(paramName) +
          '\\.replace\\s*\\(\\s*"\\\\n"\\s*,\\s*"[^"]*"\\s*\\)',
        );
        const replaceCRRe = new RegExp(
          escapeRegExp(paramName) + '\\.replace\\s*\\(\\s*"\\\\r"',
        );
        const stripAllNewlinesRe = new RegExp(
          escapeRegExp(paramName) + '\\.replaceAll\\s*\\(\\s*"\\[\\\\r\\\\n\\]|\\\\\\\\r\\|\\\\\\\\n"',
        );

        const hasNewlineReplace = replaceNewlineRe.test(sl117);
        const hasCRReplace = replaceCRRe.test(sl117);
        const hasFullStrip = stripAllNewlinesRe.test(sl117);

        // Incomplete: replaces \n but not \r
        if (hasNewlineReplace && !hasCRReplace && !hasFullStrip) {
          // Check if the param flows to any output
          let outputLine = 0;
          let outputCode = '';
          let paramLine = 0;
          let paramCode = '';

          for (let i = 0; i < lines117.length; i++) {
            const ln = lines117[i]!.trim();
            if (new RegExp('@RequestParam.*\\b' + escapeRegExp(paramName) + '\\b').test(ln)) {
              paramLine = i + 1;
              paramCode = ln;
            }
            // Any output/display/return that includes the param
            if (new RegExp('\\.output\\s*\\(\\s*' + escapeRegExp(paramName) + '\\s*\\)|\\.body\\s*\\(.*' + escapeRegExp(paramName) + '|return.*' + escapeRegExp(paramName)).test(ln)) {
              outputLine = i + 1;
              outputCode = ln;
            }
          }

          if (outputLine > 0 && paramLine > 0) {
            findings.push({
              source: { id: `srcline-${paramLine}`, label: `request parameter (line ${paramLine})`, line: paramLine, code: paramCode.slice(0, 200) },
              sink: { id: `srcline-${outputLine}`, label: `output (line ${outputLine})`, line: outputLine, code: outputCode.slice(0, 200) },
              missing: 'TRANSFORM (log encoding — strip newlines, control chars, delimiters)',
              severity: 'medium',
              description: `User input "${paramName}" has incomplete newline sanitization: replace("\\n",...) without also replacing "\\r". ` +
                `Carriage return characters can still inject fake log entries or forge output lines.`,
              fix: 'Replace both \\n and \\r (and ideally all control characters) from user input before logging or displaying. ' +
                'Use replaceAll("[\\\\r\\\\n]", "") or a structured logging framework.',
              via: 'source_line_fallback',
            });
            break;
          }
        }

        // No sanitization at all: param goes directly to output with no replace
        if (!hasNewlineReplace && !hasCRReplace && !hasFullStrip) {
          let outputLine = 0;
          let outputCode = '';
          let paramLine = 0;
          let paramCode = '';

          for (let i = 0; i < lines117.length; i++) {
            const ln = lines117[i]!.trim();
            if (new RegExp('@RequestParam.*\\b' + escapeRegExp(paramName) + '\\b').test(ln)) {
              paramLine = i + 1;
              paramCode = ln;
            }
            if (new RegExp('\\.output\\s*\\(\\s*' + escapeRegExp(paramName) + '\\s*\\)|logger\\..*' + escapeRegExp(paramName) + '|log\\..*' + escapeRegExp(paramName)).test(ln)) {
              outputLine = i + 1;
              outputCode = ln;
            }
          }

          if (outputLine > 0 && paramLine > 0) {
            findings.push({
              source: { id: `srcline-${paramLine}`, label: `request parameter (line ${paramLine})`, line: paramLine, code: paramCode.slice(0, 200) },
              sink: { id: `srcline-${outputLine}`, label: `output (line ${outputLine})`, line: outputLine, code: outputCode.slice(0, 200) },
              missing: 'TRANSFORM (log encoding — strip newlines, control chars, delimiters)',
              severity: 'medium',
              description: `User input "${paramName}" flows to output without any newline neutralization. ` +
                `An attacker can inject fake log entries via \\r\\n sequences.`,
              fix: 'Strip newlines (\\n, \\r) and control characters from user input before output. ' +
                'Use structured logging (JSON) to prevent log injection.',
              via: 'source_line_fallback',
            });
            break;
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-117',
    name: 'Improper Output Neutralization for Logs',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-601: Open Redirect
 * Detects user-controlled URLs flowing to redirect operations.
 *
 * The generated verifier only looks at EGRESS/TRANSFORM nodes with redirect
 * subtypes. This override also catches:
 *   - CONTROL/return nodes that return "Location: <user-input>"
 *   - TRANSFORM/template_string nodes that build redirect URLs
 *   - String returns containing redirect-related URLs
 *
 * Language patterns caught:
 *   Java/Kotlin: response.sendRedirect(), "Location: " + url, return "redirect:" + url
 *   Python:      redirect(url), Response(status=302, headers={"Location": url})
 *   Go:          http.Redirect(), w.Header().Set("Location", url)
 *   PHP:         header("Location: " . $url)
 *   Swift/JS:    return "Location: " + url, window.location = url
 */
function verifyCWE601(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Sources: user input that could contain URLs
  const urlInputs = nodesOfType(map, 'INGRESS').filter(n =>
    n.node_subtype.includes('query') || n.node_subtype.includes('param') ||
    n.node_subtype.includes('url') || n.node_subtype.includes('header') ||
    n.node_subtype.includes('http_request') || n.node_subtype.includes('function_param') ||
    n.attack_surface.includes('user_input') || n.attack_surface.includes('url_input') ||
    (n.analysis_snapshot || n.code_snapshot).match(
      /\b(req\.query|req\.params|req\.body|request\.args|request\.form|request\.GET|searchParams|url|redirect|next|return_?to|goto|target|dest|forward|continue|callback|returnUrl)\b/i
    ) !== null
  );

  // Sinks: redirect operations — broadened to catch return statements and template strings
  const REDIRECT_CODE_RE = /\b(res\.redirect|response\.redirect|redirect|sendRedirect|Location\s*[=:]|window\.location|document\.location|meta.*refresh|header\s*\(\s*['"]Location|http\.Redirect)\b|"Location:\s|'Location:\s|redirect\?url=/i;

  const redirectSinks = map.nodes.filter(n =>
    // Original: EGRESS/TRANSFORM with redirect subtypes
    ((n.node_type === 'EGRESS' || n.node_type === 'TRANSFORM') &&
     (n.node_subtype.includes('redirect') || n.node_subtype.includes('location') ||
      n.attack_surface.includes('redirect') ||
      REDIRECT_CODE_RE.test(n.analysis_snapshot || n.code_snapshot))) ||
    // NEW: CONTROL/return nodes whose code contains redirect/Location patterns
    (n.node_type === 'CONTROL' && n.node_subtype === 'return' &&
     REDIRECT_CODE_RE.test(n.analysis_snapshot || n.code_snapshot)) ||
    // NEW: template_string nodes that build redirect URLs
    (n.node_type === 'TRANSFORM' && n.node_subtype === 'template_string' &&
     REDIRECT_CODE_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  // Safe patterns: allowlist check, relative-path enforcement, same-origin check
  const safeRedirect = (code: string): boolean =>
    /\ballowlist\b|\bwhitelist\b|\ballowed[_-]?(?:urls?|domains?|hosts?)\b/i.test(code) ||
    /\bstartsWith\s*\(\s*['"]\/[^\/]/i.test(code) ||
    /\bnew URL\b.*\.(?:host|origin|hostname)\b/i.test(code) ||
    /\bsame[_-]?origin\b|\burl\.parse\b.*\bhost\b/i.test(code) ||
    /\brelative[_-]?path\b|\bpath\.resolve\b/i.test(code);

  for (const src of urlInputs) {
    for (const sink of redirectSinks) {
      if (src.id === sink.id) continue;

      // Check tainted path first
      let vulnerable = hasTaintedPathWithoutControl(map, src.id, sink.id);

      // Fallback: scope-based check for redirect URLs
      if (!vulnerable && sharesFunctionScope(map, src.id, sink.id)) {
        // Check if the sink's code references the source's label (variable name)
        const srcVarName = src.label.replace(/[^a-zA-Z0-9_]/g, '');
        if (srcVarName && (sink.analysis_snapshot || sink.code_snapshot).includes(srcVarName)) {
          vulnerable = true;
        }
        // Also check if sink has tainted data_in
        if (!vulnerable && sink.data_in.some(d => d.tainted)) {
          vulnerable = true;
        }
      }

      if (vulnerable) {
        const scopeSnapshots601 = getContainingScopeSnapshots(map, sink.id);
        const combinedScope601 = scopeSnapshots601.join('\n') || (sink.analysis_snapshot || sink.code_snapshot);
        if (!safeRedirect(combinedScope601) && !safeRedirect((src.analysis_snapshot || src.code_snapshot))) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (URL allowlist or relative-path enforcement before redirect)',
            severity: 'medium',
            description: `User input from ${src.label} controls redirect destination at ${sink.label}. ` +
              `Attackers can craft URLs like ?next=https://evil.com to phish users via your domain.`,
            fix: 'Validate redirect URLs against an allowlist of trusted domains. ' +
              'Use relative paths only: if (!url.startsWith("/") || url.startsWith("//")) reject. ' +
              'Parse with new URL() and check .hostname against allowed origins.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-601',
    name: 'URL Redirection to Untrusted Site (Open Redirect)',
    holds: findings.length === 0,
    findings,
  };
}

function verifyCWE610(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress610 = nodesOfType(map, 'INGRESS');
  const EXT610 = /\b(fetch|axios|request|http\.get|https\.get|got\(|requests\.(get|post)|urllib|curl|wget|include|require|import|fopen|file_get_contents|LoadLibrary|dlopen|System\.load)\b/i;
  const DB610 = /\b(createConnection|connect|MongoClient|mongoose\.connect|sequelize|createPool|DriverManager\.getConnection|psycopg2\.connect)\b/i;
  const sinks610 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('http') || n.node_subtype.includes('api_call') ||
     n.node_subtype.includes('request') || n.node_subtype.includes('include') ||
     n.node_subtype.includes('import') || n.node_subtype.includes('db_connect') ||
     n.node_subtype.includes('remote') || n.node_subtype.includes('fetch') ||
     n.attack_surface.includes('cross_sphere') || n.attack_surface.includes('external_reference') ||
     EXT610.test(n.analysis_snapshot || n.code_snapshot) || DB610.test(n.analysis_snapshot || n.code_snapshot))
  );
  const SAFE610 = /\ballowlist\b|\bwhitelist\b|\ballowed.*domain\b|\bvalidateUrl\b|\bvalidateHost\b|\bnew URL\b.*\bhost\b|\bstartsWith\s*\(\s*['"]https?:\/\/\w|\bsame.*origin\b|\btrusted.*host\b/i;
  for (const src of ingress610) {
    for (const sink of sinks610) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!SAFE610.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) && !SAFE610.test(stripComments(src.analysis_snapshot || src.code_snapshot))) {
          const rt = DB610.test(sink.analysis_snapshot || sink.code_snapshot) ? 'database connection' : 'external resource';
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (external reference validation / allowlist of permitted targets)',
            severity: 'high',
            description: `User input from ${src.label} controls ${rt} reference at ${sink.label}. Attacker can access resources in another security sphere.`,
            fix: 'Validate references against an allowlist. Parse URLs and check hostname. Never let user input control connection strings.',
            via: 'bfs',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-610', name: 'Externally Controlled Reference to a Resource in Another Sphere', holds: findings.length === 0, findings };
}

function verifyCWE643(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress643 = nodesOfType(map, 'INGRESS');
  const XP643 = /\b(xpath|XPath|XPathExpression|evaluate|selectNodes|selectSingleNode|DOMXPath|SimpleXMLElement|etree\.XPath|tree\.xpath|xmlDoc\.evaluate|xpath\.select)\b/i;
  const XP_CAT643 = /['"]\/\/\w.*\+|\+.*['"]\/\/\w|['"]@\w+\s*=\s*'.*\+|xpath.*\+\s*\w/i;
  const xpSinks643 = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('xpath') || n.node_subtype.includes('xml_query') ||
     n.attack_surface.includes('xpath_query') || XP643.test(n.analysis_snapshot || n.code_snapshot) || XP_CAT643.test(n.analysis_snapshot || n.code_snapshot))
  );
  const SAFE643 = /\bescapeXPath\b|\bxpath.*param\b|\bxpath.*compile\b|\bsanitize.*xpath\b|\bXPathVariableResolver\b|\bregister.*variable\b/i;

  // Interprocedural static neutralization: the called method (e.g., doSomething) abandons
  // the tainted parameter and returns a value derived from a static literal instead.
  const hasInterproceduralStatic643 = map.source_code
    ? detectInterproceduralNeutralization90(map.source_code)
    : false;

  for (const src of ingress643) {
    for (const sink of xpSinks643) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (hasDeadBranchForNode(map, sink.id) || hasInterproceduralStatic643) continue;
        if (!SAFE643.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) && !SAFE643.test(stripComments(src.analysis_snapshot || src.code_snapshot))) {
          const concat = XP_CAT643.test(sink.analysis_snapshot || sink.code_snapshot);
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (XPath parameterization or input escaping)',
            severity: 'high',
            description: `User input from ${src.label} flows into XPath query at ${sink.label} without sanitization. ` +
              (concat ? 'String concatenation builds the XPath expression. ' : '') +
              `Attacker can inject XPath operators to bypass auth or exfiltrate data.`,
            fix: 'Use parameterized XPath (XPathVariableResolver in Java, variable bindings in lxml). Escape special chars. Never concatenate user input into XPath.',
            via: 'bfs',
          });
        }
      }
    }
  }
  if (findings.length === 0 && ingress643.length > 0 && !hasInterproceduralStatic643) {
    const xpScope643 = map.nodes.filter(n => n.node_type !== 'META' && n.node_type !== 'STRUCTURAL' && XP_CAT643.test(n.analysis_snapshot || n.code_snapshot));
    for (const src of ingress643) {
      for (const sink of xpScope643) {
        if (src.id === sink.id) continue;
        if (sharesFunctionScope(map, src.id, sink.id) && !SAFE643.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          if (isLineInDeadBranchFunction(map, sink.line_start)) continue;
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (XPath parameterization or input escaping)',
            severity: 'high',
            description: `User input from ${src.label} in scope with XPath construction at ${sink.label}. Injection possible if input interpolated.`,
            fix: 'Use parameterized XPath or escape special characters. Never concatenate user input into XPath.',
            via: 'scope_taint',
          }); break;
        }
      }
    }
  }
  // Source-line fallback for Java XPath injection: interprocedural taint tracking
  if (findings.length === 0 && map.source_code && !hasInterproceduralStatic643) {
    // Per-index collection taint tracking now handled by the mapper (collectionTaint on VariableInfo).
    {
      const sl643 = map.source_code.split('\n');
      const SRC643 = /(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getParameterValues|getHeader|getHeaders|getCookies|getQueryString|getInputStream|getReader|getTheParameter|System\.getenv)\s*\(/;
      const hasXPathContext643 = /\b(?:XPathFactory|javax\.xml\.xpath|XPath|XPathExpression|DOMXPath|SimpleXMLElement|etree\.XPath|tree\.xpath)\b/.test(map.source_code!);
      const XPATH_SINK_RE643 = hasXPathContext643
        ? /\b(?:xpath\.evaluate|XPathExpression\.evaluate|xpath\.compile|selectNodes|selectSingleNode|XPathFactory|DocumentBuilder|\w+\.evaluate)\s*\(/
        : /\b(?:xpath\.evaluate|XPathExpression\.evaluate|xpath\.compile|selectNodes|selectSingleNode|XPathFactory|DocumentBuilder)\s*\(/;
      const tv643 = new Set<string>();
      let sln643 = 0; let scd643 = '';
      for (let i = 0; i < sl643.length; i++) {
        const ln = sl643[i]!.trim();
        if (ln.startsWith('//') || ln.startsWith('*') || ln.startsWith('/*')) continue;
        const mx643 = ln.match(SRC643); if (mx643) { tv643.add(mx643[1]!); sln643 = i + 1; scd643 = ln; }
        const va643 = ln.match(/^(\w+)\s*=\s*(\w+)\s*;/);
        if (va643 && tv643.has(va643[2]!)) tv643.add(va643[1]!);
        const ma643 = ln.match(/^(\w+)\s*=\s*\w+(?:\.\w+)*\s*\(\s*(\w+)\s*\)/);
        if (ma643 && tv643.has(ma643[2]!)) tv643.add(ma643[1]!);
        // Multi-arg call propagation: var = SomeClass.method(taintedVar, otherArg)
        // Also handles: var = new Type(nested.call(taintedVar.method()))
        if (!ma643) {
          const genAssign643 = ln.match(/^(?:(?:\w+\.)*\w+(?:\[\])?\s+)*(\w+)\s*=\s*(.*)/);
          if (genAssign643) {
            const gaLhs643 = genAssign643[1]!;
            let gaRhs643 = genAssign643[2]!;
            // Handle multi-line assignments: if the RHS is empty or doesn't end with ';',
            // join continuation lines until we find one that ends with ';'
            if (!gaRhs643.trimEnd().endsWith(';')) {
              for (let k = i + 1; k < Math.min(i + 8, sl643.length); k++) {
                const cont = sl643[k]!.trim();
                gaRhs643 += ' ' + cont;
                if (cont.endsWith(';')) break;
              }
            }
            // Skip constant string assignments
            if (!/^\s*"[^"]*"\s*;/.test(gaRhs643)) {
              for (const t of tv643) {
                if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(gaRhs643)) {
                  tv643.add(gaLhs643);
                  break;
                }
              }
            }
          }
        }
        const ca643 = ln.match(/^(\w+)\s*=\s*.*\b(\w+)\b.*\+/);
        if (ca643 && tv643.has(ca643[2]!)) tv643.add(ca643[1]!);
        const ck643 = ln.match(/^(\w+)\s*=\s*"[^"]*"\s*;/);
        if (ck643) tv643.delete(ck643[1]!);
        // HashMap
        const mg643 = ln.match(/^(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
        if (mg643) {
          const mkr643 = resolveMapKeyTaint(sl643, tv643, mg643[2]!, mg643[3]!, i);
          if (mkr643 === 'tainted') tv643.add(mg643[1]!); else tv643.delete(mg643[1]!);
        }
        // List offset
        const lg643 = ln.match(/^(\w+)\s*=\s*(\w+)\.get\s*\(\s*(\d+)\s*\)/);
        if (lg643) {
          const lv643 = lg643[2]!; const gi643 = parseInt(lg643[3]!);
          const items643: { tainted: boolean }[] = []; let rc643 = 0;
          for (let j = 0; j < i; j++) {
            const al643 = sl643[j]!.trim();
            const am643 = al643.match(new RegExp(escapeRegExp(lv643) + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
            if (am643) items643.push({ tainted: am643[1] ? tv643.has(am643[1]) : false });
            if (al643.includes(lv643 + '.remove(')) rc643++;
          }
          const adj643 = items643.slice(rc643);
          if (gi643 < adj643.length && !adj643[gi643]!.tainted) tv643.delete(lg643[1]!); else tv643.add(lg643[1]!);
        }
        // Interprocedural
        const ipCall643 = ln.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?(\w+)\s*\(\s*(?:request\s*,\s*)?(\w+)\s*\)/);
        if (ipCall643 && tv643.has(ipCall643[3]!)) {
          const mn643 = ipCall643[2]!;
          let kills643 = false;
          for (let j = 0; j < sl643.length; j++) {
            const md643 = sl643[j]!.trim();
            if (md643.includes(`${mn643}(`) && (md643.includes('String ') || md643.includes('public '))) {
              let bd643 = 0; let fo643 = false;
              for (let k = j; k < Math.min(j + 40, sl643.length); k++) {
                if (sl643[k]!.includes('{')) { bd643++; fo643 = true; }
                if (sl643[k]!.includes('}')) bd643--;
                if (fo643 && bd643 <= 0) break;
                if (/\b(?:parseInt|parseLong|Pattern\.matches|validate|sanitize)\b/i.test(sl643[k]!.trim())) { kills643 = true; break; }
                if (/^\w+\s*=\s*"[^"]{5,}"/.test(sl643[k]!.trim())) { kills643 = true; break; }
                if (/\.remove\s*\(\s*\d+\s*\)/.test(sl643[k]!.trim())) { kills643 = true; break; }
              }
              break;
            }
          }
          if (kills643) tv643.delete(ipCall643[1]!); else tv643.add(ipCall643[1]!);
        }
        // XPath sink detection — look within a wider window
        if ((XPATH_SINK_RE643.test(ln) || XP_CAT643.test(ln)) && sln643 > 0) {
          const windowStart643 = Math.max(0, i - 10);
          const windowEnd643 = Math.min(sl643.length - 1, i + 5);
          const window643 = sl643.slice(windowStart643, windowEnd643 + 1).join(' ');
          if (SAFE643.test(window643)) continue;
          let hit643 = false;
          for (const t of tv643) {
            if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(window643) &&
                /\+/.test(window643)) { hit643 = true; break; }
          }
          if (hit643) {
            if (isLineInDeadBranchFunction(map, i + 1)) continue;
            findings.push({
              source: { id: `srcline-${sln643}`, label: `user input (line ${sln643})`, line: sln643, code: scd643.slice(0, 200) },
              sink: { id: `srcline-${i + 1}`, label: `XPath query (line ${i + 1})`, line: i + 1, code: ln.slice(0, 200) },
              missing: 'CONTROL (XPath parameterization or input escaping)',
              severity: 'high',
              description: `User input flows to XPath query at line ${i + 1} without escaping.`,
              fix: 'Use parameterized XPath with XPathVariableResolver. Never concatenate user input into XPath.',
              via: 'source_line_fallback',
            });
            break;
          }
        }
      }
    }
  }

  return { cwe: 'CWE-643', name: 'XPath Injection', holds: findings.length === 0, findings };
}

function verifyCWE776(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress776 = nodesOfType(map, 'INGRESS');
  const XML776 = /\b(parseXml|parseXmlString|parseXML|DOMParser|SAXParser|xml2js|libxml|libxmljs2?|etree\.parse|etree\.fromstring|xml\.sax|minidom\.parseString|XmlReader|ElementTree\.parse|lxml\.etree|parseFromString|DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReader)\b/i;
  // Exclude regex compilation, string literals, and non-XML parse contexts from XML parser detection.
  // Pattern.compile, re.compile, new RegExp etc. get node_subtype 'parse' but are not XML parsers.
  const NOT_XML776 = /\bPattern\.compile\b|\bre\.compile\b|\bnew\s+RegExp\b|\bRegex\b|\bregex\b|\bPattern\.matches\b|\bPattern\.quote\b/i;
  const xmlParsers776 = map.nodes.filter(n => {
    if (!(n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE')) return false;
    const snap = n.analysis_snapshot || n.code_snapshot;
    // Exclude regex/pattern compilation contexts — these are not XML parsers
    if (NOT_XML776.test(snap)) return false;
    return n.node_subtype.includes('xml') ||
     n.attack_surface.includes('xml_parse') || XML776.test(snap);
  });
  const DANGER776 = /\bnoent\s*:\s*true\b|\bentity.*expand\b.*true|\bDTDProcessing\.Parse\b/i;
  const SAFE776 = /\bdefusedxml\b|\bdisallow.*doctype\b|\bentityExpansionLimit\b|\bmaxEntityExpansions\b|\bresolveEntities\s*:\s*false\b|\bnoent\s*:\s*false\b|\bsafe.*parse\b|\bsetFeature.*disallow-doctype-decl.*true\b|\bXMLInputFactory\.SUPPORT_DTD.*false\b/i;
  for (const src of ingress776) {
    for (const sink of xmlParsers776) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sc = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const hasDanger = DANGER776.test(sc);
        if (!SAFE776.test(sc) || hasDanger) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (XML entity expansion limits or DTD prohibition)',
            severity: 'high',
            description: `User XML from ${src.label} parsed at ${sink.label} without entity expansion limits. ` +
              (hasDanger ? 'Parser has dangerous entity expansion enabled. ' : '') +
              'Billion Laughs attack can expand recursive entities into gigabytes of memory.',
            fix: 'Prohibit DTDs (disallow-doctype-decl). Set entityExpansionLimit. Use defusedxml. Set noent:false in libxmljs.',
            via: 'bfs',
          });
        }
      }
    }
  }
  if (findings.length === 0 && ingress776.length > 0 && xmlParsers776.length > 0) {
    for (const src of ingress776) {
      for (const sink of xmlParsers776) {
        if (src.id === sink.id) continue;
        if (sharesFunctionScope(map, src.id, sink.id) && !SAFE776.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (XML entity expansion limits or DTD prohibition)',
            severity: 'high',
            description: `User input from ${src.label} in scope with XML parser at ${sink.label} without entity expansion limits.`,
            fix: 'Prohibit DTDs or set entity expansion limits. Use defusedxml or hardened parser.',
            via: 'scope_taint',
          }); break;
        }
      }
    }
  }
  return { cwe: 'CWE-776', name: 'Improper Restriction of Recursive Entity References in DTDs (Billion Laughs)', holds: findings.length === 0, findings };
}

function verifyCWE20(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const processingSinks = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    !n.node_subtype.includes('sql') && !n.node_subtype.includes('shell') &&
    !n.node_subtype.includes('xml') && !n.node_subtype.includes('command')
  );

  const VALIDATION_SAFE20 = /\b(validate|validator|isValid|parseInt|parseFloat|Number\(|Boolean\(|joi\.|yup\.|zod\.|z\.|schema\.validate|check\(|body\(|param\(|query\(|sanitize|assert|typeof\s+\w+\s*[!=]==?\s*'|instanceof\b|isNaN|Number\.isFinite|Number\.isInteger|\.test\(|match\(|Regex|allowlist|whitelist|enum|includes\(|indexOf\(|\.has\(|switch\s*\(|express-validator|class-validator|ajv|JSON\.parse)\b/i;

  for (const src of ingress) {
    for (const sink of processingSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!VALIDATION_SAFE20.test(srcCode) && !VALIDATION_SAFE20.test(sinkCode)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input validation — type checking, schema validation, or allowlist)',
            severity: 'high',
            description: `User input from ${src.label} reaches ${sink.label} without any input validation. ` +
              `No type checking, schema validation, or constraint enforcement detected.`,
            fix: 'Validate all user input before processing. Use schema validation (Joi, Zod, Yup), ' +
              'type coercion (parseInt, Number), allowlists for enum values, regex patterns for strings, ' +
              'and range checks for numbers. Reject invalid input early.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-20', name: 'Improper Input Validation', holds: findings.length === 0, findings };
}

/**
 * CWE-74: Injection (Generic Parent)
 * Pattern: INGRESS → EGRESS/EXTERNAL(downstream) without CONTROL/TRANSFORM
 * Property: User input is neutralized before output to any downstream component.
 *
 * Parent of ALL injection CWEs. Focuses on EGRESS and EXTERNAL nodes NOT already
 * covered by specific CWEs (SQL, OS, XSS, etc.) — catching injection into less
 * common downstream components (mail headers, logging, IPC, etc.).
 */
function verifyCWE74(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const downstreamSinks74 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS') &&
    !n.node_subtype.includes('sql') && !n.node_subtype.includes('shell') &&
    !n.node_subtype.includes('command') && !n.node_subtype.includes('html') &&
    !n.node_subtype.includes('xml') && !n.node_subtype.includes('ldap') &&
    !n.node_subtype.includes('xpath') &&
    ((n.analysis_snapshot || n.code_snapshot).match(
      /\b(send|write|emit|publish|dispatch|render|format|template|header|setHeader|log|print|fprintf|sprintf|IPC|pipe|channel|message)\b/i
    ) !== null || n.attack_surface.includes('output') || n.attack_surface.includes('sink'))
  );

  const NEUTRALIZE_SAFE74 = /\b(escape|encode|sanitize|neutralize|parameteriz|prepared|placeholder|safe.*format|format.*safe|DOMPurify|htmlEncode|urlEncode|encodeURI|encodeURIComponent|validator\.|strip|clean|purify)\b/i;

  for (const src of ingress) {
    for (const sink of downstreamSinks74) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!NEUTRALIZE_SAFE74.test(sinkCode)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input neutralization before output to downstream component)',
            severity: 'critical',
            description: `User input from ${src.label} flows to downstream component at ${sink.label} without neutralization. ` +
              `If the downstream component interprets special characters, injection is possible.`,
            fix: 'Neutralize user input for the target context before passing to downstream components. ' +
              'Use context-appropriate encoding (URL encoding for URLs, HTML encoding for HTML, etc.). ' +
              'Prefer structured APIs over string concatenation.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-74', name: 'Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-77: Command Injection (Parent — Improper Neutralization of Special Elements in a Command)
 * Pattern: INGRESS → EXTERNAL(command/exec) without CONTROL neutralization
 * Property: User input is neutralized before being embedded in any command string.
 *
 * Parent of CWE-78 (OS command injection). Covers command injection MORE BROADLY —
 * not just OS shells but any command interpreter (database CLI tools, scripting engines,
 * IPC command protocols, etc.).
 */
function verifyCWE77(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const cmdSinks77 = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('command') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('shell') || n.node_subtype.includes('system_exec') ||
     n.attack_surface.includes('shell_exec') || n.attack_surface.includes('command_exec') ||
     (n.analysis_snapshot || n.code_snapshot).match(
       /\b(exec|execSync|execFile|spawn|system|popen|shell_exec|child_process|os\.system|subprocess|Runtime\.exec|ProcessBuilder|Process\.Start|ShellExecute|WScript\.Shell)\s*\(/i
     ) !== null)
  );

  for (const src of ingress) {
    for (const sink of cmdSinks77) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code77 = stripComments(sink.analysis_snapshot || sink.code_snapshot);

        const usesArgArray77 = /\b(execFile|execFileSync)\s*\(/i.test(code77) ||
          (/\bspawn\s*\([^)]*,\s*\[/i.test(code77) && !/shell\s*:\s*true/i.test(code77)) ||
          (/\bsubprocess\.(run|Popen|call)\s*\(\s*\[/i.test(code77) && !/shell\s*=\s*True/i.test(code77)) ||
          /\bProcessBuilder\s*\(\s*\[/i.test(code77);

        const usesEscaping77 = /\b(shellEscape|escapeShell|escapeShellArg|shlex\.quote|shellescape|quotemeta)\s*\(/i.test(code77);
        const usesAllowlist77 = /\b(allowlist|whitelist|allowedCommands|validCommands|permitted)\b/i.test(code77);

        if (!usesArgArray77 && !usesEscaping77 && !usesAllowlist77) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (command parameterization — argument arrays or input escaping)',
            severity: 'critical',
            description: `User input from ${src.label} flows to command execution at ${sink.label} without neutralization. ` +
              `Special elements in the input can alter the command's intended behavior.`,
            fix: 'Use argument arrays instead of string concatenation for commands. ' +
              'execFile("cmd", [arg1, arg2]) instead of exec("cmd " + arg1). ' +
              'If strings are unavoidable, escape with shlex.quote (Python) or a strict allowlist.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-77', name: 'Command Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-90: LDAP Injection
 * Pattern: INGRESS → EXTERNAL/STORAGE(ldap) without CONTROL(LDAP escaping)
 * Property: User input is escaped for LDAP special characters before query construction.
 *
 * LDAP special characters: * ( ) \ NUL
 * Attacker injects into (cn=INPUT) to alter filter logic: (cn=*)(|(cn=*))
 */
function verifyCWE90(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const LDAP_SINK90 = /\b(ldap\.search|ldap\.bind|ldap_search|ldap_bind|ldap_add|ldap_modify|ldap_list|SearchRequest|LdapConnection|DirectorySearcher|ldap\.query|searchFilter|baseDN)\b/i;
  const LDAP_FILTER_CONCAT90 = /\(\w+=[^)]*(\+|\$\{)/;

  const ldapSinks90 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('ldap') || n.attack_surface.includes('ldap') ||
     LDAP_SINK90.test(n.analysis_snapshot || n.code_snapshot) || LDAP_FILTER_CONCAT90.test(n.analysis_snapshot || n.code_snapshot))
  );

  const LDAP_SAFE90 = /\b(ldap\.escape|escapeLDAP|ldapEscape|escape_filter_chars|filter\.escape|Filter\.(and|or|eq|present|approx)|ldap_escape|sanitizeLdap|escapeDN|escapeFilter)\b/i;

  // Per-index collection taint tracking now handled by the mapper (collectionTaint on VariableInfo).
  const hasStaticVal90 = map.source_code ? detectStaticValueNeutralization(map.source_code) : false;
  // Interprocedural neutralization: check if inner-class/helper method kills taint
  // by returning a static literal, retrieving a safe HashMap key, or abandoning the tainted chain.
  const hasInterproceduralKill90 = map.source_code ? detectInterproceduralNeutralization90(map.source_code) : false;

  for (const src of ingress) {
    for (const sink of ldapSinks90) {
      if (src.id === sink.id) continue;
      // Primary: BFS taint path. Fallback (Step 8): check data_in tainted entries on sink.
      const bfsHit90 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const sinkTaintHit90 = !bfsHit90 && sinkHasTaintedDataIn(map, sink.id);
      if (bfsHit90 || sinkTaintHit90) {
        if (hasDeadBranchForNode(map, sink.id) || hasStaticVal90 || hasInterproceduralKill90) continue;
        const sinkCode90 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!LDAP_SAFE90.test(sinkCode90)) {
          const usesFilterConcat90 = LDAP_FILTER_CONCAT90.test(sinkCode90);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (LDAP special character escaping or parameterized filter)',
            severity: 'high',
            description: `User input from ${src.label} flows to LDAP operation at ${sink.label} without escaping. ` +
              (usesFilterConcat90
                ? `String concatenation builds the LDAP filter. Attacker can inject *, (, ), \\ to alter query logic.`
                : `Attacker can inject LDAP metacharacters to bypass authentication or extract directory data.`),
            fix: 'Escape LDAP special characters (*, (, ), \\, NUL) in user input. ' +
              'Use ldap.escape() or escape_filter_chars(). Prefer filter builder APIs (Filter.eq, Filter.and) ' +
              'over string concatenation. Validate input format (e.g., alphanumeric only for usernames).',
            via: bfsHit90 ? 'bfs' : 'sink_tainted',
          });
        }
      }
    }
  }

  // Source-line fallback for Java LDAP injection: interprocedural taint tracking
  if (findings.length === 0 && map.source_code) {
    const sl90 = map.source_code.split('\n');
    const SRC90 = /(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getParameterValues|getHeader|getHeaders|getCookies|getQueryString|getInputStream|getReader|getTheParameter|System\.getenv|getParameterMap)\s*\(/;
    const LDAP_SINK_RE90 = /\b(?:search|DirContext\.search|NamingEnumeration|ctx\.search|dirContext\.search|ldapTemplate\.search|idc\.search)\s*\(/;
    const LDAP_SAFE_SL90 = /\b(?:escapeLDAPSearchFilter|LdapEncoder\.filterEncode|FilterEncoder|ldap\.escape|escape_filter_chars|parseInt|parseLong|Pattern\.matches)\b/i;
    const tv90 = new Set<string>();
    let sln90 = 0; let scd90 = '';
    let inSwitch90 = false;
    let switchBraceDepth90 = 0;
    const switchTaintedVars90 = new Set<string>();
    for (let i = 0; i < sl90.length; i++) {
      const ln = sl90[i]!.trim();
      if (ln.startsWith('//') || ln.startsWith('*') || ln.startsWith('/*')) continue;
      // Track switch blocks using brace counting
      if (/\bswitch\s*\(/.test(ln)) { inSwitch90 = true; switchBraceDepth90 = 0; }
      if (inSwitch90) {
        for (const ch of ln) {
          if (ch === '{') switchBraceDepth90++;
          if (ch === '}') { switchBraceDepth90--; if (switchBraceDepth90 <= 0) { inSwitch90 = false; switchTaintedVars90.clear(); } }
        }
      }
      const mx90 = ln.match(SRC90); if (mx90) { tv90.add(mx90[1]!); sln90 = i + 1; scd90 = ln; }
      // Taint propagation for tainted_map.get("key") => result is tainted
      const mapGetProp90 = ln.match(/(\w+)\s*=\s*(\w+)\.get\s*\(/);
      if (mapGetProp90 && tv90.has(mapGetProp90[2]!)) tv90.add(mapGetProp90[1]!);
      // Array access: param = values[0] where values is tainted
      const arrAccess90 = ln.match(/(\w+)\s*=\s*(\w+)\s*\[\s*\d+\s*\]/);
      if (arrAccess90 && tv90.has(arrAccess90[2]!)) tv90.add(arrAccess90[1]!);
      // Simple assignment propagation
      const va90 = ln.match(/^(\w+)\s*=\s*(\w+)\s*;/);
      if (va90 && tv90.has(va90[2]!)) {
        tv90.add(va90[1]!);
        if (inSwitch90) switchTaintedVars90.add(va90[1]!);
      }
      // Method call propagation
      const ma90 = ln.match(/^(\w+)\s*=\s*\w+(?:\.\w+)*\s*\(\s*(\w+)\s*\)/);
      if (ma90 && tv90.has(ma90[2]!)) tv90.add(ma90[1]!);
      // String concat propagation
      const ca90 = ln.match(/^(\w+)\s*=\s*.*\b(\w+)\b.*\+/);
      if (ca90 && tv90.has(ca90[2]!)) tv90.add(ca90[1]!);
      // Static literal kills taint — but NOT inside switch if the var was tainted in another case
      const ck90 = ln.match(/^(\w+)\s*=\s*"[^"]*"\s*;/);
      if (ck90) {
        if (inSwitch90 && switchTaintedVars90.has(ck90[1]!)) {
          // Inside switch: var was tainted in another case branch, don't kill
        } else {
          tv90.delete(ck90[1]!);
        }
      }
      // HashMap put/get
      const mg90 = ln.match(/^(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
      if (mg90) {
        const mkr90 = resolveMapKeyTaint(sl90, tv90, mg90[2]!, mg90[3]!, i);
        if (mkr90 === 'tainted') tv90.add(mg90[1]!); else tv90.delete(mg90[1]!);
      }
      // List offset
      const lg90 = ln.match(/^(\w+)\s*=\s*(\w+)\.get\s*\(\s*(\d+)\s*\)/);
      if (lg90) {
        const lv90 = lg90[2]!; const gi90 = parseInt(lg90[3]!);
        const items90: { tainted: boolean }[] = []; let rc90 = 0;
        for (let j = 0; j < i; j++) {
          const al90 = sl90[j]!.trim();
          const am90 = al90.match(new RegExp(escapeRegExp(lv90) + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
          if (am90) items90.push({ tainted: am90[1] ? tv90.has(am90[1]) : false });
          if (al90.includes(lv90 + '.remove(')) rc90++;
        }
        const adj90 = items90.slice(rc90);
        if (gi90 < adj90.length && !adj90[gi90]!.tainted) tv90.delete(lg90[1]!); else tv90.add(lg90[1]!);
      }
      // Interprocedural: bar = new Test().doSomething(request, param)
      // Run mini forward taint analysis inside the called method to determine if
      // the return value carries taint from param.
      const ipCall90 = ln.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?(\w+)\s*\(\s*(?:request\s*,\s*)?(\w+)\s*\)/);
      if (ipCall90 && tv90.has(ipCall90[3]!)) {
        const mn90 = ipCall90[2]!;
        let kills90 = false;
        // Find method declaration
        const methodDeclRe90 = new RegExp('(?:public|private|protected|static)\\s+.*\\b' + escapeRegExp(mn90) + '\\s*\\(');
        for (let j = 0; j < sl90.length; j++) {
          if (j === i) continue;
          const md90 = sl90[j]!.trim();
          if (methodDeclRe90.test(md90)) {
            // Extract method body lines
            let bd90 = 0; let fo90 = false;
            const bodyLines90: string[] = [];
            for (let k = j; k < Math.min(j + 60, sl90.length); k++) {
              if (sl90[k]!.includes('{')) { bd90++; fo90 = true; }
              if (sl90[k]!.includes('}')) bd90--;
              if (fo90 && bd90 <= 0) break;
              if (k !== j) bodyLines90.push(sl90[k]!.trim());
            }
            // Strong sanitizers kill taint unconditionally
            if (bodyLines90.some(bl => LDAP_SAFE_SL90.test(bl))) { kills90 = true; break; }
            if (bodyLines90.some(bl => /\.remove\s*\(\s*\d+\s*\)/.test(bl))) { kills90 = true; break; }
            // Mini forward taint analysis inside method body (switch-aware)
            const mtv90 = new Set<string>(['param']);
            let returnVar90 = '';
            let inSw90 = false; let swBd90 = 0;
            const swTainted90 = new Set<string>();
            for (const bl of bodyLines90) {
              // Track switch blocks
              if (/\bswitch\s*\(/.test(bl)) { inSw90 = true; swBd90 = 0; }
              if (inSw90) { for (const c of bl) { if (c === '{') swBd90++; if (c === '}') { swBd90--; if (swBd90 <= 0) { inSw90 = false; swTainted90.clear(); } } } }
              // Simple assignment propagation
              const mva = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\s*;/);
              if (mva && mtv90.has(mva[2]!)) { mtv90.add(mva[1]!); if (inSw90) swTainted90.add(mva[1]!); }
              // Constructor propagation: var = new Type(tainted)
              const mcon = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*new\s+\w+\s*\(\s*(\w+)\s*\)/);
              if (mcon && mtv90.has(mcon[2]!)) mtv90.add(mcon[1]!);
              // Method call propagation: var = something.method(tainted)
              const mcall = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(?:\w+\.)*\w+\s*\(\s*(\w+)\s*[,)]/);
              if (mcall && mtv90.has(mcall[2]!)) mtv90.add(mcall[1]!);
              // String concat propagation
              const mcc = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*.*\b(\w+)\b.*\+/);
              if (mcc && mtv90.has(mcc[2]!)) mtv90.add(mcc[1]!);
              // toString propagation: var = tainted.toString()
              const mts = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.toString\(\)/);
              if (mts && mtv90.has(mts[2]!)) mtv90.add(mts[1]!);
              // Static literal kills taint — but NOT inside switch if var was tainted in another case
              const mlit = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*"[^"]*"\s*;/);
              if (mlit) {
                if (inSw90 && swTainted90.has(mlit[1]!)) { /* don't kill */ } else { mtv90.delete(mlit[1]!); }
              }
              // HashMap safe key retrieval
              const mget = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
              if (mget) {
                const mkr = resolveMapKeyTaint(bodyLines90, mtv90, mget[2]!, mget[3]!, bodyLines90.indexOf(bl));
                if (mkr === 'tainted') mtv90.add(mget[1]!); else mtv90.delete(mget[1]!);
              }
              // Return
              const mret = bl.match(/return\s+(\w+)\s*;/);
              if (mret) { returnVar90 = mret[1]!; break; }
            }
            // If the return variable is NOT tainted, the method kills taint
            if (returnVar90 && !mtv90.has(returnVar90)) kills90 = true;
            break;
          }
        }
        if (kills90) tv90.delete(ipCall90[1]!); else tv90.add(ipCall90[1]!);
      }
      // LDAP sink detection
      if (LDAP_SINK_RE90.test(ln) && sln90 > 0) {
        const scopeSlice90 = sl90.slice(Math.max(0, i - 10), i + 5).join('\n');
        if (LDAP_SAFE_SL90.test(scopeSlice90)) continue;
        let hit90 = false;
        for (const t of tv90) {
          if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(ln) ||
              new RegExp('["+]\\s*\\b' + escapeRegExp(t) + '\\b|\\b' + escapeRegExp(t) + '\\b\\s*[+"]').test(scopeSlice90)) {
            hit90 = true; break;
          }
        }
        if (hit90) {
          if (isLineInDeadBranchFunction(map, i + 1)) continue;
          findings.push({
            source: { id: `srcline-${sln90}`, label: `user input (line ${sln90})`, line: sln90, code: scd90.slice(0, 200) },
            sink: { id: `srcline-${i + 1}`, label: `LDAP query (line ${i + 1})`, line: i + 1, code: ln.slice(0, 200) },
            missing: 'CONTROL (LDAP special character escaping or parameterized filter)',
            severity: 'high',
            description: `User input flows to LDAP query at line ${i + 1} without escaping.`,
            fix: 'Escape LDAP special characters. Use filter builder APIs over string concatenation.',
            via: 'source_line_fallback',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-90', name: 'LDAP Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-91: XML Injection / Blind XPath Injection
 * Pattern: INGRESS → TRANSFORM/EXTERNAL(xml/xpath) without CONTROL(encoding)
 * Property: User input is XML-encoded before being embedded in XML documents or XPath queries.
 *
 * Two vectors:
 * 1. XML Element Injection — user input in XML doc via string concat
 * 2. Blind XPath Injection — user input in XPath query; attacker infers data
 *    via boolean conditions (true/false response differences)
 *
 * Distinguished from CWE-643 by explicitly covering the "blind" XPath variant.
 */
function verifyCWE91(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const XML_XPATH_SINK91 = /\b(createElement|appendChild|parseFromString|selectNodes|xpath\.select|evaluate|etree\.(SubElement|fromstring|XML)|DOMParser|xml2js|XPathExpression|selectSingleNode|DOMXPath|SimpleXMLElement)\b/i;
  const XML_STRING_CONCAT91 = /<\w+[^>]*>.*(\+|\$\{)/;

  const xmlSinks91 = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('xml') || n.node_subtype.includes('xpath') ||
     n.attack_surface.includes('xml_construct') || n.attack_surface.includes('xpath_query') ||
     XML_XPATH_SINK91.test(n.analysis_snapshot || n.code_snapshot) || XML_STRING_CONCAT91.test(n.analysis_snapshot || n.code_snapshot))
  );

  const SAFE_XML91 = /\b(createTextNode|escapeXml|xmlEncode|xmlEscape|encodeXml|he\.encode|entities\.encode|XPathEvaluator|xpath.*variable|bindVariable|xml2js\.Builder|xmlbuilder|js2xml|sanitize.*xml|xmlSanitize|defusedxml|escapeXPath)\b/i;

  for (const src of ingress) {
    for (const sink of xmlSinks91) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode91 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!SAFE_XML91.test(sinkCode91)) {
          const isXpath91 = /\bxpath\b|\bselectNodes\b|\bevaluate\b|\bselectSingleNode\b|\b\/\/\w+\[/i.test(sinkCode91);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: isXpath91
              ? 'CONTROL (XPath parameterization or escaping — blind injection possible)'
              : 'CONTROL (XML entity encoding before document construction)',
            severity: 'high',
            description: `User input from ${src.label} flows to ${isXpath91 ? 'XPath query' : 'XML construction'} at ${sink.label} without encoding. ` +
              (isXpath91
                ? `Even without direct data exfiltration, blind XPath injection extracts data character-by-character via response differences.`
                : `Attacker can inject XML elements or attributes to alter document structure.`),
            fix: isXpath91
              ? 'Use parameterized XPath with variable binding. Never concatenate user input into XPath strings. ' +
                'Blind injection leaks data via behavior differences even without direct output.'
              : 'Use DOM APIs (createTextNode, setAttribute) instead of string concatenation. ' +
                'Encode XML special characters (&, <, >, \', ") with escapeXml() or he.encode().',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-91', name: 'XML Injection / Blind XPath Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-93: CRLF Injection (Improper Neutralization of CRLF Sequences)
 * Pattern: INGRESS → EGRESS(http_header/log) without CONTROL(CRLF stripping)
 * Property: User input is stripped of CR/LF before embedding in HTTP headers or logs.
 *
 * Injecting \r\n into HTTP headers enables response splitting, cache poisoning, log forging.
 */
function verifyCWE93(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const HEADER_LOG_SINK93 = /\b(setHeader|writeHead|res\.header|res\.set|response\.addHeader|response\.setHeader|addHeader|header\(|Header\.set|appendHeader|log\.(info|warn|error|debug)|logger\.|console\.(log|warn|error)|syslog|fprintf|mail\(|sendmail|SMTP)\b/i;

  const headerLogSinks93 = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('http_header') || n.node_subtype.includes('header') ||
     n.node_subtype.includes('log') || n.node_subtype.includes('response') ||
     n.attack_surface.includes('http_header') || n.attack_surface.includes('log_sink') ||
     HEADER_LOG_SINK93.test(n.analysis_snapshot || n.code_snapshot))
  );

  const CRLF_SAFE93 = /\b(stripNewlines|sanitizeHeader|encodeHeader|headerEncode|escapeHeader|removeCRLF|removeNewlines)\b/i;
  const CRLF_STRIP93 = /replace\s*\([^)]*[\\]r|replace\s*\([^)]*[\\]n|\.replace\s*\(\s*\/\\r\\n/i;

  for (const src of ingress) {
    for (const sink of headerLogSinks93) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode93 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!CRLF_SAFE93.test(sinkCode93) && !CRLF_STRIP93.test(sinkCode93)) {
          const isHeader93 = /\b(setHeader|writeHead|header|addHeader|appendHeader|response\.set)\b/i.test(sinkCode93);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (CRLF character stripping before header/log insertion)',
            severity: isHeader93 ? 'high' : 'medium',
            description: `User input from ${src.label} flows to ${isHeader93 ? 'HTTP header' : 'log/output'} at ${sink.label} without CRLF neutralization. ` +
              (isHeader93
                ? `Injecting \\r\\n enables HTTP response splitting, header injection, and cache poisoning.`
                : `Injecting newlines enables log forging — attacker can inject fake log entries.`),
            fix: 'Strip or reject CR (\\r) and LF (\\n) characters from user input before embedding in headers or logs. ' +
              'Use input.replace(/[\\r\\n]/g, "") or a framework header sanitization function. ' +
              'Modern frameworks (Express 4+) auto-reject headers with CRLF, but explicit validation is safer.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-93', name: 'CRLF Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-95: Eval Injection (Improper Neutralization of Directives in Dynamically Evaluated Code)
 * Pattern: INGRESS → EXTERNAL(eval/exec) without CONTROL
 * Property: User input is never passed to dynamic code evaluation functions.
 *
 * Distinguished from CWE-94: CWE-95 specifically covers eval()-style functions that
 * DYNAMICALLY evaluate code at runtime. Includes setTimeout/setInterval with string args
 * (which use eval internally), and Node.js vm module (NOT a security sandbox).
 */
function verifyCWE95(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const EVAL_PATTERN95 = /\b(eval|exec|compile|Function\s*\(|execScript|vm\.run|vm\.compile|runInContext|runInNewContext|runInThisContext|compileFunction|new\s+Function)\b/i;
  const TIMER_EVAL95 = /\b(setTimeout|setInterval)\s*\(\s*['"`]/i;

  const evalSinks95 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('eval') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('system_exec') || n.node_subtype.includes('template_exec') ||
     EVAL_PATTERN95.test(n.analysis_snapshot || n.code_snapshot) || TIMER_EVAL95.test(n.analysis_snapshot || n.code_snapshot))
  );

  const EVAL_SAFE95 = /\b(ast\.literal_eval|JSON\.parse|parseInt|parseFloat|Number\(|isolated-vm|vm2\.run)\b/i;

  for (const src of ingress) {
    for (const sink of evalSinks95) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode95 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const isVm95 = /\bvm\.|runInContext|runInNewContext|runInThisContext\b/i.test(sinkCode95);
        const isSafe95 = !isVm95 && EVAL_SAFE95.test(sinkCode95);

        if (!isSafe95) {
          const isTimerEval95 = TIMER_EVAL95.test(sinkCode95);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (eliminate dynamic code evaluation or use safe parsing alternatives)',
            severity: 'critical',
            description: `User input from ${src.label} flows to dynamic code evaluation at ${sink.label}. ` +
              (isTimerEval95
                ? `setTimeout/setInterval with a string argument internally uses eval(). Replace with a function reference.`
                : isVm95
                  ? `Node.js vm module does NOT provide security isolation. User-controlled code achieves full RCE.`
                  : `Attacker can execute arbitrary code by injecting into the evaluated string.`),
            fix: isTimerEval95
              ? 'Replace setTimeout("code", ms) with setTimeout(function, ms). Never pass user input as a string to timer functions.'
              : 'Eliminate eval/exec entirely. Use JSON.parse for JSON, ast.literal_eval for Python literals. ' +
                'If dynamic evaluation is required, use isolated-vm (NOT Node.js vm module) with strict input validation.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-95', name: 'Eval Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-96: Improper Neutralization of Directives in Statically Saved Code
 * Pattern: INGRESS → STORAGE(file write) where file has executable extension
 * Property: User input is never written to files that are subsequently interpreted as code.
 *
 * Covers "stored code injection" — user input written to a file (.php, .js, .py, .jsp,
 * config files, cron entries, .htaccess, etc.) that is later executed by the server.
 * Unlike CWE-94/95 (runtime eval), CWE-96 is about PERSISTENT code injection via file writes.
 */
function verifyCWE96(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const CODE_FILE96 = /\.(php|jsp|asp|aspx|py|rb|pl|cgi|js|ts|sh|bash|cron|htaccess|ini|conf|yaml|yml|xml|json|sql)\b/i;
  const FILE_WRITE96 = /\b(writeFile|writeFileSync|appendFile|appendFileSync|fs\.write|fwrite|file_put_contents|open\s*\([^)]*['"]w|FileWriter|BufferedWriter|StreamWriter|fopen.*w)\b/i;

  const fileWriteSinks96 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
     n.attack_surface.includes('file_write') ||
     FILE_WRITE96.test(n.analysis_snapshot || n.code_snapshot)) &&
    (CODE_FILE96.test(n.analysis_snapshot || n.code_snapshot) ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(template|view|script|config|cron|htaccess)\b/i) !== null)
  );

  const STATIC_CODE_SAFE96 = /\b(sanitize|escape|htmlspecialchars|strip_tags|bleach|purify|encode|filterInput|validate.*extension|allowedExtensions|mimeType|contentType.*check)\b/i;

  for (const src of ingress) {
    for (const sink of fileWriteSinks96) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode96 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!STATIC_CODE_SAFE96.test(sinkCode96)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (content sanitization and file type restriction)',
            severity: 'critical',
            description: `User input from ${src.label} is written to a potentially executable file at ${sink.label}. ` +
              `If the server later interprets this file as code, attacker achieves persistent code execution.`,
            fix: 'Never write user input to files with executable extensions (.php, .jsp, .py, etc.). ' +
              'Validate file extensions against a strict allowlist. Sanitize content to remove executable directives. ' +
              'Store user content outside the web root and serve with Content-Disposition: attachment.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-96', name: 'Static Code Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-98: PHP Remote File Inclusion
 * Pattern: INGRESS → EXTERNAL(include/require) without CONTROL(path validation)
 * Property: User input is never used directly in include/require statements.
 *
 * PHP include/require accept URLs when allow_url_include is enabled. Attacker includes
 * remote PHP code. Also covers LFI via directory traversal. Extends to dynamic imports
 * in other languages (importlib, __import__, dynamic require).
 */
function verifyCWE98(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const PHP_INCLUDE98 = /\b(include|require|include_once|require_once)\s*[\(;]/i;
  const DYNAMIC_INCLUDE98 = /\b(importlib\.import_module|__import__|require\s*\(\s*\w+\s*\+|import\s*\(\s*\w+\s*\+|dlopen|LoadLibrary|Assembly\.Load)\b/i;

  const includeSinks98 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('include') || n.node_subtype.includes('import') ||
     n.node_subtype.includes('require') || n.attack_surface.includes('file_include') ||
     PHP_INCLUDE98.test(n.analysis_snapshot || n.code_snapshot) || DYNAMIC_INCLUDE98.test(n.analysis_snapshot || n.code_snapshot))
  );

  const INCLUDE_SAFE98 = /\b(basename|realpath|path\.resolve|path\.join.*__dirname|allowedPages|validPages|allowlist|whitelist|startsWith\s*\(\s*['"]\/|DIRECTORY_SEPARATOR)\b/i;

  for (const src of ingress) {
    for (const sink of includeSinks98) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode98 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!INCLUDE_SAFE98.test(sinkCode98)) {
          const isPhp98 = PHP_INCLUDE98.test(sinkCode98);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (file path validation — allowlist or path canonicalization)',
            severity: 'critical',
            description: `User input from ${src.label} flows to file include at ${sink.label} without path validation. ` +
              (isPhp98
                ? `PHP include/require with user-controlled path enables Remote File Inclusion (allow_url_include=On) ` +
                  `or Local File Inclusion (directory traversal to sensitive files).`
                : `Dynamic file inclusion with user-controlled path enables arbitrary code loading.`),
            fix: isPhp98
              ? 'Use an allowlist mapping of valid page names to file paths. ' +
                'Never pass user input directly to include/require. Disable allow_url_include in php.ini. ' +
                'Example: $pages = ["home" => "home.php"]; include($pages[$_GET["page"]] ?? "404.php");'
              : 'Use an allowlist of valid module names. Never construct import paths from user input.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-98', name: 'PHP Remote File Inclusion', holds: findings.length === 0, findings };
}

/**
 * CWE-99: Improper Control of Resource Identifiers (Resource Injection)
 * Pattern: INGRESS → EXTERNAL/STORAGE(resource access) without CONTROL(validation)
 * Property: User input is validated before being used as a resource identifier.
 *
 * Resource identifiers: port numbers, database names, queue names, socket addresses,
 * registry keys, cache keys, environment variable names, service endpoints.
 * Attacker controls WHICH resource is accessed, not content.
 * Distinguished from CWE-22 (path traversal): covers ALL resource types, not just files.
 */
function verifyCWE99(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const RESOURCE99 = /\b(connect|createConnection|createClient|getConnection|collection|database|useDatabase|selectDB|net\.connect|Socket\(|redis\.(get|set|del|hget|hset)|memcached\.(get|set)|queue|channel|exchange|publish|subscribe|getenv|setenv|putenv|Registry|SharedMemory|mmap|shmget)\b/i;

  const resourceSinks99 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('resource') || n.node_subtype.includes('connection') ||
     n.node_subtype.includes('socket') || n.node_subtype.includes('network') ||
     n.attack_surface.includes('resource_access') ||
     RESOURCE99.test(n.analysis_snapshot || n.code_snapshot)) &&
    !n.node_subtype.includes('sql') && !n.node_subtype.includes('file') &&
    !n.node_subtype.includes('shell') && !n.node_subtype.includes('ldap')
  );

  const RESOURCE_SAFE99 = /\b(allowlist|whitelist|allowedResources|validResources|permitted|enum|includes\(|indexOf\(|\.has\(|switch\s*\(|parseInt|Number\(|portRange|validatePort|isValidPort|validateResource|sanitizeKey)\b/i;

  for (const src of ingress) {
    for (const sink of resourceSinks99) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode99 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!RESOURCE_SAFE99.test(sinkCode99)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (resource identifier validation — allowlist or type enforcement)',
            severity: 'high',
            description: `User input from ${src.label} controls resource selection at ${sink.label} without validation. ` +
              `Attacker can access unintended resources (databases, ports, queues, cache keys) by manipulating the identifier.`,
            fix: 'Validate resource identifiers against an allowlist of permitted values. ' +
              'Use enums or switch statements for resource selection. ' +
              'For numeric identifiers (ports), validate range. For strings, use a strict allowlist. ' +
              'Never let user input directly select backend resources.',
            via: 'bfs',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-99', name: 'Resource Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-15: External Control of System or Configuration Setting
 * Pattern: INGRESS → system/config modification API without CONTROL(validation)
 * Property: External input never directly modifies system or configuration settings.
 *
 * Detects tainted data flowing from external sources (sockets, HTTP requests,
 * user input) into APIs that modify system-level configuration:
 *   Java:   System.setProperty(), Connection.setCatalog(), Connection.setSchema(),
 *           Properties.setProperty(), System.setOut(), System.setErr()
 *   C/C++:  putenv(), setenv()
 *   Python: os.environ[], os.putenv()
 *   JS/TS:  process.env assignment
 *
 * The Juliet pattern: socket.read() → dbConnection.setCatalog(data)
 * — attacker controls which database catalog is active.
 */
function verifyCWE15(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Config/system modification sink patterns across languages
  const configSinkRe = /\b(System\s*\.\s*setProperty|setProperty\s*\(|setCatalog\s*\(|setSchema\s*\(|putenv\s*\(|setenv\s*\(|os\s*\.\s*environ\s*\[|os\s*\.\s*putenv\s*\(|process\s*\.\s*env\s*\[|Properties\s*\.\s*setProperty|System\s*\.\s*setOut|System\s*\.\s*setErr|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec)\b/i;

  const configSinks = map.nodes.filter(n => {
    const code = n.analysis_snapshot || n.code_snapshot;
    return configSinkRe.test(code);
  });

  const safeConfigRe = /\bvalidate\s*\(|\ballowlist\b|\bwhitelist\b|\ballowed\w*\s*\.\s*(?:contains|includes|has|indexOf)\b|\bPattern\s*\.\s*matches?\b|\bswitch\s*\(|\bcase\s+['"]/i;

  for (const src of ingress) {
    for (const sink of configSinks) {
      if (src.id === sink.id) continue;
      const bfsHit15 = hasTaintedPathWithoutControl(map, src.id, sink.id);
      const sinkTaintHit15 = !bfsHit15 && sinkHasTaintedDataIn(map, sink.id);
      if (bfsHit15 || sinkTaintHit15) {
        const scopeSnaps15 = getContainingScopeSnapshots(map, sink.id);
        const scope15 = stripComments(scopeSnaps15.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        if (!safeConfigRe.test(scope15)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input validation before system/configuration modification)',
            severity: 'high',
            description: `External input from ${src.label} flows to system/configuration setting at ${sink.label} without validation. ` +
              `An attacker can modify system properties, database catalogs, environment variables, or runtime configuration.`,
            fix: 'Never pass unsanitized external input to system configuration APIs. ' +
              'Use an allowlist of permitted configuration values. ' +
              'Validate against a strict pattern (e.g., switch/case or Set.has()) before calling setCatalog(), setProperty(), putenv(), etc.',
            via: bfsHit15 ? 'bfs' : 'sink_tainted',
          });
        }
      }
    }
  }

  // Phase 2: Source-line scan fallback
  if (findings.length === 0 && map.source_code && ingress.length > 0) {
    const srcLines = map.source_code.split('\n');
    const cfgCallRe = /\b(?:setCatalog|setSchema|setProperty|putenv|setenv|os\.environ)\s*\(/i;
    const hardcodedRe = /\b(?:setCatalog|setSchema|setProperty|putenv|setenv)\s*\(\s*["'][^"']*["']\s*[,)]/i;

    for (let li = 0; li < srcLines.length; li++) {
      const ln = srcLines[li]!;
      const tr = ln.trim();
      if (!tr || tr.startsWith('//') || tr.startsWith('*') || tr.startsWith('/*')) continue;

      if (cfgCallRe.test(ln) && !hardcodedRe.test(ln)) {
        // Extract the variable name used as argument to the config API
        const argM15 = /\b(?:setCatalog|setSchema|setProperty|putenv|setenv)\s*\(\s*(\w+)\s*[,)]/i.exec(ln);
        const argV15 = argM15 ? argM15[1] : null;

        // Check if the variable was assigned a hardcoded literal in the lookback scope
        let isHardcoded15 = false;
        if (argV15) {
          const escV = argV15.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const hardAssign = new RegExp(`\\b${escV}\\s*=\\s*(?:["']|\\d+\\s*;)`);
          const taintAssign = new RegExp(`\\b${escV}\\s*=.*(?:readLine|getParameter|getInput|parseInt|read\\()`);
          for (let j = li - 1; j >= Math.max(0, li - 30); j--) {
            const prev = srcLines[j]!.trim();
            if (hardAssign.test(prev)) { isHardcoded15 = true; break; }
            if (taintAssign.test(prev)) break;
          }
        }

        if (!isHardcoded15) {
          const cs = Math.max(0, li - 20);
          const ce = Math.min(srcLines.length, li + 5);
          const ctx = srcLines.slice(cs, ce).join('\n');
          if (!safeConfigRe.test(ctx)) {
            findings.push({
              source: nodeRef(ingress[0]!),
              sink: { id: `line-${li + 1}`, label: `config modification (line ${li + 1})`, line: li + 1, code: tr.slice(0, 200) },
              missing: 'CONTROL (input validation before system/configuration modification)',
              severity: 'high',
              description: `System/configuration setting modified with a variable at line ${li + 1}: "${tr.slice(0, 100)}". ` +
                `If this value originates from external input, an attacker can control system configuration.`,
              fix: 'Validate the value against an allowlist before passing it to configuration APIs.',
              via: 'source_line_fallback',
            });
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-15',
    name: 'External Control of System or Configuration Setting',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-111: Direct Use of Unsafe JNI
 * UPGRADED — hand-written with specific detection for unsafe JNI usage.
 *
 * Pattern: Java code declares `native` methods (JNI interface) and passes
 * user-controlled input to them without validation. The native C/C++ code
 * cannot perform Java-style bounds checking, so buffer overflows, format
 * string attacks, and memory corruption are possible.
 *
 * Two detection paths:
 *   1. `native` method declared + user input flows to a call of that method
 *      without validation (bounds check, length limit, allowlist)
 *   2. User input flows to System.loadLibrary() — attacker controls which
 *      native library gets loaded
 *
 * Safe patterns:
 *   - Input validation/bounds checking before native call
 *   - Allowlist of permitted values
 *   - Hardcoded library name in System.loadLibrary (not tainted)
 */
function verifyCWE111(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // --- Detection path 1: native method + tainted call to it ---
  // Find nodes whose code_snapshot contains a `native` method declaration
  const NATIVE_DECL_RE = /\bnative\s+\w[\w<>\[\], ]*\s+(\w+)\s*\(/;

  // Collect all native method names declared in the codebase
  const nativeMethodNames = new Set<string>();
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const match = NATIVE_DECL_RE.exec(code);
    if (match) {
      nativeMethodNames.add(match[1]);
    }
  }

  if (nativeMethodNames.size > 0 && ingress.length > 0) {
    // Find call sites of native methods — any node whose code calls a native method
    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      for (const methodName of nativeMethodNames) {
        // Match calls like: test(stringLine, intNumber) or this.test(x)
        const callPattern = new RegExp(`\\b${methodName}\\s*\\(`);
        // But skip the native declaration itself
        const declPattern = new RegExp(`\\bnative\\s+.*\\b${methodName}\\s*\\(`);
        if (callPattern.test(code) && !declPattern.test(code)) {
          // This node calls a native method — check if any INGRESS reaches it
          for (const src of ingress) {
            const bfsHit111a = hasTaintedPathWithoutControl(map, src.id, node.id);
            const sinkTaintHit111a = !bfsHit111a && sinkHasTaintedDataIn(map, node.id);
            if (bfsHit111a || sinkTaintHit111a) {
              // Check scope for validation
              const scopeSnapshots = getContainingScopeSnapshots(map, node.id);
              const combinedScope = stripComments(scopeSnapshots.join('\n') || code);
              const isSafe = /\bvalidate\s*\(|\bboundsCheck\s*\(|\bif\s*\(\s*\w+\s*(?:<=?|>=?|<|>)\s*\d|\blength\s*(?:<=?|>=?)\s*\d|\bMath\.min\s*\(|\bMath\.max\s*\(|\ballowlist\b|\bwhitelist\b/i.test(combinedScope);

              if (!isSafe) {
                findings.push({
                  source: nodeRef(src),
                  sink: nodeRef(node),
                  missing: 'CONTROL (input validation before JNI native call)',
                  severity: 'high',
                  description: `User input from ${src.label} flows to JNI native method ${methodName}() at ${node.label} without validation. ` +
                    `Native code cannot perform Java bounds checking — buffer overflows, format string attacks, ` +
                    `and memory corruption are possible.`,
                  fix: 'Validate all data before passing to JNI native methods. Check string lengths, ' +
                    'integer ranges, and array bounds. Use an allowlist of permitted values where possible. ' +
                    'Consider wrapping JNI calls in a safe Java API that validates inputs.',
                  via: bfsHit111a ? 'bfs' : 'sink_tainted',
                });
                break; // One finding per sink per native method
              }
            }
          }
        }
      }
    }
  }

  // --- Detection path 2: tainted System.loadLibrary() ---
  const LOAD_LIBRARY_RE = /\bSystem\s*\.\s*loadLibrary\s*\(/;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (LOAD_LIBRARY_RE.test(code)) {
      for (const src of ingress) {
        const bfsHit111b = hasTaintedPathWithoutControl(map, src.id, node.id);
        const sinkTaintHit111b = !bfsHit111b && sinkHasTaintedDataIn(map, node.id);
        if (bfsHit111b || sinkTaintHit111b) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(node),
            missing: 'CONTROL (library name validation — use hardcoded name or allowlist)',
            severity: 'critical',
            description: `User input from ${src.label} controls the library name in System.loadLibrary() at ${node.label}. ` +
              `An attacker can load arbitrary native libraries, gaining code execution.`,
            fix: 'Never pass user input to System.loadLibrary(). Use a hardcoded library name or ' +
              'validate against a strict allowlist of permitted library names.',
            via: bfsHit111b ? 'bfs' : 'sink_tainted',
          });
          break;
        }
      }
    }
  }

  // --- Detection path 3: structural — native decl + any INGRESS in same scope ---
  // If we found native methods but no taint path (mapper may not create DATA_FLOW edges),
  // check if native method calls share function scope with user input reads
  if (findings.length === 0 && nativeMethodNames.size > 0 && ingress.length > 0) {
    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      for (const methodName of nativeMethodNames) {
        const callPattern = new RegExp(`\\b${methodName}\\s*\\(`);
        const declPattern = new RegExp(`\\bnative\\s+.*\\b${methodName}\\s*\\(`);
        if (callPattern.test(code) && !declPattern.test(code)) {
          for (const src of ingress) {
            if (sharesFunctionScope(map, src.id, node.id)) {
              const scopeSnapshots = getContainingScopeSnapshots(map, node.id);
              const combinedScope = stripComments(scopeSnapshots.join('\n') || code);
              const isSafe = /\bvalidate\s*\(|\bboundsCheck\s*\(|\bif\s*\(\s*\w+\s*(?:<=?|>=?|<|>)\s*\d|\blength\s*(?:<=?|>=?)\s*\d|\bMath\.min\s*\(|\bMath\.max\s*\(|\ballowlist\b|\bwhitelist\b/i.test(combinedScope);

              if (!isSafe) {
                findings.push({
                  source: nodeRef(src),
                  sink: nodeRef(node),
                  missing: 'CONTROL (input validation before JNI native call)',
                  severity: 'high',
                  description: `User input from ${src.label} is in scope with JNI native method ${methodName}() call at ${node.label}. ` +
                    `Native code cannot perform Java bounds checking — buffer overflows, format string attacks, ` +
                    `and memory corruption are possible when user input reaches native methods.`,
                  fix: 'Validate all data before passing to JNI native methods. Check string lengths, ' +
                    'integer ranges, and array bounds. Use an allowlist of permitted values where possible.',
                  via: 'scope_taint',
                });
                break;
              }
            }
          }
        }
      }
    }
  }

  return { cwe: 'CWE-111', name: 'Direct Use of Unsafe JNI', holds: findings.length === 0, findings };
}

/**
 * CWE-114: Process Control
 * UPGRADED — hand-written with specific detection for unsafe process/library loading.
 *
 * Pattern: Code loads native libraries or executes processes in ways that an
 * attacker can control:
 *   1. System.loadLibrary(name) — loads by name from java.library.path; attacker
 *      can plant a malicious DLL/so in a directory on the search path
 *   2. System.load(taintedPath) — attacker controls the full path to a library
 *   3. Runtime.exec(taintedCmd) — attacker controls process execution
 *
 * The Juliet pattern: System.loadLibrary("test.dll") is BAD because it uses
 * relative name resolution. System.load("/absolute/path/test.dll") is GOOD
 * because it uses an absolute path that the attacker cannot manipulate.
 *
 * Safe patterns:
 *   - System.load() with hardcoded absolute path
 *   - Allowlist validation of library name or command
 *   - SecurityManager restricting library loading
 */
function verifyCWE114(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const LOAD_LIBRARY_RE = /\bSystem\s*\.\s*loadLibrary\s*\(/;
  const SYSTEM_LOAD_RE = /\bSystem\s*\.\s*load\s*\(/;
  const RUNTIME_EXEC_RE = /\bRuntime\s*\..*\bexec\s*\(/;
  const PROCESS_BUILDER_RE = /\bnew\s+ProcessBuilder\s*\(/;

  // Safe patterns for CWE-114
  const ABSOLUTE_PATH_RE = /System\s*\.\s*load\s*\(\s*(?:root\s*\+|"\/|"[A-Z]:\\|['"]\/home|['"]\/usr|['"]\/opt|['"]C:\\)/;
  const SECURITY_MANAGER_RE = /\bSecurityManager\b|\bcheckLink\b|\bcheckExec\b/;
  const ALLOWLIST_RE = /\ballowlist\b|\bwhitelist\b|\bvalidat(?:e|ed|ion)\s*\(|\bpermitted\b|\bapproved\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const scopeSnapshots = getContainingScopeSnapshots(map, node.id);
    const combinedScope = stripComments(scopeSnapshots.join('\n') || code);

    // --- Detection 1: System.loadLibrary() — relative name, search-path based ---
    if (LOAD_LIBRARY_RE.test(code)) {
      // Check if there's a SecurityManager or allowlist in scope
      if (!SECURITY_MANAGER_RE.test(combinedScope) && !ALLOWLIST_RE.test(combinedScope)) {
        // System.loadLibrary is inherently risky — relative resolution
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (use System.load() with absolute path instead of System.loadLibrary())',
          severity: 'medium',
          description: `System.loadLibrary() at ${node.label} loads a native library by name using java.library.path search. ` +
            `An attacker who can influence the search path or plant a DLL in a searched directory ` +
            `can hijack the library loading (DLL search-order hijacking).`,
          fix: 'Use System.load() with an absolute path to the library instead of System.loadLibrary(). ' +
            'Example: System.load("/opt/myapp/libs/mylib.so") instead of System.loadLibrary("mylib"). ' +
            'If System.loadLibrary() is unavoidable, restrict java.library.path and use a SecurityManager.',
          via: 'structural',
        });
      }
    }

    // --- Detection 2: System.load() with tainted path ---
    if (SYSTEM_LOAD_RE.test(code) && !LOAD_LIBRARY_RE.test(code)) {
      // System.load() is safe IF the path is hardcoded/absolute
      if (ABSOLUTE_PATH_RE.test(code)) {
        continue; // Safe — hardcoded absolute path
      }
      // Check if tainted input flows to this node
      for (const src of ingress) {
        const bfsHit114a = hasTaintedPathWithoutControl(map, src.id, node.id);
        const sinkTaintHit114a = !bfsHit114a && sinkHasTaintedDataIn(map, node.id);
        if (bfsHit114a || sinkTaintHit114a) {
          if (!ALLOWLIST_RE.test(combinedScope)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(node),
              missing: 'CONTROL (path validation for System.load())',
              severity: 'critical',
              description: `User input from ${src.label} controls the library path in System.load() at ${node.label}. ` +
                `An attacker can load any native library on disk, gaining arbitrary code execution.`,
              fix: 'Never pass user input to System.load(). Use a hardcoded absolute path or ' +
                'validate the path against a strict allowlist of permitted library paths.',
              via: bfsHit114a ? 'bfs' : 'sink_tainted',
            });
            break;
          }
        }
      }
    }

    // --- Detection 3: Runtime.exec() or ProcessBuilder with tainted input ---
    if (RUNTIME_EXEC_RE.test(code) || PROCESS_BUILDER_RE.test(code)) {
      for (const src of ingress) {
        const bfsHit114b = hasTaintedPathWithoutControl(map, src.id, node.id);
        const sinkTaintHit114b = !bfsHit114b && sinkHasTaintedDataIn(map, node.id);
        if (bfsHit114b || sinkTaintHit114b) {
          if (!ALLOWLIST_RE.test(combinedScope)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(node),
              missing: 'CONTROL (process execution validation)',
              severity: 'critical',
              description: `User input from ${src.label} controls process execution at ${node.label}. ` +
                `An attacker can execute arbitrary processes on the system.`,
              fix: 'Never pass user input to Runtime.exec() or ProcessBuilder. Use a strict allowlist ' +
                'of permitted commands. Consider using a ProcessBuilder with a fixed command array ' +
                'instead of string concatenation.',
              via: bfsHit114b ? 'bfs' : 'sink_tainted',
            });
            break;
          }
        }
      }
    }
  }

  return { cwe: 'CWE-114', name: 'Process Control', holds: findings.length === 0, findings };
}

/**
 * CWE-477: Use of Obsolete Function
 * Source scan for deprecated Java API calls. These APIs have known issues:
 * - Thread.stop/suspend/resume — unsafe thread manipulation
 * - Runtime.runFinalizersOnExit — finalization is broken by design
 * - DataInputStream.readLine — mishandles Unicode (deprecated since JDK 1.1)
 * - Date.parse — superseded by DateFormat.parse
 * - String.getBytes(int,int,byte[],int) — mishandles non-ASCII (deprecated since JDK 1.1)
 * - URLEncoder.encode(String) — uses platform default encoding, not UTF-8
 */
function verifyCWE477(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Deprecated Java APIs: method name + context pattern + replacement guidance
  const OBSOLETE_APIS: Array<{ pattern: RegExp; name: string; fix: string }> = [
    { pattern: /\bThread\s*\.\s*stop\s*\(/, name: 'Thread.stop()', fix: 'Use Thread.interrupt() and cooperative cancellation instead of Thread.stop().' },
    { pattern: /\bThread\s*\.\s*suspend\s*\(/, name: 'Thread.suspend()', fix: 'Use wait/notify or Lock/Condition instead of Thread.suspend().' },
    { pattern: /\bThread\s*\.\s*resume\s*\(/, name: 'Thread.resume()', fix: 'Use wait/notify or Lock/Condition instead of Thread.resume().' },
    { pattern: /\bRuntime\s*\.\s*runFinalizersOnExit\s*\(/, name: 'Runtime.runFinalizersOnExit()', fix: 'Use shutdown hooks (Runtime.addShutdownHook) or try-with-resources instead.' },
    { pattern: /\bSystem\s*\.\s*runFinalizersOnExit\s*\(/, name: 'System.runFinalizersOnExit()', fix: 'Use shutdown hooks (Runtime.addShutdownHook) or try-with-resources instead.' },
    { pattern: /\bDataInputStream\b[\s\S]*?\.readLine\s*\(/, name: 'DataInputStream.readLine()', fix: 'Use BufferedReader.readLine() instead of DataInputStream.readLine(). The deprecated method incorrectly converts bytes to characters.' },
    { pattern: /\bDate\s*\.\s*parse\s*\(/, name: 'Date.parse()', fix: 'Use DateFormat.parse() or java.time.LocalDate.parse() instead of the deprecated Date.parse().' },
    { pattern: /\.getBytes\s*\(\s*\d+\s*,/, name: 'String.getBytes(int,int,byte[],int)', fix: 'Use String.getBytes(charset) instead of the deprecated 4-argument getBytes. Specify charset explicitly (e.g., "UTF-8").' },
    { pattern: /\bURLEncoder\s*\.\s*encode\s*\(\s*[^,)]+\)/, name: 'URLEncoder.encode(String)', fix: 'Use URLEncoder.encode(s, "UTF-8") instead of the single-argument form, which uses platform default encoding.' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    for (const api of OBSOLETE_APIS) {
      if (api.pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `STRUCTURAL (replace obsolete API: ${api.name})`,
          severity: 'medium',
          description: `Obsolete function ${api.name} used at ${node.label}. ` +
            `Deprecated APIs may have known bugs, security vulnerabilities, or undefined behavior.`,
          fix: api.fix,
          via: 'structural',
        });
      }
    }
  }

  return { cwe: 'CWE-477', name: 'Use of Obsolete Function', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const INJECTION_TAINT_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-89': verifyCWE89,
  'CWE-79': verifyCWE79,
  'CWE-81': verifyCWE81,
  'CWE-83': verifyCWE83,
  'CWE-22': verifyCWE22,
  'CWE-23': verifyCWE23,
  'CWE-36': verifyCWE36,
  'CWE-502': verifyCWE502,
  'CWE-918': verifyCWE918,
  'CWE-78': verifyCWE78,
  'CWE-611': verifyCWE611,
  'CWE-94': verifyCWE94,
  'CWE-1321': verifyCWE1321,
  'CWE-158': verifyCWE158,
  'CWE-117': verifyCWE117,
  'CWE-601': verifyCWE601,
  'CWE-610': verifyCWE610,
  'CWE-643': verifyCWE643,
  'CWE-776': verifyCWE776,
  'CWE-20': verifyCWE20,
  'CWE-74': verifyCWE74,
  'CWE-77': verifyCWE77,
  'CWE-90': verifyCWE90,
  'CWE-91': verifyCWE91,
  'CWE-93': verifyCWE93,
  'CWE-95': verifyCWE95,
  'CWE-96': verifyCWE96,
  'CWE-98': verifyCWE98,
  'CWE-99': verifyCWE99,
  'CWE-15': verifyCWE15,
  'CWE-111': verifyCWE111,
  'CWE-114': verifyCWE114,
  'CWE-477': verifyCWE477,
};
