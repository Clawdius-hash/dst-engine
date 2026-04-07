/**
 * Phoneme expansion: Java — JDBC deep patterns, Hibernate HQL/Criteria, JPA native queries, connection pools
 * Agent-generated, tested against real patterns
 *
 * WHY THESE 10:
 * The base java.ts covers basic JDBC (Statement, PreparedStatement, ResultSet.getString/getInt/getLong),
 * basic JPA (EntityManager CRUD + createQuery/createNativeQuery), Spring Data repository methods,
 * JdbcTemplate, and NamedParameterJdbcTemplate. But it has critical blind spots:
 *
 *   1. CallableStatement — executes stored procedures via JDBC. If the procedure name or
 *      parameters are built from user input, it's SQL injection (CWE-89). Stored procedures
 *      are a CLASSIC enterprise blind spot — devs assume "it's a proc, it's safe" but
 *      dynamic SQL inside procedures or tainted procedure names = injection.
 *
 *   2. ResultSet as tainted source — the base dict marks ResultSet.getString as STORAGE/db_read
 *      with tainted:false. This misses SECOND-ORDER SQL INJECTION: attacker stores payload in DB
 *      via one path, then another query reads it from ResultSet and concatenates it into SQL.
 *      ResultSet data MUST be treated as a tainted source. getObject/getDate/getTimestamp/
 *      getBoolean/getDouble/getFloat/getBigDecimal/getBytes/getBlob/getClob are all missing.
 *
 *   3. Hibernate Session — the native Hibernate API. Session.createQuery() takes HQL which is
 *      string-concatenation-vulnerable just like SQL. Session.createSQLQuery() (deprecated) and
 *      Session.createNativeQuery() bypass HQL entirely — raw SQL. The scanner must flag these
 *      distinctly from EntityManager because Hibernate Session is still heavily used in legacy
 *      codebases (and even new ones via Spring's @Transactional + SessionFactory pattern).
 *
 *   4. Hibernate Criteria API — CriteriaBuilder/CriteriaQuery is the type-safe JPA way to build
 *      queries. Generally safe from injection (it's a builder, not string concat), but the scanner
 *      needs to recognize it as STORAGE to track data flow through criteria-built queries.
 *
 *   5. Connection pool configuration — HikariCP (default in Spring Boot 2+), C3P0, Apache DBCP.
 *      These are RESOURCE nodes (finite capacity). Misconfigured pool = connection exhaustion =
 *      denial of service. The scanner should flag pool setup for review.
 *
 *   6. Statement.addBatch/executeBatch — batch operations bypass individual statement logging
 *      and can accumulate tainted SQL. If addBatch receives concatenated strings, each batch
 *      entry is an injection point.
 *
 *   7. Hibernate Session.get/load — read by primary key. Not injection-vulnerable (key is typed)
 *      but the returned entity carries DB data that becomes a tainted source downstream.
 *
 *   8. Session.save/saveOrUpdate/update/delete — Hibernate write operations. The scanner needs
 *      to see these as STORAGE/db_write to complete the data flow graph.
 *
 *   9. CallableStatement.registerOutParameter — marks output parameters for stored procedures.
 *      These are how tainted data RETURNS from a stored procedure — a source, not a sink.
 *
 *  10. EntityManager.createStoredProcedureQuery — JPA 2.1 stored procedure support. Same risk
 *      as CallableStatement but through the JPA API.
 *
 * CRITICAL FINDING: ResultSet.getString/getInt/getLong are in the base dict as tainted:false.
 * This is a security-relevant decision. I'm adding the MISSING ResultSet methods but marking
 * them tainted:true because second-order injection is real and the scanner should track DB
 * output as potentially tainted. The base entries should arguably be changed too, but that's
 * outside the 10-entry scope — noting it in FINDINGS below.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JAVA_JDBC_HIBERNATE: Record<string, CalleePattern> = {

  // ── 1. CallableStatement — stored procedure execution ───────────────────
  // CallableStatement cs = conn.prepareCall("{call get_user(?)}");
  // If the procedure name or call string is built from user input, it's SQLi.
  // Connection.prepareCall creates the CallableStatement — this is the entry point.
  // executeQuery/executeUpdate/execute run the actual procedure.
  'Connection.prepareCall':               { nodeType: 'STORAGE', subtype: 'db_stored_proc', tainted: false },
  'CallableStatement.executeQuery':       { nodeType: 'STORAGE', subtype: 'db_stored_proc', tainted: false },
  'CallableStatement.executeUpdate':      { nodeType: 'STORAGE', subtype: 'db_stored_proc', tainted: false },
  'CallableStatement.execute':            { nodeType: 'STORAGE', subtype: 'db_stored_proc', tainted: false },

  // ── 2. CallableStatement output — tainted data from stored procedures ───
  // After executing a stored procedure, the caller reads OUT parameters.
  // registerOutParameter declares the output slot; getXxx() reads the value.
  // This data comes from the database and should be treated as tainted for
  // second-order injection tracking.
  'CallableStatement.registerOutParameter': { nodeType: 'STORAGE', subtype: 'db_stored_proc', tainted: false },
  'CallableStatement.getString':          { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'CallableStatement.getInt':             { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'CallableStatement.getObject':          { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },

  // ── 3. ResultSet — missing methods (second-order injection sources) ─────
  // The base dict has getString/getInt/getLong/next. These are MISSING:
  'ResultSet.getObject':                  { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'ResultSet.getBoolean':                 { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'ResultSet.getDouble':                  { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'ResultSet.getFloat':                   { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'ResultSet.getDate':                    { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'ResultSet.getTimestamp':               { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'ResultSet.getBigDecimal':              { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'ResultSet.getBytes':                   { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'ResultSet.getBlob':                    { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },
  'ResultSet.getClob':                    { nodeType: 'INGRESS', subtype: 'db_result', tainted: true },

  // ── 4. Hibernate Session — native API ───────────────────────────────────
  // Session.createQuery() takes HQL — vulnerable to HQL injection if concatenated.
  // Session.createNativeQuery() / createSQLQuery() take raw SQL — injection surface.
  // Session.get()/load() are safe reads by typed primary key.
  'Session.createQuery':                  { nodeType: 'STORAGE', subtype: 'hql_query', tainted: false },
  'Session.createSQLQuery':               { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'Session.createNativeQuery':            { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'Session.get':                          { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'Session.load':                         { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'Session.save':                         { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'Session.saveOrUpdate':                 { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'Session.update':                       { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'Session.delete':                       { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'Session.flush':                        { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'Session.beginTransaction':             { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

  // ── 5. JPA Criteria API — type-safe query building ──────────────────────
  // CriteriaBuilder is obtained from EntityManager; CriteriaQuery is built from it.
  // Generally injection-safe (it's a builder pattern, not string concat), but the
  // scanner needs to see this as STORAGE to track the data flow properly.
  'EntityManager.getCriteriaBuilder':     { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  'CriteriaBuilder.createQuery':          { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },

  // ── 6. Statement batch operations ───────────────────────────────────────
  // addBatch accumulates SQL; executeBatch runs all at once.
  // If addBatch receives concatenated strings, every entry is an injection point.
  'Statement.addBatch':                   { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'Statement.executeBatch':               { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.addBatch':           { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.executeBatch':       { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

  // ── 7. JPA StoredProcedureQuery — JPA 2.1 stored procedure support ──────
  // EntityManager.createStoredProcedureQuery("proc_name") — same risk as CallableStatement.
  'EntityManager.createStoredProcedureQuery': { nodeType: 'STORAGE', subtype: 'db_stored_proc', tainted: false },

  // ── 8. Connection pool configuration — RESOURCE nodes ───────────────────
  // Misconfigured pools = connection exhaustion = DoS. These are the pool creation
  // entry points for the 3 major Java connection pool libraries.
  'HikariDataSource.setMaximumPoolSize':  { nodeType: 'RESOURCE', subtype: 'connection_pool', tainted: false },
  'HikariDataSource.setMinimumIdle':      { nodeType: 'RESOURCE', subtype: 'connection_pool', tainted: false },
  'HikariDataSource.getConnection':       { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },
  'ComboPooledDataSource.setMaxPoolSize': { nodeType: 'RESOURCE', subtype: 'connection_pool', tainted: false },
  'BasicDataSource.setMaxTotal':          { nodeType: 'RESOURCE', subtype: 'connection_pool', tainted: false },

  // ── 9. PreparedStatement parameter setters (extended) ───────────────────
  // The base dict has setString/setInt. These are missing but security-relevant
  // because they represent parameterized query binding — the SAFE pattern.
  'PreparedStatement.setLong':            { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setDouble':          { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setObject':          { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setDate':            { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setTimestamp':       { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setNull':            { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setBytes':           { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setBlob':            { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setClob':            { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  'PreparedStatement.setBoolean':         { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },

  // ── 10. Hibernate SessionFactory — the RESOURCE for Session creation ────
  // SessionFactory is the heavyweight object that manages the connection pool
  // internally. openSession/getCurrentSession are how code gets a Session.
  'SessionFactory.openSession':           { nodeType: 'RESOURCE', subtype: 'session_factory', tainted: false },
  'SessionFactory.getCurrentSession':     { nodeType: 'RESOURCE', subtype: 'session_factory', tainted: false },

} as const;

// ─── FINDINGS ────────────────────────────────────────────────────────────
//
// 1. CRITICAL: ResultSet.getString/getInt/getLong in the base dict are marked
//    tainted:false. For first-order injection tracking this is correct (the data
//    is being READ from DB, not injected INTO DB). But for second-order injection,
//    ResultSet data IS a tainted source — attacker stored "Robert'; DROP TABLE--"
//    in a name field, and now getString("name") returns it. The new ResultSet
//    entries above use tainted:true and nodeType INGRESS (not STORAGE) because
//    they represent data ENTERING the application from an external store.
//    RECOMMENDATION: Change the 3 existing ResultSet entries to INGRESS/db_result/
//    tainted:true. This would enable the scanner to track second-order SQLi flows.
//
// 2. IMPORTANT: Statement.executeQuery takes a raw SQL String argument. If that
//    string is built from concatenation, it's CWE-89. PreparedStatement.executeQuery
//    takes NO argument (the SQL was already set in prepareStatement). The base dict
//    marks both as STORAGE/db_read with tainted:false — this is technically correct
//    for the CALL ITSELF, but the scanner should flag Statement.executeQuery(str)
//    as a SQL injection sink when 'str' is tainted. The difference:
//      stmt.executeQuery("SELECT * FROM users WHERE id=" + userId)  // VULNERABLE
//      pstmt.executeQuery()  // SAFE (parameterized)
//    The phoneme can't express this distinction — it would need the scanner to check
//    whether the argument to executeQuery is tainted. Noting for scanner-level rules.
//
// 3. SESSION vs ENTITYMANAGER: Hibernate's Session and JPA's EntityManager are often
//    used interchangeably, but Session exposes createSQLQuery() (deprecated since
//    Hibernate 5.2, replaced by createNativeQuery()) which is a raw SQL surface.
//    The scanner should flag Session.createSQLQuery specifically as a legacy injection
//    risk and suggest migration to createNativeQuery with parameterized queries.
//
// 4. MYBATIS EXTENSION: The base dict + spring_security expansion cover
//    SqlSession.selectOne/selectList. Missing: SqlSession.selectMap, SqlSession.insert,
//    SqlSession.update, SqlSession.delete. These are the other CRUD operations that
//    execute XML-mapped queries. Kept outside the 10-entry scope but should be added.
//
// 5. CONNECTION POOL DoS: HikariCP defaults to maximumPoolSize=10. If the application
//    has a query that holds connections long (e.g., streaming ResultSet), 10 concurrent
//    requests can exhaust the pool. The RESOURCE node type is the right classification
//    for this — the scanner should flag pool configuration for review.
