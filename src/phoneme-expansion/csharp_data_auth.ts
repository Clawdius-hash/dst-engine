/**
 * Phoneme expansion: C# — Entity Framework, ADO.NET, Dapper, Identity Framework
 * Agent-generated, tested against real patterns
 *
 * Focus: Database access and authentication patterns not already covered
 * in languages/csharp.ts. Specifically targets raw SQL injection vectors,
 * Dapper multi-mapping, Identity token/lockout, and EF change tracking.
 */
export const PHONEMES_CSHARP_DATA_AUTH = {

  // ── STORAGE: EF Core raw SQL reads (FromSqlRaw is the READ counterpart to ExecuteSqlRaw) ──
  // FromSqlRaw accepts interpolated strings that EF does NOT parameterize —
  // $"SELECT * FROM Users WHERE Name = '{name}'" is a live SQL injection vector.
  // The safe alternative (FromSqlInterpolated) IS already in the wildcard set,
  // but FromSqlRaw as a member call is missing.
  'DbContext.Database.SqlQueryRaw': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  // WHY: SqlQueryRaw (EF Core 8+) returns ad-hoc scalar/unmapped results from raw SQL — same injection surface as ExecuteSqlRaw but for reads.

  // ── STORAGE: ADO.NET SqlDataAdapter (bulk dataset fill from raw queries) ──
  'SqlDataAdapter.Fill': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  // WHY: SqlDataAdapter.Fill executes a SQL command and fills a DataSet/DataTable — if CommandText is user-controlled, it's a bulk SQL injection vector that returns entire result sets.

  // ── STORAGE: Dapper multi-mapping and multiple result set methods ──
  'connection.QueryMultiple': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  // WHY: Dapper.QueryMultiple executes multiple SQL statements in one roundtrip — a SQL injection here can chain arbitrary statements (SELECT + DROP, etc).

  'connection.ExecuteScalar': { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },
  // WHY: Dapper.ExecuteScalar returns the first column of the first row — commonly used for COUNT/EXISTS with inline SQL, easy to overlook for parameterization.

  // ── STORAGE: EF Core Database.BeginTransaction (transaction boundary) ──
  'DbContext.Database.BeginTransactionAsync': { nodeType: 'STORAGE', subtype: 'db_write', tainted: false },
  // WHY: Explicit transactions often wrap raw SQL blocks; marking the boundary helps the scanner find unparameterized SQL executed between Begin/Commit.

  // ── AUTH: Identity password hashing/validation ──
  'UserManager.ChangePasswordAsync': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  // WHY: Password change operations are high-value auth events — if the old password check is bypassed or the new password isn't validated, it's a credential takeover.

  'UserManager.ResetPasswordAsync': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  // WHY: Password reset with token — if the token validation is weak or the reset endpoint lacks rate-limiting, it's an account takeover vector.

  'UserManager.GeneratePasswordResetTokenAsync': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  // WHY: Generates the reset token itself — if this flows to EGRESS (email/response) without HTTPS or expiry, the token can be intercepted.

  // ── AUTH: Identity lockout (anti-brute-force) ──
  'UserManager.AccessFailedAsync': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  // WHY: Increments failed login count; if this call is missing from the login flow, there's no brute-force protection — the scanner should flag login paths that skip it.

  // ── AUTH: SignInManager two-factor flow ──
  'SignInManager.TwoFactorSignInAsync': { nodeType: 'AUTH', subtype: 'authenticate', tainted: false },
  // WHY: The 2FA verification step — if the login flow has PasswordSignInAsync but no TwoFactorSignInAsync, 2FA may be configured but never enforced.

} as const;

// ── NOTES ──
//
// DANGEROUS PATTERN NOBODY TALKS ABOUT:
// DbContext.Database.SqlQueryRaw<T>() (EF Core 8+) is the read-side twin of ExecuteSqlRaw.
// Developers who learned "use FromSqlInterpolated for safety" don't realize SqlQueryRaw
// has the same raw-string SQL injection surface but for scalar/unmapped type queries.
// It won't appear in FromSql* searches. Static analyzers that only grep for
// "ExecuteSqlRaw" miss this entirely.
//
// EXISTING ENTRY NOTE:
// 'DbContext.Database.ExecuteSqlRaw' in csharp.ts is typed STORAGE/db_write — correct.
// But it should arguably also be flagged as a taint SINK (not source), since user input
// flowing into its string parameter is the actual vulnerability. The tainted:false is
// correct (it doesn't PRODUCE tainted data), but a separate sink annotation system
// would catch the inflow. The sinkPatterns regex in csharp.ts partially covers this
// with the CWE-89 pattern.
