/**
 * Manifest Generator — derives a DSTManifest from a BuildPlan.
 *
 * The thesis: the plan IS the intent.
 * The planner tells us what the app should do.
 * The manifest encodes that.
 * DST finds the delta.
 * One mode. One manifest. One truth.
 *
 * The BuildPlan contains:
 *   - prompt: what the user asked for
 *   - files: what files get created
 *   - assignments: who writes what
 *   - contracts: cross-file APIs (function names, params, exports/imports)
 *   - researchNeeded / researchQueries: what external data the app uses
 *
 * From this, we infer:
 *   - Framework (Express, Fastify, Koa, Hapi, Next.js, NestJS) → INGRESS/EGRESS patterns
 *   - External APIs (Spotify, Stripe, weather, etc.) → EXTERNAL sinks
 *   - Database/ORM (Prisma, Sequelize, Knex, Mongoose, raw SQL) → STORAGE patterns
 *   - Auth patterns (jwt, bcrypt, passport, sessions) → AUTH patterns
 *   - Sensitive fields (price, balance, role, permissions) → data_origins
 */

import type { DSTManifest } from './scan';
import type { BuildPlan } from '../pipeline/conductor';

// ---------------------------------------------------------------------------
// Framework detection
// ---------------------------------------------------------------------------

interface FrameworkSignal {
  name: string;
  /** Patterns that indicate this framework in file names, contracts, or prompt */
  filePatterns: RegExp[];
  promptPatterns: RegExp[];
  contractPatterns: RegExp[];
  /** Intentional sinks this framework introduces */
  intentionalSinks: DSTManifest['intentional_sinks'];
}

const FRAMEWORKS: FrameworkSignal[] = [
  {
    name: 'express',
    // NOTE: app.(js|ts) is too generic — half the web uses it. Only match explicitly
    // Express-named files, server files, route directories, or middleware directories.
    filePatterns: [/express/i, /server\.(js|ts)$/i, /routes?\//i, /middleware\//i],
    promptPatterns: [/\bexpress\b/i, /\bexpress\.js\b/i, /\bexpress\s+server\b/i, /\brest\s*api\b/i, /\bapi\s+server\b/i],
    contractPatterns: [/^app$/i, /^router$/i, /^middleware$/i, /Router$/],
    intentionalSinks: [
      {
        files: ['*'],
        patterns: ['res\\.send', 'res\\.json', 'res\\.render', 'res\\.redirect'],
        type: 'EGRESS',
        reason: 'Express HTTP responses are intentional output',
      },
      {
        files: ['*'],
        patterns: ['req\\.body', 'req\\.params', 'req\\.query', 'req\\.headers'],
        type: 'INGRESS',
        reason: 'Express request data is the intentional input surface',
      },
    ],
  },
  {
    name: 'fastify',
    filePatterns: [/fastify/i, /plugins?\//i],
    promptPatterns: [/\bfastify\b/i],
    contractPatterns: [/^fastify$/i, /^reply$/i, /Plugin$/],
    intentionalSinks: [
      {
        files: ['*'],
        patterns: ['reply\\.send', 'reply\\.code', 'reply\\.redirect'],
        type: 'EGRESS',
        reason: 'Fastify reply methods are intentional output',
      },
      {
        files: ['*'],
        patterns: ['request\\.body', 'request\\.params', 'request\\.query'],
        type: 'INGRESS',
        reason: 'Fastify request data is the intentional input surface',
      },
    ],
  },
  {
    name: 'koa',
    filePatterns: [/koa/i],
    promptPatterns: [/\bkoa\b/i],
    contractPatterns: [/^ctx$/i, /^koaRouter$/i],
    intentionalSinks: [
      {
        files: ['*'],
        patterns: ['ctx\\.body', 'ctx\\.status', 'ctx\\.redirect'],
        type: 'EGRESS',
        reason: 'Koa context response is intentional output',
      },
      {
        files: ['*'],
        patterns: ['ctx\\.request', 'ctx\\.params', 'ctx\\.query'],
        type: 'INGRESS',
        reason: 'Koa context request data is the intentional input surface',
      },
    ],
  },
  {
    name: 'hapi',
    filePatterns: [/hapi/i],
    promptPatterns: [/\bhapi\b/i, /\b@hapi\b/i],
    contractPatterns: [/^server$/i, /^toolkit$/i],
    intentionalSinks: [
      {
        files: ['*'],
        patterns: ['h\\.response', 'h\\.redirect', 'h\\.view'],
        type: 'EGRESS',
        reason: 'Hapi response toolkit is intentional output',
      },
      {
        files: ['*'],
        patterns: ['request\\.payload', 'request\\.params', 'request\\.query'],
        type: 'INGRESS',
        reason: 'Hapi request data is the intentional input surface',
      },
    ],
  },
  {
    name: 'nextjs',
    filePatterns: [/next\.config/i, /pages?\//i, /app\//i, /api\//i],
    promptPatterns: [/\bnext\.?js\b/i, /\bnext\s+app\b/i, /\bapp\s+router\b/i],
    contractPatterns: [/^NextResponse$/i, /^NextRequest$/i, /^getServerSideProps$/i, /^getStaticProps$/i],
    intentionalSinks: [
      {
        files: ['*'],
        patterns: ['NextResponse\\.json', 'NextResponse\\.redirect'],
        type: 'EGRESS',
        reason: 'Next.js responses are intentional output',
      },
    ],
  },
  {
    name: 'nestjs',
    filePatterns: [/\.controller\.(ts|js)$/i, /\.module\.(ts|js)$/i, /\.service\.(ts|js)$/i, /\.guard\.(ts|js)$/i],
    promptPatterns: [/\bnestjs\b/i, /\bnest\.?js\b/i, /\bnest\s+app\b/i],
    contractPatterns: [/Controller$/i, /Service$/i, /Module$/i, /Guard$/i],
    intentionalSinks: [
      {
        files: ['*'],
        patterns: ['response\\.json', 'response\\.send', 'response\\.status'],
        type: 'EGRESS',
        reason: 'NestJS responses are intentional output (Express under the hood)',
      },
    ],
  },
];

// ---------------------------------------------------------------------------
// External API detection
// ---------------------------------------------------------------------------

interface ExternalAPISignal {
  name: string;
  promptPatterns: RegExp[];
  contractPatterns: RegExp[];
  queryPatterns: RegExp[];
  intentionalSinks: DSTManifest['intentional_sinks'];
}

const EXTERNAL_APIS: ExternalAPISignal[] = [
  {
    name: 'spotify',
    promptPatterns: [/\bspotify\b/i],
    contractPatterns: [/spotify/i],
    queryPatterns: [/spotify/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['fetch', 'axios', 'http\\.request', 'spotify'],
      type: 'EXTERNAL',
      reason: 'App intentionally calls the Spotify API',
    }],
  },
  {
    name: 'stripe',
    promptPatterns: [/\bstripe\b/i, /\bpayment/i],
    contractPatterns: [/stripe/i, /payment/i, /checkout/i],
    queryPatterns: [/stripe/i, /payment.*api/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['stripe', 'fetch', 'axios'],
      type: 'EXTERNAL',
      reason: 'App intentionally calls the Stripe payment API',
    }],
  },
  {
    name: 'openai',
    promptPatterns: [/\bopenai\b/i, /\bgpt\b/i, /\bchatgpt\b/i, /\bai\s+api\b/i],
    contractPatterns: [/openai/i, /chatCompletion/i, /gpt/i],
    queryPatterns: [/openai/i, /gpt.*api/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['openai', 'fetch', 'axios'],
      type: 'EXTERNAL',
      reason: 'App intentionally calls the OpenAI API',
    }],
  },
  {
    name: 'weather',
    promptPatterns: [/\bweather\b/i],
    contractPatterns: [/weather/i, /forecast/i],
    queryPatterns: [/weather/i, /forecast/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['fetch', 'axios', 'http\\.request'],
      type: 'EXTERNAL',
      reason: 'App intentionally calls a weather API',
    }],
  },
  {
    name: 'twilio',
    promptPatterns: [/\btwilio\b/i, /\bsms\b/i],
    contractPatterns: [/twilio/i, /sms/i, /message/i],
    queryPatterns: [/twilio/i, /sms.*api/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['twilio', 'fetch', 'axios'],
      type: 'EXTERNAL',
      reason: 'App intentionally calls the Twilio messaging API',
    }],
  },
  {
    name: 'sendgrid',
    promptPatterns: [/\bsendgrid\b/i, /\bemail\s+api\b/i],
    contractPatterns: [/sendgrid/i, /email/i, /mailer/i],
    queryPatterns: [/sendgrid/i, /email.*api/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['sendgrid', 'fetch', 'axios', 'nodemailer'],
      type: 'EXTERNAL',
      reason: 'App intentionally sends email via API',
    }],
  },
  {
    name: 'firebase',
    promptPatterns: [/\bfirebase\b/i, /\bfirestore\b/i],
    contractPatterns: [/firebase/i, /firestore/i],
    queryPatterns: [/firebase/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['firebase', 'firestore', 'fetch'],
      type: 'EXTERNAL',
      reason: 'App intentionally uses Firebase services',
    }],
  },
  {
    name: 'aws',
    promptPatterns: [/\baws\b/i, /\bs3\b/i, /\bdynamo\b/i, /\blambda\b/i],
    contractPatterns: [/aws/i, /s3/i, /dynamo/i, /lambda/i],
    queryPatterns: [/aws/i, /amazon.*api/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['aws', 's3', 'dynamodb', 'lambda', 'fetch'],
      type: 'EXTERNAL',
      reason: 'App intentionally uses AWS services',
    }],
  },
  {
    name: 'generic-http',
    promptPatterns: [/\bapi\b/i, /\bfetch\b/i, /\bhttp\b/i, /\brest\b/i, /\bendpoint\b/i],
    contractPatterns: [/fetch/i, /api/i, /client/i, /http/i],
    queryPatterns: [/api/i, /endpoint/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['fetch', 'axios', 'http\\.request', 'https\\.request'],
      type: 'EXTERNAL',
      reason: 'App intentionally makes HTTP requests to external APIs',
    }],
  },
];

// ---------------------------------------------------------------------------
// Database / ORM detection
// ---------------------------------------------------------------------------

interface DatabaseSignal {
  name: string;
  promptPatterns: RegExp[];
  contractPatterns: RegExp[];
  filePatterns: RegExp[];
  intentionalSinks: DSTManifest['intentional_sinks'];
}

const DATABASES: DatabaseSignal[] = [
  {
    name: 'prisma',
    promptPatterns: [/\bprisma\b/i],
    contractPatterns: [/prisma/i, /PrismaClient/i],
    filePatterns: [/prisma/i, /schema\.prisma/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['prisma', 'findMany', 'findUnique', 'create', 'update', 'delete'],
      type: 'STORAGE',
      reason: 'App uses Prisma ORM for database operations',
    }],
  },
  {
    name: 'sequelize',
    promptPatterns: [/\bsequelize\b/i],
    contractPatterns: [/sequelize/i, /Sequelize/i],
    filePatterns: [/models?\//i, /sequelize/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['sequelize', 'findAll', 'findOne', 'create', 'update', 'destroy'],
      type: 'STORAGE',
      reason: 'App uses Sequelize ORM for database operations',
    }],
  },
  {
    name: 'mongoose',
    promptPatterns: [/\bmongoose\b/i, /\bmongodb\b/i, /\bmongo\b/i],
    contractPatterns: [/mongoose/i, /Schema$/i, /Model$/i],
    filePatterns: [/models?\//i, /mongoose/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['mongoose', 'find', 'findById', 'save', 'insertMany'],
      type: 'STORAGE',
      reason: 'App uses Mongoose ODM for MongoDB operations',
    }],
  },
  {
    name: 'knex',
    promptPatterns: [/\bknex\b/i],
    contractPatterns: [/knex/i],
    filePatterns: [/knex/i, /migrations?\//i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['knex', 'select', 'insert', 'update', 'delete', 'raw'],
      type: 'STORAGE',
      reason: 'App uses Knex query builder for database operations',
    }],
  },
  {
    name: 'typeorm',
    promptPatterns: [/\btypeorm\b/i],
    contractPatterns: [/typeorm/i, /Repository$/i, /Entity$/i],
    filePatterns: [/entity\//i, /typeorm/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['typeorm', 'getRepository', 'find', 'save', 'createQueryBuilder'],
      type: 'STORAGE',
      reason: 'App uses TypeORM for database operations',
    }],
  },
  {
    name: 'sql-raw',
    promptPatterns: [/\bsql\b/i, /\bdatabase\b/i, /\bsqlite\b/i, /\bpostgres\b/i, /\bmysql\b/i],
    contractPatterns: [/db$/i, /database/i, /query/i, /pool$/i],
    filePatterns: [/db\.(js|ts)$/i, /database\.(js|ts)$/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['query', 'execute', 'prepare'],
      type: 'STORAGE',
      reason: 'App uses raw SQL database queries',
    }],
  },
];

// ---------------------------------------------------------------------------
// Auth pattern detection
// ---------------------------------------------------------------------------

interface AuthSignal {
  name: string;
  promptPatterns: RegExp[];
  contractPatterns: RegExp[];
  filePatterns: RegExp[];
  intentionalSinks: DSTManifest['intentional_sinks'];
}

const AUTH_PATTERNS: AuthSignal[] = [
  {
    name: 'jwt',
    promptPatterns: [/\bjwt\b/i, /\bjson\s*web\s*token/i, /\btoken[- ]?based\s+auth/i],
    contractPatterns: [/jwt/i, /token/i, /auth/i, /verify/i],
    filePatterns: [/auth/i, /jwt/i, /token/i, /middleware/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['jwt\\.sign', 'jwt\\.verify', 'jsonwebtoken'],
      type: 'AUTH',
      reason: 'App uses JWT for authentication',
    }],
  },
  {
    name: 'bcrypt',
    promptPatterns: [/\bbcrypt\b/i, /\bpassword\s+hash/i],
    contractPatterns: [/bcrypt/i, /hash/i, /password/i],
    filePatterns: [/auth/i, /user/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['bcrypt\\.compare', 'bcrypt\\.hash', 'bcrypt\\.genSalt'],
      type: 'AUTH',
      reason: 'App uses bcrypt for password hashing',
    }],
  },
  {
    name: 'passport',
    promptPatterns: [/\bpassport\b/i, /\boauth\b/i, /\bsocial\s+login\b/i],
    contractPatterns: [/passport/i, /strategy/i, /oauth/i],
    filePatterns: [/passport/i, /auth/i, /strategy/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['passport', 'authenticate', 'strategy'],
      type: 'AUTH',
      reason: 'App uses Passport.js for authentication',
    }],
  },
  {
    name: 'session',
    promptPatterns: [/\bsession\b/i, /\bcookie[- ]?based\s+auth/i],
    contractPatterns: [/session/i, /cookie/i],
    filePatterns: [/session/i],
    intentionalSinks: [{
      files: ['*'],
      patterns: ['session', 'cookie', 'express-session'],
      type: 'AUTH',
      reason: 'App uses session-based authentication',
    }],
  },
];

// ---------------------------------------------------------------------------
// Sensitive field detection
// ---------------------------------------------------------------------------

interface SensitiveFieldPattern {
  field: string;
  patterns: RegExp[];
  expected_source: 'STORAGE' | 'META' | 'AUTH';
  reason: string;
}

const SENSITIVE_FIELDS: SensitiveFieldPattern[] = [
  {
    field: 'price',
    patterns: [/\bprices?\b/i, /\bpricing\b/i, /\bcosts?\b/i, /\bamounts?\b/i, /\bpayments?\b/i, /\btotals?\b/i],
    expected_source: 'STORAGE',
    reason: 'Prices must come from the database, never from user input',
  },
  {
    field: 'balance',
    patterns: [/\bbalances?\b/i, /\bcredits?\b/i, /\bwallets?\b/i],
    expected_source: 'STORAGE',
    reason: 'Account balances must come from the database',
  },
  {
    field: 'role',
    patterns: [/\broles?\b/i, /\bisAdmin\b/i, /\bis_admin\b/i, /\bprivileges?\b/i, /\badmin\b/i],
    expected_source: 'STORAGE',
    reason: 'User roles must come from the database, not from request body',
  },
  {
    field: 'permissions',
    patterns: [/permissions?/i, /\baccess[_-]?levels?\b/i, /\bscopes?\b/i],
    expected_source: 'STORAGE',
    reason: 'Permission sets must come from the database or auth token',
  },
  {
    field: 'quantity',
    patterns: [/\bquantit(y|ies)\b/i, /\bstock\b/i, /\binventor(y|ies)\b/i],
    expected_source: 'STORAGE',
    reason: 'Inventory quantities must come from the database',
  },
  {
    field: 'discount',
    patterns: [/\bdiscounts?\b/i, /\bcoupons?\b/i, /\bpromo/i],
    expected_source: 'STORAGE',
    reason: 'Discount values must be validated server-side',
  },
];

// ---------------------------------------------------------------------------
// Core generator
// ---------------------------------------------------------------------------

/**
 * Generate a DSTManifest from a BuildPlan.
 *
 * Analyzes the plan's prompt, files, contracts, and research queries
 * to infer what the app is supposed to do. Returns a manifest that
 * DST uses to distinguish intentional behavior from vulnerabilities.
 */
export function generateManifest(buildPlan: BuildPlan): DSTManifest {
  const corpus = buildCorpus(buildPlan);

  const detectedFrameworks = detectFrameworks(corpus);
  const detectedAPIs = detectExternalAPIs(corpus);
  const detectedDatabases = detectDatabases(corpus);
  const detectedAuth = detectAuthPatterns(corpus);
  const detectedSensitiveFields = detectSensitiveFields(corpus);

  // Collect intentional sinks from all detected patterns
  const intentional_sinks: DSTManifest['intentional_sinks'] = [];

  for (const fw of detectedFrameworks) {
    intentional_sinks.push(...fw.intentionalSinks);
  }
  for (const api of detectedAPIs) {
    intentional_sinks.push(...api.intentionalSinks);
  }
  for (const db of detectedDatabases) {
    intentional_sinks.push(...db.intentionalSinks);
  }
  for (const auth of detectedAuth) {
    intentional_sinks.push(...auth.intentionalSinks);
  }

  // Scope intentional sinks to the actual files in the plan
  const scopedSinks = scopeSinksToFiles(intentional_sinks, buildPlan.files);

  // Build data_origins from sensitive fields
  const data_origins: DSTManifest['data_origins'] = detectedSensitiveFields.map(sf => ({
    field: sf.field,
    expected_source: sf.expected_source,
    reason: sf.reason,
  }));

  // Build the app name from the prompt
  const appName = deriveAppName(buildPlan.prompt);

  return {
    name: appName,
    intentional_sinks: scopedSinks,
    data_origins: data_origins.length > 0 ? data_origins : undefined,
    scan_policy: {
      cwes: 'hand_written',
      exclude_intentional: true,
      severity_threshold: 'high',
    },
  };
}

// ---------------------------------------------------------------------------
// Corpus builder — unified text block for pattern matching
// ---------------------------------------------------------------------------

interface Corpus {
  prompt: string;
  files: string[];
  contractNames: string[];
  contractParams: string[];
  researchQueries: string[];
  fullText: string; // everything concatenated for broad matching
}

function buildCorpus(plan: BuildPlan): Corpus {
  const contractNames = plan.contracts.map(c => c.name);
  const contractParams = plan.contracts.flatMap(c => c.params ?? []);
  const researchQueries = plan.researchQueries ?? [];

  const fullText = [
    plan.prompt,
    ...plan.files,
    ...contractNames,
    ...contractParams,
    ...researchQueries,
  ].join(' ');

  return {
    prompt: plan.prompt,
    files: plan.files,
    contractNames,
    contractParams,
    researchQueries,
    fullText,
  };
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

function detectFrameworks(corpus: Corpus): FrameworkSignal[] {
  const detected: FrameworkSignal[] = [];

  for (const fw of FRAMEWORKS) {
    let matched = false;

    // Check prompt
    if (fw.promptPatterns.some(p => p.test(corpus.prompt))) {
      matched = true;
    }

    // Check file names
    if (!matched && corpus.files.some(f => fw.filePatterns.some(p => p.test(f)))) {
      matched = true;
    }

    // Check contract names
    if (!matched && corpus.contractNames.some(n => fw.contractPatterns.some(p => p.test(n)))) {
      matched = true;
    }

    if (matched) {
      detected.push(fw);
    }
  }

  // If no framework detected but files suggest a server, default to Express.
  // Only trigger when both file patterns AND prompt suggest server-side work.
  // Do NOT trigger for pure frontend apps (e.g. "calculator UI" with app.js).
  if (detected.length === 0) {
    const hasServerFiles = corpus.files.some(f =>
      /server\.(js|ts)$/i.test(f) || /routes?\//i.test(f)
    );
    const hasServerPrompt = /\b(server|backend|api|endpoint|route|express|middleware)\b/i.test(corpus.prompt);
    if (hasServerFiles && hasServerPrompt) {
      detected.push(FRAMEWORKS[0]!); // Express as default
    }
  }

  return detected;
}

function detectExternalAPIs(corpus: Corpus): ExternalAPISignal[] {
  const detected: ExternalAPISignal[] = [];

  for (const api of EXTERNAL_APIS) {
    let matched = false;

    if (api.promptPatterns.some(p => p.test(corpus.prompt))) {
      matched = true;
    }

    if (!matched && corpus.contractNames.some(n => api.contractPatterns.some(p => p.test(n)))) {
      matched = true;
    }

    if (!matched && corpus.researchQueries.some(q => api.queryPatterns.some(p => p.test(q)))) {
      matched = true;
    }

    if (matched) {
      detected.push(api);
    }
  }

  return detected;
}

function detectDatabases(corpus: Corpus): DatabaseSignal[] {
  const detected: DatabaseSignal[] = [];

  for (const db of DATABASES) {
    let matched = false;

    if (db.promptPatterns.some(p => p.test(corpus.prompt))) {
      matched = true;
    }

    if (!matched && corpus.contractNames.some(n => db.contractPatterns.some(p => p.test(n)))) {
      matched = true;
    }

    if (!matched && corpus.files.some(f => db.filePatterns.some(p => p.test(f)))) {
      matched = true;
    }

    if (matched) {
      detected.push(db);
    }
  }

  return detected;
}

function detectAuthPatterns(corpus: Corpus): AuthSignal[] {
  const detected: AuthSignal[] = [];

  for (const auth of AUTH_PATTERNS) {
    let matched = false;

    if (auth.promptPatterns.some(p => p.test(corpus.prompt))) {
      matched = true;
    }

    if (!matched && corpus.contractNames.some(n => auth.contractPatterns.some(p => p.test(n)))) {
      matched = true;
    }

    if (!matched && corpus.files.some(f => auth.filePatterns.some(p => p.test(f)))) {
      matched = true;
    }

    if (matched) {
      detected.push(auth);
    }
  }

  return detected;
}

function detectSensitiveFields(corpus: Corpus): SensitiveFieldPattern[] {
  const detected: SensitiveFieldPattern[] = [];

  for (const sf of SENSITIVE_FIELDS) {
    if (sf.patterns.some(p => p.test(corpus.fullText))) {
      detected.push(sf);
    }
  }

  return detected;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Scope wildcard file patterns to the actual files in the build plan.
 * If a sink says files: ['*'], replace with the real file list.
 */
function scopeSinksToFiles(
  sinks: DSTManifest['intentional_sinks'],
  planFiles: string[],
): DSTManifest['intentional_sinks'] {
  return sinks.map(sink => {
    if (sink.files.includes('*')) {
      return { ...sink, files: [...planFiles] };
    }
    return sink;
  });
}

/**
 * Derive a short app name from the user's prompt.
 * Takes the first few meaningful words.
 */
function deriveAppName(prompt: string): string {
  if (!prompt || prompt.trim().length === 0) return 'app';

  // Strip common prefixes
  const cleaned = prompt
    .replace(/^(build|create|make|write|generate)\s+(me\s+)?(a|an|the)\s+/i, '')
    .replace(/^(build|create|make|write|generate)\s+/i, '')
    .trim();

  // Take first 4 words, kebab-case them
  const words = cleaned
    .split(/\s+/)
    .slice(0, 4)
    .map(w => w.toLowerCase().replace(/[^a-z0-9]/g, ''))
    .filter(w => w.length > 0);

  return words.join('-') || 'app';
}

// ---------------------------------------------------------------------------
// Exports for testing
// ---------------------------------------------------------------------------

export { buildCorpus, detectFrameworks, detectExternalAPIs, detectDatabases, detectAuthPatterns, detectSensitiveFields, deriveAppName, scopeSinksToFiles };
export type { Corpus, FrameworkSignal, ExternalAPISignal, DatabaseSignal, AuthSignal, SensitiveFieldPattern };
