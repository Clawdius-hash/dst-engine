/**
 * Phoneme expansion: JavaScript/TypeScript — Node.js crypto specifics, passport,
 * express-session, helmet, CORS, and postMessage as INGRESS
 *
 * Audit context:
 *   - postMessage LISTENER was missing as INGRESS (only EGRESS existed via window.postMessage)
 *   - crypto.createCipher/createDecipher (DEPRECATED, no IV) were absent — these are
 *     qualitatively different from createCipheriv/createDecipheriv and should flag differently
 *   - passport.authenticate / passport.use were completely absent
 *   - express-session, helmet(), cors() — three of the most security-critical Express
 *     middlewares — had zero representation
 *
 * What's already covered (DO NOT duplicate):
 *   - crypto.createHash, createHmac, randomBytes, createCipheriv, createDecipheriv,
 *     pbkdf2, scrypt → calleePatterns.ts MEMBER_CALLS (TRANSFORM/encrypt)
 *   - crypto.pbkdf2Sync, scryptSync → calleePatterns.ts (RESOURCE/cpu)
 *   - crypto.subtle → calleePatterns.ts (TRANSFORM/encrypt)
 *   - bcrypt.compare/hash/genSalt → calleePatterns.ts (AUTH/authenticate)
 *   - jwt.sign/verify/decode → calleePatterns.ts (AUTH/authenticate)
 *   - window.postMessage → calleePatterns.ts (EGRESS/ipc)
 *
 * 10 entries total. All real functions from real packages.
 */

import type { NodeType } from '../types.js';

export interface CalleePattern {
  nodeType: NodeType;
  subtype: string;
  tainted: boolean;
}

export const PHONEMES_JS_CRYPTO_AUTH = {

  // ═══════════════════════════════════════════════════════════════════════════
  // postMessage as INGRESS — the listener side
  // ═══════════════════════════════════════════════════════════════════════════
  // window.postMessage was already mapped as EGRESS/ipc (sending side).
  // But the RECEIVING side — window.addEventListener('message', handler) — is
  // the actual INGRESS vector. Any cross-origin window/iframe can postMessage
  // into your page. The event.data is fully attacker-controlled unless the
  // handler validates event.origin. This is CWE-345 (insufficient verification
  // of data authenticity). Most XSS-via-postMessage bugs happen because
  // developers trust event.data without checking event.origin.
  //
  // The scanner sees `window.addEventListener` as a member call. We type it
  // as INGRESS/postmessage because its primary security role is receiving
  // untrusted cross-origin data. The "message" string argument is what makes
  // it dangerous, but at the callee-pattern level we flag the call site.
  'window.addEventListener': { nodeType: 'INGRESS', subtype: 'postmessage', tainted: true },

  // ═══════════════════════════════════════════════════════════════════════════
  // DEPRECATED crypto — createCipher / createDecipher (NO IV)
  // ═══════════════════════════════════════════════════════════════════════════
  // crypto.createCipher(algorithm, password) derives a key from `password`
  // using MD5 with NO salt and NO IV. This is fundamentally broken:
  //   - Same password + same plaintext = same ciphertext (ECB-like behavior)
  //   - No authentication (no AEAD)
  //   - Deprecated since Node.js 10.0.0, removed in recent versions
  // These are typed as EXTERNAL/deprecated_crypto (not TRANSFORM/encrypt)
  // so the scanner can distinguish them from the safe createCipheriv variants.
  // Finding createCipher in a codebase is almost always a vulnerability.
  'crypto.createCipher':    { nodeType: 'EXTERNAL', subtype: 'deprecated_crypto', tainted: false },
  'crypto.createDecipher':  { nodeType: 'EXTERNAL', subtype: 'deprecated_crypto', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // crypto.createSign / createVerify — digital signatures
  // ═══════════════════════════════════════════════════════════════════════════
  // crypto.createSign(algorithm) creates a Sign object for generating digital
  // signatures (RSA, ECDSA, Ed25519). Used for token signing, webhook
  // verification, code signing. Typed as AUTH because the purpose is identity
  // verification / non-repudiation, not data transformation.
  // crypto.createVerify(algorithm) verifies a signature. If verification is
  // skipped or the result is ignored, it's an authentication bypass.
  'crypto.createSign':      { nodeType: 'AUTH',     subtype: 'signature',         tainted: false },
  'crypto.createVerify':    { nodeType: 'AUTH',     subtype: 'signature',         tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // Passport.js — authentication strategies
  // ═══════════════════════════════════════════════════════════════════════════
  // passport.authenticate('strategy') is the core auth gate in Express apps.
  // It's middleware that checks credentials against the registered strategy
  // (local, OAuth, JWT, SAML, etc.). If misconfigured (e.g., {session: false}
  // without JWT, or failureRedirect missing), it silently passes unauthenticated
  // requests. Typed as AUTH/authenticate.
  'passport.authenticate': { nodeType: 'AUTH',      subtype: 'authenticate',      tainted: false },

  // passport.use(new Strategy(...)) registers an authentication strategy.
  // This defines HOW authentication works — what database to check, what
  // fields to compare, what OAuth provider to trust. Misconfigured strategies
  // (e.g., not verifying email, accepting any OAuth callback) are auth bypasses.
  // Typed as STRUCTURAL because it defines system topology (which auth methods exist).
  'passport.use':          { nodeType: 'STRUCTURAL', subtype: 'auth_config',      tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // express-session — session middleware configuration
  // ═══════════════════════════════════════════════════════════════════════════
  // express-session creates server-side sessions with a session ID cookie.
  // The security-critical config options are:
  //   - secret: if weak/hardcoded, session IDs are forgeable
  //   - cookie.secure: if false, session cookie sent over HTTP (sniffable)
  //   - cookie.httpOnly: if false, session cookie readable by XSS
  //   - cookie.sameSite: if missing, CSRF via cross-site requests
  //   - resave/saveUninitialized: if true, creates sessions for unauthenticated users
  // Typed as META/session_config because it configures security policy, not logic.
  'session':               { nodeType: 'META',      subtype: 'session_config',    tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // Helmet — security headers middleware
  // ═══════════════════════════════════════════════════════════════════════════
  // helmet() sets HTTP security headers: Content-Security-Policy,
  // X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, etc.
  // Its ABSENCE is a vulnerability (missing security headers). When present,
  // its configuration matters (e.g., CSP directives, HSTS max-age).
  // Typed as META/security_headers because it configures transport-layer policy.
  'helmet':                { nodeType: 'META',      subtype: 'security_headers',  tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // CORS — Cross-Origin Resource Sharing middleware
  // ═══════════════════════════════════════════════════════════════════════════
  // cors() or cors({origin: ...}) controls which origins can make cross-origin
  // requests to your API. Misconfiguration is extremely common:
  //   - origin: '*' with credentials: true → credential leak to any origin
  //   - origin: true (reflect request origin) → same as wildcard with creds
  //   - Regex origin matching that's too permissive (e.g., /example\.com/)
  // Typed as META/cors_config because it defines access control policy.
  'cors':                  { nodeType: 'META',      subtype: 'cors_config',       tainted: false },
};
