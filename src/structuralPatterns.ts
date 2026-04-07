/**
 * Structural Pattern Database — the second level of phonemes.
 *
 * Callee patterns answer: "what does this function call MEAN?"
 * Structural patterns answer: "what does this ARRANGEMENT of code MEAN?"
 *
 * Example: Express middleware chains.
 *   app.get('/path', requireAuth, rateLimiter, (req, res) => { ... })
 *
 * The callee DB sees app.get and doesn't know what to do with it.
 * The structural pattern DB sees the SHAPE of the arguments and says:
 *   - Argument 0 is a route path (string)
 *   - Arguments 1..n-1 are middleware functions (if they're identifiers or function refs)
 *   - Argument n (last) is the route handler (callback)
 *   - If any middleware is a known AUTH function → the handler is auth-gated
 *
 * Each pattern is readable. A security researcher who's never seen the code
 * can read a structural pattern and understand what it means. That's the point.
 *
 * The pattern database is the structural phoneme layer. Adding framework support
 * is adding patterns, not writing code.
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { NeuralMapNode, NodeType } from './types.js';

// ---------------------------------------------------------------------------
// Structural pattern types
// ---------------------------------------------------------------------------

/** What a structural pattern discovered about a call's arguments */
export interface StructuralInsight {
  /** Middleware function names found in the call */
  middlewareNames: string[];

  /** Whether any middleware is an AUTH gate */
  hasAuthGate: boolean;

  /** Whether any middleware is a rate limiter */
  hasRateLimiter: boolean;

  /** Whether any middleware is a CSRF protector */
  hasCsrfProtection: boolean;

  /** Whether any middleware is a validator/sanitizer */
  hasValidation: boolean;

  /** The route path, if this is a route definition */
  routePath: string | null;

  /** The HTTP method, if this is a route definition */
  httpMethod: string | null;
}

// ---------------------------------------------------------------------------
// AUTH middleware name patterns — English-readable
// ---------------------------------------------------------------------------

/** Names that indicate an authentication middleware */
const AUTH_MIDDLEWARE_NAMES = new Set([
  // Express/general
  'requireAuth', 'requireLogin', 'requireAuthentication',
  'isAuthenticated', 'isLoggedIn', 'ensureAuthenticated',
  'authenticate', 'authMiddleware', 'authRequired',
  'requireUser', 'loginRequired', 'checkAuth',
  'verifyToken', 'verifyJWT', 'jwtAuth',
  'requireSession', 'sessionRequired',
  // Passport.js
  'passport',
  // Common short names
  'auth', 'protect', 'guard', 'secured',
  // Fastify
  'fastifyAuth', 'fastifyJwt', 'fastifyPassport',
  'onRequest', 'preHandler', 'preValidation',
  // NestJS guards
  'AuthGuard', 'JwtAuthGuard', 'RolesGuard', 'UseGuards',
  'CanActivate', 'GqlAuthGuard',
  // Koa
  'koaPassport', 'koaJwt',
  // Hapi
  'hapiAuth', 'hapiAuthJwt', 'hapiAuthBasic', 'hapiAuthCookie',
]);

/** Patterns in function names that suggest auth (partial match) */
const AUTH_NAME_PATTERNS = [
  /^require[A-Z]?.*auth/i,
  /^is[A-Z]?.*authenticated/i,
  /^ensure[A-Z]?.*auth/i,
  /^check[A-Z]?.*auth/i,
  /^verify[A-Z]?.*token/i,
  /^jwt[A-Z]?.*auth/i,
  /^passport\./i,
  /^auth[A-Z]?.*middleware/i,
  // NestJS patterns
  /^.*Guard$/,              // AuthGuard, JwtAuthGuard, RolesGuard
  /^UseGuards$/i,
  /^CanActivate$/i,
  // Fastify hook-based auth
  /^onRequest$/i,
  /^preHandler$/i,
  /^preValidation$/i,
];

/** Names that indicate rate limiting */
const RATE_LIMIT_NAMES = new Set([
  'rateLimit', 'rateLimiter', 'limiter', 'throttle',
  'slowDown', 'expressRateLimit', 'apiLimiter',
  // Fastify
  'fastifyRateLimit',
  // Koa
  'koaRateLimit',
  // Hapi
  'hapiRateLimit', 'hapiRateLimiter',
  // NestJS
  'ThrottlerGuard', 'Throttle',
]);

/** Names that indicate CSRF protection */
const CSRF_NAMES = new Set([
  'csrf', 'csurf', 'csrfProtection', 'csrfToken',
  'xsrf', 'antiForgery',
]);

/** Names that indicate validation/sanitization */
const VALIDATION_NAMES = new Set([
  'validate', 'validateBody', 'validateParams', 'validateQuery',
  'sanitize', 'sanitizeBody', 'sanitizeInput',
  'check', 'checkBody', 'checkSchema',
  'celebrate', 'joiValidator', 'zodValidator',
  // Fastify — uses JSON Schema validation built-in
  'fastifySchemaValidation',
  // NestJS pipes
  'ValidationPipe', 'ParseIntPipe', 'ParseBoolPipe', 'ParseUUIDPipe',
  'ParseFloatPipe', 'ParseArrayPipe', 'ParseEnumPipe',
  'UsePipes',
  // Koa
  'koaValidate', 'koaJoi',
  // Hapi — Joi is native to Hapi
  'Joi',
]);

// ---------------------------------------------------------------------------
// Route method detection
// ---------------------------------------------------------------------------

/** HTTP methods that Express/Koa/Fastify routers use */
const ROUTE_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch',
  'head', 'options', 'all', 'use',
  // Fastify-specific
  'register',
  // Hapi-specific (server.route uses a config object, but these are the verb methods)
  'route',
]);

/** Objects that are typically routers */
const ROUTER_OBJECTS = new Set([
  // Express
  'app', 'router', 'route', 'server',
  'api', 'apiRouter', 'adminRouter',
  // Fastify
  'fastify', 'instance', 'fastifyInstance',
  // Koa (koa-router)
  'koaRouter', 'koaRoute',
  // Hapi — server.route() is the main pattern
  // 'server' already included above
]);

// ---------------------------------------------------------------------------
// The matcher — reads the SHAPE of a call and produces insights
// ---------------------------------------------------------------------------

/**
 * Analyze a call_expression for structural patterns.
 *
 * If the call matches a known structural pattern (e.g., Express route
 * definition with middleware), returns insights about what the arguments mean.
 *
 * Returns null if no structural pattern matches.
 */
export function analyzeStructure(callNode: SyntaxNode): StructuralInsight | null {
  if (callNode.type !== 'call_expression') return null;

  const callee = callNode.childForFieldName('function');
  if (!callee) return null;

  // Check if this is a router method call: app.get(...), router.post(...), etc.
  if (callee.type === 'member_expression') {
    const object = callee.childForFieldName('object');
    const method = callee.childForFieldName('property');

    if (!object || !method) return null;

    const objName = object.type === 'identifier' ? object.text : null;
    const methodName = method.text;

    // Is this a route definition?
    if (objName && ROUTER_OBJECTS.has(objName) && ROUTE_METHODS.has(methodName)) {
      return analyzeRouteDefinition(callNode, methodName);
    }

    // Also match chained: router.route('/path').get(handler)
    if (object.type === 'call_expression' && ROUTE_METHODS.has(methodName)) {
      return analyzeRouteDefinition(callNode, methodName);
    }
  }

  return null;
}

/**
 * Analyze a route definition's arguments to find middleware.
 *
 * Express pattern: app.method(path, ...middlewares, handler)
 * - First arg (string): route path
 * - Middle args (identifiers/functions): middleware
 * - Last arg (arrow/function): handler
 */
function analyzeRouteDefinition(callNode: SyntaxNode, method: string): StructuralInsight {
  const argsNode = callNode.childForFieldName('arguments');
  const insight: StructuralInsight = {
    middlewareNames: [],
    hasAuthGate: false,
    hasRateLimiter: false,
    hasCsrfProtection: false,
    hasValidation: false,
    routePath: null,
    httpMethod: method,
  };

  if (!argsNode) return insight;

  const args: SyntaxNode[] = [];
  for (let i = 0; i < argsNode.namedChildCount; i++) {
    const arg = argsNode.namedChild(i);
    if (arg) args.push(arg);
  }

  if (args.length === 0) return insight;

  // First arg is usually the path (string)
  if (args[0].type === 'string' || args[0].type === 'template_string') {
    insight.routePath = args[0].text.replace(/['"`]/g, '');
  }

  // Last arg is usually the handler (arrow function or function expression)
  // Everything between first and last is middleware
  if (args.length > 2) {
    const middlewareArgs = args.slice(1, -1);

    for (const mw of middlewareArgs) {
      let name: string | null = null;

      if (mw.type === 'identifier') {
        name = mw.text;
      } else if (mw.type === 'call_expression') {
        // Middleware factory: rateLimit({ windowMs: 60000, max: 100 })
        const fn = mw.childForFieldName('function');
        if (fn?.type === 'identifier') name = fn.text;
        if (fn?.type === 'member_expression') {
          name = fn.childForFieldName('property')?.text ?? null;
        }
      } else if (mw.type === 'member_expression') {
        // passport.authenticate('jwt')
        name = mw.text;
      }

      if (name) {
        insight.middlewareNames.push(name);

        // Classify the middleware
        if (AUTH_MIDDLEWARE_NAMES.has(name) || AUTH_NAME_PATTERNS.some(p => p.test(name!))) {
          insight.hasAuthGate = true;
        }
        if (RATE_LIMIT_NAMES.has(name)) {
          insight.hasRateLimiter = true;
        }
        if (CSRF_NAMES.has(name)) {
          insight.hasCsrfProtection = true;
        }
        if (VALIDATION_NAMES.has(name)) {
          insight.hasValidation = true;
        }
      }
    }
  }

  return insight;
}

/**
 * Check if a middleware name indicates authentication.
 * Exported for use in the mapper's cross-referencing with the function registry.
 */
export function isAuthMiddleware(name: string): boolean {
  return AUTH_MIDDLEWARE_NAMES.has(name) || AUTH_NAME_PATTERNS.some(p => p.test(name));
}
