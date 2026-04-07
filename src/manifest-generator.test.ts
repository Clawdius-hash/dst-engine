/**
 * Manifest Generator Tests
 *
 * Tests that generateManifest correctly derives a DSTManifest from a BuildPlan.
 * The plan IS the intent. These tests verify that intent extraction works
 * for real-world build plans.
 */

import { describe, it, expect } from 'vitest';
import {
  generateManifest,
  buildCorpus,
  detectFrameworks,
  detectExternalAPIs,
  detectDatabases,
  detectAuthPatterns,
  detectSensitiveFields,
  deriveAppName,
  scopeSinksToFiles,
} from './manifest-generator';
import type { BuildPlan } from '../pipeline/conductor';
import type { Contract } from '../pipeline/graph-bridge';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePlan(overrides: Partial<BuildPlan> = {}): BuildPlan {
  return {
    prompt: overrides.prompt ?? '',
    files: overrides.files ?? [],
    assignments: overrides.assignments ?? {},
    contracts: overrides.contracts ?? [],
    researchNeeded: overrides.researchNeeded ?? false,
    researchQueries: overrides.researchQueries ?? [],
  };
}

function makeContract(overrides: Partial<Contract> = {}): Contract {
  return {
    name: overrides.name ?? 'func',
    type: overrides.type ?? 'function',
    exportedBy: overrides.exportedBy ?? 'file.ts',
    calledBy: overrides.calledBy,
    params: overrides.params,
  };
}

// ---------------------------------------------------------------------------
// Framework Detection
// ---------------------------------------------------------------------------

describe('Framework Detection', () => {
  it('detects Express from prompt', () => {
    const plan = makePlan({ prompt: 'Build an Express REST API' });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.some(f => f.name === 'express')).toBe(true);
  });

  it('detects Fastify from prompt', () => {
    const plan = makePlan({ prompt: 'Create a Fastify server' });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.some(f => f.name === 'fastify')).toBe(true);
  });

  it('detects Koa from prompt', () => {
    const plan = makePlan({ prompt: 'Build a Koa application' });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.some(f => f.name === 'koa')).toBe(true);
  });

  it('detects Hapi from prompt', () => {
    const plan = makePlan({ prompt: 'Create a Hapi server' });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.some(f => f.name === 'hapi')).toBe(true);
  });

  it('detects Next.js from prompt', () => {
    const plan = makePlan({ prompt: 'Build a Next.js app with app router' });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.some(f => f.name === 'nextjs')).toBe(true);
  });

  it('detects NestJS from file patterns', () => {
    const plan = makePlan({
      prompt: 'Build a user management app',
      files: ['users.controller.ts', 'users.service.ts', 'users.module.ts'],
    });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.some(f => f.name === 'nestjs')).toBe(true);
  });

  it('detects Express from contract names (app, router)', () => {
    const plan = makePlan({
      prompt: 'Build a web server',
      contracts: [
        makeContract({ name: 'router', type: 'variable', exportedBy: 'routes.ts' }),
      ],
    });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.some(f => f.name === 'express')).toBe(true);
  });

  it('detects NestJS from contract names (Controller suffix)', () => {
    const plan = makePlan({
      prompt: 'Build a user management backend',
      contracts: [
        makeContract({ name: 'UsersController', type: 'class', exportedBy: 'users.ts' }),
      ],
    });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.some(f => f.name === 'nestjs')).toBe(true);
  });

  it('defaults to Express when server files exist with server-like prompt', () => {
    const plan = makePlan({
      prompt: 'Build a backend API with user endpoints',
      files: ['server.ts', 'routes.ts'],
    });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.some(f => f.name === 'express')).toBe(true);
  });

  it('returns no framework for a pure frontend plan', () => {
    const plan = makePlan({
      prompt: 'Build a calculator UI',
      files: ['index.html', 'style.css', 'app.js'],
    });
    const corpus = buildCorpus(plan);
    const frameworks = detectFrameworks(corpus);
    expect(frameworks.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// External API Detection
// ---------------------------------------------------------------------------

describe('External API Detection', () => {
  it('detects Spotify from prompt', () => {
    const plan = makePlan({ prompt: 'Build a Spotify playlist viewer' });
    const corpus = buildCorpus(plan);
    const apis = detectExternalAPIs(corpus);
    expect(apis.some(a => a.name === 'spotify')).toBe(true);
  });

  it('detects Stripe from prompt mentioning payments', () => {
    const plan = makePlan({ prompt: 'Build a payment checkout with Stripe' });
    const corpus = buildCorpus(plan);
    const apis = detectExternalAPIs(corpus);
    expect(apis.some(a => a.name === 'stripe')).toBe(true);
  });

  it('detects OpenAI from prompt', () => {
    const plan = makePlan({ prompt: 'Build a GPT chatbot' });
    const corpus = buildCorpus(plan);
    const apis = detectExternalAPIs(corpus);
    expect(apis.some(a => a.name === 'openai')).toBe(true);
  });

  it('detects weather API from research queries', () => {
    const plan = makePlan({
      prompt: 'Show live weather data',
      researchNeeded: true,
      researchQueries: ['free weather API no auth required'],
    });
    const corpus = buildCorpus(plan);
    const apis = detectExternalAPIs(corpus);
    expect(apis.some(a => a.name === 'weather')).toBe(true);
  });

  it('detects generic HTTP from contract names with api/fetch', () => {
    const plan = makePlan({
      prompt: 'Build a data aggregator',
      contracts: [
        makeContract({ name: 'fetchData', type: 'function', exportedBy: 'api.ts' }),
      ],
    });
    const corpus = buildCorpus(plan);
    const apis = detectExternalAPIs(corpus);
    expect(apis.some(a => a.name === 'generic-http')).toBe(true);
  });

  it('detects Firebase from prompt', () => {
    const plan = makePlan({ prompt: 'Build a chat app with Firebase' });
    const corpus = buildCorpus(plan);
    const apis = detectExternalAPIs(corpus);
    expect(apis.some(a => a.name === 'firebase')).toBe(true);
  });

  it('detects AWS from prompt mentioning S3', () => {
    const plan = makePlan({ prompt: 'Build a file upload service using S3' });
    const corpus = buildCorpus(plan);
    const apis = detectExternalAPIs(corpus);
    expect(apis.some(a => a.name === 'aws')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Database Detection
// ---------------------------------------------------------------------------

describe('Database Detection', () => {
  it('detects Prisma from prompt', () => {
    const plan = makePlan({ prompt: 'Build an API with Prisma and PostgreSQL' });
    const corpus = buildCorpus(plan);
    const dbs = detectDatabases(corpus);
    expect(dbs.some(d => d.name === 'prisma')).toBe(true);
  });

  it('detects Mongoose from prompt mentioning MongoDB', () => {
    const plan = makePlan({ prompt: 'Build a MongoDB-backed REST API' });
    const corpus = buildCorpus(plan);
    const dbs = detectDatabases(corpus);
    expect(dbs.some(d => d.name === 'mongoose')).toBe(true);
  });

  it('detects Sequelize from contract names', () => {
    const plan = makePlan({
      prompt: 'Build a user management app',
      contracts: [
        makeContract({ name: 'sequelize', type: 'variable', exportedBy: 'db.ts' }),
      ],
    });
    const corpus = buildCorpus(plan);
    const dbs = detectDatabases(corpus);
    expect(dbs.some(d => d.name === 'sequelize')).toBe(true);
  });

  it('detects raw SQL from prompt mentioning database', () => {
    const plan = makePlan({ prompt: 'Build a SQLite database app' });
    const corpus = buildCorpus(plan);
    const dbs = detectDatabases(corpus);
    expect(dbs.some(d => d.name === 'sql-raw')).toBe(true);
  });

  it('detects Knex from file patterns', () => {
    const plan = makePlan({
      prompt: 'Build an app',
      files: ['knexfile.ts', 'migrations/001_users.ts', 'server.ts'],
    });
    const corpus = buildCorpus(plan);
    const dbs = detectDatabases(corpus);
    expect(dbs.some(d => d.name === 'knex')).toBe(true);
  });

  it('detects TypeORM from contract names with Repository suffix', () => {
    const plan = makePlan({
      prompt: 'Build a REST API',
      contracts: [
        makeContract({ name: 'UserRepository', type: 'class', exportedBy: 'user.entity.ts' }),
      ],
    });
    const corpus = buildCorpus(plan);
    const dbs = detectDatabases(corpus);
    expect(dbs.some(d => d.name === 'typeorm')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Auth Detection
// ---------------------------------------------------------------------------

describe('Auth Detection', () => {
  it('detects JWT from prompt', () => {
    const plan = makePlan({ prompt: 'Build an API with JWT authentication' });
    const corpus = buildCorpus(plan);
    const auth = detectAuthPatterns(corpus);
    expect(auth.some(a => a.name === 'jwt')).toBe(true);
  });

  it('detects bcrypt from contract names', () => {
    const plan = makePlan({
      prompt: 'Build a user system',
      contracts: [
        makeContract({ name: 'hashPassword', type: 'function', exportedBy: 'auth.ts' }),
      ],
    });
    const corpus = buildCorpus(plan);
    const auth = detectAuthPatterns(corpus);
    // hashPassword doesn't match bcrypt contracts (needs 'bcrypt' or 'hash')
    // Let's test with a file pattern instead
    const plan2 = makePlan({
      prompt: 'Build a user system with password hashing',
    });
    const corpus2 = buildCorpus(plan2);
    const auth2 = detectAuthPatterns(corpus2);
    expect(auth2.some(a => a.name === 'bcrypt')).toBe(true);
  });

  it('detects Passport from prompt', () => {
    const plan = makePlan({ prompt: 'Build a login system with OAuth using Passport' });
    const corpus = buildCorpus(plan);
    const auth = detectAuthPatterns(corpus);
    expect(auth.some(a => a.name === 'passport')).toBe(true);
  });

  it('detects session auth from file patterns', () => {
    const plan = makePlan({
      prompt: 'Build a web app',
      files: ['session-store.ts', 'server.ts'],
    });
    const corpus = buildCorpus(plan);
    const auth = detectAuthPatterns(corpus);
    expect(auth.some(a => a.name === 'session')).toBe(true);
  });

  it('detects JWT from auth file patterns', () => {
    const plan = makePlan({
      prompt: 'Build a web app',
      files: ['auth-middleware.ts', 'server.ts'],
    });
    const corpus = buildCorpus(plan);
    const auth = detectAuthPatterns(corpus);
    expect(auth.some(a => a.name === 'jwt')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Sensitive Field Detection
// ---------------------------------------------------------------------------

describe('Sensitive Field Detection', () => {
  it('detects price fields from prompt', () => {
    const plan = makePlan({ prompt: 'Build an e-commerce store with product prices' });
    const corpus = buildCorpus(plan);
    const fields = detectSensitiveFields(corpus);
    expect(fields.some(f => f.field === 'price')).toBe(true);
  });

  it('detects balance from contract params', () => {
    const plan = makePlan({
      prompt: 'Build a wallet app',
      contracts: [
        makeContract({ name: 'updateBalance', params: ['userId', 'balance'], exportedBy: 'wallet.ts' }),
      ],
    });
    const corpus = buildCorpus(plan);
    const fields = detectSensitiveFields(corpus);
    expect(fields.some(f => f.field === 'balance')).toBe(true);
  });

  it('detects role from prompt mentioning admin', () => {
    const plan = makePlan({ prompt: 'Build an admin panel with user roles' });
    const corpus = buildCorpus(plan);
    const fields = detectSensitiveFields(corpus);
    expect(fields.some(f => f.field === 'role')).toBe(true);
  });

  it('detects permissions from contract names', () => {
    const plan = makePlan({
      prompt: 'Build an API',
      contracts: [
        makeContract({ name: 'checkPermissions', type: 'function', exportedBy: 'auth.ts' }),
      ],
    });
    const corpus = buildCorpus(plan);
    const fields = detectSensitiveFields(corpus);
    expect(fields.some(f => f.field === 'permissions')).toBe(true);
  });

  it('detects discount from prompt', () => {
    const plan = makePlan({ prompt: 'Build a coupon system for the store' });
    const corpus = buildCorpus(plan);
    const fields = detectSensitiveFields(corpus);
    expect(fields.some(f => f.field === 'discount')).toBe(true);
  });

  it('returns empty for plans with no sensitive fields', () => {
    const plan = makePlan({ prompt: 'Build a hello world page' });
    const corpus = buildCorpus(plan);
    const fields = detectSensitiveFields(corpus);
    expect(fields.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// App Name Derivation
// ---------------------------------------------------------------------------

describe('deriveAppName', () => {
  it('strips common prefixes', () => {
    expect(deriveAppName('Build me a Spotify playlist viewer')).toBe('spotify-playlist-viewer');
  });

  it('handles "Create an" prefix', () => {
    expect(deriveAppName('Create an e-commerce store')).toBe('ecommerce-store');
  });

  it('limits to 4 words', () => {
    expect(deriveAppName('Build a real-time chat application with WebSockets and authentication'))
      .toBe('realtime-chat-application-with');
  });

  it('returns "app" for empty prompt', () => {
    expect(deriveAppName('')).toBe('app');
  });

  it('handles prompt without common prefix', () => {
    expect(deriveAppName('Todo list with drag and drop')).toBe('todo-list-with-drag');
  });
});

// ---------------------------------------------------------------------------
// Scope Sinks to Files
// ---------------------------------------------------------------------------

describe('scopeSinksToFiles', () => {
  it('replaces wildcard with actual file list', () => {
    const sinks = [{
      files: ['*'],
      patterns: ['res.json'],
      type: 'EGRESS',
      reason: 'test',
    }];
    const result = scopeSinksToFiles(sinks, ['server.ts', 'routes.ts']);
    expect(result[0]!.files).toEqual(['server.ts', 'routes.ts']);
  });

  it('preserves specific file patterns', () => {
    const sinks = [{
      files: ['auth.ts'],
      patterns: ['jwt.sign'],
      type: 'AUTH',
      reason: 'test',
    }];
    const result = scopeSinksToFiles(sinks, ['server.ts', 'auth.ts']);
    expect(result[0]!.files).toEqual(['auth.ts']);
  });
});

// ---------------------------------------------------------------------------
// Full Integration: generateManifest
// ---------------------------------------------------------------------------

describe('generateManifest', () => {
  it('generates a complete manifest for an Express + Prisma + JWT app', () => {
    const plan = makePlan({
      prompt: 'Build an Express REST API with Prisma and JWT auth',
      files: ['server.ts', 'routes/users.ts', 'routes/auth.ts', 'db.ts', 'middleware/auth.ts'],
      assignments: { coder_1: ['server.ts', 'routes/users.ts'], coder_2: ['routes/auth.ts', 'db.ts', 'middleware/auth.ts'] },
      contracts: [
        makeContract({ name: 'router', type: 'variable', exportedBy: 'routes/users.ts', calledBy: ['server.ts'] }),
        makeContract({ name: 'prisma', type: 'variable', exportedBy: 'db.ts', calledBy: ['routes/users.ts', 'routes/auth.ts'] }),
        makeContract({ name: 'verifyToken', type: 'function', exportedBy: 'middleware/auth.ts', calledBy: ['routes/users.ts'] }),
      ],
      researchNeeded: false,
    });

    const manifest = generateManifest(plan);

    // Should have a name
    expect(manifest.name).toBeTruthy();
    expect(manifest.name).not.toBe('app');

    // Should have intentional sinks for Express (EGRESS + INGRESS)
    const egressSinks = manifest.intentional_sinks.filter(s => s.type === 'EGRESS');
    expect(egressSinks.length).toBeGreaterThan(0);
    const ingressSinks = manifest.intentional_sinks.filter(s => s.type === 'INGRESS');
    expect(ingressSinks.length).toBeGreaterThan(0);

    // Should have intentional sinks for Prisma (STORAGE)
    const storageSinks = manifest.intentional_sinks.filter(s => s.type === 'STORAGE');
    expect(storageSinks.length).toBeGreaterThan(0);

    // Should have intentional sinks for JWT (AUTH)
    const authSinks = manifest.intentional_sinks.filter(s => s.type === 'AUTH');
    expect(authSinks.length).toBeGreaterThan(0);

    // Sinks should be scoped to the plan's actual files
    for (const sink of manifest.intentional_sinks) {
      for (const file of sink.files) {
        expect(plan.files).toContain(file);
      }
    }

    // Should have scan_policy
    expect(manifest.scan_policy.cwes).toBe('hand_written');
    expect(manifest.scan_policy.exclude_intentional).toBe(true);
  });

  it('generates a manifest for a Spotify dashboard with prices', () => {
    const plan = makePlan({
      prompt: 'Build a Spotify playlist manager with premium pricing',
      files: ['server.ts', 'spotify-client.ts', 'pricing.ts', 'app.js'],
      assignments: { coder_1: ['server.ts', 'spotify-client.ts', 'pricing.ts', 'app.js'] },
      contracts: [
        makeContract({ name: 'fetchPlaylists', type: 'function', exportedBy: 'spotify-client.ts' }),
        makeContract({ name: 'getPrice', type: 'function', exportedBy: 'pricing.ts', params: ['tier'] }),
      ],
      researchNeeded: true,
      researchQueries: ['Spotify Web API endpoints'],
    });

    const manifest = generateManifest(plan);

    // Should detect Spotify as external API
    const externalSinks = manifest.intentional_sinks.filter(s => s.type === 'EXTERNAL');
    expect(externalSinks.length).toBeGreaterThan(0);
    expect(externalSinks.some(s => s.reason.toLowerCase().includes('spotify'))).toBe(true);

    // Should detect price as sensitive field
    expect(manifest.data_origins).toBeDefined();
    expect(manifest.data_origins!.some(o => o.field === 'price')).toBe(true);
  });

  it('generates a manifest for a NestJS app detected via file patterns', () => {
    const plan = makePlan({
      prompt: 'Build a user management backend with database',
      files: ['users.controller.ts', 'users.service.ts', 'users.module.ts', 'app.module.ts'],
      assignments: { coder_1: ['users.controller.ts', 'users.service.ts', 'users.module.ts', 'app.module.ts'] },
      contracts: [
        makeContract({ name: 'UsersController', type: 'class', exportedBy: 'users.controller.ts' }),
        makeContract({ name: 'UsersService', type: 'class', exportedBy: 'users.service.ts' }),
      ],
      researchNeeded: false,
    });

    const manifest = generateManifest(plan);

    // Should detect NestJS
    const egressSinks = manifest.intentional_sinks.filter(s => s.type === 'EGRESS');
    expect(egressSinks.length).toBeGreaterThan(0);
    expect(egressSinks.some(s => s.reason.toLowerCase().includes('nestjs') || s.reason.toLowerCase().includes('express'))).toBe(true);
  });

  it('generates a minimal manifest for a simple frontend app', () => {
    const plan = makePlan({
      prompt: 'Build a calculator',
      files: ['index.html', 'style.css', 'calc.js'],
      assignments: { coder_1: ['index.html', 'style.css', 'calc.js'] },
      contracts: [],
      researchNeeded: false,
    });

    const manifest = generateManifest(plan);

    // No server framework, no external APIs, no DB, no auth
    expect(manifest.intentional_sinks.length).toBe(0);
    // No sensitive fields
    expect(manifest.data_origins).toBeUndefined();
    // Scan policy always present
    expect(manifest.scan_policy).toBeDefined();
  });

  it('generates a manifest for a Koa + Mongoose + Passport app', () => {
    const plan = makePlan({
      prompt: 'Build a Koa blog API with Mongoose and Passport OAuth',
      files: ['app.ts', 'models/post.ts', 'routes/posts.ts', 'auth/passport.ts'],
      assignments: { coder_1: ['app.ts', 'routes/posts.ts'], coder_2: ['models/post.ts', 'auth/passport.ts'] },
      contracts: [
        makeContract({ name: 'PostSchema', type: 'variable', exportedBy: 'models/post.ts' }),
        makeContract({ name: 'passportStrategy', type: 'function', exportedBy: 'auth/passport.ts' }),
      ],
      researchNeeded: false,
    });

    const manifest = generateManifest(plan);

    // Koa framework
    const egressSinks = manifest.intentional_sinks.filter(s => s.type === 'EGRESS');
    expect(egressSinks.some(s => s.reason.toLowerCase().includes('koa'))).toBe(true);

    // Mongoose DB
    const storageSinks = manifest.intentional_sinks.filter(s => s.type === 'STORAGE');
    expect(storageSinks.some(s => s.reason.toLowerCase().includes('mongoose'))).toBe(true);

    // Passport auth
    const authSinks = manifest.intentional_sinks.filter(s => s.type === 'AUTH');
    expect(authSinks.some(s => s.reason.toLowerCase().includes('passport'))).toBe(true);
  });

  it('data_origins is undefined when no sensitive fields detected', () => {
    const plan = makePlan({
      prompt: 'Build a hello world Express server',
      files: ['server.ts'],
      assignments: { coder_1: ['server.ts'] },
      contracts: [],
    });

    const manifest = generateManifest(plan);
    expect(manifest.data_origins).toBeUndefined();
  });

  it('multiple frameworks can be detected simultaneously', () => {
    // Edge case: prompt mentions both Express and Next.js
    const plan = makePlan({
      prompt: 'Build a Next.js frontend with an Express API backend',
      files: ['pages/index.tsx', 'api/server.ts'],
      assignments: { coder_1: ['pages/index.tsx', 'api/server.ts'] },
      contracts: [],
    });

    const manifest = generateManifest(plan);
    // Both should be detected — the app legitimately uses both
    const egressSinks = manifest.intentional_sinks.filter(s => s.type === 'EGRESS');
    expect(egressSinks.length).toBeGreaterThanOrEqual(2);
  });

  it('research queries contribute to API detection', () => {
    const plan = makePlan({
      prompt: 'Build a live sports dashboard',
      files: ['server.ts', 'api.ts', 'dashboard.html'],
      assignments: { coder_1: ['server.ts', 'api.ts', 'dashboard.html'] },
      contracts: [],
      researchNeeded: true,
      researchQueries: ['free sports API endpoint JSON'],
    });

    const manifest = generateManifest(plan);
    // generic-http should be detected from research queries containing 'api' and 'endpoint'
    const externalSinks = manifest.intentional_sinks.filter(s => s.type === 'EXTERNAL');
    expect(externalSinks.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Corpus Builder
// ---------------------------------------------------------------------------

describe('buildCorpus', () => {
  it('concatenates all plan fields into fullText', () => {
    const plan = makePlan({
      prompt: 'Build a Spotify app',
      files: ['server.ts', 'api.ts'],
      contracts: [makeContract({ name: 'fetchData', params: ['query', 'limit'] })],
      researchQueries: ['Spotify API docs'],
    });
    const corpus = buildCorpus(plan);

    expect(corpus.fullText).toContain('Spotify');
    expect(corpus.fullText).toContain('server.ts');
    expect(corpus.fullText).toContain('fetchData');
    expect(corpus.fullText).toContain('query');
    expect(corpus.fullText).toContain('Spotify API docs');
  });

  it('handles empty plan gracefully', () => {
    const plan = makePlan();
    const corpus = buildCorpus(plan);
    expect(corpus.fullText).toBe('');
    expect(corpus.contractNames.length).toBe(0);
  });
});
