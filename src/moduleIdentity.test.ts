import { describe, it, expect } from 'vitest';
import { getModuleCategory, isDangerousMethod, categoryToSecurityDomain } from './moduleIdentity.js';
import type { ModuleCategory } from './moduleIdentity.js';

describe('getModuleCategory', () => {
  it('classifies database modules', () => {
    expect(getModuleCategory('pg')).toBe('DATABASE');
    expect(getModuleCategory('mysql')).toBe('DATABASE');
    expect(getModuleCategory('mysql2')).toBe('DATABASE');
    expect(getModuleCategory('mongodb')).toBe('DATABASE');
    expect(getModuleCategory('mongoose')).toBe('DATABASE');
    expect(getModuleCategory('sqlite3')).toBe('DATABASE');
    expect(getModuleCategory('better-sqlite3')).toBe('DATABASE');
    expect(getModuleCategory('sequelize')).toBe('DATABASE');
    expect(getModuleCategory('knex')).toBe('DATABASE');
    expect(getModuleCategory('typeorm')).toBe('DATABASE');
    expect(getModuleCategory('mssql')).toBe('DATABASE');
  });

  it('classifies shell/process modules', () => {
    expect(getModuleCategory('child_process')).toBe('SHELL');
    expect(getModuleCategory('shelljs')).toBe('SHELL');
  });

  it('classifies filesystem modules', () => {
    expect(getModuleCategory('fs')).toBe('FILESYSTEM');
    expect(getModuleCategory('fs/promises')).toBe('FILESYSTEM');
  });

  it('classifies network modules', () => {
    expect(getModuleCategory('http')).toBe('NETWORK');
    expect(getModuleCategory('https')).toBe('NETWORK');
    expect(getModuleCategory('axios')).toBe('NETWORK');
    expect(getModuleCategory('node-fetch')).toBe('NETWORK');
    expect(getModuleCategory('got')).toBe('NETWORK');
    expect(getModuleCategory('superagent')).toBe('NETWORK');
  });

  it('classifies template engines', () => {
    expect(getModuleCategory('ejs')).toBe('TEMPLATE');
    expect(getModuleCategory('pug')).toBe('TEMPLATE');
    expect(getModuleCategory('handlebars')).toBe('TEMPLATE');
    expect(getModuleCategory('nunjucks')).toBe('TEMPLATE');
    expect(getModuleCategory('mustache')).toBe('TEMPLATE');
  });

  it('classifies HTTP frameworks', () => {
    expect(getModuleCategory('express')).toBe('HTTP_FRAMEWORK');
    expect(getModuleCategory('koa')).toBe('HTTP_FRAMEWORK');
    expect(getModuleCategory('fastify')).toBe('HTTP_FRAMEWORK');
    expect(getModuleCategory('@hapi/hapi')).toBe('HTTP_FRAMEWORK');
    expect(getModuleCategory('hono')).toBe('HTTP_FRAMEWORK');
  });

  it('classifies code eval modules', () => {
    expect(getModuleCategory('vm')).toBe('CODE_EVAL');
    expect(getModuleCategory('vm2')).toBe('CODE_EVAL');
  });

  it('classifies deserialization modules', () => {
    expect(getModuleCategory('js-yaml')).toBe('DESERIALIZE');
    expect(getModuleCategory('xml2js')).toBe('DESERIALIZE');
  });

  it('classifies LDAP modules', () => {
    expect(getModuleCategory('ldapjs')).toBe('LDAP');
  });

  it('returns null for unknown modules', () => {
    expect(getModuleCategory('lodash')).toBeNull();
    expect(getModuleCategory('my-custom-lib')).toBeNull();
  });

  it('returns null for relative imports', () => {
    expect(getModuleCategory('./routes/api')).toBeNull();
    expect(getModuleCategory('../lib/helper')).toBeNull();
  });
});

describe('isDangerousMethod', () => {
  it('identifies dangerous database methods', () => {
    expect(isDangerousMethod('DATABASE', 'query')).toBe(true);
    expect(isDangerousMethod('DATABASE', 'exec')).toBe(true);
    expect(isDangerousMethod('DATABASE', 'execute')).toBe(true);
    expect(isDangerousMethod('DATABASE', 'raw')).toBe(true);
    expect(isDangerousMethod('DATABASE', '$queryRaw')).toBe(true);
  });

  it('identifies dangerous shell methods', () => {
    expect(isDangerousMethod('SHELL', 'exec')).toBe(true);
    expect(isDangerousMethod('SHELL', 'execSync')).toBe(true);
    expect(isDangerousMethod('SHELL', 'spawn')).toBe(true);
  });

  it('identifies dangerous filesystem methods', () => {
    expect(isDangerousMethod('FILESYSTEM', 'readFile')).toBe(true);
    expect(isDangerousMethod('FILESYSTEM', 'writeFile')).toBe(true);
    expect(isDangerousMethod('FILESYSTEM', 'readFileSync')).toBe(true);
  });

  it('returns false for safe methods', () => {
    expect(isDangerousMethod('DATABASE', 'close')).toBe(false);
    expect(isDangerousMethod('DATABASE', 'connect')).toBe(false);
    expect(isDangerousMethod('FILESYSTEM', 'existsSync')).toBe(false);
  });

  it('HTTP_FRAMEWORK has no dangerous methods (it registers callbacks)', () => {
    expect(isDangerousMethod('HTTP_FRAMEWORK', 'get')).toBe(false);
    expect(isDangerousMethod('HTTP_FRAMEWORK', 'post')).toBe(false);
  });
});

describe('categoryToSecurityDomain', () => {
  it('maps categories to security domains', () => {
    expect(categoryToSecurityDomain('DATABASE')).toBe('sql_safe');
    expect(categoryToSecurityDomain('SHELL')).toBe('shell_safe');
    expect(categoryToSecurityDomain('FILESYSTEM')).toBe('path_safe');
    expect(categoryToSecurityDomain('TEMPLATE')).toBe('ssti_safe');
    expect(categoryToSecurityDomain('DESERIALIZE')).toBe('deserialize_safe');
    expect(categoryToSecurityDomain('LDAP')).toBe('ldap_safe');
    expect(categoryToSecurityDomain('XPATH')).toBe('xpath_safe');
  });

  it('HTTP_FRAMEWORK returns empty (frameworks are sources, not sinks)', () => {
    expect(categoryToSecurityDomain('HTTP_FRAMEWORK')).toBe('');
  });
});
