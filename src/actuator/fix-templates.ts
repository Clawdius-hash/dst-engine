/**
 * DST Actuation Engine — Fix Template Library
 *
 * Three operations: REMOVE, INSERT, WRAP
 * Each CWE pattern maps to a deterministic fix.
 * Same finding → same fix. Every time.
 *
 * Built by Atreus, March 23 2026. Extended by [?] (night agent), March 24 2026.
 * "The fix is the inverse of the finding."
 */

export type FixOperation = 'REMOVE' | 'INSERT' | 'WRAP';

export interface FixTemplate {
  cwe: string;
  operation: FixOperation;
  description: string;
  /** What to look for in the AST */
  pattern: string;
  /** The fix to apply — uses {{variable}} placeholders filled from finding context */
  template: string;
  /** Imports needed for the fix */
  imports?: string[];
}

// ---------------------------------------------------------------------------
// Core fix templates — injection family
// ---------------------------------------------------------------------------

export const FIX_TEMPLATES: Record<string, FixTemplate> = {
  'CWE-89': {
    cwe: 'CWE-89',
    operation: 'WRAP',
    description: 'SQL Injection → Parameterized query',
    pattern: 'string_concat_in_query',
    template: '{{query_function}}({{query_string}}, [{{tainted_variables}}])',
    imports: [],
  },

  'CWE-79': {
    cwe: 'CWE-79',
    operation: 'WRAP',
    description: 'XSS → Output encoding',
    pattern: 'tainted_in_html_output',
    template: 'escapeHtml({{tainted_variable}})',
    imports: ['escapeHtml'],
  },

  'CWE-78': {
    cwe: 'CWE-78',
    operation: 'REMOVE',
    description: 'OS Command Injection → Use exec array form',
    pattern: 'shell_string_with_taint',
    template: 'execFile({{command}}, [{{arguments}}])',
    imports: ['execFile from child_process'],
  },

  'CWE-22': {
    cwe: 'CWE-22',
    operation: 'INSERT',
    description: 'Path Traversal → Canonicalize + jail',
    pattern: 'tainted_in_file_path',
    template: [
      'const {{safe_var}} = path.resolve({{base_dir}}, {{tainted_variable}});',
      'if (!{{safe_var}}.startsWith(path.resolve({{base_dir}}))) throw new Error("Path traversal blocked");',
    ].join('\n'),
    imports: ['path'],
  },

  'CWE-94': {
    cwe: 'CWE-94',
    operation: 'REMOVE',
    description: 'Code Injection → Remove eval, use safe alternative',
    pattern: 'eval_with_taint',
    template: 'JSON.parse({{tainted_variable}})',
    imports: [],
  },

  'CWE-502': {
    cwe: 'CWE-502',
    operation: 'WRAP',
    description: 'Deserialization → Type-safe parse with schema',
    pattern: 'deserialize_untrusted',
    template: 'safeDeserialize({{tainted_variable}}, {{expected_schema}})',
    imports: ['safeDeserialize'],
  },

  'CWE-352': {
    cwe: 'CWE-352',
    operation: 'INSERT',
    description: 'CSRF → Add token validation',
    pattern: 'state_changing_no_csrf',
    template: 'if (!verifyCsrfToken(req)) return res.status(403).send("CSRF token invalid");',
    imports: ['verifyCsrfToken'],
  },

  'CWE-307': {
    cwe: 'CWE-307',
    operation: 'INSERT',
    description: 'Brute Force → Add rate limiting',
    pattern: 'auth_endpoint_no_rate_limit',
    template: 'app.use({{route}}, rateLimit({ windowMs: 15 * 60 * 1000, max: {{max_attempts}} }));',
    imports: ['rateLimit from express-rate-limit'],
  },

  'CWE-611': {
    cwe: 'CWE-611',
    operation: 'INSERT',
    description: 'XXE → Disable external entities',
    pattern: 'xml_parse_no_xxe_protection',
    template: '{{parser}}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
    imports: [],
  },

  'CWE-918': {
    cwe: 'CWE-918',
    operation: 'INSERT',
    description: 'SSRF → Validate URL destination',
    pattern: 'fetch_with_tainted_url',
    template: [
      'const {{parsed}} = new URL({{tainted_url}});',
      'if ({{parsed}}.hostname === "localhost" || {{parsed}}.hostname.startsWith("10.") || {{parsed}}.hostname.startsWith("192.168.")) throw new Error("SSRF blocked");',
    ].join('\n'),
    imports: [],
  },

  'CWE-798': {
    cwe: 'CWE-798',
    operation: 'REMOVE',
    description: 'Hardcoded Credentials → Use environment variable',
    pattern: 'hardcoded_secret',
    template: 'process.env.{{SECRET_NAME}}',
    imports: [],
  },

  'CWE-327': {
    cwe: 'CWE-327',
    operation: 'WRAP',
    description: 'Weak Crypto → Use strong algorithm',
    pattern: 'weak_crypto_algorithm',
    template: "crypto.createHash('sha256')",
    imports: ['crypto'],
  },

  'CWE-312': {
    cwe: 'CWE-312',
    operation: 'WRAP',
    description: 'Cleartext Storage → Encrypt before storage',
    pattern: 'sensitive_cleartext_storage',
    template: 'encrypt({{sensitive_data}}, process.env.ENCRYPTION_KEY)',
    imports: ['encrypt'],
  },

  // ---------------------------------------------------------------------------
  // Extended templates — night agent, March 24 2026
  // ---------------------------------------------------------------------------

  'CWE-287': {
    cwe: 'CWE-287',
    operation: 'INSERT',
    description: 'Improper Authentication → Add authentication middleware',
    pattern: 'unprotected_route_handler',
    template: 'app.use({{route}}, authenticateToken);',
    imports: ['authenticateToken from middleware/auth'],
  },

  'CWE-862': {
    cwe: 'CWE-862',
    operation: 'INSERT',
    description: 'Missing Authorization → Add authorization check',
    pattern: 'action_without_authz_check',
    template: 'if (!authorize({{user}}, {{resource}}, {{action}})) return res.status(403).json({ error: "Forbidden" });',
    imports: ['authorize from middleware/authz'],
  },

  'CWE-200': {
    cwe: 'CWE-200',
    operation: 'WRAP',
    description: 'Information Exposure → Sanitize error response',
    pattern: 'detailed_error_in_response',
    template: 'res.status({{status_code}}).json({ error: "An error occurred" })',
    imports: [],
  },

  'CWE-434': {
    cwe: 'CWE-434',
    operation: 'INSERT',
    description: 'Unrestricted Upload → Validate file type and size',
    pattern: 'file_upload_no_validation',
    template: [
      'const allowedTypes = [{{allowed_mime_types}}];',
      'if (!allowedTypes.includes({{file}}.mimetype)) return res.status(400).json({ error: "File type not allowed" });',
      'if ({{file}}.size > {{max_size}}) return res.status(400).json({ error: "File too large" });',
    ].join('\n'),
    imports: [],
  },

  'CWE-476': {
    cwe: 'CWE-476',
    operation: 'INSERT',
    description: 'NULL Pointer Dereference → Add null check',
    pattern: 'dereference_without_null_check',
    template: 'if ({{pointer}} == null) { {{error_handler}}; return; }',
    imports: [],
  },

  'CWE-416': {
    cwe: 'CWE-416',
    operation: 'INSERT',
    description: 'Use After Free → Nullify pointer after free',
    pattern: 'use_after_free',
    template: [
      'free({{pointer}});',
      '{{pointer}} = NULL;',
    ].join('\n'),
    imports: [],
  },

  'CWE-787': {
    cwe: 'CWE-787',
    operation: 'WRAP',
    description: 'Out-of-bounds Write → Add bounds check',
    pattern: 'write_without_bounds_check',
    template: 'if ({{index}} >= 0 && {{index}} < {{buffer_size}}) { {{buffer}}[{{index}}] = {{value}}; }',
    imports: [],
  },

  'CWE-400': {
    cwe: 'CWE-400',
    operation: 'INSERT',
    description: 'Uncontrolled Resource Consumption → Add resource limits',
    pattern: 'resource_allocation_no_limit',
    template: 'if ({{current_count}} >= {{max_limit}}) throw new Error("Resource limit exceeded");',
    imports: [],
  },

  'CWE-522': {
    cwe: 'CWE-522',
    operation: 'WRAP',
    description: 'Insufficiently Protected Credentials → Hash with bcrypt',
    pattern: 'password_stored_weak',
    template: 'await bcrypt.hash({{password}}, {{salt_rounds}})',
    imports: ['bcrypt'],
  },

  'CWE-601': {
    cwe: 'CWE-601',
    operation: 'INSERT',
    description: 'Open Redirect → Validate redirect URL against allowlist',
    pattern: 'redirect_with_tainted_url',
    template: [
      'const {{parsed}} = new URL({{redirect_url}}, {{base_url}});',
      'if ({{parsed}}.origin !== {{base_url}}) return res.status(400).json({ error: "Invalid redirect" });',
    ].join('\n'),
    imports: [],
  },
};

// ---------------------------------------------------------------------------
// Actuator engine
// ---------------------------------------------------------------------------

export interface Finding {
  cwe: string;
  line: number;
  column: number;
  source_node: string;
  sink_node: string;
  tainted_variable: string;
  context: Record<string, string>;
}

export interface Patch {
  line: number;
  column: number;
  operation: FixOperation;
  original: string;
  replacement: string;
  imports: string[];
  description: string;
}

/**
 * Generate a deterministic patch for a finding.
 * Same finding → same patch. Every time.
 */
export function actuate(finding: Finding): Patch | null {
  const template = FIX_TEMPLATES[finding.cwe];
  if (!template) return null;

  // Instantiate template with context variables
  let replacement = template.template;
  const allContext = {
    ...finding.context,
    tainted_variable: finding.tainted_variable,
    tainted_variables: finding.tainted_variable,
  };

  for (const [key, value] of Object.entries(allContext)) {
    replacement = replacement.replace(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), value);
  }

  return {
    line: finding.line,
    column: finding.column,
    operation: template.operation,
    original: '', // filled by caller from source
    replacement,
    imports: template.imports || [],
    description: template.description,
  };
}

/**
 * Apply patches to source code. Bottom-up to preserve line numbers.
 */
export function applyPatches(source: string, patches: Patch[]): string {
  const lines = source.split('\n');

  // Sort patches bottom-up so line numbers stay valid
  const sorted = [...patches].sort((a, b) => b.line - a.line);

  for (const patch of sorted) {
    const lineIdx = patch.line - 1; // 0-indexed
    if (lineIdx < 0 || lineIdx >= lines.length) continue;

    switch (patch.operation) {
      case 'WRAP':
        lines[lineIdx] = patch.replacement;
        break;
      case 'INSERT':
        lines.splice(lineIdx, 0, patch.replacement);
        break;
      case 'REMOVE':
        lines[lineIdx] = patch.replacement;
        break;
    }
  }

  // Add any needed imports at top
  const allImports = [...new Set(sorted.flatMap(p => p.imports))].filter(Boolean);
  if (allImports.length > 0) {
    const importLines = allImports.map(i => {
      if (i.includes(' from ')) return `import { ${i.split(' from ')[0]} } from '${i.split(' from ')[1]}';`;
      return `import ${i} from '${i}';`;
    });
    lines.unshift(...importLines, '');
  }

  return lines.join('\n');
}
