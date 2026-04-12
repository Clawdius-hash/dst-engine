/**
 * Neutralizer Utility Module — Phase B
 *
 * Centralizes all neutralizing subtype detection.
 * Uses prefix matching: 'sanitize_html' matches the 'sanitize' prefix.
 *
 * Zero false positives verified: no non-neutralizing subtype in the
 * codebase starts with any neutralizing prefix.
 */

import type { SecurityDomain } from './security-state.js';

const NEUTRALIZING_PREFIXES: readonly string[] = [
  'sanitize', 'encode', 'escape', 'hash', 'encrypt', 'validate', 'parameterize',
];

/**
 * Check if a TRANSFORM subtype is a neutralizing operation.
 * Matches exact values AND domain-aware variants (e.g., sanitize_html).
 */
export function isNeutralizingSubtype(subtype: string): boolean {
  if (subtype === 'prepared_statement') return true;
  return NEUTRALIZING_PREFIXES.some(p => subtype === p || subtype.startsWith(p + '_'));
}

/**
 * Map a TRANSFORM subtype to the security domains it neutralizes.
 *
 * CRITICAL: These mappings are verified against actual verifier behavior.
 *
 * hash: destroys data entirely — marks ALL domains safe.
 * encrypt: irreversible transformation — safe for injection domains.
 *   NOT deserialize_safe: encrypted serialized data is still dangerous when decrypted.
 * sanitize (generic): output-side neutralization — marks XSS/shell/log safe.
 *   NOT sql_safe — SQL requires parameterization, not sanitization.
 * encode/escape: output encoding — marks XSS/log/SSTI safe.
 * validate: input validation — marks path/redirect safe.
 *   NOT xxe_safe (XXE fix is disabling external entities, not validation).
 *   NOT deserialize_safe (validation happens AFTER the dangerous operation).
 * parameterize/prepared_statement: query parameter binding.
 *   Marks sql_safe, ldap_safe, xpath_safe (parameterized APIs exist for all three).
 */
export function getNeutralizedDomains(subtype: string): SecurityDomain[] {
  // Domain-aware variants — specific mapping
  if (subtype === 'sanitize_html') return ['xss_safe'];
  if (subtype === 'sanitize_sql') return ['sql_safe'];
  if (subtype === 'sanitize_shell') return ['shell_safe'];
  if (subtype === 'sanitize_path') return ['path_safe'];
  if (subtype === 'sanitize_ldap') return ['ldap_safe'];
  if (subtype === 'sanitize_xpath') return ['xpath_safe'];
  if (subtype === 'sanitize_log') return ['log_safe'];
  if (subtype === 'encode_url') return ['redirect_safe'];

  // Generic neutralizers — CONSERVATIVE mappings verified against verifier behavior
  switch (subtype) {
    case 'hash':
      // Data is destroyed — can't be injected into anything
      return ['sql_safe', 'xss_safe', 'shell_safe', 'path_safe', 'ldap_safe',
              'xpath_safe', 'xxe_safe', 'deserialize_safe', 'redirect_safe',
              'ssti_safe', 'log_safe'];

    case 'encrypt':
      // Data is irreversibly transformed — safe for injection domains
      // NOT deserialize_safe: encrypted serialized data is still dangerous when decrypted
      return ['sql_safe', 'xss_safe', 'shell_safe', 'path_safe', 'ldap_safe',
              'xpath_safe', 'ssti_safe', 'log_safe'];

    case 'sanitize':
      // Generic sanitize — output-side neutralization
      // NOT sql_safe: SQL requires parameterization, not sanitization
      return ['xss_safe', 'shell_safe', 'ssti_safe', 'log_safe'];

    case 'encode':
    case 'escape':
      // Output encoding — context-dependent but conservatively marks output domains
      return ['xss_safe', 'log_safe', 'ssti_safe'];

    case 'validate':
      // Input validation — structural checks
      // NOT xxe_safe (fix is config: disable external entities)
      // NOT deserialize_safe (validation happens after the dangerous operation)
      return ['path_safe', 'redirect_safe'];

    case 'parameterize':
    case 'prepared_statement':
      // Query parameter binding — verified for SQL, LDAP (Filter.eq), XPath (XPathVariableResolver)
      return ['sql_safe', 'ldap_safe', 'xpath_safe'];

    default:
      // Unknown subtype — check if it starts with a known prefix
      if (subtype.startsWith('sanitize_')) return ['xss_safe', 'shell_safe'];
      if (subtype.startsWith('encode_')) return ['xss_safe', 'log_safe'];
      if (subtype.startsWith('escape_')) return ['xss_safe', 'log_safe'];
      if (subtype.startsWith('validate_')) return ['path_safe', 'redirect_safe'];
      return [];
  }
}
