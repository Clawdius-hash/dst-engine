/**
 * Security Type-State — Phase B
 *
 * Tracks per-domain neutralization of data flowing through the graph.
 * Each flag answers: "Is this data safe for injection into domain X?"
 *
 * A value of `false` means the data has NOT been neutralized for that
 * domain. A TRANSFORM node with the appropriate neutralizing subtype
 * flips the corresponding flag(s) to `true`.
 *
 * The mismatch between actual state and sink requirement IS the finding.
 */

export interface SecurityState {
  sql_safe: boolean;
  xss_safe: boolean;
  shell_safe: boolean;
  path_safe: boolean;
  ldap_safe: boolean;
  xpath_safe: boolean;
  xxe_safe: boolean;
  deserialize_safe: boolean;
  redirect_safe: boolean;
  ssti_safe: boolean;
  log_safe: boolean;
}

export type SecurityDomain = keyof SecurityState;

export const ALL_DOMAINS: readonly SecurityDomain[] = [
  'sql_safe', 'xss_safe', 'shell_safe', 'path_safe', 'ldap_safe',
  'xpath_safe', 'xxe_safe', 'deserialize_safe', 'redirect_safe',
  'ssti_safe', 'log_safe',
] as const;

export function createUntrustedState(): SecurityState {
  return {
    sql_safe: false, xss_safe: false, shell_safe: false, path_safe: false,
    ldap_safe: false, xpath_safe: false, xxe_safe: false,
    deserialize_safe: false, redirect_safe: false, ssti_safe: false, log_safe: false,
  };
}

export function createTrustedState(): SecurityState {
  return {
    sql_safe: true, xss_safe: true, shell_safe: true, path_safe: true,
    ldap_safe: true, xpath_safe: true, xxe_safe: true,
    deserialize_safe: true, redirect_safe: true, ssti_safe: true, log_safe: true,
  };
}

import { getNeutralizedDomains } from './neutralizers.js';

/**
 * Apply a neutralizing transform to a SecurityState.
 * Returns a NEW state with the appropriate domain flags set to true.
 * Does not mutate the input.
 */
export function applyNeutralizer(state: SecurityState, subtype: string): SecurityState {
  const domains = getNeutralizedDomains(subtype);
  if (domains.length === 0) return state;

  const updated = { ...state };
  for (const domain of domains) {
    updated[domain] = true;
  }
  return updated;
}

/**
 * Check whether data in a given state is safe for a specific sink subtype.
 */
export function isStateValidForSink(state: SecurityState, sinkSubtype: string): boolean {
  const domain = sinkSubtypeToDomain(sinkSubtype);
  if (!domain) return false;
  return state[domain];
}

/**
 * Map a sink node_subtype to the SecurityState domain it requires.
 */
export function sinkSubtypeToDomain(sinkSubtype: string): SecurityDomain | null {
  if (sinkSubtype.includes('sql') || sinkSubtype === 'db_read' ||
      sinkSubtype === 'db_write' || sinkSubtype === 'db_stored_proc') return 'sql_safe';
  if (sinkSubtype === 'http_response' || sinkSubtype.includes('html_') ||
      sinkSubtype === 'template_render' || sinkSubtype === 'xss_sink') return 'xss_safe';
  if (sinkSubtype === 'system_exec' || sinkSubtype.includes('shell_') ||
      sinkSubtype === 'process_spawn') return 'shell_safe';
  if (sinkSubtype.startsWith('file_')) return 'path_safe';
  if (sinkSubtype.includes('ldap_')) return 'ldap_safe';
  if (sinkSubtype.includes('xpath_')) return 'xpath_safe';
  if (sinkSubtype.includes('xml_')) return 'xxe_safe';
  if (sinkSubtype.includes('deserialize') || sinkSubtype.includes('unserialize') ||
      sinkSubtype.includes('unpickle')) return 'deserialize_safe';
  if (sinkSubtype.includes('redirect')) return 'redirect_safe';
  if (sinkSubtype === 'template_exec') return 'ssti_safe';
  if (sinkSubtype === 'log_write') return 'log_safe';
  return null;
}

/**
 * Derive the legacy `tainted` boolean from SecurityState.
 * Data is considered tainted if ANY domain flag is still false.
 * Used for backward compatibility during migration.
 */
export function isTainted(state: SecurityState): boolean {
  return ALL_DOMAINS.some(d => !state[d]);
}
