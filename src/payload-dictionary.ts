
import type { NeuralMapNode } from './types';


export type PayloadClass =
  | 'sql_injection'
  | 'command_injection'
  | 'xss'
  | 'path_traversal'
  | 'ldap_injection'
  | 'xpath_injection'
  | 'xxe'
  | 'deserialization'
  | 'open_redirect'
  | 'log_injection'
  | 'ssti';


export const SINK_CLASS_MAP: Record<string, PayloadClass> = {
  'db_read': 'sql_injection',
  'db_write': 'sql_injection',
  'db_stored_proc': 'sql_injection',
  'sql_query': 'sql_injection',
  'system_exec': 'command_injection',
  'http_response': 'xss',
  'redirect': 'open_redirect',
  'ldap_query': 'ldap_injection',
  'xpath_query': 'xpath_injection',
  'xml_parse': 'xxe',
  'file_read': 'path_traversal',
  'file_write': 'path_traversal',
  'file_access': 'path_traversal',
  'deserialize': 'deserialization',
  'deserialize_rce': 'deserialization',
  'log_write': 'log_injection',
  'template_render': 'ssti',
};

/**
 * Resolve a sink's node_subtype to a payload class.
 * Uses exact match first, then fuzzy `.includes()` fallback.
 */
export function resolveSinkClass(subtype: string): PayloadClass | null {
  const exact = SINK_CLASS_MAP[subtype];
  if (exact) return exact;

  for (const [key, cls] of Object.entries(SINK_CLASS_MAP)) {
    if (subtype.includes(key) || key.includes(subtype)) {
      return cls;
    }
  }

  return null;
}


const CWE_TO_PAYLOAD_CLASS: Record<string, PayloadClass> = {
  'CWE-89': 'sql_injection',
  'CWE-564': 'sql_injection',
  'CWE-78': 'command_injection',
  'CWE-77': 'command_injection',
  'CWE-79': 'xss',
  'CWE-22': 'path_traversal',
  'CWE-23': 'path_traversal',
  'CWE-36': 'path_traversal',
  'CWE-90': 'ldap_injection',
  'CWE-643': 'xpath_injection',
  'CWE-611': 'xxe',
  'CWE-918': 'open_redirect',
  'CWE-601': 'open_redirect',
  'CWE-502': 'deserialization',
  'CWE-117': 'log_injection',
  'CWE-1336': 'ssti',
};

export function inferPayloadClassFromCWE(cwe: string): PayloadClass | null {
  return CWE_TO_PAYLOAD_CLASS[cwe] ?? null;
}


export interface ProofPayloadTemplate {
  value: string;
  canary: string;
  context: string;
  execution_safe: boolean;
}

export const SQL_INJECTION_PAYLOADS: Record<string, ProofPayloadTemplate> = {
  sql_string_tautology: {
    value: "' OR '1'='1",
    canary: '1',
    context: 'sql_string',
    execution_safe: true,
  },
  sql_string_union_canary: {
    value: "' UNION SELECT 'DST_CANARY_SQLI' --",
    canary: 'DST_CANARY_SQLI',
    context: 'sql_string',
    execution_safe: true,
  },
  sql_string_error: {
    value: "' AND 1=CONVERT(int,'DST_CANARY') --",
    canary: 'DST_CANARY',
    context: 'sql_string',
    execution_safe: true,
  },
  sql_numeric_tautology: {
    value: '1 OR 1=1',
    canary: '1',
    context: 'sql_numeric',
    execution_safe: true,
  },
  sql_numeric_union_canary: {
    value: "1 UNION SELECT 'DST_CANARY_SQLI' --",
    canary: 'DST_CANARY_SQLI',
    context: 'sql_numeric',
    execution_safe: true,
  },
  sql_time_mysql: {
    value: "' OR SLEEP(2) -- -",
    canary: '',
    context: 'sql_string',
    execution_safe: false,
  },
  sql_time_postgres: {
    value: "'; SELECT pg_sleep(2) --",
    canary: '',
    context: 'sql_string',
    execution_safe: false,
  },
  sql_time_mssql: {
    value: "'; WAITFOR DELAY '00:00:02' --",
    canary: '',
    context: 'sql_string',
    execution_safe: false,
  },
};


export interface TransformEffect {
  effect: 'encoding' | 'type_coercion' | 'destruction' | 'format_constraint'
        | 'path_normalization' | 'xml_processing' | 'none' | 'unknown';
  payload_action: 'encode_before_delivery' | 'check_if_numeric_only'
                | 'payload_blocked' | 'embed_in_format' | 'check_traversal_survival'
                | 'embed_in_xml' | 'pass_through' | 'flag_uncertain';
}

export const TRANSFORM_EFFECTS: Record<string, TransformEffect> = {
  'codec':        { effect: 'encoding',           payload_action: 'encode_before_delivery' },
  'format':       { effect: 'type_coercion',      payload_action: 'check_if_numeric_only' },
  'encrypt':      { effect: 'destruction',         payload_action: 'payload_blocked' },
  'parse':        { effect: 'format_constraint',   payload_action: 'embed_in_format' },
  'path_resolve': { effect: 'path_normalization',  payload_action: 'check_traversal_survival' },
  'alloc':        { effect: 'none',                payload_action: 'pass_through' },
  'xml_parse':    { effect: 'xml_processing',      payload_action: 'embed_in_xml' },
  'prng_weak':    { effect: 'none',                payload_action: 'pass_through' },
};

/**
 * Classify what a TRANSFORM node does to a payload.
 * Primary: subtype-based. Fallback: code_snapshot regex.
 *
 * CRITICAL FIX #2: `sanitize` maps to DESTRUCTION, not encoding.
 * HtmlUtils.htmlEscape DESTROYS payloads.
 */
export function classifyTransform(node: NeuralMapNode): TransformEffect {
  const effect = TRANSFORM_EFFECTS[node.node_subtype];
  if (effect) return effect;

  const snap = node.analysis_snapshot || node.code_snapshot;

  if (/\b(sanitize|htmlEscape|escapeHtml|encodeForHTML|xssFilter|DOMPurify|bleach)\b/i.test(snap)) {
    return { effect: 'destruction', payload_action: 'payload_blocked' };
  }
  if (/\b(encode|encodeURI|encodeURIComponent|URLEncoder|Base64)\b/i.test(snap)) {
    return { effect: 'encoding', payload_action: 'encode_before_delivery' };
  }
  if (/\b(parseInt|parseLong|parseDouble|parseFloat|Number\(|int\(|float\()\b/.test(snap)) {
    return { effect: 'type_coercion', payload_action: 'check_if_numeric_only' };
  }
  if (/\b(hash|digest|encrypt|cipher)\b/i.test(snap)) {
    return { effect: 'destruction', payload_action: 'payload_blocked' };
  }

  return { effect: 'unknown', payload_action: 'flag_uncertain' };
}


export const SAFE_COMMANDS = [
  'echo DST_CMDI_PROOF',
  'printf DST_CMDI_PROOF',
  'id',
  'whoami',
  'hostname',
  'uname -a',
  'ver',
];


export const SQL_DESTRUCTIVE = /\b(DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT|UPDATE|GRANT|REVOKE|EXEC)\b/i;
export const SQL_READ_ONLY = /\b(SELECT|OR|AND|UNION|SLEEP|WAITFOR|pg_sleep|CONVERT)\b/i;
