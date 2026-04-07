/** Sentence templates for DST V2 semantic decomposition.
 *  Each phoneme verb maps to a template with {slot} placeholders.
 *  Templates are language-neutral — the same template works for any language. */

export const SENTENCE_TEMPLATES: Record<string, string> = {
  'retrieves-from-source': '{subject} receives {data_type} from {source}, {context}',
  'retrieves-from-collection': '{subject} retrieves value at key {key} from {collection}, {context}',
  'assigned-from-call': '{subject} assigned from {object}.{method}({args}), {context}',
  'assigned-literal': '{subject} assigned literal value {value}, {context}',
  'executes-query': '{subject} executes {query_type} query containing {variables}, {context}',
  'calls-method': '{subject} calls {method} on {object} with {args}, {context}',
  'string-concatenation': '{subject} built by concatenating {parts}, {context}',
  'parameter-binding': '{subject} binds {variable} at position {index}, {context}',
  'returns-value': '{subject} returns {value}, {context}',
  'gate-conditional': 'IF {condition} THEN following block executes, gate type: {gate_type}',
  'iterates-over': '{subject} iterates over {collection}, {context}',
  'creates-instance': '{subject} creates new {class} with {args}, {context}',
  'writes-response': '{subject} writes {args} to client response containing {variables}, {context}',
  'accesses-path': '{subject} accesses filesystem path containing {variables}, {context}',
};

/**
 * Fill a sentence template with slot values. Deterministic string interpolation.
 * Unknown slots are left as-is. Unknown templates return a fallback.
 */
export function fillTemplate(templateKey: string, slots: Record<string, string>): string {
  const template = SENTENCE_TEMPLATES[templateKey];
  if (!template) return `[unknown-template:${templateKey}] ${JSON.stringify(slots)}`;
  return template.replace(/\{(\w+)\}/g, (match, key) => slots[key] ?? match);
}
