import { FIX_TEMPLATES } from '../actuator/fix-templates.js';
import type { Finding } from '../verifier/types.js';

export interface FixPatch {
  operation: 'INSERT' | 'WRAP' | 'REMOVE';
  targetLine: number;
  code: string;
  description: string;
}

export function deriveFix(cwe: string, finding: Finding): FixPatch | null {
  const template = FIX_TEMPLATES[cwe];
  if (!template) return null;

  let code = template.template;
  const sourceLabel = finding.source.label ?? 'input';
  const sinkLabel = finding.sink.label ?? 'sink';

  code = code.replace(/\{\{tainted_variable\}\}/g, sourceLabel);
  code = code.replace(/\{\{tainted_variables\}\}/g, sourceLabel);
  code = code.replace(/\{\{tainted_url\}\}/g, sourceLabel);
  code = code.replace(/\{\{query_function\}\}/g, sinkLabel.split('(')[0] ?? sinkLabel);
  code = code.replace(/\{\{query_string\}\}/g, "'parameterized_query'");
  code = code.replace(/\{\{parsed\}\}/g, '__parsedUrl');
  code = code.replace(/\{\{safe_var\}\}/g, '__safePath');
  code = code.replace(/\{\{base_dir\}\}/g, "'.'");
  code = code.replace(/\{\{command\}\}/g, sourceLabel);
  code = code.replace(/\{\{arguments\}\}/g, sourceLabel);

  return {
    operation: template.operation,
    targetLine: finding.sink.line,
    code,
    description: template.description,
  };
}

export function applyFix(source: string, patch: FixPatch, functionStartLine: number): string {
  const lines = source.split('\n');
  const relLine = patch.targetLine - functionStartLine;

  if (relLine < 0 || relLine >= lines.length) {
    return patch.code + '\n' + source;
  }

  if (patch.operation === 'INSERT') {
    const indent = lines[relLine].match(/^(\s*)/)?.[1] ?? '  ';
    const fixLines = patch.code.split('\n').map(l => indent + l);
    lines.splice(relLine, 0, ...fixLines);
  } else {
    const indent = lines[relLine].match(/^(\s*)/)?.[1] ?? '  ';
    lines[relLine] = indent + patch.code;
  }

  return lines.join('\n');
}
