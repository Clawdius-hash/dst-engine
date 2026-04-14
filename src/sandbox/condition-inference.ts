export interface ConditionValue {
  paramPath: string[];
  value: any;
}

export function parseCondition(condition: string): ConditionValue | null {
  const trimmed = condition.trim();

  const eqMatch = trimmed.match(/^([\w.]+)\s*===?\s*['"]([^'"]+)['"]\s*$/);
  if (eqMatch) return { paramPath: eqMatch[1].split('.'), value: eqMatch[2] };

  const neqMatch = trimmed.match(/^([\w.]+)\s*!==?\s*['"]([^'"]+)['"]\s*$/);
  if (neqMatch) return { paramPath: neqMatch[1].split('.'), value: true };

  const revEqMatch = trimmed.match(/^['"]([^'"]+)['"]\s*===?\s*([\w.]+)\s*$/);
  if (revEqMatch) return { paramPath: revEqMatch[2].split('.'), value: revEqMatch[1] };

  const cmpMatch = trimmed.match(/^([\w.]+)\s*([><=]+)\s*(\d+)\s*$/);
  if (cmpMatch) {
    const num = parseInt(cmpMatch[3]);
    const op = cmpMatch[2];
    const value = op.includes('>') ? num + 1 : op.includes('<') ? num - 1 : num;
    return { paramPath: cmpMatch[1].split('.'), value };
  }

  const truthyMatch = trimmed.match(/^([\w.]+)\s*$/);
  if (truthyMatch) return { paramPath: truthyMatch[1].split('.'), value: true };

  return null;
}

export function conditionsToParams(
  conditions: ConditionValue[],
  funcParamNames: string[],
): Record<string, any> {
  const params: Record<string, any> = {};
  for (const cond of conditions) {
    if (cond.paramPath.length === 0) continue;
    const root = cond.paramPath[0];
    if (!funcParamNames.includes(root)) continue;
    if (cond.paramPath.length === 1) {
      params[root] = cond.value;
    } else {
      if (!params[root]) params[root] = {};
      let current = params[root];
      for (let i = 1; i < cond.paramPath.length - 1; i++) {
        if (!current[cond.paramPath[i]]) current[cond.paramPath[i]] = {};
        current = current[cond.paramPath[i]];
      }
      current[cond.paramPath[cond.paramPath.length - 1]] = cond.value;
    }
  }
  return params;
}
