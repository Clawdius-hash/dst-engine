import type { SemanticSentence } from './types.js';

interface ResolverContext {
  sentences: SemanticSentence[];
  functionReturnTaint: Map<string, boolean>;
  functionRegistry: Map<string, string>;
  nodeById: Map<string, any>;
}

/**
 * Resolve PENDING taint in sentences using the completed functionReturnTaint map.
 */
export function resolveSentences(ctx: ResolverContext): void {
  for (const sentence of ctx.sentences) {
    if (sentence.taintBasis !== 'PENDING') continue;

    const calledMethod = sentence.slots?.method || sentence.slots?.value || '';

    let resolved = false;
    for (const [funcName, funcNodeId] of ctx.functionRegistry) {
      if (funcName.includes(':')) continue;
      if (calledMethod === funcName || calledMethod.includes(funcName + '(') || calledMethod.includes(funcName + ' (')) {
        const returnTaint = ctx.functionReturnTaint.get(funcNodeId);
        if (returnTaint === false) {
          sentence.reconciled = true;
          sentence.originalTaintClass = sentence.taintClass;
          sentence.taintClass = 'NEUTRAL';
          sentence.reconciliationReason = `Resolved clean: ${funcName} does not return tainted data`;
        } else if (returnTaint === true) {
          if (sentence.taintClass !== 'TAINTED') {
            sentence.reconciled = true;
            sentence.originalTaintClass = sentence.taintClass;
            sentence.taintClass = 'TAINTED';
            sentence.reconciliationReason = `Resolved tainted: ${funcName} returns tainted data`;
          }
        }
        resolved = true;
        break;
      }
    }

    if (!resolved) {
      const node = ctx.nodeById.get(sentence.nodeId);
      if (!node) continue;
      const snap = node.analysis_snapshot || node.code_snapshot || '';
      for (const [funcName, funcNodeId] of ctx.functionRegistry) {
        if (funcName.includes(':')) continue;
        if (snap.includes(funcName + '(') || snap.includes(funcName + ' (')) {
          const returnTaint = ctx.functionReturnTaint.get(funcNodeId);
          if (returnTaint === false) {
            sentence.reconciled = true;
            sentence.originalTaintClass = sentence.taintClass;
            sentence.taintClass = 'NEUTRAL';
            sentence.reconciliationReason = `Resolved clean: ${funcName} does not return tainted data`;
          } else if (returnTaint === true) {
            if (sentence.taintClass !== 'TAINTED') {
              sentence.reconciled = true;
              sentence.originalTaintClass = sentence.taintClass;
              sentence.taintClass = 'TAINTED';
              sentence.reconciliationReason = `Resolved tainted: ${funcName} returns tainted data`;
            }
          }
          break;
        }
      }
    }
  }
}
