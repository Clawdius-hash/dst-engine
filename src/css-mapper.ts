// CSS Mapper — transforms a tree-sitter CSS CST into a NeuralMap.
// Tracks: selectors (classes, IDs, elements), custom properties,
// @import/@media/@keyframes, and relationships between selectors and properties.

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { NeuralMap } from './types';
import { createNode, createNeuralMap, resetSequence } from './types';

/**
 * Build a NeuralMap from a CSS tree-sitter parse tree.
 */
export function buildCSSNeuralMap(
  tree: { rootNode: SyntaxNode },
  sourceCode: string,
  fileName: string,
): NeuralMap {
  resetSequence();
  const map = createNeuralMap(fileName, sourceCode);

  walkCSS(tree.rootNode, map, fileName);

  return map;
}

function walkCSS(node: SyntaxNode, map: NeuralMap, fileName: string): void {
  switch (node.type) {
    // --- Rule sets (selectors + declarations) ---
    case 'rule_set': {
      const selectorsNode = node.childForFieldName('selectors')
        ?? node.namedChildren.find(c => c.type === 'selectors');
      const selectorText = selectorsNode?.text ?? node.text.split('{')[0]?.trim() ?? '?';

      const ruleN = createNode({
        label: selectorText.slice(0, 60),
        node_type: 'STRUCTURAL',
        node_subtype: 'rule',
        language: 'css',
        file: fileName,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 300),
      });

      // Extract selector types for cross-referencing with HTML
      const selectors = parseSelectorTypes(selectorText);
      for (const sel of selectors) {
        ruleN.tags.push(sel);
      }

      map.nodes.push(ruleN);

      // Walk declarations for custom properties and notable values
      const block = node.namedChildren.find(c => c.type === 'block');
      if (block) {
        walkDeclarationBlock(block, map, fileName, ruleN.id);
      }
      return; // already walked block
    }

    // --- At-rules ---
    case 'import_statement': {
      const urlNode = node.namedChildren.find(c =>
        c.type === 'string_value' || c.type === 'call_expression'
      );
      const importUrl = urlNode?.text?.replace(/['"`]/g, '') ?? '?';
      const importN = createNode({
        label: `@import "${importUrl}"`,
        node_type: 'EXTERNAL',
        node_subtype: 'css_import',
        language: 'css',
        file: fileName,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200),
      });
      importN.tags.push(`ref:${importUrl}`);
      map.nodes.push(importN);
      break;
    }

    case 'media_statement': {
      const conditionText = getMediaCondition(node);
      const mediaN = createNode({
        label: `@media ${conditionText}`,
        node_type: 'CONTROL',
        node_subtype: 'media_query',
        language: 'css',
        file: fileName,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 300),
      });
      mediaN.tags.push('responsive');
      map.nodes.push(mediaN);
      break; // recurse below
    }

    case 'keyframes_statement': {
      const nameNode = node.namedChildren.find(c => c.type === 'keyframes_name');
      const name = nameNode?.text ?? '?';
      const kfN = createNode({
        label: `@keyframes ${name}`,
        node_type: 'STRUCTURAL',
        node_subtype: 'keyframes',
        language: 'css',
        file: fileName,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 300),
      });
      kfN.tags.push(`animation:${name}`);
      map.nodes.push(kfN);
      break;
    }

    case 'supports_statement': {
      const supN = createNode({
        label: `@supports`,
        node_type: 'CONTROL',
        node_subtype: 'feature_query',
        language: 'css',
        file: fileName,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200),
      });
      map.nodes.push(supN);
      break;
    }

    case 'charset_statement': {
      const charN = createNode({
        label: '@charset',
        node_type: 'META',
        node_subtype: 'charset',
        language: 'css',
        file: fileName,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 100),
      });
      map.nodes.push(charN);
      break;
    }

    case 'namespace_statement': {
      const nsN = createNode({
        label: '@namespace',
        node_type: 'META',
        node_subtype: 'namespace',
        language: 'css',
        file: fileName,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 100),
      });
      map.nodes.push(nsN);
      break;
    }

    case 'at_rule': {
      const atRuleText = node.text.split('{')[0]?.trim() ?? '@?';
      const atN = createNode({
        label: atRuleText.slice(0, 60),
        node_type: 'STRUCTURAL',
        node_subtype: 'at_rule',
        language: 'css',
        file: fileName,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200),
      });

      // Detect specific at-rules
      if (atRuleText.startsWith('@font-face')) atN.node_subtype = 'font_face';
      if (atRuleText.startsWith('@layer')) atN.node_subtype = 'layer';
      if (atRuleText.startsWith('@container')) { atN.node_subtype = 'container_query'; atN.tags.push('responsive'); }
      if (atRuleText.startsWith('@property')) { atN.node_subtype = 'custom_property_def'; atN.tags.push('custom-property'); }

      map.nodes.push(atN);
      break;
    }
  }

  // Default recursion
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) walkCSS(child, map, fileName);
  }
}

function walkDeclarationBlock(
  block: SyntaxNode,
  map: NeuralMap,
  fileName: string,
  ruleNodeId: string,
): void {
  for (let i = 0; i < block.namedChildCount; i++) {
    const decl = block.namedChild(i);
    if (!decl || decl.type !== 'declaration') continue;

    const propNode = decl.childForFieldName('property')
      ?? decl.namedChildren.find(c => c.type === 'property_name');
    const propName = propNode?.text ?? '?';

    // Custom properties (--my-var)
    if (propName.startsWith('--')) {
      const customN = createNode({
        label: propName,
        node_type: 'STRUCTURAL',
        node_subtype: 'custom_property',
        language: 'css',
        file: fileName,
        line_start: decl.startPosition.row + 1,
        line_end: decl.endPosition.row + 1,
        code_snapshot: decl.text.slice(0, 200),
      });
      customN.tags.push('custom-property', `var:${propName}`);
      map.nodes.push(customN);
      map.edges.push({ target: customN.id, edge_type: 'CONTAINS', conditional: false, async: false });
    }

    // var() references
    if (decl.text.includes('var(')) {
      const varRefs = decl.text.match(/var\(--[\w-]+/g);
      if (varRefs) {
        for (const ref of varRefs) {
          const varName = ref.slice(4); // remove 'var('
          const refN = createNode({
            label: `var(${varName})`,
            node_type: 'TRANSFORM',
            node_subtype: 'var_reference',
            language: 'css',
            file: fileName,
            line_start: decl.startPosition.row + 1,
            line_end: decl.endPosition.row + 1,
            code_snapshot: decl.text.slice(0, 200),
          });
          refN.tags.push('var-ref', `var:${varName}`);
          map.nodes.push(refN);
        }
      }
    }

    // Notable properties for mesh (animation references, content, etc.)
    if (propName === 'animation' || propName === 'animation-name') {
      const valueText = decl.text.split(':')[1]?.trim()?.split(';')[0]?.trim() ?? '';
      if (valueText) {
        const animN = createNode({
          label: `animation: ${valueText.slice(0, 30)}`,
          node_type: 'TRANSFORM',
          node_subtype: 'animation_ref',
          language: 'css',
          file: fileName,
          line_start: decl.startPosition.row + 1,
          line_end: decl.endPosition.row + 1,
          code_snapshot: decl.text.slice(0, 200),
        });
        animN.tags.push(`animation:${valueText.split(/\s/)[0]}`);
        map.nodes.push(animN);
      }
    }
  }
}

/** Parse selector text into categorized tags for HTML cross-referencing. */
function parseSelectorTypes(selectorText: string): string[] {
  const tags: string[] = [];

  // Class selectors
  const classes = selectorText.match(/\.[\w-]+/g);
  if (classes) {
    for (const cls of classes) {
      tags.push(`class:${cls.slice(1)}`);
    }
  }

  // ID selectors
  const ids = selectorText.match(/#[\w-]+/g);
  if (ids) {
    for (const id of ids) {
      tags.push(`id:${id.slice(1)}`);
    }
  }

  // Element selectors (basic)
  const elements = selectorText.match(/(?:^|[\s>+~,])([a-z][a-z0-9-]*)/gi);
  if (elements) {
    for (const el of elements) {
      tags.push(`element:${el.trim()}`);
    }
  }

  // Pseudo-classes/elements
  const pseudos = selectorText.match(/::?[\w-]+(?:\([^)]*\))?/g);
  if (pseudos) {
    for (const pseudo of pseudos) {
      tags.push(`pseudo:${pseudo}`);
    }
  }

  // Attribute selectors
  const attrSels = selectorText.match(/\[[^\]]+\]/g);
  if (attrSels) {
    for (const attr of attrSels) {
      tags.push(`attr:${attr}`);
    }
  }

  return tags;
}

function getMediaCondition(mediaNode: SyntaxNode): string {
  // Everything between @media and {
  const text = mediaNode.text;
  const braceIdx = text.indexOf('{');
  return braceIdx > 0
    ? text.slice(7, braceIdx).trim() // skip '@media '
    : text.slice(7, 60).trim();
}
