// HTML Mapper — transforms a tree-sitter HTML CST into a NeuralMap.
// Tracks: element structure, script/style references, IDs, classes,
// event handlers, form actions, links, and embedded JS/CSS.

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { NeuralMap, NeuralMapNode } from './types';
import { createNode, createNeuralMap, resetSequence } from './types';

/**
 * Build a NeuralMap from an HTML tree-sitter parse tree.
 */
export function buildHTMLNeuralMap(
  tree: { rootNode: SyntaxNode },
  sourceCode: string,
  fileName: string,
): NeuralMap {
  resetSequence();
  const map = createNeuralMap(fileName, sourceCode);

  walkHTML(tree.rootNode, map, fileName, null);

  return map;
}

function walkHTML(
  node: SyntaxNode,
  map: NeuralMap,
  fileName: string,
  parentNodeId: string | null,
): void {
  switch (node.type) {
    case 'element':
    case 'self_closing_tag': {
      const tagNode = node.type === 'element'
        ? node.childForFieldName('start_tag') ?? node.child(0)
        : node;
      const tagName = getTagName(tagNode);

      if (!tagName) break;

      const n = createElementNode(tagName, node, map, fileName);
      if (parentNodeId) {
        map.edges.push({ target: n.id, edge_type: 'CONTAINS', conditional: false, async: false });
      }

      // Extract attributes
      const attrs = extractAttributes(tagNode);

      // ID attribute
      if (attrs.id) {
        n.tags.push(`id:${attrs.id}`);
        n.label = `${tagName}#${attrs.id}`;
      }

      // Class attribute
      if (attrs.class) {
        const classes = attrs.class.split(/\s+/).filter(Boolean);
        for (const cls of classes) {
          n.tags.push(`class:${cls}`);
        }
        if (!attrs.id) {
          n.label = `${tagName}.${classes[0]}`;
        }
      }

      // Script references
      if (tagName === 'script') {
        n.node_type = 'EXTERNAL';
        if (attrs.src) {
          n.node_subtype = 'script_ref';
          n.label = `<script src="${attrs.src}">`;
          n.tags.push(`ref:${attrs.src}`);
        } else {
          n.node_subtype = 'inline_script';
          n.label = '<script> (inline)';
          // Inline script content is embedded JS — tag it
          const scriptContent = getTextContent(node);
          if (scriptContent) {
            n.code_snapshot = scriptContent.slice(0, 500);
            n.tags.push('inline-js');
          }
        }
        if (attrs.type === 'module') n.tags.push('esm');
        if (attrs.defer !== undefined) n.tags.push('defer');
        if (attrs.async !== undefined) n.tags.push('async');
      }

      // Style references
      if (tagName === 'link' && attrs.rel === 'stylesheet') {
        n.node_type = 'EXTERNAL';
        n.node_subtype = 'stylesheet_ref';
        n.label = `<link href="${attrs.href ?? '?'}">`;
        if (attrs.href) n.tags.push(`ref:${attrs.href}`);
      }

      if (tagName === 'style') {
        n.node_type = 'STRUCTURAL';
        n.node_subtype = 'inline_style';
        n.label = '<style> (inline)';
        const styleContent = getTextContent(node);
        if (styleContent) {
          n.code_snapshot = styleContent.slice(0, 500);
          n.tags.push('inline-css');
        }
      }

      // Event handlers (onclick, onsubmit, etc.)
      for (const [attr, value] of Object.entries(attrs)) {
        if (attr.startsWith('on')) {
          const evtN = createNode({
            label: `${attr}="${value?.slice(0, 40)}"`,
            node_type: 'INGRESS',
            node_subtype: 'event_handler',
            language: 'html',
            file: fileName,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: `${attr}="${value}"`,
          });
          evtN.tags.push('inline-event', `event:${attr.slice(2)}`);
          map.nodes.push(evtN);
          map.edges.push({ target: evtN.id, edge_type: 'CONTAINS', conditional: false, async: false });
        }
      }

      // Form actions
      if (tagName === 'form' && attrs.action) {
        n.node_type = 'EGRESS';
        n.node_subtype = 'form_action';
        n.label = `<form action="${attrs.action}">`;
        n.tags.push(`action:${attrs.action}`);
        if (attrs.method) n.tags.push(`method:${attrs.method}`);
      }

      // Links
      if (tagName === 'a' && attrs.href) {
        n.tags.push(`href:${attrs.href}`);
        if (attrs.target === '_blank') n.tags.push('external-link');
      }

      // Iframes
      if (tagName === 'iframe') {
        n.node_type = 'EXTERNAL';
        n.node_subtype = 'iframe';
        if (attrs.src) n.tags.push(`src:${attrs.src}`);
        if (attrs.srcdoc) n.tags.push('srcdoc');
      }

      // Input/form elements
      if (['input', 'textarea', 'select'].includes(tagName)) {
        n.node_type = 'INGRESS';
        n.node_subtype = 'form_input';
        if (attrs.name) n.tags.push(`name:${attrs.name}`);
        if (attrs.type) n.tags.push(`input-type:${attrs.type}`);
      }

      // Meta tags
      if (tagName === 'meta') {
        n.node_type = 'META';
        n.node_subtype = 'meta_tag';
        if (attrs.name) n.label = `<meta name="${attrs.name}">`;
        if (attrs.charset) n.label = `<meta charset="${attrs.charset}">`;
        if (attrs['http-equiv']) n.tags.push(`http-equiv:${attrs['http-equiv']}`);
      }

      // Recurse into children
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) walkHTML(child, map, fileName, n.id);
      }
      return; // already recursed
    }

    case 'doctype': {
      const doctypeN = createNode({
        label: '<!DOCTYPE>',
        node_type: 'META',
        node_subtype: 'doctype',
        language: 'html',
        file: fileName,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 100),
      });
      map.nodes.push(doctypeN);
      break;
    }

    case 'comment': {
      // HTML comments — check for conditional comments (IE)
      if (node.text.includes('[if ')) {
        const commentN = createNode({
          label: 'conditional comment',
          node_type: 'META',
          node_subtype: 'conditional_comment',
          language: 'html',
          file: fileName,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200),
        });
        map.nodes.push(commentN);
      }
      break;
    }
  }

  // Default recursion
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) walkHTML(child, map, fileName, parentNodeId);
  }
}

function createElementNode(
  tagName: string,
  node: SyntaxNode,
  map: NeuralMap,
  fileName: string,
): NeuralMapNode {
  const n = createNode({
    label: `<${tagName}>`,
    node_type: 'STRUCTURAL',
    node_subtype: tagName,
    language: 'html',
    file: fileName,
    line_start: node.startPosition.row + 1,
    line_end: node.endPosition.row + 1,
    code_snapshot: node.text.slice(0, 200),
  });
  map.nodes.push(n);
  return n;
}

function getTagName(node: SyntaxNode | null): string | null {
  if (!node) return null;

  // Look for tag_name child
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child?.type === 'tag_name') return child.text;
  }

  // Self-closing tags: the tag name is a direct child
  if (node.type === 'self_closing_tag') {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child?.type === 'tag_name') return child.text;
    }
  }

  return null;
}

function extractAttributes(tagNode: SyntaxNode | null): Record<string, string> {
  const attrs: Record<string, string> = {};
  if (!tagNode) return attrs;

  for (let i = 0; i < tagNode.childCount; i++) {
    const child = tagNode.child(i);
    if (child?.type === 'attribute') {
      const name = child.childForFieldName('attribute_name')?.text
        ?? child.child(0)?.text ?? '';
      const valueNode = child.childForFieldName('attribute_value')
        ?? child.namedChildren.find(c => c.type === 'attribute_value' || c.type === 'quoted_attribute_value');
      const value = valueNode?.text?.replace(/^["']|["']$/g, '') ?? '';
      if (name) attrs[name] = value;
    }
  }

  return attrs;
}

function getTextContent(elementNode: SyntaxNode): string | null {
  for (let i = 0; i < elementNode.childCount; i++) {
    const child = elementNode.child(i);
    if (child?.type === 'raw_text' || child?.type === 'text') {
      return child.text;
    }
  }
  return null;
}
