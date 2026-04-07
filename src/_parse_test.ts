import Parser from 'web-tree-sitter';
async function main() {
  await Parser.init();
  const parser = new Parser();
  const Java = await Parser.Language.load('node_modules/tree-sitter-java/tree-sitter-java.wasm');
  parser.setLanguage(Java);
  const code = `class A { void m() { String param = "x"; try { throw new RuntimeException(param); } catch (RuntimeException e) { String bar = e.getMessage(); } } }`;
  const tree = parser.parse(code);
  function p(node: any, indent: number): void {
    const txt = node.childCount === 0 ? ' [' + JSON.stringify(node.text) + ']' : '';
    console.log('  '.repeat(indent) + node.type + txt);
    for (let i = 0; i < node.childCount; i++) {
      p(node.child(i)!, indent + 1);
    }
  }
  p(tree.rootNode, 0);
}
main().catch(e => { console.error(e); process.exit(1); });
