
import * as fs from 'fs';
import * as path from 'path';
import type { NeuralMap, NeuralMapNode, Edge } from './types.js';
import { createNode, createNeuralMap, nextGeneration } from './types.js';


export interface ImportInfo {
  specifier: string;
  resolvedPath: string | null;
  importedNames: string[];
  localName: string | null;
  line: number;
}

export interface FileImports {
  filePath: string;
  imports: ImportInfo[];
}

export interface ExportInfo {
  name: string;
  nodeIds: string[];
  isDefault: boolean;
}

export interface FileExports {
  filePath: string;
  exports: ExportInfo[];
}

export interface DependencyEdge {
  from: string;
  to: string;
  importInfo: ImportInfo;
}

export interface DependencyGraph {
  files: string[];
  edges: DependencyEdge[];
  importsOf: Map<string, string[]>;
  importedBy: Map<string, string[]>;
}


/**
 * Extract require() and import statements from JavaScript/TypeScript source.
 * Returns raw specifiers — resolution to file paths happens separately.
 */
export function extractImports(source: string, filePath: string): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    const destructuredRequire = line.match(
      /(?:var|let|const)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/
    );
    if (destructuredRequire) {
      const names = destructuredRequire[1].split(',').map(n => n.trim()).filter(n => n.length > 0);
      imports.push({
        specifier: destructuredRequire[2],
        resolvedPath: null,
        importedNames: names,
        localName: null,
        line: lineNum,
      });
      continue;
    }

    const cjsMatch = line.match(
      /(?:var|let|const)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/
    );
    if (cjsMatch) {
      imports.push({
        specifier: cjsMatch[2],
        resolvedPath: null,
        importedNames: ['*'],
        localName: cjsMatch[1],
        line: lineNum,
      });
      continue;
    }

    const sideEffectRequire = line.match(
      /require\s*\(\s*['"]([^'"]+)['"]\s*\)/
    );
    if (sideEffectRequire && !cjsMatch) {
      imports.push({
        specifier: sideEffectRequire[1],
        resolvedPath: null,
        importedNames: ['*'],
        localName: null,
        line: lineNum,
      });
      continue;
    }

    const esDefaultMatch = line.match(
      /import\s+(\w+)\s+from\s+['"]([^'"]+)['"]/
    );
    if (esDefaultMatch) {
      imports.push({
        specifier: esDefaultMatch[2],
        resolvedPath: null,
        importedNames: ['default'],
        localName: esDefaultMatch[1],
        line: lineNum,
      });
      continue;
    }

    const esNamedMatch = line.match(
      /import\s*\{([^}]+)\}\s*from\s+['"]([^'"]+)['"]/
    );
    if (esNamedMatch) {
      const names = esNamedMatch[1].split(',').map(n => {
        const parts = n.trim().split(/\s+as\s+/);
        return parts[0].trim();
      }).filter(n => n.length > 0);
      imports.push({
        specifier: esNamedMatch[2],
        resolvedPath: null,
        importedNames: names,
        localName: null,
        line: lineNum,
      });
      continue;
    }

    const esStarMatch = line.match(
      /import\s+\*\s+as\s+(\w+)\s+from\s+['"]([^'"]+)['"]/
    );
    if (esStarMatch) {
      imports.push({
        specifier: esStarMatch[2],
        resolvedPath: null,
        importedNames: ['*'],
        localName: esStarMatch[1],
        line: lineNum,
      });
      continue;
    }

  }

  return imports;
}

/**
 * Extract module.exports and named exports from JavaScript source.
 * Returns export names that can be matched to NeuralMap nodes.
 */
export function extractExports(source: string): string[] {
  const exports: string[] = [];
  const lines = source.split('\n');

  for (const line of lines) {
    const namedExport = line.match(/module\.exports\.(\w+)\s*=/);
    if (namedExport) {
      exports.push(namedExport[1]);
      continue;
    }

    const shortExport = line.match(/(?<!\w)exports\.(\w+)\s*=/);
    if (shortExport) {
      exports.push(shortExport[1]);
      continue;
    }

    const esFuncExport = line.match(/export\s+(?:default\s+)?function\s+(\w+)/);
    if (esFuncExport) {
      exports.push(esFuncExport[1]);
      continue;
    }

    const esVarExport = line.match(/export\s+(?:const|let|var)\s+(\w+)/);
    if (esVarExport) {
      exports.push(esVarExport[1]);
      continue;
    }

    const moduleExportsObj = line.match(/module\.exports\s*=\s*\{/);
    if (moduleExportsObj) {
      const restOfFile = lines.slice(lines.indexOf(line)).join('\n');
      const objMatch = restOfFile.match(/module\.exports\s*=\s*\{([^}]+)\}/);
      if (objMatch) {
        const props = objMatch[1].split(',').map(p => {
          const key = p.trim().split(/\s*[:=]/)[0].trim();
          return key;
        }).filter(k => k.length > 0 && /^\w+$/.test(k));
        exports.push(...props);
      }
      continue;
    }
  }

  return [...new Set(exports)];
}


const JS_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx'];

/**
 * Resolve a require/import specifier to an absolute file path.
 * Only resolves relative paths (starts with . or ..).
 * Returns null for npm packages.
 */
export function resolveImportPath(
  specifier: string,
  importingFile: string,
  allFiles: string[],
  cachedFileSet?: Set<string>,
): string | null {
  if (!specifier.startsWith('.') && !specifier.startsWith('/')) {
    return null;
  }

  const normalizedImporting = importingFile.replace(/\\/g, '/');
  const dir = path.posix.dirname(normalizedImporting);

  const joined = path.posix.join(dir, specifier);
  const normalizedResolved = path.posix.normalize(joined);

  const fileSet = cachedFileSet ?? new Set(allFiles.map(f => f.replace(/\\/g, '/')));

  if (fileSet.has(normalizedResolved)) {
    return normalizedResolved;
  }

  for (const ext of JS_EXTENSIONS) {
    const withExt = normalizedResolved + ext;
    if (fileSet.has(withExt)) {
      return withExt;
    }
  }

  for (const ext of JS_EXTENSIONS) {
    const indexFile = normalizedResolved + '/index' + ext;
    if (fileSet.has(indexFile)) {
      return indexFile;
    }
  }

  return null;
}


/**
 * Build a dependency graph from a set of files.
 * Reads each file, extracts imports, resolves paths.
 */
export function buildDependencyGraph(files: string[]): DependencyGraph {
  const edges: DependencyEdge[] = [];
  const importsOf = new Map<string, string[]>();
  const importedBy = new Map<string, string[]>();
  const normalizedFiles = files.map(f => f.replace(/\\/g, '/'));
  const fileSet = new Set(normalizedFiles);

  for (const file of normalizedFiles) {
    importsOf.set(file, []);
    importedBy.set(file, []);
  }

  for (const file of normalizedFiles) {
    let source: string;
    try {
      source = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    const imports = extractImports(source, file);

    for (const imp of imports) {
      const resolvedPath = resolveImportPath(imp.specifier, file, normalizedFiles, fileSet);
      imp.resolvedPath = resolvedPath;

      if (resolvedPath) {
        edges.push({ from: file, to: resolvedPath, importInfo: imp });
        importsOf.get(file)?.push(resolvedPath);
        importedBy.get(resolvedPath)?.push(file);
      }
    }
  }

  return {
    files: normalizedFiles,
    edges,
    importsOf,
    importedBy,
  };
}


export interface MergedMapResult {
  mergedMap: NeuralMap;
  crossFileEdges: number;
  resolvedImports: Array<{ from: string; to: string; symbols: string[] }>;
}

/**
 * Merge multiple NeuralMaps into a single map with cross-file edges.
 *
 * Steps:
 *   1. Collect all nodes from all maps (prefix IDs to avoid collision)
 *   2. Build export registry: for each file, which nodes are exports
 *   3. Build import registry: for each file, what does it import
 *   4. Create CALLS edges between import sites and exported functions
 *   5. Propagate taint across file boundaries
 */
export function mergeNeuralMaps(
  fileMaps: Map<string, NeuralMap>,
  depGraph: DependencyGraph,
): MergedMapResult {
  nextGeneration();

  const allNodes: NeuralMapNode[] = [];
  const allEdges: Edge[] = [];
  const allSourceParts: string[] = [];
  let crossFileEdgeCount = 0;
  const resolvedImports: Array<{ from: string; to: string; symbols: string[] }> = [];

  const idMap = new Map<string, string>();

  for (const [filePath, map] of fileMaps) {
    const prefix = makeFilePrefix(filePath);
    allSourceParts.push(`// === ${filePath} ===\n${map.source_code}`);

    for (const node of map.nodes) {
      const newId = `${prefix}::${node.id}`;
      idMap.set(`${filePath}::${node.id}`, newId);

      const clonedNode: NeuralMapNode = {
        ...node,
        id: newId,
        file: filePath,
        edges: node.edges.map(e => ({
          ...e,
          target: `${prefix}::${e.target}`,
        })),
        data_in: node.data_in.map(d => ({
          ...d,
          source: d.source === 'EXTERNAL' ? 'EXTERNAL' : `${prefix}::${d.source}`,
        })),
        data_out: node.data_out.map(d => ({
          ...d,
          source: d.source === 'EXTERNAL' ? 'EXTERNAL' : `${prefix}::${d.source}`,
          target: d.target ? `${prefix}::${d.target}` : undefined,
        })),
      };

      allNodes.push(clonedNode);
    }

    for (const edge of map.edges) {
      allEdges.push({
        ...edge,
        target: `${prefix}::${edge.target}`,
      });
    }
  }

  const allNodesById = new Map<string, NeuralMapNode>();
  for (const node of allNodes) {
    allNodesById.set(node.id, node);
  }

  const exportRegistry = new Map<string, Map<string, string[]>>();

  for (const [filePath, map] of fileMaps) {
    const prefix = makeFilePrefix(filePath);
    const source = map.source_code;
    const exportNames = extractExports(source);
    const exportNodeMap = new Map<string, string[]>();

    for (const exportName of exportNames) {
      const matchingNodeIds: string[] = [];

      for (const node of map.nodes) {
        if (node.node_type === 'STRUCTURAL' &&
            (node.label.includes(exportName) || node.code_snapshot.includes(exportName))) {
          matchingNodeIds.push(`${prefix}::${node.id}`);
        }
      }

      if (matchingNodeIds.length === 0) {
        for (const node of map.nodes) {
          if (node.label.includes(exportName) || node.code_snapshot.includes(exportName)) {
            matchingNodeIds.push(`${prefix}::${node.id}`);
          }
        }
      }

      if (matchingNodeIds.length > 0) {
        exportNodeMap.set(exportName, matchingNodeIds);
      }
    }

    exportRegistry.set(filePath, exportNodeMap);
  }

  for (const edge of depGraph.edges) {
    const fromPrefix = makeFilePrefix(edge.from);
    const toPrefix = makeFilePrefix(edge.to);
    const toExports = exportRegistry.get(edge.to);

    if (!toExports) continue;

    const importInfo = edge.importInfo;
    const symbols: string[] = [];

    if (importInfo.importedNames.includes('*') && importInfo.localName) {
      const fromMap = fileMaps.get(edge.from);
      if (!fromMap) continue;

      for (const [exportName, exportNodeIds] of toExports) {
        const usagePattern = `${importInfo.localName}.${exportName}`;

        for (const fromNode of fromMap.nodes) {
          if (fromNode.code_snapshot.includes(usagePattern) ||
              fromNode.label.includes(usagePattern)) {
            for (const exportNodeId of exportNodeIds) {
              const remappedFromId = `${fromPrefix}::${fromNode.id}`;
              const fromNodeInMerged = allNodesById.get(remappedFromId);
              if (fromNodeInMerged) {
                fromNodeInMerged.edges.push({
                  target: exportNodeId,
                  edge_type: 'CALLS',
                  conditional: false,
                  async: false,
                });
                crossFileEdgeCount++;
              }
            }
            symbols.push(exportName);
          }
        }
      }
    } else {
      for (const name of importInfo.importedNames) {
        const exportNodeIds = toExports.get(name);
        if (!exportNodeIds) continue;

        const fromMap = fileMaps.get(edge.from);
        if (!fromMap) continue;

        for (const fromNode of fromMap.nodes) {
          if (fromNode.code_snapshot.includes(name) || fromNode.label.includes(name)) {
            for (const exportNodeId of exportNodeIds) {
              const remappedFromId = `${fromPrefix}::${fromNode.id}`;
              const fromNodeInMerged = allNodesById.get(remappedFromId);
              if (fromNodeInMerged) {
                fromNodeInMerged.edges.push({
                  target: exportNodeId,
                  edge_type: 'CALLS',
                  conditional: false,
                  async: false,
                });
                crossFileEdgeCount++;
              }
            }
            symbols.push(name);
          }
        }
      }
    }

    if (symbols.length > 0) {
      resolvedImports.push({
        from: edge.from,
        to: edge.to,
        symbols: [...new Set(symbols)],
      });
    }
  }

  for (const edge of depGraph.edges) {
    if (edge.to.endsWith('.java')) {
      const javaEdgeCount = createJavaCrossFileEdges(
        edge,
        fileMaps,
        allNodesById,
      );
      if (javaEdgeCount > 0) {
        crossFileEdgeCount += javaEdgeCount;
        const targetClassName = edge.importInfo.specifier;
        resolvedImports.push({
          from: edge.from,
          to: edge.to,
          symbols: [targetClassName],
        });
      }
    }
  }

  propagateCrossFileTaint(allNodes);

  const mergedMap: NeuralMap = {
    nodes: allNodes,
    edges: allEdges,
    source_file: '[merged]',
    source_code: allSourceParts.join('\n\n'),
    created_at: new Date().toISOString(),
    parser_version: '0.2.0-crossfile',
  };

  return { mergedMap, crossFileEdges: crossFileEdgeCount, resolvedImports };
}


function propagateCrossFileTaint(nodes: NeuralMapNode[]): void {
  const nodeById = new Map<string, NeuralMapNode>();
  for (const node of nodes) {
    nodeById.set(node.id, node);
  }

  let changed = true;
  let iterations = 0;
  const MAX_ITERATIONS = 10;

  while (changed && iterations < MAX_ITERATIONS) {
    changed = false;
    iterations++;

    for (const node of nodes) {
      const hasTaintedInput = node.data_in.some(d => d.tainted);
      const hasTaintedOutput = node.data_out.some(d => d.tainted);
      const isIngress = node.node_type === 'INGRESS';

      if (!hasTaintedInput && !hasTaintedOutput && !isIngress) continue;

      for (const edge of node.edges) {
        if (edge.edge_type === 'CALLS' || edge.edge_type === 'DATA_FLOW') {
          const targetNode = nodeById.get(edge.target);
          if (!targetNode) continue;

          const alreadyTainted = targetNode.data_in.some(d => d.tainted);
          if (!alreadyTainted) {
            if (targetNode.data_in.length > 0) {
              for (const dataIn of targetNode.data_in) {
                if (!dataIn.tainted) {
                  dataIn.tainted = true;
                  changed = true;
                }
              }
            } else {
              targetNode.data_in.push({
                name: `cross_file_taint_from_${node.id}`,
                source: node.id,
                data_type: 'unknown',
                tainted: true,
                sensitivity: 'NONE',
              });
              changed = true;
            }

            if (targetNode.node_type === 'STORAGE' || targetNode.node_type === 'EXTERNAL') {
              if (!targetNode.attack_surface.includes('cross_file_tainted_sink')) {
                targetNode.attack_surface.push('cross_file_tainted_sink');
              }
            }
          }
        }
      }
    }
  }
}


function makeFilePrefix(filePath: string): string {
  const normalized = filePath.replace(/\\/g, '/');
  const parts = normalized.split('/');
  const filename = parts[parts.length - 1].replace(/\.[^.]+$/, '');
  const parent = parts.length >= 2 ? parts[parts.length - 2] : '';
  const prefix = parent ? `${parent}_${filename}` : filename;
  return prefix.replace(/[^a-zA-Z0-9_]/g, '_');
}


/**
 * Extract the Java package declaration from source code.
 * Returns null for files without a package statement (default package).
 */
export function extractJavaPackage(source: string): string | null {
  const match = source.match(/^\s*package\s+([\w.]+)\s*;/m);
  return match ? match[1] : null;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Build dependency edges between Java files in the same package.
 *
 * In Java, files in the same package can reference each other's classes
 * without import statements. This function discovers those references
 * by scanning source code for patterns like:
 *   - `new ClassName(`
 *   - `ClassName.fieldName`
 *   - `ClassName.methodName(`
 *
 * @param files Normalized file paths (forward slashes)
 * @param fileMaps Pre-parsed NeuralMaps keyed by file path
 * @returns DependencyEdge[] for same-package cross-file references
 */
export function buildJavaSamePackageEdges(
  files: string[],
  fileMaps: Map<string, NeuralMap>,
): DependencyEdge[] {
  const edges: DependencyEdge[] = [];
  const javaFiles = files.filter(f => f.endsWith('.java'));
  if (javaFiles.length < 2) return edges;

  const fileInfo: Array<{
    filePath: string;
    pkg: string | null;
    className: string;
    source: string;
  }> = [];

  for (const fp of javaFiles) {
    const map = fileMaps.get(fp);
    if (!map) continue;
    const source = map.source_code;
    const pkg = extractJavaPackage(source);
    const normalized = fp.replace(/\\/g, '/');
    const className = normalized.split('/').pop()!.replace(/\.java$/, '');
    fileInfo.push({ filePath: fp, pkg, className, source });
  }

  const byPackage = new Map<string, typeof fileInfo>();
  for (const fi of fileInfo) {
    const key = fi.pkg ?? '<default>';
    let group = byPackage.get(key);
    if (!group) {
      group = [];
      byPackage.set(key, group);
    }
    group.push(fi);
  }

  for (const [, group] of byPackage) {
    if (group.length < 2) continue;

    for (const fromFile of group) {
      for (const toFile of group) {
        if (fromFile.filePath === toFile.filePath) continue;

        const escaped = escapeRegex(toFile.className);
        const pattern = new RegExp(
          `(?:new\\s+${escaped}\\s*\\(|${escaped}\\.\\w+|${escaped}<)`,
        );

        if (pattern.test(fromFile.source)) {
          edges.push({
            from: fromFile.filePath,
            to: toFile.filePath,
            importInfo: {
              specifier: toFile.className,
              resolvedPath: toFile.filePath,
              importedNames: ['*'],
              localName: toFile.className,
              line: 0,
            },
          });
        }
      }
    }
  }

  return edges;
}


const JAVA_STDLIB_PREFIXES = ['java.', 'javax.', 'sun.', 'com.sun.'];

/**
 * Extract Java import statements from source code.
 * Handles: explicit class imports, wildcard imports, static imports.
 * Skips standard library imports (java.*, javax.*, sun.*, com.sun.*).
 *
 * CRITICAL: specifier is set to the SIMPLE CLASS NAME (last dot-segment),
 * not the FQCN, because createJavaCrossFileEdges matches specifier against
 * code_snapshot content.
 */
export function extractJavaImports(source: string, filePath: string): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    const staticExplicit = line.match(/^\s*import\s+static\s+([\w.]+)\.([\w*]+)\s*;/);
    if (staticExplicit) {
      const fqcn = staticExplicit[1] + '.' + staticExplicit[2];
      if (JAVA_STDLIB_PREFIXES.some(p => fqcn.startsWith(p))) continue;
      const member = staticExplicit[2];
      const classFqcn = staticExplicit[1];
      const simpleName = classFqcn.split('.').pop()!;
      imports.push({
        specifier: simpleName,
        resolvedPath: null,
        importedNames: [member],
        localName: member === '*' ? null : member,
        line: lineNum,
      });
      continue;
    }

    const wildcardImport = line.match(/^\s*import\s+([\w.]+)\.\*\s*;/);
    if (wildcardImport) {
      const pkg = wildcardImport[1];
      if (JAVA_STDLIB_PREFIXES.some(p => pkg.startsWith(p))) continue;
      imports.push({
        specifier: pkg,
        resolvedPath: null,
        importedNames: ['*'],
        localName: null,
        line: lineNum,
      });
      continue;
    }

    const explicitImport = line.match(/^\s*import\s+([\w.]+)\s*;/);
    if (explicitImport) {
      const fqcn = explicitImport[1];
      if (JAVA_STDLIB_PREFIXES.some(p => fqcn.startsWith(p))) continue;
      const simpleName = fqcn.split('.').pop()!;
      imports.push({
        specifier: simpleName,
        resolvedPath: null,
        importedNames: [simpleName],
        localName: simpleName,
        line: lineNum,
      });
      continue;
    }
  }

  return imports;
}

/**
 * Detect Java source roots from file paths.
 * Looks for standard Maven/Gradle patterns: src/main/java/, src/test/java/
 * Fallback: src/testcases/ for NIST Juliet test suite.
 */
export function detectJavaSourceRoots(files: string[]): string[] {
  const roots = new Set<string>();
  const patterns = ['src/main/java/', 'src/test/java/', 'src/testcases/'];

  for (const file of files) {
    const normalized = file.replace(/\\/g, '/');
    for (const pattern of patterns) {
      const idx = normalized.indexOf(pattern);
      if (idx !== -1) {
        roots.add(normalized.substring(0, idx + pattern.length));
      }
    }
  }

  return [...roots];
}

/**
 * Resolve a fully-qualified Java class name to a file path.
 * Converts dots to path separators, tries each source root.
 * Handles inner classes by stripping trailing segments.
 */
export function resolveJavaImportPath(
  fqcn: string,
  sourceRoots: string[],
  fileSet: Set<string>,
): string | null {
  const relPath = fqcn.replace(/\./g, '/') + '.java';

  for (const root of sourceRoots) {
    const candidate = root + relPath;
    if (fileSet.has(candidate)) return candidate;
  }

  const parts = fqcn.split('.');
  for (let drop = 1; drop < parts.length - 1; drop++) {
    const outerFqcn = parts.slice(0, parts.length - drop).join('/') + '.java';
    for (const root of sourceRoots) {
      const candidate = root + outerFqcn;
      if (fileSet.has(candidate)) return candidate;
    }
  }

  return null;
}

/**
 * Resolve a wildcard import (import pkg.*) to actual files.
 * Returns file paths that are direct children of the package directory.
 */
export function resolveJavaWildcardImport(
  packageName: string,
  sourceRoots: string[],
  allFiles: string[],
): string[] {
  const pkgDir = packageName.replace(/\./g, '/') + '/';
  const results: string[] = [];

  for (const root of sourceRoots) {
    const prefix = root + pkgDir;
    for (const file of allFiles) {
      if (file.startsWith(prefix) && file.endsWith('.java')) {
        const remainder = file.substring(prefix.length);
        if (!remainder.includes('/')) {
          results.push(file);
        }
      }
    }
  }

  return results;
}

/**
 * Build dependency edges from Java import statements (cross-package).
 *
 * This handles imports like `import org.apache.logging.log4j.core.net.JndiManager;`
 * which are NOT in the same package (those are handled by buildJavaSamePackageEdges).
 *
 * Also scans for FQCN string literals like `new org.example.ClassName(` which
 * BenchmarkJava uses directly.
 *
 * Wildcard imports are throttled: edges are only created if the importing
 * file actually references the target class name in its source code.
 */
export function buildJavaImportEdges(
  files: string[],
  fileMaps: Map<string, NeuralMap>,
): DependencyEdge[] {
  const edges: DependencyEdge[] = [];
  const javaFiles = files.filter(f => f.endsWith('.java'));
  if (javaFiles.length < 2) return edges;

  const normalizedFiles = javaFiles.map(f => f.replace(/\\/g, '/'));
  const fileSet = new Set(normalizedFiles);
  const sourceRoots = detectJavaSourceRoots(normalizedFiles);
  if (sourceRoots.length === 0) return edges;

  for (const fp of normalizedFiles) {
    const map = fileMaps.get(fp);
    if (!map) continue;
    const source = map.source_code;

    const javaImports = extractJavaImports(source, fp);

    for (const imp of javaImports) {
      if (imp.importedNames.includes('*') && imp.localName === null) {
        const matchedFiles = resolveJavaWildcardImport(imp.specifier, sourceRoots, normalizedFiles);
        for (const targetFile of matchedFiles) {
          if (targetFile === fp) continue;
          const targetClassName = targetFile.split('/').pop()!.replace(/\.java$/, '');
          const escaped = escapeRegex(targetClassName);
          const refPattern = new RegExp(
            `(?:new\\s+${escaped}\\s*[(<]|${escaped}\\.\\w+|${escaped}<|extends\\s+${escaped}|implements\\s+[\\w,\\s]*${escaped})`,
          );
          if (refPattern.test(source)) {
            imp.resolvedPath = targetFile;
            edges.push({
              from: fp,
              to: targetFile,
              importInfo: {
                specifier: targetClassName,
                resolvedPath: targetFile,
                importedNames: ['*'],
                localName: targetClassName,
                line: imp.line,
              },
            });
          }
        }
      } else {
        const importLine = source.split('\n')[imp.line - 1] || '';
        let fqcn: string | null = null;

        const staticMatch = importLine.match(/^\s*import\s+static\s+([\w.]+)\.\w+\s*;/);
        if (staticMatch) {
          fqcn = staticMatch[1];
        } else {
          const classMatch = importLine.match(/^\s*import\s+([\w.]+)\s*;/);
          if (classMatch) {
            fqcn = classMatch[1];
          }
        }

        if (fqcn) {
          const resolved = resolveJavaImportPath(fqcn, sourceRoots, fileSet);
          if (resolved && resolved !== fp) {
            imp.resolvedPath = resolved;
            edges.push({
              from: fp,
              to: resolved,
              importInfo: {
                specifier: imp.specifier,
                resolvedPath: resolved,
                importedNames: imp.importedNames,
                localName: imp.localName,
                line: imp.line,
              },
            });
          }
        }
      }
    }

    const fqcnUsage = source.matchAll(/new\s+([\w.]+\.([A-Z]\w*))\s*\(/g);
    for (const match of fqcnUsage) {
      const fullFqcn = match[1];
      const simpleName = match[2];
      if (JAVA_STDLIB_PREFIXES.some(p => fullFqcn.startsWith(p))) continue;
      const resolved = resolveJavaImportPath(fullFqcn, sourceRoots, fileSet);
      if (resolved && resolved !== fp) {
        edges.push({
          from: fp,
          to: resolved,
          importInfo: {
            specifier: simpleName,
            resolvedPath: resolved,
            importedNames: [simpleName],
            localName: simpleName,
            line: 0,
          },
        });
      }
    }
  }

  return edges;
}

function createJavaCrossFileEdges(
  edge: DependencyEdge,
  fileMaps: Map<string, NeuralMap>,
  allNodesById: Map<string, NeuralMapNode>,
): number {
  let count = 0;

  const fromMap = fileMaps.get(edge.from);
  const toMap = fileMaps.get(edge.to);
  if (!fromMap || !toMap) return 0;

  const fromPrefix = makeFilePrefix(edge.from);
  const toPrefix = makeFilePrefix(edge.to);

  const targetClassName = edge.importInfo.specifier;
  const escapedClassName = escapeRegex(targetClassName);

  const targetMethodNodes: NeuralMapNode[] = [];
  for (const node of toMap.nodes) {
    if (node.node_type === 'STRUCTURAL') {
      targetMethodNodes.push(node);
    }
  }

  for (const fromNode of fromMap.nodes) {
    const snapshot = fromNode.code_snapshot + ' ' + fromNode.label;

    const refPattern = new RegExp(
      `(?:new\\s+${escapedClassName}\\s*\\(|${escapedClassName}\\.\\w+)`,
    );
    if (!refPattern.test(snapshot)) continue;

    const remappedFromId = `${fromPrefix}::${fromNode.id}`;
    const fromNodeInMerged = allNodesById.get(remappedFromId);
    if (!fromNodeInMerged) continue;

    for (const toNode of targetMethodNodes) {
      const remappedToId = `${toPrefix}::${toNode.id}`;
      if (!allNodesById.has(remappedToId)) continue;

      fromNodeInMerged.edges.push({
        target: remappedToId,
        edge_type: 'CALLS',
        conditional: false,
        async: false,
      });
      count++;
    }
  }

  return count;
}


export interface CrossFileResult {
  mergedMap: NeuralMap;
  depGraph: DependencyGraph;
  crossFileEdges: number;
  resolvedImports: Array<{ from: string; to: string; symbols: string[] }>;
}

/**
 * Perform cross-file analysis on a set of file maps.
 * This is the main entry point called from dst-cli.ts.
 *
 * @param fileMaps Map of absolute file path -> NeuralMap (from per-file scanning)
 * @param files List of all files in the scan (for dependency resolution)
 */
export function analyzeCrossFile(
  fileMaps: Map<string, NeuralMap>,
  files: string[],
): CrossFileResult {
  const depGraph = buildDependencyGraph(files);

  const normalizedFiles = files.map(f => f.replace(/\\/g, '/'));
  const javaEdges = buildJavaSamePackageEdges(normalizedFiles, fileMaps);
  for (const edge of javaEdges) {
    depGraph.edges.push(edge);
    if (!depGraph.importsOf.has(edge.from)) depGraph.importsOf.set(edge.from, []);
    if (!depGraph.importedBy.has(edge.to)) depGraph.importedBy.set(edge.to, []);
    depGraph.importsOf.get(edge.from)!.push(edge.to);
    depGraph.importedBy.get(edge.to)!.push(edge.from);
  }

  const existingEdgeKeys = new Set(depGraph.edges.map(e => `${e.from}->${e.to}`));
  const importEdges = buildJavaImportEdges(normalizedFiles, fileMaps);
  for (const edge of importEdges) {
    const key = `${edge.from}->${edge.to}`;
    if (existingEdgeKeys.has(key)) continue;
    existingEdgeKeys.add(key);
    depGraph.edges.push(edge);
    if (!depGraph.importsOf.has(edge.from)) depGraph.importsOf.set(edge.from, []);
    if (!depGraph.importedBy.has(edge.to)) depGraph.importedBy.set(edge.to, []);
    depGraph.importsOf.get(edge.from)!.push(edge.to);
    depGraph.importedBy.get(edge.to)!.push(edge.from);
  }

  const { mergedMap, crossFileEdges, resolvedImports } = mergeNeuralMaps(fileMaps, depGraph);

  return { mergedMap, depGraph, crossFileEdges, resolvedImports };
}
