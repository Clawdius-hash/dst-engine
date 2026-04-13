/**
 * Graph traversal helpers for CWE verifiers.
 *
 * Node filters, BFS wrappers, language inference, library detection,
 * web framework context detection, scope analysis.
 */

import type { NeuralMap, NeuralMapNode, NodeType, EdgeType } from '../types';
import type { NodeRef } from './types.ts';
import { hasPathWithoutGate } from '../generated/_helpers.js';

/**
 * Edge types that represent actual data flow between nodes.
 * CONTAINS is structural containment (function contains statement) and
 * DEPENDS is a dependency relationship — neither represents data movement.
 * BFS for vulnerability path detection should only follow flow edges.
 */
export const FLOW_EDGE_TYPES: ReadonlySet<EdgeType> = new Set([
  'DATA_FLOW', 'CALLS', 'READS', 'WRITES', 'RETURNS',
]);

export function nodeRef(node: NeuralMapNode): NodeRef {
  return {
    id: node.id,
    label: node.label,
    line: node.line_start,
    code: node.code_snapshot.slice(0, 200),
    file: node.file,
  };
}

/** Find all nodes of a given type */
export function nodesOfType(map: NeuralMap, type: NodeType): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === type);
}

/** Find all nodes with a specific subtype */
export function nodesOfSubtype(map: NeuralMap, subtype: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_subtype === subtype);
}

/** Find all nodes with a specific attack surface tag */
export function nodesWithSurface(map: NeuralMap, surface: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.attack_surface.includes(surface));
}

/**
 * Infer the primary language of a NeuralMap from node languages or source_file extension.
 * Returns a lowercase language string (e.g. 'javascript', 'go', 'python', 'ruby', 'php').
 */
export function inferMapLanguage(map: NeuralMap): string {
  // Try map-level language first (may be set dynamically)
  if ((map as any).language) return (map as any).language.toLowerCase();
  // Check majority node language
  const langCounts = new Map<string, number>();
  for (const n of map.nodes) {
    if (n.language) {
      const lang = n.language.toLowerCase();
      langCounts.set(lang, (langCounts.get(lang) ?? 0) + 1);
    }
  }
  if (langCounts.size > 0) {
    let best = ''; let bestCount = 0;
    for (const [l, c] of langCounts) { if (c > bestCount) { best = l; bestCount = c; } }
    return best;
  }
  // Fall back to source file extension
  const ext = map.source_file?.split('.').pop()?.toLowerCase() ?? '';
  const EXT_MAP: Record<string, string> = {
    js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
    ts: 'typescript', tsx: 'typescript', mts: 'typescript',
    py: 'python', rb: 'ruby', php: 'php', go: 'go',
    java: 'java', kt: 'kotlin', kts: 'kotlin',
    rs: 'rust', cs: 'csharp', swift: 'swift',
    c: 'c', cpp: 'c++', cc: 'c++', cxx: 'c++', h: 'c', hpp: 'c++',
  };
  return EXT_MAP[ext] ?? '';
}

/**
 * Detect whether the scanned file is a library/framework rather than application code.
 */
export function isLibraryCode(map: NeuralMap): boolean {
  const allCode = map.nodes.map(n => n.analysis_snapshot || n.code_snapshot).join('\n');
  const filePath = (map.source_file ?? '').replace(/\\/g, '/').toLowerCase();

  // Path-based detection: known framework/library directories
  if (/(?:node_modules|(?:express|fastify|koa|hapi|restify|connect)[\w-]*\/lib|\/lib\/(?:middleware|utils|helpers|internal))/.test(filePath)) {
    return true;
  }

  // Prototype assignment pattern — strong library signal
  const protoAssignments = (allCode.match(/\.\s*prototype\s*\.\s*\w+\s*=/g) || []).length;
  if (protoAssignments >= 3) return true;

  // module.exports = {} with many method assignments — library utility module
  if (/module\.exports\s*=\s*\{/.test(allCode) && protoAssignments >= 1) return true;

  // Many named exports (exports.xxx = function)
  if (/exports\.\w+\s*=\s*function/.test(allCode) && (allCode.match(/exports\.\w+\s*=/g) || []).length >= 5) return true;

  // Methods assigned to an exported object variable
  const methodAssignRe = /\b\w+\.\w+\s*=\s*function\b/g;
  const methodAssignments = (allCode.match(methodAssignRe) || []).length;
  if (methodAssignments >= 8 && /module\.exports/.test(allCode)) return true;

  // High structural-to-ingress ratio with many function definitions — library pattern
  const structural = nodesOfType(map, 'STRUCTURAL').length;
  const ingress = nodesOfType(map, 'INGRESS').length;
  if (structural > 20 && ingress <= 2 && methodAssignments >= 5) return true;

  return false;
}

/**
 * Detect whether the code under analysis operates in a web/API framework context.
 */
export function hasWebFrameworkContext(map: NeuralMap): boolean {
  // --- Graph-level signals ---
  if (map.nodes.some(n => n.node_type === 'STRUCTURAL' && n.node_subtype === 'route')) {
    return true;
  }
  if (map.nodes.some(n =>
    n.node_type === 'INGRESS' &&
    /http|request_param|query_param|route|api/.test(n.node_subtype)
  )) {
    return true;
  }

  // --- Source-code-level signals ---
  const allCode = map.nodes.map(n => n.analysis_snapshot || n.code_snapshot).join('\n');

  // Java web frameworks
  if (/\b(extends\s+(?:HttpServlet|AbstractTestCaseServlet\w*|GenericServlet)|@WebServlet|@Controller\b|@RestController\b|@RequestMapping\b|@GetMapping\b|@PostMapping\b|@PutMapping\b|@DeleteMapping\b|@PatchMapping\b|@WebFilter\b|ActionForm|ActionMapping|@Path\b|@GET\b|@POST\b|@PUT\b|@DELETE\b|FacesServlet|@ManagedBean)\b/.test(allCode)) {
    return true;
  }

  // Node.js / JS web frameworks
  if (/\b(app\.(get|post|put|delete|patch|use|route)\s*\(|router\.(get|post|put|delete|patch|use|route)\s*\(|fastify\.(get|post|put|delete|register)\s*\(|server\.route\s*\(|@Controller\s*\(|@Get\s*\(|@Post\s*\(|@Put\s*\(|@Delete\s*\(|Elysia\s*\()\b/.test(allCode)) {
    return true;
  }

  // Python web frameworks
  if (/\b(@app\.route|@app\.(get|post|put|delete)|@blueprint\.route|url_patterns\b|urlpatterns\b|path\s*\(\s*['"]|@api_view|class\s+\w+.*\bAPIView\b|class\s+\w+.*\bViewSet\b|@router\.(get|post|put|delete))\b/.test(allCode)) {
    return true;
  }

  // PHP web frameworks
  if (/\b(Route::(get|post|put|delete|patch|middleware)|->middleware\s*\(|\$_(GET|POST|REQUEST|SERVER|COOKIE)|class\s+\w+Controller\s+extends\s+Controller)\b/.test(allCode)) {
    return true;
  }

  // Go web frameworks
  if (/\b(http\.Handle(?:Func)?\s*\(|\.GET\s*\(|\.POST\s*\(|\.PUT\s*\(|\.DELETE\s*\(|r\.Route\s*\(|chi\.NewRouter|echo\.New|gin\.Default|gin\.New|fiber\.New)\b/.test(allCode)) {
    return true;
  }

  // Rust web frameworks
  if (/\b(#\[(?:get|post|put|delete|patch)\s*\(|web::\w+|HttpServer::new|axum::Router|rocket::routes|warp::path)\b/.test(allCode)) {
    return true;
  }

  // Ruby web frameworks
  if (/\b(Rails\.application\.routes|resources?\s+:\w+|get\s+['"]\/|post\s+['"]\/|class\s+\w+Controller\s*<\s*ApplicationController|Sinatra::Base)\b/.test(allCode)) {
    return true;
  }

  // C# / ASP.NET
  if (/\b(\[ApiController\]|\[HttpGet\]|\[HttpPost\]|\[HttpPut\]|\[HttpDelete\]|\[Route\s*\(|MapGet\s*\(|MapPost\s*\(|MapPut\s*\(|MapDelete\s*\(|ControllerBase|Controller\s*:\s*Controller)\b/.test(allCode)) {
    return true;
  }

  // Kotlin Ktor / Spring
  if (/\b(routing\s*\{|get\s*\(\s*["']\/|post\s*\(\s*["']\/|call\.respond|call\.receive|@RequestMapping|@GetMapping|@PostMapping)\b/.test(allCode)) {
    return true;
  }

  // Swift Vapor
  if (/\b(app\.(get|post|put|delete)\s*\(|req\.content\.decode|routes\s*\(\s*\w+\s*:\s*RoutesBuilder)\b/.test(allCode)) {
    return true;
  }

  // Generic: method parameters with HTTP request/response types.
  if (/[,(]\s*(HttpServletRequest|HttpServletResponse|HttpRequest|HttpResponse|ServerRequest|ServerResponse)\s+\w+/.test(allCode)) {
    return true;
  }

  return false;
}

/**
 * Check if tainted data flows from source to sink without passing through a CONTROL node.
 * Delegates to the unified hasPathWithoutGate from _helpers.ts (index-based O(n) BFS).
 */
export function hasTaintedPathWithoutControl(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): boolean {
  return hasPathWithoutGate(map, sourceId, sinkId, 'CONTROL');
}

/** Check if any data_in on the sink has tainted=true from a source */
export function sinkReceivesTaintedData(sink: NeuralMapNode): boolean {
  return sink.data_in.some(d => d.tainted);
}

/**
 * Check if tainted data flows from source to sink without passing through an AUTH node.
 * Delegates to the unified hasPathWithoutGate from _helpers.ts (index-based O(n) BFS).
 */
export function hasTaintedPathWithoutAuth(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): boolean {
  return hasPathWithoutGate(map, sourceId, sinkId, 'AUTH');
}

/**
 * Check if there is ANY path from source to sink without passing through a CONTROL node.
 * Unlike hasTaintedPathWithoutControl, this does not require taint — it checks structural flow.
 * Used for CWE-200 where the source is STORAGE (not user input).
 */
export function hasPathWithoutControl(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): boolean {
  return hasPathWithoutGate(map, sourceId, sinkId, 'CONTROL');
}

/**
 * Find the containing function (STRUCTURAL node) for a given node by walking
 * CONTAINS edges backwards. Returns the STRUCTURAL parent's id, or null.
 */
export function findContainingFunction(map: NeuralMap, nodeId: string): string | null {
  for (const n of map.nodes) {
    if (n.node_type === 'STRUCTURAL') {
      for (const edge of n.edges) {
        if (edge.target === nodeId && edge.edge_type === 'CONTAINS') {
          return n.id;
        }
      }
    }
  }
  return null;
}

/**
 * Check whether the function containing the given node had dead branches
 * eliminated by the mapper's constant evaluation.
 */
export function hasDeadBranchForNode(map: NeuralMap, nodeId: string): boolean {
  const funcId = findContainingFunction(map, nodeId);
  if (!funcId) return false;
  const funcNode = map.nodes.find(n => n.id === funcId);
  return funcNode?.metadata?.dead_branch_eliminated === true;
}

/**
 * Check whether a given source line falls within a function that had dead
 * branches eliminated by the mapper.
 */
export function isLineInDeadBranchFunction(map: NeuralMap, line: number): boolean {
  for (const n of map.nodes) {
    if (n.node_type === 'STRUCTURAL' &&
        n.metadata?.dead_branch_eliminated === true &&
        n.line_start <= line && n.line_end >= line) {
      return true;
    }
  }
  return false;
}

/**
 * STRUCTURAL node subtypes that represent function-level scopes.
 * 'function' covers: function/method declarations, constructors, arrow functions, lambdas, closures, generators
 * 'route' covers: route-annotated methods (@GetMapping, [HttpGet], etc.)
 */
export const FUNCTION_SCOPE_SUBTYPES = new Set(['function', 'route']);

/**
 * Check whether two nodes share a function scope.
 * "Shares scope" = both nodes are contained by the same function-body STRUCTURAL node.
 * Two methods in the same class do NOT share function scope.
 */
export function sharesFunctionScope(map: NeuralMap, nodeIdA: string, nodeIdB: string): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const nodeA = nodeMap.get(nodeIdA);
  const nodeB = nodeMap.get(nodeIdB);
  if (!nodeA || !nodeB) return false;

  // Strategy 1: Common CONTAINS ancestor that is a function-scope STRUCTURAL node
  const getAncestors = (nodeId: string): Set<string> => {
    const ancestors = new Set<string>();
    for (const n of map.nodes) {
      if (n.node_type === 'STRUCTURAL' && FUNCTION_SCOPE_SUBTYPES.has(n.node_subtype)) {
        for (const edge of n.edges) {
          if (edge.target === nodeId && edge.edge_type === 'CONTAINS') {
            ancestors.add(n.id);
          }
        }
      }
    }
    return ancestors;
  };

  const ancestorsA = getAncestors(nodeIdA);
  const ancestorsB = getAncestors(nodeIdB);
  for (const a of ancestorsA) {
    if (ancestorsB.has(a)) return true;
  }

  // Strategy 2: Line-range fallback — both nodes within same function-scope node's span
  const funcNodes = map.nodes.filter(n =>
    n.node_type === 'STRUCTURAL' && FUNCTION_SCOPE_SUBTYPES.has(n.node_subtype)
  );

  for (const func of funcNodes) {
    if (nodeA.line_start >= func.line_start && nodeA.line_start <= func.line_end &&
        nodeB.line_start >= func.line_start && nodeB.line_start <= func.line_end) {
      return true;
    }
  }

  return false;
}
