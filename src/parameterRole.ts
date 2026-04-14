/**
 * Parameter roles derived from structural AST analysis.
 *
 * - input:        Properties are READ from this parameter (.body, .headers, .query)
 * - output:       Methods are CALLED on this parameter (.send, .json, .status)
 * - continuation: This parameter is INVOKED as a function (next())
 * - data:         Used as a plain value (string, number, passed directly)
 * - unknown:      Insufficient usage data to determine role
 */
export type ParameterRole = 'input' | 'output' | 'continuation' | 'data' | 'unknown';

/**
 * Tracks how a function parameter is used within the function body.
 * Built by walking the AST — no pattern matching, pure structural observation.
 */
export interface ParameterUsage {
  /** Parameter name from the function signature */
  name: string;
  /** Properties read via member_expression: req.body → 'body' */
  propertiesRead: Set<string>;
  /** Properties assigned to: param.x = val → 'x' */
  propertiesWritten: Set<string>;
  /** Methods called on this parameter: res.send() → 'send' */
  methodsCalled: Set<string>;
  /** Whether this parameter is invoked as a function: next() */
  invokedAsFunction: boolean;
  /** Whether this parameter is passed as an argument to another call */
  passedAsArgument: boolean;
}

/**
 * Data origin classification for function parameters.
 * Determined by where the function sits in the call graph.
 */
export type DataOrigin =
  | 'external_callback'   // Function passed as callback to external module
  | 'internal_call'       // Function called internally with known arguments
  | 'export_entry'        // Function exported but never called in codebase
  | 'unknown';            // Cannot determine origin

/**
 * Combined inference result for a function parameter.
 */
export interface ParameterInference {
  name: string;
  role: ParameterRole;
  origin: DataOrigin;
  usage: ParameterUsage;
  /** Module category if origin is external_callback (e.g., 'HTTP_FRAMEWORK', 'DATABASE') */
  moduleCategory?: string;
}

/**
 * Create an empty ParameterUsage for a given parameter name.
 */
export function createEmptyUsage(name: string): ParameterUsage {
  return {
    name,
    propertiesRead: new Set(),
    propertiesWritten: new Set(),
    methodsCalled: new Set(),
    invokedAsFunction: false,
    passedAsArgument: false,
  };
}
