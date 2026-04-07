/**
 * Phoneme expansion: Python data science security — deserialization vectors
 * Agent-generated for DST phoneme dictionary
 *
 * Coverage gap: The entire data science ecosystem (pandas, numpy, torch, joblib)
 * had ZERO entries in the Python callee dictionary. These libraries handle untrusted
 * data daily — Kaggle datasets, model files from Hugging Face, CSV exports from
 * unknown sources — and every one of them has deserialization sinks.
 *
 * pandas.read_pickle() / pd.read_pickle() (CWE-502):
 *   Uses pickle internally. Loading a .pkl DataFrame from an untrusted source
 *   executes arbitrary code. pandas docs explicitly warn against this:
 *   "Warning: Loading pickled data received from untrusted sources can be unsafe."
 *   Real-world: ML pipelines routinely load pickled DataFrames from shared storage.
 *
 * pandas.read_csv() / pd.read_csv() (INGRESS):
 *   Not a code execution vector, but the primary INGRESS point for data science
 *   pipelines. CSV data is untrusted external input — column names, cell values,
 *   and dtypes can all be attacker-controlled. Downstream pandas.eval() or
 *   DataFrame.query() on this data creates injection chains.
 *
 * pandas.eval() (CWE-94):
 *   Evaluates a Python expression string. Uses numexpr or Python's eval() as backend.
 *   pd.eval("df.A + df.B") is common, but pd.eval(user_input) is code execution.
 *   engine='python' explicitly uses eval(). Even engine='numexpr' has risks.
 *
 * DataFrame.query() (CWE-94):
 *   df.query("age > @min_age") calls pandas.eval() internally. If the query
 *   string includes user input, it's expression injection. The @variable syntax
 *   gives false confidence — the string itself is still evaluated.
 *
 * numpy.load() / np.load() (CWE-502):
 *   np.load("model.npy", allow_pickle=True) deserializes via pickle.
 *   Before numpy 1.16.3, allow_pickle defaulted to True. Many tutorials and
 *   legacy codebases still pass allow_pickle=True. .npz files can also contain
 *   pickled objects.
 *
 * torch.load() (CWE-502):
 *   PyTorch's model loading uses pickle by default. Loading a .pt/.pth file
 *   from an untrusted source (e.g., Hugging Face, model zoo) executes arbitrary
 *   code. PyTorch 2.6+ added weights_only=True as the safe alternative, but
 *   most existing code uses the dangerous default. This is the single most
 *   exploited deserialization vector in the ML ecosystem.
 *
 * joblib.load() (CWE-502):
 *   joblib is scikit-learn's default serialization format. joblib.load("model.pkl")
 *   uses pickle internally. Every sklearn tutorial ends with joblib.dump/load.
 *   Loading a model from an untrusted source = arbitrary code execution.
 */

import type { CalleePattern } from '../languages/python.js';

export const PHONEMES_PYTHON_DATASCIENCE: Record<string, CalleePattern> = {

  // ═══════════════════════════════════════════════════════════════════════════
  // EXTERNAL — pickle-based deserialization (CWE-502)
  // ═══════════════════════════════════════════════════════════════════════════
  // These functions all use Python's pickle protocol internally. Loading data
  // from an untrusted source executes arbitrary code during deserialization.
  // The pickle module's own docs say: "Warning: The pickle module is not secure.
  // Only unpickle data you trust."

  // EXTERNAL: pandas.read_pickle(filepath_or_buffer) — loads a pickled DataFrame.
  // Uses pickle.load() internally. If the .pkl file is attacker-controlled,
  // arbitrary code execution occurs during deserialization.
  'pandas.read_pickle':   { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // EXTERNAL: pd.read_pickle() — same function via the common `import pandas as pd` alias.
  // DST resolves by variable name, so both "pandas.read_pickle" and "pd.read_pickle" must
  // be mapped. In real codebases, `pd` is used 10x more often than `pandas`.
  'pd.read_pickle':       { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // EXTERNAL: numpy.load(file, allow_pickle=True) — loads .npy/.npz files.
  // When allow_pickle=True, this calls pickle.load() on the file contents.
  // Before numpy 1.16.3, allow_pickle defaulted to True. Countless tutorials
  // still use the dangerous pattern.
  'numpy.load':           { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // EXTERNAL: np.load() — same function via the universal `import numpy as np` alias.
  'np.load':              { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // EXTERNAL: torch.load(f) — loads a PyTorch model/tensor from a file.
  // Uses pickle by default. THE most exploited deserialization vector in ML.
  // Safe alternative: torch.load(f, weights_only=True) (PyTorch 2.6+).
  'torch.load':           { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // EXTERNAL: joblib.load(filename) — loads a joblib-serialized object (typically sklearn models).
  // Uses pickle internally. scikit-learn's default serialization format.
  'joblib.load':          { nodeType: 'EXTERNAL', subtype: 'deserialize', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // INGRESS — external data entering the pipeline
  // ═══════════════════════════════════════════════════════════════════════════

  // INGRESS: pandas.read_csv(filepath_or_buffer) — reads CSV data into a DataFrame.
  // The primary data ingestion point in data science. CSV content is untrusted:
  // column names, cell values, and inferred dtypes are all attacker-controllable.
  // Downstream operations (eval, query, to_sql) on this data create injection chains.
  'pandas.read_csv':      { nodeType: 'INGRESS',  subtype: 'file_read',   tainted: false },

  // INGRESS: pd.read_csv() — same function via the common alias.
  'pd.read_csv':          { nodeType: 'INGRESS',  subtype: 'file_read',   tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // EXTERNAL — expression evaluation (CWE-94)
  // ═══════════════════════════════════════════════════════════════════════════
  // These functions evaluate expression strings — effectively eval() for DataFrames.
  // If the expression string includes user input, it is code execution.

  // EXTERNAL: pandas.eval(expr) / pd.eval(expr) — evaluates a Python expression string.
  // With engine='python', this literally calls eval(). Even engine='numexpr' can be
  // dangerous if the expression string is user-controlled.
  'pandas.eval':          { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

  // EXTERNAL: df.query(expr) — filters a DataFrame using an expression string.
  // Calls pandas.eval() internally. df.query("col == @user_input") is safe,
  // but df.query(user_string) is expression injection. The @variable syntax
  // prevents injection of the VALUE but not the EXPRESSION STRUCTURE.
  'DataFrame.query':      { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false },

} as const;

// ── Pattern count ─────────────────────────────────────────────────────────

export function getPhonemeCount(): number {
  return Object.keys(PHONEMES_PYTHON_DATASCIENCE).length;
}
