# DST Property Engine — TODO

## DONE (this session)

- [x] **Property engine foundation** — types, CWE reverse-map, engine runner, wired into verifyAll
- [x] **taint-reachability property** — replaces 30+ CWE injection verifiers
- [x] **missing-auth property** — CWE-285, 862, 863, 306
- [x] **sensitive-exposure property** — CWE-200, 209, 312, 319, 532, 598
- [x] **weak-crypto property** — CWE-327, 328, 326, 261, 321
- [x] **resource-lifecycle property** — CWE-401, 404, 772, 775
- [x] **integer-overflow property** — CWE-190, 191, 681
- [x] **sentinel-collision property** — CWE-138, 253, 170 (novel — no other SAST tool)
- [x] **buffer-size property** — CWE-119, 120, 787
- [x] **Range pipeline connected** — addDataFlow auto-bridge (4 lines), numericValue→RangeInfo bridge
- [x] **Range pipeline integration tested** — sinkHasBoundedRange/SafeRange/NonZeroRange verified end-to-end
- [x] **Handler parameter taint inference** — verb-named methods in module.exports get tainted params
- [x] **Cross-file parameter taint propagation** — margin pass pushes taint into callee params
- [x] **Margin pass source-code fallback** — searches raw source when no call-site node exists
- [x] **Star import expansion** — CommonJS require() ['*'] expanded to real function names
- [x] **TRANSFORM empty data_in taint** — synthetic tainted entry for TRANSFORM nodes with no data_in
- [x] **Ghost CMS cross-file detection** — tainted data from posts.js propagates into slug-filter-order.js
- [x] **OWASP benchmark verified** — 92.7% unchanged through all changes
- [x] **Code review at integration seam** — caught circular import, CONTROL neutralization, SAFE handler

## REAL BLOCKERS

- [ ] **Proof generation on cross-file findings** — Cross-file taint produces findings but `generateProof` isn't called on them. DST already has the payload system (`payload-gen.ts`), the delivery specs, the oracles. The tainted path from `frame.options.filter` through string concat into SQL CASE is visible. Just call `generateProof` on cross-file re-verified findings and let the proof BE the classification. A payload of `' UNION SELECT 'DST_CANARY_SQLI' --` in the slug parameter that produces a canary in the query output IS the proof it's SQL injection. No CWE label needed — the proof speaks.

- [ ] **Cross-file proof delivery spec** — The delivery spec needs to trace back from the callee's sink through the caller's INGRESS to determine the HTTP method/path/parameter. Currently delivery specs are single-file. Extend to follow the cross-file taint chain back to the original INGRESS node for accurate `http.path`, `http.param` fields.

## PROPERTIES TO BUILD (not blockers — future capability)

- [ ] **auth-ordering** — "Every security gate must precede the operation it protects." 11 CWE verifiers already implement this in the CWE layer (CWE-551, 421, 179, 180, 696, etc. using `node.sequence`). Migrating to property engine unifies them. Not urgent — they work as CWE verifiers.

- [ ] **cross-callsite-consistency** — GhostScript pattern. "All callsites of a function with a safety check have the same check." Needs cross-file sentence analysis.

- [ ] **spec-mining** — Engler's deviant behavior on semantic sentences. "If 85% of STORAGE/sql_query nodes are preceded by TRANSFORM/sanitize, flag the 15% that aren't."

## MECHANICAL (could knock off quick)

- [ ] **Remove DST_SKIP_PROPERTIES env var** — Added for V2 vs V3 A/B testing. No longer needed. Remove the env var check from verifier/index.ts.

- [ ] **Clean up sandbox debug scripts** — `src/sandbox/ast-dump.ts`, `src/sandbox/debug-deps.ts`, `src/sandbox/debug-margin.ts`, `src/sandbox/sweep-truth-v2only.ts` are development artifacts. Either delete or move to a `sandbox/debug/` subdirectory.

- [ ] **Update docs/plans/ status** — Mark Phase 1, 2, 3 plans as COMPLETE. Handler inference plan as COMPLETE.

## RANGE PIPELINE (partially done, not blocking)

- [ ] **Java range extraction from conditions** — Port JavaScript's `extractRangeFromCondition()` to Java profile. Java currently only evals conditions to boolean, doesn't extract ranges into RangeInfo.

- [ ] **Python range extraction** — Same port for Python profile.

## DETECTION PRECISION (optimization, not blocking)

- [ ] **Fix 17 OWASP false positives** — BenchmarkTest01803, 01807, etc. Unrecognized Java sanitization patterns. Could improve FPR from 7.3%.

- [ ] **Phoneme coverage for Java sanitization** — PreparedStatement via helper methods, framework-specific validators.

## REAL-WORLD VALIDATION (ongoing)

- [ ] **Keycloak (Java)** — Best target for auth-ordering, weak-crypto, sensitive-exposure properties. 190+ CVEs.
- [x] **Ghost CMS (JS/TS)** — Cross-file taint detection working. Findings produced on vulnerable version.
- [ ] **Strapi (TS)** — Auth ordering + token lifecycle CVEs.
- [ ] **Codex mock app** — Purpose-built for integer overflow, sentinel collision, buffer size. GPT building it.

## FUTURE (separate research)

- [ ] Concurrency analysis (ksmbd pattern)
- [ ] Algorithmic invariant knowledge base (CGIF LZW pattern)
- [ ] Dynamic verification sandbox (runtime proof execution)
