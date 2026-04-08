# DST: Deterministic Security Testing

Static analysis that doesn't just find vulnerabilities -- it proves them exploitable.
DST generates deterministic proof certificates: the exact payload, delivery method, and
verification oracle for each finding. No AI in the loop. Same code, same report, every time.

## Quick Start

```bash
git clone https://github.com/Clawdius-hash/dst-engine.git
cd dst-engine
npm install --legacy-peer-deps
npx tsx src/dst-cli.ts --demo --prove
```

## What You'll See

DST parses source code into a graph, traces tainted data flows, verifies 783 CWE
properties, and generates proof certificates for exploitable findings:

```
Neural Map: 46 nodes, 43 edges
  Nodes by type: STRUCTURAL(19), INGRESS(14), STORAGE(2), EGRESS(4), TRANSFORM(5), EXTERNAL(2)
  Edges by type: CONTAINS(29), DATA_FLOW(9), READS(1), DEPENDS(4)
  Tainted data flows: 45
  CWE properties to check: 783

[FAIL] CWE-89: SQL Injection
  CRITICAL: User input from req.body.login flows to SQL query at
  db.query(query, ...) without parameterization.
    Source: req.body.login (line 10)
    Sink:   db.query(query, ...) (line 11)
    Missing: CONTROL (input validation or parameterized query)
    PROOF [strong]:
      Payload: ' UNION SELECT 'DST_CANARY_SQLI' --
      Canary:  DST_CANARY_SQLI
      Context: sql_string
      Deliver: http POST /
      Oracle:  hybrid -- Source-sink path established by static analysis.
               Payload reaches sink unmodified.
      Variants: 4 additional payload(s)

528/597 properties verified clean
446 finding(s) across 69 failed properties
Deterministic: same code -> same report. Always.
```

That `PROOF` block is the difference. DST doesn't just say "this looks vulnerable" -- it gives
you the payload to prove it.

## The Numbers

| Benchmark | Result |
|-----------|--------|
| OWASP BenchmarkJava (SQLi, 504 files) | **92.7%** score (100% TPR, 7.3% FPR) |
| OWASP BenchmarkJava (all 2,740 files) | **83.7%** composite (99.6% TPR, 15.8% FPR) |
| OWASP weakrand/crypto/hash/securecookie | **100/100** (1,042 files, 0% FPR) |
| NIST Juliet Java baseline | 100% (103/103 CWE categories) |
| WebGoat (real app, 399 files) | 11,197 findings across 321 CWE categories |
| Real-app false positive rate | 2.1% (Apache Shiro differential) |
| Log4Shell detection | 5/5 chain files |
| GPT-5.4 adversarial red team | 35/35 (zero misses) |
| CWE properties checked per file | 783 |
| Test suite | 1,709 passing |
| Languages | 10 (Java, JS/TS, Python, Go, Rust, PHP, C#, Ruby, Kotlin) |

## What Makes This Different

**Proof certificates.** Other tools say "line 42 might be vulnerable." DST says "here's the
exact payload, here's where to send it, here's how to verify it worked." The proof system
generates context-aware payloads (SQL string context vs. numeric context, HTML attribute vs.
body, OS command separators) from the same graph that detected the vulnerability.

**Phoneme architecture.** DST doesn't pattern-match on API names. It classifies every API call
into a universal semantic type -- INGRESS, STORAGE, EGRESS, TRANSFORM, EXTERNAL, CONTROL --
using a phoneme dictionary. `req.body` and `request.form` and `r.FormValue` all map to the
same thing: tainted user input entering the system. Adding a new language is ~200 lines of
phoneme mappings. The graph does the rest.

**Deterministic.** No machine learning in the detection loop. No probabilistic models. No
"confidence scores." A finding either exists in the graph or it doesn't. Run it twice, get the
same report. Run it a year from now, get the same report.

**Bidirectional vocabulary.** The same phoneme dictionary that classifies `db.query` as a SQL
sink also knows what payloads are valid in SQL context. Detection and proof generation share
one vocabulary. This is the architectural insight that makes proof certificates possible
without a separate fuzzing engine.

## Scan Your Code

```bash
# Scan a single file
npx tsx src/dst-cli.ts path/to/file.java

# Scan with proof certificates
npx tsx src/dst-cli.ts path/to/file.java --prove

# Scan a directory (enables cross-file analysis)
npx tsx src/dst-cli.ts path/to/project/

# JSON output
npx tsx src/dst-cli.ts path/to/file.java --prove --json
```

## Supported Languages

**Production-ready (benchmarked, real-world apps scanned):**
- Java — 92.7% OWASP BenchmarkJava (504 SQLi files), 83.7% overall (2,740 files), WebGoat, Log4Shell, Juliet NIST
- JavaScript/TypeScript — demo apps, Express/Node patterns, single-file analysis

**Other languages have profiles and parse correctly but have not been benchmarked to production standard.** The architecture is language-neutral — each language is a phoneme profile (~200 lines). The graph and verifiers are shared.

DST reads source code only — it cannot scan compiled binaries, executables, or installed applications.

## Architecture

```
Source code
  |
  v
tree-sitter AST
  |
  v
Phoneme classification    (API calls -> universal semantic types)
  |
  v
NeuralMap graph           (nodes + tainted data flow edges)
  |
  v
CWE verification          (783 properties checked against graph)
  |
  v
Proof generation          (payload + delivery + oracle per finding)
```

The phoneme dictionary is the core. It maps language-specific API calls to universal types:

| Phoneme Type | Examples |
|-------------|----------|
| INGRESS | `req.body`, `request.form`, `r.FormValue()`, `$_GET` |
| STORAGE | `db.query()`, `redis.set()`, `fs.writeFile()` |
| EGRESS | `res.send()`, `response.write()`, `fmt.Fprintf()` |
| TRANSFORM | `encodeURIComponent()`, `html.escape()`, `sanitize()` |
| EXTERNAL | `fetch()`, `http.get()`, `urllib.urlopen()` |
| CONTROL | `if`, `try/catch`, validation functions |

A tainted INGRESS node flowing to a STORAGE node without an intervening TRANSFORM is a
potential SQL injection -- regardless of language. The CWE verifiers operate on the graph,
not on syntax.

## The Story

Built by a 21-year-old working at an aluminum warehouse in Indiana, collaborating with AI
instances across multiple sessions. No CS degree. The key insight was the phoneme
architecture: decompose code into universal semantic shapes, build a graph, let the graph be
the detection engine. The proof generation system was designed and verified by 9 independent
AI agents across 2 layers of review.

The name "phoneme" comes from linguistics -- the smallest unit of sound that distinguishes
meaning. In DST, a phoneme is the smallest unit of API behavior that distinguishes security
semantics. `mysql_query` and `pg_query` sound different but mean the same thing: data goes
to a database.

## Status

Alpha v2. 100% SQL injection detection on OWASP Benchmark. Pure semantic sentences — no regex, no confidence scores. The engine works. The proof system is v1. Open source.

**Help welcome:**
- Expanding payload dictionaries for more injection contexts
- Adding language phoneme profiles (each one is ~200 lines)
- Improving cross-file taint analysis
- Writing CWE verifiers for the remaining stub inventory

Issues and PRs welcome.

## License

MIT
