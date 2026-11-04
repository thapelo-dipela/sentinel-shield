# Sentinel Shield 3.0.0-alpha.2: security fixes and limitations

## Release blockers corrected

**Python AST reliability.** The tracer handles bare `return` and annotations, detects excessively deep ASTs, caps per-file work and helper invocations, and captures errors as named coverage gaps. It continues scanning remaining files after a problematic file. Exit 3 means incomplete coverage, exit 1 means new HIGH/CRITICAL within completed scope, and exit 2 means invalid input or unexpected process-level failure. This is not path-sensitive or complete taint analysis.

**Hostile JavaScript dependencies.** We removed `require('typescript')` and the developer-system fallback. The user must select a trusted absolute TypeScript compiler file outside the audited root and provide a SHA256 independently approved by the operator. The exact file hash is checked by Python and again in the JS process. Node 22+ runs with `--permission` and read-only allowances for the parser, audited root and compiler; arbitrary repo writes, process spawning and network calls are not enabled. The skill may not be installed inside the scanned tree for this JS mode. No repository-supplied `.npmrc`, `node_modules`, scanner configuration, package scripts or TypeScript installation commands are used. A compromised separately approved compiler is still a trust-chain risk.

**Resource and language coverage.** Python and JS per-file errors, unsupported control constructs and budget exhaustion are reported as coverage gaps, never as clean. Additional Python cases: `.strip()` and other method propagation, `request.get_json`, headers, `with`, `for`, async payloads, list/dict tracking and numeric casts. Additional JS cases: try/catch, for-of, for, while and switch, with numeric conversion sanitizers. Static modelling may still have false positives and false negatives, including callbacks, aliases, destructuring, cross-file flow, dynamic dispatch and sanitizers.

**Finding identity.** Duplicated abstract traces on different lines remain separate findings. Hashes of whitespace-normalized local source evidence make fingerprints change on relevant code changes but remain stable under line movement; identical repeated code uses deterministic occurrence indices. Raw code is never emitted.

## Verification and open issues

- The regression suite includes malformed and adversarial source cases and runs real AST parsing with a verified TypeScript compiler when it is available. Local compatibility was exercised with Node v22.16.0 and TypeScript v5.8.3; external CI still needs independent verification.
- A Python standard library scan is a **robustness smoke test**, not a detection-accuracy benchmark.
- The package is an unsigned alpha. Release in a reviewed pull request, run CI tests, verify a publisher-authenticated digest, and use the MIT licence already present in the official repository.
- Independent public benchmarks, live CodeQL/Semgrep taint analysis, actual vulnerable-function reachability, active agent red-team tests and signed provenance are still pending.

## Safe use

```bash
python3 -B -I scanner/verify_integrity.py --expected-manifest-sha256 APPROVED_MANIFEST_DIGEST
python3 -B -I scanner/advanced_engine.py --path /authorized/project
python3 -B -I scanner/advanced_engine.py --path /authorized/project --js-ast \
  --typescript-file /trusted/typescript/lib/typescript.js \
  --typescript-sha256 APPROVED_TYPESCRIPT_COMPILER_DIGEST
```

Never paste in a digest supplied by the untrusted repository being audited.
