# v3.0.0-alpha.2 feature reality and next milestones

## Implemented and locally tested

- Native Python AST and opt-in JS/TS TypeScript-compiler AST trace prototypes, hardened with per-file fault isolation, bounded work and helper calls, hash-verified compiler loading, and Node read-only permission mode. A comprehensive semantic analyser is not claimed.
- Caller-argument propagation for selected in-file helper calls; selected SQL, shell, eval, file and outbound URL sinks.
- Deterministic vulnerability triage from supplied CVSS / EPSS / verified KEV / operator reachability data.
- Static before-and-after patch regression comparison; no repository execution.
- Deterministic agent/MCP policy test cases (not live model attacks).
- Offline minimized events for OpenTelemetry-like JSON, Splunk HEC-shaped JSON, and Elastic ECS.
- Optional local Ollama AI review adapter that only sends sanitized metadata to a loopback endpoint and treats output as untrusted.
- Previous v2.5 CISA/OWASP intelligence module and v2.5 scans remain available as separate commands.

## Explicit gaps

- No general cross-file, inter-service, alias-sensitive, framework-specific, path-sensitive or heap-sensitive dataflow analysis.
- No automatically verified package vulnerable-function reachability; `dependency_usage.py` is only import evidence.
- No automatic tests of real repository code, build, deployment, or external host. Separate authorization and a hardened sandbox are required for runtime checks.
- No real adversarial LLM harness or live MCP testing. Policy fixtures exercise expected deterministic decisions only.
- No continuously running SIEM collector. An optional opt-in HTTPS event sender is provided for an operator-approved SIEM endpoint, but it does not monitor runtime application traffic.
- No bundled language model, trained cybersecurity model, or guarantee that model reviews are correct.
- No live CodeQL, Semgrep taint-rules, Trivy, EPSS or Ollama integration test performed as part of this source-only alpha release unless specified in verification report.
- No claims of certification, independent benchmark precision/recall, exploit-proof validation or production readiness.

## Open-source distribution

The existing official repository uses the MIT licence, included in this release. Copyright and third-party notices must be maintained. This archive is **unsigned**, so checksum matching alone cannot authenticate the publisher.
