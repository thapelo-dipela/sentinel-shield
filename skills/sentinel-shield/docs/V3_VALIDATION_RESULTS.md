> Historical validation report for v3.0.0-alpha.1. For current fixes and tests, see [alpha.2 fixes](ALPHA2_SECURITY_FIXES.md).

# Sentinel Shield v3.0.0-alpha.1 validation report

Date: 2026-11-04. Scope: source-only package in the assistant's working environment. **No production application or authorized third-party target was scanned.**

- Original v2.5 scanner + intelligence unit tests and new v3 modules: **129/129** unit tests passed with `python -B -I -m unittest discover -s tests` before packaging.
- Native Python AST dataflow and JS/TS TypeScript compiler AST validated on a local synthetic project with both languages. TypeScript compiler v5.8.3 was available in this environment. This is not validation against all TypeScript versions or real applications.
- Maintainer-authored v3 synthetic sanity corpus: **15** cases, **9** correctly labelled positive cases, **6** negative cases, no mismatches. These results **do not represent real-world precision/recall**.
- Agent/MCP policy fixture suite: 8/8 deterministic reference cases passed. These tests are not an independent live-model robustness assessment.
- CISA/OWASP threat-intelligence code carried over from v2.5 unchanged. Its offline regression suite was run again. Live feed-fetch and Trivy execution were not independently validated in this release.
- EPSS and CVSS modules accept offline third-party metadata. Live EPSS API or CVSS v4 vector implementation not tested or bundled.
- AI reviewer: schema-limited local Ollama adapter and dry-run tests, no actual model inference performed during release tests.
- SIEM exporter: offline JSON generation and destination-policy unit tests, no real remote collector connection performed.
- Patch verification: read-only before/after static regression tests validated. Functional test execution of untrusted project code was **not** performed.
- Source-only SBOM and `SHA256SUMS` inventory are generated after source freeze. They attest integrity only relative to a separately trusted manifest digest. Neither is a signature nor a publisher identity attestation.

## Security guarantees not provided

No guarantee of comprehensive taint tracking, complete package reachability, absence of vulnerabilities, defense against malicious binaries, continuous runtime detection, compliance certification or resistance to all AI prompt injections.
