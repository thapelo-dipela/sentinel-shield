# 3.0.0-alpha.2 - security correctness release

- Fix Python AST `None` handling, bounded recursion/work/call budgets, and per-file failures as partial coverage.
- Extend Python source models for request JSON, headers, method chaining, iterators, dictionary/list operations, `await`, and common numeric casts.
- Remove implicit Node module resolution and developer-specific TypeScript fallback. The JS parser requires a separately approved absolute compiler file with SHA256, outside the scanned repository.
- Use Node 22+ read-only filesystem permission mode; no project Node module, install hook, or build may run.
- Expand JS try/catch, loop, switch and cast modelling within documented limits.
- Bind AST finding fingerprints to normalized local source evidence without exporting raw code.
- Add bounded hostile-repo fixtures, standard library smoke coverage, direct JS parser compatibility tests and fail-closed regressions.
- Fix docs to acknowledge the existing MIT-licensed GitHub repository.

# 3.0.0-alpha.1 | 2026-11-04

Developer-preview defensive engine. Adds Python and opt-in JS/TS AST-based source-to-sink tracing, external semantic Semgrep rule templates, offline EPSS/CVSS/verified KEV/reachability triage, non-executing patch regression checks, simulated MCP and agent policy evaluations, local metadata-only AI review and privacy-minimized SIEM event export. Existing v2.5 scanner and threat intelligence remain bundled. New functions have bounded analysis and do not justify enterprise certification. Consult `docs/V3_RELEASE_LIMITATIONS.md` and `LICENSING_DECISION.md`. No third-party source files copied from reviewed repositories.

---

# Sentinel Shield v2.5.0 (4 November 2026)

- **Fail-closed KEV cache**: retained raw source bytes in the atomic snapshot; enforce rehash/reparse consistency on load, a minimum of 1,000 KEV records, sudden-drop detection (15%) and owner-controlled POSIX cache permissions. Reject symlinked cache paths and repo-local caches. A forged empty snapshot now returns incomplete rather than false clean. Legacy cache files require a new trusted refresh.
- **Commit-pinned CISA mirror fallback**: query CISA's maintained GitHub repo for the current commit, fetch the immutable 40-character-SHA snapshot and record the commit; mutable branch content is no longer consumed directly. Mirror HEAD and raw feed are not independently signed.
- **Gitleaks fingerprint correction**: use bounded local source evidence rather than redacted Gitleaks JSON; distinguishing same-file secrets, moved code and replacements, including match columns when available. Missing local files become partial coverage. Fingerprint scheme `v2.4` remains unchanged for existing baseline compatibility.
- **CISA scheduled project comparison**: workflow requires a trusted-digest-pinned Trivy v0.76.1 installation, generates actual project CVE JSON and passes `--vuln-report` to offline KEV review; no new vulnerabilities inferred from KEV alone. Requires operator configuration and deployment.
- **Release signing template**: SHA-pinned GitHub Actions workflow for keyless provenance and CycloneDX file SBOM attestations, not executed for this local ZIP. Includes documented verification and independently governed release tag requirements.
- **Evaluation**: new cache poisoning, symlink, permission, UTF-16 XML, feed shrink, mirror pinning and Gitleaks fingerprint regression tests, plus independent real-app validation protocol (not yet executed).
- **Not yet demonstrated**: real Trivy binary compatibility in this environment, live CISA fetch from this environment, real signed provenance for this ZIP, independent real-app precision/recall or comprehensive taint analysis.

# Sentinel Shield v2.4.0 (4 November 2026)

- Content-normalized finding fingerprints and machine-independent Semgrep IDs, with regression tests.
- New opt-in `scanner/threat_intel.py`: bounded CISA KEV and CISA RSS updates, exact CVE comparison to supplied Trivy/CycloneDX reports, new-feed deltas, OWASP VWAD offline lab catalog filtering and incomplete/stale feed signaling.
- New `docs/THREAT_INTELLIGENCE.md` and `templates/threat-intel-workflow.yml` for optional scheduled checks from a trusted verified package.
- Local synthetic benchmark, source-file CycloneDX inventory and explicit integrity/provenance limitations.
- **Not implemented**: signed releases/attestations, live Trivy validation, CVE version reachability, runtime attack monitoring, automatic lab execution, or independent real-world precision/recall metrics.
- **Validation note**: feed refresh parser/transport behavior tested offline with mocks; network connectivity to official feeds not end-to-end executed in the release environment.

# Changelog

## 2.3.0 | 2 November 2026

- Added safe `display_path` and explicit `trust_notice`/`untrusted_fields` to JSON findings. Raw paths remain available **only as untrusted machine data** so SARIF links and exact path matching still work.
- Narrowed suppressions to a per-finding fingerprint, trusted path/path ID, accountable owner and ticket, documented reason and max 90-day future expiry. Expired exceptions remain visible, and CRITICAL findings cannot be suppressed.
- Counted and surfaced Semgrep staging exclusions for dependency/environment directories; any excluded code now yields a partial-coverage state that blocks strict full scans, rather than an unqualified pass.
- Added regression tests for malicious filenames, JSON trust labels, duplicate findings, suppression expiry, stage omissions and mocked Trivy command/JSON parsing.
- Updated dated enterprise framework gap map: NIST SSDF 1.2 remains an initial public draft, and Microsoft SDL/Google SAIF/SLSA are not certifications for this skill.
- **Not changed:** Real Trivy compatibility remains unverified. No provenance signing, SBOM, taint engine, runtime monitoring, source-history Gitleaks scanning or measured SAST accuracy has been implemented.

# Changelog

## 2.2.0 | 2 November 2026

- Replaced Semgrep absolute ignore-file override with bounded trusted source staging, including tests/vendor, then remapped and validated result paths. No repo scanner config is copied.
- Restored actual repository paths for JSON/SARIF/suppression matching; retained independent hashed path IDs and sanitized Markdown display.
- Required independently configured manifest digest in CI and documented verifier-first/test-with-`-B` order.
- Accepted `SET search_path TO` and `security_invoker = on/true/1`; added comment/dollar-quote-aware SQL statement masking.
- Flagged arbitrary Claude/Cursor repo-supplied settings hooks, including `bash ./local-script.sh`.
- Added bounded lockfile/minified scans and lockfile remote-registry review rules. Limited head/tail sampling remains an accepted coverage gap.
- Added direct regression cases and optional isolated real-binary compatibility smoke harness.
- Real third-party scanner binaries not executed in the release-building environment.

# Changelog

## 2.1.0 (2026-11-02) - security maintenance release

- Fix Gitleaks false-negative caused by missing JSON stdout report; fail closed for empty/malformed reports; redact all secret values in tool output.
- Verify complete packaged inventory and support separately trusted manifest digest; document Python isolated invocation.
- Refuse target-controlled baselines, suppression files and tool manifests. Expired suppression entries produce audit findings.
- Expand `.env` and secret-name detection, agent rule files, code-comment prompt injection, and agent-hook cues.
- Analyze multiline SQL and correlate public table creation with RLS enable statements across SQL files; remove broad duplicate DB line rules.
- Parse all Trivy result classes and preserve Semgrep findings when parser errors exist.
- Report accepted gaps and excluded directories; preserve Unicode filename identity with a path ID.
- Run CI scanner from a trusted base checkout and retain reports after failed scans.
- Add 17 new regression tests (32 total) for critical defect scenarios and parsers.

### Explicit remaining limitations

- External scanner versions were **not** executed in this build environment; third-party command compatibility must be validated before relying on full mode.
- No verified end-to-end bypass of all repo-supplied ignore files. Local scan flags suspect suppressions; full mode marks coverage incomplete when found.
- Gitleaks integration checks current files, **not git history**.
- Advisory SQL matching is not an AST-backed parser and does not prove effective deployed RLS.
- Secret detection and AI prompt-injection pattern coverage are inherently incomplete; reports are findings, not guarantees.
- No deep taint/reachability analysis, runtime monitoring, automated incident action, or signed distribution infrastructure.
