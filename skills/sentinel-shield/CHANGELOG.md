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
