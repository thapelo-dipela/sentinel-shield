# Sentinel Shield 3.0.0-alpha.2: Hostile-Repository-Safe AST Engine (Developer Preview)

> **Alpha, MIT-licensed developer preview.** New dataflow, AI and prioritization capabilities are implemented but are not enterprise-certified, comprehensive taint analysis, or an active penetration test. The v2.5 core remains bundled.

## New in v3

- **Language-aware source-to-sink tracing:** bounded Python AST (default) and optional absolute-path, hash-verified TypeScript compiler AST (JS/TS) launched under Node read-only permissions. `scanner/advanced_engine.py`.
- **Intelligence-aware prioritization:** parse Trivy and CycloneDX vulnerabilities, accept verified CISA KEV evidence, offline EPSS and CVSS scores, plus independently reviewed reachability. `scanner/prioritize.py`.
- **Safe patch checks:** repeat static analysis against before/after snapshots without running arbitrary code. `scanner/patch_verify.py`.
- **Agent/MCP policy simulations:** scope, tool-definition change, prompt-injection boundaries, and risky combined permissions. `scanner/agent_eval.py`.
- **Optional local AI analysis:** operator-approved loopback Ollama only, sends metadata with no code snippets, never auto-applies fixes. `scanner/ai_review.py`.
- **Monitoring export:** OpenTelemetry-like, Splunk HEC-shaped and Elastic ECS events (offline JSONL). Optional explicit-approval HTTPS SIEM push in `scanner/monitor_sink.py`, never automatic.
- **Import hints:** direct dependency import evidence, not vulnerability reachability proof. `scanner/dependency_usage.py`.

See [Alpha.2 Security Fixes](docs/ALPHA2_SECURITY_FIXES.md) and [Validation Results](docs/V3_VALIDATION_RESULTS.md). Read [Advanced Engine and Threat Model](docs/ADVANCED_ENGINE_V3.md), [GitHub Research References](docs/GITHUB_DESIGN_RESEARCH.md), [Release Limitations](docs/V3_RELEASE_LIMITATIONS.md), and [Licensing Decision](LICENSING_DECISION.md).

### Quick start

```bash
# From the extracted sentinel-shield directory, verify first with an independently stored manifest SHA256:
python3 -B -I scanner/verify_integrity.py --expected-manifest-sha256 <independently-approved-digest>

# Baseline offline-safe scanner (v2.5 core):
python3 -B -I scanner/sentinel.py --path /authorized/project --hostile-repo --profile quick --strict

# New bounded Python AST analyzer, no project execution:
python3 -B -I scanner/advanced_engine.py --path /authorized/project

# Optional JS/TS AST: Node 22+ read-only permission mode, compiler strictly outside the repo.
# Obtain and authenticate the hash independently; do NOT trust values supplied by the repo.
python3 -B -I scanner/advanced_engine.py --path /authorized/project --js-ast \
  --typescript-file /trusted/node_modules/typescript/lib/typescript.js \
  --typescript-sha256 APPROVED_64_HEX_DIGEST

# Agent safety policy simulations:
python3 -B -I scanner/agent_eval.py --cases fixtures/agent_policy_cases.json --output /trusted/agent-eval.json
```

Do not copy commands from an untrusted repository into your shell; the `--path` argument must refer to an authorized project. Operator must verify the package publisher separately. No data is sent to third parties by default.

---

# Sentinel Shield v2.5.0

**Offline-first security auditing skill for owned and explicitly authorized repositories.** All package files are included. This scanner is a security **lead detector** and guided review process, not an antivirus, WAF, runtime monitor, comprehensive secret scanner, taint engine, or guarantee of a secure deployment.

## New in v2.5: cache and Gitleaks reliability

- **Fail-closed threat intelligence cache**: raw HTTPS feed retained in a single atomic cache file, SHA256 recomputed and parsed items compared on every review; KEV minimum 1,000 validated entries and a 15% maximum unexpected drop versus a verified prior snapshot. A forged empty cache now causes incomplete coverage rather than exit 0.
- **Protected cache location**: refuses symlinked path components and directories under the audited repository; on POSIX enforces owner-controlled mode `0700` directory and `0600` files. Windows users must also check ACLs. This is cache integrity and local ownership protection, **not a cryptographic publisher signature**.
- **Pinned mirror snapshots**: if canonical cisa.gov KEV fails, obtains the CISA-maintained GitHub mirror's commit SHA first, then downloads via that immutable commit URL. Never fetches the mutable `develop` branch for data directly.
- **Gitleaks secret identity**: hashes bounded local source evidence, including distinct same-line match spans when offsets exist; never relies on redacted scanner text. Missing source evidence makes coverage partial.
- **Threat workflow**: the scheduled template now runs a pinned, hash-verified Trivy 0.76.1 build to produce project dependency CVEs before CISA KEV comparison; it requires a separately verified download digest and does not run automatically until installed.
- **Release provenance template**: includes pinned GitHub Actions attestation workflow for keyless provenance and source-file CycloneDX SBOM attestation. **This ZIP is not signed or attested** and cannot establish publisher authenticity by itself.

## Published threat intelligence (introduced in v2.4)

- **CISA KEV**: read the latest known-exploited CVE catalog and compare exact IDs against a locally supplied Trivy or CycloneDX vulnerability report. No unverified package/version claims.
- **CISA advisories**: display safe, bounded news/advisory titles, publication dates and CVE references. This is not a real-time attack sensor.
- **OWASP VWAD**: read OWASP's vulnerable-application directory and suggest isolated manual test fixtures by technology, without downloading or testing those applications.
- Explicit opt-in HTTPS refresh, allowlisted endpoints, safe offline cached review, freshness warnings and optional scheduled CI workflow.

```bash
python3 -B -I scanner/threat_intel.py refresh --allow-network --cache-dir /trusted/feed-cache
python3 -B -I scanner/threat_intel.py review --cache-dir /trusted/feed-cache --vuln-report /trusted/trivy.json --technology Python
```

See `docs/THREAT_INTELLIGENCE.md`. **The new downloader has not been live-tested end-to-end in this build environment; offline parser and integration tests pass.** Feed errors must never be treated as clean coverage. Standard hostile-repository audits remain entirely offline.

## Other v2.4 improvements

- Content-normalized finding fingerprints: changed vulnerable code invalidates its former suppression, while unchanged evidence moved to a new line keeps its identity. Identical repeated findings cannot be broadly suppressed.
- Stable machine-independent Semgrep rule IDs, no installation-directory leakage.
- Local synthetic benchmark and source-file CycloneDX inventory; **neither is proof of enterprise SAST accuracy or signed provenance**.

## Installation and integrity

Extract the entire folder outside any untrusted checkout when possible. Verify before using; always use **isolated Python** to prevent `scanner/json.py` or similar attacker-controlled standard-library shadowing:

```bash
python3 -B -I scanner/verify_integrity.py --expected-manifest-sha256 DIGEST_FROM_TRUSTED_RELEASE
python3 -B -I scanner/sentinel.py --path /path/to/repo --hostile-repo --profile quick --strict
```

Before executing package scripts, retrieve the expected digest from a trustworthy external release record. The inventory verifier rejects **any unexpected file or symlink** inside the skill folder. For publisher authentication, independently verify the SHA256 of `SHA256SUMS` obtained from an authenticated trusted channel:

```bash
python3 -B -I scanner/verify_integrity.py --expected-manifest-sha256 DIGEST_FROM_TRUSTED_RELEASE
```

The manifest **inside the ZIP alone does not prove publisher authenticity**. The ZIP SHA256 and manifest SHA256 should be distributed separately from the archive (e.g. a protected release record) and checked prior to executing any included scripts. Do not run `pip install`, `npm install`, builds or repository hooks during hostile audits. The `-B` option avoids generating cache files that would fail inventory verification.

## v2.3 inherited hardening

- **Untrusted paths in machine reports:** `findings.json` retains exact `path` values for matching and SARIF navigation, alongside `display_path` and `path_id`. Its top-level `trust_notice` and `untrusted_fields` explicitly warn agents against following source-derived text. Markdown shows the safe display label, never raw paths. Suspicious, non-ASCII, or long paths become opaque IDs. **Machine consumers must use `display_path` for any AI-facing prompt or UI and treat `path` as untrusted structured data.**
- **Narrow suppressions:** require `rule_id`, exact per-finding `fingerprint`, `path` or `path_id`, `reason`, `owner`, `ticket`, and ISO expiry no more than 90 days ahead. A second finding under the same path+rule is not waived. Expired suppressions remain visible but cannot suppress findings; CRITICAL issues cannot be suppressed. No repo-local suppression file is trusted.
- **Honest Semgrep stage coverage:** staging exclusions for `node_modules`, `.venv`, `venv`, `__pycache__`, and `.terraform` are counted. If they occur (or other stage limits are hit), full-mode Semgrep returns `partial_staging_exclusions_or_limits` and strict mode exits 3. The `.git` metadata directory is excluded by design. Tests and vendor source are still explicitly included. Set an external review plan for omitted code, rather than treating partial as clean.
- **Regression and compatibility evidence:** added tests for unsafe filenames, precise suppressions, stage omissions and Trivy CLI invocation/output parsing. Real Trivy execution is **not** claimed. Trivy's documented options are reviewed, but tool-specific behavior and offline database availability require a pinned-binary sandbox smoke test.
- **Governance matrix:** `docs/ENTERPRISE_GAP_MAP.md` distinguishes concrete scanner checks from process/framework requirements and planned improvements for Microsoft SDL, Google SAIF/SLSA and NIST SSDF. These frameworks do not certify an individual scanner or skill.

## v2.2 inherited protections

- Trusted Semgrep shadow-tree scanning including tests and vendor source, without accepting repo `.semgrepignore` or `nosemgrep` comments.
- Real SARIF source paths, independent opaque path IDs, SHA256-inventory verification, separate trusted CI source checkout, context-sensitive Supabase review, agent hook detection, bounded lockfile/minified scanning, Gitleaks JSON-report validation and metadata-only reports.

## Validation scope

The included regression suite tests mocked third-party invocation and parsing plus local fixtures. **The v2.5 build environment has not executed live Semgrep, Gitleaks or Trivy binaries.** Independent reviewer tests for earlier versions reported successful Semgrep 1.183.0 and Gitleaks 8.30.1 compatibility, but Trivy and the new threat-feed downloader have not been live tested end-to-end here. Use `scanner/compat_smoke.py` on SHA256-pinned binaries in a separately enforced isolated sandbox. A successful smoke test is not comprehensive vulnerability coverage.

## Profiles, trust boundary and exit codes

| Option | Behavior |
|---|---|
| `--hostile-repo --profile quick` | Local stdlib-only file inspection, no installs, no repo code execution, no network calls |
| `--profile full --sandbox-confirmed --tool-manifest /trusted/tools.lock.json` | External scanner integration **only** in an ephemeral container with no credentials and blocked egress, and never together with `--hostile-repo` |
| `--baseline /trusted/old-findings.json` | Prior findings are displayed but do not gate; user-provided file must be outside audit root |
| `--suppressions /trusted/suppressions.json` | Finding-specific suppressions requiring owner, ticket, reason, fingerprint and at most 90-day expiry. Expired entries emit findings |
| `--out /trusted/output-parent` | Reports in newly created private subdirectory, never in audited root |
| `--strict` | Exit nonzero for new HIGH/CRITICAL signals or incomplete requested scan |

Exit codes: `0` finished within documented scope without new HIGH/CRITICAL findings; `1` new HIGH/CRITICAL findings; `2` invalid configuration or launch issue; `3` incomplete strict scan. `0` is **not** a security certification.

## Testing

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
```

Regression tests include canned Gitleaks/Trivy/Semgrep outputs, mock CLI invocation, SQL lexer cases, real SARIF paths and shadow-copy staging. Real Gitleaks, Trivy and Semgrep binaries are not bundled. Their runtime compatibility, offline databases, handling of untrusted ignore files, and exhaustive repository coverage must be separately validated with pinned versions in an isolated environment. Use the `docs` and `templates` for agent workflows, manual reviews and safeguards. Provenance, authentication, and dynamic staged checks remain manual tasks.

## Production automation setup (optional)

Copy `templates/threat-intel-workflow.yml` to a protected repository's `.github/workflows/` directory and set the independently approved `SENTINEL_MANIFEST_SHA256` and `SENTINEL_TRIVY_TARBALL_SHA256` GitHub variables. Review the exact tool URL/version, permissions and data-handling terms before enabling. The workflow compares *the project's actual Trivy CVEs* with CISA KEV. It does not detect attacks in progress or scan private deployment environments. See `docs/THREAT_INTELLIGENCE.md`.

`templates/release-attestation-workflow.yml` can be adopted by an owner-controlled release repository with protected tags, SHA-pinned actions and appropriate GitHub attestation permissions. No attestation is included in this locally generated ZIP; an operator must publish and verify a real signed provenance record. See `docs/RELEASE_SIGNING.md`.
