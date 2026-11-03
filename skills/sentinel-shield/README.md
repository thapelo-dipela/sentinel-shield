# Sentinel Shield v2.3.0

**Offline-first security auditing skill for owned and explicitly authorized repositories.** All package files are included. This scanner is a security **lead detector** and guided review process, not an antivirus, WAF, runtime monitor, comprehensive secret scanner, taint engine, or guarantee of a secure deployment.

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

## What v2.3 changes

- **Untrusted paths in machine reports:** `findings.json` retains exact `path` values for matching and SARIF navigation, alongside `display_path` and `path_id`. Its top-level `trust_notice` and `untrusted_fields` explicitly warn agents against following source-derived text. Markdown shows the safe display label, never raw paths. Suspicious, non-ASCII, or long paths become opaque IDs. **Machine consumers must use `display_path` for any AI-facing prompt or UI and treat `path` as untrusted structured data.**
- **Narrow suppressions:** require `rule_id`, exact per-finding `fingerprint`, `path` or `path_id`, `reason`, `owner`, `ticket`, and ISO expiry no more than 90 days ahead. A second finding under the same path+rule is not waived. Expired suppressions remain visible but cannot suppress findings; CRITICAL issues cannot be suppressed. No repo-local suppression file is trusted.
- **Honest Semgrep stage coverage:** staging exclusions for `node_modules`, `.venv`, `venv`, `__pycache__`, and `.terraform` are counted. If they occur (or other stage limits are hit), full-mode Semgrep returns `partial_staging_exclusions_or_limits` and strict mode exits 3. The `.git` metadata directory is excluded by design. Tests and vendor source are still explicitly included. Set an external review plan for omitted code, rather than treating partial as clean.
- **Regression and compatibility evidence:** added tests for unsafe filenames, precise suppressions, stage omissions and Trivy CLI invocation/output parsing. Real Trivy execution is **not** claimed. Trivy's documented options are reviewed, but tool-specific behavior and offline database availability require a pinned-binary sandbox smoke test.
- **Governance matrix:** `docs/ENTERPRISE_GAP_MAP.md` distinguishes concrete scanner checks from process/framework requirements and planned improvements for Microsoft SDL, Google SAIF/SLSA and NIST SSDF. These frameworks do not certify an individual scanner or skill.

## v2.2 inherited protections

- Trusted Semgrep shadow-tree scanning including tests and vendor source, without accepting repo `.semgrepignore` or `nosemgrep` comments.
- Real SARIF source paths, independent opaque path IDs, SHA256-inventory verification, separate trusted CI source checkout, context-sensitive Supabase review, agent hook detection, bounded lockfile/minified scanning, Gitleaks JSON-report validation and metadata-only reports.

## Validation scope

The included regression suite tests mocked third-party invocation and parsing plus local fixtures. **The v2.3 build environment has not executed live Semgrep, Gitleaks or Trivy binaries.** An independent v2.2 assessment reported success using Semgrep 1.183.0 and Gitleaks 8.30.1, but these are not equivalent to executing and certifying the v2.3 build or Trivy. Use `scanner/compat_smoke.py` on SHA256-pinned binaries in a separately enforced isolated sandbox. A successful smoke test is not comprehensive vulnerability coverage.

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
