# Isolated external scanners and version hygiene

The scanner defaults to zero third-party processes. A source tree can contain malicious *scanner* config and hidden files; therefore **full scans are disallowed in hostile-repo mode**. Only enable external scanners after quarantining and reviewing the repo in an ephemeral, non-root sandbox, with *read-only input*, no ambient credentials, no access to Docker socket, network egress blocked and resource limits.

## Verify binary installation

Download tool releases through trusted vendor channels in a separate controlled setup stage. Pin their exact versions and verify publisher-supplied hashes/signatures as available. Capture actual local binary SHA256 and record a trusted manifest **outside** the scanned repo:

```json
{
  "semgrep": {"path":"/trusted/bin/semgrep","sha256":"<64 hex chars from reviewed release>"},
  "trivy": {"path":"/trusted/bin/trivy","sha256":"<64 hex chars from reviewed release>"},
  "gitleaks": {"path":"/trusted/bin/gitleaks","sha256":"<64 hex chars from reviewed release>"}
}
```

The JSON shown is a template, **not valid production pin data**. Do not copy fake hashes. Actual binary checksum matching is enforced in the Python orchestrator, and missing/checksum-mismatched tools are reported as incomplete. In full mode, only tool configs bundled in the skill's `rules/` directory are passed. Treat skill distributions themselves as supply-chain artifacts and verify the ZIP hash from a trusted delivery channel before use.

## Offline and telemetry

- Semgrep is invoked with a **bundled** rule file and `--metrics=off --disable-version-check --disable-nosem --no-git-ignore` inside a bounded, temporary **trusted shadow tree**. This tree preserves supported source files from tests/ and vendor/ but excludes repository-controlled ignore/config files, installs an empty `.semgrepignore`, and uses the shadow as the working directory. The problematic `--x-semgrepignore-filename` override is removed. Paths are remapped into actual repository-relative paths. If staging hits limits, the full scan is marked incomplete. No `--config auto` or registry rules. Rule coverage is deliberately narrower than public rulepacks.
- Trivy is invoked with `--ignorefile= --secret-config=` to block implicit repo-controlled exclusions and `--offline-scan`, `--skip-db-update`, `--skip-java-db-update`, `--skip-check-update`, and trusted config. A fresh, separately provisioned, versioned mirrored vulnerability DB is required for good coverage; an absent DB is a scan failure, not an empty result.
- Gitleaks is invoked with bundled config, `--redact=100`, `--ignore-gitleaks-allow`, and `--report-path -`; only current files are scanned, not Git history. Its remaining ignore-file behavior requires a separate compatibility assessment. Raw console findings are discarded; parsed output retains only metadata. Protect temporary scan artifacts as sensitive anyway.
- OSV-Scanner supports `--offline` when local DB is already provisioned. Use separate review to integrate its JSON with dependency inventory.
- zizmor, Checkov and SBOM tools are **recommended but not automatically executed**. Running third-party tools adds risk and requires sandboxing.

**Limitations:** The manifest checks SHA256 digests but does not establish publisher identity by itself. The Python process cannot prove it is actually in a sandbox or that network egress is blocked. `--sandbox-confirmed` is an operator assertion. External tools can parse hostile source, even when telemetry is disabled, so maintain container isolation and file limits independently.

## Real binary compatibility gate (opt-in)

With a separately provisioned ephemeral sandbox, blocked egress, no ambient credentials and SHA256-reviewed binaries, run `python3 -B -I scanner/compat_smoke.py --tool-manifest /trusted/tools.lock.json --expected-manifest-sha256 DIGEST_FROM_TRUSTED_RELEASE --sandbox-confirmed`. The smoke test uses only synthetic files and checks actual tool output and selected Semgrep findings. An absent tool or stale Trivy DB must remain visibly incomplete. This check is **not** performed by the included offline unit tests and has not been run for this release against live binaries.
