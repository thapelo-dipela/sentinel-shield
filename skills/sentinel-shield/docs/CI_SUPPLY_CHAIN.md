# CI/CD, dependencies, container and site integrity

## GitHub Actions

- Pin third-party `uses:` references to full reviewed commit SHAs. Restrict `GITHUB_TOKEN` via top-level and job `permissions:`, use protected environments for deployments and review `secrets` access.
- Audit `pull_request_target` against untrusted checkout and secret contexts; avoid untrusted `${{ github.event.* }}` interpolated directly into shell commands. Scope PR and fork protections.
- Run `zizmor` and review its findings in a sandbox. Do not load repository-supplied scanner configuration without inspection. Validate PR-provenance for build artifacts and promotion to production.

## Dependencies

- Use a committed lockfile, integrity checks and approved registries. Investigate unexpected new names (including hallucinated AI-suggested packages), squatting, lifecycle install hooks, unexplained scripts and dependencies introducing new network endpoints.
- Combine Trivy and OSV-Scanner with SBOM generation (CycloneDX supported tooling) and dependency reachability checks before severity decisions. Cross-reference CISA KEV (known exploited), EPSS probability and CVSS v4 vector where provided. Never automatically score vulnerability exploitability solely by a regex or CVSS number.
- Validate provenance/attestations for package releases when supplied; evaluate npm provenance or signed artifact evidence, not just publisher names.

## Infrastructure and domains

- Use Checkov/Trivy IaC analysis for Terraform, Kubernetes and cloud policies. Review non-root container, read-only filesystem, disabled privileged mode, bounded resources, no secret-in-image layers, socket and metadata service isolation.
- Protect DNS registrar, domain, hosting, CDN, CI and deployment tokens with MFA and minimum permissions. Review stale DNS CNAMEs, unclaimed hosting aliases, TLS renewals, CSP/HSTS/headers, backups and audit logs.
- WAF/rate limiting, monitoring and alerts complement code checks and cannot be installed by this skill automatically. Validate service ownership before any domain tests or network probing.

## Optional staging DAST (separate explicit permission)

OWASP ZAP Baseline uses crawling and passive scanning, but still makes HTTP requests. Run only on *authorized staging*, with test data, documented target allowlist, traffic limits, approved timing and coordination with service owners. Do not assume static audit permission includes DAST permission. Do not run ZAP in default or hostile modes.
