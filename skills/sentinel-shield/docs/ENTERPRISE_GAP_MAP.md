# Enterprise security framework gap map | reviewed 2026-11-04

**Not a certification.** Microsoft SDL, Google SAIF, SLSA and NIST SSDF address organizational practices, secure-development processes and/or provenance. Sentinel Shield is a source-audit skill with local heuristics and opt-in externally installed scanners. No organizational assessment, attestation, independent penetration test, independently benchmarked real-world SAST precision or recall, signed release or runtime control is delivered by this package.

| Control family | Evidence in v2.5 | Coverage verdict | Needed for an enterprise program |
|---|---|---|---|
| Microsoft SDL: verification | Offline source lint, auth and CI heuristics; optional Semgrep/Trivy/Gitleaks | Partial | Dedicated SAST/SCA, expert threat modeling, dynamic tests, coordinated response |
| Microsoft SDL: requirements, design and response | Guided checklists only | Process guidance | Security requirements and threat model owner, training, operations, SLOs, incidents |
| Google SAIF: AI risk and prompt injection | Untrusted-data operating contract, repo instruction patterns, MCP heuristics | Partial | Runtime agent permission gates, adversarial evals, risk mapping, monitoring, human escalation |
| Google SAIF: monitoring and response | No active runtime monitoring | Not implemented | Telemetry, abuse detection, safe automated response, incident exercise |
| SLSA: provenance and build integrity | SHA256 file inventory verified against separately trusted digest; unsigned source-only CycloneDX file BOM | Partial | A protected GitHub release workflow template is included; signature and attestation have not been issued. Real enterprise deployment needs signed artifacts, verified provenance, reproducible pipeline and independent trust anchor |
| NIST SSDF 1.1 / 800-218A | Secure-audit instructions, CI guidance, secret response playbook | Partial guidance | Organizational control owners, training, continuous verification, measurement, supply-chain response |
| Enterprise SAST and vulnerability prioritization | Regex hints, opt-in Semgrep, synthetic rule-signal benchmark; no broad dataflow evaluation | Partial | Taint rules, CodeQL/AST integration, reachability, false-positive/recall benchmarks |
| Dependency governance | Lockfile URL checks, opt-in Trivy, source-only SBOM and exact-CVE CISA KEV enrichment from approved local vulnerability reports | Partial | Dependency SBOM/SCA, OSV, EPSS, provenance, independently validated live feed and tool ingestion |
| Confidential data governance | Model-provider data handling warning, no snippets in reports | Partial | DPA, retention/access policies, legal review, privacy threat modeling |

## Release evidence and pending work

- Local regression suite: tests for explicit behaviors only, not validated precision/recall against real applications.
- External Semgrep, Gitleaks and Trivy binary integrations must be run separately against SHA256-pinned versions within a sandbox. No live Trivy compatibility validation has been executed for this release.
- Gitleaks scans working-tree data only; it does not scan history in the current integration.
- Trivy offline mode requires a trustworthy prepopulated vulnerability database; absent data must be marked incomplete.
- Semgrep staging omits dependency/environment directories such as `node_modules` and `.venv` and reports partial coverage when present. Additional trusted scan process required if in scope.
- Signed provenance, a full dependency SBOM, independent real-world vulnerability benchmark, independent security review, and agent red-team harness are **not included**. A source-file CycloneDX BOM and **synthetic** benchmark are included, along with CISA KEV/advisory and OWASP VWAD *metadata* ingestion.

## Priority projects to reach enterprise operational maturity

1. Provide independent signed release attestations, transparent publisher key handling and a full dependency SBOM for the skill's distribution.
2. Integrate high-precision SAST and secrets-in-history scanning; add OSV and EPSS, affected-version/reachability analysis, and secure lifecycle management around the included exact-CVE CISA KEV matcher.
3. Establish seeded vulnerable-app and Supabase regression corpora; publish detection recall, precision, false-positive ratio and stage-exclusion metrics per release.
4. Build an isolated, opt-in agent/MCP evaluation harness that tests prompt-injection resilience and least-privilege tool controls without live secrets.
5. Add externally operated runtime telemetry and incident response processes; map to selected ISO, SOC 2 and NIST 800-53 controls only with evidence and ownership.

References: https://csrc.nist.gov/projects/ssdf/publications ; https://learn.microsoft.com/en-us/windows/security/threat-protection/msft-security-dev-lifecycle ; https://saif.google/secure-ai-framework ; https://slsa.dev/ .
