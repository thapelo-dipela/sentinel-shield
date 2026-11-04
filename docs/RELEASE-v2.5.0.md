# Sentinel Shield v2.5.0

CISA integrity and supply-chain hardening — 4 November 2026.

This release imports the supplied v2.5.0 package unchanged. The repository and package remain MIT licensed. The downloadable original ZIP is unsigned; LICENSE is distributed alongside it.

## Verification performed

See the [isolated-container execution report and full test log](verification/v2.5.0-container.md) for a captured repeat run and reproduction instructions.

- ZIP SHA256 matches the publisher-supplied value below.
- Internal manifest SHA256 matches the independently supplied value below.
- Complete inventory verification passed before and after testing: 42 inventoried files plus the manifest, 43 files total.
- All 95 regression tests passed with no skips in Python 3.13 in an ephemeral Linux container. The container used a read-only package mount, no network, no ambient credentials, an unprivileged user, dropped capabilities, and bounded resources.
- Static review covered cache digest/reparse checks, catalog-size/drop checks, mirror commit pinning, Gitleaks source binding, and the optional workflow templates. This is a scoped review, not a comprehensive security certification.

## SHA256

Original `Sentinel-Shield-v2.5-CISA-Integrity-Hardening.zip`:

```text
ccbe788e33977b1b434539d18d31cd65478aa716095a506cc2f5be9d2be523f2
```

Internal `skills/sentinel-shield/SHA256SUMS`:

```text
6c35bab210f891174e4a938731b70fb3d4cf7b50608ed98386a23a8d03929b69
```

These hashes establish consistency with the supplied archive, not a cryptographic publisher signature. GitHub-generated source archives have different hashes.

## Deployment scope and limitations

Source and the supplied ZIP are published. Daily threat monitoring and signing are not activated. Their templates require repository-specific paths, approved checksums, protected configuration, and a successful authorized workflow run. The release-attestation template assumes the skill sits at the checkout root; this repository stores it under `skills/sentinel-shield/`.

Live Trivy/Semgrep/Gitleaks compatibility, feed availability, and real-world precision/recall were not independently tested. Cache checks cannot authenticate a publisher against an attacker who controls the operator account. Windows cache ACLs require operator review. Git-history secret scanning, advanced taint analysis, reachability, and runtime detection remain outside the stated coverage.

The supplied report parser accepts unrecognized JSON objects as zero CVEs and caps processed rows without reporting truncation. Use complete, validated vulnerability reports; a current feed cache alone does not establish complete project coverage. The scheduled template validates the top-level Trivy Results array but does not independently establish scan completeness. This remains follow-up hardening work.
