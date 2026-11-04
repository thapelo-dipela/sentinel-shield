# Optional cryptographically attested release workflow

**Status for v2.5: a template is included, but no signed release or publisher-authenticated artifact was produced in this environment.** An internal SHA256SUMS manifest and an independent checksum printed by an assistant are integrity indicators, not a signature or attestation.

`templates/release-attestation-workflow.yml` describes an owner-controlled GitHub Actions process. It uses SHA-pinned checkout and attestation actions, requires a protected, independently configured `SENTINEL_MANIFEST_SHA256`, verifies the entire file inventory before executing tests, and builds a deterministic ZIP from tracked files. It then issues two Sigstore-backed GitHub attestations, one build provenance attestation and one using the existing *source-file-only* CycloneDX SBOM.

Before enabling:

1. Store the skill in an audited, owner-controlled release repository with only the manifest-listed files. Review branch protection, release-tag permissions, action commits and workflow-approval rules. Restrict write access and enforce human review.
2. Copy the release template to `.github/workflows/` and configure `SENTINEL_MANIFEST_SHA256` from a separate protected release record or organizational secret/variable that untrusted PRs cannot modify. The Git checkout `.git` directory is excluded by staging tracked files in a clean temporary directory prior to inventory verification.
3. Ensure the GitHub plan supports artifact attestations. As of the official documentation consulted on 2026-11-04, public repositories generally support attestations; private/internal repos may require GitHub Enterprise Cloud. Verify current requirements.
4. Trigger only a protected release tag after independent review. Publish the resulting ZIP and attestation bundle or attestation link in an independently controlled release announcement.
5. Verify the artifact with the GitHub CLI using the *expected publisher identity and repository*: `gh attestation verify path/to/Sentinel-Shield-verified.zip --repo OWNER/REPO`. Independently compare SHA256. Review signing identity, workflow, commit, predicate and SBOM scope before installation.

The template has **not** been executed with a GitHub OIDC identity. It does not assert SLSA level 3, certificate validity, comprehensive dependency inventory, or signer authenticity until the issued attestation is independently verified. The source-file BOM does not enumerate the external Gitleaks, Semgrep or Trivy binaries. Integrations must retain their own trusted SHA256 manifests.

Official reference: https://github.com/actions/attest and https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
