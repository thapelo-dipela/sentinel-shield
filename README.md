# Sentinel Shield

Open-source, offline-first security auditing skill for owned and explicitly authorized repositories. Licensed under the [MIT License](LICENSE).

**Stable release: v2.5.0. Candidate in this checkout: v3.0.0-alpha.2.**

Alpha 2 adds bounded Python and JavaScript/TypeScript dataflow analysis. See the [integration verification and open review finding](docs/verification/v3.0.0-alpha.2.md) before using the candidate.

Sentinel Shield combines a Python scanner, regression tests, review guidance, and integration templates. It detects security leads; it does not guarantee that an application is secure. Live external scanner compatibility and end-to-end feed downloads were not validated in this release review.

Version 2.5 adds raw-feed cache integrity checks, KEV catalog size and drop checks, protected cache paths, commit-pinned mirror downloads, and source-bound Gitleaks fingerprints. It also includes optional dependency monitoring and release attestation templates. See [v2.5 verification and limitations](docs/RELEASE-v2.5.0.md).

## Get started

Clone this repository, then read the [complete skill documentation](skills/sentinel-shield/README.md) for installation, trust boundaries, profiles, and exit codes.

```bash
git clone https://github.com/thapelo-dipela/sentinel-shield.git
cd sentinel-shield
python -B -I skills/sentinel-shield/scanner/verify_integrity.py
python -B -I skills/sentinel-shield/scanner/sentinel.py --path /path/to/authorized/repo --hostile-repo --profile quick --strict
```

The integrity command checks file consistency, not publisher identity. For authenticated verification, supply `--expected-manifest-sha256` using a digest obtained independently from a trusted release record.

## Repository layout

- `skills/sentinel-shield/`: original v3.0.0-alpha.2 package, including its unchanged SHA256 inventory.
- `LICENSE`: MIT terms covering this project, including the skill package.
- `CONTRIBUTING.md`: development and version-update instructions.
- `SECURITY.md`: vulnerability reporting guidance.

Keep repository metadata outside the skill directory: its integrity verifier intentionally rejects extra files. See the [package changelog](skills/sentinel-shield/CHANGELOG.md) for version history.

## Run tests

The [v2.5.0 isolated-container verification report](docs/verification/v2.5.0-container.md) records **95 passing tests**, before/after integrity checks, the pinned container image, the full test log, and reproduction commands.

Python 3.11 or newer is recommended. The local regression suite uses the standard library and mocked external scanner calls.

```bash
python -B -m unittest discover -s skills/sentinel-shield/tests -v
```

## Releases

Download the supplied archive and verification hashes from the [v2.5.0 release](https://github.com/thapelo-dipela/sentinel-shield/releases/tag/v2.5.0). The archive is unsigned. The repository's MIT license covers the package; a copy is also provided with the release. The original v2.3.0 tag remains available.

Monitoring and attestation workflows under `skills/sentinel-shield/templates/` are examples, not enabled services. Adapt their paths to this repository layout, configure independently approved hashes, and protect the publisher environment before enabling them.
