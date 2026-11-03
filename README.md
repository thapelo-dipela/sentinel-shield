# Sentinel Shield

Open-source, offline-first security auditing skill for owned and explicitly authorized repositories. Licensed under the [MIT License](LICENSE).

**Current version: 2.3.0. Version 2.4 is upcoming and is not included yet.**

Sentinel Shield combines a Python scanner, regression tests, review guidance, and integration templates. It detects security leads; it does not guarantee that an application is secure. Live Semgrep, Gitleaks, and Trivy execution has not been validated for this v2.3 build.

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

- `skills/sentinel-shield/`: original v2.3.0 package, including its unchanged SHA256 inventory.
- `LICENSE`: MIT terms covering this project, including the skill package.
- `CONTRIBUTING.md`: development and version-update instructions.
- `SECURITY.md`: vulnerability reporting guidance.

Keep repository metadata outside the skill directory: its integrity verifier intentionally rejects extra files. See the [package changelog](skills/sentinel-shield/CHANGELOG.md) for version history.

## Run tests

Python 3.11 or newer is recommended. The local regression suite uses the standard library and mocked external scanner calls.

```bash
python -B -m unittest discover -s skills/sentinel-shield/tests -v
```

## Upcoming v2.4

The repository is ready to receive v2.4. Replace the package in `skills/sentinel-shield/` with the complete new version, verify its inventory, run the tests, update the version above, and create a new release. Do not label the current v2.3 code as v2.4.
