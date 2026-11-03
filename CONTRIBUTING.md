# Contributing

Issues and pull requests are welcome. Describe the problem, the proposed behavior, and how you validated the change. Use synthetic examples; do not include credentials or private repository content.

Run `python -B -m unittest discover -s skills/sentinel-shield/tests -v` before submitting scanner changes. Add focused regression coverage for behavior changes. Do not claim live external-tool compatibility based only on mocked tests.

The skill has a strict SHA256 inventory. When changing package files, regenerate `skills/sentinel-shield/SHA256SUMS` with SHA256 hashes of all package files except the manifest itself, using relative POSIX paths and the format `HASH  path`. Exclude caches and generated outputs. Verify with `python -B -I skills/sentinel-shield/scanner/verify_integrity.py`.

For v2.4, import the complete new package, update the package changelog and repository README, validate tests and integrity, then tag the actual version. Include the root MIT license in distributed archives and generate the archive inventory after assembling its contents. Publish the archive hash and manifest hash in the release notes. Keep the original v2.3 tag unchanged.

Contributions are provided under this repository's MIT license.
