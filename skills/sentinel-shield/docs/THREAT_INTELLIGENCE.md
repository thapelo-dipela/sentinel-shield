# CISA threat intelligence and OWASP VWAD integration (v2.5)

## Purpose and provenance

- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog . Source of known exploited CVEs and remediation prioritization. Official canonical JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json . The [CISA-maintained `cisagov/kev-data` mirror](https://github.com/cisagov/kev-data) is allowed as an exact fallback when cisa.gov blocks automated access. CISA documents that the mirror is updated shortly after the canonical feed.
- **CISA all-advisories RSS**: https://www.cisa.gov/cybersecurity-advisories/all.xml . Provides new advisory titles and referenced CVEs, including cyber campaigns when published. Does **not** provide comprehensive surveillance of all cyberattacks.
- **OWASP Vulnerable Web Applications Directory**: https://vwad.owasp.org/ . The earlier `owasp.org/projects/vulnerable-web-applications-directory` address now points to the OWASP VWAD project. Its official GitHub Pages source publishes the JSON collection at https://github.com/owasp-vwad/owasp-vwad.github.io/blob/main/data/collection.json . This is a **catalog of deliberately vulnerable training applications, not a feed of newly disclosed production vulnerabilities**.

Sources verified on 2026-11-04. These endpoints may change; inspect upstream project references before changing exact allowlists. This integration is neither an exploit scanner nor real-time incident detection.

## Operating modes

**Default offline.** The main `sentinel.py --hostile-repo` audit remains offline. `threat_intel.py review` is also offline. An operator must explicitly authorize network access for `refresh`, and only fixed HTTPS endpoints are requested. No arbitrary URLs, redirects, authenticated sessions, repo scripts or target systems are fetched. Do not reuse project credentials for feed collection.

From an independently digest-verified, extracted skill directory:

```sh
# Refresh publicly available feeds by operator authorization. Requires internet.
python3 -B -I scanner/threat_intel.py refresh \
  --allow-network --cache-dir /trusted/sentinel-feed-cache

# Review cached intelligence without network access.
python3 -B -I scanner/threat_intel.py review \
  --cache-dir /trusted/sentinel-feed-cache \
  --vuln-report /trusted/trivy-results.json \
  --technology Python --technology Docker
```

`--vuln-report` accepts Trivy `Results[].Vulnerabilities[].VulnerabilityID`, CycloneDX `vulnerabilities[].id`, or `findings[].cve`. CVEs must match CISA KEV **exactly**. Package names, technology names and version ranges are **not** inferred as vulnerable merely by their presence in KEV.

Optional trusted asset inventory:

```json
[
  {"vendor":"ExampleVendor", "product":"ExampleProduct"}
]
```

```sh
python3 -B -I scanner/threat_intel.py review \
  --cache-dir /trusted/sentinel-feed-cache --inventory /trusted/assets.json
```

A product-name overlap is a **review hint only**. Verify installed versions, affected configuration, exposure, exploit preconditions and vendor remediation separately. An empty match list is not proof of no vulnerabilities.

## Safety, refresh and coverage

- **Never run** OWASP VWAD apps automatically or probe online target sites. The script reads names and metadata only. Operators may select a deliberately vulnerable local training app to install in a separately isolated lab, after explicit authorization and review of its code and licensing.
- All feeds are untrusted data, even those from official domains. Titles and descriptions do not become agent instructions. Script stores only bounded parsed fields; RSS body text and OWASP notes are not retained.
- HTTP requests are size-limited, timeout-bound, TLS HTTPS-only, exact-URL allowlisted, and redirect-refusing. Network refresh does not transmit application code or confidential client data. A proxy and DNS environment can still affect transport integrity.
- Cache and reports must be **outside the audited repository** in protected operator-owned directories. v2.5 rejects symlinked cache ancestors and, on POSIX, requires the cache directory to be owned by the user with mode `0700`, files mode `0600`. Windows users must separately validate NTFS ACLs. Supply `--repo-root /absolute/path/to/repository` where appropriate, and never put the cache inside the project.
- The v2 cache stores the original bounded feed bytes as base64 in an owner-controlled JSON snapshot, verifies the bytes' SHA256 on every load, reparses the canonical data and rejects tampered or mismatching rows. Old v2.4 cache records **are not accepted**; run a new, authorised refresh. CISA KEV must contain at least **1,000 unique valid CVEs** and may not unexpectedly shrink more than **15%** compared with a valid previous snapshot. This numerical threshold is a defensive sanity floor, not a guarantee of authentic data.
- When canonical CISA KEV is unavailable, the fallback retrieves the SHA for CISA's GitHub KEV mirror and fetches the data at that immutable Git commit. The source SHA and commit are recorded for audit. The commit resolves from a mutable HEAD and the raw publisher feed itself is not signed. An attacker with the same operator credentials could forge a self-consistent cached snapshot; independent publisher authenticity would require separate verified signatures or digests.
- CISA feed TTL defaults to **3 days**, OWASP registry TTL to **30 days**. Missing, stale, failed or malformed data yields incomplete review status (`exit 3`), not false cleanliness. `refresh` also exits `3` when any source fails (e.g. a 403). No old cache is overwritten on failure.
- First successful refresh labels all records as new, since no older baseline exists. Later refreshes calculate deltas against the prior local snapshot. For true historical deltas across CI runs, persist a secured trusted cache outside the repository or store comparison state under separately approved governance.
- `review` writes JSON and Markdown metadata to a private newly created output directory. JSON contains untrusted source titles and product names; treat all fields as data. No vulnerabilities are exploited, binaries installed, shell commands run, or private network targets contacted.
- `--vuln-report` and `--inventory` are supplied data files and are not executed. `--cache-dir` and `--out` should be operator-controlled, never repo supplied. Keep network-refresh work isolated from private production credentials and client data.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Requested feeds current and no exact KEV CVE match in supplied report, or refresh succeeded |
| `1` | Offline review identified one or more exact CVE matches in the known-exploited CISA catalog |
| `2` | Invalid arguments, untrusted input format or unsafe path / local error |
| `3` | One or more sources missing/stale/failed; review is incomplete even if there are no exact matches |

## Release and operations

`templates/threat-intel-workflow.yml` gives an opt-in scheduled CI example. It uses the scanner only from the protected default branch and requires an independently stored SHA256 manifest digest. It does not include production secrets and never runs training applications. The v2.5 workflow obtains a real Trivy JSON vulnerability report from the checked-out project using a SHA256-verified pinned Trivy 0.76.1 tarball, then performs exact KEV comparison. It requires operator-configured trusted SHA256 variables and deployment in a protected repository, and is **not yet deployed or live-tested here**. A daily feed check is monitoring of *published intelligence*, not a live IDS, SIEM, EDR or vulnerability-reachability solution.

**Assurance:** Offline parsers, mocks, feed failure behavior, exact CVE matching and OWASP lab selection are exercised in unit tests. Due to restricted network access in the build environment, **the new downloader has not been independently exercised end-to-end against live CISA and OWASP endpoints here**. The official endpoints and data shapes were checked against published sources; real operational connectivity must be validated before relying on scheduled checks.

## Operational exit codes and input integrity

- `refresh`: `0` all feeds updated, `3` one or more feeds failed and existing verified snapshots were preserved, `2` invalid configuration/cache path.
- `review`: `1` at least one exact CISA KEV CVE in the supplied report, `3` missing/invalid/stale cache, `0` no exact KEV matches with all enabled public sources current, `2` bad options/file. Exit `0` without `--vuln-report` means only public feeds are current, **not** that your application has no exploitable dependencies.
- Cache state is not publisher authentication, and GitHub branch-to-commit pinning does not replace a signed feed. Record exact source URL, fetch timestamp and digests in operator-controlled evidence.
- Use staging or protected CI with synthetic data when validating alert behavior. Feed collection does not contact scanned targets, execute test apps or transmit private source code.
