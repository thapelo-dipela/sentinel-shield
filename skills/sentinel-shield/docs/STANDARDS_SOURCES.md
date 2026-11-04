# Standards and sources | last verified 2026-11-04

The requirements below are **version pinned as reviewed**, not an assertion that they will remain latest. Refresh at least monthly and on official security release or protocol deprecation. Do not infer individual ASVS IDs from a previous major release.

| Source | Verified edition | Authoritative location |
|---|---|---|
| OWASP Top 10 | 2025 release | https://top10.owasp.org/2025/ |
| OWASP ASVS | 5.0.0, 30 May 2025 | https://asvs.owasp.org/ and https://github.com/OWASP/ASVS/tree/v5.0.0 |
| OWASP GenAI LLM Top 10 | 2026, released Sep 2026 | https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ |
| OWASP Top 10 for Agentic Applications | 2026 (released Dec 2025) | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ |
| MCP | 2026-07-28 stable published 28 Jul 2026 | https://blog.modelcontextprotocol.io/posts/2026-07-28/ |
| NIST Digital Identity | SP 800-63-4, published 2025 | https://pages.nist.gov/800-63-4/ |
| PostgreSQL/Supabase RLS | product docs checked 2026-11-02 | https://supabase.com/docs/guides/database/postgres/row-level-security |
| Supabase database functions | product docs checked 2026-11-02 | https://supabase.com/docs/guides/database/functions |
| POPIA | Act 4 of 2013, sections 19 and 22 | https://www.justice.gov.za/legislation/acts/2013-004.pdf |
| Trivy offline data | checked 2026-11-02 | https://trivy.dev/docs/dev/configuration/db/ |
| OSV-Scanner offline mode | checked 2026-11-02 | https://github.com/google/osv-scanner/blob/main/docs/offline-mode.md |
| NIST SSDF v1.1 | SP 800-218, **final** published 2022 | https://csrc.nist.gov/pubs/sp/800/218/final |
| NIST SSDF AI profile | SP 800-218A, **final** published July 2024 | https://csrc.nist.gov/pubs/sp/800/218/a/final |
| NIST SSDF v1.2 | SP 800-218 Rev. 1, **initial public draft** 17 Dec 2025, not final as of 2026-11-02 | https://csrc.nist.gov/pubs/sp/800/218/r1/ipd |
| Microsoft SDL | official lifecycle practices, not scanner certification | https://learn.microsoft.com/en-us/windows/security/threat-protection/msft-security-dev-lifecycle |
| Google SAIF | six framework elements and risk map, not certification | https://saif.google/secure-ai-framework |
| SLSA | supply-chain artifact/provenance framework, not implemented certification | https://slsa.dev/ |
| Trivy CLI config | empty ignore/secret config flags disable repo-supplied config defaults; compatibility must be tested against pinned binary | https://github.com/aquasecurity/trivy/blob/main/docs/guide/configuration/index.md |

## ASVS ID practice

Use full identifiers such as `v5.0.0-1.2.5` (OS command injection) and `v5.0.0-6.3.4` (consistent authentication across multiple pathways), confirmed from the official ASVS 5.0.0 source. Do not claim a match to every local rule without verifying the actual requirement text. The majority of automatic detector findings therefore state **review ASVS 5.0.0 mapping**.

## MCP refresh triggers

Recheck MCP spec when SDK versions change, OAuth issuer/audience behavior changes, stateless transport updates land, deprecation occurs, or the next stable spec ships. MCP 2026-07-28 changed protocol handshakes, authorization, routing headers and optional client metadata; applying obsolete 2025 assumptions without version checking is unsafe. Review the *deployed* MCP server's protocol version rather than blindly following the latest spec.

## POPIA note

Section 19 sets security safeguard obligations and risk control expectations; section 22 addresses security compromise notification to the Information Regulator and affected data subjects in defined circumstances. A source audit is not a legal determination. Escalate notifications, timelines, data-subject issues and regulator correspondence to authorized legal/privacy leadership.

## Public vulnerability intelligence and benchmark directories (verified 2026-11-04)

| Source | Purpose | Link |
|---|---|---|
| CISA Known Exploited Vulnerabilities | Confirmed in-the-wild exploitation catalog, not a complete vulnerability database | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| CISA KEV official data mirror | CISA-maintained machine-readable KEV JSON | https://github.com/cisagov/kev-data |
| CISA cybersecurity advisories | Official published advisories and threat notices, not continuous runtime detection | https://www.cisa.gov/cybersecurity-advisories/all.xml |
| OWASP Vulnerable Web Applications Directory | Curated intentionally vulnerable **learning and test** application directory, **not** currently exploited CVEs | https://vwad.owasp.org/ |
| OWASP VWAD JSON project source | VWAD static site source, machine-readable collection | https://github.com/owasp-vwad/owasp-vwad.github.io |

Feed ingestion is an optional network operation requiring `--allow-network`. An inability to obtain a feed is explicitly incomplete. Never interpret a VWAD listing as an active attack against a real application or automatically fetch and run training apps.
