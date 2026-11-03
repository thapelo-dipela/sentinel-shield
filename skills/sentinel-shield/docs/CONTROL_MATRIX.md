# Control matrix and evidence model

| Area | Automatic leads in v2 | Requires manual or other tooling |
|---|---|---|
| Code injection | eval, shell calls, SQL construction, unsafe HTML | taint reachability, tests, code paths, all languages |
| Auth/login | disabled verification, token storage, cookie settings, auth-bypass comments | session lifecycle, rate-limiting effectiveness, passkeys, per-object checks |
| Supabase | RLS disable, broad grants/policies, metadata claims, views, definer flags, Edge JWT | complete schema inventory, positive/negative RLS tests, storage/Realtime/RPC |
| Next.js | server-action cues, source maps, public env prefix | full RSC/SSR leak traces, auth at each handler, caching correctness |
| MCP | plaintext remote endpoints, pinned packages, literal creds, bypass/approval flags | server identity changes, poisoning, token audience, shadowing across multiple files |
| Repository self-defense | skipped symlink, file/line/byte limits, bidi and instruction-like text | binary malware analysis, custom Unicode evasions, external-tool parser attacks |
| CI/CD | SHA pin, PR trigger and untrusted expression markers | zizmor, permissions design, SLSA/provenance, production approvals |
| Dependencies | selected lifecycle-script hints, optional Trivy findings | OSV, EPSS, KEV, reachability, licensing, actual package provenance |
| Runtime/site | none live | WAF, DNS, registrar, CDN, TLS, hosting, backups, staging DAST |

Severity + confidence are **separate**. Prioritize a concrete exploit chain (for example, browser-exposed privileged key + exposed write API + missing RLS) over isolated noisy matches. Mark each chain's reachability, preconditions, impact, data classification and verification. Finding's `control` field contains an exact ASVS ID only where source-confirmed; otherwise assign after manual mapping to official ASVS 5.0.0.

For dependency vulnerabilities, include CVSS v4 if available, EPSS probability, KEV status, affected/available fixed version, reachability, network exposure and compensating controls. Do not fabricate missing scores.
