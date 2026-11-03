# Application, authentication and data protection

## Code analysis

For each externally reachable input, establish trust boundary, parse/validate, authorization, output encoding, sink and visible data classes. Review SQL and NoSQL injection, command execution, template injection, path traversal, XSS, SSRF, webhook destination controls, file handling, redirects and insecure deserialization. Automated regex matches are leads only: use maintained semantic or taint analysis tools, tests and code review to prove or disprove flow.

## Identity and login

- Consider passkeys/FIDO2 and phishing-resistant MFA for privileged accounts. Support secure enrollment, recovery, reauthentication and authenticator revocation.
- Use maintained libraries for login and OAuth/OIDC. Validate issuer, audience, token expiry, allowed algorithm, state, PKCE and exact redirect URI as appropriate.
- Passwords: long passphrases, compromised-password checks, no unjustified arbitrary rotations, Argon2id or equivalent vetted memory-hard hashing. Never log plaintext passwords or verification tokens.
- Cookies: Secure, HttpOnly, suitable SameSite, sensible path/domain and CSRF protection. Rotate sessions on privilege change; expire/replace refresh tokens and revoke on compromised sessions.
- Restrict sign-in, MFA and recovery endpoints with layered account/IP/device rate limits and replay resistance; prevent account enumeration.
- Use consistent access checks across REST, GraphQL, server actions, edge functions, workers, WebSockets and scheduled jobs. Test horizontal and vertical access with synthetic identities.

## Customer data

Inventory PII and special categories, collect only what is required, set explicit retention, minimize logs, segregate environments and authorize exports. Use TLS, secret managers, encryption keys managed separately, least-privilege backups, auditable access and deletion verification. A static audit cannot verify deployed encryption, backups, logging or breach response.
