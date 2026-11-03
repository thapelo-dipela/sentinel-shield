# Safe remediation patterns

- **SQL**: bind parameters using the application's driver; never concatenate request values or identifiers. For identifiers, use a tight mapping of permitted column names instead of raw interpolation.
- **HTML**: render untrusted strings as text. For required rich HTML, sanitize with a maintained parser and follow context-appropriate output encoding and CSP.
- **Shell**: prefer APIs over subprocesses. If required, use a fixed executable plus an argument array, validate allowed values and never pass untrusted strings through shell expansion.
- **Auth**: validate session/token on the server at every protected action and object boundary. Do not rely on route hiding, client state, middleware-only guards or a model's classification.
- **RLS**: pair narrow SQL grants with owner/tenant policies and independent negative tests. Review views, definer functions, storage, functions and Realtime separately.
- **Next.js**: keep admin secrets server-only; secrets must never appear in `NEXT_PUBLIC_` or `VITE_` variables. Avoid props containing private server records.
- **MCP**: least capability per approved tool, issuer/audience bound auth, namespaced tool identities, schema validation, per-action approvals and egress filtering.
- **Supply chain**: pin reviewed packages/actions by immutable identifier and verify provenance; use isolated dependency scans rather than running untrusted project scripts.
- **Secrets response**: revoke exposed token, rotate after replacement prepared, inspect provider logs and affected clients, remove from current builds and approved Git-history remediation, monitor and consider notification. Do not paste secrets into reports.
