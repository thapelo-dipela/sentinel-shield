# Supabase, PostgreSQL, Next.js and APIs

This is a **review checklist**, not a claim that automated regex detectors can prove authorization correctness.

## Supabase: minimum tenant isolation review

1. Inventory all tables in API-exposed schemas, roles with grants, default privileges, RLS enablement and whether policies cover `SELECT`, `INSERT`, `UPDATE`, `DELETE`. A policy does not revoke a broad SQL `GRANT`. Also verify anonymous and service-role paths.
2. Test each policy with real `anon`, owner, another user and different tenant roles. Assert both allowed and denied cases. Avoid client-controlled `user_id`; obtain identity from verified server-side auth context or `auth.uid()` in RLS.
3. Authorization cannot trust `auth.jwt()->'user_metadata'` / `raw_user_meta_data` because users can edit them. Use trusted `app_metadata`, with token refresh/revocation limitations understood.
4. View owners may bypass RLS. PostgreSQL 15+ views exposed to callers should be designed with `security_invoker = true`; earlier versions need restricted/unexposed views.
5. Prefer `SECURITY INVOKER`. For each `SECURITY DEFINER` function, fix `search_path` and qualify relations, audit owner and grants, avoid privileged `SECURITY DEFINER` in exposed schemas, check public PostgREST RPC reachability.
6. Check Supabase Storage bucket public access, object policies by owner/tenant, public link exposure, signed URL expiry, upload content limits. Check Realtime authorization and broadcasts separately.
7. Audit Edge Functions, including handlers with `verify_jwt = false`; determine how each caller is independently verified. Review signup policy, redirect URL allowlist, provider secrets, password reset and session lifecycle.
8. Consider `(select auth.uid())` in policy predicates where appropriate for planning efficiency, but never change security semantics for performance.
9. Inventory API-exposed schemas and database default grants after migrations. Test using `supabase test db` **only in an isolated, approved environment** with synthetic accounts and data.

## Illustrative SQL, require case-specific review

```sql
-- Scope access with both SQL grants and row-level policies.
alter table public.customer_records enable row level security;
revoke all on table public.customer_records from anon, authenticated;
grant select on table public.customer_records to authenticated;
create policy customer_record_read
on public.customer_records for select to authenticated
using ((select auth.uid()) = owner_id);

-- For PG15+ exposed views, check invoker rights and RLS.
create view public.own_records with (security_invoker = true)
as select id, owner_id from public.customer_records;
```

Granting any client rights to a view, its underlying objects, function or storage resource must be separately assessed.

## Next.js and frontend

- Server Actions and Route Handlers authenticate and authorize every operation. Middleware or proxy is not a substitute for server-side checks at each action and data access call.
- Review RSC boundary props and serialization for secrets or tenant records leaking to client components; never put service-role secrets in `NEXT_PUBLIC_`, `VITE_`, runtime HTML or exposed source maps.
- Validate CSRF and session behavior for mutation routes, including server actions; avoid unsafe redirects, cache mixing and signed URL reuse.
- Assess deployment configuration: production source maps, preview sites, CDN caching of private content and protected admin paths.
- Verify API object ownership and function-level permissions (BOLA/IDOR), rate limits and login/recovery abuse controls with authorized synthetic accounts.
