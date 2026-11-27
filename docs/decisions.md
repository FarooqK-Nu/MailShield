# Decisions

Short records of changes to the plan in `context.md`, `architecture.md` and the roadmap.

## Accepted

| ID | Date | Decision |
|---|---|---|
| A-1 | 2026-11-26 | Express 5 replaces Fastify (team choice). |
| A-3 | 2026-11-26 | npm workspaces replace pnpm (team choice). |
| A-4 | 2026-11-26 | The DNS cache keeps every answer for a fixed 60 seconds instead of each record's TTL: Node does not report TTLs for TXT records. Timeouts and server failures are not cached. |
| A-5 | 2026-11-26 | New route `POST /api/v1/lab/demo/:id` lets the Analyze page run labelled demo fixtures against fixture DNS. Results are marked simulated; live analysis cannot reach fixture DNS. |
| A-6 | 2026-11-26 | New optional `DNS_SERVERS` setting. On some Windows machines Node finds no working system DNS server; the service warns at startup when DNS is unreachable. |
| A-7 | 2026-11-27 | Database migrations are hand-written SQL files in `apps/server/src/db/migrations/`, applied by a small runner; `drizzle-kit` is not used. It pulls in an esbuild version with a known advisory. A test checks that the SQL and the Drizzle schema have the same columns. SQLite driver: `better-sqlite3`. |
| A-8 | 2026-11-27 | The "trusted brand + DMARC fail" fixture is a local equivalent: uploads and fixtures never carry trusted receiver results (invariant 3). Acme publishes `p=reject` and only an unrelated domain's DKIM passes; R6 raises a caution and the verdict is "Identity unverified". Verdict row 3's trusted DMARC fail is covered by a unit test with a synthetic `trusted_receiver` record until Phase 4. |
| A-9 | 2026-11-27 | Playwright is set up in Phase 3 (Chromium only) for the preview network assertion. |
| A-10 | 2026-11-27 | Fixture and demo runs use `fixtures/registry/fictional-orgs.json` as their registry, never the local SQLite registry, so labels and demos stay deterministic. |
| A-11 | 2026-11-27 | Only `user_trusted` and `independently_verified` registry entries can corroborate an identity (verdict rows 4 and 5). `unverified` entries still drive the mismatch rules; `revoked` entries are ignored. |
| A-12 | 2026-11-27 | Phase 4 tests the extension's logic with Vitest (state reducer and rapid switching, Gmail client, base64url decoding, selection-hint matching, and a network test showing the OAuth token goes only to the Gmail API). The Playwright test that loads the unpacked extension with a mocked Gmail API (`architecture.md` §8) moves to Phase 7 hardening. |
| A-13 | 2026-11-27 | Receiver-trust tests use committed synthetic fixtures that copy Gmail's header order on reserved domains. A second test runs only when `private/*.eml` exists, so it is skipped in CI, and it checks real downloaded messages locally. Real mail is never committed. |
| A-14 | 2026-11-27 | The side panel's "Open full report" opens the dashboard and passes the result with `window.postMessage`. The dashboard accepts it only from the fixed extension origin and validates it with the `AnalysisResult` schema. The service stores nothing and gains no route. |
| A-15 | 2026-11-27 | Gmail receiver trust (`context.md` §7) is made precise and slightly stricter. A `Received` header counts as added inside Google when its `by` host is `google.com`, a subdomain of it, or a bare IP address (Gmail's internal hops record only an address). The topmost `Authentication-Results` with `authserv-id` `mx.google.com` is trusted only when every `Received` header above it is inside Google **and** at least one of them names a `google.com` host (the reception hop). Trusted results become one evidence record per reported method (`kind` = `spf`, `dkim`, `dmarc` or `arc`). |
| A-16 | 2026-11-27 | Phase 5 keeps the lab small. Lab keys are committed TEST-ONLY files (as in Phase 1) because Node cannot generate RSA keys deterministically. Runs are stateless, so there is no lab session object. "Before" in before/after mode is the DKIM and DMARC evidence of the same run, so no second engine run exists. The evidence trail animates the real `StageEvent` list on the client. The `rules` stage reports `not_evaluated` when every rule is switched off. See `phase-5-plan.md`. |
| A-2 | 2026-11-26 | Spec items no phase covered (Settings page, header paste, demo loading, side panel quick actions, lab avatar and custom message) are now assigned in the roadmap. |

## Approved proposals

Approved 2026-11-26 and copied into `context.md` and `architecture.md`.

| ID | Decision | Reason |
|---|---|---|
| P-1 | Allow `_dmarc.<single label>` in DNS name validation. `architecture.md` §3.4 rejects single-label names. | The RFC 9989 tree walk queries names such as `_dmarc.com`; rejecting them breaks discovery. |
| P-2 | Enforce package boundaries with ESLint's built-in `no-restricted-imports` instead of `import/no-restricted-paths` (§2). | No extra plugin or workspace resolver setup. It matches import names, so a deep relative path could slip through. |
| P-3 | Keep mailauth's lenient mode and map "body hash did not verify" to our `fail`. | Strict mode also changes unrelated behaviour. |
| P-4 | Use `allowPrivateDomains: true` for registrable-domain matching. | Otherwise two unrelated `*.github.io` users count as the same domain. |
| P-5 | Hold TypeScript at 6.0. | Lint tooling does not yet support 7. |
| P-6 | Add `fixtures/smime/` (test certificates and one signed message, no private keys). | Lets the S/MIME spike run on machines without regenerating keys. |
