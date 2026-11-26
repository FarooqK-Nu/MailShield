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
