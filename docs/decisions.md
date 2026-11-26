# Decisions

Short records of changes to the plan in `context.md`, `architecture.md` and the roadmap.

## Accepted

| ID | Date | Decision |
|---|---|---|
| A-1 | 2026-11-26 | Express 5 replaces Fastify (team choice). |
| A-3 | 2026-11-26 | npm workspaces replace pnpm (team choice). |
| A-2 | 2026-11-26 | Spec items no phase covered (Settings page, header paste, demo loading, side panel quick actions, lab avatar and custom message) are now assigned in the roadmap. |

## Proposed — awaiting team approval

The code for P-1, P-2 and P-6 is already in place and can be reverted. Approved items should
be copied into `architecture.md`.

| ID | Proposal | Reason |
|---|---|---|
| P-1 | Allow `_dmarc.<single label>` in DNS name validation. `architecture.md` §3.4 rejects single-label names. | The RFC 9989 tree walk queries names such as `_dmarc.com`; rejecting them breaks discovery. |
| P-2 | Enforce package boundaries with ESLint's built-in `no-restricted-imports` instead of `import/no-restricted-paths` (§2). | No extra plugin or workspace resolver setup. It matches import names, so a deep relative path could slip through. |
| P-3 | Keep mailauth's lenient mode and map "body hash did not verify" to our `fail`. | Strict mode also changes unrelated behaviour. |
| P-4 | Use `allowPrivateDomains: true` for registrable-domain matching. | Otherwise two unrelated `*.github.io` users count as the same domain. |
| P-5 | Hold TypeScript at 6.0. | Lint tooling does not yet support 7. |
| P-6 | Add `fixtures/smime/` (test certificates and one signed message, no private keys). | Lets the S/MIME spike run on machines without regenerating keys. |
