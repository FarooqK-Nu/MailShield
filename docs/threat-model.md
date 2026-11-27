# Threat model (draft, Phase 0)

Trust boundaries are drawn in `architecture.md` §1. Invariant numbers refer to `context.md` §8.

## Assets

| Asset | Where it lives |
|---|---|
| Gmail OAuth token (can read the whole mailbox) | Extension only |
| Raw message content | Memory, for the length of one analysis |
| Trusted identity registry and key history | Local SQLite |
| Pairing code and session token | Service, extension storage, dashboard session |
| Correctness of verdicts | Engine and rule configuration |
| Lab private keys and lab CA | Lab package, test only |

## Actors

1. An email sender who controls the message, its headers, attachments, links and their own DNS.
2. A web page in the user's browser that tries to reach the local service.
3. Another process or user on the same machine.
4. A DNS or network attacker between the service and its resolver.
5. The user making a mistaken trust decision.

## Threats and planned controls

"Status" is what exists in code today.

| Threat | Control | Status |
|---|---|---|
| DNS rebinding to the local service | Host allowlist; bind `127.0.0.1` | Done |
| Cross-origin web page calls the service | Origin allowlist and pairing token (CORS is not authentication) | Done |
| Token leaves the extension | Token used only inside the service worker; service client has no token parameter; network test over the whole live flow (`apps/extension/test/token-network.test.ts`) | Done |
| Forged `Authentication-Results` | Receiver results trusted only for live Gmail retrieval (3), and then only Google's topmost result with only Google hops above it (A-15); invariant and fixture tests | Done |
| Another page or extension drives the side panel's service worker | Requests accepted only from this extension's pages; hints only from `mail.google.com` content scripts; every request validated with Zod | Done |
| Gmail page markup (or message content) misleads the selection | Hint confirmed with the Gmail API before analysis; differences shown and must be acknowledged | Done |
| Late result shown on the wrong message | Request numbers and `messageRef` check in the panel reducer; rapid-switch tests | Done |
| A web page injects a fake report into the dashboard | `#/report` accepts only the extension origin and the window that opened it; result validated against the contract | Done |
| Message-controlled DNS names probe internal hosts | Validated auth names, TXT only, lookup budget | Done (SPF names later) |
| Slow or silent DNS stalls analysis | Per-query deadline, 10 s per analysis | Done |
| Oversized or deeply nested MIME | Size, depth, part and header limits; compressed request bodies refused (11) | Done |
| Active content or tracking pixels in preview | DOMPurify, link targets removed, sandboxed iframe with CSP `default-src 'none'`; Playwright network test (5) | Done |
| Content or secrets in logs | Redacting logger and log-capture test (6) | Done |
| Lookalike or confusable domain | Boundary matching, UTS #39 skeletons (4) | Phase 2 |
| Lab trust leaks into live analysis | Separate package, trust store and resolver; clients cannot claim lab or fixture sources (7) | Import rule and route test done; runtime check Phase 5 |
| Pairing code guessed | 8 digits, single use, replaced after 5 wrong tries, 10 tries per minute; tokens stored as hashes | Done |
| Real mail committed to git | `private/` ignored | Done |
| Vulnerable dependency | Lockfile, `npm audit` | Audit clean; add to CI in hardening |

## Accepted limitations

- A process running as the same user can read the database and likely the session token.
- DNS answers are not validated with DNSSEC; a resolver attacker can influence key lookups.
- A compromised but authentic account passes authentication and identity checks.
- A wrong registry entry produces a wrong conclusion; provenance is shown so it can be reviewed.
- Gmail receiver trust is positional, not cryptographic. If Gmail ever stored a message without adding its own `Authentication-Results`, a sender-written header with a Google hop above it would be trusted.
- The extension's content-script chunks are web-accessible on `mail.google.com` (a build-tool requirement), so Gmail pages can detect that MailShield is installed.
