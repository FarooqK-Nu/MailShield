# MailShield — Working Context (Node.js Edition)

> **Status:** Working project contract for developers and AI coding agents.
> **Supersedes for implementation:** the stack and structure sections of `MailShield_context.md`.
> **Unchanged:** the academic goals, security model, ethics and acceptance criteria in `MailShield_context.md` still apply. Where this file and the original disagree on *how* to build, this file wins; on *what* must be true about security, the stricter of the two wins.
> Companion documents: [`architecture.md`](architecture.md) (how it fits together) and [`masterroadmap_plan.md`](masterroadmap_plan.md) (phased build plan).

---

## 1. One-paragraph summary

MailShield is a local-first tool that tells a Gmail user whether an email really comes from the person or organization it *claims* to be from. It verifies DKIM signatures cryptographically from the original message bytes, compares the claimed identity (display name, domain, personal signing key) against a **user-controlled trusted identity registry**, runs **deterministic, explainable rules** (no ML/LLM), and shows a plain-language verdict with evidence. It ships as a **Chrome MV3 side panel for Gmail**, a **React dashboard**, an **offline security lab**, and a **local Node.js verification service** bound to loopback.

The core idea to defend in the viva:

> *“Authenticated” is not the same as “who it claims to be.”* An attacker's own domain can pass SPF/DKIM/DMARC while its display name says “Microsoft”. MailShield checks the binding between the claimed identity and the authenticated identity, and explains the evidence.

---

## 2. Key decisions (refinements over the original spec)

| # | Decision | Why |
|---|---|---|
| D1 | **TypeScript everywhere** (Node.js ≥ 24 LTS backend, React frontend, MV3 extension). | One language for a 2-person team; shared types; no Python/JS context switching. |
| D2 | **npm workspaces monorepo** with a pure `packages/engine` library separate from the HTTP server. | The engine runs in tests, the evaluation CLI, the lab and the server with no HTTP involved. Pure functions + injected dependencies (DNS, registry, clock) give deterministic results. |
| D3 | **Zod schemas in `packages/contracts`** are the single source of truth for API payloads. | Backend validates with them, frontend/extension infer types from them, so the two cannot drift apart. |
| D4 | **`mailauth`** for DKIM verify/sign, DMARC, ARC and fixture-only SPF. | Maintained, standards-focused, accepts a **custom DNS resolver** (essential for fixture DNS and the offline lab). Replaces `dkimpy`. |
| D5 | **Express 5** instead of FastAPI. | Team preference and familiarity. Validation (Zod middleware), auth/origin guards and limits are ordinary middleware. |
| D6 | **SQLite via `better-sqlite3` + Drizzle ORM** (with migrations). | Zero-ops local DB, typed queries, parameterized by default. |
| D7 | **S/MIME via `pkijs`** (CMS SignedData verification), with the **OpenSSL CLI** as a cross-check in tests. | `node-forge` cannot fully verify PKCS#7 signatures; pkijs can. Never hand-roll crypto. |
| D8 | **Pipeline emits stage events.** | One mechanism drives the dashboard's “authentication pipeline” view, the lab animation and test assertions. Animations replay real events instead of scripted ones. |
| D9 | **Tiered risk levels, no numeric score in v1.** | A 0–100 number invites people to read it as a probability. Tiers + findings are easier to defend. A numeric heuristic indicator is optional (P2). |
| D10 | **Local service auth = pairing token + Origin allowlist + Host check.** | CORS alone is not authentication; the Host check blocks DNS-rebinding attacks against `127.0.0.1`. |
| D11 | **Uploaded `.eml` files never yield `trusted_receiver` evidence.** Only live Gmail API retrieval can, through a documented extraction strategy (see §7). | Anyone can type an `Authentication-Results` header into a file. |

---

## 3. Technology stack (Node.js)

> Versions are pinned in `package-lock.json`. **Phase 0 must confirm** each library supports the feature listed before code depends on it (see roadmap).

| Concern | Choice | Notes |
|---|---|---|
| Runtime | Node.js 24 LTS (or the current LTS) | `node:crypto`, `node:dns/promises`, `X509Certificate`. |
| Language/build | TypeScript 6.0 (strict; held below 7 until lint tooling supports it), `tsx` for dev, `tsup` for building packages | ESM throughout. |
| Monorepo | npm workspaces | `apps/*`, `packages/*`. |
| HTTP server | Express 5 + `cors`, `express-rate-limit`, `pino-http`, own Zod validation middleware | Binds `127.0.0.1` only. `express.raw()` receives message bytes. |
| Validation/contracts | Zod | Shared by server, web, extension. |
| MIME parsing | `postal-mime` (structured parse) + our own raw header reader over the original `Buffer` | Raw bytes stay untouched for signature checks; the parsed view is only for display and rules. |
| Email auth | `mailauth` | `dkimVerify`, `dmarc`, `arc`, `spf` (fixtures only), `dkimSign` (lab). |
| DNS | `node:dns/promises` `Resolver` with timeouts, wrapped in our resolver interface; fixture resolver for lab/tests | LRU cache (`lru-cache`) with a fixed 60 s lifetime (A-4); optional `DNS_SERVERS` (A-6). |
| Key fingerprints | `crypto.createPublicKey(pem).export({ type: 'spki', format: 'der' })` → SHA-256 hex | Labelled as a *key fingerprint*. |
| X.509 / CMS | `pkijs` + `asn1js`, `@peculiar/x509` (lab cert generation), `node:crypto` X509Certificate | Lab CA lives only in the lab trust store. |
| OpenPGP (stretch) | `openpgp` (OpenPGP.js) | Standard v4/v6 fingerprints. |
| Domains | `tldts` (Public Suffix List), `node:url` `domainToASCII`/`domainToUnicode`, `tr46` for UTS #46 | Registrable-domain boundaries; never substring matching. |
| Confusables | Unicode `confusables.txt` (UTS #39) loaded as versioned data → our skeleton function | Data file committed under `packages/engine/data/` with its Unicode version recorded. |
| Similarity | `fastest-levenshtein` + small Damerau (OSA) implementation, token comparison | Bounded thresholds in the rule config. |
| HTML (links only) | `htmlparser2` (parse, never render) | Extract `href` vs visible text. Do not execute anything or fetch anything. |
| Preview sanitizing | `DOMPurify` in the browser, remote resources stripped | Render inside a sandboxed iframe with a strict CSP. |
| Database | SQLite, `better-sqlite3`, Drizzle ORM + drizzle-kit migrations | |
| Web UI | React 19, Vite, Tailwind CSS, Radix UI primitives, Lucide icons, TanStack Query, React Router | Light/dark, accessible focus, reduced motion. |
| Charts | Recharts (evaluation page only, real data) | |
| Extension | Chrome MV3, Side Panel API, `chrome.identity`, Vite + `@crxjs/vite-plugin` | Fixed `key` in manifest → stable extension ID for OAuth. |
| Tests | Vitest (unit/integration everywhere), Playwright (E2E), OpenSSL CLI cross-checks | |
| Lint/format | ESLint + Prettier, `tsc --noEmit` in CI | |
| Packaging | Optional Docker Compose for the server; plain `npm run dev` is the main path | |

---

## 4. Security model — what each mechanism proves

| Mechanism | Establishes | Does **not** establish |
|---|---|---|
| SHA-256 body digest | These bytes equal the reference bytes | Who made them (anyone can recompute it) |
| DKIM | A key published under `d=` signed the covered headers and body | That the display name is honest; that a *person* wrote it |
| SPF | The sending IP was authorized for the envelope domain | Anything about the visible `From:`; it is not a signature |
| DMARC | A passing SPF/DKIM identity **aligns** with the visible `From:` domain | That the display name or content is legitimate |
| S/MIME | A certificate's key signed the covered MIME part | Identity, unless the cert chains to a trust anchor *and* binds to the expected address/person |
| Registry match | The user (or reviewed evidence) says this domain/key belongs to this identity | Objective real-world truth; it is a trust decision with recorded provenance |

**Fingerprint rule:** `key_fingerprint = hex(SHA-256(DER SubjectPublicKeyInfo))`. Never hash a name or email address and call that identity verification.

---

## 5. Evidence and result vocabulary (must be used consistently)

**Evidence source:** `local_crypto` · `trusted_receiver` · `untrusted_header` · `registry` · `heuristic` · `lab`

**Evidence status:** `pass` · `fail` · `missing` · `unknown` · `temporary_error` · `unsupported` · `untrusted` · `not_evaluated`
(`not_evaluated` = check disabled by the user or lab toggle. It must never be displayed as a pass.)

**Registry trust state:** `unverified` · `user_trusted` · `independently_verified` · `revoked`

**Identity status** (who it is) is kept separate from **risk level** (how concerning it is):

| `identity_status` | Meaning |
|---|---|
| `corroborated_domain` | Claimed org matches registry **and** a locally verified DKIM signature aligns with an approved domain |
| `corroborated_personal` | A valid personal signature with a key enrolled for the claimed person (implies nothing about outer unsigned headers) |
| `mismatch` | Claimed identity matches a registry entry but the evidence points elsewhere |
| `unverified` | No registry entry matches, or the evidence is insufficient |
| `ambiguous` | Malformed/multiple `From`, conflicting claims |

| `risk_level` | Typical trigger |
|---|---|
| `high` | Strong mismatch (R1/R2 mismatch, strong lookalike of a registry identity) |
| `caution` | Contextual anomaly (Reply-To divergence, link mismatch, invalid signature) |
| `unknown` | Missing evidence, DNS failure, header-only input |
| `low` | Corroborated match and no concerning findings. **Never displayed as “safe”.** |

**Verdict labels (UI):** `Possible impersonation` › `Authentication concern` › `Identity unverified` › `No concerning identity mismatch found` (highest applicable wins; decision table in `architecture.md` §6).

---

## 6. Deterministic rules (R1–R9)

Each rule is a pure function `(context) => Finding[]` with a stable `rule_id`, versioned config, and at least one positive and one negative regression fixture.

| Rule | Fires when | Default severity |
|---|---|---|
| R1 display-name mismatch | Display name / alias matches a registry org, but neither the From domain nor an aligned verified DKIM domain is in its approved set. **Not suppressed by DKIM/DMARC pass.** | high |
| R2 personal mismatch | Known person alias with an unexpected address, or a signature from a key that is not enrolled for them. Missing signature gives “personal identity unverified”, not fraud. | high / info |
| R3 lookalike domain | Confusable skeleton equal, mixed script, or edit distance ≤ threshold vs a registry domain (registrable part compared). Shows the exact differing characters and code points. | high / caution |
| R4 misleading structure | Brand token appears in a subdomain or a non-registrable label (e.g. `brand.example.net`). Shows the actual registrable domain. | caution |
| R5 Reply-To discrepancy | Reply-To registrable domain differs from From and is not an approved service provider. | caution (contextual) |
| R6 authentication problem | Trusted DMARC fail, invalid supported DKIM for the From domain, weak/expired key, malformed From. | caution / high |
| R7 link mismatch | Visible URL text names a different host than the `href`, or `href` points to a confusable host. No fetching. | caution |
| R8 first contact / key change | Sender or signing key not previously observed. | info |
| R9 coverage/tampering | Valid signature with `l=` partial body or important unsigned headers → limitation; body-hash/signature fail → warning (transport changes remain a possible explanation). | info / caution |

`Finding` = `{ rule_id, rule_version, severity, title, observed, expected, evidence_refs[], explanation, recommendation }`. Every finding links to the evidence records that caused it.

---

## 7. Gmail integration rules

- Extension OAuth client type: **Chrome extension**, scope **`https://www.googleapis.com/auth/gmail.readonly` only**. Consent screen in *Testing* mode with listed test users. `gmail.readonly` is a restricted scope; public release would need Google verification (out of scope, documented).
- The token stays inside the extension (`chrome.identity.getAuthToken`). **It is never sent to the local server.** The extension fetches `users.messages.get?format=raw`, base64url-decodes it and POSTs the bytes to the local service.
- The UI tells users the truth: a read-only token *can* read all mail. MailShield *chooses* to fetch only the message the user explicitly asks to analyze.
- Selection: the content script reads the opened message's identifier from the Gmail DOM (unstable, treat as a hint only), then the side panel confirms it with `format=metadata` (From/Subject/Date shown to the user) before the user clicks **Analyze**. If the mapping fails, it falls back to a consented message picker or **Show original → Download `.eml` → import**.
- **Receiver-result trust strategy (live Gmail only):** accept the **topmost** `Authentication-Results` header whose `authserv-id` is Google's, *only if* it appears above every `Received` header added outside Google's boundary. Label it `trusted_receiver` with a stated assumption. Anything else is `untrusted_header`. This strategy is a documented heuristic with regression tests; if a message doesn't fit it, the result is `unknown`. Decision A-15 defines "added inside Google" (a `by` host under `google.com`, or a bare IP address) and also requires a `google.com` reception hop above the header.
- Message switch clears the previous result immediately, and each analysis carries the `messageId` it belongs to. A late response for an old message is discarded.

---

## 8. Hard invariants (never violate; each has a regression test)

1. Signatures are verified **only from original bytes**, never from rendered HTML, DOM text or a re-serialized message.
2. A disabled, pending or failed check is never shown as passed.
3. Uploaded/pasted `Authentication-Results` are **never** trusted receiver proof.
4. Domain trust uses **registrable-domain boundary matching**, never substrings.
5. No network request to any message-supplied destination: no link fetching, no remote images, no shortener expansion. DNS queries only for validated `_domainkey` / `_dmarc` / SPF names.
6. Raw messages, bodies, OAuth tokens, private keys and attachments are **never logged or persisted** (unless the user explicitly opts in to redacted retention).
7. Lab keys, lab CA and fixture DNS are **never reachable from live analysis**. The lab trust store is a separate object, and the live resolver cannot be swapped for the fixture one.
8. No private key is accepted into the production registry.
9. Every displayed verdict links to the findings and evidence behind it.
10. No “safe” label, no fake Gmail/Google badge, no fraud accusation based on heuristics alone.
11. Input limits: 10 MiB message, MIME depth ≤ 20, parts ≤ 500, header count/size bounds, decompression bounded. Attachments are never opened.

---

## 9. Scope priorities

- **P0 (must ship):** `.eml` analyzer + DKIM + rule engine; trusted registry; dashboard + inspector; security lab (DKIM-based); Gmail extension with at least one real message (or a documented blocker plus the Show-original fallback).
- **P1:** S/MIME personal signatures + lab CA (Alice/Bob/Eve); key history & rotation; redacted report export; 40+ fixture evaluation with dev/held-out split.
- **P2 (only if P0/P1 are stable):** OpenPGP, ARC validation UI, numeric heuristic indicator, Workspace add-on, opt-in batch scan.

---

## 10. Repository layout (summary; details in `architecture.md`)

```text
mailshield/
  context.md  architecture.md  masterroadmap_plan.md  README.md
  apps/server/        Express API, security middleware, DB, routes
  apps/web/           React dashboard + Security Lab
  apps/extension/     MV3 side panel, content script, OAuth
  packages/contracts/ Zod schemas + inferred TS types
  packages/engine/    Pure analysis engine (parse, dns, auth, identity, rules, pipeline)
  packages/lab/       Lab keys, signing, fixture DNS, scenarios (never imported by live paths)
  packages/ui/        Shared React components + status language
  fixtures/           Synthetic .eml, DNS JSON, labels, test-only keys
  tools/              Fixture generator, evaluation CLI
  docs/               Threat model, API docs, test report, demo script
```

---

## 11. Working agreements

- Build the **thin vertical slice first**: `.eml` → real DKIM evidence → one rule → result card. Then widen.
- Every security claim gets a regression test with a real signed fixture. A fixture without a label file doesn't count.
- No fabricated data: no fake metrics, keys, official contacts or “pass” placeholders. Unimplemented features show “not implemented”.
- Mock/fixture providers only in `packages/lab` and tests, always visibly labelled `lab`.
- Conventional commits; PRs reviewed by the other member; `npm run check` (typecheck, lint, tests) green before merge.
- Document any change to these decisions in `docs/decisions.md` (short ADR entries).

---

## 12. Glossary (for the UI and the viva)

- **Display name**: the human-readable part of `From:` (“Microsoft Support”). Free text, anyone can set it.
- **Registrable domain**: the part of a domain someone actually registers (`example.co.uk`), found with the Public Suffix List.
- **Alignment**: the authenticated domain (DKIM `d=` / SPF) matches the visible From domain (relaxed: same registrable domain; strict: exact).
- **Selector**: the DKIM `s=` value that locates the public key at `<s>._domainkey.<d>`.
- **Skeleton**: a UTS #39 transform that maps look-alike characters to a common form, so `pаypal` (Cyrillic а) and `paypal` collide.
- **Provenance**: where a piece of evidence or a registry entry came from, and why we believe it.
