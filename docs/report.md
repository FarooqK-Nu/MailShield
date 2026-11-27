# MailShield — Phase Reports

A detailed record of each development phase: what was built, why, how it was verified and what remains.

This file records history. The plan is defined in [`context.md`](context.md), [`architecture.md`](architecture.md) and the [roadmap](masterroadmap_plan.md). Changes to that plan are listed in [`decisions.md`](decisions.md). Phase 7 separately plans a test report, `test-report.md`.

## Rules for this file

- Add one section per phase, at the end of that phase, below the earlier sections.
- Never overwrite or remove an earlier section. Correct it only by adding a dated note.
- Do not claim that something works unless it was tested or verified. Label work as **Completed**, **Partially completed** or **Unverified**.
- Include relevant file paths and explain important decisions.

## Coverage

Reporting started on 2026-11-27. Phases completed before that date have no detailed section here. Their existing records are the git history, [`decisions.md`](decisions.md), the [roadmap](masterroadmap_plan.md) and, for Phase 0, [`spikes.md`](spikes.md).

## Section template

Copy the block below for each new phase.

```markdown
## Phase N: Name

**Report date:** YYYY-MM-DD · **Branch:** name · **Commits:** first..last

### 1. Phase objective

### 2. Work completed

### 3. Implementation details

| File | Change (created, modified, deleted) | Purpose and key decisions |
|---|---|---|

### 4. Architecture and design decisions

### 5. Technical details

### 6. Dependencies

### 7. Testing and verification

| Check | Command or method | Result |
|---|---|---|

### 8. Problems and solutions

### 9. Outstanding issues

### 10. Phase outcome

### 11. Next phase
```

---

<!-- Phase sections begin below this line, oldest first. -->

## Phase 4: Gmail extension

**Report date:** 2026-11-27 · **Branch:** `phase-4-gmail-extension` (from `main` after the Phase 3 merge `d0cc62d`) · **Commits:** `bb6e59a..2b2fe9b`, plus the commit that adds this section

> **Note added 2026-11-27:** the live Gmail checklist in `docs/spikes.md` was run on the test account, and all nine steps passed, as reported by the project owner. Exit criteria 1 and 3 are now met, so every Phase 4 exit criterion is met. The paths marked **unverified** in §2, §7 and §9 (Google sign-in and consent, real Gmail markup for the hint, metadata confirmation, live analysis with trusted Gmail results, OAuth denial, disconnect and the full-report handoff from Gmail) were covered by that run. The picker was not part of the checklist and remains unverified live.

### 1. Phase objective

Build the daily-use experience inside Gmail (roadmap Phase 4): a Chrome MV3 side panel that analyzes the message the user has open, through the Gmail API and the local verification service, without the OAuth token ever leaving the extension. In the security area, implement the live receiver-result trust strategy of `context.md` §7, so that Gmail's own `Authentication-Results` can count as `trusted_receiver` evidence for messages fetched from the Gmail API, and only for those.

### 2. Work completed

| Task (roadmap owner) | Status |
|---|---|
| Live receiver-result trust strategy with tests (A) | **Completed.** Tested on synthetic Gmail-shaped fixtures and, locally, on one real downloaded Gmail message. |
| Invariant test: `gmail_api` is the only path to `trusted_receiver` (A) | **Completed.** |
| Review of extension permissions and data flow against the threat model (A) | **Completed.** Four threat rows added, two updated, and two accepted limitations recorded. |
| MV3 manifest with minimal permissions; service worker with OAuth, metadata then raw fetch, base64url decoding, POST to the service (B) | **Completed.** Verified by unit tests and a Chromium smoke test; the Google sign-in path is **unverified** (needs the test account). |
| Read-only content script that sends a selection hint (B) | **Completed.** Tested against a fake DOM; real Gmail markup is **unverified** in this phase. |
| Side panel: connect/disconnect, consent text, confirmation, Analyze/Reanalyze, progress, verdict, identity and authentication cards, findings, quick actions (B) | **Completed.** Rendering and the `.eml` path verified in Chromium; Gmail-specific paths **unverified** live. |
| Stale-result protection and rapid-switch test (B) | **Completed** (reducer tests). |
| Fallbacks: consented picker, `.eml` drop zone, Show original instructions (B) | **Completed.** `.eml` path verified in Chromium; picker **unverified** live. |
| Quick actions: full report, raw headers, copy fingerprint, registry entry, mark reviewed, privacy settings (B) | **Completed.** Full report handoff verified in Chromium. Export of a redacted report is shown disabled until Phase 6, as the roadmap says. |
| Exit criterion 1 (real message on a test account) | **Not done.** It needs a person signed in; the checklist is in `docs/spikes.md`. |

**Receiver trust.** `chooseTrustedReceiver` walks the header fields in order. The topmost `Authentication-Results` whose `authserv-id` is exactly `mx.google.com` is trusted only if every `Received` header above it was added inside Google and at least one of them names a `google.com` host. Trusted results are split into one evidence record per method (`dkim`, `spf`, `dmarc`, `arc`), with the stated assumption attached. This lets the existing R6 rule and verdict row 3 react to a trusted DMARC failure without changes to the rules. For `gmail_api` messages that do not fit, a `receiver-trust` record with status `unknown` explains why. Every other input source still produces only `untrusted_header` records (invariant 3).

**Shared UI.** `Findings`, `IdentityComparison`, `RefLinks` and the evidence-target helpers moved from the dashboard into `packages/ui`, and a new `EvidenceItem` component labels evidence by source. The dashboard and the side panel therefore present findings and evidence identically. The dashboard's "other evidence" list also stopped hiding Gmail's DKIM report, which it had previously filtered out along with local DKIM records.

**Extension.** The service worker is the only component with Gmail access. The side panel talks to it through a validated message protocol. The content script reads Gmail's page and reports which messages are expanded. The side panel confirms the chosen message with the Gmail API (`format=metadata`) and shows From, Subject and Date. If the page and the API disagree, the user must acknowledge the difference before Analyze is enabled. The service worker checks `sizeEstimate`, fetches `format=raw`, decodes base64url and posts the exact bytes to `POST /api/v1/analyze` with `X-MailShield-Source: gmail_api` and the message id as `X-MailShield-Message-Ref`.

**Dashboard.** A new `#/report` page receives a side panel result by `postMessage` (decision A-14). `#/registry?q=` pre-fills the registry search for "Open registry entry".

### 3. Implementation details

| File | Change | Purpose and key decisions |
|---|---|---|
| `packages/engine/src/authentication/receiver-results.ts` | Modified | `receivedByHost`, `chooseTrustedReceiver`, per-method trusted records, and the `unknown` explanation for Gmail messages that do not fit. Status mapping: `pass`→pass, `fail`/`softfail`→fail, `none`→missing, `temperror`→temporary_error, anything else→unknown. |
| `packages/engine/src/pipeline.ts` | Modified | The receiver stage reports `trusted` and `records` counts, passes when a trusted result exists, and states that attribution is positional. |
| `packages/engine/src/rules/rules.ts` | Modified | R6 policy wording: "SPF cannot be checked here" instead of "for an uploaded message", which was wrong for Gmail input. |
| `packages/engine/test/receiver-trust.test.ts` | Created | Strategy tests on fixtures, a pipeline test for a trusted DMARC fail (R6 finding, verdict row 3), and the local-only real-message test (A-13). |
| `packages/engine/test/invariant-03-forged-auth-results.test.ts` | Modified | Adds the `gmail_api`-only invariant and the case of a forged header with no Google hop. |
| `fixtures/gmail/*.eml`, `fixtures/gmail/README.md` | Created | Five synthetic messages that copy Gmail's header order on reserved domains and documentation IP ranges. |
| `packages/ui/src/{Findings,IdentityComparison,RefLinks,targets}` | Moved from `apps/web/src/features/inspector/` | Shared by the dashboard and the side panel. `Findings` gained an `actions` slot (used for "mark reviewed"). |
| `packages/ui/src/EvidenceItem.tsx`, `packages/ui/src/index.ts` | Created / modified | Source labels ("Reported by Gmail's receiving server", "Written in the message (not proof)") and evidence titles in one place. |
| `apps/web/src/routes/ResultView.tsx`, `apps/web/src/features/inspector/DkimInspector.tsx` | Modified | Use the shared components. |
| `apps/web/src/routes/Report.tsx`, `apps/web/src/main.tsx`, `apps/web/src/routes/Registry.tsx` | Created / modified | `#/report` handoff page, which needs no pairing and keeps the result in memory only; hash routes may carry a query string; registry search from `?q=`. |
| `apps/extension/manifest.config.ts`, `vite.config.ts`, `.env.example`, `package.json`, `tsconfig.json` | Modified | Permissions `sidePanel`, `identity`, `storage`; host access to the Gmail API and the service origin only; content script on `mail.google.com`; Tailwind; `VITE_SERVICE_URL` and `VITE_DASHBOARD_URL`; tests are typechecked. |
| `apps/extension/src/background.ts` | Rewritten (replaces the Phase 0 spike) | OAuth with `chrome.identity`, request handlers, hints in `chrome.storage.session`, progress broadcasts, sender checks by URL. |
| `apps/extension/src/background/gmail.ts` | Created | Gmail client (metadata, raw, recent), base64url decoding, id validation, one retry after a rejected token, typed errors. |
| `apps/extension/src/background/service.ts` | Created | Local service client (health, pair, analyze) with contract validation of every reply and problem+json error mapping. It has no parameter through which a Gmail token could be passed. |
| `apps/extension/src/background/flow.ts` | Created | The live flow: size check, raw fetch, upload, `messageRef` check. |
| `apps/extension/src/shared/selection.ts`, `shared/protocol.ts` | Created | Dependency-free hint types and helpers (kept small for the content script); Zod schemas for every panel request and content message. |
| `apps/extension/src/content/gmail.ts`, `content/read-hint.ts` | Created | Read-only page reader with a debounced `MutationObserver`; reports only when the hint changes. |
| `apps/extension/src/sidepanel/state.ts` | Created | Pure reducer for selection, confirmation, analysis and stale-result rules. |
| `apps/extension/src/sidepanel/{App,ResultPanel,Fallbacks,Setup}.tsx`, `api.ts`, `report.ts`, `local-data.ts`, `main.tsx`, `styles.css` | Created / rewritten | Panel UI, quick actions, privacy panel, reviewed marks, report handoff. |
| `apps/extension/test/*.test.ts`, `test/support.ts` | Created | 39 tests: reducer, Gmail client, selection helpers and page reader, token network test. |
| `docs/decisions.md` | Modified | A-12 to A-15. |
| `docs/architecture.md`, `docs/context.md`, `docs/threat-model.md`, `docs/masterroadmap_plan.md`, `docs/spikes.md`, `README.md` | Modified | "As built" notes, A-15 reference, threat rows and limitations, exit-criteria status, live-check checklist, README status. |

### 4. Architecture and design decisions

- **The service worker holds Gmail access; the panel never sees the token.** The architecture assigns Gmail calls to the service worker. Keeping the token there means a rendering bug in the panel cannot leak it, and the service client's signature makes it impossible to pass the token to the service. The alternative, calling the Gmail API from the panel, would have spread the token to a second context for no benefit.
- **All network calls go through the service worker, including `.eml` uploads.** Files reach the worker as base64 over extension messaging (at most about 14 MB for a 10 MiB file, well below Chrome's message limit). The panel could have called the service directly, but a single network client is simpler to review and test.
- **Receiver trust is positional and slightly stricter than the context text (A-15).** "Added inside Google" had to be made testable. Gmail's internal hops record only an IPv6 address (seen on the real message), so bare IP addresses count as inside Google. In addition, a `google.com` reception hop must appear above the trusted header, so that a message with no Google hop at all cannot have a header trusted. `context.md` says the stricter security rule wins, so this was recorded rather than asked about.
- **Trusted results are split per method.** One `trusted_receiver` record per method lets the existing rules (R6 checks `kind === 'dmarc'` with source `trusted_receiver`) work unchanged. A single combined record would have needed rule changes.
- **Trusted receiver DMARC pass does not corroborate identity.** Verdict rows 4 and 5 still need locally verified aligned DKIM (or a trusted personal signature). The receiver's result is context, as `architecture.md` §3.6 says.
- **Stale-result protection is a pure reducer.** Request numbers plus a `messageRef` check make the rule testable without Chrome. The alternative, aborting fetches on switch, would not protect against replies that are already in flight.
- **Multiple expanded messages: the user chooses.** The specification asks for one message, never a whole thread, so the panel asks instead of guessing (for example, taking the last message).
- **Full report by `postMessage` (A-14).** No server route and no storage were added. The dashboard checks both the origin and that the message comes from its opener.
- **Extension tests now, extension E2E later (A-12); synthetic and local-only real mail (A-13).** Both were approved before implementation.

### 5. Technical details

**Trust algorithm (`chooseTrustedReceiver`).**

```text
googleHop = false
for each header field, top to bottom:
  Received:  by = host after "by" (comments removed)
             if by is missing, or not (google.com | *.google.com | IP address): untrusted, stop
             if by is a google.com name: googleHop = true
  Authentication-Results:
             if authserv-id != "mx.google.com": skip (shown as untrusted)
             if not googleHop: untrusted, stop
             trusted: this header, stop
no Google header: untrusted
```

**Side panel states.** `empty → (choose →) confirming → ready → analyzing(steps) → result | error`. A file upload is a target of its own (`file:<n>`) and ignores Gmail hints until it is closed. A result is accepted only if `ref` and `request` match the current state and, for Gmail targets, `result.messageRef === ref`.

**Panel ↔ service worker protocol** (`shared/protocol.ts`): `status`, `pair`, `unpair`, `connect`, `disconnect`, `hint`, `metadata`, `analyze`, `analyzeFile`, `recent`. Replies are `{ok, value}` or `{ok: false, code, message}`. The worker broadcasts `hint-changed` and `progress`.

**Gmail API calls.** `GET users/me/messages/{id}?format=metadata&metadataHeaders=From|Subject|Date`, `GET …?format=raw`, and, for the picker only, `GET users/me/messages?maxResults=10` followed by metadata for each. A 401 drops the cached token and retries once. 403, 404 and 429 map to specific messages.

**Local data.** `chrome.storage.local`: the pairing session token and reviewed marks (message id → finding ids, at most 200 messages). `chrome.storage.session`: selection hints per tab. No message content is stored.

### 6. Dependencies

- `apps/extension`: added `@mailshield/contracts`, `@mailshield/ui`, `lucide-react` and `zod` (shared contracts and UI, request validation), and `tailwindcss` with `@tailwindcss/vite` as dev dependencies (the same styling as the dashboard). All were already used elsewhere in the workspace, at the same versions. No new third-party package entered the repository. `npm audit`: 0 vulnerabilities.

### 7. Testing and verification

| Check | Command or method | Result |
|---|---|---|
| Typecheck (all workspaces and tools) | `npm run typecheck` | Pass |
| Lint | `npm run lint` | Pass |
| Unit and integration tests | `npx vitest run` from `D:\` (see §8) | 23 files, 298 tests pass (39 new extension tests and 14 new engine tests, one of which runs only where `private/` exists) |
| Real Gmail message (local only) | `receiver-trust.test.ts`, `private/` case | Pass: exactly one trusted result (Google's topmost), none when the same bytes are uploaded |
| Build | `npm run build` | Pass. The content script is about 2 KB in total, with no Zod |
| Playwright | `npx playwright test` | 1 pass (preview network assertion) |
| Dependency audit | `npm audit` | 0 vulnerabilities |
| Chromium smoke test (not committed) | Playwright with the unpacked extension, the real service on a temporary data directory, and the dashboard dev server | Pass: service worker loads; pairing with a real code; `.eml` analyzed through the worker; verdict, findings and stages render; "Open full report" shows the same verdict in the dashboard; `#/report` without an opener refuses |
| Manifest review | Built `dist/manifest.json` | Permissions `sidePanel`, `identity`, `storage`; hosts `gmail.googleapis.com` and `127.0.0.1:8787`; scope `gmail.readonly` |

The smoke test found a real bug: the worker treated any sender with `sender.tab` as the content script, so requests from an extension page opened in a tab were ignored. Requests are now told apart by sender URL (commit `f46855e`).

Not verified in this phase: Google sign-in and consent, real Gmail markup for the hint, metadata confirmation, the live analysis path, OAuth denial, disconnect, and the picker. All of them need the test account.

### 8. Problems and solutions

- **Every Vitest suite failed with "Cannot read properties of undefined (reading 'config')".** The session shell started in `d:\` (lowercase), and Node loaded Vitest's runner twice, as `file:///D:/…` and `file:///d:/…`. Running from `D:\` in PowerShell fixes it; this is not a code defect.
- **`npm ci` failed on `better-sqlite3`.** npm runs `node-gyp rebuild` because the package contains `binding.gyp`, and this machine has no Visual Studio. The package ships a `win32-x64` prebuild that it loads by itself, so `npm ci --ignore-scripts` is correct (the other install scripts are only `esbuild`'s check and macOS-only `fsevents`).
- **The side panel crashed with "Cannot read properties of null (reading 'useContext')".** The reinstall from the lowercase shell had created the `node_modules/@mailshield/*` junctions with `d:\` targets, and Vite bundled React and lucide-react twice. Vite's `resolve.dedupe` did not help and was reverted. Reinstalling with `npm install --ignore-scripts` from `D:\` recreated the junctions as `D:\…`, and the bundle then had one React copy. The lockfile was left unchanged.
- **The content script pulled in an 87 KB Zod chunk**, which would be web-accessible on Gmail. Schemas moved to `protocol.ts`, leaving `selection.ts` dependency-free.
- **A real-message test printed the file name, which is the message subject.** Cases are now numbered.

### 9. Outstanding issues

- **Exit criterion 1 is open**, and so is the live part of criterion 3 (OAuth denial and disconnect messages). Follow the checklist in `docs/spikes.md` on the test account.
- Gmail's markup selectors (`data-legacy-message-id`, `span.gD[email]`, `h2.hP`) come from observed markup and are untested against today's Gmail. Metadata confirmation and the fallbacks limit the damage if they break.
- Extension E2E with Playwright and a mocked Gmail API is deferred to Phase 7 (A-12).
- Receiver trust is positional; see the new accepted limitation in `docs/threat-model.md`.
- Disconnect clears Chrome's cached token but does not revoke the grant at Google; the panel links to the Google Account page for that.
- The extension's content-script chunks are web-accessible on Gmail (a `@crxjs/vite-plugin` requirement), which reveals that MailShield is installed.
- The service URL is fixed at build time; if `PORT` changes, rebuild with `VITE_SERVICE_URL`.
- Export of a redacted report is disabled until Phase 6.
- Results opened from the side panel are not counted on the dashboard's Overview page.

### 10. Phase outcome

The extension is a working MV3 side panel rather than the Phase 0 spike. It pairs with the local service, confirms a selection through the Gmail API, fetches original bytes, gets an analysis, and shows the verdict with its findings and evidence, including Gmail's trusted receiver results. The engine now distinguishes Google's own authentication results from forged ones for live Gmail input, and only for that input. Every automated check passes. The one remaining exit criterion needs a manual run on the test account.

### 11. Next phase

Phase 5, the security laboratory: lab keys and selectors, real signing and mutations in `packages/lab`, `POST /lab/run`, the animated evidence trail, before/after mode and offline operation. Carried forward: run the Phase 4 live checklist; extension E2E in Phase 7; and, on this Windows machine, run installs and tests from `D:\` in PowerShell.

## Phase 5: Interactive security laboratory

**Report date:** 2026-11-27 · **Branch:** `phase-5-security-lab` · **Commits:** `ef49132`..`cac9ae6`, plus the documentation commit that adds this section

### 1. Phase objective

Build the semester demonstration centrepiece: an offline laboratory in which a user builds a synthetic message, has it really signed, tampers with it, and watches the real analysis engine react. The plan is `docs/masterroadmap_plan.md` (Phase 5); `docs/phase-5-plan.md` fixes the implementation shape. The user asked for a deliberately small implementation.

### 2. Work completed

Status: **completed**, with the browser checks described in section 7.

- Three new committed TEST-ONLY RSA keys: Acme selector `s2025`, Acme selector `s2026` and Eve.
- `runScenario` in `packages/lab`: builds the message, signs it with DKIM (DomainKeys Identified Mail, the signature scheme that proves a domain signed a message), applies mutations to the real bytes, builds the fixture DNS zone and runs the real engine.
- Eight mutations: edit one body character, change the signed Subject, change Reply-To after signing (not covered by the signature), remove the signature, swap the key, rotate the selector, DNS key missing, DNS timeout.
- Protection toggles: each rule R1 to R9 can be switched off (R8 stays off until Phase 6).
- `POST /api/v1/lab/run` with strict validation.
- A startup check in the service and tests for the live/lab separation.
- A dashboard page `#/lab`: scenario builder with avatar and side-by-side preview, tamper controls, protection toggles, animated evidence trail, before/after panel, hash and key panel, four guided challenges, downloadable synthetic JSON report and reset.

### 3. Implementation details

- `fixtures/keys/TEST-ONLY-lab-acme-s2025.pem`, `...-s2026.pem`, `...-eve.pem` (new).
- `packages/contracts/src/lab.ts` (new): `LabScenario`, `LabRunResponse`, `LAB_DEFAULTS` and the allowed lists. Header fields reject line breaks, quotes and angle brackets, so a field cannot inject a header; addresses must match a strict pattern.
- `packages/lab/src/scenario.ts` (new): see section 5.
- `packages/engine/src/pipeline.ts`: the `rules` stage reports `not_evaluated` when no rule ran (previously `pass`).
- `apps/server/src/routes/lab.ts`: the new route (16 KB JSON limit, the same token and rate-limit guards as other routes). `apps/server/src/server.ts`: refuses to start unless the live resolver is a `LiveResolver`.
- `apps/web/src/routes/Lab.tsx`, `features/lab/EvidenceTrail.tsx`, `features/lab/challenges.ts` (new); `main.tsx` and `api/client.ts` (navigation entry and `runLab`).
- Tests: `packages/lab/test/scenario.test.ts`, `apps/web/test/challenges.test.ts`, and a new case in `apps/server/test/app.test.ts`.
- Documentation: `docs/phase-5-plan.md`, decision A-16, a threat-model row update and ticked Phase 5 exit criteria in the roadmap.

### 4. Architecture and design decisions

- **Committed keys.** Node cannot create RSA keys deterministically, and the lab must give identical output every run. Committed TEST-ONLY keys (the Phase 1 pattern) solve this at no risk, because they guard nothing.
- **Mutations act on real bytes after signing**, the way an attacker in transit would, so the verdicts come from genuine cryptography rather than scripted outcomes.
- **Eve owns a look-alike domain.** `acrne.example` ("rn" instead of "m") publishes her key and a `p=none` DMARC policy, so her message authenticates honestly, which is the point of the look-alike demonstration.
- **Alternatives rejected** (decision A-16): a server-side lab session object (nothing needs to persist), a second engine run for "before" (the DKIM and DMARC evidence of one run does not depend on the rules) and server-pushed events (the client animates the stage list it already has).
- No deviation from the roadmap's exit criteria or table was made.

### 5. Technical details

- Fixed clock: signing at 10:00 UTC and analysis at 12:00 UTC on 2026-06-01, so results never depend on the current date.
- Signing covers From, To, Subject and Date. Reply-To is deliberately unsigned.
- `swapKey` signs with the other party's key while keeping the claimed `d=` and `s=`, which fails at the header-signature stage. `rotateSelector` signs with the other published Acme selector, so DKIM passes with a different key fingerprint and the same body hash.
- Each run performs two engine runs: the mutated message and an unmutated baseline. The page compares their body hashes and key fingerprints character by character. The body hash and the key fingerprint are shown separately because they answer different questions.
- Evidence trail: plays, pauses, steps, resets and changes speed over `result.stages`. Hovering or focusing a revealed stage shows its inputs, outputs and limits. Every stage carries a "simulated" badge.
- The DNS resolver is always a `FixtureResolver`; the registry is always the fictional seed registry (A-10). Mutated messages never leave memory.

### 6. Dependencies

None added, removed or updated. `npm audit` reports 0 vulnerabilities.

### 7. Testing and verification

| Check | Result |
|---|---|
| `npx vitest run` from `D:\` | 25 files, 316 tests pass (18 new) |
| Exit criterion 1 (one body character) | Test passes: DKIM `fail` at `body_hash`, computed body hash differs, expected hash unchanged |
| Exit criterion 2 (unsigned header) | Test passes: DKIM stays `pass`, `reply-to` appears in the unsigned headers, rule R5 fires |
| Exit criterion 3 (before/after) | Test passes: look-alike has DKIM and DMARC `pass`, R1 and R3 fire with rules on; with all rules off no finding and the `rules` stage is `not_evaluated` |
| Exit criterion 4 (offline) | Test passes with the system DNS resolver stubbed to throw; it is never called |
| Route test | Valid scenario returns 200 with source `lab`; unknown mutation, extra field and missing token are rejected; the live resolver receives no queries |
| `npm run typecheck`, `npx eslint .`, `npm run build` | Pass |
| Browser check (temporary Playwright script, not committed) | The real service and dashboard on spare ports: pairing, running a scenario, ticking a mutation and re-running worked; the first challenge was marked solved; no console errors. A screenshot was inspected by eye |

Not verified: the animation timing and the downloaded report file were not exercised by an automated test; light-theme appearance and narrow-screen layout were not inspected.

### 8. Problems and solutions

- A failed signature reports no key, so the key fingerprint cell was empty. The page now explains that verification stopped before the key was used, and the test asserts the baseline fingerprint instead.
- The developer's own service and dashboard already occupied ports 8787 and 5173. The browser check used a separate service and a temporary Vite configuration on other ports, both removed afterwards.

### 9. Outstanding issues

- No committed browser (Playwright) test for the lab page; the page logic is covered through the server and challenge tests only (Phase 7).
- The lab covers DKIM and DMARC only. Personal (S/MIME) signatures and the lab certificate authority come in Phase 6.
- The lab message is plain text, so the link-mismatch rule R7 cannot be demonstrated in the lab.
- The dashboard bundle is 549 KB (a build-tool size warning).
- Extension E2E remains Phase 7.

### 10. Phase outcome

The lab is working end to end and meets all four exit criteria in tests. A user can build a message, tamper with it, switch protections off, replay the real pipeline events and compare hashes and verdicts, entirely offline.

### 11. Next phase

Phase 6: personal signatures and key history (S/MIME with the lab certificate authority, key enrolment, key history, redacted report export, settings page). Carried forward: R8 is still disabled, the "Export redacted report" action remains disabled, and on this Windows machine tests must run from `D:\` in PowerShell.
