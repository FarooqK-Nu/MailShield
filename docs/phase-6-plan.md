# Phase 6 plan: personal signatures and key history

Source of truth: `masterroadmap_plan.md` (Phase 6). This file only fixes the implementation shape. The roadmap is not changed.

## Scope (kept deliberately small, a semester project)

1. **Lab certificates.** A lab certificate authority (CA) and Alice, Bob and Eve certificates, generated once by `tools/gen-lab-certs.ts` with `@peculiar/x509`. Private keys are TEST-ONLY files committed in `fixtures/keys/` (same reasoning as decision A-16); certificates are in `fixtures/smime/`. Validity: 2026-01-01 to 2036-01-01.
2. **`packages/engine/src/authentication/smime.ts`.** Handles `multipart/signed` with `application/pkcs7-signature`. Extracts the exact signed bytes by offset, verifies with `pkijs`, and reports separately: signature validity, chain trust (against an injected trust store only), email binding, EKU (extended key usage) `emailProtection`, time validity, revocation (`unknown`) and the signer key fingerprint. Opaque `application/pkcs7-mime` is reported as `unsupported`.
3. **Personal identity.** A valid signature whose key fingerprint is enrolled (active, not expired) for a trusted person who matches the sender, and whose certificate binds to the From address, gives `corroborated_personal` (verdict table rows 4 and 5, as `architecture.md` §3.9 already says "or trusted personal sig"). A trust store is not required for this: the enrolled key is the trust anchor.
4. **R2** uses enrolled keys: valid signature from a key not enrolled for the claimed person gives `high`; a valid but unenrolled key gives `info`; no signature stays `info`.
5. **R8 and key history.** `KeyObservation` records for DKIM keys per domain and selector. Classification: first contact, known, rotation (new selector, other selectors known), unexpected change (same selector, different key) and revoked (user action). R8 is `info`, except a key the user revoked, which is `caution`. R8 is `not_evaluated` unless the history is switched on. Recording is opt-in (off by default), and live sources only.
6. **Server.** Migration `0002` adds a `setting` table and widens the audit constraint. New routes: `GET/PUT /settings` (history on or off, rules off; audited), `POST /settings/reset`, `GET /key-history`, `POST /key-history/:id/revoke`, `DELETE /key-history`, `POST /keys/preview` (parse PEM, store nothing), `POST /session/revoke`, `POST /lab/personal`.
7. **Lab panel.** Signer (Alice, Bob, Eve, none), "Alice's key is enrolled" toggle, two mutations (edit signed body, change the unsigned outer Subject) and four guided challenges.
8. **Dashboard and extension.** Personal signature card (shared `packages/ui`), key enrolment flow in the Registry page (paste PEM, preview fingerprint, "compared through a separate channel" confirmation, provenance, trust scope), Key History page, Settings page, redacted report export (JSON and printable HTML, built by one shared function) enabled in the dashboard and in the side panel.

## Simplifications (not drifts from the exit criteria)

- S/MIME keys are not part of key history (DKIM only); enrolled keys already cover personal keys.
- Settings are one local user's settings stored in SQLite: `historyEnabled` and `disabledRules`. DNS behaviour is shown read-only (it is an environment setting). Theme reuses the existing toggle.
- "Local data deletion and reset" means: delete key history, reset settings. The registry already has export and per-entry delete.
- The live service has no S/MIME trust store (no anchors configured), so `chain` is reported as "not checked" there. The lab CA is passed only by `packages/lab`.

## Exit criteria tests

Each of the four roadmap criteria gets a test in `packages/lab/test/smime.test.ts`; the "lab CA never trusted live" invariant also has a server test. An OpenSSL `cms -verify` cross-check test runs when `openssl` is installed.
