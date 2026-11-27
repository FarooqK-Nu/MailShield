# Phase 5 plan: interactive security laboratory

Source of truth: `masterroadmap_plan.md` (Phase 5). This file only fixes the implementation shape. The roadmap is not changed.

## Scope (kept deliberately small, a semester project)

1. **Lab keys.** Three committed TEST-ONLY RSA keys in `fixtures/keys/`: Acme `s2025`, Acme `s2026` and Eve. Committed (as in Phase 1) so every run is reproducible.
2. **`packages/lab/src/scenario.ts`.** Builds a CRLF message from the editable fields, signs it with `mailauth` (`signMessage`), applies one or more mutations to the real bytes, builds the fixture DNS zone, and runs the real engine. It returns three things: the result, an unmutated baseline (for the hash comparison) and the mutation notes.
3. **Mutations:** `editBody`, `changeSignedSubject`, `alterUnsignedHeader`, `removeSignature`, `swapKey`, `rotateSelector`, `dnsMissing`, `dnsTimeout`.
4. **Protection toggles:** the nine rules can be switched off (`config.enabled`); when none is evaluated the `rules` stage reports `not_evaluated`.
5. **`POST /api/v1/lab/run`.** Body is a strict Zod `LabScenario` (preset id and mutation names from fixed lists, bounded strings, no line breaks in header fields). Only the fixture resolver and the fictional registry are used. Nothing is stored.
6. **Runtime check:** the service refuses to start unless its live resolver is a `LiveResolver`; tests assert that lab sources cannot be claimed on live routes and that the lab runs with `node:dns` disabled.
7. **Dashboard `#/lab` page:** scenario builder with a dummy avatar and a side-by-side inbox preview, mutation and protection controls, evidence trail (play, pause, step, speed, reset, hover/focus details, "simulated" badge), hash and fingerprint panel, before/after panel, four guided challenges, and a downloadable synthetic JSON report.

## Simplifications (not drifts from the exit criteria)

- "In-memory lab session": keys are read into memory once and nothing is persisted, so there is no session object.
- "Before" in before/after mode is the DKIM and DMARC evidence of the same run (rules do not influence it), so no second engine run is needed.
- The trail animates the real `StageEvent` list on the client; the server answers in one response.

## Exit criteria tests

Each of the four roadmap criteria gets a test in `packages/lab/test/scenario.test.ts`.
