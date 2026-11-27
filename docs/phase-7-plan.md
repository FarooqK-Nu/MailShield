# Phase 7 plan: evaluation, hardening and delivery

Source of truth: `masterroadmap_plan.md` (Phase 7). This file only fixes the implementation shape. The roadmap is not changed.

## Scope (kept small, a semester project)

1. **Evaluation corpus.** The label schema gains `category`, `split` (`dev` or `heldout`) and `truth` (`legitimate`, `suspicious` or `unknown`, set by construction, independent of what the engine answers). `tools/gen-eval-fixtures.ts` adds about 32 synthetic fixtures to the existing 12, giving at least 40 in total, with at least 10 legitimate, 10 impersonation, 8 tampered and 8 ambiguous cases and the edge cases (forwarding, key rotation, outsourced sender, shared name). Held-out fixtures are stored in `fixtures/eml/heldout/`.
2. **`tools/evaluate.ts`.** Runs every fixture through the real engine with the fixture DNS and registry and writes `fixtures/evaluation/results.json`: confusion matrix for the binary subset, precision, recall and F1 with denominators, the abstention rate, a per-category table and a list of every disagreement with an explanation. Option `--split dev|heldout|all`. The held-out results are written once for the report.
3. **Evaluation page.** `GET /api/v1/evaluation` serves that JSON file unchanged; the dashboard page `#/evaluation` renders it and nothing else. Real authorised messages are not included (none are available); this is stated on the page.
4. **Hardening.**
   - Parser fuzz test (seeded, no new dependency): malformed MIME, deep nesting, many parts, huge headers; each must finish quickly with a result or a clean `AnalysisError`.
   - UI copy test: no "safe", "scam", "fraud" or accusation wording in UI source.
   - Acceptance traceability: `docs/test-report.md` maps every row of `MailShield_context.md` §18 and every invariant of `context.md` §8 to a named test.
   - `npm audit`, manifest permission review and a short accessibility review (keyboard, focus rings, contrast, reduced motion), with fixes for what is found.
5. **Delivery.** README rewritten for the real status and setup, `docs/api.md`, `docs/test-report.md`, `docs/demo.md`, threat model refreshed. Not done in this repository: demo recording, slides and viva rehearsal (human tasks); the README lists them honestly.

## Decision to confirm (not yet a drift)

Decision A-12 moved the Playwright extension test with a mocked Gmail API to Phase 7. The extension depends on `chrome.identity` OAuth, which cannot be driven in automated Chrome, so a faithful test needs a large mock layer. The proposal is to keep the existing Vitest coverage (reducer, Gmail client, token-to-Gmail-only network test), add one Playwright test for the new Evaluation page, and record the extension E2E as a documented limitation. This will be raised with the user before it is recorded in `decisions.md`.
