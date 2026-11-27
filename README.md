# MailShield

A local-first tool that checks whether an email really comes from who it claims to be.
Undergraduate Information Security semester project.

**Status: Phase 7 (evaluation, hardening and delivery).** Everything below works offline except the optional live Gmail connection.

- **Analyze** an `.eml`, pasted headers or a demo: real DKIM verification from the original bytes, DMARC alignment, a rule engine and a verdict that links to its evidence.
- **Registry** of trusted organizations and people, with provenance, audit trail and key enrolment.
- **Personal signatures:** S/MIME verification judged separately for signature, chain, email binding, enrolled key and time.
- **Security lab:** sign, mutate and rotate fictional messages and watch each verification stage.
- **Key history and settings:** opt-in, local, deletable; redacted report export.
- **Evaluation:** 44 labelled synthetic fixtures with a development and a held-out set (see [test report](docs/test-report.md)).
- **Gmail side panel:** analyze the open message with read-only access.

### Not implemented (listed honestly)

OpenPGP, ARC validation, a numeric risk score, batch analysis and a Workspace add-on. S/MIME revocation checking is always "unknown", opaque S/MIME (`pkcs7-mime`) is unsupported, and key history covers DKIM keys only. The extension's end-to-end test with a mocked Gmail API is not done, and live Gmail has not been exercised by an automated test. The demo recording, slides and viva rehearsal are not in the repository. Evaluation figures come from synthetic messages only and are not real-world accuracy.

## Setup

Requires Node.js 24 or later (includes npm 11).

```bash
npm install
npm run check                 # typecheck, lint, tests
npm run dev                   # service :8787, dashboard :5173, extension :5174
npx tsx tools/evaluate.ts --split all   # optional: regenerate the evaluation results
```

- Dashboard: <http://127.0.0.1:5173>. Pair it with the 8-digit code printed by the service.
- If the service warns that DNS is unreachable, copy `.env.example` to `.env` and set
  `DNS_SERVERS` (for example your router's address).
- Extension: open `chrome://extensions`, enable Developer mode, **Load unpacked**,
  choose `apps/extension/dist` (keep `npm run dev` running, or run `npm run build` first).
- Side panel: click the MailShield icon in Gmail, pair with the service code, then connect Gmail
  (read-only). The OAuth client ID goes in `apps/extension/.env.local`; see
  [docs/spikes.md](docs/spikes.md). Without it, the panel still analyzes `.eml` files.
- Check DKIM on a downloaded message: `npm run spike:eml -- private/message.eml`
  (`private/` is ignored by git; never commit real mail).

## Documents

[Context](docs/context.md) · [Architecture](docs/architecture.md) ·
[Roadmap](docs/masterroadmap_plan.md) · [Spike results](docs/spikes.md) ·
[Decisions](docs/decisions.md) · [Threat model](docs/threat-model.md) ·
[API](docs/api.md) · [Test and evaluation report](docs/test-report.md) · [Demo script](docs/demo.md) ·
[Original specification](docs/MailShield_context.md)
