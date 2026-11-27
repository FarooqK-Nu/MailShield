# MailShield

A local-first tool that checks whether an email really comes from who it claims to be.
Undergraduate Information Security semester project.

**Status: Phase 4 (Gmail extension).** Upload an `.eml`, paste headers or run a demo in the
dashboard; manage the trusted identity registry; get rule findings and a verdict with the evidence
behind it; or analyze the open Gmail message from the Chrome side panel. The security lab, personal
signatures (S/MIME), key history, evaluation and settings are not implemented yet.

## Setup

Requires Node.js 24 or later (includes npm 11).

```bash
npm install
npm run check                 # typecheck, lint, tests
npm run dev                   # service :8787, dashboard :5173, extension :5174
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
[Original specification](docs/MailShield_context.md)
