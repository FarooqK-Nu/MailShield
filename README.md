# MailShield

A local-first tool that checks whether an email really comes from who it claims to be.
Undergraduate Information Security semester project.

**Status: Phase 1 (vertical slice).** Upload an `.eml`, paste headers or run a demo, and see
real DKIM evidence. Identity, DMARC and impersonation checks, the registry, the lab and Gmail
selection are not implemented yet, so every result is "Identity unverified".

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
- Gmail sign-in test: see [docs/spikes.md](docs/spikes.md).
- Check DKIM on a downloaded message: `npm run spike:eml -- private/message.eml`
  (`private/` is ignored by git; never commit real mail).

## Documents

[Context](docs/context.md) · [Architecture](docs/architecture.md) ·
[Roadmap](docs/masterroadmap_plan.md) · [Spike results](docs/spikes.md) ·
[Decisions](docs/decisions.md) · [Threat model](docs/threat-model.md) ·
[Original specification](docs/MailShield_context.md)
