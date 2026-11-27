# API reference

The local verification service listens on `127.0.0.1:8787` only. All routes are under `/api/v1`. Requests must carry an allowed `Host` and `Origin` header (see `.env.example`). Except `GET /health` and `POST /pair`, every route needs `Authorization: Bearer <token>`, where the token comes from `POST /pair`. Errors use a fixed problem body `{ "type": "...", "message": "..." }`; messages never contain message content. The Zod schemas that define every request and response are in `packages/contracts/src`.

## Pairing and session

| Method and path | Purpose |
|---|---|
| `GET /health` | Liveness check, no token. |
| `POST /pair` | Exchanges the 8-digit code printed by the service for a session token. Single use; limited attempts. |
| `POST /session/revoke` | Revokes every session token. |

## Analysis (live data only)

| Method and path | Body | Purpose |
|---|---|---|
| `POST /analyze` | raw `.eml` bytes (`application/octet-stream`, up to 10 MiB) | Full analysis with the live DNS resolver. Returns an `AnalysisResult`. |
| `POST /analyze/headers` | pasted headers (`text/plain`) | Header-only analysis; body-dependent checks are reported as not evaluated. |

An `AnalysisResult` holds the verdict, `verdictBasis` (the table row and the finding and evidence ids that decided it), findings, per-signature DKIM evidence, DMARC evidence, the personal signature (S/MIME) result, stages, limitations and the input source. Clients cannot choose the input source; `fixture` and `lab` are refused.

## Trusted identity registry

| Method and path | Purpose |
|---|---|
| `GET /identities`, `POST /identities` | List (filters: text, kind, trust state) or create. |
| `GET/PATCH/DELETE /identities/:id` | Read, edit or soft-delete one identity. |
| `POST /identities/:id/keys` | Enrol a **public** key or certificate. Private keys are refused. |
| `GET /identities/:id/audit`, `GET /audit` | Audit events for one identity or all. |
| `GET /registry/export`, `POST /registry/import` | JSON export and import. |
| `POST /keys/preview` | Parses pasted PEM and returns the fingerprint. Stores nothing. |

## Settings, key history and privacy

| Method and path | Purpose |
|---|---|
| `GET /settings`, `PUT /settings` | Key history on or off, rules switched off. Every change is audited. |
| `POST /settings/reset` | Back to defaults. |
| `GET /settings/audit` | Audit events for settings. |
| `GET /key-history` | DKIM keys seen per domain and selector (empty unless history is on). |
| `POST /key-history/:id/revoke` | Marks an observed key as not to be trusted. |
| `DELETE /key-history` | Deletes all observations. |

## Laboratory, demos and evaluation (fixture data only)

| Method and path | Purpose |
|---|---|
| `GET /fixtures` | The labelled fixtures (id, title, description). |
| `POST /lab/demo/:id` | Analyses one fixture against fixture DNS and the fictional registry. |
| `POST /lab/run` | DKIM lab scenario (signer, mutation, rotation). Fields are allowlisted. |
| `POST /lab/personal` | S/MIME lab scenario (Alice, Bob, Eve, enrolment toggle, mutations). |
| `GET /evaluation/:split` | `split` is `dev`, `heldout` or `all`. Returns the JSON written by `tools/evaluate.ts` unchanged; `404` if it has not been generated. |

None of the lab routes can reach live DNS or the local registry, and the live routes cannot reach fixture data (invariant 7).
