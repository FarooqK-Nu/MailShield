# Phase 0 — Spike results

Run on 2026-11-26: Windows 11, Node.js 24.13.1, OpenSSL 3.5.4, pnpm 11.29.0.
The project has since moved to npm; exact versions are pinned in `package-lock.json`.

## Exit criteria

| Criterion | Status |
|---|---|
| `mailauth` verifies a DKIM signature through our resolver wrapper | **Met** with locally signed messages (`packages/lab/test/dkim.spike.test.ts`) |
| Real Gmail-downloaded `.eml` checked (Member A spike task) | **Met** — DKIM `pass` on a real message (see below) |
| OAuth spike fetched one raw message, or blocker documented | **Met** — one raw message fetched (see below) |
| Every "(verify P0)" item answered | **Met**, below |
| CI green | **Pending** — workflow written, not yet run on GitHub |

## mailauth 8.1.0

Import paths: `mailauth/lib/dkim/verify`, `mailauth/lib/dkim/sign`,
`mailauth/lib/dmarc/get-dmarc-record` (default export).

**Resolver (verify P0):** `(name, rrtype) => Promise<string[][]>`. Failures are thrown errors
read by `code` (`ENOTFOUND`, `ENODATA`, `ETIMEOUT`, ...). `curTime` can be injected.

**Per-signature fields (verify P0):** `signingDomain`, `selector`, `algo`, `format`,
`bodyHash`, `bodyHashExpecting`, `signingHeaders.keys`, `publicKey`, `modulusLength`,
`signTime`, `expiresAfter`, `canonBodyLength`, `sourceBodyLength`,
`status.{result, comment, aligned, testing, warnings}`.

| Situation | Library result | Tested |
|---|---|---|
| Valid | `pass` | yes |
| Body changed | **`neutral`**, "body hash did not verify" | yes |
| Signed header changed | `fail`, "bad signature" | yes |
| Unsigned header added | `pass` | yes |
| Key missing | `neutral`, "no key" | yes |
| DNS timeout | `temperror` | yes |
| Unsigned message | one `none` entry | yes |
| Expired signature | `neutral`, "expired" | source reading only |
| Short key / rsa-sha1 | `policy` | source reading only |

Consequences for Phase 1:

- `dkim.ts` must map status **and** comment; `neutral` covers tampering, missing key and expiry.
- The default (lenient) mode leaves some unprocessable signatures out of the results. Compare
  the number of `DKIM-Signature` headers with the number of results and report the difference.

**DMARC discovery (verify P0):** RFC 9989 DNS tree walk, tested. It queries up to the TLD
(for example `_dmarc.example`). Parts of the DMARC check also ask for `A`/`CNAME` records,
which our adapter refuses. Phase 2 resolution: only policy discovery and the tree walk are used
(TXT only), and the `np` tag is not evaluated (see `architecture.md` §3.6).

## S/MIME: pkijs 4.0.1

An OpenSSL-signed `multipart/signed` message verifies against our test root; the chain is
rejected under an unrelated root; changed content fails. `openssl cms -verify` agrees on the
valid message. `node:crypto` exposes the certificate's email address and EKU.

Not yet tested: opaque `pkcs7-mime`, RSA-PSS/ECDSA, messages from real mail clients,
revocation. The test splitter is spike code only.

## Domains and DNS

- `tldts`: boundaries behave as required. Private suffixes (`github.io`) count only with
  `allowPrivateDomains: true` (see decisions P-4).
- `confusables.txt`: Unicode 18.0.0, committed in `packages/engine/data/`.
- Node's DNS resolver returns a timeout within our deadline against a silent server.

## Tooling

- TypeScript is held at 6.0: `typescript-eslint` 8.74 does not support TypeScript 7.
- `@crxjs/vite-plugin` 3.0.0 builds the MV3 extension with Vite 8.
- `npm audit`: no known vulnerabilities.

## OAuth spike — (COMPLETED)

1. In the Google Cloud console, create a project and enable the **Gmail API**.
2. Configure the consent screen: *External*, publishing status *Testing*, add your test
   account as a test user, add the scope `https://www.googleapis.com/auth/gmail.readonly`.
3. Create an OAuth client of type **Chrome Extension** with item ID
   `oijpcmifakangkecaplidfpgjhhidbop`.
4. Put the client ID in `apps/extension/.env.local` as `VITE_GOOGLE_CLIENT_ID=...`.
5. `npm run build`, then load `apps/extension/dist` unpacked in Chrome (signed in to the test
   account's profile).
6. Click the MailShield icon, then **Connect and test**. Success shows the byte size of one
   raw message. Record the outcome here.

### Outcome

- **Date:** 2026-11-26
- **Result:** PASS
- **Extension ID matched:** yes (`oijpcmifakangkecaplidfpgjhhidbop`)
- **Raw message size (bytes):** 114456
- **Failed step and exact error:** none
- **Notes:** Setup complete. Connect and test fetched one raw message.


## Real `.eml` check — (COMPLETED)

In Gmail: open a message, three-dot menu, **Show original**, **Download original**. Save it
under `private/` (ignored by git) and run `npm run spike:eml -- private/<file>.eml`. Record the
result here without addresses or content.

### Outcome

- **Date:** 2026-11-26
- **Result:** PASS — the DKIM signature card showed `pass` for the signing domain `nu.edu.pk`.

## Phase 4 live Gmail check — (PENDING)

Roadmap Phase 4 exit criteria 1 and 3 need a person signed in to the test account. Run once and
record the outcome here, without addresses, subjects or content.

1. `npm run dev`, then reload the unpacked extension from `apps/extension/dist` in `chrome://extensions`.
2. Open Gmail in the test account's Chrome profile and click the MailShield icon.
3. Enter the pairing code from the service terminal. Click **Connect Gmail (read-only)** and allow access.
4. Open one message. The panel must show its From, Subject and Date as confirmed by the Gmail API.
5. Click **Analyze**. Expect a verdict; under Authentication → **Reported by Gmail**, Google's SPF, DKIM and DMARC results should appear as trusted.
6. Start an analysis and immediately open another message. The first result must not appear.
7. Open the privacy panel (gear), click **Disconnect Gmail**, then Analyze again: expect "Connect Gmail first" and the connect card.
8. Click **Connect** and press **Cancel** in Google's dialog: expect "Gmail access was not granted…".
9. Click **Open full report**: the dashboard opens and shows the same verdict.

### Outcome

- **Date:**
- **Steps passed:**
- **Failed step and exact message:**
