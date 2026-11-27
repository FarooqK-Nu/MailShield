# Synthetic Gmail header fixtures

Header-order fixtures for the live Gmail receiver-trust strategy (`docs/context.md` §7,
decision A-15). They copy the order in which Gmail adds headers, as observed on a real
downloaded message (header names only). Every domain is reserved (RFC 2606) and every address
is from a documentation range (RFC 5737, RFC 3849). The DKIM signatures are placeholders and do
not verify. These files test header provenance only.

| File | What it models | Expected |
|---|---|---|
| `genuine-pass.eml` | Google's result is topmost; only Google hops above it | trusted, DMARC pass |
| `genuine-dmarc-fail.eml` | As above, Google reports DMARC fail | trusted, DMARC fail |
| `forged-below-google.eml` | Sender wrote `dmarc=pass` before sending; Google's real result is above it | Google's result trusted, forged one untrusted |
| `forged-no-google-hop.eml` | Only a forged header and no google.com `Received` above it | nothing trusted, `unknown` |
| `external-relay-above.eml` | An outside server added a `Received` above Google's result | nothing trusted, `unknown` |
