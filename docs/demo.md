# Demonstration script

Total time about 10 minutes. Everything runs offline except the optional live Gmail step. All messages, domains and people are fictional (`.example` domains).

## Preparation

1. `npm install`, then `npm run dev`. Note the 8-digit pairing code in the service terminal.
2. Open <http://127.0.0.1:5173> and pair.
3. Optional, for step 7: the Chrome extension (`apps/extension/dist` loaded unpacked) and a Gmail test account that you own.

## Steps

1. **A legitimate message.** Analyze → Demo → "Signed message from Acme". Show the domain, the DKIM signature, the key fingerprint and the verdict "No concerning identity mismatch found". Say what it does not prove: it is not proof of who wrote the message, and not a "safe" label.
2. **A look-alike whose own checks pass.** Demo → "Authenticated look-alike domain" (`acrne.example`). DKIM passes for the look-alike domain, yet the identity finding fires. Open the evidence: the exact character comparison and the real registrable domain.
3. **A tampered message.** Demo → "Body changed after signing". The body-hash check fails. Then open the Lab, sign a message, tick a mutation (for example "edit the body") and read the "Before and after" panel: verification fails at the body-hash stage. Untick the mutation and run again: it passes. The evidence trail replays each real stage.
4. **Personal signatures.** Lab → personal signatures. Alice with her key enrolled: corroborated. Eve with a valid signature from another key: the signature is valid but identity is not confirmed. Tamper the body: it fails. Change only the unsigned outer Subject: the signature stays valid and the text says the Subject is not signed.
5. **Registry and comparison.** Registry → remove or add a trusted domain, then re-analyze the same demo and explain why the verdict changes. Signatures (cryptography) and heuristics (rules) stay visibly separate.
6. **Evaluation.** Evaluation page. Show the development and held-out results, the confusion matrix and the abstention rate. Open the disagreements: for example, a link whose text and target differ is reported but not enough, on its own, to flag the message. Say clearly that the figures describe 45 synthetic fixtures and are not real-world accuracy.
7. **Live Gmail (only with an authorized test account).** Open a test message, click the MailShield icon and analyze it in the side panel. If live Gmail is not available, use "Show original" in Gmail, download the `.eml` and analyze it in the dashboard.
8. **Privacy.** Settings: key history is off by default; export a redacted report and show that it holds no subject, body or raw headers; delete key history; revoke sessions.

## Limits to state during the demonstration

OpenPGP, ARC validation, a numeric score, batch scanning and a Workspace add-on are not implemented. Revocation checking for S/MIME is always "unknown". The live Gmail flow depends on a Google OAuth client that is not part of the repository.
