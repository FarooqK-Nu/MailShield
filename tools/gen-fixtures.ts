/**
 * Regenerates the synthetic fixtures. Output is deterministic: committed TEST-ONLY key,
 * fixed signing time and RSA PKCS#1 v1.5 signatures.
 */
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dkimRecord, signMessage, TIMEOUT } from '../packages/lab/src/index.ts';

const root = new URL('../fixtures/', import.meta.url);
const path = (p: string) => new URL(p, root);
for (const dir of ['eml/dev/', 'dns/', 'labels/', 'keys/']) {
  mkdirSync(path(dir), { recursive: true });
}

const keyFile = path('keys/TEST-ONLY-acme-s1.pem');
if (!existsSync(keyFile)) {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  writeFileSync(keyFile, privateKey);
}
const privateKey = readFileSync(keyFile, 'utf8');

const NOW = '2026-06-01T12:00:00.000Z';
const NAME = 's1._domainkey.acme.example';

const message = [
  'From: Acme Support <support@acme.example>',
  'To: alice@example.org',
  'Subject: Your quarterly statement',
  'Date: Mon, 01 Jun 2026 10:00:00 +0000',
  'Message-ID: <statement-1@acme.example>',
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Hello Alice,',
  '',
  'Your quarterly statement is ready in your Acme account.',
  '',
  'Acme Support',
  '',
].join('\r\n');

const signed = await signMessage(message, {
  domain: 'acme.example',
  selector: 's1',
  privateKey,
  signTime: new Date('2026-06-01T10:00:00Z'),
});
const tampered = Buffer.from(
  signed.toString().replace('statement is ready', 'statement is overdue'),
);

writeFileSync(path('dns/acme.json'), json({ [NAME]: dkimRecord(privateKey) }));
writeFileSync(path('dns/acme-no-key.json'), json({}));
writeFileSync(path('dns/acme-timeout.json'), json({ [NAME]: TIMEOUT }));

const fixtures = [
  {
    id: 'legit-signed',
    title: 'Signed message from Acme',
    description: 'A fictional Acme message with a valid DKIM signature.',
    raw: signed,
    dns: 'acme.json',
    signatures: [{ status: 'pass', failureStage: null }],
  },
  {
    id: 'body-tampered',
    title: 'Body changed after signing',
    description: 'The same message with one phrase edited after it was signed.',
    raw: tampered,
    dns: 'acme.json',
    signatures: [{ status: 'fail', failureStage: 'body_hash' }],
  },
  {
    id: 'unsigned',
    title: 'Unsigned message',
    description: 'A message with no DKIM signature.',
    raw: Buffer.from(message),
    dns: 'acme.json',
    signatures: [],
  },
  {
    id: 'missing-dns-key',
    title: 'Public key no longer published',
    description: 'A signed message whose selector has no DNS record.',
    raw: signed,
    dns: 'acme-no-key.json',
    signatures: [{ status: 'missing', failureStage: 'dns' }],
  },
  {
    id: 'dns-timeout',
    title: 'DNS does not answer',
    description: 'A signed message checked while the DNS lookup times out.',
    raw: signed,
    dns: 'acme-timeout.json',
    signatures: [{ status: 'temporary_error', failureStage: 'dns' }],
  },
];

for (const { raw, signatures, ...fixture } of fixtures) {
  writeFileSync(path(`eml/dev/${fixture.id}.eml`), raw);
  writeFileSync(
    path(`labels/${fixture.id}.json`),
    json({
      ...fixture,
      eml: `dev/${fixture.id}.eml`,
      now: NOW,
      expected: { verdict: 'identity_unverified', signatures },
    }),
  );
}
console.log(`Wrote ${fixtures.length} fixtures.`);

function json(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}
