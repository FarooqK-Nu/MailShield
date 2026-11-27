/**
 * Regenerates the synthetic fixtures. Output is deterministic: committed TEST-ONLY keys,
 * fixed signing time and RSA PKCS#1 v1.5 signatures. All domains are reserved `.example`.
 */
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dkimRecord, signMessage, TIMEOUT, type SignOptions } from '../packages/lab/src/index.ts';

const root = new URL('../fixtures/', import.meta.url);
const path = (p: string) => new URL(p, root);
for (const dir of ['eml/dev/', 'dns/', 'labels/', 'keys/']) {
  mkdirSync(path(dir), { recursive: true });
}

function testKey(name: string): string {
  const file = path(`keys/TEST-ONLY-${name}.pem`);
  if (!existsSync(file)) {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    writeFileSync(file, privateKey);
  }
  return readFileSync(file, 'utf8');
}

const acmeKey = testKey('acme-s1');
const lookalikeKey = testKey('lookalike-s1');
const espKey = testKey('esp-s1');

const NOW = '2026-06-01T12:00:00.000Z';
const SIGN_TIME = new Date('2026-06-01T10:00:00Z');
const ACME_KEY = 's1._domainkey.acme.example';
const ACME_DMARC = { '_dmarc.acme.example': 'v=DMARC1; p=reject' };

const sign = (
  message: string,
  domain: string,
  privateKey: string,
  extra: Partial<SignOptions> = {},
) => signMessage(message, { domain, selector: 's1', privateKey, signTime: SIGN_TIME, ...extra });

function mail(headers: string[], body: string[], type = 'text/plain; charset=utf-8'): string {
  return [
    ...headers,
    'To: alice@example.org',
    'Date: Mon, 01 Jun 2026 10:00:00 +0000',
    'MIME-Version: 1.0',
    `Content-Type: ${type}`,
    '',
    ...body,
    '',
  ].join('\r\n');
}

const statement = mail(
  [
    'From: Acme Support <support@acme.example>',
    'Subject: Your quarterly statement',
    'Message-ID: <statement-1@acme.example>',
  ],
  [
    'Hello Alice,',
    '',
    'Your quarterly statement is ready in your Acme account.',
    '',
    'Acme Support',
  ],
);

const signed = await sign(statement, 'acme.example', acmeKey);
const tampered = Buffer.from(
  signed.toString().replace('statement is ready', 'statement is overdue'),
);

const lookalike = await sign(
  mail(
    [
      'From: Acme Support <support@acrne.example>',
      'Subject: Action needed: confirm your account',
      'Message-ID: <confirm-1@acrne.example>',
    ],
    ['Hello,', '', 'Please confirm your Acme account details today.', '', 'Acme Support'],
  ),
  'acrne.example',
  lookalikeKey,
);

const unaligned = await sign(
  mail(
    [
      'From: Acme Billing <billing@acme.example>',
      'Subject: Invoice overdue',
      'Message-ID: <invoice-7@bulk-mailer.example>',
    ],
    ['Your Acme invoice is overdue. Pay today to avoid suspension.'],
  ),
  'bulk-mailer.example',
  espKey,
);

const replyTo = await sign(
  mail(
    [
      'From: Acme Support <support@acme.example>',
      'Reply-To: Acme Accounts <accounts@payhelp.example>',
      'Subject: Update your payment details',
      'Message-ID: <payment-2@acme.example>',
    ],
    ['Please reply with your new payment details.'],
  ),
  'acme.example',
  acmeKey,
  { headerList: ['From', 'Reply-To', 'To', 'Subject', 'Date'] },
);

const linkMismatch = await sign(
  mail(
    [
      'From: Acme Support <support@acme.example>',
      'Subject: Sign in to review a payment',
      'Message-ID: <signin-3@acme.example>',
    ],
    [
      '<p>Review the payment at <a href="https://acme-login.example/session">https://acme.example/account</a>.</p>',
    ],
    'text/html; charset=utf-8',
  ),
  'acme.example',
  acmeKey,
);

const partialBody = Buffer.concat([
  await sign(statement, 'acme.example', acmeKey, { maxBodyLength: 20 }),
  Buffer.from('Text added after signing.\r\n'),
]);

const newsletter = mail(
  [
    'From: Acme Newsletter <news@acme-mail.example>',
    'Subject: Acme product news',
    'Message-ID: <news-4@acme-mail.example>',
  ],
  ['This month at Acme: new features.'],
);
const outsourced = await sign(newsletter, 'acme-mail.example', espKey);
const multiSigned = await sign(
  (await sign(statement, 'acme-mail.example', espKey)).toString(),
  'acme.example',
  acmeKey,
);

const zone = {
  [ACME_KEY]: dkimRecord(acmeKey),
  's1._domainkey.acrne.example': dkimRecord(lookalikeKey),
  's1._domainkey.bulk-mailer.example': dkimRecord(espKey),
  's1._domainkey.acme-mail.example': dkimRecord(espKey),
  ...ACME_DMARC,
};
writeFileSync(path('dns/acme.json'), json(zone));
writeFileSync(path('dns/acme-no-key.json'), json(ACME_DMARC));
writeFileSync(path('dns/acme-timeout.json'), json({ [ACME_KEY]: TIMEOUT, ...ACME_DMARC }));

type Signature = { status: string; failureStage: string | null };
const PASS: Signature = { status: 'pass', failureStage: null };

const fixtures: {
  id: string;
  title: string;
  description: string;
  raw: Buffer | string;
  dns: string;
  signatures: Signature[];
  verdict: string;
  rules: string[];
}[] = [
  {
    id: 'legit-signed',
    title: 'Signed message from Acme',
    description: 'A fictional Acme message with a valid DKIM signature from acme.example.',
    raw: signed,
    dns: 'acme.json',
    signatures: [PASS],
    verdict: 'no_concerning_mismatch',
    rules: [],
  },
  {
    id: 'body-tampered',
    title: 'Body changed after signing',
    description: 'The same message with one phrase edited after it was signed.',
    raw: tampered,
    dns: 'acme.json',
    signatures: [{ status: 'fail', failureStage: 'body_hash' }],
    verdict: 'authentication_concern',
    rules: ['R6', 'R9'],
  },
  {
    id: 'unsigned',
    title: 'Unsigned message',
    description: 'An Acme message with no DKIM signature, although Acme publishes p=reject.',
    raw: statement,
    dns: 'acme.json',
    signatures: [],
    verdict: 'identity_unverified',
    rules: ['R6'],
  },
  {
    id: 'missing-dns-key',
    title: 'Public key no longer published',
    description: 'A signed message whose selector has no DNS record.',
    raw: signed,
    dns: 'acme-no-key.json',
    signatures: [{ status: 'missing', failureStage: 'dns' }],
    verdict: 'identity_unverified',
    rules: ['R6'],
  },
  {
    id: 'dns-timeout',
    title: 'DNS does not answer',
    description: 'A signed message checked while the DNS key lookup times out.',
    raw: signed,
    dns: 'acme-timeout.json',
    signatures: [{ status: 'temporary_error', failureStage: 'dns' }],
    verdict: 'identity_unverified',
    rules: ['R6'],
  },
  {
    id: 'lookalike-authenticated',
    title: 'Authenticated look-alike domain',
    description:
      '“Acme Support” from acrne.example, with a valid DKIM signature for acrne.example.',
    raw: lookalike,
    dns: 'acme.json',
    signatures: [PASS],
    verdict: 'possible_impersonation',
    rules: ['R1', 'R3'],
  },
  {
    id: 'brand-dmarc-unaligned',
    title: 'Acme address, someone else’s signature',
    description: 'From acme.example (p=reject), signed only by bulk-mailer.example (A-8).',
    raw: unaligned,
    dns: 'acme.json',
    signatures: [PASS],
    verdict: 'identity_unverified',
    rules: ['R6'],
  },
  {
    id: 'reply-to-divergence',
    title: 'Replies go elsewhere',
    description: 'A valid Acme message whose Reply-To points to payhelp.example.',
    raw: replyTo,
    dns: 'acme.json',
    signatures: [PASS],
    verdict: 'identity_unverified',
    rules: ['R5'],
  },
  {
    id: 'link-mismatch',
    title: 'Link text and target differ',
    description: 'A valid Acme message whose link shows acme.example but opens acme-login.example.',
    raw: linkMismatch,
    dns: 'acme.json',
    signatures: [PASS],
    verdict: 'identity_unverified',
    rules: ['R7'],
  },
  {
    id: 'partial-body',
    title: 'Signature covers part of the body',
    description: 'Signed with l=20; text was added after the signed length.',
    raw: partialBody,
    dns: 'acme.json',
    signatures: [PASS],
    verdict: 'no_concerning_mismatch',
    rules: ['R9'],
  },
  {
    id: 'multi-signature',
    title: 'Two signatures',
    description: 'Signed by Acme and by its mail provider acme-mail.example.',
    raw: multiSigned,
    dns: 'acme.json',
    signatures: [PASS, PASS],
    verdict: 'no_concerning_mismatch',
    rules: [],
  },
  {
    id: 'outsourced-sender',
    title: 'Sent by Acme’s mail provider',
    description: 'From and signed by acme-mail.example, an approved service provider for Acme.',
    raw: outsourced,
    dns: 'acme.json',
    signatures: [PASS],
    verdict: 'no_concerning_mismatch',
    rules: [],
  },
];

/** Ground truth is set by construction (what the message really is), never from engine output. */
const META: Record<string, { category: string; truth: string }> = {
  'legit-signed': { category: 'legitimate', truth: 'legitimate' },
  'multi-signature': { category: 'legitimate', truth: 'legitimate' },
  'partial-body': { category: 'edge', truth: 'legitimate' },
  'outsourced-sender': { category: 'edge', truth: 'legitimate' },
  'body-tampered': { category: 'tampered', truth: 'suspicious' },
  'lookalike-authenticated': { category: 'impersonation', truth: 'suspicious' },
  'brand-dmarc-unaligned': { category: 'impersonation', truth: 'suspicious' },
  'reply-to-divergence': { category: 'impersonation', truth: 'suspicious' },
  'link-mismatch': { category: 'impersonation', truth: 'suspicious' },
  unsigned: { category: 'ambiguous', truth: 'unknown' },
  'missing-dns-key': { category: 'ambiguous', truth: 'unknown' },
  'dns-timeout': { category: 'ambiguous', truth: 'unknown' },
};

for (const { raw, signatures, verdict, rules, ...fixture } of fixtures) {
  writeFileSync(path(`eml/dev/${fixture.id}.eml`), raw);
  writeFileSync(
    path(`labels/${fixture.id}.json`),
    json({
      ...fixture,
      ...META[fixture.id],
      split: 'dev',
      eml: `dev/${fixture.id}.eml`,
      now: NOW,
      expected: { verdict, signatures, rules },
    }),
  );
}
console.log(`Wrote ${fixtures.length} fixtures.`);

function json(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}
