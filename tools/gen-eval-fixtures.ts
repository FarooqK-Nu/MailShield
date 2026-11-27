/**
 * Adds the evaluation fixtures (Phase 7) to the 12 from gen-fixtures.ts. Deterministic: TEST-ONLY
 * keys, a fixed signing time and reserved `.example` domains.
 *
 * `truth` is set here by construction. The `expected` regression snapshot (verdict, rules,
 * signatures) is then recorded from the engine so ordinary tests catch any later change; it is
 * not the ground truth, so a case where the two differ shows up as a miss in the evaluation.
 */
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { domainToASCII } from 'node:url';
import { analyze } from '@mailshield/engine';
import {
  dkimRecord,
  fixtureRegistry,
  FixtureResolver,
  signMessage,
  TIMEOUT,
  type SignOptions,
} from '../packages/lab/src/index.ts';

const root = new URL('../fixtures/', import.meta.url);
const path = (p: string) => new URL(p, root);
for (const dir of ['eml/dev/', 'eml/heldout/']) mkdirSync(path(dir), { recursive: true });

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

const keys = {
  acme: testKey('acme-s1'),
  acme2: testKey('acme-s2'),
  globex: testKey('globex-s1'),
  esp: testKey('esp-s1'),
  lookalike: testKey('lookalike-s1'),
};

const NOW = '2026-06-01T12:00:00.000Z';
const SIGN_TIME = new Date('2026-06-01T10:00:00Z');
const HOMOGLYPH_UNICODE = 'аcme.example'; // first letter is Cyrillic U+0430
const homoglyph = domainToASCII(HOMOGLYPH_UNICODE);

const sign = (message: string, domain: string, key: string, extra: Partial<SignOptions> = {}) =>
  signMessage(message, { domain, selector: 's1', privateKey: key, signTime: SIGN_TIME, ...extra });

function hash(s: string): number {
  let h = 7;
  for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0;
  return h;
}

function mail(
  from: string,
  subject: string,
  body: string[],
  extra: string[] = [],
  type = 'text/plain; charset=utf-8',
): string {
  const domain = /@([^>]+)>?$/.exec(from)![1];
  return [
    `From: ${from}`,
    'To: alice@example.org',
    `Subject: ${subject}`,
    `Message-ID: <${Math.abs(hash(from + subject))}@${domain}>`,
    'Date: Mon, 01 Jun 2026 10:00:00 +0000',
    'MIME-Version: 1.0',
    `Content-Type: ${type}`,
    ...extra,
    '',
    ...body,
    '',
  ].join('\r\n');
}

const swap = (raw: Buffer, from: string, to: string): Buffer => {
  const text = raw.toString();
  if (!text.includes(from)) throw new Error(`Cannot tamper: "${from}" not found.`);
  return Buffer.from(text.replace(from, to));
};

const ACME = 'Acme Support <support@acme.example>';
const GLOBEX = 'Globex Payroll <payroll@globex.example>';
const paragraph = ['Hello Alice,', '', 'Your document is ready in your account.', '', 'Thank you'];

type Category = 'legitimate' | 'impersonation' | 'tampered' | 'ambiguous' | 'edge';
type Split = 'dev' | 'heldout';
type Truth = 'legitimate' | 'suspicious' | 'unknown';
interface Spec {
  id: string;
  title: string;
  description: string;
  category: Category;
  split: Split;
  truth: Truth;
  raw: Buffer | string;
  dns?: string;
}
const specs: Spec[] = [];

/** Builds a small helper that fixes the category and truth for a group of fixtures. */
const group =
  (category: Category, truth: Truth) =>
  (
    id: string,
    title: string,
    description: string,
    split: Split,
    raw: Buffer | string,
    dns?: string,
    truthOverride?: Truth,
  ) =>
    specs.push({
      id,
      title,
      description,
      category,
      split,
      truth: truthOverride ?? truth,
      raw,
      dns,
    });

// --- Legitimate -------------------------------------------------------------------------------
const legit = group('legitimate', 'legitimate');
legit(
  'globex-payroll-signed',
  'Signed payroll notice from Globex',
  'A fictional Globex message with a valid aligned DKIM signature.',
  'dev',
  await sign(mail(GLOBEX, 'Your payslip', paragraph), 'globex.example', keys.globex),
);
legit(
  'acme-billing-registered-address',
  'Signed message from a registered Acme address',
  'billing@acme.example is listed for Acme in the registry and the signature is valid.',
  'heldout',
  await sign(
    mail('Acme Billing <billing@acme.example>', 'Receipt 4821', paragraph),
    'acme.example',
    keys.acme,
  ),
);
legit(
  'acme-subdomain-signed',
  'Signed by an Acme subdomain',
  'From and signed by mail.acme.example; the registry includes subdomains.',
  'dev',
  await sign(
    mail('Acme News <news@mail.acme.example>', 'Acme news', paragraph),
    'mail.acme.example',
    keys.acme,
  ),
);
legit(
  'globex-long-body',
  'Longer signed Globex message',
  'A valid Globex message with a multi-paragraph body.',
  'heldout',
  await sign(
    mail(
      GLOBEX,
      'Policy update',
      Array.from({ length: 30 }, (_, i) => `Paragraph ${i + 1} of the policy update.`),
    ),
    'globex.example',
    keys.globex,
  ),
);
legit(
  'acme-html-signed',
  'Signed HTML message with matching link',
  'The link text and target both use acme.example.',
  'dev',
  await sign(
    mail(
      ACME,
      'Your account',
      ['<p>Open <a href="https://acme.example/account">https://acme.example/account</a>.</p>'],
      [],
      'text/html; charset=utf-8',
    ),
    'acme.example',
    keys.acme,
  ),
);
legit(
  'acme-reply-to-same-domain',
  'Reply-To on the same domain',
  'Replies go to another Acme address, which is normal.',
  'heldout',
  await sign(
    mail(ACME, 'We can help', paragraph, ['Reply-To: Acme Help <help@acme.example>']),
    'acme.example',
    keys.acme,
    { headerList: ['From', 'Reply-To', 'To', 'Subject', 'Date'] },
  ),
);
legit(
  'acme-plain-url-matches',
  'Plain text with an Acme link',
  'A valid Acme message that mentions https://acme.example/help.',
  'dev',
  await sign(
    mail(ACME, 'Help centre', ['Visit https://acme.example/help for guides.']),
    'acme.example',
    keys.acme,
  ),
);
legit(
  'acme-second-selector',
  'Signed with a second selector',
  'Acme publishes selectors s1 and s2; this message uses s2, which is current.',
  'heldout',
  await sign(mail(ACME, 'Selector two', paragraph), 'acme.example', keys.acme2, {
    selector: 's2',
  }),
);

// --- Impersonation ----------------------------------------------------------------------------
const imp = group('impersonation', 'suspicious');
imp(
  'homoglyph-domain',
  'Cyrillic look-alike of acme.example',
  'The first letter of the domain is Cyrillic; the domain is signed correctly.',
  'dev',
  await sign(
    mail(`Acme Support <support@${HOMOGLYPH_UNICODE}>`, 'Confirm your account', paragraph),
    homoglyph,
    keys.lookalike,
  ),
);
imp(
  'globex-digit-lookalike',
  'g1obex.example look-alike',
  'The letter l is replaced by the digit 1; the domain is signed correctly.',
  'heldout',
  await sign(
    mail('Globex Payroll <payroll@g1obex.example>', 'Payroll correction', paragraph),
    'g1obex.example',
    keys.lookalike,
  ),
);
imp(
  'display-name-spoof',
  'Acme name on an unrelated domain',
  'The display name says Acme Billing; the address and signature belong to mailer-help.example.',
  'dev',
  await sign(
    mail('Acme Billing <billing@mailer-help.example>', 'Invoice overdue', paragraph),
    'mailer-help.example',
    keys.lookalike,
  ),
);
imp(
  'subdomain-trick',
  'acme.example as a prefix of another domain',
  'The sender domain is acme.example.account-help.example, whose real owner is account-help.example.',
  'heldout',
  await sign(
    mail('Acme Support <support@acme.example.account-help.example>', 'Verify', paragraph),
    'acme.example.account-help.example',
    keys.lookalike,
  ),
);
imp(
  'globex-reply-to-divergence',
  'Globex replies go elsewhere',
  'A valid Globex message whose Reply-To is on payroll-desk.example.',
  'heldout',
  await sign(
    mail(GLOBEX, 'Bank details', paragraph, ['Reply-To: Payroll <pay@payroll-desk.example>']),
    'globex.example',
    keys.globex,
    { headerList: ['From', 'Reply-To', 'To', 'Subject', 'Date'] },
  ),
);
imp(
  'globex-link-mismatch',
  'Globex link shows one site, opens another',
  'The visible link is globex.example but the target is globex-hr.example.',
  'dev',
  await sign(
    mail(
      GLOBEX,
      'Review your benefits',
      ['<p><a href="https://globex-hr.example/login">https://globex.example/benefits</a></p>'],
      [],
      'text/html; charset=utf-8',
    ),
    'globex.example',
    keys.globex,
  ),
);
imp(
  'forged-auth-results',
  'Unsigned Acme message with a forged result header',
  'The message carries “Authentication-Results: dkim=pass” that the sender typed (invariant 3).',
  'heldout',
  mail(ACME, 'Urgent', paragraph, [
    'Authentication-Results: mx.google.com; dkim=pass header.d=acme.example; dmarc=pass',
  ]),
);
imp(
  'unsigned-brand-spoof',
  'Unsigned Acme name from a free-mail domain',
  'No signature at all; the display name claims Acme.',
  'dev',
  mail('Acme Support <acme.support@freemail.example>', 'Account locked', paragraph),
);

// --- Tampered ---------------------------------------------------------------------------------
const tamp = group('tampered', 'suspicious');
const acmeSigned = await sign(
  mail(ACME, 'Quarterly statement', paragraph),
  'acme.example',
  keys.acme,
);
const globexSigned = await sign(mail(GLOBEX, 'Payslip', paragraph), 'globex.example', keys.globex);
const htmlSigned = await sign(
  mail(
    ACME,
    'Sign in',
    ['<p><a href="https://acme.example/signin">https://acme.example/signin</a></p>'],
    [],
    'text/html; charset=utf-8',
  ),
  'acme.example',
  keys.acme,
);
tamp(
  'tampered-subject',
  'Subject changed after signing',
  'Subject edited after the signature.',
  'dev',
  swap(acmeSigned, 'Subject: Quarterly statement', 'Subject: Final notice'),
);
tamp(
  'tampered-from',
  'From address changed after signing',
  'From points to another address.',
  'heldout',
  swap(acmeSigned, 'support@acme.example', 'ceo@acme.example'),
);
tamp(
  'tampered-globex-body',
  'Globex body edited',
  'One sentence changed after signing.',
  'dev',
  swap(globexSigned, 'is ready in your account', 'needs your bank details'),
);
tamp(
  'tampered-html-link',
  'Link target swapped after signing',
  'The href was changed.',
  'heldout',
  swap(htmlSigned, 'href="https://acme.example/signin"', 'href="https://acme-signin.example/"'),
);
tamp(
  'tampered-signature-value',
  'Signature value corrupted',
  'Characters of b= were altered.',
  'dev',
  Buffer.from(acmeSigned.toString().replace(/ b=([A-Za-z0-9+/]{4})/, ' b=AAAA')),
);
tamp(
  'tampered-body-hash',
  'Body hash altered',
  'bh= was replaced with another value.',
  'heldout',
  Buffer.from(acmeSigned.toString().replace(/ bh=[A-Za-z0-9+/=]+/, ` bh=${'A'.repeat(43)}=`)),
);
tamp(
  'tampered-appended-text',
  'Text appended after signing',
  'A payment request was added at the end.',
  'dev',
  Buffer.concat([acmeSigned, Buffer.from('Please send payment to account 000.\r\n')]),
);

// --- Ambiguous / unknown ----------------------------------------------------------------------
const amb = group('ambiguous', 'unknown');
amb(
  'unsigned-unknown-sender',
  'Unsigned message from an unregistered sender',
  'Nothing in the registry matches and there is no signature.',
  'dev',
  mail('Shop News <news@unknown-shop.example>', 'This week', paragraph),
);
amb(
  'signed-unknown-domain',
  'Valid signature from an unregistered domain',
  'The signature is valid but nothing is known about unknown-shop.example.',
  'heldout',
  await sign(
    mail('Shop News <news@unknown-shop.example>', 'Offers', paragraph),
    'unknown-shop.example',
    keys.esp,
  ),
);
amb(
  'dns-timeout-globex',
  'Globex key lookup times out',
  'A signed Globex message checked while DNS does not answer.',
  'dev',
  globexSigned,
  'globex-timeout.json',
);
amb(
  'bad-key-record',
  'Published key record is malformed',
  'The DNS record for the selector is not a valid DKIM key.',
  'heldout',
  acmeSigned,
  'acme-bad-key.json',
);
amb(
  'unsigned-newsletter',
  'Unsigned newsletter, no DMARC published',
  'An unregistered sender with no authentication data.',
  'heldout',
  mail('Club <club@hobby-club.example>', 'Meeting notes', paragraph),
);

// --- Edge cases -------------------------------------------------------------------------------
const edge = group('edge', 'unknown');
edge(
  'forwarded-list-footer',
  'Mailing list adds a footer',
  'A real Acme message forwarded by a list that appended text, so the body hash no longer matches.',
  'dev',
  Buffer.concat([acmeSigned, Buffer.from('-- \r\nYou are on the staff list.\r\n')]),
);
edge(
  'forwarded-subject-prefix',
  'Mailing list prefixes the Subject',
  'A real Acme message forwarded by a list that added “[staff]” to the Subject.',
  'dev',
  swap(acmeSigned, 'Subject: Quarterly statement', 'Subject: [staff] Quarterly statement'),
);
edge(
  'rotated-key-old-selector',
  'Signed with a retired selector',
  'The sender rotated keys and removed selector s0, so the old key cannot be found.',
  'heldout',
  await sign(mail(ACME, 'Old selector', paragraph), 'acme.example', keys.acme, { selector: 's0' }),
);
edge(
  'shared-personal-name',
  'Another person called Alice',
  'A valid message from Alice at an unregistered company; the name matches the registry but the address does not.',
  'heldout',
  await sign(
    mail('Alice Example <alice@other-company.example>', 'Hello', paragraph),
    'other-company.example',
    keys.esp,
  ),
);
edge(
  'list-parent-signature-strict-dmarc',
  'Group message signed by the parent domain, strict DMARC',
  'A real-world pattern (found on an authorised university message): a group sends as lists.acme.example but signs with acme.example, and acme.example publishes DMARC with adkim=s. Strict alignment cannot match a subdomain, so DMARC cannot be confirmed from DKIM alone, although the message is genuine.',
  'dev',
  await sign(
    mail('Acme Students <students@lists.acme.example>', 'Schedule for tomorrow', paragraph),
    'acme.example',
    keys.acme,
  ),
  'acme-strict-dmarc.json',
  'legitimate',
);

// --- DNS zones --------------------------------------------------------------------------------
const dmarc = (d: string): [string, string] => [`_dmarc.${d}`, 'v=DMARC1; p=reject'];
const json = (v: unknown) => `${JSON.stringify(v, null, 2)}\n`;
const zone: Record<string, string> = Object.fromEntries([
  ['s1._domainkey.acme.example', dkimRecord(keys.acme)],
  ['s2._domainkey.acme.example', dkimRecord(keys.acme2)],
  ['s1._domainkey.mail.acme.example', dkimRecord(keys.acme)],
  ['s1._domainkey.globex.example', dkimRecord(keys.globex)],
  [`s1._domainkey.${homoglyph}`, dkimRecord(keys.lookalike)],
  ['s1._domainkey.g1obex.example', dkimRecord(keys.lookalike)],
  ['s1._domainkey.mailer-help.example', dkimRecord(keys.lookalike)],
  ['s1._domainkey.acme.example.account-help.example', dkimRecord(keys.lookalike)],
  ['s1._domainkey.unknown-shop.example', dkimRecord(keys.esp)],
  ['s1._domainkey.other-company.example', dkimRecord(keys.esp)],
  dmarc('acme.example'),
  dmarc('globex.example'),
]);
writeFileSync(path('dns/eval.json'), json(zone));
writeFileSync(
  path('dns/globex-timeout.json'),
  json(Object.fromEntries([['s1._domainkey.globex.example', TIMEOUT], dmarc('globex.example')])),
);
writeFileSync(
  path('dns/acme-strict-dmarc.json'),
  json({
    's1._domainkey.acme.example': dkimRecord(keys.acme),
    '_dmarc.acme.example': 'v=DMARC1; p=quarantine; adkim=s; aspf=s',
  }),
);
writeFileSync(
  path('dns/acme-bad-key.json'),
  json(
    Object.fromEntries([
      ['s1._domainkey.acme.example', 'v=DKIM1; k=rsa; p=%%%not-a-key%%%'],
      dmarc('acme.example'),
    ]),
  ),
);

// --- Write fixtures with a recorded regression snapshot ---------------------------------------
for (const { raw, dns = 'eval.json', ...spec } of specs) {
  const zoneFile = JSON.parse(readFileSync(path(`dns/${dns}`), 'utf8')) as Record<string, string>;
  const result = await analyze(
    { raw: Buffer.from(raw), source: 'fixture' },
    {
      resolver: new FixtureResolver(zoneFile),
      registry: fixtureRegistry,
      clock: () => new Date(NOW),
    },
  );
  const rules = [...new Set(result.findings.map((f) => f.ruleId))].sort();
  writeFileSync(path(`eml/${spec.split}/${spec.id}.eml`), raw);
  writeFileSync(
    path(`labels/${spec.id}.json`),
    json({
      ...spec,
      dns,
      eml: `${spec.split}/${spec.id}.eml`,
      now: NOW,
      expected: {
        verdict: result.verdict,
        signatures: result.signatures.map(({ status, failureStage }) => ({ status, failureStage })),
        rules,
      },
    }),
  );
  console.log(
    `${spec.id.padEnd(34)} truth=${spec.truth.padEnd(10)} verdict=${result.verdict.padEnd(24)} rules=${rules.join(',')}`,
  );
}
console.log(`Wrote ${specs.length} fixtures.`);
