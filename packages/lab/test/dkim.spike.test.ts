/** Phase 0 spike: pins down the mailauth behaviour that Phase 1 depends on. */
import { generateKeyPairSync } from 'node:crypto';
import getDmarcRecord from 'mailauth/lib/dmarc/get-dmarc-record';
import { dkimSign } from 'mailauth/lib/dkim/sign';
import { beforeAll, describe, expect, it } from 'vitest';
import { keyFingerprint, rawDkimVerify, toMailauthResolver } from '@mailshield/engine';
import { FixtureResolver, TIMEOUT, type FixtureZone } from '../src/index.ts';

const NOW = new Date('2026-06-01T12:00:00Z');
const NAME = 's1._domainkey.acme.example';

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const zone: FixtureZone = { [NAME]: `v=DKIM1; k=rsa; p=${publicKey.toString('base64')}` };

const message = [
  'From: Acme Support <support@acme.example>',
  'To: alice@example.org',
  'Subject: Quarterly statement',
  'Date: Mon, 01 Jun 2026 10:00:00 +0000',
  '',
  'Your statement is ready.',
  '',
].join('\r\n');

let signed: Buffer;
beforeAll(async () => {
  const { signatures, errors } = await dkimSign(Buffer.from(message), {
    signTime: new Date('2026-06-01T10:00:00Z'),
    headerList: ['From', 'To', 'Subject', 'Date'],
    signatureData: [{ signingDomain: 'acme.example', selector: 's1', privateKey }],
  });
  expect(errors ?? []).toEqual([]);
  signed = Buffer.from(signatures + message);
});

const verify = async (raw: Buffer, records: FixtureZone = zone) =>
  (await rawDkimVerify(raw, { resolver: new FixtureResolver(records), now: NOW })).results;

const tamper = (from: string, to: string) => Buffer.from(signed.toString().replace(from, to));

describe('mailauth DKIM through our resolver', () => {
  it('passes a valid signature and exposes the per-signature fields we need', async () => {
    const [result] = await verify(signed);
    expect(result).toMatchObject({
      signingDomain: 'acme.example',
      selector: 's1',
      algo: 'rsa-sha256',
      format: 'relaxed/relaxed',
      modulusLength: 2048,
      status: { result: 'pass' },
    });
    expect(result!.bodyHash).toBe(result!.bodyHashExpecting);
    expect(result!.signingHeaders!.keys.toLowerCase()).toContain('subject');
    expect(keyFingerprint(result!.publicKey!)).toBe(
      keyFingerprint({ key: publicKey, format: 'der', type: 'spki' }),
    );
  });

  it('reports a changed body as neutral with a body-hash comment (must be mapped to fail)', async () => {
    const [result] = await verify(tamper('statement is ready', 'statement is reedy'));
    expect(result!.status).toMatchObject({
      result: 'neutral',
      comment: 'body hash did not verify',
    });
    expect(result!.bodyHash).not.toBe(result!.bodyHashExpecting);
  });

  it('fails a changed signed header', async () => {
    const [result] = await verify(tamper('Quarterly statement', 'Urgent statement'));
    expect(result!.status).toMatchObject({ result: 'fail', comment: 'bad signature' });
  });

  it('still passes when an unsigned header is added', async () => {
    const raw = Buffer.concat([Buffer.from('Reply-To: eve@evil.example\r\n'), signed]);
    expect((await verify(raw))[0]!.status.result).toBe('pass');
  });

  it('reports a missing key as neutral "no key"', async () => {
    const [result] = await verify(signed, {});
    expect(result!.status).toMatchObject({ result: 'neutral', comment: 'no key' });
  });

  it('reports a DNS timeout as temperror', async () => {
    const [result] = await verify(signed, { [NAME]: TIMEOUT });
    expect(result!.status.result).toBe('temperror');
  });

  it('reports an unsigned message as none', async () => {
    expect((await verify(Buffer.from(message)))[0]!.status.result).toBe('none');
  });
});

describe('mailauth DMARC discovery', () => {
  it('uses the RFC 9989 tree walk and every query passes our name validation', async () => {
    const resolver = new FixtureResolver({ '_dmarc.acme.example': 'v=DMARC1; p=reject' });
    const record = await getDmarcRecord('news.mail.acme.example', toMailauthResolver(resolver));
    expect(record).toMatchObject({ p: 'reject', recordDomain: 'acme.example' });
    expect(resolver.queries).toEqual([
      '_dmarc.news.mail.acme.example',
      '_dmarc.mail.acme.example',
      '_dmarc.acme.example',
      '_dmarc.example',
    ]);
  });
});
