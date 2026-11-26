import { generateKeyPairSync } from 'node:crypto';
import { AnalysisResult } from '@mailshield/contracts';
import { analyze, AnalysisError } from '@mailshield/engine';
import { describe, expect, it } from 'vitest';
import {
  dkimRecord,
  FixtureResolver,
  listFixtures,
  loadFixture,
  signMessage,
  type FixtureZone,
} from '../src/index.ts';

const NOW = new Date('2026-06-01T12:00:00Z');

const run = (raw: Buffer, zone: FixtureZone = {}, headerOnly = false) =>
  analyze(
    { raw, source: 'fixture', headerOnly },
    { resolver: new FixtureResolver(zone), clock: () => NOW },
  );

const fixture = (id: string) => loadFixture(id)!;
const legit = () => fixture('legit-signed');

describe('labelled fixtures', () => {
  it('include the Phase 1 set', () => {
    expect(listFixtures().map((f) => f.id)).toEqual([
      'body-tampered',
      'dns-timeout',
      'legit-signed',
      'missing-dns-key',
      'unsigned',
    ]);
  });

  it.each(listFixtures().map((f) => f.id))('%s matches its label', async (id) => {
    const { raw, zone, label } = fixture(id);
    const result = await run(raw, zone);

    expect(() => AnalysisResult.parse(result)).not.toThrow();
    expect(result.verdict).toBe(label.expected.verdict);
    expect(result.signatures.map(({ status, failureStage }) => ({ status, failureStage }))).toEqual(
      label.expected.signatures,
    );
  });

  it('does not resolve ids outside the label list', () => {
    expect(loadFixture('../keys/TEST-ONLY-acme-s1')).toBeNull();
  });
});

describe('DKIM evidence', () => {
  it('reports domain, selector, coverage and key fingerprint', async () => {
    const result = await run(legit().raw, legit().zone);
    expect(result.signatures[0]).toMatchObject({
      status: 'pass',
      source: 'lab',
      domain: 'acme.example',
      selector: 's1',
      algorithm: 'rsa-sha256',
      signedHeaders: ['date', 'subject', 'to', 'from'],
      unsignedHeaders: [],
      bodyCoverage: null,
      bodyHash: { matches: true },
      key: { type: 'rsa', bits: 2048, testing: false },
      signedAt: '2026-06-01T10:00:00.000Z',
    });
    expect(result.signatures[0]!.key!.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(result.sender.from).toEqual([
      expect.objectContaining({ displayName: 'Acme Support', domain: 'acme.example' }),
    ]);
  });

  it('marks real analyses as local_crypto', async () => {
    const result = await analyze(
      { raw: legit().raw, source: 'eml_upload' },
      { resolver: new FixtureResolver(legit().zone), clock: () => NOW },
    );
    expect(result.signatures[0]!.source).toBe('local_crypto');
    expect(result.stages.every((s) => !s.simulated)).toBe(true);
  });

  it('flags an important header added after signing as unsigned', async () => {
    const raw = Buffer.concat([Buffer.from('Reply-To: eve@evil.example\r\n'), legit().raw]);
    const [signature] = (await run(raw, legit().zone)).signatures;
    expect(signature).toMatchObject({ status: 'pass', unsignedHeaders: ['reply-to'] });
  });

  it('fails a changed signed header at the signature stage', async () => {
    const raw = Buffer.from(legit().raw.toString().replace('quarterly statement\r', 'URGENT\r'));
    const [signature] = (await run(raw, legit().zone)).signatures;
    expect(signature).toMatchObject({ status: 'fail', failureStage: 'header_signature' });
  });

  it('reports every signature, including ones that cannot be processed', async () => {
    const odd = 'DKIM-Signature: v=1; a=rsa-md5; d=odd.example; s=x; h=from; bh=AAAA; b=BBBB\r\n';
    const raw = Buffer.concat([Buffer.from(odd), legit().raw]);
    const { signatures } = await run(raw, legit().zone);
    expect(signatures.map((s) => [s.domain, s.status])).toEqual([
      ['odd.example', 'unsupported'],
      ['acme.example', 'pass'],
    ]);
  });

  it('shows partial body coverage when l= leaves bytes unsigned', async () => {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const message = 'From: a@acme.example\r\nSubject: x\r\n\r\nSigned part.\r\n';
    const signed = await signMessage(message, {
      domain: 'acme.example',
      selector: 'l1',
      privateKey,
      signTime: NOW,
      headerList: ['From', 'Subject'],
    });
    const zone = { 'l1._domainkey.acme.example': dkimRecord(privateKey) };
    const append = (raw: Buffer) => Buffer.concat([raw, Buffer.from('Added later.\r\n')]);

    // Without l=, appended text breaks the signature.
    expect((await run(append(signed), zone)).signatures[0]!.status).toBe('fail');

    // With l=, it still passes, and the unsigned bytes are reported.
    const limited = await signMessage(message, {
      domain: 'acme.example',
      selector: 'l1',
      privateKey,
      signTime: NOW,
      headerList: ['From', 'Subject'],
      maxBodyLength: 14,
    });
    const [signature] = (await run(append(limited), zone)).signatures;
    expect(signature).toMatchObject({
      status: 'pass',
      tags: { l: '14' },
      bodyCoverage: { signedBytes: 14, unsignedBytes: 14 },
    });
  });
});

describe('pipeline behaviour', () => {
  it('never claims who sent the message, even with a passing signature', async () => {
    const result = await run(legit().raw, legit().zone);
    expect(result).toMatchObject({
      verdict: 'identity_unverified',
      identityStatus: 'unverified',
      riskLevel: 'unknown',
      findings: [],
    });
  });

  it('emits one event per stage and never passes unbuilt stages', async () => {
    const { stages } = await run(legit().raw, legit().zone);
    expect(stages.map((s) => s.stage)).toEqual([
      'intake',
      'parse',
      'dns',
      'dkim',
      'receiver',
      'alignment',
      'smime',
      'identity',
      'registry',
      'rules',
      'verdict',
    ]);
    const status = (name: string) => stages.find((s) => s.stage === name)!.status;
    expect(status('smime')).toBe('not_evaluated');
    expect(status('registry')).toBe('skipped');
    expect(status('receiver')).toBe('skipped');
  });

  it.each([
    ['unsigned', 'warn'],
    ['body-tampered', 'fail'],
    ['dns-timeout', 'error'],
    ['missing-dns-key', 'warn'],
  ])('does not show a passing DKIM stage for %s', async (id, status) => {
    const { raw, zone } = fixture(id);
    const result = await run(raw, zone);
    expect(result.stages.find((s) => s.stage === 'dkim')!.status).toBe(status);
  });

  it('reports missing DKIM as missing', async () => {
    const result = await run(fixture('unsigned').raw);
    const dkim = result.authentication.filter((e) => e.kind === 'dkim');
    expect(dkim).toEqual([expect.objectContaining({ status: 'missing' })]);
  });

  it('checks nothing cryptographic for header-only input', async () => {
    const resolver = new FixtureResolver(legit().zone);
    const result = await analyze(
      { raw: legit().raw, source: 'header_paste', headerOnly: true },
      { resolver, clock: () => NOW },
    );
    expect(resolver.queries).toEqual([]);
    expect(result.signatures[0]!.status).toBe('not_evaluated');
    expect(result.stages.find((s) => s.stage === 'dkim')!.status).toBe('not_evaluated');
  });

  it('treats several From headers as ambiguous', async () => {
    const raw = Buffer.from('From: a@acme.example\r\nFrom: b@evil.example\r\n\r\nHi\r\n');
    expect(await run(raw)).toMatchObject({
      identityStatus: 'ambiguous',
      verdict: 'authentication_concern',
    });
  });

  it.each([
    ['an empty message', Buffer.alloc(0), 'malformed_message'],
    ['text without headers', Buffer.from('just some text\r\n\r\nmore'), 'malformed_message'],
    ['an oversized message', Buffer.alloc(10 * 1024 * 1024 + 1, 'a'), 'input_too_large'],
    [
      'too many header fields',
      Buffer.from(`${'X-A: b\r\n'.repeat(1001)}\r\n`),
      'mime_limits_exceeded',
    ],
    ['deeply nested MIME', nested(40), 'mime_limits_exceeded'],
  ])('rejects %s', async (_name, raw, type) => {
    await expect(run(raw)).rejects.toSatisfy(
      (error) => error instanceof AnalysisError && error.type === type,
    );
  });
});

function nested(depth: number): Buffer {
  let part = 'Content-Type: text/plain\r\n\r\nx\r\n';
  for (let i = 0; i < depth; i++) {
    part = `Content-Type: multipart/mixed; boundary=b${i}\r\n\r\n--b${i}\r\n${part}\r\n--b${i}--\r\n`;
  }
  return Buffer.from(`From: a@acme.example\r\n${part}`);
}
