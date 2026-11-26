import { describe, expect, it } from 'vitest';
import {
  headerValues,
  LiveResolver,
  parseMailboxes,
  readRawHeaders,
  readSender,
  toMailauthResolver,
  validateAuthName,
  type DnsResolver,
} from '../src/index.ts';

describe('readRawHeaders', () => {
  const raw = Buffer.from(
    'Received: one\r\nReceived: two\r\n continued\r\nSubject : hi\r\nnot a header\r\n\r\nbody: no\r\n',
  );
  const headers = readRawHeaders(raw);

  it('keeps every occurrence in order, unfolded', () => {
    expect(headerValues(headers, 'received')).toEqual(['one', 'two continued']);
    expect(headerValues(headers, 'subject')).toEqual(['hi']);
  });

  it('records offsets, the body start and malformed lines without touching the bytes', () => {
    expect(headers.fields[1]!.offset).toBe(raw.indexOf('Received: two'));
    expect(raw.toString('utf8', headers.bodyOffset!)).toBe('body: no\r\n');
    expect(headers.malformedLines).toBe(1);
    expect(headerValues(headers, 'body')).toEqual([]);
  });

  it('accepts bare LF line endings', () => {
    expect(headerValues(readRawHeaders(Buffer.from('From: a@b.example\n\nx')), 'from')).toEqual([
      'a@b.example',
    ]);
  });
});

describe('addresses', () => {
  it('decodes encoded words without letting them add recipients', () => {
    // "Acme, Support" encoded: the comma must stay inside one display name.
    const [mailbox, ...rest] = parseMailboxes(
      '=?utf-8?B?QWNtZSwgU3VwcG9ydA==?= <support@acme.example>',
    );
    expect(rest).toEqual([]);
    expect(mailbox).toMatchObject({ displayName: 'Acme, Support', domain: 'acme.example' });
  });

  it('keeps both forms of an internationalised domain', () => {
    expect(parseMailboxes('x@pаypal.com')[0]).toMatchObject({
      domain: expect.stringMatching(/^xn--/),
      domainUnicode: 'pаypal.com',
    });
  });

  it.each([
    'To: a@b.example',
    'From: a@b.example, c@d.example',
    'From: a@b.example\r\nFrom: a@b.example',
    'From: Acme Support',
  ])('marks %s as ambiguous', (header) => {
    expect(readSender(readRawHeaders(Buffer.from(`${header}\r\n\r\n`))).fromAmbiguous).toBe(true);
  });
});

describe('DNS limits', () => {
  it('stops waiting at the per-message deadline', async () => {
    const hang: DnsResolver = { txt: () => new Promise(() => {}) };
    const resolve = toMailauthResolver(hang, { deadlineMs: 50 });
    await expect(resolve('_dmarc.acme.example', 'TXT')).rejects.toMatchObject({ code: 'ETIMEOUT' });
    await expect(resolve('_dmarc.acme.example', 'TXT')).rejects.toMatchObject({ code: 'ETIMEOUT' });
  });

  it('does not cache timeouts', async () => {
    const resolver = new LiveResolver({ timeoutMs: 50, tries: 1, servers: ['127.0.0.1:9'] });
    const name = validateAuthName('_dmarc.acme.example')!;
    expect((await resolver.txt(name)).cached).toBeUndefined();
    expect((await resolver.txt(name)).cached).toBeUndefined();
  });
});
