import { MAX_MESSAGE_BYTES } from '@mailshield/contracts';
import { describe, expect, it, vi } from 'vitest';
import {
  createGmailClient,
  decodeBase64Url,
  GMAIL_API,
  type TokenSource,
} from '../src/background/gmail.ts';
import { base64Url, fakeFetch, GMAIL_FIXTURE, json } from './support.ts';

const ID = '18c0ffee12345678';

function tokens(...values: string[]): TokenSource & { dropped: string[] } {
  const queue = [...values];
  const dropped: string[] = [];
  return {
    dropped,
    get: vi.fn(async () => queue[0] ?? 'none'),
    drop: vi.fn(async (t: string) => {
      dropped.push(t);
      queue.shift();
    }),
  };
}

const metadataBody = {
  id: ID,
  sizeEstimate: 2048,
  payload: {
    headers: [
      { name: 'From', value: 'Acme Billing <Billing@Acme.example>' },
      { name: 'Subject', value: 'Invoice 42' },
      { name: 'Date', value: 'Fri, 27 Nov 2026 09:00:00 +0000' },
    ],
  },
};

describe('decodeBase64Url', () => {
  it('returns the exact original bytes, including - and _ characters', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf, 0x00, 0x0d, 0x0a, 0x3e, 0x3f]);
    expect(base64Url(bytes)).toMatch(/[-_]/);
    expect(decodeBase64Url(base64Url(bytes))).toEqual(bytes);
    expect(decodeBase64Url(base64Url(GMAIL_FIXTURE))).toEqual(new Uint8Array(GMAIL_FIXTURE));
  });

  it('rejects text that is not base64url', () => {
    expect(() => decodeBase64Url('abc+/')).toThrow(/base64url/);
  });
});

describe('Gmail client', () => {
  it('reads From, Subject and Date from metadata', async () => {
    const { fetch, requests } = fakeFetch([[GMAIL_API, () => json(metadataBody)]]);
    const gmail = createGmailClient({ fetch, tokens: tokens('t1') });
    expect(await gmail.metadata(ID)).toEqual({
      id: ID,
      from: 'Acme Billing <Billing@Acme.example>',
      fromAddress: 'billing@acme.example',
      subject: 'Invoice 42',
      date: 'Fri, 27 Nov 2026 09:00:00 +0000',
      sizeEstimate: 2048,
    });
    expect(requests[0]!.url).toContain(`/messages/${ID}?format=metadata`);
  });

  it('drops a rejected token and retries once', async () => {
    let calls = 0;
    const { fetch, requests } = fakeFetch([
      [GMAIL_API, () => (++calls === 1 ? json({}, 401) : json(metadataBody))],
    ]);
    const source = tokens('old', 'fresh');
    await createGmailClient({ fetch, tokens: source }).metadata(ID);
    expect(source.dropped).toEqual(['old']);
    expect(requests.map((r) => r.headers.authorization)).toEqual(['Bearer old', 'Bearer fresh']);
  });

  it('asks to connect again when the fresh token is rejected too', async () => {
    const { fetch } = fakeFetch([[GMAIL_API, () => json({}, 401)]]);
    const gmail = createGmailClient({ fetch, tokens: tokens('a', 'b') });
    await expect(gmail.metadata(ID)).rejects.toMatchObject({ code: 'not_connected' });
  });

  it.each([
    [403, 'gmail_forbidden'],
    [404, 'message_not_found'],
    [429, 'gmail_rate_limited'],
    [500, 'gmail_error'],
  ])('explains HTTP %i as %s', async (status, code) => {
    const { fetch } = fakeFetch([[GMAIL_API, () => json({}, status)]]);
    const gmail = createGmailClient({ fetch, tokens: tokens('t') });
    await expect(gmail.metadata(ID)).rejects.toMatchObject({ code });
  });

  it('refuses an id that is not a Gmail id, without any request', async () => {
    const { fetch, requests } = fakeFetch([]);
    const gmail = createGmailClient({ fetch, tokens: tokens('t') });
    await expect(gmail.raw('../../labels')).rejects.toMatchObject({ code: 'invalid_id' });
    expect(requests).toEqual([]);
  });

  it('refuses a raw message over 10 MiB', async () => {
    const big = base64Url(new Uint8Array(MAX_MESSAGE_BYTES + 1));
    const { fetch } = fakeFetch([[GMAIL_API, () => json({ id: ID, raw: big })]]);
    const gmail = createGmailClient({ fetch, tokens: tokens('t') });
    await expect(gmail.raw(ID)).rejects.toMatchObject({ code: 'input_too_large' });
  });

  it('lists at most 25 recent messages for the picker', async () => {
    const { fetch, requests } = fakeFetch([
      [`${GMAIL_API}/messages?`, () => json({ messages: [{ id: ID }] })],
      [GMAIL_API, () => json(metadataBody)],
    ]);
    const list = await createGmailClient({ fetch, tokens: tokens('t') }).recent(500);
    expect(requests[0]!.url).toContain('maxResults=25');
    expect(list.map((m) => m.subject)).toEqual(['Invoice 42']);
  });
});
