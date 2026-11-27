/**
 * The Gmail OAuth token never reaches the local service (docs/context.md §7, threat model).
 * The whole live flow runs against a recording fetch; every request is inspected.
 */
import { describe, expect, it } from 'vitest';
import { analyzeGmailMessage, type FlowStep } from '../src/background/flow.ts';
import { createGmailClient, GMAIL_API, type TokenSource } from '../src/background/gmail.ts';
import { createServiceClient } from '../src/background/service.ts';
import { base64Url, fakeFetch, GMAIL_FIXTURE, json, realResult, type Recorded } from './support.ts';

const ID = '18c0ffee12345678';
const OAUTH = 'ya29.OAUTH-TOKEN-must-stay-in-the-extension';
const SESSION = 'pairing-session-token-0123456789abcdef0123';
const SERVICE = 'http://127.0.0.1:8787';

const tokens: TokenSource = { get: async () => OAUTH, drop: async () => {} };

function setup(options: { sizeEstimate?: number; answerFor?: string } = {}) {
  const { fetch, requests } = fakeFetch([
    [
      `${GMAIL_API}/messages/${ID}?format=metadata`,
      () =>
        json({
          id: ID,
          sizeEstimate: options.sizeEstimate ?? GMAIL_FIXTURE.length,
          payload: { headers: [] },
        }),
    ],
    [
      `${GMAIL_API}/messages/${ID}?format=raw`,
      () => json({ id: ID, raw: base64Url(GMAIL_FIXTURE) }),
    ],
    [`${SERVICE}/api/v1/analyze`, async () => json(await realResult(options.answerFor ?? ID))],
  ]);
  const gmail = createGmailClient({ fetch, tokens });
  const service = createServiceClient({
    fetch,
    baseUrl: SERVICE,
    sessionToken: async () => SESSION,
  });
  return { gmail, service, requests };
}

const text = (r: Recorded) =>
  [
    r.url,
    ...Object.values(r.headers),
    typeof r.body === 'string' ? r.body : r.body ? Buffer.from(r.body).toString('latin1') : '',
  ].join('\n');

describe('token network test', () => {
  it('sends the OAuth token only to the Gmail API, and only bytes to the service', async () => {
    const { gmail, service, requests } = setup();
    const steps: FlowStep[] = [];
    const result = await analyzeGmailMessage(ID, gmail, service, (s) => steps.push(s));

    expect(result.messageRef).toBe(ID);
    expect(steps).toEqual(['checking_size', 'fetching_raw', 'sending', 'analyzing']);
    expect(requests.map((r) => `${r.method} ${new URL(r.url).host}`)).toEqual([
      'GET gmail.googleapis.com',
      'GET gmail.googleapis.com',
      'POST 127.0.0.1:8787',
    ]);

    for (const r of requests) {
      const toGmail = new URL(r.url).origin === 'https://gmail.googleapis.com';
      // The OAuth token appears nowhere except in Gmail requests' Authorization header.
      if (!toGmail) expect(text(r)).not.toContain(OAUTH);
      else {
        expect(r.headers.authorization).toBe(`Bearer ${OAUTH}`);
        expect(text(r)).not.toContain(SESSION);
      }
    }

    const post = requests[2]!;
    expect(post.headers).toEqual({
      authorization: `Bearer ${SESSION}`,
      'content-type': 'application/octet-stream',
      'x-mailshield-source': 'gmail_api',
      'x-mailshield-message-ref': ID,
    });
    // The service receives exactly the original bytes (invariant 1).
    expect(Buffer.from(post.body as Uint8Array).equals(GMAIL_FIXTURE)).toBe(true);
  });

  it('fetches nothing more when Gmail reports a message over 10 MiB', async () => {
    const { gmail, service, requests } = setup({ sizeEstimate: 11 * 1024 * 1024 });
    await expect(analyzeGmailMessage(ID, gmail, service)).rejects.toMatchObject({
      code: 'input_too_large',
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]!.url).toContain('format=metadata');
  });

  it('refuses an answer that belongs to another message', async () => {
    const { gmail, service } = setup({ answerFor: 'ffffffffffffffff' });
    await expect(analyzeGmailMessage(ID, gmail, service)).rejects.toMatchObject({
      code: 'stale_result',
    });
  });

  it('cannot analyze without pairing, and does not call the service', async () => {
    const { fetch, requests } = fakeFetch([]);
    const service = createServiceClient({
      fetch,
      baseUrl: SERVICE,
      sessionToken: async () => null,
    });
    await expect(
      service.analyze(new Uint8Array([1]), { source: 'eml_upload' }),
    ).rejects.toMatchObject({ code: 'unauthorized' });
    expect(requests).toEqual([]);
  });

  it('turns a problem+json reply into a typed error', async () => {
    const { fetch } = fakeFetch([
      [
        SERVICE,
        () => json({ type: 'origin_rejected', status: 403, title: 'Origin not allowed' }, 403),
      ],
    ]);
    const service = createServiceClient({
      fetch,
      baseUrl: SERVICE,
      sessionToken: async () => SESSION,
    });
    await expect(
      service.analyze(new Uint8Array([1]), { source: 'eml_upload' }),
    ).rejects.toMatchObject({ code: 'origin_rejected' });
  });
});
