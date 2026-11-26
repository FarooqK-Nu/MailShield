import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AnalysisResult, MAX_MESSAGE_BYTES, Problem } from '@mailshield/contracts';
import { FixtureResolver, loadFixture } from '@mailshield/lab';
import request from 'supertest';
import { afterAll, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app.ts';
import { readConfig } from '../src/config.ts';
import { dnsWarning } from '../src/dns-check.ts';
import { fileSessionStore, Pairing, type SessionStore } from '../src/middleware/pairing-auth.ts';
import { createLogger } from '../src/middleware/redact-logger.ts';

const config = readConfig({});
const HOST = '127.0.0.1:8787';
const WEB = 'http://127.0.0.1:5173';
const legit = loadFixture('legit-signed')!;

function setup() {
  let saved: string[] = [];
  const store: SessionStore = { load: () => saved, save: (hashes) => void (saved = hashes) };
  const codes: string[] = [];
  const logs: string[] = [];
  // The "live" resolver knows nothing, so fixture mail can only verify through the lab.
  const resolver = new FixtureResolver({});
  const pairing = new Pairing(store, (code) => codes.push(code));
  const app = buildApp({
    config,
    resolver,
    pairing,
    logger: createLogger({ write: (line) => void logs.push(line) }),
    clock: () => new Date(legit.label.now),
  });
  const post = (path: string) =>
    request(app).post(`/api/v1${path}`).set('Host', HOST).set('Origin', WEB);
  const pair = async () => (await post('/pair').send({ code: codes.at(-1) })).body.token as string;
  return { app, post, pair, codes, logs, resolver, saved: () => saved };
}

const upload = (ctx: ReturnType<typeof setup>, token: string, body: Buffer) =>
  ctx
    .post('/analyze')
    .set('Authorization', `Bearer ${token}`)
    .set('Content-Type', 'application/octet-stream')
    .send(body);

describe('DNS settings', () => {
  it('uses the system resolvers unless servers are listed', () => {
    expect(config.dnsServers).toBeUndefined();
    expect(readConfig({ DNS_SERVERS: '192.168.1.1, ::1' }).dnsServers).toEqual([
      '192.168.1.1',
      '::1',
    ]);
    expect(() => readConfig({ DNS_SERVERS: 'dns.example' })).toThrow();
  });

  it.each([
    ['ok', false],
    ['nxdomain', false],
    ['timeout', true],
    ['servfail', true],
  ] as const)('after a %s answer, warns: %s', async (status, warns) => {
    const warning = await dnsWarning({ txt: async () => ({ status, records: [] }) });
    expect(warning !== null).toBe(warns);
  });
});

describe('host and origin guards', () => {
  const { app } = setup();

  it('answers health on an allowed Host', async () => {
    const res = await request(app).get('/api/v1/health').set('Host', HOST);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok', version: '0.1.0' });
  });

  it.each(['evil.example', '127.0.0.1', 'localhost:9999', '127.0.0.1.evil.example:8787'])(
    'rejects Host %s',
    async (host) => {
      const res = await request(app).get('/api/v1/health').set('Host', host);
      expect(res.status).toBe(403);
      expect(Problem.parse(JSON.parse(res.text)).type).toBe('host_rejected');
    },
  );

  it.each(['https://evil.example', 'null', 'chrome-extension://aaaa', `${WEB}.evil.example`])(
    'rejects Origin %s, including preflight',
    async (origin) => {
      for (const method of ['get', 'options', 'post'] as const) {
        const client = request(app);
        const res = await client[method]('/api/v1/analyze').set('Host', HOST).set('Origin', origin);
        expect(res.status).toBe(403);
        expect(res.headers['access-control-allow-origin']).toBeUndefined();
      }
    },
  );

  it('allows preflight from the extension', async () => {
    const res = await request(app)
      .options('/api/v1/analyze')
      .set('Host', HOST)
      .set('Origin', config.extensionOrigin);
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe(config.extensionOrigin);
  });
});

describe('pairing', () => {
  it('exchanges a code once and stores only a hash', async () => {
    const ctx = setup();
    const code = ctx.codes[0]!;
    const first = await ctx.post('/pair').send({ code });
    expect(first.status).toBe(200);
    expect((await ctx.post('/pair').send({ code })).status).toBe(401);
    expect(ctx.saved()).toHaveLength(1);
    expect(ctx.saved()[0]).not.toContain(first.body.token);
    expect(ctx.codes).toHaveLength(2);
  });

  it('replaces the code after five wrong guesses', async () => {
    const ctx = setup();
    const code = ctx.codes[0]!;
    const wrong = code === '00000000' ? '11111111' : '00000000';
    for (let i = 0; i < 5; i++) await ctx.post('/pair').send({ code: wrong });
    expect((await ctx.post('/pair').send({ code })).status).toBe(401);
  });

  it('rate limits guessing', async () => {
    const ctx = setup();
    const statuses = [];
    for (let i = 0; i < 12; i++) {
      statuses.push((await ctx.post('/pair').send({ code: '12345678' })).status);
    }
    expect(statuses.at(-1)).toBe(429);
  });

  it('requires an Origin', async () => {
    const ctx = setup();
    const res = await request(ctx.app)
      .post('/api/v1/pair')
      .set('Host', HOST)
      .send({ code: ctx.codes[0] });
    expect(res.status).toBe(403);
  });

  it('keeps sessions across restarts through the file store', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mailshield-'));
    try {
      const codes: string[] = [];
      const first = new Pairing(fileSessionStore(dir), (c) => codes.push(c));
      const token = first.exchange(codes[0]!)!;
      expect(new Pairing(fileSessionStore(dir), () => {}).isValid(token)).toBe(true);
      expect(readFileSync(join(dir, 'sessions.json'), 'utf8')).not.toContain(token);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('analyze routes', () => {
  const ctx = setup();
  let token = '';
  const ready = async () => (token ||= await ctx.pair());
  afterAll(() => expect(ctx.resolver.queries.every((q) => q.includes('._domainkey.'))).toBe(true));

  it.each(['/analyze', '/analyze/headers', '/lab/demo/legit-signed'])(
    'requires a token for %s',
    async (path) => {
      expect((await ctx.post(path)).status).toBe(401);
      expect((await ctx.post(path).set('Authorization', 'Bearer wrong')).status).toBe(401);
    },
  );

  it('analyzes an upload with the live resolver only (invariant 7)', async () => {
    const res = await upload(ctx, await ready(), legit.raw);
    expect(res.status).toBe(200);
    const result = AnalysisResult.parse(res.body);
    expect(result.inputSource).toBe('eml_upload');
    // The fixture key exists only in fixture DNS, which live analysis cannot reach.
    expect(result.signatures[0]!.status).toBe('missing');
    expect(ctx.resolver.queries).toContain('s1._domainkey.acme.example');
  });

  it('inspects pasted headers without verifying', async () => {
    const res = await ctx
      .post('/analyze/headers')
      .set('Authorization', `Bearer ${await ready()}`)
      .set('Content-Type', 'text/plain')
      .send(legit.raw.toString());
    expect(res.body.signatures[0].status).toBe('not_evaluated');
  });

  it('accepts gmail_api only from the extension', async () => {
    const auth = await ready();
    const fromWeb = await upload(ctx, auth, legit.raw).set('X-MailShield-Source', 'gmail_api');
    expect(fromWeb.status).toBe(400);
    const fromExtension = await upload(ctx, auth, legit.raw)
      .set('Origin', config.extensionOrigin)
      .set('X-MailShield-Source', 'gmail_api');
    expect(fromExtension.status).toBe(200);
  });

  it.each(['fixture', 'lab', 'nonsense'])('refuses the source %s', async (source) => {
    const res = await upload(ctx, await ready(), legit.raw).set('X-MailShield-Source', source);
    expect(res.status).toBe(400);
  });

  it('rejects a body over 10 MiB', async () => {
    const res = await upload(ctx, await ready(), Buffer.alloc(MAX_MESSAGE_BYTES + 1, 'a'));
    expect(res.status).toBe(413);
    expect(JSON.parse(res.text).type).toBe('input_too_large');
  });

  it('returns typed problems for unreadable input', async () => {
    const res = await upload(ctx, await ready(), Buffer.from('not an email'));
    expect(res.status).toBe(422);
    expect(JSON.parse(res.text).type).toBe('malformed_message');
  });

  it('refuses compressed bodies', async () => {
    const res = await upload(ctx, await ready(), legit.raw).set('Content-Encoding', 'gzip');
    expect(res.status).toBe(415);
  });

  it('serves labelled demos through the lab', async () => {
    const auth = await ready();
    const list = await request(ctx.app)
      .get('/api/v1/fixtures')
      .set('Host', HOST)
      .set('Authorization', `Bearer ${auth}`);
    expect(list.body.fixtures).toHaveLength(5);
    const res = await ctx.post('/lab/demo/legit-signed').set('Authorization', `Bearer ${auth}`);
    const result = AnalysisResult.parse(res.body);
    expect(result.inputSource).toBe('fixture');
    expect(result.signatures[0]).toMatchObject({ status: 'pass', source: 'lab' });
    expect(result.stages.every((s) => s.simulated)).toBe(true);
    const unknown = await ctx.post('/lab/demo/nope').set('Authorization', `Bearer ${auth}`);
    expect(unknown.status).toBe(404);
  });
});

describe('logging (invariant 6)', () => {
  it('never records message content, tokens, codes or paths chosen by the caller', async () => {
    const ctx = setup();
    const code = ctx.codes[0]!;
    const token = await ctx.pair();
    const canary = 'CANARY-7f3a';
    const message = Buffer.from(
      `From: ${canary} <${canary}@acme.example>\r\nSubject: ${canary}\r\n\r\n${canary}\r\n`,
    );
    await upload(ctx, token, message);
    await upload(ctx, token, Buffer.from(canary));
    await ctx.post('/pair').set('Content-Type', 'application/json').send(`{"code": ${canary}`);
    await ctx.post(`/${canary}?q=${canary}`).set('Cookie', `a=${canary}`);
    await upload(ctx, canary, message);

    const output = ctx.logs.join('');
    expect(output).toContain('analysis complete');
    expect(output).not.toContain(canary);
    expect(output).not.toContain(token);
    expect(output).not.toContain(code);
  });
});
