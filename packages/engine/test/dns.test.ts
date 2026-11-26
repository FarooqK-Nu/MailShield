import { createSocket } from 'node:dgram';
import { once } from 'node:events';
import { describe, expect, it } from 'vitest';
import {
  LiveResolver,
  toMailauthResolver,
  validateAuthName,
  type DnsResolver,
} from '../src/index.ts';

describe('validateAuthName', () => {
  it.each([
    's1._domainkey.acme.example',
    'a.b._domainkey.mail.acme.example',
    '_dmarc.acme.example',
    '_dmarc.com',
  ])('accepts %s', (name) => expect(validateAuthName(name)).toBe(name));

  it.each([
    'acme.example',
    'localhost',
    '127.0.0.1',
    '_domainkey.acme.example',
    's1._domainkey.localhost',
    's1._domainkey.127.0.0.1',
    '_dmarc.',
    's1._domainkey.acme.example/path',
    'a b._domainkey.acme.example',
    `${'a'.repeat(64)}._domainkey.acme.example`,
  ])('rejects %s', (name) => expect(validateAuthName(name)).toBeNull());
});

describe('toMailauthResolver', () => {
  const ok: DnsResolver = { txt: async () => ({ status: 'ok', records: [['x']] }) };

  it('refuses other names and record types', async () => {
    const resolve = toMailauthResolver(ok);
    await expect(resolve('internal.host', 'TXT')).rejects.toMatchObject({ code: 'EBADNAME' });
    await expect(resolve('_dmarc.acme.example', 'A')).rejects.toMatchObject({ code: 'EBADNAME' });
  });

  it('enforces the lookup budget', async () => {
    const resolve = toMailauthResolver(ok, { budget: 1 });
    await resolve('_dmarc.acme.example', 'TXT');
    await expect(resolve('_dmarc.acme.example', 'TXT')).rejects.toMatchObject({ code: 'EBUDGET' });
  });
});

describe('LiveResolver', () => {
  it('returns timeout within the deadline when the server never answers', async () => {
    const silent = createSocket('udp4');
    silent.bind(0, '127.0.0.1');
    await once(silent, 'listening');
    try {
      const resolver = new LiveResolver({
        timeoutMs: 200,
        tries: 2,
        servers: [`127.0.0.1:${silent.address().port}`],
      });
      const started = Date.now();
      const answer = await resolver.txt(validateAuthName('_dmarc.acme.example')!);
      expect(answer.status).toBe('timeout');
      expect(Date.now() - started).toBeLessThan(1500);
    } finally {
      silent.close();
    }
  });
});
