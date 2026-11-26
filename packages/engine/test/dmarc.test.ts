import type { SignatureEvidence } from '@mailshield/contracts';
import { describe, expect, it } from 'vitest';
import { evaluateDmarc } from '../src/authentication/dmarc.ts';
import { toMailauthResolver } from '../src/dns/mailauth-adapter.ts';
import type { DnsAnswer, DnsResolver } from '../src/dns/resolver.ts';

class ZoneResolver implements DnsResolver {
  readonly queries: string[] = [];
  constructor(private readonly zone: Record<string, string>) {}
  async txt(name: string): Promise<DnsAnswer> {
    this.queries.push(name);
    const value = this.zone[name];
    if (value === 'TIMEOUT') return { status: 'timeout', records: [] };
    return value === undefined
      ? { status: 'nxdomain', records: [] }
      : { status: 'ok', records: [[value]] };
  }
}

const sig = (domain: string, status: SignatureEvidence['status'] = 'pass') =>
  ({ evidenceId: `dkim-${domain}`, domain, status }) as SignatureEvidence;

const run = (fromDomain: string, signatures: SignatureEvidence[], zone: Record<string, string>) => {
  const resolver = new ZoneResolver(zone);
  const promise = evaluateDmarc({
    fromDomain,
    signatures,
    lookup: toMailauthResolver(resolver),
    source: 'local_crypto',
    observedAt: '2026-11-26T00:00:00.000Z',
  });
  return Object.assign(promise, { resolver });
};

const ACME = { '_dmarc.acme.example': 'v=DMARC1; p=reject' };

describe('evaluateDmarc', () => {
  it('passes (DKIM only) when the signing domain equals the From domain', async () => {
    const result = await run('acme.example', [sig('acme.example')], ACME);
    expect(result).toMatchObject({
      status: 'pass',
      details: { policy: 'reject', alignmentMode: 'relaxed', method: 'dkim_only', aligned: true },
    });
  });

  it('aligns a subdomain signature in relaxed mode through the tree walk', async () => {
    const result = await run('acme.example', [sig('mail.acme.example')], ACME);
    expect(result.status).toBe('pass');
    expect(result.details.orgDomain).toBe('acme.example');
  });

  it('does not align a subdomain signature in strict mode', async () => {
    const zone = { '_dmarc.acme.example': 'v=DMARC1; p=reject; adkim=s' };
    const result = await run('acme.example', [sig('mail.acme.example')], zone);
    expect(result).toMatchObject({ status: 'unknown', details: { alignmentMode: 'strict' } });
  });

  it('never aligns a lookalike or a shared-suffix domain', async () => {
    const result = await run('acme.example', [sig('acme.example.net'), sig('аcme.example')], ACME);
    expect(result).toMatchObject({ status: 'unknown', details: { aligned: false } });
  });

  it('ignores signatures that did not pass', async () => {
    const result = await run('acme.example', [sig('acme.example', 'fail')], ACME);
    expect(result.status).toBe('unknown');
  });

  it('reports a missing policy without calling it a failure', async () => {
    const result = await run('initech.example', [sig('initech.example')], {});
    expect(result).toMatchObject({ status: 'missing', details: { aligned: true, policy: null } });
  });

  it('reports a DNS timeout as a temporary error', async () => {
    const result = await run('acme.example', [], { '_dmarc.acme.example': 'TIMEOUT' });
    expect(result.status).toBe('temporary_error');
  });

  it('queries only _dmarc TXT names', async () => {
    const promise = run('news.acme.example', [sig('other.example')], ACME);
    await promise;
    expect(promise.resolver.queries.every((q) => q.startsWith('_dmarc.'))).toBe(true);
  });

  it('needs a From domain', async () => {
    expect((await run('', [], ACME)).status).toBe('unknown');
  });
});
