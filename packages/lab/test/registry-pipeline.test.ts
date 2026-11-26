/** Phase 2 exit criteria through the whole pipeline, with real signatures and fixture DNS. */
import { generateKeyPairSync } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { AnalysisResult, type Identity } from '@mailshield/contracts';
import { analyze, type RegistryPort } from '@mailshield/engine';
import { describe, expect, it } from 'vitest';
import { dkimRecord, FixtureResolver, signMessage } from '../src/index.ts';

const NOW = new Date('2026-06-01T12:00:00Z');
const { privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const at = NOW.toISOString();
const org = (
  id: string,
  displayName: string,
  domain: string,
  aliases: string[] = [],
): Identity => ({
  id,
  kind: 'organization',
  displayName,
  trustState: 'user_trusted',
  provenanceUrl: null,
  notes: null,
  lastReviewed: null,
  createdAt: at,
  updatedAt: at,
  deletedAt: null,
  aliases: aliases.map((alias, i) => ({ id: `${id}-a${i}`, alias })),
  domains: [
    {
      id: `${id}-d`,
      domainAscii: domain,
      domainUnicode: domain,
      includeSubdomains: true,
      relationship: 'own',
    },
  ],
  addresses: [],
  keys: [],
});
const registry: RegistryPort = {
  identities: async () => [
    org('acme', 'Acme Corporation', 'acme.example', ['Acme', 'Acme Support']),
    org('ms', 'Microsoft', 'microsoft.example'),
  ],
};

/** A message signed by its own domain, so DKIM passes and aligns. */
async function selfSigned(fromName: string, domain: string, extraHeaders = '') {
  const ascii = domainToASCII(domain);
  const message =
    `${extraHeaders}From: ${fromName} <billing@${ascii}>\r\nTo: you@example.org\r\n` +
    `Subject: Invoice\r\nDate: Mon, 01 Jun 2026 12:00:00 +0000\r\n\r\nHello.\r\n`;
  const raw = await signMessage(message, {
    domain: ascii,
    selector: 's1',
    privateKey,
    signTime: NOW,
  });
  const zone = {
    [`s1._domainkey.${ascii}`]: dkimRecord(privateKey),
    [`_dmarc.${ascii}`]: 'v=DMARC1; p=reject',
  };
  return { raw, zone };
}

async function run(fromName: string, domain: string, extraHeaders = '') {
  const { raw, zone } = await selfSigned(fromName, domain, extraHeaders);
  const result = await analyze(
    { raw, source: 'eml_upload' },
    { resolver: new FixtureResolver(zone), registry, clock: () => NOW },
  );
  expect(() => AnalysisResult.parse(result)).not.toThrow();
  return result;
}

describe('registry and domain analysis in the pipeline', () => {
  it('corroborates the approved domain, with DKIM-only DMARC passing', async () => {
    const result = await run('Acme', 'acme.example');
    expect(result.signatures[0]!.status).toBe('pass');
    expect(result.authentication.find((e) => e.kind === 'dmarc')).toMatchObject({
      status: 'pass',
      details: { method: 'dkim_only', discovery: 'rfc9989_tree_walk' },
    });
    expect(result.candidates[0]).toMatchObject({
      identityId: 'acme',
      approvedDomain: { domain: 'acme.example' },
    });
    expect(result.stages.find((s) => s.stage === 'registry')!.status).toBe('pass');
  });

  it('flags micros0ft-support.example even though its own DKIM passes', async () => {
    const result = await run('Support', 'micros0ft-support.example');
    expect(result.signatures[0]!.status).toBe('pass');
    const [top] = result.candidates;
    expect(top).toMatchObject({ identityId: 'ms', approvedDomain: null });
    expect(top!.lookalikes[0]!.diff).toMatchObject([
      { observed: '0', expected: 'o', observedCodePoints: ['U+0030 Common'] },
    ]);
    expect(result.stages.find((s) => s.stage === 'registry')!.status).toBe('warn');
  });

  it('flags the Cyrillic а variant and shows the code point', async () => {
    const result = await run('Acme', 'аcme.example');
    const [top] = result.candidates;
    expect(top).toMatchObject({ identityId: 'acme', approvedDomain: null });
    expect(top!.reasons).toContain('lookalike_domain');
    expect(top!.lookalikes[0]!.diff[0]!.observedCodePoints).toEqual(['U+0430 Cyrillic']);
    const from = result.domains.find((d) => d.role === 'from')!;
    expect(from).toMatchObject({ isIdn: true, mixedScript: true });
    expect(from.codePoints[0]).toMatchObject({ codePoint: 'U+0430', looksLike: 'a' });
  });

  it('does not treat acme.example.net as acme.example', async () => {
    const result = await run('Acme Support', 'acme.example.net');
    const [top] = result.candidates;
    expect(top).toMatchObject({ identityId: 'acme', approvedDomain: null });
    expect(top!.reasons).toContain('brand_in_subdomain');
    expect(result.domains.find((d) => d.role === 'from')!.registrable).toBe('example.net');
  });

  it('shows a forged Authentication-Results in an upload as untrusted_header', async () => {
    const forged = 'Authentication-Results: mx.google.com; dkim=pass; dmarc=pass\r\n';
    const result = await run('Acme', 'acme.example.net', forged);
    const receiver = result.authentication.filter((e) => e.kind === 'receiver');
    expect(receiver).toEqual([
      expect.objectContaining({ source: 'untrusted_header', status: 'untrusted' }),
    ]);
    expect(result.authentication.some((e) => e.source === 'trusted_receiver')).toBe(false);
  });
});
