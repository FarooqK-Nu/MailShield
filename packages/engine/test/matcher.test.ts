import type { Identity } from '@mailshield/contracts';
import { describe, expect, it } from 'vitest';
import { inspectDomain, matchClaim, normalizeName } from '../src/identity/matcher.ts';

const at = '2026-11-26T00:00:00.000Z';
function identity(
  id: string,
  displayName: string,
  domains: string[],
  extra: Partial<Identity> = {},
): Identity {
  return {
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
    aliases: [],
    domains: domains.map((domain, i) => ({
      id: `${id}-d${i}`,
      domainAscii: domain,
      domainUnicode: domain,
      includeSubdomains: true,
      relationship: 'own' as const,
    })),
    addresses: [],
    keys: [],
    ...extra,
  };
}

const acme = identity('acme', 'Acme Corporation', ['acme.example'], {
  aliases: [{ id: 'a1', alias: 'Acme' }],
  addresses: [{ id: 't1', address: 'ceo@acme.example' }],
});
const microsoft = identity('ms', 'Microsoft', ['microsoft.example']);
const globex = identity('globex', 'Globex', ['globex.example']);
const registry = [acme, microsoft, globex];

const claim = (displayName: string, address: string) => ({
  displayName,
  address,
  domain: address.split('@')[1] ?? '',
});

describe('normalizeName', () => {
  it('folds case, width and punctuation', () => {
    expect(normalizeName('  ＡＣＭＥ,  Support!! ')).toBe('acme support');
  });
});

describe('matchClaim', () => {
  it('matches an approved domain and a display name', () => {
    const [top] = matchClaim(claim('Acme', 'news@mail.acme.example'), registry);
    expect(top).toMatchObject({
      identityId: 'acme',
      reasons: ['alias', 'approved_domain'],
      approvedDomain: { domain: 'acme.example', relationship: 'own' },
    });
  });

  it('matches a trusted address', () => {
    const [top] = matchClaim(claim('', 'ceo@acme.example'), registry);
    expect(top!.reasons).toContain('trusted_address');
  });

  it('finds the claimed brand in a display name on an unrelated domain', () => {
    const [top] = matchClaim(claim('Acme Support', 'help@acme-helpdesk.example'), registry);
    expect(top).toMatchObject({ identityId: 'acme', approvedDomain: null });
    expect(top!.reasons).toContain('name_contains');
    expect(top!.reasons).toContain('brand_token');
  });

  it('flags micros0ft-support.example against Microsoft with the differing character', () => {
    const [top] = matchClaim(claim('Support', 'it@micros0ft-support.example'), registry);
    expect(top).toMatchObject({ identityId: 'ms', reasons: ['lookalike_domain'] });
    expect(top!.lookalikes[0]).toMatchObject({
      strength: 'strong',
      matchedToken: 'micros0ft',
      diff: [{ observed: '0', expected: 'o', observedCodePoints: ['U+0030 Common'] }],
    });
  });

  it('flags a Cyrillic а variant with its code point', () => {
    const [top] = matchClaim(claim('Billing', 'billing@аcme.example'), registry);
    expect(top).toMatchObject({ identityId: 'acme', reasons: ['lookalike_domain'] });
    expect(top!.lookalikes[0]!.reasons).toContain('mixed_script');
    expect(top!.lookalikes[0]!.diff[0]).toMatchObject({
      observed: 'а',
      expected: 'a',
      observedCodePoints: ['U+0430 Cyrillic'],
    });
  });

  it('does not treat acme.example.net as acme.example', () => {
    const [top] = matchClaim(claim('', 'x@acme.example.net'), registry);
    expect(top).toMatchObject({ identityId: 'acme', approvedDomain: null });
    expect(top!.reasons).toEqual(['brand_in_subdomain']);
  });

  it('flags a display name written with a confusable letter', () => {
    const [top] = matchClaim(claim('Αcme Support', 'x@unrelated.example'), registry); // Greek Α
    expect(top!.reasons).toEqual(['lookalike_name']);
  });

  it('returns nothing for an unrelated sender', () => {
    expect(matchClaim(claim('Jane Doe', 'jane@initech.example'), registry)).toEqual([]);
  });

  it('skips deleted identities', () => {
    const deleted = { ...acme, deletedAt: at };
    expect(matchClaim(claim('Acme', 'x@acme.example'), [deleted])).toEqual([]);
  });
});

describe('inspectDomain', () => {
  it('shows the registrable boundary and the label code points', () => {
    const result = inspectDomain('from', 'mail.аcme.example');
    expect(result).toMatchObject({
      registrableUnicode: 'аcme.example',
      subdomain: 'mail',
      isIdn: true,
      mixedScript: true,
    });
    expect(result.codePoints.map((c) => c.codePoint)).toEqual([
      'U+0430',
      'U+0063',
      'U+006D',
      'U+0065',
    ]);
  });
});
