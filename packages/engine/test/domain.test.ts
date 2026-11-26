import { describe, expect, it } from 'vitest';
import { analyzeDomain, matchesApproved, sameOrganization } from '../src/identity/domain.ts';

describe('analyzeDomain', () => {
  it('splits at the public-suffix boundary', () => {
    expect(analyzeDomain('Mail.Acme.co.uk.')).toMatchObject({
      ascii: 'mail.acme.co.uk',
      registrable: 'acme.co.uk',
      subdomain: 'mail',
      publicSuffix: 'co.uk',
      label: 'acme',
    });
  });

  it.each([
    ['brand.example.net', 'example.net', 'brand'],
    ['example.com.evil.net', 'evil.net', 'example.com'],
    ['acme.example.net', 'example.net', 'acme'],
  ])('%s registers as %s', (host, registrable, subdomain) => {
    expect(analyzeDomain(host)).toMatchObject({ registrable, subdomain });
  });

  it('keeps Unicode and Punycode forms of an IDN', () => {
    const parts = analyzeDomain('pаypal.example'); // Cyrillic а
    expect(parts.ascii).toMatch(/^xn--/);
    expect(parts.unicode).toBe('pаypal.example');
    expect(parts.isIdn).toBe(true);
    expect(parts.labelUnicode).toBe('pаypal');
  });

  it('treats private suffixes as boundaries (P-4)', () => {
    expect(analyzeDomain('eve.github.io').registrable).toBe('eve.github.io');
  });

  it.each(['192.0.2.1', '', 'a b.example', 'x@y.example', 'example.com/path'])(
    'gives no registrable domain for %j',
    (input) => expect(analyzeDomain(input).registrable).toBeNull(),
  );
});

describe('matchesApproved', () => {
  const exact = { domainAscii: 'acme.example', includeSubdomains: false };
  const withSubs = { domainAscii: 'acme.example', includeSubdomains: true };

  it('matches the exact host in any case', () => {
    expect(matchesApproved('ACME.example.', exact)).toBe(true);
  });

  it('matches subdomains only when the entry allows them', () => {
    expect(matchesApproved('mail.acme.example', exact)).toBe(false);
    expect(matchesApproved('mail.acme.example', withSubs)).toBe(true);
  });

  it.each(['acme.example.net', 'evilacme.example', 'acme.example.evil.net', 'xacme.example'])(
    'never matches %s',
    (host) => expect(matchesApproved(host, withSubs)).toBe(false),
  );

  it('compares IDNs in their ASCII form', () => {
    const idn = { domainAscii: 'bücher.example', includeSubdomains: false };
    expect(matchesApproved('xn--bcher-kva.example', idn)).toBe(true);
  });
});

describe('sameOrganization', () => {
  it('compares registrable domains', () => {
    expect(sameOrganization('mail.acme.example', 'acme.example')).toBe(true);
    expect(sameOrganization('acme.example.net', 'acme.example')).toBe(false);
  });
});
