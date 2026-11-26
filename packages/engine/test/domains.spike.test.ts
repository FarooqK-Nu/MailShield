/** Phase 0 spike: public-suffix boundaries, IDNA forms and the UTS #39 data file. */
import { readFileSync } from 'node:fs';
import { domainToASCII, domainToUnicode } from 'node:url';
import { parse } from 'tldts';
import { describe, expect, it } from 'vitest';

describe('tldts boundaries', () => {
  it.each([
    ['brand.example.net', 'example.net'],
    ['example.com.evil.net', 'evil.net'],
    ['mail.acme.co.uk', 'acme.co.uk'],
  ])('%s registers as %s', (host, domain) => expect(parse(host).domain).toBe(domain));

  it('treats private suffixes as boundaries only when asked', () => {
    expect(parse('eve.github.io').domain).toBe('github.io');
    expect(parse('eve.github.io', { allowPrivateDomains: true }).domain).toBe('eve.github.io');
  });
});

describe('IDNA', () => {
  it('round-trips a Cyrillic lookalike', () => {
    const lookalike = 'pаypal.com';
    expect(domainToASCII(lookalike)).toMatch(/^xn--/);
    expect(domainToUnicode(domainToASCII(lookalike))).toBe(lookalike);
  });
});

describe('confusables.txt', () => {
  const text = readFileSync(new URL('../data/confusables.txt', import.meta.url), 'utf8');

  it('declares its version and maps Cyrillic a to Latin a', () => {
    expect(text).toMatch(/^# Version: \d+\.\d+\.\d+/m);
    expect(text).toMatch(/^0430 ;\s*0061 ;/m);
  });
});
