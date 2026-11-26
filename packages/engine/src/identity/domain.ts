import { domainToASCII, domainToUnicode } from 'node:url';
import { parse } from 'tldts';

/** One domain in both forms, split at its public-suffix boundary. */
export interface DomainParts {
  /** Exactly as given. */
  input: string;
  /** ASCII (Punycode) hostname, lower case; empty when the input is not a usable domain. */
  ascii: string;
  unicode: string;
  /** Registrable domain (ASCII), e.g. `acme.co.uk`. Null for IPs, bare suffixes and junk. */
  registrable: string | null;
  registrableUnicode: string | null;
  /** Labels left of the registrable domain, e.g. `mail` in `mail.acme.co.uk`. */
  subdomain: string;
  publicSuffix: string | null;
  /** Registrable domain without its public suffix, e.g. `acme`. */
  label: string | null;
  labelUnicode: string | null;
  isIdn: boolean;
  isIp: boolean;
}

/** Hostname written by a person or a header, normalized to lower-case ASCII; '' if unusable. */
export function toAsciiHost(value: string): string {
  const trimmed = value.trim().replace(/\.$/, '').toLowerCase();
  // domainToASCII() reads its input as a URL host, so refuse URL delimiters first.
  if (!trimmed || /[\s/\\?#@:%[\]]/.test(trimmed)) return '';
  return domainToASCII(trimmed);
}

export function analyzeDomain(input: string): DomainParts {
  const ascii = toAsciiHost(input);
  // Private suffixes count as boundaries, so two github.io users are different domains (P-4).
  const parsed = ascii ? parse(ascii, { allowPrivateDomains: true }) : null;
  const isIp = parsed?.isIp ?? false;
  const registrable = !isIp && parsed?.domain ? parsed.domain : null;
  const publicSuffix = parsed?.publicSuffix ?? null;
  const label =
    registrable && publicSuffix ? registrable.slice(0, -(publicSuffix.length + 1)) : null;
  return {
    input,
    ascii,
    unicode: ascii ? domainToUnicode(ascii) : '',
    registrable,
    registrableUnicode: registrable ? domainToUnicode(registrable) : null,
    subdomain: registrable ? (parsed?.subdomain ?? '') : '',
    publicSuffix,
    label,
    labelUnicode: label ? domainToUnicode(label) : null,
    isIdn: ascii.split('.').some((l) => l.startsWith('xn--')),
    isIp,
  };
}

export interface ApprovedDomainRule {
  domainAscii: string;
  includeSubdomains: boolean;
}

/**
 * The exact approved host always matches; a subdomain matches only at a label boundary and
 * only when the entry allows subdomains. `acme.example.net` never matches `acme.example`.
 */
export function matchesApproved(host: string, approved: ApprovedDomainRule): boolean {
  const ascii = toAsciiHost(host);
  const target = toAsciiHost(approved.domainAscii);
  if (!ascii || !target) return false;
  if (ascii === target) return true;
  return approved.includeSubdomains && ascii.endsWith(`.${target}`);
}

/** Same registrable domain (DMARC relaxed alignment). */
export function sameOrganization(a: string, b: string): boolean {
  const left = analyzeDomain(a).registrable;
  return left !== null && left === analyzeDomain(b).registrable;
}
