import { domainToASCII } from 'node:url';

declare const validated: unique symbol;
/** A DNS name that passed validateAuthName(). Resolvers accept nothing else. */
export type ValidatedDnsName = string & { [validated]: true };

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const SELECTOR_LABEL = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

function isDomain(labels: string[], minLabels: number): boolean {
  const last = labels.at(-1) ?? '';
  // An all-numeric last label means an IP address, not a domain.
  return labels.length >= minLabels && labels.every((l) => LABEL.test(l)) && !/^\d+$/.test(last);
}

/**
 * Accepts only DKIM key names and DMARC policy names. SPF target names are added with the
 * fixture-only SPF work. Returns null for anything else.
 */
export function validateAuthName(name: string): ValidatedDnsName | null {
  // domainToASCII() reads its input as a URL host, so reject URL delimiters first.
  if (/[\s/\\?#@:%[\]]/.test(name)) return null;
  const labels = name.replace(/\.$/, '').toLowerCase().split('.');
  const ascii = labels.map((l) => (/^[\x21-\x7e]*$/.test(l) ? l : domainToASCII(l)));
  if (ascii.some((l) => !l) || ascii.join('.').length > 253) return null;
  const joined = ascii.join('.') as ValidatedDnsName;

  // The RFC 9989 tree walk goes up to the TLD (`_dmarc.com`), so one label is allowed here.
  if (ascii[0] === '_dmarc') return isDomain(ascii.slice(1), 1) ? joined : null;

  const at = ascii.lastIndexOf('_domainkey');
  if (at < 1) return null;
  const selectorOk = ascii.slice(0, at).every((l) => SELECTOR_LABEL.test(l));
  return selectorOk && isDomain(ascii.slice(at + 1), 2) ? joined : null;
}
