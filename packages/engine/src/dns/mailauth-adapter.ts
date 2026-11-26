import { validateAuthName } from './name.ts';
import type { DnsResolver, DnsStatus } from './resolver.ts';

const ERROR_CODES: Record<Exclude<DnsStatus, 'ok'>, string> = {
  nxdomain: 'ENOTFOUND',
  nodata: 'ENODATA',
  timeout: 'ETIMEOUT',
  servfail: 'ESERVFAIL',
};

function dnsError(code: string): Error {
  return Object.assign(new Error(`DNS ${code}`), { code });
}

/**
 * Wraps our resolver in mailauth's `(name, rrtype)` signature. Every query is validated and
 * counted against a per-message budget. Create one adapter per analysis.
 */
export function toMailauthResolver(resolver: DnsResolver, { budget = 20 } = {}) {
  let used = 0;
  return async (name: string, rrtype: string): Promise<string[][]> => {
    const safe = validateAuthName(name);
    if (!safe || rrtype !== 'TXT') throw dnsError('EBADNAME');
    if (++used > budget) throw dnsError('EBUDGET');
    const answer = await resolver.txt(safe);
    if (answer.status !== 'ok') throw dnsError(ERROR_CODES[answer.status]);
    return answer.records;
  };
}
