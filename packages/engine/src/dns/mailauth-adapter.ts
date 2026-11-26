import { validateAuthName, type ValidatedDnsName } from './name.ts';
import type { DnsAnswer, DnsResolver, DnsStatus } from './resolver.ts';

const ERROR_CODES: Record<Exclude<DnsStatus, 'ok'>, string> = {
  nxdomain: 'ENOTFOUND',
  nodata: 'ENODATA',
  timeout: 'ETIMEOUT',
  servfail: 'ESERVFAIL',
};

function dnsError(code: string): Error {
  return Object.assign(new Error(`DNS ${code}`), { code });
}

export interface DnsLookup {
  name: string;
  status: DnsStatus;
  cached: boolean;
  durationMs: number;
}

export interface AdapterOptions {
  /** Maximum lookups per message. */
  budget?: number;
  /** Total time allowed for all lookups of one message. */
  deadlineMs?: number;
  onLookup?: (lookup: DnsLookup) => void;
}

async function within(
  resolver: DnsResolver,
  name: ValidatedDnsName,
  ms: number,
): Promise<DnsAnswer> {
  if (ms <= 0) return { status: 'timeout', records: [] };
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<DnsAnswer>((resolve) => {
    timer = setTimeout(() => resolve({ status: 'timeout', records: [] }), ms);
  });
  try {
    return await Promise.race([resolver.txt(name), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export type MailauthResolver = (name: string, rrtype: string) => Promise<string[][]>;

/**
 * Wraps our resolver in mailauth's `(name, rrtype)` signature. Every query is validated,
 * counted against a budget and bounded in time. Create one adapter per analysis.
 */
export function toMailauthResolver(
  resolver: DnsResolver,
  options: AdapterOptions = {},
): MailauthResolver {
  const { budget = 20, deadlineMs = 10_000, onLookup } = options;
  let used = 0;
  let deadline: number | undefined;
  return async (name: string, rrtype: string): Promise<string[][]> => {
    const safe = validateAuthName(name);
    if (!safe || rrtype !== 'TXT') throw dnsError('EBADNAME');
    if (++used > budget) throw dnsError('EBUDGET');

    const started = performance.now();
    deadline ??= started + deadlineMs;
    const answer = await within(resolver, safe, deadline - started);
    onLookup?.({
      name: safe,
      status: answer.status,
      cached: answer.cached ?? false,
      durationMs: Math.round(performance.now() - started),
    });
    if (answer.status !== 'ok') throw dnsError(ERROR_CODES[answer.status]);
    return answer.records;
  };
}
