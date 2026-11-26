import { dkimVerify } from 'mailauth/lib/dkim/verify';
import { toMailauthResolver, type AdapterOptions } from '../dns/mailauth-adapter.ts';
import type { DnsResolver } from '../dns/resolver.ts';

/**
 * Library output for every DKIM signature in the original bytes. dkim.ts maps this into
 * SignatureEvidence; do not show these statuses to users directly (docs/spikes.md).
 */
export function rawDkimVerify(
  raw: Buffer,
  deps: { resolver: DnsResolver; now?: Date; dns?: AdapterOptions },
) {
  return dkimVerify(raw, {
    resolver: toMailauthResolver(deps.resolver, deps.dns),
    rejectRsaSha1: true,
    curTime: deps.now,
  });
}
