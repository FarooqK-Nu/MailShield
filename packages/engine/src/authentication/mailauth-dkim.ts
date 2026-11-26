import { dkimVerify } from 'mailauth/lib/dkim/verify';
import { toMailauthResolver } from '../dns/mailauth-adapter.ts';
import type { DnsResolver } from '../dns/resolver.ts';

/**
 * Library output for every DKIM signature in the original bytes. Phase 1 maps this into our
 * SignatureEvidence type; do not show these statuses to users directly (docs/spikes.md).
 */
export function rawDkimVerify(raw: Buffer, deps: { resolver: DnsResolver; now?: Date }) {
  return dkimVerify(raw, {
    resolver: toMailauthResolver(deps.resolver),
    rejectRsaSha1: true,
    curTime: deps.now,
  });
}
