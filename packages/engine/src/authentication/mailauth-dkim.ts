import { dkimVerify } from 'mailauth/lib/dkim/verify';
import {
  toMailauthResolver,
  type AdapterOptions,
  type MailauthResolver,
} from '../dns/mailauth-adapter.ts';
import type { DnsResolver } from '../dns/resolver.ts';

/**
 * Library output for every DKIM signature in the original bytes. dkim.ts maps this into
 * SignatureEvidence; do not show these statuses to users directly (docs/spikes.md).
 * Pass `lookup` to share one DNS budget with other checks of the same message.
 */
export function rawDkimVerify(
  raw: Buffer,
  deps: { resolver: DnsResolver; now?: Date; dns?: AdapterOptions; lookup?: MailauthResolver },
) {
  return dkimVerify(raw, {
    resolver: deps.lookup ?? toMailauthResolver(deps.resolver, deps.dns),
    rejectRsaSha1: true,
    curTime: deps.now,
  });
}
