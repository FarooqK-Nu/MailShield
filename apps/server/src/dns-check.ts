import { validateAuthName, type DnsResolver } from '@mailshield/engine';

/** Any definite answer, including "no such name", shows that DNS is reachable. */
export async function dnsWarning(resolver: DnsResolver): Promise<string | null> {
  const { status } = await resolver.txt(validateAuthName('_dmarc.com')!);
  if (status !== 'timeout' && status !== 'servfail') return null;
  return 'WARNING: DNS is unreachable, so live signature checks will fail. Set DNS_SERVERS in .env (see README.md).';
}
