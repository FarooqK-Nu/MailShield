import { Resolver } from 'node:dns/promises';
import type { ValidatedDnsName } from './name.ts';

export type DnsStatus = 'ok' | 'nxdomain' | 'nodata' | 'timeout' | 'servfail';

export interface DnsAnswer {
  status: DnsStatus;
  /** One entry per TXT record, each a list of character-strings. */
  records: string[][];
}

export interface DnsResolver {
  txt(name: ValidatedDnsName): Promise<DnsAnswer>;
}

export interface LiveResolverOptions {
  timeoutMs?: number;
  tries?: number;
  /** For tests. Defaults to the system resolvers. */
  servers?: string[];
}

/** TTL-aware caching is added in Phase 1. */
export class LiveResolver implements DnsResolver {
  private readonly options: LiveResolverOptions;

  constructor(options: LiveResolverOptions = {}) {
    this.options = options;
  }

  async txt(name: ValidatedDnsName): Promise<DnsAnswer> {
    const { timeoutMs = 3000, tries = 2, servers } = this.options;
    const resolver = new Resolver({ timeout: timeoutMs, tries });
    if (servers) resolver.setServers(servers);

    // Node backs off between tries, so enforce an overall deadline as well.
    const deadline = setTimeout(() => resolver.cancel(), timeoutMs * tries);
    try {
      return { status: 'ok', records: await resolver.resolveTxt(name) };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOTFOUND') return { status: 'nxdomain', records: [] };
      if (code === 'ENODATA') return { status: 'nodata', records: [] };
      if (code === 'ETIMEOUT' || code === 'ECANCELLED') return { status: 'timeout', records: [] };
      return { status: 'servfail', records: [] };
    } finally {
      clearTimeout(deadline);
    }
  }
}
