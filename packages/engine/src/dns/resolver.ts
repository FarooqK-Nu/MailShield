import { Resolver } from 'node:dns/promises';
import { LRUCache } from 'lru-cache';
import type { ValidatedDnsName } from './name.ts';

export type DnsStatus = 'ok' | 'nxdomain' | 'nodata' | 'timeout' | 'servfail';

export interface DnsAnswer {
  status: DnsStatus;
  /** One entry per TXT record, each a list of character-strings. */
  records: string[][];
  /** True when the answer came from the cache. */
  cached?: boolean;
}

export interface DnsResolver {
  txt(name: ValidatedDnsName): Promise<DnsAnswer>;
}

export interface LiveResolverOptions {
  timeoutMs?: number;
  tries?: number;
  /** For tests. Defaults to the system resolvers. */
  servers?: string[];
  /** Fixed lifetime: Node does not report TTLs for TXT records (docs/decisions.md A-4). */
  cacheMs?: number;
}

export class LiveResolver implements DnsResolver {
  private readonly options: LiveResolverOptions;
  private readonly cache: LRUCache<string, DnsAnswer>;

  constructor(options: LiveResolverOptions = {}) {
    this.options = options;
    this.cache = new LRUCache({ max: 500, ttl: options.cacheMs ?? 60_000 });
  }

  async txt(name: ValidatedDnsName): Promise<DnsAnswer> {
    const hit = this.cache.get(name);
    if (hit) return { ...hit, cached: true };

    const answer = await this.query(name);
    // Timeouts and server failures are transient, so they are never cached.
    if (answer.status !== 'timeout' && answer.status !== 'servfail') this.cache.set(name, answer);
    return answer;
  }

  private async query(name: ValidatedDnsName): Promise<DnsAnswer> {
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
