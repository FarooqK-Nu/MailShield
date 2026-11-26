import type { DnsAnswer, DnsResolver, ValidatedDnsName } from '@mailshield/engine';

export type FixtureZone = Record<string, string>;

/** Zone value that simulates a resolver timeout. */
export const TIMEOUT = 'TIMEOUT';

/** Offline DNS for tests and the lab. Unknown names answer NXDOMAIN. */
export class FixtureResolver implements DnsResolver {
  readonly queries: string[] = [];
  private readonly zone: FixtureZone;

  constructor(zone: FixtureZone) {
    this.zone = zone;
  }

  async txt(name: ValidatedDnsName): Promise<DnsAnswer> {
    this.queries.push(name);
    const value = this.zone[name];
    if (value === undefined) return { status: 'nxdomain', records: [] };
    if (value === TIMEOUT) return { status: 'timeout', records: [] };
    return { status: 'ok', records: [[value]] };
  }
}
