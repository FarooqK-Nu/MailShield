import { readFileSync } from 'node:fs';
import { domainToASCII, domainToUnicode } from 'node:url';
import { RegistryFile, type Identity } from '@mailshield/contracts';
import type { RegistryPort } from '@mailshield/engine';

const FILE = new URL('../../../fixtures/registry/fictional-orgs.json', import.meta.url);
const CREATED = '2026-11-27T00:00:00.000Z';

/**
 * The fictional seed registry (Acme, Globex, Alice) as a read-only port. Fixture and demo
 * runs always use this, never the local database, so their results are deterministic (A-10).
 */
export function fixtureIdentities(): Identity[] {
  const file = RegistryFile.parse(JSON.parse(readFileSync(FILE, 'utf8')));
  return file.identities.map((input, i) => {
    const id = `fixture-${i + 1}`;
    return {
      id,
      kind: input.kind,
      displayName: input.displayName,
      trustState: input.trustState,
      provenanceUrl: input.provenanceUrl,
      notes: input.notes,
      lastReviewed: input.lastReviewed,
      createdAt: CREATED,
      updatedAt: CREATED,
      deletedAt: null,
      aliases: input.aliases.map((alias, n) => ({ id: `${id}-a${n}`, alias })),
      domains: input.domains.map((d, n) => {
        const ascii = domainToASCII(d.domain.toLowerCase());
        return {
          id: `${id}-d${n}`,
          domainAscii: ascii,
          domainUnicode: domainToUnicode(ascii),
          includeSubdomains: d.includeSubdomains,
          relationship: d.relationship,
        };
      }),
      addresses: input.addresses.map((address, n) => ({ id: `${id}-m${n}`, address })),
      keys: [],
    };
  });
}

export const fixtureRegistry: RegistryPort = { identities: async () => fixtureIdentities() };
