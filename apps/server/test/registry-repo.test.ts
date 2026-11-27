import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Identity, RegistryFile } from '@mailshield/contracts';
import { keyFingerprint } from '@mailshield/engine';
import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db/open.ts';
import { RegistryError, RegistryRepo } from '../src/db/registry-repo.ts';

let tick = 0;
const repo = () =>
  new RegistryRepo(openDatabase(':memory:'), () => new Date(Date.UTC(2026, 10, 27, 0, 0, tick++)));

const acme = {
  kind: 'organization' as const,
  displayName: 'Acme Corporation',
  aliases: ['Acme', 'Acme', 'Acme Support'],
  domains: [{ domain: 'Acme.Example', includeSubdomains: true }],
  addresses: ['Billing@Acme.example'],
};

describe('RegistryRepo', () => {
  it('creates an identity with normalized children and audits it', () => {
    const r = repo();
    const created = r.create(acme, 'local_user');
    expect(() => Identity.parse(created)).not.toThrow();
    expect(created).toMatchObject({
      trustState: 'unverified',
      aliases: [{ alias: 'Acme' }, { alias: 'Acme Support' }],
      domains: [{ domainAscii: 'acme.example', includeSubdomains: true, relationship: 'own' }],
      addresses: [{ address: 'billing@acme.example' }],
    });
    const [event] = r.auditTrail(created.id);
    expect(event).toMatchObject({ action: 'create', actor: 'local_user', before: null });
    expect(event!.after).toMatchObject({ displayName: 'Acme Corporation' });
  });

  it('stores IDNs in ASCII and shows them in Unicode', () => {
    const created = repo().create(
      { kind: 'organization', displayName: 'Bücher', domains: [{ domain: 'bücher.example' }] },
      'u',
    );
    expect(created.domains[0]).toMatchObject({
      domainAscii: 'xn--bcher-kva.example',
      domainUnicode: 'bücher.example',
    });
  });

  it.each(['com', '192.0.2.1', 'not a domain'])('rejects approved domain %j', (domain) => {
    expect(() =>
      repo().create({ kind: 'organization', displayName: 'X', domains: [{ domain }] }, 'u'),
    ).toThrow(RegistryError);
  });

  it('updates only the fields given and records before and after', () => {
    const r = repo();
    const { id } = r.create({ ...acme, trustState: 'user_trusted' }, 'u');
    const updated = r.update(id, { notes: 'Checked by phone.' }, 'u');
    expect(updated).toMatchObject({ notes: 'Checked by phone.', trustState: 'user_trusted' });
    expect(updated.aliases).toHaveLength(2);

    const replaced = r.update(id, { domains: [{ domain: 'acme.example.org' }] }, 'u');
    expect(replaced.domains.map((d) => d.domainAscii)).toEqual(['acme.example.org']);

    const [last] = r.auditTrail(id);
    expect(last!.action).toBe('update');
    expect((last!.before as Identity).domains[0]!.domainAscii).toBe('acme.example');
  });

  it('soft-deletes, hides the entry from analysis and keeps the audit trail', async () => {
    const r = repo();
    const { id } = r.create(acme, 'u');
    r.remove(id, 'u');
    expect(await r.identities()).toEqual([]);
    expect(r.list({ includeDeleted: true })[0]!.deletedAt).not.toBeNull();
    expect(r.auditTrail(id).map((e) => e.action)).toEqual(['delete', 'create']);
    expect(() => r.update(id, { notes: 'x' }, 'u')).toThrow(RegistryError);
  });

  it('searches names, aliases, domains and addresses and filters by kind', () => {
    const r = repo();
    r.create(acme, 'u');
    r.create(
      { kind: 'person', displayName: 'Alice Example', addresses: ['alice@acme.example'] },
      'u',
    );
    expect(r.list({ q: 'support' }).map((i) => i.displayName)).toEqual(['Acme Corporation']);
    expect(r.list({ q: 'alice@' }).map((i) => i.displayName)).toEqual(['Alice Example']);
    expect(r.list({ kind: 'organization' })).toHaveLength(1);
  });

  it('enrolls a public key and a certificate by SPKI fingerprint', () => {
    const r = repo();
    const { id } = r.create(acme, 'u');
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const key = r.addKey(id, { pem, trustSource: 'Read out by phone' }, 'u');
    expect(key).toMatchObject({ keyType: 'ec', fingerprintSha256: keyFingerprint(pem) });

    const cert = readFileSync(
      new URL('../../../fixtures/smime/alice.crt', import.meta.url),
      'utf8',
    );
    const fromCert = r.addKey(id, { pem: cert, trustSource: 'Lab CA' }, 'u');
    expect(fromCert.expiresAt).not.toBeNull();
    expect(r.get(id).keys).toHaveLength(2);
    expect(r.auditTrail(id)[0]!.action).toBe('key_added');

    expect(() => r.addKey(id, { pem, trustSource: 'again' }, 'u')).toThrow(/already enrolled/);
  });

  it('exports and imports a validated registry file, skipping duplicates', () => {
    const source = repo();
    source.create(acme, 'u');
    const file = source.exportFile();
    expect(() => RegistryFile.parse(file)).not.toThrow();

    const target = repo();
    expect(target.importFile(file, 'u')).toEqual({ imported: 1, skipped: [] });
    expect(target.importFile(file, 'u')).toEqual({ imported: 0, skipped: ['Acme Corporation'] });
    expect(target.list()[0]!.domains[0]!.domainAscii).toBe('acme.example');
    expect(target.auditTrail()[0]!.action).toBe('import');
  });

  it('imports nothing when one entry is invalid', () => {
    const r = repo();
    const file = {
      format: 'mailshield-registry' as const,
      version: 1 as const,
      exportedAt: new Date().toISOString(),
      identities: [
        {
          kind: 'organization' as const,
          displayName: 'Good',
          domains: [{ domain: 'good.example' }],
        },
        { kind: 'organization' as const, displayName: 'Bad', domains: [{ domain: 'com' }] },
      ],
    };
    expect(() => r.importFile(file, 'u')).toThrow(RegistryError);
    expect(r.list()).toEqual([]);
  });
});

describe('fictional seed registry', () => {
  it('is a valid registry file on reserved domains only', () => {
    const file = JSON.parse(
      readFileSync(
        new URL('../../../fixtures/registry/fictional-orgs.json', import.meta.url),
        'utf8',
      ),
    );
    const r = repo();
    expect(r.importFile(RegistryFile.parse(file), 'seed').imported).toBe(4);
    const domains = r
      .list()
      .flatMap((i) => [
        ...i.domains.map((d) => d.domainAscii),
        ...i.addresses.map((a) => a.address.split('@')[1]!),
      ]);
    expect(domains.every((d) => d.endsWith('.example'))).toBe(true);
  });
});
