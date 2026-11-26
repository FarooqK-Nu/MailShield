/** Invariant 8: no private key is accepted into the production registry. */
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db/open.ts';
import { KeyMaterialError, readPublicMaterial } from '../src/db/public-key.ts';
import { RegistryRepo } from '../src/db/registry-repo.ts';

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const privatePem = {
  pkcs8: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  pkcs1: pair.privateKey.export({ type: 'pkcs1', format: 'pem' }).toString(),
  encrypted: pair.privateKey
    .export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'x' })
    .toString(),
  ec: generateKeyPairSync('ec', { namedCurve: 'P-256' })
    .privateKey.export({ type: 'sec1', format: 'pem' })
    .toString(),
};

describe('invariant 8: private keys', () => {
  it.each(Object.entries(privatePem))('refuses a %s private key', (_kind, pem) => {
    expect(() => readPublicMaterial(pem)).toThrow(
      expect.objectContaining({ type: 'private_key_rejected' }),
    );
  });

  it('refuses a public key pasted together with its private key', () => {
    expect(() => readPublicMaterial(`${publicPem}\n${privatePem.pkcs8}`)).toThrow(KeyMaterialError);
  });

  it('stores nothing when enrollment is refused', () => {
    const repo = new RegistryRepo(openDatabase(':memory:'));
    const { id } = repo.create({ kind: 'person', displayName: 'Alice' }, 'u');
    expect(() => repo.addKey(id, { pem: privatePem.pkcs8, trustSource: 'x' }, 'u')).toThrow();
    expect(repo.get(id).keys).toEqual([]);
    expect(repo.auditTrail(id).map((e) => e.action)).toEqual(['create']);
  });

  it('accepts the public half', () => {
    expect(readPublicMaterial(publicPem).material).toBe('public_key');
  });
});
