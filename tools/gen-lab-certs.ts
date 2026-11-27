/**
 * Generates the lab certificate authority and the Alice, Bob and Eve certificates once.
 * Private keys are TEST-ONLY files in fixtures/keys/ (decision A-17); certificates go to
 * fixtures/smime/. Run: npx tsx tools/gen-lab-certs.ts
 */
import { X509Certificate, webcrypto } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';

const KEYS = new URL('../fixtures/keys/', import.meta.url);
const SMIME = new URL('../fixtures/smime/', import.meta.url);
const ALG = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
};
const NOT_BEFORE = new Date('2026-01-01T00:00:00Z');
const NOT_AFTER = new Date('2036-01-01T00:00:00Z');
const pem = (label: string, der: ArrayBuffer) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der)
    .toString('base64')
    .match(/.{1,64}/g)!
    .join('\n')}\n-----END ${label}-----\n`;

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

async function keyPair() {
  return (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
}
const save = async (name: string, pair: CryptoKeyPair, cert: x509.X509Certificate) => {
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', pair.privateKey);
  writeFileSync(new URL(`TEST-ONLY-lab-${name}.pem`, KEYS), pem('PRIVATE KEY', pkcs8));
  writeFileSync(new URL(`lab-${name}.crt`, SMIME), cert.toString('pem') + '\n');
};

const caPair = await keyPair();
const ca = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: '01',
  name: 'CN=MailShield Lab CA (TEST ONLY)',
  notBefore: NOT_BEFORE,
  notAfter: NOT_AFTER,
  signingAlgorithm: ALG,
  keys: caPair,
  extensions: [
    new x509.BasicConstraintsExtension(true, 0, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    await x509.SubjectKeyIdentifierExtension.create(caPair.publicKey),
  ],
});
await save('ca', caPair, ca);

const people = [
  ['alice', 'Alice Example', 'alice@acme.example', '10'],
  ['bob', 'Bob Example', 'bob@acme.example', '11'],
  ['eve', 'Eve Example', 'eve@acrne.example', '12'],
] as const;
for (const [id, name, email, serial] of people) {
  const pair = await keyPair();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial,
    subject: `CN=${name}, E=${email}`,
    issuer: ca.subject,
    notBefore: NOT_BEFORE,
    notAfter: NOT_AFTER,
    signingAlgorithm: ALG,
    publicKey: pair.publicKey,
    signingKey: caPair.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.emailProtection]),
      new x509.SubjectAlternativeNameExtension([{ type: 'email', value: email }]),
      await x509.SubjectKeyIdentifierExtension.create(pair.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(ca, false),
    ],
  });
  await save(id, pair, cert);
  console.log(id, new X509Certificate(Buffer.from(cert.rawData)).subjectAltName);
}
