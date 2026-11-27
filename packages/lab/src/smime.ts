import { X509Certificate, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { LabPersonalResponse, LabPersonalScenario, Identity } from '@mailshield/contracts';
import { analyze, keyFingerprint } from '@mailshield/engine';
import { fromBER } from 'asn1js';
import {
  Certificate,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignedData,
  SignerInfo,
} from 'pkijs';
import { fixtureIdentities } from './fixture-registry.ts';
import { FixtureResolver } from './fixture-resolver.ts';

const KEYS = new URL('../../../fixtures/keys/', import.meta.url);
const CERTS = new URL('../../../fixtures/smime/', import.meta.url);
/** Fixed clock: lab results never depend on today's date. */
const NOW = new Date('2026-06-01T12:00:00Z');
const BOUNDARY = 'lab-smime-boundary';

export type LabPerson = 'alice' | 'bob' | 'eve';

const pemToDer = (pem: string) => Buffer.from(pem.replace(/-----[A-Z ]+-----|\s+/g, ''), 'base64');
const cert = (name: string) =>
  new X509Certificate(readFileSync(new URL(`lab-${name}.crt`, CERTS))).raw;

/**
 * The lab certificate authority. It is handed to the engine only by the lab runner below; the
 * live service never imports it, so live analysis reports chain trust as "not checked" (A-17).
 */
export const labTrustStore = (): Buffer[] => [cert('ca')];

/** SPKI fingerprint of a lab person's certificate key, as the registry stores it. */
export function labKeyFingerprint(person: LabPerson): string {
  return keyFingerprint(
    new X509Certificate(cert(person)).publicKey.export({ type: 'spki', format: 'pem' }),
  );
}

/** Signs `content` as detached CMS SignedData with a lab person's TEST-ONLY key. */
async function cmsSign(person: LabPerson, content: Buffer): Promise<Buffer> {
  const key = await webcrypto.subtle.importKey(
    'pkcs8',
    pemToDer(readFileSync(new URL(`TEST-ONLY-lab-${person}.pem`, KEYS), 'utf8')),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signer = new Certificate({ schema: fromBER(new Uint8Array(cert(person))).result });
  const signedData = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: '1.2.840.113549.1.7.1',
    }),
    signerInfos: [
      new SignerInfo({
        version: 1,
        sid: new IssuerAndSerialNumber({
          issuer: signer.issuer,
          serialNumber: signer.serialNumber,
        }),
      }),
    ],
    certificates: [signer],
  });
  await signedData.sign(key, 0, 'SHA-256', new Uint8Array(content).buffer);
  const info = new ContentInfo({
    contentType: '1.2.840.113549.1.7.2',
    content: signedData.toSchema(true),
  });
  return Buffer.from(info.toSchema().toBER());
}

const wrap = (base64: string) => base64.match(/.{1,64}/g)!.join('\r\n');

/** A multipart/signed message. The signature covers the first part, headers included. */
async function buildSigned(
  signer: LabPerson,
  subject: string,
  body: string,
): Promise<{ message: string; signedPart: string }> {
  const signedPart = ['Content-Type: text/plain; charset=utf-8', '', ...body.split('\n')].join(
    '\r\n',
  );
  const der = await cmsSign(signer, Buffer.from(signedPart));
  const message = [
    'From: "Alice Example" <alice@acme.example>',
    'To: you@example.org',
    'Date: Mon, 01 Jun 2026 10:00:00 +0000',
    `Subject: ${subject}`,
    'Message-ID: <lab-personal-1@lab.example>',
    'MIME-Version: 1.0',
    `Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="${BOUNDARY}"`,
    '',
    `--${BOUNDARY}`,
    signedPart,
    `--${BOUNDARY}`,
    'Content-Type: application/pkcs7-signature; name="smime.p7s"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="smime.p7s"',
    '',
    wrap(der.toString('base64')),
    `--${BOUNDARY}--`,
    '',
  ].join('\r\n');
  return { message, signedPart };
}

const SUBJECT = 'Can you send me the report?';
const BODY = 'Hi,\n\nPlease send me the quarterly report when you can.\n\nAlice';

/** Alice and Bob as registry people. Their real keys are enrolled when the scenario says so. */
function registry(aliceKeyEnrolled: boolean): Identity[] {
  const now = NOW.toISOString();
  const key = (id: string, person: LabPerson) => ({
    id: `${id}-key`,
    keyType: 'rsa',
    fingerprintSha256: labKeyFingerprint(person),
    trustSource: 'Compared in person (lab)',
    status: 'active' as const,
    enrolledAt: now,
    expiresAt: null,
  });
  return fixtureIdentities().map((identity) => {
    if (identity.displayName === 'Alice Example') {
      return { ...identity, keys: aliceKeyEnrolled ? [key(identity.id, 'alice')] : [] };
    }
    if (identity.displayName === 'Bob Example')
      return { ...identity, keys: [key(identity.id, 'bob')] };
    return identity;
  });
}

/**
 * Builds a message that claims to be from Alice, signs it as the chosen person (or not), applies
 * the chosen tampering to the finished bytes, and runs the real engine with the lab CA trusted.
 */
export async function runPersonalScenario(
  scenario: LabPersonalScenario,
): Promise<LabPersonalResponse> {
  const notes: string[] = [];
  const m = new Set(scenario.mutations);
  const names = { alice: 'Alice', bob: 'Bob', eve: 'Eve' };
  let message: string;
  if (scenario.signer === 'none') {
    notes.push('The message is not signed.');
    message = [
      'From: "Alice Example" <alice@acme.example>',
      'To: you@example.org',
      'Date: Mon, 01 Jun 2026 10:00:00 +0000',
      `Subject: ${SUBJECT}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      ...BODY.split('\n'),
      '',
    ].join('\r\n');
  } else {
    notes.push(
      `The message claims to be from alice@acme.example and is signed with ${names[scenario.signer]}'s certificate.`,
    );
    message = (await buildSigned(scenario.signer, SUBJECT, BODY)).message;
  }
  if (m.has('editBody') && scenario.signer !== 'none') {
    message = message.replace('quarterly report', 'quarterly payment');
    notes.push('The signed body was changed after signing ("report" became "payment").');
  }
  if (m.has('changeOuterSubject')) {
    message = message.replace(`Subject: ${SUBJECT}`, 'Subject: Urgent: wire transfer needed');
    notes.push(
      'The outer Subject header was changed. It is not inside the signed part, so the signature cannot notice.',
    );
  }
  const result = await analyze(
    { raw: Buffer.from(message), source: 'lab' },
    {
      resolver: new FixtureResolver({}),
      registry: { identities: async () => registry(scenario.aliceKeyEnrolled) },
      trustStore: labTrustStore(),
      clock: () => NOW,
    },
  );
  return { result, notes, rawMessage: message };
}
