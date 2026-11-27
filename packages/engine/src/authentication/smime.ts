import { X509Certificate } from 'node:crypto';
import type { PersonalSignature } from '@mailshield/contracts';
import { fromBER } from 'asn1js';
import { Certificate, ContentInfo, SignedData } from 'pkijs';
import { headerValues, type RawHeaders } from '../parse/raw-headers.ts';
import { keyFingerprint } from './fingerprint.ts';

export const SMIME_COVERAGE =
  'Only the signed MIME part is covered. The outer headers (From, To, Subject, Date) are not signed, so they are never described as personally signed.';

const EKU_EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4';

export interface SignedPart {
  /** Exact bytes of the first part, as sent (decision: no re-serialisation). */
  content: Buffer;
  /** DER of the CMS structure, decoded from the second part. */
  signature: Buffer;
}

export type Detected =
  | { kind: 'none' }
  | { kind: 'opaque' }
  | { kind: 'detached'; part: SignedPart }
  | { kind: 'malformed'; reason: string };

const param = (value: string, name: string) =>
  new RegExp(`${name}\s*=\s*(?:"([^"]+)"|([^\s;]+))`, 'i').exec(value)?.slice(1).find(Boolean);

/**
 * Finds a `multipart/signed` pkcs7 message and cuts out the two parts by byte offset from the
 * original buffer. The first part (with its own headers) is what the signature covers; the CRLF
 * before the next boundary belongs to the boundary (RFC 1847).
 */
export function detectSmime(raw: Buffer, headers: RawHeaders): Detected {
  const type = headerValues(headers, 'content-type')[0] ?? '';
  if (/^\s*application\/(x-)?pkcs7-mime/i.test(type) && /signed-data/i.test(type)) {
    return { kind: 'opaque' };
  }
  if (!/^\s*multipart\/signed/i.test(type)) return { kind: 'none' };
  if (!/application\/(x-)?pkcs7-signature/i.test(type)) return { kind: 'none' };
  const boundary = param(type, 'boundary');
  if (!boundary) return { kind: 'malformed', reason: 'The signed message has no boundary.' };

  const open = Buffer.from(`--${boundary}\r\n`);
  const next = Buffer.from(`\r\n--${boundary}`);
  const first = raw.indexOf(open);
  if (first < 0) return { kind: 'malformed', reason: 'The first signed part was not found.' };
  const start = first + open.length;
  const end = raw.indexOf(next, start);
  if (end < 0) return { kind: 'malformed', reason: 'The signature part was not found.' };
  const afterBoundary = raw.indexOf('\r\n', end + next.length);
  const second = raw.subarray(afterBoundary + 2);
  const bodyStart = second.indexOf('\r\n\r\n');
  const close = second.indexOf(next);
  if (afterBoundary < 0 || bodyStart < 0 || close < bodyStart) {
    return { kind: 'malformed', reason: 'The signature part is incomplete.' };
  }
  const base64 = second.subarray(bodyStart + 4, close).toString('ascii');
  const signature = Buffer.from(base64.replace(/\s+/g, ''), 'base64');
  if (signature.length === 0) return { kind: 'malformed', reason: 'The signature is empty.' };
  return { kind: 'detached', part: { content: raw.subarray(start, end), signature } };
}

export interface SmimeOptions {
  /** DER certificates the caller trusts. Empty in live mode, so chain trust is not checked. */
  trustStore: readonly Buffer[];
  now: Date;
  fromAddress: string | null;
}

const base = (): Omit<PersonalSignature, 'evidenceId' | 'status' | 'reason'> => ({
  signatureValid: null,
  chainTrusted: null,
  emailBinding: null,
  ekuEmailProtection: null,
  timeValid: null,
  revocation: 'unknown',
  signer: null,
  enrolledFor: null,
  coverage: SMIME_COVERAGE,
});

const toCertificate = (der: Buffer) =>
  new Certificate({ schema: fromBER(new Uint8Array(der)).result });

/** Verifies the signature and reports each question separately (docs/architecture.md §3.7). */
export async function verifySmime(
  part: SignedPart,
  options: SmimeOptions,
): Promise<PersonalSignature> {
  const result = { evidenceId: 'smime-1', ...base() };
  let signedData: SignedData;
  try {
    const info = new ContentInfo({ schema: fromBER(new Uint8Array(part.signature)).result });
    signedData = new SignedData({ schema: info.content });
  } catch {
    return {
      ...result,
      status: 'unsupported',
      reason: 'The signature could not be read as a CMS SignedData structure.',
    };
  }

  const useChain = options.trustStore.length > 0;
  let outcome: { signatureVerified?: boolean | null; signerCertificate?: Certificate | null };
  let chainVerified: boolean | null | undefined;
  try {
    const verified = await signedData.verify({
      signer: 0,
      data: new Uint8Array(part.content).buffer,
      trustedCerts: options.trustStore.map(toCertificate),
      checkChain: useChain,
      checkDate: options.now,
      extendedMode: true,
    });
    outcome = verified;
    chainVerified = verified.signerCertificateVerified;
  } catch (error) {
    // pkijs throws with the partial result attached in extended mode.
    const e = error as typeof outcome & { signerCertificateVerified?: boolean | null };
    outcome = e;
    chainVerified = e.signerCertificateVerified;
  }

  const signatureValid = outcome.signatureVerified === true;
  let signer: PersonalSignature['signer'] = null;
  let emailBinding: boolean | null = null;
  let eku: boolean | null = null;
  let timeValid: boolean | null = null;
  const cert =
    outcome.signerCertificate ??
    signedData.certificates?.find((c): c is Certificate => c instanceof Certificate);
  if (cert) {
    const node = new X509Certificate(Buffer.from(cert.toSchema().toBER()));
    const emails = [...(node.subjectAltName?.matchAll(/email:([^,\s]+)/g) ?? [])].map((m) => m[1]!);
    emailBinding = options.fromAddress
      ? emails.some((e) => e.toLowerCase() === options.fromAddress!.toLowerCase())
      : null;
    eku = node.keyUsage?.includes(EKU_EMAIL_PROTECTION) ?? false;
    timeValid = options.now >= new Date(node.validFrom) && options.now <= new Date(node.validTo);
    signer = {
      subject: node.subject.replace(/\n/g, ', '),
      email: emails[0] ?? null,
      issuer: node.issuer.replace(/\n/g, ', '),
      notBefore: new Date(node.validFrom).toISOString(),
      notAfter: new Date(node.validTo).toISOString(),
      fingerprint: keyFingerprint(node.publicKey.export({ type: 'spki', format: 'pem' })),
    };
  }

  return {
    ...result,
    status: signatureValid ? 'pass' : 'fail',
    reason: signatureValid
      ? 'The signer’s key signed exactly the covered part.'
      : 'The signature does not match the covered part, or the signer’s certificate is missing.',
    signatureValid: cert ? signatureValid : false,
    chainTrusted: useChain ? chainVerified === true : null,
    emailBinding,
    ekuEmailProtection: eku,
    timeValid,
    signer,
  };
}
