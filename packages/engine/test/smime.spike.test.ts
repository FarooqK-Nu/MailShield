/** Phase 0 spike: pkijs verifies an OpenSSL-produced detached S/MIME message. */
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fromBER } from 'asn1js';
import { Certificate, ContentInfo, SignedData } from 'pkijs';
import { describe, expect, it } from 'vitest';

const read = (name: string) =>
  readFileSync(new URL(`../../../fixtures/smime/${name}`, import.meta.url));
const cert = (name: string) =>
  new Certificate({ schema: fromBER(new Uint8Array(new X509Certificate(read(name)).raw)).result });

/** Spike-only splitter. Phase 6 replaces it with offset-based extraction. */
function split(raw: Buffer) {
  const boundary = /boundary="([^"]+)"/.exec(raw.toString('latin1'))![1]!;
  const open = Buffer.from(`--${boundary}\r\n`);
  const next = Buffer.from(`\r\n--${boundary}`);
  const start = raw.indexOf(open) + open.length;
  const end = raw.indexOf(next, start);
  const second = raw.subarray(end + next.length + 2);
  const bodyStart = second.indexOf('\r\n\r\n') + 4;
  const base64 = second.subarray(bodyStart, second.indexOf(next)).toString('ascii');
  return { content: raw.subarray(start, end), signature: Buffer.from(base64, 'base64') };
}

async function verify(content: Buffer, signature: Buffer, root: string) {
  const info = new ContentInfo({ schema: fromBER(new Uint8Array(signature)).result });
  const signedData = new SignedData({ schema: info.content });
  try {
    const result = await signedData.verify({
      signer: 0,
      data: new Uint8Array(content).buffer,
      trustedCerts: [cert(root)],
      checkChain: true,
      checkDate: new Date(),
      extendedMode: true,
    });
    return { signature: result.signatureVerified, chain: result.signerCertificateVerified };
  } catch (error) {
    const e = error as {
      signatureVerified?: boolean | null;
      signerCertificateVerified?: boolean | null;
    };
    return { signature: e.signatureVerified, chain: e.signerCertificateVerified };
  }
}

describe('pkijs CMS verification', () => {
  const { content, signature } = split(read('signed.eml'));

  it('verifies the signature and the chain to our own root', async () => {
    expect(await verify(content, signature, 'ca.crt')).toEqual({ signature: true, chain: true });
  });

  it('does not trust the chain under an unrelated root', async () => {
    expect((await verify(content, signature, 'other.crt')).chain).not.toBe(true);
  });

  it('rejects modified content', async () => {
    const tampered = Buffer.from(content.toString('latin1').replace('agenda', 'invoice'), 'latin1');
    expect(tampered.equals(content)).toBe(false);
    expect((await verify(tampered, signature, 'ca.crt')).signature).not.toBe(true);
  });

  it('exposes the email binding and EKU through node:crypto', () => {
    const alice = new X509Certificate(read('alice.crt'));
    expect(alice.subjectAltName).toBe('email:alice@acme.example');
    expect(alice.keyUsage).toContain('1.3.6.1.5.5.7.3.4');
  });
});
