import { createHash, createPublicKey } from 'node:crypto';

/** hex(SHA-256(DER SubjectPublicKeyInfo)). A key fingerprint, not a certificate fingerprint. */
export function keyFingerprint(publicKey: Parameters<typeof createPublicKey>[0]): string {
  const der = createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}
