import { createPublicKey, X509Certificate } from 'node:crypto';
import { keyFingerprint } from '@mailshield/engine';

export class KeyMaterialError extends Error {
  constructor(
    readonly type: 'private_key_rejected' | 'invalid_request',
    message: string,
  ) {
    super(message);
  }
}

export interface PublicMaterial {
  material: 'certificate' | 'public_key';
  keyType: string;
  /** hex(SHA-256(DER SubjectPublicKeyInfo)) */
  fingerprint: string;
  /** Certificate notAfter, when the material is a certificate. */
  expiresAt: string | null;
}

const BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;

/**
 * Reads one PEM certificate or SubjectPublicKeyInfo. Anything that mentions a private key is
 * refused before parsing, so a private key never enters the registry (invariant 8).
 */
export function readPublicMaterial(pem: string): PublicMaterial {
  if (/PRIVATE\s+KEY/i.test(pem)) {
    throw new KeyMaterialError('private_key_rejected', 'Private keys are never accepted.');
  }
  const blocks = [...pem.matchAll(BLOCK)];
  if (blocks.length !== 1) {
    throw new KeyMaterialError(
      'invalid_request',
      'Paste exactly one PEM certificate or public key.',
    );
  }
  const [block, label] = blocks[0]!;
  try {
    if (label === 'CERTIFICATE') {
      const cert = new X509Certificate(block);
      return {
        material: 'certificate',
        keyType: cert.publicKey.asymmetricKeyType ?? 'unknown',
        fingerprint: keyFingerprint(cert.publicKey.export({ type: 'spki', format: 'pem' })),
        expiresAt: new Date(cert.validTo).toISOString(),
      };
    }
    if (label === 'PUBLIC KEY') {
      const key = createPublicKey(block);
      return {
        material: 'public_key',
        keyType: key.asymmetricKeyType ?? 'unknown',
        fingerprint: keyFingerprint(block),
        expiresAt: null,
      };
    }
  } catch {
    throw new KeyMaterialError('invalid_request', 'The PEM block could not be read.');
  }
  throw new KeyMaterialError(
    'invalid_request',
    'Only CERTIFICATE and PUBLIC KEY blocks are accepted.',
  );
}
