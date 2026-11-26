import { createPrivateKey, createPublicKey } from 'node:crypto';
import { dkimSign } from 'mailauth/lib/dkim/sign';

export interface SignOptions {
  domain: string;
  selector: string;
  privateKey: string;
  signTime: Date;
  headerList?: string[];
  /** Adds l=, signing only this many canonicalized body bytes. */
  maxBodyLength?: number;
}

/** Signs a CRLF message with a lab key. Deterministic for a fixed key and time. */
export async function signMessage(message: string, options: SignOptions): Promise<Buffer> {
  const { signatures, errors } = await dkimSign(Buffer.from(message), {
    signTime: options.signTime,
    headerList: options.headerList ?? ['From', 'To', 'Subject', 'Date'],
    signatureData: [
      {
        signingDomain: options.domain,
        selector: options.selector,
        privateKey: options.privateKey,
        maxBodyLength: options.maxBodyLength,
      },
    ],
  });
  if (errors?.length) throw new Error('Lab signing failed.');
  return Buffer.from(signatures + message);
}

/** The TXT record a domain would publish for this key. */
export function dkimRecord(privateKey: string): string {
  const der = createPublicKey(createPrivateKey(privateKey)).export({ type: 'spki', format: 'der' });
  return `v=DKIM1; k=rsa; p=${der.toString('base64')}`;
}
