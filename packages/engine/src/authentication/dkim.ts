import { createHash, createPublicKey } from 'node:crypto';
import type {
  EvidenceSource,
  EvidenceStatus,
  FailureStage,
  SignatureEvidence,
} from '@mailshield/contracts';
import type { AdapterOptions, MailauthResolver } from '../dns/mailauth-adapter.ts';
import type { DnsResolver } from '../dns/resolver.ts';
import { AnalysisError, LIMITS } from '../intake/limits.ts';
import { headerValues, type RawHeaders } from '../parse/raw-headers.ts';
import { keyFingerprint } from './fingerprint.ts';
import { rawDkimVerify } from './mailauth-dkim.ts';

type LibraryResult = Awaited<ReturnType<typeof rawDkimVerify>>['results'][number];

interface Outcome {
  status: EvidenceStatus;
  failureStage: FailureStage | null;
  reason: string;
}

const outcome = (
  status: EvidenceStatus,
  failureStage: FailureStage | null,
  reason: string,
): Outcome => ({ status, failureStage, reason });

/** Library comments for a `neutral` result (docs/spikes.md). */
const NEUTRAL: Record<string, Outcome> = {
  'body hash did not verify': outcome(
    'fail',
    'body_hash',
    'The body does not match the signed body hash. It changed after signing.',
  ),
  'no key': outcome(
    'missing',
    'dns',
    'No public key is published for this selector. It may have been removed or rotated.',
  ),
  expired: outcome('fail', 'expired', 'The signature has passed its expiry time.'),
  'invalid expiration': outcome('fail', 'expired', 'The signature has an impossible expiry time.'),
  'invalid public key': outcome(
    'unknown',
    'key_parse',
    'The published key record cannot be used. The key may have been revoked.',
  ),
  'unknown key type': outcome('unsupported', 'key_parse', 'The key type is not supported.'),
  'unknown key version': outcome('unsupported', 'key_parse', 'The key record version is unknown.'),
  'inappropriate hash algorithm': outcome(
    'unsupported',
    'key_parse',
    'The key does not allow the hash algorithm the signature uses.',
  ),
  'inappropriate key algorithm': outcome(
    'unsupported',
    'key_parse',
    'The key type does not match the signature algorithm.',
  ),
  'key not for email': outcome('unsupported', 'key_parse', 'The key is not published for email.'),
};

function interpret(result: LibraryResult | undefined): Outcome {
  if (!result) {
    return outcome(
      'unsupported',
      'policy',
      'This signature could not be processed (unsupported algorithm or format, or a missing tag).',
    );
  }
  const comment = String(result.status.comment || '');
  switch (result.status.result) {
    case 'pass':
      return outcome('pass', null, 'The signature matches the signed headers and body.');
    case 'fail':
      return outcome(
        'fail',
        'header_signature',
        'The signature does not match the signed headers and the published key.',
      );
    case 'temperror':
      return comment.includes('EBUDGET')
        ? outcome('unknown', 'dns', 'The DNS lookup limit for one message was reached.')
        : outcome('temporary_error', 'dns', 'The public key could not be looked up. Try again.');
    case 'policy':
      return outcome(
        'unsupported',
        'policy',
        'The signature uses an algorithm or key too weak to rely on.',
      );
    case 'neutral':
      return (
        NEUTRAL[comment] ??
        outcome('unsupported', 'policy', 'The signature is invalid or cannot be evaluated.')
      );
    default:
      return outcome('unknown', null, 'The signature could not be evaluated.');
  }
}

/** Tags as written, for display. Whitespace is removed from the base64 values. */
function parseTags(value: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of value.split(';')) {
    const at = part.indexOf('=');
    if (at < 1) continue;
    const name = part.slice(0, at).trim();
    const raw = part.slice(at + 1).trim();
    if (/^[a-z]+$/i.test(name) && !(name in tags)) {
      tags[name] = name === 'b' || name === 'bh' ? raw.replace(/\s+/g, '') : raw;
    }
  }
  return tags;
}

/** mailauth identifies a result by the SHA-256 of its signature bytes. */
const resultId = (b: string) => createHash('sha256').update(Buffer.from(b, 'base64')).digest('hex');

const IMPORTANT_HEADERS = ['from', 'to', 'subject', 'date', 'reply-to'];

/** An occurrence is covered only if h= lists the name at least that many times. */
function unsignedHeaders(headers: RawHeaders, signed: string[]): string[] {
  return IMPORTANT_HEADERS.filter(
    (name) => headerValues(headers, name).length > signed.filter((s) => s === name).length,
  );
}

function keyInfo(result: LibraryResult | undefined): SignatureEvidence['key'] {
  if (!result?.publicKey) return null;
  const key = createPublicKey(result.publicKey);
  return {
    type: key.asymmetricKeyType ?? 'unknown',
    bits: key.asymmetricKeyDetails?.modulusLength ?? null,
    fingerprint: keyFingerprint(result.publicKey),
    testing: result.status.testing === true,
  };
}

function describe(
  index: number,
  source: EvidenceSource,
  headers: RawHeaders,
  value: string,
  verdict: Outcome,
  result?: LibraryResult,
): SignatureEvidence {
  const tags = parseTags(value);
  const signed = (tags.h ?? '')
    .split(':')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  const key = keyInfo(result);
  const computed = result?.bodyHash ?? null;
  const expected = tags.bh ?? null;
  const time = (seconds: string | undefined) => {
    const date = new Date(Number(seconds) * 1000);
    return seconds && !Number.isNaN(date.getTime()) ? date.toISOString() : null;
  };

  const warnings = (result?.status.warnings ?? []).map((w) => `Library warning: ${w}`);
  if (key?.type === 'rsa' && key.bits !== null && key.bits < 2048) {
    warnings.push(`The RSA key is only ${key.bits} bits; 2048 or more is recommended.`);
  }
  if (tags.a === 'rsa-sha1') warnings.push('rsa-sha1 is obsolete and weak.');
  if (key?.testing) warnings.push('The domain marks this key as being tested (t=y).');

  return {
    evidenceId: `dkim-${index + 1}`,
    source,
    ...verdict,
    domain: tags.d ?? null,
    selector: tags.s ?? null,
    algorithm: tags.a ?? null,
    canonicalization: tags.c ?? 'simple/simple',
    tags,
    bodyHash: {
      expected,
      computed,
      matches: computed && expected ? computed === expected : null,
    },
    signedHeaders: signed,
    unsignedHeaders: unsignedHeaders(headers, signed),
    bodyCoverage:
      tags.l !== undefined && /^\d+$/.test(tags.l)
        ? {
            signedBytes: result?.canonBodyLength ?? Number(tags.l),
            unsignedBytes: result ? (result.status.underSized ?? 0) : null,
          }
        : null,
    key,
    signedAt: time(tags.t),
    expiresAt: time(tags.x),
    warnings,
  };
}

/** Lists the signatures without verifying them (header-only input). */
export function listSignatures(headers: RawHeaders, source: EvidenceSource): SignatureEvidence[] {
  return headerValues(headers, 'dkim-signature').map((value, i) =>
    describe(
      i,
      source,
      headers,
      value,
      outcome('not_evaluated', null, 'Not checked: only headers were provided.'),
    ),
  );
}

/** Verifies every DKIM signature using the original bytes. */
export async function verifyDkim(
  raw: Buffer,
  headers: RawHeaders,
  deps: {
    resolver: DnsResolver;
    now: Date;
    source: EvidenceSource;
    dns?: AdapterOptions;
    lookup?: MailauthResolver;
  },
): Promise<SignatureEvidence[]> {
  const values = headerValues(headers, 'dkim-signature');
  if (values.length === 0) return [];
  if (values.length > LIMITS.dkimSignatures) {
    throw new AnalysisError('mime_limits_exceeded', 'The message has too many DKIM signatures.');
  }

  const { results } = await rawDkimVerify(raw, deps);
  const unused = [...results];
  return values.map((value, i) => {
    const id = resultId(parseTags(value).b ?? '');
    const at = unused.findIndex((r) => r.id === id);
    const result = at === -1 ? undefined : unused.splice(at, 1)[0];
    return describe(i, deps.source, headers, value, interpret(result), result);
  });
}
