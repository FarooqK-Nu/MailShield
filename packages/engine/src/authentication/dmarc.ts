import type { Evidence, EvidenceSource, SignatureEvidence } from '@mailshield/contracts';
import getDmarcRecord from 'mailauth/lib/dmarc/get-dmarc-record';
import type { MailauthResolver } from '../dns/mailauth-adapter.ts';

export const DMARC_LIMITATION =
  'DMARC evaluated from DKIM only: SPF cannot be checked for a forwarded or uploaded message.';

export interface DmarcContext {
  /** ASCII From domain; empty when the From header is malformed. */
  fromDomain: string;
  signatures: SignatureEvidence[];
  lookup: MailauthResolver;
  source: EvidenceSource;
  observedAt: string;
}

const failureKind = (error: unknown) => {
  const code = (error as { code?: string }).code;
  return code === 'EBUDGET' ? 'budget' : 'dns';
};

/**
 * Local, partial DMARC: does a locally verified DKIM signature align with the From domain?
 * Policy discovery and Organizational Domains use mailauth's RFC 9989 DNS tree walk, which
 * queries only `_dmarc` TXT names. The `np` tag needs A queries and is not evaluated.
 */
export async function evaluateDmarc(ctx: DmarcContext): Promise<Evidence> {
  const { fromDomain, signatures, source, observedAt } = ctx;
  const base = { id: 'dmarc-local', kind: 'dmarc' as const, source, observedAt };
  const method = { method: 'dkim_only', discovery: 'rfc9989_tree_walk' };

  if (!fromDomain) {
    return {
      ...base,
      status: 'unknown',
      domains: [],
      reason: 'The From header has no single domain, so DMARC alignment cannot be checked.',
      details: method,
    };
  }

  const lookup = getDmarcRecord.createRecordLookup(ctx.lookup);
  let discovery: Awaited<ReturnType<typeof getDmarcRecord.discoverPolicy>>;
  try {
    discovery = await getDmarcRecord.discoverPolicy(fromDomain, lookup);
  } catch (error) {
    const budget = failureKind(error) === 'budget';
    return {
      ...base,
      status: budget ? 'unknown' : 'temporary_error',
      domains: [fromDomain],
      reason: budget
        ? 'The DNS lookup limit for one message was reached before the DMARC policy was found.'
        : 'The DMARC policy could not be looked up. Try again.',
      details: { ...method, fromDomain },
    };
  }

  const record = discovery.record || null;
  const policy = record ? getDmarcRecord.getPolicyTags(record) : null;
  const strict = record?.adkim === 's';
  const fromOrg = discovery.orgDomain;

  const orgOf = async (domain: string) => {
    try {
      return await getDmarcRecord.getOrgDomain(domain, lookup);
    } catch {
      return null;
    }
  };

  const aligned: string[] = [];
  for (const signature of signatures) {
    const d = signature.domain?.toLowerCase();
    if (signature.status !== 'pass' || !d) continue;
    if (d === fromDomain) aligned.push(signature.evidenceId);
    else if (!strict && fromOrg && (await orgOf(d)) === fromOrg) aligned.push(signature.evidenceId);
  }

  const details = {
    ...method,
    fromDomain,
    orgDomain: fromOrg,
    recordDomain: discovery.recordDomain,
    record: record?.rr ?? null,
    policy: policy?.p ?? null,
    subdomainPolicy: policy?.sp ?? null,
    alignmentMode: strict ? 'strict' : 'relaxed',
    pct: record?.pct ?? null,
    alignedSignatures: aligned,
    aligned: aligned.length > 0,
  };
  const domains = [...new Set([fromDomain, fromOrg].filter((d): d is string => !!d))];

  if (!record || !policy) {
    return {
      ...base,
      status: 'missing',
      domains,
      reason: aligned.length
        ? `${fromDomain} publishes no DMARC policy; a verified DKIM signature does align with it.`
        : `${fromDomain} publishes no DMARC policy.`,
      details,
    };
  }
  if (aligned.length > 0) {
    return {
      ...base,
      status: 'pass',
      domains,
      reason: `A locally verified DKIM signature aligns (${details.alignmentMode}) with ${fromDomain}. Partial result: DKIM only.`,
      details,
    };
  }
  return {
    ...base,
    status: 'unknown',
    domains,
    reason: `No locally verified DKIM signature aligns with ${fromDomain}. SPF cannot be checked here, so the receiver's DMARC result may differ.`,
    details,
  };
}
