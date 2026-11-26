import type {
  Finding,
  IdentityStatus,
  RiskLevel,
  Verdict,
  VerdictBasis,
} from '@mailshield/contracts';
import { matchesApproved } from '../identity/domain.ts';
import { alignedSignatures, type RuleContext } from './rules.ts';

export interface VerdictOutcome {
  verdict: Verdict;
  identityStatus: IdentityStatus;
  riskLevel: RiskLevel;
  basis: VerdictBasis;
  limitations: string[];
}

const CORROBORATING = new Set(['user_trusted', 'independently_verified']);
const refs = (findings: Finding[]) => [...new Set(findings.flatMap((f) => f.evidenceRefs))];

/**
 * The decision table in docs/architecture.md §3.9. The first matching row wins.
 */
export function decideVerdict(ctx: RuleContext, findings: Finding[]): VerdictOutcome {
  const limitations: string[] = [];
  const out = (
    row: number,
    verdict: Verdict,
    identityStatus: IdentityStatus,
    riskLevel: RiskLevel,
    reason: string,
    basis: Finding[],
    extraEvidence: string[] = [],
  ): VerdictOutcome => ({
    verdict,
    identityStatus,
    riskLevel,
    basis: {
      row,
      reason,
      findingIds: basis.map((f) => f.id),
      evidenceIds: [...new Set([...refs(basis), ...extraEvidence])],
    },
    limitations,
  });

  const high = findings.filter(
    (f) => f.severity === 'high' && ['R1', 'R2', 'R3'].includes(f.ruleId),
  );
  if (high.length > 0) {
    return out(1, 'possible_impersonation', 'mismatch', 'high', high[0]!.title, high);
  }

  const malformed = findings.filter((f) => f.id.startsWith('R6:malformed_from'));
  if (ctx.sender.fromAmbiguous) {
    return out(
      2,
      'authentication_concern',
      'ambiguous',
      'caution',
      'The sender is ambiguous.',
      malformed,
    );
  }

  const authFail = findings.filter(
    (f) => f.id.startsWith('R6:invalid_dkim') || f.id.startsWith('R6:dmarc_fail'),
  );
  if (authFail.length > 0) {
    return out(3, 'authentication_concern', 'unverified', 'caution', authFail[0]!.title, authFail);
  }

  const cautions = findings.filter((f) => f.severity === 'caution');
  const aligned = alignedSignatures(ctx);
  let corroboratedBy: { name: string; signatureId: string } | null = null;
  for (const c of ctx.candidates) {
    const identity = ctx.identities.find((i) => i.id === c.identityId);
    if (!identity || !c.approvedDomain) continue;
    const signature = aligned.find((s) =>
      identity.domains.some((a) => matchesApproved(s.domain ?? '', a)),
    );
    if (!signature) continue;
    if (!CORROBORATING.has(c.trustState)) {
      limitations.push(
        `The matching registry entry for ${c.displayName} is ${c.trustState}, so it cannot confirm the sender.`,
      );
      continue;
    }
    corroboratedBy = { name: c.displayName, signatureId: signature.evidenceId };
    break;
  }

  if (corroboratedBy) {
    limitations.push(
      'This confirms the domain identity, not personal authorship: anyone with access to the domain could have sent it.',
    );
    const evidence = [corroboratedBy.signatureId, 'dmarc-local'];
    if (cautions.length === 0) {
      return out(
        4,
        'no_concerning_mismatch',
        'corroborated_domain',
        'low',
        `A verified signature from an approved ${corroboratedBy.name} domain aligns with the From address.`,
        [],
        evidence,
      );
    }
    return out(
      5,
      'identity_unverified',
      'corroborated_domain',
      'caution',
      `The domain belongs to ${corroboratedBy.name}, but some findings need attention.`,
      cautions,
      evidence,
    );
  }

  if (ctx.candidates.length === 0) limitations.push('No registry identity matches this sender.');
  else if (aligned.length === 0) {
    limitations.push('No locally verified signature aligns with the From domain.');
  }
  return out(
    6,
    'identity_unverified',
    'unverified',
    cautions.length > 0 ? 'caution' : 'unknown',
    'There is not enough evidence to confirm who sent this message.',
    cautions,
  );
}
