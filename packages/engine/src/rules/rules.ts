import type {
  Evidence,
  Finding,
  Identity,
  IdentityCandidate,
  LinkEvidence,
  MatchReason,
  SenderView,
  SignatureEvidence,
} from '@mailshield/contracts';
import { analyzeDomain, matchesApproved } from '../identity/domain.ts';
import { compareLabels } from '../identity/similarity.ts';
import type { RuleConfig, RuleId } from './config.ts';

/** Everything a rule may read. Rules are pure functions of this. */
export interface RuleContext {
  sender: SenderView;
  signatures: SignatureEvidence[];
  authentication: Evidence[];
  candidates: IdentityCandidate[];
  identities: readonly Identity[];
  links: LinkEvidence[];
  headerOnly: boolean;
  config: RuleConfig;
}

type Draft = Omit<Finding, 'id' | 'ruleId' | 'ruleVersion'> & { kind: string };

const NAME_REASONS: MatchReason[] = ['display_name', 'alias', 'name_contains', 'lookalike_name'];
const RECOMMEND_CHECK =
  'Do not use links or reply details in this message. Contact the organization through an address or website you already know.';

const registrable = (domain: string) => analyzeDomain(domain).registrable ?? domain;
const domainGroup = (domain: string) => `domain:${registrable(domain)}`;

export function fromMailbox(ctx: RuleContext) {
  return ctx.sender.fromAmbiguous ? undefined : ctx.sender.from[0];
}

/** Ids of passing signatures that align with the From domain (from the DMARC stage). */
export function alignedSignatures(ctx: RuleContext): SignatureEvidence[] {
  const dmarc = ctx.authentication.find((e) => e.id === 'dmarc-local');
  const ids = (dmarc?.details.alignedSignatures as string[] | undefined) ?? [];
  return ctx.signatures.filter((s) => s.status === 'pass' && ids.includes(s.evidenceId));
}

const identityOf = (ctx: RuleContext, id: string) => ctx.identities.find((i) => i.id === id);
const active = (ctx: RuleContext) =>
  ctx.candidates.filter((c) => c.trustState !== 'revoked' && identityOf(ctx, c.identityId));
const claimedByName = (c: IdentityCandidate) => c.reasons.some((r) => NAME_REASONS.includes(r));
const signatureIds = (ctx: RuleContext) =>
  ctx.signatures.length ? ctx.signatures.map((s) => s.evidenceId) : ['dkim-none'];

/** R1: the display name claims a registry organization, but the domain is not one of its own. */
function r1(ctx: RuleContext): Draft[] {
  const from = fromMailbox(ctx);
  if (!from) return [];
  const aligned = alignedSignatures(ctx);
  return active(ctx)
    .filter((c) => c.kind === 'organization' && claimedByName(c) && !c.approvedDomain)
    .flatMap((c) => {
      const identity = identityOf(ctx, c.identityId)!;
      if (aligned.some((s) => identity.domains.some((a) => matchesApproved(s.domain ?? '', a)))) {
        return [];
      }
      const own = ctx.signatures.find(
        (s) =>
          s.status === 'pass' && s.domain && registrable(s.domain) === registrable(from.domain),
      );
      const approved = identity.domains.map((d) => d.domainUnicode).join(', ');
      return [
        {
          kind: 'display_name',
          severity: 'high' as const,
          title: `Display name claims ${identity.displayName}, but the domain is not theirs`,
          observed: `“${from.displayName}” sent from ${from.domainUnicode}`,
          expected: approved
            ? `A domain approved for ${identity.displayName}: ${approved}`
            : undefined,
          evidenceRefs: [...signatureIds(ctx), 'dmarc-local'],
          explanation: own
            ? `${from.domainUnicode} has a valid DKIM signature, so the message really comes from ${from.domainUnicode}. That domain is not one of ${identity.displayName}'s approved domains. Authentication proves the domain, not the name shown.`
            : `Anyone can type any display name. ${from.domainUnicode} is not one of ${identity.displayName}'s approved domains.`,
          recommendation: RECOMMEND_CHECK,
          group: domainGroup(from.domain),
        },
      ];
    });
}

/** R2: a known person's name with an address that is not theirs. */
function r2(ctx: RuleContext): Draft[] {
  const from = fromMailbox(ctx);
  if (!from) return [];
  return active(ctx)
    .filter((c) => c.kind === 'person' && claimedByName(c))
    .map((c) => {
      const identity = identityOf(ctx, c.identityId)!;
      const known = identity.addresses.map((a) => a.address.toLowerCase());
      const matches = known.includes(from.address.toLowerCase());
      if (!matches && known.length > 0) {
        return {
          kind: 'mismatch',
          severity: 'high' as const,
          title: `Name of ${identity.displayName}, but not one of their addresses`,
          observed: from.address,
          expected: `One of: ${known.join(', ')}`,
          evidenceRefs: [`registry:${identity.id}`],
          explanation: `The display name matches ${identity.displayName} in your registry, but ${from.address} is not an address you trust for them.`,
          recommendation: `Check with ${identity.displayName} through a contact you already know.`,
          group: `person:${identity.id}`,
        };
      }
      return {
        kind: 'unverified',
        severity: 'info' as const,
        title: `Personal identity of ${identity.displayName} not verified`,
        observed: from.address,
        evidenceRefs: [`registry:${identity.id}`],
        explanation:
          'No personal signature was checked, so the message is not confirmed to be from this person. This is not a sign of fraud on its own.',
        recommendation: 'For sensitive requests, confirm through another channel.',
        group: `person:${identity.id}`,
      };
    });
}

/** R3: the From domain looks like a registry domain but is a different one. */
function r3(ctx: RuleContext): Draft[] {
  const from = fromMailbox(ctx);
  if (!from) return [];
  return active(ctx).flatMap((c) =>
    c.lookalikes.map((l) => {
      const diff = l.diff
        .map((d) => {
          const shown = `“${d.observed}” (${d.observedCodePoints.join(', ')})`;
          if (d.kind === 'removed') return `“${d.expected}” is missing`;
          if (d.kind === 'inserted') return `${shown} is extra`;
          return `${shown} instead of “${d.expected}”`;
        })
        .join('; ');
      return {
        kind: l.strength,
        severity: l.strength === 'strong' ? ('high' as const) : ('caution' as const),
        title: `${l.observed} looks like ${l.approved}`,
        observed: l.observed,
        expected: l.approved,
        evidenceRefs: [`domain:from`, `registry:${c.identityId}`],
        explanation: `${l.observed} is a different domain from ${c.displayName}'s ${l.approved} (${l.reasons.join(', ')}). Differences: ${diff || 'same skeleton'}.`,
        recommendation: RECOMMEND_CHECK,
        group: domainGroup(from.domain),
      };
    }),
  );
}

/** R4: a brand appears only in a subdomain or inside another registrable domain. */
function r4(ctx: RuleContext): Draft[] {
  const from = fromMailbox(ctx);
  if (!from) return [];
  const actual = analyzeDomain(from.domain).registrableUnicode ?? from.domainUnicode;
  return active(ctx)
    .filter((c) => c.reasons.includes('brand_in_subdomain') || c.reasons.includes('brand_token'))
    .map((c) => ({
      kind: 'structure',
      severity: 'caution' as const,
      title: `${c.displayName}'s name is part of a different domain`,
      observed: from.domainUnicode,
      expected: `The actual domain is ${actual}`,
      evidenceRefs: [`domain:from`, `registry:${c.identityId}`],
      explanation: `The address contains “${c.displayName}”, but the domain that was actually registered is ${actual}, which is not ${c.displayName}'s.`,
      recommendation: RECOMMEND_CHECK,
      group: domainGroup(from.domain),
    }));
}

/** R5: replies would go to a different organization than the sender. */
function r5(ctx: RuleContext): Draft[] {
  const from = fromMailbox(ctx);
  if (!from) return [];
  const approved = active(ctx).flatMap((c) => identityOf(ctx, c.identityId)!.domains);
  return ctx.sender.replyTo
    .filter((r) => r.domain && registrable(r.domain) !== registrable(from.domain))
    .filter((r) => !approved.some((a) => matchesApproved(r.domain, a)))
    .map((r) => ({
      kind: 'reply_to',
      severity: 'caution' as const,
      title: 'Replies go to a different domain',
      observed: `Reply-To: ${r.address}`,
      expected: `An address at ${registrable(from.domain)}`,
      evidenceRefs: ['domain:reply_to'],
      explanation: `The message is from ${from.domainUnicode}, but replies would go to ${r.domainUnicode}. This is common in phishing, but some services do it legitimately.`,
      recommendation: 'Check the reply address before answering.',
      group: null,
    }));
}

/** R6: authentication problems with the From identity. */
function r6(ctx: RuleContext): Draft[] {
  const out: Draft[] = [];
  if (ctx.sender.fromAmbiguous) {
    out.push({
      kind: 'malformed_from',
      severity: 'caution',
      title: 'The sender is ambiguous',
      observed: `${ctx.sender.from.length} From address(es)`,
      expected: 'Exactly one From address with a domain',
      evidenceRefs: [],
      explanation:
        'A message should name exactly one sender. Mail programs may show a different one than the one that was checked.',
      recommendation: RECOMMEND_CHECK,
      group: null,
    });
  }
  const from = fromMailbox(ctx);
  const aligned = alignedSignatures(ctx);
  if (from && aligned.length === 0) {
    for (const s of ctx.signatures) {
      if (s.status !== 'fail' || !s.domain || registrable(s.domain) !== registrable(from.domain)) {
        continue;
      }
      out.push({
        kind: 'invalid_dkim',
        severity: 'caution',
        title: `The signature from ${s.domain} is invalid`,
        observed: s.reason,
        expected: 'A valid signature from the From domain',
        evidenceRefs: [s.evidenceId],
        explanation: `The message claims to be from ${from.domainUnicode} and carries its signature, but the signature does not verify. No other valid signature aligns with the From domain.`,
        recommendation: RECOMMEND_CHECK,
        group: `dkim:${s.evidenceId}`,
      });
    }
  }
  for (const e of ctx.authentication) {
    if (e.kind === 'dmarc' && e.source === 'trusted_receiver' && e.status === 'fail') {
      out.push({
        kind: 'dmarc_fail',
        severity: 'caution',
        title: 'Your mail provider reports a DMARC failure',
        observed: e.reason,
        evidenceRefs: [e.id],
        explanation:
          'The receiving server found that no authenticated identity aligns with the From domain.',
        recommendation: RECOMMEND_CHECK,
        group: null,
      });
    }
  }
  const dmarc = ctx.authentication.find((e) => e.id === 'dmarc-local');
  const policy = dmarc?.details.policy;
  if (from && dmarc && aligned.length === 0 && (policy === 'reject' || policy === 'quarantine')) {
    out.push({
      kind: 'policy_unaligned',
      severity: 'caution',
      title: `${from.domainUnicode} asks receivers to ${policy} unauthenticated mail`,
      observed: 'No locally verified signature aligns with the From domain',
      expected: `A valid signature from ${registrable(from.domain)}`,
      evidenceRefs: ['dmarc-local', ...signatureIds(ctx)],
      explanation: `${from.domainUnicode} publishes DMARC p=${policy}. Nothing checked here proves the message comes from it. SPF cannot be checked for an uploaded message, so the receiver may still have accepted it.`,
      recommendation: RECOMMEND_CHECK,
      group: domainGroup(from.domain),
    });
  }
  for (const s of ctx.signatures) {
    const weak = s.warnings.filter((w) => w.includes('bits') || w.includes('rsa-sha1'));
    if (s.status === 'pass' && weak.length > 0) {
      out.push({
        kind: 'weak_key',
        severity: 'caution',
        title: `The signature from ${s.domain} uses weak cryptography`,
        observed: weak.join(' '),
        expected: 'RSA 2048 bits or more with SHA-256',
        evidenceRefs: [s.evidenceId],
        explanation: 'Weak keys or hashes can be forged by a determined attacker.',
        recommendation: 'Treat the signature as weaker evidence.',
        group: `dkim:${s.evidenceId}`,
      });
    }
  }
  return out;
}

/** R7: a link's visible text names a different host than its target. Nothing is fetched. */
function r7(ctx: RuleContext): Draft[] {
  const out: Draft[] = [];
  const domains = active(ctx).flatMap((c) => identityOf(ctx, c.identityId)!.domains);
  const allDomains = ctx.identities.filter((i) => !i.deletedAt).flatMap((i) => i.domains);
  for (const link of ctx.links) {
    if (!link.hrefHost) continue;
    const target = analyzeDomain(link.hrefHost);
    if (link.textHost && registrable(link.textHost) !== registrable(link.hrefHost)) {
      out.push({
        kind: 'text_mismatch',
        severity: 'caution',
        title: 'A link goes somewhere other than it says',
        observed: `Shows ${link.textHost}, opens ${link.hrefHost}`,
        expected: `A link to ${link.textHost}`,
        evidenceRefs: [link.id],
        explanation:
          'The visible text of the link names one website, but clicking it opens another.',
        recommendation:
          'Do not click the link. Type the address you expect into the browser instead.',
        group: `link:${link.id}`,
      });
      continue;
    }
    if (!target.labelUnicode || allDomains.some((a) => matchesApproved(link.hrefHost!, a)))
      continue;
    const lookalike = [...domains, ...allDomains].find((a) => {
      const approved = analyzeDomain(a.domainAscii);
      return (
        approved.labelUnicode &&
        approved.registrable !== target.registrable &&
        compareLabels(target.labelUnicode!, approved.labelUnicode).lookalike
      );
    });
    if (lookalike) {
      out.push({
        kind: 'confusable_host',
        severity: 'caution',
        title: `A link points to a look-alike of ${lookalike.domainUnicode}`,
        observed: link.hrefHost,
        expected: lookalike.domainUnicode,
        evidenceRefs: [link.id],
        explanation: `${target.registrableUnicode} resembles ${lookalike.domainUnicode} in your registry but is a different domain.`,
        recommendation: 'Do not click the link.',
        group: `link:${link.id}`,
      });
    }
  }
  return out;
}

/** R9: partial coverage is a limitation; a broken signature may mean tampering. */
function r9(ctx: RuleContext): Draft[] {
  const out: Draft[] = [];
  for (const s of ctx.signatures) {
    if (s.status === 'pass' && s.bodyCoverage) {
      out.push({
        kind: 'partial_body',
        severity: 'info',
        title: `The signature from ${s.domain} covers only part of the body`,
        observed: `l=${s.bodyCoverage.signedBytes} bytes signed${s.bodyCoverage.unsignedBytes ? `, ${s.bodyCoverage.unsignedBytes} bytes not signed` : ''}`,
        expected: 'The whole body signed',
        evidenceRefs: [s.evidenceId],
        explanation:
          'Text after the signed length could have been added by anyone without breaking the signature.',
        recommendation: 'Do not rely on content near the end of the message.',
        group: `dkim:${s.evidenceId}`,
      });
    }
    if (s.status === 'pass' && s.unsignedHeaders.length > 0) {
      out.push({
        kind: 'unsigned_headers',
        severity: 'info',
        title: `Some headers are not covered by the signature from ${s.domain}`,
        observed: s.unsignedHeaders.join(', '),
        evidenceRefs: [s.evidenceId],
        explanation:
          'These headers could have been changed after signing without breaking the signature.',
        recommendation: 'Do not rely on the unsigned headers.',
        group: `dkim:${s.evidenceId}`,
      });
    }
    if (
      s.status === 'fail' &&
      (s.failureStage === 'body_hash' || s.failureStage === 'header_signature')
    ) {
      out.push({
        kind: 'tampering',
        severity: 'caution',
        title: `The message changed after ${s.domain} signed it`,
        observed: s.reason,
        evidenceRefs: [s.evidenceId],
        explanation:
          s.failureStage === 'body_hash'
            ? 'The body no longer matches the signed body hash. Mailing lists and forwarding can also change a body.'
            : 'A signed header no longer matches the signature. Some forwarding services also rewrite headers.',
        recommendation: 'Treat the content as unverified.',
        group: `dkim:${s.evidenceId}`,
      });
    }
  }
  return out;
}

const RULES: Record<RuleId, ((ctx: RuleContext) => Draft[]) | null> = {
  R1: r1,
  R2: r2,
  R3: r3,
  R4: r4,
  R5: r5,
  R6: r6,
  R7: r7,
  R8: null,
  R9: r9,
};

export interface RuleRun {
  findings: Finding[];
  evaluated: RuleId[];
  notEvaluated: RuleId[];
}

/** Runs the enabled rules in order. Finding ids look like `R6:invalid_dkim:1`. */
export function runRules(ctx: RuleContext): RuleRun {
  const findings: Finding[] = [];
  const evaluated: RuleId[] = [];
  const notEvaluated: RuleId[] = [];
  for (const [ruleId, rule] of Object.entries(RULES) as [RuleId, typeof r1 | null][]) {
    if (!rule || !ctx.config.enabled[ruleId]) {
      notEvaluated.push(ruleId);
      continue;
    }
    evaluated.push(ruleId);
    const counts = new Map<string, number>();
    for (const { kind, ...draft } of rule(ctx)) {
      const n = (counts.get(kind) ?? 0) + 1;
      counts.set(kind, n);
      findings.push({
        id: `${ruleId}:${kind}:${n}`,
        ruleId,
        ruleVersion: ctx.config.version,
        ...draft,
      });
    }
  }
  return { findings, evaluated, notEvaluated };
}
