import type {
  DomainInspection,
  DomainLookalike,
  Identity,
  IdentityCandidate,
  MatchReason,
} from '@mailshield/contracts';
import { confusableKey, describeCodePoints, isMixedScript, scriptsOf } from './confusables.ts';
import { analyzeDomain, matchesApproved } from './domain.ts';
import { compareLabels, tokens } from './similarity.ts';

/** Read-only view of the trusted identity registry. Deleted identities are left out. */
export interface RegistryPort {
  identities(): Promise<readonly Identity[]>;
}

export const emptyRegistry: RegistryPort = { identities: async () => [] };

/** Case-fold, NFKC, and collapse whitespace and punctuation to single spaces. */
export function normalizeName(value: string): string {
  return value
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[\p{P}\p{S}\s]+/gu, ' ')
    .trim();
}

function containsWords(haystack: string, needle: string): boolean {
  return needle.length > 0 && ` ${haystack} `.includes(` ${needle} `);
}

export function inspectDomain(role: DomainInspection['role'], domain: string): DomainInspection {
  const parts = analyzeDomain(domain);
  const label = parts.labelUnicode ?? parts.unicode;
  return {
    role,
    ascii: parts.ascii,
    unicode: parts.unicode,
    registrable: parts.registrable,
    registrableUnicode: parts.registrableUnicode,
    subdomain: parts.subdomain,
    publicSuffix: parts.publicSuffix,
    isIdn: parts.isIdn,
    scripts: scriptsOf(parts.unicode),
    mixedScript: parts.unicode.split('.').some(isMixedScript),
    codePoints: describeCodePoints(label),
  };
}

export interface ClaimInput {
  displayName: string;
  address: string;
  /** ASCII form of the From domain. */
  domain: string;
}

const WEIGHTS: Record<MatchReason, number> = {
  trusted_address: 100,
  approved_domain: 90,
  display_name: 80,
  alias: 80,
  lookalike_domain: 70,
  lookalike_name: 60,
  name_contains: 60,
  brand_in_subdomain: 45,
  brand_token: 40,
};

function nameReasons(identity: Identity, displayName: string): [MatchReason, string][] {
  const shown = normalizeName(displayName);
  if (!shown) return [];
  const names = [
    { text: normalizeName(identity.displayName), exact: 'display_name' as const },
    ...identity.aliases.map((a) => ({ text: normalizeName(a.alias), exact: 'alias' as const })),
  ].filter((n) => n.text);

  for (const name of names) {
    if (shown === name.text) return [[name.exact, `The display name equals “${name.text}”.`]];
  }
  for (const name of names) {
    if (containsWords(shown, name.text)) {
      return [['name_contains', `The display name contains “${name.text}”.`]];
    }
  }
  const shownKey = confusableKey(shown);
  for (const name of names) {
    const key = confusableKey(name.text);
    if (shownKey === key || containsWords(shownKey, key)) {
      return [
        [
          'lookalike_name',
          `The display name looks like “${name.text}” but is spelled differently.`,
        ],
      ];
    }
  }
  return [];
}

function domainReasons(identity: Identity, domain: string) {
  const reasons: [MatchReason, string][] = [];
  const lookalikes: DomainLookalike[] = [];
  let approvedDomain: IdentityCandidate['approvedDomain'] = null;
  const observed = analyzeDomain(domain);
  if (!observed.ascii) return { reasons, lookalikes, approvedDomain };

  for (const approved of identity.domains) {
    if (matchesApproved(observed.ascii, approved)) {
      approvedDomain = { domain: approved.domainAscii, relationship: approved.relationship };
      reasons.push(['approved_domain', `${observed.unicode} is an approved domain.`]);
      return { reasons, lookalikes, approvedDomain };
    }
  }

  for (const approved of identity.domains) {
    const target = analyzeDomain(approved.domainAscii);
    if (!target.labelUnicode || !observed.labelUnicode) continue;
    if (observed.registrable === target.registrable) continue;

    const comparison = compareLabels(observed.labelUnicode, target.labelUnicode);
    if (comparison.lookalike && comparison.strength) {
      lookalikes.push({
        observed: observed.registrableUnicode ?? observed.unicode,
        approved: target.registrableUnicode ?? target.unicode,
        strength: comparison.strength,
        reasons: comparison.reasons,
        distance: comparison.distance,
        matchedToken: comparison.matchedToken,
        diff: comparison.diff,
      });
      continue;
    }
    if (comparison.matchedToken) {
      reasons.push([
        'brand_token',
        `“${target.labelUnicode}” is part of ${observed.registrableUnicode}, a different domain.`,
      ]);
      continue;
    }
    const subLabels = observed.subdomain.split('.').flatMap(tokens);
    if (subLabels.includes(target.labelUnicode)) {
      reasons.push([
        'brand_in_subdomain',
        `“${target.labelUnicode}” appears only in the subdomain; the actual domain is ${observed.registrableUnicode}.`,
      ]);
    }
  }
  if (lookalikes.length > 0) {
    const best = lookalikes.some((l) => l.strength === 'strong') ? 'strong' : 'weak';
    reasons.push([
      'lookalike_domain',
      `${observed.registrableUnicode} looks like ${lookalikes[0]!.approved} (${best} resemblance).`,
    ]);
  }
  return { reasons, lookalikes, approvedDomain };
}

/**
 * Ranks registry identities the message may be claiming to be, by display name, alias,
 * trusted address or domain. Only the registry is searched; there is no global brand list.
 */
export function matchClaim(
  claim: ClaimInput,
  identities: readonly Identity[],
  topN = 3,
): IdentityCandidate[] {
  const address = claim.address.toLowerCase();
  const candidates: IdentityCandidate[] = [];
  for (const identity of identities) {
    if (identity.deletedAt) continue;
    const found: [MatchReason, string][] = [];
    if (address && identity.addresses.some((a) => a.address.toLowerCase() === address)) {
      found.push(['trusted_address', `${claim.address} is a trusted address.`]);
    }
    found.push(...nameReasons(identity, claim.displayName));
    const domain = domainReasons(identity, claim.domain);
    found.push(...domain.reasons);
    if (found.length === 0) continue;

    const reasons = [...new Set(found.map(([r]) => r))];
    candidates.push({
      identityId: identity.id,
      displayName: identity.displayName,
      kind: identity.kind,
      trustState: identity.trustState,
      score: Math.max(...reasons.map((r) => WEIGHTS[r])) + (reasons.length - 1) * 5,
      reasons,
      approvedDomain: domain.approvedDomain,
      lookalikes: domain.lookalikes,
      explanation: found.map(([, text]) => text),
    });
  }
  return candidates
    .sort((a, b) => b.score - a.score || a.displayName.localeCompare(b.displayName))
    .slice(0, topN);
}
