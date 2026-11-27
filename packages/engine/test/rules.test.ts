import type {
  Evidence,
  Identity,
  KeyObservation,
  Mailbox,
  SignatureEvidence,
} from '@mailshield/contracts';
import { describe, expect, it } from 'vitest';
import {
  decideVerdict,
  DEFAULT_RULE_CONFIG,
  extractLinks,
  matchClaim,
  runRules,
  type RuleContext,
} from '../src/index.ts';

const AT = '2026-06-01T12:00:00.000Z';

function identity(
  id: string,
  kind: Identity['kind'],
  name: string,
  opts: Partial<Pick<Identity, 'trustState'>> & {
    aliases?: string[];
    domains?: [string, Identity['domains'][number]['relationship']?][];
    addresses?: string[];
  } = {},
): Identity {
  return {
    id,
    kind,
    displayName: name,
    trustState: opts.trustState ?? 'user_trusted',
    provenanceUrl: null,
    notes: null,
    lastReviewed: null,
    createdAt: AT,
    updatedAt: AT,
    deletedAt: null,
    aliases: (opts.aliases ?? []).map((alias, i) => ({ id: `${id}-a${i}`, alias })),
    domains: (opts.domains ?? []).map(([domain, relationship = 'own'], i) => ({
      id: `${id}-d${i}`,
      domainAscii: domain,
      domainUnicode: domain,
      includeSubdomains: true,
      relationship,
    })),
    addresses: (opts.addresses ?? []).map((address, i) => ({ id: `${id}-m${i}`, address })),
    keys: [],
  };
}

const acme = (trustState: Identity['trustState'] = 'user_trusted') =>
  identity('acme', 'organization', 'Acme Corporation', {
    trustState,
    aliases: ['Acme Support'],
    domains: [['acme.example'], ['acme-mail.example', 'service_provider']],
  });
const alice = identity('alice', 'person', 'Alice Example', { addresses: ['alice@acme.example'] });

const box = (displayName: string, address: string): Mailbox => {
  const domain = address.split('@')[1] ?? '';
  return { displayName, address, domain, domainUnicode: domain };
};

function signature(
  domain: string,
  status: SignatureEvidence['status'] = 'pass',
  extra: Partial<SignatureEvidence> = {},
): SignatureEvidence {
  return {
    evidenceId: 'dkim-1',
    source: 'local_crypto',
    status,
    failureStage: status === 'fail' ? 'body_hash' : null,
    reason: status,
    domain,
    selector: 's1',
    algorithm: 'rsa-sha256',
    canonicalization: 'relaxed/relaxed',
    tags: {},
    bodyHash: { expected: null, computed: null, matches: null },
    signedHeaders: ['from'],
    unsignedHeaders: [],
    bodyCoverage: null,
    key: null,
    signedAt: null,
    expiresAt: null,
    warnings: [],
    ...extra,
  };
}

interface Options {
  from?: Mailbox[];
  replyTo?: Mailbox[];
  signatures?: SignatureEvidence[];
  aligned?: boolean;
  policy?: string | null;
  identities?: Identity[];
  html?: string;
  extraEvidence?: Evidence[];
  history?: KeyObservation[];
}

function context(o: Options = {}): RuleContext {
  const from = o.from ?? [box('Acme Support', 'support@acme.example')];
  const signatures = o.signatures ?? [signature(from[0]?.domain ?? '')];
  const identities = o.identities ?? [acme(), alice];
  const ambiguous = from.length !== 1;
  const aligned = (o.aligned ?? true) ? signatures.filter((s) => s.status === 'pass') : [];
  return {
    personal: null,
    sender: {
      from,
      fromAmbiguous: ambiguous,
      sender: [],
      replyTo: o.replyTo ?? [],
      returnPath: [],
      subject: null,
      date: null,
      messageId: null,
    },
    signatures,
    authentication: [
      {
        id: 'dmarc-local',
        kind: 'dmarc',
        source: 'local_crypto',
        status: aligned.length ? 'pass' : 'unknown',
        domains: [],
        reason: '',
        observedAt: AT,
        details: { alignedSignatures: aligned.map((s) => s.evidenceId), policy: o.policy ?? null },
      },
      ...(o.extraEvidence ?? []),
    ],
    candidates: ambiguous ? [] : matchClaim({ ...from[0]!, domain: from[0]!.domain }, identities),
    identities,
    links: o.html ? extractLinks(o.html) : [],
    headerOnly: false,
    config: DEFAULT_RULE_CONFIG,
    history: o.history,
  };
}

const evaluate = (o: Options = {}) => {
  const ctx = context(o);
  const { findings, notEvaluated } = runRules(ctx);
  return {
    findings,
    notEvaluated,
    ids: findings.map((f) => f.id),
    ...decideVerdict(ctx, findings),
  };
};

describe('rules', () => {
  it('stay silent on a corroborated Acme message (row 4)', () => {
    const r = evaluate();
    expect(r.ids).toEqual([]);
    expect(r.verdict).toBe('no_concerning_mismatch');
    expect(r.identityStatus).toBe('corroborated_domain');
    expect(r.riskLevel).toBe('low');
    expect(r.basis).toMatchObject({ row: 4, evidenceIds: ['dkim-1', 'dmarc-local'] });
  });

  it('R1 fires on a claimed name from another domain, even with DKIM passing', () => {
    const r = evaluate({ from: [box('Acme Support', 'help@unrelated.example')] });
    expect(r.ids).toContain('R1:display_name:1');
    expect(r.verdict).toBe('possible_impersonation');
    expect(r.basis.findingIds).toContain('R1:display_name:1');
  });

  it('R1 accepts an approved service provider', () => {
    const r = evaluate({ from: [box('Acme Support', 'news@acme-mail.example')] });
    expect(r.ids.filter((id) => id.startsWith('R1'))).toEqual([]);
  });

  it('R2 flags a known person at an unexpected address, and only notes the right one', () => {
    const wrong = evaluate({ from: [box('Alice Example', 'alice@freemail.example')] });
    expect(wrong.ids).toContain('R2:mismatch:1');
    expect(wrong.verdict).toBe('possible_impersonation');

    const right = evaluate({ from: [box('Alice Example', 'alice@acme.example')] });
    expect(right.findings.find((f) => f.ruleId === 'R2')).toMatchObject({ severity: 'info' });
    expect(right.ids).not.toContain('R2:mismatch:1');
  });

  it('R4 flags a brand inside a different registrable domain', () => {
    const r = evaluate({ from: [box('Billing', 'billing@acme.example.net')] });
    expect(r.ids).toContain('R4:structure:1');
    expect(r.findings.find((f) => f.ruleId === 'R4')!.expected).toContain('example.net');
    expect(evaluate().ids.some((id) => id.startsWith('R4'))).toBe(false);
  });

  it('R5 ignores a Reply-To at an approved domain', () => {
    const r = evaluate({ replyTo: [box('', 'replies@acme-mail.example')] });
    expect(r.ids.some((id) => id.startsWith('R5'))).toBe(false);
    const other = evaluate({ replyTo: [box('', 'x@elsewhere.example')] });
    expect(other.ids).toContain('R5:reply_to:1');
    expect(other.verdict).toBe('identity_unverified');
    expect(other.riskLevel).toBe('caution');
    expect(other.basis.row).toBe(5);
  });

  it('R6 marks an ambiguous From (row 2)', () => {
    const r = evaluate({
      from: [box('A', 'a@acme.example'), box('B', 'b@other.example')],
      signatures: [],
    });
    expect(r.ids).toContain('R6:malformed_from:1');
    expect(r.verdict).toBe('authentication_concern');
    expect(r.identityStatus).toBe('ambiguous');
  });

  it('R6 reports a trusted DMARC fail (row 3)', () => {
    const r = evaluate({
      aligned: false,
      signatures: [],
      extraEvidence: [
        {
          id: 'receiver-1',
          kind: 'dmarc',
          source: 'trusted_receiver',
          status: 'fail',
          domains: ['acme.example'],
          reason: 'dmarc=fail',
          observedAt: AT,
          details: {},
        },
      ],
    });
    expect(r.ids).toContain('R6:dmarc_fail:1');
    expect(r.verdict).toBe('authentication_concern');
    expect(r.basis.row).toBe(3);
  });

  it('R6 ignores an untrusted DMARC fail written in the message', () => {
    const r = evaluate({
      extraEvidence: [
        {
          id: 'receiver-1',
          kind: 'dmarc',
          source: 'untrusted_header',
          status: 'fail',
          domains: [],
          reason: '',
          observedAt: AT,
          details: {},
        },
      ],
    });
    expect(r.ids).toEqual([]);
  });

  it('R6 flags weak keys', () => {
    const weak = signature('acme.example', 'pass', {
      warnings: ['The RSA key is only 1024 bits; 2048 or more is recommended.'],
    });
    const r = evaluate({ signatures: [weak] });
    expect(r.ids).toContain('R6:weak_key:1');
    expect(r.basis.row).toBe(5);
  });

  it('R7 flags a link to a confusable host, and not a link to an approved one', () => {
    const bad = evaluate({ html: '<a href="https://acrne.example/x">Sign in</a>' });
    expect(bad.ids).toContain('R7:confusable_host:1');
    const good = evaluate({ html: '<a href="https://www.acme.example/x">www.acme.example</a>' });
    expect(good.ids.some((id) => id.startsWith('R7'))).toBe(false);
  });

  it('leave R8 not evaluated', () => {
    expect(evaluate().notEvaluated).toEqual(['R8']);
  });

  it('skip disabled rules', () => {
    const ctx = context({ from: [box('Acme Support', 'help@unrelated.example')] });
    ctx.config = {
      ...DEFAULT_RULE_CONFIG,
      enabled: { ...DEFAULT_RULE_CONFIG.enabled, R1: false, R3: false },
    };
    const { findings, notEvaluated } = runRules(ctx);
    expect(findings.some((f) => f.ruleId === 'R1')).toBe(false);
    expect(notEvaluated).toEqual(['R1', 'R3', 'R8']);
  });
});

describe('verdict trust states (A-11)', () => {
  it('an unverified entry cannot corroborate', () => {
    const r = evaluate({ identities: [acme('unverified')] });
    expect(r.verdict).toBe('identity_unverified');
    expect(r.identityStatus).toBe('unverified');
    expect(r.limitations.join(' ')).toContain('unverified');
  });

  it('a revoked entry is ignored by the mismatch rules', () => {
    const r = evaluate({
      identities: [acme('revoked')],
      from: [box('Acme Support', 'help@unrelated.example')],
    });
    expect(r.ids.some((id) => id.startsWith('R1'))).toBe(false);
  });

  it('no registry match gives row 6 with unknown risk', () => {
    const r = evaluate({ identities: [], from: [box('Bob', 'bob@else.example')] });
    expect(r).toMatchObject({ verdict: 'identity_unverified', riskLevel: 'unknown' });
    expect(r.basis.row).toBe(6);
  });
});

describe('links', () => {
  it('records href and visible host without fetching', () => {
    expect(
      extractLinks(
        '<p><a href="https://evil.example/a">https://acme.example/login</a> <a>x</a></p>',
      ),
    ).toEqual([
      {
        id: 'link-1',
        visibleText: 'https://acme.example/login',
        href: 'https://evil.example/a',
        hrefHost: 'evil.example',
        textHost: 'acme.example',
      },
    ]);
    expect(extractLinks('<a href="mailto:a@b.example">Write to us</a>')[0]).toMatchObject({
      hrefHost: null,
      textHost: null,
    });
  });
});

const key = (selector = 's1', fingerprint = 'aa'.repeat(32)) =>
  signature('acme.example', 'pass', {
    selector,
    key: { type: 'rsa', bits: 2048, fingerprint, testing: false },
  });
const seen = (
  selector: string,
  fingerprint: string,
  status: KeyObservation['status'] = 'current',
): KeyObservation => ({
  id: `${selector}-${fingerprint.slice(0, 2)}`,
  domain: 'acme.example',
  selector,
  fingerprint,
  firstSeen: AT,
  lastSeen: AT,
  status,
});
const r8 = (history: KeyObservation[] | undefined, signature = key()) =>
  evaluate({ signatures: [signature], history }).findings.filter((f) => f.ruleId === 'R8');

describe('R8 key history', () => {
  it('is not evaluated when history is off', () => {
    expect(evaluate({ signatures: [key()] }).notEvaluated).toContain('R8');
  });

  it('reports first contact for an unknown domain, as info', () => {
    const [f] = r8([]);
    expect(f).toMatchObject({ id: 'R8:first_contact:1', severity: 'info' });
  });

  it('is silent for a known key', () => {
    expect(r8([seen('s1', 'aa'.repeat(32))])).toEqual([]);
  });

  it('reports a new selector as rotation, and a changed key as an unexpected change', () => {
    expect(r8([seen('s0', 'bb'.repeat(32))]).map((f) => f.id)).toEqual(['R8:rotation:1']);
    expect(r8([seen('s1', 'bb'.repeat(32))]).map((f) => f.id)).toEqual(['R8:unexpected_change:1']);
  });

  it('raises a caution when the key was marked revoked', () => {
    const [f] = r8([seen('s1', 'aa'.repeat(32), 'revoked')]);
    expect(f).toMatchObject({ id: 'R8:revoked:1', severity: 'caution' });
  });
});
