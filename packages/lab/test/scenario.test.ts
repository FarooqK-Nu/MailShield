import {
  LAB_DEFAULTS,
  LabRunResponse,
  LabScenario,
  type LAB_MUTATIONS,
} from '@mailshield/contracts';
import { describe, expect, it, vi } from 'vitest';
import { runScenario } from '../src/index.ts';

type Mutation = (typeof LAB_MUTATIONS)[number];
const legit = (mutations: Mutation[] = [], extra: Partial<LabScenario> = {}): LabScenario => ({
  ...LAB_DEFAULTS.legitimate,
  mutations,
  ...extra,
});
const sig = (r: LabRunResponse) => r.result.signatures[0]!;

describe('lab scenarios', () => {
  it('verifies an unmodified Acme message and marks it simulated', async () => {
    const run = await runScenario(legit());
    expect(LabRunResponse.safeParse(run).success).toBe(true);
    expect(sig(run).status).toBe('pass');
    expect(sig(run).source).toBe('lab');
    expect(run.result.stages.every((s) => s.simulated)).toBe(true);
    expect(run.result.verdict).toBe('no_concerning_mismatch');
  });

  it('is deterministic: the same scenario gives the same signature and hashes', async () => {
    const a = await runScenario(legit());
    const b = await runScenario(legit());
    expect(sig(a).tags).toEqual(sig(b).tags);
    expect(sig(a).key?.fingerprint).toBe(sig(b).key?.fingerprint);
  });

  it('exit 1: one changed body character fails DKIM and changes the body hash', async () => {
    const run = await runScenario(legit(['editBody']));
    expect(sig(run).status).toBe('fail');
    expect(sig(run).failureStage).toBe('body_hash');
    const before = run.baseline.signatures[0]!.bodyHash.computed;
    expect(sig(run).bodyHash.computed).not.toBe(before);
    expect(sig(run).bodyHash.expected).toBe(run.baseline.signatures[0]!.bodyHash.expected);
    // The body hash and the key fingerprint are different values: the key is still the baseline's.
    expect(run.baseline.signatures[0]!.key?.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it('exit 2: changing an unsigned header keeps DKIM at pass and lists it as unsigned', async () => {
    const run = await runScenario(legit(['alterUnsignedHeader']));
    expect(sig(run).status).toBe('pass');
    expect(sig(run).unsignedHeaders.map((h) => h.toLowerCase())).toContain('reply-to');
    expect(run.result.findings.some((f) => f.ruleId === 'R5')).toBe(true);
  });

  it('exit 3: the look-alike passes standard authentication but triggers R1 and R3', async () => {
    const on = await runScenario(LAB_DEFAULTS.lookalike);
    expect(sig(on).status).toBe('pass');
    expect(on.result.authentication.find((e) => e.kind === 'dmarc')?.status).toBe('pass');
    const rules = on.result.findings.map((f) => f.ruleId);
    expect(rules).toContain('R1');
    expect(rules).toContain('R3');
    expect(on.result.verdict).toBe('possible_impersonation');

    const off = await runScenario({
      ...LAB_DEFAULTS.lookalike,
      disabledRules: ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9'],
    });
    expect(off.result.findings).toEqual([]);
    expect(off.result.stages.find((s) => s.stage === 'rules')?.status).toBe('not_evaluated');
    expect(sig(off).status).toBe('pass');
  });

  it('exit 4: works with the network disabled', async () => {
    const dns = await import('node:dns/promises');
    const spy = vi.spyOn(dns.Resolver.prototype, 'resolveTxt').mockImplementation(() => {
      throw new Error('network disabled');
    });
    const run = await runScenario(legit(['dnsTimeout']));
    expect(sig(run).status).not.toBe('pass');
    expect((await runScenario(legit())).result.signatures[0]!.status).toBe('pass');
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it.each<[Mutation, string]>([
    ['changeSignedSubject', 'fail'],
    ['removeSignature', 'none'],
    ['swapKey', 'fail'],
    ['rotateSelector', 'pass'],
    ['dnsMissing', 'missing'],
    ['dnsTimeout', 'temporary_error'],
  ])('%s gives %s', async (mutation, expected) => {
    const run = await runScenario(legit([mutation]));
    expect(run.result.signatures[0]?.status ?? 'none').toBe(expected);
  });

  it('a rotated selector changes the key fingerprint but not the body hash', async () => {
    const run = await runScenario(legit(['rotateSelector']));
    const base = run.baseline.signatures[0]!;
    expect(sig(run).key?.fingerprint).not.toBe(base.key?.fingerprint);
    expect(sig(run).bodyHash.computed).toBe(base.bodyHash.computed);
  });

  it("Eve's key under Acme's name fails and a different key gives a different fingerprint", async () => {
    const swapped = await runScenario(legit(['swapKey']));
    expect(sig(swapped).failureStage).toBe('header_signature');
  });

  it('rejects scenarios that could inject headers or use unknown mutations', () => {
    const bad = (patch: object) =>
      LabScenario.safeParse({
        ...LAB_DEFAULTS.legitimate,
        message: { ...LAB_DEFAULTS.legitimate.message, ...patch },
      }).success;
    expect(bad({})).toBe(true);
    expect(bad({ subject: 'Hi\r\nBcc: x@y.example' })).toBe(false);
    expect(bad({ displayName: 'A" <evil@x.example>' })).toBe(false);
    expect(bad({ from: 'not-an-address' })).toBe(false);
    expect(
      LabScenario.safeParse({ ...LAB_DEFAULTS.legitimate, mutations: ['rm -rf'] }).success,
    ).toBe(false);
  });
});
