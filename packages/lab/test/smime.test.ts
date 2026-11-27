/** Phase 6 exit criteria, with real CMS signatures made by the lab certificate authority. */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LabPersonalResponse, type LabPersonalScenario } from '@mailshield/contracts';
import { analyze } from '@mailshield/engine';
import { describe, expect, it } from 'vitest';
import { FixtureResolver, runPersonalScenario } from '../src/index.ts';

const scenario = (extra: Partial<LabPersonalScenario> = {}): LabPersonalScenario => ({
  signer: 'alice',
  aliceKeyEnrolled: true,
  mutations: [],
  ...extra,
});
const run = (extra?: Partial<LabPersonalScenario>) => runPersonalScenario(scenario(extra));
const personal = (r: LabPersonalResponse) => r.result.personalSignature!;

describe('personal signatures', () => {
  it('exit 1: Alice signs, her key is enrolled -> corroborated_personal', async () => {
    const r = await run();
    expect(LabPersonalResponse.safeParse(r).success).toBe(true);
    expect(personal(r)).toMatchObject({
      status: 'pass',
      signatureValid: true,
      chainTrusted: true,
      emailBinding: true,
      ekuEmailProtection: true,
      timeValid: true,
      revocation: 'unknown',
      enrolledFor: { displayName: 'Alice Example' },
    });
    expect(r.result.identityStatus).toBe('corroborated_personal');
    expect(r.result.verdict).toBe('no_concerning_mismatch');
    expect(r.result.stages.find((s) => s.stage === 'smime')!.simulated).toBe(true);
  });

  it('exit 2: Eve is valid and trusted by the lab CA, but identity is not confirmed', async () => {
    const r = await run({ signer: 'eve' });
    expect(personal(r)).toMatchObject({
      signatureValid: true,
      chainTrusted: true,
      emailBinding: false,
      enrolledFor: null,
    });
    expect(r.result.identityStatus).not.toBe('corroborated_personal');
    expect(r.result.findings.map((f) => f.id)).toContain('R2:key_not_enrolled:1');
    expect(r.result.verdict).toBe('possible_impersonation');
  });

  it('a valid key enrolled for Bob does not confirm a message claiming to be Alice', async () => {
    const r = await run({ signer: 'bob' });
    expect(personal(r).signatureValid).toBe(true);
    expect(personal(r).enrolledFor?.displayName).toBe('Bob Example');
    expect(r.result.identityStatus).not.toBe('corroborated_personal');
  });

  it('without an enrolled key a valid signature is only informational', async () => {
    const r = await run({ aliceKeyEnrolled: false });
    expect(personal(r)).toMatchObject({
      signatureValid: true,
      emailBinding: true,
      enrolledFor: null,
    });
    expect(r.result.identityStatus).not.toBe('corroborated_personal');
    expect(r.result.findings.find((f) => f.ruleId === 'R2')?.severity).toBe('info');
  });

  it('exit 3: a tampered signed body fails', async () => {
    const r = await run({ mutations: ['editBody'] });
    expect(personal(r)).toMatchObject({ status: 'fail', signatureValid: false });
    expect(r.result.identityStatus).not.toBe('corroborated_personal');
  });

  it('exit 3: an unsigned outer Subject is never described as signed', async () => {
    const r = await run({ mutations: ['changeOuterSubject'] });
    expect(personal(r).signatureValid).toBe(true);
    expect(personal(r).coverage).toContain('not signed');
    expect(r.result.sender.subject).toBe('Urgent: wire transfer needed');
    expect(r.result.limitations.join(' ')).toContain('Subject');
  });

  it('an unsigned message has no personal signature', async () => {
    const r = await run({ signer: 'none' });
    expect(r.result.personalSignature).toBeNull();
    expect(r.result.stages.find((s) => s.stage === 'smime')!.status).toBe('skipped');
  });

  it('exit 4: with no trust store (live mode) the lab CA is not trusted', async () => {
    const lab = await run();
    const live = await analyze(
      { raw: Buffer.from(lab.rawMessage), source: 'eml_upload' },
      { resolver: new FixtureResolver({}), clock: () => new Date('2026-06-01T12:00:00Z') },
    );
    expect(live.personalSignature?.signatureValid).toBe(true);
    expect(live.personalSignature?.chainTrusted).toBeNull();
    expect(live.identityStatus).not.toBe('corroborated_personal');
  });

  it('reads an unquoted multipart boundary', async () => {
    const lab = await run();
    const bare = lab.rawMessage.replace(
      'boundary="lab-smime-boundary"',
      'boundary=lab-smime-boundary',
    );
    expect(bare).not.toBe(lab.rawMessage);
    const result = await analyze(
      { raw: Buffer.from(bare), source: 'lab' },
      { resolver: new FixtureResolver({}), clock: () => new Date('2026-06-01T12:00:00Z') },
    );
    expect(result.personalSignature?.signatureValid).toBe(true);
  });

  it('rejects a certificate outside its validity period', async () => {
    const lab = await run();
    const late = await analyze(
      { raw: Buffer.from(lab.rawMessage), source: 'lab' },
      { resolver: new FixtureResolver({}), clock: () => new Date('2040-01-01T00:00:00Z') },
    );
    expect(late.personalSignature?.timeValid).toBe(false);
  });
});

const hasOpenssl = (() => {
  try {
    execFileSync('openssl', ['version']);
    return true;
  } catch {
    return false;
  }
})();

describe.skipIf(!hasOpenssl)('OpenSSL cross-check', () => {
  const ca = fileURLToPath(new URL('../../../fixtures/smime/lab-ca.crt', import.meta.url));
  const verify = (message: string) => {
    const dir = mkdtempSync(join(tmpdir(), 'mailshield-cms-'));
    try {
      const file = join(dir, 'm.eml');
      writeFileSync(file, message);
      execFileSync(
        'openssl',
        [
          'cms',
          '-verify',
          '-in',
          file,
          '-CAfile',
          ca,
          '-purpose',
          'smimesign',
          '-out',
          join(dir, 'o'),
        ],
        { stdio: 'pipe' },
      );
      return true;
    } catch {
      return false;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  it('agrees on a valid message', async () => {
    expect(verify((await run()).rawMessage)).toBe(true);
  });

  it('agrees on a tampered message', async () => {
    const r = await run({ mutations: ['editBody'] });
    expect(personal(r).signatureValid).toBe(false);
    expect(verify(r.rawMessage)).toBe(false);
  });

  it('agrees that an unsigned Subject change does not break the signature', async () => {
    const r = await run({ mutations: ['changeOuterSubject'] });
    expect(personal(r).signatureValid).toBe(true);
    expect(verify(r.rawMessage)).toBe(true);
  });
});
