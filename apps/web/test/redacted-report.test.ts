import { runPersonalScenario, runScenario } from '@mailshield/lab';
import { LAB_DEFAULTS } from '@mailshield/contracts';
import { describe, expect, it } from 'vitest';
import { buildRedactedReport, reportToHtml } from '../../../packages/ui/src/redacted-report.ts';

describe('redacted report', () => {
  it('has the verdict and fingerprints but no subject, body or raw headers', async () => {
    const { result } = await runScenario({
      ...LAB_DEFAULTS.legitimate,
      message: {
        ...LAB_DEFAULTS.legitimate.message,
        subject: 'Secret subject QX7',
        body: 'Secret body text ZK9 with https://tracker.example/zz',
      },
    });
    const report = buildRedactedReport(result);
    const json = JSON.stringify(report);
    expect(report.verdict).toBe(result.verdict);
    expect(report.signatures[0]?.keyFingerprint).toMatch(/^[0-9a-f]{64}$/);
    for (const secret of ['QX7', 'ZK9', 'tracker.example', 'Message-ID']) {
      expect(json).not.toContain(secret);
      expect(reportToHtml(report)).not.toContain(secret);
    }
  });

  it('includes the personal signature answers and escapes every value in the HTML', async () => {
    const { result } = await runPersonalScenario({
      signer: 'alice',
      aliceKeyEnrolled: true,
      mutations: [],
    });
    const report = buildRedactedReport(result);
    expect(report.personalSignature).toMatchObject({
      signatureValid: true,
      enrolledFor: 'Alice Example',
    });
    const hostile = { ...report, verdictReason: '<script>alert(1)</script>' };
    const html = reportToHtml(hostile);
    expect(html).not.toContain('<script>');
    expect(html).toContain('&#60;script&#62;');
  });
});
