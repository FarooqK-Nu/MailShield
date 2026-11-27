import type { AnalysisResult } from '@mailshield/contracts';

/**
 * A report that is safe to share: the verdict, the findings, domains and fingerprints. It never
 * contains the Subject, the body, the raw headers, link targets or the registry's notes.
 */
export interface RedactedReport {
  format: 'mailshield-redacted-report';
  version: 1;
  analysisId: string;
  analyzedAt: string;
  inputSource: string;
  verdict: string;
  identityStatus: string;
  riskLevel: string;
  verdictReason: string;
  sender: { displayName: string; address: string } | null;
  domains: string[];
  signatures: {
    domain: string | null;
    selector: string | null;
    status: string;
    keyFingerprint: string | null;
    signedHeaders: string[];
  }[];
  personalSignature: {
    status: string;
    signatureValid: boolean | null;
    chainTrusted: boolean | null;
    emailBinding: boolean | null;
    enrolledFor: string | null;
    keyFingerprint: string | null;
  } | null;
  findings: {
    id: string;
    severity: string;
    title: string;
    observed: string;
    explanation: string;
  }[];
  limitations: string[];
}

export function buildRedactedReport(result: AnalysisResult): RedactedReport {
  const personal = result.personalSignature;
  return {
    format: 'mailshield-redacted-report',
    version: 1,
    analysisId: result.analysisId,
    analyzedAt: result.analyzedAt,
    inputSource: result.inputSource,
    verdict: result.verdict,
    identityStatus: result.identityStatus,
    riskLevel: result.riskLevel,
    verdictReason: result.verdictBasis.reason,
    sender: result.claimedIdentity,
    domains: [...new Set(result.domains.map((d) => `${d.role}: ${d.unicode}`))],
    signatures: result.signatures.map((s) => ({
      domain: s.domain,
      selector: s.selector,
      status: s.status,
      keyFingerprint: s.key?.fingerprint ?? null,
      signedHeaders: s.signedHeaders,
    })),
    personalSignature: personal && {
      status: personal.status,
      signatureValid: personal.signatureValid,
      chainTrusted: personal.chainTrusted,
      emailBinding: personal.emailBinding,
      enrolledFor: personal.enrolledFor?.displayName ?? null,
      keyFingerprint: personal.signer?.fingerprint ?? null,
    },
    findings: result.findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
      observed: f.observed,
      explanation: f.explanation,
    })),
    limitations: result.limitations,
  };
}

const escape = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** A standalone page for printing or saving as PDF. Every value is escaped; there is no script. */
export function reportToHtml(report: RedactedReport): string {
  const row = (label: string, value: string) =>
    `<tr><th scope="row">${escape(label)}</th><td>${escape(value)}</td></tr>`;
  const list = (items: string[]) =>
    items.length
      ? `<ul>${items.map((i) => `<li>${escape(i)}</li>`).join('')}</ul>`
      : '<p>None.</p>';
  const p = report.personalSignature;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>MailShield redacted report</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>body{font:14px/1.5 system-ui,sans-serif;max-width:48rem;margin:2rem auto;padding:0 1rem;color:#111}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #999;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{width:11rem;background:#f1f1f1}code{word-break:break-all}</style></head><body>
<h1>MailShield redacted report</h1>
<p>Contains the verdict, findings, domains and key fingerprints only. It has no subject, body or raw headers.</p>
<table>
${row('Analysis', report.analysisId)}${row('Analyzed at', report.analyzedAt)}${row('Input source', report.inputSource)}
${row('Verdict', report.verdict.replace(/_/g, ' '))}${row('Identity status', report.identityStatus.replace(/_/g, ' '))}
${row('Risk level', report.riskLevel)}${row('Reason', report.verdictReason)}
${row('Claimed sender', report.sender ? `${report.sender.displayName} <${report.sender.address}>` : 'none')}
</table>
<h2>Domains</h2>${list(report.domains)}
<h2>DKIM signatures</h2>${list(report.signatures.map((s) => `${s.domain ?? 'no domain'} (selector ${s.selector ?? 'none'}): ${s.status}${s.keyFingerprint ? `, key ${s.keyFingerprint}` : ''}`))}
<h2>Personal signature (S/MIME)</h2>${
    p
      ? list([
          `Status: ${p.status}`,
          `Signature valid: ${p.signatureValid}`,
          `Certificate trusted: ${p.chainTrusted ?? 'not checked'}`,
          `Bound to the sender address: ${p.emailBinding}`,
          `Key enrolled for: ${p.enrolledFor ?? 'nobody'}`,
          `Key fingerprint: ${p.keyFingerprint ?? 'none'}`,
        ])
      : '<p>The message has no S/MIME signature.</p>'
  }
<h2>Findings</h2>${list(report.findings.map((f) => `[${f.severity}] ${f.title}. ${f.explanation}`))}
<h2>Limitations</h2>${list(report.limitations)}
</body></html>`;
}

/** Saves text as a file in the browser. No server is involved. */
export function downloadFile(name: string, mime: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
