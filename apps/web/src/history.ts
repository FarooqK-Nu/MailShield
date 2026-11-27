import type { AnalysisResult } from '@mailshield/contracts';

/** One analysis run in this browser session. No subject, body or addresses are kept. */
export interface SessionEntry {
  at: string;
  label: string;
  verdict: AnalysisResult['verdict'];
  riskLevel: AnalysisResult['riskLevel'];
  findings: number;
  simulated: boolean;
}

const KEY = 'mailshield.session-history';
const MAX = 50;

export function readHistory(): SessionEntry[] {
  try {
    const raw = sessionStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as SessionEntry[]) : [];
  } catch {
    return [];
  }
}

export function recordAnalysis(label: string, result: AnalysisResult): void {
  const entry: SessionEntry = {
    at: result.analyzedAt,
    label: label.startsWith('Demo:') ? label : 'Uploaded message',
    verdict: result.verdict,
    riskLevel: result.riskLevel,
    findings: result.findings.length,
    simulated: result.inputSource === 'fixture' || result.inputSource === 'lab',
  };
  try {
    sessionStorage.setItem(KEY, JSON.stringify([entry, ...readHistory()].slice(0, MAX)));
  } catch {
    // Storage blocked: the overview simply stays empty.
  }
}
