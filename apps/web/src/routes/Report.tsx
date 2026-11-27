import { AnalysisResult } from '@mailshield/contracts';
import { useEffect, useState } from 'react';
import { ResultView } from './ResultView.tsx';

/** Fixed by the public key in the extension manifest; override for another build. */
const EXTENSION_ORIGIN = `chrome-extension://${import.meta.env.VITE_EXTENSION_ID || 'oijpcmifakangkecaplidfpgjhhidbop'}`;

/** Message types shared with apps/extension/src/sidepanel/report.ts (decision A-14). */
const REPORT_READY = 'mailshield-report-ready';
const REPORT = 'mailshield-report';

/**
 * The full inspector for a result the side panel hands over. It accepts a message only from the
 * MailShield extension window that opened this tab, validates it against the contract, and keeps
 * it in memory only: reloading the page discards it.
 */
export function Report() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const opener = window.opener as Window | null;
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== EXTENSION_ORIGIN || !opener || event.source !== opener) return;
      const data = event.data as { type?: unknown; result?: unknown } | null;
      if (data?.type !== REPORT) return;
      const parsed = AnalysisResult.safeParse(data.result);
      if (parsed.success) setResult(parsed.data);
      else setError('The extension sent a report this dashboard cannot read.');
    };
    window.addEventListener('message', onMessage);
    if (opener) opener.postMessage({ type: REPORT_READY }, EXTENSION_ORIGIN);
    else setError('Open this page from the MailShield side panel with “Open full report”.');
    return () => window.removeEventListener('message', onMessage);
  }, []);

  if (result) return <ResultView result={result} />;
  return (
    <p role={error ? 'alert' : 'status'} className="text-sm">
      {error ?? 'Waiting for the report from the MailShield side panel…'}
    </p>
  );
}
