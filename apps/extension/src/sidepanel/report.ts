import type { AnalysisResult } from '@mailshield/contracts';
import { PanelError } from './api.ts';
import { DASHBOARD_URL } from './local-data.ts';

/** Message types shared with apps/web/src/routes/Report.tsx (decision A-14). */
export const REPORT_READY = 'mailshield-report-ready';
export const REPORT = 'mailshield-report';

/**
 * Opens the dashboard's full inspector and hands it the result with postMessage. The result goes
 * only to the dashboard origin, and only after the window this panel opened says it is ready.
 * Nothing is sent to or stored by the local service.
 */
export function openFullReport(result: AnalysisResult): Promise<void> {
  const win = window.open(`${DASHBOARD_URL}/#/report`, '_blank');
  if (!win) {
    return Promise.reject(new PanelError('popup_blocked', 'Chrome blocked the new tab.'));
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      window.removeEventListener('message', onMessage);
      reject(
        new PanelError(
          'dashboard_unavailable',
          `The dashboard at ${DASHBOARD_URL} did not answer. Start it with npm run dev, then try again.`,
        ),
      );
    }, 15_000);
    function onMessage(event: MessageEvent) {
      if (event.origin !== DASHBOARD_URL || event.source !== win) return;
      if ((event.data as { type?: unknown } | null)?.type !== REPORT_READY) return;
      clearTimeout(timer);
      window.removeEventListener('message', onMessage);
      win!.postMessage({ type: REPORT, result }, DASHBOARD_URL);
      resolve();
    }
    window.addEventListener('message', onMessage);
  });
}

/** The registry page, filtered to one entry's name. */
export function openRegistryEntry(displayName: string) {
  window.open(`${DASHBOARD_URL}/#/registry?q=${encodeURIComponent(displayName)}`, '_blank');
}
