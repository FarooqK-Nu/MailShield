import type { Verdict } from '@mailshield/contracts';
import { readHistory } from '../history.ts';

const LABELS: Record<Verdict, string> = {
  possible_impersonation: 'Possible impersonation',
  authentication_concern: 'Authentication concern',
  identity_unverified: 'Identity unverified',
  no_concerning_mismatch: 'No concerning identity mismatch found',
};

/** Counts from analyses run in this browser session only. Nothing is invented. */
export function Overview() {
  const history = readHistory();
  if (history.length === 0) {
    return (
      <div className="space-y-2 rounded-lg border border-dashed border-slate-400 p-6 text-center dark:border-slate-600">
        <p className="font-medium">No messages analyzed in this session yet.</p>
        <p className="text-sm">
          <a href="#/analyze" className="underline">
            Analyze a message
          </a>{' '}
          or try one of the demos. Counts here come only from what you analyze, and are cleared when
          you close the tab.
        </p>
      </div>
    );
  }
  const count = (v: Verdict) => history.filter((h) => h.verdict === v).length;
  return (
    <div className="space-y-6">
      <section aria-labelledby="counts-title">
        <h2 id="counts-title" className="mb-2 font-semibold">
          This session: {history.length} analysis{history.length === 1 ? '' : 'es'}
        </h2>
        <dl className="grid gap-3 sm:grid-cols-2">
          {(Object.keys(LABELS) as Verdict[]).map((v) => (
            <div key={v} className="rounded-lg border border-slate-300 p-3 dark:border-slate-700">
              <dt className="text-sm">{LABELS[v]}</dt>
              <dd className="text-2xl font-semibold">{count(v)}</dd>
            </div>
          ))}
        </dl>
      </section>
      <section aria-labelledby="recent-title">
        <h2 id="recent-title" className="mb-2 font-semibold">
          Recent
        </h2>
        <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
          {history.slice(0, 10).map((h) => (
            <li key={h.at + h.label} className="flex flex-wrap justify-between gap-2 py-1.5">
              <span>
                {h.label}
                {h.simulated && ' (simulated)'}
              </span>
              <span>
                {LABELS[h.verdict]} · {h.findings} finding{h.findings === 1 ? '' : 's'}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
