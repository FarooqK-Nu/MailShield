import type { EvaluationReport, Rate } from '@mailshield/contracts';
import { useCallback, useEffect, useState } from 'react';
import type { ApiError, Client } from '../api/client.ts';

interface Props {
  client: Client;
  onUnauthorized: () => void;
}

type Split = 'dev' | 'heldout' | 'all';
const SPLITS: { id: Split; label: string }[] = [
  { id: 'dev', label: 'Development' },
  { id: 'heldout', label: 'Held-out' },
  { id: 'all', label: 'All' },
];

const percent = (r: Rate) =>
  r.value === null ? 'n/a' : `${(r.value * 100).toFixed(1)}% (${r.numerator} of ${r.denominator})`;

const OUTCOME = { flagged: 'Flagged', cleared: 'Cleared', abstained: 'Abstained' } as const;

/**
 * Renders the JSON written by tools/evaluate.ts and nothing else: no figure on this page is
 * computed in the browser except the percentage format.
 */
export function Evaluation({ client, onUnauthorized }: Props) {
  const [split, setSplit] = useState<Split>('dev');
  const [report, setReport] = useState<EvaluationReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [onlyDisagreements, setOnlyDisagreements] = useState(true);

  const load = useCallback(
    (next: Split) => {
      setReport(null);
      setError(null);
      client.evaluation(next).then(setReport, (e: unknown) => {
        const err = e as ApiError;
        if (err.type === 'unauthorized') onUnauthorized();
        else if (err.type === 'not_found')
          setError('No evaluation results yet. Run "npx tsx tools/evaluate.ts" first.');
        else setError(err.message);
      });
    },
    [client, onUnauthorized],
  );
  useEffect(() => load(split), [load, split]);

  const c = report?.binary.confusion;
  const cases = report?.cases.filter((x) => !onlyDisagreements || x.disagreement) ?? [];

  return (
    <div className="space-y-5">
      <h2 className="text-xl font-semibold">Evaluation</h2>
      <p className="text-sm">
        Results of running the labelled synthetic fixtures through the real analysis engine. Rules
        are tuned on the development set only; the held-out set is run once for the report.
      </p>
      <div role="group" aria-label="Fixture set" className="flex gap-2">
        {SPLITS.map((s) => (
          <button
            key={s.id}
            type="button"
            aria-pressed={split === s.id}
            onClick={() => setSplit(s.id)}
            className="button-secondary"
          >
            {s.label}
          </button>
        ))}
      </div>

      {error && (
        <p role="alert" className="card text-sm">
          {error}
        </p>
      )}
      {!report && !error && <p role="status">Loading evaluation results…</p>}

      {report && c && (
        <>
          {report.notes.map((n) => (
            <p key={n} className="text-sm">
              {n}
            </p>
          ))}
          <section aria-labelledby="eval-metrics" className="space-y-2">
            <h3 id="eval-metrics" className="font-semibold">
              Legitimate and suspicious messages (
              {(report.counts.byTruth.legitimate ?? 0) + (report.counts.byTruth.suspicious ?? 0)}{' '}
              messages)
            </h3>
            <dl className="grid gap-3 sm:grid-cols-3">
              <Metric label="Precision" value={percent(report.binary.precision)} />
              <Metric label="Recall" value={percent(report.binary.recall)} />
              <Metric
                label="F1"
                value={report.binary.f1 === null ? 'n/a' : report.binary.f1.toFixed(3)}
              />
            </dl>
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Confusion matrix</caption>
              <thead>
                <tr>
                  <th scope="col">Truth</th>
                  <th scope="col">Flagged</th>
                  <th scope="col">Cleared</th>
                  <th scope="col">Abstained</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">Suspicious</th>
                  <td>{c.truePositive}</td>
                  <td>{c.falseNegative}</td>
                  <td>{c.abstainedSuspicious}</td>
                </tr>
                <tr>
                  <th scope="row">Legitimate</th>
                  <td>{c.falsePositive}</td>
                  <td>{c.trueNegative}</td>
                  <td>{c.abstainedLegitimate}</td>
                </tr>
              </tbody>
            </table>
            <p className="text-sm">
              Abstaining on a suspicious message counts as a miss for recall.
            </p>
          </section>

          <section aria-labelledby="eval-unknown" className="space-y-2">
            <h3 id="eval-unknown" className="font-semibold">
              Ambiguous messages ({report.counts.byTruth.unknown ?? 0})
            </h3>
            <dl className="grid gap-3 sm:grid-cols-3">
              <Metric label="Abstention rate" value={percent(report.unknown.abstentionRate)} />
              <Metric label="Concern raised" value={String(report.unknown.flagged)} />
              <Metric label="Cleared" value={String(report.unknown.cleared)} />
            </dl>
            <p className="text-sm">
              Overall abstention rate: {percent(report.overallAbstentionRate)}. Abstaining is the
              intended answer when the message alone cannot decide.
            </p>
          </section>

          <section aria-labelledby="eval-cases" className="space-y-2">
            <h3 id="eval-cases" className="font-semibold">
              {onlyDisagreements ? 'Disagreements with the ground truth' : 'Every fixture'} (
              {cases.length})
            </h3>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={onlyDisagreements}
                onChange={(e) => setOnlyDisagreements(e.target.checked)}
              />
              Show only disagreements
            </label>
            {cases.length === 0 && <p className="text-sm">No disagreements in this set.</p>}
            <ul className="space-y-2">
              {cases.map((x) => (
                <li key={x.id} className="card text-sm">
                  <p className="font-medium">
                    {x.title}{' '}
                    <span className="font-normal">
                      ({x.category}, {x.split})
                    </span>
                  </p>
                  <p>
                    Ground truth: {x.truth}. Engine: {OUTCOME[x.outcome]} ({x.verdict}).
                    {x.findings.length > 0 &&
                      ` Rules: ${[...new Set(x.findings.map((f) => f.ruleId))].join(', ')}.`}
                  </p>
                  <p>{x.explanation}</p>
                </li>
              ))}
            </ul>
          </section>
        </>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-300 p-3 dark:border-slate-700">
      <dt className="text-sm">{label}</dt>
      <dd className="text-lg font-semibold">{value}</dd>
    </div>
  );
}
