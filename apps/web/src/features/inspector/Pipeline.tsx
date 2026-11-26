import type { StageEvent, StageName } from '@mailshield/contracts';
import { StatusBadge } from '@mailshield/ui';
import { useState } from 'react';

const LABELS: Record<StageName, string> = {
  intake: 'Input limits',
  parse: 'Header and MIME parsing',
  dns: 'DNS key lookup',
  dkim: 'DKIM signatures',
  receiver: 'Receiver results',
  alignment: 'DMARC alignment',
  smime: 'Personal signature (S/MIME)',
  identity: 'Claimed identity',
  registry: 'Trusted registry',
  rules: 'Impersonation rules',
  verdict: 'Verdict',
};

const json = (value: Record<string, unknown>) =>
  Object.keys(value).length ? JSON.stringify(value, null, 2) : '(none)';

/** The stages as they actually ran. Click one to see its inputs, outputs and limits. */
export function Pipeline({ stages }: { stages: StageEvent[] }) {
  const [open, setOpen] = useState<StageName | null>(null);
  const current = stages.find((s) => s.stage === open);
  return (
    <section aria-labelledby="pipeline-title" className="space-y-2">
      <h2 id="pipeline-title" className="font-semibold">
        Authentication pipeline
      </h2>
      <ol className="space-y-1">
        {stages.map((stage, i) => (
          <li key={stage.stage}>
            <button
              type="button"
              aria-expanded={open === stage.stage}
              onClick={() => setOpen(open === stage.stage ? null : stage.stage)}
              className="flex w-full items-center justify-between gap-3 rounded-md px-2 py-1.5 text-left text-sm hover:bg-slate-100 aria-expanded:bg-slate-100 dark:hover:bg-slate-800 dark:aria-expanded:bg-slate-800"
            >
              <span>
                <span className="mr-2 text-slate-500 dark:text-slate-400">{i + 1}.</span>
                {LABELS[stage.stage]}
              </span>
              <StatusBadge status={stage.status} />
            </button>
            {current && open === stage.stage && (
              <div className="mt-1 mb-2 space-y-2 rounded-md border border-slate-300 p-3 text-xs dark:border-slate-700">
                <p>
                  Duration: {current.durationMs === undefined ? 'n/a' : `${current.durationMs} ms`}
                  {current.simulated && ' · simulated (lab inputs)'}
                </p>
                {current.limitations.length > 0 && (
                  <ul className="list-disc pl-4">
                    {current.limitations.map((l) => (
                      <li key={l}>{l}</li>
                    ))}
                  </ul>
                )}
                <p className="font-medium">Inputs</p>
                <pre className="max-h-48 overflow-auto">{json(current.inputs)}</pre>
                <p className="font-medium">Outputs</p>
                <pre className="max-h-48 overflow-auto">{json(current.outputs)}</pre>
              </div>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
