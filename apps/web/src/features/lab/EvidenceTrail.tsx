import type { StageEvent, StageName } from '@mailshield/contracts';
import { StatusBadge } from '@mailshield/ui';
import { FlaskConical, Pause, Play, RotateCcw, StepForward } from 'lucide-react';
import { useEffect, useState } from 'react';

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
const SPEEDS = [
  ['Slow', 1400],
  ['Normal', 700],
  ['Fast', 250],
] as const;

const json = (value: Record<string, unknown>) =>
  Object.keys(value).length ? JSON.stringify(value, null, 2) : '(none)';

/**
 * Replays the stages the engine really reported, one at a time. Nothing is scripted: the
 * list, the statuses and the details all come from the analysis result.
 */
export function EvidenceTrail({ stages }: { stages: StageEvent[] }) {
  const [shown, setShown] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [inspect, setInspect] = useState<StageName | null>(null);

  // A new run starts the animation again, unless the user asked for reduced motion: then every
  // stage is shown at once and the replay controls still work.
  useEffect(() => {
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    setShown(reduce ? stages.length : 0);
    setInspect(null);
    setPlaying(!reduce);
  }, [stages]);

  useEffect(() => {
    if (!playing || shown >= stages.length) return;
    const timer = setTimeout(() => setShown((n) => n + 1), SPEEDS[speed]![1]);
    return () => clearTimeout(timer);
  }, [playing, shown, stages.length, speed]);

  const done = shown >= stages.length;
  const running = playing && !done;
  const current = stages.find((s) => s.stage === inspect);

  function toggle() {
    if (done) {
      setShown(0);
      setPlaying(true);
    } else {
      setPlaying(!playing);
    }
  }
  function step() {
    setPlaying(false);
    setShown((n) => Math.min(n + 1, stages.length));
  }
  function reset() {
    setPlaying(false);
    setShown(0);
    setInspect(null);
  }

  return (
    <section aria-labelledby="trail-title" className="space-y-3">
      <h2 id="trail-title" className="font-semibold">
        Evidence trail
      </h2>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <button type="button" className="button inline-flex items-center gap-1" onClick={toggle}>
          {running ? (
            <Pause aria-hidden className="size-4" />
          ) : (
            <Play aria-hidden className="size-4" />
          )}
          {running ? 'Pause' : done ? 'Replay' : 'Play'}
        </button>
        <button
          type="button"
          className="button inline-flex items-center gap-1"
          disabled={done}
          onClick={step}
        >
          <StepForward aria-hidden className="size-4" /> Step
        </button>
        <button type="button" className="button inline-flex items-center gap-1" onClick={reset}>
          <RotateCcw aria-hidden className="size-4" /> Reset
        </button>
        <label className="ml-auto flex items-center gap-2">
          Speed
          <select
            className="field py-1"
            value={speed}
            onChange={(e) => setSpeed(Number(e.target.value))}
          >
            {SPEEDS.map(([label], i) => (
              <option key={label} value={i}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <ol className="space-y-1" aria-live="polite">
        {stages.map((stage, i) => {
          const visible = i < shown;
          return (
            <li key={stage.stage}>
              <button
                type="button"
                disabled={!visible}
                aria-expanded={inspect === stage.stage}
                onMouseEnter={() => visible && setInspect(stage.stage)}
                onFocus={() => visible && setInspect(stage.stage)}
                onClick={() => setInspect(inspect === stage.stage ? null : stage.stage)}
                className="flex w-full items-center justify-between gap-3 rounded-md px-2 py-1.5 text-left text-sm hover:bg-slate-100 aria-expanded:bg-slate-100 dark:hover:bg-slate-800 dark:aria-expanded:bg-slate-800"
              >
                <span>
                  <span className="mr-2 text-slate-500 dark:text-slate-400">{i + 1}.</span>
                  {LABELS[stage.stage]}
                  {visible && stage.simulated && (
                    <span className="ml-2 inline-flex items-center gap-1 rounded border border-dashed border-violet-600 px-1.5 text-xs">
                      <FlaskConical aria-hidden className="size-3" /> simulated
                    </span>
                  )}
                </span>
                <StatusBadge status={visible ? stage.status : 'pending'} />
              </button>
            </li>
          );
        })}
      </ol>
      {current && (
        <div className="space-y-2 rounded-md border border-slate-300 p-3 text-xs dark:border-slate-700">
          <p className="font-medium">{LABELS[current.stage]}</p>
          {current.limitations.length > 0 && (
            <ul className="list-disc pl-4">
              {current.limitations.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          )}
          <p className="font-medium">Inputs</p>
          <pre className="max-h-40 overflow-auto">{json(current.inputs)}</pre>
          <p className="font-medium">Outputs</p>
          <pre className="max-h-40 overflow-auto">{json(current.outputs)}</pre>
        </div>
      )}
    </section>
  );
}
