import { MAX_MESSAGE_BYTES, type AnalysisResult, type FixtureSummary } from '@mailshield/contracts';
import { LoaderCircle, Upload } from 'lucide-react';
import { Tabs } from 'radix-ui';
import { useEffect, useRef, useState, type DragEvent } from 'react';
import { ApiError, type Client } from '../api/client.ts';
import { recordAnalysis } from '../history.ts';
import { ResultView } from './ResultView.tsx';

interface Job {
  label: string;
  run: () => Promise<AnalysisResult>;
}

type State =
  | { step: 'idle' }
  | { step: 'running'; job: Job }
  | { step: 'done'; job: Job; result: AnalysisResult }
  | { step: 'error'; job: Job | null; message: string };

const size = (bytes: number) =>
  bytes < 1024 ? `${bytes} bytes` : `${(bytes / 1024).toFixed(1)} KiB`;

export function Analyze({ client, onUnauthorized }: Props) {
  const [state, setState] = useState<State>({ step: 'idle' });
  const [headers, setHeaders] = useState('');
  const [demos, setDemos] = useState<FixtureSummary[]>([]);
  const [dragging, setDragging] = useState(false);
  const latest = useRef(0);

  useEffect(() => {
    client
      .fixtures()
      .then((list) => setDemos(list.fixtures))
      .catch((error: ApiError) => {
        if (error.type === 'unauthorized') onUnauthorized();
        else setState({ step: 'error', job: null, message: error.message });
      });
  }, [client, onUnauthorized]);

  /** Clears the previous result at once and ignores responses that arrive late. */
  async function start(job: Job) {
    const ticket = ++latest.current;
    setState({ step: 'running', job });
    try {
      const result = await job.run();
      if (ticket !== latest.current) return;
      recordAnalysis(job.label, result);
      setState({ step: 'done', job, result });
    } catch (e) {
      if (ticket !== latest.current) return;
      const error = e as ApiError;
      if (error.type === 'unauthorized') onUnauthorized();
      else setState({ step: 'error', job, message: error.message });
    }
  }

  function startFile(file: File | undefined) {
    if (!file) return;
    if (file.size > MAX_MESSAGE_BYTES) {
      latest.current++;
      setState({ step: 'error', job: null, message: `${file.name} is larger than 10 MiB.` });
      return;
    }
    void start({
      label: `${file.name} (${size(file.size)})`,
      run: () => client.analyzeFile(file),
    });
  }

  function drop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    startFile(event.dataTransfer.files[0]);
  }

  return (
    <div className="space-y-6">
      <Tabs.Root defaultValue="file">
        <Tabs.List
          aria-label="Input"
          className="mb-4 flex gap-1 border-b border-slate-300 dark:border-slate-700"
        >
          <Tabs.Trigger value="file" className="tab">
            Upload .eml
          </Tabs.Trigger>
          <Tabs.Trigger value="headers" className="tab">
            Paste headers
          </Tabs.Trigger>
          <Tabs.Trigger value="demo" className="tab">
            Demo
          </Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="file">
          <label
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={drop}
            className={`flex cursor-pointer flex-col items-center gap-2 rounded-lg border-2 border-dashed p-8 text-center focus-within:outline-2 focus-within:outline-sky-600 ${
              dragging ? 'border-sky-600' : 'border-slate-400 dark:border-slate-600'
            }`}
          >
            <Upload aria-hidden className="size-6" />
            <span className="font-medium">Drop an .eml file here, or choose one</span>
            <span className="text-sm text-slate-500 dark:text-slate-400">
              Up to 10 MiB. In Gmail: Show original, then Download original.
            </span>
            <input
              type="file"
              accept=".eml,message/rfc822"
              className="sr-only"
              onChange={(e) => {
                startFile(e.target.files?.[0]);
                e.target.value = '';
              }}
            />
          </label>
        </Tabs.Content>

        <Tabs.Content value="headers" className="space-y-2">
          <label htmlFor="headers" className="block text-sm">
            Paste the message headers. The body and signatures cannot be checked from headers.
          </label>
          <textarea
            id="headers"
            rows={10}
            className="field w-full font-mono text-xs"
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
          />
          <button
            type="button"
            className="button"
            disabled={!headers.trim()}
            onClick={() =>
              start({ label: 'Pasted headers', run: () => client.analyzeHeaders(headers) })
            }
          >
            Inspect headers
          </button>
        </Tabs.Content>

        <Tabs.Content value="demo">
          <p className="mb-2 text-sm">Synthetic messages checked against fixture DNS.</p>
          <ul className="space-y-2">
            {demos.map((demo) => (
              <li key={demo.id}>
                <button
                  type="button"
                  className="w-full rounded-lg border border-slate-300 p-3 text-left hover:border-sky-600 dark:border-slate-700"
                  onClick={() =>
                    start({ label: `Demo: ${demo.title}`, run: () => client.runDemo(demo.id) })
                  }
                >
                  <span className="block font-medium">{demo.title}</span>
                  <span className="text-sm text-slate-500 dark:text-slate-400">
                    {demo.description}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </Tabs.Content>
      </Tabs.Root>

      <div aria-live="polite">
        {state.step === 'running' && (
          <p className="flex items-center gap-2">
            <LoaderCircle aria-hidden className="size-5 motion-safe:animate-spin" />
            Analyzing {state.job.label}…
          </p>
        )}
        {state.step === 'done' && <p className="text-sm">Analyzed: {state.job.label}</p>}
        {state.step === 'error' && (
          <div role="alert" className="space-y-2 rounded-lg border border-red-600 p-3">
            <p>{state.message}</p>
            {state.job && (
              <button type="button" className="button" onClick={() => start(state.job!)}>
                Retry
              </button>
            )}
          </div>
        )}
      </div>
      {state.step === 'done' && <ResultView result={state.result} />}
    </div>
  );
}

interface Props {
  client: Client;
  onUnauthorized: () => void;
}
