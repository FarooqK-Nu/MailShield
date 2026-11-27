import {
  CircleCheck,
  CircleDashed,
  LoaderCircle,
  RefreshCw,
  Settings,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react';
import { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { FLOW_STEPS, type FlowStep } from '../background/flow.ts';
import type { ExtensionStatus, PanelEvent } from '../shared/protocol.ts';
import { compareWithHint, type MessageMetadata } from '../shared/selection.ts';
import { fileToBase64, PanelError, send } from './api.ts';
import { Fallbacks } from './Fallbacks.tsx';
import { ResultPanel } from './ResultPanel.tsx';
import { ConnectCard, PairingForm, PrivacyPanel, ServiceDown } from './Setup.tsx';
import { initialState, reducer, type PanelAction, type PanelState } from './state.ts';

/** The reducer, with the new state available right after dispatch (for request numbers). */
function usePanel() {
  const state = useRef<PanelState>(initialState);
  const [, render] = useReducer((n: number) => n + 1, 0);
  const dispatch = useCallback((action: PanelAction) => {
    const next = reducer(state.current, action);
    if (next !== state.current) {
      state.current = next;
      render();
    }
    return next;
  }, []);
  return [state.current, dispatch] as const;
}

/** Errors that mean the setup changed: re-read the status. */
const SETUP_ERRORS = new Set(['not_connected', 'unauthorized', 'service_unavailable']);

function Chip({ ok, label }: { ok: boolean; label: string }) {
  const Icon = ok ? CircleCheck : CircleDashed;
  return (
    <span className="inline-flex items-center gap-1 text-xs">
      <Icon aria-hidden className="size-3.5" />
      {label}
    </span>
  );
}

function Steps({ done }: { done: FlowStep[] }) {
  const steps = Object.keys(FLOW_STEPS) as FlowStep[];
  const current = done.at(-1);
  return (
    <ol className="card space-y-1.5 text-sm" aria-label="Analysis progress">
      {steps.map((step) => {
        const finished = done.includes(step) && step !== current;
        const running = step === current;
        const Icon = finished ? CircleCheck : running ? LoaderCircle : CircleDashed;
        return (
          <li key={step} className="flex items-center gap-2">
            <Icon
              aria-hidden
              className={`size-4 shrink-0 ${running ? 'motion-safe:animate-spin' : ''}`}
            />
            <span>{FLOW_STEPS[step]}</span>
            <span className="sr-only">
              {finished ? '(done)' : running ? '(in progress)' : '(waiting)'}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

function Confirmed({ meta, mismatches }: { meta: MessageMetadata; mismatches: string[] }) {
  return (
    <div className="space-y-2">
      <dl className="space-y-1 text-sm">
        {(
          [
            ['From', meta.from],
            ['Subject', meta.subject],
            ['Date', meta.date],
          ] as const
        ).map(([label, value]) => (
          <div key={label}>
            <dt className="text-xs text-slate-500 dark:text-slate-400">{label}</dt>
            <dd className="wrap-break-word">{value || '(none)'}</dd>
          </div>
        ))}
      </dl>
      {mismatches.length > 0 && (
        <div role="alert" className="rounded-md border border-amber-600 p-2 text-sm">
          <p className="flex items-center gap-1.5 font-medium">
            <TriangleAlert aria-hidden className="size-4" /> This may not be the open message
          </p>
          <ul className="mt-1 list-disc pl-5">
            {mismatches.map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function App() {
  const [status, setStatus] = useState<ExtensionStatus | null>(null);
  const [privacy, setPrivacy] = useState(false);
  const [tabId, setTabId] = useState<number | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [state, dispatch] = usePanel();
  const { target, view } = state;
  const connected = status?.connected ?? false;
  const ready = Boolean(status?.serviceUp && status.paired);

  const refresh = useCallback(() => {
    send({ type: 'status' }).then(setStatus, () =>
      setStatus({ paired: false, serviceUp: false, oauthConfigured: false, connected: false }),
    );
  }, []);
  useEffect(refresh, [refresh]);

  // Follow the active tab of this window.
  useEffect(() => {
    const update = () =>
      chrome.tabs
        .query({ active: true, currentWindow: true })
        .then(([tab]) => setTabId(tab?.id ?? null));
    void update();
    chrome.tabs.onActivated.addListener(update);
    return () => chrome.tabs.onActivated.removeListener(update);
  }, []);

  const loadHint = useCallback(
    (id: number) =>
      send({ type: 'hint', tabId: id }).then(
        (hint) => dispatch({ type: 'hint', hint }),
        () => {},
      ),
    [dispatch],
  );
  useEffect(() => {
    if (tabId !== null) void loadHint(tabId);
  }, [tabId, loadHint]);

  useEffect(() => {
    const listener = (event: PanelEvent) => {
      if (event.type === 'hint-changed' && event.tabId === tabId) void loadHint(event.tabId);
      if (event.type === 'progress')
        dispatch({ type: 'progress', request: event.requestId, step: event.step });
    };
    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, [tabId, loadHint, dispatch]);

  const fail = useCallback(
    (ref: string, request: number, error: unknown, retry: 'confirm' | 'analyze' | null) => {
      const e = error instanceof PanelError ? error : new PanelError('internal', String(error));
      dispatch({ type: 'failed', ref, request, code: e.code, message: e.message, retry });
      if (SETUP_ERRORS.has(e.code)) refresh();
    },
    [dispatch, refresh],
  );

  // Confirm the selection with the Gmail API before anything can be analyzed.
  const confirmRef = view.name === 'confirming' ? target?.ref : undefined;
  useEffect(() => {
    if (!confirmRef || !connected || !target?.hint) return;
    const { request } = state;
    const hint = target.hint;
    const subject = target.hintSubject ?? null;
    setAcknowledged(false);
    send({ type: 'metadata', id: confirmRef }).then(
      (meta) =>
        dispatch({
          type: 'confirmed',
          ref: confirmRef,
          meta,
          mismatches: compareWithHint(hint, subject, meta),
        }),
      (e) => fail(confirmRef, request, e, 'confirm'),
    );
    // Runs once per confirmation request; the other values belong to that request.
  }, [confirmRef, connected, state.request]);

  async function analyze() {
    if (!target || target.kind !== 'gmail') return;
    const { request } = dispatch({ type: 'start', ref: target.ref });
    try {
      const result = await send({ type: 'analyze', id: target.ref, requestId: request });
      dispatch({ type: 'result', ref: target.ref, request, result });
    } catch (e) {
      fail(target.ref, request, e, 'analyze');
    }
  }

  async function analyzeFile(file: File) {
    const next = dispatch({ type: 'file', label: file.name });
    const ref = next.target!.ref;
    try {
      const result = await send({
        type: 'analyzeFile',
        base64: await fileToBase64(file),
        requestId: next.request,
      });
      dispatch({ type: 'result', ref, request: next.request, result });
    } catch (e) {
      fail(ref, next.request, e, null);
    }
  }

  const canAnalyze =
    target?.kind === 'gmail' &&
    target.meta !== undefined &&
    (view.name === 'ready' ||
      view.name === 'result' ||
      (view.name === 'error' && view.retry === 'analyze')) &&
    (!target.mismatches?.length || acknowledged);

  const sender = target?.meta?.from || target?.hint?.fromEmail || target?.label;

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-10 space-y-2 border-b border-slate-300 bg-slate-50/95 px-3 py-2 backdrop-blur dark:border-slate-700 dark:bg-slate-950/95">
        <div className="flex items-center gap-2">
          <ShieldCheck aria-hidden className="size-5" />
          <h1 className="mr-auto font-semibold">MailShield</h1>
          <button
            type="button"
            className="rounded-md p-1.5"
            aria-pressed={privacy}
            onClick={() => setPrivacy(!privacy)}
          >
            <Settings aria-hidden className="size-4" />
            <span className="sr-only">Privacy and data</span>
          </button>
        </div>
        <div className="flex flex-wrap gap-3">
          <Chip
            ok={Boolean(status?.serviceUp && status.paired)}
            label={
              status?.serviceUp
                ? status.paired
                  ? 'Service paired'
                  : 'Service not paired'
                : 'Service unreachable'
            }
          />
          <Chip ok={connected} label={connected ? 'Gmail connected' : 'Gmail not connected'} />
        </div>
        {sender && (
          <div className="flex items-center gap-2">
            <p className="min-w-0 flex-1 truncate text-sm" title={sender}>
              <span className="text-slate-500 dark:text-slate-400">Selected: </span>
              {sender}
            </p>
            {target?.kind === 'gmail' &&
              (view.name === 'result' || view.name === 'ready' || view.name === 'error') && (
                <button type="button" className="button" disabled={!canAnalyze} onClick={analyze}>
                  {view.name === 'result' ? (
                    <span className="inline-flex items-center gap-1">
                      <RefreshCw aria-hidden className="size-4" /> Reanalyze
                    </span>
                  ) : (
                    'Analyze'
                  )}
                </button>
              )}
          </div>
        )}
      </header>

      <main className="space-y-4 p-3">
        {privacy && (
          <PrivacyPanel
            connected={connected}
            onChanged={refresh}
            onClose={() => setPrivacy(false)}
          />
        )}
        {status === null && <p className="text-sm">Checking the local service…</p>}
        {status && !status.serviceUp && <ServiceDown onRetry={refresh} />}
        {status?.serviceUp && !status.paired && <PairingForm onPaired={refresh} />}
        {ready && !connected && (
          <ConnectCard oauthConfigured={status!.oauthConfigured} onConnected={refresh} />
        )}

        {ready && (
          <>
            {view.name === 'empty' && connected && (
              <p className="card text-sm">
                Open a message in Gmail. Its sender will appear here for you to confirm before
                anything is analyzed.
              </p>
            )}
            {view.name === 'choose' && (
              <section className="card space-y-2">
                <h2 className="font-semibold">Which message?</h2>
                <p className="text-sm">
                  This conversation has several open messages. MailShield analyzes one message at a
                  time.
                </p>
                <ul className="space-y-1">
                  {view.hint.messages.map((m) => (
                    <li key={m.id}>
                      <button
                        type="button"
                        className="button-quiet w-full justify-start"
                        onClick={() =>
                          dispatch({ type: 'choose', message: m, subject: view.hint.subject })
                        }
                      >
                        <span className="truncate">
                          {m.fromName
                            ? `${m.fromName} <${m.fromEmail ?? '?'}>`
                            : (m.fromEmail ?? 'Unknown sender')}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
            )}
            {view.name === 'confirming' && (
              <p className="card text-sm" role="status">
                {connected
                  ? 'Confirming the selected message with the Gmail API…'
                  : 'Connect Gmail to confirm and analyze the open message.'}
              </p>
            )}
            {target?.meta &&
              (view.name === 'ready' || (view.name === 'error' && view.retry === 'analyze')) && (
                <section className="card space-y-2">
                  <h2 className="font-semibold">Selected message (confirmed with the Gmail API)</h2>
                  <Confirmed meta={target.meta} mismatches={target.mismatches ?? []} />
                  {(target.mismatches?.length ?? 0) > 0 && (
                    <label className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        className="mt-1"
                        checked={acknowledged}
                        onChange={(e) => setAcknowledged(e.target.checked)}
                      />
                      I checked the sender and subject above; analyze this message.
                    </label>
                  )}
                  <button type="button" className="button" disabled={!canAnalyze} onClick={analyze}>
                    Analyze
                  </button>
                </section>
              )}
            {view.name === 'analyzing' && <Steps done={view.steps} />}
            {view.name === 'error' && (
              <section role="alert" className="card space-y-2 border-red-600">
                <h2 className="font-semibold">The analysis could not finish</h2>
                <p className="text-sm">{view.message}</p>
                {view.retry === 'confirm' && (
                  <button
                    type="button"
                    className="button"
                    onClick={() => dispatch({ type: 'retry' })}
                  >
                    Retry
                  </button>
                )}
              </section>
            )}
            {view.name === 'result' && <ResultPanel key={state.request} result={view.result} />}
            {target?.kind === 'file' && view.name !== 'analyzing' && (
              <button
                type="button"
                className="button-quiet"
                onClick={() => {
                  dispatch({ type: 'reset' });
                  if (tabId !== null) void loadHint(tabId);
                }}
              >
                Close this file and follow Gmail again
              </button>
            )}
            <Fallbacks
              gmailConnected={connected}
              onPick={(meta) => dispatch({ type: 'pick', meta })}
              onFile={analyzeFile}
            />
          </>
        )}
      </main>
    </div>
  );
}
