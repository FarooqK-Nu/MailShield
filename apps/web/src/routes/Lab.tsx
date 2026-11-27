import {
  LAB_DEFAULTS,
  LAB_RULES,
  type LabRunResponse,
  type LabScenario,
} from '@mailshield/contracts';
import { Findings, StatusBadge, VerdictCard } from '@mailshield/ui';
import { CircleCheck, Download, FlaskConical, LoaderCircle } from 'lucide-react';
import { useState } from 'react';
import { ApiError, type Client } from '../api/client.ts';
import { CHALLENGES } from '../features/lab/challenges.ts';
import { EvidenceTrail } from '../features/lab/EvidenceTrail.tsx';

type Mutation = LabScenario['mutations'][number];

const MUTATIONS: [Mutation, string, string][] = [
  ['editBody', 'Edit one body character', 'Changes the body after signing.'],
  ['changeSignedSubject', 'Change the signed Subject', 'Subject is covered by the signature.'],
  ['alterUnsignedHeader', 'Change Reply-To after signing', 'Reply-To is not covered.'],
  ['removeSignature', 'Remove the signature', 'Strips the DKIM-Signature header.'],
  ['swapKey', 'Swap the signing key', 'Signs with the other party’s key under the same name.'],
  ['rotateSelector', 'Rotate the Acme selector', 'Signs with the other published Acme key.'],
  ['dnsMissing', 'DNS key missing', 'The key record is not published.'],
  ['dnsTimeout', 'DNS timeout', 'The key lookup never answers.'],
];
const RULE_NAMES: Record<string, string> = {
  R1: 'Display-name mismatch',
  R2: 'Personal mismatch',
  R3: 'Look-alike domain',
  R4: 'Misleading structure',
  R5: 'Reply-To discrepancy',
  R6: 'Authentication problem',
  R7: 'Link mismatch',
  R8: 'First contact (needs key history, Phase 6)',
  R9: 'Coverage and tampering',
};
const AVATARS = [
  ['Blue', 'bg-sky-600'],
  ['Red', 'bg-red-600'],
  ['Green', 'bg-emerald-700'],
  ['Violet', 'bg-violet-600'],
] as const;

const toggle = <T,>(list: T[], item: T): T[] =>
  list.includes(item) ? list.filter((x) => x !== item) : [...list, item];

/** The two hex strings, with every character that differs from the other one marked. */
function Diff({
  value,
  other,
}: {
  value: string | null | undefined;
  other: string | null | undefined;
}) {
  if (!value) return <span>(none)</span>;
  return (
    <span className="font-mono text-xs break-all">
      {[...value].map((char, i) => (
        <span
          key={i}
          className={other && other[i] !== char ? 'bg-amber-300 text-black dark:bg-amber-500' : ''}
        >
          {char}
        </span>
      ))}
    </span>
  );
}

export function Lab({ client, onUnauthorized }: Props) {
  const [scenario, setScenario] = useState<LabScenario>(LAB_DEFAULTS.legitimate);
  const [avatar, setAvatar] = useState(0);
  const [run, setRun] = useState<{ scenario: LabScenario; data: LabRunResponse } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [solved, setSolved] = useState<string[]>([]);

  const patch = (changes: Partial<LabScenario>) => setScenario({ ...scenario, ...changes });
  const patchMessage = (changes: Partial<LabScenario['message']>) =>
    setScenario({ ...scenario, message: { ...scenario.message, ...changes } });

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const data = await client.runLab(scenario);
      setRun({ scenario, data });
      setSolved((done) => [
        ...done,
        ...CHALLENGES.filter((c) => !done.includes(c.id) && c.solved(scenario, data)).map(
          (c) => c.id,
        ),
      ]);
    } catch (e) {
      const failure = e as ApiError;
      if (failure.type === 'unauthorized') onUnauthorized();
      else setError(failure.message);
    } finally {
      setBusy(false);
    }
  }

  function download() {
    if (!run) return;
    const { result, baseline, notes } = run.data;
    const report = {
      kind: 'mailshield-lab-report',
      simulated: true,
      note: 'Synthetic lab data. Not a real email, and not evidence about any real sender.',
      scenario: run.scenario,
      notes,
      verdict: result.verdict,
      signatures: result.signatures.map((s) => ({
        status: s.status,
        domain: s.domain,
        selector: s.selector,
        bodyHash: s.bodyHash,
        keyFingerprint: s.key?.fingerprint ?? null,
      })),
      baselineBodyHash: baseline.signatures[0]?.bodyHash.computed ?? null,
      findings: result.findings.map((f) => ({
        rule: f.ruleId,
        severity: f.severity,
        title: f.title,
      })),
      solvedChallenges: solved,
    };
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }),
    );
    const link = document.createElement('a');
    link.href = url;
    link.download = 'mailshield-lab-report.json';
    link.click();
    URL.revokeObjectURL(url);
  }

  const sig = run?.data.result.signatures[0];
  const base = run?.data.baseline.signatures[0];
  const standard = run?.data.result.authentication.filter(
    (e) => e.kind === 'dkim' || e.kind === 'dmarc',
  );
  const initial = (scenario.message.displayName || scenario.message.from).charAt(0).toUpperCase();

  return (
    <div className="space-y-6">
      <p className="flex items-center gap-2 rounded-lg border border-dashed border-violet-600 p-3 text-sm font-medium">
        <FlaskConical aria-hidden className="size-5 shrink-0" />
        Security lab: every message here is synthetic, signed with test-only keys and checked
        against fixture DNS. It works without a network connection.
      </p>

      <section aria-labelledby="builder-title" className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-3">
          <h2 id="builder-title" className="font-semibold">
            1. Build a message
          </h2>
          <div className="flex gap-2">
            <button
              type="button"
              className="button"
              onClick={() => setScenario(LAB_DEFAULTS.legitimate)}
            >
              Alice receives Acme
            </button>
            <button
              type="button"
              className="button"
              onClick={() => setScenario(LAB_DEFAULTS.lookalike)}
            >
              Eve: look-alike domain
            </button>
          </div>
          {(
            [
              ['Display name', 'displayName'],
              ['From address', 'from'],
              ['Reply-To (optional)', 'replyTo'],
              ['Subject', 'subject'],
            ] as const
          ).map(([label, key]) => (
            <label key={key} className="block text-sm">
              {label}
              <input
                className="field mt-1 w-full"
                value={scenario.message[key]}
                onChange={(e) => patchMessage({ [key]: e.target.value })}
              />
            </label>
          ))}
          <label className="block text-sm">
            Body
            <textarea
              className="field mt-1 h-28 w-full"
              value={scenario.message.body}
              onChange={(e) => patchMessage({ body: e.target.value })}
            />
          </label>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <label>
              Signed by
              <select
                className="field mt-1 w-full"
                value={scenario.signer}
                onChange={(e) => patch({ signer: e.target.value as LabScenario['signer'] })}
              >
                <option value="acme">Acme (acme.example)</option>
                <option value="eve">Eve (acrne.example)</option>
                <option value="none">Nobody (unsigned)</option>
              </select>
            </label>
            <label>
              Acme selector
              <select
                className="field mt-1 w-full"
                value={scenario.selector}
                onChange={(e) => patch({ selector: e.target.value as LabScenario['selector'] })}
              >
                <option value="s2025">s2025</option>
                <option value="s2026">s2026</option>
              </select>
            </label>
          </div>
          <fieldset className="text-sm">
            <legend>Sender avatar (decoration only)</legend>
            <div className="mt-1 flex gap-3">
              {AVATARS.map(([name], i) => (
                <label key={name} className="flex items-center gap-1">
                  <input
                    type="radio"
                    name="avatar"
                    checked={avatar === i}
                    onChange={() => setAvatar(i)}
                  />
                  {name}
                </label>
              ))}
            </div>
          </fieldset>
        </div>

        <div className="space-y-3">
          <h2 className="font-semibold">What Alice sees</h2>
          <div className="rounded-lg border border-slate-300 p-4 dark:border-slate-700">
            <div className="flex items-center gap-3">
              <span
                aria-hidden
                className={`flex size-10 items-center justify-center rounded-full font-semibold text-white ${AVATARS[avatar]![1]}`}
              >
                {initial}
              </span>
              <div className="min-w-0">
                <p className="font-medium">{scenario.message.displayName || '(no name)'}</p>
                <p className="truncate text-sm text-slate-600 dark:text-slate-400">
                  &lt;{scenario.message.from}&gt;
                </p>
              </div>
            </div>
            <p className="mt-3 font-medium">{scenario.message.subject}</p>
            <p className="mt-2 text-sm whitespace-pre-wrap">{scenario.message.body}</p>
            {scenario.message.replyTo && (
              <p className="mt-2 text-xs text-slate-600 dark:text-slate-400">
                Replies go to {scenario.message.replyTo}
              </p>
            )}
          </div>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            The avatar is only a picture. Anyone can pick any picture and any display name, which is
            why neither counts as evidence.
          </p>

          <h2 className="pt-2 font-semibold">2. Tamper with it</h2>
          <ul className="space-y-1 text-sm">
            {MUTATIONS.map(([id, label, hint]) => (
              <li key={id}>
                <label className="flex items-start gap-2">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={scenario.mutations.includes(id)}
                    onChange={() => patch({ mutations: toggle(scenario.mutations, id) })}
                  />
                  <span>
                    {label} <span className="text-slate-500 dark:text-slate-400">({hint})</span>
                  </span>
                </label>
              </li>
            ))}
          </ul>

          <details className="text-sm">
            <summary className="cursor-pointer font-medium">3. Protections (rules)</summary>
            <ul className="mt-2 space-y-1">
              {LAB_RULES.map((id) => (
                <li key={id}>
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={!scenario.disabledRules.includes(id)}
                      disabled={id === 'R8'}
                      onChange={() => patch({ disabledRules: toggle(scenario.disabledRules, id) })}
                    />
                    {id} {RULE_NAMES[id]}
                  </label>
                </li>
              ))}
            </ul>
          </details>

          <button type="button" className="button inline-flex items-center gap-2" onClick={start}>
            {busy && <LoaderCircle aria-hidden className="size-4 animate-spin" />}
            Send and verify
          </button>
          {error && (
            <p role="alert" className="text-sm text-red-700 dark:text-red-400">
              {error}
            </p>
          )}
        </div>
      </section>

      {run && (
        <div className="space-y-6">
          <section aria-labelledby="notes-title" className="space-y-1">
            <h2 id="notes-title" className="font-semibold">
              What the lab did
            </h2>
            <ul className="list-disc pl-5 text-sm">
              {(run.data.notes.length
                ? run.data.notes
                : ['The message was signed and not changed.']
              ).map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </section>

          <div className="grid gap-6 lg:grid-cols-2">
            <EvidenceTrail stages={run.data.result.stages} />
            <div className="space-y-6">
              <section aria-labelledby="ba-title" className="space-y-2">
                <h2 id="ba-title" className="font-semibold">
                  Before and after
                </h2>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1 rounded-lg border border-slate-300 p-3 text-sm dark:border-slate-700">
                    <p className="font-medium">Standard authentication only</p>
                    {standard?.map((e) => (
                      <p key={e.id} className="flex items-center justify-between gap-2">
                        {e.kind.toUpperCase()} <StatusBadge status={e.status} />
                      </p>
                    ))}
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      DKIM and DMARC only say the message was signed by a domain, not whether that
                      domain is who you expect.
                    </p>
                  </div>
                  <div className="space-y-1 rounded-lg border border-slate-300 p-3 text-sm dark:border-slate-700">
                    <p className="font-medium">With your registry and rules</p>
                    <p>
                      {run.data.result.findings.length
                        ? [...new Set(run.data.result.findings.map((f) => f.ruleId))].join(', ')
                        : 'No rule fired'}
                    </p>
                  </div>
                </div>
                <VerdictCard result={run.data.result} />
              </section>

              <section aria-labelledby="hash-title" className="space-y-2 text-sm">
                <h2 id="hash-title" className="font-semibold">
                  Hashes and keys
                </h2>
                {sig ? (
                  <>
                    <p>
                      <strong>Body hash</strong> (changes with every edit to the body). Unchanged
                      message on top, this message below; differing characters are highlighted.
                    </p>
                    <p>
                      <Diff value={base?.bodyHash.computed} other={sig.bodyHash.computed} />
                    </p>
                    <p>
                      <Diff value={sig.bodyHash.computed} other={base?.bodyHash.computed} />
                    </p>
                    <p>
                      <strong>Key fingerprint</strong> (identifies the public key, never the
                      message). It changes only when another key is used.
                    </p>
                    <p>
                      <Diff value={base?.key?.fingerprint} other={sig.key?.fingerprint} />
                    </p>
                    <p>
                      <Diff value={sig.key?.fingerprint} other={base?.key?.fingerprint} />
                    </p>
                    <p>
                      Signed headers: {sig.signedHeaders.join(', ') || '(none)'}. Not covered:{' '}
                      {sig.unsignedHeaders.join(', ') || '(none)'}. A change to an uncovered header
                      cannot break the signature.
                    </p>
                    <p>
                      DKIM result: <StatusBadge status={sig.status} /> {sig.reason}
                    </p>
                  </>
                ) : (
                  <p>The message has no DKIM signature, so there is no hash to compare.</p>
                )}
              </section>
            </div>
          </div>

          {run.data.result.findings.length > 0 && (
            <Findings findings={run.data.result.findings} onGo={() => undefined} />
          )}
        </div>
      )}

      <section aria-labelledby="challenge-title" className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <h2 id="challenge-title" className="font-semibold">
            Guided challenges
          </h2>
          <button
            type="button"
            className="button inline-flex items-center gap-1"
            disabled={!run}
            onClick={download}
          >
            <Download aria-hidden className="size-4" /> Download lab report
          </button>
        </div>
        <ul className="space-y-2">
          {CHALLENGES.map((c) => (
            <li
              key={c.id}
              className="rounded-lg border border-slate-300 p-3 text-sm dark:border-slate-700"
            >
              <p className="flex items-center gap-2 font-medium">
                {solved.includes(c.id) && (
                  <CircleCheck aria-hidden className="size-4 text-emerald-700" />
                )}
                {c.title}
                {solved.includes(c.id) && <span className="text-xs font-normal">(solved)</span>}
              </p>
              <p>{c.task}</p>
            </li>
          ))}
        </ul>
        <button
          type="button"
          className="text-sm underline"
          onClick={() => {
            setScenario(LAB_DEFAULTS.legitimate);
            setRun(null);
            setSolved([]);
            setError(null);
          }}
        >
          Reset the lab
        </button>
      </section>
    </div>
  );
}

interface Props {
  client: Client;
  onUnauthorized: () => void;
}
