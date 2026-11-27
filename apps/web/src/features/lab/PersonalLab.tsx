import {
  LAB_PERSONAL_MUTATIONS,
  type LabPersonalResponse,
  type LabPersonalScenario,
} from '@mailshield/contracts';
import { Findings, PersonalSignatureCard, VerdictCard } from '@mailshield/ui';
import { CircleCheck, LoaderCircle } from 'lucide-react';
import { useState } from 'react';
import { ApiError, type Client } from '../../api/client.ts';
import { PERSONAL_CHALLENGES } from './personalChallenges.ts';

type Mutation = LabPersonalScenario['mutations'][number];

const SIGNERS: [LabPersonalScenario['signer'], string][] = [
  ['alice', 'Alice (the real person)'],
  ['bob', 'Bob (a different person)'],
  ['eve', 'Eve (an attacker with her own certificate)'],
  ['none', 'Nobody (unsigned)'],
];
const MUTATIONS: Record<Mutation, [string, string]> = {
  editBody: ['Edit the signed body', 'Changes the body after signing.'],
  changeOuterSubject: ['Change the outer Subject', 'The Subject is outside the signed part.'],
};
const START: LabPersonalScenario = { signer: 'alice', aliceKeyEnrolled: true, mutations: [] };

/** A message claiming to be from Alice, signed with S/MIME by a lab person. All synthetic. */
export function PersonalLab({
  client,
  onUnauthorized,
}: {
  client: Client;
  onUnauthorized: () => void;
}) {
  const [scenario, setScenario] = useState<LabPersonalScenario>(START);
  const [run, setRun] = useState<{
    scenario: LabPersonalScenario;
    data: LabPersonalResponse;
  } | null>(null);
  const [solved, setSolved] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function execute() {
    setBusy(true);
    setError(null);
    try {
      const data = await client.runPersonalLab(scenario);
      setRun({ scenario, data });
      setSolved((done) => [
        ...new Set([
          ...done,
          ...PERSONAL_CHALLENGES.filter((c) => c.solved(scenario, data)).map((c) => c.id),
        ]),
      ]);
    } catch (e) {
      if ((e as ApiError).type === 'unauthorized') onUnauthorized();
      else setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="personal-lab-title" className="space-y-4">
      <h2 id="personal-lab-title" className="text-xl font-semibold">
        Personal signatures (S/MIME)
      </h2>
      <p className="text-sm">
        A message claims to be from Alice Example (alice@acme.example) and is signed with a
        certificate from the lab certificate authority. Choose who signs, tamper with it, and see
        which questions the check answers separately. Everything here is synthetic.
      </p>

      <div className="grid gap-4 md:grid-cols-2">
        <fieldset className="card space-y-2">
          <legend className="px-1 text-sm font-semibold">Who signs</legend>
          {SIGNERS.map(([value, label]) => (
            <label key={value} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name="personal-signer"
                checked={scenario.signer === value}
                onChange={() => setScenario({ ...scenario, signer: value })}
              />
              {label}
            </label>
          ))}
          <label className="flex items-start gap-2 pt-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={scenario.aliceKeyEnrolled}
              onChange={(e) => setScenario({ ...scenario, aliceKeyEnrolled: e.target.checked })}
            />
            <span>
              Alice’s real key is enrolled in the lab registry (after a separate-channel check)
            </span>
          </label>
        </fieldset>

        <fieldset className="card space-y-2">
          <legend className="px-1 text-sm font-semibold">Tamper after signing</legend>
          {LAB_PERSONAL_MUTATIONS.map((m) => (
            <label key={m} className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-1"
                checked={scenario.mutations.includes(m)}
                onChange={(e) =>
                  setScenario({
                    ...scenario,
                    mutations: e.target.checked
                      ? [...scenario.mutations, m]
                      : scenario.mutations.filter((x) => x !== m),
                  })
                }
              />
              <span>
                {MUTATIONS[m][0]}
                <span className="block text-xs text-slate-500 dark:text-slate-400">
                  {MUTATIONS[m][1]}
                </span>
              </span>
            </label>
          ))}
        </fieldset>
      </div>

      <button
        type="button"
        className="button inline-flex items-center gap-2"
        disabled={busy}
        onClick={() => void execute()}
      >
        {busy && <LoaderCircle aria-hidden className="size-4 animate-spin" />} Verify the message
      </button>
      {error && (
        <p role="alert" className="text-sm font-medium">
          {error}
        </p>
      )}

      {run && (
        <div className="space-y-4">
          <VerdictCard result={run.data.result} />
          {run.data.notes.length > 0 && (
            <ul className="list-disc space-y-1 pl-5 text-sm">
              {run.data.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          )}
          {run.data.result.personalSignature ? (
            <PersonalSignatureCard personal={run.data.result.personalSignature} />
          ) : (
            <p className="card text-sm">The message has no personal signature to check.</p>
          )}
          {run.data.result.findings.length > 0 && (
            <Findings findings={run.data.result.findings} onGo={() => undefined} />
          )}
          <details>
            <summary className="cursor-pointer text-sm font-medium">The message as sent</summary>
            <pre className="mt-2 max-h-72 overflow-auto rounded-lg border border-slate-300 p-3 text-xs dark:border-slate-700">
              {run.data.rawMessage}
            </pre>
          </details>
        </div>
      )}

      <section aria-labelledby="personal-challenges" className="space-y-2">
        <h3 id="personal-challenges" className="font-semibold">
          Personal verification challenges
        </h3>
        <ul className="space-y-2">
          {PERSONAL_CHALLENGES.map((c) => (
            <li
              key={c.id}
              className={`card p-3 text-sm ${solved.includes(c.id) ? 'border-emerald-600 dark:border-emerald-600' : ''}`}
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
            setScenario(START);
            setRun(null);
            setSolved([]);
            setError(null);
          }}
        >
          Reset the personal lab
        </button>
      </section>
    </section>
  );
}
