import type { AnalysisResult, Evidence, Mailbox, StageName } from '@mailshield/contracts';
import { EvidenceCard, StatusBadge, VerdictCard } from '@mailshield/ui';
import { FlaskConical } from 'lucide-react';
import { DomainInspector } from '../features/inspector/DomainInspector.tsx';
import { RegistryMatches } from '../features/inspector/RegistryMatches.tsx';

const SOURCES: Record<Evidence['source'], string> = {
  local_crypto: 'Checked here',
  trusted_receiver: 'Reported by your mail provider',
  untrusted_header: 'Written in the message (not proof)',
  registry: 'Your registry',
  heuristic: 'Heuristic',
  lab: 'Lab (simulated)',
};

const KINDS: Partial<Record<Evidence['kind'], string>> = {
  dmarc: 'DMARC alignment (DKIM only)',
  receiver: 'Authentication-Results header',
};

const STAGE_LABELS: Record<StageName, string> = {
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

const mailbox = (m: Mailbox) =>
  m.displayName ? `${m.displayName} <${m.address}>` : m.address || '(no address)';

export function ResultView({ result }: { result: AnalysisResult }) {
  const { sender } = result;
  const simulated = result.inputSource === 'fixture' || result.inputSource === 'lab';
  const otherEvidence = result.authentication.filter((e) => e.kind !== 'dkim');
  const rows: [string, string][] = [
    ['From', sender.from.map(mailbox).join(', ') || '(none)'],
    ['Reply-To', sender.replyTo.map(mailbox).join(', ') || '(none)'],
    ['Subject', sender.subject ?? '(none)'],
    ['Date', sender.date ?? '(none)'],
  ];
  return (
    <div className="space-y-6">
      {simulated && (
        <p className="flex items-center gap-2 rounded-lg border border-dashed border-violet-600 p-3 text-sm font-medium">
          <FlaskConical aria-hidden className="size-5 shrink-0" />
          Simulated demo: synthetic message, fixture DNS and a fixed clock. Not a real email.
        </p>
      )}
      <VerdictCard result={result} />

      <section aria-labelledby="sender-title">
        <h2 id="sender-title" className="mb-2 font-semibold">
          What the message says
        </h2>
        <dl className="space-y-1 text-sm">
          {rows.map(([label, value]) => (
            <div key={label} className="grid gap-x-4 sm:grid-cols-[11rem_1fr]">
              <dt className="text-slate-500 dark:text-slate-400">{label}</dt>
              <dd className="min-w-0 wrap-break-word">{value}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section aria-labelledby="signatures-title" className="space-y-3">
        <h2 id="signatures-title" className="font-semibold">
          Signatures ({result.signatures.length})
        </h2>
        {result.signatures.length === 0 && (
          <p className="flex flex-wrap items-center gap-2 text-sm">
            <StatusBadge status="missing" /> This message has no DKIM signature.
          </p>
        )}
        {result.signatures.map((signature) => (
          <EvidenceCard key={signature.evidenceId} signature={signature} />
        ))}
      </section>

      <section aria-labelledby="claimed-title" className="space-y-3">
        <h2 id="claimed-title" className="font-semibold">
          Who it claims to be
        </h2>
        <RegistryMatches candidates={result.candidates} />
      </section>

      <section aria-labelledby="domains-title" className="space-y-3">
        <h2 id="domains-title" className="font-semibold">
          Domains in the message
        </h2>
        <DomainInspector domains={result.domains} />
      </section>

      {otherEvidence.length > 0 && (
        <section aria-labelledby="evidence-title" className="space-y-3">
          <h2 id="evidence-title" className="font-semibold">
            Other evidence
          </h2>
          <ul className="space-y-3">
            {otherEvidence.map((e) => (
              <li
                key={e.id}
                className="rounded-lg border border-slate-300 p-4 text-sm dark:border-slate-700"
              >
                <p className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold">{KINDS[e.kind] ?? e.kind}</span>
                  <StatusBadge status={e.status} />
                </p>
                <p className="mt-1">{e.reason}</p>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  Source: {SOURCES[e.source]}
                </p>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby="stages-title">
        <h2 id="stages-title" className="mb-2 font-semibold">
          Checks run
        </h2>
        <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
          {result.stages.map((stage) => (
            <li key={stage.stage} className="flex items-center justify-between gap-3 py-1.5">
              <span>{STAGE_LABELS[stage.stage]}</span>
              <StatusBadge status={stage.status} />
            </li>
          ))}
        </ul>
      </section>

      <details>
        <summary className="cursor-pointer text-sm font-medium">Raw result (JSON)</summary>
        <pre className="mt-2 max-h-96 overflow-auto rounded-lg border border-slate-300 p-3 text-xs dark:border-slate-700">
          {JSON.stringify(result, null, 2)}
        </pre>
      </details>
    </div>
  );
}
