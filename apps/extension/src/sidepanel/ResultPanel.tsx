import type { AnalysisResult, Evidence, Finding } from '@mailshield/contracts';
import {
  anchorId,
  EvidenceCard,
  EvidenceItem,
  Findings,
  IdentityComparison,
  PersonalSignatureCard,
  RefLinks,
  buildRedactedReport,
  downloadFile,
  reportToHtml,
  StatusBadge,
  VerdictCard,
  type Target,
} from '@mailshield/ui';
import { Check, ClipboardCopy, ExternalLink, FileDown, FlaskConical } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { reviewedFor, setReviewed } from './local-data.ts';
import { openFullReport, openRegistryEntry } from './report.ts';

const STAGE_LABELS: Record<string, string> = {
  intake: 'Size and format limits',
  parse: 'Headers and MIME parsed',
  dns: 'DNS key and policy lookup',
  dkim: 'DKIM signatures verified',
  receiver: 'Gmail’s receiver results',
  alignment: 'DMARC alignment (DKIM only)',
  smime: 'Personal signature (S/MIME)',
  identity: 'Claimed identity and domains',
  registry: 'Registry comparison',
  rules: 'Rules R1–R9',
  verdict: 'Verdict',
};

type EvidenceView = 'local' | 'gmail' | 'all';
const EVIDENCE_VIEWS: [EvidenceView, string][] = [
  ['local', 'Verified here'],
  ['gmail', 'Reported by Gmail'],
  ['all', 'All'],
];

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-title`} className="scroll-mt-28 space-y-2">
      <h2 id={`${id}-title`} className="text-sm font-semibold">
        {title}
      </h2>
      {children}
    </section>
  );
}

function shown(e: Evidence, view: EvidenceView) {
  if (view === 'all') return true;
  if (view === 'gmail') return e.source === 'trusted_receiver';
  return e.source === 'local_crypto' || e.source === 'lab';
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="button-quiet"
      onClick={() =>
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        })
      }
    >
      {copied ? (
        <Check aria-hidden className="size-4" />
      ) : (
        <ClipboardCopy aria-hidden className="size-4" />
      )}
      {copied ? 'Copied' : label}
    </button>
  );
}

/** The side panel's result: verdict, identity, authentication, findings and quick actions. */
export function ResultPanel({ result }: { result: AnalysisResult }) {
  const [view, setView] = useState<EvidenceView>('local');
  const [reviewed, setReviewedIds] = useState<string[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const ref = result.messageRef ?? null;
  const simulated = result.inputSource === 'fixture' || result.inputSource === 'lab';
  // Signatures have their own cards; any other record (for example "no DKIM signature") is listed.
  const hasCard = (e: Evidence) => result.signatures.some((s) => s.evidenceId === e.id);
  const evidence = result.authentication.filter(
    (e) => !hasCard(e) && e.kind !== 'smime' && shown(e, view),
  );
  const signatures = view === 'gmail' ? [] : result.signatures;
  const entry = result.candidates[0];

  useEffect(() => {
    if (ref) void reviewedFor(ref).then(setReviewedIds);
  }, [ref]);

  const go = (target: Target) => {
    if (target.tab === 'evidence') setView('all');
    requestAnimationFrame(() => {
      const el = document.getElementById(target.anchor);
      if (!el) return;
      el.closest('details')?.setAttribute('open', '');
      el.scrollIntoView({ block: 'center' });
      el.classList.add('flash');
      setTimeout(() => el.classList.remove('flash'), 1500);
    });
  };

  const reviewAction = (f: Finding) =>
    ref && (
      <label className="flex items-center gap-2 text-xs">
        <input
          type="checkbox"
          checked={reviewed.includes(f.id)}
          onChange={(e) => void setReviewed(ref, f.id, e.target.checked).then(setReviewedIds)}
        />
        Mark as reviewed (kept on this device only)
      </label>
    );

  return (
    <div className="space-y-5">
      {simulated && (
        <p className="flex items-center gap-2 rounded-lg border border-dashed border-violet-600 p-2 text-sm font-medium">
          <FlaskConical aria-hidden className="size-4" /> Simulated (lab or fixture data)
        </p>
      )}

      <VerdictCard result={result}>
        <div className="mt-2">
          <RefLinks
            refs={[...result.verdictBasis.findingIds, ...result.verdictBasis.evidenceIds]}
            onGo={go}
          />
        </div>
      </VerdictCard>

      <div id="inspector-claimed">
        <IdentityComparison result={result} />
      </div>

      <Section id="inspector-evidence" title="Authentication">
        <div role="radiogroup" aria-label="Which evidence to show" className="flex gap-1 text-xs">
          {EVIDENCE_VIEWS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={view === value}
              onClick={() => setView(value)}
              className="rounded-md border border-slate-400 px-2 py-1 aria-checked:bg-slate-900 aria-checked:text-white dark:border-slate-600 dark:aria-checked:bg-slate-100 dark:aria-checked:text-slate-900"
            >
              {label}
            </button>
          ))}
        </div>
        {view === 'gmail' && evidence.length === 0 && (
          <p className="text-sm">
            No result from Gmail’s receiving server is trusted for this message. Only a message
            fetched from the Gmail API can carry one.
          </p>
        )}
        <ul className="space-y-2">
          {signatures.map((s) => (
            <li key={s.evidenceId} id={anchorId(s.evidenceId)}>
              <details className="rounded-lg border border-slate-300 dark:border-slate-700">
                <summary className="flex cursor-pointer flex-wrap items-center justify-between gap-2 p-3 text-sm font-medium">
                  <span className="break-all">DKIM signature: {s.domain ?? 'no domain'}</span>
                  <StatusBadge status={s.status} />
                </summary>
                <div className="space-y-2 p-2">
                  <EvidenceCard signature={s} />
                  {s.key && <CopyButton text={s.key.fingerprint} label="Copy key fingerprint" />}
                </div>
              </details>
            </li>
          ))}
          {result.personalSignature && view !== 'gmail' && (
            <li>
              <PersonalSignatureCard personal={result.personalSignature} />
            </li>
          )}
          {evidence.map((e) => (
            <EvidenceItem key={e.id} evidence={e} />
          ))}
        </ul>
      </Section>

      <Section id="inspector-findings" title={`Findings (${result.findings.length})`}>
        <Findings findings={result.findings} onGo={go} actions={reviewAction} />
      </Section>

      <Section id="inspector-stages" title="Pipeline stages">
        <ol className="space-y-1 text-sm">
          {result.stages.map((s) => (
            <li key={s.stage} className="flex items-center justify-between gap-2">
              <span>{STAGE_LABELS[s.stage] ?? s.stage}</span>
              <StatusBadge status={s.status} />
            </li>
          ))}
        </ol>
      </Section>

      <Section id="inspector-actions" title="Quick actions">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="button-quiet"
            onClick={() =>
              openFullReport(result).then(
                () => setNotice('The full report opened in a new tab.'),
                (e: Error) => setNotice(e.message),
              )
            }
          >
            <ExternalLink aria-hidden className="size-4" /> Open full report
          </button>
          {entry && (
            <button
              type="button"
              className="button-quiet"
              onClick={() => openRegistryEntry(entry.displayName)}
            >
              <ExternalLink aria-hidden className="size-4" /> Open registry entry
            </button>
          )}
          <button
            type="button"
            className="button-quiet"
            onClick={() =>
              downloadFile(
                `mailshield-report-${result.analysisId.slice(0, 8)}.json`,
                'application/json',
                JSON.stringify(buildRedactedReport(result), null, 2),
              )
            }
          >
            <FileDown aria-hidden className="size-4" /> Export redacted report (JSON)
          </button>
          <button
            type="button"
            className="button-quiet"
            onClick={() =>
              downloadFile(
                `mailshield-report-${result.analysisId.slice(0, 8)}.html`,
                'text/html',
                reportToHtml(buildRedactedReport(result)),
              )
            }
          >
            <FileDown aria-hidden className="size-4" /> Printable report (HTML)
          </button>
        </div>
        {notice && (
          <p role="status" className="text-sm">
            {notice}
          </p>
        )}
        <details className="rounded-lg border border-slate-300 dark:border-slate-700">
          <summary className="cursor-pointer p-3 text-sm font-medium">
            Raw headers ({result.rawHeaders.length})
          </summary>
          {/* Rendered as text, never as markup. */}
          <pre className="max-h-96 overflow-auto p-3 text-xs whitespace-pre-wrap break-all">
            {result.rawHeaders.map((h) => `${h.name}: ${h.value}`).join('\n')}
          </pre>
          <div className="p-2">
            <CopyButton
              text={result.rawHeaders.map((h) => `${h.name}: ${h.value}`).join('\n')}
              label="Copy headers"
            />
          </div>
        </details>
      </Section>
    </div>
  );
}
