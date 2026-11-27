import type { AnalysisResult, Mailbox } from '@mailshield/contracts';
import {
  anchorId,
  EvidenceItem,
  Findings,
  IdentityComparison,
  RefLinks,
  VerdictCard,
  type InspectorTab,
  type Target,
} from '@mailshield/ui';
import { FlaskConical } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { DkimInspector } from '../features/inspector/DkimInspector.tsx';
import { DomainInspector } from '../features/inspector/DomainInspector.tsx';
import { Pipeline } from '../features/inspector/Pipeline.tsx';
import { Preview } from '../features/inspector/Preview.tsx';
import { RawHeaders } from '../features/inspector/RawHeaders.tsx';
import { RegistryMatches } from '../features/inspector/RegistryMatches.tsx';

const TABS: [InspectorTab, string][] = [
  ['identity', 'Identity'],
  ['evidence', 'Evidence'],
  ['findings', 'Findings'],
];

const mailbox = (m: Mailbox) =>
  m.displayName ? `${m.displayName} <${m.address}>` : m.address || '(no address)';

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-title`} className="scroll-mt-4 space-y-3">
      <h2 id={`${id}-title`} className="font-semibold">
        {title}
      </h2>
      {children}
    </section>
  );
}

/** Three columns on wide screens, tabs below `lg` (docs/architecture.md §7). */
export function ResultView({ result }: { result: AnalysisResult }) {
  const [tab, setTab] = useState<InspectorTab>('findings');
  const { sender } = result;
  const simulated = result.inputSource === 'fixture' || result.inputSource === 'lab';
  // Locally verified DKIM is shown as signature cards; the provider's DKIM report stays here.
  const otherEvidence = result.authentication.filter(
    (e) => e.kind !== 'dkim' || e.source === 'trusted_receiver',
  );
  const rows: [string, string][] = [
    ['From', sender.from.map(mailbox).join(', ') || '(none)'],
    ['Reply-To', sender.replyTo.map(mailbox).join(', ') || '(none)'],
    ['Subject', sender.subject ?? '(none)'],
    ['Date', sender.date ?? '(none)'],
  ];

  const go = (target: Target) => {
    setTab(target.tab);
    requestAnimationFrame(() => {
      const el = document.getElementById(target.anchor);
      if (!el) return;
      el.closest('details')?.setAttribute('open', '');
      el.scrollIntoView({ block: 'center' });
      el.classList.add('flash');
      setTimeout(() => el.classList.remove('flash'), 1500);
    });
  };
  const column = (name: InspectorTab) =>
    `min-w-0 space-y-6 ${tab === name ? '' : 'hidden'} lg:block`;

  return (
    <div className="space-y-6">
      {simulated && (
        <p className="flex items-center gap-2 rounded-lg border border-dashed border-violet-600 p-3 text-sm font-medium">
          <FlaskConical aria-hidden className="size-5 shrink-0" />
          Simulated demo: synthetic message, fixture DNS, the fictional seed registry and a fixed
          clock. Not a real email.
        </p>
      )}
      <VerdictCard result={result}>
        <div className="mt-2 space-y-1">
          <p className="text-xs font-medium">Based on:</p>
          <RefLinks
            refs={[...result.verdictBasis.findingIds, ...result.verdictBasis.evidenceIds]}
            onGo={go}
          />
        </div>
      </VerdictCard>

      <div
        role="tablist"
        aria-label="Inspector"
        className="flex gap-1 border-b border-slate-300 lg:hidden dark:border-slate-700"
      >
        {TABS.map(([value, label]) => (
          <button
            key={value}
            type="button"
            role="tab"
            aria-selected={tab === value}
            data-state={tab === value ? 'active' : 'inactive'}
            onClick={() => setTab(value)}
            className="tab"
          >
            {label}
            {value === 'findings' && ` (${result.findings.length})`}
          </button>
        ))}
      </div>

      <div className="grid gap-8 lg:grid-cols-3">
        <div className={column('identity')}>
          <IdentityComparison result={result} />
          <Section id="inspector-sender" title="What the message says">
            <dl className="space-y-1 text-sm">
              {rows.map(([label, value]) => (
                <div key={label}>
                  <dt className="text-xs text-slate-500 dark:text-slate-400">{label}</dt>
                  <dd className="min-w-0 wrap-break-word">{value}</dd>
                </div>
              ))}
            </dl>
          </Section>
          <Section id="inspector-claimed" title="Who it claims to be">
            <RegistryMatches candidates={result.candidates} />
          </Section>
          <Section id="inspector-domains" title="Domains in the message">
            <DomainInspector domains={result.domains} />
          </Section>
          <Preview preview={result.preview} />
          <RawHeaders lines={result.rawHeaders} />
        </div>

        <div className={column('evidence')}>
          <Pipeline stages={result.stages} />
          <Section id="inspector-signatures" title={`Signatures (${result.signatures.length})`}>
            <DkimInspector signatures={result.signatures} />
          </Section>
          {otherEvidence.length > 0 && (
            <Section id="inspector-evidence" title="Other evidence">
              <ul className="space-y-3">
                {otherEvidence.map((e) => (
                  <EvidenceItem key={e.id} evidence={e} />
                ))}
              </ul>
            </Section>
          )}
          <Section id="inspector-links" title={`Links (${result.links.length})`}>
            {result.links.length === 0 ? (
              <p className="text-sm">No links in an HTML body.</p>
            ) : (
              <ul className="space-y-2 text-sm">
                {result.links.map((link) => (
                  <li key={link.id} id={anchorId(link.id)} className="break-all">
                    <span className="text-slate-500 dark:text-slate-400">Shows</span> “
                    {link.visibleText || '(no text)'}”{' '}
                    <span className="text-slate-500 dark:text-slate-400">opens</span>{' '}
                    <code className="text-xs">{link.href}</code>
                  </li>
                ))}
              </ul>
            )}
            <p className="text-xs text-slate-500 dark:text-slate-400">Links are never opened.</p>
          </Section>
        </div>

        <div className={column('findings')}>
          <Section id="inspector-findings" title={`Findings (${result.findings.length})`}>
            <Findings findings={result.findings} onGo={go} />
          </Section>
          <details>
            <summary className="cursor-pointer text-sm font-medium">Raw result (JSON)</summary>
            <pre className="mt-2 max-h-96 overflow-auto rounded-lg border border-slate-300 p-3 text-xs dark:border-slate-700">
              {JSON.stringify(result, null, 2)}
            </pre>
          </details>
        </div>
      </div>
    </div>
  );
}
