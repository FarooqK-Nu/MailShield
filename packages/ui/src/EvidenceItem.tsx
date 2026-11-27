import type { Evidence } from '@mailshield/contracts';
import { StatusBadge } from './StatusBadge.tsx';
import { anchorId } from './targets.ts';

/** Where a piece of evidence came from, in plain words (docs/context.md §5). */
export const SOURCE_LABELS: Record<Evidence['source'], string> = {
  local_crypto: 'Checked here',
  trusted_receiver: 'Reported by Gmail’s receiving server',
  untrusted_header: 'Written in the message (not proof)',
  registry: 'Your registry',
  heuristic: 'Heuristic',
  lab: 'Lab (simulated)',
};

/** A heading that says what was checked and by whom. */
export function evidenceTitle(e: Evidence): string {
  if (e.source === 'trusted_receiver') return `${e.kind.toUpperCase()} reported by Gmail`;
  if (e.kind === 'dmarc') {
    return 'DMARC alignment (DKIM only; policy found by RFC 9989 DNS tree walk)';
  }
  if (e.kind === 'receiver') return 'Authentication-Results header';
  return e.kind.toUpperCase();
}

/** One evidence record with its status, reason and source. The id is a link target. */
export function EvidenceItem({ evidence: e }: { evidence: Evidence }) {
  const assumption = typeof e.details.assumption === 'string' ? e.details.assumption : null;
  return (
    <li
      id={anchorId(e.id)}
      className="rounded-lg border border-slate-300 p-4 text-sm dark:border-slate-700"
    >
      <p className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-semibold">{evidenceTitle(e)}</span>
        <StatusBadge status={e.status} />
      </p>
      <p className="mt-1">{e.reason}</p>
      {assumption && <p className="mt-1 text-xs">{assumption}</p>}
      <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
        Source: {SOURCE_LABELS[e.source]}
      </p>
    </li>
  );
}
