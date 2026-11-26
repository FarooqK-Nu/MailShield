import type { CharDiff, DomainLookalike, IdentityCandidate } from '@mailshield/contracts';
import { CircleCheck, TriangleAlert } from 'lucide-react';

const KIND: Record<CharDiff['kind'], string> = {
  substituted: 'instead of',
  inserted: 'added; not in',
  removed: 'missing from',
  swapped: 'swapped; expected',
};

/** The compared label with differing characters marked by weight and underline, not colour. */
function MarkedLabel({ text, diff }: { text: string; diff: CharDiff[] }) {
  const chars = [...text];
  const marked = new Set<number>();
  for (const d of diff) {
    const width = d.kind === 'swapped' ? 2 : d.kind === 'removed' ? 0 : 1;
    for (let i = 0; i < width; i++) marked.add(d.index + i);
  }
  return (
    <span className="font-mono">
      {chars.map((c, i) =>
        marked.has(i) ? (
          <mark
            key={i}
            className="bg-amber-200 font-bold underline decoration-2 underline-offset-4 dark:bg-amber-900 dark:text-amber-100"
          >
            {c}
          </mark>
        ) : (
          <span key={i}>{c}</span>
        ),
      )}
    </span>
  );
}

function Lookalike({ lookalike }: { lookalike: DomainLookalike }) {
  const label = lookalike.matchedToken ?? lookalike.observed.split('.')[0] ?? lookalike.observed;
  return (
    <div className="mt-2 rounded-md border border-amber-700/40 p-3 text-sm">
      <p className="flex items-start gap-2">
        <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
        <span>
          <strong>{lookalike.observed}</strong> looks like the approved domain{' '}
          <strong>{lookalike.approved}</strong> (
          {lookalike.strength === 'strong' ? 'reads the same' : 'a few characters apart'}).
        </span>
      </p>
      <p className="mt-2">
        Compared: <MarkedLabel text={label} diff={lookalike.diff} />
      </p>
      <ul className="mt-1 list-disc pl-5">
        {lookalike.diff.map((d, i) => (
          <li key={i}>
            Position {d.index + 1}: {d.observed ? `“${d.observed}”` : 'nothing'}
            {d.observedCodePoints.length > 0 && ` (${d.observedCodePoints.join(', ')})`}{' '}
            {KIND[d.kind]} “{d.expected}”
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RegistryMatches({ candidates }: { candidates: IdentityCandidate[] }) {
  if (candidates.length === 0) {
    return (
      <p className="text-sm">
        No registry entry matches this sender’s name, address or domain. That is not a warning: it
        only means MailShield has nothing to compare the message with.
      </p>
    );
  }
  return (
    <ul className="space-y-3">
      {candidates.map((c) => (
        <li
          key={c.identityId}
          className="rounded-lg border border-slate-300 p-4 dark:border-slate-700"
        >
          <p className="font-semibold">{c.displayName}</p>
          {c.approvedDomain ? (
            <p className="mt-1 flex items-start gap-2 text-sm">
              <CircleCheck aria-hidden className="mt-0.5 size-4 shrink-0" />
              The From domain is approved for {c.displayName}
              {c.approvedDomain.relationship === 'service_provider'
                ? ' (service provider)'
                : ''}: {c.approvedDomain.domain}.
            </p>
          ) : (
            <p className="mt-1 flex items-start gap-2 text-sm">
              <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
              The From domain is not one of {c.displayName}’s approved domains.
            </p>
          )}
          <ul className="mt-2 list-disc pl-5 text-sm">
            {c.explanation.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          {c.lookalikes.map((l) => (
            <Lookalike key={`${l.observed}-${l.approved}`} lookalike={l} />
          ))}
        </li>
      ))}
    </ul>
  );
}
