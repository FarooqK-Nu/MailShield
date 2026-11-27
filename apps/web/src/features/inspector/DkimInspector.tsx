import type { SignatureEvidence } from '@mailshield/contracts';
import { anchorId, EvidenceCard, StatusBadge } from '@mailshield/ui';
import { useState } from 'react';

const TAGS: Record<string, string> = {
  v: 'Version',
  a: 'Algorithm',
  d: 'Signing domain',
  s: 'Selector (finds the key in DNS)',
  c: 'Canonicalization',
  h: 'Signed headers',
  bh: 'Body hash',
  b: 'Signature',
  l: 'Signed body length',
  t: 'Signed at (Unix time)',
  x: 'Expires at (Unix time)',
  i: 'Agent or user identifier',
  q: 'Key lookup method',
};

function Compare({ a, b }: { a: SignatureEvidence; b: SignatureEvidence }) {
  const rows: [string, (s: SignatureEvidence) => string][] = [
    ['Domain', (s) => s.domain ?? '—'],
    ['Selector', (s) => s.selector ?? '—'],
    ['Algorithm', (s) => s.algorithm ?? '—'],
    ['Signed headers', (s) => s.signedHeaders.join(', ')],
    ['Body length limit', (s) => (s.bodyCoverage ? `${s.bodyCoverage.signedBytes} bytes` : 'none')],
    ['Key fingerprint', (s) => s.key?.fingerprint.slice(0, 16) ?? '—'],
  ];
  return (
    <table className="w-full table-fixed text-xs">
      <thead>
        <tr className="text-left">
          <th className="w-1/4 py-1">Field</th>
          <th className="py-1">Signature 1</th>
          <th className="py-1">Signature 2</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(([label, get]) => (
          <tr key={label} className="border-t border-slate-200 align-top dark:border-slate-800">
            <th
              scope="row"
              className="py-1 text-left font-normal text-slate-500 dark:text-slate-400"
            >
              {label}
            </th>
            <td className="py-1 break-all">{get(a)}</td>
            <td className="py-1 break-all">
              {get(b)}
              {get(a) !== get(b) && <span className="sr-only"> (differs)</span>}
              {get(a) !== get(b) && <span aria-hidden> ≠</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Pick a signature to see its tags explained; compare when there are two or more. */
export function DkimInspector({ signatures }: { signatures: SignatureEvidence[] }) {
  const [index, setIndex] = useState(0);
  if (signatures.length === 0) {
    return (
      <p id={anchorId('dkim-none')} className="flex flex-wrap items-center gap-2 text-sm">
        <StatusBadge status="missing" /> This message has no DKIM signature.
      </p>
    );
  }
  const selected = signatures[Math.min(index, signatures.length - 1)]!;
  return (
    <div className="space-y-3">
      {signatures.length > 1 && (
        <div role="group" aria-label="Signature" className="flex flex-wrap gap-1">
          {signatures.map((s, i) => (
            <button
              key={s.evidenceId}
              type="button"
              aria-pressed={i === index}
              onClick={() => setIndex(i)}
              className="rounded-md border border-slate-400 px-2 py-1 text-xs aria-pressed:bg-slate-200 dark:border-slate-600 dark:aria-pressed:bg-slate-800"
            >
              {i + 1}. {s.domain ?? '?'}
            </button>
          ))}
        </div>
      )}
      {signatures.map((s) => (
        <div key={s.evidenceId} id={anchorId(s.evidenceId)} hidden={s !== selected}>
          <EvidenceCard signature={s} />
        </div>
      ))}
      <details className="text-sm">
        <summary className="cursor-pointer font-medium">Tags explained</summary>
        <dl className="mt-2 space-y-1 text-xs">
          {Object.entries(selected.tags).map(([tag, value]) => (
            <div key={tag} className="grid grid-cols-[8rem_1fr] gap-2">
              <dt>
                <code>{tag}=</code> {TAGS[tag] ?? ''}
              </dt>
              <dd className="font-mono break-all">{value}</dd>
            </div>
          ))}
        </dl>
      </details>
      {signatures.length > 1 && (
        <details className="text-sm">
          <summary className="cursor-pointer font-medium">Compare signatures 1 and 2</summary>
          <div className="mt-2">
            <Compare a={signatures[0]!} b={signatures[1]!} />
          </div>
        </details>
      )}
    </div>
  );
}
