import type { DomainInspection } from '@mailshield/contracts';
import { TriangleAlert } from 'lucide-react';

const ROLES: Record<DomainInspection['role'], string> = {
  from: 'From',
  sender: 'Sender',
  reply_to: 'Reply-To',
  return_path: 'Return-Path',
  dkim: 'DKIM signing domain (d=)',
};

/** Shows where the registrable boundary is, so `acme.example.net` reads as `example.net`. */
function Boundary({ domain }: { domain: DomainInspection }) {
  if (!domain.registrableUnicode) {
    return <span className="break-all">{domain.unicode} (no registrable domain)</span>;
  }
  return (
    <span className="break-all">
      {domain.subdomain && (
        <span className="text-slate-500 dark:text-slate-400">{subdomainUnicode(domain)}.</span>
      )}
      <strong className="rounded border border-slate-500 px-1">{domain.registrableUnicode}</strong>
    </span>
  );
}

/** The Unicode labels in front of the registrable domain. */
function subdomainUnicode(domain: DomainInspection): string {
  const registrable = domain.registrableUnicode ?? '';
  return domain.unicode.slice(0, Math.max(0, domain.unicode.length - registrable.length - 1));
}

function DomainCard({ domain }: { domain: DomainInspection }) {
  const lookalikeChars = domain.codePoints.filter((c) => c.looksLike || c.script !== 'Latin');
  return (
    <article className="rounded-lg border border-slate-300 p-4 dark:border-slate-700">
      <h3 className="text-sm text-slate-500 dark:text-slate-400">{ROLES[domain.role]}</h3>
      <p className="mt-1 text-base">
        <Boundary domain={domain} />
      </p>
      <dl className="mt-3 space-y-1 text-sm">
        <div className="grid gap-x-4 sm:grid-cols-[11rem_1fr]">
          <dt className="text-slate-500 dark:text-slate-400">Registrable domain</dt>
          <dd className="break-all">
            {domain.registrableUnicode ?? 'none'}
            {domain.publicSuffix && (
              <span className="text-slate-500 dark:text-slate-400">
                {' '}
                (public suffix: {domain.publicSuffix})
              </span>
            )}
          </dd>
        </div>
        {domain.isIdn && (
          <div className="grid gap-x-4 sm:grid-cols-[11rem_1fr]">
            <dt className="text-slate-500 dark:text-slate-400">Punycode (ASCII) form</dt>
            <dd>
              <code className="text-xs break-all">{domain.ascii}</code>
            </dd>
          </div>
        )}
        <div className="grid gap-x-4 sm:grid-cols-[11rem_1fr]">
          <dt className="text-slate-500 dark:text-slate-400">Writing systems</dt>
          <dd>{domain.scripts.length ? domain.scripts.join(', ') : 'digits and symbols only'}</dd>
        </div>
      </dl>
      {domain.mixedScript && (
        <p className="mt-3 flex items-start gap-2 text-sm text-amber-800 dark:text-amber-300">
          <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
          This domain mixes writing systems in one label, which no single language does. Letters
          from different alphabets can look identical.
        </p>
      )}
      {(domain.isIdn || lookalikeChars.length > 0) && (
        <details className="mt-3 text-sm" open={domain.mixedScript}>
          <summary className="cursor-pointer font-medium">Characters of the domain name</summary>
          <table className="mt-2 w-full text-left text-xs">
            <thead>
              <tr className="text-slate-500 dark:text-slate-400">
                <th className="py-1 pr-3 font-normal">Character</th>
                <th className="py-1 pr-3 font-normal">Code point</th>
                <th className="py-1 pr-3 font-normal">Writing system</th>
                <th className="py-1 font-normal">Looks like</th>
              </tr>
            </thead>
            <tbody>
              {domain.codePoints.map((c, i) => (
                <tr
                  key={i}
                  className={c.looksLike ? 'font-semibold' : undefined}
                  aria-label={c.looksLike ? `${c.codePoint} looks like ${c.looksLike}` : undefined}
                >
                  <td className="py-0.5 pr-3 font-mono text-sm">{c.char}</td>
                  <td className="py-0.5 pr-3 font-mono">{c.codePoint}</td>
                  <td className="py-0.5 pr-3">{c.script}</td>
                  <td className="py-0.5 font-mono">{c.looksLike ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </article>
  );
}

export function DomainInspector({ domains }: { domains: DomainInspection[] }) {
  const seen = new Set<string>();
  const unique = domains.filter((d) => {
    const key = `${d.role}:${d.ascii}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  if (unique.length === 0) {
    return <p className="text-sm">The message names no domain that could be inspected.</p>;
  }
  return (
    <div className="space-y-3">
      {unique.map((d) => (
        <DomainCard key={`${d.role}:${d.ascii}`} domain={d} />
      ))}
    </div>
  );
}
