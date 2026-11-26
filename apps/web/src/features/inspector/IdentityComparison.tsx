import type { AnalysisResult } from '@mailshield/contracts';

function Column({ title, rows }: { title: string; rows: [string, string][] }) {
  return (
    <div className="min-w-0 rounded-md border border-slate-300 p-3 dark:border-slate-700">
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      <dl className="space-y-1.5 text-sm">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt className="text-xs text-slate-500 dark:text-slate-400">{label}</dt>
            <dd className="wrap-break-word">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

/** What the message claims, next to what was actually verified. */
export function IdentityComparison({ result }: { result: AnalysisResult }) {
  const claimed = result.claimedIdentity;
  const top = result.candidates[0];
  const from = result.domains.find((d) => d.role === 'from');
  const verified = result.signatures.filter((s) => s.status === 'pass').map((s) => s.domain ?? '?');
  const dmarc = result.authentication.find((e) => e.id === 'dmarc-local');
  const aligned = (dmarc?.details.alignedSignatures as string[] | undefined)?.length ?? 0;
  return (
    <section aria-labelledby="comparison-title" className="space-y-2">
      <h2 id="comparison-title" className="font-semibold">
        Claimed vs actual
      </h2>
      <div className="grid gap-3 sm:grid-cols-2">
        <Column
          title="Claimed"
          rows={[
            ['Display name', claimed?.displayName || '(none)'],
            ['Address', claimed?.address || '(none)'],
            ['Looks like registry entry', top ? top.displayName : 'No match'],
          ]}
        />
        <Column
          title="Actual"
          rows={[
            ['Registered domain', from?.registrableUnicode ?? from?.unicode ?? '(none)'],
            ['Verified signing domains', verified.length ? verified.join(', ') : 'None'],
            ['Aligned with From', aligned ? 'Yes (DKIM)' : 'No'],
            [
              'Approved domain for the entry',
              top?.approvedDomain
                ? `${top.approvedDomain.domain} (${top.approvedDomain.relationship === 'own' ? 'own' : 'service provider'})`
                : top
                  ? 'Not an approved domain'
                  : '—',
            ],
          ]}
        />
      </div>
    </section>
  );
}
