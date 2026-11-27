import type { AnalysisResult, Verdict } from '@mailshield/contracts';
import type { ReactNode } from 'react';
import { ShieldAlert, ShieldCheck, ShieldQuestionMark, type LucideIcon } from 'lucide-react';

/** The only verdict wording (docs/context.md §5). Nothing is ever labelled as safe. */
const VERDICTS: Record<Verdict, [label: string, Icon: LucideIcon, tone: string]> = {
  possible_impersonation: ['Possible impersonation', ShieldAlert, 'border-red-600'],
  authentication_concern: ['Authentication concern', ShieldAlert, 'border-amber-600'],
  identity_unverified: ['Identity unverified', ShieldQuestionMark, 'border-slate-500'],
  no_concerning_mismatch: ['No concerning identity mismatch found', ShieldCheck, 'border-sky-600'],
};

/** `children` renders the links to the findings and evidence behind the verdict (invariant 9). */
export function VerdictCard({
  result,
  children,
}: {
  result: AnalysisResult;
  children?: ReactNode;
}) {
  const [label, Icon, tone] = VERDICTS[result.verdict];
  return (
    <section className={`rounded-lg border-2 p-4 ${tone}`} aria-labelledby="verdict-title">
      <h2 id="verdict-title" className="flex items-center gap-2 text-lg font-semibold">
        <Icon aria-hidden className="size-6 shrink-0" />
        {label}
      </h2>
      <p className="mt-1 text-sm">{result.verdictBasis.reason}</p>
      {children}
      <ul className="mt-2 list-disc pl-5 text-sm">
        {result.limitations.map((limitation) => (
          <li key={limitation}>{limitation}</li>
        ))}
      </ul>
    </section>
  );
}
