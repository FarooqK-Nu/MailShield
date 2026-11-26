import type { AnalysisResult, Verdict } from '@mailshield/contracts';
import { ShieldAlert, ShieldCheck, ShieldQuestionMark, type LucideIcon } from 'lucide-react';

/** The only verdict wording (docs/context.md §5). Nothing is ever labelled as safe. */
const VERDICTS: Record<Verdict, [label: string, Icon: LucideIcon, tone: string]> = {
  possible_impersonation: ['Possible impersonation', ShieldAlert, 'border-red-600'],
  authentication_concern: ['Authentication concern', ShieldAlert, 'border-amber-600'],
  identity_unverified: ['Identity unverified', ShieldQuestionMark, 'border-slate-500'],
  no_concerning_mismatch: ['No concerning identity mismatch found', ShieldCheck, 'border-sky-600'],
};

export function VerdictCard({ result }: { result: AnalysisResult }) {
  const [label, Icon, tone] = VERDICTS[result.verdict];
  return (
    <section className={`rounded-lg border-2 p-4 ${tone}`} aria-labelledby="verdict-title">
      <h2 id="verdict-title" className="flex items-center gap-2 text-lg font-semibold">
        <Icon aria-hidden className="size-6 shrink-0" />
        {label}
      </h2>
      <ul className="mt-2 list-disc pl-5 text-sm">
        {result.limitations.map((limitation) => (
          <li key={limitation}>{limitation}</li>
        ))}
      </ul>
    </section>
  );
}
