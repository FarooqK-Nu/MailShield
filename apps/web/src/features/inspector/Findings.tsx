import type { Finding } from '@mailshield/contracts';
import { CircleAlert, Info, TriangleAlert, type LucideIcon } from 'lucide-react';
import { RefLinks } from './RefLinks.tsx';
import { anchorId, type Target } from './targets.ts';

const SEVERITY: Record<Finding['severity'], [label: string, Icon: LucideIcon, tone: string]> = {
  high: ['High', CircleAlert, 'border-red-600'],
  caution: ['Caution', TriangleAlert, 'border-amber-600'],
  info: ['Info', Info, 'border-slate-400'],
  low: ['Low', Info, 'border-slate-400'],
};
const ORDER: Finding['severity'][] = ['high', 'caution', 'info', 'low'];

/** Findings that share a group (same domain, same signature) show as one card. */
function groups(findings: Finding[]): Finding[][] {
  const out = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.group ?? f.id;
    out.set(key, [...(out.get(key) ?? []), f]);
  }
  const rank = (g: Finding[]) => Math.min(...g.map((f) => ORDER.indexOf(f.severity)));
  return [...out.values()].sort((a, b) => rank(a) - rank(b));
}

export function Findings({ findings, onGo }: { findings: Finding[]; onGo: (t: Target) => void }) {
  if (findings.length === 0) {
    return <p className="text-sm">No rule raised a finding for this message.</p>;
  }
  return (
    <ul className="space-y-3">
      {groups(findings).map((group) => {
        const top = ORDER.find((s) => group.some((f) => f.severity === s))!;
        const [label, Icon, tone] = SEVERITY[top];
        return (
          <li
            key={group[0]!.id}
            className={`rounded-lg border-l-4 ${tone} bg-white dark:bg-slate-900`}
          >
            <details open={top === 'high'} className="p-3">
              <summary className="cursor-pointer font-medium">
                <span className="inline-flex items-center gap-1.5">
                  <Icon aria-hidden className="size-4 shrink-0" />
                  <span className="text-xs font-semibold">{label}</span>
                </span>{' '}
                {group[0]!.title}
                {group.length > 1 && (
                  <span className="text-sm font-normal"> (+{group.length - 1} related)</span>
                )}
              </summary>
              <div className="mt-2 space-y-4">
                {group.map((f) => (
                  <article key={f.id} id={anchorId(f.id)} className="space-y-1.5 text-sm">
                    {group.length > 1 && <h4 className="font-semibold">{f.title}</h4>}
                    <p>
                      <span className="text-slate-500 dark:text-slate-400">Observed: </span>
                      {f.observed}
                    </p>
                    {f.expected && (
                      <p>
                        <span className="text-slate-500 dark:text-slate-400">Expected: </span>
                        {f.expected}
                      </p>
                    )}
                    <p>{f.explanation}</p>
                    <p>
                      <span className="font-medium">Next step: </span>
                      {f.recommendation}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Rule {f.ruleId} v{f.ruleVersion}
                    </p>
                    <RefLinks refs={f.evidenceRefs} onGo={onGo} />
                  </article>
                ))}
              </div>
            </details>
          </li>
        );
      })}
    </ul>
  );
}
