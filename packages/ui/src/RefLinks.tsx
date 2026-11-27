import { targetOf, type Target } from './targets.ts';

/** Links from a verdict or finding to the evidence behind it. */
export function RefLinks({ refs, onGo }: { refs: string[]; onGo: (target: Target) => void }) {
  if (refs.length === 0) return null;
  return (
    <ul className="flex flex-wrap gap-2 text-xs">
      {refs.map((ref) => {
        const target = targetOf(ref);
        return (
          <li key={ref}>
            <a
              href={`#${target.anchor}`}
              onClick={(e) => {
                e.preventDefault();
                onGo(target);
              }}
              className="rounded border border-slate-400 px-1.5 py-0.5 underline-offset-2 hover:underline dark:border-slate-600"
            >
              {target.label}
            </a>
          </li>
        );
      })}
    </ul>
  );
}
