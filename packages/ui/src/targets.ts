/** Inspector tabs. On wide screens all three columns show at once. */
export type InspectorTab = 'identity' | 'evidence' | 'findings';

export interface Target {
  tab: InspectorTab;
  anchor: string;
  label: string;
}

/** Where an evidence reference or finding id is shown in the inspector (invariant 9). */
export function targetOf(ref: string): Target {
  if (ref.startsWith('domain:')) {
    return { tab: 'identity', anchor: 'inspector-domains', label: `Domain (${ref.slice(7)})` };
  }
  if (ref.startsWith('registry:')) {
    return { tab: 'identity', anchor: 'inspector-claimed', label: 'Registry entry' };
  }
  if (/^R\d/.test(ref)) return { tab: 'findings', anchor: anchorId(ref), label: ref };
  const label = ref.startsWith('dkim-')
    ? `DKIM signature ${ref.slice(5)}`
    : ref === 'dmarc-local'
      ? 'DMARC alignment'
      : ref.startsWith('link-')
        ? `Link ${ref.slice(5)}`
        : ref;
  return { tab: 'evidence', anchor: anchorId(ref), label };
}

export const anchorId = (ref: string) => `ev-${ref.replace(/[^\w-]/g, '-')}`;
