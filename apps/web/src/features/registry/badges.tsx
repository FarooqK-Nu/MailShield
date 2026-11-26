import type { IdentityKind, TrustState } from '@mailshield/contracts';
import {
  Building2,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  UserRound,
  type LucideIcon,
} from 'lucide-react';

export const TRUST_LABELS: Record<TrustState, string> = {
  unverified: 'Unverified',
  user_trusted: 'Trusted by you',
  independently_verified: 'Independently verified',
  revoked: 'Revoked',
};

const TRUST: Record<TrustState, [LucideIcon, string]> = {
  unverified: [ShieldQuestion, 'border-slate-500/40 text-slate-600 dark:text-slate-300'],
  user_trusted: [ShieldCheck, 'border-sky-700/40 text-sky-800 dark:text-sky-300'],
  independently_verified: [
    ShieldCheck,
    'border-emerald-700/40 text-emerald-800 dark:text-emerald-300',
  ],
  revoked: [ShieldX, 'border-red-700/40 text-red-800 dark:text-red-300'],
};

const badge =
  'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium';

/** Icon and text, so trust state never depends on colour alone. */
export function TrustBadge({ state }: { state: TrustState }) {
  const [Icon, tone] = TRUST[state];
  return (
    <span className={`${badge} ${tone}`}>
      <Icon aria-hidden className="size-3.5" />
      {TRUST_LABELS[state]}
    </span>
  );
}

export function KindBadge({ kind }: { kind: IdentityKind }) {
  const Icon = kind === 'organization' ? Building2 : UserRound;
  return (
    <span className={`${badge} border-slate-500/40`}>
      <Icon aria-hidden className="size-3.5" />
      {kind === 'organization' ? 'Organization' : 'Person'}
    </span>
  );
}
