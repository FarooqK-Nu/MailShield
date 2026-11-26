import type { EvidenceStatus, StageStatus } from '@mailshield/contracts';
import {
  Ban,
  CircleCheck,
  CircleDashed,
  CircleQuestionMark,
  CircleX,
  ClockAlert,
  LoaderCircle,
  ShieldOff,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react';

type Status = EvidenceStatus | StageStatus;

const green = 'border-emerald-700/40 text-emerald-800 dark:text-emerald-300';
const red = 'border-red-700/40 text-red-800 dark:text-red-300';
const amber = 'border-amber-700/40 text-amber-800 dark:text-amber-300';
const grey = 'border-slate-500/40 text-slate-600 dark:text-slate-300';

/** One status language everywhere: icon, text and colour. Colour is never the only signal. */
const STATUS: Record<Status, [label: string, Icon: LucideIcon, tone: string]> = {
  pass: ['Passed', CircleCheck, green],
  fail: ['Failed', CircleX, red],
  error: ['Error', TriangleAlert, amber],
  warn: ['Check details', TriangleAlert, amber],
  missing: ['Missing', CircleDashed, amber],
  temporary_error: ['Temporary error', ClockAlert, amber],
  unknown: ['Unknown', CircleQuestionMark, grey],
  unsupported: ['Unsupported', Ban, grey],
  untrusted: ['Untrusted', ShieldOff, amber],
  not_evaluated: ['Not evaluated', CircleDashed, grey],
  skipped: ['Skipped', CircleDashed, grey],
  pending: ['Pending', CircleDashed, grey],
  running: ['Running', LoaderCircle, grey],
};

export function StatusBadge({ status }: { status: Status }) {
  const [label, Icon, tone] = STATUS[status];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap ${tone}`}
    >
      <Icon aria-hidden className="size-3.5" />
      {label}
    </span>
  );
}
