import type { AuditEvent } from '@mailshield/contracts';

const ACTIONS: Record<AuditEvent['action'], string> = {
  create: 'Created',
  update: 'Changed',
  delete: 'Deleted',
  key_added: 'Key enrolled',
  import: 'Imported',
};

const name = (snapshot: unknown) =>
  (snapshot as { displayName?: string } | null)?.displayName ?? 'identity';

/** Top-level fields that differ between the before and after snapshots. */
function changedFields(event: AuditEvent): string[] {
  if (!event.before || !event.after) return [];
  const before = event.before as Record<string, unknown>;
  const after = event.after as Record<string, unknown>;
  return Object.keys(after).filter(
    (key) =>
      !['updatedAt', 'deletedAt'].includes(key) &&
      JSON.stringify(before[key]) !== JSON.stringify(after[key]),
  );
}

export function AuditTrail({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-slate-500 dark:text-slate-400">No changes recorded yet.</p>;
  }
  return (
    <ol className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
      {events.map((event) => {
        const fields = changedFields(event);
        return (
          <li key={event.id} className="py-2">
            <p>
              <span className="font-medium">{ACTIONS[event.action]}</span>{' '}
              {name(event.after ?? event.before)}
              {fields.length > 0 && <> ({fields.join(', ')})</>}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              <time dateTime={event.at}>{new Date(event.at).toLocaleString()}</time> by{' '}
              {event.actor}
            </p>
          </li>
        );
      })}
    </ol>
  );
}
