import { AlertDialog } from 'radix-ui';
import { useState, type ReactNode } from 'react';

export interface Confirmation {
  title: string;
  /** What will change, in plain words. */
  changes: string[];
  confirmLabel: string;
  danger?: boolean;
  run: () => Promise<void>;
}

/**
 * Every registry change goes through this dialog: the user sees exactly what changes and
 * that it is recorded in the audit trail, then confirms.
 */
export function ConfirmDialog({
  confirmation,
  onClose,
}: {
  confirmation: Confirmation | null;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function confirm() {
    if (!confirmation) return;
    setBusy(true);
    setError(null);
    try {
      await confirmation.run();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog.Root
      open={confirmation !== null}
      onOpenChange={(open) => {
        if (!open && !busy) {
          setError(null);
          onClose();
        }
      }}
    >
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 bg-slate-950/50" />
        <AlertDialog.Content className="fixed top-1/2 left-1/2 max-h-[85vh] w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 overflow-auto rounded-lg bg-white p-5 shadow-lg dark:bg-slate-900">
          <AlertDialog.Title className="text-lg font-semibold">
            {confirmation?.title}
          </AlertDialog.Title>
          <AlertDialog.Description asChild>
            <div className="mt-2 space-y-2 text-sm">
              <ul className="list-disc space-y-1 pl-5">
                {confirmation?.changes.map((change) => (
                  <li key={change} className="wrap-break-word">
                    {change}
                  </li>
                ))}
              </ul>
              <p className="text-slate-600 dark:text-slate-400">
                The change is recorded in the audit trail.
              </p>
            </div>
          </AlertDialog.Description>
          {error && (
            <p role="alert" className="mt-3 rounded-md border border-red-600 p-2 text-sm">
              {error}
            </p>
          )}
          <div className="mt-5 flex justify-end gap-2">
            <AlertDialog.Cancel asChild>
              <button type="button" className="rounded-md px-4 py-2 text-sm" disabled={busy}>
                Cancel
              </button>
            </AlertDialog.Cancel>
            <button
              type="button"
              className={confirmation?.danger ? 'button bg-red-700 dark:bg-red-300' : 'button'}
              disabled={busy}
              onClick={() => void confirm()}
            >
              {confirmation?.confirmLabel}
            </button>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1 text-sm">
      <span className="font-medium">{label}</span>
      {children}
    </label>
  );
}
