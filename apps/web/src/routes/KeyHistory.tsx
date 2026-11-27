import type { KeyObservation, KeyObservationStatus } from '@mailshield/contracts';
import { useCallback, useEffect, useState } from 'react';
import type { ApiError, Client } from '../api/client.ts';

const STATUS: Record<KeyObservationStatus, [label: string, text: string]> = {
  current: ['Current key', 'The key most recently seen for this domain.'],
  rotated: ['Rotated', 'Replaced by a key under a newer selector. Normal for providers.'],
  unexpected: [
    'Unexpected change',
    'The same selector later showed a different key. Providers do this when they rotate, but so can an attacker who controls DNS.',
  ],
  revoked: ['Revoked by you', 'You marked this key as not to be trusted.'],
};

interface Props {
  client: Client;
  onUnauthorized: () => void;
}

/** Keys seen on verified messages, grouped by domain and selector. Only exists when switched on. */
export function KeyHistory({ client, onUnauthorized }: Props) {
  const [items, setItems] = useState<KeyObservation[] | null>(null);
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fail = useCallback(
    (e: unknown) => {
      const err = e as ApiError;
      if (err.type === 'unauthorized') onUnauthorized();
      else setError(err.message);
    },
    [onUnauthorized],
  );

  useEffect(() => {
    client.keyHistory().then((h) => setItems(h.observations), fail);
    client.settings().then((s) => setEnabled(s.historyEnabled), fail);
  }, [client, fail]);

  const groups = new Map<string, KeyObservation[]>();
  for (const o of items ?? []) {
    const key = `${o.domain} / ${o.selector}`;
    groups.set(key, [...(groups.get(key) ?? []), o]);
  }

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Key history</h2>
      <p className="text-sm">
        The signing keys that verified on messages you analysed, per domain and selector. It holds
        domains, selectors and key fingerprints only: no message content.
      </p>
      {enabled === false && (
        <p role="status" className="card text-sm">
          Key history is switched off, so nothing is recorded and rule R8 is not evaluated. Turn it
          on in{' '}
          <a href="#/settings" className="underline">
            Settings
          </a>
          .
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm font-medium">
          {error}
        </p>
      )}
      {items && items.length === 0 && <p className="text-sm">No keys recorded yet.</p>}
      {[...groups].map(([name, list]) => (
        <section key={name} aria-label={name} className="card space-y-3">
          <h3 className="font-semibold break-all">{name}</h3>
          <ol className="space-y-3 border-l-2 border-slate-300 pl-4 dark:border-slate-700">
            {list.map((o) => {
              const [label, text] = STATUS[o.status];
              return (
                <li key={o.id} className="text-sm">
                  <p className="font-medium">
                    {label}{' '}
                    <span className="text-xs font-normal text-slate-500 dark:text-slate-400">
                      first seen {o.firstSeen.slice(0, 10)}, last seen {o.lastSeen.slice(0, 10)}
                    </span>
                  </p>
                  <p className="text-xs">{text}</p>
                  <code className="block text-xs break-all">{o.fingerprint}</code>
                  {o.status !== 'revoked' && (
                    <button
                      type="button"
                      className="mt-1 text-xs underline"
                      onClick={() =>
                        client.revokeObserved(o.id).then((h) => setItems(h.observations), fail)
                      }
                    >
                      Mark as revoked
                    </button>
                  )}
                </li>
              );
            })}
          </ol>
        </section>
      ))}
    </div>
  );
}
