import {
  RULE_NAMES as RULE_IDS,
  type AuditEvent,
  type Settings as SettingsData,
} from '@mailshield/contracts';
import { useCallback, useEffect, useState } from 'react';
import type { ApiError, Client } from '../api/client.ts';
import { ConfirmDialog, type Confirmation } from '../features/registry/ConfirmDialog.tsx';
import { RULE_NAMES } from '../features/rules.ts';

interface Props {
  client: Client;
  onUnauthorized: () => void;
}

const describe = (value: unknown) => {
  const s = value as { historyEnabled?: boolean; disabledRules?: string[] } | null;
  if (!s) return '';
  const off = s.disabledRules?.length ? s.disabledRules.join(', ') : 'none';
  return `history ${s.historyEnabled ? 'on' : 'off'}, rules off: ${off}`;
};

/** Privacy, rule sensitivity, DNS behaviour, local data and sessions. */
export function Settings({ client, onUnauthorized }: Props) {
  const [data, setData] = useState<SettingsData | null>(null);
  const [draft, setDraft] = useState<{ historyEnabled: boolean; disabledRules: string[] } | null>(
    null,
  );
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);

  const fail = useCallback(
    (e: unknown) => {
      const err = e as ApiError;
      if (err.type === 'unauthorized') onUnauthorized();
      else setError(err.message);
    },
    [onUnauthorized],
  );

  const load = useCallback(() => {
    client.settings().then((s) => {
      setData(s);
      setDraft({ historyEnabled: s.historyEnabled, disabledRules: s.disabledRules });
    }, fail);
    client.settingsAudit().then((a) => setAudit(a.events), fail);
  }, [client, fail]);
  useEffect(load, [load]);

  if (!data || !draft) return <p role="status">{error ?? 'Loading settings…'}</p>;
  const changed =
    draft.historyEnabled !== data.historyEnabled ||
    draft.disabledRules.join() !== data.disabledRules.join();

  const save = () =>
    setConfirmation({
      title: 'Save these settings?',
      changes: [
        `Key history: ${draft.historyEnabled ? 'on' : 'off'}.`,
        `Rules switched off: ${draft.disabledRules.length ? draft.disabledRules.join(', ') : 'none'}.`,
        'The change is recorded in the settings audit list below.',
      ],
      confirmLabel: 'Save settings',
      run: async () => {
        await client.saveSettings({
          historyEnabled: draft.historyEnabled,
          disabledRules: RULE_IDS.filter((r) => draft.disabledRules.includes(r)),
        });
        setNotice('Settings saved.');
        load();
      },
    });

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Settings</h2>
      {error && (
        <p role="alert" className="text-sm font-medium">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="text-sm">
          {notice}
        </p>
      )}

      <fieldset className="card space-y-2">
        <legend className="px-1 font-semibold">Privacy and key history</legend>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={draft.historyEnabled}
            onChange={(e) => setDraft({ ...draft, historyEnabled: e.target.checked })}
          />
          <span>
            Remember the signing keys I see (off by default). Stores the domain, selector and key
            fingerprint of verified signatures on this computer, so rule R8 can tell a first contact
            or a key change. No message content is stored. Stored only for messages you analyse from
            Gmail or by upload.
          </span>
        </label>
      </fieldset>

      <fieldset className="card space-y-2">
        <legend className="px-1 font-semibold">Rule sensitivity</legend>
        <p className="text-sm">
          Switch off a rule you do not want. A rule that is off is shown as “not evaluated”, never
          as passed.
        </p>
        <ul className="grid gap-1 sm:grid-cols-2">
          {RULE_IDS.map((id) => (
            <li key={id}>
              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={!draft.disabledRules.includes(id)}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      disabledRules: e.target.checked
                        ? draft.disabledRules.filter((r) => r !== id)
                        : [...draft.disabledRules, id],
                    })
                  }
                />
                <span>
                  {id}: {RULE_NAMES[id]}
                </span>
              </label>
            </li>
          ))}
        </ul>
      </fieldset>

      <div className="flex gap-3">
        <button type="button" className="button" disabled={!changed} onClick={save}>
          Save settings
        </button>
        <button
          type="button"
          className="button-secondary"
          onClick={() =>
            setConfirmation({
              title: 'Reset settings to their defaults?',
              changes: ['Key history off, every rule on.', 'Recorded keys are not deleted.'],
              confirmLabel: 'Reset settings',
              run: async () => {
                await client.resetSettings();
                setNotice('Settings reset.');
                load();
              },
            })
          }
        >
          Reset to defaults
        </button>
      </div>

      <section className="card space-y-1 text-sm" aria-labelledby="dns-title">
        <h3 id="dns-title" className="font-semibold">
          DNS behaviour
        </h3>
        <p>
          Resolvers: {data.dns.servers?.join(', ') ?? 'the system resolvers'}. Timeout:{' '}
          {data.dns.timeoutMs} ms per lookup.
        </p>
        <p className="text-xs">
          Set by the <code>DNS_SERVERS</code> and <code>DNS_TIMEOUT_MS</code> environment settings
          when the service starts; it cannot be changed here.
        </p>
      </section>

      <section className="card space-y-2 text-sm" aria-labelledby="data-title">
        <h3 id="data-title" className="font-semibold">
          Local data and sessions
        </h3>
        <p>Theme: use the sun or moon button in the page header.</p>
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            className="button-secondary"
            onClick={() =>
              setConfirmation({
                title: 'Delete the key history?',
                changes: [
                  'Every recorded key is removed from this computer.',
                  'This cannot be undone.',
                ],
                confirmLabel: 'Delete key history',
                danger: true,
                run: async () => {
                  const { deleted } = await client.clearKeyHistory();
                  setNotice(`${deleted} recorded key(s) deleted.`);
                },
              })
            }
          >
            Delete key history
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() =>
              setConfirmation({
                title: 'Sign out every paired client?',
                changes: [
                  'The dashboard and the extension must pair again with a new code.',
                  'Use this if you think a token was exposed.',
                ],
                confirmLabel: 'Revoke all sessions',
                danger: true,
                run: async () => {
                  await client.revokeSessions();
                  onUnauthorized();
                },
              })
            }
          >
            Revoke all sessions
          </button>
        </div>
        <p className="text-xs">Registry entries are deleted and exported on the Registry page.</p>
      </section>

      <section aria-labelledby="audit-title" className="space-y-1 text-sm">
        <h3 id="audit-title" className="font-semibold">
          Settings changes
        </h3>
        {audit.length === 0 ? (
          <p>No changes yet.</p>
        ) : (
          <ul className="space-y-1">
            {audit.map((e) => (
              <li key={e.id}>
                {e.at.slice(0, 16).replace('T', ' ')}: {describe(e.before)} → {describe(e.after)}
              </li>
            ))}
          </ul>
        )}
      </section>

      <ConfirmDialog confirmation={confirmation} onClose={() => setConfirmation(null)} />
    </div>
  );
}
