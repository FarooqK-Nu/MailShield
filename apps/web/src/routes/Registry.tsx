import {
  TrustState,
  type AuditEvent,
  type Identity,
  type IdentityInput,
  type IdentityKind,
} from '@mailshield/contracts';
import {
  Download,
  ExternalLink,
  History,
  KeyRound,
  Pencil,
  Plus,
  Trash2,
  Upload,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { ApiError, type Client, type IdentityFilter } from '../api/client.ts';
import { AuditTrail } from '../features/registry/AuditTrail.tsx';
import { ConfirmDialog, type Confirmation } from '../features/registry/ConfirmDialog.tsx';
import { KeyEnrolment } from '../features/registry/KeyEnrolment.tsx';
import { describeChanges, IdentityForm } from '../features/registry/IdentityForm.tsx';
import { KindBadge, TRUST_LABELS, TrustBadge } from '../features/registry/badges.tsx';

type Panel =
  | { view: 'none' }
  | { view: 'edit'; identity: Identity | null }
  | { view: 'enrol'; identity: Identity }
  | { view: 'audit'; identity: Identity | null; events: AuditEvent[] };

function IdentityCard({
  identity,
  onEdit,
  onDelete,
  onAudit,
  onEnrol,
}: {
  identity: Identity;
  onEdit: () => void;
  onDelete: () => void;
  onAudit: () => void;
  onEnrol: () => void;
}) {
  return (
    <article className="rounded-lg border border-slate-300 p-4 dark:border-slate-700">
      <header className="flex flex-wrap items-center gap-2">
        <h3 className="mr-auto font-semibold">{identity.displayName}</h3>
        <KindBadge kind={identity.kind} />
        <TrustBadge state={identity.trustState} />
      </header>
      <dl className="mt-3 space-y-1 text-sm">
        <div className="grid gap-x-4 sm:grid-cols-[9rem_1fr]">
          <dt className="text-slate-500 dark:text-slate-400">Domains</dt>
          <dd className="min-w-0 wrap-break-word">
            {identity.domains.length
              ? identity.domains
                  .map(
                    (d) =>
                      `${d.domainUnicode}${d.includeSubdomains ? ' (+ subdomains)' : ''}${d.relationship === 'service_provider' ? ' (provider)' : ''}`,
                  )
                  .join(', ')
              : 'none'}
          </dd>
        </div>
        {identity.aliases.length > 0 && (
          <div className="grid gap-x-4 sm:grid-cols-[9rem_1fr]">
            <dt className="text-slate-500 dark:text-slate-400">Also known as</dt>
            <dd>{identity.aliases.map((a) => a.alias).join(', ')}</dd>
          </div>
        )}
        {identity.addresses.length > 0 && (
          <div className="grid gap-x-4 sm:grid-cols-[9rem_1fr]">
            <dt className="text-slate-500 dark:text-slate-400">Trusted addresses</dt>
            <dd className="break-all">{identity.addresses.map((a) => a.address).join(', ')}</dd>
          </div>
        )}
        {identity.keys.length > 0 && (
          <div className="grid gap-x-4 sm:grid-cols-[9rem_1fr]">
            <dt className="text-slate-500 dark:text-slate-400">Enrolled keys</dt>
            <dd>
              {identity.keys.map((k) => (
                <code key={k.id} className="block text-xs break-all">
                  {k.keyType.toUpperCase()} {k.fingerprintSha256}
                </code>
              ))}
            </dd>
          </div>
        )}
        <div className="grid gap-x-4 sm:grid-cols-[9rem_1fr]">
          <dt className="text-slate-500 dark:text-slate-400">Source</dt>
          <dd className="min-w-0 break-all">
            {identity.provenanceUrl ? (
              <a
                className="inline-flex items-center gap-1 underline"
                href={identity.provenanceUrl}
                target="_blank"
                rel="noreferrer noopener"
              >
                {identity.provenanceUrl}
                <ExternalLink aria-hidden className="size-3.5 shrink-0" />
              </a>
            ) : (
              'not recorded'
            )}
          </dd>
        </div>
        <div className="grid gap-x-4 sm:grid-cols-[9rem_1fr]">
          <dt className="text-slate-500 dark:text-slate-400">Last reviewed</dt>
          <dd>{identity.lastReviewed ? identity.lastReviewed.slice(0, 10) : 'never'}</dd>
        </div>
        {identity.notes && (
          <div className="grid gap-x-4 sm:grid-cols-[9rem_1fr]">
            <dt className="text-slate-500 dark:text-slate-400">Notes</dt>
            <dd className="wrap-break-word whitespace-pre-line">{identity.notes}</dd>
          </div>
        )}
      </dl>
      <div className="mt-3 flex flex-wrap gap-3 text-sm">
        <button type="button" className="inline-flex items-center gap-1" onClick={onEdit}>
          <Pencil aria-hidden className="size-4" /> Edit
        </button>
        {identity.kind === 'person' && (
          <button type="button" className="inline-flex items-center gap-1" onClick={onEnrol}>
            <KeyRound aria-hidden className="size-4" /> Enrol a key
          </button>
        )}
        <button type="button" className="inline-flex items-center gap-1" onClick={onAudit}>
          <History aria-hidden className="size-4" /> History
        </button>
        <button
          type="button"
          className="inline-flex items-center gap-1 text-red-800 dark:text-red-300"
          onClick={onDelete}
        >
          <Trash2 aria-hidden className="size-4" /> Delete
        </button>
      </div>
    </article>
  );
}

export function Registry({ client, onUnauthorized }: Props) {
  // The side panel's "Open registry entry" links to #/registry?q=<name>.
  const [filter, setFilter] = useState<IdentityFilter>(() => {
    const q = new URLSearchParams(window.location.hash.split('?')[1] ?? '').get('q');
    return q ? { q: q.slice(0, 200) } : {};
  });
  const [identities, setIdentities] = useState<Identity[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [panel, setPanel] = useState<Panel>({ view: 'none' });
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const fail = useCallback(
    (e: unknown) => {
      const err = e as ApiError;
      if (err.type === 'unauthorized') onUnauthorized();
      else setError(err.message);
    },
    [onUnauthorized],
  );

  const load = useCallback(() => {
    client
      .identities(filter)
      .then((list) => {
        setIdentities(list.identities);
        setError(null);
      })
      .catch(fail);
  }, [client, filter, fail]);

  useEffect(load, [load]);

  function save(before: Identity | null, input: IdentityInput) {
    const changes = describeChanges(before, input);
    if (before && changes.length === 0) {
      setNotice('Nothing changed.');
      return;
    }
    setConfirmation({
      title: before ? `Save changes to ${before.displayName}?` : `Add ${input.displayName}?`,
      changes,
      confirmLabel: before ? 'Save changes' : 'Add identity',
      run: async () => {
        if (before) {
          const { kind: _kind, ...patch } = input;
          void _kind;
          await client.updateIdentity(before.id, patch);
        } else {
          await client.createIdentity(input);
        }
        setPanel({ view: 'none' });
        setNotice(before ? 'Changes saved.' : 'Identity added.');
        load();
      },
    });
  }

  function remove(identity: Identity) {
    setConfirmation({
      title: `Delete ${identity.displayName}?`,
      changes: [
        `Messages will no longer be compared with ${identity.displayName}.`,
        'The entry stays in the audit trail.',
      ],
      confirmLabel: 'Delete',
      danger: true,
      run: async () => {
        await client.deleteIdentity(identity.id);
        setPanel({ view: 'none' });
        setNotice(`${identity.displayName} deleted.`);
        load();
      },
    });
  }

  async function showAudit(identity: Identity | null) {
    try {
      const { events } = await client.audit(identity?.id);
      setPanel({ view: 'audit', identity, events });
    } catch (e) {
      fail(e);
    }
  }

  async function exportFile() {
    try {
      const file = await client.exportRegistry();
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }),
      );
      const link = Object.assign(document.createElement('a'), {
        href: url,
        download: `mailshield-registry-${file.exportedAt.slice(0, 10)}.json`,
      });
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      fail(e);
    }
  }

  async function importFile(file: File | undefined) {
    if (!file) return;
    let parsed: { identities?: { displayName?: string }[] };
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      setError(`${file.name} is not a JSON file.`);
      return;
    }
    const names = (parsed.identities ?? []).map((i) => i.displayName ?? '(no name)');
    setConfirmation({
      title: `Import ${names.length} identities from ${file.name}?`,
      changes: [
        ...names.slice(0, 10).map((n) => `Add “${n}” unless one with this name exists.`),
        ...(names.length > 10 ? [`…and ${names.length - 10} more.`] : []),
        'Imported entries keep the trust state written in the file. Review them afterwards.',
      ],
      confirmLabel: 'Import',
      run: async () => {
        const result = await client.importRegistry(parsed);
        setNotice(
          `Imported ${result.imported}.${result.skipped.length ? ` Skipped existing: ${result.skipped.join(', ')}.` : ''}`,
        );
        load();
      },
    });
  }

  return (
    <div className="space-y-6">
      <section className="space-y-2">
        <h2 className="text-lg font-semibold">Trusted identity registry</h2>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Organizations and people you expect mail from, with the domains they really send from.
          Messages are compared with these entries only. An entry is your trust decision, not an
          objective fact, so record where it came from.
        </p>
      </section>

      <div className="flex flex-wrap items-end gap-2">
        <label className="min-w-48 flex-1 text-sm">
          <span className="sr-only">Search</span>
          <input
            type="search"
            className="field w-full"
            placeholder="Search names, domains, addresses"
            value={filter.q ?? ''}
            onChange={(e) => setFilter({ ...filter, q: e.target.value })}
          />
        </label>
        <select
          aria-label="Type"
          className="field text-sm"
          value={filter.kind ?? ''}
          onChange={(e) =>
            setFilter({ ...filter, kind: (e.target.value || undefined) as IdentityKind })
          }
        >
          <option value="">All types</option>
          <option value="organization">Organizations</option>
          <option value="person">People</option>
        </select>
        <select
          aria-label="Trust state"
          className="field text-sm"
          value={filter.trustState ?? ''}
          onChange={(e) =>
            setFilter({ ...filter, trustState: (e.target.value || undefined) as TrustState })
          }
        >
          <option value="">Any trust state</option>
          {TrustState.options.map((s) => (
            <option key={s} value={s}>
              {TRUST_LABELS[s]}
            </option>
          ))}
        </select>
      </div>

      <div className="flex flex-wrap gap-2 text-sm">
        <button
          type="button"
          className="button inline-flex items-center gap-1"
          onClick={() => setPanel({ view: 'edit', identity: null })}
        >
          <Plus aria-hidden className="size-4" /> New identity
        </button>
        <label className="inline-flex cursor-pointer items-center gap-1 rounded-md border border-slate-400 px-3 py-2 focus-within:outline-2 focus-within:outline-sky-600 dark:border-slate-600">
          <Upload aria-hidden className="size-4" /> Import
          <input
            type="file"
            accept="application/json,.json"
            className="sr-only"
            onChange={(e) => {
              void importFile(e.target.files?.[0]);
              e.target.value = '';
            }}
          />
        </label>
        <button
          type="button"
          className="inline-flex items-center gap-1 rounded-md border border-slate-400 px-3 py-2 dark:border-slate-600"
          onClick={() => void exportFile()}
        >
          <Download aria-hidden className="size-4" /> Export
        </button>
        <button
          type="button"
          className="inline-flex items-center gap-1 rounded-md border border-slate-400 px-3 py-2 dark:border-slate-600"
          onClick={() => void showAudit(null)}
        >
          <History aria-hidden className="size-4" /> All changes
        </button>
      </div>

      <div aria-live="polite">
        {notice && <p className="text-sm">{notice}</p>}
        {error && (
          <p role="alert" className="rounded-lg border border-red-600 p-3 text-sm">
            {error}
          </p>
        )}
      </div>

      {panel.view === 'edit' && (
        <IdentityForm
          key={panel.identity?.id ?? 'new'}
          identity={panel.identity}
          onCancel={() => setPanel({ view: 'none' })}
          onSubmit={(input) => save(panel.identity, input)}
        />
      )}
      {panel.view === 'enrol' && (
        <KeyEnrolment
          key={panel.identity.id}
          client={client}
          identity={panel.identity}
          onCancel={() => setPanel({ view: 'none' })}
          onDone={() => {
            setPanel({ view: 'none' });
            setNotice(`Key enrolled for ${panel.identity.displayName}.`);
            load();
          }}
        />
      )}
      {panel.view === 'audit' && (
        <section className="rounded-lg border border-slate-300 p-4 dark:border-slate-700">
          <header className="mb-2 flex items-center justify-between gap-2">
            <h2 className="font-semibold">
              {panel.identity ? `History of ${panel.identity.displayName}` : 'All registry changes'}
            </h2>
            <button type="button" className="text-sm" onClick={() => setPanel({ view: 'none' })}>
              Close
            </button>
          </header>
          <AuditTrail events={panel.events} />
        </section>
      )}

      <section aria-label="Identities" className="space-y-3">
        {identities === null && !error && <p className="text-sm">Loading…</p>}
        {identities?.length === 0 && (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            {filter.q || filter.kind || filter.trustState
              ? 'No identity matches these filters.'
              : 'The registry is empty. Add the organizations and people you expect mail from, or import a registry file.'}
          </p>
        )}
        {identities?.map((identity) => (
          <IdentityCard
            key={identity.id}
            identity={identity}
            onEdit={() => setPanel({ view: 'edit', identity })}
            onDelete={() => remove(identity)}
            onAudit={() => void showAudit(identity)}
            onEnrol={() => setPanel({ view: 'enrol', identity })}
          />
        ))}
      </section>

      <ConfirmDialog confirmation={confirmation} onClose={() => setConfirmation(null)} />
    </div>
  );
}

interface Props {
  client: Client;
  onUnauthorized: () => void;
}
