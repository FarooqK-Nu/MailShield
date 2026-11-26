import {
  TrustState,
  type DomainRelationship,
  type Identity,
  type IdentityInput,
  type IdentityKind,
} from '@mailshield/contracts';
import { Plus, X } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Field } from './ConfirmDialog.tsx';
import { TRUST_LABELS } from './badges.tsx';

interface DomainRow {
  domain: string;
  includeSubdomains: boolean;
  relationship: DomainRelationship;
}

interface FormState {
  kind: IdentityKind;
  displayName: string;
  trustState: TrustState;
  provenanceUrl: string;
  notes: string;
  /** yyyy-mm-dd */
  lastReviewed: string;
  aliases: string;
  addresses: string;
  domains: DomainRow[];
}

const lines = (text: string) =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);

function fromIdentity(identity: Identity | null): FormState {
  return {
    kind: identity?.kind ?? 'organization',
    displayName: identity?.displayName ?? '',
    trustState: identity?.trustState ?? 'unverified',
    provenanceUrl: identity?.provenanceUrl ?? '',
    notes: identity?.notes ?? '',
    lastReviewed: identity?.lastReviewed?.slice(0, 10) ?? '',
    aliases: identity?.aliases.map((a) => a.alias).join('\n') ?? '',
    addresses: identity?.addresses.map((a) => a.address).join('\n') ?? '',
    domains:
      identity?.domains.map((d) => ({
        domain: d.domainUnicode,
        includeSubdomains: d.includeSubdomains,
        relationship: d.relationship,
      })) ?? [],
  };
}

function toInput(form: FormState): IdentityInput {
  return {
    kind: form.kind,
    displayName: form.displayName.trim(),
    trustState: form.trustState,
    provenanceUrl: form.provenanceUrl.trim() || null,
    notes: form.notes.trim() || null,
    lastReviewed: form.lastReviewed
      ? new Date(`${form.lastReviewed}T00:00:00Z`).toISOString()
      : null,
    aliases: lines(form.aliases),
    addresses: lines(form.addresses),
    domains: form.domains
      .filter((d) => d.domain.trim())
      .map((d) => ({ ...d, domain: d.domain.trim() })),
  };
}

function fromInput(input: IdentityInput): FormState {
  return {
    kind: input.kind,
    displayName: input.displayName,
    trustState: input.trustState ?? 'unverified',
    provenanceUrl: input.provenanceUrl ?? '',
    notes: input.notes ?? '',
    lastReviewed: input.lastReviewed?.slice(0, 10) ?? '',
    aliases: (input.aliases ?? []).join('\n'),
    addresses: (input.addresses ?? []).join('\n'),
    domains: (input.domains ?? []).map((d) => ({
      domain: d.domain,
      includeSubdomains: d.includeSubdomains ?? false,
      relationship: d.relationship ?? 'own',
    })),
  };
}

const describeDomain = (d: DomainRow) =>
  `${d.domain}${d.includeSubdomains ? ' and its subdomains' : ' only'}${d.relationship === 'service_provider' ? ' (service provider)' : ''}`;

/** Plain-language list of what the save will change, for the confirmation dialog. */
export function describeChanges(before: Identity | null, input: IdentityInput): string[] {
  const old = fromIdentity(before);
  const next = fromInput(input);
  if (!before) {
    return [
      `Add ${next.kind === 'organization' ? 'organization' : 'person'} “${next.displayName}” as ${TRUST_LABELS[next.trustState]}.`,
      ...next.domains.map((d) => `Approve domain ${describeDomain(d)}.`),
      ...lines(next.aliases).map((a) => `Add alias “${a}”.`),
      ...lines(next.addresses).map((a) => `Trust address ${a}.`),
    ];
  }
  const changes: string[] = [];
  const field = (label: string, a: string, b: string) => {
    if (a !== b) changes.push(`${label}: “${a || '(empty)'}” → “${b || '(empty)'}”.`);
  };
  field('Name', old.displayName, next.displayName);
  if (old.trustState !== next.trustState) {
    changes.push(`Trust: ${TRUST_LABELS[old.trustState]} → ${TRUST_LABELS[next.trustState]}.`);
  }
  field('Source', old.provenanceUrl, next.provenanceUrl);
  field('Notes', old.notes, next.notes);
  field('Last reviewed', old.lastReviewed, next.lastReviewed);
  const diff = (label: string, a: string[], b: string[]) => {
    for (const item of b) if (!a.includes(item)) changes.push(`Add ${label} ${item}.`);
    for (const item of a) if (!b.includes(item)) changes.push(`Remove ${label} ${item}.`);
  };
  diff('alias', lines(old.aliases), lines(next.aliases));
  diff('trusted address', lines(old.addresses), lines(next.addresses));
  diff('approved domain', old.domains.map(describeDomain), next.domains.map(describeDomain));
  return changes;
}

export function IdentityForm({
  identity,
  onSubmit,
  onCancel,
}: {
  identity: Identity | null;
  onSubmit: (input: IdentityInput) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState(() => fromIdentity(identity));
  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }));
  const setDomain = (i: number, row: Partial<DomainRow>) =>
    set(
      'domains',
      form.domains.map((d, j) => (i === j ? { ...d, ...row } : d)),
    );

  function submit(event: FormEvent) {
    event.preventDefault();
    onSubmit(toInput(form));
  }

  return (
    <form
      onSubmit={submit}
      className="space-y-4 rounded-lg border border-slate-300 p-4 dark:border-slate-700"
    >
      <h2 className="font-semibold">
        {identity ? `Edit ${identity.displayName}` : 'New identity'}
      </h2>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Type">
          <select
            className="field w-full"
            value={form.kind}
            disabled={identity !== null}
            onChange={(e) => set('kind', e.target.value as IdentityKind)}
          >
            <option value="organization">Organization</option>
            <option value="person">Person</option>
          </select>
        </Field>
        <Field label="Trust state">
          <select
            className="field w-full"
            value={form.trustState}
            onChange={(e) => set('trustState', e.target.value as TrustState)}
          >
            {TrustState.options.map((s) => (
              <option key={s} value={s}>
                {TRUST_LABELS[s]}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <Field label="Name">
        <input
          required
          className="field w-full"
          value={form.displayName}
          onChange={(e) => set('displayName', e.target.value)}
        />
      </Field>
      <Field label="Other names it uses (one per line)">
        <textarea
          rows={2}
          className="field w-full"
          value={form.aliases}
          onChange={(e) => set('aliases', e.target.value)}
        />
      </Field>

      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Approved sending domains</legend>
        {form.domains.length === 0 && (
          <p className="text-sm text-slate-500 dark:text-slate-400">No domains yet.</p>
        )}
        {form.domains.map((d, i) => (
          <div key={i} className="flex flex-wrap items-center gap-2">
            <input
              aria-label={`Domain ${i + 1}`}
              className="field min-w-0 flex-1"
              placeholder="example.com"
              value={d.domain}
              onChange={(e) => setDomain(i, { domain: e.target.value })}
            />
            <label className="flex items-center gap-1 text-sm">
              <input
                type="checkbox"
                checked={d.includeSubdomains}
                onChange={(e) => setDomain(i, { includeSubdomains: e.target.checked })}
              />
              Subdomains
            </label>
            <select
              aria-label={`Relationship for domain ${i + 1}`}
              className="field text-sm"
              value={d.relationship}
              onChange={(e) => setDomain(i, { relationship: e.target.value as DomainRelationship })}
            >
              <option value="own">Own domain</option>
              <option value="service_provider">Service provider</option>
            </select>
            <button
              type="button"
              className="rounded-md p-2"
              onClick={() =>
                set(
                  'domains',
                  form.domains.filter((_, j) => j !== i),
                )
              }
            >
              <X aria-hidden className="size-4" />
              <span className="sr-only">Remove domain {d.domain || i + 1}</span>
            </button>
          </div>
        ))}
        <button
          type="button"
          className="inline-flex items-center gap-1 text-sm font-medium"
          onClick={() =>
            set('domains', [
              ...form.domains,
              { domain: '', includeSubdomains: false, relationship: 'own' },
            ])
          }
        >
          <Plus aria-hidden className="size-4" /> Add domain
        </button>
      </fieldset>

      <Field label="Trusted addresses (one per line)">
        <textarea
          rows={2}
          className="field w-full"
          value={form.addresses}
          onChange={(e) => set('addresses', e.target.value)}
        />
      </Field>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Where these facts come from (URL)">
          <input
            type="url"
            className="field w-full"
            placeholder="https://"
            value={form.provenanceUrl}
            onChange={(e) => set('provenanceUrl', e.target.value)}
          />
        </Field>
        <Field label="Last reviewed">
          <input
            type="date"
            className="field w-full"
            value={form.lastReviewed}
            onChange={(e) => set('lastReviewed', e.target.value)}
          />
        </Field>
      </div>
      <Field label="Notes">
        <textarea
          rows={2}
          className="field w-full"
          value={form.notes}
          onChange={(e) => set('notes', e.target.value)}
        />
      </Field>
      <div className="flex justify-end gap-2">
        <button type="button" className="rounded-md px-4 py-2 text-sm" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="button">
          Review changes
        </button>
      </div>
    </form>
  );
}
