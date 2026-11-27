import type { Identity, KeyPreview } from '@mailshield/contracts';
import { useState } from 'react';
import type { Client } from '../../api/client.ts';

const CORROBORATING = ['user_trusted', 'independently_verified'];

/**
 * Enrolling a key is a deliberate act with three steps: paste public material, read the
 * fingerprint, and confirm that it was compared with the person through another channel.
 * The key is the trust anchor for that person's personal signatures, nothing more.
 */
export function KeyEnrolment({
  client,
  identity,
  onDone,
  onCancel,
}: {
  client: Client;
  identity: Identity;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [pem, setPem] = useState('');
  const [preview, setPreview] = useState<KeyPreview | null>(null);
  const [compared, setCompared] = useState(false);
  const [source, setSource] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await work();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const ready = preview && !preview.alreadyEnrolledFor && compared && source.trim().length > 0;

  return (
    <section aria-labelledby="enrol-title" className="card space-y-4">
      <h2 id="enrol-title" className="font-semibold">
        Enrol a key for {identity.displayName}
      </h2>

      <div className="space-y-2">
        <label className="block text-sm font-medium" htmlFor="enrol-pem">
          1. Paste the person’s certificate or public key (PEM)
        </label>
        <textarea
          id="enrol-pem"
          className="field w-full font-mono text-xs"
          rows={6}
          value={pem}
          spellCheck={false}
          placeholder="-----BEGIN CERTIFICATE-----"
          onChange={(e) => {
            setPem(e.target.value);
            setPreview(null);
            setCompared(false);
          }}
        />
        <p className="text-xs">Private keys are refused and never stored.</p>
        <button
          type="button"
          className="button-secondary"
          disabled={busy || !pem.trim()}
          onClick={() => void run(async () => setPreview(await client.previewKey(pem)))}
        >
          Show fingerprint
        </button>
      </div>

      {preview && (
        <div className="space-y-3 text-sm">
          <h3 className="font-medium">2. Read the fingerprint</h3>
          <dl className="space-y-1">
            <div>
              <dt className="text-xs text-slate-500 dark:text-slate-400">
                Key fingerprint (SHA-256)
              </dt>
              <dd>
                <code className="text-xs break-all">{preview.fingerprint}</code>
              </dd>
            </div>
            <div>
              <dt className="text-xs text-slate-500 dark:text-slate-400">Type</dt>
              <dd>
                {preview.material === 'certificate' ? 'Certificate' : 'Public key'},{' '}
                {preview.keyType.toUpperCase()}
              </dd>
            </div>
            {preview.subject && (
              <div>
                <dt className="text-xs text-slate-500 dark:text-slate-400">Subject</dt>
                <dd className="break-all">{preview.subject}</dd>
              </div>
            )}
            {preview.email && (
              <div>
                <dt className="text-xs text-slate-500 dark:text-slate-400">Email address</dt>
                <dd>{preview.email}</dd>
              </div>
            )}
            {preview.issuer && (
              <div>
                <dt className="text-xs text-slate-500 dark:text-slate-400">Issued by</dt>
                <dd className="break-all">{preview.issuer}</dd>
              </div>
            )}
            {preview.expiresAt && (
              <div>
                <dt className="text-xs text-slate-500 dark:text-slate-400">Expires</dt>
                <dd>{preview.expiresAt.slice(0, 10)}</dd>
              </div>
            )}
          </dl>
          {preview.alreadyEnrolledFor && (
            <p role="alert" className="font-medium">
              This key is already enrolled for {preview.alreadyEnrolledFor}.
            </p>
          )}

          <h3 className="font-medium">3. Compare through a separate channel</h3>
          <p>
            Ask {identity.displayName} to read their fingerprint to you by phone, in person or
            through another channel you already trust, not by the email you are checking. Enrol the
            key only if both match.
          </p>
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              className="mt-1"
              checked={compared}
              onChange={(e) => setCompared(e.target.checked)}
            />
            <span>
              I compared this fingerprint with {identity.displayName} through a separate channel.
            </span>
          </label>
          <div>
            <label className="block font-medium" htmlFor="enrol-source">
              How you verified it (provenance)
            </label>
            <input
              id="enrol-source"
              className="field w-full"
              maxLength={500}
              value={source}
              placeholder="For example: read aloud on a phone call, 27 November 2026"
              onChange={(e) => setSource(e.target.value)}
            />
          </div>
          <p className="text-xs">
            Trust scope: this key can confirm a personal signature for {identity.displayName} only.
            It does not make any domain trusted. Enrolling is recorded in the audit trail.
          </p>
          {!CORROBORATING.includes(identity.trustState) && (
            <p className="text-xs">
              Note: a signature confirms this person only when the entry is at least “user trusted”.
              Its trust state is currently “{identity.trustState.replace(/_/g, ' ')}”.
            </p>
          )}
          <div className="flex gap-2">
            <button
              type="button"
              className="button"
              disabled={busy || !ready}
              onClick={() =>
                void run(async () => {
                  await client.addKey(identity.id, {
                    pem,
                    trustSource: source.trim(),
                    expiresAt: null,
                  });
                  onDone();
                })
              }
            >
              Enrol key
            </button>
          </div>
        </div>
      )}

      {error && (
        <p role="alert" className="text-sm font-medium">
          {error}
        </p>
      )}
      <button type="button" className="text-sm underline" onClick={onCancel}>
        Cancel
      </button>
    </section>
  );
}
