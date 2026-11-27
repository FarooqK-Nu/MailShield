import { useState, type FormEvent } from 'react';
import { send } from './api.ts';
import { clearReviewed } from './local-data.ts';

const REVOKE_URL = 'https://myaccount.google.com/connections';

function Alert({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p role="alert" className="text-sm text-red-700 dark:text-red-300">
      {message}
    </p>
  );
}

export function ServiceDown({ onRetry }: { onRetry: () => void }) {
  return (
    <section className="card space-y-2">
      <h2 className="font-semibold">The local service is not reachable</h2>
      <p className="text-sm">
        MailShield analyzes messages in a service on this computer. Start it from the project folder
        with <code>npm run dev</code>, then retry.
      </p>
      <button type="button" className="button" onClick={onRetry}>
        Retry
      </button>
    </section>
  );
}

export function PairingForm({ onPaired }: { onPaired: () => void }) {
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await send({ type: 'pair', code });
      onPaired();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="card space-y-2">
      <h2 className="font-semibold">Pair with the local service</h2>
      <p className="text-sm">
        Enter the 8-digit code printed in the terminal where the service runs. Each code works once.
      </p>
      <label className="block text-sm font-medium" htmlFor="pairing-code">
        Pairing code
      </label>
      <input
        id="pairing-code"
        className="field w-40 tracking-widest"
        inputMode="numeric"
        autoComplete="off"
        maxLength={8}
        value={code}
        onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
      />
      <div>
        <button type="submit" className="button" disabled={busy || code.length !== 8}>
          {busy ? 'Pairing…' : 'Pair'}
        </button>
      </div>
      <Alert message={error} />
    </form>
  );
}

/** What read-only access means, said plainly before the user grants it (docs/context.md §7). */
export function ConnectCard({
  oauthConfigured,
  onConnected,
}: {
  oauthConfigured: boolean;
  onConnected: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function connect() {
    setBusy(true);
    setError(null);
    try {
      await send({ type: 'connect' });
      onConnected();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card space-y-2">
      <h2 className="font-semibold">Connect Gmail</h2>
      <p className="text-sm">
        MailShield asks Google for <strong>read-only</strong> Gmail access. A read-only token can
        technically read all of your mail. MailShield chooses to fetch only a message you select,
        confirm and ask it to analyze.
      </p>
      <p className="text-sm">
        The token stays in Chrome. It is never sent to the MailShield service, which receives only
        the bytes of the message you chose.
      </p>
      {!oauthConfigured && (
        <p className="text-sm">
          This build has no Google OAuth client configured (see <code>docs/spikes.md</code>). You
          can still analyze a downloaded .eml file below.
        </p>
      )}
      <button
        type="button"
        className="button"
        disabled={busy || !oauthConfigured}
        onClick={connect}
      >
        {busy ? 'Waiting for Google…' : 'Connect Gmail (read-only)'}
      </button>
      <Alert message={error} />
    </section>
  );
}

/** What is kept, and controls to remove it. */
export function PrivacyPanel({
  connected,
  onChanged,
  onClose,
}: {
  connected: boolean;
  onChanged: () => void;
  onClose: () => void;
}) {
  const [notice, setNotice] = useState<string | null>(null);

  const act = async (work: () => Promise<unknown>, done: string) => {
    try {
      await work();
      setNotice(done);
      onChanged();
    } catch (e) {
      setNotice((e as Error).message);
    }
  };

  return (
    <section className="card space-y-3" aria-labelledby="privacy-title">
      <h2 id="privacy-title" className="font-semibold">
        Privacy and data
      </h2>
      <ul className="list-disc space-y-1 pl-5 text-sm">
        <li>No message content, address or subject is stored by the extension.</li>
        <li>
          The open message’s id, sender and subject are held in memory to confirm your selection,
          and cleared when Chrome closes.
        </li>
        <li>The pairing token for the local service is kept on this device.</li>
        <li>Findings you mark as reviewed are kept on this device as message and finding ids.</li>
        <li>The Gmail token is managed by Chrome and never leaves the extension.</li>
      </ul>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          className="button-quiet"
          onClick={() => act(clearReviewed, 'Reviewed marks cleared.')}
        >
          Clear reviewed marks
        </button>
        {connected && (
          <button
            type="button"
            className="button-quiet"
            onClick={() => act(() => send({ type: 'disconnect' }), 'Gmail disconnected in Chrome.')}
          >
            Disconnect Gmail
          </button>
        )}
        <button
          type="button"
          className="button-quiet"
          onClick={() => act(() => send({ type: 'unpair' }), 'Pairing removed.')}
        >
          Forget pairing
        </button>
      </div>
      <p className="text-sm">
        Disconnecting removes Chrome’s cached token. To withdraw the permission at Google as well,
        remove MailShield at{' '}
        <a href={REVOKE_URL} target="_blank" rel="noreferrer" className="underline">
          your Google Account connections
        </a>
        .
      </p>
      {notice && (
        <p role="status" className="text-sm">
          {notice}
        </p>
      )}
      <button type="button" className="button-quiet" onClick={onClose}>
        Close
      </button>
    </section>
  );
}
