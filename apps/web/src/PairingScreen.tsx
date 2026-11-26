import { useState, type FormEvent } from 'react';
import { pair } from './api/client.ts';

export function PairingScreen({ onPaired }: { onPaired: (token: string) => void }) {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      onPaired((await pair(code)).token);
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="max-w-md space-y-3">
      <h2 className="text-lg font-semibold">Pair with the local service</h2>
      <p className="text-sm">
        Enter the 8-digit code shown in the terminal where the service is running. Each code works
        once.
      </p>
      <label className="block text-sm font-medium" htmlFor="code">
        Pairing code
      </label>
      <input
        id="code"
        className="field w-48 tracking-widest"
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
      {error && (
        <p role="alert" className="text-sm text-red-700 dark:text-red-300">
          {error}
        </p>
      )}
    </form>
  );
}
