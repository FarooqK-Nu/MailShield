import { StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type { SpikeReply } from '../background.ts';

function Panel() {
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setStatus('Connecting…');
    const reply: SpikeReply = await chrome.runtime.sendMessage({ type: 'oauth-spike' });
    setStatus(
      reply.ok ? `Fetched one raw message (${reply.rawBytes} bytes).` : `Failed: ${reply.error}`,
    );
    setBusy(false);
  }

  return (
    <main style={{ fontFamily: 'system-ui', padding: 16 }}>
      <h1>MailShield</h1>
      <p>
        Connection test. Read-only Gmail access can technically read all your mail; this test
        fetches only the newest message and shows its size.
      </p>
      <button type="button" onClick={run} disabled={busy}>
        Connect and test
      </button>
      <p role="status">{status}</p>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Panel />
  </StrictMode>,
);
