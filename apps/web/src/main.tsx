import { Moon, Sun } from 'lucide-react';
import { StrictMode, useCallback, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { createClient, session } from './api/client.ts';
import { PairingScreen } from './PairingScreen.tsx';
import { Analyze } from './routes/Analyze.tsx';
import './styles.css';
import { useTheme } from './theme.ts';

function App() {
  const [token, setToken] = useState(session.get);
  const { dark, toggle } = useTheme();
  const client = useMemo(() => (token ? createClient(token) : null), [token]);

  const keep = useCallback((next: string | null) => {
    session.set(next);
    setToken(next);
  }, []);
  const forget = useCallback(() => keep(null), [keep]);

  return (
    <div className="mx-auto max-w-3xl px-4 py-6">
      <header className="mb-6 flex items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">MailShield</h1>
        <button type="button" className="rounded-md p-2" onClick={toggle}>
          {dark ? <Sun aria-hidden className="size-5" /> : <Moon aria-hidden className="size-5" />}
          <span className="sr-only">Switch to {dark ? 'light' : 'dark'} theme</span>
        </button>
      </header>
      <main>
        {client ? (
          <Analyze client={client} onUnauthorized={forget} />
        ) : (
          <PairingScreen onPaired={keep} />
        )}
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
