import { Moon, Sun } from 'lucide-react';
import { StrictMode, useCallback, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { createClient, session } from './api/client.ts';
import { PairingScreen } from './PairingScreen.tsx';
import { Analyze } from './routes/Analyze.tsx';
import { KeyHistory } from './routes/KeyHistory.tsx';
import { Lab } from './routes/Lab.tsx';
import { Overview } from './routes/Overview.tsx';
import { Registry } from './routes/Registry.tsx';
import { Report } from './routes/Report.tsx';
import { Settings } from './routes/Settings.tsx';
import './styles.css';
import { useTheme } from './theme.ts';

const PAGES = [
  { hash: '#/', label: 'Overview' },
  { hash: '#/analyze', label: 'Analyze' },
  { hash: '#/registry', label: 'Registry' },
  { hash: '#/keys', label: 'Key history' },
  { hash: '#/lab', label: 'Lab' },
  { hash: '#/settings', label: 'Settings' },
] as const;
/** Opened by the side panel's "Open full report"; not in the navigation (decision A-14). */
const REPORT = '#/report';
type Page = (typeof PAGES)[number]['hash'] | typeof REPORT;

/** Hash routing keeps the dashboard a static page with no server-side routes. */
function usePage(): Page {
  const read = (): Page => {
    // A page may carry a query, for example #/registry?q=Acme.
    const path = window.location.hash.split('?')[0];
    if (path === REPORT) return REPORT;
    return PAGES.find((p) => p.hash === path)?.hash ?? '#/';
  };
  const [page, setPage] = useState(read);
  useEffect(() => {
    const onChange = () => setPage(read());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return page;
}

function App() {
  const page = usePage();
  const [token, setToken] = useState(session.get);
  const { dark, toggle } = useTheme();
  const client = useMemo(() => (token ? createClient(token) : null), [token]);

  const keep = useCallback((next: string | null) => {
    session.set(next);
    setToken(next);
  }, []);
  const forget = useCallback(() => keep(null), [keep]);

  return (
    <div
      className={`mx-auto px-4 py-6 ${page === '#/analyze' || page === '#/lab' || page === REPORT ? 'max-w-7xl' : 'max-w-3xl'}`}
    >
      <header className="mb-6 flex flex-wrap items-center gap-4">
        <h1 className="mr-auto text-2xl font-semibold">MailShield</h1>
        {client && (
          <nav aria-label="Pages" className="flex gap-1">
            {PAGES.map((p) => (
              <a
                key={p.hash}
                href={p.hash}
                aria-current={page === p.hash ? 'page' : undefined}
                className="rounded-md px-3 py-1.5 text-sm font-medium aria-[current=page]:bg-slate-200 dark:aria-[current=page]:bg-slate-800"
              >
                {p.label}
              </a>
            ))}
          </nav>
        )}
        <button type="button" className="rounded-md p-2" onClick={toggle}>
          {dark ? <Sun aria-hidden className="size-5" /> : <Moon aria-hidden className="size-5" />}
          <span className="sr-only">Switch to {dark ? 'light' : 'dark'} theme</span>
        </button>
      </header>
      <main>
        {client && page === '#/registry' && <Registry client={client} onUnauthorized={forget} />}
        {client && page === '#/' && <Overview />}
        {client && page === '#/keys' && <KeyHistory client={client} onUnauthorized={forget} />}
        {client && page === '#/settings' && <Settings client={client} onUnauthorized={forget} />}
        {client && page === '#/lab' && <Lab client={client} onUnauthorized={forget} />}
        {client && page === '#/analyze' && <Analyze client={client} onUnauthorized={forget} />}
        {/* The report needs no pairing: its data comes from the extension, not the service. */}
        {page === REPORT && <Report />}
        {!client && page !== REPORT && <PairingScreen onPaired={keep} />}
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
