import { HealthResponse } from '@mailshield/contracts';
import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

function App() {
  const [service, setService] = useState('Checking local service…');

  useEffect(() => {
    fetch('/api/v1/health')
      .then(async (res) => HealthResponse.parse(await res.json()))
      .then((health) => setService(`Local service ready (version ${health.version})`))
      .catch(() => setService('Local service unavailable. Start it with: pnpm dev'));
  }, []);

  return (
    <main className="mx-auto max-w-2xl p-8">
      <h1 className="text-2xl font-semibold">MailShield</h1>
      <p role="status" className="mt-4">
        {service}
      </p>
      <p className="mt-2 text-sm opacity-70">Message analysis is not implemented yet.</p>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
