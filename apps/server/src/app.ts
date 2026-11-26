import { HealthResponse } from '@mailshield/contracts';
import express from 'express';
import { hostGuard } from './middleware/host-guard.ts';

/**
 * Phase 0 skeleton: Host guard and health only. Origin guard, pairing auth, limits and the
 * analyze routes arrive in Phase 1, before any route accepts message data.
 */
export function buildApp({ port }: { port: number }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(hostGuard(port));

  app.get('/api/v1/health', (_req, res) => {
    res.json(HealthResponse.parse({ status: 'ok', version: '0.0.0' }));
  });

  return app;
}
