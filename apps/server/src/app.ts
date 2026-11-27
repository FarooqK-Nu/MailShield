import { HealthResponse, PairRequest } from '@mailshield/contracts';
import type { DnsResolver } from '@mailshield/engine';
import cors from 'cors';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import type { Logger } from 'pino';
import type { Config } from './config.ts';
import type { KeyHistoryRepo } from './db/key-history-repo.ts';
import type { RegistryRepo } from './db/registry-repo.ts';
import type { SettingsRepo } from './db/settings-repo.ts';
import { errorHandler, notFound, sendProblem } from './middleware/errors.ts';
import { hostGuard } from './middleware/host-guard.ts';
import { originGuard, requireOrigin } from './middleware/origin-guard.ts';
import { requireToken, type Pairing } from './middleware/pairing-auth.ts';
import { requestLogger } from './middleware/redact-logger.ts';
import { analyzeRoutes } from './routes/analyze.ts';
import { identityRoutes } from './routes/identities.ts';
import { labRoutes } from './routes/lab.ts';
import { settingsRoutes } from './routes/settings.ts';

export interface AppDeps {
  config: Pick<
    Config,
    'port' | 'allowedOrigins' | 'extensionOrigin' | 'dnsServers' | 'dnsTimeoutMs'
  >;
  /** Used by live analysis only. */
  resolver: DnsResolver;
  registry: RegistryRepo;
  settings: SettingsRepo;
  history: KeyHistoryRepo;
  pairing: Pairing;
  logger: Logger;
  clock: () => Date;
}

const limit = (perMinute: number) =>
  rateLimit({
    windowMs: 60_000,
    limit: perMinute,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (_req, res) => sendProblem(res, 'rate_limited'),
  });

export function buildApp({
  config,
  resolver,
  registry,
  settings,
  history,
  pairing,
  logger,
  clock,
}: AppDeps) {
  const app = express();
  app.disable('x-powered-by');

  // Order matters (architecture.md §5.2). Bodies are read only after auth and rate limits.
  app.use(requestLogger(logger));
  app.use(hostGuard(config.port));
  app.use(originGuard(config.allowedOrigins));
  app.use(cors({ origin: [...config.allowedOrigins] }));

  const api = express.Router();

  api.get('/health', (_req, res) => {
    res.json(HealthResponse.parse({ status: 'ok', version: '0.1.0' }));
  });

  api.post(
    '/pair',
    requireOrigin,
    limit(10),
    express.json({ limit: '1kb', inflate: false }),
    (req, res) => {
      const token = pairing.exchange(PairRequest.parse(req.body).code);
      if (!token) return sendProblem(res, 'pairing_failed');
      res.json({ token });
    },
  );

  const guards = [requireToken(pairing), limit(60)];
  api.use(
    analyzeRoutes(
      {
        resolver,
        registry,
        settings,
        history,
        clock,
        logger,
        extensionOrigin: config.extensionOrigin,
      },
      guards,
    ),
  );
  api.use(settingsRoutes({ settings, history, registry, pairing, config }, guards));
  api.use(identityRoutes(registry, guards));
  api.use(labRoutes(guards));

  app.use('/api/v1', api);
  app.use(notFound);
  app.use(errorHandler(logger));

  return app;
}
