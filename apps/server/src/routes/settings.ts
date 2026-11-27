import {
  KeyPreview,
  KeyPreviewRequest,
  Settings,
  type KeyHistoryList,
} from '@mailshield/contracts';
import express, { Router, type RequestHandler } from 'express';
import { z } from 'zod';
import type { Config } from '../config.ts';
import type { KeyHistoryRepo } from '../db/key-history-repo.ts';
import { readPublicMaterial } from '../db/public-key.ts';
import type { RegistryRepo } from '../db/registry-repo.ts';
import type { SettingsRepo } from '../db/settings-repo.ts';
import { sendProblem } from '../middleware/errors.ts';
import type { Pairing } from '../middleware/pairing-auth.ts';

/** There is one local user; sessions are not tied to people. */
const ACTOR = 'local_user';

export interface SettingsDeps {
  settings: SettingsRepo;
  history: KeyHistoryRepo;
  registry: RegistryRepo;
  pairing: Pairing;
  config: Pick<Config, 'dnsServers' | 'dnsTimeoutMs'>;
}

/** Settings, key history, key preview and token revocation (Phase 6). */
export function settingsRoutes(
  { settings, history, registry, pairing, config }: SettingsDeps,
  guards: RequestHandler[],
): Router {
  const router = Router();
  const json = express.json({ limit: '32kb', inflate: false });
  const view = () =>
    Settings.parse({
      ...settings.get(),
      dns: { servers: config.dnsServers ?? null, timeoutMs: config.dnsTimeoutMs },
    });

  router.get('/settings', ...guards, (_req, res) => {
    res.json(view());
  });
  router.put('/settings', ...guards, json, (req, res) => {
    settings.update(req.body, ACTOR);
    res.json(view());
  });
  router.post('/settings/reset', ...guards, (_req, res) => {
    settings.reset(ACTOR);
    res.json(view());
  });
  router.get('/settings/audit', ...guards, (_req, res) => {
    res.json({ events: settings.audit() });
  });

  router.get('/key-history', ...guards, (_req, res) => {
    const body: KeyHistoryList = { observations: history.list() };
    res.json(body);
  });
  router.post('/key-history/:id/revoke', ...guards, (req, res) => {
    if (!history.revoke(z.uuid().parse(req.params.id))) return sendProblem(res, 'not_found');
    res.json({ observations: history.list() });
  });
  router.delete('/key-history', ...guards, (_req, res) => {
    res.json({ deleted: history.clear() });
  });

  // Parses pasted PEM and stores nothing; enrolment is a separate, confirmed step.
  router.post('/keys/preview', ...guards, json, (req, res) => {
    const material = readPublicMaterial(KeyPreviewRequest.parse(req.body).pem);
    res.json(
      KeyPreview.parse({
        ...material,
        alreadyEnrolledFor: registry.enrolledFor(material.fingerprint),
      }),
    );
  });

  // Every paired client, including the caller, must pair again.
  router.post('/session/revoke', ...guards, (_req, res) => {
    pairing.revokeAll();
    res.status(204).end();
  });

  return router;
}
