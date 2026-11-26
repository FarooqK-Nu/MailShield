import { IdentityKind, TrustState } from '@mailshield/contracts';
import express, { Router, type RequestHandler } from 'express';
import { z } from 'zod';
import type { RegistryRepo } from '../db/registry-repo.ts';

/** There is one local user; sessions are not tied to people. */
const ACTOR = 'local_user';

const Query = z.object({
  q: z.string().max(200).optional(),
  kind: IdentityKind.optional(),
  trustState: TrustState.optional(),
});
const Id = z.uuid();

export function identityRoutes(registry: RegistryRepo, guards: RequestHandler[]): Router {
  const router = Router();
  const json = express.json({ limit: '64kb', inflate: false });
  const id = (value: unknown) => Id.parse(value);

  router.get('/identities', ...guards, (req, res) => {
    res.json({ identities: registry.list(Query.parse(req.query)) });
  });

  router.post('/identities', ...guards, json, (req, res) => {
    res.status(201).json(registry.create(req.body, ACTOR));
  });

  router.get('/identities/:id', ...guards, (req, res) => {
    res.json(registry.get(id(req.params.id)));
  });

  router.patch('/identities/:id', ...guards, json, (req, res) => {
    res.json(registry.update(id(req.params.id), req.body, ACTOR));
  });

  router.delete('/identities/:id', ...guards, (req, res) => {
    registry.remove(id(req.params.id), ACTOR);
    res.status(204).end();
  });

  router.post('/identities/:id/keys', ...guards, json, (req, res) => {
    res.status(201).json(registry.addKey(id(req.params.id), req.body, ACTOR));
  });

  router.get('/identities/:id/audit', ...guards, (req, res) => {
    res.json({ events: registry.auditTrail(id(req.params.id)) });
  });

  router.get('/audit', ...guards, (_req, res) => {
    res.json({ events: registry.auditTrail() });
  });

  router.get('/registry/export', ...guards, (_req, res) => {
    res.attachment('mailshield-registry.json').json(registry.exportFile());
  });

  router.post(
    '/registry/import',
    ...guards,
    express.json({ limit: '2mb', inflate: false }),
    (req, res) => {
      res.json(registry.importFile(req.body, ACTOR));
    },
  );

  return router;
}
