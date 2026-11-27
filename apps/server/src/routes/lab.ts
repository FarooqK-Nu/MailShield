import { LabScenario } from '@mailshield/contracts';
import { analyze } from '@mailshield/engine';
import {
  fixtureRegistry,
  FixtureResolver,
  listFixtures,
  loadFixture,
  runScenario,
} from '@mailshield/lab';
import express, { Router, type RequestHandler } from 'express';
import { sendProblem } from '../middleware/errors.ts';

/**
 * The only place the server uses the lab package. Demo messages are verified against fixture
 * DNS and the result is labelled as simulated. Live analysis cannot reach any of this.
 */
export function labRoutes(guards: RequestHandler[]): Router {
  const router = Router();

  router.get('/fixtures', ...guards, (_req, res) => {
    res.json({
      fixtures: listFixtures().map(({ id, title, description }) => ({ id, title, description })),
    });
  });

  router.post('/lab/demo/:id', ...guards, async (req, res) => {
    const fixture = loadFixture(String(req.params.id));
    if (!fixture) return sendProblem(res, 'not_found');
    const now = new Date(fixture.label.now);
    res.json(
      await analyze(
        { raw: fixture.raw, source: 'fixture' },
        // The fictional seed registry, never the local one (A-10).
        {
          resolver: new FixtureResolver(fixture.zone),
          registry: fixtureRegistry,
          clock: () => now,
        },
      ),
    );
  });

  // Scenario fields are validated against fixed lists and patterns; nothing is stored and the
  // only DNS the engine can reach is the in-memory fixture zone.
  router.post(
    '/lab/run',
    ...guards,
    express.json({ limit: '16kb', inflate: false }),
    async (req, res) => {
      const scenario = LabScenario.safeParse(req.body);
      if (!scenario.success) return sendProblem(res, 'invalid_request');
      res.json(await runScenario(scenario.data));
    },
  );

  return router;
}
