/** Phase 7: the evaluation route serves the generated report and nothing else. */
import { EvaluationReport } from '@mailshield/contracts';
import { FixtureResolver } from '@mailshield/lab';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { buildApp } from '../src/app.ts';
import { readConfig } from '../src/config.ts';
import { openDatabase } from '../src/db/open.ts';
import { KeyHistoryRepo } from '../src/db/key-history-repo.ts';
import { RegistryRepo } from '../src/db/registry-repo.ts';
import { SettingsRepo } from '../src/db/settings-repo.ts';
import { Pairing, type SessionStore } from '../src/middleware/pairing-auth.ts';
import { createLogger } from '../src/middleware/redact-logger.ts';

const HOST = '127.0.0.1:8787';
const WEB = 'http://127.0.0.1:5173';

async function setup() {
  let saved: string[] = [];
  const store: SessionStore = { load: () => saved, save: (hashes) => void (saved = hashes) };
  const codes: string[] = [];
  const db = openDatabase(':memory:');
  const app = buildApp({
    config: readConfig({}),
    resolver: new FixtureResolver({}),
    registry: new RegistryRepo(db),
    settings: new SettingsRepo(db),
    history: new KeyHistoryRepo(db),
    pairing: new Pairing(store, (code) => codes.push(code)),
    logger: createLogger({ write: () => undefined }),
    clock: () => new Date('2026-06-01T12:00:00Z'),
  });
  const get = (path: string) =>
    request(app).get(`/api/v1${path}`).set('Host', HOST).set('Origin', WEB);
  const paired = await request(app)
    .post('/api/v1/pair')
    .set('Host', HOST)
    .set('Origin', WEB)
    .send({ code: codes.at(-1) });
  return { get, token: paired.body.token as string };
}

describe('GET /evaluation/:split', () => {
  it('requires pairing', async () => {
    const { get } = await setup();
    expect((await get('/evaluation/all')).status).toBe(401);
  });

  it('serves the generated report for each split', async () => {
    const { get, token } = await setup();
    for (const split of ['dev', 'heldout', 'all']) {
      const res = await get(`/evaluation/${split}`).set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(EvaluationReport.parse(res.body).split).toBe(split);
    }
  });

  it('only accepts the three known split names', async () => {
    const { get, token } = await setup();
    const res = await get('/evaluation/..%2Fregistry').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });
});
