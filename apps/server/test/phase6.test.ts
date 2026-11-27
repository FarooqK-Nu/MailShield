/** Phase 6 service behaviour: settings, key history, key preview, S/MIME in live mode. */
import { readFileSync } from 'node:fs';
import {
  AnalysisResult,
  KeyHistoryList,
  KeyPreview,
  LabPersonalResponse,
  Settings,
} from '@mailshield/contracts';
import { FixtureResolver, loadFixture, runPersonalScenario } from '@mailshield/lab';
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
const legit = loadFixture('legit-signed')!;

async function setup() {
  let saved: string[] = [];
  const store: SessionStore = { load: () => saved, save: (hashes) => void (saved = hashes) };
  const codes: string[] = [];
  const db = openDatabase(':memory:');
  const history = new KeyHistoryRepo(db);
  const app = buildApp({
    config: readConfig({}),
    // Fixture DNS stands in for the network, so the signed Acme fixture verifies.
    resolver: new FixtureResolver(legit.zone),
    registry: new RegistryRepo(db),
    settings: new SettingsRepo(db),
    history,
    pairing: new Pairing(store, (code) => codes.push(code)),
    logger: createLogger({ write: () => undefined }),
    clock: () => new Date(legit.label.now),
  });
  const base = (method: 'get' | 'post' | 'put' | 'delete', path: string) =>
    request(app)[method](`/api/v1${path}`).set('Host', HOST).set('Origin', WEB);
  const paired = await base('post', '/pair').send({ code: codes.at(-1) });
  const token = paired.body.token as string;
  const api = (method: 'get' | 'post' | 'put' | 'delete', path: string) =>
    base(method, path).set('Authorization', `Bearer ${token}`);
  const analyze = (body: Buffer) =>
    api('post', '/analyze').set('Content-Type', 'application/octet-stream').send(body);
  return { api, analyze, history, token };
}

describe('settings', () => {
  it('keeps history off by default, and audits every change', async () => {
    const { api } = await setup();
    const first = Settings.parse((await api('get', '/settings')).body);
    expect(first).toMatchObject({ historyEnabled: false, disabledRules: [] });
    expect(first.dns.timeoutMs).toBeGreaterThan(0);

    const put = await api('put', '/settings').send({ historyEnabled: true, disabledRules: ['R5'] });
    expect(Settings.parse(put.body)).toMatchObject({ historyEnabled: true, disabledRules: ['R5'] });
    const audit = (await api('get', '/settings/audit')).body.events;
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      entityType: 'settings',
      before: { historyEnabled: false },
      after: { historyEnabled: true, disabledRules: ['R5'] },
    });

    const reset = await api('post', '/settings/reset');
    expect(Settings.parse(reset.body).historyEnabled).toBe(false);
    // Settings changes stay out of the registry's own audit list.
    expect((await api('get', '/audit')).body.events).toEqual([]);
  });

  it('rejects unknown fields and unknown rules', async () => {
    const { api } = await setup();
    expect(
      (await api('put', '/settings').send({ historyEnabled: true, disabledRules: [], x: 1 }))
        .status,
    ).toBe(400);
    expect(
      (await api('put', '/settings').send({ historyEnabled: true, disabledRules: ['R99'] })).status,
    ).toBe(400);
  });

  it('switching a rule off makes live analysis report it as not evaluated', async () => {
    const { api, analyze } = await setup();
    await api('put', '/settings').send({ historyEnabled: false, disabledRules: ['R9'] });
    const result = AnalysisResult.parse((await analyze(legit.raw)).body);
    const rules = result.stages.find((s) => s.stage === 'rules')!;
    expect(rules.outputs.notEvaluated).toContain('R9');
  });
});

describe('key history', () => {
  it('is not recorded and R8 is not evaluated while history is off', async () => {
    const { api, analyze } = await setup();
    const result = AnalysisResult.parse((await analyze(legit.raw)).body);
    expect(result.stages.find((s) => s.stage === 'rules')!.outputs.notEvaluated).toContain('R8');
    expect(KeyHistoryList.parse((await api('get', '/key-history')).body).observations).toEqual([]);
  });

  it('records the verified key once enabled; the second message is a known key', async () => {
    const { api, analyze } = await setup();
    await api('put', '/settings').send({ historyEnabled: true, disabledRules: [] });
    const first = AnalysisResult.parse((await analyze(legit.raw)).body);
    expect(first.findings.map((f) => f.id)).toContain('R8:first_contact:1');
    const list = KeyHistoryList.parse((await api('get', '/key-history')).body).observations;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ status: 'current', domain: 'acme.example' });

    const second = AnalysisResult.parse((await analyze(legit.raw)).body);
    expect(second.findings.map((f) => f.ruleId)).not.toContain('R8');
    expect(KeyHistoryList.parse((await api('get', '/key-history')).body).observations).toHaveLength(
      1,
    );
  });

  it('classifies rotation and an unexpected change, and honours a revoked key', async () => {
    const { history, api } = await setup();
    history.record('acme.example', 's1', 'aa');
    history.record('acme.example', 's2', 'bb');
    history.record('acme.example', 's2', 'cc');
    const byKey = Object.fromEntries(history.list().map((o) => [o.fingerprint, o.status]));
    expect(byKey).toEqual({ aa: 'rotated', bb: 'current', cc: 'unexpected' });

    const id = history.list().find((o) => o.fingerprint === 'bb')!.id;
    await api('post', `/key-history/${id}/revoke`).expect(200);
    expect(history.list().find((o) => o.id === id)!.status).toBe('revoked');
    await api('post', '/key-history/00000000-0000-4000-8000-000000000000/revoke').expect(404);
  });

  it('deletes all history on request', async () => {
    const { history, api } = await setup();
    history.record('acme.example', 's1', 'aa');
    expect((await api('delete', '/key-history')).body).toEqual({ deleted: 1 });
    expect(history.list()).toEqual([]);
  });
});

describe('key preview and session revocation', () => {
  it('previews a certificate without storing it, and refuses a private key', async () => {
    const { api } = await setup();
    const pem = readFileSync(
      new URL('../../../fixtures/smime/lab-alice.crt', import.meta.url),
      'utf8',
    );
    const preview = KeyPreview.parse((await api('post', '/keys/preview').send({ pem })).body);
    expect(preview).toMatchObject({
      material: 'certificate',
      email: 'alice@acme.example',
      alreadyEnrolledFor: null,
    });
    expect(preview.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    const key = readFileSync(
      new URL('../../../fixtures/keys/TEST-ONLY-lab-alice.pem', import.meta.url),
      'utf8',
    );
    const refused = await api('post', '/keys/preview').send({ pem: key });
    expect(refused.status).toBe(422);
    expect(refused.body.type).toBe('private_key_rejected');
  });

  it('revokes every session, so the old token no longer works', async () => {
    const { api } = await setup();
    await api('post', '/session/revoke').expect(204);
    await api('get', '/settings').expect(401);
  });
});

describe('invariant: the lab CA is never trusted in live mode', () => {
  it('reports chain trust as not checked and gives no personal corroboration', async () => {
    const { analyze } = await setup();
    const lab = await runPersonalScenario({
      signer: 'alice',
      aliceKeyEnrolled: true,
      mutations: [],
    });
    expect(LabPersonalResponse.safeParse(lab).success).toBe(true);
    const live = AnalysisResult.parse((await analyze(Buffer.from(lab.rawMessage))).body);
    expect(live.inputSource).toBe('eml_upload');
    expect(live.personalSignature).toMatchObject({ signatureValid: true, chainTrusted: null });
    expect(live.identityStatus).not.toBe('corroborated_personal');
  });

  it('serves the personal lab only through its strict, allowlisted route', async () => {
    const { api } = await setup();
    const ok = await api('post', '/lab/personal').send({
      signer: 'eve',
      aliceKeyEnrolled: true,
      mutations: [],
    });
    expect(LabPersonalResponse.parse(ok.body).result.personalSignature?.chainTrusted).toBe(true);
    const bad = await api('post', '/lab/personal').send({
      signer: 'mallory',
      aliceKeyEnrolled: true,
      mutations: [],
    });
    expect(bad.status).toBe(400);
  });
});
