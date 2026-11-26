import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { buildApp } from '../src/app.ts';

const app = buildApp({ port: 8787 });

describe('local service', () => {
  it('answers health on an allowed Host', async () => {
    const res = await request(app).get('/api/v1/health').set('Host', '127.0.0.1:8787');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok', version: '0.0.0' });
  });

  it.each(['evil.example', '127.0.0.1', 'localhost:9999', '127.0.0.1.evil.example:8787'])(
    'rejects Host %s',
    async (host) => {
      const res = await request(app).get('/api/v1/health').set('Host', host);
      expect(res.status).toBe(403);
    },
  );
});
