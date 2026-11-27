import { describe, expect, it } from 'vitest';
import { analyze, AnalysisError, LIMITS, type DnsResolver } from '../src/index.ts';

/** Hardening (roadmap Phase 7): hostile input must end quickly in a result or a clean error. */
const resolver: DnsResolver = { txt: async () => ({ status: 'nxdomain', records: [] }) };
const clock = () => new Date('2026-06-01T12:00:00Z');

/** Small seeded generator, so a failure is reproducible. */
function rng(seed: number) {
  let s = seed;
  return () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
}

async function run(raw: Buffer | string, headerOnly = false) {
  const started = performance.now();
  try {
    const result = await analyze(
      { raw: Buffer.from(raw), source: 'eml_upload', headerOnly },
      { resolver, clock },
    );
    expect([
      'possible_impersonation',
      'authentication_concern',
      'identity_unverified',
      'no_concerning_mismatch',
    ]).toContain(result.verdict);
  } catch (error) {
    // Only the engine's own typed failure is acceptable; anything else is a crash.
    expect(error).toBeInstanceOf(AnalysisError);
  }
  return performance.now() - started;
}

const base = 'From: a@acme.example\r\nTo: b@example.org\r\nSubject: x\r\n';

describe('parser fuzzing', () => {
  it('survives random byte noise', async () => {
    const next = rng(1);
    for (let i = 0; i < 40; i++) {
      const bytes = Buffer.alloc(1 + Math.floor(next() * 4000));
      for (let j = 0; j < bytes.length; j++) bytes[j] = Math.floor(next() * 256);
      expect(await run(bytes)).toBeLessThan(3000);
    }
  });

  it('survives mutated, otherwise valid messages', async () => {
    const next = rng(2);
    const seed = `${base}MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n`;
    for (let i = 0; i < 60; i++) {
      const bytes = Buffer.from(seed);
      for (let k = 0; k < 6; k++)
        bytes[Math.floor(next() * bytes.length)] = Math.floor(next() * 256);
      expect(await run(bytes)).toBeLessThan(3000);
    }
  });

  it('bounds MIME nesting deeper than the limit', async () => {
    let body = 'hello\r\n';
    for (let i = 0; i < LIMITS.mimeDepth + 30; i++) {
      body = `Content-Type: multipart/mixed; boundary="b${i}"\r\n\r\n--b${i}\r\n${body}--b${i}--\r\n`;
    }
    expect(await run(`${base}MIME-Version: 1.0\r\n${body}`)).toBeLessThan(3000);
  });

  it('bounds the number of MIME parts', async () => {
    const parts = Array.from(
      { length: LIMITS.mimeParts + 200 },
      () => '--b\r\nContent-Type: text/plain\r\n\r\nx\r\n',
    ).join('');
    const raw = `${base}MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n${parts}--b--\r\n`;
    expect(await run(raw)).toBeLessThan(5000);
  });

  it('bounds very large and very many headers', async () => {
    expect(
      await run(`${base}X-Big: ${'a'.repeat(LIMITS.headerBytes * 2)}\r\n\r\nbody`),
    ).toBeLessThan(3000);
    const many = Array.from({ length: LIMITS.headerFields * 3 }, (_, i) => `X-H${i}: v`).join(
      '\r\n',
    );
    expect(await run(`${base}${many}\r\n\r\nbody`)).toBeLessThan(3000);
  });

  it('bounds a header with a long folded value and unterminated quotes', async () => {
    const folded = `Subject: ${'word \r\n '.repeat(5000)}`;
    expect(
      await run(`From: "${'x'.repeat(20000)} <a@b.example\r\n${folded}\r\n\r\nbody`),
    ).toBeLessThan(3000);
  });

  it('refuses an oversized message with the typed error', async () => {
    await expect(
      analyze(
        { raw: Buffer.alloc(LIMITS.messageBytes + 1, 97), source: 'eml_upload' },
        { resolver, clock },
      ),
    ).rejects.toBeInstanceOf(AnalysisError);
  });

  it('rejects a DKIM signature with hostile tag values without crashing', async () => {
    const sig = `DKIM-Signature: v=1; a=rsa-sha256; d=${'a'.repeat(300)}.example; s=../../x; h=from; bh=!!!; b=@@@; l=99999999999999999999\r\n`;
    expect(await run(`${sig}${base}\r\nbody`)).toBeLessThan(3000);
  });
});
