import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { AnalysisResult } from '@mailshield/contracts';
import { analyze, type DnsResolver } from '@mailshield/engine';

export const ROOT = resolve(import.meta.dirname, '../../..');
export const GMAIL_FIXTURE = readFileSync(resolve(ROOT, 'fixtures/gmail/genuine-pass.eml'));

const noDns: DnsResolver = { txt: async () => ({ status: 'nxdomain', records: [] }) };

/** A real engine result for the synthetic Gmail fixture, as the service would return it. */
export async function realResult(messageRef: string): Promise<AnalysisResult> {
  const result = await analyze(
    { raw: GMAIL_FIXTURE, source: 'gmail_api', messageRef },
    { resolver: noDns, clock: () => new Date('2026-11-27T17:00:00Z') },
  );
  return JSON.parse(JSON.stringify(result)) as AnalysisResult;
}

/** Gmail's base64url encoding of raw bytes. */
export const base64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

export interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: Uint8Array | string | null;
}

type Route = (req: Recorded) => Response | Promise<Response>;

/** A fetch that records every request and answers from the first matching route. */
export function fakeFetch(routes: [prefix: string, route: Route][]) {
  const requests: Recorded[] = [];
  const fetch = async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    const headers = Object.fromEntries(
      Object.entries((init.headers ?? {}) as Record<string, string>).map(([k, v]) => [
        k.toLowerCase(),
        v,
      ]),
    );
    const body =
      init.body instanceof Uint8Array || typeof init.body === 'string' ? init.body : null;
    const req: Recorded = { url, method: init.method ?? 'GET', headers, body };
    requests.push(req);
    const match = routes.find(([prefix]) => url.startsWith(prefix));
    if (!match) throw new TypeError(`unexpected request to ${url}`);
    return match[1](req);
  };
  return { fetch: fetch as typeof globalThis.fetch, requests };
}

export const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
