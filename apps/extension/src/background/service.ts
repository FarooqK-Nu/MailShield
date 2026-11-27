import { AnalysisResult, PairResponse, Problem } from '@mailshield/contracts';
import { z } from 'zod';
import { ExtensionError } from './gmail.ts';

export interface ServiceDeps {
  fetch: typeof fetch;
  /** Origin of the local verification service, for example http://127.0.0.1:8787. */
  baseUrl: string;
  /** The pairing session token for the local service. Never a Gmail token. */
  sessionToken: () => Promise<string | null>;
}

export interface AnalyzeOptions {
  source: 'gmail_api' | 'eml_upload';
  /** The Gmail message id the bytes belong to, echoed back for stale-result checks. */
  messageRef?: string;
}

/**
 * Client for the local verification service (docs/architecture.md §5.1). It sends message bytes
 * and the pairing token only. It has no parameter through which a Gmail token could be passed.
 */
export function createServiceClient({ fetch, baseUrl, sessionToken }: ServiceDeps) {
  async function call<T>(schema: z.ZodType<T>, path: string, init: RequestInit): Promise<T> {
    let res: Response;
    try {
      res = await fetch(`${baseUrl}/api/v1${path}`, init);
    } catch {
      throw new ExtensionError(
        'service_unavailable',
        'The local MailShield service is not reachable. Start it with npm run dev.',
      );
    }
    const body: unknown = await res.json().catch(() => null);
    if (!res.ok) {
      const problem = Problem.safeParse(body);
      if (problem.success) {
        throw new ExtensionError(problem.data.type, problem.data.detail ?? problem.data.title);
      }
      throw new ExtensionError(
        'service_unavailable',
        `The local service returned HTTP ${res.status}.`,
      );
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      throw new ExtensionError(
        'invalid_response',
        'The local service sent an unexpected response.',
      );
    }
    return parsed.data;
  }

  async function authorization(): Promise<Record<string, string>> {
    const token = await sessionToken();
    if (!token)
      throw new ExtensionError('unauthorized', 'Pair the extension with the local service first.');
    return { Authorization: `Bearer ${token}` };
  }

  return {
    health: () =>
      call(z.object({ status: z.literal('ok') }), '/health', { method: 'GET' }).then(() => true),

    pair: (code: string) =>
      call(PairResponse, '/pair', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      }),

    async analyze(bytes: Uint8Array, options: AnalyzeOptions): Promise<AnalysisResult> {
      const headers: Record<string, string> = {
        ...(await authorization()),
        'Content-Type': 'application/octet-stream',
        'X-MailShield-Source': options.source,
      };
      if (options.messageRef) headers['X-MailShield-Message-Ref'] = options.messageRef;
      return call(AnalysisResult, '/analyze', {
        method: 'POST',
        headers,
        body: bytes as Uint8Array<ArrayBuffer>,
      });
    },
  };
}

export type ServiceClient = ReturnType<typeof createServiceClient>;
