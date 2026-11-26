import { AnalysisResult, FixtureList, PairResponse, Problem } from '@mailshield/contracts';
import type { z } from 'zod';

const TOKEN_KEY = 'mailshield.token';

export const session = {
  get(): string | null {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set(token: string | null): void {
    try {
      if (token) sessionStorage.setItem(TOKEN_KEY, token);
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      // Storage blocked: the user pairs again after a reload.
    }
  },
};

export class ApiError extends Error {
  readonly type: string;

  constructor(type: string, message: string) {
    super(message);
    this.type = type;
  }
}

async function request<T>(schema: z.ZodType<T>, path: string, init: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, init);
  } catch {
    throw new ApiError('unavailable', 'The local service is not reachable.');
  }
  const body: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const problem = Problem.safeParse(body);
    if (problem.success) throw new ApiError(problem.data.type, problem.data.title);
    throw new ApiError('unavailable', `The local service is not reachable (HTTP ${res.status}).`);
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new ApiError('invalid_response', 'The service sent an unexpected response.');
  }
  return parsed.data;
}

export function createClient(token: string) {
  const auth = { Authorization: `Bearer ${token}` };
  return {
    analyzeFile: (file: Blob) =>
      request(AnalysisResult, '/analyze', {
        method: 'POST',
        headers: { ...auth, 'Content-Type': 'application/octet-stream' },
        body: file,
      }),
    analyzeHeaders: (text: string) =>
      request(AnalysisResult, '/analyze/headers', {
        method: 'POST',
        headers: { ...auth, 'Content-Type': 'text/plain' },
        body: text,
      }),
    fixtures: () => request(FixtureList, '/fixtures', { headers: auth }),
    runDemo: (id: string) =>
      request(AnalysisResult, `/lab/demo/${encodeURIComponent(id)}`, {
        method: 'POST',
        headers: auth,
      }),
  };
}

export type Client = ReturnType<typeof createClient>;

export const pair = (code: string) =>
  request(PairResponse, '/pair', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
