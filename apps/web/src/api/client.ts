import {
  AnalysisResult,
  AuditList,
  FixtureList,
  Identity,
  IdentityList,
  ImportResult,
  PairResponse,
  Problem,
  PublicKeyRecord,
  RegistryFile,
  type IdentityInput,
  type IdentityKind,
  type IdentityPatch,
  type KeyEnrollRequest,
  type TrustState,
} from '@mailshield/contracts';
import { z } from 'zod';

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
  const body: unknown = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    const problem = Problem.safeParse(body);
    if (problem.success) {
      throw new ApiError(problem.data.type, problem.data.detail ?? problem.data.title);
    }
    throw new ApiError('unavailable', `The local service is not reachable (HTTP ${res.status}).`);
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new ApiError('invalid_response', 'The service sent an unexpected response.');
  }
  return parsed.data;
}

export interface IdentityFilter {
  q?: string;
  kind?: IdentityKind;
  trustState?: TrustState;
}

export function createClient(token: string) {
  const auth = { Authorization: `Bearer ${token}` };
  const sendJson = (method: string, body: unknown): RequestInit => ({
    method,
    headers: { ...auth, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const id = (value: string) => encodeURIComponent(value);
  return {
    identities: (filter: IdentityFilter = {}) => {
      const query = new URLSearchParams(
        Object.entries(filter).filter((e): e is [string, string] => !!e[1]),
      );
      return request(IdentityList, `/identities?${query}`, { headers: auth });
    },
    createIdentity: (input: IdentityInput) =>
      request(Identity, '/identities', sendJson('POST', input)),
    updateIdentity: (identityId: string, patch: IdentityPatch) =>
      request(Identity, `/identities/${id(identityId)}`, sendJson('PATCH', patch)),
    deleteIdentity: (identityId: string) =>
      request(z.null(), `/identities/${id(identityId)}`, { method: 'DELETE', headers: auth }),
    addKey: (identityId: string, key: KeyEnrollRequest) =>
      request(PublicKeyRecord, `/identities/${id(identityId)}/keys`, sendJson('POST', key)),
    audit: (identityId?: string) =>
      request(AuditList, identityId ? `/identities/${id(identityId)}/audit` : '/audit', {
        headers: auth,
      }),
    exportRegistry: () => request(RegistryFile, '/registry/export', { headers: auth }),
    importRegistry: (file: unknown) =>
      request(ImportResult, '/registry/import', sendJson('POST', file)),
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
