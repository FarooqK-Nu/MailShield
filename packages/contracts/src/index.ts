import { z } from 'zod';

/** Shared vocabulary (docs/context.md §5). Full AnalysisResult schemas arrive in Phase 1. */
export const EvidenceSource = z.enum([
  'local_crypto',
  'trusted_receiver',
  'untrusted_header',
  'registry',
  'heuristic',
  'lab',
]);
export type EvidenceSource = z.infer<typeof EvidenceSource>;

export const EvidenceStatus = z.enum([
  'pass',
  'fail',
  'missing',
  'unknown',
  'temporary_error',
  'unsupported',
  'untrusted',
  'not_evaluated',
]);
export type EvidenceStatus = z.infer<typeof EvidenceStatus>;

export const HealthResponse = z.object({ status: z.literal('ok'), version: z.string() });
export type HealthResponse = z.infer<typeof HealthResponse>;
