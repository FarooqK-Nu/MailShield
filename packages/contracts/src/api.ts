import { z } from 'zod';

/** Largest message the service accepts (docs/context.md §8, invariant 11). */
export const MAX_MESSAGE_BYTES = 10 * 1024 * 1024;

export const HealthResponse = z.object({ status: z.literal('ok'), version: z.string() });
export type HealthResponse = z.infer<typeof HealthResponse>;

export const PairRequest = z.strictObject({ code: z.string().regex(/^\d{8}$/) });
export type PairRequest = z.infer<typeof PairRequest>;

export const PairResponse = z.object({ token: z.string().min(32) });
export type PairResponse = z.infer<typeof PairResponse>;

export const FixtureSummary = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
});
export type FixtureSummary = z.infer<typeof FixtureSummary>;

export const FixtureList = z.object({ fixtures: z.array(FixtureSummary) });
export type FixtureList = z.infer<typeof FixtureList>;

export const ProblemType = z.enum([
  'malformed_message',
  'input_too_large',
  'mime_limits_exceeded',
  'dns_timeout',
  'unsupported_crypto',
  'unauthorized',
  'origin_rejected',
  'host_rejected',
  'pairing_failed',
  'invalid_request',
  'rate_limited',
  'not_found',
  'internal_error',
]);
export type ProblemType = z.infer<typeof ProblemType>;

/** Body of every `application/problem+json` response. */
export const Problem = z.object({ type: ProblemType, status: z.number(), title: z.string() });
export type Problem = z.infer<typeof Problem>;
