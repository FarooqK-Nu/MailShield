import { z } from 'zod';

/** Shared vocabulary (docs/context.md §5). */
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

export const InputSource = z.enum(['gmail_api', 'eml_upload', 'header_paste', 'lab', 'fixture']);
export type InputSource = z.infer<typeof InputSource>;

export const IdentityStatus = z.enum([
  'corroborated_domain',
  'corroborated_personal',
  'mismatch',
  'unverified',
  'ambiguous',
]);
export type IdentityStatus = z.infer<typeof IdentityStatus>;

export const RiskLevel = z.enum(['high', 'caution', 'unknown', 'low']);
export type RiskLevel = z.infer<typeof RiskLevel>;

export const Verdict = z.enum([
  'possible_impersonation',
  'authentication_concern',
  'identity_unverified',
  'no_concerning_mismatch',
]);
export type Verdict = z.infer<typeof Verdict>;
