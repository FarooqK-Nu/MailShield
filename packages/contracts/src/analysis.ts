import { z } from 'zod';
import {
  EvidenceSource,
  EvidenceStatus,
  IdentityStatus,
  InputSource,
  RiskLevel,
  Verdict,
} from './vocabulary.ts';

const Details = z.record(z.string(), z.unknown());

export const Evidence = z.object({
  id: z.string(),
  kind: z.enum(['dkim', 'spf', 'dmarc', 'arc', 'smime', 'registry', 'domain', 'link', 'receiver']),
  source: EvidenceSource,
  status: EvidenceStatus,
  domains: z.array(z.string()),
  coverage: Details.optional(),
  reason: z.string(),
  observedAt: z.iso.datetime(),
  details: Details,
});
export type Evidence = z.infer<typeof Evidence>;

export const FailureStage = z.enum([
  'dns',
  'key_parse',
  'body_hash',
  'header_signature',
  'expired',
  'policy',
]);
export type FailureStage = z.infer<typeof FailureStage>;

export const SignatureEvidence = z.object({
  /** Matches the id of the corresponding Evidence record. */
  evidenceId: z.string(),
  source: EvidenceSource,
  status: EvidenceStatus,
  failureStage: FailureStage.nullable(),
  reason: z.string(),
  domain: z.string().nullable(),
  selector: z.string().nullable(),
  algorithm: z.string().nullable(),
  canonicalization: z.string().nullable(),
  /** Tags exactly as written in the DKIM-Signature header, for display. */
  tags: z.record(z.string(), z.string()),
  bodyHash: z.object({
    expected: z.string().nullable(),
    computed: z.string().nullable(),
    matches: z.boolean().nullable(),
  }),
  signedHeaders: z.array(z.string()),
  /** Important headers present in the message that this signature does not cover. */
  unsignedHeaders: z.array(z.string()),
  /** Set only when the signature limits the signed body length (l=). */
  bodyCoverage: z
    .object({ signedBytes: z.number(), unsignedBytes: z.number().nullable() })
    .nullable(),
  key: z
    .object({
      type: z.string(),
      bits: z.number().nullable(),
      /** hex(SHA-256(DER SubjectPublicKeyInfo)) */
      fingerprint: z.string(),
      testing: z.boolean(),
    })
    .nullable(),
  signedAt: z.string().nullable(),
  expiresAt: z.string().nullable(),
  warnings: z.array(z.string()),
});
export type SignatureEvidence = z.infer<typeof SignatureEvidence>;

export const Mailbox = z.object({
  displayName: z.string(),
  address: z.string(),
  /** ASCII (Punycode) form; empty when the address has no usable domain. */
  domain: z.string(),
  domainUnicode: z.string(),
});
export type Mailbox = z.infer<typeof Mailbox>;

export const SenderView = z.object({
  from: z.array(Mailbox),
  /** True for zero or several From headers or mailboxes. */
  fromAmbiguous: z.boolean(),
  sender: z.array(Mailbox),
  replyTo: z.array(Mailbox),
  returnPath: z.array(Mailbox),
  subject: z.string().nullable(),
  date: z.string().nullable(),
  messageId: z.string().nullable(),
});
export type SenderView = z.infer<typeof SenderView>;

export const ClaimedIdentity = z.object({ displayName: z.string(), address: z.string() });
export type ClaimedIdentity = z.infer<typeof ClaimedIdentity>;

export const Finding = z.object({
  ruleId: z.string(),
  ruleVersion: z.string(),
  severity: z.enum(['high', 'caution', 'info', 'low']),
  title: z.string(),
  observed: z.string(),
  expected: z.string().optional(),
  evidenceRefs: z.array(z.string()),
  explanation: z.string(),
  recommendation: z.string(),
});
export type Finding = z.infer<typeof Finding>;

export const StageName = z.enum([
  'intake',
  'parse',
  'dns',
  'dkim',
  'receiver',
  'alignment',
  'smime',
  'identity',
  'registry',
  'rules',
  'verdict',
]);
export type StageName = z.infer<typeof StageName>;

export const StageStatus = z.enum([
  'pending',
  'running',
  'pass',
  'fail',
  'warn',
  'skipped',
  'not_evaluated',
  'error',
]);
export type StageStatus = z.infer<typeof StageStatus>;

export const StageEvent = z.object({
  stage: StageName,
  status: StageStatus,
  startedAt: z.iso.datetime(),
  durationMs: z.number().optional(),
  /** Summaries only, never message bodies. */
  inputs: Details,
  outputs: Details,
  limitations: z.array(z.string()),
  /** True only when the stage ran on lab-provided inputs. */
  simulated: z.boolean(),
});
export type StageEvent = z.infer<typeof StageEvent>;

export const AnalysisResult = z.object({
  analysisId: z.uuid(),
  schemaVersion: z.literal('1'),
  inputSource: InputSource,
  messageRef: z.string().optional(),
  sender: SenderView,
  claimedIdentity: ClaimedIdentity.nullable(),
  authentication: z.array(Evidence),
  signatures: z.array(SignatureEvidence),
  findings: z.array(Finding),
  stages: z.array(StageEvent),
  verdict: Verdict,
  identityStatus: IdentityStatus,
  riskLevel: RiskLevel,
  limitations: z.array(z.string()),
  analyzedAt: z.iso.datetime(),
});
export type AnalysisResult = z.infer<typeof AnalysisResult>;
