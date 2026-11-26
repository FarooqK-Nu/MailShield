import { z } from 'zod';
import {
  EvidenceSource,
  EvidenceStatus,
  IdentityStatus,
  InputSource,
  RiskLevel,
  Verdict,
} from './vocabulary.ts';
import { DomainRelationship, IdentityKind, TrustState } from './registry.ts';

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

export const CodePoint = z.object({
  char: z.string(),
  codePoint: z.string(),
  script: z.string(),
  looksLike: z.string().nullable(),
});
export type CodePoint = z.infer<typeof CodePoint>;

/** One domain from the message, split at its public-suffix boundary (domain inspector). */
export const DomainInspection = z.object({
  /** Which header the domain came from. */
  role: z.enum(['from', 'sender', 'reply_to', 'return_path', 'dkim']),
  ascii: z.string(),
  unicode: z.string(),
  registrable: z.string().nullable(),
  registrableUnicode: z.string().nullable(),
  subdomain: z.string(),
  publicSuffix: z.string().nullable(),
  isIdn: z.boolean(),
  scripts: z.array(z.string()),
  mixedScript: z.boolean(),
  /** Code points of the registrable label, Unicode form. */
  codePoints: z.array(CodePoint),
});
export type DomainInspection = z.infer<typeof DomainInspection>;

export const CharDiff = z.object({
  index: z.number(),
  kind: z.enum(['substituted', 'inserted', 'removed', 'swapped']),
  observed: z.string(),
  expected: z.string(),
  observedCodePoints: z.array(z.string()),
});
export type CharDiff = z.infer<typeof CharDiff>;

export const MatchReason = z.enum([
  'trusted_address',
  'approved_domain',
  'display_name',
  'alias',
  'name_contains',
  'lookalike_name',
  'lookalike_domain',
  'brand_in_subdomain',
  'brand_token',
]);
export type MatchReason = z.infer<typeof MatchReason>;

export const DomainLookalike = z.object({
  observed: z.string(),
  approved: z.string(),
  strength: z.enum(['strong', 'weak']),
  reasons: z.array(z.string()),
  distance: z.number(),
  matchedToken: z.string().nullable(),
  diff: z.array(CharDiff),
});
export type DomainLookalike = z.infer<typeof DomainLookalike>;

/** A registry identity the message may be claiming to be, with the reasons why. */
export const IdentityCandidate = z.object({
  identityId: z.string(),
  displayName: z.string(),
  kind: IdentityKind,
  trustState: TrustState,
  score: z.number(),
  reasons: z.array(MatchReason),
  /** Approved domain the From domain falls under, when it does. */
  approvedDomain: z.object({ domain: z.string(), relationship: DomainRelationship }).nullable(),
  lookalikes: z.array(DomainLookalike),
  explanation: z.array(z.string()),
});
export type IdentityCandidate = z.infer<typeof IdentityCandidate>;

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
  domains: z.array(DomainInspection),
  /** Best registry matches, strongest first; empty when nothing in the registry matches. */
  candidates: z.array(IdentityCandidate),
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
