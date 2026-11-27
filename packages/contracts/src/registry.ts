import { z } from 'zod';

/** Trusted identity registry (docs/context.md §5, docs/architecture.md §5.3). */
export const TrustState = z.enum([
  'unverified',
  'user_trusted',
  'independently_verified',
  'revoked',
]);
export type TrustState = z.infer<typeof TrustState>;

export const IdentityKind = z.enum(['organization', 'person']);
export type IdentityKind = z.infer<typeof IdentityKind>;

export const DomainRelationship = z.enum(['own', 'service_provider']);
export type DomainRelationship = z.infer<typeof DomainRelationship>;

const Text = (max: number) => z.string().trim().min(1).max(max);

/** A domain written by the user. The service stores its ASCII (Punycode) form. */
export const ApprovedDomainInput = z.strictObject({
  domain: Text(253),
  includeSubdomains: z.boolean().default(false),
  relationship: DomainRelationship.default('own'),
});
export type ApprovedDomainInput = z.input<typeof ApprovedDomainInput>;

export const ApprovedDomain = z.object({
  id: z.string(),
  domainAscii: z.string(),
  domainUnicode: z.string(),
  includeSubdomains: z.boolean(),
  relationship: DomainRelationship,
});
export type ApprovedDomain = z.infer<typeof ApprovedDomain>;

export const IdentityAlias = z.object({ id: z.string(), alias: z.string() });
export type IdentityAlias = z.infer<typeof IdentityAlias>;

export const TrustedAddress = z.object({ id: z.string(), address: z.string() });
export type TrustedAddress = z.infer<typeof TrustedAddress>;

export const KeyStatus = z.enum(['active', 'retired', 'revoked']);
export type KeyStatus = z.infer<typeof KeyStatus>;

export const PublicKeyRecord = z.object({
  id: z.string(),
  keyType: z.string(),
  /** hex(SHA-256(DER SubjectPublicKeyInfo)) */
  fingerprintSha256: z.string(),
  trustSource: z.string(),
  status: KeyStatus,
  enrolledAt: z.iso.datetime(),
  expiresAt: z.iso.datetime().nullable(),
});
export type PublicKeyRecord = z.infer<typeof PublicKeyRecord>;

export const Identity = z.object({
  id: z.string(),
  kind: IdentityKind,
  displayName: z.string(),
  trustState: TrustState,
  /** Where the registry facts came from, e.g. the organization's official page. */
  provenanceUrl: z.string().nullable(),
  notes: z.string().nullable(),
  lastReviewed: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
  deletedAt: z.iso.datetime().nullable(),
  aliases: z.array(IdentityAlias),
  domains: z.array(ApprovedDomain),
  addresses: z.array(TrustedAddress),
  keys: z.array(PublicKeyRecord),
});
export type Identity = z.infer<typeof Identity>;

export const IdentityInput = z.strictObject({
  kind: IdentityKind,
  displayName: Text(200),
  trustState: TrustState.default('unverified'),
  provenanceUrl: z
    .url({ protocol: /^https?$/ })
    .max(2000)
    .nullable()
    .default(null),
  notes: z.string().max(4000).nullable().default(null),
  lastReviewed: z.iso.datetime().nullable().default(null),
  aliases: z.array(Text(200)).max(50).default([]),
  domains: z.array(ApprovedDomainInput).max(50).default([]),
  addresses: z.array(z.email().max(320)).max(50).default([]),
});
export type IdentityInput = z.input<typeof IdentityInput>;

/**
 * Fields left out are unchanged; lists given replace the stored list. Written out without
 * defaults, because `IdentityInput.partial()` would still fill them in and reset fields.
 */
export const IdentityPatch = z.strictObject({
  displayName: Text(200).optional(),
  trustState: TrustState.optional(),
  provenanceUrl: z
    .url({ protocol: /^https?$/ })
    .max(2000)
    .nullable()
    .optional(),
  notes: z.string().max(4000).nullable().optional(),
  lastReviewed: z.iso.datetime().nullable().optional(),
  aliases: z.array(Text(200)).max(50).optional(),
  domains: z.array(ApprovedDomainInput).max(50).optional(),
  addresses: z.array(z.email().max(320)).max(50).optional(),
});
export type IdentityPatch = z.input<typeof IdentityPatch>;

export const IdentityList = z.object({ identities: z.array(Identity) });
export type IdentityList = z.infer<typeof IdentityList>;

/** Public material only. Anything containing a private key block is rejected. */
export const KeyEnrollRequest = z.strictObject({
  pem: z.string().min(1).max(20_000),
  trustSource: Text(500),
  expiresAt: z.iso.datetime().nullable().default(null),
});
export type KeyEnrollRequest = z.input<typeof KeyEnrollRequest>;

export const AuditAction = z.enum(['create', 'update', 'delete', 'key_added', 'import']);
export type AuditAction = z.infer<typeof AuditAction>;

export const AuditEvent = z.object({
  id: z.string(),
  at: z.iso.datetime(),
  actor: z.string(),
  entityType: z.enum(['identity', 'registry', 'settings']),
  entityId: z.string(),
  action: AuditAction,
  before: z.unknown().nullable(),
  after: z.unknown().nullable(),
});
export type AuditEvent = z.infer<typeof AuditEvent>;

export const AuditList = z.object({ events: z.array(AuditEvent) });
export type AuditList = z.infer<typeof AuditList>;

/** Registry import/export file. Keys are not included; enroll them again from their PEM. */
export const RegistryFile = z.strictObject({
  format: z.literal('mailshield-registry'),
  version: z.literal(1),
  exportedAt: z.iso.datetime(),
  identities: z.array(IdentityInput).max(1000),
});
export type RegistryFile = z.input<typeof RegistryFile>;

export const ImportResult = z.object({ imported: z.number(), skipped: z.array(z.string()) });
export type ImportResult = z.infer<typeof ImportResult>;
