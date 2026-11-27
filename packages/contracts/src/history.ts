import { z } from 'zod';

/** Key history and settings (docs/architecture.md §5.3). */
export const KeyObservationStatus = z.enum(['current', 'rotated', 'unexpected', 'revoked']);
export type KeyObservationStatus = z.infer<typeof KeyObservationStatus>;

export const KeyObservation = z.object({
  id: z.string(),
  domain: z.string(),
  selector: z.string(),
  /** hex(SHA-256(DER SubjectPublicKeyInfo)) */
  fingerprint: z.string(),
  firstSeen: z.iso.datetime(),
  lastSeen: z.iso.datetime(),
  status: KeyObservationStatus,
});
export type KeyObservation = z.infer<typeof KeyObservation>;

export const KeyHistoryList = z.object({ observations: z.array(KeyObservation) });
export type KeyHistoryList = z.infer<typeof KeyHistoryList>;

export const RULE_NAMES = ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9'] as const;

/** What the user can change. History retention is off by default. */
export const SettingsInput = z.strictObject({
  historyEnabled: z.boolean(),
  /** Rules switched off for live analysis. */
  disabledRules: z.array(z.enum(RULE_NAMES)).max(RULE_NAMES.length),
});
export type SettingsInput = z.infer<typeof SettingsInput>;

export const Settings = SettingsInput.extend({
  /** Read-only: these come from the service's environment. */
  dns: z.object({ servers: z.array(z.string()).nullable(), timeoutMs: z.number() }),
});
export type Settings = z.infer<typeof Settings>;

/** What a pasted certificate or public key contains. Nothing is stored by the preview. */
export const KeyPreview = z.object({
  material: z.enum(['certificate', 'public_key']),
  keyType: z.string(),
  fingerprint: z.string(),
  expiresAt: z.string().nullable(),
  /** Certificates only. */
  subject: z.string().nullable(),
  email: z.string().nullable(),
  issuer: z.string().nullable(),
  /** Set when the key is already enrolled for someone. */
  alreadyEnrolledFor: z.string().nullable(),
});
export type KeyPreview = z.infer<typeof KeyPreview>;

export const KeyPreviewRequest = z.strictObject({ pem: z.string().min(1).max(20_000) });
export type KeyPreviewRequest = z.infer<typeof KeyPreviewRequest>;
