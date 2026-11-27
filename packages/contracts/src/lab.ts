import { z } from 'zod';
import { AnalysisResult } from './analysis.ts';

export const LAB_PRESETS = ['legitimate', 'lookalike'] as const;
export const LAB_SIGNERS = ['acme', 'eve', 'none'] as const;
export const LAB_SELECTORS = ['s2025', 's2026'] as const;
export const LAB_MUTATIONS = [
  'editBody',
  'changeSignedSubject',
  'alterUnsignedHeader',
  'removeSignature',
  'swapKey',
  'rotateSelector',
  'dnsMissing',
  'dnsTimeout',
] as const;
export const LAB_RULES = ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9'] as const;

/** One header-field value: no line breaks, so a field can never inject another header. */
const field = (max: number) =>
  z
    .string()
    .max(max)
    .regex(/^[^\r\n\0<>"]*$/);
const address = z
  .string()
  .max(120)
  .regex(/^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$/);

/** Everything the scenario builder can change. The server validates it strictly. */
export const LabScenario = z.strictObject({
  preset: z.enum(LAB_PRESETS),
  message: z.strictObject({
    displayName: field(80),
    from: address,
    /** Empty string means no Reply-To header. */
    replyTo: z.union([z.literal(''), address]),
    subject: field(120),
    body: z
      .string()
      .max(2000)
      .regex(/^[^\0]*$/),
  }),
  signer: z.enum(LAB_SIGNERS),
  selector: z.enum(LAB_SELECTORS),
  mutations: z.array(z.enum(LAB_MUTATIONS)).max(LAB_MUTATIONS.length),
  /** Rules switched off; their stage reports `not_evaluated`. */
  disabledRules: z.array(z.enum(LAB_RULES)).max(LAB_RULES.length),
});
export type LabScenario = z.infer<typeof LabScenario>;

export const LabRunResponse = z.object({
  result: AnalysisResult,
  /** The same scenario with no mutations, for the hash and key comparison. */
  baseline: AnalysisResult,
  /** What each applied mutation did to the bytes, in plain words. */
  notes: z.array(z.string()),
  /** The message as the lab produced it, with signature, for display. */
  rawMessage: z.string(),
});
export type LabRunResponse = z.infer<typeof LabRunResponse>;

/** Starting points for the scenario builder: Alice receiving mail from Acme, or from Eve. */
export const LAB_DEFAULTS: Record<(typeof LAB_PRESETS)[number], LabScenario> = {
  legitimate: {
    preset: 'legitimate',
    message: {
      displayName: 'Acme Support',
      from: 'support@acme.example',
      replyTo: '',
      subject: 'Your quarterly statement',
      body: 'Hello Alice,\n\nYour quarterly statement is ready in your Acme account.\n\nAcme Support',
    },
    signer: 'acme',
    selector: 's2025',
    mutations: [],
    disabledRules: [],
  },
  lookalike: {
    preset: 'lookalike',
    message: {
      displayName: 'Acme Support',
      from: 'support@acrne.example',
      replyTo: '',
      subject: 'Action needed: confirm your account',
      body: 'Hello Alice,\n\nPlease confirm your Acme account details today.\n\nAcme Support',
    },
    signer: 'eve',
    selector: 's2025',
    mutations: [],
    disabledRules: [],
  },
};

export const LAB_PERSONAL_SIGNERS = ['alice', 'bob', 'eve', 'none'] as const;
export const LAB_PERSONAL_MUTATIONS = ['editBody', 'changeOuterSubject'] as const;

/**
 * The personal-signature lab: a message that claims to be from Alice, signed (or not) by one of
 * the lab people, then perhaps tampered with. Fixed lists only; the server validates strictly.
 */
export const LabPersonalScenario = z.strictObject({
  signer: z.enum(LAB_PERSONAL_SIGNERS),
  /** Is Alice's real key enrolled in the lab registry? */
  aliceKeyEnrolled: z.boolean(),
  mutations: z.array(z.enum(LAB_PERSONAL_MUTATIONS)).max(LAB_PERSONAL_MUTATIONS.length),
});
export type LabPersonalScenario = z.infer<typeof LabPersonalScenario>;

export const LabPersonalResponse = z.object({
  result: AnalysisResult,
  notes: z.array(z.string()),
  rawMessage: z.string(),
});
export type LabPersonalResponse = z.infer<typeof LabPersonalResponse>;
