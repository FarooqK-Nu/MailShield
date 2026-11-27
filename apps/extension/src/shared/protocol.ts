import type { AnalysisResult } from '@mailshield/contracts';
import { z } from 'zod';
import type { FlowStep } from '../background/flow.ts';
import { GMAIL_ID, type MessageMetadata, type SelectionHint } from './selection.ts';

/** Validates a hint from the content script before the service worker keeps it. */
export const SelectionHintSchema = z.object({
  subject: z.string().max(1000).nullable(),
  messages: z
    .array(
      z.object({
        id: z.string().regex(GMAIL_ID),
        fromEmail: z.string().max(320).nullable(),
        fromName: z.string().max(200).nullable(),
      }),
    )
    .max(100),
}) satisfies z.ZodType<SelectionHint>;

/** Requests from the side panel to the service worker, validated before use. */
export const PanelRequest = z.discriminatedUnion('type', [
  z.object({ type: z.literal('status') }),
  z.object({ type: z.literal('pair'), code: z.string().regex(/^\d{8}$/) }),
  z.object({ type: z.literal('unpair') }),
  z.object({ type: z.literal('connect') }),
  z.object({ type: z.literal('disconnect') }),
  z.object({ type: z.literal('hint'), tabId: z.number().int() }),
  z.object({ type: z.literal('metadata'), id: z.string().regex(GMAIL_ID) }),
  z.object({
    type: z.literal('analyze'),
    id: z.string().regex(GMAIL_ID),
    requestId: z.number().int(),
  }),
  z.object({
    type: z.literal('analyzeFile'),
    base64: z.string().max(15_000_000),
    requestId: z.number().int(),
  }),
  z.object({ type: z.literal('recent'), count: z.number().int().min(1).max(25) }),
]);
export type PanelRequest = z.infer<typeof PanelRequest>;

/** Requests from the Gmail content script. */
export const ContentMessage = z.object({ type: z.literal('selection'), hint: SelectionHintSchema });
export type ContentMessage = z.infer<typeof ContentMessage>;

export interface ExtensionStatus {
  paired: boolean;
  serviceUp: boolean;
  oauthConfigured: boolean;
  connected: boolean;
}

/** What each request answers with. */
export interface ReplyValues {
  status: ExtensionStatus;
  pair: null;
  unpair: null;
  connect: null;
  disconnect: null;
  hint: SelectionHint;
  metadata: MessageMetadata;
  analyze: AnalysisResult;
  analyzeFile: AnalysisResult;
  recent: MessageMetadata[];
}

export type Reply<T> = { ok: true; value: T } | { ok: false; code: string; message: string };

/** Broadcasts from the service worker to open side panels. */
export type PanelEvent =
  { type: 'hint-changed'; tabId: number } | { type: 'progress'; requestId: number; step: FlowStep };
