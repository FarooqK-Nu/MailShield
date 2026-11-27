/** Gmail API message ids are lower-case hexadecimal (the "legacy" id in the Gmail UI). */
export const GMAIL_ID = /^[0-9a-f]{8,24}$/;

/**
 * What the content script read from the Gmail page. Only a hint: the DOM is not stable.
 * This module has no dependencies, so the content script stays small; the service worker
 * validates hints with the schema in protocol.ts.
 */
export interface HintMessage {
  id: string;
  fromEmail: string | null;
  fromName: string | null;
}

export interface SelectionHint {
  subject: string | null;
  /** Every expanded message of the open conversation, in page order. */
  messages: HintMessage[];
}

export const EMPTY_HINT: SelectionHint = { subject: null, messages: [] };

/**
 * The Gmail API id for a message element. Gmail writes it as `data-legacy-message-id` (hex) and
 * as `data-message-id="#msg-f:<decimal>"`; both name the same message.
 */
export function toApiId(legacyId: string | null, messageId: string | null): string | null {
  if (legacyId && GMAIL_ID.test(legacyId)) return legacyId;
  const decimal = /^#?msg-f:(\d{1,20})$/.exec(messageId ?? '')?.[1];
  if (!decimal) return null;
  const hex = BigInt(decimal).toString(16);
  return GMAIL_ID.test(hex) ? hex : null;
}

/** From, Subject and Date as the Gmail API reports them, shown to the user for confirmation. */
export interface MessageMetadata {
  id: string;
  from: string;
  fromAddress: string | null;
  subject: string;
  date: string;
  sizeEstimate: number;
}

const normalize = (value: string) =>
  value.normalize('NFKC').replace(/\s+/g, ' ').trim().toLowerCase();
const stripReply = (subject: string) =>
  normalize(subject).replace(/^((re|fwd?|aw|sv)\s*:\s*)+/i, '');

/** The address inside a From header such as `Acme <billing@acme.example>`. */
export function addressOf(from: string): string | null {
  const angle = /<([^<>\s]+@[^<>\s]+)>/.exec(from)?.[1];
  const bare = /^\s*([^\s<>"]+@[^\s<>"]+)\s*$/.exec(from)?.[1];
  return (angle ?? bare)?.toLowerCase() ?? null;
}

/**
 * Differences between what the page showed and what the Gmail API returned for the same id.
 * An empty list means the confirmation matches. A conversation's subject can differ from one
 * message's subject by a reply prefix, so that is not counted.
 */
export function compareWithHint(
  hint: HintMessage,
  hintSubject: string | null,
  meta: MessageMetadata,
): string[] {
  const out: string[] = [];
  if (hint.fromEmail && meta.fromAddress && normalize(hint.fromEmail) !== meta.fromAddress) {
    out.push(
      `Gmail showed the sender ${hint.fromEmail}, but the Gmail API returned ${meta.fromAddress}.`,
    );
  }
  if (hintSubject && meta.subject && stripReply(hintSubject) !== stripReply(meta.subject)) {
    out.push(
      `Gmail showed the subject “${hintSubject}”, but the Gmail API returned “${meta.subject}”.`,
    );
  }
  return out;
}
