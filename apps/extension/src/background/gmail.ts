import { MAX_MESSAGE_BYTES } from '@mailshield/contracts';
import { z } from 'zod';
import { addressOf, GMAIL_ID, type MessageMetadata } from '../shared/selection.ts';

export const GMAIL_API = 'https://gmail.googleapis.com/gmail/v1/users/me';

/** A failure the side panel can explain and act on. */
export class ExtensionError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export interface TokenSource {
  /** Returns a Gmail access token without prompting. Throws `not_connected` when there is none. */
  get(): Promise<string>;
  /** Drops a token Google rejected, so the next `get` fetches a fresh one. */
  drop(token: string): Promise<void>;
}

export interface GmailDeps {
  fetch: typeof fetch;
  tokens: TokenSource;
}

const MetadataResponse = z.object({
  id: z.string(),
  sizeEstimate: z.number().default(0),
  payload: z
    .object({ headers: z.array(z.object({ name: z.string(), value: z.string() })).default([]) })
    .default({ headers: [] }),
});
const RawResponse = z.object({ id: z.string(), raw: z.string() });
const ListResponse = z.object({ messages: z.array(z.object({ id: z.string() })).default([]) });

const STATUS_ERRORS: Record<number, [string, string]> = {
  403: [
    'gmail_forbidden',
    'Gmail refused access. Check that this Google account is a test user of the OAuth consent screen and that the Gmail API is enabled.',
  ],
  404: [
    'message_not_found',
    'Gmail has no message with this id. The selection may be out of date; reopen the message.',
  ],
  429: ['gmail_rate_limited', 'Gmail is limiting requests. Wait a moment and try again.'],
};

/** Decodes Gmail's base64url `raw` field into the original message bytes. */
export function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value)) {
    throw new ExtensionError(
      'malformed_raw',
      'Gmail returned a message that is not valid base64url.',
    );
  }
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Read-only Gmail API access for one message at a time. The access token is used only in the
 * Authorization header of requests to gmail.googleapis.com and is never returned.
 */
export function createGmailClient({ fetch, tokens }: GmailDeps) {
  async function get<T>(path: string, schema: z.ZodType<T>, retried = false): Promise<T> {
    const token = await tokens.get();
    let res: Response;
    try {
      res = await fetch(`${GMAIL_API}${path}`, { headers: { Authorization: `Bearer ${token}` } });
    } catch {
      throw new ExtensionError(
        'gmail_unreachable',
        'Gmail could not be reached. Check the network.',
      );
    }
    if (res.status === 401) {
      await tokens.drop(token);
      if (!retried) return get(path, schema, true);
      throw new ExtensionError('not_connected', 'Gmail access expired. Connect again.');
    }
    if (!res.ok) {
      const [code, message] = STATUS_ERRORS[res.status] ?? [
        'gmail_error',
        `Gmail returned HTTP ${res.status}.`,
      ];
      throw new ExtensionError(code, message);
    }
    const parsed = schema.safeParse(await res.json().catch(() => null));
    if (!parsed.success) {
      throw new ExtensionError('gmail_error', 'Gmail sent an unexpected response.');
    }
    return parsed.data;
  }

  const checkId = (id: string) => {
    if (!GMAIL_ID.test(id))
      throw new ExtensionError('invalid_id', 'That is not a Gmail message id.');
    return encodeURIComponent(id);
  };

  async function metadata(id: string): Promise<MessageMetadata> {
    const query =
      'format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date';
    const m = await get(`/messages/${checkId(id)}?${query}`, MetadataResponse);
    const header = (name: string) =>
      m.payload.headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? '';
    const from = header('From');
    return {
      id: m.id,
      from,
      fromAddress: addressOf(from),
      subject: header('Subject'),
      date: header('Date'),
      sizeEstimate: m.sizeEstimate,
    };
  }

  return {
    metadata,

    /** The original bytes (format=raw). Signatures are verified only from these (invariant 1). */
    async raw(id: string): Promise<Uint8Array> {
      const { raw } = await get(`/messages/${checkId(id)}?format=raw`, RawResponse);
      const bytes = decodeBase64Url(raw);
      if (bytes.length > MAX_MESSAGE_BYTES) {
        throw new ExtensionError('input_too_large', 'The message is larger than 10 MiB.');
      }
      return bytes;
    },

    /** Sender, subject and date of the newest messages, for the consented picker only. */
    async recent(count: number): Promise<MessageMetadata[]> {
      const n = Math.min(Math.max(1, Math.trunc(count)), 25);
      const list = await get(`/messages?maxResults=${n}`, ListResponse);
      return Promise.all(list.messages.map((m) => metadata(m.id)));
    },
  };
}

export type GmailClient = ReturnType<typeof createGmailClient>;
