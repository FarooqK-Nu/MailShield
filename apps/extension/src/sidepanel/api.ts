import type { PanelRequest, Reply, ReplyValues } from '../shared/protocol.ts';

export class PanelError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** Sends one request to the service worker and unwraps its reply. */
export async function send<T extends PanelRequest>(request: T): Promise<ReplyValues[T['type']]> {
  let reply: Reply<ReplyValues[T['type']]> | undefined;
  try {
    reply = await chrome.runtime.sendMessage(request);
  } catch {
    throw new PanelError(
      'extension_error',
      'The extension background is not responding. Reopen the panel.',
    );
  }
  if (!reply) throw new PanelError('extension_error', 'The extension background did not answer.');
  if (!reply.ok) throw new PanelError(reply.code, reply.message);
  return reply.value;
}

/** Reads a file as standard base64 for the trip to the service worker. */
export async function fileToBase64(file: Blob): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}
