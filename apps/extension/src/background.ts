/**
 * Service worker (docs/architecture.md §6). It alone holds Gmail access: it asks Chrome for the
 * OAuth token, calls the Gmail API and posts message bytes to the local service. The token is
 * never stored by MailShield, never sent to the local service and never given to the side panel.
 */
import { analyzeGmailMessage } from './background/flow.ts';
import { createGmailClient, ExtensionError, type TokenSource } from './background/gmail.ts';
import { createServiceClient } from './background/service.ts';
import {
  ContentMessage,
  PanelRequest,
  type PanelEvent,
  type Reply,
  type ReplyValues,
  SelectionHintSchema,
} from './shared/protocol.ts';
import { EMPTY_HINT, type SelectionHint } from './shared/selection.ts';

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

const SERVICE_URL = new URL(import.meta.env.VITE_SERVICE_URL || 'http://127.0.0.1:8787').origin;
const SESSION_KEY = 'serviceToken';

async function silentToken(): Promise<string | null> {
  try {
    return (await chrome.identity.getAuthToken({ interactive: false })).token ?? null;
  } catch {
    return null;
  }
}

const tokens: TokenSource = {
  async get() {
    const token = await silentToken();
    if (!token) throw new ExtensionError('not_connected', 'Connect Gmail first.');
    return token;
  },
  drop: (token) => chrome.identity.removeCachedAuthToken({ token }),
};

const sessionToken = async () => {
  const stored = await chrome.storage.local.get(SESSION_KEY);
  return typeof stored[SESSION_KEY] === 'string' ? stored[SESSION_KEY] : null;
};

const gmail = createGmailClient({ fetch: (...args) => fetch(...args), tokens });
const service = createServiceClient({
  fetch: (...args) => fetch(...args),
  baseUrl: SERVICE_URL,
  sessionToken,
});

const broadcast = (event: PanelEvent) => chrome.runtime.sendMessage(event).catch(() => {});

/** Selection hints per Gmail tab, kept in session storage (memory only, cleared on exit). */
const hintKey = (tabId: number) => `hint:${tabId}`;

async function readHint(tabId: number): Promise<SelectionHint> {
  const stored = await chrome.storage.session.get(hintKey(tabId));
  const parsed = SelectionHintSchema.safeParse(stored[hintKey(tabId)]);
  return parsed.success ? parsed.data : EMPTY_HINT;
}

chrome.tabs.onRemoved.addListener((tabId) => void chrome.storage.session.remove(hintKey(tabId)));

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function connect(): Promise<null> {
  if (!chrome.runtime.getManifest().oauth2) {
    throw new ExtensionError(
      'oauth_not_configured',
      'No Google OAuth client is configured for this build. See docs/spikes.md, or use the .eml fallback.',
    );
  }
  try {
    const { token } = await chrome.identity.getAuthToken({ interactive: true });
    if (!token) throw new Error('no token');
    return null;
  } catch (error) {
    const message = (error as Error).message ?? '';
    if (/did not approve|denied|cancel/i.test(message)) {
      throw new ExtensionError(
        'oauth_denied',
        'Gmail access was not granted. Connect again to retry, or use the .eml fallback below.',
      );
    }
    throw new ExtensionError(
      'oauth_failed',
      `Google sign-in failed: ${message || 'unknown error'}.`,
    );
  }
}

async function disconnect(): Promise<null> {
  const token = await silentToken();
  if (token) await chrome.identity.removeCachedAuthToken({ token });
  await chrome.identity.clearAllCachedAuthTokens();
  return null;
}

type Handlers = {
  [K in PanelRequest['type']]: (r: Extract<PanelRequest, { type: K }>) => Promise<ReplyValues[K]>;
};

const handlers: Handlers = {
  status: async () => ({
    paired: (await sessionToken()) !== null,
    serviceUp: await service.health().catch(() => false),
    oauthConfigured: Boolean(chrome.runtime.getManifest().oauth2),
    connected: (await silentToken()) !== null,
  }),
  pair: async ({ code }) => {
    const { token } = await service.pair(code);
    await chrome.storage.local.set({ [SESSION_KEY]: token });
    return null;
  },
  unpair: async () => {
    await chrome.storage.local.remove(SESSION_KEY);
    return null;
  },
  connect,
  disconnect,
  hint: ({ tabId }) => readHint(tabId),
  metadata: ({ id }) => gmail.metadata(id),
  analyze: ({ id, requestId }) =>
    analyzeGmailMessage(id, gmail, service, (step) =>
      broadcast({ type: 'progress', requestId, step }),
    ),
  analyzeFile: async ({ base64, requestId }) => {
    broadcast({ type: 'progress', requestId, step: 'sending' });
    return service.analyze(decodeBase64(base64), { source: 'eml_upload' });
  },
  recent: ({ count }) => gmail.recent(count),
};

async function handle(request: PanelRequest): Promise<Reply<unknown>> {
  try {
    const run = handlers[request.type] as (r: PanelRequest) => Promise<unknown>;
    return { ok: true, value: await run(request) };
  } catch (error) {
    const e =
      error instanceof ExtensionError
        ? error
        : new ExtensionError('internal', 'Something went wrong in the extension.');
    // The service no longer knows this session (for example after it was revoked).
    if (e.code === 'unauthorized' && (await sessionToken()))
      await chrome.storage.local.remove(SESSION_KEY);
    return { ok: false, code: e.code, message: e.message };
  }
}

const EXTENSION_PAGES = chrome.runtime.getURL('');

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;

  // Requests come only from this extension's own pages (the side panel). A page opened in a tab
  // also has `sender.tab`, so the sender is told apart by URL, not by the tab.
  if (sender.url?.startsWith(EXTENSION_PAGES)) {
    const request = PanelRequest.safeParse(message);
    if (!request.success) return;
    void handle(request.data).then(sendResponse);
    return true;
  }

  // The Gmail content script reports what is open. It is a hint only.
  const tabId = sender.tab?.id;
  const parsed = ContentMessage.safeParse(message);
  if (parsed.success && tabId !== undefined && sender.url?.startsWith('https://mail.google.com/')) {
    void chrome.storage.session
      .set({ [hintKey(tabId)]: parsed.data.hint })
      .then(() => broadcast({ type: 'hint-changed', tabId }));
  }
});
