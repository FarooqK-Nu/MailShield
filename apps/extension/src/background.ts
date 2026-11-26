/**
 * Phase 0 OAuth spike: sign in, fetch the newest message with format=raw and report only its
 * size. Nothing is stored, logged or sent anywhere else. Phase 4 replaces this.
 */
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

export type SpikeReply = { ok: true; rawBytes: number } | { ok: false; error: string };

const GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me';

async function gmailGet<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`${GMAIL}${path}`, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 401) await chrome.identity.removeCachedAuthToken({ token });
  if (!res.ok) throw new Error(`Gmail API returned HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

async function runSpike(): Promise<SpikeReply> {
  if (!chrome.runtime.getManifest().oauth2) {
    return { ok: false, error: 'No OAuth client ID configured. See docs/spikes.md.' };
  }
  const { token } = await chrome.identity.getAuthToken({ interactive: true });
  if (!token) return { ok: false, error: 'Sign-in did not return a token.' };

  const list = await gmailGet<{ messages?: { id: string }[] }>('/messages?maxResults=1', token);
  const id = list.messages?.[0]?.id;
  if (!id) return { ok: false, error: 'This mailbox has no messages.' };

  const message = await gmailGet<{ raw: string }>(
    `/messages/${encodeURIComponent(id)}?format=raw`,
    token,
  );
  const binary = atob(message.raw.replace(/-/g, '+').replace(/_/g, '/'));
  return { ok: true, rawBytes: binary.length };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || message?.type !== 'oauth-spike') return;
  runSpike()
    .catch((error: Error): SpikeReply => ({ ok: false, error: error.message }))
    .then(sendResponse);
  return true;
});
