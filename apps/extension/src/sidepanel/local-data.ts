/**
 * Data the side panel keeps on this device. Findings marked as reviewed are stored as message id
 * and finding id only: no subject, address or content. The user can clear them in Privacy.
 */
const REVIEWED_KEY = 'reviewedFindings';
const MAX_MESSAGES = 200;

type Reviewed = Record<string, string[]>;

async function readAll(): Promise<Reviewed> {
  const stored = await chrome.storage.local.get(REVIEWED_KEY);
  const value = stored[REVIEWED_KEY];
  return value && typeof value === 'object' ? (value as Reviewed) : {};
}

export async function reviewedFor(messageRef: string): Promise<string[]> {
  return (await readAll())[messageRef] ?? [];
}

export async function setReviewed(messageRef: string, findingId: string, reviewed: boolean) {
  const all = await readAll();
  const current = new Set(all[messageRef] ?? []);
  if (reviewed) current.add(findingId);
  else current.delete(findingId);
  delete all[messageRef];
  if (current.size) all[messageRef] = [...current];
  // Oldest messages are forgotten first.
  const kept = Object.fromEntries(Object.entries(all).slice(-MAX_MESSAGES));
  await chrome.storage.local.set({ [REVIEWED_KEY]: kept });
  return [...current];
}

export async function clearReviewed() {
  await chrome.storage.local.remove(REVIEWED_KEY);
}

export const DASHBOARD_URL = new URL(import.meta.env.VITE_DASHBOARD_URL || 'http://127.0.0.1:5173')
  .origin;
