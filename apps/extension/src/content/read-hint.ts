import { toApiId, type HintMessage, type SelectionHint } from '../shared/selection.ts';

/**
 * Reads the open conversation from Gmail's page, without changing it. Observed markup (not a
 * public interface): each expanded message carries `data-legacy-message-id` (or
 * `data-message-id="#msg-f:<decimal>"`), its sender is a `span.gD` with `email` and `name`
 * attributes, and the conversation subject is the `h2.hP` heading.
 */
export function readHint(doc: Document): SelectionHint {
  const messages: HintMessage[] = [];
  const seen = new Set<string>();
  for (const el of doc.querySelectorAll('[data-legacy-message-id], [data-message-id]')) {
    const sender = el.querySelector('span.gD[email]');
    // Only expanded messages show a sender element; collapsed ones are skipped.
    if (!sender) continue;
    const id = toApiId(
      el.getAttribute('data-legacy-message-id'),
      el.getAttribute('data-message-id'),
    );
    if (!id || seen.has(id)) continue;
    seen.add(id);
    messages.push({
      id,
      fromEmail: sender.getAttribute('email')?.slice(0, 320) || null,
      fromName: sender.getAttribute('name')?.slice(0, 200) || null,
    });
    if (messages.length === 100) break;
  }
  const subject = doc.querySelector('h2.hP')?.textContent?.trim().slice(0, 1000) || null;
  return { subject: messages.length ? subject : null, messages };
}
