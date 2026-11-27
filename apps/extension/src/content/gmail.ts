/**
 * Gmail content script: reads which message is open and tells the service worker. It only reads
 * the page; it never changes Gmail's interface or message content (docs/architecture.md §6).
 * Gmail's markup is not a stable interface, so the result is a hint that the side panel confirms
 * through the Gmail API before anything is analyzed.
 */
import { readHint } from './read-hint.ts';

let last = '';
let timer: ReturnType<typeof setTimeout> | undefined;

function report() {
  const hint = readHint(document);
  const key = JSON.stringify(hint);
  if (key === last) return;
  last = key;
  chrome.runtime.sendMessage({ type: 'selection', hint }).catch(() => {
    // The extension was reloaded; this page keeps the old script until it is refreshed.
  });
}

function schedule() {
  clearTimeout(timer);
  timer = setTimeout(report, 300);
}

new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
window.addEventListener('hashchange', schedule);
schedule();
