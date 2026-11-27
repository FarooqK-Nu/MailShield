import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/** Invariant 10: no "safe" label and no fraud accusation in any user-facing text. */
const ROOTS = ['apps/web/src', 'apps/extension/src', 'packages/ui/src'].map(
  (p) => new URL(`../../../${p}`, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'),
);
// `(?<![-\w])` skips CSS utility classes such as motion-safe.
const BANNED = /(?<![-\w])(safe|scam|scammer|fraud|fraudulent|phishing|malicious|hacker|criminal)\b/i;
// Phrases that name the rule itself or deny the claim are allowed.
const ALLOWED = /(not|never|no)\b[^.]*\bsafe\b|\bnot\s+(a\s+)?(proof|label)/i;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return files(full);
    return /\.(tsx?|html)$/.test(name) ? [full] : [];
  });
}

describe('user-facing copy', () => {
  it('contains no safe-label or accusation wording', () => {
    const hits: string[] = [];
    for (const file of ROOTS.flatMap(files)) {
      readFileSync(file, 'utf8')
        .split('\n')
        .forEach((line, i) => {
          const text = line.trim();
          if (text.startsWith('//') || text.startsWith('*') || text.startsWith('/*')) return;
          if (BANNED.test(text) && !ALLOWED.test(text)) hits.push(`${file}:${i + 1}: ${text}`);
        });
    }
    expect(hits).toEqual([]);
  });
});
