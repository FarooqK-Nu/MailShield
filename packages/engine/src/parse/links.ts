import type { LinkEvidence } from '@mailshield/contracts';
import { Parser } from 'htmlparser2';
import { toAsciiHost } from '../identity/domain.ts';

const MAX_LINKS = 200;

/** Host of an http(s) URL, or null. Parsing only; nothing is fetched. */
function urlHost(value: string): string | null {
  try {
    const url = new URL(value.trim());
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return toAsciiHost(url.hostname) || null;
  } catch {
    return null;
  }
}

/** Host named by visible text such as `https://acme.example/login` or `www.acme.example`. */
function textHost(text: string): string | null {
  const trimmed = text.trim();
  if (/^https?:\/\//i.test(trimmed)) return urlHost(trimmed);
  if (!/^[^\s/:?#@]+\.[^\s/:?#@.]+(?:[/:?#]\S*)?$/.test(trimmed)) return null;
  return toAsciiHost(trimmed.split(/[/:?#]/)[0]!) || null;
}

/** Walks `<a href>` elements and records the target next to the visible text. */
export function extractLinks(html: string): LinkEvidence[] {
  const links: LinkEvidence[] = [];
  let open: { href: string; text: string } | null = null;
  const parser = new Parser(
    {
      onopentag(name, attrs) {
        if (name === 'a' && attrs.href !== undefined) open = { href: attrs.href, text: '' };
      },
      ontext(text) {
        if (open) open.text += text;
      },
      onclosetag(name) {
        if (name !== 'a' || !open || links.length >= MAX_LINKS) return;
        const visibleText = open.text.replace(/\s+/g, ' ').trim();
        links.push({
          id: `link-${links.length + 1}`,
          visibleText,
          href: open.href,
          hrefHost: urlHost(open.href),
          textHost: textHost(visibleText),
        });
        open = null;
      },
    },
    { decodeEntities: true },
  );
  parser.write(html);
  parser.end();
  return links;
}
