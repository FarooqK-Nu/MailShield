import DOMPurify from 'dompurify';

/** Blocks every remote load even if something slips past the sanitizer (invariant 5). */
export const PREVIEW_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:";

const URL_ATTRS = ['src', 'srcset', 'background', 'poster', 'action', 'formaction', 'xlink:href'];

/**
 * Sanitized HTML for the preview iframe: no scripts, no remote images, and links that cannot
 * be followed (their target is kept in the title so the user can still read it).
 */
export function sanitizePreview(html: string): { html: string; blocked: number } {
  let blocked = 0;
  const purify = DOMPurify();
  purify.addHook('afterSanitizeAttributes', (node) => {
    for (const attr of URL_ATTRS) {
      const value = node.getAttribute(attr);
      if (value === null) continue;
      if (attr === 'src' && value.startsWith('data:image/')) continue;
      node.removeAttribute(attr);
      blocked++;
      if (node.tagName === 'IMG') node.setAttribute('alt', `[remote image blocked]`);
    }
    const href = node.getAttribute('href');
    if (href !== null) {
      node.removeAttribute('href');
      node.setAttribute('title', `Link target (not opened): ${href}`);
    }
    const style = node.getAttribute('style');
    if (style && /url\s*\(/i.test(style)) {
      node.setAttribute('style', style.replace(/url\s*\([^)]*\)/gi, 'none'));
      blocked++;
    }
  });
  const clean = purify.sanitize(html, {
    FORBID_TAGS: [
      'style',
      'link',
      'meta',
      'base',
      'iframe',
      'object',
      'embed',
      'form',
      'video',
      'audio',
      'source',
      'picture',
    ],
  });
  return { html: clean, blocked };
}

export function previewDocument(html: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${PREVIEW_CSP}"><style>body{font:14px system-ui,sans-serif;margin:12px;color:#0f172a;background:#fff;word-wrap:break-word}img{max-width:100%}</style></head><body>${html}</body></html>`;
}
