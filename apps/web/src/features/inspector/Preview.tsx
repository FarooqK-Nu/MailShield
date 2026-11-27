import type { MessagePreview } from '@mailshield/contracts';
import { useMemo } from 'react';
import { PREVIEW_CSP, previewDocument, sanitizePreview } from './sanitize.ts';

/**
 * Sanitized preview in a sandboxed iframe with a strict CSP. No scripts, no remote resources,
 * and the frame cannot navigate (invariant 5).
 */
export function Preview({ preview }: { preview: MessagePreview }) {
  const clean = useMemo(
    () => (preview.html ? sanitizePreview(preview.html) : null),
    [preview.html],
  );
  return (
    <section aria-labelledby="preview-title" className="space-y-2">
      <h2 id="preview-title" className="font-semibold">
        Message preview
      </h2>
      {clean ? (
        <>
          <iframe
            title="Sanitized message preview"
            sandbox=""
            // Chromium honours the csp attribute; the meta tag in the document covers the rest.
            {...{ csp: PREVIEW_CSP }}
            srcDoc={previewDocument(clean.html)}
            className="h-80 w-full rounded-md border border-slate-300 bg-white dark:border-slate-700"
          />
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Sanitized. Links are disabled and no remote content loads
            {clean.blocked > 0 && ` (${clean.blocked} remote reference(s) removed)`}.
          </p>
        </>
      ) : preview.text ? (
        <pre className="max-h-80 overflow-auto rounded-md border border-slate-300 p-3 text-sm whitespace-pre-wrap dark:border-slate-700">
          {preview.text}
        </pre>
      ) : (
        <p className="text-sm">No body to preview (header-only input or empty body).</p>
      )}
    </section>
  );
}
