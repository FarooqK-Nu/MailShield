import PostalMime from 'postal-mime';
import { AnalysisError, LIMITS } from '../intake/limits.ts';

export interface MimeSummary {
  hasText: boolean;
  hasHtml: boolean;
  /** Counted only. Attachments are never opened. */
  attachments: number;
}

const LIMIT_CODES = new Set([
  'EMAXNESTINGDEPTH',
  'EMAXPARTCOUNT',
  'EMAXHEADERSIZE',
  'EMAXFORWARDEDADDRESSES',
]);

/** Structured view for display and link extraction only. Signatures never use it. */
export async function parseMime(raw: Buffer): Promise<MimeSummary> {
  try {
    const email = await PostalMime.parse(raw, {
      maxNestingDepth: LIMITS.mimeDepth,
      maxPartCount: LIMITS.mimeParts,
      maxHeadersSize: LIMITS.headerBytes,
    });
    return {
      hasText: Boolean(email.text),
      hasHtml: Boolean(email.html),
      attachments: email.attachments.length,
    };
  } catch (error) {
    if (LIMIT_CODES.has((error as { code?: string }).code ?? '')) {
      throw new AnalysisError('mime_limits_exceeded', 'The message structure exceeds safe limits.');
    }
    throw new AnalysisError('malformed_message', 'The message could not be parsed.');
  }
}
