import { MAX_MESSAGE_BYTES, type AnalysisResult } from '@mailshield/contracts';
import { ExtensionError, type GmailClient } from './gmail.ts';
import type { ServiceClient } from './service.ts';

/** Steps the extension itself performs; the engine's own stages arrive with the result. */
export type FlowStep = 'checking_size' | 'fetching_raw' | 'sending' | 'analyzing';

export const FLOW_STEPS: Record<FlowStep, string> = {
  checking_size: 'Checking the message size with Gmail',
  fetching_raw: 'Fetching the original message bytes from Gmail',
  sending: 'Sending the bytes to the local service',
  analyzing: 'Verifying signatures and comparing identities',
};

/**
 * Fetches one message the user chose and has it analyzed (docs/architecture.md §6).
 * The Gmail token stays inside `gmail`; the service receives only bytes and the message id.
 */
export async function analyzeGmailMessage(
  id: string,
  gmail: GmailClient,
  service: ServiceClient,
  onStep: (step: FlowStep) => void = () => {},
): Promise<AnalysisResult> {
  onStep('checking_size');
  const meta = await gmail.metadata(id);
  if (meta.sizeEstimate > MAX_MESSAGE_BYTES) {
    throw new ExtensionError(
      'input_too_large',
      'The message is larger than 10 MiB, so it was not fetched. Large attachments are the usual cause.',
    );
  }
  onStep('fetching_raw');
  const bytes = await gmail.raw(id);
  onStep('sending');
  const pending = service.analyze(bytes, { source: 'gmail_api', messageRef: id });
  onStep('analyzing');
  const result = await pending;
  if (result.messageRef !== id) {
    throw new ExtensionError('stale_result', 'The service answered for a different message.');
  }
  return result;
}
