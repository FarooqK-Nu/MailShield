import { MAX_MESSAGE_BYTES, type ProblemType } from '@mailshield/contracts';

export const LIMITS = {
  messageBytes: MAX_MESSAGE_BYTES,
  headerBytes: 256 * 1024,
  headerFields: 1000,
  mimeDepth: 20,
  mimeParts: 500,
  dkimSignatures: 20,
} as const;

/** A typed failure. The message is fixed text and never includes message content. */
export class AnalysisError extends Error {
  readonly type: ProblemType;

  constructor(type: ProblemType, message: string) {
    super(message);
    this.name = 'AnalysisError';
    this.type = type;
  }
}
