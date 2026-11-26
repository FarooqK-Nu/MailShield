import type { Problem, ProblemType } from '@mailshield/contracts';
import { AnalysisError } from '@mailshield/engine';
import type { ErrorRequestHandler, RequestHandler, Response } from 'express';
import type { Logger } from 'pino';
import { ZodError } from 'zod';
import { KeyMaterialError } from '../db/public-key.ts';
import { RegistryError } from '../db/registry-repo.ts';

const PROBLEMS: Record<ProblemType, [status: number, title: string]> = {
  malformed_message: [422, 'The input is not a readable email message.'],
  input_too_large: [413, 'The input is larger than the allowed size.'],
  mime_limits_exceeded: [422, 'The message structure exceeds safe limits.'],
  dns_timeout: [504, 'DNS did not answer in time.'],
  unsupported_crypto: [422, 'The message uses unsupported cryptography.'],
  unauthorized: [401, 'Pair this client with the local service first.'],
  origin_rejected: [403, 'This origin is not allowed.'],
  host_rejected: [403, 'This host name is not allowed.'],
  pairing_failed: [401, 'That pairing code is not valid.'],
  invalid_request: [400, 'The request is not valid.'],
  rate_limited: [429, 'Too many requests. Wait a moment and try again.'],
  not_found: [404, 'Not found.'],
  conflict: [409, 'This conflicts with an existing entry.'],
  private_key_rejected: [
    422,
    'Private keys are never accepted. Paste a certificate or public key.',
  ],
  internal_error: [500, 'The service could not complete the request.'],
};

/** `detail` is our own text, at most quoting the caller's registry input; never library errors. */
export function sendProblem(
  res: Response,
  type: ProblemType,
  status = PROBLEMS[type][0],
  detail?: string,
): void {
  const problem: Problem = { type, status, title: PROBLEMS[type][1], ...(detail && { detail }) };
  res.status(status).type('application/problem+json').send(JSON.stringify(problem));
}

export const notFound: RequestHandler = (_req, res) => sendProblem(res, 'not_found');

/**
 * Responses and logs carry fixed text only. Parser errors can hold the request body, so the
 * error object itself is never logged.
 */
export function errorHandler(logger: Logger): ErrorRequestHandler {
  return (error, _req, res, next) => {
    if (res.headersSent) return next(error);
    if (error instanceof AnalysisError) return sendProblem(res, error.type);
    if (error instanceof RegistryError)
      return sendProblem(res, error.type, undefined, error.message);
    if (error instanceof KeyMaterialError) {
      return sendProblem(res, error.type, undefined, error.message);
    }
    if (error instanceof ZodError) return sendProblem(res, 'invalid_request');

    const { type, status } = error as { type?: string; status?: number };
    if (type === 'entity.too.large') return sendProblem(res, 'input_too_large');
    if (typeof status === 'number' && status >= 400 && status < 500) {
      return sendProblem(res, 'invalid_request', status);
    }
    logger.error({ errorName: (error as Error).name }, 'request failed');
    sendProblem(res, 'internal_error');
  };
}
