import type { RequestHandler } from 'express';
import { sendProblem } from './errors.ts';

/**
 * Rejects any origin outside the allowlist. A request without an Origin header (a command line
 * client, or a same-origin GET) passes here and still needs a token on protected routes.
 */
export function originGuard(allowed: Set<string>): RequestHandler {
  return (req, res, next) => {
    const { origin } = req.headers;
    if (origin === undefined || allowed.has(origin)) return next();
    sendProblem(res, 'origin_rejected');
  };
}

/** For pairing, where there is no token yet: a listed origin is required. */
export const requireOrigin: RequestHandler = (req, res, next) => {
  if (req.headers.origin !== undefined) return next();
  sendProblem(res, 'origin_rejected');
};
