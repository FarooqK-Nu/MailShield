import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';
import { pino, type DestinationStream, type Logger } from 'pino';
import { pinoHttp } from 'pino-http';

export function createLogger(destination?: DestinationStream): Logger {
  return pino(
    {
      // Defence in depth: the serializers below already leave these out.
      redact: ['req.headers', 'req.body', '*.authorization', '*.cookie', '*.token', '*.code'],
    },
    destination,
  );
}

/**
 * Logs method, path, status and timing. Never headers, query strings or bodies. Unknown paths
 * are chosen by the caller, so they are not recorded.
 */
export function requestLogger(logger: Logger): RequestHandler {
  const KNOWN =
    /^\/api\/v1\/(health|pair|analyze|analyze\/headers|fixtures|lab\/demo\/[a-z0-9-]+)$/;
  return pinoHttp({
    logger,
    genReqId: () => randomUUID(),
    serializers: {
      req: (req: { id: string; method: string; url: string }) => {
        const path = req.url.split('?')[0]!;
        return { id: req.id, method: req.method, path: KNOWN.test(path) ? path : '(other)' };
      },
      res: (res: { statusCode: number }) => ({ status: res.statusCode }),
      err: (err: { type?: string }) => ({ type: err.type }),
    },
  });
}
