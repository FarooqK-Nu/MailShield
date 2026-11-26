import { InputSource, MAX_MESSAGE_BYTES } from '@mailshield/contracts';
import { analyze, AnalysisError, type DnsResolver } from '@mailshield/engine';
import express, { Router, type Request, type RequestHandler } from 'express';
import type { Logger } from 'pino';
import { z } from 'zod';
import { sendProblem } from '../middleware/errors.ts';

export interface AnalyzeDeps {
  resolver: DnsResolver;
  clock: () => Date;
  logger: Logger;
  extensionOrigin: string;
}

const Headers = z.object({
  // A client cannot claim to be the lab or a fixture.
  'x-mailshield-source': InputSource.extract(['eml_upload', 'gmail_api']).default('eml_upload'),
  'x-mailshield-message-ref': z
    .string()
    .regex(/^[\w-]{1,64}$/)
    .optional(),
});

/** Message bytes exactly as sent. Compressed bodies are refused. */
const rawBody = (type: string, limit: number) => express.raw({ type, limit, inflate: false });

function bytes(req: Request): Buffer {
  if (!Buffer.isBuffer(req.body)) throw new AnalysisError('malformed_message', 'No message body.');
  return req.body;
}

export function analyzeRoutes(deps: AnalyzeDeps, guards: RequestHandler[]): Router {
  const router = Router();

  const run = async (input: Parameters<typeof analyze>[0]) => {
    const started = performance.now();
    const result = await analyze(input, { resolver: deps.resolver, clock: deps.clock });
    deps.logger.info(
      { analysisId: result.analysisId, ms: Math.round(performance.now() - started) },
      'analysis complete',
    );
    return result;
  };

  router.post(
    '/analyze',
    ...guards,
    rawBody('application/octet-stream', MAX_MESSAGE_BYTES),
    async (req, res) => {
      const headers = Headers.parse(req.headers);
      const source = headers['x-mailshield-source'];
      // Only the extension fetches from the Gmail API.
      if (source === 'gmail_api' && req.headers.origin !== deps.extensionOrigin) {
        return sendProblem(res, 'invalid_request');
      }
      res.json(
        await run({ raw: bytes(req), source, messageRef: headers['x-mailshield-message-ref'] }),
      );
    },
  );

  router.post(
    '/analyze/headers',
    ...guards,
    rawBody('text/plain', 1024 * 1024),
    async (req, res) => {
      res.json(await run({ raw: bytes(req), source: 'header_paste', headerOnly: true }));
    },
  );

  return router;
}
