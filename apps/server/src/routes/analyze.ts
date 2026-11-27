import { InputSource, MAX_MESSAGE_BYTES } from '@mailshield/contracts';
import {
  analyze,
  AnalysisError,
  DEFAULT_RULE_CONFIG,
  type DnsResolver,
  type RegistryPort,
  type RuleConfig,
} from '@mailshield/engine';
import express, { Router, type Request, type RequestHandler } from 'express';
import type { Logger } from 'pino';
import { z } from 'zod';
import type { KeyHistoryRepo } from '../db/key-history-repo.ts';
import type { SettingsRepo } from '../db/settings-repo.ts';
import { sendProblem } from '../middleware/errors.ts';

export interface AnalyzeDeps {
  resolver: DnsResolver;
  registry: RegistryPort;
  settings: SettingsRepo;
  history: KeyHistoryRepo;
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
    const { historyEnabled, disabledRules } = deps.settings.get();
    const config: RuleConfig = {
      ...DEFAULT_RULE_CONFIG,
      enabled: {
        ...DEFAULT_RULE_CONFIG.enabled,
        ...Object.fromEntries(disabledRules.map((id) => [id, false])),
      },
    };
    // No trustStore: the live service has no S/MIME anchors, so the lab CA can never be trusted.
    const result = await analyze(input, {
      resolver: deps.resolver,
      registry: deps.registry,
      history: historyEnabled ? deps.history : undefined,
      config,
      clock: deps.clock,
    });
    // Opt-in recording of the keys that verified, after the rules read the earlier history.
    if (historyEnabled && input.source !== 'header_paste') {
      for (const s of result.signatures) {
        if (s.status === 'pass' && s.key && s.domain && s.selector) {
          deps.history.record(s.domain, s.selector, s.key.fingerprint);
        }
      }
    }
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
