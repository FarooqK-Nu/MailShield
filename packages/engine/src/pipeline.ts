import { randomUUID } from 'node:crypto';
import type {
  AnalysisResult,
  Evidence,
  InputSource,
  SignatureEvidence,
  StageEvent,
  StageName,
  StageStatus,
} from '@mailshield/contracts';
import { listSignatures, verifyDkim } from './authentication/dkim.ts';
import type { DnsLookup } from './dns/mailauth-adapter.ts';
import type { DnsResolver } from './dns/resolver.ts';
import { AnalysisError, LIMITS } from './intake/limits.ts';
import { readSender } from './parse/addresses.ts';
import { parseMime } from './parse/mime.ts';
import { readRawHeaders } from './parse/raw-headers.ts';

export interface AnalysisInput {
  /** Original bytes, never mutated. */
  raw: Buffer;
  source: InputSource;
  headerOnly?: boolean;
  messageRef?: string;
}

/** Registry, key history, trust store and rule configuration join these in later phases. */
export interface EngineDeps {
  resolver: DnsResolver;
  clock: () => Date;
  onStage?: (event: StageEvent) => void;
}

interface StageReport {
  status: StageStatus;
  inputs?: Record<string, unknown>;
  outputs?: Record<string, unknown>;
  limitations?: string[];
}

const NOT_BUILT: [StageName, string][] = [
  ['receiver', 'Results reported by the receiving mail provider are not evaluated yet.'],
  ['alignment', 'DMARC alignment is not evaluated yet.'],
  ['smime', 'Personal (S/MIME) signatures are not evaluated yet.'],
  ['identity', 'The claimed identity is not analysed yet.'],
  ['registry', 'There is no trusted identity registry yet.'],
  ['rules', 'Impersonation rules are not evaluated yet.'],
];

function dkimStageStatus(signatures: SignatureEvidence[]): StageStatus {
  const has = (status: SignatureEvidence['status']) => signatures.some((s) => s.status === status);
  if (has('pass')) return signatures.every((s) => s.status === 'pass') ? 'pass' : 'warn';
  if (has('fail')) return 'fail';
  if (has('temporary_error')) return 'error';
  return 'warn';
}

export async function analyze(input: AnalysisInput, deps: EngineDeps): Promise<AnalysisResult> {
  const { raw, source, headerOnly = false } = input;
  const simulated = source === 'lab' || source === 'fixture';
  const evidenceSource = simulated ? 'lab' : 'local_crypto';
  const stages: StageEvent[] = [];
  const limitations: string[] = [];

  const record = (stage: StageName, startedAt: Date, report: StageReport, durationMs?: number) => {
    const event: StageEvent = {
      stage,
      status: report.status,
      startedAt: startedAt.toISOString(),
      durationMs,
      inputs: report.inputs ?? {},
      outputs: report.outputs ?? {},
      limitations: report.limitations ?? [],
      simulated,
    };
    stages.push(event);
    deps.onStage?.(event);
  };
  const run = async <T>(stage: StageName, work: () => Promise<StageReport & { value: T }>) => {
    const startedAt = deps.clock();
    const started = performance.now();
    deps.onStage?.({
      stage,
      status: 'running',
      startedAt: startedAt.toISOString(),
      inputs: {},
      outputs: {},
      limitations: [],
      simulated,
    });
    const { value, ...report } = await work();
    record(stage, startedAt, report, Math.round(performance.now() - started));
    return value;
  };

  await run('intake', async () => {
    if (raw.length === 0) throw new AnalysisError('malformed_message', 'The message is empty.');
    if (raw.length > LIMITS.messageBytes) {
      throw new AnalysisError('input_too_large', 'The message is larger than 10 MiB.');
    }
    return { status: 'pass', inputs: { bytes: raw.length, source }, value: null };
  });

  const { headers, sender } = await run('parse', async () => {
    const headers = readRawHeaders(raw);
    if (headers.fields.length === 0) {
      throw new AnalysisError('malformed_message', 'No email headers were found.');
    }
    const mime = headerOnly ? null : await parseMime(raw);
    const sender = readSender(headers);
    const notes: string[] = [];
    if (headers.malformedLines > 0) notes.push('Some header lines are malformed.');
    if (sender.fromAmbiguous) notes.push('The From header does not name exactly one sender.');
    return {
      status: notes.length ? 'warn' : 'pass',
      outputs: { headerFields: headers.fields.length, ...mime },
      limitations: notes,
      value: { headers, sender },
    };
  });

  const lookups: DnsLookup[] = [];
  let signatures: SignatureEvidence[];
  const dkimStarted = deps.clock();
  const dkimTimer = performance.now();
  if (headerOnly) {
    signatures = listSignatures(headers, evidenceSource);
    const note = 'Header-only input: body and signatures were not checked.';
    limitations.push(note);
    record('dns', dkimStarted, { status: 'not_evaluated', limitations: [note] });
    record('dkim', dkimStarted, {
      status: 'not_evaluated',
      outputs: { signatures: signatures.length },
      limitations: [note],
    });
  } else {
    signatures = await verifyDkim(raw, headers, {
      resolver: deps.resolver,
      now: deps.clock(),
      source: evidenceSource,
      dns: { onLookup: (lookup) => lookups.push(lookup) },
    });
    const durationMs = Math.round(performance.now() - dkimTimer);
    const dnsFailed = lookups.some((l) => l.status === 'timeout' || l.status === 'servfail');
    record(
      'dns',
      dkimStarted,
      {
        status: lookups.length === 0 ? 'skipped' : dnsFailed ? 'error' : 'pass',
        outputs: { lookups },
      },
      lookups.reduce((total, l) => total + l.durationMs, 0),
    );
    record(
      'dkim',
      dkimStarted,
      {
        status: dkimStageStatus(signatures),
        outputs: { signatures: signatures.map((s) => ({ id: s.evidenceId, status: s.status })) },
      },
      durationMs,
    );
  }

  const observedAt = deps.clock().toISOString();
  const authentication: Evidence[] = signatures.map((s) => ({
    id: s.evidenceId,
    kind: 'dkim',
    source: s.source,
    status: s.status,
    domains: s.domain ? [s.domain] : [],
    reason: s.reason,
    observedAt,
    details: { selector: s.selector, failureStage: s.failureStage },
  }));
  if (signatures.length === 0) {
    authentication.push({
      id: 'dkim-none',
      kind: 'dkim',
      source: evidenceSource,
      status: 'missing',
      domains: [],
      reason: 'The message has no DKIM signature.',
      observedAt,
      details: {},
    });
  }

  for (const [stage, note] of NOT_BUILT) {
    record(stage, deps.clock(), { status: 'not_evaluated', limitations: [note] });
  }
  limitations.push(
    'No identity, DMARC or impersonation checks have run, so this result cannot confirm who sent the message.',
  );
  if (signatures.some((s) => s.status === 'missing' || s.status === 'temporary_error')) {
    limitations.push('A DNS key is unavailable now; a check made at delivery time may differ.');
  }

  // Rows 2 and 6 of the verdict table (architecture.md §3.9). The rest needs the Phase 3 rules.
  const ambiguous = sender.fromAmbiguous;
  const verdict = ambiguous ? 'authentication_concern' : 'identity_unverified';
  record('verdict', deps.clock(), { status: 'warn', outputs: { verdict } });

  return {
    analysisId: randomUUID(),
    schemaVersion: '1',
    inputSource: source,
    messageRef: input.messageRef,
    sender,
    claimedIdentity: null,
    authentication,
    signatures,
    findings: [],
    stages,
    verdict,
    identityStatus: ambiguous ? 'ambiguous' : 'unverified',
    riskLevel: ambiguous ? 'caution' : 'unknown',
    limitations,
    analyzedAt: deps.clock().toISOString(),
  };
}
