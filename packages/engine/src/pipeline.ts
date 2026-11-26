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
import { DMARC_LIMITATION, evaluateDmarc } from './authentication/dmarc.ts';
import { readReceiverResults } from './authentication/receiver-results.ts';
import { toMailauthResolver, type DnsLookup } from './dns/mailauth-adapter.ts';
import type { DnsResolver } from './dns/resolver.ts';
import { emptyRegistry, inspectDomain, matchClaim, type RegistryPort } from './identity/matcher.ts';
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

/** Key history, trust store and rule configuration join these in later phases. */
export interface EngineDeps {
  resolver: DnsResolver;
  /** Trusted identity registry; empty when not given. */
  registry?: RegistryPort;
  clock: () => Date;
  onStage?: (event: StageEvent) => void;
}

interface StageReport {
  status: StageStatus;
  inputs?: Record<string, unknown>;
  outputs?: Record<string, unknown>;
  limitations?: string[];
}

const SMIME_NOTE = 'Personal (S/MIME) signatures are not evaluated yet.';
const RULES_NOTE = 'Impersonation rules are not evaluated yet.';

const ALIGNMENT_STAGE: Record<Evidence['status'], StageStatus> = {
  pass: 'pass',
  fail: 'fail',
  missing: 'warn',
  unknown: 'warn',
  temporary_error: 'error',
  unsupported: 'warn',
  untrusted: 'warn',
  not_evaluated: 'not_evaluated',
};

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
  // One adapter per message, so DKIM and DMARC share the lookup budget and deadline.
  const lookup = toMailauthResolver(deps.resolver, { onLookup: (l) => lookups.push(l) });
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
      lookup,
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

  const receiver = await run('receiver', async () => {
    const evidence = readReceiverResults(headers, source, observedAt);
    return {
      status: evidence.length ? 'warn' : 'skipped',
      outputs: { headers: evidence.length, trusted: 0 },
      limitations: evidence.length
        ? ['Authentication-Results headers in the message are shown for information only.']
        : [],
      value: evidence,
    };
  });
  authentication.push(...receiver);

  const fromBox = sender.fromAmbiguous ? undefined : sender.from[0];
  if (headerOnly) {
    record('alignment', deps.clock(), {
      status: 'not_evaluated',
      limitations: ['Header-only input: DMARC alignment needs verified signatures.'],
    });
  } else {
    const fromDomain = fromBox?.domain ?? '';
    const dmarc = await run('alignment', async () => {
      const before = lookups.length;
      const evidence = await evaluateDmarc({
        fromDomain,
        signatures,
        lookup,
        source: evidenceSource,
        observedAt,
      });
      return {
        status: ALIGNMENT_STAGE[evidence.status],
        inputs: { fromDomain },
        outputs: { status: evidence.status, ...evidence.details, lookups: lookups.slice(before) },
        limitations: [DMARC_LIMITATION],
        value: evidence,
      };
    });
    authentication.push(dmarc);
    limitations.push(DMARC_LIMITATION);
  }

  record('smime', deps.clock(), { status: 'not_evaluated', limitations: [SMIME_NOTE] });

  const domains = await run('identity', async () => {
    const roles = [
      ...sender.from.map((m) => ['from', m.domain] as const),
      ...sender.sender.map((m) => ['sender', m.domain] as const),
      ...sender.replyTo.map((m) => ['reply_to', m.domain] as const),
      ...sender.returnPath.map((m) => ['return_path', m.domain] as const),
      ...signatures.map((s) => ['dkim', s.domain ?? ''] as const),
    ];
    const inspected = roles
      .filter(([, domain]) => domain)
      .map(([role, domain]) => inspectDomain(role, domain));
    const mixed = inspected.filter((d) => d.mixedScript).map((d) => d.unicode);
    return {
      status: mixed.length ? 'warn' : 'pass',
      outputs: { domains: inspected.length, mixedScript: mixed },
      limitations: mixed.length ? ['A domain mixes writing systems in one label.'] : [],
      value: inspected,
    };
  });

  const candidates = await run('registry', async () => {
    const identities = await (deps.registry ?? emptyRegistry).identities();
    const found = fromBox
      ? matchClaim(
          { displayName: fromBox.displayName, address: fromBox.address, domain: fromBox.domain },
          identities,
        )
      : [];
    const unapproved = found.some((c) => !c.approvedDomain);
    const notes =
      identities.length === 0
        ? ['The trusted identity registry is empty.']
        : found.length === 0
          ? ['No registry identity matches this sender.']
          : [];
    return {
      status: identities.length === 0 ? 'skipped' : unapproved ? 'warn' : 'pass',
      inputs: { registryEntries: identities.length },
      outputs: {
        candidates: found.map((c) => ({ id: c.identityId, score: c.score, reasons: c.reasons })),
      },
      limitations: notes,
      value: found,
    };
  });

  record('rules', deps.clock(), { status: 'not_evaluated', limitations: [RULES_NOTE] });
  limitations.push(
    'Impersonation rules have not run, so this result cannot confirm who sent the message.',
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
    claimedIdentity: fromBox
      ? { displayName: fromBox.displayName, address: fromBox.address }
      : null,
    domains,
    candidates,
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
