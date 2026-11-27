/**
 * The live Gmail receiver-trust strategy (docs/context.md §7, decision A-15), on synthetic
 * messages that copy Gmail's header order (fixtures/gmail/README.md).
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Evidence } from '@mailshield/contracts';
import { describe, expect, it } from 'vitest';
import {
  chooseTrustedReceiver,
  readReceiverResults,
  receivedByHost,
} from '../src/authentication/receiver-results.ts';
import type { DnsResolver } from '../src/dns/resolver.ts';
import { analyze } from '../src/pipeline.ts';
import { readRawHeaders } from '../src/parse/raw-headers.ts';

const ROOT = resolve(import.meta.dirname, '../../..');
const gmail = (name: string) => readFileSync(join(ROOT, 'fixtures/gmail', name));
const NOW = '2026-11-27T17:00:00.000Z';
const read = (name: string) => readReceiverResults(readRawHeaders(gmail(name)), 'gmail_api', NOW);
const trusted = (evidence: Evidence[]) => evidence.filter((e) => e.source === 'trusted_receiver');

describe('receivedByHost', () => {
  it('reads the by host and ignores comments', () => {
    expect(receivedByHost('from a.example (by evil.example) by mx.google.com with ESMTPS')).toBe(
      'mx.google.com',
    );
    expect(receivedByHost('by 2001:db8::1 with SMTP id x')).toBe('2001:db8::1');
    expect(receivedByHost('from a.example with SMTP')).toBeNull();
  });
});

describe('Gmail receiver trust', () => {
  it('trusts Google’s topmost result and splits it per method', () => {
    const evidence = trusted(read('genuine-pass.eml'));
    expect(evidence.map((e) => [e.kind, e.status])).toEqual([
      ['dkim', 'pass'],
      ['spf', 'pass'],
      ['dmarc', 'pass'],
    ]);
    expect(evidence[0]!.details.assumption).toMatch(/heuristic, not cryptographic proof/);
    expect(evidence.find((e) => e.kind === 'dmarc')!.domains).toEqual(['acme.example']);
  });

  it('maps a reported failure (softfail counts as fail)', () => {
    expect(trusted(read('genuine-dmarc-fail.eml')).map((e) => e.status)).toEqual([
      'fail',
      'fail',
      'fail',
    ]);
  });

  it('keeps a forged header below Google’s untrusted', () => {
    const evidence = read('forged-below-google.eml');
    expect(trusted(evidence).find((e) => e.kind === 'dmarc')!.status).toBe('fail');
    const forged = evidence.filter((e) => e.source === 'untrusted_header');
    expect(forged).toHaveLength(1);
    expect(forged[0]).toMatchObject({ id: 'receiver-1', status: 'untrusted' });
  });

  it.each([
    ['forged-no-google-hop.eml', /No Received header from a google.com server/],
    ['external-relay-above.eml', /relay\.forwarder\.example/],
  ])('trusts nothing in %s and says why', (name, reason) => {
    const evidence = read(name);
    expect(trusted(evidence)).toEqual([]);
    expect(evidence[0]).toMatchObject({ id: 'receiver-trust', status: 'unknown' });
    expect(evidence[0]!.reason).toMatch(reason);
  });

  it('needs an exact mx.google.com authserv-id', () => {
    const raw = Buffer.from(
      [
        'Received: from a.example by mx.google.com with ESMTPS id 1',
        'Authentication-Results: mx.google.com.evil.example; dmarc=pass header.from=acme.example',
        'From: a@acme.example',
        '',
        'x',
      ].join('\r\n'),
    );
    expect(chooseTrustedReceiver(readRawHeaders(raw))).toMatchObject({ trusted: false });
  });
});

const noDns: DnsResolver = { txt: async () => ({ status: 'nxdomain', records: [] }) };

describe('pipeline with a trusted Gmail result', () => {
  it('raises R6 and decides verdict row 3 on a trusted DMARC fail', async () => {
    const result = await analyze(
      { raw: gmail('genuine-dmarc-fail.eml'), source: 'gmail_api', messageRef: '18c0ffee' },
      { resolver: noDns, clock: () => new Date(NOW) },
    );
    expect(result.messageRef).toBe('18c0ffee');
    expect(result.stages.find((s) => s.stage === 'receiver')).toMatchObject({
      status: 'pass',
      outputs: { trusted: 3 },
    });
    expect(result.findings.some((f) => f.id.startsWith('R6:dmarc_fail'))).toBe(true);
    expect(result.verdict).toBe('authentication_concern');
    expect(result.verdictBasis.row).toBe(3);
  });
});

/**
 * Real messages downloaded from Gmail (Show original → Download original) under `private/`.
 * They are never committed, so this test is skipped in CI (decision A-13).
 */
const privateDir = join(ROOT, 'private');
const realMessages = existsSync(privateDir)
  ? readdirSync(privateDir).filter((f) => f.endsWith('.eml'))
  : [];

describe.skipIf(realMessages.length === 0)('real Gmail messages in private/', () => {
  // Numbered, not named: a downloaded file is usually named after its subject.
  it.each(realMessages.map((file, i) => [i + 1, file] as const))(
    'message #%i yields exactly one trusted Google result',
    (_n, file) => {
      const headers = readRawHeaders(readFileSync(join(privateDir, file)));
      const choice = chooseTrustedReceiver(headers);
      expect(choice.trusted).toBe(true);
      expect(choice.trusted && choice.index).toBe(0);
      const evidence = readReceiverResults(headers, 'gmail_api', NOW);
      expect(new Set(trusted(evidence).map((e) => e.details.position))).toEqual(new Set([0]));
      // The same bytes uploaded as a file are never trusted.
      expect(trusted(readReceiverResults(headers, 'eml_upload', NOW))).toEqual([]);
    },
  );
});
