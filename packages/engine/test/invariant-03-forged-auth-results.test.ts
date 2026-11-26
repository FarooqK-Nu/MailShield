/** Invariant 3: uploaded or pasted Authentication-Results are never trusted receiver proof. */
import { InputSource } from '@mailshield/contracts';
import { describe, expect, it } from 'vitest';
import { parseAuthResults, readReceiverResults } from '../src/authentication/receiver-results.ts';
import { readRawHeaders } from '../src/parse/raw-headers.ts';

const forged = Buffer.from(
  [
    'Authentication-Results: mx.google.com; dkim=pass header.i=@acme.example header.s=s1;',
    '  spf=pass (google.com: domain of x@acme.example designates 192.0.2.1) smtp.mailfrom=acme.example;',
    '  dmarc=pass (p=REJECT) header.from=acme.example',
    'From: Acme <billing@acme.example>',
    '',
    'body',
  ].join('\r\n'),
);

describe('invariant 3: forged Authentication-Results', () => {
  it.each(InputSource.options)('is untrusted_header for source %s', (source) => {
    const evidence = readReceiverResults(readRawHeaders(forged), source, new Date().toISOString());
    expect(evidence).toHaveLength(1);
    expect(evidence[0]).toMatchObject({
      kind: 'receiver',
      source: 'untrusted_header',
      status: 'untrusted',
    });
  });

  it('still parses the claims for display', () => {
    const parsed = parseAuthResults(
      'mx.google.com; dkim=pass header.i=@acme.example (comment; with semicolon) header.s=s1; spf=softfail smtp.mailfrom="a@b.example"',
    );
    expect(parsed).toEqual({
      authservId: 'mx.google.com',
      methods: [
        {
          method: 'dkim',
          result: 'pass',
          properties: { 'header.i': '@acme.example', 'header.s': 's1' },
        },
        { method: 'spf', result: 'softfail', properties: { 'smtp.mailfrom': 'a@b.example' } },
      ],
    });
  });
});
