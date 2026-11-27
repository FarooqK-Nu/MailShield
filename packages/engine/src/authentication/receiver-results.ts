import { isIP } from 'node:net';
import type { Evidence, EvidenceStatus, InputSource } from '@mailshield/contracts';
import { headerValues, type RawHeaders } from '../parse/raw-headers.ts';

export interface ReceiverMethod {
  method: string;
  result: string;
  /** Properties such as `header.d` or `smtp.mailfrom`. */
  properties: Record<string, string>;
}

export interface ParsedAuthResults {
  authservId: string;
  methods: ReceiverMethod[];
}

/** Removes RFC 5322 comments (nested parentheses) outside quoted strings. */
function stripComments(value: string): string {
  let out = '';
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i]!;
    if (c === '\\' && i + 1 < value.length) {
      if (depth === 0) out += c + value[i + 1];
      i++;
    } else if (quoted) {
      out += c;
      if (c === '"') quoted = false;
    } else if (c === '"' && depth === 0) {
      quoted = true;
      out += c;
    } else if (c === '(') depth++;
    else if (c === ')' && depth > 0) depth--;
    else if (depth === 0) out += c;
  }
  return out;
}

/** Parses one Authentication-Results header (RFC 8601) for display. Never trusted by itself. */
export function parseAuthResults(value: string): ParsedAuthResults {
  const [head = '', ...parts] = stripComments(value).split(';');
  const authservId = head.trim().split(/\s+/)[0] ?? '';
  const methods: ReceiverMethod[] = [];
  for (const part of parts) {
    const words = part.trim().split(/\s+/).filter(Boolean);
    const first = words.shift();
    const match = first && /^([\w.-]+)(?:\/\d+)?=([\w-]+)$/.exec(first);
    if (!match) continue;
    const properties: Record<string, string> = {};
    for (const word of words) {
      const prop = /^([\w-]+\.[\w.-]+)=(.+)$/.exec(word);
      if (prop) properties[prop[1]!.toLowerCase()] = prop[2]!.replace(/^"|"$/g, '');
    }
    methods.push({ method: match[1]!.toLowerCase(), result: match[2]!.toLowerCase(), properties });
  }
  return { authservId, methods };
}

const GOOGLE_AUTHSERV = 'mx.google.com';

/** The `by` host of a Received header, ignoring comments. Null when there is no `by` clause. */
export function receivedByHost(value: string): string | null {
  return /(?:^|\s)by\s+([^\s;]+)/i.exec(stripComments(value))?.[1]?.toLowerCase() ?? null;
}

const isGoogleName = (host: string) => host === 'google.com' || host.endsWith('.google.com');
/** Gmail's internal hops record only an address, for example `by 2002:a05:6400:...`. */
const isAddress = (host: string) => isIP(host.replace(/^\[|\]$/g, '')) !== 0;

export type ReceiverTrust =
  { trusted: true; index: number; assumption: string } | { trusted: false; reason: string };

/**
 * The live Gmail strategy (docs/context.md §7, decision A-15). Accept the topmost
 * Authentication-Results header written by mx.google.com, but only when every Received header
 * above it was added inside Google and at least one of them names a google.com host. Gmail adds
 * its own headers at the top of the message, so anything the sender wrote sits below them. This
 * is a documented heuristic, not cryptographic proof.
 */
export function chooseTrustedReceiver(headers: RawHeaders): ReceiverTrust {
  let googleHop = false;
  let position = 0;
  for (const field of headers.fields) {
    if (field.name === 'received') {
      const by = receivedByHost(field.value);
      if (by === null || !(isGoogleName(by) || isAddress(by))) {
        return {
          trusted: false,
          reason: `A server outside Google (${by ?? 'unnamed'}) added a Received header above Google's Authentication-Results, so the provider's results cannot be attributed to Google.`,
        };
      }
      if (isGoogleName(by)) googleHop = true;
    } else if (field.name === 'authentication-results') {
      const index = position++;
      if (parseAuthResults(field.value).authservId.toLowerCase() !== GOOGLE_AUTHSERV) continue;
      if (!googleHop) {
        return {
          trusted: false,
          reason:
            'No Received header from a google.com server appears above the Authentication-Results header, so it may not have been written by Google.',
        };
      }
      return {
        trusted: true,
        index,
        assumption:
          "Taken as Google's own result because it is the topmost Authentication-Results from mx.google.com and every Received header above it was added inside Google. This is a documented heuristic, not cryptographic proof.",
      };
    }
  }
  return {
    trusted: false,
    reason: 'The message has no Authentication-Results header from mx.google.com.',
  };
}

const RECEIVER_STATUS: Record<string, EvidenceStatus> = {
  pass: 'pass',
  fail: 'fail',
  softfail: 'fail',
  none: 'missing',
  temperror: 'temporary_error',
};

const TRUSTED_KINDS = new Set(['dkim', 'spf', 'dmarc', 'arc']);

function untrustedRecord(
  value: string,
  i: number,
  source: InputSource,
  observedAt: string,
  why: string,
): Evidence {
  const parsed = parseAuthResults(value);
  const summary = parsed.methods.map((m) => `${m.method}=${m.result}`).join(', ');
  return {
    id: `receiver-${i}`,
    kind: 'receiver',
    source: 'untrusted_header',
    status: 'untrusted',
    domains: [],
    reason: `Reported by “${parsed.authservId || 'unknown'}”${summary ? `: ${summary}` : ''}. ${why}`,
    observedAt,
    details: { position: i, inputSource: source, ...parsed },
  };
}

/** One record per method in the trusted header, so rules can use, for example, its DMARC result. */
function trustedRecords(value: string, i: number, assumption: string, observedAt: string) {
  const parsed = parseAuthResults(value);
  return parsed.methods
    .filter((m) => TRUSTED_KINDS.has(m.method))
    .map((m, j): Evidence => ({
      id: `receiver-${i}-${j}`,
      kind: m.method as Evidence['kind'],
      source: 'trusted_receiver',
      status: RECEIVER_STATUS[m.result] ?? 'unknown',
      domains: [
        m.properties['header.d'],
        m.properties['header.from'],
        m.properties['smtp.mailfrom'],
      ]
        .map((d) => d?.replace(/^.*@/, '').toLowerCase())
        .filter((d): d is string => !!d),
      reason: `Google's receiving server (${parsed.authservId}) reports ${m.method}=${m.result}.`,
      observedAt,
      details: {
        position: i,
        authservId: parsed.authservId,
        method: m.method,
        result: m.result,
        properties: m.properties,
        assumption,
      },
    }));
}

/**
 * Authentication-Results headers as evidence. Anything that arrived inside the message
 * itself — an upload, a paste, a fixture — is shown for information as `untrusted_header`
 * and never used as proof (invariant 3). Only a message fetched from the Gmail API can yield
 * `trusted_receiver` evidence, through `chooseTrustedReceiver`.
 */
export function readReceiverResults(
  headers: RawHeaders,
  source: InputSource,
  observedAt: string,
): Evidence[] {
  const values = headerValues(headers, 'authentication-results');
  if (source !== 'gmail_api') {
    return values.map((v, i) =>
      untrustedRecord(
        v,
        i,
        source,
        observedAt,
        'This header came with the message and anyone can write it, so it is not used as proof.',
      ),
    );
  }
  const trust = chooseTrustedReceiver(headers);
  const out: Evidence[] = [];
  if (!trust.trusted) {
    out.push({
      id: 'receiver-trust',
      kind: 'receiver',
      source: 'untrusted_header',
      status: 'unknown',
      domains: [],
      reason: `Gmail's own authentication results could not be identified. ${trust.reason}`,
      observedAt,
      details: { inputSource: source },
    });
  }
  values.forEach((v, i) => {
    if (trust.trusted && i === trust.index)
      out.push(...trustedRecords(v, i, trust.assumption, observedAt));
    else
      out.push(
        untrustedRecord(
          v,
          i,
          source,
          observedAt,
          'Only the topmost result from Google is trusted; this one is shown for information.',
        ),
      );
  });
  return out;
}
