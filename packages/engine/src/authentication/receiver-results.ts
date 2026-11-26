import type { Evidence, InputSource } from '@mailshield/contracts';
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

/**
 * Authentication-Results headers as evidence. Anything that arrived inside the message
 * itself — an upload, a paste, a fixture — is shown for information as `untrusted_header`
 * and never used as proof (invariant 3). The live Gmail trust strategy (docs/context.md §7)
 * is built with the extension in Phase 4; until then Gmail messages are treated the same.
 */
export function readReceiverResults(
  headers: RawHeaders,
  source: InputSource,
  observedAt: string,
): Evidence[] {
  return headerValues(headers, 'authentication-results').map((value, i) => {
    const parsed = parseAuthResults(value);
    const summary = parsed.methods.map((m) => `${m.method}=${m.result}`).join(', ');
    return {
      id: `receiver-${i}`,
      kind: 'receiver',
      source: 'untrusted_header',
      status: 'untrusted',
      domains: [],
      reason: `Reported by “${parsed.authservId || 'unknown'}”${summary ? `: ${summary}` : ''}. This header came with the message and anyone can write it, so it is not used as proof.`,
      observedAt,
      details: { position: i, inputSource: source, ...parsed },
    };
  });
}
