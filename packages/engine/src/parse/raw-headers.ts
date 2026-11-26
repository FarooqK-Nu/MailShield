import { AnalysisError, LIMITS } from '../intake/limits.ts';

export interface HeaderField {
  /** Lower-cased field name. */
  name: string;
  /** Unfolded value, not RFC 2047 decoded. */
  value: string;
  /** Byte offset of the field in the original message. */
  offset: number;
}

export interface RawHeaders {
  /** Every occurrence, in message order. */
  fields: HeaderField[];
  /** Offset of the first body byte, or null when there is no blank line. */
  bodyOffset: number | null;
  /** Lines in the header block that are neither a field nor a continuation. */
  malformedLines: number;
}

const FIELD = /^([\x21-\x39\x3b-\x7e]+)[ \t]*:(.*)$/s;

/** The authoritative header view. Reads the original bytes and never modifies them. */
export function readRawHeaders(raw: Buffer): RawHeaders {
  const fields: HeaderField[] = [];
  let malformedLines = 0;
  let bodyOffset: number | null = null;
  let current: { text: string; offset: number } | null = null;

  const flush = () => {
    if (!current) return;
    const match = FIELD.exec(current.text);
    if (match) {
      fields.push({
        name: match[1]!.toLowerCase(),
        value: match[2]!.trim(),
        offset: current.offset,
      });
      if (fields.length > LIMITS.headerFields) {
        throw new AnalysisError('mime_limits_exceeded', 'The message has too many header fields.');
      }
    } else {
      malformedLines++;
    }
    current = null;
  };

  let offset = 0;
  while (offset < raw.length) {
    const newline = raw.indexOf(0x0a, offset);
    const next = newline === -1 ? raw.length : newline + 1;
    let end = newline === -1 ? raw.length : newline;
    if (end > offset && raw[end - 1] === 0x0d) end--;

    if (next > LIMITS.headerBytes && end > offset) {
      throw new AnalysisError('mime_limits_exceeded', 'The message headers are too large.');
    }
    if (end === offset) {
      bodyOffset = next;
      break;
    }

    const line = raw.toString('utf8', offset, end);
    if (current && (line.startsWith(' ') || line.startsWith('\t'))) {
      current.text += line;
    } else {
      flush();
      // An mbox "From " separator line is not a header.
      if (!(offset === 0 && line.startsWith('From '))) current = { text: line, offset };
    }
    offset = next;
  }
  flush();

  return { fields, bodyOffset, malformedLines };
}

export const headerValues = (headers: RawHeaders, name: string): string[] =>
  headers.fields.filter((f) => f.name === name).map((f) => f.value);
