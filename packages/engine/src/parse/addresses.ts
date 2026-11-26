import { domainToASCII, domainToUnicode } from 'node:url';
import type { Mailbox, SenderView } from '@mailshield/contracts';
import { addressParser, decodeWords } from 'postal-mime';
import { headerValues, type RawHeaders } from './raw-headers.ts';

function toMailbox(name: string, address: string): Mailbox {
  const at = address.lastIndexOf('@');
  const written = at === -1 ? '' : address.slice(at + 1);
  // domainToASCII() reads its input as a URL host, so refuse URL delimiters.
  const domain = /^[^\s/\\?#:%[\]]+$/.test(written) ? domainToASCII(written) : '';
  return {
    displayName: decodeWords(name).trim(),
    address,
    domain,
    domainUnicode: domain ? domainToUnicode(domain) : '',
  };
}

/** Parses first and decodes afterwards, so encoded commas cannot split a display name. */
export function parseMailboxes(value: string): Mailbox[] {
  return addressParser(value, { flatten: true })
    .filter((entry) => entry.address || entry.name)
    .map((entry) => toMailbox(entry.name ?? '', entry.address ?? ''));
}

export function readSender(headers: RawHeaders): SenderView {
  const mailboxes = (name: string) => headerValues(headers, name).flatMap(parseMailboxes);
  const text = (name: string) => {
    const value = headerValues(headers, name)[0];
    return value === undefined ? null : decodeWords(value);
  };
  const from = mailboxes('from');
  return {
    from,
    fromAmbiguous:
      headerValues(headers, 'from').length !== 1 || from.length !== 1 || !from[0]?.domain,
    sender: mailboxes('sender'),
    replyTo: mailboxes('reply-to'),
    returnPath: mailboxes('return-path'),
    subject: text('subject'),
    date: text('date'),
    messageId: text('message-id'),
  };
}
