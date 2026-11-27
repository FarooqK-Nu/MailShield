import { describe, expect, it } from 'vitest';
import { readHint } from '../src/content/read-hint.ts';
import {
  addressOf,
  compareWithHint,
  toApiId,
  type MessageMetadata,
} from '../src/shared/selection.ts';

describe('toApiId', () => {
  it('takes the hexadecimal legacy id as it is', () => {
    expect(toApiId('18c0ffee12345678', null)).toBe('18c0ffee12345678');
  });

  it('converts #msg-f:<decimal> to the same hexadecimal id', () => {
    const decimal = BigInt('0x18c0ffee12345678').toString(10);
    expect(toApiId(null, `#msg-f:${decimal}`)).toBe('18c0ffee12345678');
  });

  it('rejects anything else', () => {
    expect(toApiId('../x', null)).toBeNull();
    expect(toApiId(null, '#thread-f:123')).toBeNull();
    expect(toApiId(null, null)).toBeNull();
  });
});

describe('addressOf', () => {
  it.each([
    ['Acme <Billing@Acme.example>', 'billing@acme.example'],
    ['billing@acme.example', 'billing@acme.example'],
    ['"Acme, Inc." <a@acme.example>', 'a@acme.example'],
    ['Acme Billing', null],
  ])('%s → %s', (from, address) => expect(addressOf(from)).toBe(address));
});

describe('compareWithHint', () => {
  const meta: MessageMetadata = {
    id: '18c0ffee12345678',
    from: 'Acme <billing@acme.example>',
    fromAddress: 'billing@acme.example',
    subject: 'Invoice 42',
    date: '',
    sizeEstimate: 1,
  };
  const hint = { id: meta.id, fromEmail: 'Billing@acme.example', fromName: 'Acme' };

  it('matches, ignoring case and a reply prefix on the conversation subject', () => {
    expect(compareWithHint(hint, 'Re: invoice  42', meta)).toEqual([]);
  });

  it('reports a different sender or subject', () => {
    const diff = compareWithHint({ ...hint, fromEmail: 'eve@evil.example' }, 'Payroll', meta);
    expect(diff).toHaveLength(2);
    expect(diff[0]).toMatch(/eve@evil\.example.*billing@acme\.example/);
  });
});

/** A minimal stand-in for the four DOM methods `readHint` uses. */
interface FakeEl {
  attrs: Record<string, string>;
  sender?: FakeEl;
}
function fakeDocument(subject: string | null, elements: FakeEl[]): Document {
  const element = (el: FakeEl) => ({
    getAttribute: (name: string) => el.attrs[name] ?? null,
    querySelector: (sel: string) =>
      sel === 'span.gD[email]' && el.sender ? element(el.sender) : null,
  });
  return {
    querySelectorAll: () => elements.map(element),
    querySelector: (sel: string) =>
      sel === 'h2.hP' && subject ? { textContent: ` ${subject} ` } : null,
  } as unknown as Document;
}

describe('readHint (Gmail page reader)', () => {
  const sender = (email: string, name: string): FakeEl => ({ attrs: { email, name } });

  it('lists expanded messages once each and skips collapsed ones', () => {
    const doc = fakeDocument('Invoice 42', [
      {
        attrs: { 'data-legacy-message-id': '18c0ffee12345678' },
        sender: sender('a@acme.example', 'Acme'),
      },
      { attrs: { 'data-legacy-message-id': '18c0ffee12345679' } },
      {
        attrs: { 'data-legacy-message-id': '18c0ffee12345678' },
        sender: sender('a@acme.example', 'Acme'),
      },
    ]);
    expect(readHint(doc)).toEqual({
      subject: 'Invoice 42',
      messages: [{ id: '18c0ffee12345678', fromEmail: 'a@acme.example', fromName: 'Acme' }],
    });
  });

  it('reports nothing when no message is open', () => {
    expect(readHint(fakeDocument('Inbox', []))).toEqual({ subject: null, messages: [] });
  });
});
