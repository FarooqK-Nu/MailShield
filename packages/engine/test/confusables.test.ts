import { describe, expect, it } from 'vitest';
import {
  confusableKey,
  confusablesVersion,
  describeCodePoints,
  isMixedScript,
  scriptsOf,
  skeleton,
} from '../src/identity/confusables.ts';

describe('skeleton', () => {
  it('maps a Cyrillic а to Latin a', () => {
    expect(skeleton('pаypal')).toBe(skeleton('paypal'));
  });

  it('is case-sensitive, so confusableKey folds case', () => {
    expect(skeleton('micros0ft')).not.toBe(skeleton('microsoft'));
    expect(confusableKey('micros0ft')).toBe(confusableKey('microsoft'));
    expect(confusableKey('PAYPAL')).toBe(confusableKey('paypal'));
  });

  it.each([
    ['acrne', 'acme'],
    ['g00gle', 'google'],
    ['examp1e', 'example'],
  ])('%s looks like %s', (a, b) => expect(confusableKey(a)).toBe(confusableKey(b)));

  it('keeps different names different', () => {
    expect(confusableKey('globex')).not.toBe(confusableKey('acme'));
  });

  it('reports the data version', () => {
    expect(confusablesVersion()).toBe('18.0.0');
  });
});

describe('mixed script', () => {
  it('flags Latin mixed with Cyrillic', () => {
    expect(scriptsOf('pаypal')).toEqual(['Latin', 'Cyrillic']);
    expect(isMixedScript('pаypal')).toBe(true);
  });

  it.each(['bücher', 'почта', 'example-2', '東京', 'ひらがなカタカナ漢字', '한국어'])(
    'does not flag single-language %s',
    (label) => expect(isMixedScript(label)).toBe(false),
  );
});

describe('describeCodePoints', () => {
  it('names each code point, its script and its lookalike', () => {
    const [p, a] = describeCodePoints('pа');
    expect(p).toMatchObject({ codePoint: 'U+0070', script: 'Latin', looksLike: null });
    expect(a).toMatchObject({ codePoint: 'U+0430', script: 'Cyrillic', looksLike: 'a' });
  });
});
