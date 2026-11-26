import { describe, expect, it } from 'vitest';
import {
  charDiff,
  compareLabels,
  distanceThreshold,
  osaDistance,
  tokens,
} from '../src/identity/similarity.ts';

describe('osaDistance', () => {
  it.each([
    ['acme', 'acme', 0],
    ['acme', 'acne', 1],
    ['acme', 'amce', 1],
    ['acme', 'acmee', 1],
    ['globex', 'glbex', 1],
    ['kitten', 'sitting', 3],
  ])('%s → %s is %i', (a, b, n) => expect(osaDistance(a, b)).toBe(n));

  it('counts code points, not UTF-16 units', () => {
    expect(osaDistance('a𝐚', 'aa')).toBe(1);
  });

  it('scales the threshold with length', () => {
    expect(distanceThreshold(6)).toBe(1);
    expect(distanceThreshold(7)).toBe(2);
  });
});

describe('tokens', () => {
  it('splits at separators', () => {
    expect(tokens('Micros0ft-Support_team')).toEqual(['micros0ft', 'support', 'team']);
  });
});

describe('charDiff', () => {
  it('names the substituted code point', () => {
    expect(charDiff('pаypal', 'paypal')).toEqual([
      {
        index: 1,
        kind: 'substituted',
        observed: 'а',
        expected: 'a',
        observedCodePoints: ['U+0430 Cyrillic'],
      },
    ]);
  });

  it('reports swaps, insertions and removals', () => {
    expect(charDiff('amce', 'acme').map((d) => d.kind)).toEqual(['swapped']);
    expect(charDiff('acmee', 'acme').map((d) => d.kind)).toEqual(['inserted']);
    expect(charDiff('acm', 'acme').map((d) => d.kind)).toEqual(['removed']);
  });
});

describe('compareLabels', () => {
  it('does not call an identical label a lookalike', () => {
    expect(compareLabels('acme', 'ACME')).toMatchObject({ identical: true, lookalike: false });
  });

  it('flags a Cyrillic homograph as strong, with the exact character', () => {
    const result = compareLabels('аcme', 'acme');
    expect(result).toMatchObject({ lookalike: true, strength: 'strong' });
    expect(result.reasons).toEqual(['confusable_skeleton', 'mixed_script']);
    expect(result.diff[0]).toMatchObject({ observed: 'а', expected: 'a' });
  });

  it('flags a digit substitution inside a longer label through its token', () => {
    const result = compareLabels('micros0ft-support', 'microsoft');
    expect(result).toMatchObject({
      lookalike: true,
      strength: 'strong',
      matchedToken: 'micros0ft',
    });
    expect(result.diff).toMatchObject([{ observed: '0', expected: 'o' }]);
  });

  it('flags small edits as weak', () => {
    expect(compareLabels('globx', 'globex')).toMatchObject({
      lookalike: true,
      strength: 'weak',
      reasons: ['edit_distance'],
    });
  });

  it('records a whole-word brand token without calling it a lookalike', () => {
    expect(compareLabels('acme-billing', 'acme')).toMatchObject({
      lookalike: false,
      matchedToken: 'acme',
    });
  });

  it.each([
    ['globex', 'acme'],
    ['ibm', 'ibn'], // too short for edit-distance matching
    ['initech', 'acme'],
  ])('leaves %s and %s apart', (a, b) => expect(compareLabels(a, b).lookalike).toBe(false));
});
