import { confusableKey, describeCodePoints, isMixedScript } from './confusables.ts';

/** Optimal string alignment (restricted Damerau-Levenshtein) table, by code point. */
function osaTable(s: string[], t: string[]): number[][] {
  const d: number[][] = Array.from({ length: s.length + 1 }, (_, i) =>
    Array.from({ length: t.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i <= s.length; i++) {
    for (let j = 1; j <= t.length; j++) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      let best = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && s[i - 1] === t[j - 2] && s[i - 2] === t[j - 1]) {
        best = Math.min(best, d[i - 2]![j - 2]! + 1);
      }
      d[i]![j] = best;
    }
  }
  return d;
}

export function osaDistance(a: string, b: string): number {
  const s = [...a];
  const t = [...b];
  return osaTable(s, t)[s.length]![t.length]!;
}

/** Edits allowed before two labels stop counting as lookalikes: ≤1 up to 6 chars, else ≤2. */
export function distanceThreshold(length: number): number {
  return length <= 6 ? 1 : 2;
}

/** Splits a label into words at hyphens, dots, underscores and digits-to-letters joins. */
export function tokens(label: string): string[] {
  return label
    .toLowerCase()
    .split(/[-_.\s]+/)
    .filter((t) => t.length > 0);
}

export interface CharDiff {
  /** Position in the observed string (code points). */
  index: number;
  kind: 'substituted' | 'inserted' | 'removed' | 'swapped';
  observed: string;
  expected: string;
  /** Code points of the observed characters, e.g. `U+0430 Cyrillic`. */
  observedCodePoints: string[];
}

/** Character-level differences between an observed and an expected string. */
export function charDiff(observed: string, expected: string): CharDiff[] {
  const s = [...observed];
  const t = [...expected];
  const d = osaTable(s, t);
  const describe = (chars: string[]) =>
    describeCodePoints(chars.join('')).map((c) => `${c.codePoint} ${c.script}`);

  const out: CharDiff[] = [];
  let i = s.length;
  let j = t.length;
  while (i > 0 || j > 0) {
    const here = d[i]![j]!;
    if (i > 0 && j > 0 && s[i - 1] === t[j - 1] && here === d[i - 1]![j - 1]) {
      i--;
      j--;
    } else if (i > 0 && j > 0 && here === d[i - 1]![j - 1]! + 1) {
      out.push({
        index: i - 1,
        kind: 'substituted',
        observed: s[i - 1]!,
        expected: t[j - 1]!,
        observedCodePoints: describe([s[i - 1]!]),
      });
      i--;
      j--;
    } else if (
      i > 1 &&
      j > 1 &&
      s[i - 1] === t[j - 2] &&
      s[i - 2] === t[j - 1] &&
      here === d[i - 2]![j - 2]! + 1
    ) {
      const pair = [s[i - 2]!, s[i - 1]!];
      out.push({
        index: i - 2,
        kind: 'swapped',
        observed: pair.join(''),
        expected: t[j - 2]! + t[j - 1]!,
        observedCodePoints: describe(pair),
      });
      i -= 2;
      j -= 2;
    } else if (i > 0 && here === d[i - 1]![j]! + 1) {
      out.push({
        index: i - 1,
        kind: 'inserted',
        observed: s[i - 1]!,
        expected: '',
        observedCodePoints: describe([s[i - 1]!]),
      });
      i--;
    } else {
      out.push({
        index: i,
        kind: 'removed',
        observed: '',
        expected: t[j - 1]!,
        observedCodePoints: [],
      });
      j--;
    }
  }
  return out.reverse();
}

export type LookalikeReason =
  | 'confusable_skeleton'
  | 'mixed_script'
  | 'edit_distance'
  | 'token_confusable'
  | 'token_edit_distance';

export interface LabelComparison {
  observed: string;
  expected: string;
  identical: boolean;
  lookalike: boolean;
  /** Strong: the two look the same to a reader (skeleton or mixed-script match). */
  strength: 'strong' | 'weak' | null;
  reasons: LookalikeReason[];
  distance: number;
  /** The token of `observed` that resembles `expected`, when the match came from a token. */
  matchedToken: string | null;
  diff: CharDiff[];
}

/**
 * Compares a registrable label (no public suffix) with a registry label, in Unicode form.
 * Identical labels are not lookalikes; matching is about labels that differ but look alike.
 */
export function compareLabels(observed: string, expected: string): LabelComparison {
  const o = observed.toLowerCase().normalize('NFC');
  const e = expected.toLowerCase().normalize('NFC');
  const base = { observed: o, expected: e, matchedToken: null as string | null };
  if (o === e) {
    return {
      ...base,
      identical: true,
      lookalike: false,
      strength: null,
      reasons: [],
      distance: 0,
      diff: [],
    };
  }

  const reasons: LookalikeReason[] = [];
  const sameSkeleton = confusableKey(o) === confusableKey(e);
  if (sameSkeleton) reasons.push('confusable_skeleton');
  if (sameSkeleton && isMixedScript(o)) reasons.push('mixed_script');
  const distance = osaDistance(o, e);
  if (!sameSkeleton && distance <= distanceThreshold([...e].length) && [...e].length >= 4) {
    reasons.push('edit_distance');
  }

  let matchedToken: string | null = null;
  const parts = tokens(o);
  if (reasons.length === 0 && parts.length > 1) {
    for (const token of parts) {
      if (token === e) {
        // The brand appears as a whole word inside a longer label, e.g. `acme-support`.
        matchedToken = token;
        break;
      }
      if (confusableKey(token) === confusableKey(e)) {
        reasons.push('token_confusable');
        matchedToken = token;
        break;
      }
      if ([...e].length >= 4 && osaDistance(token, e) <= distanceThreshold([...e].length)) {
        reasons.push('token_edit_distance');
        matchedToken = token;
        break;
      }
    }
  }

  const strong = reasons.some((r) => r === 'confusable_skeleton' || r === 'token_confusable');
  const lookalike = reasons.length > 0;
  return {
    ...base,
    matchedToken,
    identical: false,
    lookalike,
    strength: lookalike ? (strong ? 'strong' : 'weak') : null,
    reasons,
    distance,
    diff: lookalike || matchedToken ? charDiff(matchedToken ?? o, e) : [],
  };
}
