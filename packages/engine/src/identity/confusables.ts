import { readFileSync } from 'node:fs';

/** UTS #39 confusable mappings, loaded once from the committed Unicode data file. */
let table: Map<number, string> | undefined;
let version: string | undefined;

function load(): Map<number, string> {
  if (table) return table;
  const text = readFileSync(new URL('../../data/confusables.txt', import.meta.url), 'utf8');
  version = /^# Version: (\S+)/m.exec(text)?.[1] ?? 'unknown';
  table = new Map();
  for (const line of text.split('\n')) {
    const match = /^([0-9A-F]+)\s*;\s*([0-9A-F ]+?)\s*;/.exec(line);
    if (!match) continue;
    const target = match[2]!.split(' ').map((hex) => String.fromCodePoint(parseInt(hex, 16)));
    table.set(parseInt(match[1]!, 16), target.join(''));
  }
  return table;
}

/** Unicode version of the confusables data, for display next to results. */
export function confusablesVersion(): string {
  load();
  return version!;
}

/** UTS #39 skeleton: NFD, map every code point through confusables.txt, NFD again. */
export function skeleton(value: string): string {
  const map = load();
  let out = '';
  for (const char of value.normalize('NFD')) out += map.get(char.codePointAt(0)!) ?? char;
  return out.normalize('NFD');
}

/**
 * Case-insensitive comparison key for domain labels and names. Skeletons are case-sensitive
 * (`0` maps to `O`), so fold case and map again until stable.
 */
export function confusableKey(value: string): string {
  let key = value.toLowerCase();
  for (let i = 0; i < 4; i++) {
    const next = skeleton(key).toLowerCase();
    if (next === key) break;
    key = next;
  }
  return key;
}

const SCRIPTS = [
  'Latin',
  'Cyrillic',
  'Greek',
  'Armenian',
  'Georgian',
  'Hebrew',
  'Arabic',
  'Devanagari',
  'Bengali',
  'Thai',
  'Cherokee',
  'Han',
  'Hiragana',
  'Katakana',
  'Hangul',
  'Bopomofo',
] as const;
const SCRIPT_TESTS = SCRIPTS.map((name) => [name, new RegExp(`^\\p{Script=${name}}$`, 'u')]);

/** Script of one character; 'Common' covers digits, hyphens and punctuation. */
export function scriptOf(char: string): string {
  if (/^[\p{Script=Common}\p{Script=Inherited}]$/u.test(char)) return 'Common';
  for (const [name, test] of SCRIPT_TESTS) if ((test as RegExp).test(char)) return name as string;
  return 'Other';
}

/** Distinct scripts in a string, ignoring Common and Inherited characters. */
export function scriptsOf(value: string): string[] {
  const found = new Set<string>();
  for (const char of value.normalize('NFC')) {
    const script = scriptOf(char);
    if (script !== 'Common') found.add(script);
  }
  return [...found];
}

/** Script combinations that are normal in one language (UTS #39 "highly restrictive"). */
const ALLOWED_MIXES = [
  ['Han', 'Hiragana', 'Katakana', 'Latin'],
  ['Han', 'Hangul', 'Latin'],
  ['Han', 'Bopomofo', 'Latin'],
];

/**
 * True when one label mixes scripts in a way no single language does, such as Latin with
 * Cyrillic. A label written entirely in one script is never flagged.
 */
export function isMixedScript(value: string): boolean {
  const scripts = scriptsOf(value);
  if (scripts.length <= 1) return false;
  return !ALLOWED_MIXES.some((allowed) => scripts.every((s) => allowed.includes(s)));
}

export interface CodePointInfo {
  char: string;
  /** e.g. `U+0430` */
  codePoint: string;
  script: string;
  /** What the character looks like, when confusables.txt maps it to something else. */
  looksLike: string | null;
}

export function describeCodePoints(value: string): CodePointInfo[] {
  const map = load();
  return [...value.normalize('NFC')].map((char) => {
    const cp = char.codePointAt(0)!;
    const target = map.get(cp);
    return {
      char,
      codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`,
      script: scriptOf(char),
      looksLike: target && target !== char ? target : null,
    };
  });
}
