import type { KeyObservation } from '@mailshield/contracts';

/** Read-only view of what the user has seen before (opt-in history; docs/architecture.md §5.3). */
export interface KeyHistoryPort {
  observations(): Promise<readonly KeyObservation[]>;
}

export type KeyClass =
  /** Nothing has been seen for this domain. */
  | 'first_contact'
  /** This exact key was seen before for this selector. */
  | 'known'
  /** A new selector for a known domain: normal key rotation. */
  | 'rotation'
  /** The same selector now has a different key. */
  | 'unexpected_change'
  /** The user marked this key as revoked. */
  | 'revoked';

/** One pure classification, shared by rule R8 (reading) and the service (recording). */
export function classifyKey(
  history: readonly KeyObservation[],
  domain: string,
  selector: string,
  fingerprint: string,
): KeyClass {
  const same = history.filter((o) => o.domain === domain);
  if (same.some((o) => o.fingerprint === fingerprint && o.status === 'revoked')) return 'revoked';
  if (same.length === 0) return 'first_contact';
  if (same.some((o) => o.selector === selector && o.fingerprint === fingerprint)) return 'known';
  if (same.some((o) => o.selector === selector)) return 'unexpected_change';
  return 'rotation';
}
