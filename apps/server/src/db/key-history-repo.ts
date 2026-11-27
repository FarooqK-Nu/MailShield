import { randomUUID } from 'node:crypto';
import type { KeyObservation } from '@mailshield/contracts';
import { classifyKey, type KeyHistoryPort } from '@mailshield/engine';
import { and, asc, eq } from 'drizzle-orm';
import type { Db } from './open.ts';
import { keyObservations } from './schema.ts';

/** Keys seen on verified messages, per domain and selector. Opt-in; holds no message content. */
export class KeyHistoryRepo implements KeyHistoryPort {
  constructor(
    private readonly db: Db,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async observations(): Promise<readonly KeyObservation[]> {
    return this.list();
  }

  list(): KeyObservation[] {
    return this.db
      .select()
      .from(keyObservations)
      .orderBy(
        asc(keyObservations.domain),
        asc(keyObservations.selector),
        asc(keyObservations.firstSeen),
      )
      .all()
      .map((r) => ({
        id: r.id,
        domain: r.domain,
        selector: r.selector,
        fingerprint: r.fingerprintSha256,
        firstSeen: r.firstSeen,
        lastSeen: r.lastSeen,
        status: r.status,
      }));
  }

  /**
   * Records one verified key. The same classification the rule uses decides the status:
   * a known key only moves `last_seen`; a new selector marks the older current keys as rotated;
   * a changed key behind a known selector is stored as unexpected.
   */
  record(domain: string, selector: string, fingerprint: string): void {
    const now = this.clock().toISOString();
    this.db.transaction((tx) => {
      const history = this.list();
      const kind = classifyKey(history, domain, selector, fingerprint);
      if (kind === 'known' || kind === 'revoked') {
        tx.update(keyObservations)
          .set({ lastSeen: now })
          .where(
            and(
              eq(keyObservations.domain, domain),
              eq(keyObservations.selector, selector),
              eq(keyObservations.fingerprintSha256, fingerprint),
            ),
          )
          .run();
        return;
      }
      if (kind === 'rotation') {
        tx.update(keyObservations)
          .set({ status: 'rotated' })
          .where(and(eq(keyObservations.domain, domain), eq(keyObservations.status, 'current')))
          .run();
      }
      tx.insert(keyObservations)
        .values({
          id: randomUUID(),
          domain,
          selector,
          fingerprintSha256: fingerprint,
          firstSeen: now,
          lastSeen: now,
          status: kind === 'unexpected_change' ? 'unexpected' : 'current',
        })
        .run();
    });
  }

  /** The user's decision: this key must no longer be trusted. Returns false when unknown. */
  revoke(id: string): boolean {
    return (
      this.db
        .update(keyObservations)
        .set({ status: 'revoked' })
        .where(eq(keyObservations.id, id))
        .run().changes > 0
    );
  }

  clear(): number {
    return this.db.delete(keyObservations).run().changes;
  }
}
