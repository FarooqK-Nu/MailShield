import { randomUUID } from 'node:crypto';
import { SettingsInput, type AuditEvent } from '@mailshield/contracts';
import { desc, eq } from 'drizzle-orm';
import type { Db } from './open.ts';
import { auditEvents, settings } from './schema.ts';

export const DEFAULT_SETTINGS: SettingsInput = { historyEnabled: false, disabledRules: [] };

/** One local user's settings, stored as JSON values. Every change is audited. */
export class SettingsRepo {
  constructor(
    private readonly db: Db,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  get(): SettingsInput {
    const rows = new Map(
      this.db
        .select()
        .from(settings)
        .all()
        .map((r) => [r.key, r.value]),
    );
    const parsed = SettingsInput.safeParse({
      historyEnabled: JSON.parse(rows.get('historyEnabled') ?? 'false'),
      disabledRules: JSON.parse(rows.get('disabledRules') ?? '[]'),
    });
    return parsed.success ? parsed.data : DEFAULT_SETTINGS;
  }

  update(input: unknown, actor: string): SettingsInput {
    const next = SettingsInput.parse(input);
    const before = this.get();
    this.db.transaction((tx) => {
      for (const [key, value] of Object.entries(next)) {
        tx.insert(settings)
          .values({ key, value: JSON.stringify(value) })
          .onConflictDoUpdate({ target: settings.key, set: { value: JSON.stringify(value) } })
          .run();
      }
      tx.insert(auditEvents)
        .values({
          id: randomUUID(),
          at: this.clock().toISOString(),
          actor,
          entityType: 'settings',
          entityId: 'settings',
          action: 'update',
          before: JSON.stringify(before),
          after: JSON.stringify(next),
        })
        .run();
    });
    return next;
  }

  reset(actor: string): SettingsInput {
    return this.update(DEFAULT_SETTINGS, actor);
  }

  audit(limit = 20): AuditEvent[] {
    return this.db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.entityType, 'settings'))
      .orderBy(desc(auditEvents.at))
      .limit(limit)
      .all()
      .map((row) => ({
        ...row,
        before: row.before === null ? null : JSON.parse(row.before),
        after: row.after === null ? null : JSON.parse(row.after),
      }));
  }
}
