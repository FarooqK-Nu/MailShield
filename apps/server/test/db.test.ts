import { getTableConfig, type SQLiteTable } from 'drizzle-orm/sqlite-core';
import { describe, expect, it } from 'vitest';
import { migrate, openDatabase } from '../src/db/open.ts';
import * as schema from '../src/db/schema.ts';

describe('database', () => {
  it('applies migrations once', () => {
    const db = openDatabase(':memory:');
    expect(migrate(db.sqlite)).toEqual([]);
  });

  it('matches the Drizzle schema column for column', () => {
    const db = openDatabase(':memory:');
    for (const table of Object.values(schema) as SQLiteTable[]) {
      const config = getTableConfig(table);
      const columns = db.sqlite.pragma(`table_info(${config.name})`) as {
        name: string;
        notnull: number;
        pk: number;
      }[];
      const actual = columns.map((c) => [c.name, c.notnull === 1 || c.pk === 1]).sort();
      const expected = config.columns.map((c) => [c.name, c.notNull || c.primary]).sort();
      expect(actual, config.name).toEqual(expected);
    }
  });

  it('enforces foreign keys and value checks', () => {
    const { sqlite } = openDatabase(':memory:');
    expect(() =>
      sqlite
        .prepare("INSERT INTO identity_alias (id, identity_id, alias) VALUES ('a', 'missing', 'x')")
        .run(),
    ).toThrow(/FOREIGN KEY/);
    expect(() =>
      sqlite
        .prepare(
          "INSERT INTO identity (id, kind, display_name, trust_state, created_at, updated_at) VALUES ('i', 'robot', 'x', 'unverified', 't', 't')",
        )
        .run(),
    ).toThrow(/CHECK/);
  });
});
