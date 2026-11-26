import { mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import * as schema from './schema.ts';

const MIGRATIONS = new URL('./migrations/', import.meta.url);

export type Db = ReturnType<typeof openDatabase>;

/**
 * Applies every migrations/NNNN_*.sql file not yet recorded, in name order, each in its own
 * transaction. Plain SQL files keep the schema reviewable (docs/decisions.md A-7).
 */
export function migrate(sqlite: Database.Database): string[] {
  sqlite.exec(
    'CREATE TABLE IF NOT EXISTS schema_migration (name TEXT PRIMARY KEY NOT NULL, applied_at TEXT NOT NULL)',
  );
  const done = new Set(
    sqlite
      .prepare('SELECT name FROM schema_migration')
      .all()
      .map((row) => (row as { name: string }).name),
  );
  const applied: string[] = [];
  const files = readdirSync(MIGRATIONS)
    .filter((f) => /^\d{4}_[\w-]+\.sql$/.test(f))
    .sort();
  for (const file of files) {
    if (done.has(file)) continue;
    const sql = readFileSync(new URL(file, MIGRATIONS), 'utf8');
    sqlite.transaction(() => {
      sqlite.exec(sql);
      sqlite
        .prepare('INSERT INTO schema_migration (name, applied_at) VALUES (?, ?)')
        .run(file, new Date().toISOString());
    })();
    applied.push(file);
  }
  return applied;
}

/** Opens (or creates) the SQLite file and brings it up to date. `:memory:` for tests. */
export function openDatabase(path: string) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const sqlite = new Database(path);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  migrate(sqlite);
  return Object.assign(drizzle(sqlite, { schema }), { sqlite });
}
