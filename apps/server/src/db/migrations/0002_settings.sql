-- Phase 6: user settings, and audit events for settings changes.
CREATE TABLE setting (
  key TEXT PRIMARY KEY NOT NULL,
  value TEXT NOT NULL
);

-- SQLite cannot change a CHECK constraint, so the audit table is rebuilt with 'settings' allowed.
CREATE TABLE audit_event_new (
  id TEXT PRIMARY KEY NOT NULL,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  entity_type TEXT NOT NULL CHECK (entity_type IN ('identity', 'registry', 'settings')),
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete', 'key_added', 'import')),
  before_json TEXT,
  after_json TEXT
);
INSERT INTO audit_event_new SELECT id, at, actor, entity_type, entity_id, action, before_json, after_json FROM audit_event;
DROP TABLE audit_event;
ALTER TABLE audit_event_new RENAME TO audit_event;
CREATE INDEX audit_event_entity ON audit_event (entity_id);
