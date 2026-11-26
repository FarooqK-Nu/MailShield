-- Trusted identity registry, key history and audit trail (docs/architecture.md §5.3).
CREATE TABLE identity (
  id TEXT PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('organization', 'person')),
  display_name TEXT NOT NULL,
  trust_state TEXT NOT NULL
    CHECK (trust_state IN ('unverified', 'user_trusted', 'independently_verified', 'revoked')),
  provenance_url TEXT,
  notes TEXT,
  last_reviewed TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);

CREATE TABLE identity_alias (
  id TEXT PRIMARY KEY NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  alias TEXT NOT NULL
);
CREATE INDEX identity_alias_identity ON identity_alias (identity_id);

CREATE TABLE approved_domain (
  id TEXT PRIMARY KEY NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  domain_ascii TEXT NOT NULL,
  include_subdomains INTEGER NOT NULL CHECK (include_subdomains IN (0, 1)),
  relationship TEXT NOT NULL CHECK (relationship IN ('own', 'service_provider'))
);
CREATE INDEX approved_domain_identity ON approved_domain (identity_id);

CREATE TABLE trusted_address (
  id TEXT PRIMARY KEY NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  address TEXT NOT NULL
);
CREATE INDEX trusted_address_identity ON trusted_address (identity_id);

CREATE TABLE public_key_record (
  id TEXT PRIMARY KEY NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  key_type TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL,
  trust_source TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'retired', 'revoked')),
  enrolled_at TEXT NOT NULL,
  expires_at TEXT
);
CREATE UNIQUE INDEX public_key_record_fingerprint ON public_key_record (fingerprint_sha256);

CREATE TABLE key_observation (
  id TEXT PRIMARY KEY NOT NULL,
  domain TEXT NOT NULL,
  selector TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('current', 'rotated', 'unexpected', 'revoked'))
);
CREATE INDEX key_observation_domain_selector ON key_observation (domain, selector);

CREATE TABLE audit_event (
  id TEXT PRIMARY KEY NOT NULL,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  entity_type TEXT NOT NULL CHECK (entity_type IN ('identity', 'registry')),
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete', 'key_added', 'import')),
  before_json TEXT,
  after_json TEXT
);
CREATE INDEX audit_event_entity ON audit_event (entity_id);
