import { index, integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';

/**
 * Registry and key history (docs/architecture.md §5.3). Raw messages, bodies and private
 * keys are never stored. Times are ISO 8601 strings. Keep in step with migrations/*.sql;
 * test/db.test.ts compares the two.
 */
export const identities = sqliteTable('identity', {
  id: text('id').primaryKey(),
  kind: text('kind', { enum: ['organization', 'person'] }).notNull(),
  displayName: text('display_name').notNull(),
  trustState: text('trust_state', {
    enum: ['unverified', 'user_trusted', 'independently_verified', 'revoked'],
  }).notNull(),
  provenanceUrl: text('provenance_url'),
  notes: text('notes'),
  lastReviewed: text('last_reviewed'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
  deletedAt: text('deleted_at'),
});

export const identityAliases = sqliteTable(
  'identity_alias',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id')
      .notNull()
      .references(() => identities.id, { onDelete: 'cascade' }),
    alias: text('alias').notNull(),
  },
  (t) => [index('identity_alias_identity').on(t.identityId)],
);

export const approvedDomains = sqliteTable(
  'approved_domain',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id')
      .notNull()
      .references(() => identities.id, { onDelete: 'cascade' }),
    domainAscii: text('domain_ascii').notNull(),
    includeSubdomains: integer('include_subdomains', { mode: 'boolean' }).notNull(),
    relationship: text('relationship', { enum: ['own', 'service_provider'] }).notNull(),
  },
  (t) => [index('approved_domain_identity').on(t.identityId)],
);

export const trustedAddresses = sqliteTable(
  'trusted_address',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id')
      .notNull()
      .references(() => identities.id, { onDelete: 'cascade' }),
    address: text('address').notNull(),
  },
  (t) => [index('trusted_address_identity').on(t.identityId)],
);

export const publicKeyRecords = sqliteTable(
  'public_key_record',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id')
      .notNull()
      .references(() => identities.id, { onDelete: 'cascade' }),
    keyType: text('key_type').notNull(),
    fingerprintSha256: text('fingerprint_sha256').notNull(),
    trustSource: text('trust_source').notNull(),
    status: text('status', { enum: ['active', 'retired', 'revoked'] }).notNull(),
    enrolledAt: text('enrolled_at').notNull(),
    expiresAt: text('expires_at'),
  },
  (t) => [uniqueIndex('public_key_record_fingerprint').on(t.fingerprintSha256)],
);

export const keyObservations = sqliteTable(
  'key_observation',
  {
    id: text('id').primaryKey(),
    domain: text('domain').notNull(),
    selector: text('selector').notNull(),
    fingerprintSha256: text('fingerprint_sha256').notNull(),
    firstSeen: text('first_seen').notNull(),
    lastSeen: text('last_seen').notNull(),
    status: text('status', { enum: ['current', 'rotated', 'unexpected', 'revoked'] }).notNull(),
  },
  (t) => [index('key_observation_domain_selector').on(t.domain, t.selector)],
);

export const auditEvents = sqliteTable(
  'audit_event',
  {
    id: text('id').primaryKey(),
    at: text('at').notNull(),
    actor: text('actor').notNull(),
    entityType: text('entity_type', { enum: ['identity', 'registry'] }).notNull(),
    entityId: text('entity_id').notNull(),
    action: text('action', {
      enum: ['create', 'update', 'delete', 'key_added', 'import'],
    }).notNull(),
    before: text('before_json'),
    after: text('after_json'),
  },
  (t) => [index('audit_event_entity').on(t.entityId)],
);
