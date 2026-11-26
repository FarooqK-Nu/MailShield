import { randomUUID } from 'node:crypto';
import { domainToUnicode } from 'node:url';
import {
  IdentityInput,
  IdentityPatch,
  KeyEnrollRequest,
  RegistryFile,
  type AuditAction,
  type AuditEvent,
  type Identity,
  type IdentityKind,
  type ImportResult,
  type PublicKeyRecord,
  type TrustState,
} from '@mailshield/contracts';
import { analyzeDomain, type RegistryPort } from '@mailshield/engine';
import { and, desc, eq, inArray, isNull } from 'drizzle-orm';
import type { Db } from './open.ts';
import { readPublicMaterial } from './public-key.ts';
import {
  approvedDomains,
  auditEvents,
  identities,
  identityAliases,
  publicKeyRecords,
  trustedAddresses,
} from './schema.ts';

export class RegistryError extends Error {
  constructor(
    readonly type: 'invalid_request' | 'not_found' | 'conflict',
    message: string,
  ) {
    super(message);
  }
}

export interface ListFilter {
  q?: string;
  kind?: IdentityKind;
  trustState?: TrustState;
  includeDeleted?: boolean;
}

type ParsedInput = ReturnType<typeof IdentityInput.parse>;
type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];

function normalizeDomains(domains: ParsedInput['domains']) {
  const seen = new Set<string>();
  return domains.flatMap((d) => {
    const parts = analyzeDomain(d.domain);
    if (!parts.registrable) {
      throw new RegistryError('invalid_request', `“${d.domain}” is not a registrable domain.`);
    }
    if (seen.has(parts.ascii)) return [];
    seen.add(parts.ascii);
    return [{ ...d, domainAscii: parts.ascii }];
  });
}

const unique = (values: string[]) => [...new Set(values)];

function toKeyRecord(row: typeof publicKeyRecords.$inferSelect): PublicKeyRecord {
  return {
    id: row.id,
    keyType: row.keyType,
    fingerprintSha256: row.fingerprintSha256,
    trustSource: row.trustSource,
    status: row.status,
    enrolledAt: row.enrolledAt,
    expiresAt: row.expiresAt,
  };
}

/** The registry, backed by SQLite. Every change writes an audit event in the same transaction. */
export class RegistryRepo implements RegistryPort {
  constructor(
    private readonly db: Db,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async identities(): Promise<readonly Identity[]> {
    return this.list();
  }

  list(filter: ListFilter = {}): Identity[] {
    const conditions = [
      filter.includeDeleted ? undefined : isNull(identities.deletedAt),
      filter.kind ? eq(identities.kind, filter.kind) : undefined,
      filter.trustState ? eq(identities.trustState, filter.trustState) : undefined,
    ].filter((c) => c !== undefined);
    const rows = this.db
      .select()
      .from(identities)
      .where(conditions.length ? and(...conditions) : undefined)
      .orderBy(identities.displayName)
      .all();
    const all = this.hydrate(this.db, rows);
    const q = filter.q?.trim().toLowerCase();
    if (!q) return all;
    return all.filter(
      (i) =>
        i.displayName.toLowerCase().includes(q) ||
        i.aliases.some((a) => a.alias.toLowerCase().includes(q)) ||
        i.domains.some((d) => d.domainAscii.includes(q) || d.domainUnicode.includes(q)) ||
        i.addresses.some((a) => a.address.includes(q)),
    );
  }

  get(id: string, db: Db | Tx = this.db): Identity {
    const row = db.select().from(identities).where(eq(identities.id, id)).get();
    if (!row) throw new RegistryError('not_found', 'No identity with that id.');
    return this.hydrate(db, [row])[0]!;
  }

  create(input: IdentityInput, actor: string, action: AuditAction = 'create'): Identity {
    const parsed = IdentityInput.parse(input);
    const domains = normalizeDomains(parsed.domains);
    const now = this.clock().toISOString();
    const id = randomUUID();
    return this.db.transaction((tx) => {
      tx.insert(identities)
        .values({
          id,
          kind: parsed.kind,
          displayName: parsed.displayName,
          trustState: parsed.trustState,
          provenanceUrl: parsed.provenanceUrl,
          notes: parsed.notes,
          lastReviewed: parsed.lastReviewed,
          createdAt: now,
          updatedAt: now,
        })
        .run();
      this.writeChildren(tx, id, {
        aliases: parsed.aliases,
        domains,
        addresses: parsed.addresses,
      });
      const after = this.get(id, tx);
      this.audit(tx, actor, id, action, null, after);
      return after;
    });
  }

  update(id: string, patch: IdentityPatch, actor: string): Identity {
    const parsed = IdentityPatch.parse(patch);
    const domains = parsed.domains ? normalizeDomains(parsed.domains) : undefined;
    return this.db.transaction((tx) => {
      const before = this.get(id, tx);
      if (before.deletedAt) throw new RegistryError('not_found', 'That identity was deleted.');
      const { aliases, addresses, ...fields } = parsed;
      tx.update(identities)
        .set({
          displayName: fields.displayName,
          trustState: fields.trustState,
          provenanceUrl: fields.provenanceUrl,
          notes: fields.notes,
          lastReviewed: fields.lastReviewed,
          updatedAt: this.clock().toISOString(),
        })
        .where(eq(identities.id, id))
        .run();
      this.writeChildren(tx, id, { aliases, domains, addresses }, true);
      const after = this.get(id, tx);
      this.audit(tx, actor, id, 'update', before, after);
      return after;
    });
  }

  /** Soft delete: the row stays, so the audit trail keeps its subject. */
  remove(id: string, actor: string): void {
    this.db.transaction((tx) => {
      const before = this.get(id, tx);
      if (before.deletedAt) throw new RegistryError('not_found', 'That identity was deleted.');
      const now = this.clock().toISOString();
      tx.update(identities)
        .set({ deletedAt: now, updatedAt: now })
        .where(eq(identities.id, id))
        .run();
      this.audit(tx, actor, id, 'delete', before, this.get(id, tx));
    });
  }

  addKey(id: string, request: KeyEnrollRequest, actor: string): PublicKeyRecord {
    const parsed = KeyEnrollRequest.parse(request);
    const material = readPublicMaterial(parsed.pem);
    return this.db.transaction((tx) => {
      const before = this.get(id, tx);
      if (before.deletedAt) throw new RegistryError('not_found', 'That identity was deleted.');
      const taken = tx
        .select({ id: publicKeyRecords.id })
        .from(publicKeyRecords)
        .where(eq(publicKeyRecords.fingerprintSha256, material.fingerprint))
        .get();
      if (taken) throw new RegistryError('conflict', 'This key is already enrolled.');
      const record = {
        id: randomUUID(),
        identityId: id,
        keyType: material.keyType,
        fingerprintSha256: material.fingerprint,
        trustSource: parsed.trustSource,
        status: 'active' as const,
        enrolledAt: this.clock().toISOString(),
        expiresAt: parsed.expiresAt ?? material.expiresAt,
      };
      tx.insert(publicKeyRecords).values(record).run();
      this.audit(tx, actor, id, 'key_added', before, this.get(id, tx));
      return toKeyRecord(record);
    });
  }

  auditTrail(entityId?: string, limit = 200): AuditEvent[] {
    return this.db
      .select()
      .from(auditEvents)
      .where(entityId ? eq(auditEvents.entityId, entityId) : undefined)
      .orderBy(desc(auditEvents.at))
      .limit(limit)
      .all()
      .map((row) => ({
        ...row,
        before: row.before === null ? null : JSON.parse(row.before),
        after: row.after === null ? null : JSON.parse(row.after),
      }));
  }

  exportFile(): RegistryFile {
    return {
      format: 'mailshield-registry',
      version: 1,
      exportedAt: this.clock().toISOString(),
      identities: this.list().map((i) => ({
        kind: i.kind,
        displayName: i.displayName,
        trustState: i.trustState,
        provenanceUrl: i.provenanceUrl,
        notes: i.notes,
        lastReviewed: i.lastReviewed,
        aliases: i.aliases.map((a) => a.alias),
        domains: i.domains.map((d) => ({
          domain: d.domainAscii,
          includeSubdomains: d.includeSubdomains,
          relationship: d.relationship,
        })),
        addresses: i.addresses.map((a) => a.address),
      })),
    };
  }

  /** Adds identities from a file; one with the same kind and name as an existing one is skipped. */
  importFile(file: RegistryFile, actor: string): ImportResult {
    const parsed = RegistryFile.parse(file);
    const existing = new Set(this.list().map((i) => `${i.kind}:${i.displayName.toLowerCase()}`));
    const skipped: string[] = [];
    let imported = 0;
    // Validate everything first, so a bad entry imports nothing.
    for (const entry of parsed.identities) normalizeDomains(entry.domains);
    for (const entry of parsed.identities) {
      const key = `${entry.kind}:${entry.displayName.toLowerCase()}`;
      if (existing.has(key)) {
        skipped.push(entry.displayName);
        continue;
      }
      this.create(entry, actor, 'import');
      existing.add(key);
      imported++;
    }
    return { imported, skipped };
  }

  private writeChildren(
    tx: Tx,
    id: string,
    lists: {
      aliases?: string[];
      domains?: ReturnType<typeof normalizeDomains>;
      addresses?: string[];
    },
    replace = false,
  ) {
    if (lists.aliases) {
      if (replace) tx.delete(identityAliases).where(eq(identityAliases.identityId, id)).run();
      for (const alias of unique(lists.aliases)) {
        tx.insert(identityAliases).values({ id: randomUUID(), identityId: id, alias }).run();
      }
    }
    if (lists.domains) {
      if (replace) tx.delete(approvedDomains).where(eq(approvedDomains.identityId, id)).run();
      for (const d of lists.domains) {
        tx.insert(approvedDomains)
          .values({
            id: randomUUID(),
            identityId: id,
            domainAscii: d.domainAscii,
            includeSubdomains: d.includeSubdomains,
            relationship: d.relationship,
          })
          .run();
      }
    }
    if (lists.addresses) {
      if (replace) tx.delete(trustedAddresses).where(eq(trustedAddresses.identityId, id)).run();
      for (const address of unique(lists.addresses.map((a) => a.toLowerCase()))) {
        tx.insert(trustedAddresses).values({ id: randomUUID(), identityId: id, address }).run();
      }
    }
  }

  private hydrate(db: Db | Tx, rows: (typeof identities.$inferSelect)[]): Identity[] {
    if (rows.length === 0) return [];
    const ids = rows.map((r) => r.id);
    const group = <T extends { identityId: string }>(items: T[]) => {
      const map = new Map<string, T[]>();
      for (const item of items)
        map.set(item.identityId, [...(map.get(item.identityId) ?? []), item]);
      return map;
    };
    const aliases = group(
      db.select().from(identityAliases).where(inArray(identityAliases.identityId, ids)).all(),
    );
    const domains = group(
      db.select().from(approvedDomains).where(inArray(approvedDomains.identityId, ids)).all(),
    );
    const addresses = group(
      db.select().from(trustedAddresses).where(inArray(trustedAddresses.identityId, ids)).all(),
    );
    const keys = group(
      db.select().from(publicKeyRecords).where(inArray(publicKeyRecords.identityId, ids)).all(),
    );
    return rows.map((row) => ({
      ...row,
      aliases: (aliases.get(row.id) ?? []).map(({ id, alias }) => ({ id, alias })),
      domains: (domains.get(row.id) ?? []).map((d) => ({
        id: d.id,
        domainAscii: d.domainAscii,
        domainUnicode: domainToUnicode(d.domainAscii),
        includeSubdomains: d.includeSubdomains,
        relationship: d.relationship,
      })),
      addresses: (addresses.get(row.id) ?? []).map(({ id, address }) => ({ id, address })),
      keys: (keys.get(row.id) ?? []).map(toKeyRecord),
    }));
  }

  private audit(
    tx: Tx,
    actor: string,
    entityId: string,
    action: AuditAction,
    before: unknown,
    after: unknown,
  ) {
    tx.insert(auditEvents)
      .values({
        id: randomUUID(),
        at: this.clock().toISOString(),
        actor,
        entityType: 'identity',
        entityId,
        action,
        before: before === null ? null : JSON.stringify(before),
        after: after === null ? null : JSON.stringify(after),
      })
      .run();
  }
}
