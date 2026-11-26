import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { RequestHandler } from 'express';
import { z } from 'zod';
import { sendProblem } from './errors.ts';

const MAX_ATTEMPTS = 5;
const MAX_SESSIONS = 10;

const sha256 = (value: string) => createHash('sha256').update(value).digest();
/** Compares digests, so length and content do not leak through timing. */
const matches = (value: string, digest: Buffer) => timingSafeEqual(sha256(value), digest);

export interface SessionStore {
  load(): string[];
  save(hashes: string[]): void;
}

/** Keeps only token hashes on disk. Delete the file to revoke every client. */
export function fileSessionStore(dataDir: string): SessionStore {
  const file = join(dataDir, 'sessions.json');
  return {
    load() {
      try {
        return z
          .array(z.string().regex(/^[0-9a-f]{64}$/))
          .parse(JSON.parse(readFileSync(file, 'utf8')));
      } catch {
        return [];
      }
    },
    save(hashes) {
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(file, JSON.stringify(hashes), { mode: 0o600 });
    },
  };
}

export class Pairing {
  private code = '';
  private attempts = 0;
  private sessions: string[];
  private readonly store: SessionStore;
  private readonly announce: (code: string) => void;

  constructor(store: SessionStore, announce: (code: string) => void) {
    this.store = store;
    this.announce = announce;
    this.sessions = store.load();
    this.newCode();
  }

  /** Each code works once, and is replaced after too many wrong guesses. */
  exchange(code: string): string | null {
    if (!matches(code, sha256(this.code))) {
      if (++this.attempts >= MAX_ATTEMPTS) this.newCode();
      return null;
    }
    const token = randomBytes(32).toString('base64url');
    this.sessions = [...this.sessions, sha256(token).toString('hex')].slice(-MAX_SESSIONS);
    this.store.save(this.sessions);
    this.newCode();
    return token;
  }

  isValid(token: string): boolean {
    return this.sessions.some((hash) => matches(token, Buffer.from(hash, 'hex')));
  }

  private newCode(): void {
    this.code = String(randomInt(0, 100_000_000)).padStart(8, '0');
    this.attempts = 0;
    this.announce(this.code);
  }
}

export function requireToken(pairing: Pairing): RequestHandler {
  return (req, res, next) => {
    const token = /^Bearer ([\w-]+)$/.exec(req.headers.authorization ?? '')?.[1];
    if (token && pairing.isValid(token)) return next();
    sendProblem(res, 'unauthorized');
  };
}
