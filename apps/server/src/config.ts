import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { z } from 'zod';

/** Fixed by the public key in the extension manifest. */
const DEFAULT_EXTENSION_ID = 'oijpcmifakangkecaplidfpgjhhidbop';
const REPO_ROOT = resolve(import.meta.dirname, '../../..');

const list = (value: string) =>
  value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

const Env = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(8787),
  ALLOWED_ORIGINS: z.string().default('http://127.0.0.1:5173,http://localhost:5173'),
  EXTENSION_ID: z
    .string()
    .regex(/^[a-p]{32}$/)
    .default(DEFAULT_EXTENSION_ID),
  DATA_DIR: z.string().default('.mailshield'),
  DNS_SERVERS: z
    .string()
    .default('')
    .transform(list)
    .pipe(z.array(z.string().refine((ip) => isIP(ip) !== 0, 'DNS_SERVERS takes IP addresses'))),
  DNS_TIMEOUT_MS: z.coerce.number().int().min(100).max(10_000).default(3000),
});

export interface Config {
  port: number;
  allowedOrigins: Set<string>;
  extensionOrigin: string;
  dataDir: string;
  dnsTimeoutMs: number;
  /** Undefined means the system resolvers. */
  dnsServers: string[] | undefined;
}

export function readConfig(env: NodeJS.ProcessEnv): Config {
  const parsed = Env.parse(env);
  const extensionOrigin = `chrome-extension://${parsed.EXTENSION_ID}`;
  return {
    port: parsed.PORT,
    allowedOrigins: new Set([...list(parsed.ALLOWED_ORIGINS), extensionOrigin]),
    extensionOrigin,
    dataDir: resolve(REPO_ROOT, parsed.DATA_DIR),
    dnsTimeoutMs: parsed.DNS_TIMEOUT_MS,
    dnsServers: parsed.DNS_SERVERS.length ? parsed.DNS_SERVERS : undefined,
  };
}
