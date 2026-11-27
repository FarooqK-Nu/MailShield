import { LiveResolver } from '@mailshield/engine';
import { buildApp } from './app.ts';
import { readConfig } from './config.ts';
import { openDatabase } from './db/open.ts';
import { KeyHistoryRepo } from './db/key-history-repo.ts';
import { RegistryRepo } from './db/registry-repo.ts';
import { SettingsRepo } from './db/settings-repo.ts';
import { dnsWarning } from './dns-check.ts';
import { fileSessionStore, Pairing } from './middleware/pairing-auth.ts';
import { createLogger } from './middleware/redact-logger.ts';

const config = readConfig(process.env);

// The code goes to the console only, never through the logger.
const pairing = new Pairing(fileSessionStore(config.dataDir), (code) => {
  console.log(`\n  MailShield pairing code: ${code}\n`);
});

const resolver = new LiveResolver({
  timeoutMs: config.dnsTimeoutMs,
  servers: config.dnsServers,
});
// Runtime check for invariant 7: live analysis must never run on fixture DNS.
if (!(resolver instanceof LiveResolver)) throw new Error('Live analysis needs the live resolver.');
void dnsWarning(resolver).then((warning) => warning && console.warn(warning));

const db = openDatabase(config.dbPath);
const registry = new RegistryRepo(db);
const settings = new SettingsRepo(db);
const history = new KeyHistoryRepo(db);

const app = buildApp({
  config,
  resolver,
  registry,
  settings,
  history,
  pairing,
  logger: createLogger(),
  clock: () => new Date(),
});

app.listen(config.port, '127.0.0.1', (error) => {
  if (error) throw error;
  console.log(`MailShield service on http://127.0.0.1:${config.port}`);
});
