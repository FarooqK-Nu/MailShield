import { readFileSync } from 'node:fs';
import {
  LAB_MUTATIONS,
  type AnalysisResult,
  type LabRunResponse,
  type LabScenario,
} from '@mailshield/contracts';
import { analyze, DEFAULT_RULE_CONFIG, type RuleConfig } from '@mailshield/engine';
import { fixtureRegistry } from './fixture-registry.ts';
import { FixtureResolver, TIMEOUT, type FixtureZone } from './fixture-resolver.ts';
import { dkimRecord, signMessage } from './sign.ts';

const KEYS = new URL('../../../fixtures/keys/', import.meta.url);
const SIGN_TIME = new Date('2026-06-01T10:00:00Z');
/** Fixed clock: lab results never depend on today's date. */
const NOW = new Date('2026-06-01T12:00:00Z');

const ACME = 'acme.example';
/** Eve's look-alike domain ("rn" instead of "m"). She really controls its DNS. */
const EVE = 'acrne.example';

/** Read once and kept in memory. These are TEST-ONLY keys that guard nothing. */
let cachedKeys: Record<string, string> | undefined;
function keys(): Record<string, string> {
  cachedKeys ??= Object.fromEntries(
    ['lab-acme-s2025', 'lab-acme-s2026', 'lab-eve'].map((name) => [
      name,
      readFileSync(new URL(`TEST-ONLY-${name}.pem`, KEYS), 'utf8'),
    ]),
  );
  return cachedKeys;
}
const acmeKey = (selector: string) => keys()[`lab-acme-${selector}`]!;
const eveKey = () => keys()['lab-eve']!;

interface Signing {
  domain: string;
  selector: string;
  key: string;
}

/** Which key signs, and under which d= and s=. Mutations that act at signing time change it. */
function signingFor(scenario: LabScenario, notes: string[]): Signing | null {
  const m = new Set(scenario.mutations);
  if (scenario.signer === 'none') return null;
  let selector = scenario.selector;
  if (scenario.signer === 'acme' && m.has('rotateSelector')) {
    selector = selector === 's2025' ? 's2026' : 's2025';
    notes.push(`Acme rotated its signing key: the message is signed with selector ${selector}.`);
  }
  const own: Signing =
    scenario.signer === 'acme'
      ? { domain: ACME, selector, key: acmeKey(selector) }
      : { domain: EVE, selector: 's2025', key: eveKey() };
  if (m.has('swapKey')) {
    const other = scenario.signer === 'acme' ? "Eve's" : "Acme's";
    notes.push(`The key was swapped: the signature claims d=${own.domain} but uses ${other} key.`);
    return { ...own, key: scenario.signer === 'acme' ? eveKey() : acmeKey('s2025') };
  }
  return own;
}

function buildMessage(scenario: LabScenario): string {
  const { displayName, from, replyTo, subject, body } = scenario.message;
  return [
    `From: ${displayName ? `"${displayName}" <${from}>` : from}`,
    'To: alice@example.org',
    'Date: Mon, 01 Jun 2026 10:00:00 +0000',
    `Subject: ${subject}`,
    ...(replyTo ? [`Reply-To: ${replyTo}`] : []),
    'Message-ID: <lab-1@lab.example>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    ...body.split(/\r?\n/),
    '',
  ].join('\r\n');
}

/** The published DNS records. Acme has two selectors; Eve has her own. */
function buildZone(): FixtureZone {
  return {
    [`s2025._domainkey.${ACME}`]: dkimRecord(acmeKey('s2025')),
    [`s2026._domainkey.${ACME}`]: dkimRecord(acmeKey('s2026')),
    [`_dmarc.${ACME}`]: 'v=DMARC1; p=reject',
    [`s2025._domainkey.${EVE}`]: dkimRecord(eveKey()),
    [`_dmarc.${EVE}`]: 'v=DMARC1; p=none',
  };
}

const splitAt = (text: string) => {
  const i = text.indexOf('\r\n\r\n');
  return [text.slice(0, i), text.slice(i)] as const;
};

/** Edits on the finished bytes, made after signing, as an attacker in transit would. */
function mutateBytes(text: string, scenario: LabScenario, notes: string[]): string {
  const m = new Set(scenario.mutations);
  let out = text;
  if (m.has('editBody')) {
    const [head, body] = splitAt(out);
    const i = body.search(/[a-z]/);
    out =
      i >= 0
        ? head + body.slice(0, i) + body[i]!.toUpperCase() + body.slice(i + 1)
        : head + body + 'x';
    notes.push('One character of the body was changed after signing.');
  }
  if (m.has('changeSignedSubject')) {
    out = out.replace(/^Subject: .*$/m, (line) => `${line}!`);
    notes.push('The Subject header, which the signature covers, was changed after signing.');
  }
  if (m.has('alterUnsignedHeader')) {
    const [head, body] = splitAt(out);
    const forged = 'Reply-To: Acme Accounts <accounts@payhelp.example>';
    out =
      (/^Reply-To: /m.test(head)
        ? head.replace(/^Reply-To: .*$/m, forged)
        : head.replace(/^Message-ID: /m, `${forged}\r\nMessage-ID: `)) + body;
    notes.push(
      'Reply-To was changed after signing. The signature does not cover Reply-To, so DKIM cannot notice.',
    );
  }
  if (m.has('removeSignature')) {
    out = out.replace(/^DKIM-Signature:[^\r\n]*(\r\n[ \t][^\r\n]*)*\r\n/, '');
    notes.push('The DKIM-Signature header was removed.');
  }
  return out;
}

async function build(scenario: LabScenario) {
  const notes: string[] = [];
  const unsigned = buildMessage(scenario);
  const signing = signingFor(scenario, notes);
  let signed = unsigned;
  if (signing) {
    signed = (
      await signMessage(unsigned, {
        domain: signing.domain,
        selector: signing.selector,
        privateKey: signing.key,
        signTime: SIGN_TIME,
      })
    ).toString();
  } else {
    notes.push('The message is not signed.');
  }

  const zone = buildZone();
  if (signing) {
    const name = `${signing.selector}._domainkey.${signing.domain}`;
    if (scenario.mutations.includes('dnsMissing')) {
      delete zone[name];
      notes.push(`DNS no longer publishes ${name}.`);
    } else if (scenario.mutations.includes('dnsTimeout')) {
      zone[name] = TIMEOUT;
      notes.push(`The DNS lookup for ${name} times out.`);
    }
  }
  return { message: mutateBytes(signed, scenario, notes), zone, notes };
}

function run(message: string, zone: FixtureZone, disabled: string[]): Promise<AnalysisResult> {
  const config: RuleConfig = {
    ...DEFAULT_RULE_CONFIG,
    enabled: {
      ...DEFAULT_RULE_CONFIG.enabled,
      ...Object.fromEntries(disabled.map((id) => [id, false])),
    },
  };
  return analyze(
    { raw: Buffer.from(message), source: 'lab' },
    // Fixture DNS and the fictional registry only. There is no live resolver in this file.
    { resolver: new FixtureResolver(zone), registry: fixtureRegistry, clock: () => NOW, config },
  );
}

/**
 * Builds, signs and mutates a synthetic message, then runs the real engine over it. The
 * baseline is the same scenario with no mutations, so the UI can compare hashes and keys.
 */
export async function runScenario(scenario: LabScenario): Promise<LabRunResponse> {
  const ordered = LAB_MUTATIONS.filter((m) => scenario.mutations.includes(m));
  const mutated = await build({ ...scenario, mutations: ordered });
  const baseline = await build({ ...scenario, mutations: [] });
  return {
    result: await run(mutated.message, mutated.zone, scenario.disabledRules),
    baseline: await run(baseline.message, baseline.zone, scenario.disabledRules),
    notes: mutated.notes,
    rawMessage: mutated.message,
  };
}
