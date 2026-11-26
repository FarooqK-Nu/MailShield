/** Spike tool: verify a downloaded .eml with live DNS. Prints no body or recipient data. */
import { readFile } from 'node:fs/promises';
import { keyFingerprint, LiveResolver, rawDkimVerify } from '../packages/engine/src/index.ts';

const path = process.argv[2];
if (!path) {
  console.error('Usage: pnpm spike:eml <path-to.eml>');
  process.exit(1);
}

const { results, headerFrom } = await rawDkimVerify(await readFile(path), {
  resolver: new LiveResolver(),
});
console.log(`From domain(s): ${headerFrom.map((a) => a.split('@').at(-1)).join(', ') || 'none'}`);
for (const r of results) {
  console.log({
    domain: r.signingDomain,
    selector: r.selector,
    algorithm: r.algo,
    result: r.status.result,
    comment: r.status.comment || undefined,
    bodyHashMatches: r.bodyHash ? r.bodyHash === r.bodyHashExpecting : undefined,
    keyBits: r.modulusLength,
    keyFingerprint: r.publicKey ? keyFingerprint(r.publicKey) : undefined,
  });
}
