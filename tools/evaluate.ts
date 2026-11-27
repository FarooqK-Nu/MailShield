/**
 * Evaluation runner: tsx tools/evaluate.ts [--split dev|heldout|all]
 * Writes fixtures/evaluation/<split>.json. Thresholds are tuned on dev only; the held-out file
 * is generated once for the report and is not used to change any rule.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { evaluate } from '../packages/lab/src/index.ts';

const arg = process.argv.indexOf('--split');
const split = (arg >= 0 ? process.argv[arg + 1] : 'all') as 'dev' | 'heldout' | 'all';
if (!['dev', 'heldout', 'all'].includes(split)) throw new Error('Use --split dev|heldout|all.');

const report = await evaluate(split);
const dir = new URL('../fixtures/evaluation/', import.meta.url);
mkdirSync(dir, { recursive: true });
writeFileSync(new URL(`${split}.json`, dir), `${JSON.stringify(report, null, 2)}\n`);

const pct = (r: { numerator: number; denominator: number; value: number | null }) =>
  r.value === null ? 'n/a' : `${(r.value * 100).toFixed(1)}% (${r.numerator}/${r.denominator})`;
console.log(`split=${split} total=${report.counts.total}`);
console.log(
  `precision ${pct(report.binary.precision)}  recall ${pct(report.binary.recall)}  F1 ${report.binary.f1?.toFixed(3) ?? 'n/a'}`,
);
console.log(
  `unknown-case abstention ${pct(report.unknown.abstentionRate)}  overall abstention ${pct(report.overallAbstentionRate)}`,
);
for (const c of report.cases.filter((c) => c.disagreement)) {
  console.log(`  disagreement: ${c.id} (${c.truth} -> ${c.outcome})`);
}
