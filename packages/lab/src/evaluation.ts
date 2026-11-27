import { readFileSync } from 'node:fs';
import { EvaluationReport, type EvaluationCase, type Rate } from '@mailshield/contracts';
import { analyze } from '@mailshield/engine';
import { fixtureRegistry } from './fixture-registry.ts';
import { FixtureResolver } from './fixture-resolver.ts';
import { listFixtures, loadFixture } from './fixtures.ts';

type Split = 'dev' | 'heldout' | 'all';
type Outcome = EvaluationCase['outcome'];

const OUTCOME: Record<string, Outcome> = {
  possible_impersonation: 'flagged',
  authentication_concern: 'flagged',
  no_concerning_mismatch: 'cleared',
  identity_unverified: 'abstained',
};

const rate = (numerator: number, denominator: number): Rate => ({
  numerator,
  denominator,
  value: denominator === 0 ? null : numerator / denominator,
});

/**
 * Runs every fixture of a split through the real engine (fixture DNS and registry, fixed clock)
 * and compares the outcome with the ground truth recorded in the label.
 *
 * Definitions (documented because the numbers are meaningless without them):
 * - A positive is a suspicious message; "flagged" means possible_impersonation or
 *   authentication_concern.
 * - precision = flagged suspicious / all flagged among legitimate and suspicious messages.
 * - recall = flagged suspicious / all suspicious messages. A suspicious message that the engine
 *   abstained on counts as missed, so abstaining never improves recall.
 * - Messages whose truth is unknown are excluded from precision, recall and F1.
 */
export async function evaluate(split: Split, now = new Date()): Promise<EvaluationReport> {
  const labels = listFixtures().filter((l) => split === 'all' || l.split === split);
  const cases: EvaluationCase[] = [];

  for (const label of labels) {
    const fixture = loadFixture(label.id)!;
    const result = await analyze(
      { raw: fixture.raw, source: 'fixture' },
      {
        resolver: new FixtureResolver(fixture.zone),
        registry: fixtureRegistry,
        clock: () => new Date(label.now),
      },
    );
    const outcome = OUTCOME[result.verdict]!;
    const disagreement =
      (label.truth === 'legitimate' && outcome !== 'cleared') ||
      (label.truth === 'suspicious' && outcome !== 'flagged') ||
      (label.truth === 'unknown' && outcome !== 'abstained');
    cases.push({
      id: label.id,
      title: label.title,
      category: label.category,
      split: label.split,
      truth: label.truth,
      verdict: result.verdict,
      outcome,
      disagreement,
      explanation: explain(label.truth, outcome, label.description),
      findings: result.findings.map(({ ruleId, title, severity }) => ({ ruleId, title, severity })),
    });
  }

  const of = (truth: string, outcome?: Outcome) =>
    cases.filter((c) => c.truth === truth && (!outcome || c.outcome === outcome)).length;
  const count = (key: 'category' | 'truth') => {
    const out: Record<string, number> = {};
    for (const c of cases) out[c[key]] = (out[c[key]] ?? 0) + 1;
    return out;
  };
  const tp = of('suspicious', 'flagged');
  const fp = of('legitimate', 'flagged');
  const precision = rate(tp, tp + fp);
  const recall = rate(tp, of('suspicious'));
  const p = precision.value;
  const r = recall.value;

  return EvaluationReport.parse({
    generatedAt: now.toISOString(),
    split,
    counts: { total: cases.length, byCategory: count('category'), byTruth: count('truth') },
    binary: {
      confusion: {
        truePositive: tp,
        falsePositive: fp,
        trueNegative: of('legitimate', 'cleared'),
        falseNegative: of('suspicious', 'cleared'),
        abstainedSuspicious: of('suspicious', 'abstained'),
        abstainedLegitimate: of('legitimate', 'abstained'),
      },
      precision,
      recall,
      f1: p === null || r === null || p + r === 0 ? null : (2 * p * r) / (p + r),
    },
    unknown: {
      abstentionRate: rate(of('unknown', 'abstained'), of('unknown')),
      flagged: of('unknown', 'flagged'),
      cleared: of('unknown', 'cleared'),
    },
    overallAbstentionRate: rate(
      cases.filter((c) => c.outcome === 'abstained').length,
      cases.length,
    ),
    cases,
    notes: [
      'All messages are synthetic and use reserved .example domains. These figures describe this fixture set only and are not an estimate of accuracy on real mail.',
      'Ground truth is set when a fixture is created and does not depend on the engine output.',
      'No authorised real messages were available, so none are included.',
    ],
  });
}

function explain(truth: string, outcome: Outcome, description: string): string {
  const base = `${description} `;
  if (truth === 'legitimate' && outcome === 'flagged')
    return `${base}False positive: a legitimate message was flagged.`;
  if (truth === 'legitimate' && outcome === 'abstained')
    return `${base}Not cleared: the engine abstained on a legitimate message.`;
  if (truth === 'suspicious' && outcome === 'cleared')
    return `${base}False negative: a suspicious message was cleared.`;
  if (truth === 'suspicious' && outcome === 'abstained')
    return `${base}Missed: the engine abstained, which counts against recall.`;
  if (truth === 'unknown' && outcome === 'flagged')
    return `${base}The engine raised a concern on a case that cannot be judged from the message alone (for example a legitimate forward). The wording shown to the user is a concern, not an accusation.`;
  if (truth === 'unknown' && outcome === 'cleared')
    return `${base}The engine cleared a case that cannot be judged from the message alone.`;
  return `${base}Agrees with the ground truth.`;
}

/** The report written by tools/evaluate.ts, or null when it has not been generated. */
export function loadEvaluation(split: Split): EvaluationReport | null {
  const file = new URL(`../../../fixtures/evaluation/${split}.json`, import.meta.url);
  try {
    return EvaluationReport.parse(JSON.parse(readFileSync(file, 'utf8')));
  } catch {
    return null;
  }
}
