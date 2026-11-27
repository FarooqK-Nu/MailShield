import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { evaluate, listFixtures, loadEvaluation } from '../src/index.ts';

const labels = listFixtures();
const count = (pick: (l: (typeof labels)[number]) => boolean) => labels.filter(pick).length;

describe('evaluation corpus (roadmap Phase 7)', () => {
  it('has at least 40 fixtures with the required category minimums', () => {
    expect(labels.length).toBeGreaterThanOrEqual(40);
    expect(count((l) => l.category === 'legitimate')).toBeGreaterThanOrEqual(10);
    expect(count((l) => l.category === 'impersonation')).toBeGreaterThanOrEqual(10);
    expect(count((l) => l.category === 'tampered')).toBeGreaterThanOrEqual(8);
    expect(count((l) => l.truth === 'unknown')).toBeGreaterThanOrEqual(8);
    expect(count((l) => l.category === 'edge')).toBeGreaterThanOrEqual(4);
  });

  it('keeps development and held-out fixtures in separate folders', () => {
    for (const l of labels) expect(l.eml.startsWith(`${l.split}/`)).toBe(true);
    expect(count((l) => l.split === 'heldout')).toBeGreaterThanOrEqual(10);
    expect(count((l) => l.split === 'dev')).toBeGreaterThanOrEqual(20);
  });

  it('uses only reserved example domains for senders', () => {
    for (const l of labels) {
      const raw = readFileSync(
        new URL(`../../../fixtures/eml/${l.eml}`, import.meta.url),
        'latin1',
      );
      const from = /^From:.*$/im.exec(raw)![0];
      expect(from).toMatch(/\.example/);
    }
  });
});

describe('evaluate()', { timeout: 60_000 }, () => {
  let all: Awaited<ReturnType<typeof evaluate>>;
  beforeAll(async () => {
    all = await evaluate('all');
  });

  it('computes metrics whose counts add up', async () => {
    const report = all;
    const c = report.binary.confusion;
    const suspicious = report.counts.byTruth.suspicious ?? 0;
    const legitimate = report.counts.byTruth.legitimate ?? 0;
    expect(c.truePositive + c.falseNegative + c.abstainedSuspicious).toBe(suspicious);
    expect(c.falsePositive + c.trueNegative + c.abstainedLegitimate).toBe(legitimate);
    expect(report.binary.recall.denominator).toBe(suspicious);
    expect(report.unknown.abstentionRate.denominator).toBe(report.counts.byTruth.unknown);
    expect(report.counts.total).toBe(labels.length);
  });

  it('never produces a false positive on legitimate fixtures (critical regression)', async () => {
    const report = all;
    expect(report.binary.confusion.falsePositive).toBe(0);
  });

  it('flags every tampered fixture (critical regression)', async () => {
    const report = all;
    for (const c of report.cases.filter((x) => x.category === 'tampered')) {
      expect(c.outcome, c.id).toBe('flagged');
    }
  });

  it('never clears a suspicious fixture', async () => {
    const report = all;
    expect(report.binary.confusion.falseNegative).toBe(0);
  });

  it('matches the committed results file, so the page never shows stale numbers', async () => {
    for (const split of ['dev', 'heldout', 'all'] as const) {
      const live = await evaluate(split);
      const saved = loadEvaluation(split);
      expect(saved, `${split}.json is missing; run tools/evaluate.ts`).not.toBeNull();
      expect({ ...saved!, generatedAt: '' }).toEqual({ ...live, generatedAt: '' });
    }
  });
});
