import { z } from 'zod';

const Count = z.number().int().nonnegative();
const Ratio = z.number().min(0).max(1).nullable();

/** A ratio with the counts behind it, so a reader can always see the denominator. */
export const Rate = z.object({ numerator: Count, denominator: Count, value: Ratio });
export type Rate = z.infer<typeof Rate>;

export const EvaluationCase = z.object({
  id: z.string(),
  title: z.string(),
  category: z.string(),
  split: z.enum(['dev', 'heldout']),
  truth: z.enum(['legitimate', 'suspicious', 'unknown']),
  verdict: z.string(),
  /** What the engine did with it: flagged, cleared or abstained. */
  outcome: z.enum(['flagged', 'cleared', 'abstained']),
  /** True when the outcome contradicts the ground truth. */
  disagreement: z.boolean(),
  explanation: z.string(),
  findings: z.array(z.object({ ruleId: z.string(), title: z.string(), severity: z.string() })),
});
export type EvaluationCase = z.infer<typeof EvaluationCase>;

/** The only data the dashboard's evaluation page renders (written by tools/evaluate.ts). */
export const EvaluationReport = z.object({
  generatedAt: z.iso.datetime(),
  split: z.enum(['dev', 'heldout', 'all']),
  counts: z.object({
    total: Count,
    byCategory: z.record(z.string(), Count),
    byTruth: z.record(z.string(), Count),
  }),
  /** Only messages whose truth is legitimate or suspicious. Abstentions are not guessed. */
  binary: z.object({
    confusion: z.object({
      truePositive: Count,
      falsePositive: Count,
      trueNegative: Count,
      falseNegative: Count,
      abstainedSuspicious: Count,
      abstainedLegitimate: Count,
    }),
    precision: Rate,
    recall: Rate,
    f1: Ratio,
  }),
  /** Messages whose truth is unknown, reported separately. */
  unknown: z.object({
    abstentionRate: Rate,
    flagged: Count,
    cleared: Count,
  }),
  overallAbstentionRate: Rate,
  cases: z.array(EvaluationCase),
  notes: z.array(z.string()),
});
export type EvaluationReport = z.infer<typeof EvaluationReport>;
