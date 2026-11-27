import { LAB_DEFAULTS, type LabScenario } from '@mailshield/contracts';
import { runScenario } from '@mailshield/lab';
import { describe, expect, it } from 'vitest';
import { CHALLENGES } from '../src/features/lab/challenges.ts';

const solves = async (scenario: LabScenario) => {
  const run = await runScenario(scenario);
  return CHALLENGES.filter((c) => c.solved(scenario, run)).map((c) => c.id);
};
const legit = (mutations: LabScenario['mutations']): LabScenario => ({
  ...LAB_DEFAULTS.legitimate,
  mutations,
});

describe('guided challenges', () => {
  it('are solved by exactly the intended actions', async () => {
    expect(await solves(legit([]))).toEqual([]);
    expect(await solves(legit(['editBody']))).toEqual(['one-character']);
    expect(await solves(legit(['alterUnsignedHeader']))).toEqual(['unsigned-header']);
    expect(await solves(legit(['rotateSelector']))).toEqual(['rotation']);
    expect(await solves(LAB_DEFAULTS.lookalike)).toEqual(['lookalike']);
  });

  it('are not solved by the look-alike once the rules are off', async () => {
    const off = { ...LAB_DEFAULTS.lookalike, disabledRules: ['R1', 'R3'] as const };
    expect(await solves({ ...off, disabledRules: [...off.disabledRules] })).toEqual([]);
  });
});
