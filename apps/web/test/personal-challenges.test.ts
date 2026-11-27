import type { LabPersonalScenario } from '@mailshield/contracts';
import { runPersonalScenario } from '@mailshield/lab';
import { describe, expect, it } from 'vitest';
import { PERSONAL_CHALLENGES } from '../src/features/lab/personalChallenges.ts';

const base: LabPersonalScenario = { signer: 'alice', aliceKeyEnrolled: true, mutations: [] };
const solves = async (scenario: LabPersonalScenario) => {
  const run = await runPersonalScenario(scenario);
  return PERSONAL_CHALLENGES.filter((c) => c.solved(scenario, run)).map((c) => c.id);
};

describe('personal lab challenges', () => {
  it('is solved only by the scenario each one describes', async () => {
    expect(await solves(base)).toEqual(['alice-signs']);
    expect(await solves({ ...base, aliceKeyEnrolled: false })).toEqual(['not-enrolled']);
    expect(await solves({ ...base, signer: 'eve' })).toEqual(['eve']);
    expect(await solves({ ...base, mutations: ['editBody'] })).toEqual(['tamper']);
    expect(await solves({ ...base, mutations: ['changeOuterSubject'] })).toEqual([
      'alice-signs',
      'outer-subject',
    ]);
  });
});
