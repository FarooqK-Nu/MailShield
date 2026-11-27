import type { LabRunResponse, LabScenario } from '@mailshield/contracts';

export interface Challenge {
  id: string;
  title: string;
  task: string;
  /** True when the current run solves it. Pure, so it can be tested without a browser. */
  solved: (scenario: LabScenario, run: LabRunResponse) => boolean;
}

const dkim = (run: LabRunResponse) => run.result.signatures[0];

function standardPass(run: LabRunResponse): boolean {
  const standard = run.result.authentication.filter((e) => e.kind === 'dkim' || e.kind === 'dmarc');
  return standard.length > 0 && standard.every((e) => e.status === 'pass');
}

export const CHALLENGES: Challenge[] = [
  {
    id: 'one-character',
    title: 'Break a signature with one character',
    task: 'Start from the legitimate Acme message and tick "Edit one body character". Compare the two body hashes.',
    solved: (s, run) =>
      s.mutations.includes('editBody') &&
      dkim(run)?.status === 'fail' &&
      dkim(run)?.bodyHash.computed !== run.baseline.signatures[0]?.bodyHash.computed,
  },
  {
    id: 'unsigned-header',
    title: 'Change a header the signature does not cover',
    task: 'Tick "Change Reply-To after signing". DKIM should still pass. Find out why in the signature details.',
    solved: (s, run) => s.mutations.includes('alterUnsignedHeader') && dkim(run)?.status === 'pass',
  },
  {
    id: 'lookalike',
    title: 'Pass standard checks as a look-alike',
    task: 'Load "Eve: look-alike domain". DKIM and DMARC pass, yet the rules should still object. Then switch every rule off and see what remains.',
    solved: (s, run) =>
      s.disabledRules.length === 0 &&
      standardPass(run) &&
      run.result.findings.some((f) => f.ruleId === 'R1' || f.ruleId === 'R3'),
  },
  {
    id: 'rotation',
    title: 'Rotate the signing key',
    task: 'Tick "Rotate the Acme selector". DKIM stays valid, the key fingerprint changes and the body hash does not.',
    solved: (s, run) => {
      const now = dkim(run);
      const before = run.baseline.signatures[0];
      return (
        s.mutations.includes('rotateSelector') &&
        now?.status === 'pass' &&
        now.key?.fingerprint !== before?.key?.fingerprint &&
        now.bodyHash.computed === before?.bodyHash.computed
      );
    },
  },
];
