import type { LabPersonalResponse, LabPersonalScenario } from '@mailshield/contracts';

export interface PersonalChallenge {
  id: string;
  title: string;
  task: string;
  /** Pure, so it can be tested without a browser. */
  solved: (scenario: LabPersonalScenario, run: LabPersonalResponse) => boolean;
}

const personal = (run: LabPersonalResponse) => run.result.personalSignature;

export const PERSONAL_CHALLENGES: PersonalChallenge[] = [
  {
    id: 'alice-signs',
    title: 'Confirm a person, not a domain',
    task: 'Sign as Alice with her key enrolled. The identity should become “corroborated personal”.',
    solved: (s, run) =>
      s.signer === 'alice' &&
      s.aliceKeyEnrolled &&
      run.result.identityStatus === 'corroborated_personal',
  },
  {
    id: 'not-enrolled',
    title: 'A valid signature is not enough',
    task: 'Sign as Alice, but untick “Alice’s key is enrolled”. The signature is valid, yet the person is not confirmed. Why?',
    solved: (s, run) =>
      s.signer === 'alice' &&
      !s.aliceKeyEnrolled &&
      personal(run)?.signatureValid === true &&
      run.result.identityStatus !== 'corroborated_personal',
  },
  {
    id: 'eve',
    title: 'Eve signs as Alice',
    task: 'Sign as Eve. Her certificate is real and trusted by the lab CA, but it names a different address and is not enrolled for Alice. Compare the checks on the card.',
    solved: (s, run) =>
      s.signer === 'eve' &&
      personal(run)?.signatureValid === true &&
      personal(run)?.enrolledFor === null &&
      run.result.identityStatus !== 'corroborated_personal',
  },
  {
    id: 'tamper',
    title: 'Tamper with a signed message',
    task: 'Sign as Alice and tick “Edit the signed body”. The signature must fail.',
    solved: (s, run) => s.mutations.includes('editBody') && personal(run)?.status === 'fail',
  },
  {
    id: 'outer-subject',
    title: 'Change what the signature does not cover',
    task: 'Sign as Alice and tick “Change the outer Subject”. The signature stays valid. Find out why the Subject is not personally signed.',
    solved: (s, run) =>
      s.mutations.includes('changeOuterSubject') && personal(run)?.signatureValid === true,
  },
];
