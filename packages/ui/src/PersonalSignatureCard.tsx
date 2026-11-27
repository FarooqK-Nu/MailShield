import type { PersonalSignature } from '@mailshield/contracts';
import { CircleCheck, CircleDashed, CircleX } from 'lucide-react';
import { StatusBadge } from './StatusBadge.tsx';
import { anchorId } from './targets.ts';

type Answer = boolean | null;

/** One question with its own answer. Icon and words carry the meaning, never colour alone. */
function Check({
  label,
  answer,
  yes,
  no,
  unknown,
}: {
  label: string;
  answer: Answer;
  yes: string;
  no: string;
  unknown: string;
}) {
  const Icon = answer === true ? CircleCheck : answer === false ? CircleX : CircleDashed;
  const tone =
    answer === true
      ? 'text-emerald-800 dark:text-emerald-300'
      : answer === false
        ? 'text-red-800 dark:text-red-300'
        : 'text-slate-600 dark:text-slate-300';
  return (
    <li className="flex items-start gap-2">
      <Icon aria-hidden className={`mt-0.5 size-4 shrink-0 ${tone}`} />
      <span className="min-w-0">
        <strong>{label}:</strong> {answer === true ? yes : answer === false ? no : unknown}
      </span>
    </li>
  );
}

/**
 * The S/MIME result. A valid signature, a trusted certificate, a certificate that names the
 * sender, and a key enrolled for the person are four separate facts (docs/architecture.md §3.7).
 */
export function PersonalSignatureCard({ personal }: { personal: PersonalSignature }) {
  const { signer } = personal;
  return (
    <article
      id={anchorId(personal.evidenceId)}
      className="rounded-lg border border-slate-300 p-4 text-sm dark:border-slate-700"
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-semibold">Personal signature (S/MIME)</h3>
        <StatusBadge status={personal.status} />
      </header>
      <p className="mt-1">{personal.reason}</p>
      <ul className="mt-3 space-y-1.5">
        <Check
          label="Signature valid"
          answer={personal.signatureValid}
          yes="the signer’s key signed exactly the covered part."
          no="the covered part does not match the signature."
          unknown="not checked."
        />
        <Check
          label="Certificate trusted"
          answer={personal.chainTrusted}
          yes="it chains to a trust anchor this check was given."
          no="it does not chain to a trust anchor this check was given."
          unknown="not checked: no trust anchors are configured here."
        />
        <Check
          label="Identity bound to the sender"
          answer={personal.emailBinding}
          yes="the certificate names the From address."
          no="the certificate does not name the From address."
          unknown="not checked."
        />
        <Check
          label="Key enrolled for a person"
          answer={personal.signatureValid ? personal.enrolledFor !== null : null}
          yes={`enrolled for ${personal.enrolledFor?.displayName ?? ''}.`}
          no="this key is not enrolled for anyone in your registry."
          unknown="not checked."
        />
        <Check
          label="Email protection allowed"
          answer={personal.ekuEmailProtection}
          yes="the certificate may be used for email."
          no="the certificate does not allow email use."
          unknown="not checked."
        />
        <Check
          label="Certificate in date"
          answer={personal.timeValid}
          yes="valid at the time of this check."
          no="expired or not yet valid at the time of this check."
          unknown="not checked."
        />
        <li className="flex items-start gap-2">
          <CircleDashed
            aria-hidden
            className="mt-0.5 size-4 shrink-0 text-slate-600 dark:text-slate-300"
          />
          <span>
            <strong>Revocation:</strong> unknown. No revocation list is consulted.
          </span>
        </li>
      </ul>
      {signer && (
        <dl className="mt-3 space-y-1 text-xs">
          <div>
            <dt className="text-slate-500 dark:text-slate-400">Certificate subject</dt>
            <dd className="break-all">{signer.subject}</dd>
          </div>
          <div>
            <dt className="text-slate-500 dark:text-slate-400">Issuer</dt>
            <dd className="break-all">{signer.issuer}</dd>
          </div>
          <div>
            <dt className="text-slate-500 dark:text-slate-400">Valid</dt>
            <dd>
              {signer.notBefore.slice(0, 10)} to {signer.notAfter.slice(0, 10)}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500 dark:text-slate-400">Key fingerprint (SHA-256)</dt>
            <dd>
              <code className="break-all">{signer.fingerprint}</code>
            </dd>
          </div>
        </dl>
      )}
      <p className="mt-3 text-xs">{personal.coverage}</p>
    </article>
  );
}
