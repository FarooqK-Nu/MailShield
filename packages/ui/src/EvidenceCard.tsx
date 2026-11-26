import type { SignatureEvidence } from '@mailshield/contracts';
import type { ReactNode } from 'react';
import { StatusBadge } from './StatusBadge.tsx';

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-x-4 sm:grid-cols-[11rem_1fr]">
      <dt className="text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="min-w-0 wrap-break-word">{children}</dd>
    </div>
  );
}

const list = (items: string[]) => (items.length ? items.join(', ') : 'none');

function bodyHashText({ matches }: SignatureEvidence['bodyHash']) {
  if (matches === null) return 'Not checked';
  return matches ? 'Matches the signed value' : 'Does not match the signed value';
}

function coverageText(coverage: SignatureEvidence['bodyCoverage']) {
  if (!coverage) return 'Whole body (no l= limit)';
  const unsigned =
    coverage.unsignedBytes === null ? '' : `, ${coverage.unsignedBytes} bytes unsigned`;
  return `Limited: first ${coverage.signedBytes} bytes signed${unsigned}`;
}

export function EvidenceCard({ signature }: { signature: SignatureEvidence }) {
  const { key } = signature;
  return (
    <article className="rounded-lg border border-slate-300 p-4 dark:border-slate-700">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-semibold break-all">
          DKIM signature: {signature.domain ?? 'no signing domain'}
        </h3>
        <StatusBadge status={signature.status} />
      </header>
      <p className="mt-1 text-sm">{signature.reason}</p>
      <dl className="mt-3 space-y-1.5 text-sm">
        <Row label="Selector (s=)">{signature.selector ?? 'missing'}</Row>
        <Row label="Algorithm (a=)">{signature.algorithm ?? 'missing'}</Row>
        <Row label="Canonicalization (c=)">{signature.canonicalization}</Row>
        <Row label="Body hash">{bodyHashText(signature.bodyHash)}</Row>
        <Row label="Body covered">{coverageText(signature.bodyCoverage)}</Row>
        <Row label="Signed headers (h=)">{list(signature.signedHeaders)}</Row>
        <Row label="Not signed">{list(signature.unsignedHeaders)}</Row>
        <Row label="Public key">
          {key
            ? `${key.type.toUpperCase()}${key.bits ? ` ${key.bits} bits` : ''}`
            : 'Not retrieved'}
        </Row>
        {key && (
          <Row label="Key fingerprint (SHA-256)">
            <code className="text-xs break-all">{key.fingerprint}</code>
          </Row>
        )}
        {signature.signedAt && <Row label="Signed at">{signature.signedAt}</Row>}
        {signature.expiresAt && <Row label="Expires at">{signature.expiresAt}</Row>}
      </dl>
      {signature.warnings.length > 0 && (
        <ul className="mt-3 list-disc pl-5 text-sm text-amber-800 dark:text-amber-300">
          {signature.warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      )}
    </article>
  );
}
