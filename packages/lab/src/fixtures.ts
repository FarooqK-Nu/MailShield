import { readdirSync, readFileSync } from 'node:fs';
import { z } from 'zod';
import type { FixtureZone } from './fixture-resolver.ts';

const ROOT = new URL('../../../fixtures/', import.meta.url);

export const FixtureLabel = z.object({
  id: z.string().regex(/^[a-z0-9-]+$/),
  title: z.string(),
  description: z.string(),
  eml: z.string(),
  dns: z.string(),
  /** Fixed clock, so results never depend on today's date. */
  now: z.iso.datetime(),
  expected: z.object({
    verdict: z.string(),
    signatures: z.array(z.object({ status: z.string(), failureStage: z.string().nullable() })),
    /** Rule ids that must produce findings; every other rule must stay silent. */
    rules: z.array(z.string()),
  }),
});
export type FixtureLabel = z.infer<typeof FixtureLabel>;

export interface Fixture {
  label: FixtureLabel;
  raw: Buffer;
  zone: FixtureZone;
}

const read = (path: string) => readFileSync(new URL(path, ROOT));

/** Only fixtures that have a label file exist (docs/context.md §11). */
export function listFixtures(): FixtureLabel[] {
  return readdirSync(new URL('labels/', ROOT))
    .filter((file) => file.endsWith('.json'))
    .sort()
    .map((file) => FixtureLabel.parse(JSON.parse(read(`labels/${file}`).toString())));
}

/** Looks the id up in the label list, so a caller can never choose a file path. */
export function loadFixture(id: string): Fixture | null {
  const label = listFixtures().find((f) => f.id === id);
  if (!label) return null;
  return {
    label,
    raw: read(`eml/${label.eml}`),
    zone: z.record(z.string(), z.string()).parse(JSON.parse(read(`dns/${label.dns}`).toString())),
  };
}
