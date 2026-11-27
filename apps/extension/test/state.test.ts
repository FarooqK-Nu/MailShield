/** Stale-result protection in the side panel (docs/context.md §7, roadmap Phase 4). */
import type { AnalysisResult } from '@mailshield/contracts';
import { describe, expect, it } from 'vitest';
import type { MessageMetadata, SelectionHint } from '../src/shared/selection.ts';
import {
  initialState,
  reducer,
  type PanelAction,
  type PanelState,
} from '../src/sidepanel/state.ts';

const hint = (...ids: string[]): SelectionHint => ({
  subject: 'Invoice',
  messages: ids.map((id) => ({ id, fromEmail: `${id}@acme.example`, fromName: null })),
});
const meta = (id: string): MessageMetadata => ({
  id,
  from: `A <${id}@acme.example>`,
  fromAddress: `${id}@acme.example`,
  subject: 'Invoice',
  date: 'Fri, 27 Nov 2026 09:00:00 +0000',
  sizeEstimate: 1000,
});
const result = (messageRef?: string) =>
  ({ messageRef, verdict: 'identity_unverified' }) as AnalysisResult;

const run = (actions: PanelAction[], from: PanelState = initialState) =>
  actions.reduce(reducer, from);

/** Selects a message, confirms it and starts an analysis; returns the state and its request. */
function analyzing(id: string, from: PanelState = initialState) {
  const state = run(
    [
      { type: 'hint', hint: hint(id) },
      { type: 'confirmed', ref: id, meta: meta(id), mismatches: [] },
    ],
    from,
  );
  const started = reducer(state, { type: 'start', ref: id });
  return { state: started, request: started.request };
}

const A = 'aaaaaaaaaaaaaaa1';
const B = 'bbbbbbbbbbbbbbb2';

describe('side panel state', () => {
  it('confirms a selection before it can be analyzed', () => {
    const selected = run([{ type: 'hint', hint: hint(A) }]);
    expect(selected.view.name).toBe('confirming');
    const ready = reducer(selected, { type: 'confirmed', ref: A, meta: meta(A), mismatches: [] });
    expect(ready.view.name).toBe('ready');
    expect(ready.target?.meta?.id).toBe(A);
  });

  it('never shows the old result after a rapid switch to another message', () => {
    const { state, request } = analyzing(A);
    // The user opens message B while A is still being analyzed.
    const switched = reducer(state, { type: 'hint', hint: hint(B) });
    expect(switched.target?.ref).toBe(B);
    expect(switched.view.name).toBe('confirming');
    // A's answer arrives late.
    const late = reducer(switched, { type: 'result', ref: A, request, result: result(A) });
    expect(late).toBe(switched);
    expect(late.view.name).not.toBe('result');
  });

  it('drops replies for an older request of the same message (reanalyze)', () => {
    const { state, request: first } = analyzing(A);
    const again = reducer(state, { type: 'start', ref: A });
    const late = reducer(again, { type: 'result', ref: A, request: first, result: result(A) });
    expect(late.view.name).toBe('analyzing');
    const current = reducer(late, {
      type: 'result',
      ref: A,
      request: again.request,
      result: result(A),
    });
    expect(current.view.name).toBe('result');
  });

  it('rejects a Gmail result that names a different message', () => {
    const { state, request } = analyzing(A);
    expect(reducer(state, { type: 'result', ref: A, request, result: result(B) })).toBe(state);
    expect(reducer(state, { type: 'result', ref: A, request, result: result() })).toBe(state);
  });

  it('ignores late failures and progress from older requests', () => {
    const { state, request } = analyzing(A);
    const switched = analyzing(B, state).state;
    const failure: PanelAction = {
      type: 'failed',
      ref: A,
      request,
      code: 'gmail_error',
      message: 'x',
      retry: 'analyze',
    };
    expect(reducer(switched, failure)).toBe(switched);
    expect(reducer(switched, { type: 'progress', request, step: 'fetching_raw' })).toBe(switched);
  });

  it('clears the result immediately when the user leaves the message', () => {
    const { state, request } = analyzing(A);
    const done = reducer(state, { type: 'result', ref: A, request, result: result(A) });
    const left = reducer(done, { type: 'hint', hint: hint() });
    expect(left.target).toBeNull();
    expect(left.view.name).toBe('empty');
  });

  it('asks which message when a conversation has several open', () => {
    const several = run([{ type: 'hint', hint: hint(A, B) }]);
    expect(several.view.name).toBe('choose');
    expect(several.target).toBeNull();
    const chosen = reducer(several, {
      type: 'choose',
      message: hint(B).messages[0]!,
      subject: 'Invoice',
    });
    expect(chosen.target?.ref).toBe(B);
    expect(chosen.view.name).toBe('confirming');
    // Gmail re-reports the same conversation: the choice stays.
    expect(reducer(chosen, { type: 'hint', hint: hint(A, B) })).toBe(chosen);
  });

  it('ignores a confirmation for a message that is no longer selected', () => {
    const state = run([
      { type: 'hint', hint: hint(A) },
      { type: 'hint', hint: hint(B) },
    ]);
    const stale = reducer(state, { type: 'confirmed', ref: A, meta: meta(A), mismatches: [] });
    expect(stale).toBe(state);
  });

  it('keeps an uploaded file on screen while Gmail changes, until closed', () => {
    const file = reducer(initialState, { type: 'file', label: 'saved.eml' });
    const ref = file.target!.ref;
    expect(ref).toMatch(/^file:/);
    expect(reducer(file, { type: 'hint', hint: hint(A) })).toBe(file);
    const shown = reducer(file, { type: 'result', ref, request: file.request, result: result() });
    expect(shown.view.name).toBe('result');
    expect(reducer(shown, { type: 'reset' }).target).toBeNull();
  });

  it('takes a picked message as already confirmed by the Gmail API', () => {
    const picked = reducer(initialState, { type: 'pick', meta: meta(A) });
    expect(picked.view.name).toBe('ready');
    expect(picked.target?.meta?.id).toBe(A);
  });

  it('retries a failed confirmation for the same message', () => {
    const selected = run([{ type: 'hint', hint: hint(A) }]);
    const failed = reducer(selected, {
      type: 'failed',
      ref: A,
      request: selected.request,
      code: 'gmail_unreachable',
      message: 'x',
      retry: 'confirm',
    });
    const retried = reducer(failed, { type: 'retry' });
    expect(retried.view.name).toBe('confirming');
    expect(retried.request).toBeGreaterThan(failed.request);
  });
});
