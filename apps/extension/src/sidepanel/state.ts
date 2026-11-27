import type { AnalysisResult } from '@mailshield/contracts';
import type { FlowStep } from '../background/flow.ts';
import type { HintMessage, MessageMetadata, SelectionHint } from '../shared/selection.ts';

/**
 * What the panel is looking at. `ref` is the Gmail message id, or `file:<n>` for an uploaded
 * `.eml`. Every result must carry the `ref` and request number it was asked for.
 */
export interface Target {
  ref: string;
  kind: 'gmail' | 'file';
  /** What the Gmail page showed (Gmail targets chosen from the page only). */
  hint?: HintMessage;
  hintSubject?: string | null;
  /** What the Gmail API confirmed. */
  meta?: MessageMetadata;
  /** Differences between the page and the API; the user must acknowledge them. */
  mismatches?: string[];
  /** File name, for uploads. */
  label?: string;
}

export type View =
  | { name: 'empty' }
  | { name: 'choose'; hint: SelectionHint }
  | { name: 'confirming' }
  | { name: 'ready' }
  | { name: 'analyzing'; steps: FlowStep[] }
  | { name: 'result'; result: AnalysisResult }
  | { name: 'error'; code: string; message: string; retry: 'confirm' | 'analyze' | null };

export interface PanelState {
  target: Target | null;
  view: View;
  /** Increases on every new target and every analysis request. Late replies carry an old one. */
  request: number;
}

export type PanelAction =
  /** The Gmail page changed. A new message clears the old result immediately. */
  | { type: 'hint'; hint: SelectionHint }
  | { type: 'choose'; message: HintMessage; subject: string | null }
  | { type: 'pick'; meta: MessageMetadata }
  | { type: 'confirmed'; ref: string; meta: MessageMetadata; mismatches: string[] }
  | { type: 'file'; label: string }
  | { type: 'start'; ref: string }
  | { type: 'progress'; request: number; step: FlowStep }
  | { type: 'result'; ref: string; request: number; result: AnalysisResult }
  | {
      type: 'failed';
      ref: string;
      request: number;
      code: string;
      message: string;
      retry: 'confirm' | 'analyze' | null;
    }
  | { type: 'retry' }
  | { type: 'reset' };

export const initialState: PanelState = { target: null, view: { name: 'empty' }, request: 0 };

const select = (state: PanelState, target: Target, view: View): PanelState => ({
  target,
  view,
  request: state.request + 1,
});

export function reducer(state: PanelState, action: PanelAction): PanelState {
  switch (action.type) {
    case 'hint': {
      const { messages } = action.hint;
      // An uploaded file stays on screen while the user browses Gmail.
      if (state.target?.kind === 'file') return state;
      if (messages.length === 0) {
        // Back to the inbox: nothing is selected and no result is shown.
        if (!state.target && state.view.name === 'empty') return state;
        return { ...initialState, request: state.request + 1 };
      }
      if (messages.length > 1) {
        // A conversation with several expanded messages: the user chooses one.
        const current = state.target && messages.some((m) => m.id === state.target!.ref);
        if (current) return state;
        return {
          target: null,
          view: { name: 'choose', hint: action.hint },
          request: state.request + 1,
        };
      }
      const [message] = messages as [HintMessage];
      if (state.target?.ref === message.id) return state;
      return select(
        state,
        { ref: message.id, kind: 'gmail', hint: message, hintSubject: action.hint.subject },
        { name: 'confirming' },
      );
    }
    case 'choose':
      if (state.target?.ref === action.message.id) return state;
      return select(
        state,
        {
          ref: action.message.id,
          kind: 'gmail',
          hint: action.message,
          hintSubject: action.subject,
        },
        { name: 'confirming' },
      );
    case 'pick':
      // Chosen from the consented picker: the metadata came from the Gmail API itself.
      return select(
        state,
        { ref: action.meta.id, kind: 'gmail', meta: action.meta, mismatches: [] },
        { name: 'ready' },
      );
    case 'confirmed':
      if (state.target?.ref !== action.ref || state.view.name !== 'confirming') return state;
      return {
        ...state,
        target: { ...state.target, meta: action.meta, mismatches: action.mismatches },
        view: { name: 'ready' },
      };
    case 'file':
      return select(
        state,
        { ref: `file:${state.request + 1}`, kind: 'file', label: action.label },
        { name: 'analyzing', steps: [] },
      );
    case 'start':
      if (state.target?.ref !== action.ref) return state;
      return { ...state, view: { name: 'analyzing', steps: [] }, request: state.request + 1 };
    case 'progress':
      if (action.request !== state.request || state.view.name !== 'analyzing') return state;
      if (state.view.steps.includes(action.step)) return state;
      return { ...state, view: { name: 'analyzing', steps: [...state.view.steps, action.step] } };
    case 'result': {
      // Stale-result protection (docs/context.md §7): a reply for another message or an older
      // request is dropped, and a Gmail result must name the message it was asked for.
      if (state.target?.ref !== action.ref || action.request !== state.request) return state;
      if (state.target.kind === 'gmail' && action.result.messageRef !== action.ref) return state;
      return { ...state, view: { name: 'result', result: action.result } };
    }
    case 'failed':
      if (state.target?.ref !== action.ref || action.request !== state.request) return state;
      return {
        ...state,
        view: { name: 'error', code: action.code, message: action.message, retry: action.retry },
      };
    case 'retry':
      // Confirm the same message again after a failed confirmation.
      if (!state.target || state.view.name !== 'error' || state.view.retry !== 'confirm')
        return state;
      return { ...state, view: { name: 'confirming' }, request: state.request + 1 };
    case 'reset':
      return { ...initialState, request: state.request + 1 };
  }
}
