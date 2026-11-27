import { MAX_MESSAGE_BYTES } from '@mailshield/contracts';
import { FileUp, ListChecks } from 'lucide-react';
import { useState, type DragEvent } from 'react';
import type { MessageMetadata } from '../shared/selection.ts';
import { send } from './api.ts';

const PICKER_COUNT = 10;

/**
 * Lists recent messages, but only after the user agrees to MailShield reading their sender,
 * subject and date. Nothing is fetched before that click.
 */
function Picker({ onPick }: { onPick: (meta: MessageMetadata) => void }) {
  const [consented, setConsented] = useState(false);
  const [items, setItems] = useState<MessageMetadata[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setBusy(true);
    setError(null);
    try {
      setItems(await send({ type: 'recent', count: PICKER_COUNT }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        <ListChecks aria-hidden className="size-4" /> Pick a message
      </h3>
      <p className="text-sm">
        Use this when the open message cannot be recognised. To show the list, MailShield reads the
        sender, subject and date of your {PICKER_COUNT} newest messages. It reads no message content
        until you pick one and click Analyze.
      </p>
      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-1"
          checked={consented}
          onChange={(e) => setConsented(e.target.checked)}
        />
        I agree to MailShield reading the sender, subject and date of my {PICKER_COUNT} newest
        messages.
      </label>
      <button type="button" className="button" disabled={!consented || busy} onClick={load}>
        {busy ? 'Loading…' : 'Show recent messages'}
      </button>
      {error && (
        <p role="alert" className="text-sm text-red-700 dark:text-red-300">
          {error}
        </p>
      )}
      {items && (
        <ul className="divide-y divide-slate-200 rounded-md border border-slate-300 dark:divide-slate-800 dark:border-slate-700">
          {items.map((m) => (
            <li key={m.id}>
              <button
                type="button"
                className="w-full p-2 text-left text-sm hover:bg-slate-100 dark:hover:bg-slate-800"
                onClick={() => onPick(m)}
              >
                <span className="block truncate font-medium">{m.from || '(no sender)'}</span>
                <span className="block truncate">{m.subject || '(no subject)'}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function DropZone({ onFile }: { onFile: (file: File) => void }) {
  const [over, setOver] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const take = (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_MESSAGE_BYTES) return setError('The file is larger than 10 MiB.');
    setError(null);
    onFile(file);
  };
  const drop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    take(e.dataTransfer.files[0]);
  };

  return (
    <div className="space-y-2">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        <FileUp aria-hidden className="size-4" /> Analyze an .eml file
      </h3>
      <label
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={drop}
        className={`block cursor-pointer rounded-lg border-2 border-dashed p-4 text-center text-sm ${over ? 'border-sky-600' : 'border-slate-400 dark:border-slate-600'}`}
      >
        Drop an .eml file here, or click to choose one.
        <input
          type="file"
          accept=".eml,message/rfc822"
          className="sr-only"
          onChange={(e) => take(e.target.files?.[0])}
        />
      </label>
      {error && (
        <p role="alert" className="text-sm text-red-700 dark:text-red-300">
          {error}
        </p>
      )}
      <p className="text-xs text-slate-600 dark:text-slate-400">
        Results reported inside an uploaded file are never trusted: anyone can write them.
      </p>
    </div>
  );
}

function ShowOriginal() {
  return (
    <div className="space-y-2 text-sm">
      <h3 className="font-semibold">Get the original message from Gmail</h3>
      <ol className="list-decimal space-y-1 pl-5">
        <li>Open the message in Gmail.</li>
        <li>Click the three-dot menu next to Reply, then Show original.</li>
        <li>Click Download original. Gmail saves an .eml file.</li>
        <li>Drop that file in the box above.</li>
      </ol>
    </div>
  );
}

/** Ways to analyze a message when live Gmail selection is unavailable. */
export function Fallbacks({
  gmailConnected,
  onPick,
  onFile,
}: {
  gmailConnected: boolean;
  onPick: (meta: MessageMetadata) => void;
  onFile: (file: File) => void;
}) {
  return (
    <details
      className="rounded-lg border border-slate-300 dark:border-slate-700"
      open={!gmailConnected}
    >
      <summary className="cursor-pointer p-3 text-sm font-semibold">Other ways to analyze</summary>
      <div className="space-y-5 p-3 pt-0">
        {gmailConnected && <Picker onPick={onPick} />}
        <DropZone onFile={onFile} />
        <ShowOriginal />
      </div>
    </details>
  );
}
