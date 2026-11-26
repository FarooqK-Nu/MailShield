import type { HeaderLine } from '@mailshield/contracts';
import { Copy } from 'lucide-react';
import { useMemo, useState } from 'react';

/** Header names grouped in message order. Values are rendered as text, never as HTML. */
function group(lines: HeaderLine[]) {
  const out = new Map<string, HeaderLine[]>();
  for (const line of lines) out.set(line.name, [...(out.get(line.name) ?? []), line]);
  return [...out.entries()];
}

export function RawHeaders({ lines }: { lines: HeaderLine[] }) {
  const [query, setQuery] = useState('');
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return group(
      q ? lines.filter((l) => l.name.includes(q) || l.value.toLowerCase().includes(q)) : lines,
    );
  }, [lines, query]);
  const copy = (text: string) => void navigator.clipboard?.writeText(text).catch(() => {});

  return (
    <section aria-labelledby="headers-title" className="space-y-2">
      <h2 id="headers-title" className="font-semibold">
        Raw headers ({lines.length})
      </h2>
      <input
        type="search"
        aria-label="Search headers"
        placeholder="Search headers"
        className="field w-full text-sm"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      <ul className="max-h-96 space-y-1 overflow-auto font-mono text-xs">
        {shown.map(([name, items]) => (
          <li key={name}>
            {items.length === 1 ? (
              <Line line={items[0]!} onCopy={copy} />
            ) : (
              <details>
                <summary className="cursor-pointer">
                  {name} ({items.length} fields)
                </summary>
                <ul className="ml-4 space-y-1">
                  {items.map((line) => (
                    <li key={line.offset}>
                      <Line line={line} onCopy={copy} />
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </li>
        ))}
        {shown.length === 0 && <li className="font-sans">No header matches.</li>}
      </ul>
    </section>
  );
}

function Line({ line, onCopy }: { line: HeaderLine; onCopy: (text: string) => void }) {
  return (
    <div className="flex items-start gap-2">
      <p className="min-w-0 flex-1 break-all">
        <span className="font-semibold">{line.name}:</span> {line.value}
      </p>
      <button
        type="button"
        onClick={() => onCopy(`${line.name}: ${line.value}`)}
        className="shrink-0 rounded p-0.5"
      >
        <Copy aria-hidden className="size-3.5" />
        <span className="sr-only">Copy {line.name}</span>
      </button>
    </div>
  );
}
