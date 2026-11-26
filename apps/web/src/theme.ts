import { useEffect, useState } from 'react';

const KEY = 'mailshield.theme';

function initial(): boolean {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved) return saved === 'dark';
  } catch {
    // Storage blocked: follow the system setting.
  }
  return matchMedia('(prefers-color-scheme: dark)').matches;
}

export function useTheme() {
  const [dark, setDark] = useState(initial);
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);
  const toggle = () => {
    setDark(!dark);
    try {
      localStorage.setItem(KEY, dark ? 'light' : 'dark');
    } catch {
      // Per-viewer convenience only.
    }
  };
  return { dark, toggle };
}
