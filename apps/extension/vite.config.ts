import { crx } from '@crxjs/vite-plugin';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';
import { manifest } from './manifest.config.ts';

export const DEFAULT_SERVICE_URL = 'http://127.0.0.1:8787';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, import.meta.dirname, 'VITE_');
  const serviceOrigin = new URL(env.VITE_SERVICE_URL || DEFAULT_SERVICE_URL).origin;
  return {
    plugins: [
      react(),
      tailwindcss(),
      crx({ manifest: manifest({ googleClientId: env.VITE_GOOGLE_CLIENT_ID, serviceOrigin }) }),
    ],
    server: { port: 5174, strictPort: true },
  };
});
