import { crx } from '@crxjs/vite-plugin';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';
import { manifest } from './manifest.config.ts';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, import.meta.dirname, 'VITE_');
  return {
    plugins: [react(), crx({ manifest: manifest(env.VITE_GOOGLE_CLIENT_ID) })],
    server: { port: 5174, strictPort: true },
  };
});
