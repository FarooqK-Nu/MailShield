import { defineManifest } from '@crxjs/vite-plugin';

/**
 * The public key fixes the extension ID (oijpcmifakangkecaplidfpgjhhidbop) on every machine,
 * which the Google OAuth client is bound to. It is not a secret.
 */
const KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu2s+C45zrPWBu/oKHibAc2GxNhgEFz4+aRkgcN1Ag39x78M/X1OyI1N7h2r8C4VLiUtrGKzchpboJxv9tiRG5Sv3fu0l95epTrnCx0Zo15rKIbd7DXKrKSq3dr50hA8hVBbq/vWetxCDIZ6KBHH0sKd94UMqsUNIrE0bkL3pCvJwmYiutHvHw4oivtwQI/rhS8SZpnBIQ+S97r11CSw4O3+TMtjBbkCr1XW+IHuJ35jDypB6krnBIc6DVsEX9oYB1vmMBnzRrF9wujct55X11eddXCSCI1vRY+fVw5SUZ+J7hQ4mfRS22/LWKAyQjZL/6arnvxzgh3GkfKbz/Cf1UQIDAQAB';

export interface ManifestOptions {
  googleClientId: string | undefined;
  /** Origin of the local verification service, for example http://127.0.0.1:8787. */
  serviceOrigin: string;
}

/**
 * Least privilege (docs/architecture.md §6): side panel, OAuth, local storage. Host access only
 * to the Gmail API and the local service; the content script runs on Gmail and only reads.
 */
export const manifest = ({ googleClientId, serviceOrigin }: ManifestOptions) =>
  defineManifest({
    manifest_version: 3,
    name: 'MailShield (development)',
    version: '0.1.0',
    description: 'Checks whether an email comes from who it claims to be.',
    key: KEY,
    minimum_chrome_version: '116',
    permissions: ['sidePanel', 'identity', 'storage'],
    host_permissions: ['https://gmail.googleapis.com/*', `${serviceOrigin}/*`],
    background: { service_worker: 'src/background.ts', type: 'module' },
    content_scripts: [
      {
        matches: ['https://mail.google.com/*'],
        js: ['src/content/gmail.ts'],
        run_at: 'document_idle',
      },
    ],
    side_panel: { default_path: 'src/sidepanel/index.html' },
    action: { default_title: 'Open MailShield' },
    ...(googleClientId && {
      oauth2: {
        client_id: googleClientId,
        scopes: ['https://www.googleapis.com/auth/gmail.readonly'],
      },
    }),
  });
