import { defineManifest } from '@crxjs/vite-plugin';

/**
 * The public key fixes the extension ID (oijpcmifakangkecaplidfpgjhhidbop) on every machine,
 * which the Google OAuth client is bound to. It is not a secret.
 */
const KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu2s+C45zrPWBu/oKHibAc2GxNhgEFz4+aRkgcN1Ag39x78M/X1OyI1N7h2r8C4VLiUtrGKzchpboJxv9tiRG5Sv3fu0l95epTrnCx0Zo15rKIbd7DXKrKSq3dr50hA8hVBbq/vWetxCDIZ6KBHH0sKd94UMqsUNIrE0bkL3pCvJwmYiutHvHw4oivtwQI/rhS8SZpnBIQ+S97r11CSw4O3+TMtjBbkCr1XW+IHuJ35jDypB6krnBIc6DVsEX9oYB1vmMBnzRrF9wujct55X11eddXCSCI1vRY+fVw5SUZ+J7hQ4mfRS22/LWKAyQjZL/6arnvxzgh3GkfKbz/Cf1UQIDAQAB';

export const manifest = (googleClientId: string | undefined) =>
  defineManifest({
    manifest_version: 3,
    name: 'MailShield (development)',
    version: '0.0.1',
    description: 'Checks whether an email comes from who it claims to be.',
    key: KEY,
    minimum_chrome_version: '116',
    permissions: ['sidePanel', 'identity'],
    host_permissions: ['https://gmail.googleapis.com/*'],
    background: { service_worker: 'src/background.ts', type: 'module' },
    side_panel: { default_path: 'src/sidepanel/index.html' },
    action: { default_title: 'Open MailShield' },
    ...(googleClientId && {
      oauth2: {
        client_id: googleClientId,
        scopes: ['https://www.googleapis.com/auth/gmail.readonly'],
      },
    }),
  });
