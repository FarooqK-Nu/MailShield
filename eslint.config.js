import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/** Package boundaries (docs/architecture.md §2). */
const forbid = (files, group, message) => ({
  files,
  rules: { 'no-restricted-imports': ['error', { patterns: [{ group, message }] }] },
});

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { languageOptions: { globals: { ...globals.node, ...globals.browser } } },
  forbid(
    ['packages/engine/src/**'],
    ['@mailshield/lab*', '@mailshield/server*', '**/lab/**', 'express', 'express/*'],
    'The engine is pure: no lab, server or HTTP imports.',
  ),
  forbid(
    ['packages/contracts/src/**'],
    ['@mailshield/*'],
    'Contracts depend on no other MailShield package.',
  ),
  forbid(
    ['apps/web/src/**', 'apps/extension/src/**', 'packages/ui/src/**'],
    ['@mailshield/engine*', '@mailshield/lab*', '@mailshield/server*'],
    'Frontends talk to the local service through contracts only.',
  ),
);
