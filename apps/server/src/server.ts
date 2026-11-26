import { z } from 'zod';
import { buildApp } from './app.ts';

const port = z.coerce.number().int().min(1).max(65535).default(8787).parse(process.env.PORT);

buildApp({ port }).listen(port, '127.0.0.1', (error) => {
  if (error) throw error;
  console.log(`MailShield service on http://127.0.0.1:${port}`);
});
