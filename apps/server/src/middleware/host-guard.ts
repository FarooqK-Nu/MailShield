import type { RequestHandler } from 'express';
import { sendProblem } from './errors.ts';

/** DNS-rebinding defence: only our own loopback names are acceptable. */
export function hostGuard(port: number): RequestHandler {
  const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  return (req, res, next) => {
    if (hosts.has(req.headers.host ?? '')) return next();
    sendProblem(res, 'host_rejected');
  };
}
