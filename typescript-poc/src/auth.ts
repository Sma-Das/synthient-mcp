import type { NextFunction, Request, RequestHandler, Response } from 'express';

declare module 'http' {
  interface IncomingHttpHeaders {
    'x-api-key'?: string;
    'x-forwarded-for'?: string;
  }
}

function normalizeAddress(address: string): string {
  if (address.startsWith('::ffff:')) return address.slice(7);
  return address;
}

export function getCanonicalClientIp(request: Request): string {
  const address = request.ip ?? request.socket.remoteAddress;
  if (!address) return 'unknown';

  const normalized = normalizeAddress(address.trim());
  if (normalized.includes(',') || /[\r\n]/u.test(normalized)) {
    throw new Error('Resolved client IP is not a single valid forwarding value');
  }
  return normalized;
}

export function requireSynthientCredentials(): RequestHandler {
  return (request: Request, response: Response, next: NextFunction): void => {
    const apiKey = request.headers['x-api-key'];

    if (typeof apiKey !== 'string' || apiKey.trim() === '') {
      response.status(401).json({
        error: 'Unauthorized',
        message: 'Provide your Synthient API key in the x-api-key header.',
      });
      return;
    }

    try {
      // Pass one unambiguous caller address downstream. Express only trusts an
      // incoming X-Forwarded-For chain when TRUST_PROXY_HOPS is configured.
      request.headers['x-forwarded-for'] = getCanonicalClientIp(request);
      next();
    } catch (error) {
      response.status(400).json({
        error: 'Bad Request',
        message: error instanceof Error ? error.message : 'Invalid forwarding information',
      });
    }
  };
}
