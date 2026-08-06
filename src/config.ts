const DEFAULT_ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

export interface AppConfig {
  host: string;
  port: number;
  allowedHosts: string[];
  allowedOrigins: string[];
  trustProxyHops: number;
  synthientBaseUrl: URL;
  requestTimeoutMs: number;
}

function parseInteger(
  value: string | undefined,
  fallback: number,
  name: string,
  range: { min: number; max: number },
): number {
  if (value === undefined || value === '') return fallback;

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < range.min || parsed > range.max) {
    throw new Error(
      `${name} must be an integer between ${range.min} and ${range.max}`,
    );
  }
  return parsed;
}

function parseList(value: string | undefined, fallback: string[]): string[] {
  if (value === undefined) return fallback;

  const values = value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

  if (values.length === 0) {
    throw new Error('Comma-separated allow lists cannot be empty');
  }
  return values;
}

function parseBaseUrl(value: string | undefined): URL {
  const url = new URL(value ?? 'https://api.synthient.com/api/v4/');
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new Error('SYNTHIENT_API_BASE_URL must use HTTPS unless it targets localhost');
  }
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return url;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const allowedHosts = parseList(env.ALLOWED_HOSTS, DEFAULT_ALLOWED_HOSTS);

  return {
    host: env.HOST ?? '0.0.0.0',
    port: parseInteger(env.PORT, 3000, 'PORT', { min: 1, max: 65_535 }),
    allowedHosts,
    allowedOrigins: parseList(env.ALLOWED_ORIGINS, allowedHosts),
    trustProxyHops: parseInteger(env.TRUST_PROXY_HOPS, 0, 'TRUST_PROXY_HOPS', {
      min: 0,
      max: 10,
    }),
    synthientBaseUrl: parseBaseUrl(env.SYNTHIENT_API_BASE_URL),
    requestTimeoutMs: parseInteger(env.REQUEST_TIMEOUT_MS, 15_000, 'REQUEST_TIMEOUT_MS', {
      min: 100,
      max: 120_000,
    }),
  };
}
