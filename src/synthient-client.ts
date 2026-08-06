const USER_AGENT = 'synthient-mcp/0.1.0';

export interface SynthientClientOptions {
  apiKey: string;
  forwardedFor: string;
  baseUrl: URL;
  timeoutMs: number;
  fetch?: typeof globalThis.fetch;
}

export class SynthientApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfter?: string,
  ) {
    super(message);
    this.name = 'SynthientApiError';
  }
}

function stringifyErrorBody(value: unknown): string | undefined {
  if (typeof value === 'string') return value.trim() || undefined;
  if (value && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    for (const key of ['message', 'error', 'detail']) {
      const candidate = object[key];
      if (typeof candidate === 'string' && candidate.trim()) return candidate;
    }
  }
  return undefined;
}

export class SynthientClient {
  readonly #apiKey: string;
  readonly #forwardedFor: string;
  readonly #baseUrl: URL;
  readonly #timeoutMs: number;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: SynthientClientOptions) {
    this.#apiKey = options.apiKey;
    this.#forwardedFor = options.forwardedFor;
    this.#baseUrl = options.baseUrl;
    this.#timeoutMs = options.timeoutMs;
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  getAccount(signal?: AbortSignal): Promise<Record<string, unknown>> {
    return this.#request('account/me', signal ? { signal } : {});
  }

  lookupIp(ip: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
    return this.#request(`lookup/ip/${encodeURIComponent(ip)}`, signal ? { signal } : {});
  }

  lookupIps(ips: string[], signal?: AbortSignal): Promise<Record<string, unknown>> {
    return this.#request('lookup/ips', {
      method: 'POST',
      body: JSON.stringify({ ips }),
      ...(signal ? { signal } : {}),
    });
  }

  lookupDomain(domain: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
    return this.#request(
      `lookup/domain/${encodeURIComponent(domain)}`,
      signal ? { signal } : {},
    );
  }

  async #request(
    path: string,
    init: { method?: 'POST'; body?: string; signal?: AbortSignal },
  ): Promise<Record<string, unknown>> {
    const timeoutSignal = AbortSignal.timeout(this.#timeoutMs);
    const signal = init.signal
      ? AbortSignal.any([init.signal, timeoutSignal])
      : timeoutSignal;

    const response = await this.#fetch(new URL(path, this.#baseUrl), {
      method: init.method ?? 'GET',
      ...(init.body ? { body: init.body } : {}),
      signal,
      headers: {
        accept: 'application/json',
        ...(init.body ? { 'content-type': 'application/json' } : {}),
        'user-agent': USER_AGENT,
        'x-api-key': this.#apiKey,
        'x-forwarded-for': this.#forwardedFor,
      },
    });

    const rawBody = await response.text();
    let body: unknown = rawBody;
    if (rawBody) {
      try {
        body = JSON.parse(rawBody) as unknown;
      } catch {
        // Keep the text body so upstream non-JSON errors still remain useful.
      }
    }
    if (!response.ok) {
      const detail = stringifyErrorBody(body);
      const suffix = detail ? `: ${detail}` : '';
      throw new SynthientApiError(
        `Synthient API returned HTTP ${response.status}${suffix}`,
        response.status,
        response.headers.get('retry-after') ?? undefined,
      );
    }

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw new SynthientApiError('Synthient API returned an invalid JSON object', 502);
    }

    return body as Record<string, unknown>;
  }
}
