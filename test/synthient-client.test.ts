import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { SynthientApiError, SynthientClient } from '../src/synthient-client.js';

function createClient(fetch: typeof globalThis.fetch): SynthientClient {
  return new SynthientClient({
    apiKey: 'exact-caller-key',
    forwardedFor: '203.0.113.9',
    baseUrl: new URL('https://api.synthient.test/api/v4/'),
    timeoutMs: 1_000,
    fetch,
  });
}

describe('SynthientClient', () => {
  it('forwards the caller credentials and address without replacing them', async () => {
    const calls: Array<[URL | RequestInfo, RequestInit | undefined]> = [];
    const fetch: typeof globalThis.fetch = async (input, init) => {
      calls.push([input, init]);
      return new Response(JSON.stringify({ ip: '2001:db8::1' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    await createClient(fetch).lookupIp('2001:db8::1');

    assert.equal(calls.length, 1);
    const [url, init] = calls[0]!;
    assert.equal(
      url.toString(),
      'https://api.synthient.test/api/v4/lookup/ip/2001%3Adb8%3A%3A1',
    );
    assert.equal(new Headers(init?.headers).get('x-api-key'), 'exact-caller-key');
    assert.equal(new Headers(init?.headers).get('x-forwarded-for'), '203.0.113.9');
  });

  it('sends the documented batch request shape', async () => {
    const calls: Array<[URL | RequestInfo, RequestInit | undefined]> = [];
    const fetch: typeof globalThis.fetch = async (input, init) => {
      calls.push([input, init]);
      return Response.json({ results: [] });
    };

    await createClient(fetch).lookupIps(['8.8.8.8', '1.1.1.1']);

    const [url, init] = calls[0]!;
    assert.equal(url.toString(), 'https://api.synthient.test/api/v4/lookup/ips');
    assert.equal(init?.method, 'POST');
    assert.equal(init?.body, '{"ips":["8.8.8.8","1.1.1.1"]}');
  });

  it('preserves downstream status and Retry-After on errors', async () => {
    const fetch: typeof globalThis.fetch = async () =>
      Response.json(
        { message: 'rate limit exceeded' },
        { status: 429, headers: { 'retry-after': '12' } },
      );

    const error = await createClient(fetch).getAccount().catch((caught: unknown) => caught);

    assert.ok(error instanceof SynthientApiError);
    assert.equal(error.status, 429);
    assert.equal(error.retryAfter, '12');
    assert.match(error.message, /rate limit exceeded/u);
  });
});
