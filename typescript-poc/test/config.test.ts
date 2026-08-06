import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  it('uses secure production defaults', () => {
    const config = loadConfig({});

    assert.equal(config.host, '0.0.0.0');
    assert.equal(config.port, 3000);
    assert.equal(config.trustProxyHops, 0);
    assert.equal(config.synthientBaseUrl.href, 'https://api.synthient.com/api/v4/');
    assert.ok(config.allowedHosts.includes('localhost'));
  });

  it('rejects an insecure non-local Synthient endpoint', () => {
    assert.throws(
      () => loadConfig({ SYNTHIENT_API_BASE_URL: 'http://api.example.com/api/v4' }),
      /must use HTTPS/u,
    );
  });

  it('validates proxy hop counts', () => {
    assert.throws(() => loadConfig({ TRUST_PROXY_HOPS: '-1' }), /TRUST_PROXY_HOPS/u);
    assert.throws(() => loadConfig({ TRUST_PROXY_HOPS: 'all' }), /TRUST_PROXY_HOPS/u);
  });
});
