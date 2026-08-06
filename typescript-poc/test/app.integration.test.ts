import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, it } from 'node:test';

import { createApp, type AppHandle } from '../src/app.js';
import type { AppConfig } from '../src/config.js';

interface SeenRequest {
  method: string;
  url: string;
  apiKey: string | undefined;
  forwardedFor: string | undefined;
  body: string;
}

const servers: Server[] = [];
const appHandles: AppHandle[] = [];
const clients: Client[] = [];

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

afterEach(async () => {
  await Promise.all(clients.splice(0).map(async (client) => client.close()));
  await Promise.all(appHandles.splice(0).map(async (handle) => handle.close()));
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        ),
    ),
  );
});

describe('Synthient MCP HTTP server', () => {
  it('negotiates current MCP, lists tools, and forwards auth plus canonical IP', async () => {
    const seen: SeenRequest[] = [];
    const upstream = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        seen.push({
          method: request.method ?? '',
          url: request.url ?? '',
          apiKey: request.headers['x-api-key'],
          forwardedFor: request.headers['x-forwarded-for'],
          body: Buffer.concat(chunks).toString('utf8'),
        });
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({ ip: '8.8.8.8', intelligence: { risk_score: 0 } }));
      });
    });
    const upstreamPort = await listen(upstream);

    const config: AppConfig = {
      host: '127.0.0.1',
      port: 0,
      allowedHosts: ['127.0.0.1'],
      allowedOrigins: ['127.0.0.1'],
      trustProxyHops: 0,
      synthientBaseUrl: new URL(`http://127.0.0.1:${upstreamPort}/api/v4/`),
      requestTimeoutMs: 1_000,
    };
    const appHandle = createApp(config);
    appHandles.push(appHandle);
    const mcpHttpServer = createServer(appHandle.app);
    const mcpPort = await listen(mcpHttpServer);

    const client = new Client(
      { name: 'integration-test', version: '1.0.0' },
      { versionNegotiation: { mode: 'auto' } },
    );
    clients.push(client);
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${mcpPort}/mcp`),
      {
        requestInit: {
          headers: {
            'x-api-key': 'caller-key-is-preserved',
            'x-forwarded-for': '198.51.100.77',
          },
        },
      },
    );
    await client.connect(transport);

    assert.equal(client.getProtocolEra(), 'modern');
    const tools = await client.listTools();
    assert.deepEqual(tools.tools.map((tool) => tool.name), [
      'synthient_account',
      'synthient_lookup_ip',
      'synthient_lookup_ips',
      'synthient_lookup_domain',
    ]);

    const result = await client.callTool({
      name: 'synthient_lookup_ip',
      arguments: { ip: '8.8.8.8' },
    });

    assert.notEqual(result.isError, true);
    assert.deepEqual(result.structuredContent, {
      ip: '8.8.8.8',
      intelligence: { risk_score: 0 },
    });
    assert.equal(seen.length, 1);
    assert.deepEqual(seen[0], {
      method: 'GET',
      url: '/api/v4/lookup/ip/8.8.8.8',
      apiKey: 'caller-key-is-preserved',
      // The direct peer wins because TRUST_PROXY_HOPS=0; the spoofed header is discarded.
      forwardedFor: '127.0.0.1',
      body: '',
    });
  });

  it('rejects MCP requests without a Synthient API key', async () => {
    const config: AppConfig = {
      host: '127.0.0.1',
      port: 0,
      allowedHosts: ['127.0.0.1'],
      allowedOrigins: ['127.0.0.1'],
      trustProxyHops: 0,
      synthientBaseUrl: new URL('http://127.0.0.1:1/api/v4/'),
      requestTimeoutMs: 1_000,
    };
    const appHandle = createApp(config);
    appHandles.push(appHandle);
    const server = createServer(appHandle.app);
    const port = await listen(server);

    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });

    assert.equal(response.status, 401);
    const body = (await response.json()) as Record<string, unknown>;
    assert.equal(body.error, 'Unauthorized');
  });
});
