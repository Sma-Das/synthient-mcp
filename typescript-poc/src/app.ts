import { createMcpExpressApp } from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler } from '@modelcontextprotocol/server';
import type { Express } from 'express';

import { requireSynthientCredentials } from './auth.js';
import type { AppConfig } from './config.js';
import { createSynthientMcpServer } from './mcp-server.js';

export interface AppHandle {
  app: Express;
  close: () => Promise<void>;
}

export function createApp(config: AppConfig): AppHandle {
  const handler = createMcpHandler(
    (context) =>
      createSynthientMcpServer(context, {
        baseUrl: config.synthientBaseUrl,
        timeoutMs: config.requestTimeoutMs,
      }),
    {
      // The same stateless endpoint supports both current MCP and 2025-era clients.
      legacy: 'stateless',
      responseMode: 'auto',
      onerror: (error) => console.error('MCP request failed:', error.message),
    },
  );

  const app = createMcpExpressApp({
    host: config.host,
    allowedHosts: config.allowedHosts,
    allowedOrigins: config.allowedOrigins,
    jsonLimit: '1mb',
  });

  app.set('trust proxy', config.trustProxyHops === 0 ? false : config.trustProxyHops);

  app.get('/healthz', (_request, response) => {
    response.json({ status: 'ok' });
  });

  const nodeHandler = toNodeHandler(handler, {
    onerror: (error) => console.error('HTTP adapter failed:', error.message),
  });

  app.all('/mcp', requireSynthientCredentials(), (request, response) => {
    void nodeHandler(request, response, request.body);
  });

  return { app, close: () => handler.close() };
}
