import { createServer } from 'node:http';

import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const { app, close } = createApp(config);
const httpServer = createServer(app);

httpServer.listen(config.port, config.host, () => {
  console.log(`Synthient MCP server listening on http://${config.host}:${config.port}/mcp`);
});

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}; shutting down`);

  httpServer.closeIdleConnections();
  await close();
  await new Promise<void>((resolve, reject) => {
    httpServer.close((error) => (error ? reject(error) : resolve()));
  });
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    void shutdown(signal)
      .then(() => process.exit(0))
      .catch((error: unknown) => {
        console.error('Shutdown failed:', error);
        process.exit(1);
      });
  });
}
