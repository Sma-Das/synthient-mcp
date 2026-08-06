import { McpServer, type McpRequestContext, type ServerContext } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

import { SynthientApiError, SynthientClient } from './synthient-client.js';

const outputSchema = z.looseObject({});
const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export interface SynthientMcpServerOptions {
  baseUrl: URL;
  timeoutMs: number;
}

function toolSuccess(data: Record<string, unknown>) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }],
    structuredContent: data,
  };
}

function accountOutput(data: Record<string, unknown>): Record<string, unknown> {
  const { api_key: _apiKey, apiKey: _camelCaseApiKey, ...safe } = data;
  return safe;
}

function toolFailure(error: unknown) {
  let message = 'Synthient request failed unexpectedly. Retry the request.';

  if (error instanceof SynthientApiError) {
    message = error.message;
    if (error.status === 429 && error.retryAfter) {
      message += ` Retry after ${error.retryAfter} seconds.`;
    }
  } else if (error instanceof Error && error.name === 'TimeoutError') {
    message = 'Synthient API request timed out. Retry the request.';
  } else if (error instanceof Error && error.name === 'AbortError') {
    message = 'Synthient API request was cancelled.';
  }

  return {
    content: [{ type: 'text' as const, text: message }],
    isError: true as const,
  };
}

async function runTool(
  operation: (signal: AbortSignal) => Promise<Record<string, unknown>>,
  context: ServerContext,
) {
  try {
    return toolSuccess(await operation(context.mcpReq.signal));
  } catch (error) {
    return toolFailure(error);
  }
}

function getRequestCredential(context: McpRequestContext, header: string): string {
  const value = context.requestInfo?.headers.get(header);
  if (!value) throw new Error(`Missing required ${header} request header`);
  return value;
}

export function createSynthientMcpServer(
  context: McpRequestContext,
  options: SynthientMcpServerOptions,
): McpServer {
  const client = new SynthientClient({
    apiKey: getRequestCredential(context, 'x-api-key'),
    forwardedFor: getRequestCredential(context, 'x-forwarded-for'),
    baseUrl: options.baseUrl,
    timeoutMs: options.timeoutMs,
  });

  const server = new McpServer(
    {
      name: 'synthient-mcp',
      title: 'Synthient Intelligence',
      version: '0.1.0',
    },
    {
      instructions:
        'Use these read-only tools to enrich IP addresses, inspect domain honeypot activity, and check the caller\'s Synthient account scopes and quota.',
    },
  );

  server.registerTool(
    'synthient_account',
    {
      title: 'Get Synthient account',
      description:
        'Return account ownership, granted API scopes, remaining lookup credits, and quota reset timing for the supplied Synthient API key.',
      outputSchema,
      annotations: readOnlyAnnotations,
    },
    async (toolContext) =>
      runTool(
        async (signal) => accountOutput(await client.getAccount(signal)),
        toolContext,
      ),
  );

  server.registerTool(
    'synthient_lookup_ip',
    {
      title: 'Look up IP intelligence',
      description:
        'Enrich one IPv4 or IPv6 address with network, location, risk, behavior, anonymizer category, device, and provider intelligence from Synthient.',
      inputSchema: z.object({
        ip: z.string().min(2).max(45).describe('IPv4 or IPv6 address to enrich.'),
      }),
      outputSchema,
      annotations: readOnlyAnnotations,
    },
    async ({ ip }, toolContext) =>
      runTool((signal) => client.lookupIp(ip, signal), toolContext),
  );

  server.registerTool(
    'synthient_lookup_ips',
    {
      title: 'Look up multiple IPs',
      description:
        'Enrich 1 to 1,000 IPv4 or IPv6 addresses in one discounted Synthient batch lookup. Invalid and duplicate IPs are excluded from billing by Synthient.',
      inputSchema: z.object({
        ips: z
          .array(z.string().min(2).max(45))
          .min(1)
          .max(1_000)
          .describe('IPv4 or IPv6 addresses to enrich, up to 1,000 entries.'),
      }),
      outputSchema,
      annotations: readOnlyAnnotations,
    },
    async ({ ips }, toolContext) =>
      runTool((signal) => client.lookupIps(ips, signal), toolContext),
  );

  server.registerTool(
    'synthient_lookup_domain',
    {
      title: 'Look up domain intelligence',
      description:
        'Return Synthient Helios honeypot intelligence for a domain, including observation status, event statistics, time series, top subdomains and ports, and recent events.',
      inputSchema: z.object({
        domain: z
          .string()
          .min(1)
          .max(253)
          .describe('Domain name to inspect, such as example.com.'),
      }),
      outputSchema,
      annotations: readOnlyAnnotations,
    },
    async ({ domain }, toolContext) =>
      runTool((signal) => client.lookupDomain(domain, signal), toolContext),
  );

  return server;
}
