# Synthient MCP

A dockerized remote Model Context Protocol server for the [Synthient](https://docs.synthient.com/) intelligence API.

The server uses the current MCP `2026-07-28` stateless protocol and Streamable HTTP transport through the official TypeScript SDK v2. It also accepts stateless 2025-era clients on the same endpoint for compatibility.

## Tools

| Tool | Synthient endpoint | Purpose |
| --- | --- | --- |
| `synthient_account` | `GET /api/v4/account/me` | Inspect account, scopes, credits, and quota reset timing |
| `synthient_lookup_ip` | `GET /api/v4/lookup/ip/{ip}` | Enrich one IPv4 or IPv6 address |
| `synthient_lookup_ips` | `POST /api/v4/lookup/ips` | Enrich up to 1,000 IP addresses in a discounted batch |
| `synthient_lookup_domain` | `GET /api/v4/lookup/domain/{domain}` | Retrieve Helios domain and honeypot intelligence |

All tools are declared read-only, idempotent, and open-world. Results include both readable JSON text and MCP structured content.

## Authentication and caller IP forwarding

Clients authenticate with Synthient's existing mechanism:

```http
x-api-key: <YOUR_SYNTHIENT_API_KEY>
```

There is no MCP-specific credential, user database, or server-wide Synthient key. For every tool call, the server passes the exact inbound `x-api-key` value to `api.synthient.com`. The key is never logged.

The same request carries one canonical `X-Forwarded-For` address to Synthient:

- With the default `TRUST_PROXY_HOPS=0`, any inbound `X-Forwarded-For` value is discarded and the direct TCP peer address is forwarded. This prevents callers from spoofing an address.
- Behind exactly one trusted reverse proxy, set `TRUST_PROXY_HOPS=1`. The server then resolves the original caller using Express's trusted-proxy algorithm and forwards that single address.
- Increase the value only when every listed hop is an infrastructure proxy you control. An overly large value lets clients supply a false address.

TLS should terminate at the server or at the trusted reverse proxy so API keys are never sent in cleartext.

## Run with Docker

Build and start the image:

```bash
docker build -t synthient-mcp .
docker run --rm -p 3000:3000 synthient-mcp
```

Or use Compose:

```bash
docker compose up --build
```

The MCP endpoint is `http://localhost:3000/mcp`; the unauthenticated health check is `http://localhost:3000/healthz`.

Pass the API key from the MCP client's secret store or environment. A generic client configuration looks like this (exact syntax varies by host):

```json
{
  "mcpServers": {
    "synthient": {
      "type": "http",
      "url": "http://localhost:3000/mcp",
      "headers": {
        "x-api-key": "${SYNTHIENT_API_KEY}"
      }
    }
  }
}
```

Do not paste a real key into a committed configuration file.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Listen address |
| `PORT` | `3000` | Listen port |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` | Comma-separated `Host` header allowlist; set the public MCP hostname in production |
| `ALLOWED_ORIGINS` | Same as `ALLOWED_HOSTS` | Comma-separated browser `Origin` hostname allowlist |
| `TRUST_PROXY_HOPS` | `0` | Number of trusted reverse-proxy hops used to resolve the caller IP |
| `REQUEST_TIMEOUT_MS` | `15000` | Synthient API request timeout, from 100 to 120,000 ms |
| `SYNTHIENT_API_BASE_URL` | `https://api.synthient.com/api/v4/` | API base override, primarily for tests; non-local values must use HTTPS |

For a deployment at `mcp.example.com` behind one load balancer:

```bash
docker run --rm -p 3000:3000 \
  -e ALLOWED_HOSTS=mcp.example.com \
  -e ALLOWED_ORIGINS=mcp.example.com \
  -e TRUST_PROXY_HOPS=1 \
  synthient-mcp
```

Host and Origin validation are enabled through the official MCP Express adapter to protect against DNS rebinding and browser cross-origin requests. Non-browser MCP clients normally omit `Origin` and are unaffected.

## Development

Node.js 22.12 or newer is required.

```bash
npm ci
npm run typecheck
npm test
npm run dev
```

The tests use the official MCP client to negotiate the modern protocol and exercise a tool call end to end against a local mock Synthient API. They also verify exact API-key propagation, canonical caller-IP forwarding, request schemas, error mapping, and configuration validation.

## API behavior

Synthient HTTP failures become MCP tool errors that the model can read and act on. Status context is preserved without exposing credentials, and `429` responses include the upstream `Retry-After` guidance when provided. Input schemas enforce the documented 1,000-address batch limit before a request reaches Synthient.

The upstream key still determines access: `BASIC` is required for account, IP, batch, and domain tools. Synthient remains the source of truth for key validity, scopes, quota, and billing.
