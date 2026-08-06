# Synthient MCP — Go

A production-oriented, dockerized remote Model Context Protocol server for the [Synthient](https://docs.synthient.com/) intelligence API, implemented with the official MCP Go SDK.

The server negotiates the current MCP `2026-07-28` protocol over Streamable HTTP. It is stateless, so requests can be distributed across replicas without shared session storage.

## Tools

| Tool | Synthient endpoint | Purpose |
| --- | --- | --- |
| `synthient_account` | `GET /api/v4/account/me` | Inspect account, scopes, credits, and quota reset timing; echoed credentials are omitted |
| `synthient_lookup_ip` | `GET /api/v4/lookup/ip/{ip}` | Enrich one IPv4 or IPv6 address |
| `synthient_lookup_ips` | `POST /api/v4/lookup/ips` | Enrich up to 1,000 IP addresses in a discounted batch |
| `synthient_lookup_domain` | `GET /api/v4/lookup/domain/{domain}` | Retrieve Helios domain and honeypot intelligence |

All tools are declared read-only, idempotent, and open-world. Responses are returned as MCP structured content and readable JSON text.

## Authentication and caller IP forwarding

Clients use Synthient's existing authentication mechanism:

```http
x-api-key: <YOUR_SYNTHIENT_API_KEY>
```

The server does not issue another credential and does not keep a server-wide Synthient key. It passes the exact inbound `x-api-key` to Synthient for every tool call and never logs it.

The upstream request also carries one canonical `X-Forwarded-For` address:

- With the default `TRUST_PROXY_HOPS=0`, the server discards any caller-supplied forwarding chain and uses the direct TCP peer. This prevents spoofing.
- Behind exactly one trusted reverse proxy, set `TRUST_PROXY_HOPS=1`. The server removes the trusted hop from the right side of the chain and forwards the resolved client address.
- Increase the value only when every counted hop is a proxy you control.

Terminate TLS at the server or at a trusted reverse proxy so API keys are not transmitted in cleartext.

## Run with Docker

From this directory:

```bash
docker build -t synthient-mcp-go .
docker run --rm -p 3000:3000 synthient-mcp-go
```

Or use Compose:

```bash
docker compose up --build
```

The MCP endpoint is `http://localhost:3000/mcp`. The unauthenticated health endpoint is `http://localhost:3000/healthz`.

A generic MCP client configuration looks like this; exact syntax varies by host:

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

Keep real keys in the client's secret store or environment, never in committed configuration.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Listen address |
| `PORT` | `3000` | Listen port |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` | Comma-separated `Host` header allowlist; add the public MCP hostname in production |
| `ALLOWED_ORIGINS` | Same as `ALLOWED_HOSTS` | Comma-separated browser `Origin` hostname allowlist |
| `TRUST_PROXY_HOPS` | `0` | Number of trusted reverse-proxy hops used to resolve the caller IP |
| `REQUEST_TIMEOUT_MS` | `15000` | Synthient request timeout, from 100 to 120,000 ms |
| `SYNTHIENT_API_BASE_URL` | `https://api.synthient.com/api/v4/` | API base override for testing; non-local values must use HTTPS |

For a deployment at `mcp.example.com` behind one load balancer:

```bash
docker run --rm -p 3000:3000 \
  -e ALLOWED_HOSTS=mcp.example.com \
  -e ALLOWED_ORIGINS=mcp.example.com \
  -e TRUST_PROXY_HOPS=1 \
  synthient-mcp-go
```

Host and Origin validation protect the HTTP transport from DNS rebinding and browser cross-origin requests. Non-browser MCP clients normally omit `Origin` and are unaffected.

## Development

Go 1.24 or newer is required.

```bash
go test ./...
go vet ./...
go run ./cmd/server
```

The integration suite uses the official MCP Go client to negotiate protocol `2026-07-28`, list all four tools, and execute a tool against a mock Synthient API. Tests also cover exact API-key propagation, canonical caller-IP forwarding, error mapping, configuration validation, and HTTP defenses.

Synthient HTTP failures become MCP tool errors with useful status context but no credential data. A `429` response retains upstream `Retry-After` guidance. The caller's key remains the source of truth for validity, scopes, quota, and billing.
