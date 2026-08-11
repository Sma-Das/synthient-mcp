# Synthient MCP Server

A production-ready, Dockerized Go [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for the [Synthient](https://synthient.com/) intelligence API. Connect AI clients to IP enrichment, batch IP lookup, Helios domain and honeypot intelligence, and Synthient account quota data through Streamable HTTP.

The server uses the official MCP Go SDK, negotiates protocol `2026-07-28`, and runs statelessly for safe horizontal scaling. The Go service is the repository’s only implementation.

## Features

- Four read-only, idempotent Synthient intelligence tools
- Remote MCP over stateless Streamable HTTP
- Caller-supplied Synthient authentication with no stored server credential
- Trusted-proxy-aware caller IP forwarding
- Host and browser-origin validation
- Timeouts, request-size limits, graceful shutdown, and container health checks
- Multi-stage, non-root Docker image and Docker Compose configuration

## Quick start with Docker

Run the published image from Docker Hub:

```bash
docker pull smadas/synthient-mcp:latest
docker run --rm -p 3000:3000 smadas/synthient-mcp:latest
```

To build from source, start the Synthient MCP server from the repository root:

```bash
docker compose up --build
```

Or build and run the image directly:

```bash
docker build -t synthient-mcp .
docker run --rm -p 3000:3000 synthient-mcp
```

Published images support `linux/amd64` and `linux/arm64`. Use an immutable version tag such as `smadas/synthient-mcp:1.2.3` in production instead of `latest`.

Once running:

| URL | Purpose |
| --- | --- |
| `http://localhost:3000/mcp` | MCP Streamable HTTP endpoint |
| `http://localhost:3000/healthz` | Container health endpoint |

## MCP client configuration

MCP clients supply an existing Synthient API key in the `x-api-key` request header:

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

Keep real API keys in your MCP client’s secret store or environment. Never commit them to source control.

## Synthient MCP tools

| Tool | Synthient endpoint | Purpose |
| --- | --- | --- |
| `synthient_account` | `GET /api/v4/account/me` | Inspect account, scopes, credits, and quota reset timing; echoed credentials are omitted |
| `synthient_lookup_ip` | `GET /api/v4/lookup/ip/{ip}` | Enrich one IPv4 or IPv6 address |
| `synthient_lookup_ips` | `POST /api/v4/lookup/ips` | Enrich as many as 1,000 IP addresses in a discounted batch |
| `synthient_lookup_domain` | `GET /api/v4/lookup/domain/{domain}` | Retrieve Helios domain and honeypot intelligence |

Tool results include MCP structured content and readable JSON text. Synthient remains the source of truth for key validity, API scopes, quota, and billing.

## Authentication and caller IP forwarding

The server does not issue a separate MCP credential and does not keep a server-wide Synthient key. It forwards the exact inbound `x-api-key` value to Synthient for each tool call and never logs it.

Each upstream request also carries one canonical `X-Forwarded-For` address:

- With the default `TRUST_PROXY_HOPS=0`, the server discards caller-supplied forwarding chains and uses the direct TCP peer to prevent spoofing.
- Behind exactly one trusted reverse proxy, set `TRUST_PROXY_HOPS=1`. The server removes that trusted hop from the right side of the chain and forwards the resolved client address.
- Increase the value only when every counted hop is a proxy you control.

Terminate TLS at the server or a trusted reverse proxy so API keys are not transmitted in cleartext.

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
ALLOWED_HOSTS=mcp.example.com \
ALLOWED_ORIGINS=mcp.example.com \
TRUST_PROXY_HOPS=1 \
docker compose up --build -d
```

Host and Origin validation protect the MCP transport from DNS rebinding and browser cross-origin requests. Non-browser MCP clients normally omit `Origin` and are unaffected.

## Development

Go 1.25 or newer is required for local development:

```bash
cd go
go test ./...
go vet ./...
go run ./cmd/server
```

## Publishing Docker images

Pushing a semantic-version Git tag publishes a multi-platform image to [Docker Hub](https://hub.docker.com/r/smadas/synthient-mcp). For example:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `v1.2.3` Git tag produces the Docker tags `1.2.3`, `1.2`, `1`, and `latest`. The workflow can also be started manually from GitHub Actions with a semantic version such as `v1.2.3`.

The repository must define the GitHub Actions variable `DOCKERHUB_USERNAME` and secret `DOCKERHUB_TOKEN`. The Docker Hub access token needs read and write permission for that namespace. Published images include an SBOM and build-provenance attestations.

The integration suite uses the official MCP Go client to negotiate protocol `2026-07-28`, list all four tools, and execute calls against a mock Synthient API. Tests also cover exact API-key propagation, canonical caller-IP forwarding, error mapping, configuration validation, and HTTP defenses.

## API behavior

Synthient HTTP failures become MCP tool errors with useful status context but no credential data. A `429` response retains upstream `Retry-After` guidance so clients can react appropriately.
