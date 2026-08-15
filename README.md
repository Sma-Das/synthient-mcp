# Synthient MCP Server

A Dockerized Go [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for the [Synthient](https://synthient.com/) intelligence API. It exposes account, IP, domain, snapshot, live-feed, and protobuf intelligence over stateless Streamable HTTP.

This is an independent, community-maintained project. It is not an official Synthient product and is not affiliated with or endorsed by Synthient.

The server uses the official MCP Go SDK and currently negotiates protocol `2026-07-28`. It supports local stdio, per-caller API keys over HTTP, and standards-based OAuth protection for managed remote deployments.

## Security model

- In API-key mode, the service forwards the caller's `x-api-key` only to the configured Synthient origin and refuses upstream redirects.
- In OAuth mode, MCP access tokens are audience-validated and never passed through; the server uses a separate Synthient credential.
- The gRPC reflection endpoint is fixed by server configuration, uses TLS, and cannot be overridden by MCP callers.
- IP and domain path inputs are validated, canonicalized, and escaped before upstream requests.
- Credential-shaped fields and the literal caller key are removed from upstream results and errors.
- Host and browser-Origin checks protect the MCP endpoint. Caller-IP forwarding is disabled by default and trusts proxy headers only when explicitly enabled with configured proxy CIDRs.
- Request bodies, headers, upstream duration, response size, and concurrent work are bounded.
- The container runs without root, capabilities, or a writable root filesystem.

API-key mode is intended for loopback and controlled self-hosting. Public deployments should use OAuth mode or an authenticated gateway, TLS, network restrictions, and edge rate limiting. Host validation is not network access control.

## Quick start with Docker

Run the published image on loopback only:

```bash
docker pull smadas/synthient-mcp:latest
docker run --rm -p 127.0.0.1:3000:3000 smadas/synthient-mcp:latest
```

For reproducible production deployment, pin the image digest shown by the release workflow rather than relying on a mutable tag.

Build from source:

```bash
docker compose up --build
```

The Compose configuration publishes on `127.0.0.1:3000` by default. Once running:

| URL | Purpose |
| --- | --- |
| `http://localhost:3000/mcp` | MCP Streamable HTTP endpoint |
| `http://localhost:3000/healthz` | Liveness and build identity |
| `http://localhost:3000/metrics` | Optional low-cardinality metrics |

## HTTP client configuration

Store the Synthient key in the MCP client's environment or secret store:

```bash
export SYNTHIENT_API_KEY='your-synthient-api-key'
```

Then configure the client to send it with every MCP request:

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

Environment-variable expansion is performed by the MCP client. If the client does not support this syntax, use its native secret store. In the default `AUTH_MODE=api_key`, the server deliberately ignores a server-side `SYNTHIENT_API_KEY`.

## Local stdio

Build the binary, store the key in the launcher's environment, and run:

```bash
make binary
SYNTHIENT_API_KEY='your-synthient-api-key' ./go/synthient-mcp stdio
```

Example MCP configuration:

```json
{
  "mcpServers": {
    "synthient": {
      "command": "/absolute/path/to/synthient-mcp",
      "args": ["stdio"],
      "env": { "SYNTHIENT_API_KEY": "${SYNTHIENT_API_KEY}" }
    }
  }
}
```

The stdio transport reads credentials from the environment, writes only MCP protocol messages to stdout, and uses the same tools, validation, timeouts, and endpoint restrictions as HTTP.

## OAuth-protected HTTP

Set `AUTH_MODE=oauth` for a managed remote deployment. The server validates JWT signatures through the configured JWKS endpoint, issuer, audience, expiration, subject, and required scopes. It publishes RFC 9728 Protected Resource Metadata and returns its URL in `WWW-Authenticate` challenges so compatible MCP clients can discover the authorization server.

OAuth access tokens and Synthient credentials are deliberately separate. `SYNTHIENT_API_KEY` is a server-side downstream credential only in this mode and is never derived from or replaced by the inbound bearer token.

## Tools and metering

| Tool | Synthient endpoint | Behavior |
| --- | --- | --- |
| `get_account` | `GET /api/v4/account/me` | Reads account ownership, scopes, credits, and reset timing; credential fields are omitted |
| `lookup_ip` | `GET /api/v4/lookup/ip/{ip}` or `POST /api/v4/lookup/ips` | Enriches 1–1,000 validated addresses, using discounted batch billing for multiple addresses |
| `lookup_domain` | `GET /api/v4/lookup/domain/{domain}` | Retrieves Helios domain intelligence and consumes lookup credit |
| `list_feed_streams` | local catalog | Lists seven snapshot feeds, aliases, live availability, and required scopes |
| `list_feed_snapshots` | `GET /api/v4/feeds/.../export` | Lists daily and hourly Parquet snapshots with bounded cursor pagination |
| `feed_snapshot_meta` | `GET /api/v4/feeds/.../export/{date}/meta` | Reads checksum, size, rows, and Parquet schema for one validated snapshot |
| `sample_stream` | `GET /api/v4/feeds/.../stream` | Returns at most 50 filtered events, 1 MiB of output, or 15 seconds of live data |
| `grpc_schema` | Synthient gRPC reflection | Returns a bounded service summary; descriptor JSON is optional and limited to 1 MiB |

Tool names and response shapes follow Synthient's official MCP contract. Lookup tools are advertised conservatively as metered, non-idempotent operations so MCP clients do not assume that automatic retries are cost-free. Results use the official typed Synthient SDK models and include structured content plus a useful short text summary.

The server deliberately does not expose snapshot downloads as MCP results. Parquet files are too large for model context; use Synthient's official CLI for download and checksum verification.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `HOST` | `127.0.0.1` (`0.0.0.0` in the image) | Application listen address |
| `PORT` | `3000` | Application listen port |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` | Comma-separated Host-header names |
| `ALLOWED_ORIGINS` | empty | Exact trusted cross-origins, including scheme and optional port; same-origin requests remain allowed |
| `TRUST_PROXY_HOPS` | `0` | Number of trusted hops removed from the right of the forwarding chain |
| `TRUSTED_PROXY_CIDRS` | empty | Required CIDRs for every trusted hop when `TRUST_PROXY_HOPS` is nonzero |
| `FORWARD_CLIENT_IP` | `false` | Forward the canonical caller IP to Synthient; enable only when required |
| `CORS_ENABLED` | `false` | Return exact-origin CORS headers and credential-free preflight responses for `ALLOWED_ORIGINS` |
| `REQUEST_TIMEOUT_MS` | `15000` | Upstream timeout, from 100 to 120,000 ms |
| `READ_TIMEOUT_MS` | request timeout + 5 seconds | Complete inbound-request timeout |
| `WRITE_TIMEOUT_MS` | request timeout + 5 seconds | Complete response-write timeout |
| `IDLE_TIMEOUT_MS` | `60000` | HTTP keep-alive idle timeout |
| `SHUTDOWN_TIMEOUT_MS` | `10000` | Graceful-drain deadline |
| `MAX_HEADER_BYTES` | `32768` | Maximum inbound HTTP header size |
| `MAX_CONCURRENT_REQUESTS` | `8` | Maximum simultaneous authenticated MCP requests |
| `MAX_CONCURRENT_PER_PRINCIPAL` | `2` | Per-API-key or per-OAuth-subject concurrency ceiling |
| `SYNTHIENT_API_BASE_URL` | `https://api.synthient.com/api/v4/` | Test override; HTTP is accepted only for loopback |
| `SYNTHIENT_GRPC_ENDPOINT` | `grpc.synthient.com:443` | TLS gRPC reflection endpoint fixed at server startup; MCP callers cannot override it |
| `AUTH_MODE` | `api_key` | `api_key` for per-caller keys or `oauth` for a protected remote resource |
| `SYNTHIENT_API_KEY` | empty | Server-side downstream key required only for OAuth mode and stdio |
| `OAUTH_ISSUER_URL` | empty | HTTPS authorization-server issuer required in OAuth mode |
| `OAUTH_JWKS_URL` | empty | HTTPS JWT verification key set required in OAuth mode |
| `OAUTH_AUDIENCE` | empty | Required JWT audience for this MCP resource |
| `MCP_RESOURCE_URL` | empty | Canonical public MCP URL advertised in protected-resource metadata |
| `OAUTH_REQUIRED_SCOPES` | `mcp:tools` | Comma-separated scopes required on every MCP access token |
| `METRICS_ENABLED` | `false` | Expose `GET /metrics`; protect it at the network or proxy layer |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `LOG_FORMAT` | `text` | `text` or `json` structured logs |

Docker Compose uses separate host-publication settings:

| Variable | Default | Description |
| --- | --- | --- |
| `PUBLISHED_HOST` | `127.0.0.1` | Host interface on which Docker publishes the service |
| `PUBLISHED_PORT` | `3000` | Published host port |
| `APP_PORT` | `3000` | Port used inside the container |

Copy `.env.example` for non-secret deployment settings. Never place a Synthient API key in that file.

### Trusted reverse proxy example

For `mcp.example.com` behind one reverse proxy running on the Docker host:

```bash
PUBLISHED_HOST=127.0.0.1 \
ALLOWED_HOSTS=mcp.example.com \
ALLOWED_ORIGINS=https://app.example.com \
TRUST_PROXY_HOPS=1 \
TRUSTED_PROXY_CIDRS=127.0.0.0/8 \
FORWARD_CLIENT_IP=true \
docker compose up --build -d
```

Caller-IP forwarding is normally unnecessary. When enabled, the direct TCP peer and every removed proxy hop must fall within `TRUSTED_PROXY_CIDRS`; short or inconsistent chains fail closed. Use the actual proxy-network CIDR if the proxy does not connect over host loopback. Ensure only the proxy can reach the published port.

`ALLOWED_ORIGINS` always controls browser-origin admission. Set `CORS_ENABLED=true` only when those origins must call the server directly; preflights remain exact-host and exact-origin, and wildcard credentialed CORS is never emitted.

## Observability

Requests receive an `X-Request-ID`. Logs contain method, fixed route, status, duration, version, and safe capacity settings. They intentionally omit API keys, request/response bodies, queried IPs and domains, and forwarding chains.

Optional metrics expose only bounded counters for HTTP traffic, global and per-principal concurrency rejection, upstream outcome classes, and cumulative upstream duration. `/healthz` is a liveness check and does not make Synthient availability a readiness dependency.

## Development

Go 1.25 or newer, Docker, and Make are supported:

```bash
make test
make race
make cover
make ci
make smoke
```

The Go module remains under `go/`; root Make targets provide a consistent interface for local work and CI.

CI checks formatting, module tidiness, vet, unit/integration tests, the race detector, vulnerability data, compilation, Dockerfile validation, and a container health smoke test. Security-sensitive parsing also has fuzz targets.

## Publishing

Create and push an existing semantic-version tag:

```bash
git tag v0.2.0
git push origin v0.2.0
```

Release jobs re-run all verification before publishing `linux/amd64` and `linux/arm64` images. Stable releases receive full, minor, major, and `latest` tags; prereleases receive only their full prerelease version. Runtime MCP metadata, User-Agent, health output, and image metadata share the injected version and commit. Published images include an SBOM and provenance, and the workflow reports the immutable image digest.

The repository requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. See [SECURITY.md](SECURITY.md) for vulnerability and credential-handling guidance and [CONTRIBUTING.md](CONTRIBUTING.md) for the change workflow.

## License

Licensed under the [Apache License 2.0](LICENSE).
