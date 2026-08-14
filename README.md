# Synthient MCP Server

A Dockerized Go [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for the [Synthient](https://synthient.com/) intelligence API. It exposes account, IP, batch-IP, and Helios domain intelligence over stateless Streamable HTTP.

The server uses the official MCP Go SDK and currently negotiates protocol `2026-07-28`. Every caller supplies its own Synthient API key; the service has no server-wide Synthient credential.

## Security model

- The service forwards the caller's `x-api-key` only to the configured Synthient origin and refuses upstream redirects.
- IP and domain path inputs are validated, canonicalized, and escaped before upstream requests.
- Credential-shaped fields and the literal caller key are removed from upstream results and errors.
- Host and browser-Origin checks protect the MCP endpoint. Proxy forwarding headers are trusted only from configured proxy CIDRs.
- Request bodies, headers, upstream duration, response size, and concurrent work are bounded.
- The container runs without root, capabilities, or a writable root filesystem.

The key is validated by Synthient when a tool calls the upstream API. A public deployment should additionally use TLS, an authenticated gateway or standards-based MCP authorization, network restrictions, and edge rate limiting. Host validation is not network access control.

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

## MCP client configuration

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

Environment-variable expansion is performed by the MCP client. If the client does not support this syntax, use its native secret store. Do not pass `SYNTHIENT_API_KEY` to the server container; it deliberately does not read that variable.

## Tools and metering

| Tool | Synthient endpoint | Behavior |
| --- | --- | --- |
| `synthient_account` | `GET /api/v4/account/me` | Reads account ownership, scopes, credits, and reset timing; credential fields are omitted |
| `synthient_lookup_ip` | `GET /api/v4/lookup/ip/{ip}` | Enriches one validated IPv4 or IPv6 address and consumes lookup credit |
| `synthient_lookup_ips` | `POST /api/v4/lookup/ips` | Enriches 1–1,000 validated addresses using Synthient's discounted batch billing |
| `synthient_lookup_domain` | `GET /api/v4/lookup/domain/{domain}` | Retrieves Helios domain intelligence and consumes lookup credit |

Lookup tools are advertised conservatively as metered, non-idempotent operations so MCP clients do not assume that automatic retries are cost-free. Results include structured content plus a short text summary rather than a duplicate full JSON document.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `HOST` | `127.0.0.1` (`0.0.0.0` in the image) | Application listen address |
| `PORT` | `3000` | Application listen port |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` | Comma-separated Host-header names |
| `ALLOWED_ORIGINS` | empty | Exact trusted cross-origins, including scheme and optional port; same-origin requests remain allowed |
| `TRUST_PROXY_HOPS` | `0` | Number of trusted hops removed from the right of the forwarding chain |
| `TRUSTED_PROXY_CIDRS` | empty | Required CIDRs for every trusted hop when `TRUST_PROXY_HOPS` is nonzero |
| `REQUEST_TIMEOUT_MS` | `15000` | Upstream timeout, from 100 to 120,000 ms |
| `READ_TIMEOUT_MS` | request timeout + 5 seconds | Complete inbound-request timeout |
| `WRITE_TIMEOUT_MS` | request timeout + 5 seconds | Complete response-write timeout |
| `IDLE_TIMEOUT_MS` | `60000` | HTTP keep-alive idle timeout |
| `SHUTDOWN_TIMEOUT_MS` | `10000` | Graceful-drain deadline |
| `MAX_HEADER_BYTES` | `32768` | Maximum inbound HTTP header size |
| `MAX_CONCURRENT_REQUESTS` | `8` | Maximum simultaneous authenticated MCP requests |
| `SYNTHIENT_API_BASE_URL` | `https://api.synthient.com/api/v4/` | Test override; HTTP is accepted only for loopback |
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
docker compose up --build -d
```

The direct TCP peer and every removed proxy hop must fall within `TRUSTED_PROXY_CIDRS`; short or inconsistent chains fail closed. Use the actual proxy-network CIDR if the proxy does not connect over host loopback. Ensure only the proxy can reach the published port. Terminate TLS and enforce MCP authentication at that proxy.

`ALLOWED_ORIGINS` permits trusted browser origins through CSRF protection; it does not enable CORS. Cross-origin browser clients also require deliberate CORS response headers at an authenticated gateway.

## Observability

Requests receive an `X-Request-ID`. Logs contain method, fixed route, status, duration, version, and safe capacity settings. They intentionally omit API keys, request/response bodies, queried IPs and domains, and forwarding chains.

Optional metrics expose only bounded counters for HTTP traffic, concurrency rejection, upstream outcome classes, and cumulative upstream duration. `/healthz` is a liveness check and does not make Synthient availability a readiness dependency.

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
