# Changelog

Notable changes are recorded here. This project follows semantic versioning.

## 1.1.0 - 2026-11-26

### Security

- Upgrade `golang.org/x/net`, `google.golang.org/grpc`, `go-jose`, the MCP Go SDK, and other modules; `govulncheck` reports no reachable vulnerabilities.
- Require Go 1.26.11 or newer, the first 1.26 release with the `net/http` fix for GO-2026-6859. Build release binaries and the container with Go 1.27.
- Bound OAuth JWKS fetches with a dedicated timeout and 1 MiB response cap, and give each token verification a deadline, so a stalled identity provider cannot exhaust MCP request slots.
- Accept ES, PS, and EdDSA access tokens in addition to RS256.
- Reject JSON-RPC batch requests so each tool call is counted against concurrency and rate limits. The check runs after the per-principal limits, so an over-limit caller is refused before its body is read.
- When the per-principal rate table is full, evict the soonest-expiring window that still has quota instead of refusing every new principal, so floods of unverified API keys cannot lock out legitimate callers. Exhausted windows are never evicted.
- Normalize upstream `Retry-After` to whole seconds instead of relaying the raw header, and drop JSON properties whose names contain the caller credential.
- Map gRPC reflection failures to status codes rather than relaying upstream status text, and cap schema summaries by file, service, and method count and by serialized size.
- Log the matched route pattern instead of the raw request path.
- Release jobs build the commit the verified tag resolves to, require that commit to be on `main`, re-check the remote tag before creating the GitHub release, and only move `latest`, `MAJOR`, and `MAJOR.MINOR` image tags forward among releases on `main`.

### Fixed

- Trusted-proxy client-IP forwarding stripped `X-Forwarded-For` before reading it, so every forwarded MCP request failed with HTTP 400.
- Browser clients can complete current MCP calls: CORS preflights allow `Mcp-Method` and `Mcp-Name`, responses expose `WWW-Authenticate`, and same-origin requests, including behind a trusted TLS proxy, are admitted without being listed in `ALLOWED_ORIGINS`.
- Live samples use a transport without the lookup response-header timeout, so `STREAM_TIMEOUT_MS` above `REQUEST_TIMEOUT_MS` works. They count bytes as read from the connection, cap the serialized redacted output, reject non-object events, and send the versioned `User-Agent`.
- Legacy tool aliases return their JSON payload as text again, matching v0.1.
- The container health check probes `::1` for IPv6 wildcard binds and the configured address for specific binds, and ignores `HTTP_PROXY`.
- `make fmt-check` no longer passes silently when `gofmt` is not on `PATH`.
- `make smoke` uses per-run image and container names, so concurrent runs on a shared Docker daemon do not remove each other's resources.
- `.env.example` no longer pins read and write timeouts that reject a larger `STREAM_TIMEOUT_MS`.

### Changed

- CI tests Go 1.26 and 1.27, and uses staticcheck v0.8.2 and govulncheck v1.10.0.
- The Docker quick start applies the same read-only, no-capability hardening as Compose.

## 1.0.0 - 2026-08-16

### Security

- Validate and canonicalize IP and domain lookup inputs.
- Escape upstream URL path segments and reject upstream redirects.
- Redact caller credentials from all upstream success and error payloads.
- Require trusted proxy CIDRs and fail closed on inconsistent forwarding chains.
- Use a deny-by-default Docker build context.

### Reliability

- Await graceful shutdown and bound headers, complete requests, upstream calls, and concurrency.
- Give live samples an independent server-configured deadline and enforce per-principal request rates.
- Add secret-safe request telemetry, health build identity, and optional bounded metrics.
- Use the official typed Synthient SDK contracts and current flat domain response model.

### Changed

- Align account, IP, and domain tool names and response shapes with Synthient's official MCP server.
- Combine single and batch IP enrichment in `lookup_ip` and return useful text summaries alongside structured output.

### Added

- Add the official feed catalog, snapshot listing, snapshot metadata, live sampling, and gRPC schema tools.
- Bound live samples by validated stream, filter count, event size, total bytes, matching event count, and deadline.
- Restrict gRPC reflection to a TLS endpoint selected by server configuration and return summaries by default.
- Add local stdio transport using environment-provided Synthient credentials.
- Add OAuth resource-server mode with JWT verification, scope enforcement, RFC 9728 discovery, and strict token separation.
- Add exact-origin opt-in CORS and per-principal concurrency limits.
- Add opt-in aliases for clients migrating from this project's original tool names.

### Privacy

- Disable forwarding caller IP addresses to Synthient by default and discard spoofed forwarding headers unless explicitly enabled.

### Delivery

- Add CI, release verification, immutable build identity, stable-only `latest` tagging, dependency automation, a scratch runtime image, and hardened Docker Compose defaults.
- Publish checksummed native stdio binaries for Linux, macOS, and Windows from the same verified tag as the container image.
- Add an Apache-2.0 license and clarify that this is an independent community project.
