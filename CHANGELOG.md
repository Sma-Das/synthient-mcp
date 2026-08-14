# Changelog

Notable changes are recorded here. This project follows semantic versioning.

## Unreleased

### Security

- Validate and canonicalize IP and domain lookup inputs.
- Escape upstream URL path segments and reject upstream redirects.
- Redact caller credentials from all upstream success and error payloads.
- Require trusted proxy CIDRs and fail closed on inconsistent forwarding chains.
- Use a deny-by-default Docker build context.

### Reliability

- Await graceful shutdown and bound headers, complete requests, upstream calls, and concurrency.
- Add secret-safe request telemetry, health build identity, and optional bounded metrics.

### Delivery

- Add CI, release verification, immutable build identity, stable-only `latest` tagging, dependency automation, a scratch runtime image, and hardened Docker Compose defaults.
- Add an Apache-2.0 license and clarify that this is an independent community project.
