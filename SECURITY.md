# Security policy

## Reporting a vulnerability

Use GitHub's private security-advisory flow for this repository. Do not open a public issue containing a Synthient API key, request or response body, exploit payload, private IP/domain lookup, or infrastructure detail.

Include the affected version, impact, reproduction steps with synthetic credentials, and any suggested mitigation. Maintainers should acknowledge a report before discussing disclosure timing.

## Credential handling

- The server never needs a global `SYNTHIENT_API_KEY`; callers provide their own `x-api-key` header.
- Keep keys in the MCP client's environment, OS keychain, or secret manager.
- Do not store keys in `.env`, `.synthient`, client configuration committed to Git, logs, screenshots, or issue reports.
- Rotate and revoke a key immediately if it may have reached a public repository, log, untrusted build service, or third party.
- Use separate, narrowly scoped keys for development and production.

The Docker build context is deny-by-default. Changes to `.dockerignore` or Docker `COPY` statements require security review so workspace credentials cannot become available to builders or image layers.

## Deployment expectations

Local deployments should remain bound to loopback. Remote deployments should use TLS, network restrictions, an authenticated gateway or standards-based MCP authorization, edge rate limiting, and a correctly configured trusted-proxy CIDR list.

`ALLOWED_HOSTS` and Origin validation mitigate HTTP attacks; neither replaces network access control or authentication. The optional metrics endpoint should remain private.

## Supported versions

Security fixes are applied to the current release line. Consumers should deploy by immutable image digest and upgrade to the newest patched release.
