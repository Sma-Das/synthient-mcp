# Security policy

## Reporting a vulnerability

Use GitHub's private security-advisory flow for this repository. Do not open a public issue containing a Synthient API key, request or response body, exploit payload, private IP/domain lookup, or infrastructure detail.

Include the affected version, impact, reproduction steps with synthetic credentials, and any suggested mitigation. Maintainers should acknowledge a report before discussing disclosure timing.

## Credential handling

- API-key mode does not use a global `SYNTHIENT_API_KEY`; callers provide their own `x-api-key` header.
- OAuth mode uses a server-side Synthient key that is separate from audience-bound MCP access tokens. Inbound bearer tokens are never passed through to Synthient.
- Keep keys in the MCP client's environment, OS keychain, or secret manager.
- Do not store keys in `.env`, `.synthient`, client configuration committed to Git, logs, screenshots, or issue reports.
- Rotate and revoke a key immediately if it may have reached a public repository, log, untrusted build service, or third party.
- Use separate, narrowly scoped keys for development and production.

The Docker build context is deny-by-default. Changes to `.dockerignore` or Docker `COPY` statements require security review so workspace credentials cannot become available to builders or image layers.

## Deployment expectations

Local API-key deployments should remain bound to loopback. Remote deployments should use TLS, OAuth mode or an authenticated gateway, network restrictions, and edge rate limiting. Configure trusted-proxy CIDRs only when caller-IP forwarding is explicitly required.

`ALLOWED_HOSTS` and Origin validation mitigate HTTP attacks; neither replaces network access control or authentication. The optional metrics endpoint should remain private.

## Supported versions

Security fixes are applied to the current release line. Consumers should deploy by immutable image digest and upgrade to the newest patched release.
