# Contributing

## Development workflow

Go 1.25 or newer, Docker, and Make are required.

```bash
make fmt
make ci
make smoke
```

Before opening a pull request:

1. Add tests that fail without the change.
2. Run `make ci` from the repository root.
3. Run `make smoke` for HTTP, container, configuration, or Docker changes.
4. Update `README.md`, `SECURITY.md`, and `CHANGELOG.md` when behavior or deployment guidance changes.

Do not use real Synthient credentials in tests. Use `httptest` servers and obviously synthetic values. Tests and logs must not print caller keys, query bodies, queried IPs/domains, or raw forwarding chains.

## Design guidelines

- Validate external input at the MCP boundary and preserve invariants at the upstream HTTP boundary.
- Treat dynamic URL values as opaque escaped segments.
- Keep the service stateless and caller-key-scoped.
- Prefer bounded queues, payloads, cardinality, and timeouts.
- Keep MCP schemas, annotations, descriptions, runtime validation, and billing behavior aligned.
- Avoid automatic retries for metered lookup calls.

## Releases

Release tags must be exact semantic versions such as `v1.2.3` or `v1.2.3-rc.1`. The release workflow checks out the tagged commit, runs the full verification suite, injects build identity, and publishes an immutable digest. Do not move or reuse an existing release tag.
