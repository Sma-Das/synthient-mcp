# Synthient MCP implementations

This repository contains two independent implementations of the Synthient MCP server:

- [`typescript-poc/`](typescript-poc/) — TypeScript implementation using the official MCP TypeScript SDK v2.
- [`go/`](go/) — Go implementation using the official MCP Go SDK.

Each directory has its own dependencies, tests, Dockerfile, Compose configuration, and operating instructions. Neither implementation reads a server-wide Synthient credential: MCP clients supply their existing Synthient key in the `x-api-key` request header.
