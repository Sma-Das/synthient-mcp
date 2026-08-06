# syntax=docker/dockerfile:1.7

FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/synthient-mcp \
    ./cmd/server

FROM alpine:3.23 AS runtime

RUN apk add --no-cache ca-certificates

ENV HOST=0.0.0.0 \
    PORT=3000

COPY --from=build /out/synthient-mcp /usr/local/bin/synthient-mcp

USER 65534:65534

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/synthient-mcp"]
