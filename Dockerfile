# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:70b46548e42db77e0966aaf3619fd068734dc6c77584d526b91126504fd95816 AS build

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go/go.mod go/go.sum ./
RUN go mod download && go mod verify

COPY go/cmd ./cmd
COPY go/internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w \
      -X github.com/Sma-Das/synthient-mcp/go/internal/buildinfo.Version=$VERSION \
      -X github.com/Sma-Das/synthient-mcp/go/internal/buildinfo.Commit=$COMMIT \
      -X github.com/Sma-Das/synthient-mcp/go/internal/buildinfo.Date=$BUILD_DATE" \
    -o /out/synthient-mcp \
    ./cmd/server

FROM scratch AS runtime

ENV HOST=0.0.0.0 \
    PORT=3000

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/synthient-mcp /usr/local/bin/synthient-mcp

USER 65534:65534

EXPOSE 3000
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/synthient-mcp", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/synthient-mcp"]
