GO_DIR := go
GOVULNCHECK_VERSION := v1.10.0
STATICCHECK_VERSION := v0.8.2

.PHONY: all fmt fmt-check tidy-check vet staticcheck test race cover vuln build binary docker-check docker-build smoke ci

all: ci

# Resolve gofmt from the active Go toolchain so fmt-check cannot pass vacuously
# when gofmt is missing from PATH.
GOFMT := $(shell go env GOROOT)/bin/gofmt

fmt:
	cd $(GO_DIR) && $(GOFMT) -w .

fmt-check:
	@files="$$(cd $(GO_DIR) && $(GOFMT) -l .)" || exit 1; test -z "$$files" || { echo "gofmt required:"; echo "$$files"; exit 1; }

tidy-check:
	cd $(GO_DIR) && go mod tidy -diff

vet:
	cd $(GO_DIR) && go vet ./...

staticcheck:
	cd $(GO_DIR) && go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

test:
	cd $(GO_DIR) && go test ./...

race:
	cd $(GO_DIR) && go test -race ./...

cover:
	mkdir -p coverage
	cd $(GO_DIR) && go test -coverprofile=../coverage/coverage.out ./...
	cd $(GO_DIR) && go tool cover -func=../coverage/coverage.out

vuln:
	cd $(GO_DIR) && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

build:
	cd $(GO_DIR) && go build ./...

binary:
	cd $(GO_DIR) && go build -o synthient-mcp ./cmd/server

docker-check:
	docker build --check .

docker-build:
	docker build -t synthient-mcp-go:local .

# The smoke test builds a per-run image tag and tracks its own container ID, so
# concurrent runs on a shared Docker daemon never remove each other's
# resources. It runs with the same hardening flags as compose.yaml. Pass extra
# docker run flags, such as labels, with SMOKE_RUN_ARGS.
SMOKE_RUN_ARGS ?=

smoke:
	@set -e; \
		image="synthient-mcp-go:smoke-$$$$-$$(date +%s)"; \
		container=""; \
		cleanup() { \
			if [ -n "$$container" ]; then docker rm -f "$$container" >/dev/null 2>&1 || true; fi; \
			docker image rm "$$image" >/dev/null 2>&1 || true; \
		}; \
		trap cleanup EXIT; \
		docker build -q -t "$$image" . >/dev/null; \
		container="$$(docker run -d --read-only --cap-drop ALL --security-opt no-new-privileges:true \
			-p 127.0.0.1::3000 $(SMOKE_RUN_ARGS) "$$image")"; \
		port="$$(docker port "$$container" 3000/tcp | head -n 1 | sed 's/.*://')"; \
		for attempt in $$(seq 1 30); do \
			if curl --fail --silent "http://127.0.0.1:$$port/healthz" >/dev/null; then \
				docker exec "$$container" /usr/local/bin/synthient-mcp healthcheck; \
				echo "smoke test passed"; \
				exit 0; \
			fi; \
			sleep 1; \
		done; \
		docker logs "$$container"; \
		exit 1

ci: fmt-check tidy-check vet staticcheck test race vuln build docker-check
