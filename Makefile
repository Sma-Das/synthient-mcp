GO_DIR := go
GOVULNCHECK_VERSION := v1.7.0
STATICCHECK_VERSION := v0.7.0

.PHONY: all fmt fmt-check tidy-check vet staticcheck test race cover vuln build docker-check docker-build smoke ci

all: ci

fmt:
	cd $(GO_DIR) && gofmt -w .

fmt-check:
	@files="$$(cd $(GO_DIR) && gofmt -l .)"; test -z "$$files" || { echo "gofmt required:"; echo "$$files"; exit 1; }

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

docker-check:
	docker build --check .

docker-build:
	docker build -t synthient-mcp-go:local .

smoke: docker-build
	@container="synthient-mcp-smoke"; \
		docker rm -f "$$container" >/dev/null 2>&1 || true; \
		docker run -d --name "$$container" -p 127.0.0.1::3000 synthient-mcp-go:local >/dev/null; \
		trap 'docker rm -f "$$container" >/dev/null 2>&1' EXIT; \
		port="$$(docker port "$$container" 3000/tcp | sed 's/.*://')"; \
		for attempt in $$(seq 1 30); do \
			curl --fail --silent "http://127.0.0.1:$$port/healthz" >/dev/null && exit 0; \
			sleep 1; \
		done; \
		docker logs "$$container"; \
		exit 1

ci: fmt-check tidy-check vet staticcheck test race vuln build docker-check
