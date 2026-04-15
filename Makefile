AIR := $(shell command -v air 2>/dev/null || echo $(HOME)/go/bin/air)
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/Infisical/agent-vault/cmd.version=$(VERSION) \
	-X github.com/Infisical/agent-vault/cmd.commit=$(COMMIT) \
	-X github.com/Infisical/agent-vault/cmd.date=$(DATE)

.PHONY: build dev test lint coverage test-all clean docker web web-dev sdk-ts sdk-ts-test

web:
	cd web && npm ci && npm run build

web-dev:
	cd web && npm run dev

build: web
	go build -trimpath -ldflags '$(LDFLAGS)' -o agent-vault .

# Hot-reload dev: Go backend (air) + React frontend (Vite HMR)
# Env vars can come from .env file OR `infisical run -- make dev`.
# Open http://localhost:5173/app/ in browser
dev: web
	@echo ""
	@echo "  ➜ Open http://localhost:5173 in your browser (not 14321)"
	@echo ""
	@trap 'kill 0' EXIT; \
	if [ -f .env ]; then set -a; . ./.env; set +a; echo "  ✓ Loaded .env"; fi; \
	$(AIR) & (cd web && npm run dev) & wait

test:
	go test ./...

lint:
	golangci-lint run ./...
	cd web && npx tsc --noEmit

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-all: test lint

clean:
	rm -f agent-vault
	rm -rf internal/server/webdist

sdk-ts:
	cd sdks/sdk-typescript && npm ci && npm run build

sdk-ts-test:
	cd sdks/sdk-typescript && npm test

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(DATE) \
		-t infisical/agent-vault .
