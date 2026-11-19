.PHONY: test test-db lint ui build images feed feed-validate dev-db dev-api dev-agent dev-ui helm-lint

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
REGISTRY ?= ghcr.io/huseyinbabal

# Local development database (docker). Port 55499 to stay clear of other projects.
DEV_DB_PORT ?= 55499
DEV_DB_URL  ?= postgres://cvedetector:dev@127.0.0.1:$(DEV_DB_PORT)/cvedetector?sslmode=disable
TEST_DB_URL ?= postgres://cvedetector:dev@127.0.0.1:$(DEV_DB_PORT)/cvedetector_test?sslmode=disable

# Unit tests; database tests are skipped.
test:
	go test ./...

# All tests including PostgreSQL integration tests (needs `make dev-db`).
# -p 1: the database-backed packages share the test database.
test-db:
	TEST_DATABASE_URL='$(TEST_DB_URL)' go test -race -p 1 ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"
	cd apps/ui && npm run typecheck

ui:
	cd apps/ui && npm ci --no-audit --no-fund && npm run build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/agent ./apps/agent/cmd/agent
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/api ./apps/api/cmd/api

images:
	docker build -f apps/agent/Dockerfile --build-arg VERSION=$(VERSION) -t $(REGISTRY)/cvedetector-agent:$(VERSION) .
	docker build -f apps/api/Dockerfile --build-arg VERSION=$(VERSION) -t $(REGISTRY)/cvedetector-api:$(VERSION) .
	docker build -t $(REGISTRY)/cvedetector-ui:$(VERSION) apps/ui

# Builds the feed into dist/feed/v1. Set NVD_API_KEY for faster NVD queries.
feed:
	go run ./tools/feedgen -config feed/products -out dist/feed

feed-validate:
	go run ./tools/feedgen -validate

# ---- local stack: make dev-db, then dev-api, dev-agent and dev-ui in separate terminals
dev-db:
	docker run -d --name cvedetector-pg-dev -e POSTGRES_USER=cvedetector -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=cvedetector \
		-p 127.0.0.1:$(DEV_DB_PORT):5432 postgres:18.6-alpine
	@sleep 3; docker exec cvedetector-pg-dev psql -U cvedetector -qc 'CREATE DATABASE cvedetector_test' || true

dev-api: build
	DATABASE_URL='$(DEV_DB_URL)' INGEST_TOKEN=dev-token FEED_URL=file://$(CURDIR)/dist/feed/ \
		LISTEN_ADDR=127.0.0.1:8090 LOG_FORMAT=text ./dist/api

# Reports the current kubeconfig context (read-only) to the local API.
dev-agent: build
	CLUSTER_NAME=local API_URL=http://127.0.0.1:8090 INGEST_TOKEN=dev-token \
		LISTEN_ADDR=127.0.0.1:8091 LOG_FORMAT=text ./dist/agent

dev-ui:
	cd apps/ui && API_URL=http://127.0.0.1:8090 npm run dev

helm-lint:
	helm lint deploy/helm/cvedetector
