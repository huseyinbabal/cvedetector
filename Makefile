.PHONY: test test-db lint ui build images catalog feed feed-validate dev-db dev-api dev-agent dev-ui

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
REGISTRY ?= ghcr.io/huseyinbabal

# Local development database (docker). Port 55499 to stay clear of other projects.
DEV_DB_PORT ?= 55499
DEV_DB_URL  ?= postgres://cvedetector:dev@127.0.0.1:$(DEV_DB_PORT)/cvedetector?sslmode=disable
TEST_DB_URL ?= postgres://cvedetector:dev@127.0.0.1:$(DEV_DB_PORT)/cvedetector_test?sslmode=disable
DEV_API_PORT   ?= 28090
DEV_AGENT_PORT ?= 28091
DEV_UI_PORT    ?= 5180
# Published feed (data branch). Private repo: the token comes from `gh auth token`.
# FEED_URL=file://$(CURDIR)/dist/feed/ uses the one `make feed` builds.
FEED_URL       ?= https://raw.githubusercontent.com/huseyinbabal/cvedetector/data/
# Required by dev-agent: the agent reads this context, never the current one.
KUBE_CONTEXT   ?=

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

# The catalog lives on the data branch. `make catalog` puts a read-only copy in
# .catalog/. To edit it: git worktree add ../cvedetector-data data, then pass
# CATALOG=../cvedetector-data/catalog.
CATALOG ?= .catalog

catalog:
	git fetch -q origin data
	rm -rf .catalog && mkdir -p .catalog
	git archive FETCH_HEAD catalog | tar -x --strip-components=1 -C .catalog

# Builds the feed into dist/feed/v1. Set NVD_API_KEY for faster NVD queries.
feed: $(if $(filter .catalog,$(CATALOG)),catalog)
	go run ./tools/feedgen -config $(CATALOG) -out dist/feed

feed-validate: $(if $(filter .catalog,$(CATALOG)),catalog)
	go run ./tools/feedgen -config $(CATALOG) -validate

# ---- local stack: make dev-db, then dev-api, dev-agent and dev-ui in separate terminals
dev-db:
	docker start cvedetector-pg-dev 2>/dev/null || docker run -d --name cvedetector-pg-dev -e POSTGRES_USER=cvedetector -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=cvedetector \
		-p 127.0.0.1:$(DEV_DB_PORT):5432 postgres:18.6-alpine
	@sleep 3; docker exec cvedetector-pg-dev psql -U cvedetector -qc 'CREATE DATABASE cvedetector_test' || true

dev-api: build
	DATABASE_URL='$(DEV_DB_URL)' INGEST_TOKEN=dev-token FEED_URL='$(FEED_URL)' \
		FEED_TOKEN="$${FEED_TOKEN:-$$(gh auth token 2>/dev/null)}" \
		LISTEN_ADDR=127.0.0.1:$(DEV_API_PORT) LOG_FORMAT=text ./dist/api

# Reports one kubeconfig context (read-only: lists pods, replicasets, jobs) to the local API.
dev-agent: build
	@test -n "$(KUBE_CONTEXT)" || { echo "Set KUBE_CONTEXT, e.g. make dev-agent KUBE_CONTEXT=kind-dev"; exit 1; }
	CLUSTER_NAME=local KUBE_CONTEXT='$(KUBE_CONTEXT)' API_URL=http://127.0.0.1:$(DEV_API_PORT) INGEST_TOKEN=dev-token \
		LISTEN_ADDR=127.0.0.1:$(DEV_AGENT_PORT) LOG_FORMAT=text ./dist/agent

dev-ui:
	cd apps/ui && API_URL=http://127.0.0.1:$(DEV_API_PORT) npx vite --host 127.0.0.1 --port $(DEV_UI_PORT) --strictPort
