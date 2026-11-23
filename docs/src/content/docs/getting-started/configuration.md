---
title: Configuration
description: Helm values and the environment variables behind them.
---

Everything is set through Helm values. The chart turns them into environment variables, listed below for running the binaries yourself. See [values.yaml](https://github.com/huseyinbabal/charts/blob/main/stable/cvedetector/values.yaml) for every key.

## Helm values

| Key | Default | Description |
|---|---|---|
| `image.tag` | chart `appVersion` | Tag of all three images |
| `agent.clusterName` | `local` | Name shown in the UI (lowercase, digits, `-`, max 63) |
| `agent.apiUrl` | this release's API | API base URL, for agent-only installs |
| `agent.existingTokenSecret` | | Secret with the API token (key `token`), for agent-only installs |
| `agent.namespaces.include` / `exclude` | `[]` | Only report these namespaces / skip these |
| `agent.resyncInterval` | `10m` | Heartbeat: report at least this often, even if nothing changed |
| `api.replicas` | `1` | Stateless; feed sync runs on one replica at a time |
| `api.feed.url` | `data` branch on raw.githubusercontent.com | Directory that contains `v1/index.json`. Point it at a mirror for air-gapped clusters. |
| `api.feed.refreshInterval` | `1h` | How often the API checks for a new feed |
| `api.feed.existingTokenSecret` | | Secret with a GitHub token for a private feed (key `token`) |
| `api.retention` | `8760h` | How long resolved findings are kept |
| `api.extraTokensSecret.name` | | Secret with more agent tokens, comma-separated, one per remote cluster |
| `api.workloadMetrics` | `false` | One metric series per workload |
| `ingress.enabled` / `host` / `className` | `false` | `/` → UI, `/api` → API |
| `postgresql.enabled` | `true` | Bundled single-instance PostgreSQL |
| `postgresql.persistence.size` | `8Gi` | Use block storage, not NFS |
| `externalDatabase.*` | | `host`, `port`, `database`, `username`, `existingSecret`, `sslmode` |
| `metrics.*`, `dashboard.*` | off | See [Monitoring and alerts](/cvedetector/features/monitoring/) |

## Agent environment

| Variable | Default | |
|---|---|---|
| `CLUSTER_NAME` | required | DNS label |
| `API_URL` | required | e.g. `http://cvedetector-api:8080` |
| `INGEST_TOKEN` / `INGEST_TOKEN_FILE` | required | |
| `RESYNC_INTERVAL` | `10m` | |
| `DEBOUNCE` | `5s` | Wait after a pod change before reporting |
| `NAMESPACES_INCLUDE` / `NAMESPACES_EXCLUDE` | | Comma-separated |
| `LISTEN_ADDR` | `:8080` | `/healthz`, `/metrics` |

## API environment

| Variable | Default | |
|---|---|---|
| `DATABASE_URL` or `PGHOST`, `PGUSER`, … | required | |
| `INGEST_TOKEN`, `INGEST_TOKENS` | at least one | `INGEST_TOKENS` is comma-separated |
| `FEED_URL` | `https://raw.githubusercontent.com/huseyinbabal/cvedetector/data/` | |
| `FEED_REFRESH_INTERVAL` | `1h` | |
| `FEED_TOKEN` | | Bearer token for a private feed. Not sent when a redirect goes to another host. |
| `RETENTION` | `8760h` | |
| `WORKLOAD_METRICS` | `false` | |
| `LISTEN_ADDR`, `LOG_LEVEL`, `LOG_FORMAT` | `:8080`, `info`, `json` | |
