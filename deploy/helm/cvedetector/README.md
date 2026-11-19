# cvedetector

Shows which known CVEs affect the container images running in your Kubernetes clusters, and tracks them over time. No image scanning: image versions are read from tags and matched against a CVE feed built from NVD and OSV.

Components: **agent** (read-only, per cluster) → **API** (PostgreSQL) ← **UI**.

## Install

```sh
helm repo add huseyinbabal https://huseyinbabal.github.io/charts
helm install cvedetector huseyinbabal/cvedetector -n cvedetector --create-namespace
kubectl -n cvedetector port-forward svc/cvedetector-ui 8080
```

## Database

The API requires PostgreSQL.

| | Values |
|---|---|
| Bundled (default) | `postgresql.enabled=true`: single-instance `postgres:18.6-alpine` StatefulSet with an 8Gi PVC. Password generated once and kept across upgrades. |
| External | `postgresql.enabled=false`, `externalDatabase.host`, `externalDatabase.existingSecret` (key `password`), `externalDatabase.sslmode` |

## Private feed

While the feed repository is private, give the API a GitHub fine-grained token with read-only *Contents* access:

```sh
kubectl -n cvedetector create secret generic cvedetector-feed --from-literal=token=<github token>
--set api.feed.existingTokenSecret=cvedetector-feed
```

## More clusters

Install the agent only in each additional cluster, pointing at the central API (exposed with `ingress.enabled=true`, which routes `/api` to the API):

```sh
kubectl -n cvedetector create secret generic cvedetector-token --from-literal=token=<token of the central install>
helm install cvedetector huseyinbabal/cvedetector -n cvedetector --create-namespace \
  --set api.enabled=false,ui.enabled=false,postgresql.enabled=false \
  --set agent.clusterName=prod-eu-1,agent.apiUrl=https://cvedetector.example.com \
  --set agent.existingTokenSecret=cvedetector-token
```

The central install's token: `kubectl -n cvedetector get secret cvedetector-ingest -o jsonpath='{.data.token}' | base64 -d`.

## Main values

| Key | Default | Description |
|---|---|---|
| `agent.clusterName` | `local` | Name shown in the UI (lowercase, digits, `-`) |
| `agent.namespaces.include` / `exclude` | `[]` | Namespace filter |
| `api.replicas` | `1` | Stateless; coordinates through PostgreSQL locks |
| `api.feed.url` | data branch on raw.githubusercontent.com | Feed location |
| `api.retention` | `8760h` | How long resolved findings are kept |
| `api.workloadMetrics` | `false` | One metric series per workload |
| `ingress.enabled` / `host` | `false` | `/` → UI, `/api` → API |
| `serviceMonitor.enabled` | `false` | Prometheus Operator ServiceMonitor for API and agent |

See [values.yaml](values.yaml) for everything.
