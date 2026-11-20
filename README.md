# cvedetector

Shows which known CVEs affect the container images **running right now** in your Kubernetes clusters, and tracks them over time, without scanning anything.

- A daily GitHub Actions job builds a CVE feed from NVD and OSV and commits it to the `data` branch when something changed. The feed maps image repositories (e.g. `docker.io/library/nginx`) to products and lists each product's CVEs with their affected version ranges; `changes/YYYY/MM/YYYY-MM-DD.json` records what changed each day.
- An **agent** in each cluster watches pods and reports which images run where. It needs read-only access to pods and no internet access.
- The **API** stores inventories in PostgreSQL, mirrors the feed, reads each image's version from its tag (`nginx:1.27.1` → `1.27.1`), matches it against the ranges and keeps a history of when each CVE appeared and was resolved.
- The **UI** shows it all: per cluster or across clusters, with trends.

No image is pulled, no SBOM is generated, no registry credentials are needed. The trade-off: only the image's main software is covered (NGINX itself, not the OpenSSL package inside the NGINX image). See [SPEC.md](SPEC.md).

## Install

This repository builds the images (`ghcr.io/huseyinbabal/cvedetector-{agent,api,ui}`); the Helm chart lives in [huseyinbabal/charts](https://github.com/huseyinbabal/charts/tree/main/stable/cvedetector).

```sh
helm repo add huseyinbabal https://huseyinbabal.github.io/charts
helm install cvedetector huseyinbabal/cvedetector -n cvedetector --create-namespace
kubectl -n cvedetector port-forward svc/cvedetector-ui 8080
open http://localhost:8080
```

While this repository is private the API needs a GitHub token to read the feed: see the [chart README](https://github.com/huseyinbabal/charts/tree/main/stable/cvedetector#private-feed).

This deploys the agent, API, UI and a bundled PostgreSQL. With your own database:

```sh
--set postgresql.enabled=false \
--set externalDatabase.host=pg.example.com \
--set externalDatabase.existingSecret=cvedetector-db   # key "password"
```

Report another cluster to the same API (agent only):

```sh
kubectl -n cvedetector create secret generic cvedetector-token --from-literal=token=<token from the main install>
helm install cvedetector huseyinbabal/cvedetector -n cvedetector \
  --set api.enabled=false,ui.enabled=false,postgresql.enabled=false \
  --set agent.clusterName=prod-eu-1,agent.apiUrl=https://cvedetector.example.com \
  --set agent.existingTokenSecret=cvedetector-token
```

## Add an image to the feed

The feed knows which product an image is from `catalog/<id>.yaml` on the [`data` branch](../../tree/data/catalog). Missing one? Open a pull request against `data` (the UI's **Coverage gaps** page pre-fills it); a check queries NVD/OSV and reports what would match. A weekly `discover` workflow also proposes new products from popular Helm charts and Docker Official/Bitnami images. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Develop

```sh
make dev-db                          # PostgreSQL in docker on 127.0.0.1:55499
make dev-api                         # API on 127.0.0.1:28090, published feed (token from `gh auth token`)
make dev-agent KUBE_CONTEXT=<ctx>    # agent reporting that kubeconfig context (read-only)
make dev-ui                          # UI with hot reload on http://127.0.0.1:5180
make feed                            # optional: build the feed locally, then dev-api FEED_URL=file://$PWD/dist/feed/
make test          # unit tests
make test-db       # + PostgreSQL integration tests
```

The UI uses React, Tailwind CSS v4, [shadcn/ui](https://ui.shadcn.com) and [Lucide](https://lucide.dev). Add a component with `npx shadcn@latest add <name> -y` from `apps/ui`, then check that its imports use `@/lib/utils`. Press ⌘K / Ctrl+K in the UI to search.

## Layout

| Path | What |
|---|---|
| `apps/agent` | In-cluster inventory agent (Go) |
| `apps/api` | API: PostgreSQL, feed sync, matching, history (Go) |
| `apps/ui` | UI (React + TypeScript), served by nginx |
| `tools/feedgen` | Feed generator (NVD, OSV, CISA KEV, EPSS); `discover/` proposes new products |
| `pkg/feed`, `pkg/inventory` | Contracts: feed format, agent → API report |
| `data` branch | Product catalog (`catalog/`, edited via pull requests), generated feed and daily changelogs |
