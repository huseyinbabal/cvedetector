---
title: Development
description: Run the whole stack locally, test it, and re-record these docs.
---

Requirements: Go, Node.js, Docker, and the `gh` CLI (the API reads the private feed with your GitHub token).

## Local stack

```sh
make dev KUBE_CONTEXT=kind-dev      # PostgreSQL, API, agent and UI in one terminal; Ctrl+C stops it
```

The parts can also run on their own:

| Command | |
|---|---|
| `make dev-db` | PostgreSQL in Docker on `127.0.0.1:55499` (`make dev-db-stop`) |
| `make dev-api` | API on `127.0.0.1:28090`, reading the published feed |
| `make dev-agent KUBE_CONTEXT=<ctx>` | Agent reporting that kubeconfig context (read-only). There is no default, so it never reports a cluster by accident. |
| `make dev-ui` | UI with hot reload on http://127.0.0.1:5180 |
| `make feed` | Build the feed locally, then `make dev-api FEED_URL=file://$PWD/dist/feed/` |

## Tests

```sh
make test       # unit tests
make test-db    # + PostgreSQL integration tests
make lint
```

## UI

React, Tailwind CSS v4, [shadcn/ui](https://ui.shadcn.com) and [Lucide](https://lucide.dev). Add a component with `npx shadcn@latest add <name> -y` from `apps/ui`, then check that its imports use `@/lib/utils`.

## Docs

The site is [Starlight](https://starlight.astro.build) in `docs/`, published to GitHub Pages on every push to `main` that touches it.

```sh
cd docs && bun install && bun run dev
```

The demo GIF and screenshots come from a kind cluster with well-known software:

```sh
make demo-cluster CHART=../charts/stable/cvedetector   # kind cluster + workloads + Helm install, UI on :28180
make demo                                              # docs/public/demo.gif and docs/public/screenshots/
make demo-cluster-delete
```

`demo-cluster` keeps its kubeconfig in `.demo/kubeconfig` and never touches your current context.
