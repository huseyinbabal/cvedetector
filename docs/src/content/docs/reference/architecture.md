---
title: Architecture
description: The agent, the API, the UI, the feed, and why matching happens in the API.
---

```
 GitHub ─────────────────────────────────────────────────────────────
  data:catalog/*.yaml ─► Actions (daily) ─► feedgen
                         NVD + OSV + KEV + EPSS ─► v1/index.json, v1/products/<id>.json
                                                   committed to the data branch
                                                              │ HTTPS (ETag)
 Central cluster ─────────────────────────────────────────────┼───────
                                                              ▼
   ui (nginx) ── GET /api/* ──► api (N replicas) ──────────► PostgreSQL
                                 ├─ feed sync (one replica at a time)
                                 ├─ POST /api/v1/ingest (Bearer token)
                                 ├─ matching and finding history
                                 └─ read API, /metrics
                                        ▲
 Every cluster ─────────────────────────┼────────────────────────────
   agent (1 pod, read-only RBAC)
     pod informer → inventory report (images + workloads), gzip JSON
```

## Agent

- Watches pods and resolves their owners: Pod → ReplicaSet → Deployment, Pod → Job → CronJob.
- Keeps only names, owners, images and image IDs in memory.
- Reports when the inventory changes (after a 5 second debounce), and at least every 10 minutes as a heartbeat. An unchanged inventory isn't re-sent.
- On failure it retries with backoff (2 seconds up to 2 minutes) and keeps only the latest inventory.
- Needs no internet access and no database.

## API

- Mirrors the feed into PostgreSQL and matches every cluster's images against it.
- Keeps the history of findings: first seen, last seen, resolved.
- Applies migrations at startup. Feed sync, migrations and per-cluster matching use PostgreSQL advisory locks, so replicas can be added freely.
- Deletes resolved findings older than `RETENTION` once a day.

## UI

- A static React app served by nginx, which passes only `GET` and `HEAD` on `/api` to the API.
- Refreshes every 30 seconds while the tab is visible, using ETags.

## Why matching happens in the API

1. **New CVEs show up without a deploy.** When the feed changes, the API re-matches every cluster.
2. **The agent stays offline.** It talks only to the API.
3. **Many clusters, one view.** Every agent reports to the same API.
