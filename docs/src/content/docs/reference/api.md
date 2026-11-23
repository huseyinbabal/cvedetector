---
title: HTTP API
description: The endpoints the agent and the UI use.
---

All read endpoints are `GET`, return JSON, and send an `ETag` (`If-None-Match` gets a `304`).

## Ingest

| Endpoint | |
|---|---|
| `POST /api/v1/ingest` | Agent report. `Authorization: Bearer <token>`, gzip accepted, up to 64 MB. Returns `202 {images, opened, resolved, open, changed}`. |
| `DELETE /api/v1/clusters/{name}` | Deletes a cluster and its history. Needs a token. |

## Read

| Endpoint | |
|---|---|
| `GET /api/v1/summary?cluster=` | Severity counts (distinct CVEs), KEV, fixable, image statuses, top 10 workloads, CVEs per product |
| `GET /api/v1/history?cluster=&days=30` | Open CVEs at the end of each day by severity, findings opened and resolved, mean time to resolve |
| `GET /api/v1/clusters` | Last report, agent version, counts |
| `GET /api/v1/images` | Paged list of images |
| `GET /api/v1/image?cluster=&ref=` | Image, open and resolved CVEs, workloads |
| `GET /api/v1/workloads` | Paged list of workloads |
| `GET /api/v1/workloads/{cluster}/{ns}/{kind}/{name}` | Workload and its images |
| `GET /api/v1/cves` | Paged list of CVEs |
| `GET /api/v1/cves/{id}?cluster=` | CVE, affected and resolved images, workloads |
| `GET /api/v1/products` | Products in the feed |
| `GET /api/v1/feed` | Feed status |
| `GET /api/v1/namespaces` | Namespaces |
| `GET /healthz`, `/readyz`, `/metrics` | Liveness, readiness (database ping), Prometheus |

## List parameters

Paged lists return `{items, total}`.

| Parameter | |
|---|---|
| `cluster`, `namespace`, `q` | Scope and text search |
| `minSeverity` | `critical`, `high`, `medium`, `low` |
| `status` | `matched`, `approximate`, `no-version`, `unknown` |
| `product`, `kev`, `fixable` | |
| `sort`, `order` | `order` is `asc` or `desc` |
| `limit`, `offset` | `limit` up to 500 |

The CVE list defaults to: known exploited first, then severity, CVSS and affected workloads.

```sh
curl -s 'http://localhost:8080/api/v1/cves?kev=true&limit=5' | jq '.items[].id'
```
