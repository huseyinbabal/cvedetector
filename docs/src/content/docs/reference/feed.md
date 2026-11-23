---
title: The feed
description: How the CVE feed is built, where it lives and its format.
---

The feed is built by a GitHub Actions workflow and committed to the [`data` branch](https://github.com/huseyinbabal/cvedetector/tree/data). The API downloads it over HTTPS. Nothing in your cluster talks to NVD or OSV.

## Sources

| Source | Used for |
|---|---|
| [NVD](https://nvd.nist.gov) | CVEs and affected ranges by CPE, CVSS |
| [OSV](https://osv.dev) | Affected ranges for Go and other language packages, GitHub advisories |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited flag |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit probability |

When NVD and OSV both describe a CVE, their ranges are merged.

## Schedule

- Daily at 03:17 UTC.
- When a catalog pull request is merged into `data`.
- When the generator on `main` changes.

The output is deterministic. A commit happens only when something changed, and the message summarizes it: `feed 2026-11-23: 0 new, 25 updated, 0 removed`.

## Layout

```
catalog/<id>.yaml           product catalog (input, edited via pull requests)
v1/index.json               products, image → product map, sha256 of every file
v1/products/<id>.json       current CVEs of a product with their affected ranges
v1/epss.json                EPSS scores
changes/YYYY/MM/DD.json     CVEs added, updated and removed that day
```

Each product file holds the current state. For history:

- **git:** `git log -p -- v1/products/nginx.json` shows how NGINX's CVEs changed over time.
- **daily changelogs:** the files under `changes/`.

## How the API syncs

Every `api.feed.refreshInterval`:

1. It fetches `v1/index.json` with an ETag.
2. It downloads only the product files whose sha256 changed, and verifies them.
3. It applies everything in one transaction.
4. It re-matches every cluster.

If anything fails, the previous feed stays in place and the error appears in the UI and in `cvedetector_feed_sync_errors_total`.

## Air-gapped clusters

Mirror the `data` branch (`v1/` is enough) to any HTTP server the API can reach, and set `api.feed.url` to it.
