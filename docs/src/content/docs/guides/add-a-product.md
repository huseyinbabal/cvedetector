---
title: Add a product to the feed
description: Map an image repository to a product so its CVEs are tracked.
---

cvedetector doesn't scan images. It knows that `docker.io/library/php:8.3.14-fpm` is PHP 8.3.14 because a product file says so, and it gets PHP's CVEs from NVD or OSV. If an image you run shows up under [Coverage gaps](/cvedetector/features/coverage-gaps/), add a product file for it.

The catalog lives on the **`data` branch** under [`catalog/`](https://github.com/huseyinbabal/cvedetector/tree/data/catalog), next to the feed built from it.

## 1. Write the product file

Create `catalog/<id>.yaml` on the `data` branch. The file name must equal `id`. The UI's **Add to feed** button opens this file pre-filled.

```yaml
# PHP runtime (official php images and Bitnami php-fpm).
id: php
name: "PHP"
images:                        # full repository names, no tag
  - docker.io/library/php
  - docker.io/bitnami/php-fpm
nvd:
  cpes:
    - cpe:2.3:a:php:php        # vendor:product
testTags:                      # real tags and the version in them ("" = none)
  "8.3.14-fpm-alpine": "8.3.14"
  "8.2-apache": "8.2"
  "fpm": ""
```

## 2. Find the vulnerability source

- **NVD (most software):** search the [CPE dictionary](https://nvd.nist.gov/products/cpe/search) and use the `cpe:2.3:a:<vendor>:<product>` prefix.
- **OSV (Go and other language packages):** if the image ships a Go module whose version equals the image tag, use `osv: [{ecosystem: Go, package: github.com/org/repo}]`. Check that [osv.dev](https://osv.dev) lists vulnerabilities for it.

The product's version numbers must be the ones in the image tag. An operator or exporter named after a product (for example `prometheus-operator`) is a different product with its own versions.

## 3. Tags that don't start with the version

Add `versionPattern`, a regexp with a named group `version`:

```yaml
versionPattern: '^(?:distroless-|contrib-)?v?(?P<version>\d+(?:\.\d+){0,3})'
```

Products whose full versions have two parts (PostgreSQL's `16.4`) set `minSegments: 2`. Otherwise a tag like `postgres:16.4` would be treated as a floating tag.

## 4. Check and open the pull request

The tools are on `main`, so check out the catalog next to it:

```sh
git worktree add ../cvedetector-data data          # from a clone of main
# edit ../cvedetector-data/catalog/php.yaml
go run ./tools/feedgen -config ../cvedetector-data/catalog -validate     # schema, test tags, duplicate images
go run ./tools/feedgen -config ../cvedetector-data/catalog -probe php    # queries NVD/OSV, prints what matches
```

Open the pull request against `data`. The `catalog` check runs the same probe and posts the report in the job summary. A source that returns no vulnerabilities fails the check: it almost always means a wrong CPE or package name. After the merge, the feed is rebuilt, and installs pick it up within `api.feed.refreshInterval`.

## Automatic discovery

A weekly `discover` workflow proposes new products. It looks at:

- images used by the most-starred Helm charts on Artifact Hub
- Docker Official Images
- Bitnami images

It matches them to NVD products by name and opens a pull request against `data` for a person to review.
