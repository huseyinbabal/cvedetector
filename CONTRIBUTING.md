# Contributing

## Add a product to the feed

cvedetector doesn't scan images. It knows that `docker.io/library/php:8.3.14-fpm` is PHP 8.3.14 because a product file says so, and it gets PHP's CVEs from NVD or OSV. If an image you run shows up under **Coverage gaps** in the UI, add a product file for it.

1. Create `feed/products/<id>.yaml` (the file name must equal `id`). The UI's **Add to feed** button opens this file pre-filled on GitHub.

   ```yaml
   # PHP runtime (official php images and Bitnami php-fpm).
   id: php
   name: "PHP"
   images:                        # full repository names, no tag
     - docker.io/library/php
     - docker.io/bitnami/php-fpm
   nvd:
     cpes:
       - cpe:2.3:a:php:php        # vendor:product, see below
   testTags:                      # real tags and the version in them ("" = none)
     "8.3.14-fpm-alpine": "8.3.14"
     "8.2-apache": "8.2"
     "fpm": ""
   ```

2. Find the vulnerability source:
   - **NVD (most software):** search https://nvd.nist.gov/products/cpe/search for the product and use the `cpe:2.3:a:<vendor>:<product>` prefix of its CPEs.
   - **OSV (Go and other language packages):** if the image ships a Go module whose version equals the image tag, use `osv: [{ecosystem: Go, package: github.com/org/repo}]`. Check that https://osv.dev lists vulnerabilities for it.
   - The product's version numbers must be the ones in the image tag. An operator or exporter named after a product (for example `prometheus-operator`) is a different product with its own versions.

3. Tags that don't start with the version need `versionPattern`, a regexp with a named group `version`:

   ```yaml
   versionPattern: '^(?:distroless-|contrib-)?v?(?P<version>\d+(?:\.\d+){0,3})'
   ```

   Products whose full versions have two parts (PostgreSQL's `16.4`) set `minSegments: 2`. Otherwise a tag like `nginx:1.27` is treated as a floating tag.

4. Check locally, then open a pull request:

   ```sh
   go run ./tools/feedgen -validate        # schema, test tags, duplicate images
   go run ./tools/feedgen -probe php       # queries NVD/OSV, prints what matches
   ```

The `products` check runs the same on your pull request and posts the report in the job summary. A source returning no vulnerabilities fails the check: it almost always means a wrong CPE or package name.

## Automatic discovery

The `discover` workflow runs every week. It looks at the images used by the most-starred Helm charts on Artifact Hub, Docker Official Images and Bitnami images, and matches the ones not yet mapped to NVD products by name. It opens a pull request with its proposals; a person reviews and merges it. You can run it locally:

```sh
go run ./tools/feedgen/discover -dry-run -report /tmp/report.md
```

## Code

See the [README](README.md#develop) for the local stack. Run `make lint test-db` before opening a pull request.
