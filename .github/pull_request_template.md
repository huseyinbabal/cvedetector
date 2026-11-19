<!-- Adding or changing a product? See CONTRIBUTING.md. -->

## What

## Product checklist (delete if not a product change)

- [ ] The pull request targets the `data` branch
- [ ] `make feed-validate CATALOG=<path to catalog>` passes
- [ ] `go run ./tools/feedgen -config <path to catalog> -probe <id>` shows vulnerabilities for every source
- [ ] The CPE / package is the product inside the image, not something with the same name
- [ ] `testTags` use real tags from the registry
