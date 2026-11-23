---
title: How matching works
description: From an image tag to a list of CVEs, and the limits of doing it without scanning.
---

## From image to product

The feed's index maps image repositories to products:

```
docker.io/library/nginx          → nginx (NGINX)
docker.io/nginxinc/nginx-unprivileged → nginx
docker.io/bitnami/nginx          → nginx
```

Repositories are normalized first: `nginx` becomes `docker.io/library/nginx`.

## From tag to version

By default the version is the leading number in the tag: `^v?(\d+(\.\d+){0,3})`.

| Tag | Version | Status |
|---|---|---|
| `1.27.3-alpine` | 1.27.3 | Matched |
| `v2.10.5` | 2.10.5 | Matched |
| `1.27` | 1.27 | Approximate: compared as 1.27.0 |
| `latest`, `stable`, digest only | | No version |

Products whose tags look different set their own `versionPattern`. Products with two-part versions (PostgreSQL `16.4`) set `minSegments: 2`, so `16.4` counts as a full version.

## From version to CVEs

Each CVE in the feed lists the affected ranges of the product: `introduced`, `fixed`, or `lastAffected`. A version inside any range is affected. The **Fixed in** column shows the version that fixes it.

The API matches, not the agent. When the feed changes, every cluster is re-matched, so a CVE published today shows up even if nothing was deployed.

## History

Each (image, CVE) pair is a finding:

- It **opens** the first time the pair appears.
- It **resolves** when the pair disappears: the image was upgraded or removed, or the feed no longer lists the CVE for that version.

Resolved findings are kept for `api.retention` (one year by default) and feed the trend on the Overview.

## Limits

This is a deliberate trade-off for not scanning anything:

- **Only the main software is covered.** NGINX itself, not the OpenSSL or glibc packages inside the NGINX image. Use an image scanner if you need OS packages.
- **Backports.** Debian or Ubuntu based images sometimes patch a CVE without changing the version. Those show up as false positives.
- **Tags can lie.** A re-tagged or custom-built image is judged by its tag.
- **Your own images** have no public CVE records, so they stay under Coverage gaps.
