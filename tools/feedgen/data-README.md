# cvedetector feed (data branch)

The product catalog and the CVE feed built from it. The tools that build the feed are on `main`.

```
catalog/<id>.yaml        product catalog: which images are which product (edit via pull request)
v1/index.json            products, image mappings, checksums of every file below
v1/products/<id>.json    vulnerabilities of one product with affected version ranges
v1/epss.json             EPSS scores (changes daily, kept apart from the shards)
changes/YYYY/MM/DD.json  what changed that day: added, updated, removed vulnerabilities
```

- **`catalog/`** is the only part people edit. Open pull requests against this branch;
  the `catalog` check queries NVD/OSV for the changed products. See CONTRIBUTING.md on `main`.
- **`v1/` and `changes/`** are written by the `feed` workflow on `main` (daily, and after
  every catalog merge). Do not edit them by hand.
- Files under `v1/` always describe the **current** state. Git history is the archive:
  `git log -p -- v1/products/nginx.json` shows how NGINX's CVEs evolved.
- A commit is made only when something changed. The commit message lists new CVEs.
- The cvedetector API reads `v1/` from
  `https://raw.githubusercontent.com/<owner>/cvedetector/data/`.
