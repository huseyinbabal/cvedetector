# cvedetector feed (data branch)

This branch is written by the `feed` workflow on `main`. Do not edit it by hand.

```
v1/index.json            products, image mappings, checksums of every file below
v1/products/<id>.json    vulnerabilities of one product with affected version ranges
v1/epss.json             EPSS scores (changes daily, kept apart from the shards)
changes/YYYY/MM/DD.json  what changed that day: added, updated, removed vulnerabilities
```

- Files under `v1/` always describe the **current** state. Git history is the archive:
  `git log -p -- v1/products/nginx.json` shows how NGINX's CVEs evolved.
- A commit is made only when something changed. The commit message lists new CVEs.
- The cvedetector API reads `v1/` from
  `https://raw.githubusercontent.com/<owner>/cvedetector/data/` (a token is needed while
  the repository is private: `FEED_TOKEN`).
